package dynstate

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func typecheckMethodsAndSinksPkg(t *testing.T, pkgPath, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", pkgPath, err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	conf := types.Config{Importer: importer.Default()}
	tpkg, err := conf.Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("typecheck %s: %v", pkgPath, err)
	}
	return &packages.Package{
		PkgPath:   pkgPath,
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     tpkg,
		TypesInfo: info,
	}
}

func TestDeriveNonMutatingMethodsAndNoPostInitCarrierWrites(t *testing.T) {
	p := typecheckMethodsAndSinksPkg(t, "example.com/p", `package p

type Reader struct {
	n int
}

func (r *Reader) helper() int {
	x := r.n + 1
	return x
}

func (r *Reader) ReadCount() int {
	return r.helper()
}

func (r *Reader) MutateCount() {
	r.n++
}
`)
	idx := refconfine.BuildPkgIndex(p)
	methods := deriveNonMutatingMethods(true, p, idx)
	want := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.ReadCount"}
	bad := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.MutateCount"}
	foundWant := false
	for _, m := range methods {
		if m == want {
			foundWant = true
		}
		if m == bad {
			t.Fatalf("unexpected mutating method in deriveNonMutatingMethods: %v", m)
		}
	}
	if !foundWant {
		t.Fatalf("expected %v in deriveNonMutatingMethods, got %v", want, methods)
	}
	if clean, culprits := deriveNoPostInitCarrierWrites(true, p, idx, idx.InitOnly, nil); !clean || len(culprits) > 0 {
		t.Fatalf("expected deriveNoPostInitCarrierWrites=(true, nil) on carrier-clean package, got (%v, %v)", clean, culprits)
	}
	if writes := collectDirectCrossPkgVarWrites(true, p, idx); len(writes) != 0 {
		t.Fatalf("expected empty collectDirectCrossPkgVarWrites, got %v", writes)
	}
	if uses := collectNonMethodCrossPkgVarUses(true, p, idx, nil); len(uses) != 0 {
		t.Fatalf("expected empty collectNonMethodCrossPkgVarUses, got %v", uses)
	}
}

func TestDeriveNonMutatingAndNoPostInitRejectMutatingAndSendingStdlibCalls(t *testing.T) {
	mutPkg := typecheckMethodsAndSinksPkg(t, "example.com/mut", `package mut

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"sync"
	"unicode/utf8"
)

type Mutator interface {
	Mutate()
}

type Box struct {
	raw   []byte
	nums  []int
	buf   *bytes.Buffer
	mu    *sync.Mutex
	rw    *sync.RWMutex
	once  *sync.Once
	pool  *sync.Pool
	iface Mutator
}

func (b Box) CleanLen() int {
	if bytes.Equal(b.raw, []byte("ok")) && utf8.Valid(b.raw) {
		return len(b.raw)
	}
	return 0
}

func (b Box) ReverseRaw() { slices.Reverse(b.raw) }
func (b Box) SortNums()   { sort.Ints(b.nums) }
func (b Box) PutBin()     { binary.LittleEndian.PutUint64(b.raw, 1) }
func (b Box) EncodeUTF8() { utf8.EncodeRune(b.raw, 'x') }
func (b Box) AppendNum()  { _ = strconv.AppendInt(b.raw, 1, 10) }
func (b Box) ClearRefl()  { reflect.ValueOf(b.raw).Clear() }
func (b Box) ResetBuf()   { b.buf.Reset() }
func (b Box) UnlockMu()   { b.mu.Unlock() }
func (b Box) RLockRW()    { b.rw.RLock() }
func (b Box) DoOnce()     { b.once.Do(func() {}) }
func (b Box) GetPool()    { _ = b.pool.Get() }
func (b Box) CallIface()  { b.iface.Mutate() }
`)
	mutIdx := refconfine.BuildPkgIndex(mutPkg)
	gotMethods := deriveNonMutatingMethods(true, mutPkg, mutIdx)
	wantOnly := []syntaxutil.FuncKey{{Pkg: "example.com/mut", Name: "Box.CleanLen"}}
	if !slices.Equal(gotMethods, wantOnly) {
		t.Fatalf("deriveNonMutatingMethods = %v, want exact %v", gotMethods, wantOnly)
	}

	for _, tc := range []struct {
		name      string
		src       string
		wantClean bool
	}{
		{
			name: "local_unexported_pool_carrier_free_put_clean",
			src: `package p
import "sync"
type scratch struct{ buf [16]byte }
var pool sync.Pool
func Run() {
	v := pool.Get()
	_ = v
	pool.Put(&scratch{})
}
`,
			wantClean: true,
		},
		{
			name: "param_pool_put_rejected",
			src: `package p
import "sync"
func Stash(pool *sync.Pool, x any) {
	pool.Put(x)
}
`,
			wantClean: false,
		},
		{
			name: "reflect_value_send_rejected",
			src: `package p
import "reflect"
func Forward(ch, v any) {
	reflect.ValueOf(ch).Send(reflect.ValueOf(v))
}
`,
			wantClean: false,
		},
		{
			name: "reflect_value_trysend_rejected",
			src: `package p
import "reflect"
func TryForward(ch, v any) bool {
	return reflect.ValueOf(ch).TrySend(reflect.ValueOf(v))
}
`,
			wantClean: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := typecheckMethodsAndSinksPkg(t, "example.com/p", tc.src)
			idx := refconfine.BuildPkgIndex(pkg)
			clean, culprits := deriveNoPostInitCarrierWrites(true, pkg, idx, idx.InitOnly, nil)
			if clean != tc.wantClean {
				t.Fatalf("deriveNoPostInitCarrierWrites = (%v, %v), want clean=%v", clean, culprits, tc.wantClean)
			}
		})
	}
}
