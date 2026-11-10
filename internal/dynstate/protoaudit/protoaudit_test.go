package protoaudit

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func typecheckTestPkg(t *testing.T, pkgPath, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("typecheck: %v", err)
	}
	return &packages.Package{
		PkgPath:   pkgPath,
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     pkg,
		TypesInfo: info,
	}
}

func TestDeriveNonMutatingMethodsAndUnifiedLockedRoles(t *testing.T) {
	p := typecheckTestPkg(t, "example.com/p", `package p

import (
	"sync"
	"sync/atomic"
)

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

type EnumInfo struct {
	Name string
}

type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}

func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 42
	atomic.StoreUint32(&mi.done, 1)
}
`)
	idx := refconfine.BuildPkgIndex(p)
	methods := DeriveNonMutatingMethods(true, p, idx)
	want := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.ReadCount"}
	bad := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.MutateCount"}
	foundWant := false
	for _, m := range methods {
		if m == want {
			foundWant = true
		}
		if m == bad {
			t.Fatalf("unexpected mutating method in DeriveNonMutatingMethods: %v", m)
		}
	}
	if !foundWant {
		t.Fatalf("expected %v in DeriveNonMutatingMethods, got %v", want, methods)
	}

	_, _, runtimeTypes, _, _, _ := DeriveProtoAndStructFacts(true, p, idx, idx.InitOnly, nil)
	roles := map[string]bool{}
	for _, rt := range runtimeTypes {
		if !rt.Valid() {
			t.Fatalf("invalid ProtoRuntimeTypeFact: %+v", rt)
		}
		roles[rt.Type.Name+":"+rt.Role] = true
	}
	if !roles["MessageInfo:message"] {
		t.Fatalf("expected MessageInfo:message role, got %v", runtimeTypes)
	}
	if !roles["EnumInfo:enum"] {
		t.Fatalf("expected EnumInfo:enum role, got %v", runtimeTypes)
	}
}
