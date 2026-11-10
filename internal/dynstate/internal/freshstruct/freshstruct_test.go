package freshstruct

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func typecheckTestPkg(t *testing.T, pkgPath, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	cfg := &types.Config{Importer: importer.Default()}
	pkg, err := cfg.Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	return &packages.Package{
		PkgPath:   pkgPath,
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     pkg,
		TypesInfo: info,
	}
}

func TestCollectFreshLocalStructVarsAndMutatedTypes(t *testing.T) {
	p := typecheckTestPkg(t, "example.com/p", `package p

type FreshBuilt struct {
	Count int
	Items []int
}

type MutatedAfterReturn struct {
	Count int
}

func NewFresh(n int) *FreshBuilt {
	f := &FreshBuilt{}
	fillFresh(f, n)
	return f
}

func fillFresh(f *FreshBuilt, n int) {
	f.Count = n
	f.Items = make([]int, n)
}

func MutateExisting(m *MutatedAfterReturn) {
	m.Count++
}
`)
	idx := refconfine.BuildPkgIndex(p)
	cache := NewFreshLocalsCache(p, idx)
	mutated, conds := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
	if len(conds) != 0 {
		t.Fatalf("unexpected conds: %+v", conds)
	}
	want := []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: "MutatedAfterReturn"}}
	if !slices.Equal(mutated, want) {
		t.Fatalf("MutatedStructTypes = %+v, want %+v", mutated, want)
	}
}

func TestFindMutexConfinedConstructorCaches(t *testing.T) {
	p := typecheckTestPkg(t, "example.com/p", `package p

import (
	"reflect"
	"sync"
)

type Desc struct {
	Name string
}

var (
	cacheMu sync.Mutex
	cache   map[reflect.Type]*Desc
)

func GetDesc(rt reflect.Type) *Desc {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cache == nil {
		cache = make(map[reflect.Type]*Desc)
	}
	if d, ok := cache[rt]; ok {
		return d
	}
	d := &Desc{Name: rt.Name()}
	cache[rt] = d
	return d
}
`)
	idx := refconfine.BuildPkgIndex(p)
	confined := FindMutexConfinedConstructorCaches(p, idx)
	if len(confined) != 1 {
		t.Fatalf("len(confined) = %d, want 1", len(confined))
	}
	cache := NewFreshLocalsCache(p, idx)
	mutated, _ := CollectMutatedStructTypes(p, idx, cache, confined, nil, nil, nil)
	if len(mutated) != 0 {
		t.Fatalf("expected 0 mutated struct types for mutex-confined constructor cache, got %+v", mutated)
	}
}
