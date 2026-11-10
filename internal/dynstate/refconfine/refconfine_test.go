package refconfine

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
)

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func mustTypecheckPkg(t *testing.T, pkgPath string, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Instances:  make(map[*ast.Ident]types.Instance),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	tp, err := (&types.Config{
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == "unsafe" {
				return types.Unsafe, nil
			}
			return nil, fmt.Errorf("unexpected import %q", path)
		}),
	}).Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	return &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      tp.Name(),
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     tp,
		TypesInfo: info,
		Module:    &packages.Module{Path: "example.com/mod"},
	}
}

func TestVerifyReadOnlyRefConfinementUnsafeConstantBuiltins(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/unsafeconfine", `package unsafeconfine

import "unsafe"

type holder struct {
	items []int
	tag   int
}

var seed = holder{items: []int{1, 2, 3}, tag: 7}

const (
	seedSize  = unsafe.Sizeof(seed)
	seedAlign = unsafe.Alignof(seed)
	itemsOff  = unsafe.Offsetof(seed.items)
)

func Inspect() uintptr {
	h := &seed
	return unsafe.Sizeof(*h) + unsafe.Alignof(*h) + unsafe.Offsetof(h.items) + uintptr(len(h.items))
}
`)
	idx := BuildPkgIndex(pkg)
	seedObj, ok := pkg.Types.Scope().Lookup("seed").(*types.Var)
	if !ok || seedObj == nil {
		t.Fatal("missing seed var")
	}
	holderType, ok := pkg.Types.Scope().Lookup("holder").(*types.TypeName)
	if !ok || holderType == nil {
		t.Fatal("missing holder type")
	}
	holderNamed, ok := holderType.Type().(*types.Named)
	if !ok || holderNamed == nil {
		t.Fatal("holder is not a *types.Named")
	}
	cfg := Config{
		Index: idx,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && pkg.TypesInfo.Uses[id] == seedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == holderNamed.Origin()
		},
	}
	if !VerifyReadOnlyRefConfinement(pkg, cfg) {
		t.Fatal("VerifyReadOnlyRefConfinement rejected compile-time constant unsafe.{Sizeof,Alignof,Offsetof} on seed struct")
	}
	// Verify repeated query reusing idx produces identical result.
	if !VerifyReadOnlyRefConfinement(pkg, cfg) {
		t.Fatal("VerifyReadOnlyRefConfinement failed on second query with shared PkgIndex")
	}

	badPkg := mustTypecheckPkg(t, "example.com/unsafeconfinebad", `package unsafeconfinebad

import "unsafe"

type holder struct {
	items []int
}

var seed = holder{items: []int{1, 2, 3}}

func Leak() *int {
	return unsafe.SliceData(seed.items)
}
`)
	badSeedObj := badPkg.Types.Scope().Lookup("seed").(*types.Var)
	badHolderNamed := badPkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
	if VerifyReadOnlyRefConfinement(badPkg, Config{
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && badPkg.TypesInfo.Uses[id] == badSeedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == badHolderNamed.Origin()
		},
	}) {
		t.Fatal("VerifyReadOnlyRefConfinement unexpectedly accepted unsafe.SliceData on seed slice")
	}
}

func TestVerifyProtectedStructOriginConfinement(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/memo", `package memo

type entry struct {
	names []string
	count int
}

func buildEntry() *entry {
	e := &entry{names: []string{"a", "b"}}
	e.count = len(e.names)
	return e
}

func ReadFirst() string {
	e := buildEntry()
	if e == nil || len(e.names) == 0 {
		return ""
	}
	return e.names[0]
}
`)
	idx := BuildPkgIndex(pkg)
	entryNamed := pkg.Types.Scope().Lookup("entry").(*types.TypeName).Type().(*types.Named)
	buildFD := idx.PlainByName["buildEntry"][0]
	ok, reason := VerifyProtectedStructOriginConfinement(pkg, idx, buildFD, map[*types.Named]bool{entryNamed: true}, nil)
	if !ok {
		t.Fatalf("VerifyProtectedStructOriginConfinement(clean) = false (%s), want true", reason)
	}

	mutPkg := mustTypecheckPkg(t, "example.com/memomut", `package memomut

type entry struct {
	names []string
}

func buildEntry() *entry {
	return &entry{names: []string{"a"}}
}

func Mutate() {
	e := buildEntry()
	e.names[0] = "b"
}
`)
	mutIdx := BuildPkgIndex(mutPkg)
	mutEntryNamed := mutPkg.Types.Scope().Lookup("entry").(*types.TypeName).Type().(*types.Named)
	mutBuildFD := mutIdx.PlainByName["buildEntry"][0]
	if ok, _ := VerifyProtectedStructOriginConfinement(mutPkg, mutIdx, mutBuildFD, map[*types.Named]bool{mutEntryNamed: true}, nil); ok {
		t.Fatal("VerifyProtectedStructOriginConfinement unexpectedly accepted slice element write outside buildEntry")
	}
}
