package seams

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

func parseSeamTestPkg(t *testing.T, filename, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Implicits:  make(map[ast.Node]types.Object),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("example.com/p", fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return &packages.Package{
		PkgPath:   "example.com/p",
		Name:      pkg.Name(),
		Fset:      fset,
		Syntax:    []*ast.File{f},
		Types:     pkg,
		TypesInfo: info,
	}
}

func TestAnalyzeBracketedSeamsAndCallGraph(t *testing.T) {
	p := parseSeamTestPkg(t, "seam_test.go", `package p
import "testing"

var hook func() int = func() int { return 1 }

func WithHook(fn func() int, body func()) {
	orig := hook
	defer func() { hook = orig }()
	hook = fn
	body()
}

func TestSequentialCleanup(t *testing.T) {
	orig := hook
	t.Cleanup(func() { hook = orig })
	hook = func() int { return 2 }
}

func ParallelHelper(t *testing.T) {
	t.Parallel()
}
`)
	idx := refconfine.BuildPkgIndex(p)
	res := AnalyzeBracketedSeams(true, p, idx, nil)
	if len(res.Exempt) != 4 {
		t.Fatalf("expected 4 exempted LHS assignment nodes (2 in WithHook, 2 in TestSequentialCleanup), got %d", len(res.Exempt))
	}
	wantSeam := syntaxutil.ExportedSeam{
		Func: syntaxutil.FuncKey{Pkg: "example.com/p", Name: "WithHook"},
		Key:  "example.com/p.hook",
	}
	foundWithHook := false
	for _, s := range res.ExportedSeams {
		if s == wantSeam {
			foundWithHook = true
		}
	}
	if !foundWithHook {
		t.Fatalf("expected ExportedSeams to contain %+v, got %+v", wantSeam, res.ExportedSeams)
	}
	wantPar := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "ParallelHelper"}
	foundPar := false
	for _, fk := range res.ParallelFuncs {
		if fk == wantPar {
			foundPar = true
		}
	}
	if !foundPar {
		t.Fatalf("expected ParallelFuncs to contain %+v, got %+v", wantPar, res.ParallelFuncs)
	}
}
