package seams

import (
	"fmt"
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
	"pgregory.net/rapid"
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
	res := AnalyzeBracketedSeams(true, p, idx)
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
	if len(res.ExportedSeamSites) != 2 {
		t.Fatalf("expected 2 ExportedSeamSites (WithHook + TestSequentialCleanup), got %+v", res.ExportedSeamSites)
	}
	wantTestSeamFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "TestSequentialCleanup"}
	seenSiteFns := map[syntaxutil.FuncKey]bool{}
	for _, site := range res.ExportedSeamSites {
		if site.Key != wantSeam.Key || site.Pos == token.NoPos {
			t.Fatalf("unexpected ExportedSeamSite %+v, want Key=%q non-zero Pos", site, wantSeam.Key)
		}
		seenSiteFns[site.Func] = true
	}
	if !seenSiteFns[wantSeam.Func] || !seenSiteFns[wantTestSeamFn] {
		t.Fatalf("expected ExportedSeamSites for both %+v and %+v, got %+v", wantSeam.Func, wantTestSeamFn, res.ExportedSeamSites)
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

func TestForeignUnexportedMethodsSkippedAndParallelHubCompaction(t *testing.T) {
	fset := token.NewFileSet()
	depFile, err := parser.ParseFile(fset, "dep.go", `package dep
type Box struct{}
func (Box) ExportedA() {}
func (Box) ExportedB() {}
func (Box) ExportedC() {}
func (Box) ExportedD() {}
func (Box) unexportedDead() {}
`, 0)
	if err != nil {
		t.Fatalf("ParseFile dep: %v", err)
	}
	depInfo := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Implicits:  make(map[ast.Node]types.Object),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	depPkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/dep", fset, []*ast.File{depFile}, depInfo)
	if err != nil {
		t.Fatalf("Check dep: %v", err)
	}

	hostFile, err := parser.ParseFile(fset, "host.go", `package host
import "example.com/dep"

func hubAlpha(b dep.Box) {
	b.ExportedA()
	b.ExportedB()
	b.ExportedC()
}

func hubBeta(b dep.Box) {
	b.ExportedB()
	b.ExportedC()
	b.ExportedD()
}

func Caller1(b dep.Box) { hubAlpha(b) }
func Caller2(b dep.Box) { hubAlpha(b); hubBeta(b) }
func Caller3(b dep.Box) { hubAlpha(b); hubBeta(b) }
func Caller4(b dep.Box) { hubBeta(b) }
`, 0)
	if err != nil {
		t.Fatalf("ParseFile host: %v", err)
	}
	hostInfo := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Implicits:  make(map[ast.Node]types.Object),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	hostConf := types.Config{
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == "example.com/dep" {
				return depPkg, nil
			}
			return importer.Default().Import(path)
		}),
	}
	hostTypes, err := hostConf.Check("example.com/host", fset, []*ast.File{hostFile}, hostInfo)
	if err != nil {
		t.Fatalf("Check host: %v", err)
	}
	hostPkg := &packages.Package{
		PkgPath:   "example.com/host",
		Name:      hostTypes.Name(),
		Fset:      fset,
		Syntax:    []*ast.File{hostFile},
		Types:     hostTypes,
		TypesInfo: hostInfo,
	}
	idx := refconfine.BuildPkgIndex(hostPkg)
	res := AnalyzeBracketedSeams(true, hostPkg, idx)

	sawHub0 := false
	sawHub1 := false
	for _, edge := range res.ParallelEdges {
		if edge.Callee.Pkg == "example.com/dep" && edge.Callee.Name == "Box.unexportedDead" {
			t.Fatalf("foreign unexported method leaked into ParallelEdges: %+v", edge)
		}
		if edge.Callee.Pkg == "example.com/host" && edge.Callee.Name == "#par#0" {
			sawHub0 = true
		}
		if edge.Callee.Pkg == "example.com/host" && edge.Callee.Name == "#par#1" {
			sawHub1 = true
		}
	}
	if !sawHub0 || !sawHub1 {
		t.Fatalf("expected shared internal hubs to be retained as #par#0 and #par#1 in ParallelEdges, got %+v", res.ParallelEdges)
	}
	for iter := 0; iter < 25; iter++ {
		again := AnalyzeBracketedSeams(true, hostPkg, idx)
		if !slices.Equal(again.ParallelEdges, res.ParallelEdges) {
			t.Fatalf("iter %d: non-deterministic ParallelEdges:\ngot:  %+v\nwant: %+v", iter, again.ParallelEdges, res.ParallelEdges)
		}
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func TestRapidCompareRootBitsetsMatchesSliceCompare(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		nRoots := rapid.IntRange(1, 200).Draw(rt, "n_roots")
		roots := make([]syntaxutil.FuncKey, nRoots)
		for i := range roots {
			roots[i] = syntaxutil.FuncKey{Pkg: "example.com/p", Name: fmt.Sprintf("F%03d", i)}
		}
		words := (nRoots + 63) / 64
		drawSet := func(label string) ([]uint64, []syntaxutil.FuncKey) {
			bits := make([]uint64, words)
			var list []syntaxutil.FuncKey
			for i := range nRoots {
				if rapid.Bool().Draw(rt, fmt.Sprintf("%s_%d", label, i)) {
					bits[i/64] |= uint64(1) << (uint(i) % 64)
					list = append(list, roots[i])
				}
			}
			return bits, list
		}
		aBits, aList := drawSet("a")
		bBits, bList := drawSet("b")
		got := compareRootBitsets(aBits, bBits)
		want := slices.CompareFunc(aList, bList, syntaxutil.FuncKey.Compare)
		if got != want {
			rt.Fatalf("compareRootBitsets(%x, %x) = %d, slices.CompareFunc = %d (aLen=%d bLen=%d)", aBits, bBits, got, want, len(aList), len(bList))
		}
		if popcountWords(aBits) != len(aList) {
			rt.Fatalf("popcountWords = %d, want %d", popcountWords(aBits), len(aList))
		}
	})
}
