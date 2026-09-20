package gofresh

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// An installed runner reaches every go command the engine spawns
// itself: an observation over a module pays its snapshot, its toolchain
// probe, and its listings through the runner's hook — and none outside
// it, which the source walk below pins for the sites.
func TestEngineSpawnsThroughTheInstalledRunner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package m\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m_test.go"), []byte("package m\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { if F() != 1 { t.Fatal() } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var args [][]string
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		mu.Lock()
		defer mu.Unlock()
		args = append(args, append([]string(nil), cmd.Args...))
	}}
	e, err := New(WithDir(dir), WithGoRunner(runner))
	if err != nil {
		t.Fatal(err)
	}
	// Construction validates the flags through the runner too; the pass
	// is judged on its own spawns.
	mu.Lock()
	args = nil
	mu.Unlock()
	if _, err := e.Capture(context.Background(), Subject{Package: "example.com/m", Symbol: "TestF"}, dir); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	snapshots := 0
	for _, a := range args {
		seen[strings.Join(a[1:], " ")] = true
		if len(a) > 1 && a[1] == "list" {
			seen["list"] = true
		}
		if strings.Join(a[1:], " ") == "env -json" {
			snapshots++
		}
	}
	for _, want := range []string{"env -json", "version", "list"} {
		if !seen[want] {
			t.Errorf("the runner never saw `go %s` on the pass; spawns seen: %v", want, args)
		}
	}
	// One snapshot serves each pass: the closure's construction, the
	// guard's digest, and the flag validation read the construction
	// pass's, and the bracket's closing pass takes exactly one fresh
	// snapshot of its own whose guard comparison refuses drift
	// (REQ-guard-buildconfig) — two per capture, never a third.
	if snapshots != 2 {
		t.Fatalf("%d `go env -json` spawns on one capture, want 2 (the construction pass and the closing pass): %v", snapshots, args)
	}
}

// Every go command the engine's packages spawn goes through a Runner
// value: the free-function spawns (gotool.Run, TakeEnvSnapshot,
// SampleGoVersion — the (ctx, dir, env) forms a runner value also
// offers) and an inline plain runner's call appear in no non-test
// source outside gotool itself, so a site cannot bypass the runner it
// was handed by spelling the plain one. A plain Runner value built at
// a site and handed on (the directive scan's) is that site's stated
// choice, outside the walk. The walk reads sources from disk (a
// hand-edit oracle); its logic is pinned over synthetic sources below.
func TestEngineSpawnSitesReadARunner(t *testing.T) {
	free := freeSpawnFunctions(t)
	if want := []string{"Run", "SampleGoVersion", "TakeEnvSnapshot"}; strings.Join(free, ",") != strings.Join(want, ",") {
		t.Fatalf("gotool's free spawn functions = %v, want %v (a fourth one joins the walk here)", free, want)
	}
	bare, err := bareSpawnSites(".", free)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != 0 {
		t.Fatalf("free-function spawns outside gotool: %v", bare)
	}
}

// The walk's logic over synthetic sources: the free spawn functions
// are read whatever local name the import takes, an inline plain
// runner's spawn is read, a runner value's own call is not, and a test
// file, a fixture directory, and gotool itself are skipped.
//
//gofresh:pure
func TestBareSpawnWalkReadsTheThreeFreeFunctions(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package a\n\nimport gt \"github.com/greatliontech/gofresh/gotool\"\n\nfunc f(r gt.Runner) {\n\tgt.Run(ctx, d, e)\n\tgt.TakeEnvSnapshot(ctx, d, e)\n\tgt.SampleGoVersion(ctx, d, e)\n\tgt.Runner{}.Run(ctx, d, e)\n\tr.Run(ctx, d, e)\n\tgt.NewEnvReader(r, d, e)\n\tother.Run(ctx)\n}\n")
	write("b.go", "package a\n\nimport \"github.com/greatliontech/gofresh/gotool\"\n\nfunc g() { gotool.Run(ctx, d, e) }\n")
	write("a_test.go", "package a\n\nimport \"github.com/greatliontech/gofresh/gotool\"\n\nfunc h() { gotool.Run(ctx, d, e) }\n")
	write("fixtures/c.go", "package c\n\nimport \"github.com/greatliontech/gofresh/gotool\"\n\nfunc h() { gotool.Run(ctx, d, e) }\n")
	write("gotool/g.go", "package gotool\n\nfunc h() { Run(ctx, d, e) }\n")
	write("d.go", "package a\n\nimport . \"github.com/greatliontech/gofresh/gotool\"\n\nfunc k() { Run(ctx, d, e); other(ctx) }\n")
	got, err := bareSpawnSites(dir, []string{"Run", "TakeEnvSnapshot", "SampleGoVersion"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.go:6 gt.Run", "a.go:7 gt.TakeEnvSnapshot", "a.go:8 gt.SampleGoVersion", "a.go:9 gt.Runner{}.Run", "b.go:5 gotool.Run", "d.go:5 .Run"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("bare sites = %v, want %v", got, want)
	}
}

// freeSpawnFunctions derives the names of gotool's free spawn
// functions from its source: the package-level functions taking
// (ctx, dir, env) — the forms a runner value also offers — so a fourth
// one is read by the walk the day it exists.
func freeSpawnFunctions(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, "gotool", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Params == nil || len(fn.Type.Params.List) < 3 {
					continue
				}
				params := fn.Type.Params.List
				ctxT, ok1 := params[0].Type.(*ast.SelectorExpr)
				dirT, ok2 := params[1].Type.(*ast.Ident)
				envT, ok3 := params[2].Type.(*ast.ArrayType)
				if ok1 && ok2 && ok3 && ctxT.Sel.Name == "Context" && dirT.Name == "string" {
					if elt, ok := envT.Elt.(*ast.Ident); ok && elt.Name == "string" {
						names = append(names, fn.Name.Name)
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// bareSpawnSites walks the non-test Go sources under root, outside the
// gotool package, for calls of gotool's free spawn functions — through
// whatever local name a file imports the package under — and for an
// inline plain runner's spawn (gotool.Runner{}.Run), which is the same
// bypass spelled differently.
func bareSpawnSites(root string, free []string) ([]string, error) {
	var sites []string
	fset := token.NewFileSet()
	const gotoolPath = "github.com/greatliontech/gofresh/gotool"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "fixtures" || rel == "gotool") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		local := ""
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, "\"") != gotoolPath {
				continue
			}
			local = "gotool"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		if local == "" {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			line := fset.Position(call.Pos()).Line
			if local == "." {
				// A dot import: the free function is a bare identifier.
				if id, ok := call.Fun.(*ast.Ident); ok && slices.Contains(free, id.Name) {
					sites = append(sites, rel+":"+strconv.Itoa(line)+" ."+id.Name)
				}
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch x := sel.X.(type) {
			case *ast.Ident:
				if x.Name == local && slices.Contains(free, sel.Sel.Name) {
					sites = append(sites, rel+":"+strconv.Itoa(line)+" "+local+"."+sel.Sel.Name)
				}
			case *ast.CompositeLit:
				if typ, ok := x.Type.(*ast.SelectorExpr); ok {
					if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == local && typ.Sel.Name == "Runner" && len(x.Elts) == 0 {
						sites = append(sites, rel+":"+strconv.Itoa(line)+" "+local+".Runner{}."+sel.Sel.Name)
					}
				}
			}
			return true
		})
		return nil
	})
	return sites, err
}
