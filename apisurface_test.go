package gofresh

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every exported analysis entry of the public packages names its
// environment in its signature (REQ-closure-analysis: the analyzed tree
// and build selection are explicit inputs, never implicit coupling): no
// production source of guard, runtimeinput, closure, gotool, the
// internal packages, or the root's directive scanner reads the ambient
// process environment (os.Environ, Getenv, LookupEnv, ExpandEnv, and
// syscall's). The ambient defaults are the root's own — New without
// WithEnv, and an engine-less view's runtime-input check — and live in
// gofresh.go and view.go, outside this walk.
//
//gofresh:pure
func TestPublicPackagesReadNoAmbientEnvironment(t *testing.T) {
	roots := []string{"guard", "runtimeinput", "closure", "gotool", "internal"}
	files := []string{"purity.go"}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "fixtures" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, hit := range ambientReads(t, files) {
		t.Errorf("%s: reads the ambient environment; the entry must take env", hit)
	}
}

// ambientReads names every call of an ambient-environment reader in the
// given Go sources, as file:line:col.
func ambientReads(t *testing.T, files []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var hits []string
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			ambient := (pkg.Name == "os" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" || sel.Sel.Name == "ExpandEnv")) ||
				(pkg.Name == "syscall" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv"))
			if ambient {
				hits = append(hits, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return hits
}

// The walk's logic over synthetic sources: every ambient reader is named,
// a same-named method on another receiver is not, and a clean file yields
// nothing — the real-source walk above is this logic's hand-edit oracle
// (a source-reading pin cannot see an overlay, so the logic is pinned
// where a probe can reach it).
//
//gofresh:pure
func TestAmbientReadsNameEveryAmbientReader(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.go")
	if err := os.WriteFile(dirty, []byte(`package p

import (
	"os"
	"syscall"
)

type env struct{}

func (env) Environ() []string { return nil }

func f() {
	_ = os.Environ()
	_ = os.Getenv("K")
	_, _ = os.LookupEnv("K")
	_ = os.ExpandEnv("$K")
	_ = syscall.Environ()
	_, _ = syscall.Getenv("K")
	_ = env{}.Environ()
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(clean, []byte("package p\n\nfunc g(env []string) []string { return env }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := ambientReads(t, []string{dirty, clean})
	if len(hits) != 6 {
		t.Fatalf("hits = %v; want the six ambient readers and not the method", hits)
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, dirty+":") {
			t.Fatalf("a clean file was named: %s", h)
		}
	}
}
