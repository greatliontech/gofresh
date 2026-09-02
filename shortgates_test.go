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

// The fast tier's gates are inert under a plain `go test`: every
// `if testing.Short()` in the root and closure test files is the first
// statement of a Test or Fuzz function and nothing else — never inside
// a fixture source string, where it would change what the full tier
// analyzes. The pin compares the source-line count of gate lines with
// the count of gates found at the head of a Test/Fuzz body; a gate
// planted anywhere else raises the first count without the second.
func TestShortGatesAreFirstStatementsOfTestFunctions(t *testing.T) {
	var lines, gates int
	for _, dir := range []string{".", "closure"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range strings.Split(string(src), "\n") {
				if strings.TrimSpace(l) == "if testing.Short() {" {
					lines++
				}
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Body == nil || len(fd.Body.List) == 0 {
					continue
				}
				if !strings.HasPrefix(fd.Name.Name, "Test") && !strings.HasPrefix(fd.Name.Name, "Fuzz") {
					continue
				}
				if isShortGate(fd.Body.List[0]) {
					gates++
				}
			}
		}
	}
	if lines != gates {
		t.Fatalf("%d `if testing.Short()` lines but %d gates at the head of Test/Fuzz bodies — a gate sits somewhere else (a fixture string, a helper, a later statement)", lines, gates)
	}
	if gates == 0 {
		t.Fatal("no gates found; the fast tier partition is gone")
	}
}

func isShortGate(s ast.Stmt) bool {
	ifs, ok := s.(*ast.IfStmt)
	if !ok || ifs.Init != nil {
		return false
	}
	call, ok := ifs.Cond.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Short" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing"
}
