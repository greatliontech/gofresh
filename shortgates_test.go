package gofresh

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The fast tier's gates are inert under a plain `go test`: every
// `if testing.Short()` in the module's test files is a statement of a
// Test or Fuzz function body — at its head, or after the cheap controls
// it deliberately runs first — whose body skips; never in a helper the
// full tier could not see through, never inside a closure the test may
// not invoke, and never inside a fixture source string, where it would
// change what the full tier analyzes. The pin walks every test file in
// the module (testdata excluded, so a new package cannot escape it),
// counts every gate statement anywhere against the gates found as
// direct statements of Test/Fuzz bodies (a t.Run subtest or f.Fuzz
// body counts as a body; any other closure does not), requires each
// such gate to skip, and refuses any string literal carrying the gate
// text — a literal assembled by concatenation would evade that last
// arm, which guards against the mechanical pass, not deliberate
// evasion.
func TestShortGatesLiveInTestBodiesAndSkip(t *testing.T) {
	var anywhere, inBodies int
	// The gate shape, not the bare call: a fixture may legitimately
	// exercise testing.Short() as analysis input. Composed so this
	// file's own diagnostics never match themselves.
	needle := "if testing." + "Short() {"
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == ".git" || (path != "." && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if v, err := strconv.Unquote(n.Value); err == nil && strings.Contains(v, needle) {
						t.Errorf("%s: a string literal carries %s — a gate planted in fixture source", fset.Position(n.Pos()), needle)
					}
				}
			case ast.Stmt:
				if isShortGate(n) {
					anywhere++
				}
			}
			return true
		})
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			if !strings.HasPrefix(fd.Name.Name, "Test") && !strings.HasPrefix(fd.Name.Name, "Fuzz") {
				continue
			}
			entered := frameworkEnteredClosures(fd.Body)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if lit, closure := n.(*ast.FuncLit); closure {
					// A subtest or fuzz body the framework enters is a
					// test body; any other closure may never run.
					return entered[lit]
				}
				if st, ok := n.(ast.Stmt); ok && isShortGate(st) {
					inBodies++
					if !skips(st.(*ast.IfStmt)) {
						t.Errorf("%s: a gate that does not skip", fset.Position(st.Pos()))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if anywhere != inBodies {
		t.Fatalf("%d gates in the module but %d as direct statements of Test/Fuzz bodies — a gate sits in a helper or a closure", anywhere, inBodies)
	}
	if inBodies == 0 {
		t.Fatal("no gates found; the fast tier partition is gone")
	}
}

// frameworkEnteredClosures collects the function literals passed as the
// body argument of a Run or Fuzz call anywhere under body — the
// closures the testing framework itself invokes.
func frameworkEnteredClosures(body *ast.BlockStmt) map[*ast.FuncLit]bool {
	entered := map[*ast.FuncLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Run" && sel.Sel.Name != "Fuzz") {
			return true
		}
		for _, a := range call.Args {
			if lit, ok := a.(*ast.FuncLit); ok {
				entered[lit] = true
			}
		}
		return true
	})
	return entered
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

// skips reports whether the gate's body is exactly one Skip/Skipf call
// on the test handle.
func skips(ifs *ast.IfStmt) bool {
	if len(ifs.Body.List) != 1 {
		return false
	}
	es, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf")
}
