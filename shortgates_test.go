package gofresh

import (
	"fmt"
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
// not invoke (a t.Run subtest or f.Fuzz body counts as a body; any
// other closure does not), and never inside a fixture source string,
// where it would change what the full tier analyzes. The pin walks
// every test file in the repository (testdata excluded, so a new
// package cannot escape it) and runs the checker below over them; the
// checker's own arms are pinned by TestShortGateCheckerDetectsEachViolation
// over synthetic sources, since a probe through the build overlay never
// reaches a file this test reads from disk. A literal assembled by
// concatenation would evade the string arm, which guards against the
// mechanical pass, not deliberate evasion.
func TestShortGatesLiveInTestBodiesAndSkip(t *testing.T) {
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || (path != "." && strings.HasPrefix(d.Name(), ".")) {
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
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		files[path] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The walk's scope is itself pinned: it must have reached this file
	// and descended into a subdirectory, so a narrowed walk cannot pass
	// over the gates it silently dropped.
	if _, ok := files["shortgates_test.go"]; !ok {
		t.Fatal("the walk did not reach its own file")
	}
	descended := false
	for path := range files {
		if strings.Contains(path, string(filepath.Separator)) {
			descended = true
		}
	}
	if !descended {
		t.Fatal("the walk did not descend into any subdirectory")
	}
	rep := checkShortGates(fset, files)
	for _, p := range rep.problems {
		t.Error(p)
	}
	if rep.anywhere != rep.inBodies {
		t.Fatalf("%d gates in the repository but %d as statements of Test/Fuzz bodies — a gate sits in a helper or an uninvoked closure", rep.anywhere, rep.inBodies)
	}
	if rep.inBodies == 0 {
		t.Fatal("no gates found; the fast tier partition is gone")
	}
}

// TestShortGateCheckerDetectsEachViolation pins every arm of the checker
// over synthetic sources: the shapes it must admit and each shape it
// must refuse, so a neutered arm fails here rather than passing
// silently over a tree that happens to be clean.
func TestShortGateCheckerDetectsEachViolation(t *testing.T) {
	const gate = "if testing." + "Short() {\n\t\tt.Skip(\"x\")\n\t}\n"
	cases := []struct {
		name     string
		src      string
		mismatch bool
		problem  string
	}{
		{"gate at the head of a test", "func TestA(t *testing.T) {\n\t" + gate + "\t_ = 1\n}\n", false, ""},
		{"gate after cheap controls", "func TestA(t *testing.T) {\n\t_ = 1\n\t" + gate + "}\n", false, ""},
		{"gate in a t.Run subtest body counts", "func TestA(t *testing.T) {\n\tt.Run(\"s\", func(t *testing.T) {\n\t\t" + gate + "\t})\n}\n", false, ""},
		{"gate in a fuzz body counts", "func FuzzA(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, s string) {\n\t\t" + gate + "\t})\n}\n", false, ""},
		{"gate in an uninvoked closure", "func TestA(t *testing.T) {\n\t_ = func() {\n\t\t" + gate + "\t}\n}\n", true, ""},
		{"gate in a helper", "func helper(t *testing.T) {\n\t" + gate + "}\n\nfunc TestA(t *testing.T) { helper(t) }\n", true, ""},
		{"gate text in a raw string literal", "func TestA(t *testing.T) {\n\t_ = `package p\n\nfunc TestX(t *testing.T) {\n\t" + gate + "}\n`\n}\n", false, "string literal"},
		{"gate text in an interpreted string literal", "func TestA(t *testing.T) {\n\t_ = \"func TestX(t *testing.T) {\\n\\tif testing." + "Short() {\\n\\t\\tt.Skip(\\\"x\\\")\\n\\t}\\n}\\n\"\n}\n", false, "string literal"},
		{"gate that does not skip", "func TestA(t *testing.T) {\n\tif testing." + "Short() {\n\t\tt.Log(\"gated\")\n\t}\n}\n", false, "does not skip"},
		{"gate that skips and does more", "func TestA(t *testing.T) {\n\tif testing." + "Short() {\n\t\tt.Log(\"x\")\n\t\tt.Skip(\"x\")\n\t}\n}\n", false, "does not skip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "case_test.go", "package p\n\nimport \"testing\"\n\n"+tc.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			rep := checkShortGates(fset, map[string]*ast.File{"case_test.go": f})
			if got := rep.anywhere != rep.inBodies; got != tc.mismatch {
				t.Errorf("mismatch = %t (anywhere %d, in bodies %d), want %t", got, rep.anywhere, rep.inBodies, tc.mismatch)
			}
			joined := strings.Join(rep.problems, "\n")
			if tc.problem == "" && joined != "" {
				t.Errorf("unexpected problems:\n%s", joined)
			}
			if tc.problem != "" && !strings.Contains(joined, tc.problem) {
				t.Errorf("problems %q do not name %q", joined, tc.problem)
			}
		})
	}
}

type shortGateReport struct {
	// anywhere counts every gate statement in the files; inBodies counts
	// the ones that are statements of a Test/Fuzz body (framework-entered
	// closures included). Equal iff no gate sits in a helper or an
	// uninvoked closure.
	anywhere, inBodies int
	problems           []string
}

// checkShortGates applies the fast-tier gate rules to parsed test files.
func checkShortGates(fset *token.FileSet, files map[string]*ast.File) shortGateReport {
	var rep shortGateReport
	// The gate shape, not the bare call: a fixture may legitimately
	// exercise testing.Short() as analysis input. Composed so this
	// file's own text never matches itself.
	needle := "if testing." + "Short() {"
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if v, err := strconv.Unquote(n.Value); err == nil && strings.Contains(v, needle) {
						rep.problems = append(rep.problems, fmt.Sprintf("%s: a string literal carries the gate text — a gate planted in fixture source", fset.Position(n.Pos())))
					}
				}
			case ast.Stmt:
				if isShortGate(n) {
					rep.anywhere++
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
					return entered[lit]
				}
				if st, ok := n.(ast.Stmt); ok && isShortGate(st) {
					rep.inBodies++
					if !skips(st.(*ast.IfStmt)) {
						rep.problems = append(rep.problems, fmt.Sprintf("%s: a gate that does not skip", fset.Position(st.Pos())))
					}
				}
				return true
			})
		}
	}
	return rep
}

// frameworkEnteredClosures collects the function literals passed as
// arguments of a Run or Fuzz call anywhere under body — the closures the
// testing framework itself invokes.
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

// skips reports whether the gate's body is exactly one Skip/Skipf call.
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
