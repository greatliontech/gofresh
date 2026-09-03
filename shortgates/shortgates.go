// Package shortgates pins a repository's fast-tier partition: every
// `if testing.Short()` gate in its test files is a skipping statement of
// a Test or Fuzz function body — at its head, or after the cheap controls
// it deliberately runs first — never in a helper the full tier could not
// see through, never inside a closure the test may not invoke (a t.Run
// subtest or f.Fuzz body counts as a body; any other closure does not),
// and never inside a fixture source string, where it would change what
// the full tier analyzes. One repository's pin is one call; the checker's
// own arms are pinned here over synthetic sources, since a probe through
// the build overlay never reaches a file the pin reads from disk. A
// literal assembled by concatenation would evade the string arm, which
// guards against the mechanical pass, not deliberate evasion.
package shortgates

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
)

// Failer is the slice of testing.TB a pin needs, so a harness that is
// not the testing package can drive one.
type Failer interface {
	Helper()
	Error(args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Pin fails t unless every test file under root (testdata and
// dot-directories excluded, so a new package cannot escape it) keeps
// the partition: no gate outside a Test/Fuzz body, every gate skipping,
// no gate text inside a string literal, at least one gate, and a walk
// that reached a test file in root itself and descended below it.
func Pin(t Failer, root string) {
	t.Helper()
	rep, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Problems {
		t.Error(p)
	}
	// The walk's scope is itself pinned, so a narrowed walk cannot pass
	// over the gates it silently dropped.
	if !rep.AtRoot {
		t.Fatalf("the walk reached no test file in %s itself", root)
	}
	if !rep.Descended {
		t.Fatal("the walk did not descend into any subdirectory")
	}
	if rep.Anywhere != rep.InBodies {
		t.Fatalf("%d gates in the repository but %d as statements of Test/Fuzz bodies — a gate sits in a helper or an uninvoked closure", rep.Anywhere, rep.InBodies)
	}
	if rep.InBodies == 0 {
		t.Fatal("no gates found; the fast tier partition is gone")
	}
}

// WalkReport is a checker pass over a walked tree with the walk's reach.
type WalkReport struct {
	Report
	// AtRoot and Descended record the walk's reach: a test file in the
	// walked root itself, and one below it.
	AtRoot, Descended bool
}

// Walk parses every test file under root (testdata and dot-directories
// excluded) and checks them, recording whether the walk reached a test
// file in root itself and whether it descended below it.
func Walk(root string) (WalkReport, error) {
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || (path != root && strings.HasPrefix(d.Name(), ".")) {
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
		return WalkReport{}, err
	}
	rep := WalkReport{Report: Check(fset, files)}
	for path := range files {
		if rel, err := filepath.Rel(root, path); err == nil {
			if strings.Contains(rel, string(filepath.Separator)) {
				rep.Descended = true
			} else {
				rep.AtRoot = true
			}
		}
	}
	return rep, nil
}

// Report is one checker pass over parsed test files.
type Report struct {
	// Anywhere counts every gate statement in the files; InBodies counts
	// the ones that are statements of a Test/Fuzz body (framework-entered
	// closures included). Equal iff no gate sits in a helper or an
	// uninvoked closure.
	Anywhere, InBodies int
	Problems           []string
}

// Check applies the fast-tier gate rules to parsed test files.
func Check(fset *token.FileSet, files map[string]*ast.File) Report {
	var rep Report
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
						rep.Problems = append(rep.Problems, fmt.Sprintf("%s: a string literal carries the gate text — a gate planted in fixture source", fset.Position(n.Pos())))
					}
				}
			case ast.Stmt:
				if isShortGate(n) {
					rep.Anywhere++
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
					rep.InBodies++
					if !skips(st.(*ast.IfStmt)) {
						rep.Problems = append(rep.Problems, fmt.Sprintf("%s: a gate that does not skip", fset.Position(st.Pos())))
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
