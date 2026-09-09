package closure

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A retained comment's attachment in the canonical form is the
// parser's doc rule: for every retained comment of any class — line or
// block directive, export, build constraint, generated marker —
// immediately preceding a declaration, the form's lead-group bit equals whether go/parser
// attaches that comment as the declaration's doc — under a blank line,
// a block comment, and a `//line` directive between the comment and the
// declaration, whose adjusted positions the form never reads
// (REQ-closure-canonical-member).
func TestRetainedCommentAttachmentFollowsTheParser(t *testing.T) {
	sources := map[string]string{
		"adjacent":              "package p\n\n//go:noinline\nfunc F(a int) int { return a }\n",
		"blank line":            "package p\n\n//go:noinline\n\nfunc F(a int) int { return a }\n",
		"line directive after":  "package p\n\n//go:noinline\n//line other.go:10\nfunc F(a int) int { return a }\n",
		"line directive before": "package p\n\n//line other.go:10\n//go:noinline\nfunc F(a int) int { return a }\n",
		"line directive far":    "package p\n\n//go:noinline\n//line other.go:100\nfunc F(a int) int { return a }\n",
		"block between":         "package p\n\n//go:noinline\n/* x */ func F(a int) int { return a }\n",
		"same-line group":       "package p\n\n//go:noinline\n/* a */ /* x\ny */\nfunc F(a int) int { return a }\n",
		"same-line group blank": "package p\n\n//go:noinline\n/* a */ /* x\ny */\n\nfunc F(a int) int { return a }\n",
		"twice":                 "package p\n\n//go:noinline\nfunc F(a int) int { return a }\n\n//go:noinline\n\nfunc G(a int) int { return a }\n",
		"on a var":              "package p\n\n//go:embed x\nvar X string\n\n//go:embed y\n\nvar Y string\n",
		"block directive":       "package p\n\n/*go:noinline*/\nfunc F(a int) int { return a }\n\n/*go:noinline*/\n\nfunc G(a int) int { return a }\n",
		"export and build":      "//go:build linux\n\npackage p\n\n//export F\nfunc F(a int) int { return a }\n",
	}
	for name, src := range sources {
		items, ok := scanCanonical([]byte(src))
		if !ok {
			t.Fatalf("%s: the scanner refused", name)
		}
		lead := leadGroups(items)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// A doc comment is identified by its unadjusted line and text,
		// so two identical directives never collapse; every doc-bearing
		// node counts, not functions alone.
		doc := map[string]bool{}
		note := func(g *ast.CommentGroup) {
			if g == nil {
				return
			}
			for _, c := range g.List {
				doc[fmt.Sprintf("%d:%s", fset.PositionFor(c.Pos(), false).Line, c.Text)] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.FuncDecl:
				note(d.Doc)
			case *ast.GenDecl:
				note(d.Doc)
			case *ast.TypeSpec:
				note(d.Doc)
			case *ast.ValueSpec:
				note(d.Doc)
			case *ast.ImportSpec:
				note(d.Doc)
			case *ast.Field:
				note(d.Doc)
			}
			return true
		})
		for i, it := range items {
			if it.tok != token.COMMENT || !retainedComment(it.lit) {
				continue
			}
			key := fmt.Sprintf("%d:%s", it.line, it.lit)
			if lead[i] != doc[key] {
				t.Errorf("%s: %q at line %d lead=%v, parser doc=%v", name, it.lit, it.line, lead[i], doc[key])
			}
		}
	}
}
