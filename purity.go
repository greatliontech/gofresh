package gofresh

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ScanPureDirectives loads pkgPaths and returns a purity predicate marking every
// symbol whose declaration carries a //gofresh:pure directive (REQ-purity-directive).
// It is the durable, in-code form of a purity assertion — written once and honored
// by every consumer of the engine — and composes with a whole-run assertion by ORing
// predicates before passing one to WithAssumePure. gofresh reads the directive; it
// never infers purity from behavior (REQ-purity-responsibility).
//
// A symbol is named as the closure engine resolves it: a function by its name, a
// method as "Type.Method" with the receiver's pointer star and generics dropped.
func ScanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesIn("", pkgPaths...)
}

// ScanPureDirectivesIn scans under an explicit tree root ("" = the process
// working directory), for callers fingerprinting a tree they do not run
// inside.
func ScanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedForTest,
		Tests: true,
		Dir:   dir,
	}
	pkgs, err := packages.Load(cfg, pkgPaths...)
	if err != nil {
		return nil, err
	}
	pure := map[Subject]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		// A subject's package is the import path the engine resolves it under. A
		// test variant (in-package or external "pkg_test") declares subjects of the
		// package under test, so key by ForTest there — keying by the variant's own
		// PkgPath would silently drop a directive on an external-test-file subject
		// (REQ-purity-directive).
		pkgPath := p.PkgPath
		if p.ForTest != "" {
			pkgPath = p.ForTest
		}
		for _, f := range p.Syntax {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || !hasPureDirective(fd.Doc) {
					continue
				}
				sym := fd.Name.Name
				if recv := recvTypeName(fd); recv != "" {
					sym = recv + "." + sym
				}
				pure[Subject{Package: pkgPath, Symbol: sym}] = true
			}
		}
	})
	return func(s Subject) bool { return pure[s] }, nil
}

// hasPureDirective reports whether a doc comment group carries the //gofresh:pure
// directive — a comment line whose text (after the slashes) is exactly gofresh:pure,
// the Go directive form with no leading space.
func hasPureDirective(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if strings.TrimSpace(strings.TrimPrefix(c.Text, "//")) == "gofresh:pure" {
			return true
		}
	}
	return false
}

// recvTypeName is a method's receiver type name with the leading pointer star and
// any generic parameters stripped — "" for a plain function or an unnameable
// receiver. It matches stipulator's Go backend, so a method is named identically
// going into a bind and resolving here.
func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok { // Recv[T]
		t = idx.X
	}
	if idx, ok := t.(*ast.IndexListExpr); ok { // Recv[T, U]
		t = idx.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}
