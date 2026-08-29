package gofresh

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The receiver-naming grammar reduces every legal receiver form,
// the parenthesized ones included — a method is never minted as a
// plain-function subject because its receiver wore parentheses.
// The convention shared across the tools is AST-side DECLARATION
// naming: the declarer's name, all three reducers unwrapping the
// same grammar. Subject and binding naming are wider — this
// package's types-side walk and stipulator's lookup both admit
// promoted methods, in agreement.
func TestRecvTypeNameReducesEveryReceiverForm(t *testing.T) {
	cases := []struct {
		recv string
		want string
	}{
		{"T", "T"},
		{"*T", "T"},
		{"(T)", "T"},
		{"(*T)", "T"},
		{"((*T))", "T"},
		{"(((T)))", "T"},
		{"(P[X])", "P"},
		{"((*P[X, Y]))", "P"},
		{"pkg.T", ""}, // a selector receiver is a type error the grammar refuses
		{"[]T", ""},   // as is any non-name form
	}
	for _, tc := range cases {
		src := "package p\ntype T struct{}\nfunc (r " + tc.recv + ") M() {}\n"
		f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", tc.recv, err)
		}
		var fd *ast.FuncDecl
		for _, d := range f.Decls {
			if x, ok := d.(*ast.FuncDecl); ok && x.Recv != nil {
				fd = x
			}
		}
		if got := recvTypeName(fd); got != tc.want {
			t.Errorf("recvTypeName(recv %s) = %q, want %q", tc.recv, got, tc.want)
		}
	}
	// The entry guard's second operand is reachable only from a
	// hand-constructed AST — the parser never yields a receiver-bearing
	// declaration with an empty field list — so construct it directly:
	// the pinned outcome is the guard's "" refusal, not an index panic.
	if got := recvTypeName(&ast.FuncDecl{Name: ast.NewIdent("M"), Recv: &ast.FieldList{}}); got != "" {
		t.Errorf(`recvTypeName(empty receiver list) = %q, want ""`, got)
	}
}

// The mint site honors the grammar's refusal: a receiver-bearing
// declaration whose receiver the grammar cannot name (a type error
// the parser tolerates) yields NO subject — never a plain-function
// phantom under the bare method name. The reducer returning "" is
// necessary but not sufficient for that; this pins the skip itself.
func TestUnnameableReceiverNeverMintsPlainFunctionSubject(t *testing.T) {
	scanFor := func(t *testing.T, src string) *subjectScan {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "q.go", src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		// The loader's error-package shape: Types allocated before
		// type-checking, info empty — so BOTH minting walks run (the
		// AST walk and the package-scope method-set walk).
		pkg := &packages.Package{
			ID:        "example.com/q",
			PkgPath:   "example.com/q",
			Fset:      fset,
			Syntax:    []*ast.File{f},
			Types:     types.NewPackage("example.com/q", "q"),
			TypesInfo: &types.Info{},
		}
		scan, err := scanSubjectsFromLoaded(true, []*packages.Package{pkg}, &viewDynamicState{}, "example.com/q")
		if err != nil {
			t.Fatal(err)
		}
		return scan
	}
	subject := Subject{Package: "example.com/q", Symbol: "Foo"}
	t.Run("no phantom without a real twin", func(t *testing.T) {
		scan := scanFor(t, "package q\n\n//gofresh:pure\nfunc (r pkg.T) Foo() {}\n")
		// No subject AT ALL — not merely none named Foo: a mint under
		// any residual name (the bare method's, "") is the same
		// phantom class.
		if len(scan.known) != 0 {
			t.Errorf("the skipped declaration minted subjects: %v", scan.known)
		}
		if scan.pure[subject] {
			t.Error("the skipped declaration's //gofresh:pure marked a phantom subject")
		}
	})
	t.Run("a real twin stays clean", func(t *testing.T) {
		scan := scanFor(t, "package q\n\n//gofresh:pure\nfunc (r pkg.T) Foo() {}\n\nfunc Foo() {}\n")
		if !scan.known[subject] {
			t.Fatal("the plain function Foo was not recorded")
		}
		if len(scan.known) != 1 {
			t.Errorf("the skipped declaration minted a subject beside the plain Foo: %v", scan.known)
		}
		if len(scan.ambiguous) != 0 {
			t.Errorf("the skipped method collided with its plain twin: %v", scan.ambiguous)
		}
		if scan.pure[subject] {
			t.Error("the skipped declaration's //gofresh:pure leaked onto the plain function")
		}
	})
}
