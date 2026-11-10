package syntaxutil

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func parseAndCheck(t *testing.T, src string) (*token.FileSet, *ast.File, *types.Package, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
		Implicits:  make(map[ast.Node]types.Object),
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("conf.Check: %v", err)
	}
	return fset, file, pkg, info
}

func TestRecvTypeNameReducesEveryReceiverForm(t *testing.T) {
	const src = `package p
type Box[T any] struct{}
type Duo[K comparable, V any] struct{}
func (Box[T]) ValueIndexed() {}
func (*Box[T]) PtrIndexed() {}
func (Duo[K, V]) ValueIndexList() {}
func (*Duo[K, V]) PtrIndexList() {}
func ((*(Box[T]))) ParenWrapped() {}
func Plain() {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	decls := map[string]*ast.FuncDecl{}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			decls[fd.Name.Name] = fd
		}
	}
	cases := []struct {
		fn   string
		want string
	}{
		{"ValueIndexed", "Box"},
		{"PtrIndexed", "Box"},
		{"ValueIndexList", "Duo"},
		{"PtrIndexList", "Duo"},
		{"ParenWrapped", "Box"},
		{"Plain", ""},
	}
	for _, tc := range cases {
		if got := RecvTypeName(decls[tc.fn]); got != tc.want {
			t.Errorf("RecvTypeName(%s) = %q, want %q", tc.fn, got, tc.want)
		}
	}
	if got := RecvTypeName(&ast.FuncDecl{Name: ast.NewIdent("M"), Recv: &ast.FieldList{}}); got != "" {
		t.Errorf(`RecvTypeName(empty receiver list) = %q, want ""`, got)
	}
	if got := RecvTypeName(&ast.FuncDecl{
		Name: ast.NewIdent("M"),
		Recv: &ast.FieldList{List: []*ast.Field{{Type: &ast.SelectorExpr{X: ast.NewIdent("pkg"), Sel: ast.NewIdent("T")}}}},
	}); got != "" {
		t.Errorf(`RecvTypeName(selector receiver) = %q, want ""`, got)
	}
}

func TestRootIdentAndChainRoot(t *testing.T) {
	const src = `package p
type S struct { items []int }
func F(s *S) int {
	_ = (*s).items[0:1][0]
	return (*s).items[0]
}
`
	_, file, _, _ := parseAndCheck(t, src)
	fn := file.Decls[1].(*ast.FuncDecl)
	sliceIdx := fn.Body.List[0].(*ast.AssignStmt).Rhs[0]
	if got := RootIdent(sliceIdx); got != nil {
		t.Fatalf("RootIdent on SliceExpr spine = %v, want nil", got)
	}
	if got := ChainRoot(sliceIdx); got == nil || got.Name != "s" {
		t.Fatalf("ChainRoot on SliceExpr spine = %v, want s", got)
	}
	plainIdx := fn.Body.List[1].(*ast.ReturnStmt).Results[0]
	if got := RootIdent(plainIdx); got == nil || got.Name != "s" {
		t.Fatalf("RootIdent on IndexExpr spine = %v, want s", got)
	}
}

func TestPropagateLocalTaintHandlesRangeAndCopy(t *testing.T) {
	const src = `package p
var globalHooks []func()
func F() {
	var copied = make([]func(), len(globalHooks))
	copy(copied, globalHooks)
	for _, h := range copied {
		fn := h
		_ = fn
	}
}
`
	_, file, pkg, info := parseAndCheck(t, src)
	globalVar := pkg.Scope().Lookup("globalHooks")
	fn := file.Decls[1].(*ast.FuncDecl)
	tainted := map[types.Object]bool{}
	rhsTainted := func(expr ast.Expr) bool {
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if obj := IdentDefOrUse(info, id); obj == globalVar || tainted[obj] {
					found = true
				}
			}
			return true
		})
		return found
	}
	PropagateLocalTaint(info, fn.Body, tainted, func(types.Object) bool { return true }, rhsTainted, rhsTainted)
	for _, wantName := range []string{"copied", "h", "fn"} {
		found := false
		for obj := range tainted {
			if obj.Name() == wantName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("PropagateLocalTaint did not taint local %q", wantName)
		}
	}
}

func TestPropagateBFSMatchesReachFixedPoint(t *testing.T) {
	adj := map[string]map[string]bool{
		"a": {"b": true},
		"b": {"a": true, "c": true},
		"c": {"d": true},
		"x": {"y": true},
	}
	set := map[string]bool{"a": true}
	PropagateBFS(set, adj)
	for _, want := range []string{"a", "b", "c", "d"} {
		if !set[want] {
			t.Errorf("PropagateBFS missed reachable node %q", want)
		}
	}
	if set["x"] || set["y"] {
		t.Errorf("PropagateBFS reached disconnected component: %v", set)
	}
}
