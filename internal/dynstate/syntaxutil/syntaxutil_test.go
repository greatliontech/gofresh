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

func TestNewTypeEachLocalBindingAndFreshStringSliceCopyHelpers(t *testing.T) {
	const src = `package p

type StrAlias string
type BytesAlias []byte

func F(in any, s []int, str string) {
	pZero := new(int)
	pInit := new(*pZero)
	_ = pInit
	var dst = make([]int, len(s))
	copy(dst, s)
	for i, v := range dst {
		_, _ = i, v
	}
	_ = []byte(str)
	switch x := in.(type) {
	case int:
		_ = x
	case string:
		_ = x
	}
}
`
	_, file, pkg, info := parseAndCheck(t, src)
	if IsLocalVar(pkg.Scope().Lookup("F")) {
		t.Fatal("IsLocalVar(*types.Func) = true, want false")
	}

	var calls []*ast.CallExpr
	var bindings int
	ast.Inspect(file, func(n ast.Node) bool {
		if n != nil {
			EachLocalBinding(info, n, func(_, _ ast.Expr) {
				bindings++
			})
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			if b := LookupBuiltin(info, x.Fun); b != nil && b.Name() == "new" {
				calls = append(calls, x)
			}
		case *ast.TypeSwitchStmt:
			for _, st := range x.Body.List {
				if cc, ok := st.(*ast.CaseClause); ok {
					if v, ok := info.Implicits[cc].(*types.Var); ok && !IsLocalVar(v) {
						t.Errorf("IsLocalVar(type-switch implicit %v) = false, want true", v)
					}
				}
			}
		}
		return true
	})

	if len(calls) != 2 {
		t.Fatalf("got %d builtin new calls, want 2", len(calls))
	}
	if !IsBuiltinNewType(info, calls[0]) {
		t.Fatal("IsBuiltinNewType(new(int)) = false, want true")
	}
	if IsBuiltinNewType(info, calls[1]) {
		t.Fatal("IsBuiltinNewType(new(*pZero)) = true, want false")
	}
	if bindings < 5 {
		t.Fatalf("EachLocalBinding visited %d bindings, want >= 5", bindings)
	}
	strT := pkg.Scope().Lookup("StrAlias").Type()
	bytesT := pkg.Scope().Lookup("BytesAlias").Type()
	if !IsFreshStringSliceCopy(strT, bytesT) || !IsFreshStringSliceCopy(bytesT, strT) {
		t.Fatal("IsFreshStringSliceCopy failed on string <-> []byte conversions")
	}
	if IsFreshStringSliceCopy(strT, types.NewSlice(types.Typ[types.Int])) {
		t.Fatal("IsFreshStringSliceCopy accepted []int conversion")
	}
}
