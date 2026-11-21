package syntaxutil

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"testing"

	"pgregory.net/rapid"
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

func TestPropertySolveBipartiteLFPMatchesProductOracle(t *testing.T) {
	// Deterministic multi-round B -> A -> B -> A chain where iteration 1 makes
	// zero progress in A and unlocks b0 in B, which unlocks a0 in iteration 2,
	// b1 in iteration 2, and a1 in iteration 3, while false candidate entries
	// remain inert.
	{
		setA := map[int]bool{}
		candA := map[int]bool{0: true, 1: true, 2: false}
		setB := map[string]bool{}
		candB := map[string]bool{"b0": true, "b1": true, "b2": false}
		SolveBipartiteLFP(
			setA,
			candA,
			func(a int) bool {
				switch a {
				case 0:
					return setB["b0"]
				case 1:
					return setB["b1"]
				default:
					return true
				}
			},
			setB,
			candB,
			func(b string) bool {
				switch b {
				case "b0":
					return true
				case "b1":
					return setA[0]
				default:
					return true
				}
			},
		)
		if !maps.Equal(setA, map[int]bool{0: true, 1: true}) || !maps.Equal(setB, map[string]bool{"b0": true, "b1": true}) {
			t.Fatalf("alternating B->A->B->A chain got A=%v B=%v", setA, setB)
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		nA := rapid.IntRange(0, 6).Draw(rt, "nA")
		nB := rapid.IntRange(0, 6).Draw(rt, "nB")
		candA := make(map[int]bool, nA)
		candB := make(map[string]bool, nB)
		seedA := make(map[int]bool)
		seedB := make(map[string]bool)
		bKey := func(j int) string { return string(rune('a' + j)) }

		for i := 0; i < nA; i++ {
			candA[i] = rapid.Bool().Draw(rt, "candA")
			if rapid.IntRange(0, 3).Draw(rt, "seedA") == 0 {
				seedA[i] = true
			}
		}
		for j := 0; j < nB; j++ {
			k := bKey(j)
			candB[k] = rapid.Bool().Draw(rt, "candB")
			if rapid.IntRange(0, 3).Draw(rt, "seedB") == 0 {
				seedB[k] = true
			}
		}

		depsAA := make(map[int][]int, nA)
		depsAB := make(map[int][]string, nA)
		for i := 0; i < nA; i++ {
			for i2 := 0; i2 < nA; i2++ {
				if rapid.IntRange(0, 3).Draw(rt, "edgeAA") == 0 {
					depsAA[i] = append(depsAA[i], i2)
				}
			}
			for j := 0; j < nB; j++ {
				if rapid.IntRange(0, 3).Draw(rt, "edgeAB") == 0 {
					depsAB[i] = append(depsAB[i], bKey(j))
				}
			}
		}
		depsBB := make(map[string][]string, nB)
		depsBA := make(map[string][]int, nB)
		for j := 0; j < nB; j++ {
			k := bKey(j)
			for j2 := 0; j2 < nB; j2++ {
				if rapid.IntRange(0, 3).Draw(rt, "edgeBB") == 0 {
					depsBB[k] = append(depsBB[k], bKey(j2))
				}
			}
			for i := 0; i < nA; i++ {
				if rapid.IntRange(0, 3).Draw(rt, "edgeBA") == 0 {
					depsBA[k] = append(depsBA[k], i)
				}
			}
		}

		gotA := maps.Clone(seedA)
		gotB := maps.Clone(seedB)
		satA := func(i int) bool {
			for _, d := range depsAA[i] {
				if !gotA[d] {
					return false
				}
			}
			for _, d := range depsAB[i] {
				if !gotB[d] {
					return false
				}
			}
			return true
		}
		satB := func(k string) bool {
			for _, d := range depsBB[k] {
				if !gotB[d] {
					return false
				}
			}
			for _, d := range depsBA[k] {
				if !gotA[d] {
					return false
				}
			}
			return true
		}
		SolveBipartiteLFP(gotA, candA, satA, gotB, candB, satB)

		// Independent oracle: embed both domains into a single tagged domain and
		// solve via SolveLeastFixedPoint.
		type tagNode struct {
			isB bool
			a   int
			b   string
		}
		want := make(map[tagNode]bool)
		for i, ok := range seedA {
			if ok {
				want[tagNode{a: i}] = true
			}
		}
		for k, ok := range seedB {
			if ok {
				want[tagNode{isB: true, b: k}] = true
			}
		}
		prodDeps := make(map[tagNode]map[tagNode]bool)
		for i, active := range candA {
			if !active {
				continue
			}
			u := tagNode{a: i}
			prodDeps[u] = make(map[tagNode]bool)
			for _, d := range depsAA[i] {
				prodDeps[u][tagNode{a: d}] = true
			}
			for _, d := range depsAB[i] {
				prodDeps[u][tagNode{isB: true, b: d}] = true
			}
		}
		for k, active := range candB {
			if !active {
				continue
			}
			u := tagNode{isB: true, b: k}
			prodDeps[u] = make(map[tagNode]bool)
			for _, d := range depsBB[k] {
				prodDeps[u][tagNode{isB: true, b: d}] = true
			}
			for _, d := range depsBA[k] {
				prodDeps[u][tagNode{a: d}] = true
			}
		}
		SolveLeastFixedPoint(want, prodDeps, func(n tagNode) bool { return want[n] })

		for i := 0; i < nA; i++ {
			if gotA[i] != want[tagNode{a: i}] {
				rt.Fatalf("A[%d] = %v, want %v", i, gotA[i], want[tagNode{a: i}])
			}
		}
		for j := 0; j < nB; j++ {
			k := bKey(j)
			if gotB[k] != want[tagNode{isB: true, b: k}] {
				rt.Fatalf("B[%q] = %v, want %v", k, gotB[k], want[tagNode{isB: true, b: k}])
			}
		}

		// Idempotence on converged sets.
		snapA := maps.Clone(gotA)
		snapB := maps.Clone(gotB)
		SolveBipartiteLFP(gotA, candA, satA, gotB, candB, satB)
		if !maps.Equal(gotA, snapA) || !maps.Equal(gotB, snapB) {
			rt.Fatalf("SolveBipartiteLFP not idempotent")
		}
	})
}

func TestPropertyPruneUnsatisfiedDepsInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		nK := rapid.IntRange(0, 6).Draw(rt, "nK")
		nD := rapid.IntRange(0, 6).Draw(rt, "nD")
		satK := make(map[int]bool, nK)
		satD := make(map[string]bool, nD)
		dKey := func(j int) string { return string(rune('a' + j)) }
		for i := 0; i < nK; i++ {
			satK[i] = rapid.Bool().Draw(rt, "satK")
		}
		for j := 0; j < nD; j++ {
			satD[dKey(j)] = rapid.Bool().Draw(rt, "satD")
		}
		deps := make(map[int]map[string]bool, nK)
		for i := 0; i < nK; i++ {
			if rapid.Bool().Draw(rt, "nilRow") {
				continue
			}
			row := make(map[string]bool)
			for j := 0; j < nD; j++ {
				if rapid.Bool().Draw(rt, "hasEntry") {
					row[dKey(j)] = rapid.Bool().Draw(rt, "activeEntry")
				}
			}
			deps[i] = row
		}
		pruned := PruneUnsatisfiedDeps(deps, func(k int) bool { return satK[k] }, func(d string) bool { return satD[d] })
		for i := 0; i < nK; i++ {
			gotRow, hasRow := pruned[i]
			var wantEdges []string
			if !satK[i] {
				for j := 0; j < nD; j++ {
					dk := dKey(j)
					if deps[i][dk] && !satD[dk] {
						wantEdges = append(wantEdges, dk)
					}
				}
			}
			if len(wantEdges) == 0 {
				if hasRow {
					rt.Fatalf("PruneUnsatisfiedDeps kept satisfied or empty key %d: %v", i, gotRow)
				}
				continue
			}
			if !hasRow || len(gotRow) != len(wantEdges) {
				rt.Fatalf("PruneUnsatisfiedDeps[%d] = %v, want %v", i, gotRow, wantEdges)
			}
			for _, dk := range wantEdges {
				if !gotRow[dk] {
					rt.Fatalf("PruneUnsatisfiedDeps[%d] missing unsatisfied edge %q", i, dk)
				}
			}
		}
	})
}

func TestIsRefHeaderTypeAndNodeHasGotoOrLabel(t *testing.T) {
	const src = `package p
import "unsafe"
type S struct{ x int }
func cleanWithClosureGoto() {
	_ = func() {
		goto L
	L:
	}
}
func directGoto() {
	goto L
L:
}
func directLabelOnly() {
L:
	for {
		break L
	}
	_ = unsafe.Pointer(nil)
}
`
	_, file, pkg, _ := parseAndCheck(t, src)
	decls := map[string]*ast.FuncDecl{}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			decls[fd.Name.Name] = fd
		}
	}
	if NodeHasGotoOrLabel(nil) {
		t.Fatal("NodeHasGotoOrLabel(nil) = true, want false")
	}
	if NodeHasGotoOrLabel(decls["cleanWithClosureGoto"].Body) {
		t.Fatal("NodeHasGotoOrLabel crossed nested FuncLit boundary")
	}
	if !NodeHasGotoOrLabel(decls["directGoto"].Body) {
		t.Fatal("NodeHasGotoOrLabel missed direct goto")
	}
	if !NodeHasGotoOrLabel(decls["directLabelOnly"].Body) {
		t.Fatal("NodeHasGotoOrLabel missed direct label")
	}

	sType := pkg.Scope().Lookup("S").Type()
	for _, refT := range []types.Type{
		types.NewPointer(sType),
		types.NewSlice(types.Typ[types.Byte]),
		types.NewMap(types.Typ[types.String], types.Typ[types.Int]),
		types.NewChan(types.SendRecv, types.Typ[types.Int]),
		types.NewInterfaceType(nil, nil),
		types.Typ[types.UnsafePointer],
	} {
		if !IsRefHeaderType(refT) {
			t.Errorf("IsRefHeaderType(%v) = false, want true", refT)
		}
	}
	for _, valT := range []types.Type{
		nil,
		sType,
		types.NewArray(types.Typ[types.Int], 4),
		types.Typ[types.String],
		types.Typ[types.Uintptr],
		types.NewSignatureType(nil, nil, nil, nil, nil, false),
	} {
		if IsRefHeaderType(valT) {
			t.Errorf("IsRefHeaderType(%v) = true, want false", valT)
		}
	}
}
