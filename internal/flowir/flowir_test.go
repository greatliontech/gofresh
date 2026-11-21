package flowir_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"strings"
	"testing"

	. "github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"pgregory.net/rapid"
)

func mustTypecheck(t *testing.T, src string) (*token.FileSet, *ast.File, *types.Package, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	cfg := &types.Config{Importer: importer.Default()}
	pkg, err := cfg.Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("typecheck failed: %v", err)
	}
	return fset, file, pkg, info
}

func findFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("missing FuncDecl %s", name)
	return nil
}

func TestLowerAllocNewTypeVsNewExprAndCompositeElidedAmpersand(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

type item struct {
	label string
	fn    func()
}

func Build(seed int, cb func()) ([]*item, *int, *int) {
	pZero := new(int)
	pInit := new(seed)
	items := []*item{{label: "a", fn: cb}}
	return items, pZero, pInit
}
`)
	body := LowerFunc(info, pkg, findFuncDecl(t, file, "Build"))
	if body == nil || len(body.Ops) != 4 {
		t.Fatalf("unexpected lowered ops count: %+v", body)
	}
	if got := body.Ops[0].Srcs[0]; got.Kind != ValAllocFresh || got.AllocKind != AllocBuiltinNewType {
		t.Fatalf("new(int) lowered to (%v, %v), want (ValAllocFresh, AllocBuiltinNewType)", got.Kind, got.AllocKind)
	}
	if got := body.Ops[1].Srcs[0]; got.Kind != ValAllocFresh || got.AllocKind != AllocBuiltinNewExpr || len(got.Args) != 1 || got.Args[0].Kind != ValPlace {
		t.Fatalf("new(seed) lowered to %+v, want AllocBuiltinNewExpr with 1 ValPlace arg", got)
	}
	comp := body.Ops[2].Srcs[0]
	if comp.Kind != ValAllocFresh || comp.AllocKind != AllocCompositeLit || len(comp.CompositeElts) != 1 {
		t.Fatalf("slice composite literal lowered to %+v", comp)
	}
	inner := comp.CompositeElts[0].Value
	if inner.Kind != ValAllocFresh || inner.AllocKind != AllocCompositeLit || len(inner.CompositeElts) != 2 {
		t.Fatalf("elided-& struct element lowered to %+v", inner)
	}
	if inner.CompositeElts[1].Field == nil || inner.CompositeElts[1].Field.Name() != "fn" {
		t.Fatalf("expected resolved struct Field 'fn' on elided-& element, got %+v", inner.CompositeElts[1].Field)
	}
}

func TestPlaceAsMapWriteGenericAndParenRawPreservation(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

type holder struct {
	str string
	m   map[string]int
	ms  map[string][]int
}

func GenericMapWrite[M ~map[K]V, K comparable, V any](gm M, k K, v V, h *holder) {
	(gm)[k] = v
	h.m["x"]++
	h.ms["x"][0] = 9
	h.str = "direct"
	(h.str) = "paren"
}
`)
	body := LowerFunc(info, pkg, findFuncDecl(t, file, "GenericMapWrite"))
	if len(body.Ops) != 5 {
		t.Fatalf("expected 5 ops, got %d", len(body.Ops))
	}
	if mp, key, ok := body.Ops[0].Dsts[0].AsMapWrite(); !ok || mp.Root != RootParam || key == nil {
		t.Fatalf("(gm)[k] = v AsMapWrite = (%+v, %+v, %v), want generic map write", mp, key, ok)
	}
	if mp, _, ok := body.Ops[1].Dsts[0].AsMapWrite(); !ok || mp.Root != RootParam || len(mp.Projs) != 1 || mp.Projs[0].Field.Name() != "m" {
		t.Fatalf("h.m[\"x\"]++ AsMapWrite = (%+v, %v), want field map write", mp, ok)
	}
	if _, _, ok := body.Ops[2].Dsts[0].AsMapWrite(); ok {
		t.Fatal("h.ms[\"x\"][0] = 9 writes a slice element inside a map, want AsMapWrite == false")
	}
	if !refconfine.FillSelection(info, body.Ops[3].Dsts[0].Raw) {
		t.Fatal("h.str FillSelection = false, want true")
	}
	if refconfine.FillSelection(info, body.Ops[4].Dsts[0].Raw) {
		t.Fatal("(h.str) FillSelection = true, want false (parenthesized Raw preserved)")
	}
}

func TestMethodExprNormalizationAutoAddrAndArraySlice(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

type inner struct{ x int }
func (i *inner) PtrM(delta int) int { return i.x + delta }

type valEmbed struct{ inner }
type ptrEmbed struct{ *inner }

func Exercise[A ~[4]int](ve valEmbed, pe ptrEmbed, pi *inner, arr [4]int, pArr *[4]int, ga A) {
	_ = ve.PtrM(1)
	_ = pe.PtrM(2)
	_ = pi.PtrM(3)
	_ = (*inner).PtrM(pi, 4)
	mvVal := ve.PtrM
	mvPtr := pe.PtrM
	_, _ = mvVal, mvPtr
	_ = arr[1:3]
	_ = pArr[1:3]
	_ = ga[0:2]
}
`)
	body := LowerFunc(info, pkg, findFuncDecl(t, file, "Exercise"))
	// Ops[0]: ve.PtrM(1) -> AutoAddrRecv == true
	c0 := body.Ops[0].Srcs[0]
	if c0.Kind != ValCall || c0.CallKind != CallMethod || !c0.AutoAddrRecv {
		t.Fatalf("ve.PtrM(1): got %+v, want CallMethod with AutoAddrRecv=true", c0)
	}
	// Ops[1]: pe.PtrM(2) -> AutoAddrRecv == false (crosses embedded *inner pointer)
	c1 := body.Ops[1].Srcs[0]
	if c1.Kind != ValCall || c1.CallKind != CallMethod || c1.AutoAddrRecv {
		t.Fatalf("pe.PtrM(2): got %+v, want CallMethod with AutoAddrRecv=false", c1)
	}
	// Ops[2]: pi.PtrM(3) -> AutoAddrRecv == false
	c2 := body.Ops[2].Srcs[0]
	if c2.AutoAddrRecv {
		t.Fatalf("pi.PtrM(3): got AutoAddrRecv=true, want false")
	}
	// Ops[3]: (*inner).PtrM(pi, 4) -> IsMethodExprCall == true, 1 arg, CalleeSig has 1 param
	c3 := body.Ops[3].Srcs[0]
	if c3.Kind != ValCall || c3.CallKind != CallMethod || !c3.IsMethodExprCall || len(c3.Args) != 1 || c3.CalleeSig.Params().Len() != 1 {
		t.Fatalf("(*inner).PtrM(pi, 4): got %+v, want normalized CallMethod with 1 arg/param", c3)
	}
	if pIdx, ok := c3.ParamIndexForArg(0); !ok || pIdx != 0 {
		t.Fatalf("ParamIndexForArg(0) on MethodExpr = (%d, %v), want (0, true)", pIdx, ok)
	}
	// Ops[4]: mvVal := ve.PtrM -> ValMethodVal with AutoAddr == true
	if mv := body.Ops[4].Srcs[0]; mv.Kind != ValMethodVal || !mv.AutoAddr {
		t.Fatalf("ve.PtrM method value: got %+v, want AutoAddr=true", mv)
	}
	// Ops[5]: mvPtr := pe.PtrM -> ValMethodVal with AutoAddr == false
	if mv := body.Ops[5].Srcs[0]; mv.Kind != ValMethodVal || mv.AutoAddr {
		t.Fatalf("pe.PtrM method value: got %+v, want AutoAddr=false", mv)
	}
	// Ops[7]: arr[1:3] -> ValAddrOf{IsArraySlice: true}
	if sArr := body.Ops[7].Srcs[0]; sArr.Kind != ValAddrOf || !sArr.IsArraySlice {
		t.Fatalf("arr[1:3]: got %+v, want ValAddrOf{IsArraySlice: true}", sArr)
	}
	// Ops[8]: pArr[1:3] -> ValPlace with ProjSlice (pArr is already pointer *[4]int)
	if spArr := body.Ops[8].Srcs[0]; spArr.Kind != ValPlace || len(spArr.Place.Projs) != 1 || spArr.Place.Projs[0].Kind != ProjSlice {
		t.Fatalf("pArr[1:3]: got %+v, want ValPlace with ProjSlice", spArr)
	}
	// Ops[9]: ga[0:2] on A ([4]int | []int) -> ValAddrOf{IsArraySlice: true}
	if sGen := body.Ops[9].Srcs[0]; sGen.Kind != ValAddrOf || !sGen.IsArraySlice {
		t.Fatalf("ga[0:2] on array-union type param: got %+v, want ValAddrOf{IsArraySlice: true}", sGen)
	}
}

func TestTypeSwitchBindsTransitiveFreeVarsLabelsAndMemAliases(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

func Complex(in any) func() int {
	scalar := 7
	ptr := &scalar
	var arr [2]int
	sl := arr[:]
	ch := make(chan *int, 1)
	ch <- ptr

	switch v := in.(type) {
	case []int:
		_ = v[0]
	case int, int64:
		_ = v
	default:
		_ = v
	}

retry:
	_ = sl
	if false {
		goto retry
	}

	outerFn := func() int {
		innerFn := func() int {
			return scalar
		}
		return innerFn()
	}
	return outerFn
}
`)
	fd := findFuncDecl(t, file, "Complex")
	body := LowerFunc(info, pkg, fd)

	// Verify TypeSwitchBind ops cover the header operand and all 3 case implicit vars.
	var switchBinds []*types.Var
	headerSwitchSeen := false
	labeledTopLevel := false
	body.ForEachSyncOp(func(op *Op) bool {
		if op.Kind == OpTypeSwitchBind {
			if op.SwitchDst == nil {
				headerSwitchSeen = true
			} else {
				switchBinds = append(switchBinds, op.SwitchDst)
			}
		}
		if op.Kind == OpAssign && len(op.Dsts) == 1 && op.Dsts[0].IsBlank() && len(op.Srcs) == 1 &&
			op.Srcs[0].Kind == ValPlace && op.Srcs[0].Place.Obj != nil && op.Srcs[0].Place.Obj.Name() == "sl" {
			labeledTopLevel = op.TopLevelInBody
		}
		return true
	})
	if !headerSwitchSeen || len(switchBinds) != 3 {
		t.Fatalf("expected header OpTypeSwitchBind + 3 case implicit vars, got header=%v vars=%d", headerSwitchSeen, len(switchBinds))
	}
	if labeledTopLevel {
		t.Fatal("labeled statement under `retry:` must have TopLevelInBody == false")
	}

	// Verify outerFn's FreeVars transitively captures `scalar` from innerFn.
	var outerClosure *Body
	for i := range body.Ops {
		if len(body.Ops[i].Srcs) == 1 && body.Ops[i].Srcs[0].Kind == ValMakeClosure {
			outerClosure = body.Ops[i].Srcs[0].Closure
		}
	}
	if outerClosure == nil || len(outerClosure.FreeVars) != 1 {
		t.Fatalf("expected outerClosure.FreeVars to contain `scalar`, got %+v", outerClosure)
	}

	// Verify BuildEnclosingMemAliases links scalar <-> ptr <-> ch and arr <-> sl.
	aliases := BuildEnclosingMemAliases(body, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	varsByName := map[string]*types.Var{}
	for _, obj := range info.Defs {
		if v, ok := obj.(*types.Var); ok && v != nil {
			varsByName[v.Name()] = v
		}
	}
	if !aliases[varsByName["scalar"]][varsByName["ptr"]] {
		t.Fatal("expected scalar <-> ptr alias edge from `ptr := &scalar`")
	}
	if !aliases[varsByName["ptr"]][varsByName["ch"]] {
		t.Fatal("expected ptr <-> ch alias edge from `ch <- ptr`")
	}
	if !aliases[varsByName["arr"]][varsByName["sl"]] {
		t.Fatal("expected arr <-> sl alias edge from `sl := arr[:]`")
	}
}

func TestPropLowerFuncInvariantsAndAliasSymmetry(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	stmtTemplates := []string{
		"pZero := new([]int); _ = pZero",
		"pInit := new(in); _ = pInit",
		"cp := make([]int, len(in)); copy(cp, in)",
		"sl := arr[:]; _ = sl",
		"ptr := &scalar; ch <- ptr",
		"switch v := box.(type) { case []int: _ = len(v); default: _ = v }",
		"for i, v := range in { _, _ = i, v }",
		"fn := func() int { return len(in) + scalar }; _ = fn()",
		"go func(n int) { _ = n }(len(in))",
		"defer func() { _ = scalar }()",
	}
	for iter := 0; iter < 40; iter++ {
		var sb strings.Builder
		sb.WriteString("package p\nfunc Generated(in []int, box any) int {\n\tscalar := 1\n\tvar arr [4]int\n\tch := make(chan *int, 4)\n\t_, _, _ = scalar, arr, ch\n")
		nStmts := 2 + rng.Intn(6)
		for j := 0; j < nStmts; j++ {
			sb.WriteString("\t{\n\t\t")
			sb.WriteString(stmtTemplates[rng.Intn(len(stmtTemplates))])
			sb.WriteString("\n\t}\n")
		}
		sb.WriteString("\treturn scalar\n}\n")
		src := sb.String()

		_, file1, pkg1, info1 := mustTypecheck(t, src)
		fd1 := findFuncDecl(t, file1, "Generated")
		b1 := LowerFunc(info1, pkg1, fd1)
		b2 := LowerFunc(info1, pkg1, fd1)
		if b1 == nil || b2 == nil || len(b1.Ops) != len(b2.Ops) {
			t.Fatalf("iter %d: non-deterministic op count", iter)
		}
		for fv := range b1.FreeVars {
			if b1.OwnsVar(fv) {
				t.Fatalf("iter %d: top-level body reported owned var %v in FreeVars", iter, fv)
			}
		}
		b1.ForEachSyncOp(func(op *Op) bool {
			if op.Kind == OpAssign {
				op.ForEachAssignPair(func(_ int, dst Place, _ bool, _ *Value) bool {
					if dst.Root == 0 {
						t.Fatalf("iter %d: zero RootKind on assigned place", iter)
					}
					return true
				})
			}
			return true
		})
		aliases := BuildEnclosingMemAliases(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
		for u, nbrs := range aliases {
			if nbrs[u] {
				t.Fatalf("iter %d: self-loop on %v in BuildEnclosingMemAliases", iter, u)
			}
			for v := range nbrs {
				if !aliases[v][u] {
					t.Fatalf("iter %d: asymmetric alias edge %v -> %v", iter, u, v)
				}
			}
		}
	}
}

func TestForEachArgParamTupleAndVariadicMapping(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

func pair() (int, []int) { return 1, []int{2} }
func triple() (int, []int, []int) { return 1, []int{2}, []int{3} }
func sink(a int, b []int) {}
func varSink(a int, rest ...[]int) {}
func anyVarSink(a any, rest ...any) {}

func Calls(xs [][]int, ys []any) {
	sink(pair())
	varSink(triple())
	varSink(0, xs...)
	buf := make([]int, 1)
	func(n int, s []int) {
		_ = n
		_ = s
	}(func() (int, []int) {
		return 7, buf
	}())
	anyVarSink("hi", 1, "there")
	anyVarSink("hi", ys...)
}
`)
	body := LowerFunc(info, pkg, findFuncDecl(t, file, "Calls"))
	if len(body.Ops) < 5 {
		t.Fatalf("Calls ops = %d, want >= 5", len(body.Ops))
	}

	type slotWant struct {
		slotIdx int
		pIdx    int
		packed  bool
	}
	collect := func(v *Value) []slotWant {
		var got []slotWant
		v.ForEachArgParam(func(_ *Value, slotType types.Type, slotIdx int, paramIdx int, ok bool, packed bool) bool {
			if !ok || slotType == nil {
				t.Fatalf("unexpected invalid slot (%d, %d, ok=%v, type=%v)", slotIdx, paramIdx, ok, slotType)
			}
			got = append(got, slotWant{slotIdx: slotIdx, pIdx: paramIdx, packed: packed})
			return true
		})
		return got
	}

	if got := collect(body.Ops[0].Expr); len(got) != 2 || got[0] != (slotWant{0, 0, false}) || got[1] != (slotWant{1, 1, false}) {
		t.Fatalf("sink(pair()) slots = %+v, want [(0,0,false) (1,1,false)]", got)
	}
	if got := collect(body.Ops[1].Expr); len(got) != 3 ||
		got[0] != (slotWant{0, 0, false}) ||
		got[1] != (slotWant{1, 1, true}) ||
		got[2] != (slotWant{2, 1, true}) {
		t.Fatalf("varSink(triple()) slots = %+v, want [(0,0,false) (1,1,true) (2,1,true)]", got)
	}
	if got := collect(body.Ops[2].Expr); len(got) != 2 || got[0] != (slotWant{0, 0, false}) || got[1] != (slotWant{1, 1, false}) {
		t.Fatalf("varSink(0, xs...) slots = %+v, want [(0,0,false) (1,1,false)]", got)
	}

	aliases := BuildScopedMemAliases(body, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
	bufObj := body.Ops[3].Dsts[0].Obj
	iifeCall := body.Ops[4].Expr
	paramN := iifeCall.IIFE.Params[0]
	paramS := iifeCall.IIFE.Params[1]
	if !aliases[bufObj][paramS] || !aliases[paramS][bufObj] {
		t.Fatalf("expected BuildScopedMemAliases to link buf <-> s across multi-return IIFE, got %+v", aliases)
	}
	if aliases[bufObj][paramN] || aliases[paramN][bufObj] {
		t.Fatalf("scalar parameter n unexpectedly linked to buf in BuildScopedMemAliases: %+v", aliases)
	}

	packedCall := body.Ops[5].Expr
	packedCall.ForEachArgParam(func(_ *Value, slotType types.Type, slotIdx int, paramIdx int, ok bool, packed bool) bool {
		pt := packedCall.FormalParamSlotType(paramIdx, packed)
		if !ok || pt == nil || !types.IsInterface(pt) {
			t.Fatalf("packedCall slot %d FormalParamSlotType(%d, %v) = %v, want any interface (arg slotType=%v)", slotIdx, paramIdx, packed, pt, slotType)
		}
		return true
	})
	ellipsisCall := body.Ops[6].Expr
	ellipsisCall.ForEachArgParam(func(_ *Value, _ types.Type, slotIdx int, paramIdx int, ok bool, packed bool) bool {
		pt := ellipsisCall.FormalParamSlotType(paramIdx, packed)
		if !ok || pt == nil {
			t.Fatalf("ellipsisCall slot %d FormalParamSlotType = nil", slotIdx)
		}
		if slotIdx == 1 {
			if _, isSlice := pt.Underlying().(*types.Slice); !isSlice || packed {
				t.Fatalf("ellipsisCall slot 1 FormalParamSlotType(%d, %v) = %v, want []any with packed=false", paramIdx, packed, pt)
			}
		}
		return true
	})
}

func TestLowerNodeGenDeclValueSpecRootPosCalleeSelectorAndShadowedNil(t *testing.T) {
	_, file, pkg, info := mustTypecheck(t, `package p

import (
	"bytes"
	"slices"
)

func pair() (int, []int) { return 7, []int{8} }

const (
	cZero = 1 << iota
	cOne
	cPairA, cPairB = 10, 20
)

var (
	vSingle     = 42
	vZero       []int
	vMultiA, vMultiB = 1, 2
	vTupA, vTupB     = pair()
	vErrNil     error = nil
)

type holder struct {
	buf []int
	n   int
}

func (h *holder) Touch(x int) int { return h.n + x }

func makeHolder() *holder { return &holder{} }

func ExerciseSelectorsPositionsAndNil(in []int) int {
	var nilSlice []int = nil
	local := holder{buf: in, n: 3}
	_ = ((local).buf)[0]
	_ = bytes.ErrTooLarge
	_ = makeHolder().n
	_ = (&local).Touch(1)
	_ = (local.Touch)(2)
	_ = slices.Clone[[]int](in)
	_ = slices.Insert[[]int, int](in, 0, 9)
	_ = plainHelper(3)
	_ = (func() int { return 4 })()
	_ = new(int)
	return len(nilSlice)
}

func plainHelper(x int) int { return x }

func ShadowVarNil() []int {
	nil := []int{1, 2}
	return nil
}

func ShadowErrNil() error {
	var nil error
	return nil
}

func ShadowConstNil() int {
	const nil = 99
	return nil
}
`)

	var constGD, varGD *ast.GenDecl
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		if gd.Tok == token.CONST {
			constGD = gd
		} else if gd.Tok == token.VAR {
			varGD = gd
		}
	}
	if constGD == nil || varGD == nil {
		t.Fatalf("missing const or var GenDecl: const=%v var=%v", constGD, varGD)
	}

	// 1. const GenDecl lowers explicit expressions to OpExpr{IsConst: true} with zero Dsts;
	// implicit iota carry-forward specs have no Values and emit no spurious AssignZeroDecl.
	constBody := LowerNode(info, pkg, constGD)
	if constBody == nil || len(constBody.Ops) != 3 {
		t.Fatalf("const GenDecl ops = %+v, want 3 OpExprs", constBody)
	}
	for i, op := range constBody.Ops {
		if op.Kind != OpExpr || len(op.Dsts) != 0 || op.Expr == nil || !op.Expr.IsConst || op.Expr.IsNil {
			t.Fatalf("const op[%d] = %+v (expr=%+v), want OpExpr{IsConst:true, IsNil:false}", i, op, op.Expr)
		}
	}
	constSpec0 := constGD.Specs[0].(*ast.ValueSpec)
	if vsB := LowerNode(info, pkg, constSpec0); vsB == nil || len(vsB.Ops) != 1 || vsB.Ops[0].Kind != OpExpr || !vsB.Ops[0].Expr.IsConst {
		t.Fatalf("LowerNode(const ValueSpec) = %+v, want 1 OpExpr{IsConst:true}", vsB)
	}

	// 2. var GenDecl covers AssignPlain, AssignZeroDecl, multi-name AssignPlain, tuple AssignMulti, and typed error nil.
	varBody := LowerNode(info, pkg, varGD)
	if varBody == nil || len(varBody.Ops) != 5 {
		t.Fatalf("var GenDecl ops = %+v, want 5 OpAssigns", varBody)
	}
	wantAssignKinds := []AssignKind{AssignPlain, AssignZeroDecl, AssignPlain, AssignMulti, AssignPlain}
	for i, wantK := range wantAssignKinds {
		if varBody.Ops[i].Kind != OpAssign || varBody.Ops[i].AssignKind != wantK {
			t.Fatalf("var op[%d] = (%v, %v), want (OpAssign, %v)", i, varBody.Ops[i].Kind, varBody.Ops[i].AssignKind, wantK)
		}
	}
	errNilVal := varBody.Ops[4].Srcs[0]
	if !errNilVal.IsNil || errNilVal.IsConst {
		t.Fatalf("typed error nil = (IsNil=%v, IsConst=%v), want (true, false)", errNilVal.IsNil, errNilVal.IsConst)
	}
	varSpec1 := varGD.Specs[1].(*ast.ValueSpec)
	if vsZero := LowerNode(info, pkg, varSpec1); vsZero == nil || len(vsZero.Ops) != 1 || vsZero.Ops[0].AssignKind != AssignZeroDecl {
		t.Fatalf("LowerNode(zero var ValueSpec) = %+v, want AssignZeroDecl", vsZero)
	}

	// 3. Place.RootPos, CalleeSelector(), and IsTypeExpr.
	var nilVal *Value
	if nilVal.CalleeSelector() != nil {
		t.Fatal("nil Value.CalleeSelector() != nil")
	}

	exFD := findFuncDecl(t, file, "ExerciseSelectorsPositionsAndNil")
	exBody := LowerFunc(info, pkg, exFD)
	if exBody == nil || len(exBody.Ops) < 11 {
		t.Fatalf("unexpected ExerciseSelectorsPositionsAndNil ops: %+v", exBody)
	}
	if !exBody.Ops[0].Srcs[0].IsNil {
		t.Fatalf("var nilSlice []int = nil Src[0].IsNil = false, want true")
	}
	if exBody.Ops[0].Srcs[0].CalleeSelector() != nil {
		t.Fatal("non-call Value.CalleeSelector() != nil")
	}

	// Ops[2]: `_ = ((local).buf)[0]` -> RootPos matches inner `local` Ident.Pos().
	projRead := exBody.Ops[2].Srcs[0]
	localObj := exBody.Ops[1].Dsts[0].Obj
	var wantLocalIdentPos token.Pos
	ast.Inspect(exFD.Body.List[2], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == localObj {
			wantLocalIdentPos = id.Pos()
		}
		return true
	})
	if projRead.Kind != ValPlace || projRead.Place.RootPos != wantLocalIdentPos || !wantLocalIdentPos.IsValid() {
		t.Fatalf("((local).buf)[0] RootPos = %v, want %v", projRead.Place.RootPos, wantLocalIdentPos)
	}

	// Ops[3]: `_ = bytes.ErrTooLarge` -> RootPos matches `Sel.Pos()`, NOT `bytes` PkgName Pos().
	pkgQualRead := exBody.Ops[3].Srcs[0]
	selPkgAST := exFD.Body.List[3].(*ast.AssignStmt).Rhs[0].(*ast.SelectorExpr)
	if pkgQualRead.Kind != ValPlace || pkgQualRead.Place.RootPos != selPkgAST.Sel.Pos() {
		t.Fatalf("bytes.ErrTooLarge RootPos = %v, want Sel.Pos() %v (X.Pos()=%v)", pkgQualRead.Place.RootPos, selPkgAST.Sel.Pos(), selPkgAST.X.Pos())
	}

	// Ops[4]: `_ = makeHolder().n` -> RootTransient RootPos matches Base CallExpr.Pos().
	transRead := exBody.Ops[4].Srcs[0]
	if transRead.Kind != ValPlace || transRead.Place.Root != RootTransient || transRead.Place.RootPos != transRead.Place.Base.Raw.Pos() {
		t.Fatalf("makeHolder().n transient RootPos = %v, want %v", transRead.Place.RootPos, transRead.Place.Base.Raw.Pos())
	}

	// Ops[5..10]: CalleeSelector matrix across direct, paren, IndexExpr generic, IndexListExpr generic, plain, and IIFE calls.
	selMatrix := []struct {
		opIdx   int
		wantSel string
	}{
		{opIdx: 5, wantSel: "Touch"},
		{opIdx: 6, wantSel: "Touch"},
		{opIdx: 7, wantSel: "Clone"},
		{opIdx: 8, wantSel: "Insert"},
		{opIdx: 9, wantSel: ""},
		{opIdx: 10, wantSel: ""},
	}
	for _, tc := range selMatrix {
		callVal := exBody.Ops[tc.opIdx].Srcs[0]
		gotSel := callVal.CalleeSelector()
		if tc.wantSel == "" {
			if gotSel != nil {
				t.Fatalf("op[%d] CalleeSelector() = %v, want nil", tc.opIdx, gotSel.Sel.Name)
			}
		} else if gotSel == nil || gotSel.Sel.Name != tc.wantSel {
			t.Fatalf("op[%d] CalleeSelector() = %+v, want %q", tc.opIdx, gotSel, tc.wantSel)
		}
	}

	// Ops[11]: `_ = new(int)` -> LowerNode on CallExpr.Args[0] yields IsTypeExpr == true.
	newTypeCall := exFD.Body.List[11].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr)
	typeArgBody := LowerNode(info, pkg, newTypeCall.Args[0])
	if typeArgBody == nil || len(typeArgBody.Ops) != 1 || typeArgBody.Ops[0].Expr == nil || !typeArgBody.Ops[0].Expr.IsTypeExpr {
		t.Fatalf("LowerNode(new(int) type arg) = %+v, want IsTypeExpr=true", typeArgBody)
	}

	// 4. Shadowed `nil` (local slice var, local error var, local const) must NEVER set IsNil == true.
	for _, fnName := range []string{"ShadowVarNil", "ShadowErrNil", "ShadowConstNil"} {
		sb := LowerFunc(info, pkg, findFuncDecl(t, file, fnName))
		retOp := sb.Ops[len(sb.Ops)-1]
		if retOp.Kind != OpReturn || len(retOp.Results) != 1 {
			t.Fatalf("%s missing single-result return: %+v", fnName, retOp)
		}
		rv := retOp.Results[0]
		if rv.IsNil {
			t.Fatalf("%s: shadowed `nil` had IsNil=true (%+v)", fnName, rv)
		}
		if fnName == "ShadowConstNil" && !rv.IsConst {
			t.Fatalf("%s: const `nil` had IsConst=false (%+v)", fnName, rv)
		}
	}

	// 5. AssignCompound synthetic ValCompositeExpr leaves Raw == nil so parenthesized
	// RHS expressions index to their own lowered Value rather than the synthetic wrapper.
	_, compFile, compPkg, compInfo := mustTypecheck(t, `package p
func AddParen(x int) int {
	y := 1
	x += (y)
	return x
}
`)
	compFD := findFuncDecl(t, compFile, "AddParen")
	compBody := LowerFunc(compInfo, compPkg, compFD)
	if len(compBody.Ops) < 2 || compBody.Ops[1].Kind != OpAssign || compBody.Ops[1].AssignKind != AssignCompound {
		t.Fatalf("expected AssignCompound at Ops[1], got %+v", compBody.Ops)
	}
	compSrc := compBody.Ops[1].Srcs[0]
	if compSrc.Kind != ValCompositeExpr || compSrc.Raw != nil || len(compSrc.Args) != 2 {
		t.Fatalf("AssignCompound Src[0] = %+v, want ValCompositeExpr with Raw == nil and 2 Args", compSrc)
	}
	if compSrc.Args[1].Kind != ValPlace || compSrc.Args[1].Raw == nil {
		t.Fatalf("AssignCompound Args[1] = %+v, want ValPlace with non-nil Raw", compSrc.Args[1])
	}
}

func TestBodyHazardFlagsAndSignatureFuncLitCacheMatrix(t *testing.T) {
	const src = `package p

import "unsafe"

type TypeWithLit [unsafe.Sizeof(func() {
	goto L
L:
})]byte

func Clean() {}

func ClosureGotoOnly() {
	_ = func() {
		goto L
	L:
	}
}

func RangeGoto(xs []int) {
	for range xs {
		goto Done
	}
Done:
}

func FallthroughAndDefer(x int) {
	defer func() {}()
	switch x {
	case 1:
		fallthrough
	default:
	}
}

func LabeledBreakAndGo(xs []int) {
	go func() {}()
Outer:
	for range xs {
		break Outer
	}
}
`
	_, file, pkg, info := mustTypecheck(t, src)
	cache := NewPkgCache(info, pkg, []*ast.File{file})
	if cache.DeclLowerCount != 5 {
		t.Fatalf("DeclLowerCount = %d, want 5", cache.DeclLowerCount)
	}
	// Pre-indexed FuncLit inside TypeWithLit must hit cache with 0 MissCount.
	var typeLit *ast.FuncLit
	ast.Inspect(file.Decls[1], func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok {
			typeLit = fl
			return false
		}
		return true
	})
	if typeLit == nil {
		t.Fatal("missing FuncLit in TypeWithLit")
	}
	tlBody := cache.LitBody(typeLit)
	if tlBody == nil || !tlBody.HasGoto || !tlBody.HasLabel || cache.MissCount != 0 {
		t.Fatalf("typeLit body = %+v, MissCount = %d", tlBody, cache.MissCount)
	}

	cases := []struct {
		name              string
		hasGoto           bool
		hasNestedGoto     bool
		hasGotoAnywhere   bool
		hasLabel          bool
		hasGotoOrLabel    bool
		hasFallthrough    bool
		hasGotoLabelOrFT  bool
		hasLabeledBranch  bool
		hasUnstructuredBr bool
		hasDefer          bool
		hasGo             bool
	}{
		{name: "Clean"},
		{name: "ClosureGotoOnly", hasNestedGoto: true, hasGotoAnywhere: true},
		{name: "RangeGoto", hasGoto: true, hasGotoAnywhere: true, hasLabel: true, hasGotoOrLabel: true, hasGotoLabelOrFT: true, hasLabeledBranch: true, hasUnstructuredBr: true},
		{name: "FallthroughAndDefer", hasFallthrough: true, hasGotoLabelOrFT: true, hasUnstructuredBr: true, hasDefer: true},
		{name: "LabeledBreakAndGo", hasLabel: true, hasGotoOrLabel: true, hasGotoLabelOrFT: true, hasLabeledBranch: true, hasUnstructuredBr: true, hasGo: true},
	}
	for _, tc := range cases {
		b := cache.FuncBody(findFuncDecl(t, file, tc.name))
		if b == nil {
			t.Fatalf("%s: nil body", tc.name)
		}
		if b.HasGoto != tc.hasGoto || b.HasNestedGoto != tc.hasNestedGoto || b.HasGotoAnywhere() != tc.hasGotoAnywhere ||
			b.HasLabel != tc.hasLabel || b.HasGotoOrLabel() != tc.hasGotoOrLabel ||
			b.HasFallthrough != tc.hasFallthrough || b.HasGotoLabelOrFallthrough() != tc.hasGotoLabelOrFT ||
			b.HasLabeledBranch != tc.hasLabeledBranch || b.HasUnstructuredBranch() != tc.hasUnstructuredBr ||
			b.HasDefer != tc.hasDefer || b.HasGo != tc.hasGo {
			t.Fatalf("%s mismatch: got goto=%v nested=%v any=%v label=%v ft=%v labBr=%v defer=%v go=%v",
				tc.name, b.HasGoto, b.HasNestedGoto, b.HasGotoAnywhere(), b.HasLabel, b.HasFallthrough, b.HasLabeledBranch, b.HasDefer, b.HasGo)
		}
	}
}

func TestPropertyBodyHazardFlagsMatchASTOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		emitGoto := rapid.Bool().Draw(rt, "emitGoto")
		emitLabelOnly := !emitGoto && rapid.Bool().Draw(rt, "emitLabelOnly")
		emitRangeGoto := !emitGoto && !emitLabelOnly && rapid.Bool().Draw(rt, "emitRangeGoto")
		emitFallthrough := rapid.Bool().Draw(rt, "emitFallthrough")
		emitLabeledBreak := rapid.Bool().Draw(rt, "emitLabeledBreak")
		emitDefer := rapid.Bool().Draw(rt, "emitDefer")
		emitGo := rapid.Bool().Draw(rt, "emitGo")
		closureGoto := rapid.Bool().Draw(rt, "closureGoto")
		iifeGoto := rapid.Bool().Draw(rt, "iifeGoto")
		typeExprGoto := rapid.Bool().Draw(rt, "typeExprGoto")

		var sb strings.Builder
		sb.WriteString("package p\n")
		if typeExprGoto {
			sb.WriteString("import \"unsafe\"\n")
		}
		sb.WriteString("func F(xs []int, n int) {\n")

		if emitDefer {
			sb.WriteString("\tdefer func() {}()\n")
		}
		if emitGo {
			sb.WriteString("\tgo func() {}()\n")
		}
		if emitFallthrough {
			sb.WriteString("\tswitch n { case 0: fallthrough; default: }\n")
		}
		if emitLabeledBreak {
			sb.WriteString("Loop:\n\tfor range xs { break Loop }\n")
		}
		if closureGoto {
			sb.WriteString("\t_ = func() { goto CL; CL: }\n")
		} else {
			sb.WriteString("\t_ = func() { defer func() {}() }\n")
		}
		if iifeGoto {
			sb.WriteString("\tfunc() { goto IL; IL: }()\n")
		}
		if typeExprGoto {
			sb.WriteString("\tfor range xs { _ = [unsafe.Sizeof(func() { goto TL; TL: })]byte{} }\n")
		}
		if emitGoto {
			sb.WriteString("\tgoto Target\nTarget:\n")
		} else if emitLabelOnly {
			sb.WriteString("UnusedLabel:\n\tfor { break UnusedLabel }\n")
		} else if emitRangeGoto {
			sb.WriteString("\tfor range xs { goto AfterRange }\nAfterRange:\n")
		}
		sb.WriteString("}\n")

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "p.go", sb.String(), 0)
		if err != nil {
			rt.Fatalf("parse failed: %v\n%s", err, sb.String())
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Instances:  make(map[*ast.Ident]types.Instance),
			Implicits:  make(map[ast.Node]types.Object),
		}
		pkg, err := (&types.Config{Importer: importer.Default()}).Check("p", fset, []*ast.File{file}, info)
		if err != nil {
			rt.Fatalf("check failed: %v\n%s", err, sb.String())
		}
		var fd *ast.FuncDecl
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				fd = fn
				break
			}
		}
		b := LowerFunc(info, pkg, fd)
		cachedB := NewPkgCache(info, pkg, []*ast.File{file}).FuncBody(fd)

		var wantGoto, wantNestedGoto, wantLabel, wantFT, wantLabBr, wantDefer, wantGo bool
		var walkAST func(n ast.Node, inLit bool)
		walkAST = func(n ast.Node, inLit bool) {
			if n == nil {
				return
			}
			switch s := n.(type) {
			case *ast.FuncLit:
				if s.Type != nil {
					walkAST(s.Type, true)
				}
				if s.Body != nil {
					for _, st := range s.Body.List {
						walkAST(st, true)
					}
				}
				return
			case *ast.LabeledStmt:
				if !inLit {
					wantLabel = true
				}
			case *ast.DeferStmt:
				if !inLit {
					wantDefer = true
				}
			case *ast.GoStmt:
				if !inLit {
					wantGo = true
				}
			case *ast.BranchStmt:
				if s.Tok == token.GOTO {
					if inLit {
						wantNestedGoto = true
					} else {
						wantGoto = true
					}
				}
				if !inLit && s.Tok == token.FALLTHROUGH {
					wantFT = true
				}
				if !inLit && s.Label != nil {
					wantLabBr = true
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == nil || ch == n {
					return ch == n
				}
				walkAST(ch, inLit)
				return false
			})
		}
		walkAST(fd.Body, false)

		for _, got := range []*Body{b, cachedB} {
			if got.HasGoto != wantGoto || got.HasNestedGoto != wantNestedGoto ||
				got.HasGotoAnywhere() != (wantGoto || wantNestedGoto) ||
				got.HasLabel != wantLabel || got.HasFallthrough != wantFT ||
				got.HasLabeledBranch != wantLabBr || got.HasDefer != wantDefer || got.HasGo != wantGo {
				rt.Fatalf("oracle mismatch on:\n%s\ngot: %+v", sb.String(), got)
			}
		}
	})
}

func TestVarWriteInfosPlaceEntersInteriorAndMentionsMatrix(t *testing.T) {
	const src = `package p

type Box[T any] struct {
	val T
	ptr *int
}

type Counter struct{ n int }

func (c *Counter) Inc() { c.n++ }

var (
	CleanGlobal      = []int{1, 2}
	MutatedGlobal    = []int{3}
	ZeroGlobal       []int
	AutoAddrGlobal   = Counter{n: 1}
	ExplicitAddrGlob = 7
	ChanGlobal       = make(chan int, 1)
	BuiltinMutGlobal = map[string]int{"a": 1}
	StrCopyGlobal    = "hello"
)

func Ops(in *Box[int]) int {
	MutatedGlobal[0] = 9
	AutoAddrGlobal.Inc()
	_ = &ExplicitAddrGlob
	ChanGlobal <- 1
	delete(BuiltinMutGlobal, "a")
	clear([]byte(StrCopyGlobal))
	cleanLocal := 42
	mutLocal := 1
	mutLocal++
	box := Box[int]{val: cleanLocal}
	fn := func() int {
		return in.val + box.val
	}
	res := func() int {
		return cleanLocal
	}()
	p := &in.ptr
	_ = p
	return fn() + res + mutLocal
}
`
	_, file, pkg, info := mustTypecheck(t, src)
	cache := NewPkgCache(info, pkg, []*ast.File{file})

	cleanGV := pkg.Scope().Lookup("CleanGlobal").(*types.Var)
	mutGVVar := pkg.Scope().Lookup("MutatedGlobal").(*types.Var)
	zeroGV := pkg.Scope().Lookup("ZeroGlobal").(*types.Var)
	autoAddrGV := pkg.Scope().Lookup("AutoAddrGlobal").(*types.Var)
	explicitAddrGV := pkg.Scope().Lookup("ExplicitAddrGlob").(*types.Var)
	chanGV := pkg.Scope().Lookup("ChanGlobal").(*types.Var)
	builtinMutGV := pkg.Scope().Lookup("BuiltinMutGlobal").(*types.Var)
	strCopyGV := pkg.Scope().Lookup("StrCopyGlobal").(*types.Var)

	if initV, ok := cache.SingleWritePkgGlobalInit(cleanGV); !ok || initV == nil {
		t.Fatalf("CleanGlobal SingleWritePkgGlobalInit = (%v, %v), want non-nil, true", initV, ok)
	}
	if cache.VarHasExplicitWriteOrAddr(cleanGV) {
		t.Fatal("CleanGlobal unexpectedly reported written/addressed")
	}
	if initV, ok := cache.SingleWritePkgGlobalInit(strCopyGV); !ok || initV == nil || cache.VarHasExplicitWriteOrAddr(strCopyGV) {
		t.Fatalf("StrCopyGlobal should remain clean across fresh []byte(StrCopyGlobal) copy: (%v, %v)", initV, ok)
	}
	for _, hazardGV := range []*types.Var{mutGVVar, autoAddrGV, explicitAddrGV, chanGV, builtinMutGV} {
		if _, ok := cache.SingleWritePkgGlobalInit(hazardGV); ok || !cache.VarHasExplicitWriteOrAddr(hazardGV) {
			t.Fatalf("%s should reject SingleWritePkgGlobalInit and report written/addressed", hazardGV.Name())
		}
	}
	if _, ok := cache.SingleWritePkgGlobalInit(zeroGV); ok || cache.VarHasExplicitWriteOrAddr(zeroGV) {
		t.Fatal("ZeroGlobal should reject SingleWritePkgGlobalInit (no initializer) while having zero post-decl writes")
	}

	opsFD := findFuncDecl(t, file, "Ops")
	opsBody := cache.FuncBody(opsFD)
	var cleanLocal, mutLocal *types.Var
	for id, obj := range info.Defs {
		if id.Name == "cleanLocal" {
			cleanLocal = obj.(*types.Var)
		} else if id.Name == "mutLocal" {
			mutLocal = obj.(*types.Var)
		}
	}
	if _, ok := cache.SingleWriteLocalInit(opsBody, cleanLocal); !ok {
		t.Fatal("cleanLocal SingleWriteLocalInit = false, want true")
	}
	if _, ok := cache.SingleWriteLocalInit(opsBody, mutLocal); ok || !cache.VarHasExplicitWriteOrAddr(mutLocal) {
		t.Fatal("mutLocal should reject SingleWriteLocalInit and report written")
	}

	boxOrigin := pkg.Scope().Lookup("Box").Type().(*types.Named)
	valField := boxOrigin.Underlying().(*types.Struct).Field(0)
	if !BodyMentionsVar(opsBody, valField) {
		t.Fatal("BodyMentionsVar missed instantiated generic struct field Box.val")
	}
	if !BodyMentionsVar(opsBody, cleanLocal) {
		t.Fatal("BodyMentionsVar missed cleanLocal inside closure/IIFE")
	}
	if !BodyMentionsVars(opsBody, map[*types.Var]bool{valField: true}) || BodyMentionsVars(opsBody, nil) {
		t.Fatal("BodyMentionsVars failed positive or empty-target check")
	}
	if !OpMentionsVars(&opsBody.Ops[0], map[*types.Var]bool{mutGVVar: true}) {
		t.Fatal("OpMentionsVars missed MutatedGlobal write")
	}
	if !ValueMentionsVars(opsBody.Ops[len(opsBody.Ops)-1].Results[0], map[*types.Var]bool{mutLocal: true}) {
		t.Fatal("ValueMentionsVars missed mutLocal in return expression")
	}

	// PlaceEntersInterior: `MutatedGlobal[0]` crosses 1 hop on a slice header (single-hop header -> false),
	// whereas `&in.ptr` dereferences `*Box` (1 hop) and projects `.ptr`; dereferencing `*in.ptr` would cross 2 hops.
	sliceElemDst := opsBody.Ops[0].Dsts[0]
	if PlaceEntersInterior(sliceElemDst, false) {
		t.Fatal("PlaceEntersInterior(slice[0], false) = true, want false (1st hop of slice header)")
	}
	if !PlaceEntersInterior(sliceElemDst, true) {
		t.Fatal("PlaceEntersInterior(slice[0], true) = false, want true (container write beyond 1st hop)")
	}

	var syncCount, allCount int
	VisitSyncAndIIFEOps(opsBody, func(*Op) { syncCount++ })
	VisitAllOps(opsBody, func(*Op) { allCount++ })
	if allCount <= syncCount {
		t.Fatalf("VisitAllOps (%d) should exceed VisitSyncAndIIFEOps (%d) due to uncalled closure", allCount, syncCount)
	}
}

func TestTypeExpressionFuncLitIndexingAndPromotedEmbeddedPtrAliases(t *testing.T) {
	const src = `package p

import "unsafe"

type Inner struct{ ptr *int }
type Holder struct{ in *Inner }
type Outer struct{ *Holder }

type NestedSig [unsafe.Sizeof(func(a [unsafe.Sizeof(func() {
	goto InnerLbl
InnerLbl:
})]byte) {})]byte

var VarTypeLit [unsafe.Sizeof(func(q *Inner) (out int) {
	var p *Inner
	var a any = p
	_ = a
	return 0
})]byte

func LocalTypeExprGoto(xs []int) {
	for range xs {
		_ = [unsafe.Sizeof(func() {
			goto LocalLbl
		LocalLbl:
		})]byte{}
	}
}

func LinkViaPromotedEmbeddedPtr() {
	h := &Holder{}
	o := &Outer{}
	in := &Inner{}
	o.Holder = h
	o.in = in
}
`
	_, file, pkg, info := mustTypecheck(t, src)
	cache := NewPkgCache(info, pkg, []*ast.File{file})

	// Every FuncLit anywhere in file (type decls, nested FuncLit signatures,
	// var ValueSpec.Type, and expression types) must be pre-indexed with full
	// LowerFuncLit metadata and zero cache misses on both LitBody(lit) and Body(lit.Body).
	litCount := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		litCount++
		b1 := cache.LitBody(lit)
		b2 := cache.Body(lit.Body)
		if b1 == nil || b1 != b2 || b1.FuncLit != lit || b1.ScopeStart != lit.Pos() || cache.MissCount != 0 {
			t.Fatalf("FuncLit #%d not pre-indexed cleanly: b1=%+v b2=%+v MissCount=%d", litCount, b1, b2, cache.MissCount)
		}
		return true
	})
	if litCount != 4 {
		t.Fatalf("visited %d FuncLits, want 4", litCount)
	}

	localTypeGotoFD := findFuncDecl(t, file, "LocalTypeExprGoto")
	for _, b := range []*Body{cache.FuncBody(localTypeGotoFD), LowerFunc(info, pkg, localTypeGotoFD)} {
		if !b.HasNestedGoto || !b.HasGotoAnywhere() || b.HasGoto || len(b.Ops) != 1 || b.Ops[0].RangeBody == nil || !b.Ops[0].RangeBody.HasNestedGoto {
			t.Fatalf("LocalTypeExprGoto hazard flags = %+v, want HasNestedGoto=true on both func and RangeBody", b)
		}
	}

	// 2-hop write through promoted embedded pointer (`o.in = in` on `*Outer -> *Holder -> in`)
	// mutates `h.in` and must link `h` and `in` in BuildLocalMemAliases.
	linkFD := findFuncDecl(t, file, "LinkViaPromotedEmbeddedPtr")
	linkBody := cache.FuncBody(linkFD)
	adj := BuildScopedMemAliases(linkBody, func(types.Object) bool { return true }, func(types.Type) bool { return true })
	var hVar, inVar *types.Var
	for id, obj := range info.Defs {
		v, ok := obj.(*types.Var)
		if !ok || v.IsField() {
			continue
		}
		switch id.Name {
		case "h":
			hVar = v
		case "in":
			inVar = v
		}
	}
	if hVar == nil || inVar == nil || !adj[inVar][hVar] || !adj[hVar][inVar] {
		t.Fatalf("BuildLocalMemAliases missed 2-hop promoted embedded pointer write o.in = in: adj=%v", adj)
	}
}
