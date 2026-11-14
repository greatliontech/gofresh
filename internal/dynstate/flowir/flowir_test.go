package flowir

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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
