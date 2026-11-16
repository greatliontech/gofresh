package flowir

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"testing"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

func TestLowerNilAndBoundarySafety(t *testing.T) {
	if got := LowerFunc(nil, nil, nil); got != nil {
		t.Fatalf("LowerFunc(nil) = %+v, want nil", got)
	}
	if got := LowerFuncLit(nil, nil, nil); got != nil {
		t.Fatalf("LowerFuncLit(nil) = %+v, want nil", got)
	}
	if got := LowerNode(nil, nil, nil); got != nil {
		t.Fatalf("LowerNode(nil) = %+v, want nil", got)
	}

	var nilBody *Body
	if nilBody.OwnsVar(nil) {
		t.Fatal("nil Body.OwnsVar(nil) = true, want false")
	}
	if !nilBody.ForEachSyncOp(func(*Op) bool { return false }) {
		t.Fatal("nil Body.ForEachSyncOp = false, want true")
	}

	var nilVal *Value
	if !nilVal.ForEachChildValue(func(*Value) bool { return false }) {
		t.Fatal("nil Value.ForEachChildValue = false, want true")
	}
	visited := false
	nilVal.WalkValues(func(*Value) bool { visited = true; return true })
	if visited {
		t.Fatal("nil Value.WalkValues visited callback")
	}
	if idx, ok := nilVal.ParamIndexForArg(0); ok || idx != 0 {
		t.Fatalf("nil Value.ParamIndexForArg(0) = (%d, %v), want (0, false)", idx, ok)
	}

	var nilOp *Op
	if !nilOp.ForEachAssignPair(func(int, Place, bool, *Value) bool { return false }) {
		t.Fatal("nil Op.ForEachAssignPair = false, want true")
	}

	if adj := BuildLocalMemAliases(nil, nil, nil); len(adj) != 0 {
		t.Fatalf("BuildLocalMemAliases(nil) = %+v, want empty", adj)
	}
}

func TestLowerConstructMatrix(t *testing.T) {
	const preamble = `package p

type inner struct {
	v int
	s []int
}

func (in inner) ValM(x int) int  { return in.v + x }
func (in *inner) PtrM(x int) int { return in.v + x }

type valBox struct {
	inner
	m   map[string]int
	arr [4]int
	pa  *[4]int
	fn  func(int) int
}

type ptrBox struct {
	*inner
}

const pkgConst = 19

var pkgGlobal = []int{1, 2, 3}

func plainOne(x int) int               { return x + 1 }
func plainTwo(x int) (int, bool)       { return x, x > 0 }
func plainVar(tag string, xs ...int) int { return len(tag) + len(xs) }
func genId[T any](v T) T               { return v }
func genPair[A, B any](a A, b B) A     { _ = b; return a }
func makePtr() *int                    { x := 3; return &x }
func makeSeq(yield func(int) bool)     { _ = yield(1) }
`

	cases := []struct {
		name  string
		decls string
		check func(t *testing.T, file *ast.File, pkg *types.Package, info *types.Info)
	}{
		{
			name: "roots_and_projections",
			decls: `
func Target[S ~[]int, M ~map[string]int](param S, gm M, vb valBox, pb ptrBox, pp **int) (namedRes int) {
	local := pkgGlobal
	fnRef := plainOne
	_ = fnRef
	_ = pkgConst
	_ = local == nil
	_ = vb.v
	_ = pb.v
	_ = (&vb).s[0]
	_ = gm["k"]
	_ = param[0:1]
	_ = param[0:1:1]
	_ = vb.pa[1:3]
	_ = vb.arr[1:3]
	_ = **pp
	*makePtr() = 11
	closure := func() int {
		return len(local) + len(param) + namedRes
	}
	namedRes = closure()
	return
}
`,
			check: func(t *testing.T, file *ast.File, pkg *types.Package, info *types.Info) {
				b := LowerFunc(info, pkg, findFuncDecl(t, file, "Target"))
				if b == nil || len(b.Results) != 1 || b.Results[0] == nil {
					t.Fatalf("unexpected Body signature metadata: %+v", b)
				}
				seenRoots := map[RootKind]bool{}
				seenProjs := map[ProjKind]bool{}
				seenValAddrSlice := false
				seenNakedReturn := false
				var closureBody *Body

				b.ForEachSyncOp(func(op *Op) bool {
					if op.Kind == OpReturn && op.IsNaked {
						seenNakedReturn = true
					}
					for _, d := range op.Dsts {
						seenRoots[d.Root] = true
						for _, pr := range d.Projs {
							seenProjs[pr.Kind] = true
						}
					}
					for _, s := range op.Srcs {
						s.WalkValues(func(v *Value) bool {
							if v.Kind == ValPlace {
								seenRoots[v.Place.Root] = true
								for _, pr := range v.Place.Projs {
									seenProjs[pr.Kind] = true
								}
							}
							if v.Kind == ValAddrOf && v.IsArraySlice {
								seenValAddrSlice = true
							}
							if v.Kind == ValMakeClosure {
								closureBody = v.Closure
							}
							return true
						})
					}
					return true
				})

				for _, wantRoot := range []RootKind{RootLocal, RootParam, RootResult, RootPkgGlobal, RootFunc, RootBlank, RootTransient} {
					if !seenRoots[wantRoot] {
						t.Fatalf("missing RootKind %v in %+v", wantRoot, seenRoots)
					}
				}
				for _, wantProj := range []ProjKind{ProjField, ProjIndex, ProjSlice, ProjDeref} {
					if !seenProjs[wantProj] {
						t.Fatalf("missing ProjKind %v in %+v", wantProj, seenProjs)
					}
				}
				if !seenValAddrSlice {
					t.Fatal("expected value-array slice ValAddrOf{IsArraySlice: true}")
				}
				if !seenNakedReturn {
					t.Fatal("expected naked return OpReturn{IsNaked: true}")
				}
				if closureBody == nil || len(closureBody.FreeVars) != 3 {
					t.Fatalf("expected closure FreeVars of size 3, got %+v", closureBody)
				}
				outer := false
				closureBody.ForEachSyncOp(func(op *Op) bool {
					for _, r := range op.Results {
						r.WalkValues(func(v *Value) bool {
							if v.Kind == ValPlace && v.Place.Root == RootOuterVar {
								outer = true
							}
							return true
						})
					}
					return true
				})
				if !outer {
					t.Fatal("expected RootOuterVar inside nested closure")
				}
			},
		},
		{
			name: "calls_allocs_conversions_and_control_flow",
			decls: `
func (b *valBox) ExerciseAll(ch chan int, anyVal any, str string) int {
	var zeroSlice []int
	const localConst = 3
	a, ok := plainTwo(localConst)
	if initV := plainOne(a); ok && initV == 4 {
		a += 2
		a++
	} else {
		a = genId[int](a) + genPair[int, string](a, str)
	}
	_ = plainVar("tag", 1, 2, 3)
	_ = plainVar("spread", zeroSlice...)
	_ = b.ValM(1)
	_ = b.PtrM(2)
	_ = (*inner).PtrM(&b.inner, 3)
	_ = b.fn(4)
	iife := (func(v int) int { return v + 1 })(a)
	mkSlice := make([]int, 2, 4)
	mkSlice = append(mkSlice, len(str))
	mkMap := make(map[string]*inner, 2)
	mkMap["k"] = &inner{v: iife}
	elided := []*inner{{v: 1, s: mkSlice}}
	pZero := new(int)
	pExpr := new(iife)
	conv := []byte(str)
	asserted, _ := anyVal.([]int)
	_, _, _, _, _ = elided, pZero, pExpr, conv, asserted

	select {
	case ch <- a:
	case got := <-ch:
		a = got
	default:
	}

	for i := 0; i < 1; i++ {
		if i == 9 {
			continue
		}
		break
	}
	for k, v := range mkSlice {
		_, _ = k, v
	}
	for v := range makeSeq {
		_ = v
	}
	switch tag := a; tag {
	case 1, 2:
		a = 3
	default:
	}
	go plainOne(a)
	defer plainOne(a)
	return a
}
`,
			check: func(t *testing.T, file *ast.File, pkg *types.Package, info *types.Info) {
				fd := findFuncDecl(t, file, "ExerciseAll")
				b := LowerFunc(info, pkg, fd)
				if b == nil || b.Recv == nil {
					t.Fatalf("expected non-nil method Body and Recv: %+v", b)
				}
				callKinds := map[CallKind]bool{}
				allocKinds := map[AllocKind]bool{}
				assignKinds := map[AssignKind]bool{}
				opKinds := map[OpKind]bool{}

				var walkBodyAll func(*Body)
				walkBodyAll = func(cur *Body) {
					if cur == nil {
						return
					}
					for i := range cur.Ops {
						op := &cur.Ops[i]
						opKinds[op.Kind] = true
						if op.Kind == OpAssign {
							assignKinds[op.AssignKind] = true
							if op.RangeBody != nil {
								walkBodyAll(op.RangeBody)
							}
						}
						visitVal := func(v *Value) {
							if v == nil {
								return
							}
							v.WalkValues(func(sub *Value) bool {
								if sub.Kind == ValInvalid {
									t.Fatalf("unexpected ValInvalid in valid Go AST: %#v", sub.Raw)
								}
								if sub.Kind == ValCall {
									callKinds[sub.CallKind] = true
									if sub.IIFE != nil {
										walkBodyAll(sub.IIFE)
									}
								}
								if sub.Kind == ValAllocFresh {
									allocKinds[sub.AllocKind] = true
								}
								if sub.Kind == ValMakeClosure && sub.Closure != nil {
									walkBodyAll(sub.Closure)
								}
								return true
							})
						}
						for _, d := range op.Dsts {
							d.ForEachChildValue(func(cv *Value) bool { visitVal(cv); return true })
						}
						for _, s := range op.Srcs {
							visitVal(s)
						}
						visitVal(op.SwitchSrc)
						visitVal(op.ChanVal)
						visitVal(op.SendVal)
						for _, r := range op.Results {
							visitVal(r)
						}
						visitVal(op.Call)
						visitVal(op.Expr)
					}
				}
				walkBodyAll(b)

				for _, ck := range []CallKind{CallPlain, CallMethod, CallBuiltin, CallIndirect, CallIIFE} {
					if !callKinds[ck] {
						t.Fatalf("missing CallKind %v in %+v", ck, callKinds)
					}
				}
				for _, ak := range []AllocKind{AllocCompositeLit, AllocMake, AllocBuiltinNewType, AllocBuiltinNewExpr} {
					if !allocKinds[ak] {
						t.Fatalf("missing AllocKind %v in %+v", ak, allocKinds)
					}
				}
				for _, ask := range []AssignKind{AssignPlain, AssignMulti, AssignCompound, AssignIncDec, AssignZeroDecl, AssignRange} {
					if !assignKinds[ask] {
						t.Fatalf("missing AssignKind %v in %+v", ask, assignKinds)
					}
				}
				for _, ok := range []OpKind{OpAssign, OpChanSend, OpReturn, OpDefer, OpGo, OpBranch, OpExpr} {
					if !opKinds[ok] {
						t.Fatalf("missing OpKind %v in %+v", ok, opKinds)
					}
				}

				// Verify LowerNode dispatches across BlockStmt, Stmt, and Expr.
				if blkB := LowerNode(info, pkg, fd.Body); blkB == nil || len(blkB.Ops) == 0 {
					t.Fatalf("LowerNode(*ast.BlockStmt) failed: %+v", blkB)
				}
				if stmtB := LowerNode(info, pkg, fd.Body.List[0]); stmtB == nil || len(stmtB.Ops) == 0 {
					t.Fatalf("LowerNode(ast.Stmt) failed: %+v", stmtB)
				}
				retStmt := fd.Body.List[len(fd.Body.List)-1].(*ast.ReturnStmt)
				if exprB := LowerNode(info, pkg, retStmt.Results[0]); exprB == nil || len(exprB.Ops) != 1 || exprB.Ops[0].Kind != OpExpr {
					t.Fatalf("LowerNode(ast.Expr) failed: %+v", exprB)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, file, pkg, info := mustTypecheck(t, preamble+tc.decls)
			tc.check(t, file, pkg, info)
		})
	}
}

func generateValidFlowIRProgram(rt *rapid.T) string {
	isGeneric := rapid.Bool().Draw(rt, "isGeneric")
	isMethod := !isGeneric && rapid.Bool().Draw(rt, "isMethod")
	namedResult := rapid.Bool().Draw(rt, "namedResult")

	sigHeader := "func Generated(pSlice []int, pMap map[string][]int, pAny any)"
	if isGeneric {
		sigHeader = "func Generated[S ~[]int](pSlice S, pMap map[string][]int, pAny any)"
	} else if isMethod {
		if rapid.Bool().Draw(rt, "ptrRecv") {
			sigHeader = "func (r * box) Generated(pSlice []int, pMap map[string][]int, pAny any)"
		} else {
			sigHeader = "func (r box) Generated(pSlice []int, pMap map[string][]int, pAny any)"
		}
	}
	if namedResult {
		sigHeader += " (res []int)"
	} else {
		sigHeader += " []int"
	}

	stmtChoices := []string{
		"s1 = append(s1, len(pSlice))",
		"copy(s2, pSlice)",
		"s2 = arr[:]",
		"ptr = &scalar; ch <- ptr",
		"pNewT := new([]int); _ = pNewT",
		"pNewE := new(s1); s2 = *pNewE",
		"mLocal[\"k\"] = s1",
		"v, ok := pMap[\"x\"]; if ok { s2 = v }",
		"switch tv := pAny.(type) { case []int: s2 = tv; case int: scalar += tv; default: _ = tv }",
		"for i, elem := range pSlice { scalar += i + elem }",
		"cl := func() int { inner := func() int { return len(s1) + scalar }; return inner() }; scalar += cl()",
		"iifeOut := (func(in []int) []int { return in })(s1); s2 = iifeOut",
		"go func(xs []int) { _ = len(xs) }(s1)",
		"defer func() { _ = len(s2) }()",
		"takeTwo(s1, s2)",
		"localBox.PtrTouch(s1)",
		"(*box).PtrTouch(&localBox, s2)",
		"elided := []*box{{buf: s1}}; s2 = elided[0].buf",
	}

	nStmts := rapid.IntRange(2, 9).Draw(rt, "nStmts")
	bodyLines := ""
	for i := 0; i < nStmts; i++ {
		pick := rapid.SampledFrom(stmtChoices).Draw(rt, fmt.Sprintf("stmt_%d", i))
		if rapid.Bool().Draw(rt, fmt.Sprintf("wrapIf_%d", i)) {
			bodyLines += fmt.Sprintf("\tif scalar >= 0 {\n\t\t%s\n\t}\n", pick)
		} else {
			bodyLines += fmt.Sprintf("\t{\n\t\t%s\n\t}\n", pick)
		}
	}

	retLine := "\treturn s2\n"
	if namedResult && rapid.Bool().Draw(rt, "nakedReturn") {
		retLine = "\tres = s2\n\treturn\n"
	}

	return fmt.Sprintf(`package p

type box struct {
	buf []int
	val int
}

func (b *box) PtrTouch(in []int) {
	if len(in) > 0 {
		b.val = in[0]
	}
}

func takeTwo(a, b []int) int {
	return len(a) + len(b)
}

%s {
	scalar := 1
	var arr [4]int
	s1 := make([]int, 2, 4)
	s2 := make([]int, 2)
	mLocal := make(map[string][]int)
	ptr := &scalar
	ch := make(chan *int, 4)
	localBox := box{buf: s1, val: scalar}
	_, _, _, _, _, _, _ = arr, s1, s2, mLocal, ptr, ch, localBox
%s%s}
`, sigHeader, bodyLines, retLine)
}

func assertAliasGraphLaws(t *testing.T, label string, adj map[types.Object]map[types.Object]bool, isLocal func(types.Object) bool) {
	t.Helper()
	for u, nbrs := range adj {
		if !isLocal(u) {
			t.Fatalf("%s: non-local object %v in alias graph", label, u)
		}
		if nbrs[u] {
			t.Fatalf("%s: self-loop on %v", label, u)
		}
		for v := range nbrs {
			if !isLocal(v) {
				t.Fatalf("%s: non-local neighbor %v from %v", label, v, u)
			}
			if !adj[v][u] {
				t.Fatalf("%s: asymmetric edge %v -> %v", label, u, v)
			}
		}
	}
}

func assertAliasSubset(t *testing.T, subName, supName string, sub, sup map[types.Object]map[types.Object]bool) {
	t.Helper()
	for u, nbrs := range sub {
		for v := range nbrs {
			if !sup[u][v] {
				t.Fatalf("%s edge (%v, %v) missing from superset %s", subName, u, v, supName)
			}
		}
	}
}

func TestRapidFlowIRStructuralAndAliasInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		src := generateValidFlowIRProgram(rt)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "gen.go", src, parser.ParseComments)
		if err != nil {
			rt.Fatalf("generated invalid syntax: %v\n%s", err, src)
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
		pkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/p", fset, []*ast.File{file}, info)
		if err != nil {
			rt.Fatalf("generated ill-typed code: %v\n%s", err, src)
		}
		var fd *ast.FuncDecl
		for _, d := range file.Decls {
			if cand, ok := d.(*ast.FuncDecl); ok && cand.Name.Name == "Generated" {
				fd = cand
				break
			}
		}
		if fd == nil {
			rt.Fatal("missing Generated FuncDecl")
		}

		b1 := LowerFunc(info, pkg, fd)
		b2 := LowerFunc(info, pkg, fd)
		if b1 == nil || b2 == nil || !reflect.DeepEqual(b1.FreeVars, b2.FreeVars) || len(b1.Ops) != len(b2.Ops) {
			rt.Fatalf("non-deterministic LowerFunc")
		}

		// Verify FreeVars vs OwnsVar disjointness + upward bubbling + zero Invalid kinds.
		var callExprs []*ast.CallExpr
		var checkBody func(cur *Body)
		checkBody = func(cur *Body) {
			if cur == nil {
				return
			}
			for fv := range cur.FreeVars {
				if cur.OwnsVar(fv) {
					rt.Fatalf("body owns var %v yet lists it in FreeVars", fv)
				}
			}
			for i := range cur.Ops {
				op := &cur.Ops[i]
				if op.Kind == 0 {
					rt.Fatal("zero OpKind")
				}
				if op.Kind == OpAssign {
					op.ForEachAssignPair(func(_ int, dst Place, _ bool, _ *Value) bool {
						if dst.Root == RootInvalid {
							rt.Fatalf("RootInvalid on assigned dst: %#v", dst.Raw)
						}
						return true
					})
					if op.RangeBody != nil {
						checkBody(op.RangeBody)
					}
				}
				checkVal := func(v *Value) {
					if v == nil {
						return
					}
					v.WalkValues(func(sub *Value) bool {
						if sub.Kind == ValInvalid {
							rt.Fatalf("ValInvalid on valid Go expression: %#v", sub.Raw)
						}
						if sub.Kind == ValPlace && sub.Place.Root == RootInvalid {
							rt.Fatalf("RootInvalid on ValPlace: %#v", sub.Raw)
						}
						if sub.Kind == ValCall && sub.CallAST != nil {
							callExprs = append(callExprs, sub.CallAST)
						}
						if sub.Kind == ValMakeClosure && sub.Closure != nil {
							for cfv := range sub.Closure.FreeVars {
								if !cur.OwnsVar(cfv) && !cur.FreeVars[cfv] {
									rt.Fatalf("free var %v of child closure did not bubble to enclosing FreeVars", cfv)
								}
							}
							checkBody(sub.Closure)
						}
						if sub.Kind == ValCall && sub.IIFE != nil {
							for cfv := range sub.IIFE.FreeVars {
								if !cur.OwnsVar(cfv) && !cur.FreeVars[cfv] {
									rt.Fatalf("free var %v of child IIFE did not bubble to enclosing FreeVars", cfv)
								}
							}
							checkBody(sub.IIFE)
						}
						return true
					})
				}
				for _, d := range op.Dsts {
					d.ForEachChildValue(func(cv *Value) bool { checkVal(cv); return true })
				}
				for _, s := range op.Srcs {
					checkVal(s)
				}
				checkVal(op.SwitchSrc)
				checkVal(op.ChanVal)
				checkVal(op.SendVal)
				for _, r := range op.Results {
					checkVal(r)
				}
				checkVal(op.Call)
				checkVal(op.Expr)
			}
		}
		checkBody(b1)

		// Verify ForEachSyncOp never visits OpGo inner closure ops.
		b1.ForEachSyncOp(func(op *Op) bool {
			if op.Kind == 0 {
				rt.Fatal("zero OpKind in ForEachSyncOp")
			}
			return true
		})

		// Verify alias hierarchy: Local ⊆ Scoped ⊆ Enclosing, and EnclosingExcept(E) ⊆ Enclosing.
		localAdj := BuildLocalMemAliases(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
		scopedAdj := BuildScopedMemAliases(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
		enclAdj := BuildEnclosingMemAliases(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
		enclEmptyExcept := BuildEnclosingMemAliasesExcept(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut, nil)

		assertAliasGraphLaws(t, "Local", localAdj, syntaxutil.IsLocalVar)
		assertAliasGraphLaws(t, "Scoped", scopedAdj, syntaxutil.IsLocalVar)
		assertAliasGraphLaws(t, "Enclosing", enclAdj, syntaxutil.IsLocalVar)
		assertAliasSubset(t, "Local", "Scoped", localAdj, scopedAdj)
		assertAliasSubset(t, "Scoped", "Enclosing", scopedAdj, enclAdj)
		if !reflect.DeepEqual(enclAdj, enclEmptyExcept) {
			rt.Fatal("BuildEnclosingMemAliasesExcept(nil) differed from BuildEnclosingMemAliases")
		}
		if len(callExprs) > 0 {
			exempt := map[*ast.CallExpr]bool{callExprs[0]: true}
			enclSub := BuildEnclosingMemAliasesExcept(b1, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut, exempt)
			assertAliasGraphLaws(t, "EnclosingExcept", enclSub, syntaxutil.IsLocalVar)
			assertAliasSubset(t, "EnclosingExcept", "Enclosing", enclSub, enclAdj)
		}
	})
}

func canonicalAliasByVarName(info *types.Info, adj map[types.Object]map[types.Object]bool) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	_ = info
	for u, nbrs := range adj {
		if len(nbrs) == 0 {
			continue
		}
		m := map[string]bool{}
		for v := range nbrs {
			m[v.Name()] = true
		}
		out[u.Name()] = m
	}
	return out
}

func TestRapidFlowIRDesugaringEquivalence(t *testing.T) {
	type desugarPair struct {
		sugared   string
		desugared string
	}
	pairs := []desugarPair{
		{
			sugared:   "pb.buf = s1",
			desugared: "(*pb).buf = (s1)",
		},
		{
			sugared:   "s2 = pb.buf",
			desugared: "s2 = ((*pb).buf)",
		},
		{
			sugared:   "pb.PtrTouch(s1)",
			desugared: "(*box).PtrTouch(pb, (s1))",
		},
		{
			sugared:   "vb.PtrTouch(s1)",
			desugared: "(*box).PtrTouch(&vb, s1)",
		},
		{
			sugared:   "items := []*box{{buf: s1}}; s2 = items[0].buf",
			desugared: "items := []*box{&box{buf: (s1)}}; s2 = (*(items[0])).buf",
		},
		{
			sugared:   "copy(s2, s1)",
			desugared: "(copy)((s2), (s1))",
		},
		{
			sugared:   "s2 = append(s2, s1...)",
			desugared: "s2 = (append)((s2), (s1)...)",
		},
	}

	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 5).Draw(rt, "n")
		var bodyA, bodyB string
		for i := 0; i < n; i++ {
			p := rapid.SampledFrom(pairs).Draw(rt, fmt.Sprintf("pair_%d", i))
			bodyA += fmt.Sprintf("\t{\n\t\t%s\n\t}\n", p.sugared)
			bodyB += fmt.Sprintf("\t{\n\t\t%s\n\t}\n", p.desugared)
		}
		buildProg := func(stmts string) string {
			return fmt.Sprintf(`package p

type box struct {
	buf []int
}

func (b *box) PtrTouch(in []int) {
	b.buf = in
}

func Run(s1 []int) []int {
	s2 := make([]int, 2)
	vb := box{}
	pb := &box{}
	_, _, _ = s2, vb, pb
%s	return s2
}
`, stmts)
		}

		_, fileA, pkgA, infoA := mustTypecheck(t, buildProg(bodyA))
		_, fileB, pkgB, infoB := mustTypecheck(t, buildProg(bodyB))
		bA := LowerFunc(infoA, pkgA, findFuncDecl(t, fileA, "Run"))
		bB := LowerFunc(infoB, pkgB, findFuncDecl(t, fileB, "Run"))
		if len(bA.Ops) != len(bB.Ops) {
			rt.Fatalf("op count mismatch across desugaring: %d vs %d", len(bA.Ops), len(bB.Ops))
		}
		adjA := canonicalAliasByVarName(infoA, BuildEnclosingMemAliases(bA, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut))
		adjB := canonicalAliasByVarName(infoB, BuildEnclosingMemAliases(bB, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut))
		if !reflect.DeepEqual(adjA, adjB) {
			rt.Fatalf("alias equivalence broken across surface desugaring:\nsugared:   %+v\ndesugared: %+v\nprogA:\n%s\nprogB:\n%s",
				adjA, adjB, buildProg(bodyA), buildProg(bodyB))
		}
	})
}

func TestRapidFlowIRGenDeclSelectorPosAndShadowedNilInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		shadowNilKind := rapid.IntRange(0, 2).Draw(rt, "shadowNilKind") // 0: predeclared nil, 1: local var nil, 2: local const nil
		nConstSpecs := rapid.IntRange(1, 4).Draw(rt, "nConstSpecs")
		nVarSpecs := rapid.IntRange(1, 4).Draw(rt, "nVarSpecs")

		constLines := "\tcBase = 1 << iota\n"
		wantConstExprOps := 1
		for i := 0; i < nConstSpecs; i++ {
			if rapid.Bool().Draw(rt, fmt.Sprintf("constImplicit_%d", i)) {
				constLines += fmt.Sprintf("\tcImp%d\n", i)
			} else {
				constLines += fmt.Sprintf("\tcExp%d = %d + iota\n", i, i+3)
				wantConstExprOps++
			}
		}

		varLines := ""
		for i := 0; i < nVarSpecs; i++ {
			switch rapid.IntRange(0, 2).Draw(rt, fmt.Sprintf("varKind_%d", i)) {
			case 0:
				varLines += fmt.Sprintf("\tvZero%d []int\n", i)
			case 1:
				varLines += fmt.Sprintf("\tvInit%d = []int{%d}\n", i, i)
			case 2:
				varLines += fmt.Sprintf("\tvPairA%d, vPairB%d = makePair(%d)\n", i, i, i)
			}
		}

		nilSnippet := "\tvar preNil []int = nil\n\t_ = preNil\n"
		switch shadowNilKind {
		case 1:
			nilSnippet = "\tnil := []int{5}\n\t_ = len(nil)\n"
		case 2:
			nilSnippet = "\tconst nil = 77\n\t_ = nil\n"
		}

		src := fmt.Sprintf(`package p

import "slices"

const (
%s)

var (
%s)

func makePair(x int) (int, []int) { return x, []int{x} }

type holder struct {
	items []int
}

func (h *holder) First() int {
	if len(h.items) == 0 {
		return 0
	}
	return h.items[0]
}

func Exercise(in []int) int {
%s	h := &holder{items: slices.Clone[[]int](in)}
	ins := slices.Insert[[]int, int](h.items, 0, cBase)
	return h.First() + len(ins)
}
`, constLines, varLines, nilSnippet)

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "gen.go", src, parser.ParseComments)
		if err != nil {
			rt.Fatalf("parse failed: %v\n%s", err, src)
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
		pkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/p", fset, []*ast.File{file}, info)
		if err != nil {
			rt.Fatalf("typecheck failed: %v\n%s", err, src)
		}

		identAtPos := map[token.Pos]types.Object{}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if obj := syntaxutil.IdentDefOrUse(info, id); obj != nil {
					identAtPos[id.Pos()] = obj
				}
			}
			return true
		})

		verifyPlaceRootPos := func(pl Place) {
			if pl.Obj != nil {
				if !pl.RootPos.IsValid() {
					rt.Fatalf("Place with Obj=%v had invalid RootPos", pl.Obj)
				}
				if gotObj := identAtPos[pl.RootPos]; gotObj != pl.Obj {
					rt.Fatalf("Place.RootPos resolved to %v, want %v", gotObj, pl.Obj)
				}
			}
		}

		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				b := LowerNode(info, pkg, d)
				if b == nil {
					rt.Fatalf("LowerNode(GenDecl %v) returned nil", d.Tok)
				}
				if d.Tok == token.CONST {
					if len(b.Ops) != wantConstExprOps {
						rt.Fatalf("const GenDecl ops = %d, want %d", len(b.Ops), wantConstExprOps)
					}
					for _, op := range b.Ops {
						if op.Kind != OpExpr || op.Expr == nil || !op.Expr.IsConst {
							rt.Fatalf("unexpected const op: %+v", op)
						}
					}
				} else if d.Tok == token.VAR {
					if len(b.Ops) != nVarSpecs {
						rt.Fatalf("var GenDecl ops = %d, want %d", len(b.Ops), nVarSpecs)
					}
					for _, op := range b.Ops {
						for _, dst := range op.Dsts {
							verifyPlaceRootPos(dst)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name != "Exercise" {
					continue
				}
				b := LowerFunc(info, pkg, d)
				sawCloneSel, sawInsertSel, sawMethodSel := false, false, false
				sawIsNil := false
				for i := range b.Ops {
					op := &b.Ops[i]
					for _, dst := range op.Dsts {
						verifyPlaceRootPos(dst)
					}
					checkVal := func(v *Value) {
						if v == nil {
							return
						}
						v.WalkValues(func(sub *Value) bool {
							if sub.Kind == ValPlace {
								verifyPlaceRootPos(sub.Place)
							}
							if sub.Kind == ValAddrOf {
								verifyPlaceRootPos(sub.AddrPlace)
							}
							if sub.IsNil {
								sawIsNil = true
							}
							if sub.Kind == ValCall {
								if sel := sub.CalleeSelector(); sel != nil {
									switch sel.Sel.Name {
									case "Clone":
										sawCloneSel = true
									case "Insert":
										sawInsertSel = true
									case "First":
										sawMethodSel = true
									}
								}
							}
							return true
						})
					}
					for _, s := range op.Srcs {
						checkVal(s)
					}
					for _, r := range op.Results {
						checkVal(r)
					}
					checkVal(op.Expr)
				}
				if !sawCloneSel || !sawInsertSel || !sawMethodSel {
					rt.Fatalf("CalleeSelector missed Clone=%v Insert=%v First=%v", sawCloneSel, sawInsertSel, sawMethodSel)
				}
				wantNil := shadowNilKind == 0
				if sawIsNil != wantNil {
					rt.Fatalf("shadowNilKind=%d: sawIsNil=%v, want %v", shadowNilKind, sawIsNil, wantNil)
				}
			}
		}
	})
}

func FuzzLowerArbitraryGoSource(f *testing.F) {
	seeds := []string{
		`package p; func F(x []int) *[]int { return new(x) }`,
		`package p; type B struct{ x int }; func (b *B) M(y int) { (*B).M(b, y) }`,
		`package p; func G[T any, S ~[4]T](s S) []T { return s[1:3] }`,
		`package p; func H(a any) { switch v := a.(type) { case []int: v[0] = 1; default: _ = v } }`,
		`package p; func Broken(x int) { y := unknownCall(x); *(&y) += ; goto lbl; lbl: }`,
		`package p; func ChanSel(ch chan *int, p *int) { select { case ch <- p: case q := <-ch: _ = q } }`,
		`package p; const ( A = 1 << iota; B ); var ( X, Y = 1, 2; Z []int )`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16<<10 {
			return
		}
		fset := token.NewFileSet()
		file, _ := parser.ParseFile(fset, "fuzz.go", src, parser.ParseComments)
		if file == nil {
			return
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
		cfg := &types.Config{
			Error:    func(error) {},
			Importer: importer.Default(),
		}
		pkg, _ := cfg.Check("example.com/fuzz", fset, []*ast.File{file}, info)
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				b := LowerFunc(info, pkg, node)
				if b != nil {
					adj := BuildEnclosingMemAliases(b, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
					assertAliasGraphLaws(t, "FuzzFuncDecl", adj, syntaxutil.IsLocalVar)
				}
			case *ast.FuncLit:
				b := LowerFuncLit(info, pkg, node)
				if b != nil {
					adj := BuildEnclosingMemAliases(b, syntaxutil.IsLocalVar, refconfine.CallResultHandsOut)
					assertAliasGraphLaws(t, "FuzzFuncLit", adj, syntaxutil.IsLocalVar)
				}
			case *ast.GenDecl, *ast.ValueSpec:
				b := LowerNode(info, pkg, node)
				if b != nil {
					for i := range b.Ops {
						for _, s := range b.Ops[i].Srcs {
							if s != nil {
								_ = s.CalleeSelector()
							}
						}
					}
				}
			case ast.Stmt:
				_ = LowerNode(info, pkg, node)
			case ast.Expr:
				_ = LowerNode(info, pkg, node)
			}
			return true
		})
	})
}
