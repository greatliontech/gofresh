package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type onceMemoRecvState struct {
	pkgConf             *packageConfinementSummary
	ownerNamed          *types.Named
	recvVar             *types.Var
	onceField           *types.Var
	allowMemoAccess     bool
	memoFields          map[*types.Var]bool
	inputFields         map[*types.Var]bool
	allowedAssignNodes  map[ast.Node]bool
	allowedLocalBindOps map[*flowir.Op]bool
	allowedDoLit        *ast.FuncLit
	inputParamDeps      map[syntaxutil.ParamKey]bool
	recvAliases         map[*types.Var]bool
	inputFieldLocals    map[*types.Var]bool
}

// verifyOnceMemoRecvUsesInBody verifies via confinementEngine (confinementModeOnceMemoRecv)
// that b accesses recvVar (and single-def bare local aliases of recvVar) strictly
// through admitted inputFields, sibling *ownerNamed methods, the getter's once.Do
// call, or post-Do memoField returns.
func verifyOnceMemoRecvUsesInBody(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	pkgConf *packageConfinementSummary,
	ownerNamed *types.Named,
	recvVar *types.Var,
	onceField *types.Var,
	allowMemoAccess bool,
	memoFields map[*types.Var]bool,
	inputFields map[*types.Var]bool,
	allowedMemoAssigns []*ast.AssignStmt,
	allowedDoLit *ast.FuncLit,
	b *flowir.Body,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	return verifyOnceMemoRecvUsesWithAliases(
		audited, p, fc, pkgConf, ownerNamed, recvVar, nil, onceField, allowMemoAccess,
		memoFields, inputFields, allowedMemoAssigns, allowedDoLit, b, inputParamDeps,
	)
}

func verifyOnceMemoRecvUsesWithAliases(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	pkgConf *packageConfinementSummary,
	ownerNamed *types.Named,
	recvVar *types.Var,
	parentRecvAliases map[*types.Var]bool,
	onceField *types.Var,
	allowMemoAccess bool,
	memoFields map[*types.Var]bool,
	inputFields map[*types.Var]bool,
	allowedMemoAssigns []*ast.AssignStmt,
	allowedDoLit *ast.FuncLit,
	b *flowir.Body,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	if p == nil || b == nil || recvVar == nil {
		return false
	}
	allowedAssignNodes := make(map[ast.Node]bool, len(allowedMemoAssigns))
	for _, as := range allowedMemoAssigns {
		allowedAssignNodes[as] = true
	}
	recvAliases := make(map[*types.Var]bool, 1+len(parentRecvAliases))
	recvAliases[recvVar] = true
	roots := make(map[types.Object]bool, 1+len(parentRecvAliases))
	roots[recvVar] = true
	for alias := range parentRecvAliases {
		if alias != nil {
			recvAliases[alias] = true
			roots[alias] = true
		}
	}
	eng := &confinementEngine{
		mode:     confinementModeOnceMemoRecv,
		audited:  audited,
		p:        p,
		fc:       fc,
		rootBody: b,
		roots:    roots,
		onceMemo: &onceMemoRecvState{
			pkgConf:             pkgConf,
			ownerNamed:          ownerNamed,
			recvVar:             recvVar,
			onceField:           onceField,
			allowMemoAccess:     allowMemoAccess,
			memoFields:          memoFields,
			inputFields:         inputFields,
			allowedAssignNodes:  allowedAssignNodes,
			allowedLocalBindOps: map[*flowir.Op]bool{},
			allowedDoLit:        allowedDoLit,
			inputParamDeps:      inputParamDeps,
			recvAliases:         recvAliases,
			inputFieldLocals:    map[*types.Var]bool{},
		},
	}
	return eng.run()
}

func (e *confinementEngine) isOnceMemoRecvVar(v *types.Var) bool {
	return v != nil && e.onceMemo.recvAliases[v]
}

func (e *confinementEngine) runOnceMemoRecv() bool {
	st := e.onceMemo
	b := e.rootBody

	defCount := map[*types.Var]int{}
	flowir.VisitAllOps(b, func(op *flowir.Op) {
		if op.Kind == flowir.OpAssign {
			for _, dst := range op.Dsts {
				if dst.IsBareVar() {
					defCount[dst.Obj]++
				}
			}
		}
	})

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain && len(op.Dsts) == 1 && len(op.Srcs) == 1 {
			dst := op.Dsts[0]
			src := op.Srcs[0]
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && defCount[dst.Obj] == 1 && src.Kind == flowir.ValPlace {
				if src.Place.IsBareVar() && st.recvAliases[src.Place.Obj] {
					st.recvAliases[dst.Obj] = true
					e.roots[dst.Obj] = true
					st.allowedLocalBindOps[op] = true
				} else if e.isOnceMemoRecvVar(src.Place.Obj) && len(src.Place.Projs) == 1 &&
					src.Place.Projs[0].Kind == flowir.ProjField && st.inputFields[src.Place.Projs[0].Field] &&
					refconfine.TypeCarriesMutableRef(src.Place.Projs[0].Field.Type()) {
					st.inputFieldLocals[dst.Obj] = true
					st.allowedLocalBindOps[op] = true
				}
			}
		}
		return true
	})

	// Judge any local variables initialized from a mutable-reach inputField via
	// confinementModeBoundValue.
	if len(st.inputFieldLocals) > 0 && b.AST != nil {
		localRoots := make(map[types.Object]bool, len(st.inputFieldLocals))
		for lv := range st.inputFieldLocals {
			localRoots[lv] = true
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		fieldWants := map[syntaxutil.FieldPosKey]bool{}
		elemWants := map[syntaxutil.ElemParamUse]bool{}
		var returns bool
		if !boundValueLeakFreeJudged(e.audited, e.p, e.fc, localRoots, b.AST, wants, &returns, methodWants, fieldWants, elemWants) {
			return false
		}
		if returns || len(fieldWants) > 0 || len(elemWants) > 0 {
			return false
		}
		for mw := range methodWants {
			if mw.Pkg != e.p.Types.Path() || !st.pkgConf.readOnly[mw.Name] {
				return false
			}
		}
		for pw := range wants {
			if !recordOrVerifyOnceMemoParamDep(e.p.Types.Path(), st.pkgConf, pw, st.inputParamDeps) {
				return false
			}
		}
	}

	return e.checkOnceMemoBody(b)
}

func (e *confinementEngine) checkOnceMemoBody(cur *flowir.Body) bool {
	if cur == nil {
		return true
	}
	st := e.onceMemo
	for i := range cur.Ops {
		op := &cur.Ops[i]
		switch op.Kind {
		case flowir.OpAssign:
			if st.allowedAssignNodes[op.StmtAST] {
				for _, src := range op.Srcs {
					if !e.checkOnceMemoValueTree(src, false) {
						return false
					}
				}
				continue
			}
			if st.allowedLocalBindOps[op] {
				continue
			}
			for _, dst := range op.Dsts {
				if e.isOnceMemoRecvVar(dst.Obj) {
					return false
				}
				okDst := true
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					if !e.checkOnceMemoValueTree(cv, false) {
						okDst = false
						return false
					}
					return true
				})
				if !okDst {
					return false
				}
			}
			for _, src := range op.Srcs {
				if !e.checkOnceMemoValueTree(src, false) {
					return false
				}
			}
			if op.RangeBody != nil && !e.checkOnceMemoBody(op.RangeBody) {
				return false
			}
		case flowir.OpReturn:
			for _, r := range op.Results {
				if !e.checkOnceMemoValueTree(r, st.allowMemoAccess) {
					return false
				}
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst != nil && e.isOnceMemoRecvVar(op.SwitchDst) {
				return false
			}
			if !e.checkOnceMemoValueTree(op.SwitchSrc, false) {
				return false
			}
		case flowir.OpChanSend:
			if e.isOnceMemoRecvVar(op.ChanPlace.Obj) {
				return false
			}
			if !e.checkOnceMemoValueTree(op.ChanVal, false) || !e.checkOnceMemoValueTree(op.SendVal, false) {
				return false
			}
		case flowir.OpGo, flowir.OpDefer:
			if op.Call != nil && flowir.ValueMentionsVars(op.Call, st.recvAliases) {
				return false
			}
			if !e.checkOnceMemoValueTree(op.Call, false) {
				return false
			}
		case flowir.OpExpr:
			if !e.checkOnceMemoValueTree(op.Expr, false) {
				return false
			}
		}
	}
	return true
}

func (e *confinementEngine) checkOnceMemoValueTree(rootVal *flowir.Value, allowPostDoMemoReturn bool) bool {
	if rootVal == nil {
		return true
	}
	st := e.onceMemo
	if allowPostDoMemoReturn && rootVal.Kind == flowir.ValPlace &&
		e.isOnceMemoRecvVar(rootVal.Place.Obj) && len(rootVal.Place.Projs) == 1 &&
		rootVal.Place.Projs[0].Kind == flowir.ProjField && st.memoFields[rootVal.Place.Projs[0].Field] {
		return true
	}

	consumedPlaces := map[*flowir.Value]bool{}
	ok := true
	var visit func(v *flowir.Value)
	visit = func(v *flowir.Value) {
		if v == nil || !ok {
			return
		}
		switch v.Kind {
		case flowir.ValInvalid:
			ok = false
			return
		case flowir.ValAddrOf, flowir.ValMethodVal:
			if (v.Kind == flowir.ValAddrOf && e.isOnceMemoRecvVar(v.AddrPlace.Obj)) ||
				(v.Kind == flowir.ValMethodVal && ((v.Recv != nil && flowir.ValueMentionsVars(v.Recv, st.recvAliases)) || (v.HasRecvPlace && e.isOnceMemoRecvVar(v.RecvPlace.Obj)))) {
				ok = false
				return
			}
		case flowir.ValMakeClosure:
			if v.Lit == st.allowedDoLit {
				return
			}
			if v.Closure == nil {
				ok = false
				return
			}
			for fv := range v.Closure.FreeVars {
				if e.isOnceMemoRecvVar(fv) {
					ok = false
					return
				}
			}
			if !verifyOnceMemoRecvUsesWithAliases(
				e.audited, e.p, e.fc, st.pkgConf, st.ownerNamed, st.recvVar, st.recvAliases, nil, false,
				st.memoFields, st.inputFields, nil, nil, v.Closure, st.inputParamDeps,
			) {
				ok = false
				return
			}
			return
		case flowir.ValCall:
			if v.CallKind == flowir.CallIIFE {
				if v.IIFE == nil || !verifyOnceMemoRecvUsesWithAliases(
					e.audited, e.p, e.fc, st.pkgConf, st.ownerNamed, st.recvVar, st.recvAliases, nil, false,
					st.memoFields, st.inputFields, nil, nil, v.IIFE, st.inputParamDeps,
				) {
					ok = false
					return
				}
			}
			if v.CallKind == flowir.CallMethod && st.onceField != nil && v.CalleeFunc != nil &&
				v.CalleeFunc.Pkg() != nil && v.CalleeFunc.Pkg().Path() == "sync" && v.CalleeFunc.Name() == "Do" &&
				len(v.Args) == 1 && v.Args[0].Kind == flowir.ValMakeClosure && v.Args[0].Lit == st.allowedDoLit &&
				v.HasRecvPlace && e.isOnceMemoRecvVar(v.RecvPlace.Obj) && len(v.RecvPlace.Projs) == 1 &&
				v.RecvPlace.Projs[0].Kind == flowir.ProjField && v.RecvPlace.Projs[0].Field == st.onceField {
				if v.Recv != nil {
					consumedPlaces[v.Recv] = true
				}
				return
			}
			if v.CallKind == flowir.CallMethod && v.Recv != nil && v.Recv.Kind == flowir.ValPlace &&
				v.Recv.Place.IsBareVar() && e.isOnceMemoRecvVar(v.Recv.Place.Obj) {
				if v.Selection == nil || len(v.Selection.Index()) != 1 || v.CalleeFunc == nil ||
					v.CalleeFunc.Pkg() != e.p.Types {
					ok = false
					return
				}
				if recvSig, okSig := v.CalleeFunc.Type().(*types.Signature); !okSig || recvSig.Recv() == nil ||
					!syntaxutil.IsPtrToNamed(recvSig.Recv().Type(), st.ownerNamed) {
					ok = false
					return
				}
				consumedPlaces[v.Recv] = true
			}
			for ai, arg := range v.Args {
				if arg == nil || arg.Kind != flowir.ValPlace || !e.isOnceMemoRecvVar(arg.Place.Obj) ||
					len(arg.Place.Projs) != 1 || arg.Place.Projs[0].Kind != flowir.ProjField ||
					!st.inputFields[arg.Place.Projs[0].Field] ||
					!refconfine.TypeCarriesMutableRef(arg.Type) {
					continue
				}
				if v.CallKind == flowir.CallBuiltin && (v.BuiltinName == "len" || v.BuiltinName == "cap") {
					consumedPlaces[arg] = true
					continue
				}
				if v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil && v.CalleeFunc.Origin() == v.CalleeFunc && v.CalleeFunc.Pkg() != nil {
					if isReadOnlyInputSliceStdlibCallee(e.p, v.CalleeFunc) {
						consumedPlaces[arg] = true
						continue
					}
					if !v.Ellipsis {
						if pi, okPI := v.ParamIndexForArg(ai); okPI {
							pk := syntaxutil.ParamKey{
								Func:  syntaxutil.FuncKey{Pkg: v.CalleeFunc.Pkg().Path(), Name: v.CalleeFunc.Name()},
								Index: pi,
							}
							if pk.Valid() && recordOrVerifyOnceMemoParamDep(e.p.Types.Path(), st.pkgConf, pk, st.inputParamDeps) {
								consumedPlaces[arg] = true
								continue
							}
						}
					}
				}
			}
		case flowir.ValConvert:
			if !v.IsTypeAssert && v.Arg != nil && v.Arg.Kind == flowir.ValPlace &&
				e.isOnceMemoRecvVar(v.Arg.Place.Obj) && len(v.Arg.Place.Projs) == 1 &&
				v.Arg.Place.Projs[0].Kind == flowir.ProjField && st.inputFields[v.Arg.Place.Projs[0].Field] &&
				!refconfine.TypeCarriesMutableRef(v.Type) {
				consumedPlaces[v.Arg] = true
			}
		case flowir.ValPlace:
			if consumedPlaces[v] {
				return
			}
			if e.isOnceMemoRecvVar(v.Place.Obj) {
				if len(v.Place.Projs) == 0 {
					ok = false
					return
				}
				p0 := v.Place.Projs[0]
				if p0.Kind != flowir.ProjField || !st.inputFields[p0.Field] || refconfine.TypeCarriesMutableRef(v.Type) {
					ok = false
					return
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			visit(ch)
			return ok
		})
	}
	visit(rootVal)
	return ok
}
