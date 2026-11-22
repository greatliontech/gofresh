package dynstate

import (
	"go/ast"
	"go/types"
	"math"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func outflowPlaceProjsAdmitted(projs []flowir.Proj) bool {
	for _, pr := range projs {
		switch pr.Kind {
		case flowir.ProjField:
		case flowir.ProjIndex:
			if pr.BaseType == nil {
				return false
			}
			switch u := types.Unalias(pr.BaseType).Underlying().(type) {
			case *types.Map, *types.Slice, *types.Array, *types.Basic:
			case *types.Pointer:
				if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); !isArr {
					return false
				}
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (a *outflowAnalyzer) foldRootConfinementDeps(ctx *outflowEvalCtx, rRoot types.Object) {
	for pk := range a.objParamDeps[rRoot] {
		ctx.paramDeps[pk] = true
	}
	for mk := range a.objMethodDeps[rRoot] {
		ctx.methodDeps[mk] = true
	}
	for pk := range ctx.resolved.paramDeps[rRoot] {
		ctx.paramDeps[pk] = true
	}
	for mk := range ctx.resolved.methodDeps[rRoot] {
		ctx.methodDeps[mk] = true
	}
}

func (a *outflowAnalyzer) judgeObj(ctx *outflowEvalCtx, obj types.Object, isParam bool) (bool, int) {
	root := a.aliasFind(obj)
	rRoot := a.reachFind(obj)
	if isParam {
		if ctx.insMode {
			if a.paramRebound[obj] || a.captureBroken[obj] || ctx.resolved.poison[rRoot] {
				ctx.localFree[obj] = 3
				return false, math.MaxInt
			}
		} else if a.localBroken[obj] || ctx.resolved.poison[rRoot] {
			ctx.localFree[obj] = 3
			return false, math.MaxInt
		}
	} else if ctx.resolved.poison[rRoot] {
		ctx.localFree[obj] = 3
		return false, math.MaxInt
	}
	for use := range ctx.resolved.uses[rRoot] {
		ctx.useDeps[use] = true
	}
	a.foldRootConfinementDeps(ctx, rRoot)
	switch ctx.localFree[obj] {
	case 2:
		return true, math.MaxInt
	case 3:
		return false, math.MaxInt
	}
	if d, active := ctx.provingDepth[obj]; active && d > 0 {
		return true, d
	}
	if !isParam && a.localBroken[obj] {
		ctx.localFree[obj] = 3
		return false, math.MaxInt
	}
	myDepth := ctx.curDepth + 1
	ctx.curDepth = myDepth
	ctx.provingDepth[obj] = myDepth
	defer func() {
		delete(ctx.provingDepth, obj)
		ctx.curDepth = myDepth - 1
	}()

	objMinCycle := math.MaxInt
	if !isParam {
		for _, src := range a.localSources[obj] {
			okSrc, cyc := a.evalFree(ctx, src)
			if !okSrc {
				ctx.localFree[obj] = 3
				return false, math.MaxInt
			}
			if cyc < objMinCycle {
				objMinCycle = cyc
			}
		}
	}
	for _, stored := range a.sharedWrites[root] {
		okSt, cyc := a.evalFree(ctx, stored)
		if !okSt {
			ctx.localFree[obj] = 3
			return false, math.MaxInt
		}
		if cyc < objMinCycle {
			objMinCycle = cyc
		}
	}
	for _, stored := range a.sharedInsertionWrites[rRoot] {
		okSt, cyc := a.evalFree(ctx, stored)
		if !okSt {
			ctx.localFree[obj] = 3
			return false, math.MaxInt
		}
		if cyc < objMinCycle {
			objMinCycle = cyc
		}
	}
	if objMinCycle >= myDepth {
		ctx.localFree[obj] = 2
		return true, math.MaxInt
	}
	return true, objMinCycle
}

func (a *outflowAnalyzer) evalFree(ctx *outflowEvalCtx, v *flowir.Value) (resOK bool, resCyc int) {
	if ctx.onRefusal != nil {
		defer func() {
			if !resOK {
				ctx.onRefusal(v)
			}
		}()
	}
	if v == nil {
		return false, math.MaxInt
	}
	if v.Type != nil && !refconfine.TypeCarriesSignature(v.Type) {
		return true, math.MaxInt
	}
	minCycle := math.MaxInt
	merge := func(childOK bool, cyc int) bool {
		if !childOK {
			return false
		}
		if cyc < minCycle {
			minCycle = cyc
		}
		return true
	}

	switch v.Kind {
	case flowir.ValScalarLitOrConst:
		return true, math.MaxInt

	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return true, math.MaxInt
		case flowir.AllocBuiltinNewExpr:
			if len(v.Args) != 1 {
				return false, math.MaxInt
			}
			return a.evalFree(ctx, v.Args[0])
		case flowir.AllocCompositeLit:
			for i := range v.CompositeElts {
				if v.CompositeElts[i].MapKey != nil {
					if !merge(a.evalFree(ctx, v.CompositeElts[i].MapKey)) {
						return false, math.MaxInt
					}
				}
				if v.CompositeElts[i].Value != nil {
					if !merge(a.evalFree(ctx, v.CompositeElts[i].Value)) {
						return false, math.MaxInt
					}
				}
			}
			return true, minCycle
		}

	case flowir.ValMakeClosure:
		if v.Lit == nil || v.Closure == nil || a.visitingLits[v.Lit] {
			return false, math.MaxInt
		}
		a.visitingLits[v.Lit] = true
		defer delete(a.visitingLits, v.Lit)
		litCtx := ctx
		if ctx.insMode {
			litCtx = &outflowEvalCtx{
				insMode:       false,
				resolved:      ctx.resolved,
				localFree:     map[types.Object]int{},
				provingDepth:  map[types.Object]int{},
				reachVisiting: ctx.reachVisiting,
				fnDeps:        ctx.fnDeps,
				useDeps:       ctx.useDeps,
				paramDeps:     ctx.paramDeps,
				methodDeps:    ctx.methodDeps,
				onRefusal:     ctx.onRefusal,
			}
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		origin := &rootOriginPolicy{
			verifyLocalOrigins:   true,
			allowEnclosingParams: true,
			settledGlobals:       a.settledGlobals,
			checkCarryingValue: func(sub *flowir.Value) bool {
				okSub, _ := a.evalFree(litCtx, sub)
				return okSub
			},
		}
		if !environmentFreeFuncLitWithOrigin(a.audited, a.p, a.fc, v.Lit, a.fd, wants, methodWants, origin) {
			return false, math.MaxInt
		}
		if !a.classifyWants(wants, methodWants, litCtx.paramDeps, litCtx.methodDeps) {
			return false, math.MaxInt
		}
		for fv := range v.Closure.FreeVars {
			if typeHandsOutReachOrAddr(fv.Type()) {
				fvVal := &flowir.Value{
					Kind: flowir.ValPlace,
					Type: fv.Type(),
					Place: flowir.Place{
						Root: flowir.RootLocal,
						Obj:  fv,
						Type: fv.Type(),
					},
				}
				if !a.checkPlainCallReachArg(litCtx, fvVal, nil, nil, false) {
					return false, math.MaxInt
				}
			}
			if !refconfine.TypeCarriesSignature(fv.Type()) {
				continue
			}
			if a.params[fv] {
				if !merge(a.judgeObj(ctx, fv, true)) {
					return false, math.MaxInt
				}
			} else if syntaxutil.IsLocalVar(fv) {
				if !merge(a.judgeObj(ctx, fv, false)) {
					return false, math.MaxInt
				}
			}
		}
		return true, minCycle

	case flowir.ValPlace:
		if !outflowPlaceProjsAdmitted(v.Place.Projs) {
			return false, math.MaxInt
		}
		switch v.Place.Root {
		case flowir.RootFunc, flowir.RootConstOrNil:
			return true, math.MaxInt
		case flowir.RootParam, flowir.RootLocal, flowir.RootResult:
			obj := v.Place.Obj
			if obj == nil {
				return false, math.MaxInt
			}
			if a.params[obj] {
				return a.judgeObj(ctx, obj, true)
			}
			if syntaxutil.IsLocalVar(obj) {
				return a.judgeObj(ctx, obj, false)
			}
		case flowir.RootTransient:
			if v.Place.Base != nil {
				return a.evalFree(ctx, v.Place.Base)
			}
		}
		return false, math.MaxInt

	case flowir.ValConvert:
		if v.IsTypeAssert || v.Arg == nil || syntaxutil.IsUnsafePointerType(v.Arg.Type) {
			return false, math.MaxInt
		}
		return a.evalFree(ctx, v.Arg)

	case flowir.ValCall:
		switch v.CallKind {
		case flowir.CallBuiltin:
			if v.BuiltinName == "append" {
				for _, arg := range v.Args {
					if !merge(a.evalFree(ctx, arg)) {
						return false, math.MaxInt
					}
				}
				return true, minCycle
			}
			return false, math.MaxInt

		case flowir.CallPlain:
			if v.CalleeFunc == nil || v.IsMethodExprCall {
				return false, math.MaxInt
			}
			calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
			isVP := auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name)
			perArg := make([]map[types.Object]bool, len(v.Args))
			for i, arg := range v.Args {
				if !merge(a.evalFree(ctx, arg)) {
					return false, math.MaxInt
				}
				if !isVP {
					if !a.checkPlainCallReachArg(ctx, arg, v, nil, false) {
						return false, math.MaxInt
					}
					perArg[i] = a.collectMutableArgRoots(arg)
				}
			}
			if !isVP {
				for i := 0; i < len(perArg); i++ {
					for j := i + 1; j < len(perArg); j++ {
						for r := range perArg[i] {
							if perArg[j][r] && !a.params[r] {
								return false, math.MaxInt
							}
						}
					}
				}
				ctx.fnDeps[calleeFK] = true
			}
			return true, minCycle
		}
		return false, math.MaxInt
	}
	return false, math.MaxInt
}

func (a *outflowAnalyzer) checkPlainCallReachArg(
	ctx *outflowEvalCtx,
	arg *flowir.Value,
	currentCall *flowir.Value,
	skipInsertionRoot types.Object,
	allowInsParam bool,
) bool {
	if isPureFreshDataValue(a.settledGlobals, arg) {
		return true
	}
	return checkPureOrFreshValue(arg, valuePurityPolicy{
		allowAppend:          true,
		allowValuePlane:      true,
		allowRuntimeOps:      true,
		allowNonMutableReach: true,
		allowSigLeaf: func(leaf *flowir.Value) bool {
			okArg, _ := a.evalFree(ctx, leaf)
			return okArg
		},
		allowPlace: func(pv *flowir.Value) bool {
			if pv.Place.Root == flowir.RootFunc && !pv.Place.IsMethodExpr {
				return true
			}
			if pv.Place.Root == flowir.RootPkgGlobal {
				return pv.Place.Obj != nil && a.settledGlobals.hasUnembedded(pv.Place.Obj)
			}
			if pv.Place.Root == flowir.RootTransient && pv.Place.Base != nil {
				return a.checkPlainCallReachArg(ctx, pv.Place.Base, currentCall, skipInsertionRoot, allowInsParam)
			}
			if pv.Place.Obj != nil {
				obj := pv.Place.Obj
				if !a.params[obj] && !syntaxutil.IsLocalVar(obj) {
					return false
				}
				isInsParam := allowInsParam && a.params[obj]
				vk := reachVisitKey{obj: obj, allowInsParam: allowInsParam}
				if ctx.reachVisiting[vk] {
					return isInsParam
				}
				root := a.aliasFind(obj)
				rRoot := a.reachFind(obj)
				if isInsParam {
					if a.paramRebound[obj] || a.captureBroken[obj] || ctx.resolved.poison[rRoot] {
						return false
					}
				} else if a.localBroken[obj] || a.captureBroken[obj] || ctx.resolved.poison[rRoot] {
					return false
				}
				if !a.params[obj] && !a.freshObj[obj] && !a.hasZeroDecl[obj] && len(a.localSources[obj]) == 0 {
					return false
				}
				for use := range ctx.resolved.uses[rRoot] {
					ctx.useDeps[use] = true
				}
				a.foldRootConfinementDeps(ctx, rRoot)
				if !allowInsParam && rRoot != skipInsertionRoot {
					for _, use := range a.pendingInsertionUses {
						if a.reachFind(use.root) == rRoot && use.call != currentCall {
							provenLocal, conditional := a.pkgConf.classifyParam(a.ownPath, use.calleeParam)
							if !provenLocal {
								if !conditional {
									return false
								}
								ctx.paramDeps[use.calleeParam] = true
							}
						}
					}
				}
				ctx.reachVisiting[vk] = true
				defer delete(ctx.reachVisiting, vk)
				for _, src := range a.localSources[obj] {
					if !a.checkPlainCallReachArg(ctx, src, currentCall, skipInsertionRoot, allowInsParam) {
						return false
					}
				}
				for _, st := range a.sharedWrites[root] {
					if !a.checkPlainCallReachArg(ctx, st, currentCall, skipInsertionRoot, allowInsParam) {
						return false
					}
				}
				for _, st := range a.sharedInsertionWrites[rRoot] {
					if !a.checkPlainCallReachArg(ctx, st, currentCall, skipInsertionRoot, allowInsParam) {
						return false
					}
				}
				return true
			}
			return false
		},
	})
}

func (a *outflowAnalyzer) computeResolvedUses(insMode bool) resolvedInsertionState {
	if len(a.pendingInsertionUses) == 0 {
		return resolvedInsertionState{}
	}
	state := resolvedInsertionState{
		poison:     map[types.Object]bool{},
		uses:       map[types.Object]map[syntaxutil.EnvAuditTarget]bool{},
		paramDeps:  map[types.Object]map[syntaxutil.ParamKey]bool{},
		methodDeps: map[types.Object]map[syntaxutil.FuncKey]bool{},
	}
	step := func(record bool) bool {
		changed := false
		for _, use := range a.pendingInsertionUses {
			rRoot := a.reachFind(use.root)
			if state.poison[rRoot] {
				continue
			}
			stepCtx := newOutflowEvalCtx(insMode, state)
			allFree := true
			for _, arg := range use.args {
				if okA, _ := a.evalFree(stepCtx, arg); !okA {
					allFree = false
					break
				}
				if arg != nil && arg.Type != nil && typeHandsOutReachOrAddr(arg.Type) &&
					!a.checkPlainCallReachArg(stepCtx, arg, use.call, rRoot, insMode) {
					allFree = false
					break
				}
			}
			if !allFree {
				state.poison[rRoot] = true
				changed = true
				continue
			}
			if record {
				if state.uses[rRoot] == nil {
					state.uses[rRoot] = map[syntaxutil.EnvAuditTarget]bool{}
				}
				addUse := func(t syntaxutil.EnvAuditTarget) {
					if !state.uses[rRoot][t] {
						state.uses[rRoot][t] = true
						changed = true
					}
				}
				addUse(syntaxutil.ParamAuditTarget(use.calleeParam))
				for fk := range stepCtx.fnDeps {
					addUse(syntaxutil.FuncAuditTarget(fk))
				}
				for u := range stepCtx.useDeps {
					addUse(u)
				}
				for pk := range stepCtx.paramDeps {
					if state.paramDeps[rRoot] == nil {
						state.paramDeps[rRoot] = map[syntaxutil.ParamKey]bool{}
					}
					if !state.paramDeps[rRoot][pk] {
						state.paramDeps[rRoot][pk] = true
						changed = true
					}
				}
				for mk := range stepCtx.methodDeps {
					if state.methodDeps[rRoot] == nil {
						state.methodDeps[rRoot] = map[syntaxutil.FuncKey]bool{}
					}
					if !state.methodDeps[rRoot][mk] {
						state.methodDeps[rRoot][mk] = true
						changed = true
					}
				}
			}
		}
		return changed
	}
	for step(false) {
	}
	for step(true) {
	}
	return state
}

func (a *outflowAnalyzer) evaluateParams(insResolved resolvedInsertionState) {
	for obj, idx := range a.paramIndex {
		key := syntaxutil.ParamKey{Func: a.ownFuncKey, Index: idx}
		root := a.aliasFind(obj)
		rRoot := a.reachFind(obj)
		if a.captureBroken[obj] || insResolved.poison[rRoot] {
			continue
		}
		insCtx := newOutflowEvalCtx(true, insResolved)
		a.foldRootConfinementDeps(insCtx, rRoot)
		okIns := true
		for _, stores := range [][]*flowir.Value{a.sharedWrites[root], a.sharedInsertionWrites[rRoot]} {
			for _, stored := range stores {
				if okSt, _ := a.evalFree(insCtx, stored); !okSt {
					okIns = false
					break
				}
				if stored != nil && stored.Type != nil && typeHandsOutReachOrAddr(stored.Type) &&
					!a.checkPlainCallReachArg(insCtx, stored, nil, nil, true) {
					okIns = false
					break
				}
			}
			if !okIns {
				break
			}
		}
		if !okIns {
			continue
		}
		for fk := range insCtx.fnDeps {
			insCtx.useDeps[syntaxutil.FuncAuditTarget(fk)] = true
		}
		for use := range insResolved.uses[rRoot] {
			insCtx.useDeps[use] = true
		}
		a.out.paramInsertionFree[key] = true
		if len(insCtx.useDeps) > 0 {
			a.out.paramInsertionDeps[key] = insCtx.useDeps
		}
		if len(insCtx.paramDeps) > 0 {
			a.out.paramInsertionParams[key] = insCtx.paramDeps
		}
		if len(insCtx.methodDeps) > 0 {
			a.out.paramInsertionMethods[key] = insCtx.methodDeps
		}
	}
}

func (a *outflowAnalyzer) namedResultIdent(rv *types.Var) ast.Expr {
	if rv == nil {
		return &ast.Ident{}
	}
	if a.fd.Type != nil && a.fd.Type.Results != nil {
		for _, field := range a.fd.Type.Results.List {
			for _, id := range field.Names {
				if id != nil && a.p.TypesInfo.Defs[id] == rv {
					return id
				}
			}
		}
	}
	return &ast.Ident{NamePos: rv.Pos(), Name: rv.Name()}
}

func (a *outflowAnalyzer) explainRefusal(retResolved resolvedInsertionState, v *flowir.Value) {
	if v == nil || v.Raw == nil {
		return
	}
	e := syntaxutil.UnparenExpr(v.Raw)
	clause := "an unrecognized return shape"
	switch e := e.(type) {
	case *ast.Ident:
		obj := a.p.TypesInfo.Uses[e]
		if obj == nil {
			obj = a.p.TypesInfo.Defs[e]
		}
		switch {
		case obj != nil && a.localBroken[obj]:
			clause = "write or capture broke the binding"
		case obj != nil && retResolved.poison[a.reachFind(obj)]:
			clause = "an unjudgeable argument to a deferring call poisoned the storage"
		case obj != nil && len(a.sharedWrites[a.aliasFind(obj)]) > 0:
			clause = "a stored value refused"
		default:
			clause = "a binding source refused"
		}
	case *ast.CallExpr:
		clause = "callee outside the audited set and dependency channel"
	case *ast.CompositeLit:
		clause = "a literal element refused"
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
		clause = "an unadmitted derivation shape"
	}
	syntaxutil.ExplainRefusalMark(a.hooks, a.p, a.fd.Name.Name, e, clause)
}

func (a *outflowAnalyzer) evaluateReturns(retResolved resolvedInsertionState) {
	retCtx := newOutflowEvalCtx(false, retResolved)
	for callee := range a.stmtCallDeps {
		retCtx.fnDeps[callee] = true
	}
	if a.hooks != nil && a.hooks.Refusal != nil {
		retCtx.onRefusal = func(v *flowir.Value) {
			a.explainRefusal(retResolved, v)
		}
	}

	okRet := true
	var firstNamedResult *types.Var
	for _, rv := range a.body.Results {
		if rv != nil {
			if firstNamedResult == nil {
				firstNamedResult = rv
			}
			if a.localBroken[rv] {
				syntaxutil.ExplainRefusalMark(a.hooks, a.p, a.fd.Name.Name, a.namedResultIdent(rv), "write or capture broke the binding")
				okRet = false
				break
			}
		}
	}
	sawReturn := false
	if okRet {
		a.body.ForEachSyncOp(func(op *flowir.Op) bool {
			if op.Kind != flowir.OpReturn {
				return true
			}
			sawReturn = true
			if op.IsNaked {
				retExpr := a.namedResultIdent(firstNamedResult)
				if op.StmtAST != nil {
					retExpr = &ast.Ident{NamePos: op.StmtAST.Pos()}
				}
				syntaxutil.ExplainRefusalMark(a.hooks, a.p, a.fd.Name.Name, retExpr, "an unrecognized return shape")
				okRet = false
				return false
			}
			for _, res := range op.Results {
				if okRes, _ := a.evalFree(retCtx, res); !okRes {
					okRet = false
					return false
				}
			}
			return true
		})
	}
	if !okRet {
		return
	}
	if firstNamedResult != nil && !sawReturn {
		syntaxutil.ExplainRefusalMark(a.hooks, a.p, a.fd.Name.Name, a.namedResultIdent(firstNamedResult), "an unrecognized return shape")
		return
	}
	a.out.returnEnvFree[a.fnKey] = true
	if len(retCtx.fnDeps) > 0 {
		a.out.returnEnvDeps[a.fnKey] = retCtx.fnDeps
	}
	if len(retCtx.paramDeps) > 0 {
		a.out.returnEnvParamDeps[a.fnKey] = retCtx.paramDeps
	}
	if len(retCtx.methodDeps) > 0 {
		a.out.returnEnvMethodDeps[a.fnKey] = retCtx.methodDeps
	}
	if len(retCtx.useDeps) > 0 {
		a.out.returnInsertionCallDep[a.fnKey] = retCtx.useDeps
	}
	recordReturnFieldRegistrants(a.audited, a.p, a.fc, a.fnKey, a.body, a.out.returnFieldDefer, a.out.returnFieldPoison)
}

func (a *outflowAnalyzer) analyzeFunc() {
	a.initParams()
	a.collectBodyOps()
	a.finalizeTables()
	retResolved := a.computeResolvedUses(false)
	insResolved := a.computeResolvedUses(true)
	a.evaluateParams(insResolved)
	a.evaluateReturns(retResolved)
}
