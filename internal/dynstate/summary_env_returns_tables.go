package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (a *outflowAnalyzer) propagateBroken() {
	for changed := true; changed; {
		changed = false
		for _, pairs := range [][][2]types.Object{a.aliasPairs, a.heldPairs} {
			for _, pair := range pairs {
				if a.localBroken[pair[0]] != a.localBroken[pair[1]] {
					a.localBroken[pair[0]], a.localBroken[pair[1]] = true, true
					changed = true
				}
				if a.captureBroken[pair[0]] != a.captureBroken[pair[1]] {
					a.captureBroken[pair[0]], a.captureBroken[pair[1]] = true, true
					changed = true
				}
			}
		}
	}
}

func (a *outflowAnalyzer) unwrapBareOrResliceVar(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool) {
	if v == nil {
		return nil, false
	}
	if v.Kind == flowir.ValConvert && !v.IsTypeAssert && isSliceOrMapType(v.Type) {
		return a.unwrapBareOrResliceVar(v.Arg, extras)
	}
	if v.Kind != flowir.ValPlace || v.Place.Obj == nil || a.params[v.Place.Obj] {
		return nil, false
	}
	if _, tr := a.trackedVar(v.Place.Obj); !tr || !isSliceOrMapType(v.Place.Obj.Type()) {
		return nil, false
	}
	if len(v.Place.Projs) == 0 {
		return v.Place.Obj, true
	}
	if !isSliceResliceOnlyPlace(v.Place) {
		return nil, false
	}
	if extras != nil {
		for _, pr := range v.Place.Projs {
			if pr.Low != nil {
				*extras = append(*extras, pr.Low)
			}
			if pr.High != nil {
				*extras = append(*extras, pr.High)
			}
			if pr.Max != nil {
				*extras = append(*extras, pr.Max)
			}
		}
	}
	return v.Place.Obj, true
}

func (a *outflowAnalyzer) unwrapSameHeaderVar(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool) {
	if v == nil {
		return nil, false
	}
	if v.Kind == flowir.ValConvert && !v.IsTypeAssert && isSliceOrMapType(v.Type) {
		return a.unwrapSameHeaderVar(v.Arg, extras)
	}
	if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" &&
		!v.Ellipsis && len(v.Args) > 0 {
		var subExtras []*flowir.Value
		obj, ok := a.unwrapSameHeaderVar(v.Args[0], &subExtras)
		if !ok {
			return nil, false
		}
		if extras != nil {
			*extras = append(*extras, subExtras...)
			*extras = append(*extras, v.Args[1:]...)
		}
		return obj, true
	}
	return a.unwrapBareOrResliceVar(v, extras)
}

func (a *outflowAnalyzer) collectEmbeddedObjs() map[types.Object]bool {
	embeddedObj := map[types.Object]bool{}
	markObjEmbedded := func(o *types.Var) {
		if o != nil {
			embeddedObj[o] = true
		}
	}
	var markValueEmbedded func(v *flowir.Value)
	markValueEmbedded = func(v *flowir.Value) {
		if v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if isElementReadPlace(v.Place) {
				v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
					markValueEmbedded(cv)
					return true
				})
				return
			}
			markObjEmbedded(v.Place.Obj)
			v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
				markValueEmbedded(cv)
				return true
			})
			return
		case flowir.ValAddrOf:
			markObjEmbedded(v.AddrPlace.Obj)
			v.AddrPlace.ForEachChildValue(func(cv *flowir.Value) bool {
				markValueEmbedded(cv)
				return true
			})
			markValueEmbedded(v.Low)
			markValueEmbedded(v.High)
			markValueEmbedded(v.Max)
			return
		case flowir.ValMethodVal:
			if v.HasRecvPlace {
				markObjEmbedded(v.RecvPlace.Obj)
				v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					markValueEmbedded(cv)
					return true
				})
			}
			markValueEmbedded(v.Recv)
			return
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				for fv := range v.Closure.FreeVars {
					markObjEmbedded(fv)
				}
			}
			return
		case flowir.ValCall:
			switch v.CallKind {
			case flowir.CallBuiltin:
				switch v.BuiltinName {
				case "Sizeof", "Alignof", "Offsetof":
					return
				case "len", "cap", "clear":
					if len(v.Args) == 1 {
						var extras []*flowir.Value
						if _, ok := a.unwrapBareOrResliceVar(v.Args[0], &extras); ok {
							for _, ex := range extras {
								markValueEmbedded(ex)
							}
							return
						}
					}
				case "delete":
					if len(v.Args) == 2 {
						var extras []*flowir.Value
						if _, ok := a.unwrapBareOrResliceVar(v.Args[0], &extras); ok {
							for _, ex := range extras {
								markValueEmbedded(ex)
							}
							markValueEmbedded(v.Args[1])
							return
						}
					}
				}
			case flowir.CallPlain:
				if v.CalleeFunc != nil && !v.IsMethodExprCall {
					calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
					if auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
						for _, arg := range v.Args {
							var extras []*flowir.Value
							if _, ok := a.unwrapBareOrResliceVar(arg, &extras); ok {
								for _, ex := range extras {
									markValueEmbedded(ex)
								}
								continue
							}
							markValueEmbedded(arg)
						}
						return
					}
					for j, arg := range v.Args {
						idx := j
						if v.CalleeSig != nil && v.CalleeSig.Variadic() && v.CalleeSig.Params().Len() > 0 && idx >= v.CalleeSig.Params().Len()-1 {
							idx = v.CalleeSig.Params().Len() - 1
						}
						calleeParam := syntaxutil.ParamKey{Func: calleeFK, Index: idx}
						if a.pkgConf != nil && calleeParam.Func.Pkg == a.ownPath && a.pkgConf.paramLeakFree[calleeParam] {
							var extras []*flowir.Value
							if _, ok := a.unwrapBareOrResliceVar(arg, &extras); ok {
								for _, ex := range extras {
									markValueEmbedded(ex)
								}
								continue
							}
						}
						markValueEmbedded(arg)
					}
					return
				}
			}
			if v.AutoAddrRecv && v.HasRecvPlace {
				markObjEmbedded(v.RecvPlace.Obj)
			}
			if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
				for fv := range v.IIFE.FreeVars {
					markObjEmbedded(fv)
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			markValueEmbedded(ch)
			return true
		})
	}
	markDstPlaceEmbedded := func(dst flowir.Place) {
		if dst.IsBareVar() {
			return
		}
		if !isDirectIndexPlace(dst) {
			markObjEmbedded(dst.Obj)
		}
		dst.ForEachChildValue(func(cv *flowir.Value) bool {
			markValueEmbedded(cv)
			return true
		})
	}
	a.body.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			switch op.AssignKind {
			case flowir.AssignZeroDecl:
				for _, dst := range op.Dsts {
					markDstPlaceEmbedded(dst)
				}
			case flowir.AssignIncDec, flowir.AssignCompound:
				for _, dst := range op.Dsts {
					markDstPlaceEmbedded(dst)
				}
				for _, src := range op.Srcs {
					markValueEmbedded(src)
				}
			case flowir.AssignRange:
				for _, dst := range op.Dsts {
					markDstPlaceEmbedded(dst)
				}
				if len(op.Srcs) == 1 {
					if len(op.Dsts) <= 1 || op.Dsts[1].IsBlank() {
						var extras []*flowir.Value
						if _, ok := a.unwrapBareOrResliceVar(op.Srcs[0], &extras); ok {
							for _, ex := range extras {
								markValueEmbedded(ex)
							}
							break
						}
					}
					markValueEmbedded(op.Srcs[0])
				}
			default:
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					if dst.IsBareVar() {
						if dst.Obj != nil && !a.params[dst.Obj] {
							if _, tr := a.trackedVar(dst.Obj); tr && isSliceOrMapType(dst.Obj.Type()) {
								var extras []*flowir.Value
								if _, ok := a.unwrapSameHeaderVar(src, &extras); ok {
									for _, ex := range extras {
										markValueEmbedded(ex)
									}
									return true
								}
							}
						}
						markValueEmbedded(src)
						return true
					}
					markDstPlaceEmbedded(dst)
					markValueEmbedded(src)
					return true
				})
			}
		case flowir.OpTypeSwitchBind:
			markValueEmbedded(op.SwitchSrc)
		case flowir.OpChanSend:
			markObjEmbedded(op.ChanPlace.Obj)
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
				markValueEmbedded(cv)
				return true
			})
			markValueEmbedded(op.ChanVal)
			markValueEmbedded(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				var extras []*flowir.Value
				if _, ok := a.unwrapBareOrResliceVar(r, &extras); ok {
					for _, ex := range extras {
						markValueEmbedded(ex)
					}
					continue
				}
				markValueEmbedded(r)
			}
		case flowir.OpDefer:
			markValueEmbedded(op.Call)
		case flowir.OpGo:
			markValueEmbedded(op.Call)
		case flowir.OpExpr:
			if op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallKind == flowir.CallBuiltin &&
				op.Expr.BuiltinName == "append" && !op.Expr.Ellipsis && len(op.Expr.Args) >= 2 {
				var extras []*flowir.Value
				if _, ok := a.unwrapBareOrResliceVar(op.Expr.Args[0], &extras); ok {
					for _, ex := range extras {
						markValueEmbedded(ex)
					}
					for _, arg := range op.Expr.Args[1:] {
						markValueEmbedded(arg)
					}
					return true
				}
			}
			markValueEmbedded(op.Expr)
		}
		return true
	})
	return embeddedObj
}

func outflowDeepWrite(dst flowir.Place, fresh bool) bool {
	selectorSeen := false
	for idx, pr := range dst.Projs {
		atRoot := idx == 0
		final := idx == len(dst.Projs)-1
		switch pr.Kind {
		case flowir.ProjDeref:
			if !atRoot || !fresh {
				return true
			}
			if pr.Type == nil {
				selectorSeen = true
			} else if _, isArr := types.Unalias(pr.Type).Underlying().(*types.Array); !isArr {
				selectorSeen = true
			}
		case flowir.ProjField:
			ptrBase := pr.Indirect
			if !ptrBase && pr.BaseType != nil {
				_, ptrBase = types.Unalias(pr.BaseType).Underlying().(*types.Pointer)
			}
			if ptrBase && (!atRoot || !fresh) {
				return true
			}
			selectorSeen = true
		case flowir.ProjIndex:
			if !final || !fresh || selectorSeen {
				return true
			}
		case flowir.ProjSlice:
			if !fresh || selectorSeen {
				return true
			}
		}
	}
	return false
}

func (a *outflowAnalyzer) finalizeTables() {
	for _, ps := range a.pendingStores {
		a.linkBacking(ps.robj, ps.source)
	}
	for _, pa := range a.pendingAppendSlices {
		a.linkBacking(pa.robj, pa.source)
	}

	a.aliasFind = newObjectUnionFind(a.aliasPairs)
	a.reachFind = newObjectUnionFind(a.aliasPairs, a.heldPairs)
	a.propagateBroken()

	var headerPairs [][2]types.Object
	for obj, binds := range a.directBinds {
		if a.params[obj] || !isSliceOrMapType(obj.Type()) {
			continue
		}
		for _, b := range binds {
			if srcObj, ok := a.unwrapSameHeaderVar(b, nil); ok && srcObj != obj {
				headerPairs = append(headerPairs, [2]types.Object{obj, srcObj})
			}
		}
	}
	a.headerFind = newObjectUnionFind(headerPairs)

	embeddedObj := a.collectEmbeddedObjs()
	headerMembers := map[types.Object][]types.Object{}
	headerSeen := map[types.Object]bool{}
	headerEmbedded := map[types.Object]bool{}
	addHeaderCandidate := func(o types.Object) {
		v, ok := o.(*types.Var)
		if !ok || v == nil || a.params[v] || v.Type() == nil || !isSliceOrMapType(v.Type()) {
			return
		}
		if _, tr := a.trackedVar(o); !tr {
			return
		}
		hRoot := a.headerFind(o)
		if !headerSeen[o] {
			headerSeen[o] = true
			headerMembers[hRoot] = append(headerMembers[hRoot], o)
		}
		if embeddedObj[o] {
			headerEmbedded[hRoot] = true
		}
	}
	for o := range a.directBinds {
		addHeaderCandidate(o)
	}
	for _, ps := range a.pendingStores {
		addHeaderCandidate(ps.robj)
	}
	for _, pa := range a.pendingAppendSlices {
		addHeaderCandidate(pa.robj)
	}
	for o := range a.insertionWrites {
		addHeaderCandidate(o)
	}
	for o := range embeddedObj {
		addHeaderCandidate(o)
	}

	a.freshObj, _ = computeOutflowFreshOwnedLocals(outflowFreshInput{
		directBinds:         a.directBinds,
		hasZeroDecl:         a.hasZeroDecl,
		params:              a.params,
		localBroken:         a.localBroken,
		rangeBound:          a.rangeBound,
		hasSpreadAppend:     a.hasSpreadAppend,
		headerMembers:       headerMembers,
		headerEmbedded:      headerEmbedded,
		headerFind:          a.headerFind,
		insertionWrites:     a.insertionWrites,
		pendingStores:       a.pendingStores,
		pendingAppendSlices: a.pendingAppendSlices,
	})

	for _, ps := range a.pendingStores {
		if outflowDeepWrite(ps.place, a.freshObj[ps.robj]) {
			a.breakObj(ps.robj, false, nil)
			a.insertionWrites[ps.robj] = append(a.insertionWrites[ps.robj], ps.source)
			continue
		}
		a.writeSources[ps.robj] = append(a.writeSources[ps.robj], ps.source)
	}
	for _, pa := range a.pendingAppendSlices {
		if !a.freshObj[pa.robj] || outflowDeepWrite(pa.place, true) {
			a.breakObj(pa.robj, false, nil)
			a.insertionWrites[pa.robj] = append(a.insertionWrites[pa.robj], pa.source)
			continue
		}
		a.writeSources[pa.robj] = append(a.writeSources[pa.robj], pa.source)
		a.insertionWrites[pa.robj] = append(a.insertionWrites[pa.robj], pa.source)
	}

	a.sharedWrites = map[types.Object][]*flowir.Value{}
	for obj, stores := range a.writeSources {
		root := a.aliasFind(obj)
		a.sharedWrites[root] = append(a.sharedWrites[root], stores...)
	}
	a.sharedInsertionWrites = map[types.Object][]*flowir.Value{}
	for obj, stores := range a.insertionWrites {
		rRoot := a.reachFind(obj)
		a.sharedInsertionWrites[rRoot] = append(a.sharedInsertionWrites[rRoot], stores...)
	}

	a.objParamDeps = map[types.Object]map[syntaxutil.ParamKey]bool{}
	for obj, pks := range a.rawObjParamDeps {
		rRoot := a.reachFind(obj)
		if a.objParamDeps[rRoot] == nil {
			a.objParamDeps[rRoot] = map[syntaxutil.ParamKey]bool{}
		}
		for pk := range pks {
			a.objParamDeps[rRoot][pk] = true
		}
	}
	a.objMethodDeps = map[types.Object]map[syntaxutil.FuncKey]bool{}
	for obj, mks := range a.rawObjMethodDeps {
		rRoot := a.reachFind(obj)
		if a.objMethodDeps[rRoot] == nil {
			a.objMethodDeps[rRoot] = map[syntaxutil.FuncKey]bool{}
		}
		for mk := range mks {
			a.objMethodDeps[rRoot][mk] = true
		}
	}

	componentMembers := map[types.Object][]types.Object{}
	memberSeen := map[types.Object]bool{}
	collectMember := func(o types.Object) {
		if o != nil && !memberSeen[o] {
			memberSeen[o] = true
			componentMembers[a.aliasFind(o)] = append(componentMembers[a.aliasFind(o)], o)
		}
	}
	for _, pair := range a.aliasPairs {
		collectMember(pair[0])
		collectMember(pair[1])
	}
	for obj := range a.writeSources {
		collectMember(obj)
	}
	for obj := range a.params {
		collectMember(obj)
	}
	for root, ms := range componentMembers {
		if len(a.sharedWrites[root]) == 0 {
			continue
		}
		hasParam := false
		for _, m := range ms {
			if a.params[m] {
				hasParam = true
				break
			}
		}
		if hasParam {
			for _, m := range ms {
				a.localBroken[m] = true
			}
		}
	}

	a.propagateBroken()
}
