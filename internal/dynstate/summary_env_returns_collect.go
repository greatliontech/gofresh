package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (a *outflowAnalyzer) initParams() {
	paramCount := 0
	if a.fd.Type.Params == nil {
		return
	}
	for _, field := range a.fd.Type.Params.List {
		if len(field.Names) == 0 {
			a.out.paramInsertionFree[syntaxutil.ParamKey{Func: a.ownFuncKey, Index: paramCount}] = true
			paramCount++
			continue
		}
		for _, name := range field.Names {
			if obj := a.p.TypesInfo.Defs[name]; obj != nil && name.Name != "_" {
				a.params[obj] = true
				a.paramIndex[obj] = paramCount
			} else {
				a.out.paramInsertionFree[syntaxutil.ParamKey{Func: a.ownFuncKey, Index: paramCount}] = true
			}
			paramCount++
		}
	}
}

func (a *outflowAnalyzer) trackedVar(obj types.Object) (*types.Var, bool) {
	if !syntaxutil.IsLocalVar(obj) {
		return nil, false
	}
	v := obj.(*types.Var)
	if !refconfine.TypeCarriesSignature(v.Type()) &&
		!refconfine.TypeMayCarryUnknownDynamic(a.audited, v.Type()) &&
		!typeHandsOutReachOrAddr(v.Type()) {
		return nil, false
	}
	return v, true
}

func (a *outflowAnalyzer) breakObj(obj types.Object, capture bool, gate func(types.Object) bool) {
	if obj == nil {
		return
	}
	if _, ok := a.trackedVar(obj); (ok || a.params[obj]) && (gate == nil || gate(obj)) {
		a.localBroken[obj] = true
		if capture {
			a.captureBroken[obj] = true
		}
	}
}

func (a *outflowAnalyzer) breakValueVars(v *flowir.Value, capture bool, gate func(types.Object) bool) {
	if v == nil {
		return
	}
	v.WalkValues(func(cur *flowir.Value) bool {
		switch cur.Kind {
		case flowir.ValPlace:
			a.breakObj(cur.Place.Obj, capture, gate)
		case flowir.ValAddrOf:
			a.breakObj(cur.AddrPlace.Obj, capture, gate)
		case flowir.ValMethodVal:
			if cur.HasRecvPlace {
				a.breakObj(cur.RecvPlace.Obj, capture, gate)
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					a.breakObj(fv, capture, gate)
				}
			}
		case flowir.ValCall:
			if cur.AutoAddrRecv && cur.HasRecvPlace {
				a.breakObj(cur.RecvPlace.Obj, capture, gate)
			}
			if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
				for fv := range cur.IIFE.FreeVars {
					a.breakObj(fv, capture, gate)
				}
			}
		}
		return true
	})
}

func (a *outflowAnalyzer) breakPlaceBase(pl flowir.Place, capture bool) {
	if pl.Obj != nil {
		a.breakObj(pl.Obj, capture, nil)
		return
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		a.breakValueVars(pl.Base, capture, nil)
	}
}

func (a *outflowAnalyzer) breakTargets(v *flowir.Value) {
	a.breakValueVars(v, true, nil)
}

func (a *outflowAnalyzer) breakReachIn(val *flowir.Value) {
	a.breakValueVars(val, true, func(obj types.Object) bool {
		return typeHandsOutReachOrAddr(obj.Type())
	})
}

func (a *outflowAnalyzer) pairLink(obj, sobj types.Object, shares bool) {
	if obj == nil || sobj == nil {
		return
	}
	if v, ok := sobj.(*types.Var); ok && v.IsField() {
		return
	}
	_, tracked := a.trackedVar(sobj)
	if !tracked || !typeHandsOutReachOrAddr(sobj.Type()) {
		return
	}
	if shares {
		a.aliasPairs = append(a.aliasPairs, [2]types.Object{obj, sobj})
	} else {
		a.heldPairs = append(a.heldPairs, [2]types.Object{obj, sobj})
	}
}

func (a *outflowAnalyzer) linkPlaceValue(obj types.Object, pl flowir.Place, valType types.Type, shares bool) {
	if pl.Obj != nil {
		a.pairLink(obj, pl.Obj, shares && outflowSharesHeader(valType))
		return
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		pl.Base.WalkValues(func(cur *flowir.Value) bool {
			if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
				a.pairLink(obj, cur.Place.Obj, true)
			} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
				a.pairLink(obj, cur.AddrPlace.Obj, true)
			}
			return true
		})
	}
}

func (a *outflowAnalyzer) linkBacking(obj types.Object, src *flowir.Value) {
	if src == nil {
		return
	}
	switch src.Kind {
	case flowir.ValPlace:
		a.linkPlaceValue(obj, src.Place, src.Type, true)
	case flowir.ValAddrOf:
		if src.AddrPlace.Obj != nil {
			a.pairLink(obj, src.AddrPlace.Obj, true)
		} else if src.AddrPlace.Root == flowir.RootTransient {
			a.linkBacking(obj, src.AddrPlace.Base)
		}
	case flowir.ValMethodVal:
		if src.AutoAddr && src.HasRecvPlace && src.RecvPlace.Obj != nil {
			a.pairLink(obj, src.RecvPlace.Obj, true)
		}
		a.linkBacking(obj, src.Recv)
	case flowir.ValAllocFresh:
		switch src.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return
		case flowir.AllocBuiltinNewExpr:
			for _, arg := range src.Args {
				a.linkBacking(obj, arg)
			}
		case flowir.AllocCompositeLit:
			for i := range src.CompositeElts {
				a.linkBacking(obj, src.CompositeElts[i].MapKey)
				a.linkBacking(obj, src.CompositeElts[i].Value)
			}
		}
	case flowir.ValConvert:
		a.linkBacking(obj, src.Arg)
	case flowir.ValCall:
		if src.CallKind == flowir.CallBuiltin {
			switch src.BuiltinName {
			case "len", "cap", "Sizeof", "Alignof", "Offsetof":
				return
			case "Slice", "SliceData", "String", "StringData":
				if len(src.Args) > 0 {
					a.linkBacking(obj, src.Args[0])
				}
				return
			case "append":
				if len(src.Args) > 0 {
					if src.Args[0].Kind == flowir.ValPlace {
						a.linkPlaceValue(obj, src.Args[0].Place, src.Args[0].Type, true)
					} else {
						a.linkBacking(obj, src.Args[0])
					}
					for _, arg := range src.Args[1:] {
						a.linkBacking(obj, arg)
					}
				}
				return
			}
		}
		if src.AutoAddrRecv && src.HasRecvPlace && src.RecvPlace.Obj != nil {
			a.pairLink(obj, src.RecvPlace.Obj, true)
		}
		a.linkBacking(obj, src.Recv)
		a.linkBacking(obj, src.Callee)
		for _, arg := range src.Args {
			a.linkBacking(obj, arg)
		}
	case flowir.ValChanRecv:
		a.linkBacking(obj, src.Chan)
	case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
		return
	case flowir.ValCompositeExpr:
		for _, arg := range src.Args {
			a.linkBacking(obj, arg)
		}
	}
}

func (a *outflowAnalyzer) bindPlace(dst flowir.Place, src *flowir.Value, broken bool, isZeroDecl bool) {
	if dst.IsBlank() {
		return
	}
	if !dst.IsBareVar() {
		if !broken && src != nil && dst.Obj != nil {
			if _, tracked := a.trackedVar(dst.Obj); tracked {
				if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
					a.pendingStores = append(a.pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
				}
				a.pendingStores = append(a.pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: src})
				return
			}
		}
		a.breakPlaceBase(dst, true)
		if src != nil {
			a.breakReachIn(src)
		}
		return
	}
	obj := dst.Obj
	if obj != nil && a.params[obj] {
		a.paramRebound[obj] = true
		a.localBroken[obj] = true
		a.linkBacking(obj, src)
		return
	}
	if _, ok := a.trackedVar(obj); !ok {
		if src != nil && (dst.Root == flowir.RootPkgGlobal || dst.Root == flowir.RootOuterVar || dst.Root == flowir.RootTransient) {
			a.breakReachIn(src)
		}
		return
	}
	if isZeroDecl {
		a.hasZeroDecl[obj] = true
		return
	}
	if broken || src == nil {
		a.localBroken[obj] = true
		return
	}
	if src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
		src.BuiltinName == "append" && len(src.Args) > 0 &&
		src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
		src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == obj {
		a.linkBacking(obj, src)
		a.directBinds[obj] = append(a.directBinds[obj], src)
		a.localSources[obj] = append(a.localSources[obj], src.Args[1:]...)
		return
	}
	a.linkBacking(obj, src)
	a.directBinds[obj] = append(a.directBinds[obj], src)
	a.localSources[obj] = append(a.localSources[obj], src)
}

func (a *outflowAnalyzer) collectMutableArgRoots(arg *flowir.Value) map[types.Object]bool {
	roots := map[types.Object]bool{}
	if arg == nil || (arg.Type != nil && !typeHandsOutReachOrAddr(arg.Type)) {
		return roots
	}
	var walk func(v *flowir.Value)
	walk = func(v *flowir.Value) {
		if v == nil {
			return
		}
		isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
			(v.BuiltinName == "String" || v.BuiltinName == "StringData")
		if !isStrBuiltin && v.Kind != flowir.ValAddrOf && v.Type != nil && !typeHandsOutReachOrAddr(v.Type) {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if v.Place.Obj != nil {
				if _, tr := a.trackedVar(v.Place.Obj); (tr || a.params[v.Place.Obj]) && typeHandsOutReachOrAddr(v.Place.Obj.Type()) {
					roots[v.Place.Obj] = true
				}
			} else if v.Place.Root == flowir.RootTransient {
				walk(v.Place.Base)
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil {
				if _, tr := a.trackedVar(v.AddrPlace.Obj); tr || a.params[v.AddrPlace.Obj] {
					roots[v.AddrPlace.Obj] = true
				}
			} else if v.AddrPlace.Root == flowir.RootTransient {
				walk(v.AddrPlace.Base)
			}
		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocBuiltinNewExpr:
				for _, child := range v.Args {
					walk(child)
				}
			case flowir.AllocCompositeLit:
				for i := range v.CompositeElts {
					walk(v.CompositeElts[i].MapKey)
					walk(v.CompositeElts[i].Value)
				}
			}
		case flowir.ValConvert:
			walk(v.Arg)
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin {
				switch v.BuiltinName {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return
				case "Slice", "SliceData", "String", "StringData":
					if len(v.Args) > 0 {
						walk(v.Args[0])
					}
					return
				case "append":
					for _, child := range v.Args {
						walk(child)
					}
					return
				}
			}
			walk(v.Recv)
			for _, child := range v.Args {
				walk(child)
			}
		}
	}
	walk(arg)
	return roots
}

func outflowUnwrapSlicePlace(cur *flowir.Value) (flowir.Place, bool) {
	for cur != nil {
		if cur.Kind == flowir.ValConvert && !cur.IsTypeAssert && cur.Arg != nil && cur.Arg.Type != nil {
			if _, isSlice := types.Unalias(cur.Arg.Type).Underlying().(*types.Slice); isSlice {
				cur = cur.Arg
				continue
			}
		}
		break
	}
	if cur == nil {
		return flowir.Place{}, false
	}
	if cur.Kind == flowir.ValAddrOf && cur.IsArraySlice && cur.AddrPlace.Obj != nil {
		return cur.AddrPlace, true
	}
	if cur.Kind != flowir.ValPlace || cur.Place.Obj == nil {
		return flowir.Place{}, false
	}
	pl := cur.Place
	for len(pl.Projs) > 0 {
		last := pl.Projs[len(pl.Projs)-1]
		if last.Kind != flowir.ProjSlice || last.BaseType == nil {
			break
		}
		okSlice := false
		switch u := types.Unalias(last.BaseType).Underlying().(type) {
		case *types.Slice, *types.Array:
			okSlice = true
		case *types.Pointer:
			if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); isArr {
				okSlice = true
			}
		}
		if !okSlice {
			break
		}
		pl.Projs = pl.Projs[:len(pl.Projs)-1]
	}
	return pl, true
}

func (a *outflowAnalyzer) classifyInsertionLit(elts []flowir.CompositeElt) {
	for i := range elts {
		for _, part := range []*flowir.Value{elts[i].MapKey, elts[i].Value} {
			if part == nil || (part.Type != nil && !typeHandsOutReachOrAddr(part.Type)) {
				continue
			}
			switch part.Kind {
			case flowir.ValAllocFresh:
				switch part.AllocKind {
				case flowir.AllocMake, flowir.AllocBuiltinNewType:
				case flowir.AllocBuiltinNewExpr:
					for _, child := range part.Args {
						a.breakReachIn(child)
					}
				case flowir.AllocCompositeLit:
					a.classifyInsertionLit(part.CompositeElts)
				}
			case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
			default:
				a.breakReachIn(part)
			}
		}
	}
}

func (a *outflowAnalyzer) classifyInsertionArg(call *flowir.Value, arg *flowir.Value, calleeParam syntaxutil.ParamKey, callArgs []*flowir.Value) {
	if arg == nil || (arg.Type != nil && !typeHandsOutReachOrAddr(arg.Type)) {
		return
	}
	switch arg.Kind {
	case flowir.ValPlace:
		if arg.Place.Obj != nil {
			obj := arg.Place.Obj
			_, tracked := a.trackedVar(obj)
			if (tracked || a.params[obj]) && typeHandsOutReachOrAddr(obj.Type()) {
				a.pendingInsertionUses = append(a.pendingInsertionUses, outflowInsertionUse{
					call:        call,
					root:        obj,
					calleeParam: calleeParam,
					args:        callArgs,
				})
			}
			return
		}
		a.breakReachIn(arg)
	case flowir.ValAllocFresh:
		switch arg.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return
		case flowir.AllocBuiltinNewExpr:
			for _, child := range arg.Args {
				a.classifyInsertionArg(call, child, calleeParam, callArgs)
			}
		case flowir.AllocCompositeLit:
			a.classifyInsertionLit(arg.CompositeElts)
		}
	case flowir.ValAddrOf:
		if arg.AddrPlace.Root == flowir.RootTransient {
			a.breakReachIn(arg.AddrPlace.Base)
		}
	case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
	case flowir.ValConvert:
		if arg.IsTypeAssert {
			a.breakReachIn(arg)
			return
		}
		a.classifyInsertionArg(call, arg.Arg, calleeParam, callArgs)
	case flowir.ValCall:
		switch arg.CallKind {
		case flowir.CallBuiltin:
			switch arg.BuiltinName {
			case "append":
				for ai, child := range arg.Args {
					if ai == len(arg.Args)-1 && arg.Ellipsis && child != nil && child.Type != nil {
						if sl, ok := types.Unalias(child.Type).Underlying().(*types.Slice); ok &&
							!typeHandsOutReachOrAddr(sl.Elem()) {
							continue
						}
					}
					a.classifyInsertionArg(call, child, calleeParam, callArgs)
				}
				return
			default:
				a.breakReachIn(arg)
				return
			}
		case flowir.CallPlain:
			if arg.CalleeFunc != nil && !arg.IsMethodExprCall {
				if auditset.ValuePlaneClone(arg.CalleePkg, arg.CalleeFunc.Name()) && !containerElemHandsOutReach(arg.Type) {
					return
				}
			}
			a.breakReachIn(arg)
		default:
			a.breakReachIn(arg)
		}
	default:
		a.breakReachIn(arg)
	}
}

func (a *outflowAnalyzer) scanPlainCallEffects(v *flowir.Value) {
	if v.CalleeFunc == nil || v.IsMethodExprCall {
		a.breakTargets(v.Callee)
		for _, arg := range v.Args {
			a.breakTargets(arg)
		}
		return
	}
	calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
	if auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
		return
	}
	reaches := refconfine.TypeCarriesSignature(v.Type)
	for _, arg := range v.Args {
		if reaches {
			break
		}
		arg.WalkValues(func(cur *flowir.Value) bool {
			if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
				if _, tr := a.trackedVar(cur.Place.Obj); tr || a.params[cur.Place.Obj] {
					reaches = true
					return false
				}
			}
			return !reaches
		})
	}
	if reaches {
		a.stmtCallDeps[calleeFK] = true
	}

	perArgRoots := make([]map[types.Object]bool, len(v.Args))
	for i, arg := range v.Args {
		perArgRoots[i] = a.collectMutableArgRoots(arg)
	}
	for i := 0; i < len(perArgRoots); i++ {
		for j := i + 1; j < len(perArgRoots); j++ {
			for r1 := range perArgRoots[i] {
				for r2 := range perArgRoots[j] {
					if r1 == r2 {
						a.localBroken[r1] = true
						a.captureBroken[r1] = true
					} else {
						a.pairLink(r1, r2, true)
					}
				}
			}
		}
	}

	v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, pIdx int, pOK bool, _ bool) bool {
		if slotType != nil && !refconfine.CallResultHandsOut(slotType) {
			return true
		}
		idx := slotIdx
		if pOK {
			idx = pIdx
		}
		a.classifyInsertionArg(v, arg, syntaxutil.ParamKey{Func: calleeFK, Index: idx}, v.Args)
		return true
	})
}

func (a *outflowAnalyzer) scanMethodCallEffects(v *flowir.Value) {
	for _, arg := range v.Args {
		a.breakTargets(arg)
	}
	recvExempt := false
	var deferredRecvMethod syntaxutil.FuncKey
	if !v.IsMethodExprCall && v.CalleeFunc != nil && !syntaxutil.InterfaceReceiver(v.CalleeFunc) &&
		v.Selection != nil && refconfine.InstantiatedResultsHandOutNothing(a.audited, v.Selection.Type()) {
		if sig, ok := v.CalleeFunc.Type().(*types.Signature); ok && sig.Recv() != nil {
			_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
			if !ptr && !v.AutoAddrRecv && !outflowSharesHeader(sig.Recv().Type()) &&
				!refconfine.CallResultHandsOut(sig.Recv().Type()) {
				recvExempt = true
			}
		}
		if !recvExempt {
			mk := syntaxutil.MethodFactKey(v.CalleeFunc)
			provenLocal, conditional := a.pkgConf.classifyMethod(a.ownPath, mk)
			if provenLocal {
				recvExempt = true
			} else if conditional {
				deferredRecvMethod = mk
			}
		}
	}
	if !recvExempt && deferredRecvMethod.Valid() {
		var recvPl flowir.Place
		hasRecvPl := false
		if v.AutoAddrRecv && v.HasRecvPlace {
			recvPl = v.RecvPlace
			hasRecvPl = true
		} else {
			cur := v.Recv
			for cur != nil && cur.Kind == flowir.ValConvert && !cur.IsTypeAssert {
				cur = cur.Arg
			}
			if cur != nil && cur.Kind == flowir.ValPlace {
				recvPl = cur.Place
				hasRecvPl = true
			}
		}
		if hasRecvPl && recvPl.Obj != nil {
			if _, tr := a.trackedVar(recvPl.Obj); tr || a.params[recvPl.Obj] {
				recvPl.ForEachChildValue(func(cv *flowir.Value) bool {
					a.breakTargets(cv)
					return true
				})
				if a.rawObjMethodDeps[recvPl.Obj] == nil {
					a.rawObjMethodDeps[recvPl.Obj] = map[syntaxutil.FuncKey]bool{}
				}
				a.rawObjMethodDeps[recvPl.Obj][deferredRecvMethod] = true
				recvExempt = true
			}
		}
	}
	if !recvExempt {
		if v.AutoAddrRecv && v.HasRecvPlace {
			a.breakPlaceBase(v.RecvPlace, true)
		}
		a.breakTargets(v.Recv)
	}
}

func (a *outflowAnalyzer) scanValueEffects(v *flowir.Value) {
	if v == nil {
		return
	}
	switch v.Kind {
	case flowir.ValConvert:
		if v.Arg != nil && (syntaxutil.IsUnsafePointerType(v.Arg.Type) ||
			(syntaxutil.IsUnsafePointerType(v.Type) && syntaxutil.ContainsUintptr(v.Arg.Type))) {
			a.breakTargets(v.Arg)
		}
	case flowir.ValAddrOf:
		a.breakPlaceBase(v.AddrPlace, true)
	case flowir.ValChanRecv:
		a.breakTargets(v.Chan)
	case flowir.ValMethodVal:
		shouldBreak := true
		if v.Method != nil {
			if sig, ok := v.Method.Type().(*types.Signature); ok && sig.Recv() != nil {
				_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
				shouldBreak = ptr || v.AutoAddr || outflowSharesHeader(sig.Recv().Type()) || typeHandsOutReachOrAddr(sig.Recv().Type())
			}
		}
		if shouldBreak {
			if v.AutoAddr && v.HasRecvPlace {
				a.breakPlaceBase(v.RecvPlace, true)
			}
			a.breakTargets(v.Recv)
		}
	case flowir.ValMakeClosure:
		if v.Closure != nil && v.Lit != nil && v.Lit.Body != nil {
			for fv := range v.Closure.FreeVars {
				if _, tr := a.trackedVar(fv); !tr && !a.params[fv] {
					continue
				}
				wants := map[syntaxutil.ParamKey]bool{}
				mw := map[syntaxutil.FuncKey]bool{}
				fvParams := map[syntaxutil.ParamKey]bool{}
				fvMethods := map[syntaxutil.FuncKey]bool{}
				if !boundValueClosureEnvLeakFreeJudged(a.audited, a.p, a.fc, map[types.Object]bool{fv: true}, v.Lit.Body, wants, mw) ||
					!a.classifyWants(wants, mw, fvParams, fvMethods) {
					a.localBroken[fv] = true
					a.captureBroken[fv] = true
					continue
				}
				if len(fvParams) > 0 {
					if a.rawObjParamDeps[fv] == nil {
						a.rawObjParamDeps[fv] = map[syntaxutil.ParamKey]bool{}
					}
					for pk := range fvParams {
						a.rawObjParamDeps[fv][pk] = true
					}
				}
				if len(fvMethods) > 0 {
					if a.rawObjMethodDeps[fv] == nil {
						a.rawObjMethodDeps[fv] = map[syntaxutil.FuncKey]bool{}
					}
					for mk := range fvMethods {
						a.rawObjMethodDeps[fv][mk] = true
					}
				}
			}
		}
		return
	case flowir.ValCall:
		switch v.CallKind {
		case flowir.CallBuiltin:
			switch {
			case v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof" || v.BuiltinName == "Offsetof":
				return
			case v.BuiltinName == "StringData" || v.BuiltinName == "String" || v.BuiltinName == "Slice" || v.BuiltinName == "SliceData" || v.BuiltinName == "Add":
				for _, arg := range v.Args {
					a.breakTargets(arg)
				}
			case v.BuiltinName == "copy" && len(v.Args) == 2:
				if v.Args[0] != nil && v.Args[0].Kind == flowir.ValPlace {
					a.breakPlaceBase(v.Args[0].Place, true)
					a.bindPlace(v.Args[0].Place, nil, true, false)
				}
				a.breakTargets(v.Args[0])
				if v.Args[0] == nil || v.Args[0].Type == nil || containerElemHandsOutReach(v.Args[0].Type) {
					a.breakReachIn(v.Args[1])
				}
			case v.BuiltinName == "append" && len(v.Args) >= 2:
				base := v.Args[0]
				freshBase := base != nil && (base.Kind == flowir.ValScalarLitOrConst ||
					base.Kind == flowir.ValPlace && base.Place.Root == flowir.RootConstOrNil ||
					base.Kind == flowir.ValAllocFresh && (base.AllocKind == flowir.AllocMake || base.AllocKind == flowir.AllocBuiltinNewType || base.AllocKind == flowir.AllocCompositeLit) ||
					isPureFreshDataValueWith(base, nil))
				if !freshBase {
					if slicePlace, ok := outflowUnwrapSlicePlace(base); ok {
						baseObj := slicePlace.Obj
						if _, tr := a.trackedVar(baseObj); tr || a.params[baseObj] {
							if v.Ellipsis {
								a.hasSpreadAppend[baseObj] = true
							}
							if slicePlace.IsBareVar() {
								for _, elem := range v.Args[1:] {
									a.insertionWrites[baseObj] = append(a.insertionWrites[baseObj], elem)
									a.linkBacking(baseObj, elem)
								}
							} else {
								for _, elem := range v.Args[1:] {
									a.pendingAppendSlices = append(a.pendingAppendSlices, outflowPendingStore{
										robj:   baseObj,
										place:  slicePlace,
										source: elem,
									})
								}
							}
						} else {
							a.breakPlaceBase(slicePlace, true)
							for _, elem := range v.Args[1:] {
								a.breakReachIn(elem)
							}
						}
					} else {
						a.breakTargets(base)
						for _, elem := range v.Args[1:] {
							a.breakReachIn(elem)
						}
					}
				}
			}
		case flowir.CallPlain:
			a.scanPlainCallEffects(v)
		case flowir.CallMethod:
			a.scanMethodCallEffects(v)
		default:
			if v.AutoAddrRecv && v.HasRecvPlace {
				a.breakPlaceBase(v.RecvPlace, true)
			}
			a.breakTargets(v.Recv)
			a.breakTargets(v.Callee)
			for _, arg := range v.Args {
				a.breakTargets(arg)
			}
			if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
				for fv := range v.IIFE.FreeVars {
					a.breakObj(fv, true, nil)
				}
			}
		}
	}
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		a.scanValueEffects(ch)
		return true
	})
}

func (a *outflowAnalyzer) collectBodyOps() {
	a.body.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			for i := range op.Dsts {
				op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
					a.scanValueEffects(cv)
					return true
				})
			}
			for _, src := range op.Srcs {
				a.scanValueEffects(src)
			}
			switch op.AssignKind {
			case flowir.AssignZeroDecl:
				for _, dst := range op.Dsts {
					a.bindPlace(dst, nil, false, true)
				}
			case flowir.AssignIncDec, flowir.AssignCompound:
				for _, dst := range op.Dsts {
					if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && dst.Obj != nil {
						if _, tr := a.trackedVar(dst.Obj); tr {
							a.pendingStores = append(a.pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
						}
					}
					a.bindPlace(dst, nil, true, false)
				}
			case flowir.AssignRange:
				var rangeSrc *flowir.Value
				if len(op.Srcs) == 1 {
					rangeSrc = op.Srcs[0]
				}
				container := false
				if rangeSrc != nil && rangeSrc.Type != nil {
					switch u := types.Unalias(rangeSrc.Type).Underlying().(type) {
					case *types.Slice, *types.Array, *types.Map, *types.Basic:
						container = true
					case *types.Pointer:
						_, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array)
						container = isArr
					case *types.Chan:
						a.breakTargets(rangeSrc)
					}
				}
				for _, dst := range op.Dsts {
					if dst.IsBareVar() && dst.Obj != nil {
						a.rangeBound[dst.Obj] = true
					}
					if container {
						a.bindPlace(dst, rangeSrc, false, false)
					} else {
						a.bindPlace(dst, nil, true, false)
					}
				}
			default:
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					a.bindPlace(dst, src, src == nil, false)
					return true
				})
			}
		case flowir.OpTypeSwitchBind:
			a.scanValueEffects(op.SwitchSrc)
			if op.SwitchDst != nil {
				srcVal := op.SwitchSrc
				if srcVal != nil && op.SwitchDst.Type() != nil &&
					(srcVal.Type == nil || !types.Identical(op.SwitchDst.Type(), srcVal.Type)) {
					srcVal = &flowir.Value{
						Kind:         flowir.ValConvert,
						Type:         op.SwitchDst.Type(),
						Raw:          srcVal.Raw,
						Arg:          srcVal,
						IsTypeAssert: true,
					}
				}
				a.bindPlace(flowir.Place{
					Root: flowir.RootLocal,
					Obj:  op.SwitchDst,
					Type: op.SwitchDst.Type(),
				}, srcVal, srcVal == nil, false)
			}
		case flowir.OpChanSend:
			a.breakPlaceBase(op.ChanPlace, true)
			a.breakTargets(op.ChanVal)
			a.breakTargets(op.SendVal)
			a.scanValueEffects(op.ChanVal)
			a.scanValueEffects(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				a.scanValueEffects(r)
			}
		case flowir.OpDefer:
			a.scanValueEffects(op.Call)
		case flowir.OpGo:
			a.breakTargets(op.Call)
		case flowir.OpExpr:
			a.scanValueEffects(op.Expr)
		}
		return true
	})
}
