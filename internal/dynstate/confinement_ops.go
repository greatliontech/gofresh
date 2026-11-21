package dynstate

import (
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (e *confinementEngine) checkBody(b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	if b == nil {
		return false
	}
	for _, resVar := range b.Results {
		if resVar == nil || !e.isRootOrTainted(resVar) {
			continue
		}
		synth := &flowir.Value{
			Kind: flowir.ValPlace,
			Type: resVar.Type(),
			Place: flowir.Place{
				Root: flowir.RootResult,
				Obj:  resVar,
				Type: resVar.Type(),
			},
		}
		if !e.checkReturnResult(synth, resVar.Type(), isTopBody) {
			return false
		}
	}
	for i := range b.Ops {
		if !e.checkOp(&b.Ops[i], b, isTopBody, inOnceDo) {
			return false
		}
	}
	return true
}

func (e *confinementEngine) checkOp(op *flowir.Op, b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	switch op.Kind {
	case flowir.OpGo:
		if op.Call == nil || op.Call.Kind != flowir.ValCall || op.Call.CallKind == flowir.CallBuiltin {
			return !e.valueTouchesAnyRoot(op.Call)
		}
		if op.Call.CallKind == flowir.CallIIFE && (op.Call.IIFE == nil || e.bodyTouchesAnyRoot(op.Call.IIFE)) {
			return false
		}
		if (op.Call.Recv != nil && e.valueIsRooted(op.Call.Recv)) ||
			(op.Call.AutoAddrRecv && op.Call.HasRecvPlace && e.placeIsRooted(op.Call.RecvPlace)) ||
			(op.Call.Callee != nil && e.valueIsRooted(op.Call.Callee)) {
			return false
		}
		prevAllow := e.allowCapturedClosure
		prevInGo := e.inGoSubtree
		e.allowCapturedClosure = false
		e.inGoSubtree = true
		defer func() {
			e.allowCapturedClosure = prevAllow
			e.inGoSubtree = prevInGo
		}()
		if op.Call.Recv != nil && !e.checkValue(op.Call.Recv, modeGeneral) {
			return false
		}
		if op.Call.Callee != nil && !e.checkValue(op.Call.Callee, modeGeneral) {
			return false
		}
		for _, arg := range op.Call.Args {
			if e.valueSuppliesRoot(arg) || !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.OpDefer:
		return e.checkValue(op.Call, modeGeneral)

	case flowir.OpBranch:
		return true

	case flowir.OpExpr:
		return e.checkValue(op.Expr, modeGeneral)

	case flowir.OpChanSend:
		if e.placeIsRooted(op.ChanPlace) || e.valueIsRooted(op.ChanVal) {
			return false
		}
		if !e.checkValue(op.ChanVal, modeGeneral) {
			return false
		}
		return e.checkValue(op.SendVal, modeGeneral)

	case flowir.OpTypeSwitchBind:
		if e.valueIsRooted(op.SwitchSrc) || (e.isRecvMode() && e.isGovernableRecvCall(op.SwitchSrc)) {
			if e.isMethodVal(op.SwitchSrc) ||
				op.SwitchSrc.Type == nil ||
				refconfine.TypeReachesSyncNoCopyByValue(op.SwitchSrc.Type) ||
				(op.SwitchDst != nil && (op.SwitchDst.Type() == nil ||
					refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type()) ||
					(refconfine.TypeCarriesSignature(op.SwitchDst.Type()) && !refconfine.TypeCarriesSignature(op.SwitchSrc.Type)))) {
				return false
			}
			return e.checkValue(op.SwitchSrc, modeGovernedBindOrReturn)
		}
		return e.checkValue(op.SwitchSrc, modeGeneral)

	case flowir.OpReturn:
		for i, res := range op.Results {
			var slotType types.Type
			if b != nil && i < len(b.ResultTypes) {
				slotType = b.ResultTypes[i]
			}
			if !e.checkReturnResult(res, slotType, isTopBody) {
				return false
			}
		}
		return true

	case flowir.OpAssign:
		return e.checkAssignOp(op, isTopBody, inOnceDo)

	default:
		return false
	}
}

func (e *confinementEngine) checkReturnResult(res *flowir.Value, slotType types.Type, isTopBody bool) bool {
	if res == nil {
		return false
	}
	effType := res.Type
	if slotType != nil && refconfine.CallResultHandsOut(slotType) {
		effType = slotType
	}
	if !e.isRecvMode() && !isTopBody && e.valueSuppliesRoot(res) && refconfine.CallResultHandsOut(effType) {
		return false
	}
	if e.valueIsRooted(res) || (e.isRecvMode() && e.isGovernableRecvCall(res)) {
		if e.isMethodVal(res) || res.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(res.Type) {
			return false
		}
		if e.isRecvMode() {
			if !isTopBody {
				return false
			}
			return e.checkValue(res, modeGovernedBindOrReturn)
		}
		if refconfine.TypeHandsOutMutableReach(effType) || syntaxutil.ContainsUintptr(effType) {
			if isTopBody && e.returns != nil {
				*e.returns = true
				return e.checkValue(res, modeGovernedBindOrReturn)
			}
			return false
		}
		if refconfine.TypeCarriesSignature(effType) {
			return false
		}
		return e.checkValue(res, modeGovernedBindOrReturn)
	}
	return e.checkValue(res, modeGeneral)
}

func (e *confinementEngine) dstAcceptsGovernedRoot(dst flowir.Place) bool {
	if dst.IsBlank() {
		return true
	}
	if !dst.IsBareVar() {
		return false
	}
	if dst.Root == flowir.RootPkgGlobal {
		return !e.isEscapingGlobalType(dst.Type)
	}
	return true
}

func (e *confinementEngine) checkAssignLHS(op *flowir.Op, dst flowir.Place, isDef bool, src *flowir.Value, inOnceDo bool) bool {
	if !e.checkPlaceChildValues(dst) {
		return false
	}
	if dst.IsBlank() {
		return true
	}
	if dst.IsBareVar() {
		if dst.Root == flowir.RootPkgGlobal {
			if src != nil && (e.valueIsRooted(src) || e.valueSuppliesRoot(src) || (e.isRecvMode() && e.isGovernableRecvCall(src))) {
				if e.isEscapingGlobalType(dst.Type) {
					return false
				}
			}
			return true
		}
		if e.isRecvMode() && dst.Obj == e.recvObj {
			return false
		}
		if e.isRootOrTainted(dst.Obj) {
			if dst.Obj.Pos() < e.rootBody.BodyStart || dst.Obj.Pos() > e.rootBody.BodyEnd {
				return false
			}
			if !e.isRecvMode() && e.fieldWants != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
				originDefine := e.roots[dst.Obj] && isDef
				if (src == nil || !e.valueIsRooted(src)) && !originDefine {
					return false
				}
			}
		}
		return true
	}
	if e.placeIsRooted(dst) {
		return e.checkRootedStoreAllowed(op, dst, isDef, src, inOnceDo)
	}
	return true
}

func (e *confinementEngine) checkAssignOp(op *flowir.Op, isTopBody bool, inOnceDo bool) bool {
	if op.AssignKind == flowir.AssignRange {
		var rngSrc *flowir.Value
		if len(op.Srcs) == 1 {
			rngSrc = op.Srcs[0]
		}
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, rngSrc, inOnceDo) {
				return false
			}
		}
		if rngSrc != nil {
			if e.valueIsRooted(rngSrc) || (e.isRecvMode() && e.isGovernableRecvCall(rngSrc)) {
				if rngSrc.Type == nil || e.isMethodVal(rngSrc) {
					return false
				}
				switch syntaxutil.UnderlyingType(rngSrc.Type).(type) {
				case *types.Chan, *types.Signature:
					return false
				}
				for _, dst := range op.Dsts {
					if !e.dstAcceptsGovernedRoot(dst) {
						return false
					}
					if !dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
						return false
					}
				}
				if !e.checkValue(rngSrc, modeGovernedBindOrReturn) {
					return false
				}
			} else if !e.checkValue(rngSrc, modeGeneral) {
				return false
			}
		}
		if op.RangeBody != nil {
			return e.checkBody(op.RangeBody, isTopBody, false)
		}
		return true
	}

	if op.AssignKind == flowir.AssignIncDec {
		if len(op.Dsts) != 1 {
			return false
		}
		return e.checkAssignLHS(op, op.Dsts[0], false, op.Srcs[0], inOnceDo)
	}

	if op.AssignKind == flowir.AssignCompound {
		if len(op.Dsts) != 1 || len(op.Srcs) != 1 {
			return false
		}
		dst := op.Dsts[0]
		var rhsOperand *flowir.Value
		if op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			rhsOperand = op.Srcs[0].Args[1]
		} else {
			rhsOperand = op.Srcs[0]
		}
		if !e.checkAssignLHS(op, dst, false, rhsOperand, inOnceDo) {
			return false
		}
		if !e.placeIsRooted(dst) && op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			if !e.checkValue(op.Srcs[0].Args[0], modeGeneral) {
				return false
			}
		}
		return rhsOperand == nil || e.checkValue(rhsOperand, modeGeneral)
	}

	if op.AssignKind == flowir.AssignZeroDecl {
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, nil, inOnceDo) {
				return false
			}
		}
		return true
	}

	if op.AssignKind == flowir.AssignMulti && len(op.Srcs) == 1 {
		src := op.Srcs[0]
		allGoverned := true
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
				return false
			}
			accepted := e.dstAcceptsGovernedRoot(dst) || (e.isRecvMode() && inOnceDo && op.TopLevelInBody && e.placeIsRooted(dst))
			if !accepted || (!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				allGoverned = false
			}
		}
		mode := modeGeneral
		if allGoverned {
			mode = modeGovernedBindOrReturn
			if len(op.Dsts) > 0 && op.Dsts[0].IsBlank() {
				blankPrimary := true
				for _, dst := range op.Dsts[1:] {
					if !dst.IsBlank() && (dst.Type == nil || e.typeHandsOut(dst.Type) || refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
						blankPrimary = false
						break
					}
				}
				if blankPrimary {
					mode = modeBlankDiscard
				}
			}
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) {
				return false
			}
		}
		return e.checkValue(src, mode)
	}

	// AssignPlain (1:1 or N:N).
	ok := true
	op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
		if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
			ok = false
			return false
		}
		if src == nil {
			return true
		}
		mode := modeGeneral
		if dst.IsBlank() {
			mode = modeBlankDiscard
		} else if e.dstAcceptsGovernedRoot(dst) || (e.isRecvMode() && inOnceDo && op.TopLevelInBody && e.placeIsRooted(dst)) {
			mode = modeGovernedBindOrReturn
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) ||
				(!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				ok = false
				return false
			}
		}
		if !e.checkValue(src, mode) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

func (e *confinementEngine) checkValue(v *flowir.Value, mode valueEvalMode) bool {
	if v == nil {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return false

	case flowir.ValScalarLitOrConst:
		return true

	case flowir.ValPlace:
		if e.placeIsRooted(v.Place) {
			if mode == modeGovernedBindOrReturn || mode == modeBlankDiscard {
				return e.checkRootedReadOperand(v)
			}
			if v.Type == nil || refconfine.CallResultHandsOut(v.Type) {
				return false
			}
			return e.checkRootedReadOperand(v)
		}
		return e.checkPlaceChildValues(v.Place)

	case flowir.ValAddrOf:
		if e.placeIsRooted(v.AddrPlace) {
			return false
		}
		if !e.checkPlaceChildValues(v.AddrPlace) {
			return false
		}
		if v.Low != nil && !e.checkValue(v.Low, modeGeneral) {
			return false
		}
		if v.High != nil && !e.checkValue(v.High, modeGeneral) {
			return false
		}
		if v.Max != nil && !e.checkValue(v.Max, modeGeneral) {
			return false
		}
		return true

	case flowir.ValMethodVal:
		if e.valueIsRooted(v.Recv) || (v.HasRecvPlace && e.placeIsRooted(v.RecvPlace)) {
			return false
		}
		return e.checkValue(v.Recv, modeGeneral)

	case flowir.ValChanRecv:
		if e.valueIsRooted(v.Chan) {
			return false
		}
		return e.checkValue(v.Chan, modeGeneral)

	case flowir.ValConvert:
		if syntaxutil.IsUnsafePointerType(v.Type) &&
			(v.Arg == nil || v.Arg.Type == nil || syntaxutil.ContainsUintptr(v.Arg.Type) || e.valueSuppliesRoot(v.Arg)) {
			return false
		}
		if e.valueIsRooted(v.Arg) || (e.isRecvMode() && e.isGovernableRecvCall(v.Arg)) {
			if e.isMethodVal(v.Arg) || v.Arg == nil || v.Arg.Type == nil || v.Type == nil ||
				syntaxutil.IsUnsafePointerType(v.Type) ||
				syntaxutil.IsUnsafePointerType(v.Arg.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Arg.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
				return false
			}
			if v.IsTypeAssert && mode != modeBlankDiscard &&
				refconfine.TypeCarriesSignature(v.Type) && !refconfine.TypeCarriesSignature(v.Arg.Type) {
				return false
			}
			if !refconfine.CallResultHandsOut(v.Type) {
				return e.checkRootedReadOperand(v.Arg)
			}
			if !v.IsTypeAssert && !refconfine.CallResultHandsOut(v.Arg.Type) {
				if _, isSlice := syntaxutil.UnderlyingType(v.Type).(*types.Slice); isSlice {
					return e.checkRootedReadOperand(v.Arg)
				}
			}
			if v.IsTypeAssert && (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) {
				return e.checkRootedReadOperand(v.Arg)
			}
			return false
		}
		return e.checkValue(v.Arg, mode)

	case flowir.ValCompare:
		for _, side := range []*flowir.Value{v.Left, v.Right} {
			if side == nil {
				continue
			}
			if e.valueIsRooted(side) {
				if e.isMethodVal(side) || side.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(side.Type) {
					return false
				}
				if !e.checkRootedReadOperand(side) {
					return false
				}
			} else if !e.checkValue(side, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValAllocFresh:
		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if elt.MapKey != nil && !e.checkValue(elt.MapKey, modeGeneral) {
				return false
			}
			if elt.Index != nil && !e.checkValue(elt.Index, modeGeneral) {
				return false
			}
			if elt.Value != nil && !e.checkValue(elt.Value, modeGeneral) {
				return false
			}
		}
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValMakeClosure:
		if v.Closure == nil {
			return false
		}
		captured := map[types.Object]bool{}
		for fv := range v.Closure.FreeVars {
			if e.isRootOrTainted(fv) {
				captured[fv] = true
			}
		}
		if len(captured) == 0 {
			return true
		}
		if !e.allowCapturedClosure {
			return false
		}
		subEng := &confinementEngine{
			audited:              e.audited,
			p:                    e.p,
			fc:                   e.fc,
			rootBody:             v.Closure,
			roots:                captured,
			tainted:              map[types.Object]bool{},
			tolerateRootedStores: e.tolerateRootedStores,
			allowCapturedClosure: true,
			wants:                e.wants,
			methodWants:          e.methodWants,
			fieldWants:           e.fieldWants,
			elemWants:            e.elemWants,
		}
		return subEng.run()

	case flowir.ValCall:
		return e.checkCall(v, mode == modeGovernedBindOrReturn || mode == modeBlankDiscard)

	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	default:
		return false
	}
}

func (e *confinementEngine) checkCall(v *flowir.Value, governed bool) bool {
	switch v.CallKind {
	case flowir.CallBuiltin:
		if v.BuiltinName == "StringData" && len(v.Args) > 0 && (e.valueIsRooted(v.Args[0]) || e.valueSuppliesRoot(v.Args[0])) {
			return false
		}
		switch v.BuiltinName {
		case "Sizeof", "Alignof", "Offsetof":
			return true
		case "len", "cap":
			for _, arg := range v.Args {
				if e.valueIsRooted(arg) {
					if e.isMethodVal(arg) || !e.checkRootedReadOperand(arg) {
						return false
					}
				} else if !e.checkValue(arg, modeGeneral) {
					return false
				}
			}
			return true
		}
		for _, arg := range v.Args {
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.CallIIFE:
		if v.IIFE == nil {
			return false
		}
		if len(v.Args) == 1 && !v.Ellipsis && v.Args[0] != nil && v.Args[0].Type != nil {
			if tup, isTuple := types.Unalias(v.Args[0].Type).(*types.Tuple); isTuple && tup.Len() > 1 {
				arg := v.Args[0]
				allGoverned := true
				v.ForEachArgParam(func(_ *flowir.Value, slotType types.Type, _ int, pIdx int, ok bool, packedVariadic bool) bool {
					if !ok || packedVariadic || pIdx >= len(v.IIFE.Params) {
						allGoverned = false
						return false
					}
					pv := v.IIFE.Params[pIdx]
					isBlank := pv != nil && pv.Name() == "_"
					if !isBlank && (slotType == nil || refconfine.TypeReachesSyncNoCopyByValue(slotType)) {
						allGoverned = false
						return false
					}
					return true
				})
				if allGoverned && (e.valueIsRooted(arg) || (e.isRecvMode() && e.isGovernableRecvCall(arg))) {
					if e.isMethodVal(arg) || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
						return false
					}
					if !e.checkValue(arg, modeGovernedBindOrReturn) {
						return false
					}
				} else if !e.checkValue(arg, modeGeneral) {
					return false
				}
				return e.checkBody(v.IIFE, false, false)
			}
		}
		for i, arg := range v.Args {
			pIdx, ok := v.ParamIndexForArg(i)
			isPackedVariadic := v.CalleeSig != nil && v.CalleeSig.Variadic() && !v.Ellipsis && i >= v.CalleeSig.Params().Len()-1
			if ok && !isPackedVariadic && pIdx < len(v.IIFE.Params) {
				if e.valueIsRooted(arg) || (e.isRecvMode() && e.isGovernableRecvCall(arg)) {
					if e.isMethodVal(arg) || arg.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
						return false
					}
					if !e.checkValue(arg, modeGovernedBindOrReturn) {
						return false
					}
					continue
				}
			}
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return e.checkBody(v.IIFE, false, false)

	case flowir.CallMethod:
		if e.isSyncOnceCall(v) {
			if e.valueIsRooted(v.Recv) {
				if !e.checkRootedReadOperand(v.Recv) {
					return false
				}
			} else if !e.checkValue(v.Recv, modeGeneral) {
				return false
			}
			prevAdm := e.activeOnceAdmission
			if e.isRecvMode() && v.CallAST != nil {
				e.activeOnceAdmission = e.admittedOnceDo[v.CallAST]
			}
			defer func() { e.activeOnceAdmission = prevAdm }()
			return e.checkBody(v.Args[0].Closure, false, e.isRecvMode() && e.activeOnceAdmission != nil)
		}
		if e.valueIsRooted(v.Recv) {
			if e.inGoSubtree || v.IsMethodExprCall || !e.checkRootedReadOperand(v.Recv) {
				return false
			}
			if refconfine.AuditedSynchronization(e.audited, v.CalleeFunc) {
				if !v.HasRecvPlace || !refconfine.InPlaceSyncReceiver(e.p.TypesInfo, v.RecvPlace.Raw) {
					return false
				}
				return e.checkCallArgs(v)
			}
			if e.isRecvMode() {
				if v.CalleeFunc == nil || v.Selection == nil || v.CallAST == nil {
					return false
				}
				if v.CalleeFunc.Pkg() != e.p.Types {
					if e.methodWants == nil || v.CalleeFunc.Pkg() == nil ||
						v.CalleeFunc.Pkg().Path() == "sync" || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
						!refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) {
						return false
					}
					e.methodWants[syntaxutil.MethodFactKey(v.CalleeFunc)] = true
					return e.checkCallArgs(v)
				}
				sel := v.CalleeSelector()
				if sel == nil {
					return false
				}
				target := syntaxutil.RecvTypeNameOf(e.p, sel) + "." + v.CalleeFunc.Name()
				if _, sibling := e.methods[target]; sibling {
					if e.recordMethodChain != nil {
						e.recordMethodChain(target)
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				} else {
					targets, ok := unexportedDispatchTargets(e.p, v.Selection, v.CalleeFunc, e.declaredByName, e.bodyless)
					if !ok && !e.bodyless[v.CalleeFunc.Name()] {
						targets, ok = closedFieldDispatchTargets(e.p.TypesInfo, e.recvObj, sel, v.CalleeFunc.Name(), e.closedFields, e.declared)
					}
					if !ok {
						return false
					}
					if e.recordMethodChain != nil {
						for _, t := range targets {
							e.recordMethodChain(t)
						}
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				}
				return e.checkCallArgs(v)
			}
			if e.methodWants == nil || v.CalleeFunc == nil || v.CalleeFunc.Pkg() == nil ||
				v.CalleeFunc.Pkg().Path() == "sync" || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
				v.Selection == nil || !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) {
				return false
			}
			e.methodWants[syntaxutil.MethodFactKey(v.CalleeFunc)] = true
			return e.checkCallArgs(v)
		}
		if !e.checkValue(v.Recv, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	case flowir.CallPlain:
		return e.checkCallArgs(v)

	case flowir.CallIndirect:
		if e.valueIsRooted(v.Callee) {
			if e.isRecvMode() || e.isMethodVal(v.Callee) || e.typeHandsOut(v.Type) {
				return false
			}
			if !e.checkRootedReadOperand(v.Callee) {
				return false
			}
		} else if !e.checkValue(v.Callee, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	default:
		return false
	}
}

func (e *confinementEngine) checkCallArgs(v *flowir.Value) bool {
	var checkedUnrooted *flowir.Value
	okAll := true
	v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, _ int, pIdx int, hasParam bool, packedVariadic bool) bool {
		paramType := v.FormalParamSlotType(pIdx, packedVariadic)
		if !e.valueIsRooted(arg) {
			if arg != checkedUnrooted {
				checkedUnrooted = arg
				if !e.checkValue(arg, modeGeneral) {
					okAll = false
					return false
				}
			}
			return true
		}
		if slotType == nil || e.isMethodVal(arg) ||
			refconfine.TypeReachesSyncNoCopyByValue(slotType) ||
			(paramType != nil && refconfine.TypeReachesSyncNoCopyByValue(paramType)) {
			okAll = false
			return false
		}
		handsOutSlot := refconfine.CallResultHandsOut(slotType)
		if !handsOutSlot {
			if !e.checkRootedReadOperand(arg) {
				okAll = false
				return false
			}
			return true
		}
		if e.inGoSubtree {
			okAll = false
			return false
		}
		deferred := false
		if v.CallKind == flowir.CallPlain && e.wants != nil && v.CalleeFunc != nil && v.CalleeSig != nil && v.CalleeSig.Recv() == nil &&
			(!e.isRecvMode() || (!refconfine.TypeCarriesSignature(slotType) && (paramType == nil || !refconfine.TypeCarriesSignature(paramType)))) {
			if hasParam {
				e.wants[syntaxutil.ParamKey{
					Func:  syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()},
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.fieldWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace && len(v.Callee.Place.Projs) > 0 {
			last := v.Callee.Place.Projs[len(v.Callee.Place.Projs)-1]
			prefix := v.Callee.Place
			prefix.Projs = v.Callee.Place.Projs[:len(v.Callee.Place.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil && e.placeIsRooted(prefix) {
				if hasParam {
					e.fieldWants[syntaxutil.FieldPosKey{Field: last.Field.Name(), Index: pIdx}] = true
					deferred = true
				}
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.elemWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace &&
			v.Callee.Place.Root == flowir.RootPkgGlobal && v.Callee.Place.Obj != nil &&
			len(v.Callee.Place.Projs) == 1 && v.Callee.Place.Projs[0].Kind == flowir.ProjIndex &&
			refconfine.TypeMayCarryUnknownDynamic(e.audited, v.Callee.Place.Obj.Type()) {
			if hasParam {
				e.elemWants[syntaxutil.ElemParamUse{
					Owner: syntaxutil.DynamicVarKey(v.Callee.Place.Obj),
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred {
			okAll = false
			return false
		}
		if !e.checkRootedReadOperand(arg) {
			okAll = false
			return false
		}
		return true
	})
	return okAll
}
