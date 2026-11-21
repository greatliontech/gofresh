package freshstruct

import (
	"go/ast"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func (msc *mutatedStructCollector) scanTypesInfoAndFinalize() ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	for id, inst := range msc.p.TypesInfo.Instances {
		syncEncl := msc.idx.SyncEnclFuncDecl(id)
		if tn, isTN := msc.p.TypesInfo.Uses[id].(*types.TypeName); isTN && tn != nil {
			isStdTN := msc.isTrueStdPkg(tn.Pkg())
			if isStdTN && tn.Pkg().Path() == "sync/atomic" && tn.Name() == "Pointer" {
				continue
			}
			isForeignTN := tn.Pkg() != nil && tn.Pkg() != msc.p.Types && !isStdTN
			if isStdTN {
				msc.recordGenericArgTypes(id, inst.Type)
			} else {
				msc.recordNonStdGenericTypeUse(id, syncEncl, inst.Type, isForeignTN)
				if inst.TypeArgs != nil {
					for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
						msc.recordNonStdGenericTypeUse(id, syncEncl, inst.TypeArgs.At(ti), isForeignTN)
					}
				}
			}
			if inst.Type != nil && !types.IsInterface(inst.Type) {
				mset := types.NewMethodSet(types.NewPointer(inst.Type))
				for mi := 0; mi < mset.Len(); mi++ {
					msc.recordGenericArgTypes(id, mset.At(mi).Type())
				}
			}
			continue
		}
		fnObj, ok := msc.p.TypesInfo.Uses[id].(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		orig := fnObj.Origin()
		instSig, okInst := syntaxutil.UnderlyingType(inst.Type).(*types.Signature)
		origSig, okOrig := orig.Type().(*types.Signature)
		if !okInst || !okOrig {
			continue
		}
		isStdOrig := msc.isTrueStdPkg(orig.Pkg())
		isForeignNonStd := orig.Pkg() != nil && orig.Pkg() != msc.p.Types && !isStdOrig
		isCmp := isStdOrig && orig.Pkg().Path() == "cmp"
		if msc.directCallFuns[id] {
			if inst.TypeArgs != nil && origSig.TypeParams() != nil {
				for ti := 0; ti < inst.TypeArgs.Len() && ti < origSig.TypeParams().Len(); ti++ {
					tp := origSig.TypeParams().At(ti)
					ta := inst.TypeArgs.At(ti)
					if !isStdOrig {
						msc.recordNonStdGenericTypeUse(id, syncEncl, ta, isForeignNonStd)
					}
					if !sigMentionsSpecificTypeParam(origSig, tp) {
						if !(isCmp && !types.IsInterface(ta)) {
							msc.recordGenericArgTypes(id, types.NewPointer(ta))
						}
					}
				}
			}
			continue
		}
		for pi := 0; pi < instSig.Params().Len() && pi < origSig.Params().Len(); pi++ {
			instPT := instSig.Params().At(pi).Type()
			checkPT := instPT
			if instSig.Variadic() && pi == instSig.Params().Len()-1 {
				if sl, isSl := types.Unalias(instPT).Underlying().(*types.Slice); isSl {
					checkPT = sl.Elem()
				}
			}
			if isCmp && !types.IsInterface(checkPT) {
				continue
			}
			if syntaxutil.TypeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				if isStdOrig {
					msc.recordGenericArgTypes(id, instPT)
				} else {
					msc.recordNonStdGenericTypeUse(id, syncEncl, instPT, isForeignNonStd)
				}
			}
		}
		for ri := 0; ri < instSig.Results().Len() && ri < origSig.Results().Len(); ri++ {
			instRT := instSig.Results().At(ri).Type()
			if isCmp && !types.IsInterface(instRT) {
				continue
			}
			if syntaxutil.TypeMentionsTypeParam(origSig.Results().At(ri).Type()) {
				if isStdOrig {
					msc.recordGenericArgTypes(id, instRT)
					if orig.Pkg() != nil && orig.Pkg().Path() == "reflect" && orig.Name() == "TypeAssert" && !isEmptyInterfaceType(instRT) {
						msc.recordBoundaryResultOrRecvChanType(instRT)
					}
				} else {
					msc.recordNonStdGenericTypeUse(id, syncEncl, instRT, isForeignNonStd)
				}
			}
		}
		if inst.TypeArgs != nil {
			for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
				ta := inst.TypeArgs.At(ti)
				if isCmp && !types.IsInterface(ta) {
					continue
				}
				if !isStdOrig {
					msc.recordNonStdGenericTypeUse(id, syncEncl, ta, isForeignNonStd)
				}
				msc.recordGenericArgTypes(id, types.NewPointer(ta))
			}
		}
	}
	for selExpr, selInfo := range msc.p.TypesInfo.Selections {
		if msc.directCallFuns[selExpr] || selInfo == nil || (selInfo.Kind() != types.MethodVal && selInfo.Kind() != types.MethodExpr) {
			continue
		}
		fnObj, ok := selInfo.Obj().(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		syncEncl := msc.idx.SyncEnclFuncDecl(selExpr)
		fresh, freshEsc := msc.getFresh(syncEncl)
		if recvSt := msc.unexportedForeignRecvStruct(fnObj); recvSt != nil {
			msc.recordStructAt(selExpr, recvSt)
			if selInfo.Kind() == types.MethodVal {
				msc.recordMutatedExpr(selExpr, selExpr.X, fresh, freshEsc)
			}
		}
		orig := fnObj.Origin()
		if msc.isTrueStdPkg(orig.Pkg()) && orig.Pkg().Path() == "sync/atomic" && syntaxutil.MethodRecvNamedTypeName(orig) == "Pointer" {
			if selInfo.Kind() == types.MethodVal && orig.Name() != "Load" && !msc.isFreshAddrTarget(syncEncl, selExpr.X, fresh, freshEsc) {
				msc.recordMutatedExpr(selExpr, selExpr.X, fresh, freshEsc)
			}
			continue
		}
		origSig, okOrig := orig.Type().(*types.Signature)
		instSig, okInst := syntaxutil.UnderlyingType(selInfo.Type()).(*types.Signature)
		if okInst && !msc.exempted[selExpr] && !isUnreachableConstIfBranch(msc.p, msc.idx, selExpr) {
			for pi := 0; pi < instSig.Params().Len(); pi++ {
				if capNamed := msc.foreignReflectTypeCapsulePtrElem(instSig.Params().At(pi).Type()); capNamed != nil {
					msc.recordStructAt(selExpr, capNamed)
				}
			}
		}
		isCrossOrIfaceSel := !msc.isTrueStdPkg(orig.Pkg()) &&
			((orig.Pkg() != nil && orig.Pkg() != msc.p.Types) ||
				(okOrig && origSig.Recv() != nil && isRuntimeInterfaceType(origSig.Recv().Type())))
		if isCrossOrIfaceSel {
			if okOrig {
				if origSig.Recv() != nil {
					msc.recordBoundaryParamType(origSig.Recv().Type())
				}
				for pi := 0; pi < origSig.Params().Len(); pi++ {
					msc.recordBoundaryParamType(origSig.Params().At(pi).Type())
				}
				for ri := 0; ri < origSig.Results().Len(); ri++ {
					msc.recordBoundaryResultOrRecvChanType(origSig.Results().At(ri).Type())
				}
			}
			if selInfo.Kind() == types.MethodVal && typeMentionsReflectValue(msc.p.TypesInfo.TypeOf(selExpr.X)) {
				msc.sawReflectValueCrossPkgArg = true
			}
			if okInst {
				for pi := 0; pi < instSig.Params().Len(); pi++ {
					msc.recordBoundaryParamType(instSig.Params().At(pi).Type())
				}
				for ri := 0; ri < instSig.Results().Len(); ri++ {
					msc.recordBoundaryResultOrRecvChanType(instSig.Results().At(ri).Type())
				}
			}
		}
		if !okOrig || !okInst || (origSig.TypeParams().Len() == 0 && origSig.RecvTypeParams().Len() == 0) {
			continue
		}
		isStdOrig := msc.isTrueStdPkg(orig.Pkg())
		isForeignNonStd := orig.Pkg() != nil && orig.Pkg() != msc.p.Types && !isStdOrig
		recordSelGeneric := func(t types.Type) {
			if isStdOrig {
				msc.recordGenericArgTypes(selExpr, t)
			} else {
				msc.recordNonStdGenericTypeUse(selExpr, syncEncl, t, isForeignNonStd)
			}
		}
		offset := 0
		if selInfo.Kind() == types.MethodExpr {
			offset = 1
			if origSig.RecvTypeParams().Len() > 0 && instSig.Params().Len() > 0 {
				recordSelGeneric(instSig.Params().At(0).Type())
			}
		} else if origSig.RecvTypeParams().Len() > 0 && !msc.isFreshAddrTarget(syncEncl, selExpr.X, fresh, freshEsc) {
			recordSelGeneric(selInfo.Recv())
		}
		for pi := 0; pi < origSig.Params().Len() && pi+offset < instSig.Params().Len(); pi++ {
			if syntaxutil.TypeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				recordSelGeneric(instSig.Params().At(pi + offset).Type())
			}
		}
		for ri := 0; ri < origSig.Results().Len() && ri < instSig.Results().Len(); ri++ {
			if syntaxutil.TypeMentionsTypeParam(origSig.Results().At(ri).Type()) {
				recordSelGeneric(instSig.Results().At(ri).Type())
			}
		}
	}
	for id, obj := range msc.p.TypesInfo.Uses {
		if msc.exempted[id] || isUnreachableConstIfBranch(msc.p, msc.idx, id) || obj == nil {
			continue
		}
		if v, okVar := obj.(*types.Var); okVar {
			if !v.IsField() && v.Pkg() != nil && v.Pkg() != msc.p.Types && !msc.isTrueStdPkg(v.Pkg()) {
				msc.recordBoundaryParamType(v.Type())
				msc.recordBoundaryResultOrRecvChanType(v.Type())
			}
			continue
		}
		fn, okFn := obj.(*types.Func)
		if !okFn || fn == nil {
			continue
		}
		orig := fn.Origin()
		qPkg := orig.Pkg()
		if qPkg == nil || qPkg == msc.p.Types || msc.isTrueStdPkg(qPkg) {
			continue
		}
		if !msc.directCallFuns[id] {
			uType := msc.p.TypesInfo.TypeOf(id)
			if uSig, okUS := syntaxutil.UnderlyingType(uType).(*types.Signature); okUS {
				for pi := 0; pi < uSig.Params().Len(); pi++ {
					msc.recordBoundaryParamType(uSig.Params().At(pi).Type())
				}
				for ri := 0; ri < uSig.Results().Len(); ri++ {
					msc.recordBoundaryResultOrRecvChanType(uSig.Results().At(ri).Type())
				}
			} else {
				msc.recordBoundaryParamType(uType)
			}
		}
		if !sigMentionsReflectTypeParam(orig) {
			continue
		}
		qScope := qPkg.Scope()
		if qScope == nil {
			continue
		}
		for _, nm := range qScope.Names() {
			tn, okTN := qScope.Lookup(nm).(*types.TypeName)
			if !okTN || tn == nil {
				continue
			}
			if _, isSt := tn.Type().Underlying().(*types.Struct); isSt {
				ref := syntaxutil.TypeRef{Pkg: qPkg.Path(), Name: tn.Name()}
				if ref.Valid() {
					msc.markMutated(ref, "foreign_reflect_type_param_ref", nil)
				}
			}
		}
	}

	exportedRefSelsByOwner := map[syntaxutil.TypeRef]map[*ast.SelectorExpr]bool{}
	isStructTrackedPtr := func(t types.Type) bool {
		if t == nil {
			return false
		}
		ptr, isP := types.Unalias(t).(*types.Pointer)
		if !isP {
			return false
		}
		_, _, st, ok := syntaxutil.TypeRefOfStructFull(ptr.Elem())
		return ok && st != nil && st.NumFields() > 0
	}
	isNonEmptyStructElemSeq := func(t types.Type) bool {
		switch u := syntaxutil.UnderlyingType(t).(type) {
		case *types.Slice:
			_, _, elemSt, isSt := syntaxutil.TypeRefOfStructFull(u.Elem())
			return isSt && elemSt.NumFields() > 0
		case *types.Array:
			_, _, elemSt, isSt := syntaxutil.TypeRefOfStructFull(u.Elem())
			return isSt && elemSt.NumFields() > 0
		}
		return false
	}
	for selExpr, selInfo := range msc.p.TypesInfo.Selections {
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || !selInfo.Obj().Exported() {
			continue
		}
		if fv, isFV := selInfo.Obj().(*types.Var); isFV && msc.exemptReadFields[fv] {
			continue
		}
		ft := selInfo.Type()
		if !refconfine.TypeCarriesMutableRefWith(ft, isStructTrackedPtr) || isNonEmptyStructElemSeq(ft) {
			continue
		}
		if refconfine.IsInsideExemptWriteOrAddr(msc.idx, selExpr, msc.exempted) {
			continue
		}
		if parAs, isAs := msc.idx.ParentUnparen(selExpr).(*ast.AssignStmt); isAs {
			onLHS := false
			for _, lhs := range parAs.Lhs {
				if ast.Unparen(lhs) == selExpr {
					onLHS = true
					break
				}
			}
			if onLHS {
				continue
			}
		}
		syncEncl := msc.idx.SyncEnclFuncDecl(selExpr)
		fresh, freshEsc := msc.getFresh(syncEncl)
		if msc.isFreshAddrTarget(syncEncl, selExpr, fresh, freshEsc) {
			continue
		}
		syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
			if hop == nil || (syncEncl != nil && msc.exemptFamilyByFunc[syncEncl][hop]) {
				return
			}
			ref, _, hopSt, okHop := syntaxutil.TypeRefOfStructFull(hop)
			if !okHop || !ref.Valid() || hopSt.NumFields() == 0 || msc.seen[ref] {
				return
			}
			if exportedRefSelsByOwner[ref] == nil {
				exportedRefSelsByOwner[ref] = map[*ast.SelectorExpr]bool{}
			}
			exportedRefSelsByOwner[ref][selExpr] = true
		})
	}
	for ownerRef, selSet := range exportedRefSelsByOwner {
		if msc.seen[ownerRef] {
			continue
		}
		var pendingConds []syntaxutil.ConditionalStructMutation
		if !refconfine.VerifyReadOnlyRefConfinement(msc.p, refconfine.Config{
			Index:                         msc.idx,
			IsImmutablePtr:                isStructTrackedPtr,
			AllowReturnFromUnexportedFunc: true,
			IsExemptField: func(fv *types.Var) bool {
				return fv != nil && msc.exemptReadFields[fv]
			},
			AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
				ct := msc.p.TypesInfo.TypeOf(containerExpr)
				if ct == nil {
					return false
				}
				var elemT types.Type
				switch u := syntaxutil.UnderlyingType(ct).(type) {
				case *types.Slice:
					elemT = u.Elem()
				case *types.Array:
					elemT = u.Elem()
				case *types.Map:
					elemT = u.Elem()
				default:
					return false
				}
				iface, okI := syntaxutil.UnderlyingType(elemT).(*types.Interface)
				return okI && iface.NumMethods() > 0
			},
			AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
				if callee == nil || call.Ellipsis.IsValid() {
					return false
				}
				orig := callee.Origin()
				sig, okSig := orig.Type().(*types.Signature)
				if !okSig || sig.Recv() == nil {
					return false
				}
				recvT := types.Unalias(sig.Recv().Type())
				if _, isPtr := recvT.(*types.Pointer); isPtr {
					return false
				}
				rn, isRN := recvT.(*types.Named)
				if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
					return false
				}
				if _, isSl := rn.Underlying().(*types.Slice); !isSl {
					return false
				}
				for _, a := range call.Args {
					at := msc.p.TypesInfo.TypeOf(a)
					if refconfine.TypeContainsRefOrPointerWith(at, isStructTrackedPtr) && !types.Identical(types.Unalias(at), rn) {
						return false
					}
				}
				for ri := 0; ri < sig.Results().Len(); ri++ {
					if refconfine.TypeContainsRefOrPointerWith(sig.Results().At(ri).Type(), isStructTrackedPtr) {
						return false
					}
				}
				sliceRef := syntaxutil.TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
				if !sliceRef.Valid() {
					return false
				}
				guardPkg := ""
				if orig.Pkg() != nil {
					guardPkg = orig.Pkg().Path()
				}
				pendingConds = append(pendingConds, syntaxutil.ConditionalStructMutation{
					Struct:      ownerRef,
					GuardPkg:    guardPkg,
					GuardStruct: sliceRef,
				})
				return true
			},
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel || !selSet[sel] {
					return false, false
				}
				ft := msc.p.TypesInfo.TypeOf(sel)
				return refconfine.IsDirectMutableRefWith(ft, isStructTrackedPtr), true
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(msc.p, call)
			},
			AllowAssignTarget: func(lhs, _ ast.Expr, rhsIsRef bool) bool {
				if rhsIsRef {
					return false
				}
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel {
					return false
				}
				selInfo := msc.p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false
				}
				syncEncl := msc.idx.SyncEnclFuncDecl(lhs)
				fresh, freshEsc := msc.getFresh(syncEncl)
				if !msc.isFreshMutTarget(syncEncl, lhs, fresh, freshEsc) {
					return false
				}
				stNamed, isN := types.Unalias(msc.p.TypesInfo.TypeOf(lhs)).(*types.Named)
				if !isN || !isOpaqueUnexportedForeignStruct(msc.p.Types, stNamed) {
					return false
				}
				guardRef := syntaxutil.TypeRef{Pkg: stNamed.Obj().Pkg().Path(), Name: stNamed.Obj().Name()}
				if !guardRef.Valid() {
					return false
				}
				pendingConds = append(pendingConds, syntaxutil.ConditionalStructMutation{
					Struct:                       ownerRef,
					GuardStruct:                  guardRef,
					RequireImmutableCapsuleGuard: true,
				})
				return true
			},
		}) {
			msc.markMutated(ownerRef, "unconfined_exported_ref_field", nil)
		} else {
			for _, cm := range pendingConds {
				if cm.Valid() {
					msc.condSeen[cm] = true
				}
			}
		}
	}

	sawReflectValueInterfaceCall := false
	sawReflectValueCallMethod := false
	for id, obj := range msc.p.TypesInfo.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || fn == nil || !msc.isTrueStdPkg(fn.Pkg()) {
			continue
		}
		if isMutatingOrEscapingReflectCallee(fn) {
			msc.sawReflectMutOrEscape = true
		} else if fn.Pkg().Path() == "reflect" {
			if sig, okS := fn.Type().(*types.Signature); okS {
				if sig.Recv() == nil && fn.Origin().Name() == "TypeAssert" {
					sawReflectValueInterfaceCall = true
					if !msc.directCallFuns[id] {
						msc.sawReflectMutOrEscape = true
					}
				} else if sig.Recv() != nil && syntaxutil.IsNamedInPkg(sig.Recv().Type(), "reflect", "Value") {
					switch fn.Name() {
					case "Interface":
						sawReflectValueInterfaceCall = true
						if !msc.directCallFuns[id] {
							msc.sawReflectMutOrEscape = true
						}
					case "Call":
						sawReflectValueCallMethod = true
						if !msc.directCallFuns[id] {
							msc.sawReflectMutOrEscape = true
						}
					case "CallSlice":
						msc.sawReflectMutOrEscape = true
					}
				}
			}
		}
	}
	if !msc.sawReflectMutOrEscape && sawReflectValueCallMethod {
		if !pkgConfinesAllReflectValueCalls(msc.ctx, msc.traceTarget, msc.p, msc.idx, msc.isTrueStdPkg) {
			msc.sawReflectMutOrEscape = true
		}
	}
	if !msc.sawReflectMutOrEscape && sawReflectValueInterfaceCall && (msc.sawCarrierPanic || pkgCanPassOrReturnExtractedObject(msc.ctx, msc.traceTarget, msc.p, msc.idx, msc.isTrueStdPkg)) {
		msc.sawReflectMutOrEscape = true
	}
	if sawReflectValueInterfaceCall && msc.sawFmtPointerIdentityOnAny {
		for k := range msc.directReflectedNonEmptyIfaces {
			msc.fmtPointerErasedIfaces[k] = true
		}
		for k := range msc.directReflectedUnexportedIfaces {
			msc.fmtPointerErasedIfaces[k] = true
		}
	}
	canBypassFlagRO, hasRVBoundaryEscape := pkgCanBypassReflectFlagRO(msc.p, msc.idx, msc.sawReflectValueCrossPkgArg, msc.funcParamVars)
	if hasRVBoundaryEscape {
		msc.sawReflectMutOrEscape = true
	}
	if msc.sawUnsafeIfaceHeaderBypass {
		canBypassFlagRO = true
	}
	if canBypassFlagRO {
		for k := range msc.directReflectedUnexportedIfaces {
			msc.directReflectedNonEmptyIfaces[k] = true
		}
		for k := range msc.anyErasedUnexportedIfaces {
			msc.anyErasedNonEmptyIfaces[k] = true
		}
	}
	if msc.sawReflectMutOrEscape {
		if canBypassFlagRO {
			for ref := range msc.directFlagROStructs {
				msc.markMutated(ref, "direct_reflect_flag_ro_bypass", nil)
			}
		} else if hasRVBoundaryEscape {
			for ref := range msc.directFlagROStructs {
				if !msc.seen[ref] {
					msc.pendingBoxed[pendingBoxedKey{ref: ref, methodSet: syntaxutil.ReflectFlagROLocalBypassKey}] = true
				}
			}
		}
	}
	if canBypassFlagRO {
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
	}
	if msc.sawReflectMutOrEscape {
		for k := range msc.directReflectedNonEmptyIfaces {
			msc.reflectedIfaceSets[k] = true
			if canBypassFlagRO {
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] = true
			}
		}
	}
	if msc.sawFmtPointerIdentityOnAny && msc.sawRawUintptrToUnsafePtr {
		msc.sawReflectValueOfAny = true
		msc.sawReflectMutOrEscape = true
		canBypassFlagRO = true
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
	}
	localAnyReflect := (msc.sawReflectValueOfAny && msc.sawReflectMutOrEscape) || msc.sawStdMutatingEmptyIfaceCall || msc.sawCarrierPanic
	localAnyReflectFlagRO := msc.sawReflectValueOfAny && msc.sawReflectMutOrEscape && canBypassFlagRO
	pkgLeaksAnyUpward := pkgCanLeakEmptyIfaceUpward(msc.p, msc.idx)
	canReflectOrLeakAny := localAnyReflect || pkgLeaksAnyUpward
	if localAnyReflectFlagRO {
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
	}
	uncondAnyReflect := localAnyReflect || msc.pkgCrossesAnyBoundary
	if uncondAnyReflect {
		for k := range msc.anyErasedNonEmptyIfaces {
			msc.reflectedIfaceSets[k] = true
			if localAnyReflectFlagRO {
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] = true
			}
		}
	}
	if msc.sawRawUintptrToUnsafePtr {
		for k := range msc.fmtPointerErasedIfaces {
			msc.reflectedIfaceSets[k] = true
			msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] = true
		}
	}
	sortedParamKeys := func(m map[syntaxutil.ParamKey]bool) []syntaxutil.ParamKey {
		if len(m) == 0 {
			return nil
		}
		res := make([]syntaxutil.ParamKey, 0, len(m))
		for pk := range m {
			if pk.Valid() {
				res = append(res, pk)
			}
		}
		slices.SortFunc(res, syntaxutil.ParamKey.Compare)
		return res
	}
	thiefFacts := collectContextKeyThiefFacts(msc.p, msc.idx)
	var reflectedFacts []syntaxutil.ReflectedIfaceFact
	if canReflectOrLeakAny {
		reflectedFacts = append(reflectedFacts, syntaxutil.ReflectedIfaceFact{
			MethodSet:                  syntaxutil.EmptyIfaceMethodSetKey,
			ReflectsEmptyIfaceLocally:  localAnyReflect,
			LeaksEmptyIfaceUpward:      pkgLeaksAnyUpward,
			ReflectValueBoundaryEscape: msc.sawReflectValueOfAny && msc.sawReflectMutOrEscape && hasRVBoundaryEscape && !localAnyReflectFlagRO,
		})
	}
	reflectedFacts = append(reflectedFacts, thiefFacts...)
	for k := range msc.reflectedIfaceSets {
		isPlainIface := !strings.HasPrefix(k, syntaxutil.ReflectFlagROBypassPrefix)
		erasedCrossPkg := isPlainIface &&
			msc.anyErasedNonEmptyIfaces[k] && msc.pkgCrossesAnyBoundary &&
			!msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k]
		rvBoundary := isPlainIface &&
			(msc.directReflectedNonEmptyIfaces[k] || (msc.anyErasedNonEmptyIfaces[k] && msc.sawReflectValueOfAny && msc.sawReflectMutOrEscape)) &&
			hasRVBoundaryEscape && !msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k]
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:                  k,
			ErasedToEmptyIface:         erasedCrossPkg,
			ReflectValueBoundaryEscape: rvBoundary,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	if !canBypassFlagRO && msc.sawReflectMutOrEscape && hasRVBoundaryEscape {
		for k := range msc.directReflectedUnexportedIfaces {
			if msc.directReflectedNonEmptyIfaces[k] || msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] {
				continue
			}
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:                  k,
				ReflectValueBoundaryEscape: true,
				UnexportedIfaceField:       true,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	anyUnexportedRVBoundary := msc.sawReflectValueOfAny && msc.sawReflectMutOrEscape && hasRVBoundaryEscape
	if !localAnyReflectFlagRO && (msc.pkgCrossesAnyBoundary || anyUnexportedRVBoundary) {
		for k := range msc.anyErasedUnexportedIfaces {
			if msc.anyErasedNonEmptyIfaces[k] || msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] {
				continue
			}
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:                  k,
				ErasedToEmptyIface:         msc.pkgCrossesAnyBoundary,
				ReflectValueBoundaryEscape: anyUnexportedRVBoundary,
				UnexportedIfaceField:       true,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	if !msc.sawRawUintptrToUnsafePtr {
		if msc.sawFmtPointerIdentityOnAny && !localAnyReflectFlagRO {
			reflectedFacts = append(reflectedFacts, syntaxutil.ReflectedIfaceFact{
				MethodSet:         syntaxutil.EmptyIfaceMethodSetKey,
				ContextValueBoxed: syntaxutil.ReflectRawUintptrToPtrKey,
			})
		}
		for k := range msc.fmtPointerErasedIfaces {
			if msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] {
				continue
			}
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:            k,
				UnexportedIfaceField: true,
				ContextValueBoxed:    syntaxutil.ReflectRawUintptrToPtrKey,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	for boxKey := range msc.nestedAnyInConcreteBoxes {
		for k := range msc.anyErasedNonEmptyIfaces {
			nk := nestedBoxIfaceKey{boxKey: boxKey, methodSet: k}
			msc.nestedExportedIfacesInBox[nk] = true
			msc.nestedAllIfacesInBox[nk] = true
		}
		for k := range msc.anyErasedUnexportedIfaces {
			msc.nestedAllIfacesInBox[nestedBoxIfaceKey{boxKey: boxKey, methodSet: k}] = true
		}
	}
	for boxKey := range msc.nestedUnexportedAnyInConcreteBoxes {
		for k := range msc.anyErasedNonEmptyIfaces {
			msc.nestedAllIfacesInBox[nestedBoxIfaceKey{boxKey: boxKey, methodSet: k}] = true
		}
		for k := range msc.anyErasedUnexportedIfaces {
			msc.nestedAllIfacesInBox[nestedBoxIfaceKey{boxKey: boxKey, methodSet: k}] = true
		}
	}
	for nk := range msc.nestedAllIfacesInBox {
		if msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+nk.methodSet] {
			continue
		}
		if !nk.opaqueGuardStruct.IsZero() && msc.nestedAllIfacesInBox[nestedBoxIfaceKey{boxKey: nk.boxKey, methodSet: nk.methodSet}] {
			continue
		}
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:            nk.methodSet,
			UnexportedIfaceField: !msc.nestedExportedIfacesInBox[nk],
			NestedInConcreteBox:  nk.boxKey,
			NestedOpaqueStruct:   nk.opaqueGuardStruct,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	if !localAnyReflectFlagRO {
		for boxKey := range msc.nestedAnyInConcreteBoxes {
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:           syntaxutil.EmptyIfaceMethodSetKey,
				NestedInConcreteBox: boxKey,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	for k, pkMap := range msc.deferredParamAnyIfaces {
		if msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] {
			continue
		}
		pks := sortedParamKeys(pkMap)
		if len(pks) == 0 {
			continue
		}
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:           k,
			UnlessParamLeakFree: pks,
			ErasedToEmptyIface:  true,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	for k, pkMap := range msc.deferredParamAnyUnexportedIfaces {
		if msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] {
			continue
		}
		var filtered map[syntaxutil.ParamKey]bool
		for pk := range pkMap {
			if !msc.deferredParamAnyIfaces[k][pk] {
				if filtered == nil {
					filtered = map[syntaxutil.ParamKey]bool{}
				}
				filtered[pk] = true
			}
		}
		pks := sortedParamKeys(filtered)
		if len(pks) == 0 {
			continue
		}
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:            k,
			UnlessParamLeakFree:  pks,
			ErasedToEmptyIface:   true,
			UnexportedIfaceField: true,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	for ck := range msc.ctxBoxedAll {
		if msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+ck.methodSet] {
			continue
		}
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:            ck.methodSet,
			UnexportedIfaceField: !msc.ctxBoxedExported[ck],
			ContextValueBoxed:    ck.ctxKey,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	for fk := range msc.foreignUnsafeIfaces {
		if msc.reflectedIfaceSets[fk.methodSet] {
			continue
		}
		rf := syntaxutil.ReflectedIfaceFact{
			MethodSet:                 fk.methodSet,
			UnlessSafeCapsuleStruct:   fk.guard.capStruct,
			UnlessSafeCapsuleParam:    fk.guard.capParam,
			UnlessSafeAtomicPtrCopy:   fk.guard.atomicCopyFn,
			ReflectsEmptyIfaceLocally: fk.methodSet == syntaxutil.EmptyIfaceMethodSetKey,
		}
		if rf.Valid() {
			reflectedFacts = append(reflectedFacts, rf)
		}
	}
	for fnKey := range msc.atomicPtrCopyGuards {
		for _, ms := range []string{
			syntaxutil.EmptyIfaceMethodSetKey,
			syntaxutil.ReflectFlagROBypassAnyKey,
			syntaxutil.ReflectFlagROLocalBypassKey,
		} {
			if ms != syntaxutil.EmptyIfaceMethodSetKey && msc.reflectedIfaceSets[ms] {
				continue
			}
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:                 ms,
				UnlessSafeAtomicPtrCopy:   fnKey,
				ReflectsEmptyIfaceLocally: ms == syntaxutil.EmptyIfaceMethodSetKey,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	if !localAnyReflectFlagRO {
		for ck := range msc.unsafePtrCarrierBoxes {
			if ck.opaqueOwnerPkg != "" && msc.unsafePtrCarrierBoxes[unsafeCarrierBoxKey{boxKey: ck.boxKey}] {
				continue
			}
			rf := syntaxutil.ReflectedIfaceFact{
				MethodSet:             syntaxutil.ReflectFlagROBypassAnyKey,
				UnsafePtrCarrierBoxed: ck.boxKey,
				NestedOpaqueOwnerPkg:  ck.opaqueOwnerPkg,
			}
			if rf.Valid() {
				reflectedFacts = append(reflectedFacts, rf)
			}
		}
	}
	if len(reflectedFacts) > 0 {
		slices.SortFunc(reflectedFacts, syntaxutil.ReflectedIfaceFact.Compare)
		reflectedFacts = slices.CompactFunc(reflectedFacts, func(a, b syntaxutil.ReflectedIfaceFact) bool {
			return a.Compare(b) == 0
		})
		if trace.Enabled(msc.ctx, trace.DomainDynstate, msc.traceTarget) {
			for _, rf := range reflectedFacts {
				trace.Emit(msc.ctx, trace.DomainDynstate, "dynstate.iface.reflected", msc.traceTarget,
					trace.String("method_set", rf.MethodSet),
					trace.String("nested", rf.NestedInConcreteBox),
					trace.String("carrier", rf.UnsafePtrCarrierBoxed),
					trace.String("opaque_guard", rf.NestedOpaqueStruct.Key()),
					trace.String("opaque_owner", rf.NestedOpaqueOwnerPkg),
					trace.String("ctx_box", rf.ContextValueBoxed),
					trace.Bool("unexp", rf.UnexportedIfaceField),
					trace.Bool("erased_any", rf.ErasedToEmptyIface),
					trace.Bool("rv_escape", rf.ReflectValueBoundaryEscape),
				)
			}
		}
	}
	for pk := range msc.pendingBoxed {
		if msc.seen[pk.ref] {
			continue
		}
		matchedLocal := false
		for k := range msc.reflectedIfaceSets {
			if syntaxutil.MethodSetSubset(k, pk.methodSet) {
				matchedLocal = true
				break
			}
		}
		if matchedLocal {
			msc.markMutated(pk.ref, "boxed_concrete_matched_locally", nil)
		} else {
			cm := syntaxutil.ConditionalStructMutation{
				Struct:                 pk.ref,
				BoxedConcreteMethodSet: pk.methodSet,
			}
			if cm.Valid() {
				msc.condSeen[cm] = true
			}
		}
	}
	for fk := range msc.pendingForeignBoxed {
		baseKey := pendingBoxedKey{ref: fk.ref, methodSet: fk.methodSet}
		if msc.seen[fk.ref] || msc.pendingBoxed[baseKey] {
			continue
		}
		if fk.foreignPkg == msc.p.Types.Path() && localAnyReflect {
			matchedLocalAny := (fk.methodSet == syntaxutil.ReflectFlagROBypassAnyKey && localAnyReflectFlagRO) ||
				(fk.methodSet == syntaxutil.ReflectRawUintptrToPtrKey && msc.sawRawUintptrToUnsafePtr)
			if !matchedLocalAny {
				for k := range msc.anyErasedNonEmptyIfaces {
					if syntaxutil.MethodSetSubset(k, fk.methodSet) ||
						(localAnyReflectFlagRO && syntaxutil.MethodSetSubset(syntaxutil.ReflectFlagROBypassPrefix+k, fk.methodSet)) {
						matchedLocalAny = true
						break
					}
				}
			}
			if matchedLocalAny {
				msc.markMutated(fk.ref, "foreign_capsule_boxed_matched_locally", nil)
				continue
			}
		}
		cm := syntaxutil.ConditionalStructMutation{
			Struct:                 fk.ref,
			BoxedConcreteMethodSet: fk.methodSet,
			ForeignReflectPkg:      fk.foreignPkg,
		}
		if cm.Valid() {
			msc.condSeen[cm] = true
		}
	}

	var out []syntaxutil.TypeRef
	if len(msc.seen) > 0 {
		out = make([]syntaxutil.TypeRef, 0, len(msc.seen))
		for ref := range msc.seen {
			out = append(out, ref)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	}
	var condOut []syntaxutil.ConditionalStructMutation
	if len(msc.condSeen) > 0 {
		condOut = make([]syntaxutil.ConditionalStructMutation, 0, len(msc.condSeen))
		for cm := range msc.condSeen {
			if !msc.seen[cm.Struct] {
				condOut = append(condOut, cm)
			}
		}
		if len(condOut) == 0 {
			condOut = nil
		} else {
			slices.SortFunc(condOut, syntaxutil.ConditionalStructMutation.Compare)
		}
	}
	return out, condOut, reflectedFacts
}
