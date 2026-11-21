package structmut

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (msc *mutatedStructCollector) scanTypesInfoAndFinalize() ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	msc.scanInstancesSelectionsAndRefConfinement()
	return msc.finalizeReflectedIfacesAndStructs()
}

func (msc *mutatedStructCollector) scanInstancesSelectionsAndRefConfinement() {
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
				(okOrig && origSig.Recv() != nil && freshalloc.IsRuntimeInterfaceType(origSig.Recv().Type())))
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
			if selInfo.Kind() == types.MethodVal && freshalloc.TypeMentionsReflectValue(msc.p.TypesInfo.TypeOf(selExpr.X)) {
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
				if !isN || !syntaxutil.IsOpaqueUnexportedForeignStruct(msc.p.Types, stNamed) {
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
}
