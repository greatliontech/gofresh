package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func (msc *mutatedStructCollector) isOpaqueForeignWrapperField(callConv *ast.CallExpr, ownerT types.Type, st *types.Struct, f *types.Var) (capsuleCallGuard, bool) {
	if callConv == nil || f == nil || f.Exported() || f.Embedded() || f.Pkg() == nil || f.Pkg() == msc.p.Types {
		return capsuleCallGuard{}, false
	}
	cls, okCls := msc.foreignPtrConvClasses[callConv]
	if !okCls || !cls.isCapsuleWrapper || cls.capStruct.Pkg != f.Pkg().Path() {
		return capsuleCallGuard{}, false
	}
	fPtr, isFP := types.Unalias(f.Type()).(*types.Pointer)
	if !isFP {
		return capsuleCallGuard{}, false
	}
	elemNamed, isEN := types.Unalias(fPtr.Elem()).(*types.Named)
	if !isEN || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != f.Pkg() {
		return capsuleCallGuard{}, false
	}
	tNamed, isTN := ownerT.(*types.Named)
	if !isTN || tNamed.Obj() == nil || tNamed.Obj().Pkg() != f.Pkg() {
		return capsuleCallGuard{}, false
	}
	for si := 0; si < st.NumFields(); si++ {
		sf := st.Field(si)
		if sf.Exported() && !(sf.Embedded() && isZeroSizedPaddingType(sf.Type())) {
			return capsuleCallGuard{}, false
		}
	}
	return capsuleCallGuard{capStruct: cls.capStruct, capParam: cls.capParam}, true
}

func (msc *mutatedStructCollector) recordUnsafeValueTypeIface(callConv *ast.CallExpr, vt types.Type, fGuard capsuleCallGuard) {
	var checkIface func(t types.Type, fg capsuleCallGuard)
	checkIface = func(t types.Type, fg capsuleCallGuard) {
		if t == nil {
			return
		}
		if syntaxutil.IsUnsafePointerType(t) {
			if !msc.isZeroGuard(fg) {
				msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.EmptyIfaceMethodSetKey}] = true
				msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROBypassAnyKey}] = true
				msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROLocalBypassKey}] = true
				return
			}
			msc.sawUnsafeIfaceHeaderBypass = true
			msc.sawReflectValueOfAny = true
			msc.sawReflectMutOrEscape = true
			msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
			msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
			return
		}
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Interface:
			if !msc.isZeroGuard(fg) {
				if u.NumMethods() == 0 {
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.EmptyIfaceMethodSetKey}] = true
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROBypassAnyKey}] = true
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROLocalBypassKey}] = true
				} else if k := syntaxutil.IfaceMethodSetKey(u); k != "" {
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: k}] = true
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROBypassPrefix + k}] = true
					msc.foreignUnsafeIfaces[foreignIfaceKey{guard: fg, methodSet: syntaxutil.ReflectFlagROLocalBypassKey}] = true
				}
				return
			}
			if u.NumMethods() == 0 {
				msc.sawUnsafeIfaceHeaderBypass = true
				msc.sawReflectValueOfAny = true
				msc.sawReflectMutOrEscape = true
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
			} else if k := syntaxutil.IfaceMethodSetKey(u); k != "" {
				msc.sawUnsafeIfaceHeaderBypass = true
				msc.sawReflectMutOrEscape = true
				msc.reflectedIfaceSets[k] = true
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassPrefix+k] = true
				msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
			}
		case *types.Array:
			checkIface(u.Elem(), fg)
		}
	}
	vt = types.Unalias(vt)
	checkIface(vt, fGuard)
	if st, isSt := vt.Underlying().(*types.Struct); isSt {
		var capWrapGuard capsuleCallGuard
		if callConv != nil {
			if cls := msc.foreignPtrConvClasses[callConv]; cls.isCapsuleWrapper && !cls.capStruct.IsZero() {
				capWrapGuard = capsuleCallGuard{capStruct: cls.capStruct, capParam: cls.capParam}
			}
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if !msc.exemptReadFields[f] {
				fg := fGuard
				if msc.isZeroGuard(fg) {
					if g, okG := msc.isOpaqueForeignWrapperField(callConv, vt, st, f); okG {
						fg = g
					} else if !msc.isZeroGuard(capWrapGuard) && ifaceOrArrayElemIsPkgSealed(f.Type(), msc.p, capWrapGuard.capStruct.Pkg) {
						fg = capWrapGuard
					}
				}
				checkIface(f.Type(), fg)
			}
		}
	}
}

func (msc *mutatedStructCollector) recordUnsafeTargetElem(at ast.Node, elem types.Type) {
	callConv, _ := at.(*ast.CallExpr)
	skipCapsuleField := callConv != nil && msc.safeCapsuleWrapUnsafeConvs[callConv]
	var capWrapGuard capsuleCallGuard
	var initStructGuard, initIfaceGuard capsuleCallGuard
	if callConv != nil {
		if cls := msc.foreignPtrConvClasses[callConv]; cls.isCapsuleWrapper && !cls.capStruct.IsZero() {
			capWrapGuard = capsuleCallGuard{capStruct: cls.capStruct, capParam: cls.capParam}
		} else if cls.isAtomicPtrCopy && cls.atomicCopyFn.Valid() {
			initStructGuard = capsuleCallGuard{atomicCopyFn: cls.atomicCopyFn}
			initIfaceGuard = initStructGuard
		}
	}
	type visitElemKey struct {
		t           types.Type
		structGuard capsuleCallGuard
		ifaceGuard  capsuleCallGuard
	}
	seenElem := map[visitElemKey]bool{}
	var walkElem func(t types.Type, structGuard, ifaceGuard capsuleCallGuard)
	recordElemStruct := func(vt types.Type, fGuard capsuleCallGuard) {
		if msc.isZeroGuard(fGuard) {
			msc.recordStructAt(at, vt)
			return
		}
		if ref, ok := msc.resolveStructAt(at, vt); ok && !msc.seen[ref] {
			cm := syntaxutil.ConditionalStructMutation{
				Struct:                  ref,
				UnlessSafeCapsuleStruct: fGuard.capStruct,
				UnlessSafeCapsuleParam:  fGuard.capParam,
				UnlessSafeAtomicPtrCopy: fGuard.atomicCopyFn,
			}
			if cm.Valid() {
				msc.condSeen[cm] = true
			}
		}
	}
	walkSealedImpls := func(t types.Type, structGuard capsuleCallGuard) {
		if msc.isZeroGuard(capWrapGuard) {
			return
		}
		for _, implSt := range sealedPkgIfaceImplementorStructs(t, msc.p, capWrapGuard.capStruct.Pkg) {
			walkElem(implSt, structGuard, capsuleCallGuard{})
		}
	}
	walkElem = func(t types.Type, structGuard, ifaceGuard capsuleCallGuard) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		isSealedIface := false
		if !msc.isZeroGuard(capWrapGuard) && msc.isZeroGuard(ifaceGuard) {
			if isNamedInPkgPath(t, capWrapGuard.capStruct.Pkg) {
				ifaceGuard = capWrapGuard
			} else if ifaceOrArrayElemIsPkgSealed(t, msc.p, capWrapGuard.capStruct.Pkg) {
				ifaceGuard = capWrapGuard
				isSealedIface = true
			}
		}
		vk := visitElemKey{t: t, structGuard: structGuard, ifaceGuard: ifaceGuard}
		if seenElem[vk] {
			return
		}
		seenElem[vk] = true
		if isSealedIface {
			walkSealedImpls(t, structGuard)
		}
		msc.recordUnsafeValueTypeIface(callConv, t, ifaceGuard)
		syntaxutil.ForEachValueContainedStructType(t, func(vt types.Type) {
			vtIfaceGuard := ifaceGuard
			if !msc.isZeroGuard(capWrapGuard) && msc.isZeroGuard(vtIfaceGuard) && isNamedInPkgPath(vt, capWrapGuard.capStruct.Pkg) {
				vtIfaceGuard = capWrapGuard
			}
			recordElemStruct(vt, structGuard)
			msc.recordUnsafeValueTypeIface(callConv, vt, vtIfaceGuard)
		})
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walkElem(u.Elem(), structGuard, ifaceGuard)
		case *types.Slice:
			if msc.isZeroGuard(structGuard) {
				msc.recordNamedContainerAt(at, t)
			}
			walkElem(u.Elem(), structGuard, ifaceGuard)
		case *types.Map:
			if msc.isZeroGuard(structGuard) {
				msc.recordNamedContainerAt(at, t)
			}
			walkElem(u.Elem(), structGuard, ifaceGuard)
		case *types.Array:
			walkElem(u.Elem(), structGuard, ifaceGuard)
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if msc.exemptReadFields[f] || (msc.foreignReflectFields[f] && skipCapsuleField) {
					continue
				}
				nextStruct := structGuard
				nextIface := ifaceGuard
				if msc.isZeroGuard(nextStruct) {
					if g, okG := msc.isOpaqueForeignWrapperField(callConv, t, u, f); okG {
						nextStruct = g
						if msc.isZeroGuard(nextIface) {
							nextIface = g
						}
					}
				}
				if !msc.isZeroGuard(capWrapGuard) && msc.isZeroGuard(nextIface) && ifaceOrArrayElemIsPkgSealed(f.Type(), msc.p, capWrapGuard.capStruct.Pkg) {
					nextIface = capWrapGuard
					walkSealedImpls(f.Type(), nextStruct)
				}
				walkElem(f.Type(), nextStruct, nextIface)
			}
		}
	}
	walkElem(elem, initStructGuard, initIfaceGuard)
}

func (msc *mutatedStructCollector) recordUnsafeSliceArg(at ast.Node, arg ast.Expr) {
	argT := msc.p.TypesInfo.TypeOf(arg)
	msc.recordStructAt(at, argT)
	if ptr, isPtr := syntaxutil.UnderlyingType(argT).(*types.Pointer); isPtr {
		msc.recordUnsafeTargetElem(at, ptr.Elem())
	}
}

func (msc *mutatedStructCollector) isTrueStdPkg(pkg *types.Package) bool {
	return pkg != nil && syntaxutil.IsTrueStdlibInPkg(msc.p, pkg.Path())
}

func (msc *mutatedStructCollector) unexportedForeignRecvStruct(callee *types.Func) *types.Named {
	if callee == nil {
		return nil
	}
	orig := callee.Origin()
	if orig.Pkg() == nil || orig.Pkg() == msc.p.Types {
		return nil
	}
	sig, okSig := orig.Type().(*types.Signature)
	if !okSig || sig.Recv() == nil {
		return nil
	}
	ptr, isPtr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
	if !isPtr {
		return nil
	}
	named, isN := types.Unalias(ptr.Elem()).(*types.Named)
	if !isN || named.Obj() == nil || named.Obj().Exported() {
		return nil
	}
	if _, isSt := named.Underlying().(*types.Struct); !isSt {
		return nil
	}
	return named
}

func (msc *mutatedStructCollector) foreignReflectTypeCapsuleStruct(named *types.Named) *types.Named {
	if named == nil || named.Obj() == nil || named.TypeParams() != nil {
		return nil
	}
	qPkg := named.Obj().Pkg()
	if qPkg == nil || qPkg == msc.p.Types || msc.isTrueStdPkg(qPkg) {
		return nil
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt {
		return nil
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() && syntaxutil.IsNamedInPkg(f.Type(), "reflect", "Type") {
			return named
		}
	}
	return nil
}

func (msc *mutatedStructCollector) markCrossesAnyBoundary(reason string, typ types.Type, at ast.Node) {
	if !msc.pkgCrossesAnyBoundary {
		msc.pkgCrossesAnyBoundary = true
		emitAnyBoundaryCross(msc.ctx, msc.p, msc.traceTarget, reason, typ, at)
	}
}

func (msc *mutatedStructCollector) recordBoundaryParamType(t types.Type) {
	if t == nil {
		return
	}
	if msc.typeCrossesAnyOrEfaceUnion(t) {
		msc.markCrossesAnyBoundary("boundary_param_type", t, nil)
	}
	if typeMentionsReflectValue(t) {
		msc.sawReflectValueCrossPkgArg = true
	}
}

func (msc *mutatedStructCollector) recordBoundaryResultOrRecvChanType(t types.Type) {
	if t == nil {
		return
	}
	if msc.typeCrossesAnyOrEfaceUnion(t) {
		msc.markCrossesAnyBoundary("boundary_result_or_chan_type", t, nil)
	}
	if typeMentionsReflectValue(t) {
		msc.sawReflectMutOrEscape = true
		if !syntaxutil.IsNamedInPkg(t, "reflect", "Value") {
			msc.sawReflectValueCrossPkgArg = true
		}
	}
}

func (msc *mutatedStructCollector) inspectBoxedConcreteMethodCapabilities(root types.Type) {
	seen := map[types.Type]bool{}
	seenSigs := map[*types.Signature]bool{}
	var walk func(t types.Type)
	var walkSig func(sig *types.Signature)
	walkSig = func(sig *types.Signature) {
		if sig == nil || seenSigs[sig] {
			return
		}
		seenSigs[sig] = true
		if sigExposesReflectValue(sig) {
			msc.sawReflectValueCrossPkgArg = true
		}
		if sigExposesEmptyIface(sig) {
			msc.markCrossesAnyBoundary("boxed_concrete_method_exposes_any", sig, nil)
		}
		for i := 0; i < sig.Params().Len(); i++ {
			walk(sig.Params().At(i).Type())
		}
		for i := 0; i < sig.Results().Len(); i++ {
			walk(sig.Results().At(i).Type())
		}
	}
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP || seen[t] {
			return
		}
		seen[t] = true
		if named, isN := t.(*types.Named); isN {
			if named.TypeArgs() != nil {
				for ti := 0; ti < named.TypeArgs().Len(); ti++ {
					walk(named.TypeArgs().At(ti))
				}
			}
			orig := named.Origin()
			if orig.Obj() == nil || orig.Obj().Pkg() != msc.p.Types {
				return
			}
		}
		if !isRuntimeInterfaceType(t) {
			ms := types.NewMethodSet(t)
			for i := 0; i < ms.Len(); i++ {
				fn, _ := ms.At(i).Obj().(*types.Func)
				if fn == nil || !fn.Exported() || msc.isTrueStdPkg(fn.Pkg()) {
					continue
				}
				if sig, okS := ms.At(i).Type().(*types.Signature); okS {
					walkSig(sig)
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if u.Field(i).Exported() {
					walk(u.Field(i).Type())
				}
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		}
	}
	walk(root)
}

func (msc *mutatedStructCollector) recordNonStdGenericTypeUse(at ast.Node, syncEncl *ast.FuncDecl, t types.Type, isForeignNonStd bool) {
	if t == nil {
		return
	}
	msc.recordGenericArgTypes(at, t)
	tu := types.Unalias(t)
	if _, isTP := tu.(*types.TypeParam); isTP {
		return
	}
	if !isEmptyInterfaceType(tu) {
		if typeMentionsReflectValue(tu) {
			msc.sawReflectValueCrossPkgArg = true
		}
		if msc.hasEfaceUnion && syntaxutil.ContainsUnsafePointer(tu) {
			msc.markCrossesAnyBoundary("generic_eface_union_unsafe_ptr", tu, at)
		}
		fam := msc.exemptFamilyByFunc[syncEncl]
		forEachNestedNonEmptyIface(tu, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
			if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
				msc.anyErasedNonEmptyIfaces[k] = true
			}
		})
		forEachNestedNonEmptyIface(tu, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
			if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
				msc.anyErasedUnexportedIfaces[k] = true
			}
		})
		if !types.IsInterface(tu) {
			msc.recordAnyBoxedArgTypes(at, syncEncl, tu)
		}
	}
	if isForeignNonStd {
		if refconfine.TypeContainsRefOrPointer(tu) || isRuntimeInterfaceType(tu) || msc.typeCrossesAnyOrEfaceUnion(tu) {
			msc.markCrossesAnyBoundary("foreign_generic_type_arg", tu, at)
		}
		msc.recordBoundaryParamType(tu)
	}
}

func rangeKeyValueTypes(rxT types.Type) (keyT, valT types.Type) {
	if rxT == nil {
		return nil, nil
	}
	switch u := syntaxutil.UnderlyingType(rxT).(type) {
	case *types.Slice:
		return types.Typ[types.Int], u.Elem()
	case *types.Array:
		return types.Typ[types.Int], u.Elem()
	case *types.Pointer:
		if arr, isArr := syntaxutil.UnderlyingType(u.Elem()).(*types.Array); isArr {
			return types.Typ[types.Int], arr.Elem()
		}
	case *types.Map:
		return u.Key(), u.Elem()
	case *types.Chan:
		return u.Elem(), nil
	case *types.Signature:
		if u.Params().Len() == 1 {
			if ySig, okY := syntaxutil.UnderlyingType(u.Params().At(0).Type()).(*types.Signature); okY {
				if ySig.Params().Len() >= 1 {
					keyT = ySig.Params().At(0).Type()
				}
				if ySig.Params().Len() >= 2 {
					valT = ySig.Params().At(1).Type()
				}
			}
		}
	}
	return keyT, valT
}

func (msc *mutatedStructCollector) foreignReflectTypeCapsulePtrElem(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	ptr, isP := types.Unalias(t).(*types.Pointer)
	if !isP {
		return nil
	}
	named, _ := types.Unalias(ptr.Elem()).(*types.Named)
	return msc.foreignReflectTypeCapsuleStruct(named)
}

func (msc *mutatedStructCollector) extractForeignCapsuleWrapperPkg(root types.Type) string {
	foundPkg := ""
	syntaxutil.ForEachValueContainedStructType(root, func(vt types.Type) {
		if foundPkg != "" {
			return
		}
		wNamed, isN := types.Unalias(vt).(*types.Named)
		if !isN || wNamed.Obj() == nil || wNamed.Obj().Pkg() == nil || wNamed.Obj().Pkg() == msc.p.Types || msc.isTrueStdPkg(wNamed.Obj().Pkg()) {
			return
		}
		wSt, isSt := wNamed.Underlying().(*types.Struct)
		if !isSt {
			return
		}
		for i := 0; i < wSt.NumFields(); i++ {
			f := wSt.Field(i)
			if !f.Exported() && !f.Embedded() && msc.foreignReflectTypeCapsulePtrElem(f.Type()) != nil {
				foundPkg = wNamed.Obj().Pkg().Path()
				return
			}
		}
	})
	return foundPkg
}

func (msc *mutatedStructCollector) recordForeignCapsuleMsgIfaces(root types.Type, capPkg string) {
	if root == nil || capPkg == "" {
		return
	}
	visited := map[types.Type]bool{}
	var walkMsg func(t types.Type)
	walkMsg = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if isNamedInPkgPath(t, capPkg) {
			return
		}
		if ifaceOrArrayElemIsPkgSealed(t, msc.p, capPkg) {
			if visited[t] {
				return
			}
			visited[t] = true
			for _, implSt := range sealedPkgIfaceImplementorStructs(t, msc.p, capPkg) {
				walkMsg(implSt)
			}
			return
		}
		if visited[t] {
			return
		}
		visited[t] = true
		msc.recordUnsafeValueTypeIface(nil, t, capsuleCallGuard{})
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walkMsg(u.Elem())
		case *types.Slice:
			walkMsg(u.Elem())
		case *types.Array:
			walkMsg(u.Elem())
		case *types.Map:
			walkMsg(u.Key())
			walkMsg(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if msc.exemptReadFields[f] || msc.foreignReflectFields[f] {
					continue
				}
				walkMsg(f.Type())
			}
		}
	}
	walkMsg(root)
}

func (msc *mutatedStructCollector) isTypedNilOrNilExpr(expr ast.Expr) bool {
	if expr == nil {
		return true
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(msc.p.TypesInfo, expr) || syntaxutil.IsTypedNilSliceConv(msc.p, expr) || isProvablyNilVarExpr(msc.p, msc.idx, expr) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	tv := msc.p.TypesInfo.Types[ast.Unparen(call.Fun)]
	return tv.IsType() && syntaxutil.IsNilIdent(msc.p.TypesInfo, call.Args[0])
}

func (msc *mutatedStructCollector) recordReflectedNonEmptyIface(syncEncl *ast.FuncDecl, t types.Type) {
	fam := msc.exemptFamilyByFunc[syncEncl]
	forEachNestedNonEmptyIface(t, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
		if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
			msc.directReflectedNonEmptyIfaces[k] = true
		}
	})
	forEachNestedNonEmptyIface(t, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
		if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
			msc.directReflectedUnexportedIfaces[k] = true
		}
	})
}

func (msc *mutatedStructCollector) recordDeferredParamAnyBox(at ast.Node, syncEncl *ast.FuncDecl, srcExpr ast.Expr, srcT types.Type, pk syntaxutil.ParamKey, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
	if srcT == nil || !pk.Valid() {
		return
	}
	if srcExpr != nil && syntaxutil.IsNilIdent(msc.p.TypesInfo, srcExpr) {
		return
	}
	if !types.IsInterface(srcT) {
		msc.inspectBoxedConcreteMethodCapabilities(srcT)
	}
	if srcExpr != nil && (msc.isTypedNilOrNilExpr(srcExpr) || msc.isFreshReflectOrBoxTarget(syncEncl, srcExpr, fresh, freshEsc)) {
		return
	}
	if !isEmptyInterfaceType(srcT) {
		if typeMentionsReflectValue(srcT) {
			msc.sawReflectValueCrossPkgArg = true
		}
		fam := msc.exemptFamilyByFunc[syncEncl]
		forEachNestedNonEmptyIface(srcT, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
			if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
				if msc.deferredParamAnyIfaces[k] == nil {
					msc.deferredParamAnyIfaces[k] = map[syntaxutil.ParamKey]bool{}
				}
				msc.deferredParamAnyIfaces[k][pk] = true
			}
		})
		forEachNestedNonEmptyIface(srcT, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
			if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
				if msc.deferredParamAnyUnexportedIfaces[k] == nil {
					msc.deferredParamAnyUnexportedIfaces[k] = map[syntaxutil.ParamKey]bool{}
				}
				msc.deferredParamAnyUnexportedIfaces[k][pk] = true
			}
		})
		msc.recordAnyBoxedArgTypes(at, syncEncl, srcT)
	}
}

func (msc *mutatedStructCollector) recordInterfaceBox(at ast.Node, syncEncl *ast.FuncDecl, dstT types.Type, srcExpr ast.Expr, srcT types.Type, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
	if dstT == nil || srcT == nil {
		return
	}
	dstU := types.Unalias(dstT)
	if _, isDstTP := dstU.(*types.TypeParam); isDstTP {
		return
	}
	dstIface, ok := dstU.Underlying().(*types.Interface)
	if !ok {
		return
	}
	if srcExpr != nil && syntaxutil.IsNilIdent(msc.p.TypesInfo, srcExpr) {
		return
	}
	if !types.IsInterface(srcT) {
		msc.inspectBoxedConcreteMethodCapabilities(srcT)
	}
	if srcExpr != nil && (msc.isTypedNilOrNilExpr(srcExpr) || msc.isFreshReflectOrBoxTarget(syncEncl, srcExpr, fresh, freshEsc)) {
		return
	}
	if dstIface.NumMethods() == 0 {
		if !isEmptyInterfaceType(srcT) {
			if typeMentionsReflectValue(srcT) {
				msc.sawReflectValueCrossPkgArg = true
			}
			if msc.hasEfaceUnion && syntaxutil.ContainsUnsafePointer(srcT) {
				msc.markCrossesAnyBoundary("box_any_eface_union_unsafe_ptr", srcT, at)
			}
			fam := msc.exemptFamilyByFunc[syncEncl]
			forEachNestedNonEmptyIface(srcT, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
				if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
					msc.anyErasedNonEmptyIfaces[k] = true
				}
			})
			forEachNestedNonEmptyIface(srcT, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(iface *types.Interface) {
				if k := syntaxutil.IfaceMethodSetKey(iface); k != "" {
					msc.anyErasedUnexportedIfaces[k] = true
				}
			})
			msc.recordAnyBoxedArgTypes(at, syncEncl, srcT)
		}
		return
	}
	if !types.IsInterface(srcT) {
		msc.recordPendingNonEmptyIfaceBox(at, syncEncl, srcT)
	}
}

func (msc *mutatedStructCollector) enclosingFuncResultTypes(at ast.Node) *types.Tuple {
	cur := at
	for cur != nil {
		switch fnNode := cur.(type) {
		case *ast.FuncLit:
			if sig, ok := msc.p.TypesInfo.TypeOf(fnNode).(*types.Signature); ok {
				return sig.Results()
			}
			return nil
		case *ast.FuncDecl:
			if fnNode.Name != nil {
				if fnObj, ok := msc.p.TypesInfo.Defs[fnNode.Name].(*types.Func); ok && fnObj != nil {
					if sig, okS := fnObj.Type().(*types.Signature); okS {
						return sig.Results()
					}
				}
			}
			return nil
		}
		cur = msc.idx.ParentMap[cur]
	}
	return nil
}
