package structmut

import (
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func (msc *mutatedStructCollector) finalizeReflectedIfacesAndStructs() ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
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
