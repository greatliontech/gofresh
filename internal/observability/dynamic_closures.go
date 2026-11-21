package observability

import (
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/trace"
)

func walkDynamicSeedValue(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if value.Type() != nil && !typeMayCarryDynamicTop(fp != nil && fp.selectionAudited, value.Type()) {
		return true
	}
	if fp == nil {
		if seen[value] {
			return true
		}
		seen[value] = true
		walkDynamicValueUncached(value, collect, seen, done, nil)
		return true
	}
	outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
	seedsTable := fp.enumSeedsTable()
	inSeedProgScope := seedsTable != nil && fp.canReadProgMemo(outsideCallee)
	if outsideCallee {
		if inSeedProgScope {
			if entry, ok := seedsTable[value]; ok {
				for _, t := range entry.types {
					collect.types[t] = true
				}
				for _, fn := range entry.funcs {
					collect.funcs[fn] = true
				}
				return true
			}
		}
		if fp.rootSeen != nil {
			if fp.rootSeen[value] {
				return true
			}
			fp.rootSeen[value] = true
			walkDynamicValueUncached(value, collect, seen, done, fp)
			return true
		}
		if seen != nil && seen[value] {
			return true
		}
		topSeedWalk := len(collect.visitedStructs) == 0
		usedSubject := false
		rootFP := *fp
		rootFP.rootSeen = map[ssa.Value]bool{value: true}
		rootFP.usedSubject = &usedSubject
		var subVisited map[*types.Named]bool
		subSeen := seen
		if topSeedWalk {
			subSeen = map[ssa.Value]bool{}
		} else {
			subVisited = collect.visitedStructs
		}
		subCollect := dynamicValueCollector{
			types:          map[types.Type]bool{},
			funcs:          map[*ssa.Function]bool{},
			seeds:          true,
			visitedStructs: subVisited,
		}
		walkDynamicValueUncached(value, &subCollect, subSeen, done, &rootFP)
		if seen != nil {
			seen[value] = true
		}
		if usedSubject {
			fp.markSubjectUsed()
		}
		for t := range subCollect.types {
			collect.types[t] = true
		}
		for fn := range subCollect.funcs {
			collect.funcs[fn] = true
		}
		if topSeedWalk && len(subCollect.visitedStructs) > 0 {
			if collect.visitedStructs == nil {
				collect.visitedStructs = map[*types.Named]bool{}
			}
			for s := range subCollect.visitedStructs {
				collect.visitedStructs[s] = true
			}
		}
		if topSeedWalk && seedsTable != nil && fp.canWriteProgMemo(outsideCallee, usedSubject) {
			var dedupTypes []types.Type
			if len(subCollect.types) > 0 {
				dedupTypes = make([]types.Type, 0, len(subCollect.types))
				for t := range subCollect.types {
					dedupTypes = append(dedupTypes, t)
				}
			}
			var funcs []*ssa.Function
			if len(subCollect.funcs) > 0 {
				funcs = make([]*ssa.Function, 0, len(subCollect.funcs))
				for fn := range subCollect.funcs {
					funcs = append(funcs, fn)
				}
			}
			seedsTable[value] = dynamicSeedEntry{
				types: dedupTypes,
				funcs: funcs,
			}
		}
		return true
	}
	if seen[value] {
		return true
	}
	seen[value] = true
	walkDynamicValueUncached(value, collect, seen, done, fp)
	return true
}

func walkDerefDynamicValue(v *ssa.UnOp, value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis, recurse func(ssa.Value) bool) bool {
	collecting := collect.collecting()
	if v.Op != token.MUL {
		return collect.isSeeds()
	}
	if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && (isUnmutatedStandardSentinelGlobalAny(fp.prog, g) || isUnmutatedSentinelGlobal(fp.selectionAudited, fp.prog, fp.userPkgPaths(), g)) {
		if !collecting {
			markDynamicLeaf(fp)
			return true
		}
		if collect.types != nil {
			return sentinelGlobalConcreteTypes(g, collect.types) || collect.isSeeds()
		}
		return collect.isSeeds()
	}
	if fa, ok := v.X.(*ssa.FieldAddr); ok && fp != nil {
		if closed, handled := walkUserStructFieldDynamicValue(fa.X, fa.Field, collect, seen, done, fp); handled {
			return closed
		}
	}
	if ia, ok := v.X.(*ssa.IndexAddr); ok && ia.X != nil {
		if _, isSlice := types.Unalias(ia.X.Type()).Underlying().(*types.Slice); isSlice {
			return recurse(ia.X)
		}
	}
	if fp != nil && (fp.selectionAudited || collect.isSeeds()) && v.Type() != nil {
		if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
			if userNamed := derefNamedStruct(fp.userPkgPaths(), v.Type()); userNamed != nil {
				if !collect.isSeeds() && fp.structPoisoned[structFieldKey{named: userNamed, field: -1}] {
					return false
				}
				if !collecting {
					if !recurse(v.X) {
						return false
					}
					if (fp.enumOnly || isAuditedStdErrorWrapperNamed(userNamed)) && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
						if userNamed == fp.enumRecvNamed {
							if fp.usedSubject != nil {
								*fp.usedSubject = true
							}
						} else if !enumUserStructClosed(userNamed, fp) {
							return false
						}
					}
					markDynamicLeaf(fp)
					return true
				}
				if collect.types != nil {
					collect.types[v.Type()] = true
					if collect.isSeeds() {
						recurse(v.X)
						if typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
							collectUserStructSeeds(userNamed, collect, fp)
						}
					}
					return true
				}
				if collect.isSeeds() {
					recurse(v.X)
					if typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
						collectUserStructSeeds(userNamed, collect, fp)
					}
					return true
				}
			}
		}
	}
	cell := cellOf(v.X, map[ssa.Value]bool{})
	if cell == nil {
		return collect.isSeeds()
	}
	if !collecting {
		if fp != nil && fp.stackDepth != nil {
			cellKey := fp.carrierKey(cell)
			valKey := fp.carrierKey(value)
			if d, onStack := fp.stackDepth[cellKey]; onStack {
				if fp.selectionAudited {
					if *fp.lowlink == 0 || d < *fp.lowlink {
						*fp.lowlink = d
					}
					return true
				}
				return false
			}
			fp.stackDepth[cellKey] = fp.stackDepth[valKey]
			defer delete(fp.stackDepth, cellKey)
		} else {
			if seen[cell] {
				return false
			}
			seen[cell] = true
			defer delete(seen, cell)
		}
	}
	return walkLoadCellReferrersWithFP(v.X, fp, func(val ssa.Value) bool {
		return recurse(val) || collect.isSeeds()
	}) || collect.isSeeds()
}

func walkMakeClosureDynamicValue(v *ssa.MakeClosure, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	collecting := collect.collecting()
	fn, ok := v.Fn.(*ssa.Function)
	if !collect.isSeeds() && ok && strings.HasPrefix(fn.Synthetic, "bound ") && !(v.Parent() != nil && fp.isStdFunc(v.Parent())) && fp != nil && fp.isNonInternalPureDelegate(funcPkgPath(fn)) {
		if len(v.Bindings) == 0 || !isAuditedStdAliasValue(fp.selectionAudited, v.Bindings[0]) {
			return false
		}
	}
	wrapFP, wrapDone := fp, done
	if ok && syntheticInterfaceMethodWrapper(fn) {
		if mObj, mOK := fn.Object().(*types.Func); mOK && isContextCancelMethod(mObj) {
			wrapFP, wrapDone = withIgnoreContextValuePayloadDone(fp, done)
		}
	}
	if !collecting {
		if ok && syntheticInterfaceMethodWrapper(fn) {
			for _, binding := range v.Bindings {
				if !walkDynamicValue(binding, nil, seen, wrapDone, wrapFP) {
					return false
				}
			}
		} else if ok && wrapFP != nil && wrapFP.verifiedHarnesses[funcPkgPath(fn)] != nil {
			for _, binding := range v.Bindings {
				if binding == nil || !refconfine.TypeMayCarryDynamic(wrapFP.selectionAudited, binding.Type(), map[types.Type]bool{}) {
					continue
				}
				if !propertyHarnessClosedValue(binding, wrapFP) {
					return false
				}
			}
		}
		markDynamicLeaf(fp)
		return true
	}
	if !ok || collect.funcs == nil {
		return collect.isSeeds()
	}
	if syntheticInterfaceMethodWrapper(fn) && wrapFP != nil && wrapFP.selectionAudited {
		if collect.isSeeds() && len(v.Bindings) == 1 {
			walkDynamicValue(v.Bindings[0], collect, seen, wrapDone, wrapFP)
		}
		if len(v.Bindings) != 1 || v.Parent() == nil || v.Parent().Prog == nil {
			if collect.isSeeds() {
				collect.funcs[fn] = true
				return true
			}
			return false
		}
		method, ok := fn.Object().(*types.Func)
		if !ok || method == nil {
			if collect.isSeeds() {
				collect.funcs[fn] = true
				return true
			}
			return false
		}
		cts := map[types.Type]bool{}
		subFP := *wrapFP
		subFP.rootSeen = nil
		if !walkDynamicValue(v.Bindings[0], &dynamicValueCollector{types: cts}, map[ssa.Value]bool{}, nil, &subFP) {
			if collect.isSeeds() {
				collect.funcs[fn] = true
				return true
			}
			return false
		}
		targets, ok := resolveConcreteMethodTargets(v.Parent().Prog, v.Bindings[0].Type(), method, cts, wrapFP)
		if !ok {
			if collect.isSeeds() {
				collect.funcs[fn] = true
				return true
			}
			return false
		}
		for t := range targets {
			collect.funcs[t] = true
		}
		return true
	}
	collect.funcs[fn] = true
	return true
}

func enumUserStructClosed(named *types.Named, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || named == nil {
		return false
	}
	if fp.baseCarrierNamed != nil {
		if named == fp.baseCarrierNamed {
			markDynamicLeaf(fp)
			return true
		}
		copied := *fp
		copied.baseCarrierNamed = nil
		fp = &copied
	}
	if fp.enumRecvNamed != nil && named == fp.enumRecvNamed {
		if fp.usedSubject != nil {
			*fp.usedSubject = true
		}
		markDynamicLeaf(fp)
		return true
	}
	if fp.structPoisoned[structFieldKey{named: named, field: -1}] || !fp.structReferencedByType[named] {
		if trace.AnyEnabled() {
			reason := "unreferenced"
			if fp.structPoisoned[structFieldKey{named: named, field: -1}] {
				reason = "struct_poisoned"
			}
			trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.struct.unclosed", named.String(),
				trace.String("reason", reason),
			)
		}
		return false
	}
	if fp.enumStructVisiting[named] {
		markDynamicLeaf(fp)
		return true
	}
	structMemo := fp.enumStructTable()
	if structMemo != nil {
		if r, ok := structMemo[named]; ok && (r || (len(fp.enumStructVisiting) == 0 && fp.enumRecvNamed == nil)) {
			if r {
				markDynamicLeaf(fp)
			}
			return r
		}
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	topLevel := len(fp.enumStructVisiting) == 0 && fp.enumRecvNamed == nil
	visiting := fp.enumStructVisiting
	if len(visiting) == 0 {
		visiting = make(map[*types.Named]bool, 4)
		if fp.enumRecvNamed != nil {
			visiting[fp.enumRecvNamed] = true
		}
		fp = fp.newStructVisitingScopeFP(visiting)
	}
	visiting[named] = true
	usedSubject := false
	for _, wv := range fp.structWholeStores[named] {
		var lowlink int
		var hasLeaf, storeUsedSubject bool
		wholeFP := fp.newStructStoreWalkFP(true, true, visiting, &lowlink, &hasLeaf, &storeUsedSubject)
		ok := walkDynamicValue(wv, nil, map[ssa.Value]bool{}, wholeFP.rootDone, wholeFP)
		if storeUsedSubject {
			usedSubject = true
		}
		if !ok {
			if trace.AnyEnabled() {
				var fnName, storeValStr string
				if wv != nil {
					storeValStr = wv.String()
					if wv.Parent() != nil {
						fnName = wv.Parent().String()
					}
				}
				trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.struct.unclosed", named.String(),
					trace.String("reason", "whole_store"),
					trace.String("store_val", storeValStr),
					trace.String("fn", fnName),
				)
			}
			if usedSubject && fp.usedSubject != nil {
				*fp.usedSubject = true
			}
			if topLevel && !usedSubject && structMemo != nil {
				structMemo[named] = false
			}
			return false
		}
	}
	for f := 0; f < st.NumFields(); f++ {
		fType := st.Field(f).Type()
		if !typeMayCarryDynamicTop(fp.selectionAudited, fType) {
			continue
		}
		key := structFieldKey{named: named, field: f}
		if fp.structPoisoned[key] {
			if trace.AnyEnabled() {
				trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.struct.unclosed", named.String(),
					trace.String("reason", "field_poisoned"),
					trace.String("field", st.Field(f).Name()),
				)
			}
			if topLevel && structMemo != nil {
				structMemo[named] = false
			}
			return false
		}
		if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
			if innerNamed := derefNamedStruct(fp.userPkgPaths(), fType); innerNamed != nil {
				innerFP := *fp
				innerFP.enumStructVisiting = visiting
				innerUsedSubject := false
				innerFP.usedSubject = &innerUsedSubject
				ok := enumUserStructClosed(innerNamed, &innerFP)
				if innerUsedSubject {
					usedSubject = true
				}
				if !ok {
					if trace.AnyEnabled() {
						trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.struct.unclosed", named.String(),
							trace.String("reason", "inner_struct"),
							trace.String("field", st.Field(f).Name()),
						)
					}
					if usedSubject && fp.usedSubject != nil {
						*fp.usedSubject = true
					}
					if topLevel && !usedSubject && structMemo != nil {
						structMemo[named] = false
					}
					return false
				}
			}
		}
		for _, sv := range fp.structFieldStores[key] {
			var lowlink int
			var hasLeaf, storeUsedSubject bool
			fieldFP := fp.newStructStoreWalkFP(fp.inProgramSites, true, visiting, &lowlink, &hasLeaf, &storeUsedSubject)
			ok := walkDynamicValue(sv, nil, map[ssa.Value]bool{}, fieldFP.rootDone, fieldFP)
			if storeUsedSubject {
				usedSubject = true
			}
			if !ok {
				if trace.AnyEnabled() {
					var fnName, storeValStr string
					if sv != nil {
						storeValStr = sv.String()
						if sv.Parent() != nil {
							fnName = sv.Parent().String()
						}
					}
					trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.struct.unclosed", named.String(),
						trace.String("reason", "field_store"),
						trace.String("field", st.Field(f).Name()),
						trace.String("store_val", storeValStr),
						trace.String("fn", fnName),
					)
				}
				if usedSubject && fp.usedSubject != nil {
					*fp.usedSubject = true
				}
				if topLevel && !usedSubject && structMemo != nil {
					structMemo[named] = false
				}
				return false
			}
		}
	}
	if usedSubject && fp.usedSubject != nil {
		*fp.usedSubject = true
	}
	if topLevel && !usedSubject && structMemo != nil {
		for s := range visiting {
			structMemo[s] = true
		}
	}
	markDynamicLeaf(fp)
	return true
}

func (fp *freshParamAnalysis) isEnumSiteCaller(fn *ssa.Function) bool {
	if fp == nil || fn == nil {
		return false
	}
	for _, site := range fp.enumSites {
		if site != nil && site.Parent() == fn {
			return true
		}
	}
	return false
}

func collectUserStructSeeds(named *types.Named, collect *dynamicValueCollector, fp *freshParamAnalysis) {
	if !collect.isSeeds() || fp == nil || !fp.selectionAudited || named == nil {
		return
	}
	if collect.visitedStructs != nil && collect.visitedStructs[named] {
		return
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return
	}
	if collect.visitedStructs == nil {
		collect.visitedStructs = map[*types.Named]bool{}
	}
	collect.visitedStructs[named] = true
	wasProgScope := fp.inProgramSites || fp.inFieldStore
	wholeFP := *fp
	wholeFP.calleeFrame = calleeFrame{inProgramSites: true}
	if !wasProgScope {
		wholeFP.rootSeen = nil
	}
	for _, wv := range fp.structWholeStores[named] {
		walkDynamicValue(wv, collect, map[ssa.Value]bool{}, nil, &wholeFP)
	}
	fieldFP := *fp
	fieldFP.calleeFrame = calleeFrame{inProgramSites: fp.inProgramSites, inFieldStore: true}
	if !wasProgScope {
		fieldFP.rootSeen = nil
	}
	for f := 0; f < st.NumFields(); f++ {
		fType := st.Field(f).Type()
		if !typeMayCarryDynamicTop(fp.selectionAudited, fType) {
			continue
		}
		if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
			if innerNamed := derefNamedStruct(fp.userPkgPaths(), fType); innerNamed != nil {
				collectUserStructSeeds(innerNamed, collect, fp)
			}
		}
		key := structFieldKey{named: named, field: f}
		for _, sv := range fp.structFieldStores[key] {
			walkDynamicValue(sv, collect, map[ssa.Value]bool{}, nil, &fieldFP)
		}
	}
}

func userStructWholeStoresClosed(named *types.Named, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || named == nil {
		return collect.isSeeds()
	}
	if !collect.isSeeds() && fp.structPoisoned[structFieldKey{named: named, field: -1}] {
		return false
	}
	wholeStores := fp.structWholeStores[named]
	if len(wholeStores) == 0 {
		return true
	}
	wasProgScope := fp.inProgramSites || fp.inFieldStore
	wholeFP := *fp
	wholeFP.inProgramSites = true
	wholeFP.inFieldStore = true
	wholeFP.baseCarrierNamed = nil
	wholeFP.callBindings = nil
	wholeFP.calleeSeen = nil
	wholeFP.calleeDepth = nil
	if !wasProgScope {
		wholeFP.isolateRootScope()
	}
	wholeDone := done
	if wholeFP.rootDone != nil {
		wholeDone = wholeFP.rootDone
	} else if (!wasProgScope || fp.baseCarrierNamed != nil) && done != nil {
		wholeDone = map[ssa.Value]bool{}
	}
	if !collect.collecting() {
		savedLeaf := false
		if fp.hasLeaf != nil {
			savedLeaf = *fp.hasLeaf
		}
		for _, wv := range wholeStores {
			if !walkDynamicValue(wv, nil, seen, wholeDone, &wholeFP) {
				return false
			}
		}
		if fp.hasLeaf != nil {
			*fp.hasLeaf = savedLeaf
		}
		return true
	}
	if collect.isSeeds() {
		for _, wv := range wholeStores {
			walkDynamicValue(wv, collect, seen, wholeDone, &wholeFP)
		}
	}
	return true
}

func walkUserStructFieldDynamicValue(base ssa.Value, fieldIdx int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) (closed, handled bool) {
	if fp == nil || base == nil {
		return false, false
	}
	collecting := collect.collecting()
	wasProgScope := fp.inProgramSites || fp.inFieldStore
	fieldFP := *fp
	fieldFP.inFieldStore = true
	fieldFP.baseCarrierNamed = nil
	fieldFP.callBindings = nil
	fieldFP.calleeSeen = nil
	fieldFP.calleeDepth = nil
	if !wasProgScope {
		fieldFP.isolateRootScope()
	}
	fieldDone := done
	if fieldFP.rootDone != nil {
		fieldDone = fieldFP.rootDone
	} else if (!wasProgScope || fp.baseCarrierNamed != nil) && done != nil {
		fieldDone = map[ssa.Value]bool{}
	}
	checkInnerStruct := func(named *types.Named) bool {
		if named == nil {
			return true
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok || fieldIdx < 0 || fieldIdx >= st.NumFields() {
			return true
		}
		fType := st.Field(fieldIdx).Type()
		if _, isPtr := types.Unalias(fType).(*types.Pointer); isPtr {
			return true
		}
		innerNamed := derefNamedStruct(fp.userPkgPaths(), fType)
		if innerNamed == nil || !typeMayCarryDynamicTop(fp.selectionAudited, innerNamed) {
			return true
		}
		if !collecting {
			return enumUserStructClosed(innerNamed, &fieldFP)
		}
		if collect.isSeeds() {
			collectUserStructSeeds(innerNamed, collect, &fieldFP)
		}
		return true
	}
	if fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && base == fp.enumRoot.Params[0] {
		fp.markSubjectUsed()
		if len(fp.enumFieldStores) > 0 {
			named := derefNamedStruct(fp.userPkgPaths(), base.Type())
			if named != nil && (!userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) || !checkInnerStruct(named)) && !collect.isSeeds() {
				return false, true
			}
			stores, ok := fp.enumFieldStores[fieldIdx]
			if ok && len(stores) == 0 {
				if !collecting {
					markDynamicLeaf(fp)
				}
				return true, true
			}
			for _, sv := range stores {
				if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
					return false, true
				}
			}
			return true, true
		}
	}
	if !fp.selectionAudited && !collect.isSeeds() {
		return false, false
	}
	named := derefNamedStruct(fp.userPkgPaths(), base.Type())
	if named == nil {
		return false, false
	}
	key := structFieldKey{named: named, field: fieldIdx}
	if !collect.isSeeds() && (fp.structPoisoned[key] || !fp.structReferencedByType[named]) {
		return false, true
	}
	if !collecting {
		savedLeaf := false
		if fp.hasLeaf != nil {
			savedLeaf = *fp.hasLeaf
		}
		baseFP := *fp
		baseFP.baseCarrierNamed = named
		baseDone := done
		if fp.baseCarrierNamed != named && done != nil {
			baseDone = map[ssa.Value]bool{}
		}
		if !walkDynamicValue(base, nil, seen, baseDone, &baseFP) {
			return false, true
		}
		if fp.hasLeaf != nil {
			*fp.hasLeaf = savedLeaf
		}
	} else if collect.isSeeds() {
		walkDynamicValue(base, collect, seen, done, fp)
	}
	if (!userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) || !checkInnerStruct(named)) && !collect.isSeeds() {
		return false, true
	}
	stores := fp.structFieldStores[key]
	if len(stores) == 0 {
		if !collecting {
			markDynamicLeaf(fp)
		}
		return true, true
	}
	for _, sv := range stores {
		if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
			return false, true
		}
	}
	return true, true
}
