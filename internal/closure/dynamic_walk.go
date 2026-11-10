package closure

import (
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
)

// locallyClosedDynamicValue is the intraprocedural projection of
// subjectClosedDynamicValue: with no caller-edge analysis, the
// parameter arm fails closed, so only locally constructed values close.
func locallyClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	return subjectClosedDynamicValue(value, seen, nil)
}

// subjectClosedDynamicValue extends locallyClosedDynamicValue across
// exactly one boundary kind: a parameter is subject-closed when every
// subject-attributed call site of its function passes a subject-closed
// value at its position, so the operand's dynamic types are fully
// determined by the subject's own flow. A load from a global or field
// refuses: analysis is subject-scoped but the process heap is shared,
// so a sibling subject's runtime flow can plant an implementation the
// subject's attributed enumeration cannot see
// (REQ-closure-observability-dispatch
// admission).
func inActiveCallee(fn *ssa.Function, calleeSeen map[*ssa.Function]bool) bool {
	if len(calleeSeen) == 0 {
		return false
	}
	for fn != nil {
		if calleeSeen[fn] {
			return true
		}
		fn = fn.Parent()
	}
	return false
}

func resetWalkState(fp *freshParamAnalysis) *freshParamAnalysis {
	if fp == nil || (fp.stackDepth == nil && fp.rootSeen == nil) {
		return fp
	}
	copied := *fp
	copied.walkFrame = walkFrame{}
	return &copied
}

func subjectClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return closedDynamicValue(value, seen, map[ssa.Value]bool{}, resetWalkState(fp))
}

// closedDynamicValue walks with a gray set (cycle guard — one value
// legitimately feeds several call sites of one parameter, so a
// completed evaluation must not poison the next) and a done memo (a
// completed result is reused, bounding the walk linearly where DAG
// revisits would otherwise re-evaluate exponentially). A refusal forced
// by a gray ancestor memoizes conservatively: deterministic under SSA
// operand order, fail-closed, never a wrong acceptance — gray only ever
// forces false and every combinator is conjunctive.
func closedDynamicValue(value ssa.Value, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return walkDynamicValue(value, nil, seen, done, fp)
}

type dynamicValueCollector struct {
	funcs          map[*ssa.Function]bool
	types          map[types.Type]bool
	seeds          bool
	sinkOnly       bool
	visitedStructs map[*types.Named]bool
}

func (c *dynamicValueCollector) collecting() bool {
	return c != nil
}

func (c *dynamicValueCollector) isSeeds() bool {
	return c != nil && c.seeds
}

func (c *dynamicValueCollector) isSink() bool {
	return c != nil && c.sinkOnly
}

// walkDynamicValue is the single SSA shape ladder serving the
// closed-value judgment (collect == nil, with a gray seen set and done memo),
// the function-target collector (collect.funcs != nil), the concrete
// interface-type collector (collect.types != nil), the combined RTA
// seed collector (collect.seeds == true), and the in-memory formatted
// sink judgment (collect.sinkOnly == true).
func walkDynamicValue(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if value == nil {
		return false
	}
	if collect.isSink() {
		if r, ok := done[value]; ok {
			return r
		}
		if seen[value] {
			return false
		}
		seen[value] = true
		defer delete(seen, value)
		r := walkDynamicValueUncached(value, collect, seen, done, fp)
		if done != nil {
			done[value] = r
		}
		return r
	}
	if collect.isSeeds() {
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
		if fp.usedSubject != nil && value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot) {
			*fp.usedSubject = true
		}
		outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
		inProgScope := outsideCallee && !fp.ignoreContextValuePayload && fp.enumRecvNamed == nil && value.Parent() != fp.enumRoot && value.Parent() != fp.subjectRoot
		if outsideCallee {
			if inProgScope && fp.summary != nil {
				if entry, ok := fp.summary.enumSeedsMemo[value]; ok {
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
			usedSubject := value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)
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
			if fp.usedSubject != nil && usedSubject {
				*fp.usedSubject = true
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
			if topSeedWalk && inProgScope && fp.summary != nil && !usedSubject && len(fp.calleeSeen) == 0 && len(fp.invokeSeen) == 0 {
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
				fp.summary.enumSeedsMemo[value] = dynamicSeedEntry{
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
	collecting := collect.collecting()
	if fp == nil {
		if collecting {
			if seen[value] {
				return true
			}
			seen[value] = true
			return walkDynamicValueUncached(value, collect, seen, done, nil)
		}
		if r, ok := done[value]; ok {
			return r
		}
		if seen[value] {
			return false
		}
		seen[value] = true
		defer delete(seen, value)
		r := walkDynamicValueUncached(value, nil, seen, done, nil)
		if done != nil {
			done[value] = r
		}
		return r
	}
	if fp.usedSubject != nil && value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot) {
		*fp.usedSubject = true
	}
	outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
	inCycleScope := (fp.enumOnly || fp.enumRoot == nil) && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly) && value.Parent() != fp.enumRoot && value.Parent() != fp.subjectRoot
	inProgScope := outsideCallee && inCycleScope && !fp.ignoreContextValuePayload && fp.enumRecvNamed == nil
	if collecting {
		if outsideCallee {
			if inProgScope && fp.summary != nil {
				if collect.types != nil && collect.funcs == nil {
					tMemo, tFail := fp.summary.progTypesMemo, fp.summary.progTypesFailed
					if fp.enumOnly {
						tMemo, tFail = fp.summary.enumTypesMemo, fp.summary.enumTypesFailed
					}
					if tFail[value] {
						return false
					}
					if ts, ok := tMemo[value]; ok {
						for _, t := range ts {
							collect.types[t] = true
						}
						return true
					}
				} else if collect.funcs != nil && collect.types == nil && !fp.enumOnly {
					if fp.summary.progFuncsFailed[value] {
						return false
					}
					if fs, ok := fp.summary.progFuncsMemo[value]; ok {
						for _, fn := range fs {
							collect.funcs[fn] = true
						}
						return true
					}
				}
			}
			if collect.types != nil && collect.funcs == nil {
				if fp.typesFailed != nil && fp.typesFailed[value] {
					return false
				}
				if fp.typesMemo != nil {
					if ts, ok := fp.typesMemo[value]; ok {
						for _, t := range ts {
							collect.types[t] = true
						}
						return true
					}
				}
			} else if collect.funcs != nil && collect.types == nil {
				if fp.funcsFailed != nil && fp.funcsFailed[value] {
					return false
				}
				if fp.funcsMemo != nil {
					if fs, ok := fp.funcsMemo[value]; ok {
						for _, fn := range fs {
							collect.funcs[fn] = true
						}
						return true
					}
				}
			}
			if fp.rootSeen != nil {
				if fp.rootSeen[value] {
					return true
				}
				fp.rootSeen[value] = true
				return walkDynamicValueUncached(value, collect, seen, done, fp)
			}
			usedSubject := value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)
			rootFP := *fp
			rootFP.rootSeen = map[ssa.Value]bool{value: true}
			rootFP.usedSubject = &usedSubject
			var subCollect dynamicValueCollector
			if collect.types != nil {
				subCollect.types = map[types.Type]bool{}
			}
			if collect.funcs != nil {
				subCollect.funcs = map[*ssa.Function]bool{}
			}
			r := walkDynamicValueUncached(value, &subCollect, seen, done, &rootFP)
			if fp.usedSubject != nil && usedSubject {
				*fp.usedSubject = true
			}
			if r {
				for t := range subCollect.types {
					collect.types[t] = true
				}
				for fn := range subCollect.funcs {
					collect.funcs[fn] = true
				}
			}
			if len(fp.calleeSeen) == 0 && len(fp.invokeSeen) == 0 && fp.baseCarrierNamed == nil {
				canSaveProg := inProgScope && fp.summary != nil && !usedSubject && len(fp.enumStructVisiting) == 0
				if collect.types != nil && collect.funcs == nil {
					if r {
						ts := make([]types.Type, 0, len(subCollect.types))
						for t := range subCollect.types {
							ts = append(ts, t)
						}
						if fp.typesMemo != nil {
							fp.typesMemo[value] = ts
						}
						if canSaveProg {
							tMemo := fp.summary.progTypesMemo
							if fp.enumOnly {
								tMemo = fp.summary.enumTypesMemo
							}
							tMemo[value] = ts
						}
					} else {
						if fp.typesFailed != nil {
							fp.typesFailed[value] = true
						}
						if canSaveProg {
							tFail := fp.summary.progTypesFailed
							if fp.enumOnly {
								tFail = fp.summary.enumTypesFailed
							}
							tFail[value] = true
						}
					}
				} else if collect.funcs != nil && collect.types == nil {
					if r {
						fs := make([]*ssa.Function, 0, len(subCollect.funcs))
						for fn := range subCollect.funcs {
							fs = append(fs, fn)
						}
						if fp.funcsMemo != nil {
							fp.funcsMemo[value] = fs
						}
						if canSaveProg && !fp.enumOnly {
							fp.summary.progFuncsMemo[value] = fs
						}
					} else {
						if fp.funcsFailed != nil {
							fp.funcsFailed[value] = true
						}
						if canSaveProg && !fp.enumOnly {
							fp.summary.progFuncsFailed[value] = true
						}
					}
				}
			}
			return r
		}
		if seen[value] {
			return true
		}
		seen[value] = true
		return walkDynamicValueUncached(value, collect, seen, done, fp)
	}
	if fp.stackDepth == nil {
		var lowlink int
		var hasLeaf, usedSubject bool
		if done == nil {
			done = map[ssa.Value]bool{}
		}
		if seen == nil {
			seen = map[ssa.Value]bool{}
		}
		rootFP := *fp
		rootFP.stackDepth = map[ssa.Value]int{}
		rootFP.lowlink = &lowlink
		rootFP.hasLeaf = &hasLeaf
		rootFP.usedSubject = &usedSubject
		rootFP.rootDone = done
		rootFP.rootLowlink = map[ssa.Value]int{}
		rootFP.rootHasLeaf = map[ssa.Value]bool{}
		rootFP.rootUsedSubject = map[ssa.Value]bool{}
		fp = &rootFP
	}
	if outsideCallee {
		if inProgScope && fp.summary != nil {
			progMemo := fp.summary.progClosedDone
			if fp.enumOnly {
				progMemo = fp.summary.enumClosedDone
			}
			if r, ok := progMemo[value]; ok && (r || (len(fp.enumStructVisiting) == 0 && fp.baseCarrierNamed == nil)) {
				if r {
					markDynamicLeaf(fp)
				}
				return r
			}
		}
		if fp.closedDone != nil {
			if r, ok := fp.closedDone[value]; ok && (r || fp.baseCarrierNamed == nil) {
				if r {
					markDynamicLeaf(fp)
				}
				return r
			}
		}
	} else if done != nil {
		if r, ok := done[value]; ok && (r || fp.baseCarrierNamed == nil) {
			if r {
				markDynamicLeaf(fp)
			}
			return r
		}
	}
	if d, onStack := fp.stackDepth[value]; onStack {
		if fp.selectionAudited && !isTestingTBInterface(value.Type()) {
			if *fp.lowlink == 0 || d < *fp.lowlink {
				*fp.lowlink = d
			}
			return true
		}
		return false
	}
	if outsideCallee && fp.rootDone != nil {
		if r, ok := fp.rootDone[value]; ok {
			if ll := fp.rootLowlink[value]; ll != 0 && (*fp.lowlink == 0 || ll < *fp.lowlink) {
				*fp.lowlink = ll
			}
			if r && fp.rootHasLeaf[value] {
				markDynamicLeaf(fp)
			}
			if fp.rootUsedSubject[value] && fp.usedSubject != nil {
				*fp.usedSubject = true
			}
			return r
		}
	}
	myDepth := fp.baseDepth + len(fp.stackDepth) + 1
	fp.stackDepth[value] = myDepth
	outerLowlink := *fp.lowlink
	*fp.lowlink = 0
	outerHasLeaf := *fp.hasLeaf
	*fp.hasLeaf = false
	outerUsedSubject := *fp.usedSubject
	*fp.usedSubject = value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)

	r := walkDynamicValueUncached(value, nil, seen, done, fp)

	delete(fp.stackDepth, value)
	myLowlink := *fp.lowlink
	myHasLeaf := *fp.hasLeaf
	myUsedSubject := *fp.usedSubject
	if myLowlink != 0 && myLowlink >= myDepth {
		if r && !myHasLeaf {
			if !(fp.selectionAudited && inCycleScope && !myUsedSubject) {
				r = false
			}
		}
		myLowlink = 0
		if outsideCallee {
			for k, ll := range fp.rootLowlink {
				if ll >= myDepth {
					delete(fp.rootDone, k)
					delete(fp.rootLowlink, k)
					delete(fp.rootHasLeaf, k)
					delete(fp.rootUsedSubject, k)
				}
			}
		}
	}
	*fp.lowlink = outerLowlink
	if myLowlink != 0 && (*fp.lowlink == 0 || myLowlink < *fp.lowlink) {
		*fp.lowlink = myLowlink
	}
	*fp.hasLeaf = outerHasLeaf || (r && myHasLeaf)
	*fp.usedSubject = outerUsedSubject || myUsedSubject

	if myLowlink == 0 && (!r || myHasLeaf) {
		if outsideCallee {
			if fp.closedDone != nil && fp.baseCarrierNamed == nil {
				fp.closedDone[value] = r
			}
			if inProgScope && fp.summary != nil && !myUsedSubject && len(fp.enumStructVisiting) == 0 && fp.baseCarrierNamed == nil {
				progMemo := fp.summary.progClosedDone
				if fp.enumOnly {
					progMemo = fp.summary.enumClosedDone
				}
				progMemo[value] = r
			}
		} else if done != nil && fp.baseCarrierNamed == nil {
			done[value] = r
		}
	} else if outsideCallee && fp.rootDone != nil {
		fp.rootDone[value] = r
		fp.rootLowlink[value] = myLowlink
		fp.rootHasLeaf[value] = r && myHasLeaf
		fp.rootUsedSubject[value] = myUsedSubject
	}
	return r
}

func markDynamicLeaf(fp *freshParamAnalysis) {
	if fp != nil && fp.hasLeaf != nil {
		*fp.hasLeaf = true
	}
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
		return false
	}
	if fp.enumStructVisiting[named] {
		markDynamicLeaf(fp)
		return true
	}
	if fp.summary != nil && !fp.ignoreContextValuePayload {
		if r, ok := fp.summary.enumStructClosed[named]; ok && (r || (len(fp.enumStructVisiting) == 0 && fp.enumRecvNamed == nil)) {
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
			if usedSubject && fp.usedSubject != nil {
				*fp.usedSubject = true
			}
			if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
				fp.summary.enumStructClosed[named] = false
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
			if topLevel && fp.summary != nil && !fp.ignoreContextValuePayload {
				fp.summary.enumStructClosed[named] = false
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
					if usedSubject && fp.usedSubject != nil {
						*fp.usedSubject = true
					}
					if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
						fp.summary.enumStructClosed[named] = false
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
				if usedSubject && fp.usedSubject != nil {
					*fp.usedSubject = true
				}
				if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
					fp.summary.enumStructClosed[named] = false
				}
				return false
			}
		}
	}
	if usedSubject && fp.usedSubject != nil {
		*fp.usedSubject = true
	}
	if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
		for s := range visiting {
			fp.summary.enumStructClosed[s] = true
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
	wholeFP := *fp
	wholeFP.calleeFrame = calleeFrame{inProgramSites: true}
	for _, wv := range fp.structWholeStores[named] {
		walkDynamicValue(wv, collect, map[ssa.Value]bool{}, nil, &wholeFP)
	}
	fieldFP := *fp
	fieldFP.calleeFrame = calleeFrame{inProgramSites: fp.inProgramSites, inFieldStore: true}
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
	wholeFP := *fp
	wholeFP.inProgramSites = true
	wholeFP.inFieldStore = true
	wholeFP.callBindings = nil
	wholeFP.calleeSeen = nil
	wholeFP.calleeDepth = nil
	wholeDone := done
	if fp.rootDone != nil {
		wholeDone = fp.rootDone
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

func isTestingTBInterface(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB"
}

func isHarnessPointerType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

func walkDynamicValueUncached(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	collecting := collect.collecting()
	if !collect.isSink() && value != nil && value.Type() != nil {
		audited := fp != nil && fp.selectionAudited
		if !typeMayCarryDynamicTop(audited, value.Type()) {
			if !collecting {
				markDynamicLeaf(fp)
			}
			return true
		}
		if audited && isHarnessPointerType(value.Type()) {
			if !collecting {
				markDynamicLeaf(fp)
				return true
			}
			if collect.types != nil {
				collect.types[value.Type()] = true
				return true
			}
			return false
		}
	}
	recurse := func(next ssa.Value) bool {
		return walkDynamicValue(next, collect, seen, done, fp)
	}
	switch v := value.(type) {
	case *ssa.Builtin:
		if !collecting {
			markDynamicLeaf(fp)
		}
		return !collecting || collect.isSeeds()
	case *ssa.Const:
		if collect.isSink() {
			return false
		}
		if !collecting || v.Value == nil {
			markDynamicLeaf(fp)
			return true
		}
		return collect.isSeeds()
	case *ssa.MakeSlice:
		if collect.isSink() {
			return false
		}
		if collect.isSeeds() {
			if fp != nil && fp.selectionAudited {
				walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
					recurse(val)
					return true
				})
			}
			return true
		}
		wrote := false
		if !walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
			wrote = true
			if fp == nil || !fp.selectionAudited {
				return false
			}
			return recurse(val)
		}) {
			return false
		}
		if !wrote {
			if !collecting {
				markDynamicLeaf(fp)
			}
			return !collecting
		}
		return true
	case *ssa.MakeMap:
		if collect.isSink() || fp == nil || !fp.selectionAudited {
			return collect.isSeeds()
		}
		if !walkMakeMapValuesWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
			return recurse(val) || collect.isSeeds()
		}) && !collect.isSeeds() {
			return false
		}
		if !collecting {
			markDynamicLeaf(fp)
		}
		return true
	case *ssa.Lookup:
		if collect.isSink() || fp == nil || !fp.selectionAudited || v.X == nil {
			return collect.isSeeds()
		}
		return recurse(v.X)
	case *ssa.MakeInterface:
		if collect.isSink() {
			return v.X != nil && auditedInMemorySinkType(v.X.Type())
		}
		// An interface value pins its dynamic type at this instruction —
		// closed for dispatch enumeration. A FUNCTION laundered through an
		// interface is different: an interface is never invoked as a
		// function (its contents must be asserted back out first), so the
		// walk here is judging the function value's provenance, and the
		// interface hop must not wash the wrapper obligation — recurse.
		if v.X == nil || v.X.Type() == nil {
			return collect.isSeeds()
		}
		if _, isIface := types.Unalias(v.X.Type()).Underlying().(*types.Interface); isIface {
			return collect.isSeeds()
		}
		_, isFunc := types.Unalias(v.X.Type()).Underlying().(*types.Signature)
		audited := fp != nil && fp.selectionAudited
		if !collect.isSeeds() && !(v.Parent() != nil && fp.isStdFunc(v.Parent())) {
			if xPkg := unaliasedDerefNamedPkgPath(v.X.Type()); fp != nil && fp.isNonInternalPureDelegate(xPkg) && !isAuditedStdAliasValue(audited, v.X) {
				return false
			}
		}
		carriesInner := !isFunc && audited && typeMayCarryDynamicTop(audited, v.X.Type()) && !isHarnessPointerType(v.X.Type()) && (!(v.X.Parent() != nil && fp.isStdFunc(v.X.Parent())) || isAuditedStdErrorWrapperType(v.X.Type())) && (fp.enumOnly || collect.isSeeds() || fp.stdTypeMayDelegateDynamic(v.X.Type()))
		if collect != nil && collect.types != nil {
			collect.types[v.X.Type()] = true
			if (isFunc && collect.funcs != nil) || (carriesInner && collect.isSeeds()) {
				return recurse(v.X)
			}
			return true
		}
		if isFunc || (collect != nil && collect.funcs != nil) {
			return recurse(v.X)
		}
		if carriesInner && !collecting && fp != nil {
			return recurse(v.X)
		}
		markDynamicLeaf(fp)
		return true
	case *ssa.Function:
		if collect.isSink() {
			return false
		}
		// A synthetic interface-method thunk as a VALUE is never closed:
		// its receiver arrives as the call's first argument at sites the
		// value walk cannot see, and the thunk's toolchain-attributed body
		// is unscanned. Direct static calls judge the receiver at the site
		// instead and never consult the value walk for the static callee.
		if !collect.isSeeds() && ((syntheticInterfaceMethodWrapper(v) && len(v.FreeVars) == 0) || (fp != nil && fp.isNonInternalPureDelegate(funcPkgPath(v)))) {
			return false
		}
		if collect != nil {
			if collect.funcs == nil {
				return false
			}
			collect.funcs[v] = true
		}
		markDynamicLeaf(fp)
		return true
	case *ssa.MakeClosure:
		// A synthetic interface-method bound wrapper performs the real
		// dispatch on its captured receiver inside a body no walk scans:
		// the closure value is closed only through its bindings, whatever
		// later carries it to a call site. Bound wrappers on audited
		// property-harness methods likewise close only when their captured
		// receiver bindings pass the harness boundary gate.
		fn, ok := v.Fn.(*ssa.Function)
		if !collect.isSeeds() && ok && strings.HasPrefix(fn.Synthetic, "bound ") && !(v.Parent() != nil && fp.isStdFunc(v.Parent())) && fp != nil && fp.isNonInternalPureDelegate(funcPkgPath(fn)) {
			if len(v.Bindings) == 0 || !isAuditedStdAliasValue(fp.selectionAudited, v.Bindings[0]) {
				return false
			}
		}
		wrapFP := fp
		if ok && syntheticInterfaceMethodWrapper(fn) {
			if mObj, mOK := fn.Object().(*types.Func); mOK && isContextCancelMethod(mObj) {
				wrapFP = withIgnoreContextValuePayload(fp)
			}
		}
		if !collecting {
			if ok && syntheticInterfaceMethodWrapper(fn) {
				for _, binding := range v.Bindings {
					if !walkDynamicValue(binding, nil, seen, done, wrapFP) {
						return false
					}
				}
			} else if ok && propharness.IsHarnessPath(funcPkgPath(fn)) {
				if wrapFP == nil || !wrapFP.propertyHarnessAudited {
					return false
				}
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
				walkDynamicValue(v.Bindings[0], collect, seen, done, wrapFP)
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
	case *ssa.ChangeInterface:
		return recurse(v.X)
	case *ssa.TypeAssert:
		if !collect.isSeeds() && collect != nil && collect.types != nil && fp != nil && fp.selectionAudited && v.AssertedType != nil {
			subTypes := map[types.Type]bool{}
			subCollect := *collect
			subCollect.types = subTypes
			if !walkDynamicValue(v.X, &subCollect, seen, done, fp) {
				return false
			}
			assertedIface, isIface := types.Unalias(v.AssertedType).Underlying().(*types.Interface)
			for ct := range subTypes {
				if isIface {
					if types.Implements(ct, assertedIface) {
						collect.types[ct] = true
					}
				} else if types.AssignableTo(ct, v.AssertedType) || types.Identical(ct, v.AssertedType) {
					collect.types[ct] = true
				}
			}
			return true
		}
		return recurse(v.X)
	case *ssa.ChangeType:
		return recurse(v.X)
	case *ssa.Convert:
		return recurse(v.X)
	case *ssa.Slice:
		if collect.isSink() {
			return false
		}
		if v.X != nil {
			if _, isSlice := types.Unalias(v.X.Type()).Underlying().(*types.Slice); isSlice {
				return recurse(v.X)
			}
			if alloc, ok := v.X.(*ssa.Alloc); ok {
				if cell := cellOf(alloc, map[ssa.Value]bool{}); cell != nil {
					if !collecting {
						if fp != nil && fp.stackDepth != nil {
							if d, onStack := fp.stackDepth[cell]; onStack {
								if fp.selectionAudited {
									if *fp.lowlink == 0 || d < *fp.lowlink {
										*fp.lowlink = d
									}
									return true
								}
								return false
							}
							fp.stackDepth[cell] = fp.stackDepth[value]
							defer delete(fp.stackDepth, cell)
						} else {
							if seen[cell] {
								return false
							}
							seen[cell] = true
							defer delete(seen, cell)
						}
					}
					if !walkLoadCellReferrersWithFP(alloc, fp, recurse) && !collect.isSeeds() {
						return false
					}
					if !collecting {
						markDynamicLeaf(fp)
					}
					return true
				}
			}
		}
		return collect.isSeeds()
	case *ssa.Alloc:
		if !collect.isSink() && fp != nil && fp.selectionAudited && v.Type() != nil {
			stdAlloc := v.Parent() != nil && fp.isStdFunc(v.Parent()) && !isAuditedStdErrorWrapperType(v.Type())
			var userNamed *types.Named
			if !stdAlloc {
				userNamed = derefNamedStruct(fp.userPkgPaths(), v.Type())
			}
			if stdAlloc || (userNamed != nil && !fp.structPoisoned[structFieldKey{named: userNamed, field: -1}]) {
				if !collecting {
					if userNamed != nil && (fp.enumOnly || isAuditedStdErrorWrapperNamed(userNamed)) && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
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
					if userNamed != nil && collect.isSeeds() && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
						collectUserStructSeeds(userNamed, collect, fp)
					}
					return true
				}
			}
		}
		return collect.isSeeds()
	case *ssa.Field:
		if !collect.isSink() {
			if closed, handled := walkUserStructFieldDynamicValue(v.X, v.Field, collect, seen, done, fp); handled {
				return closed
			}
		}
		return collect.isSeeds()
	case *ssa.FieldAddr:
		if !collect.isSink() && fp != nil && fp.selectionAudited && v.X != nil {
			if !collecting && fp.baseCarrierNamed != nil && derefNamedStruct(fp.userPkgPaths(), v.Type()) == fp.baseCarrierNamed {
				outerNamed := derefNamedStruct(fp.userPkgPaths(), v.X.Type())
				if outerNamed == nil || fp.structPoisoned[structFieldKey{named: outerNamed, field: v.Field}] || !fp.structReferencedByType[outerNamed] {
					return false
				}
				outerFP := *fp
				outerFP.baseCarrierNamed = outerNamed
				return walkDynamicValue(v.X, nil, seen, done, &outerFP)
			}
			if closed, handled := walkUserStructFieldDynamicValue(v.X, v.Field, collect, seen, done, fp); handled {
				if !closed {
					return false
				}
				if collect != nil && collect.types != nil && v.Type() != nil {
					collect.types[v.Type()] = true
				}
				return true
			}
		}
		return collect.isSeeds()
	case *ssa.Call:
		if collect.isSink() {
			return false
		}
		if b, ok := v.Common().Value.(*ssa.Builtin); ok && b.Name() == "append" {
			for _, arg := range v.Common().Args {
				if !recurse(arg) && !collect.isSeeds() {
					return false
				}
			}
			return walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
				return fp != nil && fp.selectionAudited && (recurse(val) || collect.isSeeds())
			}) || collect.isSeeds()
		}
		if (collect.isSeeds() || (fp != nil && fp.selectionAudited)) && !v.Common().IsInvoke() && len(v.Common().Args) == 1 {
			if callee := v.Common().StaticCallee(); callee != nil && funcPkgPath(callee) == "slices" && functionSymbolName(callee) == "Clone" {
				if !recurse(v.Common().Args[0]) && !collect.isSeeds() {
					return false
				}
				if fp != nil && fp.selectionAudited {
					return walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
						return recurse(val) || collect.isSeeds()
					}) || collect.isSeeds()
				}
				return collect.isSeeds()
			}
		}
		if isHarnessContextCall(v, seen, done, fp) {
			if !collecting {
				markDynamicLeaf(fp)
				return true
			}
			if collect != nil && collect.types != nil {
				if ct := harnessCancelCtxType(v); ct != nil {
					collect.types[ct] = true
					return true
				}
			}
			return collect.isSeeds()
		}
		// A gate-passing static call into the property harness yields a
		// closed value: the harness wraps exactly the closed callables
		// the boundary gate judged (rapid.MakeCheck's returned callback
		// feeding the subtest driver is the driving shape).
		if !collecting && propertyHarnessClosedResult(v, fp) {
			markDynamicLeaf(fp)
			return true
		}
		return staticCallResultDynamicValue(v, -1, collect, seen, done, fp) || collect.isSeeds()
	case *ssa.Phi:
		if len(v.Edges) == 0 {
			return collect.isSeeds()
		}
		for _, edge := range v.Edges {
			if !recurse(edge) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.Extract:
		if !collect.isSink() {
			if call, ok := v.Tuple.(*ssa.Call); ok {
				if !collecting && propertyHarnessClosedResult(call, fp) {
					markDynamicLeaf(fp)
					return true
				}
				return staticCallResultDynamicValue(call, v.Index, collect, seen, done, fp) || collect.isSeeds()
			}
		}
		return recurse(v.Tuple)
	case *ssa.Parameter:
		if !collect.isSink() && fp != nil {
			if bound, ok := fp.callBindings[v]; ok && bound != nil {
				return walkDynamicValue(bound, collect, seen, done, fp.withoutCallee(v.Parent()))
			}
			if fp.enumRecvNamed != nil && fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && v == fp.enumRoot.Params[0] {
				if !collecting {
					markDynamicLeaf(fp)
					return true
				}
				if collect.types != nil {
					collect.types[v.Type()] = true
					return true
				}
				return collect.isSeeds()
			}
		}
		args, usedProgramSites, ok := attributedParameterArgs(v, fp)
		if !ok {
			if !collect.isSink() && fp != nil && fp.selectionAudited && ((!fp.enumOnly && fp.enumRoot == nil) || fp.enumOnly) && (fp.inProgramSites || fp.inFieldStore) {
				fn := v.Parent()
				if fn != nil && fn != fp.enumRoot && fn != fp.subjectRoot && !fp.isEnumSiteCaller(fn) && !fp.functions[fn] && !fp.dynamic[fn] && len(fp.callers[fn]) == 0 && !fp.programValueRef[fn] && len(fp.programSites[fn]) == 0 && !initFlowFrame(fn) {
					if fp.usedSubject != nil {
						*fp.usedSubject = true
					}
					markDynamicLeaf(fp)
					return true
				}
			}
			return collect.isSeeds()
		}
		argFP, argDone := fp, done
		if usedProgramSites {
			argFP, argDone = fp.withProgramSites(done)
		}
		for _, arg := range args {
			if !walkDynamicValue(arg, collect, seen, argDone, argFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.FreeVar:
		if collect.isSink() {
			return false
		}
		bindings, usedProgramSites, ok := attributedFreeVarBindings(v, fp)
		if !ok {
			return collect.isSeeds()
		}
		bindFP, bindDone := fp, done
		if usedProgramSites {
			bindFP, bindDone = fp.withProgramSites(done)
		} else {
			bindFP = fp.withoutCallee(v.Parent())
		}
		for _, b := range bindings {
			if !walkDynamicValue(b, collect, seen, bindDone, bindFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.UnOp:
		// A load from a closed cell: the recursive local closure's
		// idiom (`var visit func(); visit = func() { visit() }`) calls
		// through the cell the closure captured.
		if v.Op != token.MUL {
			return collect.isSeeds()
		}
		if collect.isSink() {
			if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && isUnmutatedStandardSentinelGlobal(fp.prog, g, "io", "Discard") {
				return true
			}
			if cellOf(v.X, map[ssa.Value]bool{}) == nil {
				return false
			}
			wrote := false
			ok := walkLoadCellReferrers(v.X, func(val ssa.Value) bool {
				wrote = true
				return recurse(val)
			})
			return ok && wrote
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
				if d, onStack := fp.stackDepth[cell]; onStack {
					if fp.selectionAudited {
						if *fp.lowlink == 0 || d < *fp.lowlink {
							*fp.lowlink = d
						}
						return true
					}
					return false
				}
				fp.stackDepth[cell] = fp.stackDepth[value]
				defer delete(fp.stackDepth, cell)
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
	default:
		return collect.isSeeds()
	}
}

func walkUserStructFieldDynamicValue(base ssa.Value, fieldIdx int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) (closed, handled bool) {
	if fp == nil || base == nil {
		return false, false
	}
	collecting := collect.collecting()
	fieldFP := *fp
	fieldFP.inFieldStore = true
	fieldFP.baseCarrierNamed = nil
	fieldFP.callBindings = nil
	fieldFP.calleeSeen = nil
	fieldFP.calleeDepth = nil
	fieldDone := done
	if fp.rootDone != nil {
		fieldDone = fp.rootDone
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
	if fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && base == fp.enumRoot.Params[0] && len(fp.enumFieldStores) > 0 {
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
		if !walkDynamicValue(base, nil, seen, done, &baseFP) {
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
