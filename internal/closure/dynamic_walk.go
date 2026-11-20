package closure

import (
	"context"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/trace"
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
// (REQ-closure-observability-dispatch admission).
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
	copied.walkFrame = walkFrame{usedSubject: fp.usedSubject}
	return &copied
}

func subjectClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return closedDynamicValue(value, seen, map[ssa.Value]bool{}, resetWalkState(fp))
}

// closedDynamicValue walks with a gray set (cycle guard — one value
// legitimately feeds several call sites of one parameter, so a
// completed evaluation must not poison the next) and a done memo (a
// completed result is reused, bounding the walk linearly where DAG
// revisits would otherwise re-evaluate exponentially).
func closedDynamicValue(value ssa.Value, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return walkDynamicValue(value, nil, seen, done, fp)
}

type dynamicValueCollector struct {
	funcs          map[*ssa.Function]bool
	types          map[types.Type]bool
	seeds          bool
	visitedStructs map[*types.Named]bool
}

func (c *dynamicValueCollector) collecting() bool {
	return c != nil
}

func (c *dynamicValueCollector) isSeeds() bool {
	return c != nil && c.seeds
}

// walkDynamicValue is the single SSA shape ladder serving the
// closed-value judgment (collect == nil, with a gray seen set and done memo),
// the function-target collector (collect.funcs != nil), the concrete
// interface-type collector (collect.types != nil), and the combined RTA
// seed collector (collect.seeds == true).
func walkDynamicValue(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if value == nil {
		return false
	}
	if collect.isSeeds() {
		return walkDynamicSeedValue(value, collect, seen, done, fp)
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
	outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
	pMemo := fp.progMemo()
	sMemo := fp.subjMemo()
	canReadProg := fp.canReadProgMemo(outsideCallee)
	if collecting {
		if outsideCallee {
			if canReadProg && pMemo != nil {
				if collect.types != nil && collect.funcs == nil {
					if entry, ok := pMemo.typesMemo[value]; ok {
						if entry.ok {
							for _, t := range entry.types {
								collect.types[t] = true
							}
							return true
						}
						if fp.canReadNegativeProgMemo() {
							return false
						}
					}
				} else if collect.funcs != nil && collect.types == nil {
					if entry, ok := pMemo.funcsMemo[value]; ok {
						if entry.ok {
							for _, fn := range entry.funcs {
								collect.funcs[fn] = true
							}
							return true
						}
						if fp.canReadNegativeProgMemo() {
							return false
						}
					}
				}
			}
			if sMemo != nil {
				if collect.types != nil && collect.funcs == nil {
					if entry, ok := sMemo.typesMemo[value]; ok && (entry.ok || fp.baseCarrierNamed == nil) {
						if entry.usedSubject {
							fp.markSubjectUsed()
						}
						if !entry.ok {
							return false
						}
						for _, t := range entry.types {
							collect.types[t] = true
						}
						return true
					}
				} else if collect.funcs != nil && collect.types == nil {
					if entry, ok := sMemo.funcsMemo[value]; ok && (entry.ok || fp.baseCarrierNamed == nil) {
						if entry.usedSubject {
							fp.markSubjectUsed()
						}
						if !entry.ok {
							return false
						}
						for _, fn := range entry.funcs {
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
			usedSubject := false
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
			if usedSubject {
				fp.markSubjectUsed()
			}
			if r {
				for t := range subCollect.types {
					collect.types[t] = true
				}
				for fn := range subCollect.funcs {
					collect.funcs[fn] = true
				}
			}
			if fp.canWriteSubjMemo(outsideCallee) && fp.baseCarrierNamed == nil {
				canSaveProg := fp.canWriteProgMemo(outsideCallee, usedSubject) && pMemo != nil
				if collect.types != nil && collect.funcs == nil {
					if r {
						ts := make([]types.Type, 0, len(subCollect.types))
						for t := range subCollect.types {
							ts = append(ts, t)
						}
						if sMemo != nil {
							sMemo.typesMemo[value] = typesMemoEntry{types: ts, ok: true, usedSubject: usedSubject}
						}
						if canSaveProg {
							pMemo.typesMemo[value] = typesMemoEntry{types: ts, ok: true}
						}
					} else {
						if sMemo != nil {
							sMemo.typesMemo[value] = typesMemoEntry{ok: false, usedSubject: usedSubject}
						}
						if canSaveProg {
							pMemo.typesMemo[value] = typesMemoEntry{ok: false}
						}
					}
				} else if collect.funcs != nil && collect.types == nil {
					if r {
						fs := make([]*ssa.Function, 0, len(subCollect.funcs))
						for fn := range subCollect.funcs {
							fs = append(fs, fn)
						}
						if sMemo != nil {
							sMemo.funcsMemo[value] = funcsMemoEntry{funcs: fs, ok: true, usedSubject: usedSubject}
						}
						if canSaveProg {
							pMemo.funcsMemo[value] = funcsMemoEntry{funcs: fs, ok: true}
						}
					} else {
						if sMemo != nil {
							sMemo.funcsMemo[value] = funcsMemoEntry{ok: false, usedSubject: usedSubject}
						}
						if canSaveProg {
							pMemo.funcsMemo[value] = funcsMemoEntry{ok: false}
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
		callerUsedSubject := fp.usedSubject
		if callerUsedSubject != nil {
			defer func() {
				if usedSubject {
					*callerUsedSubject = true
				}
			}()
		}
		if done == nil {
			done = map[ssa.Value]bool{}
		}
		if seen == nil {
			seen = map[ssa.Value]bool{}
		}
		rootFP := *fp
		rootFP.stackDepth = map[carrierMemoKey]int{}
		rootFP.lowlink = &lowlink
		rootFP.hasLeaf = &hasLeaf
		rootFP.usedSubject = &usedSubject
		rootFP.rootDone = done
		rootFP.rootLowlink = map[ssa.Value]int{}
		rootFP.rootHasLeaf = map[ssa.Value]bool{}
		rootFP.rootUsedSubject = map[ssa.Value]bool{}
		rootFP.carrierRootDone = map[carrierMemoKey]carrierRootMemoEntry{}
		fp = &rootFP
	}
	stackKey := fp.carrierKey(value)
	if outsideCallee {
		if canReadProg && pMemo != nil {
			if entry, ok := pMemo.closedDone[value]; ok && (entry.closed || fp.canReadNegativeProgMemo()) {
				if entry.closed {
					markDynamicLeaf(fp)
				}
				return entry.closed
			}
			if fp.baseCarrierNamed != nil {
				if entry, ok := pMemo.carrierDone[stackKey]; ok && (entry.closed || len(fp.enumStructVisiting) == 0) {
					if entry.closed {
						markDynamicLeaf(fp)
					}
					return entry.closed
				}
			}
		}
		if sMemo != nil {
			if entry, ok := sMemo.closedDone[value]; ok && (entry.closed || fp.baseCarrierNamed == nil) {
				if entry.usedSubject {
					fp.markSubjectUsed()
				}
				if entry.closed {
					markDynamicLeaf(fp)
				}
				return entry.closed
			}
			if fp.baseCarrierNamed != nil {
				if entry, ok := sMemo.carrierDone[stackKey]; ok {
					if entry.usedSubject {
						fp.markSubjectUsed()
					}
					if entry.closed {
						markDynamicLeaf(fp)
					}
					return entry.closed
				}
			}
		}
	} else if done != nil {
		if r, ok := done[value]; ok {
			if r {
				markDynamicLeaf(fp)
			}
			return r
		}
	}
	if d, onStack := fp.stackDepth[stackKey]; onStack {
		if fp.selectionAudited && !isTestingTBInterface(value.Type()) {
			if *fp.lowlink == 0 || d < *fp.lowlink {
				*fp.lowlink = d
			}
			return true
		}
		return false
	}
	if outsideCallee {
		if fp.baseCarrierNamed == nil && fp.rootDone != nil {
			if r, ok := fp.rootDone[value]; ok {
				if ll := fp.rootLowlink[value]; ll != 0 && (*fp.lowlink == 0 || ll < *fp.lowlink) {
					*fp.lowlink = ll
				}
				if r && fp.rootHasLeaf[value] {
					markDynamicLeaf(fp)
				}
				if fp.rootUsedSubject[value] {
					fp.markSubjectUsed()
				}
				return r
			}
		} else if fp.baseCarrierNamed != nil && fp.carrierRootDone != nil {
			if entry, ok := fp.carrierRootDone[stackKey]; ok {
				if entry.lowlink != 0 && (*fp.lowlink == 0 || entry.lowlink < *fp.lowlink) {
					*fp.lowlink = entry.lowlink
				}
				if entry.closed && entry.hasLeaf {
					markDynamicLeaf(fp)
				}
				if entry.usedSubject {
					fp.markSubjectUsed()
				}
				return entry.closed
			}
		}
	}
	myDepth := fp.baseDepth + len(fp.stackDepth) + 1
	fp.stackDepth[stackKey] = myDepth
	outerLowlink := *fp.lowlink
	*fp.lowlink = 0
	outerHasLeaf := *fp.hasLeaf
	*fp.hasLeaf = false
	outerUsedSubject := *fp.usedSubject
	*fp.usedSubject = false

	r := walkDynamicValueUncached(value, nil, seen, done, fp)

	delete(fp.stackDepth, stackKey)
	myLowlink := *fp.lowlink
	myHasLeaf := *fp.hasLeaf
	myUsedSubject := *fp.usedSubject
	if myLowlink != 0 && myLowlink >= myDepth {
		if r && !myHasLeaf {
			if !(fp.selectionAudited && fp.inCycleScope() && !myUsedSubject) {
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
			for k, entry := range fp.carrierRootDone {
				if entry.lowlink >= myDepth {
					delete(fp.carrierRootDone, k)
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
			canSaveSubj := fp.canWriteSubjMemo(outsideCallee) && sMemo != nil
			canSaveProg := fp.canWriteProgMemo(outsideCallee, myUsedSubject) && pMemo != nil
			if fp.baseCarrierNamed == nil {
				if canSaveSubj {
					sMemo.closedDone[value] = closedMemoEntry{closed: r, usedSubject: myUsedSubject}
				}
				if fp.rootDone != nil {
					fp.rootDone[value] = r
					fp.rootLowlink[value] = 0
					fp.rootHasLeaf[value] = r && myHasLeaf
					fp.rootUsedSubject[value] = myUsedSubject
				}
				if canSaveProg {
					pMemo.closedDone[value] = closedMemoEntry{closed: r}
				}
			} else {
				ckey := fp.carrierKey(value)
				if canSaveSubj {
					sMemo.carrierDone[ckey] = closedMemoEntry{closed: r, usedSubject: myUsedSubject}
				}
				if fp.carrierRootDone != nil {
					fp.carrierRootDone[ckey] = carrierRootMemoEntry{
						closed:      r,
						hasLeaf:     r && myHasLeaf,
						usedSubject: myUsedSubject,
						lowlink:     0,
					}
				}
				if canSaveProg {
					pMemo.carrierDone[ckey] = closedMemoEntry{closed: r}
				}
			}
		} else if done != nil {
			done[value] = r
		}
	} else if outsideCallee {
		if fp.baseCarrierNamed == nil && fp.rootDone != nil {
			fp.rootDone[value] = r
			fp.rootLowlink[value] = myLowlink
			fp.rootHasLeaf[value] = r && myHasLeaf
			fp.rootUsedSubject[value] = myUsedSubject
		} else if fp.baseCarrierNamed != nil && fp.carrierRootDone != nil {
			fp.carrierRootDone[fp.carrierKey(value)] = carrierRootMemoEntry{
				closed:      r,
				hasLeaf:     r && myHasLeaf,
				usedSubject: myUsedSubject,
				lowlink:     myLowlink,
			}
		}
	}
	return r
}

func markDynamicLeaf(fp *freshParamAnalysis) {
	if fp != nil && fp.hasLeaf != nil {
		*fp.hasLeaf = true
	}
}

func (fp *freshParamAnalysis) emitCtx() context.Context {
	if fp == nil {
		return nil
	}
	if fp.traceCtx != nil {
		return fp.traceCtx
	}
	if fp.summary != nil {
		return fp.summary.ctx
	}
	return nil
}

func isCrossScopeMutableStdAlloc(audited bool, fp *freshParamAnalysis, v ssa.Value, concrete bool) bool {
	if fp == nil || !(fp.enumOnly || fp.inFieldStore || fp.inProgramSites) || v == nil || v.Type() == nil {
		return false
	}
	if !isMutableStdCarrierAllocType(audited, v.Type(), concrete) {
		return false
	}
	if trace.AnyEnabled() {
		var fnName string
		if v.Parent() != nil {
			fnName = v.Parent().String()
		}
		target := fnName
		if fp.enumRoot != nil {
			target = fp.enumRoot.String()
		}
		trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.std_alloc.mutable", target,
			trace.String("type", v.Type().String()),
			trace.String("fn", fnName),
			trace.String("reason", "mutable_std_carrier_alloc"),
		)
	}
	return true
}

func walkDynamicValueUncached(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	collecting := collect.collecting()
	if value != nil && value.Type() != nil {
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
		if !collecting || v.Value == nil {
			markDynamicLeaf(fp)
			return true
		}
		return collect.isSeeds()
	case *ssa.MakeSlice:
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
		if fp == nil || !fp.selectionAudited {
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
		if fp == nil || !fp.selectionAudited || v.X == nil {
			return collect.isSeeds()
		}
		return recurse(v.X)
	case *ssa.MakeInterface:
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
		crossScope := fp != nil && (fp.enumOnly || fp.inFieldStore || fp.inProgramSites)
		boxedInStd := v.Parent() != nil && fp.isStdFunc(v.Parent())
		isStdInner := v.X.Parent() != nil && fp.isStdFunc(v.X.Parent()) && derefNamedStruct(fp.userPkgPaths(), v.X.Type()) == nil
		carriesInner := !isFunc && audited && typeMayCarryDynamicTop(audited, v.X.Type()) && !isHarnessPointerType(v.X.Type()) && (!isStdInner || isAuditedStdErrorWrapperType(v.X.Type()) || isCrossScopeMutableStdAlloc(audited, fp, v.X, !boxedInStd)) && (crossScope || collect.isSeeds() || fp.stdTypeMayDelegateDynamic(v.X.Type()))
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
		return walkMakeClosureDynamicValue(v, collect, seen, done, fp)
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
		if v.X != nil {
			if _, isSlice := types.Unalias(v.X.Type()).Underlying().(*types.Slice); isSlice {
				return recurse(v.X)
			}
			if alloc, ok := v.X.(*ssa.Alloc); ok {
				if cell := cellOf(alloc, map[ssa.Value]bool{}); cell != nil {
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
		if fp != nil && fp.selectionAudited && v.Type() != nil {
			stdAlloc := v.Parent() != nil && fp.isStdFunc(v.Parent()) && derefNamedStruct(fp.userPkgPaths(), v.Type()) == nil && !isAuditedStdErrorWrapperType(v.Type()) &&
				!isCrossScopeMutableStdAlloc(fp.selectionAudited, fp, v, true)
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
		if closed, handled := walkUserStructFieldDynamicValue(v.X, v.Field, collect, seen, done, fp); handled {
			return closed
		}
		return collect.isSeeds()
	case *ssa.FieldAddr:
		if fp != nil && fp.selectionAudited && v.X != nil {
			if !collecting && fp.baseCarrierNamed != nil && derefNamedStruct(fp.userPkgPaths(), v.Type()) == fp.baseCarrierNamed {
				outerNamed := derefNamedStruct(fp.userPkgPaths(), v.X.Type())
				if outerNamed == nil || fp.structPoisoned[structFieldKey{named: outerNamed, field: v.Field}] || !fp.structReferencedByType[outerNamed] {
					return false
				}
				outerFP := *fp
				outerFP.baseCarrierNamed = outerNamed
				outerDone := done
				if fp.baseCarrierNamed != outerNamed && done != nil {
					outerDone = map[ssa.Value]bool{}
				}
				return walkDynamicValue(v.X, nil, seen, outerDone, &outerFP)
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
		if call, ok := v.Tuple.(*ssa.Call); ok {
			if !collecting && propertyHarnessClosedResult(call, fp) {
				markDynamicLeaf(fp)
				return true
			}
			return staticCallResultDynamicValue(call, v.Index, collect, seen, done, fp) || collect.isSeeds()
		}
		return recurse(v.Tuple)
	case *ssa.Parameter:
		if fp != nil {
			if bound, ok := fp.callBindings[v]; ok && bound != nil {
				return walkDynamicValue(bound, collect, seen, done, fp.withoutCallee(v.Parent()))
			}
			if fp.enumRecvNamed != nil && fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && v == fp.enumRoot.Params[0] {
				fp.markSubjectUsed()
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
			if fp != nil && fp.selectionAudited && fp.programSites != nil && (fp.inProgramSites || fp.inFieldStore) {
				fn := v.Parent()
				if fn != nil && !fp.programValueRef[fn] && len(fp.programSites[fn]) == 0 && !initFlowFrame(fn) {
					fp.markSubjectUsed()
					if !fp.isSubjectRoot(fn) && !fp.isEnumSiteCaller(fn) && (fp.enumOnly || (fp.functions != nil && !fp.functions[fn] && fp.enumRoot == nil)) && !fp.dynamic[fn] && len(fp.callersOf(fn)) == 0 {
						markDynamicLeaf(fp)
						return true
					}
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
		return walkDerefDynamicValue(v, value, collect, seen, done, fp, recurse)
	default:
		return collect.isSeeds()
	}
}
