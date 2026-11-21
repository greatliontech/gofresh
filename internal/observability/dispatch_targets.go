package observability

import (
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/trace"
)

func newDispatchWalkStates(fp *freshParamAnalysis) (evalFP, collectFP *freshParamAnalysis, rootDone map[ssa.Value]bool, propagate func() (noEscape, usedSubj bool)) {
	var lowlink1, lowlink2 int
	var hasLeaf1, usedSubject1, usedSubject2 bool
	if fp != nil {
		e := *fp
		if fp.stackDepth != nil {
			e.stackDepth = fp.stackDepth
			e.rootDone = fp.rootDone
			e.rootLowlink = fp.rootLowlink
			e.rootHasLeaf = fp.rootHasLeaf
			e.rootUsedSubject = fp.rootUsedSubject
			e.carrierRootDone = fp.carrierRootDone
		} else {
			e.stackDepth = map[carrierMemoKey]int{}
			e.rootDone = map[ssa.Value]bool{}
			e.rootLowlink = map[ssa.Value]int{}
			e.rootHasLeaf = map[ssa.Value]bool{}
			e.rootUsedSubject = map[ssa.Value]bool{}
			e.carrierRootDone = map[carrierMemoKey]carrierRootMemoEntry{}
		}
		e.lowlink = &lowlink1
		e.hasLeaf = &hasLeaf1
		e.usedSubject = &usedSubject1
		e.baseCarrierNamed = nil
		e.rootSeen = nil
		evalFP = &e
		rootDone = evalFP.rootDone

		col := *fp
		col.stackDepth = nil
		col.lowlink = &lowlink2
		col.hasLeaf = nil
		col.usedSubject = &usedSubject2
		col.baseCarrierNamed = nil
		col.rootDone = nil
		col.rootLowlink = nil
		col.rootHasLeaf = nil
		col.rootUsedSubject = nil
		col.carrierRootDone = nil
		col.rootSeen = nil
		collectFP = &col
	} else {
		rootDone = map[ssa.Value]bool{}
	}
	propagate = func() (bool, bool) {
		usedSubj := usedSubject1 || usedSubject2
		noEscape := lowlink1 == 0 && lowlink2 == 0
		if fp != nil {
			if fp.lowlink != nil {
				if lowlink1 != 0 && (*fp.lowlink == 0 || lowlink1 < *fp.lowlink) {
					*fp.lowlink = lowlink1
				}
				if lowlink2 != 0 && (*fp.lowlink == 0 || lowlink2 < *fp.lowlink) {
					*fp.lowlink = lowlink2
				}
			}
			if fp.hasLeaf != nil && hasLeaf1 {
				*fp.hasLeaf = true
			}
			if fp.usedSubject != nil && usedSubj {
				*fp.usedSubject = true
			}
		}
		return noEscape, usedSubj
	}
	return evalFP, collectFP, rootDone, propagate
}

// closedDynamicTargets collects the functions a computed call's operand
// can hold when the closed-value walk closes it through shapes whose
// leaves are function values — function constants and closure
// creations, through phis, tuple extractions, type changes, closed
// cells, and the subject-attributed parameter crossing. A leaf the
// walk closes without naming a function (a gate-passing harness call
// result) or any open shape yields no set, and the enumeration's own
// targets stand. The set bounds the operand exactly: every function
// value that can reach the load or the parameter is one of the leaves
// (REQ-closure-observability-dispatch).
func closedDynamicTargets(value ssa.Value, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	evalFP, collectFP, rootDone, propagate := newDispatchWalkStates(fp)
	if !walkDynamicValue(value, nil, make(map[ssa.Value]bool), rootDone, evalFP) {
		propagate()
		return nil, false
	}
	targets := map[*ssa.Function]bool{}
	if !walkDynamicValue(value, &dynamicValueCollector{funcs: targets}, map[ssa.Value]bool{}, nil, collectFP) {
		propagate()
		return nil, false
	}
	propagate()
	return targets, true
}

// closedInvokeTargets resolves the methods of the invoked name on the concrete
// types an interface operand can hold, through the program's method sets.
// An operand the walk cannot close, a closed operand naming no concrete type,
// or a method the concrete type promotes from an unscanned body returns false
// so the enumeration's projection stays whole (REQ-closure-observability-dispatch).
func closedInvokeTargets(site ssa.CallInstruction, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	if site == nil || site.Parent() == nil || site.Parent().Prog == nil {
		return nil, false
	}
	c := site.Common()
	if c == nil || !c.IsInvoke() || c.Method == nil {
		return nil, false
	}
	fp = contextCancelMethodFP(site, fp)
	outsideCallee := fp != nil && (c.Value == nil || !inActiveCallee(c.Value.Parent(), fp.calleeSeen))
	pMemo := fp.progMemo()
	if fp.canReadProgMemo(outsideCallee) && pMemo != nil {
		if entry, ok := pMemo.invokeMemo[site]; ok {
			if entry.ok {
				return entry.targets, true
			}
			if fp.canReadNegativeProgMemo() {
				return nil, false
			}
		}
	}
	sMemo := fp.subjMemo()
	if outsideCallee && sMemo != nil {
		if entry, ok := sMemo.invokeMemo[site]; ok && (entry.ok || fp.baseCarrierNamed == nil) {
			if entry.usedSubject {
				fp.markSubjectUsed()
			}
			return entry.targets, entry.ok
		}
	}
	evalFP, collectFP, rootDone, propagateWalkFlags := newDispatchWalkStates(fp)
	var concreteTypes map[types.Type]bool
	fail := func(reason string) (map[*ssa.Function]bool, bool) {
		if trace.AnyEnabled() && site != nil && site.Parent() != nil && !fp.isStdFunc(site.Parent()) {
			var methodStr, recvStr, recvTypeStr string
			if c.Method != nil {
				methodStr = c.Method.FullName()
			}
			if c.Value != nil {
				recvStr = c.Value.String()
				if c.Value.Type() != nil {
					recvTypeStr = c.Value.Type().String()
				}
			}
			trace.Emit(fp.emitCtx(), trace.DomainClosure, "closure.invoke.unclosed", site.Parent().String(),
				trace.String("method", methodStr),
				trace.String("recv", recvStr),
				trace.String("recv_type", recvTypeStr),
				trace.Int("concrete_count", len(concreteTypes)),
				trace.String("reason", reason),
			)
		}
		noEscape, usedSubj := propagateWalkFlags()
		if noEscape && fp.baseCarrierNamed == nil {
			if sMemo != nil && fp.canWriteSubjMemo(outsideCallee) {
				sMemo.invokeMemo[site] = invokeMemoEntry{ok: false, usedSubject: usedSubj}
			}
			if fp.canWriteProgMemo(outsideCallee, usedSubj) && pMemo != nil {
				pMemo.invokeMemo[site] = invokeMemoEntry{ok: false}
			}
		}
		return nil, false
	}
	if !walkDynamicValue(c.Value, nil, make(map[ssa.Value]bool), rootDone, evalFP) {
		return fail("eval_recv")
	}
	concreteTypes = map[types.Type]bool{}
	allowEmptyConcrete := fp != nil && fp.selectionAudited && !isDirectNilOnlyParam(c.Value, collectFP)
	if !walkDynamicValue(c.Value, &dynamicValueCollector{types: concreteTypes}, map[ssa.Value]bool{}, nil, collectFP) || (len(concreteTypes) == 0 && !allowEmptyConcrete) {
		return fail("collect_concrete_types")
	}
	hmacReceiverAdmitted := false
	if fp != nil && fp.selectionAudited && c.Value != nil {
		for ct := range concreteTypes {
			if isHMAC, _, okH := classifyStatefulStreamType(ct, streamKindWriter); okH && isHMAC {
				hmacReceiverAdmitted, _ = inMemoryStreamValue(c.Value, streamKindWriter, collectFP, 0, nil)
				break
			}
		}
	}
	targets, ok := resolveConcreteMethodTargetsSeen(site.Parent().Prog, c.Value.Type(), c.Method, concreteTypes, collectFP, hmacReceiverAdmitted, map[types.Type]bool{})
	if !ok {
		return fail("resolve_method_targets")
	}
	noEscape, usedSubj := propagateWalkFlags()
	if noEscape {
		if sMemo != nil && fp.canWriteSubjMemo(outsideCallee) {
			sMemo.invokeMemo[site] = invokeMemoEntry{targets: targets, ok: true, usedSubject: usedSubj}
		}
		if fp.canWriteProgMemo(outsideCallee, usedSubj) && pMemo != nil {
			pMemo.invokeMemo[site] = invokeMemoEntry{targets: targets, ok: true}
		}
	}
	return targets, true
}

func isDirectNilOnlyParam(v ssa.Value, fp *freshParamAnalysis) bool {
	if fp == nil || fp.inProgramSites || fp.inFieldStore || fp.enumOnly || len(fp.invokeSeen) > 0 {
		return false
	}
	p, ok := v.(*ssa.Parameter)
	if !ok {
		return false
	}
	args, usedProg, ok := attributedParameterArgs(p, fp)
	if !ok || usedProg || len(args) == 0 {
		return false
	}
	for _, arg := range args {
		c, isConst := arg.(*ssa.Const)
		if !isConst || c.Value != nil {
			return false
		}
	}
	return true
}

func resolveConcreteMethodTargets(prog *ssa.Program, recvType types.Type, method *types.Func, concreteTypes map[types.Type]bool, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	return resolveConcreteMethodTargetsSeen(prog, recvType, method, concreteTypes, fp, false, map[types.Type]bool{})
}

func resolveConcreteMethodTargetsSeen(prog *ssa.Program, recvType types.Type, method *types.Func, concreteTypes map[types.Type]bool, fp *freshParamAnalysis, hmacReceiverAdmitted bool, seenTypes map[types.Type]bool) (map[*ssa.Function]bool, bool) {
	if prog == nil || method == nil {
		return nil, false
	}
	audited := fp != nil && fp.selectionAudited
	hasIOWrapper, hasTeeReader, hasMultiWriter, hasNonWrapperConcrete := false, false, false, false
	if audited {
		for ct := range concreteTypes {
			if isAuditedStandardIOWrapperType(ct) {
				hasIOWrapper = true
				switch auditedIOWrapperTypeName(ct) {
				case "teeReader":
					hasTeeReader = true
				case "multiWriter":
					hasMultiWriter = true
				}
			} else {
				hasNonWrapperConcrete = true
			}
		}
		if hasIOWrapper && method.Name() != "Close" && !hasNonWrapperConcrete {
			return nil, false
		}
	}
	iface, _ := types.Unalias(recvType).Underlying().(*types.Interface)
	targets := make(map[*ssa.Function]bool, len(concreteTypes))
	resolveOne := func(ct types.Type, mPkg *types.Package, mName string, mFunc *types.Func) bool {
		if seenTypes[ct] {
			return true
		}
		if mFunc != nil && isAuditedStandardContextInvoke(audited, ct, mFunc) {
			cmethod := prog.LookupMethod(ct, mPkg, mName)
			if cmethod == nil || len(cmethod.Blocks) == 0 {
				return false
			}
			targets[cmethod] = true
			return true
		}
		if mName == "Error" && isAdmittedOSGetwdErrorType(audited, ct, fp) {
			if cmethod := prog.LookupMethod(ct, mPkg, mName); cmethod != nil && len(cmethod.Blocks) > 0 {
				targets[cmethod] = true
			}
			return true
		}
		sel := prog.MethodSets.MethodSet(ct).Lookup(mPkg, mName)
		if sel == nil {
			return false
		}
		fnObj, ok := sel.Obj().(*types.Func)
		if !ok || fnObj == nil {
			return false
		}
		declFn := prog.FuncValue(fnObj)
		if declFn == nil {
			if !audited || fp == nil || len(sel.Index()) < 2 {
				return false
			}
			fieldPath := sel.Index()[:len(sel.Index())-1]
			sig, ok := fnObj.Type().(*types.Signature)
			if !ok || sig.Recv() == nil {
				return false
			}
			if _, isIface := types.Unalias(sig.Recv().Type()).Underlying().(*types.Interface); !isIface {
				return false
			}
			if fnObj.Pkg() != nil && fp != nil && fp.verifiedHarnesses[fnObj.Pkg().Path()] != nil {
				return false
			}
			named := derefNamedStruct(fp.userPkgPaths(), ct)
			if named == nil {
				return false
			}
			curNamed := named
			var stores []ssa.Value
			for i, fIdx := range fieldPath {
				key := structFieldKey{named: curNamed, field: fIdx}
				if fp.structPoisoned[key] || !fp.structReferencedByType[curNamed] || !userStructWholeStoresClosed(curNamed, nil, map[ssa.Value]bool{}, nil, resetWalkState(fp)) {
					return false
				}
				if i == len(fieldPath)-1 {
					stores = fp.structFieldStores[key]
				} else {
					st, ok := curNamed.Underlying().(*types.Struct)
					if !ok || fIdx < 0 || fIdx >= st.NumFields() {
						return false
					}
					curNamed = derefNamedStruct(fp.userPkgPaths(), st.Field(fIdx).Type())
					if curNamed == nil {
						return false
					}
				}
			}
			if len(stores) == 0 {
				return false
			}
			seenTypes[ct] = true
			fieldFP := *fp
			fieldFP.inFieldStore = true
			fieldFP.callBindings = nil
			fieldFP.calleeSeen = nil
			fieldFP.calleeDepth = nil
			embeddedTypes := map[types.Type]bool{}
			for _, sv := range stores {
				if !subjectClosedDynamicValue(sv, map[ssa.Value]bool{}, resetWalkState(&fieldFP)) || !walkDynamicValue(sv, &dynamicValueCollector{types: embeddedTypes}, map[ssa.Value]bool{}, nil, resetWalkState(&fieldFP)) {
					return false
				}
			}
			if len(embeddedTypes) == 0 {
				return true
			}
			embeddedTargets, ok := resolveConcreteMethodTargetsSeen(prog, sig.Recv().Type(), fnObj, embeddedTypes, &fieldFP, false, seenTypes)
			if !ok {
				return false
			}
			for t := range embeddedTargets {
				targets[t] = true
			}
			return true
		} else {
			if len(declFn.Blocks) == 0 || (fp != nil && fp.verifiedHarnesses[funcPkgPath(declFn)] != nil) {
				return false
			}
			if fp.isStdFunc(declFn) {
				if mFunc == nil || !isAuditedStandardContextInvoke(audited, ct, mFunc) {
					if audited && fp != nil && isAuditedStdErrorWrapperType(ct) && (mName == "Error" || mName == "Unwrap") {
						named := derefNamedStruct(fp.userPkgPaths(), ct)
						if named == nil {
							return false
						}
						st, ok := named.Underlying().(*types.Struct)
						if !ok || st.NumFields() < 3 {
							return false
						}
						errKey := structFieldKey{named: named, field: 2}
						if fp.structPoisoned[structFieldKey{named: named, field: -1}] || fp.structPoisoned[errKey] || !fp.structReferencedByType[named] || !userStructWholeStoresClosed(named, nil, map[ssa.Value]bool{}, nil, resetWalkState(fp)) {
							return false
						}
						seenTypes[ct] = true
						fieldFP := *fp
						fieldFP.inFieldStore = true
						fieldFP.callBindings = nil
						fieldFP.calleeSeen = nil
						fieldFP.calleeDepth = nil
						innerTypes := map[types.Type]bool{}
						for _, sv := range fp.structFieldStores[errKey] {
							if !subjectClosedDynamicValue(sv, map[ssa.Value]bool{}, resetWalkState(&fieldFP)) || !walkDynamicValue(sv, &dynamicValueCollector{types: innerTypes}, map[ssa.Value]bool{}, nil, resetWalkState(&fieldFP)) {
								return false
							}
						}
						if mName == "Error" && len(innerTypes) > 0 {
							errMethod := mFunc
							if errMethod == nil {
								errMethod = fnObj
							}
							innerTargets, ok := resolveConcreteMethodTargetsSeen(prog, st.Field(2).Type(), errMethod, innerTypes, &fieldFP, false, seenTypes)
							if !ok {
								return false
							}
							for t := range innerTargets {
								targets[t] = true
							}
						}
					} else {
						isHMAC, _, okH := classifyStatefulStreamType(ct, streamKindWriter)
						admittedHashRecv := isAdmittedPureHashConcreteType(audited, ct) || (hmacReceiverAdmitted && okH && isHMAC)
						if !admittedHashRecv && typeMayCarryDynamicTop(audited, ct) && (len(declFn.Params) == 0 || paramMaySupplyDynamicSeen(audited, fp.userPkgPaths(), declFn.Params[0], nil, make(map[*ssa.Parameter]bool))) {
							return false
						}
						declPkg := funcPkgPath(declFn)
						if !admittedHashRecv && !fp.isAuditedStandardOrDelegate(declPkg) && !auditedStandardCallee(audited, declPkg, functionSymbolName(declFn), declFn) {
							return false
						}
					}
				}
			}
		}
		cmethod := prog.LookupMethod(ct, mPkg, mName)
		if cmethod == nil || len(cmethod.Blocks) == 0 {
			return false
		}
		targets[cmethod] = true
		return true
	}
	for ct := range concreteTypes {
		if audited && isAuditedStandardIOWrapperType(ct) {
			if iface != nil && !types.Implements(ct, iface) {
				continue
			}
			if auditedIOWrapperTypeName(ct) == "multiReader" && method.Name() == "WriteTo" {
				return nil, false
			}
			cmethod := prog.LookupMethod(ct, method.Pkg(), method.Name())
			if cmethod == nil || len(cmethod.Blocks) == 0 {
				return nil, false
			}
			targets[cmethod] = true
			continue
		}
		if hasTeeReader && method.Name() == "Read" && prog.MethodSets.MethodSet(ct).Lookup(nil, "Write") != nil {
			if !resolveOne(ct, nil, "Write", nil) {
				return nil, false
			}
		}
		if hasMultiWriter && method.Name() == "WriteString" && prog.MethodSets.MethodSet(ct).Lookup(nil, "WriteString") == nil && prog.MethodSets.MethodSet(ct).Lookup(nil, "Write") != nil {
			if !resolveOne(ct, nil, "Write", nil) {
				return nil, false
			}
		}
		if iface != nil && !types.Implements(ct, iface) {
			if !hasIOWrapper || prog.MethodSets.MethodSet(ct).Lookup(method.Pkg(), method.Name()) == nil {
				continue
			}
		}
		if !resolveOne(ct, method.Pkg(), method.Name(), method) {
			return nil, false
		}
	}
	return targets, true
}

// narrowedTargets returns a dynamic call's or interface invoke's targets
// narrowed to the functions or concrete-type methods its operand can hold,
// within the enumeration's own set; a static call or an operand yielding no
// set keeps the enumeration's targets whole (REQ-closure-observability-dispatch).
func narrowedTargets(site ssa.CallInstruction, targets map[*ssa.Function]bool, fp *freshParamAnalysis) map[*ssa.Function]bool {
	c := site.Common()
	if c == nil || c.StaticCallee() != nil || len(targets) == 0 {
		return targets
	}
	var held map[*ssa.Function]bool
	var ok bool
	if c.IsInvoke() {
		held, ok = closedInvokeTargets(site, fp)
	} else {
		held, ok = closedDynamicTargets(c.Value, fp)
	}
	if !ok {
		return targets
	}
	narrowed := make(map[*ssa.Function]bool, len(held))
	anyInTargets := false
	for fn := range held {
		if targets[fn] {
			anyInTargets = true
		}
		narrowed[fn] = true
	}
	// A held function the enumeration does not list is a vocabulary
	// mismatch between the collector and RTA (a bound-method wrapper
	// against its method, say) — a fail-closed backstop no fixture
	// constructs, never a demonstrated bug: the enumeration's targets
	// stand rather than an empty set admitting the site. An empty held
	// set (a nil function value) is the one legitimate empty result.
	if !anyInTargets && len(held) > 0 {
		return targets
	}
	return narrowed
}

// attributedParameterArgs returns the value passed at param's position by
// every subject-attributed call site of its function, or ok=false when
// the crossing is unavailable — the function is dynamically targeted,
// closes over state, is variadic, or has no attributed caller (absence
// of provenance is refused, never a vacuous pass). It is the one
// caller-boundary discipline shared by every value walk that crosses a
// parameter. (The subject root's own harness parameter never reaches the
// dispatch walk's crossing: it is concrete *testing.T/B/F, and every
// concrete-to-interface boundary materializes a MakeInterface the walk
// closes on.)
func attributedParameterArgs(param *ssa.Parameter, fp *freshParamAnalysis) ([]ssa.Value, bool, bool) {
	if fp != nil {
		if bound, ok := fp.callBindings[param]; ok && bound != nil {
			return []ssa.Value{bound}, false, true
		}
	}
	fn := param.Parent()
	if !fp.paramCrossingEligible(fn) {
		return nil, false, false
	}
	idx := -1
	for i, p := range fn.Params {
		if p == param {
			idx = i
		}
	}
	if idx < 0 {
		return nil, false, false
	}
	var sites []ssa.CallInstruction
	if fn == fp.enumRoot || (!fp.inProgramSites && !fp.inFieldStore) {
		if !fp.enumOnly {
			fp.markSubjectUsed()
		}
		sites = fp.callersOf(fn)
	}
	usedProgramSites := false
	if fn == fp.enumRoot {
		fp.markSubjectUsed()
		// The subject root's own parameters cross to its whole-view
		// caller enumeration; any subject-internal recursion sites join
		// the conjunction rather than replacing it.
		sites = append(append([]ssa.CallInstruction(nil), sites...), fp.enumSites...)
		if len(fp.enumSites) > 0 {
			usedProgramSites = true
		}
	}
	needRecvProgram := fn != fp.enumRoot && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly || len(sites) == 0 || len(fn.FreeVars) != 0 || fp.dynamic[fn])
	if idx == 0 && fn.Signature != nil && fn.Signature.Recv() != nil && fp != nil && fp.selectionAudited && fp.summary != nil && needRecvProgram {
		if namedSig := derefNamedSignature(fp.userPkgPaths(), param.Type()); namedSig != nil {
			if _, isPtr := types.Unalias(param.Type()).(*types.Pointer); isPtr || fp.programValueRef[fn] || fp.summary.namedSigPoisoned[namedSig] {
				return nil, false, false
			}
			sources := fp.summary.namedSigSources[namedSig]
			progSites := fp.programSites[fn]
			combined := make([]ssa.Value, 0, len(progSites)+len(sources))
			for _, site := range progSites {
				if site.Common().IsInvoke() {
					continue
				}
				if len(site.Common().Args) > 0 {
					combined = append(combined, site.Common().Args[0])
				} else {
					return nil, false, false
				}
			}
			combined = append(combined, sources...)
			if len(combined) == 0 {
				return nil, false, false
			}
			return combined, true, true
		}
		if named := derefNamedStruct(fp.userPkgPaths(), param.Type()); named != nil {
			if fp.programValueRef[fn] || fp.structPoisoned[structFieldKey{named: named, field: -1}] {
				return nil, false, false
			}
			boxed := fp.summary.structBoxedValues[named]
			if len(boxed) > 0 {
				combined := make([]ssa.Value, 0, len(fp.programSites[fn])+len(boxed))
				for _, site := range fp.programSites[fn] {
					if site.Common().IsInvoke() {
						continue
					}
					if len(site.Common().Args) > 0 {
						combined = append(combined, site.Common().Args[0])
					} else {
						return nil, false, false
					}
				}
				combined = append(combined, boxed...)
				return combined, true, true
			}
		}
	}
	isSigParam := false
	if param.Type() != nil {
		_, isSigParam = types.Unalias(param.Type()).Underlying().(*types.Signature)
	}
	if isSigParam && fp.enumOnly {
		fp.markSubjectUsed()
	}
	if isSigParam && !fp.inFieldStore && !fp.inProgramSites {
		localClosed := !fp.enumOnly && fp.localClosureSitesClosed(fn)
		if ((!fp.functions[fn] || fp.dynamic[fn] || len(fn.FreeVars) != 0) && !localClosed) || fn.Signature.Variadic() {
			return nil, false, false
		}
	}
	isEnumSigParam := fp.enumOnly && !fp.inFieldStore && !fp.inProgramSites && isSigParam
	perSubjectSigParam := isSigParam && !fp.inFieldStore && !fp.inProgramSites && !fp.enumOnly && fp.functions[fn] && (len(sites) > 0 || !fp.selectionAudited)
	localSubjectSites := !fp.inFieldStore && !fp.inProgramSites && !fp.enumOnly && fp.functions[fn] && fp.localClosureSitesClosed(fn) && len(sites) > 0
	needProgramSites := (len(sites) == 0 || ((len(fn.FreeVars) != 0 || (fn != fp.enumRoot && fp.dynamic[fn])) && !localSubjectSites) || (fn != fp.enumRoot && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly))) && !isEnumSigParam && !perSubjectSigParam
	if needProgramSites {
		if fp.programSites == nil || fp.programValueRef[fn] || (len(fn.FreeVars) != 0 && (!fp.selectionAudited || len(fp.closures[fn]) == 0)) {
			return nil, false, false
		}
		sites = fp.programSites[fn]
		usedProgramSites = true
	}
	if len(sites) == 0 {
		// Absence of provenance refuses, never a vacuous pass. A
		// subject-reachable, statically called function always has an
		// attributed caller, so this arm is the clause's fail-closed
		// backstop rather than a reachable state.
		return nil, false, false
	}
	args := make([]ssa.Value, 0, len(sites))
	for _, site := range sites {
		if site.Common().IsInvoke() {
			if fn.Signature == nil || fn.Signature.Recv() == nil {
				return nil, false, false
			}
			if idx == 0 {
				args = append(args, site.Common().Value)
				continue
			}
			siteArgs := site.Common().Args
			if idx-1 >= len(siteArgs) {
				return nil, false, false
			}
			args = append(args, siteArgs[idx-1])
			continue
		}
		if site.Common().StaticCallee() == nil && (fn.Signature == nil || fn.Signature.Recv() != nil || fn.Signature.Variadic()) {
			return nil, false, false
		}
		siteArgs := site.Common().Args
		if idx >= len(siteArgs) {
			return nil, false, false
		}
		args = append(args, siteArgs[idx])
	}
	return args, usedProgramSites, true
}

func attributedFreeVarBindings(fv *ssa.FreeVar, fp *freshParamAnalysis) ([]ssa.Value, bool, bool) {
	if fv == nil || fp == nil || !fp.selectionAudited {
		return nil, false, false
	}
	fn := fv.Parent()
	if fn == nil {
		return nil, false, false
	}
	idx := slices.Index(fn.FreeVars, fv)
	if idx < 0 {
		return nil, false, false
	}
	if fn.Parent() != nil && inActiveCallee(fn.Parent(), fp.calleeSeen) {
		mcs := closureCreations(fn)
		if len(mcs) == 0 {
			return nil, false, false
		}
		bindings := make([]ssa.Value, 0, len(mcs))
		for _, mc := range mcs {
			if mc == nil || idx >= len(mc.Bindings) || mc.Bindings[idx] == nil {
				return nil, false, false
			}
			bindings = append(bindings, mc.Bindings[idx])
		}
		return bindings, false, true
	}
	var mcs []*ssa.MakeClosure
	if fp.closures != nil {
		mcs = fp.closures[fn]
	} else if fp.summary != nil {
		if fp.summary.nonClosureRef[fn] {
			return nil, false, false
		}
		mcs = fp.summary.closures[fn]
	} else if fn.Parent() != nil {
		mcs = closureCreations(fn)
	}
	if len(mcs) == 0 {
		return nil, false, false
	}
	filterSubjectOnly := !fp.programValueRef[fn] && !fp.inProgramSites && !fp.inFieldStore && !fp.enumOnly && len(fp.functions) > 0
	if filterSubjectOnly {
		fp.markSubjectUsed()
		bindings := make([]ssa.Value, 0, len(mcs))
		for _, mc := range mcs {
			if mc == nil || idx >= len(mc.Bindings) || mc.Bindings[idx] == nil {
				return nil, false, false
			}
			if fp.functions[mc.Parent()] {
				bindings = append(bindings, mc.Bindings[idx])
			}
		}
		if len(bindings) == 0 {
			return nil, false, false
		}
		return bindings, false, true
	}
	usedProgramSites := fn.Parent() == nil || (fp.inProgramSites && !fp.inFieldStore && len(fp.callBindings) == 0 && len(fp.calleeSeen) == 0)
	bindings := make([]ssa.Value, 0, len(mcs))
	for _, mc := range mcs {
		if mc == nil || idx >= len(mc.Bindings) || mc.Bindings[idx] == nil {
			return nil, false, false
		}
		if !usedProgramSites {
			if !fp.enumOnly {
				fp.markSubjectUsed()
			}
			if len(fp.functions) == 0 || !fp.functions[mc.Parent()] {
				usedProgramSites = true
			}
		}
		bindings = append(bindings, mc.Bindings[idx])
	}
	return bindings, usedProgramSites, true
}

// syntheticInterfaceMethodWrapper reports whether fn is a compiler
// synthetic (bound wrapper or thunk) over an interface method: the one
// wrapper family whose std-attributed body performs a real dynamic
// dispatch the walks never scan, so the dispatch provenance must be
// read at the wrapper's call site instead.
func syntheticInterfaceMethodWrapper(fn *ssa.Function) bool {
	if fn == nil || fn.Synthetic == "" {
		return false
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj == nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, isInterface := types.Unalias(sig.Recv().Type()).Underlying().(*types.Interface)
	return isInterface
}

// wrapperReceiver returns the value carrying a static wrapper call's
// dispatch provenance: a thunk's receiver argument (thunks close over
// nothing and take the receiver first), or the operand itself for a
// bound wrapper — whose bindings the closed-value walk already gates.
func wrapperReceiver(c *ssa.CallCommon, callee *ssa.Function) ssa.Value {
	if len(callee.FreeVars) == 0 {
		if len(c.Args) == 0 {
			return nil
		}
		return c.Args[0]
	}
	return c.Value
}

func isHarnessContextCall(call *ssa.Call, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil || call.Parent() == nil || call.Parent().Prog == nil {
		return false
	}
	ssaProg := call.Parent().Prog
	c := call.Common()
	if c.IsInvoke() {
		if c.Method == nil || c.Method.Name() != "Context" || c.Method.Pkg() == nil || c.Method.Pkg().Path() != "testing" {
			return false
		}
		return closedHarnessContextReceiver(c.Value, ssaProg, fp) && programContextCanceledUnmutated(fp.prog, ssaProg)
	}
	callee := c.StaticCallee()
	if callee == nil || funcPkgPath(callee) != "testing" || callee.Name() != "Context" {
		return false
	}
	if syntheticInterfaceMethodWrapper(callee) {
		recv := wrapperReceiver(c, callee)
		return closedHarnessContextReceiver(recv, ssaProg, fp) && programContextCanceledUnmutated(fp.prog, ssaProg)
	}
	_, ok := harnessCalleeEffect(fp.selectionAudited, callee, false)
	return ok && programContextCanceledUnmutated(fp.prog, ssaProg)
}

func findProgramContextPackage(ssaProg *ssa.Program) *ssa.Package {
	if ssaProg == nil {
		return nil
	}
	if pkg := ssaProg.ImportedPackage("context"); pkg != nil && pkg.Pkg != nil {
		return pkg
	}
	for _, pkg := range ssaProg.AllPackages() {
		if pkg != nil && pkg.Pkg != nil && pkg.Pkg.Path() == "context" {
			return pkg
		}
	}
	return nil
}

func programContextCanceledUnmutated(p *program, ssaProg *ssa.Program) bool {
	if ssaProg == nil {
		return false
	}
	if pkg := findProgramContextPackage(ssaProg); pkg != nil {
		if g := pkg.Var("Canceled"); g != nil {
			return isUnmutatedStandardSentinelGlobal(p, g, "context", "Canceled")
		}
	}
	return true
}

func closedHarnessContextReceiver(recv ssa.Value, prog *ssa.Program, fp *freshParamAnalysis) bool {
	if recv == nil || prog == nil || fp == nil || !fp.selectionAudited {
		return false
	}
	if !subjectClosedDynamicValue(recv, map[ssa.Value]bool{}, fp) {
		return false
	}
	cts := map[types.Type]bool{}
	if !walkDynamicValue(recv, &dynamicValueCollector{types: cts}, map[ssa.Value]bool{}, nil, resetWalkState(fp)) || len(cts) == 0 {
		return false
	}
	for ct := range cts {
		cmethod := prog.LookupMethod(ct, nil, "Context")
		if !harnessInvokeAdmitted(fp.selectionAudited, cmethod) {
			return false
		}
	}
	return true
}

func harnessCancelCtxType(call *ssa.Call) types.Type {
	if call == nil || call.Parent() == nil || call.Parent().Prog == nil {
		return nil
	}
	return programCancelCtxType(call.Parent().Prog)
}

func programCancelCtxType(prog *ssa.Program) types.Type {
	if pkg := findProgramContextPackage(prog); pkg != nil {
		if obj := pkg.Pkg.Scope().Lookup("cancelCtx"); obj != nil {
			return types.NewPointer(obj.Type())
		}
	}
	return nil
}

func isAuditedStandardContextInvoke(audited bool, ct types.Type, method *types.Func) bool {
	if !audited || ct == nil || method == nil || method.Pkg() == nil || method.Pkg().Path() != "context" {
		return false
	}
	switch method.Name() {
	case "Deadline", "Done", "Err", "Value":
	default:
		return false
	}
	return isAuditedStandardContextRecvType(ct)
}

func isContextCancelMethod(method *types.Func) bool {
	if method == nil || method.Pkg() == nil || method.Pkg().Path() != "context" {
		return false
	}
	switch method.Name() {
	case "Deadline", "Done", "Err":
	default:
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recvType := sig.Recv().Type()
	if named, ok := types.Unalias(recvType).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context" {
		return true
	}
	return isAuditedStandardContextRecvType(recvType)
}

func isContextCancelSite(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	if c.IsInvoke() {
		return isContextCancelMethod(c.Method)
	}
	callee := c.StaticCallee()
	if callee == nil {
		return false
	}
	if mObj, ok := callee.Object().(*types.Func); ok && isContextCancelMethod(mObj) {
		return true
	}
	return false
}

func withIgnoreContextValuePayloadDone(fp *freshParamAnalysis, done map[ssa.Value]bool) (*freshParamAnalysis, map[ssa.Value]bool) {
	if fp == nil || !fp.selectionAudited || fp.ignoreContextValuePayload {
		return fp, done
	}
	copied := *fp
	copied.ignoreContextValuePayload = true
	if copied.memoTables == nil {
		copied.resetDynamicMemos()
	}
	copied.isolateRootScope()
	outDone := done
	if copied.baseCarrierNamed == nil && copied.rootDone != nil && len(copied.calleeSeen) == 0 {
		outDone = copied.rootDone
	} else if done != nil {
		outDone = map[ssa.Value]bool{}
	}
	return &copied, outDone
}

func contextCancelMethodFPDone(site ssa.CallInstruction, fp *freshParamAnalysis, done map[ssa.Value]bool) (*freshParamAnalysis, map[ssa.Value]bool) {
	if fp == nil || !fp.selectionAudited || fp.ignoreContextValuePayload || !isContextCancelSite(site) {
		return fp, done
	}
	return withIgnoreContextValuePayloadDone(fp, done)
}

func contextCancelMethodFP(site ssa.CallInstruction, fp *freshParamAnalysis) *freshParamAnalysis {
	outFP, _ := contextCancelMethodFPDone(site, fp, nil)
	return outFP
}

func isAuditedStandardContextRecvType(ct types.Type) bool {
	if ct == nil {
		return false
	}
	base := ct
	if ptr, ok := types.Unalias(ct).(*types.Pointer); ok {
		base = ptr.Elem()
	}
	named, ok := types.Unalias(base).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "context" {
		return false
	}
	switch named.Obj().Name() {
	case "cancelCtx", "withoutCancelCtx", "valueCtx", "backgroundCtx", "todoCtx", "emptyCtx":
		return true
	default:
		return false
	}
}

func isAuditedStandardFmtErrorRecvType(ct types.Type) bool {
	if ct == nil {
		return false
	}
	base := ct
	if ptr, ok := types.Unalias(ct).(*types.Pointer); ok {
		base = ptr.Elem()
	}
	named, ok := types.Unalias(base).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "fmt" {
		return false
	}
	switch named.Obj().Name() {
	case "wrapError", "wrapErrors":
		return true
	default:
		return false
	}
}
