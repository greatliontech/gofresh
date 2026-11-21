package observability

import (
	"context"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/propharness"
)

// freshParamAnalysis carries fresh-path capabilities across static
// function boundaries inside one subject's attributed reachability
// (REQ-inputs-fresh-mutation's boundary extension): a parameter holds a
// fresh capability when every attributed call site of its function
// passes a fresh value at that position, and its uses inside the
// function stay within the recognized operation graph under the same
// consumer discipline. Dynamic dispatch, variadic and closure callees,
// goroutine call sites, cyclic blocks, and recursion all refuse —
// fail-closed, exactly like the intraprocedural grammar. The analysis
// is derived from the per-subject reachability alone, so batch
// equivalence holds by construction
// (REQ-closure-observability-batch-equivalence), and the fixpoint
// evaluates eagerly in a deterministic order so cycle refusals never
// depend on map iteration.
// ssaProgramIndex holds the program-wide SSA reference summary, user package
// set, and audit configuration shared across all subject queries on one SSA
// program.
type ssaProgramIndex struct {
	prog                   *program
	summary                *callerReferenceSummary
	userPaths              map[string]bool
	structFieldStores      map[structFieldKey][]ssa.Value
	structWholeStores      map[*types.Named][]ssa.Value
	structPoisoned         map[structFieldKey]bool
	structReferencedByType map[*types.Named]bool
	programSites           map[*ssa.Function][]ssa.CallInstruction
	programValueRef        map[*ssa.Function]bool
	programFunctions       map[*ssa.Function]bool
	closures               map[*ssa.Function][]*ssa.MakeClosure
	unmutatedSentinel      map[*ssa.Global]bool
	// verifiedHarnesses maps verified property-harness dependency paths in
	// prog to their discovered protocol surface; empty disables harness arms.
	verifiedHarnesses map[string]*propharness.VerifiedPackage
	// selectionAudited is the analysis' toolchain-source audit verdict
	// (the Hasher's, resolved at construction).
	selectionAudited bool
	pureDelegates    map[string]bool
	// isStd reports whether a function belongs to a standard-library
	// package according to the program's listed metadata (falling back
	// to the import-path heuristic when nil).
	isStd func(*ssa.Function) bool
}

type closedMemoEntry struct {
	closed      bool
	usedSubject bool
}

type typesMemoEntry struct {
	types       []types.Type
	ok          bool
	usedSubject bool
}

type funcsMemoEntry struct {
	funcs       []*ssa.Function
	ok          bool
	usedSubject bool
}

type invokeMemoEntry struct {
	targets     map[*ssa.Function]bool
	ok          bool
	usedSubject bool
}

// dynamicMemoTables holds the dynamic-value, concrete-type, function-target,
// and invoke-target memo maps for one (program-scope, context-payload-mode)
// slice, recording per-entry subject-state dependency so subject-local memos
// never launder subject-dependent outcomes into program-wide memos.
type dynamicMemoTables struct {
	closedDone  map[ssa.Value]closedMemoEntry
	carrierDone map[carrierMemoKey]closedMemoEntry
	typesMemo   map[ssa.Value]typesMemoEntry
	funcsMemo   map[ssa.Value]funcsMemoEntry
	invokeMemo  map[ssa.CallInstruction]invokeMemoEntry
}

func newDynamicMemoTables() dynamicMemoTables {
	return dynamicMemoTables{
		closedDone:  make(map[ssa.Value]closedMemoEntry),
		carrierDone: make(map[carrierMemoKey]closedMemoEntry),
		typesMemo:   make(map[ssa.Value]typesMemoEntry),
		funcsMemo:   make(map[ssa.Value]funcsMemoEntry),
		invokeMemo:  make(map[ssa.CallInstruction]invokeMemoEntry),
	}
}

func newDynamicMemoQuad() *[4]dynamicMemoTables {
	return &[4]dynamicMemoTables{
		newDynamicMemoTables(),
		newDynamicMemoTables(),
		newDynamicMemoTables(),
		newDynamicMemoTables(),
	}
}

// subjectQuery holds the per-subject reachability, caller enumeration, and
// per-subject memo tables.
type subjectQuery struct {
	traceCtx         context.Context
	functions     map[*ssa.Function]bool
	flowFunctions map[*ssa.Function]bool
	rtaFunctions  map[*ssa.Function]bool
	// callers lists the attributed static call sites per callee; only
	// sites inside reachable functions participate.
	callers map[*ssa.Function][]ssa.CallInstruction
	// dynamic marks functions any attributed dynamic site targets: a
	// capability cannot be proven through dispatch the analysis cannot
	// enumerate call sites for.
	dynamic map[*ssa.Function]bool
	// enumRoot/enumSites carry a signature-open subject root's
	// whole-view caller enumeration (REQ-closure-analysis): the
	// closed-value walks cross the root's own parameters to these
	// sites. They never join callers — the fresh-path capability
	// fixpoint stays subject-internal.
	enumRoot                  *ssa.Function
	enumSites                 []ssa.CallInstruction
	enumFieldStores           map[int][]ssa.Value
	enumOnly                  bool
	enumRecvNamed             *types.Named
	baseCarrierNamed          *types.Named
	enumStructVisiting        map[*types.Named]bool
	ignoreContextValuePayload bool
	subjectRoot               *ssa.Function

	memoTables *[4]dynamicMemoTables

	argFresh map[freshParamKey]bool
	usesOK   map[freshParamKey]bool
	state    *freshParamState
}

type freshParamState struct {
	callersReady bool
	resolved     bool
}

// calleeFrame tracks active call-site parameter bindings and recursion guards
// during interprocedural value walks.
type calleeFrame struct {
	callBindings   map[*ssa.Parameter]ssa.Value
	calleeSeen     map[*ssa.Function]bool
	calleeDepth    map[*ssa.Function]int
	invokeSeen     map[ssa.CallInstruction]bool
	invokeDepth    map[ssa.CallInstruction]int
	inFieldStore   bool
	inProgramSites bool
	baseDepth      int
}

// walkFrame holds ephemeral per-traversal Tarjan SCC and cycle-detection state
// for walkDynamicValue.
type walkFrame struct {
	stackDepth      map[carrierMemoKey]int
	lowlink         *int
	hasLeaf         *bool
	usedSubject     *bool
	rootDone        map[ssa.Value]bool
	rootLowlink     map[ssa.Value]int
	rootHasLeaf     map[ssa.Value]bool
	rootUsedSubject map[ssa.Value]bool
	carrierRootDone map[carrierMemoKey]carrierRootMemoEntry
	rootSeen        map[ssa.Value]bool
}

type freshParamAnalysis struct {
	ssaProgramIndex
	subjectQuery
	calleeFrame
	walkFrame
}

func (fp *freshParamAnalysis) isAuditedStandardOrDelegate(pkgPath string) bool {
	if fp == nil || !fp.selectionAudited {
		return false
	}
	return isSourceOnlyStandardPackage(true, pkgPath) || fp.pureDelegates[pkgPath]
}

func (fp *freshParamAnalysis) isNonInternalPureDelegate(pkgPath string) bool {
	if fp == nil || !fp.selectionAudited || pkgPath == "" {
		return false
	}
	return !isSourceOnlyStandardPackage(true, pkgPath) && !isInternalStdPackagePath(pkgPath) && fp.pureDelegates[pkgPath]
}

func unaliasedDerefNamedPkgPath(t types.Type) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if named, ok := t.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
		return named.Obj().Pkg().Path()
	}
	return ""
}

func isAuditedStdAliasCarrier(audited bool, t types.Type) bool {
	if !audited || t == nil {
		return false
	}
	derefed := false
	for t != nil {
		if alias, ok := t.(*types.Alias); ok {
			obj := alias.Obj()
			if obj != nil && obj.Exported() && obj.Pkg() != nil && isSourceOnlyStandardPackage(true, obj.Pkg().Path()) {
				return true
			}
			t = alias.Rhs()
			continue
		}
		if ptr, ok := t.(*types.Pointer); ok && !derefed {
			derefed = true
			t = ptr.Elem()
			continue
		}
		return false
	}
	return false
}

func isAuditedStdAliasValue(audited bool, v ssa.Value) bool {
	if !audited || v == nil {
		return false
	}
	if isAuditedStdAliasCarrier(true, v.Type()) {
		return true
	}
	if unop, ok := v.(*ssa.UnOp); ok && unop.Op == token.MUL && unop.X != nil {
		return isAuditedStdAliasCarrier(true, unop.X.Type())
	}
	return false
}

func (fp *freshParamAnalysis) userPkgPaths() map[string]bool {
	if fp == nil {
		return nil
	}
	if fp.userPaths != nil {
		return fp.userPaths
	}
	if fp.summary != nil {
		return fp.summary.userPaths
	}
	return nil
}

func (fp *freshParamAnalysis) isStdFunc(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if fp != nil && fp.isStd != nil {
		return fp.isStd(fn)
	}
	return isStdPkgPath(fp.userPkgPaths(), funcPkgPath(fn))
}

type freshParamKey struct {
	fn  *ssa.Function
	idx int
}

func (s *callerReferenceSummary) ssaIndex(selectionAudited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, pureDelegates, userPaths map[string]bool, isStd func(*ssa.Function) bool) ssaProgramIndex {
	if s != nil {
		if pureDelegates == nil {
			pureDelegates = s.pureDelegates
		}
		if userPaths == nil {
			userPaths = s.userPaths
		}
	}
	if isStd == nil && userPaths != nil {
		isStd = func(fn *ssa.Function) bool {
			return isStdPkgPath(userPaths, funcPkgPath(fn))
		}
	}
	idx := ssaProgramIndex{
		verifiedHarnesses: verifiedHarnesses,
		selectionAudited:  selectionAudited,
		pureDelegates:     pureDelegates,
		userPaths:         userPaths,
		summary:           s,
		isStd:             isStd,
	}
	if s != nil {
		idx.prog = s.prog
		idx.structFieldStores = s.structFieldStores
		idx.structWholeStores = s.structWholeStores
		idx.structPoisoned = s.structPoisoned
		idx.structReferencedByType = s.structReferencedByType
		idx.programSites = s.sites
		idx.programValueRef = s.valueRef
		idx.programFunctions = s.allFunctions
		idx.closures = s.closures
	}
	return idx
}

func newBitOnlyFreshParamAnalysis(includeHarnesses, selectionAudited bool, pureDelegates map[string]bool, userPaths map[string]bool, summary *callerReferenceSummary, isStd func(*ssa.Function) bool) *freshParamAnalysis {
	var verified map[string]*propharness.VerifiedPackage
	if includeHarnesses && summary != nil {
		verified = summary.verifiedHarnesses
		if verified == nil && summary.prog != nil {
			verified = verifiedHarnessesProg(selectionAudited, summary.prog)
		}
	}
	idx := summary.ssaIndex(selectionAudited, verified, pureDelegates, userPaths, isStd)
	// Parameter crossing stays refused on bit-only analyses
	// (REQ-closure-observability-property-harness).
	idx.programSites = nil
	idx.programValueRef = nil
	idx.programFunctions = nil
	idx.closures = nil
	if isStd == nil {
		idx.isStd = nil
	}
	fp := &freshParamAnalysis{ssaProgramIndex: idx}
	fp.resetDynamicMemos()
	return fp
}

func (fp *freshParamAnalysis) resetDynamicMemos() {
	fp.memoTables = newDynamicMemoQuad()
}

func (fp *freshParamAnalysis) markSubjectUsed() {
	if fp != nil && fp.usedSubject != nil {
		*fp.usedSubject = true
	}
}

func (fp *freshParamAnalysis) isSubjectRoot(fn *ssa.Function) bool {
	return fp != nil && fn != nil && (fn == fp.enumRoot || fn == fp.subjectRoot)
}

func (fp *freshParamAnalysis) progScopeIndex() int {
	if fp != nil && (fp.inProgramSites || fp.inFieldStore) {
		return 1
	}
	return 0
}

func (fp *freshParamAnalysis) memoModeIndex() int {
	if fp != nil && fp.ignoreContextValuePayload {
		return 1
	}
	return 0
}

func (fp *freshParamAnalysis) memoScopeIndex() int {
	return (fp.progScopeIndex() << 1) | fp.memoModeIndex()
}

func (fp *freshParamAnalysis) carrierKey(v ssa.Value) carrierMemoKey {
	if fp == nil {
		return carrierMemoKey{value: v}
	}
	return carrierMemoKey{
		value: v,
		named: fp.baseCarrierNamed,
		scope: uint8(fp.memoScopeIndex()),
	}
}

func (fp *freshParamAnalysis) isolateRootScope() {
	if fp == nil {
		return
	}
	if fp.rootDone != nil {
		fp.rootDone = map[ssa.Value]bool{}
		fp.rootLowlink = map[ssa.Value]int{}
		fp.rootHasLeaf = map[ssa.Value]bool{}
		fp.rootUsedSubject = map[ssa.Value]bool{}
		fp.carrierRootDone = map[carrierMemoKey]carrierRootMemoEntry{}
	}
	fp.rootSeen = nil
}

func (fp *freshParamAnalysis) subjMemo() *dynamicMemoTables {
	if fp == nil || fp.memoTables == nil {
		return nil
	}
	return &fp.memoTables[fp.memoScopeIndex()]
}

func (fp *freshParamAnalysis) progMemo() *dynamicMemoTables {
	if fp == nil || fp.summary == nil || fp.programSites == nil {
		return nil
	}
	if fp.enumOnly {
		return &fp.summary.enumMemos[fp.memoScopeIndex()]
	}
	return &fp.summary.progMemos[fp.memoScopeIndex()]
}

func (fp *freshParamAnalysis) enumSeedsTable() map[ssa.Value]dynamicSeedEntry {
	if fp == nil || fp.summary == nil || fp.programSites == nil || !fp.enumOnly || fp.ignoreContextValuePayload {
		return nil
	}
	return fp.summary.enumSeedsMemo[fp.progScopeIndex()]
}

func (fp *freshParamAnalysis) enumStructTable() map[*types.Named]bool {
	if fp == nil || fp.summary == nil || fp.programSites == nil || fp.ignoreContextValuePayload {
		return nil
	}
	if fp.enumOnly {
		return fp.summary.enumStructClosed[1]
	}
	return fp.summary.enumStructClosed[0]
}

func (fp *freshParamAnalysis) inCycleScope() bool {
	return fp != nil && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly)
}

func (fp *freshParamAnalysis) canWriteSubjMemo(outsideCallee bool) bool {
	return outsideCallee && fp != nil && len(fp.calleeSeen) == 0 && len(fp.invokeSeen) == 0 && len(fp.callBindings) == 0
}

// canReadProgMemo reports whether dynamic-walk queries outside active callee
// bindings may consult whole-program or enum-only summary memos. Summary
// memos partition (inProgramSites || inFieldStore, ignoreContextValuePayload)
// into 4 disjoint slices on both progMemos and enumMemos; bit-only analyses
// (programSites == nil) never consult summary memos, and enumRecvNamed == nil
// guards against optimistic receiver-method exemptions.
func (fp *freshParamAnalysis) canReadProgMemo(outsideCallee bool) bool {
	return outsideCallee && fp != nil && fp.summary != nil && fp.programSites != nil && fp.enumRecvNamed == nil
}

// canReadNegativeProgMemo guards negative (!ok / !closed) reads from summary
// memos against optimistic cycle/carrier exemptions that could close a value a
// general walk rejected.
func (fp *freshParamAnalysis) canReadNegativeProgMemo() bool {
	return fp != nil && len(fp.enumStructVisiting) == 0 && fp.baseCarrierNamed == nil
}

// canWriteProgMemo admits summary-memo writes only when no per-subject state,
// struct-cycle visiting set, active callee/invoke stack, or call binding
// participated in the evaluation.
func (fp *freshParamAnalysis) canWriteProgMemo(outsideCallee bool, usedSubject bool) bool {
	return fp.canReadProgMemo(outsideCallee) && !usedSubject && len(fp.enumStructVisiting) == 0 && fp.canWriteSubjMemo(outsideCallee)
}

func newEnumFreshParamAnalysis(audited bool, pureDelegates map[string]bool, userPaths map[string]bool, root *ssa.Function, sites []ssa.CallInstruction, summary *callerReferenceSummary) *freshParamAnalysis {
	fp := &freshParamAnalysis{
		ssaProgramIndex: summary.ssaIndex(audited, nil, pureDelegates, userPaths, nil),
		subjectQuery: subjectQuery{
			enumOnly:    true,
			enumRoot:    root,
			subjectRoot: root,
			enumSites:   sites,
		},
	}
	fp.resetDynamicMemos()
	return fp
}

func (fp *freshParamAnalysis) withoutCallee(fn *ssa.Function) *freshParamAnalysis {
	if fp == nil || fn == nil || !fp.calleeSeen[fn] {
		return fp
	}
	copied := *fp
	calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen))
	for k, val := range fp.calleeSeen {
		if k != fn {
			calleeSeen[k] = val
		}
	}
	copied.calleeSeen = calleeSeen
	calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth))
	for k, val := range fp.calleeDepth {
		if k != fn {
			calleeDepth[k] = val
		}
	}
	copied.calleeDepth = calleeDepth
	bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings))
	for k, val := range fp.callBindings {
		if k.Parent() != fn {
			bindings[k] = val
		}
	}
	copied.callBindings = bindings
	return &copied
}

func (fp *freshParamAnalysis) withProgramSites(done map[ssa.Value]bool) (*freshParamAnalysis, map[ssa.Value]bool) {
	if fp == nil {
		return nil, done
	}
	wasProgScope := fp.inProgramSites || fp.inFieldStore
	outFP := fp
	if !fp.inProgramSites || fp.inFieldStore || len(fp.callBindings) > 0 {
		copied := *fp
		copied.inProgramSites = true
		copied.inFieldStore = false
		copied.callBindings = nil
		copied.calleeSeen = nil
		copied.calleeDepth = nil
		if !wasProgScope {
			copied.isolateRootScope()
		}
		outFP = &copied
	}
	outDone := done
	if !wasProgScope {
		if outFP.rootDone != nil && done != nil {
			outDone = outFP.rootDone
		} else if done != nil {
			outDone = map[ssa.Value]bool{}
		}
	} else if fp.baseCarrierNamed == nil && fp.rootDone != nil {
		outDone = fp.rootDone
	} else if fp.baseCarrierNamed != nil && done != nil {
		outDone = map[ssa.Value]bool{}
	}
	return outFP, outDone
}

func (fp *freshParamAnalysis) newStructVisitingScopeFP(visiting map[*types.Named]bool) *freshParamAnalysis {
	sub := *fp
	sub.baseCarrierNamed = nil
	sub.enumStructVisiting = visiting
	sub.resetDynamicMemos()
	return &sub
}

func (fp *freshParamAnalysis) newStructStoreWalkFP(inProgramSites, inFieldStore bool, visiting map[*types.Named]bool, lowlink *int, hasLeaf, usedSubject *bool) *freshParamAnalysis {
	sub := *fp
	sub.calleeFrame = calleeFrame{
		inProgramSites: inProgramSites,
		inFieldStore:   inFieldStore,
	}
	sub.baseCarrierNamed = nil
	sub.enumStructVisiting = visiting
	if sub.memoTables == nil {
		sub.resetDynamicMemos()
	}
	sub.walkFrame = walkFrame{
		stackDepth:      map[carrierMemoKey]int{},
		lowlink:         lowlink,
		hasLeaf:         hasLeaf,
		usedSubject:     usedSubject,
		rootDone:        map[ssa.Value]bool{},
		rootLowlink:     map[ssa.Value]int{},
		rootHasLeaf:     map[ssa.Value]bool{},
		rootUsedSubject: map[ssa.Value]bool{},
		carrierRootDone: map[carrierMemoKey]carrierRootMemoEntry{},
	}
	return &sub
}

func newFreshParamAnalysis(audited bool, pureDelegates map[string]bool, reach attributedReachability, isStd func(*ssa.Function) bool) *freshParamAnalysis {
	idx := reach.summary.ssaIndex(audited, reach.verifiedHarnesses, pureDelegates, reach.userPaths, isStd)
	if isStd == nil {
		idx.isStd = nil
	}
	if reach.prog != nil {
		idx.prog = reach.prog
	}
	if reach.structFieldStores != nil {
		idx.structFieldStores = reach.structFieldStores
	}
	if reach.structWholeStores != nil {
		idx.structWholeStores = reach.structWholeStores
	}
	if reach.structPoisoned != nil {
		idx.structPoisoned = reach.structPoisoned
	}
	if reach.structReferencedByType != nil {
		idx.structReferencedByType = reach.structReferencedByType
	}
	if reach.programSites != nil {
		idx.programSites = reach.programSites
	}
	if reach.programValueRef != nil {
		idx.programValueRef = reach.programValueRef
	}
	if reach.programFunctions != nil {
		idx.programFunctions = reach.programFunctions
	}
	fp := &freshParamAnalysis{
		ssaProgramIndex: idx,
		subjectQuery: subjectQuery{
			functions:    reach.functions,
			rtaFunctions: reach.rtaFunctions,
			callers:      map[*ssa.Function][]ssa.CallInstruction{},
			dynamic:      map[*ssa.Function]bool{},
			subjectRoot:  reach.subjectRoot,
			argFresh:     map[freshParamKey]bool{},
			usesOK:       map[freshParamKey]bool{},
			state:        &freshParamState{},
		},
	}
	fp.resetDynamicMemos()
	if len(reach.enumeratedRootSites) > 0 || len(reach.enumeratedFieldStores) > 0 || reach.enumeratedRoot {
		fp.enumRoot = reach.subjectRoot
		fp.enumSites = reach.enumeratedRootSites
		fp.enumFieldStores = reach.enumeratedFieldStores
		if fp.enumRoot != nil && fp.enumRoot.Signature != nil && fp.enumRoot.Signature.Recv() != nil {
			fp.enumRecvNamed = derefNamedStruct(fp.userPkgPaths(), fp.enumRoot.Signature.Recv().Type())
		}
	}
	// The dynamic-carrier view is built over the enumeration's own
	// targets, before any narrowing: the narrowing consults this view
	// (the parameter crossing), so it must not depend on it — the
	// conservative direction, and the one that keeps the two acyclic.
	for _, targets := range reach.dynamicTargets {
		for target := range targets {
			fp.dynamic[target] = true
		}
	}
	return fp
}

func (fp *freshParamAnalysis) localClosureSitesClosed(fn *ssa.Function) bool {
	if fp == nil || !fp.selectionAudited || fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.Signature.Variadic() {
		return false
	}
	if fp.summary == nil || !fp.summary.strictLocalFunc[fn] || fp.programSites == nil || fp.programValueRef[fn] || len(fp.programSites[fn]) == 0 {
		return false
	}
	if len(fn.FreeVars) > 0 && len(fp.closures[fn]) == 0 {
		return false
	}
	return true
}

func (fp *freshParamAnalysis) appendLocalClosureSites(fn *ssa.Function, sites []ssa.CallInstruction) []ssa.CallInstruction {
	if !fp.localClosureSitesClosed(fn) {
		return sites
	}
	for _, site := range fp.programSites[fn] {
		if site == nil || site.Common() == nil || site.Common().IsInvoke() || !fp.functions[site.Parent()] {
			continue
		}
		if !slices.Contains(sites, site) {
			sites = append(sites, site)
		}
	}
	return sites
}

func (fp *freshParamAnalysis) callersOf(fn *ssa.Function) []ssa.CallInstruction {
	if fp == nil || fn == nil || !fp.functions[fn] {
		return nil
	}
	if sites, ok := fp.callers[fn]; ok || (fp.state != nil && fp.state.callersReady) {
		return sites
	}
	if fp.summary != nil && len(fp.summary.allStaticSites) > 0 {
		var sites []ssa.CallInstruction
		for _, site := range fp.summary.allStaticSites[fn] {
			if fp.functions[site.Parent()] {
				sites = append(sites, site)
			}
		}
		sites = fp.appendLocalClosureSites(fn, sites)
		if fp.callers != nil {
			fp.callers[fn] = sites
		}
		return sites
	}
	fp.ensureAllCallers()
	return fp.callers[fn]
}

func (fp *freshParamAnalysis) ensureAllCallers() {
	if fp == nil || fp.state == nil || fp.state.callersReady {
		return
	}
	fp.state.callersReady = true
	if fp.summary != nil && len(fp.summary.allStaticSites) > 0 {
		for callee := range fp.functions {
			if _, ok := fp.callers[callee]; ok {
				continue
			}
			var sites []ssa.CallInstruction
			for _, site := range fp.summary.allStaticSites[callee] {
				if fp.functions[site.Parent()] {
					sites = append(sites, site)
				}
			}
			sites = fp.appendLocalClosureSites(callee, sites)
			if len(sites) > 0 {
				fp.callers[callee] = sites
			}
		}
		return
	}
	for fn := range fp.functions {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil && fp.functions[callee] {
					fp.callers[callee] = append(fp.callers[callee], site)
				}
			}
		}
	}
	for callee := range fp.functions {
		if sites := fp.appendLocalClosureSites(callee, fp.callers[callee]); len(sites) > 0 {
			fp.callers[callee] = sites
		}
	}
}

func (fp *freshParamAnalysis) ensureResolved() {
	if fp == nil || fp.state == nil || fp.state.resolved {
		return
	}
	fp.state.resolved = true
	fp.ensureAllCallers()
	fp.resolve()
}

// resolve evaluates both fixpoint directions for every candidate
// parameter in a deterministic order, so recursion's fail-closed
// refusal is identical run to run regardless of map iteration.
func (fp *freshParamAnalysis) resolve() {
	type sortKey struct {
		key    freshParamKey
		fnName string
	}
	var keys []sortKey
	for fn, sites := range fp.callers {
		if len(sites) == 0 || !fp.paramCrossingEligible(fn) || ((fp.dynamic[fn] || len(fn.FreeVars) != 0) && !fp.localClosureSitesClosed(fn)) || fn.Signature.Variadic() {
			continue
		}
		var fnName string
		for i := range fn.Params {
			if !fp.paramEligible(fn, i) {
				continue
			}
			if fnName == "" {
				fnName = fn.String()
			}
			keys = append(keys, sortKey{key: freshParamKey{fn: fn, idx: i}, fnName: fnName})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].key.fn != keys[j].key.fn {
			return keys[i].fnName < keys[j].fnName
		}
		return keys[i].key.idx < keys[j].key.idx
	})
	inArg := map[freshParamKey]bool{}
	for _, entry := range keys {
		fp.paramArgFreshMemo(entry.key, inArg)
	}
	inUses := map[freshParamKey]bool{}
	for _, entry := range keys {
		fp.paramUsesObservableMemo(entry.key, inUses)
	}
}

// paramCrossingEligible is the one caller-boundary refusal set every
// parameter crossing shares: the function must be attributed, not
// dynamically targeted (unless closed via non-escaping programSites),
// capture-disciplined, and non-variadic.
func (fp *freshParamAnalysis) paramCrossingEligible(fn *ssa.Function) bool {
	if fp == nil || fn == nil {
		return false
	}
	if fn == fp.enumRoot {
		fp.markSubjectUsed()
	}
	if len(fn.FreeVars) != 0 {
		if !fp.selectionAudited || fp.programSites == nil || fp.programValueRef[fn] || len(fp.closures[fn]) == 0 {
			return false
		}
	}
	dynRefusalCond := fn != fp.enumRoot && (!fp.selectionAudited || fp.programSites == nil || fp.programValueRef[fn] || (fn.Signature == nil || (fn.Signature.Recv() == nil && len(fp.programSites[fn]) == 0)))
	if dynRefusalCond {
		if fp.dynamic[fn] {
			fp.markSubjectUsed()
			return false
		}
		if !fp.selectionAudited || fn.Signature == nil || (!fp.inProgramSites && !fp.inFieldStore && !fp.enumOnly) {
			fp.markSubjectUsed()
		}
	}
	if fn.Signature != nil && fn.Signature.Variadic() && fn != fp.enumRoot && !fp.selectionAudited {
		fp.markSubjectUsed()
		if !fp.inFieldStore && !fp.inProgramSites {
			return false
		}
	}
	if fp.programFunctions[fn] {
		return true
	}
	if !fp.enumOnly {
		fp.markSubjectUsed()
	}
	return fp.functions[fn] || fn == fp.enumRoot
}

// paramEligible refuses every shape the boundary extension cannot
// carry: the shared crossing refusals plus variadic, out-of-range, and
// non-string parameters.
func (fp *freshParamAnalysis) paramEligible(fn *ssa.Function, idx int) bool {
	if !fp.paramCrossingEligible(fn) || ((fp.dynamic[fn] || len(fn.FreeVars) != 0) && !fp.localClosureSitesClosed(fn)) || fn.Signature.Variadic() {
		return false
	}
	if idx < 0 || idx >= len(fn.Params) {
		return false
	}
	basic, ok := fn.Params[idx].Type().Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func (fp *freshParamAnalysis) paramArgFreshMemo(key freshParamKey, inProgress map[freshParamKey]bool) bool {
	fp.ensureResolved()
	if v, done := fp.argFresh[key]; done {
		return v
	}
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	if inProgress[key] {
		// Recursion refuses fail-closed; the eager sorted resolve makes
		// the refusal deterministic.
		fp.argFresh[key] = false
		return false
	}
	if !fp.paramEligible(key.fn, key.idx) {
		fp.argFresh[key] = false
		return false
	}
	sites := fp.callersOf(key.fn)
	if len(sites) == 0 {
		fp.argFresh[key] = false
		return false
	}
	inProgress[key] = true
	fresh := true
	for _, site := range sites {
		// Subject-level this guard is redundant defense-in-depth: every
		// caller site is also a referrer in some origin's or parameter's
		// uses walk, whose consumer refuses go-sites and cyclic blocks
		// on its own. It stays because argFresh must hold independently
		// of which walk reached it.
		if _, concurrent := site.(*ssa.Go); concurrent || blockInCycle(site.Block()) {
			fresh = false
			break
		}
		args := site.Common().Args
		if key.idx >= len(args) || !freshPathValue(args[key.idx], make(map[ssa.Value]bool), fp, inProgress) {
			fresh = false
			break
		}
	}
	delete(inProgress, key)
	fp.argFresh[key] = fresh
	return fresh
}

func (fp *freshParamAnalysis) paramUsesObservableMemo(key freshParamKey, inProgress map[freshParamKey]bool) bool {
	fp.ensureResolved()
	if v, done := fp.usesOK[key]; done {
		return v
	}
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	if inProgress[key] {
		fp.usesOK[key] = false
		return false
	}
	if !fp.paramEligible(key.fn, key.idx) {
		fp.usesOK[key] = false
		return false
	}
	inProgress[key] = true
	ok := observableFreshPathUses(key.fn.Params[key.idx], make(map[ssa.Value]bool), fp, inProgress)
	delete(inProgress, key)
	fp.usesOK[key] = ok
	return ok
}

// boundaryCrossingObservable admits passing a fresh capability into a
// static non-standard callee or a non-escaping closed local function/closure:
// every attributed call site of the callee must pass fresh at each position
// the value occupies, and the parameter's uses inside the callee must stay
// within the graph.
func (fp *freshParamAnalysis) boundaryCrossingObservable(site ssa.CallInstruction, pathValue ssa.Value, inProgress map[freshParamKey]bool) bool {
	if fp == nil || site == nil || site.Common() == nil || site.Common().IsInvoke() {
		return false
	}
	var callees []*ssa.Function
	if callee := site.Common().StaticCallee(); callee != nil {
		if fp.isStdFunc(callee) {
			return false
		}
		callees = []*ssa.Function{callee}
	} else {
		if !fp.selectionAudited || site.Common().Value == pathValue || !subjectClosedDynamicValue(site.Common().Value, make(map[ssa.Value]bool), fp) {
			return false
		}
		targets, ok := closedDynamicTargets(site.Common().Value, fp)
		if !ok || len(targets) == 0 {
			return false
		}
		for target := range targets {
			if target == nil || fp.isStdFunc(target) || !fp.localClosureSitesClosed(target) {
				return false
			}
			callees = append(callees, target)
		}
	}
	found := false
	for i, arg := range site.Common().Args {
		if arg != pathValue {
			continue
		}
		found = true
		for _, callee := range callees {
			key := freshParamKey{fn: callee, idx: i}
			// The two fixpoint directions keep separate in-progress
			// namespaces: inProgress here is the uses direction's, and the
			// arg direction starts its own chain - a key mid-evaluation for
			// uses is not an arg-direction cycle.
			if !fp.paramArgFreshMemo(key, map[freshParamKey]bool{}) || !fp.paramUsesObservableMemo(key, inProgress) {
				return false
			}
		}
	}
	return found
}
