package closure

import (
	"fmt"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/trace"
)

func subjectRunsThroughHarness(prog *program, fn *ssa.Function) bool {
	if fn == nil || fn.Pos() == token.NoPos {
		return true
	}
	return strings.HasSuffix(prog.Prog.Fset.Position(fn.Pos()).Filename, "_test.go")
}

// Subject identifies a function or method whose source closure is requested.
type Subject struct {
	Package string
	Symbol  string
}

// Observability is the complete subject-tier disposition for runtime-input
// observation. Observable is true only when every reachable effect is admitted.
type Observability struct {
	Observable                bool
	Reason                    string
	OutcomeMethod             string
	EffectFree                bool
	RequiresSingleSubject     bool
	SharedProcessUnsafeReason string
	TrackedChdirSafe          bool
}

// ImmutableEnvironmentOutcomes identifies the derivation for an empty effect
// set or admitted environment lookups under an unchanged complete inherited
// environment. Its implementation semantics are audited for Linux only.
const ImmutableEnvironmentOutcomes = outcome.Method

const maxAttributedSubjects = subjectMaskBits

// ComputeObservabilityBatch computes caller-selected per-subject observation
// proofs, sharing the loaded program, attributed reachability masks, and
// package effect scans across each package's subjects. Every disposition
// equals independent per-subject analysis
// (REQ-closure-observability-batch-equivalence).
func (h *Hasher) ComputeObservabilityBatch(subjects []Subject) (map[Subject]Observability, error) {
	// One call observes one tree generation; a later call re-observes.
	h.resetCallScope()
	defer func() {
		h.contents = nil
		h.maximalParsedFiles = nil
		h.maximalTestingUnfiltered = nil
	}()
	results, err := runSubjectBatch(h, h.ctx, subjects, "observability proof", h.groupMemo, h.observabilityGroup)
	if err != nil {
		return nil, err
	}
	if axis := h.SelectionAttribution(); axis != "" {
		for subject, proof := range results {
			proof.Reason = AttributeSelection(proof.Reason, axis)
			proof.SharedProcessUnsafeReason = AttributeSelection(proof.SharedProcessUnsafeReason, axis)
			results[subject] = proof
		}
	}
	if trace.AnyEnabled() {
		for _, subject := range subjects {
			proof, ok := results[subject]
			if !ok {
				continue
			}
			target := subject.Package + "." + subject.Symbol
			if trace.Enabled(h.ctx, trace.DomainClosure, target) {
				trace.Emit(h.ctx, trace.DomainClosure, "observability", target,
					trace.Bool("observable", proof.Observable),
					trace.Bool("effect_free", proof.EffectFree),
					trace.String("outcome_method", proof.OutcomeMethod),
					trace.String("reason", proof.Reason),
				)
			}
		}
	}
	return results, nil
}

func (h *Hasher) observabilityGroup(group *packageBatch, bp *batchPreparer, results map[Subject]Observability) error {
	closureHash := group.closureHash
	prog, err := h.loadCachedFrom(h.ctx, group.path, bp)
	if err != nil {
		return err
	}
	defer h.releaseProgram(group.path)
	memoScope := h.scope.Proofs()
	memoArmed := memoScope != "" && closureHash != ""
	rootedScope := h.scope.Rooted()
	rootedMemoArmed := rootedScope != "" && closureHash != ""
	unrooted := map[string]Observability{}
	unrootedRooted := map[string]RootedFunctions{}
	rooted := group.subjects[:0:0]
	for _, subject := range group.subjects {
		if prog.Roots[subject.Symbol] == nil {
			reason := fmt.Sprintf("observation analysis unavailable: subject %s not found in %s", subject.Symbol, group.path)
			if prog.Ambiguous[subject.Symbol] {
				reason = fmt.Sprintf("observation analysis unavailable: subject name %s is ambiguous in %s (declared by both the package and its external test package)", subject.Symbol, group.path)
			}
			proof := Observability{Reason: reason}
			results[subject] = proof
			unrooted[subject.Symbol] = proof
			unrootedRooted[subject.Symbol] = RootedFunctions{}
			continue
		}
		rooted = append(rooted, subject)
	}
	group.subjects = rooted
	stampUnrooted := func(base *tier2Base) {
		if len(unrooted) == 0 || !base.binaryTrackedChdirSafe() {
			return
		}
		for sym, proof := range unrooted {
			proof.TrackedChdirSafe = true
			unrooted[sym] = proof
		}
		for subject, proof := range results {
			if subject.Package == group.path && unrooted[subject.Symbol].Reason != "" {
				proof.TrackedChdirSafe = true
				results[subject] = proof
			}
		}
	}
	metas, err := h.list(group.path)
	if err != nil {
		if h.ctx != nil {
			if ctxErr := h.ctx.Err(); ctxErr != nil {
				return fmt.Errorf("closure: analysis cancelled: %w", ctxErr)
			}
		}
		return err
	}
	base := newTier2Base(h, prog, metas)
	stampUnrooted(base)
	if h.ctx != nil {
		if err := h.ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
	}
	if memoArmed && len(unrooted) > 0 {
		storeMemo(memoScope, closureHash, unrooted)
		h.persisted.proofs++
	}
	if rootedMemoArmed && len(unrootedRooted) > 0 {
		storeRootedMemo(rootedScope, closureHash, unrootedRooted)
	}
	if len(group.subjects) == 0 {
		return nil
	}
	slicesCount := (len(group.subjects) + maxAttributedSubjects - 1) / maxAttributedSubjects
	for start := 0; start < len(group.subjects); start += maxAttributedSubjects {
		if err := h.ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		h.emitUnit("prove", group.path, start/maxAttributedSubjects+1, slicesCount)
		end := min(start+maxAttributedSubjects, len(group.subjects))
		requestedBatch := group.subjects[start:end]
		batch := requestedBatch
		var reachable []attributedReachability
		if (memoArmed || rootedMemoArmed) && start == 0 && len(requestedBatch) < maxAttributedSubjects && len(h.packageMates[group.path]) > 0 {
			seenSym := make(map[string]bool, len(group.subjects)+len(unrooted))
			for _, s := range group.subjects {
				seenSym[s.Symbol] = true
			}
			for sym := range unrooted {
				seenSym[sym] = true
			}
			var mates []Subject
			for _, mate := range h.packageMates[group.path] {
				if len(requestedBatch)+len(mates) >= maxAttributedSubjects {
					break
				}
				if mate.Package != group.path || seenSym[mate.Symbol] || group.memoSymbols[mate.Symbol] {
					continue
				}
				if prog.Roots[mate.Symbol] == nil || prog.Ambiguous[mate.Symbol] {
					continue
				}
				seenSym[mate.Symbol] = true
				mates = append(mates, mate)
			}
			if len(mates) > 0 {
				combined := make([]Subject, 0, len(requestedBatch)+len(mates))
				combined = append(combined, requestedBatch...)
				combined = append(combined, mates...)
				if combReach, combErr := runAnalyzeAttributedBatch(h.ctx, h.SelectionAudited(), h.source.pureDelegates, prog, combined); combErr == nil {
					batch = combined
					reachable = combReach
				}
			}
		}
		if reachable == nil {
			var err error
			reachable, err = attributedReachableSets(h.ctx, h.SelectionAudited(), h.source.pureDelegates, prog, requestedBatch)
			if err != nil {
				return err
			}
		}
		sliceProofs := make(map[string]Observability, len(batch))
		sliceRooted := make(map[string]RootedFunctions, len(batch))
		for i, subject := range batch {
			if err := h.ctx.Err(); err != nil {
				return fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			isRequested := i < len(requestedBatch)
			sliceRooted[subject.Symbol] = rootedFunctionsFromReachability(reachable[i])
			if reachable[i].unavailable != "" {
				if !isRequested {
					delete(sliceRooted, subject.Symbol)
					continue
				}
				full := reachable[i].unavailable
				h.emitDiagnostic("analysis-unavailable", subject.Package, subject.Symbol+": "+full)
				result := Observability{Observable: false, Reason: unsupportedShapeReason, TrackedChdirSafe: base.binaryTrackedChdirSafe()}
				results[subject] = result
				sliceProofs[subject.Symbol] = result
				continue
			}
			result, err := h.observabilityFromReachability(base, subject.Package, reachable[i])
			if err != nil {
				if !isRequested && h.ctx.Err() == nil {
					delete(sliceRooted, subject.Symbol)
					continue
				}
				return err
			}
			if isRequested {
				results[subject] = result
			}
			sliceProofs[subject.Symbol] = result
		}
		if err := h.ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		if memoArmed {
			storeMemo(memoScope, closureHash, sliceProofs)
			h.persisted.proofs++
		}
		if rootedMemoArmed {
			storeRootedMemo(rootedScope, closureHash, sliceRooted)
		}
	}
	return nil
}

func (h *Hasher) observabilityFromReachability(base *tier2Base, pkgPath string, reach attributedReachability) (Observability, error) {
	out, err := h.observabilityFromReachabilityCore(base, pkgPath, reach)
	if err != nil {
		return Observability{}, err
	}
	out.TrackedChdirSafe = base.binaryTrackedChdirSafe()
	return out, nil
}

func (h *Hasher) observabilityFromReachabilityCore(base *tier2Base, pkgPath string, reach attributedReachability) (Observability, error) {
	subjectReach := reach
	subjectReach.functions = subjectReach.subjectFunctions
	subjectResult, subjectObjects, err := h.tier2ReachableWithObjects(base, subjectReach)
	if err != nil {
		return Observability{}, err
	}
	var startupResult tier2Result
	if reach.baseStartup && base != nil {
		slot := 0
		if reach.summary != nil {
			slot = 1
		}
		if !base.baseStartupResultDone[slot] {
			startupReach := reach
			startupReach.enumeratedTypes = nil
			startupReach.initBoxedTypes = nil
			startupReach.functions = nonStandardFunctions(base, startupReach.startupFunctions)
			if startupReach.startupDynamicTargets != nil {
				startupReach.dynamicTargets = startupReach.startupDynamicTargets
			}
			base.baseStartupResult[slot] = directExternalEffects(base, startupReach)
			base.baseStartupResultDone[slot] = true
		}
		startupResult = base.baseStartupResult[slot]
	} else {
		startupReach := reach
		startupReach.enumeratedTypes = nil
		startupReach.initBoxedTypes = nil
		startupReach.functions = nonStandardFunctions(base, startupReach.startupFunctions)
		if startupReach.startupDynamicTargets != nil {
			startupReach.dynamicTargets = startupReach.startupDynamicTargets
		}
		startupResult = directExternalEffects(base, startupReach)
	}
	if startupResult.unverifiable {
		reason := startupResult.reason
		if reason == "" {
			reason = "external dependence"
		}
		return Observability{Reason: "startup effect: " + reason}, nil
	}
	if startupResult.widen {
		reason := startupResult.widenReason
		if reason == "" {
			reason = "startup dispatch is not closed"
		}
		return Observability{Reason: "startup effect: " + reason}, nil
	}
	var testMainEffects []externalEffect
	if len(reach.testMainFunctions) > 0 {
		testMainReach := reach
		testMainReach.functions = nonStandardFunctions(base, reach.testMainFunctions)
		testMainResult := testMainObservedEffects(base, testMainReach)
		testMainEffects = testMainResult.effects
		if testMainResult.widen {
			reason := testMainResult.widenReason
			if reason == "" {
				reason = "test-main dispatch is not closed"
			}
			return Observability{Reason: reason}, nil
		}
		var blocking *externalEffect
		blockingRank := 0
		for i := range testMainResult.effects {
			effect := &testMainResult.effects[i]
			if effect.observable {
				continue
			}
			if rank := effectCauseRank(*effect); blocking == nil || rank > blockingRank {
				blocking = effect
				blockingRank = rank
			}
		}
		if blocking != nil {
			return Observability{Reason: blocking.reason}, nil
		}
	}
	if subjectResult.widen || subjectReach.openWorld {
		reason := subjectResult.widenReason
		if reason == "" {
			reason = "open subject world"
		}
		return Observability{Reason: "subject reachability is not closed: " + reason}, nil
	}
	maximalEffects, _, err := h.maximalExternalEffects(pkgPath)
	if err != nil {
		return Observability{}, err
	}
	zeroGlobals := startupZeroGlobalsForReach(base, reach)
	hasAnyBlocker := hasAnyMaximalBlocker(h.SelectionAudited(), maximalEffects)
	var wholeZeroGlobals map[*ssa.Global]bool
	if hasAnyBlocker {
		wholeZeroGlobals = wholeZeroGlobalsForBase(base, reach.userPaths)
	}
	if hasFilterableMaximalBlocker(h.SelectionAudited(), maximalEffects) || (hasAnyBlocker && (len(zeroGlobals) > 0 || len(wholeZeroGlobals) > 0)) {
		reachedDecls, startupOnlyDecls := subjectReachedAndStartupOnlyDeclKeys(base, reach, subjectObjects, zeroGlobals)
		maximalEffects, err = h.subjectMaximalExternalEffectsWithZeroGlobals(base, pkgPath, reachedDecls, startupOnlyDecls, zeroGlobalDeclKeys(zeroGlobals), zeroGlobalDeclKeys(wholeZeroGlobals))
		if err != nil {
			return Observability{}, err
		}
	}
	for _, effect := range maximalEffects {
		if maximalObservabilityBlocker(h.SelectionAudited(), effect) {
			return Observability{Reason: "package scan: " + effect.reason}, nil
		}
	}
	if _, poisonedPkgs := base.flagRegistrationFacts(); len(poisonedPkgs) != 0 {
		paths := slices.Sorted(maps.Keys(poisonedPkgs))
		return Observability{Reason: poisonedPkgs[paths[0]]}, nil
	}
	var blocking *externalEffect
	blockingRank := 0
	for i := range subjectResult.effects {
		effect := &subjectResult.effects[i]
		if effect.observable {
			continue
		}
		if rank := effectCauseRank(*effect); blocking == nil || rank > blockingRank {
			blocking = effect
			blockingRank = rank
		}
	}
	if blocking != nil {
		return Observability{Reason: blocking.reason}, nil
	}
	method := ""
	if h.SelectionAudited() && h.snapshot != nil && h.snapshot.Value("GOOS") == "linux" {
		method = immutableEnvironmentMethod(subjectResult.effects, testMainEffects)
	}
	effectFree := h.SelectionAudited() && hasNoExternalInputEffects(subjectResult.effects, testMainEffects)
	if unsafeReason := base.binaryUnconfinedUnsafeReason(); unsafeReason != "" {
		return Observability{
			Observable:                true,
			OutcomeMethod:             method,
			EffectFree:                effectFree,
			RequiresSingleSubject:     true,
			SharedProcessUnsafeReason: unsafeReason,
		}, nil
	}
	return Observability{Observable: true, OutcomeMethod: method, EffectFree: effectFree}, nil
}

func (b *tier2Base) ensureBinaryUnsafeEvaluated() {
	if b == nil || b.prog == nil || b.binaryUnsafeDone {
		return
	}
	b.binaryUnsafeDone = true
	b.pkgUnsafeKnown = map[string]bool{}
	b.pkgUnsafeHazard = map[string]bool{}
	loadedByTypes := make(map[*types.Package]*packages.Package, len(b.prog.Pkgs))
	for _, p := range b.prog.Pkgs {
		if p != nil && p.Types != nil {
			loadedByTypes[p.Types] = p
		}
	}
	var candidates []*pkgIndex
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.std || idx.testMain || idx.pkg == nil {
			continue
		}
		candidates = append(candidates, idx)
	}
	slices.SortFunc(candidates, func(x, y *pkgIndex) int {
		if c := strings.Compare(x.path, y.path); c != 0 {
			return c
		}
		return strings.Compare(x.id, y.id)
	})
	var sizes types.Sizes
	if b.prog.GOARCH != "" {
		sizes = types.SizesFor("gc", b.prog.GOARCH)
	}
	for _, idx := range candidates {
		pkgSizes := sizes
		if pkgSizes == nil {
			pkgSizes = idx.pkg.TypesSizes
		}
		b.pkgUnsafeKnown[idx.path] = true
		b.pkgUnsafeKnown[idx.id] = true
		if refconfine.PackageHasUnconfinedUnsafeMemoryHazard(idx.pkg, pkgSizes, loadedByTypes) {
			b.pkgUnsafeHazard[idx.path] = true
			b.pkgUnsafeHazard[idx.id] = true
			if b.binaryUnsafeReason == "" {
				b.binaryUnsafeReason = "package scan: reaches un-confined unsafe.Pointer in " + idx.path
			}
		}
	}
	if b.binaryUnsafeReason == "" {
		b.binaryUnsafeReason = b.binaryUnverifiedAsmReason(candidates)
	}
}

func (b *tier2Base) binaryUnconfinedUnsafeReason() string {
	if b == nil || b.prog == nil {
		return ""
	}
	b.ensureBinaryUnsafeEvaluated()
	return b.binaryUnsafeReason
}

func (b *tier2Base) pkgConfinedUnsafe(importID, srcPath string) bool {
	if b == nil || b.prog == nil {
		return false
	}
	b.ensureBinaryUnsafeEvaluated()
	if importID != "" && b.pkgUnsafeKnown[importID] {
		return !b.pkgUnsafeHazard[importID] && !b.pkgUnsafeHazard[srcPath]
	}
	if srcPath != "" && b.pkgUnsafeKnown[srcPath] {
		return !b.pkgUnsafeHazard[srcPath]
	}
	return false
}

func hasNoExternalInputEffects(sets ...[]externalEffect) bool {
	for _, effects := range sets {
		for _, effect := range effects {
			if !harnessOutcomeAdmitted(effect) {
				return false
			}
		}
	}
	return true
}

func immutableEnvironmentMethod(sets ...[]externalEffect) string {
	for _, effects := range sets {
		for _, effect := range effects {
			if harnessOutcomeAdmitted(effect) {
				continue
			}
			if !effect.observable || effect.packagePath != "os" || (effect.symbol != "Getenv" && effect.symbol != "LookupEnv") {
				return ""
			}
		}
	}
	return ImmutableEnvironmentOutcomes
}

func testMainObservedEffects(base *tier2Base, reachable attributedReachability) tier2Result {
	return walkDirectFlowEffects(base, reachable, true)
}

func directExternalEffects(base *tier2Base, reachable attributedReachability) tier2Result {
	return walkDirectFlowEffects(base, reachable, false)
}

func walkDirectFlowEffects(base *tier2Base, reachable attributedReachability, isTestMain bool) tier2Result {
	analyzer := base.analyzer()
	audited := analyzer.h.SelectionAudited()
	bitFP := newBitOnlyFreshParamAnalysis(len(reachable.verifiedHarnesses) > 0, audited, analyzer.h.source.pureDelegates, reachable.userPaths, reachable.summary, analyzer.isStdFunction)
	if bitFP.verifiedHarnesses == nil {
		bitFP.verifiedHarnesses = reachable.verifiedHarnesses
	}
	if bitFP.prog == nil {
		bitFP.prog = base.prog
	}
	bitFP.flowFunctions = reachable.functions
	bitFP.traceCtx = analyzer.h.ctx
	if isTestMain {
		analyzer.fresh = newFreshParamAnalysis(audited, analyzer.h.source.pureDelegates, reachable, analyzer.isStdFunction)
		analyzer.fresh.traceCtx = analyzer.h.ctx
	} else {
		analyzer.fresh = bitFP
	}

	var startupZeroGlobals map[*ssa.Global]bool
	var asyncStartup map[*ssa.Function]bool
	if !isTestMain {
		startupZeroGlobals = startupZeroGlobalsForReach(base, reachable)
		asyncStartup = asyncOrDynamicStartupFunctionsForBase(base, reachable)
	}

	rawFlowFunctions := reachable.startupFunctions
	if isTestMain {
		rawFlowFunctions = reachable.testMainFunctions
	}
	for function := range rawFlowFunctions {
		idx := analyzer.idxForFunction(function)
		if idx == nil || !idx.std {
			continue
		}
		for _, block := range liveBlocks(function, nil) {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				for target := range narrowedTargets(site, reachable.dynamicTargets[site], analyzer.fresh) {
					tIdx := analyzer.idxForFunction(target)
					if tIdx == nil {
						continue
					}
					if (!tIdx.std && len(target.Blocks) == 0) || tIdx.path == "net/url" {
						recordCallEffect(analyzer, target, site, isTestMain)
					}
				}
			}
		}
	}

	var ops [16]*ssa.Value
	for function := range reachable.functions {
		idx := analyzer.idxForFunction(function)
		if idx != nil && idx.std {
			continue
		}
		if (idx == nil && !isAnalyzableUnnamedWrapper(function)) || (idx != nil && idx.testMain) {
			continue
		}
		if len(function.Blocks) == 0 {
			analyzer.scanBodylessNonStdFunction(function, idx, false)
			continue
		}
		var fnZeroGlobals map[*ssa.Global]bool
		if !isTestMain && !reachable.cleanupFunctions[function] {
			if !asyncStartup[function] {
				fnZeroGlobals = startupZeroGlobals
			} else {
				fnZeroGlobals = wholeZeroGlobalsForBase(base, reachable.userPaths)
			}
		}
		for _, block := range liveBlocks(function, fnZeroGlobals) {
			for _, instruction := range block.Instrs {
				if v, ok := instruction.(ssa.Value); ok {
					analyzer.addValueType(idx, v)
				}
				for _, op := range instruction.Operands(ops[:0]) {
					if op == nil || *op == nil {
						continue
					}
					if fnOp, isFn := (*op).(*ssa.Function); isFn && funcPkgPath(fnOp) == "go/ast" && baseFunctionSymbolName(fnOp) == "String" && !auditedStandardMethod(audited, fnOp) {
						analyzer.recordExternalEffect(unauditedStandardEffect("go/ast", "String"))
					}
					opIdx := analyzer.idxForFunction((*op).Parent())
					if _, isConst := (*op).(*ssa.Const); isConst {
						opIdx = idx
					}
					analyzer.addValueType(opIdx, *op)
				}
				recordFlagBackedReferences(analyzer.flagBacked, fnZeroGlobals, analyzer.recordExternalEffect, instruction)
				analyzer.checkInstructionStdHooks(function, false, instruction)
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestMain {
					if !dispatchProvenanceClosed(site, bitFP) {
						analyzer.requestWiden("test-main dispatch on unattributable state in " + function.String())
					}
				} else if reachable.cleanupFunctions[function] {
					if !dispatchProvenanceClosed(site, analyzer.fresh) {
						analyzer.requestWiden("cleanup dispatch on unattributable state in " + function.String())
					}
					if callee != nil && funcPkgPath(callee) == "reflect" {
						switch functionSymbolName(callee) {
						case "Call", "CallSlice", "MakeFunc", "MethodByName":
							analyzer.requestWiden("reflect dispatch in cleanup flow")
						}
					}
				}
				if callee != nil {
					recordCallEffect(analyzer, callee, site, isTestMain)
				}
				for target := range narrowedTargets(site, reachable.dynamicTargets[site], analyzer.fresh) {
					recordCallEffect(analyzer, target, site, isTestMain)
				}
			}
		}
	}
	return analyzer.result()
}

func recordTestMainCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	recordCallEffect(analyzer, callee, site, true)
}

func recordDirectCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction) {
	recordCallEffect(analyzer, callee, site, false)
}

func recordCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction, isTestMain bool) {
	if analyzer == nil || callee == nil || observableFileMethod(callee) || observableDirEntryCall(site) || isTestingMRun(callee) {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	if flagRegistrationSymbol(pkgPath, name) && site.Common().StaticCallee() == callee {
		return
	}
	if vp := analyzer.verifiedHarness(pkgPath); vp != nil {
		flowName := "startup flow"
		if isTestMain {
			flowName = "test-main flow"
		}
		if site.Common().StaticCallee() != callee {
			analyzer.requestWiden("property harness reached as a dynamic target in " + flowName)
		} else if !propertyHarnessClosedArgs(site.Common(), analyzer.fresh) {
			analyzer.requestWiden("property-harness argument is not locally closed in " + flowName)
		} else if mk, isSample := propertyHarnessSeededSampleCallee(vp, callee); isSample && !harnessSeededSampleHasExplicitSeed(site.Common()) {
			analyzer.recordExternalEffect(propertyHarnessUnseededSampleEffect(vp, mk))
		}
		return
	}
	if isTestMain && pkgPath == "os" && name == "Exit" {
		return
	}
	effect, classified := analyzer.classifyCalleeEffect(callee, pkgPath, name, site.Common(), site, false)
	if classified {
		if isTestMain {
			effect.observable = observableCallEffect(analyzer.h.SelectionAudited(), effect, site.Common(), site, analyzer.fresh)
		}
		if !isTestMain && !effect.observable && trace.AnyEnabled() && site != nil && site.Parent() != nil {
			trace.Emit(analyzer.h.ctx, trace.DomainClosure, "closure.startup.effect", site.Parent().String(),
				trace.String("callee", callee.String()),
				trace.String("reason", effect.reason),
			)
		}
		analyzer.recordExternalEffect(effect)
	}
}

func dispatchProvenanceClosed(site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	c := site.Common()
	siteFP := contextCancelMethodFP(site, fp)
	if callee := c.StaticCallee(); callee != nil {
		if syntheticInterfaceMethodWrapper(callee) {
			receiver := wrapperReceiver(c, callee)
			return receiver != nil && subjectClosedDynamicValue(receiver, make(map[ssa.Value]bool), siteFP)
		}
		if siteFP != nil && siteFP.verifiedHarnesses[funcPkgPath(callee)] != nil {
			return propertyHarnessClosedArgs(c, siteFP)
		}
		if _, isFunc := c.Value.(*ssa.Function); isFunc {
			return true
		}
	}
	return subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), siteFP)
}

func nonStandardFunctions(base *tier2Base, functions map[*ssa.Function]bool) map[*ssa.Function]bool {
	filtered := make(map[*ssa.Function]bool)
	for function := range functions {
		if idx := base.idxForFunction(function); idx != nil {
			if !idx.std {
				filtered[function] = true
			}
			continue
		}
		if isAnalyzableUnnamedWrapper(function) {
			filtered[function] = true
			continue
		}
		if !isStdImportPath(funcPkgPath(function)) {
			filtered[function] = true
		}
	}
	return filtered
}

const unsupportedShapeReason = "attributed reachability unavailable: unsupported analysis shape"
