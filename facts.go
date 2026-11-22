package gofresh

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
)

// subjectEntry consolidates one subject's immutable construction-time facts
// within an observationFacts pass.
type subjectEntry struct {
	maximal         subjectFacts
	purity          string
	vouchDischarges string
	discharges      attestationDischarges
	// cut records that the analysis budget left this subject undischarged in
	// this pass — a fact of the pass, never of the tree (REQ-fresh-context).
	cut         bool
	sourceFiles []string
}

// observationFacts is one generation's immutable observation: derived
// by an observation pass (or assembled as a subject-scoped subset by
// sibling) and shared read-only by every Snapshot holding it. The struct
// is mutex-free and setter-free, so read-only sharing is structural,
// never conventional; the Snapshot keeps only transactional state (seal,
// captured proofs, runtime attachments) beside it. Explicit snapshots retain only
// source/build guards here; their immutable runtime binding supplies the rest.
type observationFacts struct {
	// snapshot is the construction pass's env snapshot. The process
	// environment is immutable configuration (REQ-fresh-coherent-view);
	// go env FILE values can still change on disk, so a bracket reusing
	// this snapshot resolves only GOMODCACHE from it, revalidates GOFLAGS
	// live before any load (the memo write precedes the closing compare),
	// and relies on the closing pass's fresh snapshot to refuse any drift
	// the guards cover.
	snapshot *gotool.EnvSnapshot
	// reader is the construction pass's reader, the snapshot's home: the
	// bracket's constructor reads the construction snapshot through it.
	reader   *gotool.EnvReader
	subjects map[Subject]subjectEntry
	// source retains only typed inputs actually loaded by this generation. A
	// warm scan memo can leave it absent or partially populated; that is not
	// permission to acquire replacement inputs or infer implementation support.
	source      *closure.ViewLoad
	guards      guard.Guards
	sourceFiles []string
	// fileDigests carries a construction-time content digest per source
	// identity, so a later validation failure can name the moved file
	// (REQ-fresh-producer-view's naming arm). Best-effort attribution:
	// the digests are read moments after the closure hashes, so a file
	// that moves inside that window names imprecisely while the closure
	// comparison still refuses.
	fileDigests map[string]string
	// testVariantLedgers: per-package compartment ledgers, pure functions
	// of the same bytes the compartment hashes fold, so the agreement
	// pair's hash comparison vouches for them.
	testVariantLedgers map[string]testvariant.TestVariantLedger
	modelProjections   [3]executionModelProjection
	hasProjection      [3]bool
}

func (s *Session) observeView(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind) (facts observationFacts, err error) {
	return s.observeViewWithExecution(ctx, subjects, requests, packages, moduleDir, kind, s.executionModel)
}

func (s *Session) observeViewWithExecution(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind, execModel ExecutionModel) (facts observationFacts, err error) {
	emitObserveViewHook()
	var hasher *closure.Hasher
	defer func() { accountPass(ctx, hasher) }()
	if s.progress != nil {
		s.progress(Progress{Phase: "observe"})
	}
	reader := s.newPassReader()
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return observationFacts{}, err
	}
	hasher, err = closure.NewAt(ctx, reader, s.buildFlags...)
	if err != nil {
		return observationFacts{}, err
	}
	if s.progress != nil {
		emitUnauditedToolchainNotice(&s.unauditedNotice, hasher.SelectionNotice(), func(detail string) {
			s.progress(Progress{Phase: "toolchain-unaudited", Detail: detail})
		})
		s.wireProgress(hasher)
	}
	inputs := s.guardInputs()
	identity, err := guard.CompleteBuildEnvironment(ctx, snapshot, s.dir, s.env)
	if err != nil {
		return observationFacts{}, err
	}
	inputs = append(inputs, "gofresh/build-description@2="+identity)
	guards, err := guard.Capture(ctx, gotool.PrimedEnvReader(s.runner, observedGuardDir(reader.Dir), s.env, snapshot), s.evidenceEnv(), CodeResult, inputs...)
	if err != nil {
		return observationFacts{}, err
	}
	scope := hasher.SetAnalysisScope(s.analysisScope(guards))
	emitFactScopeViewHook(scope.Facts())
	if kind == SourceResult {
		emitScanScopeViewHook(scope.SourceScan())
	} else {
		emitScanScopeViewHook(scope.Scan())
	}
	scan, source, cut, err := scanViewSubjectsWithMode(ctx, hasher, scope, s.buildFlags, s.analysisBudget, true, &s.localFacts, kind == SourceResult, execModel, packages...)
	if err != nil {
		return observationFacts{}, err
	}
	reportBudgetCut(s.progress, s.analysisBudget, len(cut), "undischarged")
	directivePure, known, openWorld, external := scan.directivePure, scan.known, scan.openWorld, scan.external
	if kind == SourceResult {
		for _, pkg := range packages {
			if errMsg := scan.loadErr[pkg]; errMsg != "" {
				return observationFacts{}, fmt.Errorf("gofresh: load %s: %s", pkg, errMsg)
			}
		}
	} else {
		for _, s := range subjects {
			if (!known[s] || scan.staticDecl[s]) && scan.loadErr[s.Package] != "" {
				return observationFacts{}, fmt.Errorf("gofresh: load %s: %s", s.Package, scan.loadErr[s.Package])
			}
		}
	}
	if err := requireSubjects(subjects, func(s Subject) bool { return known[s] }, SelectedSource); err != nil {
		return observationFacts{}, err
	}
	if kind == Measurement {
		if err := checkStaticDeclsForMeasurement(ctx, subjects, scan.staticDecl, moduleDir); err != nil {
			return observationFacts{}, err
		}
	}
	emitMaximalBatchViewHook()
	computed, sources, err := hasher.ComputeMaximalFactsBatch(requests)
	if err != nil {
		return observationFacts{}, err
	}
	observation := observationFacts{
		snapshot:           snapshot,
		reader:             reader,
		subjects:           make(map[Subject]subjectEntry, len(subjects)),
		source:             source,
		guards:             guards,
		testVariantLedgers: make(map[string]testvariant.TestVariantLedger, len(packages)),
	}
	for _, pkg := range packages {
		ledger, err := hasher.TestVariantLedger(pkg)
		if err != nil {
			return observationFacts{}, err
		}
		observation.testVariantLedgers[pkg] = ledger
	}
	sourceGroups := make([][]string, 0, len(requests))
	for _, request := range requests {
		sourceGroups = append(sourceGroups, sources[request])
	}
	observation.sourceFiles = sortedUniqueUnion(sourceGroups)
	observation.fileDigests = make(map[string]string, len(observation.sourceFiles))
	for _, path := range observation.sourceFiles {
		if err := ctx.Err(); err != nil {
			return observationFacts{}, err
		}
		if digest, ok := hasher.FileDigest(path); ok {
			observation.fileDigests[path] = digest
		}
	}
	if kind != SourceResult {
		observation.modelProjections, observation.hasProjection = buildModelProjections(subjects, scan, hasher.SelectionAttribution(), budgetExhausted(s.analysisBudget))
	}
	for _, subject := range subjects {
		isStatic := scan.staticDecl[subject]
		maximal := subjectFacts{
			source:     computed[closure.Subject{Package: subject.Package, Symbol: subject.Symbol}],
			staticDecl: isStatic,
			sourceOnly: kind == SourceResult,
		}
		var entry subjectEntry
		if kind != SourceResult && !isStatic {
			if term := openWorld[subject]; term != "" {
				maximal.openWorld = &subjectRefusal{reason: closure.AttributeSelection("subject accepts caller-supplied dynamic behavior through its "+term+" (dischargeable by bounding that type away from dynamic carriers, or by "+closure.PurityResponsibility+")", hasher.SelectionAttribution())}
			}
			if reason := scan.downgradeReason[subject]; reason != "" {
				var culprit Subject
				if !cut[subject] {
					culprit = scan.downgradeCulprit[subject]
				}
				if cut[subject] {
					reason += " (reachability unjudged: " + budgetExhausted(s.analysisBudget) + ")"
				}
				maximal.sharedState = &subjectRefusal{
					reason:  closure.AttributeSelection(reason, hasher.SelectionAttribution()),
					culprit: culprit,
				}
			}
			entry.vouchDischarges = scan.vouchDischarges[subject]
			entry.discharges = scan.discharges[subject]
			entry.cut = cut[subject]
		}
		if detail := scan.ambiguous[subject]; detail != "" {
			maximal.ambiguous = &subjectRefusal{reason: "ambiguous subject identity: " + detail + "; rename one declaration to address either"}
		}
		if kind != SourceResult && external[subject] {
			maximal.external = true
		}
		entry.maximal = maximal
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		entry.sourceFiles = slices.Clone(sources[request])
		sort.Strings(entry.sourceFiles)
		if kind != SourceResult && !isStatic && !external[subject] && scan.ambiguous[subject] == "" {
			switch caller, directive := s.assumePure(subject), directivePure(subject); {
			case caller && directive:
				entry.purity = "caller assertion and source directive"
			case caller:
				entry.purity = "caller assertion"
			case directive:
				entry.purity = "source directive"
			}
		}
		observation.subjects[subject] = entry
	}
	if trace.AnyEnabled() {
		for _, subject := range subjects {
			target := subject.Package + "." + subject.Symbol
			if !trace.Enabled(ctx, trace.DomainClosure, target) {
				continue
			}
			c := observation.subjects[subject].maximal.closure()
			culpritStr := ""
			if c.Culprit.Package != "" || c.Culprit.Symbol != "" {
				culpritStr = c.Culprit.Package + "." + c.Culprit.Symbol
			}
			trace.Emit(ctx, trace.DomainClosure, "subject_closure", target,
				trace.String("hash", c.Hash),
				trace.String("test_variants", c.TestVariants),
				trace.Bool("unverifiable", c.Unverifiable),
				trace.Int("refusal", int(c.Refusal)),
				trace.String("culprit", culpritStr),
				trace.String("reason", c.Reason),
			)
		}
		if trace.Enabled(ctx, trace.DomainView, moduleDir) {
			trace.Emit(ctx, trace.DomainView, "pass_summary", moduleDir,
				trace.Int("subjects", len(subjects)),
				trace.Int("source_files", len(observation.sourceFiles)),
				trace.Int("cut_subjects", len(cut)),
				trace.String("guards_toolchain", observation.guards.Toolchain),
				trace.String("guards_buildconfig", observation.guards.BuildConfig),
			)
		}
	}
	return observation, nil
}

// scopeSubjects derives one view scope — the deduplicated subjects,
// their closure requests, and their unique packages, in first-seen
// order — the single recipe every view construction and derivation
// shares, so two scopes over one subject set can never disagree.
func scopeSubjects(subjects []Subject) (unique []Subject, requests []closure.Subject, packages []string, err error) {
	seen := make(map[Subject]bool, len(subjects))
	seenPackage := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if subject.Package == "" || subject.Symbol == "" {
			return nil, nil, nil, fmt.Errorf("gofresh: invalid empty subject %+v", subject)
		}
		if seen[subject] {
			continue
		}
		seen[subject] = true
		unique = append(unique, subject)
		requests = append(requests, closure.Subject{Package: subject.Package, Symbol: subject.Symbol})
		if !seenPackage[subject.Package] {
			seenPackage[subject.Package] = true
			packages = append(packages, subject.Package)
		}
	}
	return unique, requests, packages, nil
}

// sortedUniqueUnion folds per-subject source-identity lists into the
// observation's canonical union form — sorted, deduplicated — the one
// recipe construction and sibling derivation share, so a derived
// union always compares equal to a freshly observed one on an
// unchanged tree.
func sortedUniqueUnion(groups [][]string) []string {
	seen := map[string]bool{}
	var union []string
	for _, group := range groups {
		for _, path := range group {
			if !seen[path] {
				seen[path] = true
				union = append(union, path)
			}
		}
	}
	sort.Strings(union)
	return union
}

// takeCut adopts the other observation's fail-closed shape for a subject
// it cut: the undischarged downgrade and Stage-A-only discharges.
func (f *observationFacts) takeCut(other observationFacts, subject Subject) {
	if f.subjects == nil {
		f.subjects = map[Subject]subjectEntry{}
	}
	entry := f.subjects[subject]
	otherEntry := other.subjects[subject]
	entry.maximal.sharedState = otherEntry.maximal.sharedState
	entry.discharges = otherEntry.discharges
	entry.cut = true
	f.subjects[subject] = entry
	takeModelCut(f, other, subject)
}

// analysisScope is the pass's analysis identity outside the source
// closure under guards: the strategy versions, the code guards, the
// execution attestations — each changes what a derived fact records,
// so attested and unattested sessions never serve each other's facts
// (REQ-closure-dynamic-state-memo) — and the caller's vouch set.
func (s *Session) analysisScope(guards guard.Guards) closure.AnalysisScope {
	return closure.AnalysisScope{
		ProofStrategy: ObservationRTA, FactStrategy: DynamicStateStrategy,
		Toolchain: guards.Toolchain, BuildConfig: guards.BuildConfig,
		SingleSubject: s.executionModel.singleSubject(), PackageProcess: s.executionModel.packageProcess(),
		Vouches: slices.Clone(s.sortedVouches),
	}
}

// subjectFacts separates immutable maximal inputs from consumer-tier obligations.
// The obligations are independent: selecting one diagnostic must not erase the
// others. They describe the construction's conservative analysis, never a later
// producing unit's or historical candidate's admission.
type subjectFacts struct {
	source      closure.MaximalFacts
	staticDecl  bool
	sourceOnly  bool
	openWorld   *subjectRefusal
	sharedState *subjectRefusal
	ambiguous   *subjectRefusal
	external    bool
}

// Presence carries the obligation; even an empty diagnostic cannot remove it.
// A refusal is immutable after construction and may be shared with siblings.
type subjectRefusal struct {
	reason  string
	culprit Subject
}

func sameRefusal(a, b *subjectRefusal) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// closure is the ordinary verdict ladder's projection. A caller may refine its
// local decision using separately admitted evidence, but cannot write it back to
// these facts. The source inventory and every consumer-tier obligation survive
// even when a higher-priority diagnostic is selected here.
func (f subjectFacts) closure() closure.Closure {
	c := f.source.Closure()
	if (f.sourceOnly || f.staticDecl) && c.Hash != "" {
		c.Unverifiable, c.Refusal, c.Reason, c.Culprit = false, 0, "", closure.Subject{}
	}
	if f.openWorld != nil {
		c.Unverifiable, c.Refusal, c.Reason, c.Culprit = true, closure.OpenWorldRefusal, f.openWorld.reason, closure.Subject{}
	}
	if f.sharedState != nil {
		c.Unverifiable, c.Refusal, c.Reason, c.Culprit = true, closure.SharedDynamicStateRefusal, f.sharedState.reason, closure.Subject{
			Package: f.sharedState.culprit.Package,
			Symbol:  f.sharedState.culprit.Symbol,
		}
	}
	if f.ambiguous != nil {
		c.Unverifiable, c.Refusal, c.Reason, c.Culprit = true, closure.AmbiguousSubjectRefusal, f.ambiguous.reason, closure.Subject{}
	}
	if f.external {
		c.External, c.Unverifiable, c.Reason, c.Culprit = true, true, "external directive", closure.Subject{}
	}
	return c
}

// equal compares base observations, not evidence-dependent decisions. A budget
// cut can change only the shared-state discharge; all other obligations must
// still agree, including ones hidden by the selected diagnostic.
func (f subjectFacts) equal(other subjectFacts, cut bool) bool {
	return f.source.Equal(other.source) && f.staticDecl == other.staticDecl && f.sourceOnly == other.sourceOnly &&
		sameRefusal(f.openWorld, other.openWorld) &&
		(cut || sameRefusal(f.sharedState, other.sharedState)) &&
		sameRefusal(f.ambiguous, other.ambiguous) && f.external == other.external
}

func diffSubjectFacts(first, second subjectFacts, cut bool) (diffField, firstVal, secondVal string) {
	if !first.source.Equal(second.source) {
		c1 := first.source.Closure()
		c2 := second.source.Closure()
		switch {
		case c1.Hash != c2.Hash:
			return "closure_hash", c1.Hash, c2.Hash
		case c1.TestVariants != c2.TestVariants:
			return "closure_test_variants", c1.TestVariants, c2.TestVariants
		case c1.ToolchainContent != c2.ToolchainContent:
			return "closure_toolchain_content", c1.ToolchainContent, c2.ToolchainContent
		case c1.AdmissionPolicy != c2.AdmissionPolicy:
			return "closure_admission_policy", c1.AdmissionPolicy, c2.AdmissionPolicy
		case c1.Unverifiable != c2.Unverifiable:
			return "closure_unverifiable", strconv.FormatBool(c1.Unverifiable), strconv.FormatBool(c2.Unverifiable)
		case c1.Reason != c2.Reason:
			return "closure_reason", c1.Reason, c2.Reason
		default:
			return "closure_effects", fmt.Sprintf("%+v", first.source), fmt.Sprintf("%+v", second.source)
		}
	}
	if !sameRefusal(first.openWorld, second.openWorld) {
		return "open_world", formatRefusal(first.openWorld), formatRefusal(second.openWorld)
	}
	if !cut && !sameRefusal(first.sharedState, second.sharedState) {
		return "shared_state", formatRefusal(first.sharedState), formatRefusal(second.sharedState)
	}
	if !sameRefusal(first.ambiguous, second.ambiguous) {
		return "ambiguous", formatRefusal(first.ambiguous), formatRefusal(second.ambiguous)
	}
	if first.external != second.external {
		return "external", strconv.FormatBool(first.external), strconv.FormatBool(second.external)
	}
	return "closure", fmt.Sprintf("%+v", first), fmt.Sprintf("%+v", second)
}

func formatRefusal(r *subjectRefusal) string {
	if r == nil {
		return ""
	}
	if r.culprit.Package != "" || r.culprit.Symbol != "" {
		return r.culprit.Package + "." + r.culprit.Symbol + ": " + r.reason
	}
	return r.reason
}

func (f *observationFacts) closure(subject Subject) closure.Closure {
	if f == nil {
		return closure.Closure{}
	}
	return f.subjects[subject].maximal.closure()
}
