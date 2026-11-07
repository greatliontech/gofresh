package gofresh

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/render"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
)

// ErrViewChanged reports that a producer Snapshot no longer describes the current
// source, build, guard, or purity state and its results must not be persisted.
var ErrViewChanged = errors.New("gofresh: analysis view changed")

// errViewSealed reports a capture attempted after producer validation started.
var errViewSealed = errors.New("gofresh: analysis view sealed by validation")

// ErrAnalysisUnavailable reports that producer validation could not
// re-establish a captured observation proof because the current analysis was
// unavailable — an exhausted analysis budget or a failed load — never because
// the view drifted: it is reported only once every other check of the
// validation passed, the runtime-input comparison that closes the proof
// pass included, so a caller holding it knows nothing else moved. The
// error names the first subject the pass could not re-establish; the
// pass's own progress diagnostic carries the count. The evidence is not
// persisted; the caller may retry with a larger budget or record the
// run's outcomes under unverifiable observation evidence.
var ErrAnalysisUnavailable = errors.New("gofresh: observation analysis unavailable during validation")

// Snapshot is one immutable observation of the source, build, guards, and purity
// behind a caller-supplied subject set. It can serve a current check batch or a
// producer transaction. Analysis state never crosses view generations; within
// one generation, Sibling derives subset views sharing this view's observation
// while owning their producer transactions.
type Snapshot struct {
	mu                   sync.RWMutex
	session              *Session
	subjects             []Subject
	requests             []closure.Subject
	packages             []string
	moduleDir            string
	kind                 Kind
	facts                *observationFacts
	runtime              *boundRuntime
	observable           map[Subject]closure.Observability
	capturedObserved     map[Subject]bool
	attachedObservations map[Subject]runtimeinput.State
	sealed               bool
	applicabilityChecks  []applicabilityCheck
	// cutUnavailable holds a comparison's unavailability that a budget
	// cut alone explains (compareFactsContext): never returned where it
	// arose — a capture keeps the view's fail-closed facts, a validation
	// runs every other check first — and read by the observed
	// validation's end (REQ-fresh-context).
	cutUnavailable error
	runtimeCurrent func(context.Context, string, string) (runtimeinput.State, error)
	// beforePreciseAnalysis observes the start of drift-forced precise analysis
	// (the observability proof). Tests use it to pin which check paths run
	// analysis and to inject cancellation at the analysis boundary. It stays
	// per-view — outside the package-level viewTestHooks surface — because
	// its granularity is load-bearing: pass-economy tests count analyses on
	// one view while another is live, which a package-global hook cannot
	// attribute.
	beforePreciseAnalysis func()
	// beforeOutcomeIssue lets lifecycle tests intervene after capture has
	// released its lock and before preparation checks the transaction seal.
	beforeOutcomeIssue func()
}

// observeSnapshot observes one analysis view with the guards applicable to kind
// under the caller's context. Reachability and package loading are shared
// across the requested set, but each subject retains its independent closure
// semantics (REQ-closure-batch-equivalence).
func (s *Session) observeSnapshot(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (view *Snapshot, opErr error) {
	ctx, done := s.beginOperation(ctx)
	defer done(&opErr)
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validKind(kind) {
		return nil, fmt.Errorf("gofresh: invalid result kind %d", kind)
	}
	if len(subjects) == 0 {
		return nil, errors.New("gofresh: analysis view requires at least one subject")
	}
	var err error
	moduleDir, err = gotool.CanonicalDir(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve guards tree: %w", err)
	}
	if err := s.coherentDir(moduleDir); err != nil {
		return nil, err
	}

	unique, requests, packages, err := scopeSubjects(subjects)
	if err != nil {
		return nil, err
	}

	first, err := s.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	second, err := s.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	if err := compareObservations(ctx, unique, &first, first.guards, second, true); err != nil {
		return nil, err
	}

	v := &Snapshot{
		session:              s,
		subjects:             unique,
		requests:             requests,
		packages:             packages,
		moduleDir:            moduleDir,
		kind:                 kind,
		facts:                &first,
		observable:           make(map[Subject]closure.Observability, len(unique)),
		capturedObserved:     make(map[Subject]bool, len(unique)),
		attachedObservations: make(map[Subject]runtimeinput.State, len(unique)),
	}
	return v, nil
}

// observationFacts is one generation's immutable observation: derived
// by an observation pass (or assembled as a subject-scoped subset by
// Sibling) and shared read-only by every Snapshot holding it. The struct
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
	reader  *gotool.EnvReader
	maximal map[Subject]subjectFacts
	// source retains only typed inputs actually loaded by this generation. A
	// warm scan memo can leave it absent or partially populated; that is not
	// permission to acquire replacement inputs or infer implementation support.
	source                *closure.ViewLoad
	guards          guard.Guards
	purity          map[Subject]string
	vouchDischarges map[Subject]string
	discharges      map[Subject]attestationDischarges
	// cut is the set of subjects the analysis budget left undischarged
	// in this pass — a fact of the pass, never of the tree: the fields
	// the discharge shapes (the downgrade in maximal, the attestation
	// and package-process discharges) are compared only between passes
	// not cut on the subject, and a difference a cut explains is the
	// analysis's unavailability, never drift (REQ-fresh-context).
	cut                  map[Subject]bool
	sourceFiles          []string
	sourceFilesBySubject map[Subject][]string
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
}

// wireProgress routes a Hasher's step, unit, and diagnostic events to
// the session's progress callback as Progress values.
func (s *Session) wireProgress(hasher *closure.Hasher) {
	hasher.OnProgress(func(phase, pkgPath string) {
		s.progress(Progress{Phase: phase, Package: pkgPath})
	})
	hasher.OnDiagnostic(func(phase, pkgPath, detail string) {
		s.progress(Progress{Phase: phase, Package: pkgPath, Detail: detail})
	})
	hasher.OnUnit(func(phase, pkgPath string, index, total int) {
		s.progress(Progress{Phase: phase, Package: pkgPath, Index: index, Total: total})
	})
}

// opAccount accumulates, across every pass an operation performs, what
// its Hashers persisted to the memo store and which packages the store
// served per memo class — the facts the operation's one kept-on-cancel
// report and its one served summary per class carry. It rides the
// operation's context so every pass finds it without a signature.
type opAccount struct {
	proofs, scans int
	served        map[string]map[string]bool
}

type opAccountKey struct{}

// beginOperation opens one operation's accounting on ctx and returns the
// finisher the operation defers: it emits the served summary (one event
// per class) and, when the operation returns its caller's context error,
// the kept-on-cancel report — once per operation, whatever its passes.
func (s *Session) beginOperation(ctx context.Context) (context.Context, func(*error)) {
	refreshTraceFromEnv()
	if s.progress == nil || ctx == nil {
		return ctx, func(*error) {}
	}
	if _, nested := ctx.Value(opAccountKey{}).(*opAccount); nested {
		// A pass inside an already-accounted operation reports through
		// that operation.
		return ctx, func(*error) {}
	}
	acc := &opAccount{served: map[string]map[string]bool{}}
	return context.WithValue(ctx, opAccountKey{}, acc), func(err *error) {
		classes := make([]string, 0, len(acc.served))
		for class := range acc.served {
			classes = append(classes, class)
		}
		sort.Strings(classes)
		for _, class := range classes {
			s.progress(Progress{Phase: "served", Served: class, Index: len(acc.served[class])})
		}
		if err != nil && *err != nil && (errors.Is(*err, context.Canceled) || errors.Is(*err, context.DeadlineExceeded)) {
			s.progress(Progress{Phase: "cancelled", Detail: keptOnCancelDetail(acc.proofs, acc.scans)})
		}
	}
}

// accountPass folds one pass's Hasher into the operation's accounting.
func accountPass(ctx context.Context, hasher *closure.Hasher) {
	if hasher == nil {
		return
	}
	acc, ok := ctx.Value(opAccountKey{}).(*opAccount)
	if !ok {
		return
	}
	proofs, scans := hasher.Persisted()
	acc.proofs += proofs
	acc.scans += scans
	for class, pkgs := range hasher.ServedSummary() {
		if acc.served[class] == nil {
			acc.served[class] = map[string]bool{}
		}
		for p := range pkgs {
			acc.served[class][p] = true
		}
	}
}

func (s *Session) observeView(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind) (facts observationFacts, err error) {
	emitObserveViewHook()
	var hasher *closure.Hasher
	defer func() { accountPass(ctx, hasher) }()
	if s.progress != nil {
		s.progress(Progress{Phase: "observe"})
	}
	// One `go env -json` read serves this whole pass: the hasher's
	// GOMODCACHE and GOFLAGS validation, the guard's build-config digest,
	// and the typed load's validation all derive from it. The snapshot is
	// pass-scoped - a later pass takes its own, so environment drift still
	// meets an observation (REQ-guard-buildconfig; the toolchain guard is
	// the snapshot's GOVERSION with the host platform, REQ-guard-toolchain).
	reader := s.newPassReader()
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return observationFacts{}, err
	}
	hasher, err = closure.NewAt(ctx, reader, s.buildFlags...)
	if err != nil {
		return observationFacts{}, err
	}
	// The toolchain-selection verdict is a construction fact: the Hasher
	// resolved it from the snapshot it was built on, so the notice that a
	// selection outside the audit degrades every later proof is announced
	// here, before any load — never first on the precise-analysis path a
	// caller may reach only after execution.
	if s.progress != nil {
		emitUnauditedToolchainNotice(&s.unauditedNotice, hasher.SelectionNotice(), func(detail string) {
			s.progress(Progress{Phase: "toolchain-unaudited", Detail: detail})
		})
		// The construction pass reports its units too: each package's
		// listing and closure fold, the shared typed load, and every
		// memo hit that stood in for a step — the operator sees why a
		// warm pass is quick and where a cold one is.
		s.wireProgress(hasher)
	}
	// The guard reads the pass's one snapshot — the reader that took it
	// is the guard's, its directory the one every guard observation
	// captures in — never a second probe of the same pass
	// (REQ-guard-buildconfig, REQ-guard-toolchain).
	inputs := s.guardInputs()
	guardKind := kind
	if s.build.Directory != "" {
		identity, err := completeBuildEnvironment(ctx, snapshot, s.dir, s.env)
		if err != nil {
			return observationFacts{}, err
		}
		inputs = append(inputs, "gofresh/build-description@2="+identity)
		guardKind = CodeResult
	}
	// Explicit snapshots retain compilation facts only. A runtime-bound view
	// adds its independently captured measurement guards at use and comparison.
	guards, err := guard.Capture(ctx, gotool.PrimedEnvReader(s.runner, observedGuardDir(reader.Dir), s.env, snapshot), s.evidenceEnv(), guardKind, inputs...)
	if err != nil {
		return observationFacts{}, err
	}
	// One typed load serves this whole observation pass: scanViewSubjects
	// loads the view packages and every mutable-local graph package once,
	// installs the load on the hasher for the testing-type effect scan, and
	// serves version-pinned dynamic-state facts from the memo under the
	// guard-derived scope — so no two derivations of one pass can straddle
	// an edit (REQ-fresh-coherent-view). Each pass loads afresh; the paired
	// observations stay independent witnesses.
	// The analysis scope is the identity outside the source closure —
	// the strategy versions, the code guards, the attestations, the
	// vouches — set once for the pass: it arms every memo the closure
	// folds consult (the typed testing-effect scan included, without
	// which every fold would recompute the scan through a private typed
	// load) and keys the facts and the scan below
	// (REQ-closure-observability-memo, REQ-closure-testing-scan-memo,
	// REQ-closure-dynamic-state-memo, REQ-closure-scan-memo).
	scope := hasher.SetAnalysisScope(s.analysisScope(guards))
	emitFactScopeViewHook(scope.Facts())
	scan, source, cut, err := scanViewSubjects(ctx, hasher, scope, s.buildFlags, s.analysisBudget, packages...)
	if err != nil {
		return observationFacts{}, err
	}
	// One diagnostic per pass the budget cut, never one per subject —
	// the discharge's twin of the proof pass's report (REQ-fresh-progress).
	reportBudgetCut(s.progress, s.analysisBudget, len(cut), "undischarged")
	directivePure, known, openWorld, external := scan.directivePure, scan.known, scan.openWorld, scan.external
	// Subject existence is decided by the scan; refusing here, before
	// the maximal fold reads and hashes every contributing file, is
	// preparation — the fold below cannot change the answer. The
	// refusal names every unknown subject of the batch at once, so a
	// caller narrows its batch in one step (REQ-fresh-preparation).
	if err := requireSubjects(subjects, func(s Subject) bool { return known[s] }, SelectedSource); err != nil {
		return observationFacts{}, err
	}
	emitMaximalBatchViewHook()
	computed, sources, err := hasher.ComputeMaximalFactsBatch(requests)
	if err != nil {
		return observationFacts{}, err
	}
	observation := observationFacts{
		cut:                  cut,
		snapshot:             snapshot,
		reader:               reader,
		maximal:              make(map[Subject]subjectFacts, len(subjects)),
		source:               source,
		guards:               guards,
		purity:               make(map[Subject]string, len(subjects)),
		vouchDischarges:      make(map[Subject]string, len(subjects)),
		discharges:           make(map[Subject]attestationDischarges, len(subjects)),
		sourceFilesBySubject: make(map[Subject][]string, len(subjects)),
		testVariantLedgers:   make(map[string]testvariant.TestVariantLedger, len(packages)),
	}
	for _, pkg := range packages {
		// Served from the hasher's compartment memo: the ledger was derived
		// from the same reads as the compartment hash above, never a
		// re-read that could straddle an edit.
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
		// The digest comes from the Hasher's own closure reads — the exact
		// bytes the compared closure hash was built over — never a second
		// read that could straddle an edit. A source the closure's reads
		// did not digest keeps degraded attribution; detection is the
		// closure comparison's, not this naming pass's.
		if digest, ok := hasher.FileDigest(path); ok {
			observation.fileDigests[path] = digest
		}
	}
	for _, subject := range subjects {
		maximal := subjectFacts{source: computed[closure.Subject{Package: subject.Package, Symbol: subject.Symbol}]}
		// The two consumer-tier judgments — signature dynamism and
		// shared dynamic state — ran under the selection the Hasher
		// resolved, so each attributes it at its own composition, as
		// the closure tiers do at theirs; the declaration-borne refusals
		// below (ambiguous identity, the external directive) are no
		// degraded judgment and carry none (REQ-closure-refusal-channels).
		if term := openWorld[subject]; term != "" {
			maximal.openWorld = &subjectRefusal{reason: closure.AttributeSelection("subject accepts caller-supplied dynamic behavior through its "+term+" (dischargeable by bounding that type away from dynamic carriers, or by "+closure.PurityResponsibility+")", hasher.SelectionAttribution())}
		}
		if reason := scan.downgradeReason[subject]; reason != "" {
			// A culprit the budget left unjudged names the budget: the
			// reason is the record's, read long after the pass, and the
			// culprit alone would read as the program's own refusal
			// (REQ-fresh-context).
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
		if discharges := scan.vouchDischarges[subject]; discharges != "" {
			observation.vouchDischarges[subject] = discharges
		}
		if d := scan.discharges[subject]; d != (attestationDischarges{}) {
			observation.discharges[subject] = d
		}
		if detail := scan.ambiguous[subject]; detail != "" {
			// Distinct declarations collapsed onto this identity: capture
			// is refused for this subject alone — the maximal package
			// closure stays the sound floor (it spans every declaring
			// variant), but no evidence can say WHICH declaration it
			// vouches for (REQ-purity-directive).
			maximal.ambiguous = &subjectRefusal{reason: "ambiguous subject identity: " + detail + "; rename one declaration to address either"}
		}
		if external[subject] {
			// The author declared external state: unverifiable by
			// declaration, and no purity attribution is recorded — a purity
			// assertion confers nothing on an external-state subject
			// (REQ-external-directive, REQ-external-precedence).
			maximal.external = true
		}
		observation.maximal[subject] = maximal
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		observation.sourceFilesBySubject[subject] = slices.Clone(sources[request])
		sort.Strings(observation.sourceFilesBySubject[subject])
		if external[subject] {
			continue
		}
		if scan.ambiguous[subject] != "" {
			// A purity attribution names one declarer taking
			// responsibility; a collapsed identity has two, so neither a
			// caller assertion nor a directive can be attributed
			// (REQ-purity-directive, REQ-purity-responsibility).
			continue
		}
		switch caller, directive := s.assumePure(subject), directivePure(subject); {
		case caller && directive:
			observation.purity[subject] = "caller assertion and source directive"
		case caller:
			observation.purity[subject] = "caller assertion"
		case directive:
			observation.purity[subject] = "source directive"
		}
	}
	if trace.AnyEnabled() {
		for _, subject := range subjects {
			target := subject.Package + "." + subject.Symbol
			if !trace.Enabled(ctx, trace.DomainClosure, target) {
				continue
			}
			c := observation.maximal[subject].closure()
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
				trace.Int("cut_subjects", len(observation.cut)),
				trace.String("guards_toolchain", observation.guards.Toolchain),
				trace.String("guards_buildconfig", observation.guards.BuildConfig),
			)
		}
	}
	return observation, nil
}

// Capture returns subject's precomputed fingerprint from this Snapshot. Runtime-input
// evidence belongs to the producing run and is attached by the caller afterward.
func (v *Snapshot) Capture(ctx context.Context, subject Subject) (Fingerprint, error) {
	if ctx == nil {
		return Fingerprint{}, errors.New("gofresh: nil analysis context")
	}
	if v == nil || v.facts == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return Fingerprint{}, errViewSealed
	}
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	return v.fingerprintLocked(subject, v.facts.closure(subject)), nil
}

// SourceFiles returns the absolute mutable source paths whose bytes contribute
// to this view's maximal closures. The returned slice is caller-owned.
func (v *Snapshot) SourceFiles() []string {
	if v == nil || v.facts == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]string(nil), v.facts.sourceFiles...)
}

// SourceFilesFor returns the caller-owned mutable source paths contributing to
// subject's maximal closure in this view.
func (v *Snapshot) SourceFilesFor(subject Subject) ([]string, error) {
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return nil, err
	}
	return slices.Clone(v.facts.sourceFilesBySubject[subject]), nil
}

// TestVariantLedger returns the declaration ledger over subject's package
// test-variant compartment, as observed by this view: it is derived at view
// construction from the same file reads as the compartment hash the
// fingerprint records, so a caller persists it at capture and diffs it at
// check against exactly the bytes the verdict compared — never a re-read that
// could straddle a later edit (REQ-closure-test-variant-ledger,
// REQ-fresh-coherent-view). The returned value is caller-owned. A package with
// no test files yields an empty ledger.
func (v *Snapshot) TestVariantLedger(subject Subject) (TestVariantLedger, error) {
	if v == nil || v.facts == nil {
		return TestVariantLedger{}, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return TestVariantLedger{}, err
	}
	// Clone, not a shallow struct copy: declarations carry reference-list
	// slices, and a shallow copy would alias them into the view's internal
	// ledger, breaking caller ownership.
	return v.facts.testVariantLedgers[subject.Package].Clone(), nil
}

// CaptureBatch captures a fingerprint for every subject in the view,
// sharing the view's batched analysis across the set.
func (v *Snapshot) CaptureBatch(ctx context.Context) (map[Subject]Fingerprint, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return nil, errViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		cl := v.facts.closure(subject)
		result[subject] = v.fingerprintLocked(subject, cl)
	}
	return result, nil
}

// fingerprintLocked projects the view's immutable producing facts. Callers
// hold the view lock; observed capture adds its independently derived proof.
func (v *Snapshot) fingerprintLocked(subject Subject, cl closure.Closure) Fingerprint {
	d := v.facts.discharges[subject]
	return Fingerprint{
		MaximalClosure: cl.Hash, TestVariantClosure: cl.TestVariants,
		ToolchainContent: cl.ToolchainContent, AdmissionPolicy: cl.AdmissionPolicy,
		Guards: v.guards(), PurityAssertion: v.facts.purity[subject],
		DynamicStateVouches:      v.facts.vouchDischarges[subject],
		SingleSubjectDischarges:  d.singleSubject,
		PackageProcessDischarges: d.packageProcess,
		DynamicStateStrategy:     DynamicStateStrategy, ClosureStrategy: ClosureStrategy,
		ResultKind: v.kind,
	}
}

// captureObserved returns maximal closure evidence plus a caller-selected,
// attributable observation proof for subject.
func (v *Snapshot) captureObserved(ctx context.Context, subject Subject) (fp Fingerprint, opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	if err := v.ensureObservable(ctx, []Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Fingerprint{}, fmt.Errorf("gofresh: observation proof cancelled: %w", err)
	}
	if v.sealed {
		return Fingerprint{}, errViewSealed
	}
	v.capturedObserved[subject] = true
	return v.observedFingerprintLocked(subject), nil
}

// CaptureObservedBatch captures observation proof evidence for every
// subject, sharing one proof analysis across the set.
func (v *Snapshot) CaptureObservedBatch(ctx context.Context) (fps map[Subject]Fingerprint, opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	if err := v.ensureObservable(ctx, v.subjects); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gofresh: observation proof cancelled: %w", err)
	}
	if v.sealed {
		return nil, errViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		v.capturedObserved[subject] = true
		result[subject] = v.observedFingerprintLocked(subject)
	}
	return result, nil
}

func (v *Snapshot) observedFingerprintLocked(subject Subject) Fingerprint {
	disposition := v.observable[subject]
	proof := ObservationProof{
		Strategy:   ObservationRTA,
		Subject:    subject,
		Observable: disposition.Observable,
		Reason:     disposition.Reason,
	}
	const assertion = "caller assertion"
	fingerprint := v.fingerprintLocked(subject, v.facts.closure(subject))
	fingerprint.ObservationAssertion, fingerprint.ObservationProof = assertion, proof
	fingerprint.ObservationProof.Evidence = observationProofEvidenceMode(fingerprint, disposition.EffectFree)
	return fingerprint
}

// AttachObservation binds sealed, process-backed runtime evidence to a captured
// observation proof. The returned fingerprint is ready for producer validation.
func (v *Snapshot) AttachObservation(subject Subject, fingerprint Fingerprint, observation Observation) (Fingerprint, error) {
	if v == nil || v.facts == nil || v.session == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized snapshot")
	}
	return v.attachObservation(subject, fingerprint, observation, true)
}

// attachObservation checks the producing form the unit prepared. The ordinary
// form carries identity-only evidence without synthesizing an observation proof.
func (v *Snapshot) attachObservation(subject Subject, fingerprint Fingerprint, observation runtimeinput.Observation, observed bool) (Fingerprint, error) {
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		return Fingerprint{}, err
	}
	return v.attachRuntimeState(subject, fingerprint, &state, observed)
}

// attachRuntimeState validates the exact prepared fingerprint even when no
// observation was selected. Nil state supplies no runtime evidence or assertion.
func (v *Snapshot) attachRuntimeState(subject Subject, fingerprint Fingerprint, state *runtimeinput.State, observed bool) (Fingerprint, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return Fingerprint{}, errViewSealed
	}
	if err := v.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	want := v.fingerprintLocked(subject, v.facts.closure(subject))
	if observed {
		want = v.observedFingerprintLocked(subject)
	}
	if (observed && !v.capturedObserved[subject]) || fingerprint != want {
		return Fingerprint{}, errors.New("gofresh: observation does not match captured subject proof")
	}
	if state == nil {
		return fingerprint, nil
	}
	if _, attached := v.attachedObservations[subject]; attached {
		return Fingerprint{}, errors.New("gofresh: runtime observation already attached for subject")
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	v.attachedObservations[subject] = *state
	return fingerprint, nil
}

// Check compares recorded against subject's current facts under this Snapshot's
// result kind and the caller's context. Under a deferred-close engine the
// verdict is provisional until the view validates (withDeferredCheckClose).
func (v *Snapshot) Check(ctx context.Context, recorded Fingerprint, subject Subject) (Verdict, error) {
	verdicts, err := v.CheckBatch(ctx, map[Subject]Fingerprint{subject: recorded})
	if err != nil {
		return Verdict{}, err
	}
	return verdicts[subject], nil
}

// CheckBatch checks a caller-supplied recording set under the shared
// evidence ladder (REQ-fresh-hierarchical-check). Under a deferred-close
// engine the verdicts are provisional until the view validates
// (withDeferredCheckClose).
func (v *Snapshot) CheckBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	if v == nil || v.facts == nil || v.session == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	return v.checkMap(ctx, recorded, false, v.session.deferredCheckClose)
}

// CheckObserved explicitly checks a fingerprint under its recorded observation
// assertion and proof. Ordinary Check never infers this policy from evidence.
// A persisted inert endpoint retains original support and requires the current
// proof and outcome inventory when observation is needed to establish validity.
// It is the single-record form of CheckObservedBatch, so both share one window
// semantics: a runtime input moving mid-check stales a record whose verdict is
// not already stale, and demonstrated staleness is preferred over
// unverifiability. Under a deferred-close engine the verdict is
// provisional until the view validates (withDeferredCheckClose).
func (v *Snapshot) CheckObserved(ctx context.Context, recorded Fingerprint, subject Subject) (verdict Verdict, opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return Verdict{}, errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	verdicts, err := v.CheckObservedBatch(ctx, map[Subject]Fingerprint{subject: recorded})
	if err != nil {
		return Verdict{}, err
	}
	return verdicts[subject], nil
}

// CheckObservedBatch checks a caller-supplied recording set under the explicit
// observed policy, sharing one drift bracket pair, one runtime-input
// observation window, and one drift-forced precise analysis across the set.
// Every subject's verdict equals a single CheckObserved of its recording over
// the same view; an unavailable shared analysis degrades only the drifted
// subjects, and caller cancellation returns the context error. Under a
// deferred-close engine the verdicts are provisional until the view
// validates (withDeferredCheckClose).
func (v *Snapshot) CheckObservedBatch(ctx context.Context, recorded map[Subject]Fingerprint) (verdicts map[Subject]Verdict, opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	return v.checkMap(ctx, recorded, true, v.session.deferredCheckClose)
}

func (v *Snapshot) purityMatches(recorded Fingerprint, subject Subject) PurityAuthority {
	return PurityAuthority{Recorded: purityAttribution(recorded.PurityAssertion), Current: purityAttribution(v.facts.purity[subject])}
}

func (v *Snapshot) currentRuntimeContext(ctx context.Context, recorded Fingerprint, shared map[string]runtimeinput.State) (runtimeinput.State, error) {
	if err := ctx.Err(); err != nil {
		return runtimeinput.State{}, err
	}
	var rt runtimeinput.State
	var err error
	if recorded.RuntimeInputs != "" {
		// An unevaluable runtime-input guard is absence of proof: Stale, never
		// valid (REQ-guard-completeness).
		current := v.runtimeCheck()
		if cached, ok := shared[recorded.RuntimeInputs]; ok {
			return cached, nil
		}
		if rt, err = current(ctx, recorded.RuntimeInputs, v.evidenceRoot()); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return runtimeinput.State{}, contextErr
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return runtimeinput.State{}, err
			}
			rt = runtimeinput.State{}
		}
		if err := ctx.Err(); err != nil {
			return runtimeinput.State{}, err
		}
		shared[recorded.RuntimeInputs] = rt
	}
	return rt, nil
}

// Validate re-observes the Snapshot's complete subject set under the caller's
// context and reports ErrViewChanged when any source closure, guard, or purity
// assertion moved. A producer calls it after execution before persisting
// results (REQ-fresh-producer-view). Selected applicability checks are also
// re-established, including their historical runtime evidence and any current
// proof needed for an observation lift; they require no new process receipt.
func (v *Snapshot) Validate(ctx context.Context) (opErr error) {
	if v == nil || v.facts == nil || v.session == nil {
		return errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	v.mu.Lock()
	v.sealed = true
	hasObserved := len(v.capturedObserved) != 0
	hasApplicability := len(v.applicabilityChecks) != 0
	identities := make(map[Subject]runtimeinput.State)
	var identitySubjects []Subject
	for _, subject := range v.subjects {
		if state, attached := v.attachedObservations[subject]; attached && !v.capturedObserved[subject] {
			identities[subject] = state
			identitySubjects = append(identitySubjects, subject)
		}
	}
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Identity-only attachments select no proof, but their runtime span still
	// closes after source comparison. A concrete input move outranks a cut.
	if len(identitySubjects) != 0 {
		defer func() {
			if opErr == nil || errors.Is(opErr, ErrAnalysisUnavailable) {
				if err := v.compareAttachedObservations(ctx, identities, identitySubjects); err != nil {
					opErr = err
				}
			}
		}()
	}
	// The view validates whatever it captured: observation proofs pull
	// in the observed arm, and a maximal-only producer the base
	// comparison - the engine owns the dispatch exactly as it owns the
	// capture strategy.
	if hasObserved || hasApplicability {
		var unavailable error
		if hasObserved {
			if err := deferValidationUnavailability(v.validateObserved(ctx), &unavailable); err != nil {
				return err
			}
		}
		if hasApplicability {
			if err := deferValidationUnavailability(v.validateApplicabilityChecks(ctx), &unavailable); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return unavailable
	}
	// A comparison-only observation reads once: these facts are never
	// recorded, so a torn read can only compare unequal and refuse - the
	// safe direction - while an equal torn read is the contract-excluded
	// restore interval (REQ-fresh-coherent-view's record/compare
	// asymmetry). The agreement pair is load-bearing exactly where an
	// observation becomes the record: view construction.
	observation, err := v.observe(ctx)
	if err != nil {
		return err
	}
	if err := v.compareObservationContext(ctx, observation); err != nil {
		return err
	}
	return ctx.Err()
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

// Sibling derives a view over a subset of this view's subjects that
// shares this view's single observation: every fact the sibling serves —
// closures, guards, purity, source identities, digests, ledgers, analysis cuts, and
// captured observation proofs — is the parent's, so no generation can
// mix (REQ-fresh-coherent-view), and the guards remain the family's one
// capture (REQ-guard-view-lifetime). What the sibling owns is its
// producer transaction: fresh runtime-observation attachment state and
// its own validation seal, so a caller running one producer transaction
// per measured subset — a mutation campaign's per-target attach and
// validate cycles — pays the expensive observation once. Validation on
// a sibling re-observes the tree for comparison exactly as on any view;
// only the recorded facts are shared. Every requested subject must
// belong to the parent view. A sealed parent still derives — the
// sibling's own validation is its drift gate, and the facts are
// construction-time either way. Inherited captured-proof flags commit
// the sibling to the observed validation arm: a sibling of an observed
// parent validates through attachment, exactly as the parent would.
// Applicability checks for the subset are inherited as separate validation
// obligations over historical records, never as producing attachments.
func (v *Snapshot) Sibling(subjects []Subject) (*Snapshot, error) {
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(subjects) == 0 {
		return nil, errors.New("gofresh: sibling view requires at least one subject")
	}
	parent := make(map[Subject]bool, len(v.subjects))
	for _, subject := range v.subjects {
		parent[subject] = true
	}
	if err := requireSubjects(subjects, func(s Subject) bool { return parent[s] }, ParentView); err != nil {
		return nil, err
	}
	unique, requests, packages, err := scopeSubjects(subjects)
	if err != nil {
		return nil, err
	}
	// The narrowed union follows the observation's own recipe (sorted
	// unique union of the subset's per-subject identities), so a
	// validation-time observation over the subset compares equal on an
	// unchanged tree.
	sourceFilesBySubject := make(map[Subject][]string, len(unique))
	maximal := make(map[Subject]subjectFacts, len(unique))
	observable := make(map[Subject]closure.Observability, len(unique))
	purity := make(map[Subject]string, len(unique))
	vouchDischarges := make(map[Subject]string, len(unique))
	discharges := make(map[Subject]attestationDischarges, len(unique))
	cut := make(map[Subject]bool, len(unique))
	capturedObserved := make(map[Subject]bool, len(unique))
	ledgers := make(map[string]testvariant.TestVariantLedger, len(packages))
	groups := make([][]string, 0, len(unique))
	for _, subject := range unique {
		sourceFilesBySubject[subject] = v.facts.sourceFilesBySubject[subject]
		groups = append(groups, v.facts.sourceFilesBySubject[subject])
		if contribution, ok := v.facts.maximal[subject]; ok {
			maximal[subject] = contribution
		}
		if proof, ok := v.observable[subject]; ok {
			observable[subject] = proof
		}
		if assertion, ok := v.facts.purity[subject]; ok {
			purity[subject] = assertion
		}
		if dischargesVal, ok := v.facts.vouchDischarges[subject]; ok {
			vouchDischarges[subject] = dischargesVal
		}
		if d, ok := v.facts.discharges[subject]; ok {
			discharges[subject] = d
		}
		if v.facts.cut[subject] {
			cut[subject] = true
		}
		if v.capturedObserved[subject] {
			capturedObserved[subject] = true
		}
	}
	sourceFiles := sortedUniqueUnion(groups)
	for _, pkg := range packages {
		if ledger, ok := v.facts.testVariantLedgers[pkg]; ok {
			ledgers[pkg] = ledger
		}
	}
	var applicabilityChecks []applicabilityCheck
	for _, check := range v.applicabilityChecks {
		if _, ok := maximal[check.subject]; ok {
			applicabilityChecks = append(applicabilityChecks, check)
		}
	}
	return &Snapshot{
		session:   v.session,
		runtime:   v.runtime,
		subjects:  unique,
		requests:  requests,
		packages:  packages,
		moduleDir: v.moduleDir,
		kind:      v.kind,
		facts: &observationFacts{
			snapshot:             v.facts.snapshot,
			reader:               v.facts.reader,
			maximal:              maximal,
			source:               v.facts.source,
			guards:               v.facts.guards,
			purity:               purity,
			vouchDischarges:      vouchDischarges,
			discharges:           discharges,
			cut:                  cut,
			sourceFiles:          sourceFiles,
			sourceFilesBySubject: sourceFilesBySubject,
			fileDigests:          v.facts.fileDigests,
			testVariantLedgers:   ledgers,
		},
		observable:           observable,
		capturedObserved:     capturedObserved,
		applicabilityChecks:  applicabilityChecks,
		attachedObservations: make(map[Subject]runtimeinput.State, len(unique)),
		runtimeCurrent:       v.runtimeCurrent,
	}, nil
}

// newSeededValidationView builds the validation arm's view from one fresh
// observation: the current tree is read once and compared against the
// producer view's captured facts — refusal on any drift — and on agreement
// the captured facts seed the validation view directly. The seeded facts
// rest on a genuine agreement pair whose reads span capture time and
// validation time, so they are record-grade without a second construction
// pair (REQ-fresh-coherent-view's record/compare asymmetry).
func (v *Snapshot) newSeededValidationView(ctx context.Context) (*Snapshot, error) {
	observation, err := v.observe(ctx)
	if err != nil {
		return nil, err
	}
	if err := v.holdCutUnavailable(v.compareObservationContext(ctx, observation)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	current := &Snapshot{
		session:              v.session,
		runtime:              v.runtime,
		runtimeCurrent:       v.runtimeCurrent,
		subjects:             v.subjects,
		requests:             v.requests,
		packages:             v.packages,
		moduleDir:            v.moduleDir,
		kind:                 v.kind,
		facts:                v.facts,
		observable:           make(map[Subject]closure.Observability, len(v.subjects)),
		capturedObserved:     make(map[Subject]bool, len(v.subjects)),
		attachedObservations: make(map[Subject]runtimeinput.State, len(v.subjects)),
	}
	return current, nil
}

// validateObserved re-establishes every captured observation proof and
// attached runtime state.
func (v *Snapshot) validateObserved(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil observation validation context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Preparation: what the validation needs from the sealed view is
	// known before any re-observation — a proof-less view or a subject
	// with no completed observation attached refuses here, never after a
	// full observation pass has been paid.
	v.mu.RLock()
	subjects := make([]Subject, 0, len(v.capturedObserved))
	expected := make(map[Subject]closure.Observability, len(v.capturedObserved))
	attached := make(map[Subject]runtimeinput.State, len(v.capturedObserved))
	for _, subject := range v.subjects {
		if v.capturedObserved[subject] {
			subjects = append(subjects, subject)
			expected[subject] = v.observable[subject]
			attached[subject] = v.attachedObservations[subject]
		}
	}
	v.mu.RUnlock()
	if len(subjects) == 0 {
		return errors.New("gofresh: no captured observation proof")
	}
	if err := requireCompletedAttachments(attached, subjects); err != nil {
		return err
	}
	current, err := v.newSeededValidationView(ctx)
	if err != nil {
		return err
	}
	if err := v.compareAttachedObservations(ctx, attached, subjects); err != nil {
		return err
	}
	if err := current.ensureObservable(ctx, subjects); err != nil {
		return err
	}
	current.mu.RLock()
	var unavailable error
	for _, subject := range subjects {
		err := compareObservationProof(subject, current.observable[subject], expected[subject])
		switch {
		case err == nil:
		case errors.Is(err, ErrAnalysisUnavailable):
			// Held, not returned: the closing runtime-input comparison
			// below still runs, so an unavailable re-establishment is
			// reported only when nothing else moved — the disposition
			// under which a caller records the run's outcomes as
			// unverifiable evidence (ErrAnalysisUnavailable's contract).
			if unavailable == nil {
				unavailable = err
			}
		default:
			// The conservative arm, kept by construction rather than
			// by witness: within one coherent validation the captured
			// proofs are this view's own over sources the seeded view
			// just re-observed, so an analyzed proof that changed has
			// no reachable path — a drift here would be the analysis's
			// own nondeterminism, refused at once.
			current.mu.RUnlock()
			return err
		}
	}
	current.mu.RUnlock()
	if err := v.compareAttachedObservations(ctx, attached, subjects); err != nil {
		return err
	}
	// The held cut-explained unavailability — the seeded view's
	// re-observation or the closing pass — is reported last, after the
	// closing runtime-input comparison, exactly as the proof's.
	return v.resolveValidationUnavailable(ctx, current, unavailable)
}

// Unavailability is a verdict only after all other validation obligations have
// closed. A concrete fault or cancellation always outranks a held cut.
func deferValidationUnavailability(err error, unavailable *error) error {
	if errors.Is(err, ErrAnalysisUnavailable) {
		if *unavailable == nil {
			*unavailable = err
		}
		return nil
	}
	return err
}

func (v *Snapshot) resolveValidationUnavailable(ctx context.Context, current *Snapshot, unavailable error) error {
	for _, held := range []*Snapshot{v, current} {
		held.mu.RLock()
		cut := held.cutUnavailable
		held.mu.RUnlock()
		if err := deferValidationUnavailability(cut, &unavailable); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return unavailable
}

func (v *Snapshot) closeValidationReobservation(ctx context.Context, current *Snapshot, unavailable error) error {
	if err := deferValidationUnavailability(current.reobserveBase(ctx), &unavailable); err != nil {
		return err
	}
	return v.resolveValidationUnavailable(ctx, current, unavailable)
}

// holdCutUnavailable keeps a comparison's cut-explained unavailability on
// the view and reports nil for it, so the caller continues; every other
// error is returned as is.
func (v *Snapshot) holdCutUnavailable(err error) error {
	if err == nil || !errors.Is(err, ErrAnalysisUnavailable) {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cutUnavailable == nil {
		v.cutUnavailable = err
	}
	return nil
}

// compareObservationProof re-establishes one captured observation disposition
// against the post-execution analysis. Unavailable analysis is compared by
// class, never by error text: a re-establishment the current analysis cannot
// perform is an availability failure, not evidence of drift, and an
// unavailable captured proof — which confers nothing whatever the current
// analysis says — is consistent with any current disposition.
func compareObservationProof(subject Subject, observed, captured closure.Observability) error {
	if analysisUnavailable(captured.Reason) {
		return nil
	}
	if analysisUnavailable(observed.Reason) {
		return fmt.Errorf("%w: observation proof for %s.%s: %s", ErrAnalysisUnavailable, subject.Package, subject.Symbol, observed.Reason)
	}
	if observed != captured {
		return fmt.Errorf("%w: observation proof for %s.%s (captured %s, now %s)", ErrViewChanged, subject.Package, subject.Symbol, describeObservability(captured), describeObservability(observed))
	}
	return nil
}

// budgetExhausted is the one spelling of an exhausted analysis budget,
// read by the cut proof's reason and the pass's diagnostic alike.
func budgetExhausted(budget time.Duration) string {
	return "analysis budget " + budget.String() + " exhausted"
}

// countNoun renders a count with its noun, pluralized past one.
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// keptOnCancelDetail renders a cancelled operation's kept-on-cancel
// report: what the passes persisted before the cancellation, so a
// rerun's served set is known (REQ-fresh-progress).
func keptOnCancelDetail(proofs, scans int) string {
	return countNoun(proofs, "observability proof slice") + " and " + countNoun(scans, "scan") + " persisted this operation; a rerun serves them"
}

// unavailableReason composes an unavailable observability disposition
// from its cause — the one spelling of the prefix in this package;
// the closure analysis composes the same prefix at its own refusal
// sites (closure/observability.go), which analysisUnavailable
// recognizes alike.
func unavailableReason(cause string) string {
	return analysisUnavailablePrefix + ": " + cause
}

const analysisUnavailablePrefix = "observation analysis unavailable"

// analysisUnavailable reports whether an observability disposition records
// analysis unavailability rather than an analyzed rejection. The prefix is the
// one vocabulary both the closure analysis and the isolation fallback emit.
func analysisUnavailable(reason string) bool {
	return strings.HasPrefix(reason, analysisUnavailablePrefix)
}

// movedIdentitySuffix names the source identities behind a drift
// refusal, best-effort: membership changes name added and removed
// paths exactly; content drift names paths whose construction-time
// digests disagree. An empty diff (a change-and-restore, or a digest
// the capture could not read) keeps the bare refusal - naming is
// advisory, detection is the comparison itself
// (REQ-fresh-producer-view's naming arm).
func movedIdentitySuffix(captured, current []string, capturedDigests, currentDigests map[string]string) string {
	capturedSet := make(map[string]bool, len(captured))
	for _, path := range captured {
		capturedSet[path] = true
	}
	currentSet := make(map[string]bool, len(current))
	for _, path := range current {
		currentSet[path] = true
	}
	var moved []string
	for _, path := range captured {
		if !currentSet[path] {
			moved = append(moved, "removed "+path)
		}
	}
	for _, path := range current {
		if !capturedSet[path] {
			moved = append(moved, "added "+path)
		}
	}
	for _, path := range captured {
		if !currentSet[path] {
			continue
		}
		was, hasWas := capturedDigests[path]
		now, hasNow := currentDigests[path]
		if hasWas && hasNow && was != now {
			moved = append(moved, "changed "+path)
		}
	}
	if len(moved) == 0 {
		return ""
	}
	sort.Strings(moved)
	return " (moved: " + render.CappedList(moved) + ")"
}

// differingGuard names the first environment guard whose two construction
// observations disagreed — the actionable component behind a bare "guards
// moved".
func differingGuard(a, b guard.Guards) string {
	switch {
	case a.Toolchain != b.Toolchain:
		return "toolchain"
	case a.BuildConfig != b.BuildConfig:
		return "buildconfig"
	case a.Machine != b.Machine:
		return "machine"
	case a.RuntimeConfig != b.RuntimeConfig:
		return "runtimeconfig"
	default:
		return "guards"
	}
}

// describeObservability renders an observability disposition for drift
// refusals: the verdict class and its reason, compact.
func describeObservability(o closure.Observability) string {
	if o.Observable {
		return "observable"
	}
	if o.Reason == "" {
		return "not observable"
	}
	return "not observable: " + o.Reason
}

// movedInputsForView attributes against the view's own environment, degrading
// to no attribution on an engine-less view (the direct-construct test shape).
func movedInputsForView(ctx context.Context, v *Snapshot, encoded string) ([]string, error) {
	if v.session == nil {
		return nil, nil
	}
	return runtimeinput.MovedInputs(ctx, encoded, v.evidenceRoot(), v.evidenceEnv())
}

// runtimeCheck is the view's one runtime-input check: the injected seam
// where a test set one, else its bound runtime or session environment, else — on
// a session-less view, the direct-construct test shape — the ambient
// environment.
func (v *Snapshot) runtimeCheck() func(context.Context, string, string) (runtimeinput.State, error) {
	if v.runtimeCurrent != nil {
		return v.runtimeCurrent
	}
	return func(ctx context.Context, encoded, root string) (runtimeinput.State, error) {
		env := os.Environ()
		if v.session != nil {
			env = v.evidenceEnv()
		}
		return runtimeinput.Current(ctx, encoded, root, env)
	}
}

// observedGuardDir is the directory a guard observation captures in —
// the pass reader's, where its one snapshot was taken — passed through
// the test hook that pins it to the module directory.
func observedGuardDir(dir string) string {
	emitGuardDirViewHook(dir)
	return dir
}

// evidenceRoot is the root this view re-hashes runtime-input identities
// under: the session's declared evidence root, else the view's module
// directory (a session-less view has only the latter).
func (v *Snapshot) evidenceRoot() string {
	if v.session == nil {
		return v.moduleDir
	}
	return v.session.evidenceRootFor(v.moduleDir)
}

// withMovedInputs names the movers behind a stale runtime-inputs verdict
// (REQ-inputs-path-identities attribution): the one-word reason stays for
// undecodable or moverless manifests — an older recording regenerates either
// way — and gains "(moved: …)" whenever attribution is derivable.
func (v *Snapshot) withMovedInputs(ctx context.Context, verdict Verdict, recorded Fingerprint) Verdict {
	if verdict.Status != Stale || verdict.Ground.Cause.Kind != RuntimeInputsCause || recorded.RuntimeInputs == "" || v.session == nil {
		return verdict
	}
	movers, err := movedInputsForView(ctx, v, recorded.RuntimeInputs)
	if err != nil || len(movers) == 0 {
		return verdict
	}
	verdict.Reason = "runtimeinputs (moved: " + render.CappedList(movers) + ")"
	return verdict
}

// requireCompletedAttachments is the one statement of what a validation
// needs attached per subject — a completed observation with its manifest
// and digest — shared by the preparation check and the comparison so the
// two cannot drift.
func requireCompletedAttachments(attached map[Subject]runtimeinput.State, subjects []Subject) error {
	for _, subject := range subjects {
		if state := attached[subject]; !state.OK || state.Manifest == "" || state.Digest == "" {
			return fmt.Errorf("gofresh: subject %s.%s has no attached completed observation", subject.Package, subject.Symbol)
		}
	}
	return nil
}

func (v *Snapshot) compareAttachedObservations(ctx context.Context, attached map[Subject]runtimeinput.State, subjects []Subject) error {
	// One evaluation per distinct encoded manifest per pass: the observed
	// state is a function of (manifest, module, env) alone, so subjects
	// sharing a manifest share it - the same amplification collapse the
	// check window carries, on the producer path. The memo is per-call
	// on purpose: the second validation pass must re-evaluate to prove
	// the inputs stable across the re-analysis window.
	if err := requireCompletedAttachments(attached, subjects); err != nil {
		return err
	}
	observedByManifest := map[string]runtimeinput.State{}
	for _, subject := range subjects {
		state := attached[subject]
		observed, evaluated := observedByManifest[state.Manifest]
		if !evaluated {
			var err error
			observed, err = v.runtimeCheck()(ctx, state.Manifest, v.evidenceRoot())
			if err != nil {
				return err
			}
			observedByManifest[state.Manifest] = observed
		}
		if observed != state {
			detail := ""
			if movers, moveErr := movedInputsForView(ctx, v, state.Manifest); moveErr == nil && len(movers) > 0 {
				detail = " (moved: " + render.CappedList(movers) + ")"
			}
			return fmt.Errorf("%w: runtime inputs for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, detail)
		}
	}
	return ctx.Err()
}

// closeCheckWindow closes one check's runtime-input window: the base
// re-observation proves the tree stable across the window's reads. A
// deferred-close engine skips it — the view's validation is the one
// close for every deferred interval (REQ-fresh-coherent-view's deferred
// close) — and a window that read no runtime inputs has nothing to
// close.
func (v *Snapshot) closeCheckWindow(ctx context.Context, hasRuntimeInputs, deferClose bool) error {
	if hasRuntimeInputs && !deferClose {
		return v.reobserveBase(ctx)
	}
	return nil
}

// reobserveBase detects source, guard, or purity drift since view construction
// with one fresh observation compared against the constructing view. This
// provides the same ordinary-drift guarantee as a full double-observed view per
// side: any change persisting to an observation is caught, while a
// mutation-and-restore interval between agreeing observations is not guaranteed
// detectable under either shape (REQ-inputs-observation-coherence).
func (v *Snapshot) reobserveBase(ctx context.Context) error {
	observation, err := v.observe(ctx)
	if err != nil {
		return err
	}
	return v.compareObservationContext(ctx, observation)
}

// guards composes the immutable capture without putting execution-specific facts
// in the shared source/build generation.
func (v *Snapshot) guards() guard.Guards {
	g := v.facts.guards
	if v.runtime != nil {
		g.Machine, g.RuntimeConfig = v.runtime.guards.Machine, v.runtime.guards.RuntimeConfig
	}
	return g
}

func (v *Snapshot) evidenceEnv() []string {
	if v.runtime != nil {
		return v.runtime.env
	}
	return v.session.evidenceEnv()
}

// observe is the single comparison-pass entry for closing, seeded validation,
// runtime windows and precise-analysis refinement. It observes compilation under
// the session and runtime guards under the view's immutable binding. The composed
// result is comparison-only; it never replaces shared source facts.
func (v *Snapshot) observe(ctx context.Context) (observationFacts, error) {
	facts, err := v.session.observeView(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind)
	if err != nil {
		return observationFacts{}, err
	}
	if v.runtime != nil {
		runtime, err := v.runtime.observe(ctx, v.kind)
		if err != nil {
			return observationFacts{}, err
		}
		facts.guards.Machine, facts.guards.RuntimeConfig = runtime.Machine, runtime.RuntimeConfig
	}
	return facts, nil
}

func (v *Snapshot) compareObservationContext(ctx context.Context, observation observationFacts) error {
	return compareObservations(ctx, v.subjects, v.facts, v.guards(), observation, false)
}

// takeCut adopts the other observation's fail-closed shape for a subject
// it cut: the undischarged downgrade and the absent discharges.
func (f *observationFacts) takeCut(other observationFacts, subject Subject) {
	base := f.maximal[subject]
	base.sharedState = other.maximal[subject].sharedState
	f.maximal[subject] = base
	delete(f.discharges, subject)
	if f.cut == nil {
		f.cut = map[Subject]bool{}
	}
	f.cut[subject] = true
}

// analysisBound derives the analysis context a precise-analysis phase
// runs under: the operation's own when the budget is zero, a child with
// the budget's deadline otherwise (REQ-fresh-context). The cancel is the
// caller's to defer.
func analysisBound(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return ctx, func() {}
	}
	if boundCtx, cancel, ok := runAnalysisBoundViewHook(ctx, budget); ok {
		return boundCtx, cancel
	}
	return context.WithTimeout(ctx, budget)
}

// reportBudgetCut reports one pass's cut — once, with the count of
// subjects the budget left in the named state — on the progress sink;
// a pass that cut nothing reports nothing (REQ-fresh-progress).
func reportBudgetCut(progress func(Progress), budget time.Duration, cut int, state string) {
	if cut == 0 || progress == nil {
		return
	}
	progress(Progress{Phase: "budget-exhausted", Detail: budgetExhausted(budget) + ": " + countNoun(cut, "subject") + " " + state})
}

// compareObservations compares two observation passes for either paired view
// construction (construction == true) or post-construction drift validation
// (construction == false). Post-construction comparison deliberately omits the
// vouch-discharge map: those discharges derive from version-pinned packages'
// facts under the engine's fixed vouch set, and pinned source cannot move
// without the guard and closure movement the other comparisons already refuse
// (construction's paired observations still compare discharges directly, where
// no such immutability argument is available).
func compareObservations(ctx context.Context, subjects []Subject, base *observationFacts, baseGuards guard.Guards, current observationFacts, construction bool) error {
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	during := ""
	if construction {
		during = " during construction"
	}
	if current.guards != baseGuards {
		if err := ctx.Err(); err != nil {
			return err
		}
		if trace.Enabled(ctx, trace.DomainView, "") {
			trace.Emit(ctx, trace.DomainView, "two_pass_diff", "",
				trace.String("diff_field", "guards"),
				trace.String("first_value", fmt.Sprintf("%+v", baseGuards)),
				trace.String("second_value", fmt.Sprintf("%+v", current.guards)),
			)
		}
		return fmt.Errorf("%w: guards%s (%s)", ErrViewChanged, during, differingGuard(current.guards, baseGuards))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !construction && !slices.Equal(current.sourceFiles, base.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if trace.Enabled(ctx, trace.DomainView, "") {
			trace.Emit(ctx, trace.DomainView, "two_pass_diff", "",
				trace.String("diff_field", "source_files"),
				trace.Strings("first_value", base.sourceFiles),
				trace.Strings("second_value", current.sourceFiles),
			)
		}
		return fmt.Errorf("%w: maximal source identities%s", ErrViewChanged, movedIdentitySuffix(base.sourceFiles, current.sourceFiles, base.fileDigests, current.fileDigests))
	}
	var unjudged []Subject
	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !construction && !slices.Equal(current.sourceFilesBySubject[subject], base.sourceFilesBySubject[subject]) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if trace.AnyEnabled() {
				target := subject.Package + "." + subject.Symbol
				if trace.Enabled(ctx, trace.DomainView, target) {
					trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
						trace.String("diff_field", "subject_source_files"),
						trace.String("subject", target),
						trace.Strings("first_value", base.sourceFilesBySubject[subject]),
						trace.Strings("second_value", current.sourceFilesBySubject[subject]),
					)
				}
			}
			return fmt.Errorf("%w: maximal source identities for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject], base.fileDigests, current.fileDigests))
		}
		// A budget cut in either observation compares with the
		// discharge-shaped fields cleared; during construction the view
		// adopts the cut pass's fail-closed shape, while post-construction
		// comparison reports a difference those fields alone carry as
		// analysis unavailability after every other comparison holds
		// (REQ-fresh-context).
		cutHere := current.cut[subject] || base.cut[subject]
		if !current.maximal[subject].equal(base.maximal[subject], cutHere) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if trace.AnyEnabled() {
				target := subject.Package + "." + subject.Symbol
				if trace.Enabled(ctx, trace.DomainView, target) {
					diffField, firstVal, secondVal := diffSubjectFacts(base.maximal[subject], current.maximal[subject], cutHere)
					trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
						trace.String("diff_field", diffField),
						trace.String("subject", target),
						trace.String("first_value", firstVal),
						trace.String("second_value", secondVal),
					)
				}
			}
			return fmt.Errorf("%w: closure for %s.%s%s%s", ErrViewChanged, subject.Package, subject.Symbol, during, movedIdentitySuffix(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject], base.fileDigests, current.fileDigests))
		}
		if !construction && cutHere && !current.maximal[subject].equal(base.maximal[subject], false) {
			unjudged = append(unjudged, subject)
		}
		if current.purity[subject] != base.purity[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			if trace.AnyEnabled() {
				target := subject.Package + "." + subject.Symbol
				if trace.Enabled(ctx, trace.DomainView, target) {
					trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
						trace.String("diff_field", "purity"),
						trace.String("subject", target),
						trace.String("first_value", base.purity[subject]),
						trace.String("second_value", current.purity[subject]),
					)
				}
			}
			return fmt.Errorf("%w: purity for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, during)
		}
		if construction {
			if base.vouchDischarges[subject] != current.vouchDischarges[subject] {
				if err := ctx.Err(); err != nil {
					return err
				}
				if trace.AnyEnabled() {
					target := subject.Package + "." + subject.Symbol
					if trace.Enabled(ctx, trace.DomainView, target) {
						trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
							trace.String("diff_field", "vouch_discharges"),
							trace.String("subject", target),
							trace.String("first_value", base.vouchDischarges[subject]),
							trace.String("second_value", current.vouchDischarges[subject]),
						)
					}
				}
				return fmt.Errorf("%w: vouch discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if !cutHere && base.discharges[subject].singleSubject != current.discharges[subject].singleSubject {
				if err := ctx.Err(); err != nil {
					return err
				}
				if trace.AnyEnabled() {
					target := subject.Package + "." + subject.Symbol
					if trace.Enabled(ctx, trace.DomainView, target) {
						trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
							trace.String("diff_field", "single_subject_discharges"),
							trace.String("subject", target),
							trace.String("first_value", base.discharges[subject].singleSubject),
							trace.String("second_value", current.discharges[subject].singleSubject),
						)
					}
				}
				return fmt.Errorf("%w: single-subject attestation discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if !cutHere && base.discharges[subject].packageProcess != current.discharges[subject].packageProcess {
				if err := ctx.Err(); err != nil {
					return err
				}
				if trace.AnyEnabled() {
					target := subject.Package + "." + subject.Symbol
					if trace.Enabled(ctx, trace.DomainView, target) {
						trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
							trace.String("diff_field", "package_process_discharges"),
							trace.String("subject", target),
							trace.String("first_value", base.discharges[subject].packageProcess),
							trace.String("second_value", current.discharges[subject].packageProcess),
						)
					}
				}
				return fmt.Errorf("%w: package-process attestation discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if current.cut[subject] && !base.cut[subject] {
				base.takeCut(current, subject)
			}
			if !slices.Equal(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject]) {
				if err := ctx.Err(); err != nil {
					return err
				}
				if trace.AnyEnabled() {
					target := subject.Package + "." + subject.Symbol
					if trace.Enabled(ctx, trace.DomainView, target) {
						trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
							trace.String("diff_field", "subject_source_files"),
							trace.String("subject", target),
							trace.Strings("first_value", base.sourceFilesBySubject[subject]),
							trace.Strings("second_value", current.sourceFilesBySubject[subject]),
						)
					}
				}
				return fmt.Errorf("%w: maximal source identities for %s.%s during construction%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject], base.fileDigests, current.fileDigests))
			}
		}
	}
	if construction && !slices.Equal(base.sourceFiles, current.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if trace.Enabled(ctx, trace.DomainView, "") {
			trace.Emit(ctx, trace.DomainView, "two_pass_diff", "",
				trace.String("diff_field", "source_files"),
				trace.Strings("first_value", base.sourceFiles),
				trace.Strings("second_value", current.sourceFiles),
			)
		}
		// The construction race is the one refusal with no reproduction
		// path afterward, so naming here matters most.
		return fmt.Errorf("%w: maximal source identities during construction%s", ErrViewChanged, movedIdentitySuffix(base.sourceFiles, current.sourceFiles, base.fileDigests, current.fileDigests))
	}
	if len(unjudged) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: the dynamic-state discharge for %s was cut by the analysis budget (%s)", ErrAnalysisUnavailable, countNoun(len(unjudged), "subject"), subjectNames(unjudged))
	}
	return ctx.Err()
}

// subjectNames spells subjects for a refusal, bounded at four.
func subjectNames(subjects []Subject) string {
	var names []string
	for i, s := range subjects {
		if i == 4 {
			names = append(names, fmt.Sprintf("+%d more", len(subjects)-i))
			break
		}
		names = append(names, s.Package+"."+s.Symbol)
	}
	return strings.Join(names, ", ")
}

// ensureObservable runs the drift-forced observability proof for subjects
// not yet computed, inside one single-observation drift bracket pair and
// over one shared closure Hasher
// (REQ-fresh-coherent-view attribution; equivalence per
// REQ-closure-observability-batch-equivalence).
func (v *Snapshot) ensureObservable(ctx context.Context, subjects []Subject) (err error) {
	if ctx == nil {
		return errors.New("gofresh: nil precise-analysis context")
	}
	var hasher *closure.Hasher
	defer func() { accountPass(ctx, hasher) }()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	v.mu.RLock()
	observableRequests := make([]closure.Subject, 0, len(subjects))
	for _, subject := range subjects {
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		if _, ok := v.observable[subject]; !ok {
			observableRequests = append(observableRequests, request)
		}
	}
	v.mu.RUnlock()
	if len(observableRequests) == 0 {
		return nil
	}
	if v.beforePreciseAnalysis != nil {
		v.beforePreciseAnalysis()
	}
	// The bracket opens on the view's own agreed facts: any change since
	// construction that persists to the closing observation refuses there,
	// so a separate opening observation bought only earlier refusal on a
	// dirty tree at the price of one pass on every clean one
	// (REQ-fresh-coherent-view: the pair is load-bearing where facts
	// become the record; the bracket only compares).
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	emitSnapshotViewHook(v.facts.snapshot)
	hasher, err = closure.NewBracketAt(ctx, v.facts.reader, v.session.buildFlags...)
	emitBeforeAnalysisViewHook()
	if err != nil {
		return err
	}
	liveSnapshot, err := hasher.PassReader().Snapshot(ctx)
	if err != nil {
		return err
	}
	if liveSnapshot.Identity() != v.facts.snapshot.Identity() {
		return fmt.Errorf("%w: analysis environment", ErrViewChanged)
	}
	// The bracket's analysis scope is the view's: the same identity
	// outside the source closure the observation pass set, so its
	// memos and the pass's are one store. The observability memo's key
	// completes with the package test-binary closure hash inside the
	// Hasher (REQ-closure-observability-memo). Since the per-subject
	// isolation landed, SHAPE REFUSALS memoize too - a change to the
	// analyzer's shape capability (a new admitted shape, a widened
	// guard) must bump ObservationRTA, or cached refusals serve under
	// semantics that no longer refuse them.
	hasher.SetAnalysisScope(v.session.analysisScope(v.facts.guards))
	if v.session.progress != nil {
		v.session.wireProgress(hasher)
	}
	// The caller's analysis budget bounds only the precise analysis itself: the
	// Hasher's analysis context carries the budget deadline, so exhaustion
	// surfaces as analysis failure — degrading to unavailable evidence, never
	// validity — while the operation, its brackets, and Hasher construction
	// stay governed by the caller's context alone.
	var analysisCtx context.Context
	budget := v.session.analysisBudget
	if budget > 0 {
		bound, cancelBudget := analysisBound(ctx, budget)
		defer cancelBudget()
		analysisCtx = bound
		if err := hasher.BoundAnalysis(analysisCtx); err != nil {
			return err
		}
	}
	observableComputed, err := hasher.ComputeObservabilityBatch(observableRequests)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
		}
		// Isolation retries per subject so a fact reached only by one
		// subject can never deny a sibling's proof. While the analysis
		// context lives, the Hasher memoizes load failures, so a failing
		// package's load runs once per analysis however many subjects
		// retry; once the analysis budget expires, retries fail at the
		// subprocess boundary without real work.
		observableComputed = make(map[closure.Subject]closure.Observability, len(observableRequests))
		cut := 0
		for _, request := range observableRequests {
			isolated, isolatedErr := hasher.ComputeObservabilityBatch([]closure.Subject{request})
			if isolatedErr != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
				}
				// The isolated refusal composes here, outside the batch's
				// attributed return, so it attributes the selection itself
				// exactly as its in-batch twin does
				// (REQ-closure-refusal-channels). A refusal under an
				// expired analysis budget names the budget: the reason
				// is the record's, read long after the pass, and "context
				// deadline exceeded" alone would not say whose deadline
				// (REQ-fresh-context).
				reason := unavailableReason(isolatedErr.Error())
				if analysisCtx != nil && analysisCtx.Err() != nil {
					cut++
					reason = unavailableReason(budgetExhausted(budget) + ": " + isolatedErr.Error())
				}
				observableComputed[request] = closure.Observability{Reason: closure.AttributeSelection(reason, hasher.SelectionAttribution())}
				continue
			}
			maps.Copy(observableComputed, isolated)
		}
		// One diagnostic per pass the budget cut, never one per
		// subject: the count is the fact, the per-subject reasons
		// ride the records (REQ-fresh-progress).
		reportBudgetCut(v.session.progress, budget, cut, "unproven")
	}
	after, err := v.observe(ctx)
	if err != nil {
		return err
	}
	if err := v.holdCutUnavailable(v.compareObservationContext(ctx, after)); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return errViewSealed
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: precise analysis cancelled: %w", err)
	}
	for _, request := range observableRequests {
		subject := Subject{Package: request.Package, Symbol: request.Symbol}
		v.observable[subject] = observableComputed[request]
	}
	return ctx.Err()
}

func compatibleObservationProof(recorded Fingerprint, subject Subject) bool {
	compatible, _ := compatibleObservationProofMode(recorded, subject)
	return compatible
}

func compatibleObservationProofMode(recorded Fingerprint, subject Subject) (compatible, effectFree bool) {
	proof := recorded.ObservationProof
	if recorded.ObservationAssertion != "caller assertion" || proof.Strategy != ObservationRTA || proof.Subject != subject || recorded.ToolchainContent == "" || recorded.AdmissionPolicy == "" {
		return false, false
	}
	if proof.Observable == (proof.Reason != "") {
		return false, false
	}
	if proof.Evidence == observationProofEvidence(recorded) {
		return true, false
	}
	if proof.Observable && proof.Evidence == observationProofEvidenceMode(recorded, true) {
		return true, true
	}
	return false, false
}

func observationProofEvidence(recorded Fingerprint) string {
	return observationProofEvidenceMode(recorded, false)
}

func observationProofEvidenceMode(recorded Fingerprint, effectFree bool) string {
	proof := recorded.ObservationProof
	maximalClosure, assertion := recorded.MaximalClosure, recorded.ObservationAssertion
	if !effectFree {
		sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
		return hex.EncodeToString(sum[:])[:32]
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%t%d:%s%d:%s%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, effectFree, len(proof.Reason), proof.Reason, len(recorded.ToolchainContent), recorded.ToolchainContent, len(recorded.AdmissionPolicy), recorded.AdmissionPolicy))
	return hex.EncodeToString(sum[:])[:32]
}

// emitUnauditedToolchainNotice announces an unverified toolchain ONCE
// PER ENGINE on the diagnostic channel: one line of each consumer
// run's output points at the refusing axis - the surface packages that
// failed structural verification, or a surface that could not be
// read - without which the degradation surfaces only as a scatter of
// ordinary fail-closed refusals, the exact discovery shape the content
// keying was built to prevent. Per-engine (not per-process) so a long-lived
// server's every campaign log carries it; the once is the caller's,
// so a consumer-less engine's emission is never spent into a void it
// shares with a later consumer.
func emitUnauditedToolchainNotice(once *sync.Once, notice string, emit func(detail string)) {
	if notice == "" {
		return
	}
	once.Do(func() {
		// The owned axis-naming rendering, with the operator-facing
		// source pointer this face has always carried appended as
		// attribution — the same decoration a consumer adds.
		emit(notice + " (closure/toolchainaudit.go)")
	})
}

// analysisScope is the pass's analysis identity outside the source
// closure under guards: the strategy versions, the code guards, the
// execution attestations — each changes what a derived fact records,
// so attested and unattested sessions never serve each other's facts
// (REQ-closure-dynamic-state-memo) — and the caller's vouch set.
func (s *Session) analysisScope(guards guard.Guards) closure.AnalysisScope {
	vouches := make([]string, 0, len(s.dynamicStateVouches))
	for v := range s.dynamicStateVouches {
		vouches = append(vouches, v)
	}
	return closure.AnalysisScope{
		ProofStrategy: ObservationRTA, FactStrategy: DynamicStateStrategy,
		Toolchain: guards.Toolchain, BuildConfig: guards.BuildConfig,
		SingleSubject: s.executionModel.singleSubject(), PackageProcess: s.executionModel.packageProcess(),
		Vouches: vouches,
	}
}

// SubjectScope states what a membership refusal tested. A declaration outside
// a selected view can still exist in source; these refusals do not conflate it
// with a missing declaration.
type SubjectScope uint8

const (
	SelectedSource SubjectScope = iota
	SelectedView
	ParentView
)

// UnknownSubjectsError names every missing member once, in request order (or
// package/symbol lexical order for map-backed requests). SelectedSource means
// declarations were absent from the source scan, including a formerly held
// subject disappearing during re-observation. Other scopes concern selection
// alone and make no assertion about source existence.
type UnknownSubjectsError struct {
	Subjects []Subject
	Scope    SubjectScope
}

func (e *UnknownSubjectsError) Error() string {
	noun := "subjects"
	if len(e.Subjects) == 1 {
		noun = "subject"
	}
	names := make([]string, 0, len(e.Subjects))
	for _, s := range e.Subjects {
		names = append(names, s.Package+"."+s.Symbol)
	}
	where := "not found in selected source"
	switch e.Scope {
	case SelectedView:
		where = "not in this analysis view"
	case ParentView:
		where = "not in the parent view"
	}
	return fmt.Sprintf("gofresh: %s %s %s", noun, strings.Join(names, ", "), where)
}

func requireSubjects(subjects []Subject, contains func(Subject) bool, scope SubjectScope) error {
	seen := make(map[Subject]bool, len(subjects))
	var unknown []Subject
	for _, subject := range subjects {
		if !seen[subject] && !contains(subject) {
			unknown = append(unknown, subject)
		}
		seen[subject] = true
	}
	if len(unknown) == 0 {
		return nil
	}
	return &UnknownSubjectsError{Subjects: unknown, Scope: scope}
}

// requireMembers judges selection, not whether today's source declares a name.
// The immutable closure inventory is the shared membership authority for every
// projection, attachment and check over a constructed view.
func (v *Snapshot) requireMembers(subjects []Subject) error {
	return requireSubjects(subjects, func(s Subject) bool {
		_, ok := v.facts.maximal[s]
		return ok
	}, SelectedView)
}

func orderedRecordedSubjects(recorded map[Subject]Fingerprint) []Subject {
	ordered := make([]Subject, 0, len(recorded))
	for subject := range recorded {
		ordered = append(ordered, subject)
	}
	slices.SortFunc(ordered, func(a, b Subject) int {
		if order := cmp.Compare(a.Package, b.Package); order != 0 {
			return order
		}
		return cmp.Compare(a.Symbol, b.Symbol)
	})
	return ordered
}

// RecordedRefusalKind identifies the preparation tier refusing a record batch.
type RecordedRefusalKind uint8

const (
	RecordShapeRefusal RecordedRefusalKind = iota + 1
	RecordKindRefusal
)

// RecordedFailure attributes one record's preparation failure. Shape refusals
// carry the fingerprint validator's error; kind refusals carry the recorded kind.
type RecordedFailure struct {
	Subject Subject
	Shape   error
	Kind    Kind
}

// RecordedBatchError reports every failure in the first refusing preparation
// tier, in request order (package/symbol order for map-backed APIs). All shape failures precede every view-kind
// mismatch; every kind mismatch precedes membership. No partial verdict exists.
type RecordedBatchError struct {
	Tier     RecordedRefusalKind
	ViewKind Kind
	Failures []RecordedFailure
}

func (e *RecordedBatchError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, failure := range e.Failures {
		if e.Tier == RecordShapeRefusal {
			parts = append(parts, fmt.Sprintf("%s.%s: %v", failure.Subject.Package, failure.Subject.Symbol, failure.Shape))
		} else {
			parts = append(parts, fmt.Sprintf("gofresh: recorded result kind %d for %s.%s does not match view kind %d", failure.Kind, failure.Subject.Package, failure.Subject.Symbol, e.ViewKind))
		}
	}
	return strings.Join(parts, "; ")
}

// Unwrap exposes the original fingerprint shape errors without making their
// diagnostic wording the batch's refusal classification.
func (e *RecordedBatchError) Unwrap() []error {
	var errors []error
	for _, failure := range e.Failures {
		if failure.Shape != nil {
			errors = append(errors, failure.Shape)
		}
	}
	return errors
}

// subjectFacts separates immutable maximal inputs from consumer-tier obligations.
// The obligations are independent: selecting one diagnostic must not erase the
// others. They describe the construction's conservative analysis, never a later
// producing unit's or historical candidate's admission.
type subjectFacts struct {
	source      closure.MaximalFacts
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
	return f.source.Equal(other.source) && sameRefusal(f.openWorld, other.openWorld) &&
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
	return f.maximal[subject].closure()
}

// scanPureDirectivesAt loads pkgPaths from dir ("" = the current directory)
// under env as the complete process environment and buildFlags as the
// build selection, and returns a purity predicate marking every symbol
// whose declaration carries a //gofresh:pure directive
// (REQ-purity-directive).
func scanPureDirectivesAt(dir string, env, buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	scan, err := scanSubjectsInWithBuildFlagsEnv(context.Background(), dir, env, buildFlags, pkgPaths...)
	if err != nil {
		return nil, err
	}
	return scan.directivePure, nil
}

// sharedDynamicStatePrefix opens every shared-dynamic-state downgrade
// diagnostic. The verdict uses the closure's typed refusal origin, never this
// spelling, to keep shared state outside the observation lift.
const sharedDynamicStatePrefix = "package graph shares mutated dynamic state: "

// scanFactsDirName is the view scan memo's sibling store directory:
// one entry per (scope, package scan key) holding the package's scan
// outputs (REQ-closure-scan-memo).
const scanFactsDirName = "scanfacts"

func loadScanFacts(scope, key string, payload any) bool {
	if scope == "" || key == "" {
		return false
	}
	return cachefile.Load(scanFactsDirName, scope, key, payload)
}

func storeScanFacts(scope, key string, payload any) {
	if scope == "" || key == "" {
		return
	}
	cachefile.Store(scanFactsDirName, scope, key, payload)
}

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*subjectScan, error) {
	// A directive scan takes no engine: its own pass over the plain
	// runner, loading only the requested packages and extracting only
	// method directives without running FactOf or Compose.
	hasher, err := closure.NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
	if err != nil {
		return nil, err
	}
	load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, pkgPaths...)
	if err != nil {
		return nil, err
	}
	byPkg := map[string][]dynamicStateFact{}
	for _, pkg := range load.Packages() {
		if pkg.Name == "main" && strings.HasSuffix(pkg.PkgPath, ".test") {
			continue
		}
		for _, loadErr := range pkg.Errors {
			return nil, fmt.Errorf("gofresh: directive scan: load %s: %s", pkg.PkgPath, loadErr)
		}
		byPkg[pkg.PkgPath] = append(byPkg[pkg.PkgPath], dynstate.MethodDirectivesFactOf(pkg))
	}
	missingPromoted := map[string]bool{}
	for _, pkg := range load.Packages() {
		if pkg.Types == nil {
			continue
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			for _, methods := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(typeName.Type())),
				types.NewMethodSet(typeName.Type()),
			} {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok || method.Pkg() == nil {
						continue
					}
					depPath := method.Pkg().Path()
					first, _, _ := strings.Cut(depPath, "/")
					if len(byPkg[depPath]) == 0 && strings.Contains(first, ".") {
						missingPromoted[depPath] = true
					}
				}
			}
		}
	}
	if len(missingPromoted) > 0 {
		depPatterns := make([]string, 0, len(missingPromoted))
		for depPath := range missingPromoted {
			depPatterns = append(depPatterns, depPath)
		}
		sort.Strings(depPatterns)
		depLoad, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, depPatterns...)
		if err != nil {
			return nil, err
		}
		for _, pkg := range depLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			byPkg[pkg.PkgPath] = append(byPkg[pkg.PkgPath], dynstate.MethodDirectivesFactOf(pkg))
		}
	}
	cones := make(map[string]map[string][]dynamicStateFact, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		cones[pkgPath] = byPkg
	}
	state := &viewDynamicState{cones: cones}
	return scanSubjectsFromLoadedWith(hasher.SelectionAudited(), false, load.Packages(), state, pkgPaths...)
}

// scanViewSubjects performs one observation pass's whole subject scan: the
// metadata graph names every node and its mutability class, one typed load
// covers the view packages' variants and every mutable-local graph package,
// the dynamic-state derivation serves version-pinned facts from the memo, and
// the subject walk reads that one load (REQ-fresh-coherent-view). The typed
// load is installed on the hasher for the pass's sibling consumers. An empty
// factScope disables fact persistence, never the derivation. budget bounds
// the reachability discharges' precise analysis (zero: unbounded); a pass
// the budget cuts leaves every culprit standing and persists no scan facts
// of a package it cut — cut is the set of subjects it left undischarged
// (REQ-fresh-context, REQ-closure-shared-dynamic-state-reachability).
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	return scanViewSubjectsWithMemo(ctx, hasher, scope, buildFlags, budget, true, pkgPaths...)
}

func scanViewSubjectsWithMemo(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, useScanMemo bool, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	scope = hasher.SetAnalysisScope(scope)
	// The scope is the one source of the attestations and the vouches:
	// what keys a memo is what the derivation applies.
	factScope := scope.Facts()
	singleSubject, packageProcess := scope.SingleSubject, scope.PackageProcess
	vouches := make(map[string]bool, len(scope.Vouches))
	for _, v := range scope.Vouches {
		vouches[v] = true
	}
	// The scan memo: a view package whose scan the persistent store
	// already holds under this scope and its current package scan key
	// serves its subjects' outputs whole and takes no part in the typed
	// load, the derivation, or the discharges below — every output is a
	// pure function of the package's typed test-binary program, which
	// the key pins byte for byte (REQ-closure-scan-memo). A key that
	// cannot derive, or an entry that cannot load, recomputes.
	scanScope := scope.Scan()
	if !useScanMemo || isScanMemoOffViewHook() {
		scanScope = ""
	}
	served := map[string]packageScanEntry{}
	keys := map[string]string{}
	var misses []string
	for _, pkgPath := range pkgPaths {
		key, err := hasher.PackageScanKey(pkgPath)
		if err == nil {
			keys[pkgPath] = key
			var entry packageScanEntry
			if loadScanFacts(scanScope, key, &entry) && entry.Version == scanEntryVersion {
				served[pkgPath] = entry
				hasher.Served("scan", pkgPath)
				continue
			}
		}
		misses = append(misses, pkgPath)
	}
	if len(misses) == 0 {
		return scanFromEntries(served), nil, nil, nil
	}
	// Every listing, load, and derivation below reads the misses' graph
	// alone; a served package's cone costs the pass nothing.
	pkgPaths = misses
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
	// A test variant of a module-cache-resident view package: the view
	// packages are the only test-expanded ones, and a subject package
	// inside the read-only cache has no runnable tests to vouch for it —
	// refused from the listing, before the typed load below is paid, and
	// named rather than surfaced as a coverage gap. A pinned view package
	// with no test files carries no variant and derives through the
	// pinned-fact path as before.
	for _, node := range meta {
		if node.Class == closure.PinnedPackage && node.ForTest != "" && requested[node.ForTest] && (node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test") {
			return nil, nil, nil, fmt.Errorf("gofresh: view package %s resolves into the module cache; module-cache-resident subjects are unsupported", node.ForTest)
		}
	}
	patterns := append([]string(nil), pkgPaths...)
	seenPattern := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		seenPattern[pkgPath] = true
	}
	for _, node := range meta {
		// Plain mutable-local graph packages load as patterns; test
		// variants of the view packages load through the view patterns, and
		// an intermediate recompilation ("r [a.test]") is scanned from its
		// own compilation via the dependency-expanded fallback load in
		// deriveViewDynamicState — a plain stand-in would miss variant-only
		// resolution and need not even compile.
		if node.Class != closure.MutableLocalPackage || node.TestMain || node.ForTest != "" || seenPattern[node.PkgPath] {
			continue
		}
		seenPattern[node.PkgPath] = true
		patterns = append(patterns, node.PkgPath)
	}
	emitTypedLoadViewHook()
	hasher.Unit("typecheck", "", 0, len(patterns))
	load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
	if err != nil {
		return nil, nil, nil, err
	}
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, buildFlags, load, pkgPaths, vouches, singleSubject, scope.PackageProcess)
	if err != nil {
		return nil, nil, nil, err
	}
	scan, err := scanSubjectsFromLoaded(hasher.SelectionAudited(), load.Packages(), state, pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	// The discharges' reachability analysis is precise analysis under
	// the caller's budget: bounded here alone — the listing, the typed
	// load, the derivation, and the closure fold stay under the
	// operation's own context (REQ-fresh-context).
	analysisCtx, cancelBudget := analysisBound(ctx, budget)
	defer cancelBudget()
	var cut map[Subject]bool
	emitBeforeDischargeViewHook()
	if singleSubject {
		// The attestation-gated reachability scoping: per downgraded
		// subject, a culprit whose every marking site is provably
		// outside the subject's rooted flow discharges — no proof, no
		// discharge (REQ-closure-shared-dynamic-state).
		if cut, err = dischargeUnreachableCulprits(ctx, analysisCtx, hasher, state, scan); err != nil {
			return nil, nil, nil, err
		}
	} else if packageProcess {
		// The package-process attestation's binary-scoped reachability
		// judgment: every measured process is the subject package's own
		// test binary, so sibling subjects are themselves harness roots
		// of the analyzed binary, and a culprit no harness root's
		// post-init flow can reach is init-determined for every subject
		// of the binary — no proof, no discharge
		// (REQ-closure-shared-dynamic-state).
		if cut, err = dischargeBinaryUnreachableCulprits(ctx, analysisCtx, hasher, state, scan); err != nil {
			return nil, nil, nil, err
		}
	}
	// Persist each missed package's outputs now that the discharges have
	// finished shaping them, then fold the served packages' in. A package
	// the budget cut persists nothing: its undischarged shape is the
	// budget's, not the program's, and the next pass derives it cold;
	// the other missed packages' facts are the program's and persist.
	cutPackages := map[string]bool{}
	for subject := range cut {
		cutPackages[subject.Package] = true
	}
	for _, pkgPath := range pkgPaths {
		if key := keys[pkgPath]; key != "" && !cutPackages[pkgPath] {
			storeScanFacts(scanScope, key, entryOf(scan, pkgPath))
		}
	}
	mergeEntries(scan, served)
	return scan, load, cut, nil
}

// scanEntryVersion versions the persisted scan entry — its shape and the
// text of every field it persists (a downgrade reason is scan output, so
// a change to its composition bumps the version); a bump recomputes
// rather than serving an older entry's text or misreading its shape.
const scanEntryVersion = 5

// subjectScanEntry is one subject's scan outputs as persisted.
type subjectScanEntry struct {
	Pure bool `json:"pure,omitempty"`
	// OpenWorld is the conferring term of an open-world subject — the
	// type parameter, receiver, or parameter whose type carries
	// dynamic reach — and empty for a closed one: one field, so an open
	// subject without its term is unrepresentable
	// (REQ-closure-refusal-channels).
	OpenWorld                string  `json:"openWorld,omitempty"`
	External                 bool    `json:"external,omitempty"`
	DowngradeReason          string  `json:"downgradeReason,omitempty"`
	DowngradeCulprit         Subject `json:"downgradeCulprit,omitempty"`
	VouchDischarges          string  `json:"vouchDischarges,omitempty"`
	AttestationDischarges    string  `json:"attestationDischarges,omitempty"`
	PackageProcessDischarges string  `json:"packageProcessDischarges,omitempty"`
	Ambiguous                string  `json:"ambiguous,omitempty"`
}

// packageScanEntry is one view package's scan outputs as persisted: every
// subject the scan knew in the package, by symbol.
type packageScanEntry struct {
	Version  int                         `json:"version"`
	Subjects map[string]subjectScanEntry `json:"subjects"`
}

// attestationDischarges holds the positive execution-model attestations'
// load-bearing discharge sets for one subject: carried as one comparable value
// across subjectScan, observationFacts, and Snapshot.Sibling so no attestation axis
// can be omitted when copying or clearing subject facts.
type attestationDischarges struct {
	singleSubject  string
	packageProcess string
}

// entryOf projects the scan's outputs for one package into its entry.
func entryOf(scan *subjectScan, pkgPath string) packageScanEntry {
	entry := packageScanEntry{Version: scanEntryVersion, Subjects: map[string]subjectScanEntry{}}
	for subject := range scan.known {
		if subject.Package != pkgPath {
			continue
		}
		d := scan.discharges[subject]
		entry.Subjects[subject.Symbol] = subjectScanEntry{
			Pure: scan.pure[subject], OpenWorld: scan.openWorld[subject], External: scan.external[subject],
			DowngradeReason: scan.downgradeReason[subject], DowngradeCulprit: scan.downgradeCulprit[subject],
			VouchDischarges: scan.vouchDischarges[subject],
			AttestationDischarges: d.singleSubject, PackageProcessDischarges: d.packageProcess,
			Ambiguous: scan.ambiguous[subject],
		}
	}
	return entry
}

// mergeEntries folds served packages' entries into a scan.
func mergeEntries(scan *subjectScan, served map[string]packageScanEntry) {
	for pkgPath, entry := range served {
		for symbol, e := range entry.Subjects {
			subject := Subject{Package: pkgPath, Symbol: symbol}
			scan.known[subject] = true
			if e.Pure {
				scan.pure[subject] = true
			}
			if e.OpenWorld != "" {
				scan.openWorld[subject] = e.OpenWorld
			}
			if e.External {
				scan.external[subject] = true
			}
			if e.DowngradeReason != "" {
				scan.downgradeReason[subject] = e.DowngradeReason
			}
			if e.DowngradeCulprit != (Subject{}) {
				scan.downgradeCulprit[subject] = e.DowngradeCulprit
			}
			if e.VouchDischarges != "" {
				scan.vouchDischarges[subject] = e.VouchDischarges
			}
			if e.AttestationDischarges != "" || e.PackageProcessDischarges != "" {
				scan.discharges[subject] = attestationDischarges{
					singleSubject:  e.AttestationDischarges,
					packageProcess: e.PackageProcessDischarges,
				}
			}
			if e.Ambiguous != "" {
				scan.ambiguous[subject] = e.Ambiguous
			}
		}
	}
}

// scanFromEntries builds a scan entirely from served entries.
func scanFromEntries(served map[string]packageScanEntry) *subjectScan {
	scan := &subjectScan{
		pure: map[Subject]bool{}, known: map[Subject]bool{}, openWorld: map[Subject]string{}, external: map[Subject]bool{},
		downgradeReason: map[Subject]string{}, downgradeCulprit: map[Subject]Subject{},
		vouchDischarges: map[Subject]string{}, discharges: map[Subject]attestationDischarges{},
		ambiguous: map[Subject]string{},
	}
	mergeEntries(scan, served)
	return scan
}

// subjectScan is one observation pass's subject-walk result: enumeration,
// directive purity, per-subject dynamic-signature marks, and the subjects
// whose identity collapsed distinct declarations.
type subjectScan struct {
	pure  map[Subject]bool
	known map[Subject]bool
	// openWorld maps each open-world subject to the term conferring its
	// openness (REQ-closure-analysis's openness rule), the refusal's
	// named identity; a closed subject is absent
	// (REQ-closure-refusal-channels).
	openWorld map[Subject]string
	external  map[Subject]bool
	// downgradeReason maps each subject of a shared-dynamic-state
	// downgraded package to the refusal reason naming the owning package
	// and variable (REQ-closure-shared-dynamic-state-reason).
	downgradeReason  map[Subject]string
	downgradeCulprit map[Subject]Subject
	// vouchDischarges maps each subject to the canonical sorted
	// comma-joined caller-vouch identities that discharged would-be
	// culprits reachable from its package (REQ-vouch-recorded).
	vouchDischarges map[Subject]string
	// discharges maps each subject to the positive execution-model
	// attestations' load-bearing discharge sets (single-subject and
	// package-process) reachable from its package (REQ-vouch-recorded).
	discharges map[Subject]attestationDischarges
	// ambiguous holds, per subject whose identity is declared more than
	// once across the package and its test variants, the message naming
	// both declarations. Capture is refused for exactly these subjects —
	// no directive or assertion can be attributed to one declaration —
	// while sibling subjects scan normally (REQ-purity-directive).
	ambiguous map[Subject]string
}

func (s *subjectScan) directivePure(subject Subject) bool { return s.pure[subject] }

// scanSubjectsFromLoaded derives the subject walk — subject enumeration,
// directives, per-subject dynamic-signature marks — from an observation
// pass's already-loaded packages, applying the pass's dynamic-state
// derivation for the shared-dynamic-state downgrade and promoted-method
// directives (REQ-fresh-coherent-view, REQ-closure-shared-dynamic-state).
func scanSubjectsFromLoaded(audited bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	return scanSubjectsFromLoadedWith(audited, true, pkgs, state, pkgPaths...)
}

func scanSubjectsFromLoadedWith(audited, computeOpenWorld bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	scan := &subjectScan{
		pure:             map[Subject]bool{},
		known:            map[Subject]bool{},
		openWorld:        map[Subject]string{},
		external:         map[Subject]bool{},
		downgradeReason:  map[Subject]string{},
		downgradeCulprit: map[Subject]Subject{},
		vouchDischarges:  map[Subject]string{},
		discharges:       map[Subject]attestationDischarges{},
		ambiguous:        map[Subject]string{},
	}
	var cones map[string]map[string][]dynamicStateFact
	if state != nil {
		cones = state.cones
	}
	declarations := map[Subject]string{}
	err := dynstate.WalkLoadedSubjects(audited, computeOpenWorld, pkgs, cones, pkgPaths, func(s dynstate.ScannedSymbol) {
		subject := Subject{Package: s.Package, Symbol: s.Symbol}
		if previous := declarations[subject]; previous != "" && previous != s.Declaration {
			scan.ambiguous[subject] = fmt.Sprintf("declared at both %s and %s", previous, s.Declaration)
		} else {
			declarations[subject] = s.Declaration
			scan.known[subject] = true
		}
		if s.Pure {
			scan.pure[subject] = true
		}
		if s.External {
			scan.external[subject] = true
		}
		if s.OpenWorld != "" {
			scan.openWorld[subject] = s.OpenWorld
		}
	})
	if err != nil {
		return nil, err
	}
	for subject := range scan.ambiguous {
		delete(scan.pure, subject)
		delete(scan.external, subject)
	}
	if state != nil {
		for subject := range scan.known {
			if reason := state.downgraded[subject.Package]; reason != "" {
				scan.downgradeReason[subject] = sharedDynamicStatePrefix + reason
				if culprit := state.culprits[subject.Package]; culprit != (Subject{}) {
					scan.downgradeCulprit[subject] = culprit
				}
			}
			if discharges := state.vouchDischarges[subject.Package]; discharges != "" {
				scan.vouchDischarges[subject] = discharges
			}
			if attested := state.attestationDischarges[subject.Package]; attested != "" {
				scan.discharges[subject] = attestationDischarges{singleSubject: attested}
			}
		}
	}
	return scan, nil
}

func nodeDeclarationKey(pkg *packages.Package, node ast.Node) string {
	return dynstate.NodeDeclarationKey(pkg, node)
}

func objectDeclarationKey(pkg *packages.Package, obj types.Object) string {
	return dynstate.ObjectDeclarationKey(pkg, obj)
}

func recvTypeName(fd *ast.FuncDecl) string {
	return dynstate.RecvTypeName(fd)
}

func auditedSynchronization(audited bool, fn *types.Func) bool {
	return dynstate.AuditedSynchronization(audited, fn)
}

func auditedPooling(audited bool, fn *types.Func) bool {
	return dynstate.AuditedPooling(audited, fn)
}

func auditedImmutableType(audited bool, t types.Type) bool {
	return dynstate.AuditedImmutableType(audited, t)
}

// dynamicStateFact is one package's contribution to the shared-dynamic-state
// downgrade (REQ-closure-shared-dynamic-state) plus its method-directive
// declarations: everything the analysis needs from the package's syntax, so a
// version-pinned package's syntax never loads twice per key.
type dynamicStateFact = dynstate.Fact

// dynamicStateFactOf derives one typed package's fact. Pure function of the
// package's selected syntax and type environment plus the caller-attested
// single-subject-process execution model — the attestation changes what the
// fact records (the audited pooling set's discharge), so it is part of every
// fact-cache identity the fact is stored under
// (REQ-closure-dynamic-state-memo).
func dynamicStateFactOf(audited bool, p *packages.Package, singleSubject bool) dynamicStateFact {
	return dynstate.FactOf(audited, p, singleSubject)
}

const dynamicStateDirName = "dynamicstate"

func loadDynamicStateFacts(scope, bucket string) map[string]json.RawMessage {
	if scope == "" {
		return nil
	}
	var facts map[string]json.RawMessage
	if !cachefile.Load(dynamicStateDirName, scope, bucket, &facts) {
		return nil
	}
	return facts
}

func storeDynamicStateFacts(scope, bucket string, facts map[string]json.RawMessage) {
	if scope == "" {
		return
	}
	cachefile.Merge(dynamicStateDirName, scope, bucket, facts)
}

// processFactCache serves version-pinned package facts within one process.
// Keyed by (scope, bucket, package path) — the same complete identity the
// persistent memo trusts, so a hit is sound wherever the persistent entry
// would be.
var processFactCache cachefile.SyncMemo[dynamicStateFact]

// viewDynamicState is the per-pass dynamic-state derivation over one view's
// metadata graph: fresh facts for every mutable-local node from the pass's
// own typed load, memoized facts for version-pinned modules (persistent under
// factScope, in-process always), standard-library nodes skipped — inert by
// construction: their declaration side is excluded and toolchain source
// cannot reach module variables (imports are acyclic).
type viewDynamicState struct {
	cones                 map[string]map[string][]dynamicStateFact
	downgraded            map[string]string
	culprits              map[string]Subject
	vouchDischarges       map[string]string
	attestationDischarges map[string]string
	rootCulprits          map[string][]dynCulprit
	culpritSites          map[string]map[string]culpritSiteSet
}

// coneDynamicState is one view package's composed dynamic-state judgment over
// its own test-binary cone.
type coneDynamicState struct {
	downgraded            string
	culprit               Subject
	vouchDischarges       string
	attestationDischarges string
	rootCulprits          []dynCulprit
	culpritSites          map[string]culpritSiteSet
}

// dischargeUnreachableCulprits applies the single-subject reachability
// scoping of the shared-dynamic-state judgment (REQ-closure-shared-dynamic-state).
func dischargeUnreachableCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) (cut map[Subject]bool, err error) {
	var downgraded []Subject
	for subject := range scan.known {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].key].unattributed {
			downgraded = append(downgraded, subject)
		}
	}
	if len(downgraded) == 0 {
		return nil, nil
	}
	requests := make([]closure.Subject, len(downgraded))
	for i, subject := range downgraded {
		requests[i] = closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
	}
	rooted, err := hasher.ComputeRootedFunctions(analysisCtx, requests)
	if err != nil {
		return dischargeCut(ctx, analysisCtx, downgraded, err)
	}
	for i, subject := range downgraded {
		proof := rooted[requests[i]]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, subject.Package)
		if surviving == "" {
			delete(scan.downgradeReason, subject)
			delete(scan.downgradeCulprit, subject)
		} else {
			scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
			scan.downgradeCulprit[subject] = culprit
		}
		if len(dischargedKeys) > 0 {
			d := scan.discharges[subject]
			for _, key := range strings.Split(d.singleSubject, ",") {
				if key != "" {
					dischargedKeys[key] = true
				}
			}
			d.singleSubject = joinDischargedKeys(dischargedKeys)
			scan.discharges[subject] = d
		}
	}
	return nil, nil
}

// dischargeCut classifies a reachability analysis's failure
// (REQ-fresh-context, REQ-closure-shared-dynamic-state-reachability).
func dischargeCut(ctx, analysisCtx context.Context, downgraded []Subject, err error) (map[Subject]bool, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("gofresh: dynamic-state discharge cancelled: %w", ctx.Err())
	}
	if analysisCtx.Err() != nil {
		cut := make(map[Subject]bool, len(downgraded))
		for _, subject := range downgraded {
			cut[subject] = true
		}
		return cut, nil
	}
	return nil, err
}

// dischargeBinaryUnreachableCulprits applies the BINARY-scoped
// reachability judgment of the shared-dynamic-state invariant
// (REQ-closure-shared-dynamic-state).
func dischargeBinaryUnreachableCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) (cut map[Subject]bool, err error) {
	packageSubjects := map[string][]Subject{}
	var downgraded []Subject
	for subject := range scan.known {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].key].unattributed {
			packageSubjects[subject.Package] = append(packageSubjects[subject.Package], subject)
			downgraded = append(downgraded, subject)
		}
	}
	if len(packageSubjects) == 0 {
		return nil, nil
	}
	paths := make([]string, 0, len(packageSubjects))
	for path := range packageSubjects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	inventories, err := hasher.ComputeBinaryRootedFunctions(analysisCtx, paths)
	if err != nil {
		return dischargeCut(ctx, analysisCtx, downgraded, err)
	}
	for _, path := range paths {
		proof := inventories[path]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, path)
		for _, subject := range packageSubjects[path] {
			if surviving == "" {
				delete(scan.downgradeReason, subject)
				delete(scan.downgradeCulprit, subject)
			} else {
				scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
				scan.downgradeCulprit[subject] = culprit
			}
			if len(dischargedKeys) > 0 {
				d := scan.discharges[subject]
				d.packageProcess = joinDischargedKeys(dischargedKeys)
				scan.discharges[subject] = d
			}
		}
	}
	return nil, nil
}

// dischargeCulprits walks one package's root culprits against a
// complete rooted-flow inventory (REQ-closure-shared-dynamic-state).
func dischargeCulprits(proof closure.RootedFunctions, state *viewDynamicState, pkgPath string) (surviving string, culpritSubj Subject, discharged map[string]bool) {
	discharged = map[string]bool{}
	for _, culprit := range state.rootCulprits[pkgPath] {
		sites := state.culpritSites[pkgPath][culprit.key]
		if sites.unattributed {
			return culprit.reasonBody(), culprit.subject(), discharged
		}
		for fn := range sites.fns {
			if proof.Fns[fn] {
				return culprit.reasonBody(), culprit.subject(), discharged
			}
		}
		discharged[culprit.key] = true
	}
	return "", Subject{}, discharged
}

func joinDischargedKeys(discharged map[string]bool) string {
	keys := make([]string, 0, len(discharged))
	for key := range discharged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func generatedProtoHeader(text string) string {
	return dynstate.GeneratedProtoHeader(text)
}

type culpritVerb = dynstate.CulpritVerb
type culpritChannel = dynstate.CulpritChannel

type dynCulprit struct {
	pkgPath string
	key     string
	verb    culpritVerb
	channel culpritChannel
}

func (c dynCulprit) reasonBody() string {
	return (dynstate.Culprit{PkgPath: c.pkgPath, Key: c.key, Verb: c.verb, Channel: c.channel}).ReasonBody()
}

func (c dynCulprit) subject() Subject {
	pkg, sym := (dynstate.Culprit{PkgPath: c.pkgPath, Key: c.key, Verb: c.verb, Channel: c.channel}).SubjectParts()
	return Subject{Package: pkg, Symbol: sym}
}

type culpritSiteSet struct {
	fns          map[string]bool
	unattributed bool
}

func (s *viewDynamicState) methodDirectives(viewPackage string, m *types.Func) (pureKey, externalKey string) {
	if s == nil {
		return "", ""
	}
	return dynstate.MethodDirectives(s.cones, viewPackage, m)
}

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope string, buildFlags []string, load *closure.ViewLoad, viewPackages []string, vouches map[string]bool, singleSubject, packageProcess bool) (*viewDynamicState, error) {
	meta, err := hasher.GraphMetadata(viewPackages...)
	if err != nil {
		return nil, err
	}
	state := &viewDynamicState{downgraded: map[string]string{}, culprits: map[string]Subject{}, cones: map[string]map[string][]dynamicStateFact{}}
	factsByListing := map[string]dynamicStateFact{}
	record := func(listing, _ string, fact dynamicStateFact) {
		factsByListing[listing] = fact
	}

	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	matched := map[string]bool{}
	for _, pkg := range load.Packages() {
		listing := pkg.PkgPath
		if pkg.ForTest != "" {
			listing = pkg.PkgPath + " [" + pkg.ForTest + ".test]"
		}
		node, ok := nodesByListing[listing]
		if !ok || node.Class != closure.MutableLocalPackage || node.TestMain {
			continue
		}
		matched[listing] = true
		record(listing, pkg.PkgPath, dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject))
	}
	var testedWithIntermediates []string
	seenTested := map[string]bool{}
	for _, node := range meta {
		if node.Class == closure.StandardPackage || matched[node.ImportPath] || node.TestMain || node.ForTest == "" {
			continue
		}
		if node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test" {
			continue
		}
		if !seenTested[node.ForTest] {
			seenTested[node.ForTest] = true
			testedWithIntermediates = append(testedWithIntermediates, node.ForTest)
		}
	}
	if len(testedWithIntermediates) > 0 {
		sort.Strings(testedWithIntermediates)
		hasher.Unit("typecheck", "", 0, len(testedWithIntermediates))
		graphLoad, err := closure.LoadViewGraph(ctx, hasher.PassReader(), buildFlags, testedWithIntermediates...)
		if err != nil {
			return nil, err
		}
		packages.Visit(graphLoad.Packages(), nil, func(pkg *packages.Package) {
			if pkg.ForTest == "" {
				return
			}
			listing := pkg.PkgPath + " [" + pkg.ForTest + ".test]"
			node, ok := nodesByListing[listing]
			if !ok || node.Class == closure.StandardPackage || matched[listing] {
				return
			}
			matched[listing] = true
			record(listing, pkg.PkgPath, dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject))
		})
	}
	for _, node := range meta {
		if node.TestMain || node.Class == closure.StandardPackage || matched[node.ImportPath] {
			continue
		}
		if node.Class == closure.PinnedPackage && node.ForTest == "" {
			continue
		}
		return nil, fmt.Errorf("gofresh: dynamic-state scan did not cover package %s", node.ImportPath)
	}

	buckets, unkeyable := pinnedBuckets(meta)
	var missing []closure.GraphPackage
	persisted := map[string]map[string]json.RawMessage{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage || node.ForTest != "" || node.TestMain {
			continue
		}
		if factScope == "" || unkeyable[node.Pin] {
			missing = append(missing, node)
			continue
		}
		bucket := buckets[node.Pin]
		cacheKey := factScope + "\x00" + bucket + "\x00" + node.PkgPath
		if cached, ok := processFactCache.Load(cacheKey); ok {
			record(node.ImportPath, node.PkgPath, cached)
			continue
		}
		if persisted[bucket] == nil {
			if facts := loadDynamicStateFacts(factScope, bucket); facts != nil {
				persisted[bucket] = facts
			} else {
				persisted[bucket] = map[string]json.RawMessage{}
			}
		}
		if raw, ok := persisted[bucket][node.PkgPath]; ok {
			var fact dynamicStateFact
			if json.Unmarshal(raw, &fact) == nil {
				hasher.Served("dynamic-state facts", node.PkgPath)
				processFactCache.Store(cacheKey, fact)
				record(node.ImportPath, node.PkgPath, fact)
				continue
			}
		}
		missing = append(missing, node)
	}
	if len(missing) > 0 {
		patterns := make([]string, 0, len(missing))
		for _, node := range missing {
			patterns = append(patterns, node.PkgPath)
		}
		sort.Strings(patterns)
		emitDynamicStateMissLoadViewHook(patterns)
		hasher.Unit("typecheck", "", 0, len(patterns))
		missLoad, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
		if err != nil {
			return nil, err
		}
		derived := map[string]dynamicStateFact{}
		for _, pkg := range missLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject)
		}
		store := map[string]map[string]json.RawMessage{}
		for _, node := range missing {
			fact, ok := derived[node.PkgPath]
			if !ok {
				return nil, fmt.Errorf("gofresh: dynamic-state scan did not load pinned package %s", node.PkgPath)
			}
			record(node.ImportPath, node.PkgPath, fact)
			if factScope == "" || unkeyable[node.Pin] {
				continue
			}
			bucket := buckets[node.Pin]
			processFactCache.Store(factScope+"\x00"+bucket+"\x00"+node.PkgPath, fact)
			if raw, err := json.Marshal(fact); err == nil {
				if store[bucket] == nil {
					store[bucket] = map[string]json.RawMessage{}
				}
				store[bucket][node.PkgPath] = raw
			}
		}
		for bucket, facts := range store {
			storeDynamicStateFacts(factScope, bucket, facts)
		}
	}

	for _, viewPackage := range viewPackages {
		coneMeta, coneFacts := dynamicStateCone(meta, nodesByListing, factsByListing, viewPackage)
		state.cones[viewPackage] = coneFacts
		cone := composeDynamicState(coneMeta, coneFacts, viewPackage, vouches, singleSubject, packageProcess)
		if cone.downgraded != "" {
			state.downgraded[viewPackage] = cone.downgraded
			state.culprits[viewPackage] = cone.culprit
		}
		if cone.vouchDischarges != "" {
			if state.vouchDischarges == nil {
				state.vouchDischarges = map[string]string{}
			}
			state.vouchDischarges[viewPackage] = cone.vouchDischarges
		}
		if cone.attestationDischarges != "" {
			if state.attestationDischarges == nil {
				state.attestationDischarges = map[string]string{}
			}
			state.attestationDischarges[viewPackage] = cone.attestationDischarges
		}
		if len(cone.rootCulprits) > 0 {
			if state.rootCulprits == nil {
				state.rootCulprits = map[string][]dynCulprit{}
				state.culpritSites = map[string]map[string]culpritSiteSet{}
			}
			state.rootCulprits[viewPackage] = cone.rootCulprits
			state.culpritSites[viewPackage] = cone.culpritSites
		}
	}
	return state, nil
}

func composeDynamicState(meta []closure.GraphPackage, allFacts map[string][]dynamicStateFact, viewPackage string, vouches map[string]bool, singleSubject, packageProcess bool) coneDynamicState {
	composed := dynstate.Compose(meta, allFacts, viewPackage, vouches, singleSubject, packageProcess)
	out := coneDynamicState{
		downgraded:            composed.Downgraded,
		culprit:               Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym},
		vouchDischarges:       composed.VouchDischarges,
		attestationDischarges: composed.AttestationDischarges,
	}
	if len(composed.RootCulprits) > 0 {
		out.rootCulprits = make([]dynCulprit, len(composed.RootCulprits))
		for i, c := range composed.RootCulprits {
			out.rootCulprits[i] = dynCulprit{
				pkgPath: c.PkgPath,
				key:     c.Key,
				verb:    c.Verb,
				channel: c.Channel,
			}
		}
		out.culpritSites = make(map[string]culpritSiteSet, len(composed.CulpritSites))
		for k, s := range composed.CulpritSites {
			out.culpritSites[k] = culpritSiteSet{
				fns:          s.Fns,
				unattributed: s.Unattributed,
			}
		}
	}
	return out
}

func dynamicStateCone(meta []closure.GraphPackage, byListing map[string]closure.GraphPackage, factsByListing map[string]dynamicStateFact, viewPackage string) ([]closure.GraphPackage, map[string][]dynamicStateFact) {
	return dynstate.Cone(meta, byListing, factsByListing, viewPackage)
}

func pinnedBuckets(meta []closure.GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	return dynstate.PinnedBuckets(meta)
}

func newDeferralResolution(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) *dynstate.DeferralResolution {
	return dynstate.NewDeferralResolution(allFacts, malformed)
}

func resolveEnvAudit(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) *dynstate.EnvAuditResolution {
	return dynstate.ResolveEnvAudit(allFacts, malformed)
}

func carrierLinkGraph(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) map[string]map[string]bool {
	return dynstate.CarrierLinkGraph(allFacts, malformed)
}
