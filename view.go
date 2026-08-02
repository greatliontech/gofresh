package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// ErrViewChanged reports that a producer View no longer describes the current
// source, build, guard, or purity state and its results must not be persisted.
var ErrViewChanged = errors.New("gofresh: analysis view changed")

// ErrViewSealed reports a capture attempted after producer validation started.
var ErrViewSealed = errors.New("gofresh: analysis view sealed by validation")

// ErrAnalysisUnavailable reports that producer validation could not
// re-establish a captured observation proof because the current analysis was
// unavailable — an exhausted analysis budget or a failed load — never because
// the view drifted. The evidence is not persisted; the caller may retry with a
// larger budget or record the run without observation evidence.
var ErrAnalysisUnavailable = errors.New("gofresh: observation analysis unavailable during validation")

// View is one immutable observation of the source, build, guards, and purity
// behind a caller-supplied subject set. It can serve a current check batch or a
// producer transaction; analysis state is never shared with another View.
type View struct {
	mu        sync.RWMutex
	engine    *Engine
	subjects  []Subject
	requests  []closure.Subject
	packages  []string
	moduleDir string
	kind      Kind
	// snapshot is the construction pass's env snapshot. The process
	// environment is immutable configuration (REQ-fresh-coherent-view);
	// go env FILE values can still change on disk, so a bracket reusing
	// this snapshot resolves only GOMODCACHE from it, revalidates GOFLAGS
	// live before any load (the memo write precedes the closing compare),
	// and relies on the closing pass's fresh snapshot to refuse any drift
	// the guards cover.
	snapshot             *gotool.EnvSnapshot
	maximal              map[Subject]closure.Closure
	observable           map[Subject]closure.Observability
	guards               guard.Guards
	purity               map[Subject]string
	sourceFiles          []string
	sourceFilesBySubject map[Subject][]string
	// fileDigests: construction-time content digest per source identity,
	// for naming moved files in validation refusals
	// (REQ-fresh-producer-view's naming arm).
	fileDigests map[string]string
	// testVariantLedgers: per-package declaration ledgers over the
	// test-variant compartment, derived at construction from the same file
	// reads as the compartment hashes the agreement pair compares, so the
	// served ledger describes exactly the observed bytes
	// (REQ-closure-test-variant-compartment, REQ-fresh-coherent-view).
	testVariantLedgers   map[string]closure.TestVariantLedger
	capturedObserved     map[Subject]bool
	attachedObservations map[Subject]runtimeinput.State
	sealed               bool
	runtimeCurrent       func(context.Context, string, string) (runtimeinput.State, error)
	// beforePreciseAnalysis observes the start of drift-forced precise analysis
	// (the observability proof). Tests use it to pin which check paths run
	// analysis and to inject cancellation at the analysis boundary. It stays
	// per-view — outside the package-level viewTestHooks surface — because
	// its granularity is load-bearing: pass-economy tests count analyses on
	// one view while another is live, which a package-global hook cannot
	// attribute.
	beforePreciseAnalysis func()
}

// NewView observes subjects and moduleDir as one code-result analysis view
// under the caller's context. Reachability and package loading are shared
// across the requested set, but each subject retains its independent closure
// semantics (REQ-closure-batch-equivalence).
func (e *Engine) NewView(ctx context.Context, subjects []Subject, moduleDir string) (*View, error) {
	return e.NewViewFor(ctx, subjects, moduleDir, CodeResult)
}

// NewViewFor observes one analysis view with the guards applicable to kind
// under the caller's context.
func (e *Engine) NewViewFor(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*View, error) {
	return e.newView(ctx, subjects, moduleDir, kind)
}

func (e *Engine) newView(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*View, error) {
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
	moduleDir, err = canonicalDir(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve guards tree: %w", err)
	}
	if err := e.coherentDir(moduleDir); err != nil {
		return nil, err
	}

	unique := make([]Subject, 0, len(subjects))
	seen := make(map[Subject]bool, len(subjects))
	packages := make([]string, 0, len(subjects))
	seenPackage := make(map[string]bool, len(subjects))
	requests := make([]closure.Subject, 0, len(subjects))
	for _, subject := range subjects {
		if subject.Package == "" || subject.Symbol == "" {
			return nil, fmt.Errorf("gofresh: invalid empty subject %+v", subject)
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

	first, err := e.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	second, err := e.observeView(ctx, unique, requests, packages, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	if first.guards != second.guards {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: guards during construction (%s)", ErrViewChanged, differingGuard(first.guards, second.guards))
	}
	for _, subject := range unique {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if first.maximal[subject] != second.maximal[subject] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: closure for %s.%s during construction%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(first.sourceFilesBySubject[subject], second.sourceFilesBySubject[subject], first.fileDigests, second.fileDigests))
		}
		if first.purity[subject] != second.purity[subject] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: purity for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
		}
		if !slices.Equal(first.sourceFilesBySubject[subject], second.sourceFilesBySubject[subject]) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: maximal source identities for %s.%s during construction%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(first.sourceFilesBySubject[subject], second.sourceFilesBySubject[subject], first.fileDigests, second.fileDigests))
		}
	}
	if !slices.Equal(first.sourceFiles, second.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// The construction race is the one refusal with no reproduction
		// path afterward, so naming here matters most.
		return nil, fmt.Errorf("%w: maximal source identities during construction%s", ErrViewChanged, movedIdentitySuffix(first.sourceFiles, second.sourceFiles, first.fileDigests, second.fileDigests))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	v := &View{
		engine:               e,
		subjects:             unique,
		requests:             requests,
		packages:             packages,
		moduleDir:            moduleDir,
		kind:                 kind,
		snapshot:             first.snapshot,
		maximal:              first.maximal,
		observable:           make(map[Subject]closure.Observability, len(unique)),
		guards:               first.guards,
		purity:               first.purity,
		sourceFiles:          first.sourceFiles,
		sourceFilesBySubject: first.sourceFilesBySubject,
		fileDigests:          first.fileDigests,
		testVariantLedgers:   first.testVariantLedgers,
		capturedObserved:     make(map[Subject]bool, len(unique)),
		attachedObservations: make(map[Subject]runtimeinput.State, len(unique)),
	}
	return v, nil
}

type viewObservation struct {
	snapshot             *gotool.EnvSnapshot
	maximal              map[Subject]closure.Closure
	guards               guard.Guards
	purity               map[Subject]string
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
	testVariantLedgers map[string]closure.TestVariantLedger
}

func (e *Engine) observeView(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind) (viewObservation, error) {
	if viewTestHooks.observe != nil {
		viewTestHooks.observe()
	}
	if e.progress != nil {
		e.progress(Progress{Phase: "observe"})
	}
	// One `go env -json` read serves this whole pass: the hasher's
	// GOMODCACHE and GOFLAGS validation, the guard's build-config digest,
	// and the typed load's validation all derive from it. The snapshot is
	// pass-scoped - a later pass takes its own, so environment drift still
	// meets an observation (REQ-guard-buildconfig; the toolchain guard's
	// `go version` stays a live probe: it carries the host platform).
	snapshot, err := gotool.TakeEnvSnapshot(ctx, e.dir, e.env)
	if err != nil {
		return viewObservation{}, err
	}
	hasher, err := closure.NewAtContextEnvSnapshot(ctx, e.dir, e.env, snapshot, e.buildFlags...)
	if err != nil {
		return viewObservation{}, err
	}
	guards, err := guard.CaptureForContextEnvSnapshot(ctx, moduleDir, e.env, kind, snapshot, e.guardInputs()...)
	if err != nil {
		return viewObservation{}, err
	}
	// One typed load serves this whole observation pass: scanViewSubjects
	// loads the view packages and every mutable-local graph package once,
	// installs the load on the hasher for the testing-type effect scan, and
	// serves version-pinned dynamic-state facts from the memo under the
	// guard-derived scope — so no two derivations of one pass can straddle
	// an edit (REQ-fresh-coherent-view). Each pass loads afresh; the paired
	// observations stay independent witnesses.
	factScope := DynamicStateStrategy + "|" + guards.Toolchain + "|" + guards.BuildConfig
	scan, _, err := scanViewSubjects(ctx, hasher, factScope, e.dir, e.env, e.buildFlags, snapshot, packages...)
	if err != nil {
		return viewObservation{}, err
	}
	directivePure, known, openWorld, external := scan.directivePure, scan.known, scan.openWorld, scan.external
	computed, sources, err := hasher.ComputeMaximalBatchWithSources(requests)
	if err != nil {
		return viewObservation{}, err
	}
	observation := viewObservation{
		snapshot:             snapshot,
		maximal:              make(map[Subject]closure.Closure, len(subjects)),
		guards:               guards,
		purity:               make(map[Subject]string, len(subjects)),
		sourceFilesBySubject: make(map[Subject][]string, len(subjects)),
		testVariantLedgers:   make(map[string]closure.TestVariantLedger, len(packages)),
	}
	for _, pkg := range packages {
		// Served from the hasher's compartment memo: the ledger was derived
		// from the same reads as the compartment hash above, never a
		// re-read that could straddle an edit.
		ledger, err := hasher.TestVariantLedger(pkg)
		if err != nil {
			return viewObservation{}, err
		}
		observation.testVariantLedgers[pkg] = ledger
	}
	seenSource := map[string]bool{}
	for _, request := range requests {
		for _, path := range sources[request] {
			if !seenSource[path] {
				seenSource[path] = true
				observation.sourceFiles = append(observation.sourceFiles, path)
			}
		}
	}
	sort.Strings(observation.sourceFiles)
	observation.fileDigests = make(map[string]string, len(observation.sourceFiles))
	for _, path := range observation.sourceFiles {
		if err := ctx.Err(); err != nil {
			return viewObservation{}, err
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
		if !known[subject] {
			return viewObservation{}, fmt.Errorf("gofresh: subject %s.%s not found in selected source", subject.Package, subject.Symbol)
		}
		maximal := computed[closure.Subject{Package: subject.Package, Symbol: subject.Symbol}]
		if openWorld[subject] {
			maximal.Unverifiable = true
			maximal.Reason = "subject accepts caller-supplied dynamic behavior"
		}
		if detail := scan.ambiguous[subject]; detail != "" {
			// Distinct declarations collapsed onto this identity: capture
			// is refused for this subject alone — the maximal package
			// closure stays the sound floor (it spans every declaring
			// variant), but no evidence can say WHICH declaration it
			// vouches for (REQ-purity-directive).
			maximal.Unverifiable = true
			maximal.Reason = "ambiguous subject identity: " + detail + "; rename one declaration to address either"
		}
		if external[subject] {
			// The author declared external state: unverifiable by
			// declaration, and no purity attribution is recorded — a purity
			// assertion confers nothing on an external-state subject
			// (REQ-external-directive, REQ-external-precedence).
			maximal.External = true
			maximal.Unverifiable = true
			maximal.Reason = "external directive"
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
		switch caller, directive := e.assumePure(subject), directivePure(subject); {
		case caller && directive:
			observation.purity[subject] = "caller assertion and source directive"
		case caller:
			observation.purity[subject] = "caller assertion"
		case directive:
			observation.purity[subject] = "source directive"
		}
	}
	return observation, nil
}

// Capture returns subject's precomputed fingerprint from this View. Runtime-input
// evidence belongs to the producing run and is attached by the caller afterward.
func (v *View) Capture(ctx context.Context, subject Subject) (Fingerprint, error) {
	if ctx == nil {
		return Fingerprint{}, errors.New("gofresh: nil analysis context")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return Fingerprint{}, ErrViewSealed
	}
	cl, ok := v.maximal[subject]
	if !ok {
		return Fingerprint{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	return Fingerprint{MaximalClosure: cl.Hash, TestVariantClosure: cl.TestVariants, Guards: v.guards, PurityAssertion: v.purity[subject], ResultKind: v.kind}, nil
}

// SourceFiles returns the absolute mutable source paths whose bytes contribute
// to this view's maximal closures. The returned slice is caller-owned.
func (v *View) SourceFiles() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]string(nil), v.sourceFiles...)
}

// SourceFilesFor returns the caller-owned mutable source paths contributing to
// subject's maximal closure in this view.
func (v *View) SourceFilesFor(subject Subject) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	files, ok := v.sourceFilesBySubject[subject]
	if !ok {
		return nil, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	return slices.Clone(files), nil
}

// TestVariantLedger returns the declaration ledger over subject's package
// test-variant compartment, as observed by this view: it is derived at view
// construction from the same file reads as the compartment hash the
// fingerprint records, so a caller persists it at capture and diffs it at
// check against exactly the bytes the verdict compared — never a re-read that
// could straddle a later edit (REQ-closure-test-variant-compartment,
// REQ-fresh-coherent-view). The returned value is caller-owned. A package with
// no test files yields an empty ledger.
func (v *View) TestVariantLedger(subject Subject) (TestVariantLedger, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if _, ok := v.maximal[subject]; !ok {
		return TestVariantLedger{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	ledger := v.testVariantLedgers[subject.Package]
	return TestVariantLedger{
		Declarations: slices.Clone(ledger.Declarations),
		FileHeaders:  slices.Clone(ledger.FileHeaders),
	}, nil
}

// CaptureBatch captures a fingerprint for every subject in the view,
// sharing the view's batched analysis across the set.
func (v *View) CaptureBatch(ctx context.Context) (map[Subject]Fingerprint, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return nil, ErrViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		cl := v.maximal[subject]
		result[subject] = Fingerprint{MaximalClosure: cl.Hash, TestVariantClosure: cl.TestVariants, Guards: v.guards, PurityAssertion: v.purity[subject], ResultKind: v.kind}
	}
	return result, nil
}

// CaptureObserved returns maximal closure evidence plus a caller-selected,
// attributable observation proof for subject.
func (v *View) CaptureObserved(ctx context.Context, subject Subject) (Fingerprint, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Fingerprint{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
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
		return Fingerprint{}, ErrViewSealed
	}
	v.capturedObserved[subject] = true
	return v.observedFingerprintLocked(subject), nil
}

// CaptureObservedBatch captures observation proof evidence for every
// subject, sharing one proof analysis across the set.
func (v *View) CaptureObservedBatch(ctx context.Context) (map[Subject]Fingerprint, error) {
	if err := v.ensureObservable(ctx, v.subjects); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gofresh: observation proof cancelled: %w", err)
	}
	if v.sealed {
		return nil, ErrViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		v.capturedObserved[subject] = true
		result[subject] = v.observedFingerprintLocked(subject)
	}
	return result, nil
}

func (v *View) observedFingerprintLocked(subject Subject) Fingerprint {
	disposition := v.observable[subject]
	proof := ObservationProof{
		Strategy:   ObservationRTA,
		Subject:    subject,
		Observable: disposition.Observable,
		Reason:     disposition.Reason,
	}
	const assertion = "caller assertion"
	proof.Evidence = observationProofEvidence(v.maximal[subject].Hash, assertion, proof)
	return Fingerprint{
		MaximalClosure:       v.maximal[subject].Hash,
		TestVariantClosure:   v.maximal[subject].TestVariants,
		ObservationAssertion: assertion,
		ObservationProof:     proof,
		Guards:               v.guards,
		PurityAssertion:      v.purity[subject],
		ResultKind:           v.kind,
	}
}

// AttachObservation binds sealed, process-backed runtime evidence to a captured
// observation proof. The returned fingerprint is ready for producer validation.
func (v *View) AttachObservation(subject Subject, fingerprint Fingerprint, observation runtimeinput.Observation) (Fingerprint, error) {
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		return Fingerprint{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return Fingerprint{}, ErrViewSealed
	}
	observed := v.observedFingerprintLocked(subject)
	if !v.capturedObserved[subject] || fingerprint != observed {
		return Fingerprint{}, errors.New("gofresh: observation does not match captured subject proof")
	}
	if _, attached := v.attachedObservations[subject]; attached {
		return Fingerprint{}, errors.New("gofresh: runtime observation already attached for subject")
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	v.attachedObservations[subject] = state
	return fingerprint, nil
}

// Check compares recorded against subject's current facts under this View's
// result kind and the caller's context.
func (v *View) Check(ctx context.Context, recorded Fingerprint, subject Subject) (Verdict, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	verdicts, err := v.checkBatch(ctx, map[Subject]Fingerprint{subject: recorded})
	if err != nil {
		return Verdict{}, err
	}
	return verdicts[subject], nil
}

// CheckBatch checks a caller-supplied recording set under the shared
// evidence ladder (REQ-fresh-hierarchical-check).
func (v *View) CheckBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	return v.checkBatch(ctx, recorded)
}

// CheckObserved explicitly checks a fingerprint under its recorded observation
// assertion and proof. Ordinary Check never infers this policy from evidence.
// It is the single-record form of CheckObservedBatch, so both share one window
// semantics: a runtime input moving mid-check stales a record whose verdict is
// not already stale, and demonstrated staleness is preferred over
// unverifiability.
func (v *View) CheckObserved(ctx context.Context, recorded Fingerprint, subject Subject) (Verdict, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
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
// subjects, and caller cancellation returns the context error.
func (v *View) CheckObservedBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil observation proof context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verdicts := make(map[Subject]Verdict, len(recorded))
	// Records whose staleness follows from their evidence alone are decided
	// before the observation window opens: their verdicts never consult runtime
	// state, so observing for them would only add cost and failure modes.
	pending := make(map[Subject]Fingerprint, len(recorded))
	positives := make(map[Subject]bool, len(recorded))
	for subject, rec := range recorded {
		if err := validateRecordedKind(rec); err != nil {
			return nil, err
		}
		if rec.ResultKind != v.kind {
			return nil, fmt.Errorf("gofresh: recorded result kind %d for %s.%s does not match view kind %d", rec.ResultKind, subject.Package, subject.Symbol, v.kind)
		}
		cl, ok := v.maximal[subject]
		if !ok {
			return nil, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
		}
		// The shared evidence ladder (core, compartment, fail-closed
		// pre-partition tiers) decides evidence-only staleness once for
		// every check surface (recordedEvidenceVerdict).
		if verdict, failed := recordedEvidenceVerdict(rec, cl); failed {
			verdicts[subject] = verdict
			continue
		}
		pending[subject] = rec
		positives[subject] = compatibleObservationProof(rec.ObservationProof, rec.ObservationAssertion, subject, rec.MaximalClosure) && rec.ObservationProof.Observable
	}
	hasRuntimeInputs := false
	for _, fingerprint := range pending {
		hasRuntimeInputs = hasRuntimeInputs || fingerprint.RuntimeInputs != ""
	}
	// The runtime-input window opens on the view's agreed facts and reads
	// only at close: any change since construction persisting to the
	// closing observation refuses there, so the re-read runtime values
	// bind to a source interval the close verifies stable - the opening
	// observation verified a prefix of the same interval
	// (REQ-fresh-coherent-view's record/compare asymmetry).
	runtimeBefore, err := v.observeRuntimeInputs(ctx, pending)
	if err != nil {
		return nil, err
	}
	finish := func() (map[Subject]Verdict, error) {
		finished, err := v.finishRuntimeObservation(ctx, pending, runtimeBefore, verdicts)
		if err != nil {
			return nil, err
		}
		if hasRuntimeInputs {
			if err := v.reobserveBase(ctx); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return finished, nil
	}
	for subject, rec := range pending {
		cl := v.maximal[subject]
		verdicts[subject] = v.withMovedInputs(ctx, decideAfterClosureObserved(rec, cl, v.guards, runtimeBefore[subject], v.kind, v.purityMatches(rec, subject), positives[subject] && rec.RuntimeInputs != ""), rec)
	}
	return finish()
}

func (v *View) checkBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verdicts := make(map[Subject]Verdict, len(recorded))
	// Evidence-only staleness is decided before the observation window opens;
	// those verdicts never consult runtime state.
	pending := make(map[Subject]Fingerprint, len(recorded))
	for subject, rec := range recorded {
		if err := validateRecordedKind(rec); err != nil {
			return nil, err
		}
		if rec.ResultKind != v.kind {
			return nil, fmt.Errorf("gofresh: recorded result kind %d for %s.%s does not match view kind %d", rec.ResultKind, subject.Package, subject.Symbol, v.kind)
		}
		maximal, ok := v.maximal[subject]
		if !ok {
			return nil, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
		}
		// The shared evidence ladder (core, compartment, fail-closed
		// pre-partition tiers) decides evidence-only staleness once for
		// every check surface (recordedEvidenceVerdict).
		if verdict, failed := recordedEvidenceVerdict(rec, maximal); failed {
			verdicts[subject] = verdict
			continue
		}
		pending[subject] = rec
	}
	hasRuntimeInputs := false
	for _, fingerprint := range pending {
		hasRuntimeInputs = hasRuntimeInputs || fingerprint.RuntimeInputs != ""
	}
	// The runtime-input window opens on the view's agreed facts and reads
	// only at close: any change since construction persisting to the
	// closing observation refuses there, so the re-read runtime values
	// bind to a source interval the close verifies stable - the opening
	// observation verified a prefix of the same interval
	// (REQ-fresh-coherent-view's record/compare asymmetry).
	runtimeBefore, err := v.observeRuntimeInputs(ctx, pending)
	if err != nil {
		return nil, err
	}
	finish := func() (map[Subject]Verdict, error) {
		finished, err := v.finishRuntimeObservation(ctx, pending, runtimeBefore, verdicts)
		if err != nil {
			return nil, err
		}
		if hasRuntimeInputs {
			if err := v.reobserveBase(ctx); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return finished, nil
	}
	for subject, rec := range pending {
		maximal := v.maximal[subject]
		verdicts[subject] = v.withMovedInputs(ctx, decideAfterClosure(rec, maximal, v.guards, runtimeBefore[subject], v.kind, v.purityMatches(rec, subject)), rec)
	}
	return finish()
}

func (v *View) purityMatches(recorded Fingerprint, subject Subject) bool {
	assertion := v.purity[subject]
	return validPurityAssertion(assertion) && validPurityAssertion(recorded.PurityAssertion)
}

func validPurityAssertion(assertion string) bool {
	switch assertion {
	case "caller assertion", "source directive", "caller assertion and source directive":
		return true
	default:
		return false
	}
}

func (v *View) observeRuntimeInputs(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]runtimeinput.State, error) {
	if v.engine != nil && v.engine.progress != nil {
		for _, fingerprint := range recorded {
			if fingerprint.RuntimeInputs != "" {
				v.engine.progress(Progress{Phase: "runtime"})
				break
			}
		}
	}
	observed := make(map[Subject]runtimeinput.State, len(recorded))
	for subject, fingerprint := range recorded {
		state, err := v.currentRuntimeContext(ctx, fingerprint)
		if err != nil {
			return nil, err
		}
		observed[subject] = state
	}
	return observed, nil
}

func (v *View) finishRuntimeObservation(ctx context.Context, recorded map[Subject]Fingerprint, before map[Subject]runtimeinput.State, verdicts map[Subject]Verdict) (map[Subject]Verdict, error) {
	after, err := v.observeRuntimeInputs(ctx, recorded)
	if err != nil {
		return nil, err
	}
	for subject, fingerprint := range recorded {
		if fingerprint.RuntimeInputs != "" && before[subject] != after[subject] {
			if verdicts[subject].Status != Stale {
				verdicts[subject] = v.withMovedInputs(ctx, Verdict{Stale, "runtimeinputs"}, fingerprint)
			}
		}
	}
	return verdicts, nil
}

func (v *View) currentRuntimeContext(ctx context.Context, recorded Fingerprint) (runtimeinput.State, error) {
	var rt runtimeinput.State
	var err error
	if recorded.RuntimeInputs != "" {
		// An unevaluable runtime-input guard is absence of proof: Stale, never
		// valid (REQ-guard-completeness).
		current := v.runtimeCurrent
		if current == nil {
			current = runtimeinput.CurrentContext
			if v.engine != nil {
				current = func(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
					return runtimeinput.CurrentEnvContext(ctx, encoded, moduleDir, v.engine.env)
				}
			}
		}
		if rt, err = current(ctx, recorded.RuntimeInputs, v.moduleDir); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return runtimeinput.State{}, contextErr
			}
			rt = runtimeinput.State{}
		}
	}
	return rt, nil
}

// Validate re-observes the View's complete subject set under the caller's
// context and reports ErrViewChanged when any source closure, guard, or purity
// assertion moved. A producer calls it after execution before persisting
// results (REQ-fresh-producer-view).
func (v *View) Validate(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	hasObserved := len(v.capturedObserved) != 0
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The view validates whatever it captured: observation proofs pull
	// in the observed arm, and a maximal-only producer the base
	// comparison - the engine owns the dispatch exactly as it owns the
	// capture strategy.
	if hasObserved {
		return v.validateObserved(ctx)
	}
	// A comparison-only observation reads once: these facts are never
	// recorded, so a torn read can only compare unequal and refuse - the
	// safe direction - while an equal torn read is the contract-excluded
	// restore interval (REQ-fresh-coherent-view's record/compare
	// asymmetry). The agreement pair is load-bearing exactly where an
	// observation becomes the record: view construction.
	observation, err := v.engine.observeView(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := v.compareObservationContext(ctx, observation); err != nil {
		return err
	}
	return ctx.Err()
}

// newSeededValidationView builds the validation arm's view from one fresh
// observation: the current tree is read once and compared against the
// producer view's captured facts — refusal on any drift — and on agreement
// the captured facts seed the validation view directly. The seeded facts
// rest on a genuine agreement pair whose reads span capture time and
// validation time, so they are record-grade without a second construction
// pair (REQ-fresh-coherent-view's record/compare asymmetry).
func (v *View) newSeededValidationView(ctx context.Context) (*View, error) {
	observation, err := v.engine.observeView(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind)
	if err != nil {
		return nil, err
	}
	if err := v.compareObservationContext(ctx, observation); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	current := &View{
		engine:               v.engine,
		subjects:             v.subjects,
		requests:             v.requests,
		packages:             v.packages,
		moduleDir:            v.moduleDir,
		kind:                 v.kind,
		snapshot:             v.snapshot,
		maximal:              v.maximal,
		observable:           make(map[Subject]closure.Observability, len(v.subjects)),
		guards:               v.guards,
		purity:               v.purity,
		sourceFiles:          v.sourceFiles,
		sourceFilesBySubject: v.sourceFilesBySubject,
		fileDigests:          v.fileDigests,
		testVariantLedgers:   v.testVariantLedgers,
		capturedObserved:     make(map[Subject]bool, len(v.subjects)),
		attachedObservations: make(map[Subject]runtimeinput.State, len(v.subjects)),
	}
	return current, nil
}

// validateObserved re-establishes every captured observation proof and
// attached runtime state.
func (v *View) validateObserved(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil observation validation context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := v.newSeededValidationView(ctx)
	if err != nil {
		return err
	}
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
	if err := v.compareAttachedObservations(ctx, attached, subjects); err != nil {
		return err
	}
	if err := current.ensureObservable(ctx, subjects); err != nil {
		return err
	}
	current.mu.RLock()
	for _, subject := range subjects {
		if err := compareObservationProof(subject, current.observable[subject], expected[subject]); err != nil {
			current.mu.RUnlock()
			return err
		}
	}
	current.mu.RUnlock()
	return v.compareAttachedObservations(ctx, attached, subjects)
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

// analysisUnavailable reports whether an observability disposition records
// analysis unavailability rather than an analyzed rejection. The prefix is the
// one vocabulary both the closure analysis and the isolation fallback emit.
func analysisUnavailable(reason string) bool {
	return strings.HasPrefix(reason, "observation analysis unavailable")
}

// differingGuard names the first environment guard whose two construction
// observations disagreed — the actionable component behind a bare "guards
// moved".
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
	const show = 3
	if len(moved) > show {
		return fmt.Sprintf(" (moved: %s, and %d more)", strings.Join(moved[:show], ", "), len(moved)-show)
	}
	return fmt.Sprintf(" (moved: %s)", strings.Join(moved, ", "))
}

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

// movedSummary renders a bounded mover list for refusal texts: enough to act
// on, never a wall of paths.
func movedSummary(movers []string) string {
	const limit = 3
	if len(movers) <= limit {
		return strings.Join(movers, ", ")
	}
	return strings.Join(movers[:limit], ", ") + fmt.Sprintf(", and %d more", len(movers)-limit)
}

// movedInputsForView attributes against the view's own environment, degrading
// to no attribution on an engine-less view (the direct-construct test shape).
func movedInputsForView(ctx context.Context, v *View, encoded string) ([]string, error) {
	if v.engine == nil {
		return nil, nil
	}
	return runtimeinput.MovedInputsContext(ctx, encoded, v.moduleDir, v.engine.env)
}

// withMovedInputs names the movers behind a stale runtime-inputs verdict
// (REQ-inputs-path-identities attribution): the one-word reason stays for
// undecodable or moverless manifests — an older recording regenerates either
// way — and gains "(moved: …)" whenever attribution is derivable.
func (v *View) withMovedInputs(ctx context.Context, verdict Verdict, recorded Fingerprint) Verdict {
	if verdict.Status != Stale || verdict.Reason != "runtimeinputs" || recorded.RuntimeInputs == "" || v.engine == nil {
		return verdict
	}
	movers, err := movedInputsForView(ctx, v, recorded.RuntimeInputs)
	if err != nil || len(movers) == 0 {
		return verdict
	}
	verdict.Reason = "runtimeinputs (moved: " + movedSummary(movers) + ")"
	return verdict
}

func (v *View) compareAttachedObservations(ctx context.Context, attached map[Subject]runtimeinput.State, subjects []Subject) error {
	for _, subject := range subjects {
		state := attached[subject]
		if !state.OK || state.Manifest == "" || state.Digest == "" {
			return fmt.Errorf("gofresh: subject %s.%s has no attached completed observation", subject.Package, subject.Symbol)
		}
		var observed runtimeinput.State
		var err error
		if v.runtimeCurrent != nil {
			observed, err = v.runtimeCurrent(ctx, state.Manifest, v.moduleDir)
		} else {
			observed, err = runtimeinput.CurrentEnvContext(ctx, state.Manifest, v.moduleDir, v.engine.env)
		}
		if err != nil {
			return err
		}
		if observed != state {
			detail := ""
			if movers, moveErr := movedInputsForView(ctx, v, state.Manifest); moveErr == nil && len(movers) > 0 {
				detail = " (moved: " + movedSummary(movers) + ")"
			}
			return fmt.Errorf("%w: runtime inputs for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, detail)
		}
	}
	return ctx.Err()
}

// reobserveBase detects source, guard, or purity drift since view construction
// with one fresh observation compared against the constructing view. This
// provides the same ordinary-drift guarantee as a full double-observed view per
// side: any change persisting to an observation is caught, while a
// mutation-and-restore interval between agreeing observations is not guaranteed
// detectable under either shape (REQ-inputs-observation-coherence).
func (v *View) reobserveBase(ctx context.Context) error {
	observation, err := v.engine.observeView(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	return v.compareObservationContext(ctx, observation)
}

func (v *View) compareBaseContext(ctx context.Context, current *View) error {
	return v.compareFactsContext(ctx, current.guards, current.sourceFiles, current.maximal, current.purity, current.sourceFilesBySubject, current.fileDigests)
}

func (v *View) compareObservationContext(ctx context.Context, observation viewObservation) error {
	return v.compareFactsContext(ctx, observation.guards, observation.sourceFiles, observation.maximal, observation.purity, observation.sourceFilesBySubject, observation.fileDigests)
}

func (v *View) compareFactsContext(ctx context.Context, guards guard.Guards, sourceFiles []string, maximal map[Subject]closure.Closure, purity map[Subject]string, sourceFilesBySubject map[Subject][]string, fileDigests map[string]string) error {
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if guards != v.guards {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: guards (%s)", ErrViewChanged, differingGuard(guards, v.guards))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !slices.Equal(sourceFiles, v.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: maximal source identities%s", ErrViewChanged, movedIdentitySuffix(v.sourceFiles, sourceFiles, v.fileDigests, fileDigests))
	}
	for _, subject := range v.subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !slices.Equal(sourceFilesBySubject[subject], v.sourceFilesBySubject[subject]) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: maximal source identities for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(v.sourceFilesBySubject[subject], sourceFilesBySubject[subject], v.fileDigests, fileDigests))
		}
		if maximal[subject] != v.maximal[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: closure for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(v.sourceFilesBySubject[subject], sourceFilesBySubject[subject], v.fileDigests, fileDigests))
		}
		if purity[subject] != v.purity[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: purity for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	return ctx.Err()
}

// ensureObservable runs the drift-forced observability proof for subjects
// not yet computed, inside one single-observation drift bracket pair and
// over one shared closure Hasher
// (REQ-fresh-coherent-view attribution; equivalence per
// REQ-closure-observability-batch-equivalence).
func (v *View) ensureObservable(ctx context.Context, subjects []Subject) error {
	if ctx == nil {
		return errors.New("gofresh: nil precise-analysis context")
	}
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
	if viewTestHooks.snapshot != nil {
		viewTestHooks.snapshot(v.snapshot)
	}
	hasher, err := closure.NewAtContextEnvBracket(ctx, v.engine.dir, v.engine.env, v.snapshot, v.engine.buildFlags...)
	if err != nil {
		return err
	}
	// The observability memo's scope is the analysis identity outside the
	// source closure: the proof-strategy version plus the code guards.
	// The memo key completes with the package test-binary closure hash
	// inside the Hasher (REQ-closure-observability-memo).
	hasher.SetMemoScope(ObservationRTA + "|" + v.guards.Toolchain + "|" + v.guards.BuildConfig)
	if progress := v.engine.progress; progress != nil {
		hasher.OnProgress(func(phase, pkgPath string) {
			progress(Progress{Phase: phase, Package: pkgPath})
		})
	}
	// The caller's analysis budget bounds only the precise analysis itself: the
	// Hasher's analysis context carries the budget deadline, so exhaustion
	// surfaces as analysis failure — degrading to unavailable evidence, never
	// validity — while the operation, its brackets, and Hasher construction
	// stay governed by the caller's context alone.
	if budget := v.engine.analysisBudget; budget > 0 {
		analysisCtx, cancelBudget := context.WithTimeout(ctx, budget)
		defer cancelBudget()
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
		for _, request := range observableRequests {
			isolated, isolatedErr := hasher.ComputeObservabilityBatch([]closure.Subject{request})
			if isolatedErr != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("gofresh: observation proof cancelled: %w", ctx.Err())
				}
				observableComputed[request] = closure.Observability{Reason: "observation analysis unavailable: " + isolatedErr.Error()}
				continue
			}
			maps.Copy(observableComputed, isolated)
		}
	}
	after, err := v.engine.observeView(ctx, v.subjects, v.requests, v.packages, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := v.compareObservationContext(ctx, after); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return ErrViewSealed
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

func compatibleObservationProof(proof ObservationProof, assertion string, subject Subject, maximalClosure string) bool {
	if assertion != "caller assertion" || proof.Strategy != ObservationRTA || proof.Subject != subject {
		return false
	}
	if proof.Observable == (proof.Reason != "") {
		return false
	}
	return proof.Evidence == observationProofEvidence(maximalClosure, assertion, proof)
}

func observationProofEvidence(maximalClosure, assertion string, proof ObservationProof) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%d:%s", len(maximalClosure), maximalClosure, len(assertion), assertion, len(proof.Strategy), proof.Strategy, len(proof.Subject.Package), proof.Subject.Package, len(proof.Subject.Symbol), proof.Subject.Symbol, proof.Observable, len(proof.Reason), proof.Reason))
	return hex.EncodeToString(sum[:])[:32]
}
