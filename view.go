package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// ErrViewChanged reports that a producer View no longer describes the current
// source, build, guard, or purity state and its results must not be persisted.
var ErrViewChanged = errors.New("gofresh: analysis view changed")

// ErrRefinedValidationRequired reports that a producer captured refined evidence
// and must validate it through ValidateRefined with caller-owned cancellation.
var ErrRefinedValidationRequired = errors.New("gofresh: refined producer view requires refined validation")

// ErrViewSealed reports a capture attempted after producer validation started.
var ErrViewSealed = errors.New("gofresh: analysis view sealed by validation")

// View is one immutable observation of the source, build, guards, and purity
// behind a caller-supplied subject set. It can serve a current check batch or a
// producer transaction; analysis state is never shared with another View.
type View struct {
	mu                   sync.RWMutex
	engine               *Engine
	subjects             []Subject
	moduleDir            string
	kind                 Kind
	maximal              map[Subject]closure.Closure
	refined              map[Subject]closure.Closure
	guards               guard.Guards
	purity               map[Subject]string
	openWorld            map[Subject]bool
	sourceFiles          []string
	sourceFilesBySubject map[Subject][]string
	capturedRefined      map[Subject]bool
	sealed               bool
	runtimeCurrent       func(context.Context, string, string) (runtimeinput.State, error)
}

// NewView observes subjects and moduleDir as one code-result analysis view.
// Reachability and
// package loading are shared across the requested set, but each subject retains
// its independent closure semantics (REQ-closure-batch-equivalence).
func (e *Engine) NewView(subjects []Subject, moduleDir string) (*View, error) {
	return e.NewViewFor(subjects, moduleDir, CodeResult)
}

// NewViewContext observes one code-result analysis view under ctx.
func (e *Engine) NewViewContext(ctx context.Context, subjects []Subject, moduleDir string) (*View, error) {
	return e.NewViewForContext(ctx, subjects, moduleDir, CodeResult)
}

// NewViewFor observes one analysis view with the guards applicable to kind.
func (e *Engine) NewViewFor(subjects []Subject, moduleDir string, kind Kind) (*View, error) {
	return e.newView(context.Background(), subjects, moduleDir, kind)
}

// NewViewForContext observes one analysis view with kind's guards under ctx.
func (e *Engine) NewViewForContext(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*View, error) {
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
		return nil, fmt.Errorf("%w: guards during construction", ErrViewChanged)
	}
	for _, subject := range unique {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if first.maximal[subject] != second.maximal[subject] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: closure for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
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
			return nil, fmt.Errorf("%w: maximal source identities for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	if !slices.Equal(first.sourceFiles, second.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: maximal source identities during construction", ErrViewChanged)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	v := &View{
		engine:               e,
		subjects:             unique,
		moduleDir:            moduleDir,
		kind:                 kind,
		maximal:              first.maximal,
		refined:              make(map[Subject]closure.Closure, len(unique)),
		guards:               first.guards,
		purity:               first.purity,
		openWorld:            first.openWorld,
		sourceFiles:          first.sourceFiles,
		sourceFilesBySubject: first.sourceFilesBySubject,
		capturedRefined:      make(map[Subject]bool, len(unique)),
	}
	return v, nil
}

type viewObservation struct {
	maximal              map[Subject]closure.Closure
	guards               guard.Guards
	purity               map[Subject]string
	openWorld            map[Subject]bool
	sourceFiles          []string
	sourceFilesBySubject map[Subject][]string
}

func (e *Engine) observeView(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string, kind Kind) (viewObservation, error) {
	hasher, err := closure.NewAtContextEnv(ctx, e.dir, e.env, e.buildFlags...)
	if err != nil {
		return viewObservation{}, err
	}
	computed, sources, err := hasher.ComputeMaximalBatchWithSources(requests)
	if err != nil {
		return viewObservation{}, err
	}
	guards, err := guard.CaptureForContextEnv(ctx, moduleDir, e.env, kind, e.guardInputs()...)
	if err != nil {
		return viewObservation{}, err
	}
	directivePure, known, openWorld, err := scanSubjectsInWithBuildFlagsEnv(ctx, e.dir, e.env, e.buildFlags, packages...)
	if err != nil {
		return viewObservation{}, err
	}
	observation := viewObservation{
		maximal:              make(map[Subject]closure.Closure, len(subjects)),
		guards:               guards,
		purity:               make(map[Subject]string, len(subjects)),
		openWorld:            make(map[Subject]bool, len(subjects)),
		sourceFilesBySubject: make(map[Subject][]string, len(subjects)),
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
	for _, subject := range subjects {
		if !known[subject] {
			return viewObservation{}, fmt.Errorf("gofresh: subject %s.%s not found in selected source", subject.Package, subject.Symbol)
		}
		maximal := computed[closure.Subject{Package: subject.Package, Symbol: subject.Symbol}]
		if openWorld[subject] {
			maximal.Unverifiable = true
			maximal.Reason = "subject accepts caller-supplied dynamic behavior"
			observation.openWorld[subject] = true
		}
		observation.maximal[subject] = maximal
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		observation.sourceFilesBySubject[subject] = slices.Clone(sources[request])
		sort.Strings(observation.sourceFilesBySubject[subject])
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
func (v *View) Capture(subject Subject) (Fingerprint, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return Fingerprint{}, ErrViewSealed
	}
	cl, ok := v.maximal[subject]
	if !ok {
		return Fingerprint{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	return Fingerprint{MaximalClosure: cl.Hash, Guards: v.guards, PurityAssertion: v.purity[subject], ResultKind: v.kind}, nil
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

// CaptureRefined returns maximal and declaration-RTA evidence for subject under
// the caller-selected ctx. Use CaptureRefinedBatch to share attributed analysis
// across the view's complete subject set.
func (v *View) CaptureRefined(ctx context.Context, subject Subject) (Fingerprint, error) {
	return v.captureRefined(ctx, subject, nil)
}

func (v *View) captureRefined(ctx context.Context, subject Subject, beforePublish func()) (Fingerprint, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Fingerprint{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	if err := v.ensureRefined(ctx, []Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	if beforePublish != nil {
		beforePublish()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Fingerprint{}, fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	if v.sealed {
		return Fingerprint{}, ErrViewSealed
	}
	v.capturedRefined[subject] = true
	return v.refinedFingerprintLocked(subject), nil
}

// CaptureRefinedBatch captures refined evidence for every subject in the view.
func (v *View) CaptureRefinedBatch(ctx context.Context) (map[Subject]Fingerprint, error) {
	if err := v.ensureRefined(ctx, v.subjects); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	if v.sealed {
		return nil, ErrViewSealed
	}
	result := make(map[Subject]Fingerprint, len(v.subjects))
	for _, subject := range v.subjects {
		v.capturedRefined[subject] = true
		result[subject] = v.refinedFingerprintLocked(subject)
	}
	return result, nil
}

func (v *View) refinedFingerprintLocked(subject Subject) Fingerprint {
	cl := v.refined[subject]
	reason := ""
	if cl.Unverifiable {
		reason = reasonOr(cl.Reason, "external dependence")
	}
	refinement := Refinement{
		Strategy:     DeclarationRTA,
		Subject:      subject,
		Closure:      refinedSubjectHash(subject, cl.Hash),
		Unverifiable: cl.Unverifiable,
		Reason:       reason,
	}
	refinement.Evidence = refinementEvidence(v.maximal[subject].Hash, refinement)
	return Fingerprint{
		MaximalClosure:  v.maximal[subject].Hash,
		Refinement:      refinement,
		Guards:          v.guards,
		PurityAssertion: v.purity[subject],
		ResultKind:      v.kind,
	}
}

// Check compares recorded against subject's current facts under this View's result kind.
func (v *View) Check(recorded Fingerprint, subject Subject) (Verdict, error) {
	return v.CheckContext(context.Background(), recorded, subject)
}

// CheckContext compares recorded against subject's current facts under ctx.
func (v *View) CheckContext(ctx context.Context, recorded Fingerprint, subject Subject) (Verdict, error) {
	if ctx == nil {
		return Verdict{}, errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	if err := validateRecordedKind(recorded); err != nil {
		return Verdict{}, err
	}
	if recorded.ResultKind != v.kind {
		return Verdict{}, fmt.Errorf("gofresh: recorded result kind %d does not match view kind %d", recorded.ResultKind, v.kind)
	}
	cl, ok := v.maximal[subject]
	if !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	if recorded.MaximalClosure == "" || recorded.MaximalClosure != cl.Hash {
		if err := ctx.Err(); err != nil {
			return Verdict{}, err
		}
		return Verdict{Stale, "closure"}, nil
	}
	if recorded.RuntimeInputs != "" {
		if err := v.reobserveBase(ctx); err != nil {
			return Verdict{}, err
		}
		runtimeState, err := v.currentRuntimeContext(ctx, recorded)
		if err != nil {
			return Verdict{}, err
		}
		afterRuntime, err := v.currentRuntimeContext(ctx, recorded)
		if err != nil {
			return Verdict{}, err
		}
		if err := v.reobserveBase(ctx); err != nil {
			return Verdict{}, err
		}
		if runtimeState != afterRuntime {
			if err := ctx.Err(); err != nil {
				return Verdict{}, err
			}
			return Verdict{Stale, "runtimeinputs"}, nil
		}
		verdict := decideAfterClosure(recorded, cl, v.guards, runtimeState, v.kind, v.purityMatches(recorded, subject))
		if err := ctx.Err(); err != nil {
			return Verdict{}, err
		}
		return verdict, nil
	}
	verdict := v.checkAfterClosure(recorded, subject, cl)
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	return verdict, nil
}

// CheckRefined compares maximal evidence first. It invokes declaration-RTA under
// ctx only after maximal drift and only for compatible refined evidence.
func (v *View) CheckRefined(ctx context.Context, recorded Fingerprint, subject Subject) (Verdict, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	verdicts, err := v.checkRefinedBatch(ctx, map[Subject]Fingerprint{subject: recorded})
	if err != nil {
		return Verdict{}, err
	}
	return verdicts[subject], nil
}

// CheckRefinedBatch checks a caller-supplied recording set, batching precise
// analysis only for subjects whose maximal evidence drifted.
func (v *View) CheckRefinedBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	return v.checkRefinedBatch(ctx, recorded)
}

func (v *View) checkRefinedBatch(ctx context.Context, recorded map[Subject]Fingerprint) (map[Subject]Verdict, error) {
	verdicts := make(map[Subject]Verdict, len(recorded))
	observationCtx := context.Background()
	hasRuntimeInputs := false
	for _, fingerprint := range recorded {
		hasRuntimeInputs = hasRuntimeInputs || fingerprint.RuntimeInputs != ""
	}
	if hasRuntimeInputs {
		if err := v.reobserveBase(observationCtx); err != nil {
			return nil, err
		}
	}
	runtimeBefore := v.observeRuntimeInputs(recorded)
	finish := func() (map[Subject]Verdict, error) {
		finished := v.finishRuntimeObservation(recorded, runtimeBefore, verdicts)
		if hasRuntimeInputs {
			if err := v.reobserveBase(observationCtx); err != nil {
				return nil, err
			}
		}
		return finished, nil
	}
	var drifted []Subject
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
		if rec.MaximalClosure == "" {
			verdicts[subject] = Verdict{Stale, "closure"}
			continue
		}
		if rec.Refinement != (Refinement{}) && !compatibleRefinement(rec.Refinement, subject, rec.MaximalClosure) {
			verdicts[subject] = Verdict{Stale, "refinement"}
			continue
		}
		if rec.MaximalClosure != maximal.Hash {
			if rec.Refinement == (Refinement{}) {
				verdicts[subject] = Verdict{Stale, "refinement"}
				continue
			}
			if verdict, failed := decideKnownGuards(rec, v.guards, runtimeBefore[subject], v.kind); failed {
				verdicts[subject] = verdict
				continue
			}
			drifted = append(drifted, subject)
			continue
		}

		// Maximal equality proves the source behind compatible recorded precise
		// evidence is unchanged, so no precise analysis is run.
		effective := maximal
		if compatibleRefinement(rec.Refinement, subject, rec.MaximalClosure) {
			effective.Unverifiable = rec.Refinement.Unverifiable
			effective.Reason = rec.Refinement.Reason
		}
		verdicts[subject] = decideAfterClosure(rec, effective, v.guards, runtimeBefore[subject], v.kind, v.purityMatches(rec, subject))
	}

	if len(drifted) == 0 {
		return finish()
	}
	if err := v.ensureRefined(ctx, drifted); err != nil {
		for _, subject := range drifted {
			verdicts[subject] = Verdict{Unverifiable, "refinement unavailable: " + err.Error()}
		}
		return finish()
	}
	v.mu.RLock()
	currentRefined := make(map[Subject]closure.Closure, len(drifted))
	for _, subject := range drifted {
		currentRefined[subject] = v.refined[subject]
	}
	v.mu.RUnlock()
	for _, subject := range drifted {
		rec := recorded[subject]
		current := currentRefined[subject]
		if rec.Refinement.Closure != refinedSubjectHash(subject, current.Hash) {
			verdicts[subject] = Verdict{Stale, "refinement"}
			continue
		}
		verdicts[subject] = decideAfterClosure(rec, current, v.guards, runtimeBefore[subject], v.kind, v.purityMatches(rec, subject))
	}
	return finish()
}

func (v *View) checkAfterClosure(recorded Fingerprint, subject Subject, cl closure.Closure) Verdict {
	rt := v.currentRuntime(recorded)
	return decideAfterClosure(recorded, cl, v.guards, rt, v.kind, v.purityMatches(recorded, subject))
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

func (v *View) knownGuardVerdict(recorded Fingerprint) (Verdict, bool) {
	return decideKnownGuards(recorded, v.guards, v.currentRuntime(recorded), v.kind)
}

func (v *View) observeRuntimeInputs(recorded map[Subject]Fingerprint) map[Subject]runtimeinput.State {
	observed := make(map[Subject]runtimeinput.State, len(recorded))
	for subject, fingerprint := range recorded {
		observed[subject] = v.currentRuntime(fingerprint)
	}
	return observed
}

func (v *View) finishRuntimeObservation(recorded map[Subject]Fingerprint, before map[Subject]runtimeinput.State, verdicts map[Subject]Verdict) map[Subject]Verdict {
	after := v.observeRuntimeInputs(recorded)
	for subject, fingerprint := range recorded {
		if fingerprint.RuntimeInputs != "" && before[subject] != after[subject] {
			if verdicts[subject].Status != Stale {
				verdicts[subject] = Verdict{Stale, "runtimeinputs"}
			}
		}
	}
	return verdicts
}

func (v *View) currentRuntime(recorded Fingerprint) runtimeinput.State {
	rt, _ := v.currentRuntimeContext(context.Background(), recorded)
	return rt
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

// Validate re-observes the View's complete subject set and reports ErrViewChanged
// when any source closure, guard, or purity assertion moved. A producer calls it
// after execution before persisting results (REQ-fresh-producer-view).
func (v *View) Validate() error {
	return v.ValidateContext(context.Background())
}

// ValidateContext re-observes the complete maximal view under ctx.
func (v *View) ValidateContext(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	hasRefined := len(v.capturedRefined) != 0
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if hasRefined {
		return ErrRefinedValidationRequired
	}
	current, err := v.engine.NewViewForContext(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := v.compareBaseContext(ctx, current); err != nil {
		return err
	}
	return ctx.Err()
}

// ValidateRefined re-observes the view and every refined closure captured from it
// under ctx. A producer must use it before persisting refined results.
func (v *View) ValidateRefined(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	v.mu.Unlock()
	if ctx == nil {
		return errors.New("gofresh: nil refinement context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := v.engine.newView(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := v.compareBaseContext(ctx, current); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.RLock()
	subjects := make([]Subject, 0, len(v.capturedRefined))
	expected := make(map[Subject]closure.Closure, len(v.capturedRefined))
	for _, subject := range v.subjects {
		if v.capturedRefined[subject] {
			subjects = append(subjects, subject)
			expected[subject] = v.refined[subject]
		}
	}
	v.mu.RUnlock()
	if len(subjects) == 0 {
		return ctx.Err()
	}
	if err := current.ensureRefined(ctx, subjects); err != nil {
		return err
	}
	final, err := v.engine.newView(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := current.compareBaseContext(ctx, final); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current.mu.RLock()
	defer current.mu.RUnlock()
	return compareRefinedContext(ctx, current.refined, expected, subjects)
}

func compareRefinedContext(ctx context.Context, current, expected map[Subject]closure.Closure, subjects []Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if current[subject] != expected[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: refinement for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	return ctx.Err()
}

func (v *View) reobserveBase(ctx context.Context) error {
	current, err := v.engine.newView(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	return v.compareBaseContext(ctx, current)
}

func (v *View) compareBase(current *View) error {
	return v.compareBaseContext(context.Background(), current)
}

func (v *View) compareBaseContext(ctx context.Context, current *View) error {
	if ctx == nil {
		return errors.New("gofresh: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if current.guards != v.guards {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: guards", ErrViewChanged)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !slices.Equal(current.sourceFiles, v.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: maximal source identities", ErrViewChanged)
	}
	for _, subject := range v.subjects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !slices.Equal(current.sourceFilesBySubject[subject], v.sourceFilesBySubject[subject]) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: maximal source identities for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
		if current.maximal[subject] != v.maximal[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: closure for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
		if current.purity[subject] != v.purity[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: purity for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	return ctx.Err()
}

func (v *View) ensureRefined(ctx context.Context, subjects []Subject) error {
	if ctx == nil {
		return errors.New("gofresh: nil refinement context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	v.mu.RLock()
	requests := make([]closure.Subject, 0, len(subjects))
	expected := make(map[closure.Subject]closure.Closure, len(subjects))
	for _, subject := range subjects {
		if _, ok := v.refined[subject]; ok {
			continue
		}
		request := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
		requests = append(requests, request)
		expected[request] = v.maximal[subject]
	}
	v.mu.RUnlock()
	if len(requests) == 0 {
		return nil
	}
	beforeView, err := v.engine.newView(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := v.compareBaseContext(ctx, beforeView); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	hasher, err := closure.NewAtContextEnv(ctx, v.engine.dir, v.engine.env, v.engine.buildFlags...)
	if err != nil {
		return err
	}
	computed, err := hasher.ComputeBatch(requests)
	if err != nil {
		return err
	}
	afterView, err := v.engine.newView(ctx, v.subjects, v.moduleDir, v.kind)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	if err := v.compareBaseContext(ctx, afterView); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	for _, request := range requests {
		subject := Subject{Package: request.Package, Symbol: request.Symbol}
		if _, ok := v.refined[subject]; !ok {
			v.refined[subject] = retainMaximalDisposition(expected[request], computed[request], v.openWorld[subject])
		}
	}
	return nil
}

func retainMaximalDisposition(maximal, refined closure.Closure, openWorld bool) closure.Closure {
	if maximal.Unverifiable && (openWorld || refined.Widened || maximal.Unrefinable) {
		refined.Unverifiable = true
		refined.Reason = maximal.Reason
	}
	return refined
}

func compatibleRefinement(ref Refinement, subject Subject, maximalClosure string) bool {
	return ref.Strategy == DeclarationRTA && ref.Subject == subject && ref.Closure != "" && ref.Unverifiable == (ref.Reason != "") && ref.Evidence == refinementEvidence(maximalClosure, ref)
}

func refinementEvidence(maximalClosure string, ref Refinement) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s%d:%s%t%d:%s", len(maximalClosure), maximalClosure, len(ref.Strategy), ref.Strategy, len(ref.Subject.Package), ref.Subject.Package, len(ref.Subject.Symbol), ref.Subject.Symbol, len(ref.Closure), ref.Closure, ref.Unverifiable, len(ref.Reason), ref.Reason))
	return hex.EncodeToString(sum[:])[:32]
}

func refinedSubjectHash(subject Subject, closureHash string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s", len(DeclarationRTA), DeclarationRTA, len(closureHash), closureHash, len(subject.Package), subject.Package, len(subject.Symbol), subject.Symbol))
	return hex.EncodeToString(sum[:])[:32]
}
