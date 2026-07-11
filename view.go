package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	mu              sync.RWMutex
	engine          *Engine
	subjects        []Subject
	moduleDir       string
	maximal         map[Subject]closure.Closure
	refined         map[Subject]closure.Closure
	guards          guard.Guards
	purity          map[Subject]string
	openWorld       map[Subject]bool
	capturedRefined map[Subject]bool
	sealed          bool
	runtimeCurrent  func(string, string) (runtimeinput.State, error)
}

// NewView observes subjects and moduleDir as one analysis view. Reachability and
// package loading are shared across the requested set, but each subject retains
// its independent closure semantics (REQ-closure-batch-equivalence).
func (e *Engine) NewView(subjects []Subject, moduleDir string) (*View, error) {
	return e.newView(context.Background(), subjects, moduleDir)
}

func (e *Engine) newView(ctx context.Context, subjects []Subject, moduleDir string) (*View, error) {
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

	first, err := e.observeView(ctx, unique, requests, packages, moduleDir)
	if err != nil {
		return nil, err
	}
	second, err := e.observeView(ctx, unique, requests, packages, moduleDir)
	if err != nil {
		return nil, err
	}
	if first.guards != second.guards {
		return nil, fmt.Errorf("%w: guards during construction", ErrViewChanged)
	}
	for _, subject := range unique {
		if first.maximal[subject] != second.maximal[subject] {
			return nil, fmt.Errorf("%w: closure for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
		}
		if first.purity[subject] != second.purity[subject] {
			return nil, fmt.Errorf("%w: purity for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}

	v := &View{
		engine:          e,
		subjects:        unique,
		moduleDir:       moduleDir,
		maximal:         first.maximal,
		refined:         make(map[Subject]closure.Closure, len(unique)),
		guards:          first.guards,
		purity:          first.purity,
		openWorld:       first.openWorld,
		capturedRefined: make(map[Subject]bool, len(unique)),
	}
	return v, nil
}

type viewObservation struct {
	maximal   map[Subject]closure.Closure
	guards    guard.Guards
	purity    map[Subject]string
	openWorld map[Subject]bool
}

func (e *Engine) observeView(ctx context.Context, subjects []Subject, requests []closure.Subject, packages []string, moduleDir string) (viewObservation, error) {
	hasher, err := closure.NewAtContext(ctx, e.dir, e.buildFlags...)
	if err != nil {
		return viewObservation{}, err
	}
	computed, err := hasher.ComputeMaximalBatch(requests)
	if err != nil {
		return viewObservation{}, err
	}
	guards, err := guard.CaptureContext(ctx, moduleDir, e.guardInputs()...)
	if err != nil {
		return viewObservation{}, err
	}
	directivePure, known, openWorld, err := scanSubjectsInWithBuildFlags(ctx, e.dir, e.buildFlags, packages...)
	if err != nil {
		return viewObservation{}, err
	}
	observation := viewObservation{
		maximal:   make(map[Subject]closure.Closure, len(subjects)),
		guards:    guards,
		purity:    make(map[Subject]string, len(subjects)),
		openWorld: make(map[Subject]bool, len(subjects)),
	}
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
	return Fingerprint{MaximalClosure: cl.Hash, Guards: v.guards, PurityAssertion: v.purity[subject]}, nil
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
	}
}

// Check compares recorded against subject's current facts in this View.
func (v *View) Check(recorded Fingerprint, subject Subject, kind Kind) (Verdict, error) {
	cl, ok := v.maximal[subject]
	if !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	if recorded.MaximalClosure == "" || recorded.MaximalClosure != cl.Hash {
		return Verdict{Stale, "closure"}, nil
	}
	if recorded.RuntimeInputs != "" {
		if err := v.reobserveBase(context.Background()); err != nil {
			return Verdict{}, err
		}
		runtimeState := v.currentRuntime(recorded)
		afterRuntime := v.currentRuntime(recorded)
		if err := v.reobserveBase(context.Background()); err != nil {
			return Verdict{}, err
		}
		if runtimeState != afterRuntime {
			return Verdict{Stale, "runtimeinputs"}, nil
		}
		return decideAfterClosure(recorded, cl, v.guards, runtimeState, kind, v.purityMatches(recorded, subject)), nil
	}
	return v.checkAfterClosure(recorded, subject, cl, kind), nil
}

// CheckRefined compares maximal evidence first. It invokes declaration-RTA under
// ctx only after maximal drift and only for compatible refined evidence.
func (v *View) CheckRefined(ctx context.Context, recorded Fingerprint, subject Subject, kind Kind) (Verdict, error) {
	if _, ok := v.maximal[subject]; !ok {
		return Verdict{}, fmt.Errorf("gofresh: subject %s.%s is not in this analysis view", subject.Package, subject.Symbol)
	}
	verdicts, err := v.checkRefinedBatch(ctx, map[Subject]Fingerprint{subject: recorded}, kind)
	if err != nil {
		return Verdict{}, err
	}
	return verdicts[subject], nil
}

// CheckRefinedBatch checks a caller-supplied recording set, batching precise
// analysis only for subjects whose maximal evidence drifted.
func (v *View) CheckRefinedBatch(ctx context.Context, recorded map[Subject]Fingerprint, kind Kind) (map[Subject]Verdict, error) {
	return v.checkRefinedBatch(ctx, recorded, kind)
}

func (v *View) checkRefinedBatch(ctx context.Context, recorded map[Subject]Fingerprint, kind Kind) (map[Subject]Verdict, error) {
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
			if verdict, failed := decideKnownGuards(rec, v.guards, runtimeBefore[subject], kind); failed {
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
		verdicts[subject] = decideAfterClosure(rec, effective, v.guards, runtimeBefore[subject], kind, v.purityMatches(rec, subject))
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
		verdicts[subject] = decideAfterClosure(rec, current, v.guards, runtimeBefore[subject], kind, v.purityMatches(rec, subject))
	}
	return finish()
}

func (v *View) checkAfterClosure(recorded Fingerprint, subject Subject, cl closure.Closure, kind Kind) Verdict {
	rt := v.currentRuntime(recorded)
	return decideAfterClosure(recorded, cl, v.guards, rt, kind, v.purityMatches(recorded, subject))
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

func (v *View) knownGuardVerdict(recorded Fingerprint, kind Kind) (Verdict, bool) {
	return decideKnownGuards(recorded, v.guards, v.currentRuntime(recorded), kind)
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
	var rt runtimeinput.State
	var err error
	if recorded.RuntimeInputs != "" {
		// An unevaluable runtime-input guard is absence of proof: Stale, never
		// valid (REQ-guard-completeness).
		current := v.runtimeCurrent
		if current == nil {
			current = runtimeinput.Current
		}
		if rt, err = current(recorded.RuntimeInputs, v.moduleDir); err != nil {
			rt = runtimeinput.State{}
		}
	}
	return rt
}

// Validate re-observes the View's complete subject set and reports ErrViewChanged
// when any source closure, guard, or purity assertion moved. A producer calls it
// after execution before persisting results (REQ-fresh-producer-view).
func (v *View) Validate() error {
	v.mu.Lock()
	v.sealed = true
	hasRefined := len(v.capturedRefined) != 0
	v.mu.Unlock()
	if hasRefined {
		return ErrRefinedValidationRequired
	}
	current, err := v.engine.NewView(v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	return v.compareBase(current)
}

// ValidateRefined re-observes the view and every refined closure captured from it
// under ctx. A producer must use it before persisting refined results.
func (v *View) ValidateRefined(ctx context.Context) error {
	v.mu.Lock()
	v.sealed = true
	v.mu.Unlock()
	current, err := v.engine.newView(ctx, v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	if err := v.compareBase(current); err != nil {
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
		return nil
	}
	if err := current.ensureRefined(ctx, subjects); err != nil {
		return err
	}
	final, err := v.engine.newView(ctx, v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	if err := current.compareBase(final); err != nil {
		return err
	}
	current.mu.RLock()
	defer current.mu.RUnlock()
	for _, subject := range subjects {
		if current.refined[subject] != expected[subject] {
			return fmt.Errorf("%w: refinement for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	return nil
}

func (v *View) reobserveBase(ctx context.Context) error {
	current, err := v.engine.newView(ctx, v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	return v.compareBase(current)
}

func (v *View) compareBase(current *View) error {
	if current.guards != v.guards {
		return fmt.Errorf("%w: guards", ErrViewChanged)
	}
	for _, subject := range v.subjects {
		if current.maximal[subject] != v.maximal[subject] {
			return fmt.Errorf("%w: closure for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
		if current.purity[subject] != v.purity[subject] {
			return fmt.Errorf("%w: purity for %s.%s", ErrViewChanged, subject.Package, subject.Symbol)
		}
	}
	return nil
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
	beforeView, err := v.engine.newView(ctx, v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	if err := v.compareBase(beforeView); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	hasher, err := closure.NewAtContext(ctx, v.engine.dir, v.engine.buildFlags...)
	if err != nil {
		return err
	}
	computed, err := hasher.ComputeBatch(requests)
	if err != nil {
		return err
	}
	afterView, err := v.engine.newView(ctx, v.subjects, v.moduleDir)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gofresh: refinement cancelled: %w", err)
	}
	if err := v.compareBase(afterView); err != nil {
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
