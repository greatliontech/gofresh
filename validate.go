package gofresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/render"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/trace"
)

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
	var validateStart time.Time
	tracing := trace.Enabled(ctx, trace.DomainView, v.moduleDir)
	if tracing {
		validateStart = time.Now()
		defer func() {
			trace.Emit(ctx, trace.DomainView, "view.validate.done", v.moduleDir,
				trace.Int("subjects", len(v.subjects)),
				trace.Bool("ok", opErr == nil),
				trace.Int64("elapsed_ms", time.Since(validateStart).Milliseconds()),
			)
		}()
	}
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
	if hasObserved && hasApplicability {
		var unavailable error
		subjects, expected, attached, err := v.prepareObservedValidation()
		if err != nil {
			return err
		}
		current, err := v.newSeededValidationView(ctx)
		if err != nil {
			return err
		}
		if err := deferValidationUnavailability(v.validateObservedWithSeeded(ctx, current, subjects, expected, attached), &unavailable); err != nil {
			return err
		}
		v.mu.RLock()
		checks := append([]applicabilityCheck(nil), v.applicabilityChecks...)
		v.mu.RUnlock()
		if len(checks) > 0 {
			if err := deferValidationUnavailability(v.validateApplicabilityBatches(ctx, current, checks), &unavailable); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return unavailable
	}
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

func (v *Snapshot) prepareObservedValidation() ([]Subject, map[Subject]closure.Observability, map[Subject]runtimeinput.State, error) {
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
		return nil, nil, nil, errors.New("gofresh: no captured observation proof")
	}
	if err := requireCompletedAttachments(attached, subjects); err != nil {
		return nil, nil, nil, err
	}
	return subjects, expected, attached, nil
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
	subjects, expected, attached, err := v.prepareObservedValidation()
	if err != nil {
		return err
	}
	current, err := v.newSeededValidationView(ctx)
	if err != nil {
		return err
	}
	return v.validateObservedWithSeeded(ctx, current, subjects, expected, attached)
}

func (v *Snapshot) validateObservedWithSeeded(ctx context.Context, current *Snapshot, subjects []Subject, expected map[Subject]closure.Observability, attached map[Subject]runtimeinput.State) error {
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
