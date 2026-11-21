package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/observability"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/trace"
)

const movedListCap = 3

func cappedList(names []string) string {
	if len(names) <= movedListCap {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:movedListCap], ", ") + fmt.Sprintf(", and %d more", len(names)-movedListCap)
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
	checks := slices.Clone(v.applicabilityChecks)
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
	// The view validates whatever it captured: observation proofs and retained
	// applicability checks share one seeded validation view; a maximal-only
	// producer runs one comparison-only re-observation (REQ-fresh-coherent-view).
	var unavailable error
	if !hasObserved && len(checks) == 0 {
		if err := deferValidationUnavailability(v.reobserveBase(ctx), &unavailable); err != nil {
			return err
		}
		return v.resolveValidationUnavailable(ctx, nil, unavailable)
	}
	var (
		subjects []Subject
		expected map[Subject]observability.Observability
		attached map[Subject]runtimeinput.State
	)
	if hasObserved {
		var err error
		subjects, expected, attached, err = v.prepareObservedValidation()
		if err != nil {
			return err
		}
	}
	current, err := v.newSeededValidationView(ctx)
	if err != nil {
		return err
	}
	if hasObserved {
		if err := deferValidationUnavailability(v.validateObservedWithSeeded(ctx, current, subjects, expected, attached), &unavailable); err != nil {
			return err
		}
	}
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
	return v.cloneShell(v.subjects, v.requests, v.packages, v.facts), nil
}

func (v *Snapshot) prepareObservedValidation() ([]Subject, map[Subject]observability.Observability, map[Subject]runtimeinput.State, error) {
	v.mu.RLock()
	subjects := make([]Subject, 0, len(v.capturedObserved))
	expected := make(map[Subject]observability.Observability, len(v.capturedObserved))
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

func (v *Snapshot) validateObservedWithSeeded(ctx context.Context, current *Snapshot, subjects []Subject, expected map[Subject]observability.Observability, attached map[Subject]runtimeinput.State) error {
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
		if held == nil {
			continue
		}
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
func compareObservationProof(subject Subject, observed, captured observability.Observability) error {
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
// the observability analysis composes the same prefix at its own refusal
// sites (observability/observability.go), which analysisUnavailable
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
	return " (moved: " + cappedList(moved) + ")"
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
func describeObservability(o observability.Observability) string {
	if o.Observable {
		return "observable"
	}
	if o.Reason == "" {
		return "not observable"
	}
	return "not observable: " + o.Reason
}

type runtimeEval struct {
	state     runtimeinput.State
	movers    []string
	hasMovers bool
}

// runtimeEndpoint holds one point-in-time runtime-input evaluation pass:
// Go-comparable States per record, single-pass movers per manifest when
// evaluated via CurrentWithMovers, and a pass-scoped fallback memo for
// synthetic runtimeCurrent test hooks. Never shared across before/after or
// pre-run/post-run endpoints.
type runtimeEndpoint struct {
	states     []runtimeinput.State
	byManifest map[string]runtimeEval
	moverMemo  map[string][]string
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
// where a test set one, else its bound runtime or session environment (or an
// empty environment on a session-less direct-construct test view).
func (v *Snapshot) runtimeCheck() func(context.Context, string, string) (runtimeinput.State, error) {
	if v.runtimeCurrent != nil {
		return v.runtimeCurrent
	}
	return func(ctx context.Context, encoded, root string) (runtimeinput.State, error) {
		var env []string
		if v.session != nil {
			env = v.evidenceEnv()
		}
		return runtimeinput.Current(ctx, encoded, root, env)
	}
}

func (v *Snapshot) evaluateRuntimeManifest(ctx context.Context, encoded, root string) (runtimeEval, error) {
	if v.runtimeCurrent != nil {
		state, err := v.runtimeCurrent(ctx, encoded, root)
		return runtimeEval{state: state}, err
	}
	var env []string
	if v.session != nil {
		env = v.evidenceEnv()
	}
	state, movers, err := runtimeinput.CurrentWithMovers(ctx, encoded, root, env)
	return runtimeEval{state: state, movers: movers, hasMovers: true}, err
}

func (v *Snapshot) moversFromEndpoint(ctx context.Context, encoded string, ep *runtimeEndpoint) []string {
	if v.session == nil || encoded == "" {
		return nil
	}
	if ep != nil {
		if eval, ok := ep.byManifest[encoded]; ok && eval.hasMovers {
			return eval.movers
		}
		if ep.moverMemo != nil {
			if movers, cached := ep.moverMemo[encoded]; cached {
				return movers
			}
		}
	}
	movers, err := movedInputsForView(ctx, v, encoded)
	if err != nil {
		return nil
	}
	if ep != nil && ep.moverMemo != nil {
		ep.moverMemo[encoded] = movers
	}
	return movers
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
	return v.withEndpointMovedInputs(ctx, verdict, recorded, nil)
}

func (v *Snapshot) withEndpointMovedInputs(ctx context.Context, verdict Verdict, recorded Fingerprint, ep *runtimeEndpoint) Verdict {
	if verdict.Status != Stale || verdict.Ground.Cause.Kind != RuntimeInputsCause || recorded.RuntimeInputs == "" || v.session == nil {
		return verdict
	}
	movers := v.moversFromEndpoint(ctx, recorded.RuntimeInputs, ep)
	if len(movers) == 0 {
		return verdict
	}
	verdict.Reason = "runtimeinputs (moved: " + cappedList(movers) + ")"
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
	// state and movers are functions of (manifest, module, env) alone, so
	// subjects sharing a manifest share both - the same amplification
	// collapse the check window carries, on the producer path. The memo is
	// per-call on purpose: the second validation pass must re-evaluate to
	// prove the inputs stable across the re-analysis window.
	if err := requireCompletedAttachments(attached, subjects); err != nil {
		return err
	}
	ep := runtimeEndpoint{
		byManifest: map[string]runtimeEval{},
		moverMemo:  map[string][]string{},
	}
	for _, subject := range subjects {
		state := attached[subject]
		eval, evaluated := ep.byManifest[state.Manifest]
		if !evaluated {
			var err error
			eval, err = v.evaluateRuntimeManifest(ctx, state.Manifest, v.evidenceRoot())
			if err != nil {
				return err
			}
			ep.byManifest[state.Manifest] = eval
		}
		if eval.state != state {
			detail := ""
			if movers := v.moversFromEndpoint(ctx, state.Manifest, &ep); len(movers) > 0 {
				detail = " (moved: " + cappedList(movers) + ")"
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
		emitTwoPassDiff(ctx, nil, func() (string, string, string) {
			return "guards", fmt.Sprintf("%+v", baseGuards), fmt.Sprintf("%+v", current.guards)
		})
		return fmt.Errorf("%w: guards%s (%s)", ErrViewChanged, during, differingGuard(current.guards, baseGuards))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !construction && !slices.Equal(current.sourceFiles, base.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		emitTwoPassStringsDiff(ctx, nil, "source_files", base.sourceFiles, current.sourceFiles)
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
			emitTwoPassStringsDiff(ctx, &subject, "subject_source_files", base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject])
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
			emitTwoPassDiff(ctx, &subject, func() (string, string, string) {
				return diffSubjectFacts(base.maximal[subject], current.maximal[subject], cutHere)
			})
			return fmt.Errorf("%w: closure for %s.%s%s%s", ErrViewChanged, subject.Package, subject.Symbol, during, movedIdentitySuffix(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject], base.fileDigests, current.fileDigests))
		}
		if !construction && cutHere && !current.maximal[subject].equal(base.maximal[subject], false) {
			unjudged = append(unjudged, subject)
		}
		if current.purity[subject] != base.purity[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			emitTwoPassStringDiff(ctx, &subject, "purity", base.purity[subject], current.purity[subject])
			return fmt.Errorf("%w: purity for %s.%s%s", ErrViewChanged, subject.Package, subject.Symbol, during)
		}
		if construction {
			if base.vouchDischarges[subject] != current.vouchDischarges[subject] {
				if err := ctx.Err(); err != nil {
					return err
				}
				emitTwoPassStringDiff(ctx, &subject, "vouch_discharges", base.vouchDischarges[subject], current.vouchDischarges[subject])
				return fmt.Errorf("%w: vouch discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if !cutHere && base.discharges[subject].singleSubject != current.discharges[subject].singleSubject {
				if err := ctx.Err(); err != nil {
					return err
				}
				emitTwoPassStringDiff(ctx, &subject, "single_subject_discharges", base.discharges[subject].singleSubject, current.discharges[subject].singleSubject)
				return fmt.Errorf("%w: single-subject attestation discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if !cutHere && base.discharges[subject].packageProcess != current.discharges[subject].packageProcess {
				if err := ctx.Err(); err != nil {
					return err
				}
				emitTwoPassStringDiff(ctx, &subject, "package_process_discharges", base.discharges[subject].packageProcess, current.discharges[subject].packageProcess)
				return fmt.Errorf("%w: package-process attestation discharges for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
			}
			if current.cut[subject] && !base.cut[subject] {
				base.takeCut(current, subject)
			}
			if !slices.Equal(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject]) {
				if err := ctx.Err(); err != nil {
					return err
				}
				emitTwoPassStringsDiff(ctx, &subject, "subject_source_files", base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject])
				return fmt.Errorf("%w: maximal source identities for %s.%s during construction%s", ErrViewChanged, subject.Package, subject.Symbol, movedIdentitySuffix(base.sourceFilesBySubject[subject], current.sourceFilesBySubject[subject], base.fileDigests, current.fileDigests))
			}
		}
	}
	if construction && !slices.Equal(base.sourceFiles, current.sourceFiles) {
		if err := ctx.Err(); err != nil {
			return err
		}
		emitTwoPassStringsDiff(ctx, nil, "source_files", base.sourceFiles, current.sourceFiles)
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

func emitTwoPassStringDiff(ctx context.Context, subject *Subject, diffField, firstVal, secondVal string) {
	emitTwoPassDiff(ctx, subject, func() (string, string, string) {
		return diffField, firstVal, secondVal
	})
}

func emitTwoPassDiff(ctx context.Context, subject *Subject, compute func() (string, string, string)) {
	if !trace.AnyEnabled() {
		return
	}
	target := ""
	if subject != nil {
		target = subject.Package + "." + subject.Symbol
	}
	if !trace.Enabled(ctx, trace.DomainView, target) {
		return
	}
	diffField, firstVal, secondVal := compute()
	if subject != nil {
		trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
			trace.String("diff_field", diffField),
			trace.String("subject", target),
			trace.String("first_value", firstVal),
			trace.String("second_value", secondVal),
		)
		return
	}
	trace.Emit(ctx, trace.DomainView, "two_pass_diff", "",
		trace.String("diff_field", diffField),
		trace.String("first_value", firstVal),
		trace.String("second_value", secondVal),
	)
}

func emitTwoPassStringsDiff(ctx context.Context, subject *Subject, diffField string, firstVal, secondVal []string) {
	if !trace.AnyEnabled() {
		return
	}
	target := ""
	if subject != nil {
		target = subject.Package + "." + subject.Symbol
	}
	if !trace.Enabled(ctx, trace.DomainView, target) {
		return
	}
	if subject != nil {
		trace.Emit(ctx, trace.DomainView, "two_pass_diff", target,
			trace.String("diff_field", diffField),
			trace.String("subject", target),
			trace.Strings("first_value", firstVal),
			trace.Strings("second_value", secondVal),
		)
		return
	}
	trace.Emit(ctx, trace.DomainView, "two_pass_diff", "",
		trace.String("diff_field", diffField),
		trace.Strings("first_value", firstVal),
		trace.Strings("second_value", secondVal),
	)
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
