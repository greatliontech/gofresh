package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
)

// RuntimeBinding owns an immutable process directory, complete environment and
// applicable runtime guards over one snapshot. It owns no execution or closing
// state; independent units may use the same retained package artifact.
type RuntimeBinding struct {
	snapshot *Snapshot
	runtime  boundRuntime
}

// boundRuntime is shared read-only by every view derived from a binding. Source
// observations stay on the engine's compilation environment.
type boundRuntime struct {
	dir    string
	env    []string
	guards guard.RuntimeGuards
}

// Snapshot returns the immutable source/build generation underlying this binding.
func (b *RuntimeBinding) Snapshot() *Snapshot {
	if b == nil {
		return nil
	}
	return b.snapshot
}

// BindRuntime admits the actual process configuration without re-observing source
// or compilation facts. Nil Environment inherits the build environment; a present
// empty environment contains only derived PWD. Measurement guards require a fresh
// agreement pair. The caller protects both dependency sets through their spans.
func (s *Snapshot) BindRuntime(ctx context.Context, execution RuntimeDescription) (binding *RuntimeBinding, err error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil runtime binding context")
	}
	defer func() {
		if cause := ctx.Err(); cause != nil {
			binding, err = nil, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.session == nil || s.session.build.Directory == "" || !validKind(s.kind) {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	dir, err := rebaseProcessPath(s.session.build.Directory, execution.Directory)
	if err != nil {
		return nil, fmt.Errorf("gofresh: runtime directory: %w", err)
	}
	dir, err = gotool.CanonicalDir(dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: runtime directory: %w", err)
	}
	env := execution.Environment
	if env == nil {
		env = s.session.build.Environment
	}
	env, err = gotool.EnvForCommand(env, dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: runtime environment: %w", err)
	}
	r := boundRuntime{dir: dir, env: env}
	r.guards, err = r.observe(ctx, s.kind)
	if err != nil {
		return nil, err
	}
	second, err := r.observe(ctx, s.kind)
	if err != nil {
		return nil, err
	}
	if r.guards != second {
		return nil, fmt.Errorf("%w: runtime guards during binding", ErrViewChanged)
	}
	return &RuntimeBinding{snapshot: s, runtime: r}, nil
}

func (r *boundRuntime) observe(ctx context.Context, kind Kind) (guard.RuntimeGuards, error) {
	guards, err := guard.CaptureRuntime(ctx, r.env, kind)
	if err != nil {
		return guard.RuntimeGuards{}, err
	}
	emitRuntimeGuardsViewHook(&guards)
	if err := ctx.Err(); err != nil {
		return guard.RuntimeGuards{}, err
	}
	return guards, nil
}

// newView selects immutable source facts and the binding while giving the caller
// a fresh transaction. No attachment, obligation or seal crosses this boundary.
func (b *RuntimeBinding) newView(subjects []Subject) (*Snapshot, error) {
	if b == nil || b.snapshot == nil || b.snapshot.facts == nil {
		return nil, errors.New("gofresh: uninitialized runtime binding")
	}
	v, err := b.snapshot.sibling(subjects)
	if err != nil {
		return nil, err
	}
	v.runtime = &b.runtime
	return v, nil
}

// BuildDescription returns an owned copy for a package represented in the
// snapshot. The executor protects these build dependencies through execution and
// closing, and uses this description rather than rebuilding under runtime env.
func (s *Snapshot) BuildDescription(pkg string) (BuildDescription, error) {
	if s == nil || s.session == nil || s.session.build.Directory == "" || !slices.Contains(s.packages, pkg) {
		return BuildDescription{}, fmt.Errorf("gofresh: package %q is outside the snapshot", pkg)
	}
	b := s.session.build
	b.Package = pkg
	b.Environment, b.Flags, b.Inputs = slices.Clone(b.Environment), slices.Clone(b.Flags), slices.Clone(b.Inputs)
	return b, nil
}

// BuildBinding is the executor's declaration that a retained package test
// artifact was successfully built from this snapshot's description. It prevents
// accidental cross-snapshot borrowing; it does not authenticate the executor
// or certify that the executor followed the description.
type BuildBinding struct {
	snapshot *Snapshot
	pkg      string
	identity string
}

func rootSnapshotGeneration(s *Snapshot) *Snapshot {
	if s != nil && s.parent != nil {
		return s.parent
	}
	return s
}

// BindBuilt binds the executor's nonempty artifact identity to this snapshot.
// The executor keeps the artifact and its dependencies protected through use.
func (s *Snapshot) BindBuilt(pkg, identity string) (BuildBinding, error) {
	if _, err := s.BuildDescription(pkg); err != nil {
		return BuildBinding{}, err
	}
	if identity == "" {
		return BuildBinding{}, errors.New("gofresh: empty built-artifact identity")
	}
	return BuildBinding{snapshot: rootSnapshotGeneration(s), pkg: pkg, identity: identity}, nil
}

func (v *Snapshot) subjectNeedsObservationLocked(subject Subject, fp Fingerprint) bool {
	return decide(fp, v.facts.closure(subject), v.guards(), runtimeinput.State{}, v.kind, v.purityMatches(fp, subject)).Status != Valid
}

// NeedsObservation reports whether preparing an ordinary producing Unit for
// subjects under this runtime binding requires runtime observation capture
// (-test.testlogfile). It applies the exact preparation checks of BeginPackage
// (refusing empty, unknown, cross-package, source-result, or non-callable
// declaration subjects, as well as multi-subject sets under
// SingleSubjectExecution) and evaluates the ordinary evidence ladder without
// walking directories or spawning processes.
func (b *RuntimeBinding) NeedsObservation(subjects []Subject) (bool, error) {
	v, err := b.newView(subjects)
	if err != nil {
		return false, err
	}
	if err := validateUnitView(v); err != nil {
		return false, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, subject := range v.subjects {
		cl := v.facts.closure(subject)
		fp := v.fingerprintLocked(subject, cl)
		if v.subjectNeedsObservationLocked(subject, fp) {
			return true, nil
		}
	}
	return false, nil
}

// Check automatically selects admissible established native evidence and closes
// its own checking interval before returning a judgment. It never fills missing
// historical producing support or seals another unit.
func (b *RuntimeBinding) Check(ctx context.Context, subject Subject, recorded Fingerprint) (Verdict, error) {
	u, err := b.BeginCheck([]Subject{subject})
	if err != nil {
		return Verdict{}, err
	}
	defer u.Abort()
	if _, err := u.CheckBatch(ctx, []Candidate{{subject, recorded}}); err != nil {
		return Verdict{}, err
	}
	checked, err := u.Close(ctx)
	if err != nil {
		return Verdict{}, err
	}
	return checked[0].Verdict, nil
}

// CurrentFacts returns this binding's analysis-only fingerprint projection for
// explanations. It carries neither an execution receipt nor runtime observation
// or selected producing proof. It is not a newly produced result.
func (b *RuntimeBinding) CurrentFacts(ctx context.Context, subject Subject) (Fingerprint, error) {
	if ctx == nil {
		return Fingerprint{}, errors.New("gofresh: nil facts context")
	}
	if err := ctx.Err(); err != nil {
		return Fingerprint{}, err
	}
	if b == nil || b.snapshot == nil || b.snapshot.facts == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized runtime binding")
	}
	b.snapshot.mu.RLock()
	defer b.snapshot.mu.RUnlock()
	if err := b.snapshot.requireMembers([]Subject{subject}); err != nil {
		return Fingerprint{}, err
	}
	fp := b.snapshot.fingerprintLocked(subject, b.snapshot.facts.closure(subject))
	fp.Guards.Machine, fp.Guards.RuntimeConfig = b.runtime.guards.Machine, b.runtime.guards.RuntimeConfig
	return fp, nil
}

// prepareOutcomeSupport derives support for exactly this view's contributing
// subject set, before execution. Use a sibling view for a narrower process set.
// The caller runs that exact set under the view's complete runtime environment
// and excludes environment mutation. Unsupported inventories return a capability
// carrying their refusal; they never turn process health into outcome evidence.
// Preparation selects each subject's observation proof for producer validation.
func (v *Snapshot) prepareOutcomeSupport(ctx context.Context, frame runtimeinput.ProducerFrame, process string) (runtimeinput.OutcomeSupport, map[Subject]Fingerprint, error) {
	if v == nil || v.facts == nil || v.session == nil {
		return runtimeinput.OutcomeSupport{}, nil, errors.New("gofresh: uninitialized snapshot")
	}
	if len(v.subjects) == 0 {
		return runtimeinput.OutcomeSupport{}, nil, fmt.Errorf("gofresh: outcome support needs contributing subjects")
	}
	env, err := gotool.EnvForCommand(v.evidenceEnv(), frame.PkgDir)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, nil, err
	}
	binding, err := frame.OutcomeBinding(process, env)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, nil, err
	}
	fingerprints, err := v.captureObservedBatch(ctx)
	if err != nil {
		return runtimeinput.OutcomeSupport{}, nil, err
	}
	if v.beforeOutcomeIssue != nil {
		v.beforeOutcomeIssue()
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return runtimeinput.OutcomeSupport{}, nil, errViewSealed
	}
	if err := ctx.Err(); err != nil {
		return runtimeinput.OutcomeSupport{}, nil, err
	}
	var subjects []string
	reason := ""
	singleSubject := v.effectiveExecutionModel().singleSubject()
	for _, subject := range v.subjects {
		proof := v.txState[subject].observable
		if (proof.OutcomeMethod != runtimeinput.OutcomeMethod || (proof.RequiresSingleSubject && !singleSubject)) && reason == "" {
			reason = fmt.Sprintf("operation-outcome support unavailable for %q", subject.Package+"."+subject.Symbol)
		}
		subjects = append(subjects, outcomeSubject(fingerprints[subject], subject))
	}
	return runtimeinput.PrepareOutcomeSupport(binding, subjects, reason), fingerprints, nil
}

func (v *Snapshot) prepareTrackedChdirSupport(ctx context.Context, frame runtimeinput.ProducerFrame, pkg string) (support runtimeinput.TrackedChdirSupport, opErr error) {
	if ctx == nil {
		return runtimeinput.TrackedChdirSupport{}, errors.New("gofresh: nil tracked-chdir preparation context")
	}
	if v == nil || v.facts == nil || v.session == nil {
		return runtimeinput.TrackedChdirSupport{}, errors.New("gofresh: uninitialized snapshot")
	}
	ctx, done := v.session.beginOperation(ctx)
	defer done(&opErr)
	if err := ctx.Err(); err != nil {
		return runtimeinput.TrackedChdirSupport{}, err
	}
	if !slices.Contains(v.packages, pkg) {
		return runtimeinput.TrackedChdirSupport{}, fmt.Errorf("gofresh: package %q is outside the snapshot", pkg)
	}
	if frame.Reason() != "" {
		return runtimeinput.TrackedChdirSupport{}, nil
	}
	var probe Subject
	haveProbe := false
	v.mu.RLock()
	if v.sealed {
		v.mu.RUnlock()
		return runtimeinput.TrackedChdirSupport{}, errViewSealed
	}
	for _, s := range v.subjects {
		if s.Package != pkg {
			continue
		}
		if tx := v.txState[s]; tx.hasObservable {
			v.mu.RUnlock()
			return frame.PrepareTrackedChdir(tx.observable.TrackedChdirSafe), nil
		}
		if !haveProbe {
			probe = s
			haveProbe = true
		}
	}
	v.mu.RUnlock()
	if !haveProbe {
		return runtimeinput.TrackedChdirSupport{}, nil
	}
	if err := v.ensureObservable(ctx, []Subject{probe}); err != nil {
		if errors.Is(err, ErrAnalysisUnavailable) {
			return runtimeinput.TrackedChdirSupport{}, nil
		}
		return runtimeinput.TrackedChdirSupport{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sealed {
		return runtimeinput.TrackedChdirSupport{}, errViewSealed
	}
	if err := ctx.Err(); err != nil {
		return runtimeinput.TrackedChdirSupport{}, err
	}
	return frame.PrepareTrackedChdir(v.txState[probe].observable.TrackedChdirSafe), nil
}

func outcomeSubject(fingerprint Fingerprint, subject Subject) string {
	// A string-array encoding is total; it frames every field and uses the
	// manifest's canonical escaping without another serialization grammar.
	data, _ := json.Marshal([]string{runtimeinput.OutcomeMethod, subject.Package, subject.Symbol, fingerprint.MaximalClosure, fingerprint.TestVariantClosure, fingerprint.Guards.Toolchain, fingerprint.Guards.BuildConfig, fingerprint.ToolchainContent, fingerprint.AdmissionPolicy, fingerprint.ObservationProof.Strategy})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
