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
	"github.com/greatliontech/gofresh/internal/outcome"
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

// ProducerSnapshot selects a nonempty subset of this binding's source snapshot
// for a caller-managed producer transaction. It observes no new source or build
// facts and uses this binding's runtime environment and guards. Subjects outside
// the source snapshot are refused; duplicates collapse in first-request order.
// Captured source observability proofs and their validation obligations survive
// selection, but attachments and closing state do not. Capture any missing proof
// before execution, attach the execution's observation afterward, and successfully
// Validate before publishing its fingerprints. The caller owns execution scope,
// completion and dependency protection throughout that span. This operation
// supplies no built-artifact declaration, execution receipt or outcome support;
// identity-only observations retain their original authority.
func (b *RuntimeBinding) ProducerSnapshot(subjects []Subject) (*Snapshot, error) {
	return b.newView(subjects)
}

// newView selects immutable source facts and the binding while giving the caller
// a fresh transaction. No attachment, obligation or seal crosses this boundary.
func (b *RuntimeBinding) newView(subjects []Subject) (*Snapshot, error) {
	if b == nil || b.snapshot == nil || b.snapshot.facts == nil {
		return nil, errors.New("gofresh: uninitialized runtime binding")
	}
	v, err := b.snapshot.Sibling(subjects)
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

// BindBuilt binds the executor's nonempty artifact identity to this snapshot.
// The executor keeps the artifact and its dependencies protected through use.
func (s *Snapshot) BindBuilt(pkg, identity string) (BuildBinding, error) {
	if _, err := s.BuildDescription(pkg); err != nil {
		return BuildBinding{}, err
	}
	if identity == "" {
		return BuildBinding{}, errors.New("gofresh: empty built-artifact identity")
	}
	return BuildBinding{snapshot: s, pkg: pkg, identity: identity}, nil
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
	fingerprints, err := v.CaptureObservedBatch(ctx)
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
	for _, subject := range v.subjects {
		proof := v.observable[subject]
		if proof.OutcomeMethod != outcome.Method && reason == "" {
			reason = fmt.Sprintf("operation-outcome support unavailable for %q", subject.Package+"."+subject.Symbol)
		}
		subjects = append(subjects, outcomeSubject(fingerprints[subject], subject))
	}
	return outcome.Prepare(binding, subjects, reason), fingerprints, nil
}

func outcomeSubject(fingerprint Fingerprint, subject Subject) string {
	// A string-array encoding is total; it frames every field and uses the
	// manifest's canonical escaping without another serialization grammar.
	data, _ := json.Marshal([]string{outcome.Method, subject.Package, subject.Symbol, fingerprint.MaximalClosure, fingerprint.TestVariantClosure, fingerprint.Guards.Toolchain, fingerprint.Guards.BuildConfig, fingerprint.ToolchainContent, fingerprint.AdmissionPolicy, fingerprint.ObservationProof.Strategy})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
