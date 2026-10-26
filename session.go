package gofresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// BuildDescription describes compilation, not the environment of the resulting
// program. Inputs is explicitly present (possibly empty): the executor accepts
// responsibility for supplying every additional build input, including profiles
// consumed by default. Package is filled by a snapshot's BuildDescription method.
type BuildDescription struct {
	Directory   string
	Package     string
	Environment []string
	Flags       []string
	Inputs      []string
}

// TestCompileArgs returns the go command arguments to compile Package's test
// binary to outputPath under Flags and any caller-supplied extraFlags.
func (d BuildDescription) TestCompileArgs(outputPath string, extraFlags ...string) []string {
	args := make([]string, 0, 4+len(d.Flags)+len(extraFlags)+1)
	args = append(args, "test", "-c", "-o", outputPath)
	args = append(args, d.Flags...)
	args = append(args, extraFlags...)
	args = append(args, d.Package)
	return args
}

// RuntimeDescription is the complete environment of the built program. A nil
// Environment inherits the session's build environment; a nonnil empty slice
// describes an otherwise empty environment. Directory supplies PWD; omission
// uses the build directory, and a relative directory is based at that directory.
// The executor runs the retained artifact under this description; a compiling Go
// command under this environment does not execute the admitted build description.
type RuntimeDescription struct {
	Directory   string
	Environment []string
}

// ExecutionModel is the executor's attestation about every contributing process.
type ExecutionModel uint8

const (
	// GeneralExecution makes no package-process or single-subject assertion.
	GeneralExecution ExecutionModel = iota
	// PackageExecution asserts that a subject runs in its package's test binary.
	PackageExecution
	// SingleSubjectExecution asserts that each contributing process runs only
	// its one selected subject, including during initialization and harness use.
	SingleSubjectExecution
)

// SessionPolicy carries the operation's accepted analysis and assertion policy.
// Vouches is the complete, caller-resolved set of canonical import-path.Variable
// identities, as returned by ParseVouchEntries; session construction
// reads no additional repository vouch file. PureSubjects are explicit caller
// assertions, distinct from selected source directives. Callback behavior remains
// its author's responsibility; descriptions and sets are owned copies.
type SessionPolicy struct {
	EvidenceRoot   string
	Vouches        []string
	PureSubjects   []Subject
	Execution      ExecutionModel
	AnalysisBudget time.Duration
	Runner         gotool.Runner
	Progress       func(Progress)
}

// Session owns one judged operation's immutable build configuration and
// policy. It executes no subject and stores no result. Source generations belong
// to its snapshots, and producing obligations belong to their independent units.
type Session struct {
	engine *Engine
	build  BuildDescription
	roots  runtimeinput.Roots
}

// NewSession admits a complete compilation description and analysis policy.
// Snapshots observe source/build generations; BindRuntime separately admits the
// environment of executions using a retained artifact. Construction honors ctx.
func NewSession(ctx context.Context, build BuildDescription, policy SessionPolicy) (session *Session, err error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil session context")
	}
	defer func() {
		if cause := ctx.Err(); cause != nil {
			session, err = nil, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if build.Directory == "" || build.Package != "" {
		return nil, errors.New("gofresh: session requires a build directory; the snapshot selects the package")
	}
	if build.Environment == nil || build.Inputs == nil {
		return nil, errors.New("gofresh: session requires a complete build environment and an explicitly present additional-input declaration")
	}
	if policy.Execution > SingleSubjectExecution || policy.AnalysisBudget < 0 {
		return nil, errors.New("gofresh: invalid session execution model or analysis budget")
	}
	buildDir, err := gotool.CanonicalDir(build.Directory)
	if err != nil {
		return nil, fmt.Errorf("gofresh: build directory: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buildEnv, err := gotool.EnvForPackages(build.Environment)
	if err != nil {
		return nil, fmt.Errorf("gofresh: build environment: %w", err)
	}
	buildEnv, err = gotool.EnvForCommand(buildEnv, buildDir)
	if err != nil {
		return nil, err
	}
	vouches, err := canonicalSessionVouches(policy.Vouches)
	if err != nil {
		return nil, err
	}
	pure := make(map[Subject]bool, len(policy.PureSubjects))
	for _, subject := range policy.PureSubjects {
		if subject.Package == "" || subject.Symbol == "" {
			return nil, errors.New("gofresh: empty purity-assertion subject")
		}
		pure[subject] = true
	}
	runner := policy.Runner
	if runner.Containment != nil {
		owned := *runner.Containment
		runner.Containment = &owned
	}
	opts := []Option{
		WithDir(buildDir), WithEnv(buildEnv...), WithBuildFlags(build.Flags...),
		WithBuildInputs(build.Inputs...), WithEvidenceRoot(policy.EvidenceRoot),
		WithoutRepositoryVouches(), WithDynamicStateVouches(vouches...),
		WithAssumePure(func(subject Subject) bool { return pure[subject] }),
		WithGoRunner(runner), WithProgress(policy.Progress), WithAnalysisBudget(policy.AnalysisBudget),
	}
	switch policy.Execution {
	case PackageExecution:
		opts = append(opts, WithPackageProcessExecution())
	case SingleSubjectExecution:
		opts = append(opts, WithSingleSubjectExecution())
	}
	e, err := NewContext(ctx, opts...)
	if err != nil {
		return nil, err
	}
	e.completeBuild = true
	e.deferredCheckClose = true
	owned := BuildDescription{Directory: e.dir, Environment: slices.Clone(e.env), Flags: slices.Clone(e.buildFlags), Inputs: append([]string{}, e.buildInputs...)}
	return &Session{engine: e, build: owned}, nil
}

// canonicalSessionVouches validates the already-resolved identity form through
// the vouch grammar's one validator, rather than asking an API caller to turn
// identities back into flag spellings. Dots in import paths are not separators.
func canonicalSessionVouches(identities []string) ([]string, error) {
	owned := make([]string, 0, len(identities))
	for _, identity := range identities {
		separator := strings.LastIndexByte(identity, '.')
		if separator <= strings.LastIndexByte(identity, '/') || separator <= 0 {
			return nil, fmt.Errorf("gofresh: vouch identity %q is not canonical import-path.Variable", identity)
		}
		canonical, err := ParseVouchEntry(identity[:separator] + ":" + identity[separator+1:])
		if err != nil || canonical != identity {
			return nil, fmt.Errorf("gofresh: vouch identity %q is not canonical import-path.Variable", identity)
		}
		owned = append(owned, canonical)
	}
	slices.Sort(owned)
	return slices.Compact(owned), nil
}

// rebaseProcessPath gives a process-relative path one absolute spelling without
// lexically cancelling symlink/.. components. Existing directories can then be
// canonicalized; future captures retain this spelling until the kernel opens
// them. Drive-relative and rooted-without-drive forms are not cwd-relative.
func rebaseProcessPath(directory, path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	if path == "" {
		return directory, nil
	}
	if filepath.VolumeName(path) != "" || os.IsPathSeparator(path[0]) {
		return "", errors.New("path must be absolute or relative to the execution directory")
	}
	return directory + string(filepath.Separator) + path, nil
}

// Snapshot owns one immutable coherent source/build generation. It exposes no
// mutable legacy view: finishing a unit cannot seal the parent or a sibling.
type Snapshot struct {
	session *Session
	view    *View
}

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
	if s == nil || s.view == nil || s.session == nil {
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
	r.guards, err = r.observe(ctx, s.view.kind)
	if err != nil {
		return nil, err
	}
	second, err := r.observe(ctx, s.view.kind)
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
	if viewTestHooks.runtimeGuards != nil {
		viewTestHooks.runtimeGuards(&guards)
	}
	if err := ctx.Err(); err != nil {
		return guard.RuntimeGuards{}, err
	}
	return guards, nil
}

// newView selects immutable source facts and the binding while giving the caller
// a fresh transaction. No attachment, obligation or seal crosses this boundary.
func (b *RuntimeBinding) newView(subjects []Subject) (*View, error) {
	if b == nil || b.snapshot == nil || b.snapshot.view == nil {
		return nil, errors.New("gofresh: uninitialized runtime binding")
	}
	v, err := b.snapshot.view.Sibling(subjects)
	if err != nil {
		return nil, err
	}
	v.runtime = &b.runtime
	return v, nil
}

// Snapshot observes the requested subjects under the session's admitted build.
// It captures no measurement-side guards; BindRuntime admits those separately.
func (s *Session) Snapshot(ctx context.Context, subjects []Subject, kind Kind) (*Snapshot, error) {
	if s == nil || s.engine == nil {
		return nil, errors.New("gofresh: uninitialized session")
	}
	v, err := s.engine.NewViewFor(ctx, subjects, s.build.Directory, kind)
	if err != nil {
		return nil, err
	}
	return &Snapshot{session: s, view: v}, nil
}

// BuildDescription returns an owned copy for a package represented in the
// snapshot. The executor protects these build dependencies through execution and
// closing, and uses this description rather than rebuilding under runtime env.
func (s *Snapshot) BuildDescription(pkg string) (BuildDescription, error) {
	if s == nil || s.view == nil || !slices.Contains(s.view.packages, pkg) {
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
// or certify that the executor followed the description. BindArtifact additionally
// captures immutable file inputs; those observations confer no semantic authority.
type BuildBinding struct {
	snapshot  *Snapshot
	pkg       string
	identity  string
	inspected *inspectedArtifact
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

// SourceFiles returns the snapshot's caller-owned mutable source inventory for
// exclusion, dirty-source attribution and publication checks.
func (s *Snapshot) SourceFiles() []string {
	if s == nil || s.view == nil {
		return nil
	}
	return s.view.SourceFiles()
}

// SourceFilesFor returns the subject's caller-owned source inventory.
func (s *Snapshot) SourceFilesFor(subject Subject) ([]string, error) {
	if s == nil || s.view == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	return s.view.SourceFilesFor(subject)
}

// TestVariantLedger returns the native ledger from the same immutable generation
// as the subject's fingerprint, never a separate reread of the package.
func (s *Snapshot) TestVariantLedger(subject Subject) (TestVariantLedger, error) {
	if s == nil || s.view == nil {
		return TestVariantLedger{}, errors.New("gofresh: uninitialized snapshot")
	}
	return s.view.TestVariantLedger(subject)
}

// ExplainDynamicState derives the refusal chain for a dynamic-state culprit
// against the snapshot's package scope and configuration.
func (s *Snapshot) ExplainDynamicState(ctx context.Context, pkgPath, varName string) (Chain, error) {
	if s == nil || s.view == nil {
		return Chain{}, errors.New("gofresh: uninitialized snapshot")
	}
	return s.view.ExplainDynamicState(ctx, pkgPath, varName)
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
	if b == nil || b.snapshot == nil || b.snapshot.view == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized runtime binding")
	}
	if err := requireSubjects([]Subject{subject}, func(s Subject) bool {
		return slices.Contains(b.snapshot.view.subjects, s)
	}, SelectedView); err != nil {
		return Fingerprint{}, err
	}
	v, err := b.newView([]Subject{subject})
	if err != nil {
		return Fingerprint{}, err
	}
	return v.Capture(ctx, subject)
}

// CheckInertExtension explicitly requests the native inert-test-variant license.
// It preserves producing evidence and returns the checked endpoint/ledger pair
// only after closing validation. Ordinary Check never requests this transform.
func (b *RuntimeBinding) CheckInertExtension(ctx context.Context, subject Subject, recorded Fingerprint, prior TestVariantLedger) (Fingerprint, TestVariantLedger, Verdict, error) {
	u, err := b.BeginCheck([]Subject{subject})
	if err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	defer u.Abort()
	if _, err := u.CheckBatch(ctx, []Candidate{{subject, recorded}}); err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	if _, err := u.ExtendInertBatch(ctx, []InertRequest{{0, prior}}); err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	checked, err := u.Close(ctx)
	if err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	result := checked[1]
	if result.Extension == nil {
		return Fingerprint{}, TestVariantLedger{}, result.Verdict, nil
	}
	return result.Extension.Fingerprint, result.Extension.Ledger, result.Verdict, nil
}

// CheckBatchWithLedgers checks a batch of candidates and, for any candidate
// that fails with ReasonTestVariants and has a prior ledger in ledgers,
// explicitly attempts an inert test-variant extension within the same checking
// unit before closing. The returned slice has one entry per candidate in
// request order, with Extension populated when an inert extension succeeded.
func (b *RuntimeBinding) CheckBatchWithLedgers(ctx context.Context, candidates []Candidate, ledgers map[int]TestVariantLedger) ([]CheckedCandidate, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil checking context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b == nil || b.snapshot == nil || b.snapshot.view == nil {
		return nil, errors.New("gofresh: uninitialized runtime binding")
	}
	if err := b.snapshot.view.prepareCandidates(candidates); err != nil {
		return nil, err
	}
	var subjects []Subject
	seen := make(map[Subject]bool, len(candidates))
	for _, c := range candidates {
		if !seen[c.Subject] {
			seen[c.Subject] = true
			subjects = append(subjects, c.Subject)
		}
	}
	if len(subjects) == 0 {
		subjects = slices.Clone(b.snapshot.view.subjects)
	}
	u, err := b.BeginCheck(subjects)
	if err != nil {
		return nil, err
	}
	defer u.Abort()
	provisional, err := u.CheckBatch(ctx, candidates)
	if err != nil {
		return nil, err
	}
	var requests []InertRequest
	var requestCandidate []int
	for i, p := range provisional {
		if p.Verdict.Status == Stale && p.Verdict.Reason == ReasonTestVariants {
			if prior, ok := ledgers[i]; ok {
				requests = append(requests, InertRequest{Index: i, PriorLedger: prior})
				requestCandidate = append(requestCandidate, i)
			}
		}
	}
	if len(requests) > 0 {
		if _, err := u.ExtendInertBatch(ctx, requests); err != nil {
			return nil, err
		}
	}
	closed, err := u.Close(ctx)
	if err != nil {
		return nil, err
	}
	results := append([]CheckedCandidate(nil), closed[:len(candidates)]...)
	for k, candIdx := range requestCandidate {
		ext := closed[len(candidates)+k]
		if ext.Verdict.Status == Valid && ext.Extension != nil {
			results[candIdx] = CheckedCandidate{
				Index:     candIdx,
				Subject:   candidates[candIdx].Subject,
				Verdict:   ext.Verdict,
				Extension: ext.Extension,
			}
		} else {
			results[candIdx].Verdict = ext.Verdict
		}
	}
	return results, nil
}

// CheckWithLedger checks a candidate and, when it fails with ReasonTestVariants
// and prior is non-nil, explicitly attempts an inert test-variant extension
// within the same checking unit before closing.
func (b *RuntimeBinding) CheckWithLedger(ctx context.Context, subject Subject, recorded Fingerprint, prior *TestVariantLedger) (CheckedCandidate, error) {
	var ledgers map[int]TestVariantLedger
	if prior != nil {
		ledgers = map[int]TestVariantLedger{0: *prior}
	}
	results, err := b.CheckBatchWithLedgers(ctx, []Candidate{{Subject: subject, Recorded: recorded}}, ledgers)
	if err != nil {
		return CheckedCandidate{}, err
	}
	return results[0], nil
}
