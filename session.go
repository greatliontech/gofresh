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

// RuntimeDescription is the complete environment of the built program. A nil
// Environment inherits the session's build environment; a nonnil empty slice
// describes an otherwise empty environment. Directory supplies PWD; omission
// uses the build directory, and a relative directory is based at that directory.
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

// Session owns one judged operation's immutable build/runtime configuration and
// policy. It executes no subject and stores no result. Source generations belong
// to its snapshots, and producing obligations belong to their independent units.
type Session struct {
	engine     *Engine
	build      BuildDescription
	runtimeDir string
	roots      runtimeinput.Roots
}

// NewSession admits explicitly separate compilation and runtime descriptions.
// The executor builds under the former and runs that retained artifact under the
// latter; running a compiling go command under the runtime description violates
// the binding. Construction and its queries honor ctx.
func NewSession(ctx context.Context, build BuildDescription, execution RuntimeDescription, policy SessionPolicy) (session *Session, err error) {
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
	runtimeDir := execution.Directory
	if runtimeDir == "" {
		runtimeDir = buildDir
	} else {
		runtimeDir, err = rebaseProcessPath(buildDir, runtimeDir)
		if err != nil {
			return nil, fmt.Errorf("gofresh: runtime directory: %w", err)
		}
	}
	runtimeDir, err = gotool.CanonicalDir(runtimeDir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: runtime directory: %w", err)
	}
	buildEnv, err := gotool.EnvForPackages(build.Environment)
	if err != nil {
		return nil, fmt.Errorf("gofresh: build environment: %w", err)
	}
	buildEnv, err = gotool.EnvForCommand(buildEnv, buildDir)
	if err != nil {
		return nil, err
	}
	runtimeEnv := execution.Environment
	if runtimeEnv == nil {
		runtimeEnv = buildEnv
	}
	runtimeEnv, err = gotool.NormalizeEnv(runtimeEnv)
	if err != nil {
		return nil, fmt.Errorf("gofresh: runtime environment: %w", err)
	}
	runtimeEnv, err = gotool.EnvForCommand(runtimeEnv, runtimeDir)
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
	// This is the explicit prebuilt-execution form, never the legacy option
	// that ambiguously described a process which might also compile.
	e.producerEnv, e.producerEnvSet = slices.Clone(runtimeEnv), true
	e.completeBuild = true
	e.deferredCheckClose = true
	owned := BuildDescription{Directory: e.dir, Environment: slices.Clone(e.env), Flags: slices.Clone(e.buildFlags), Inputs: append([]string{}, e.buildInputs...)}
	return &Session{engine: e, build: owned, runtimeDir: runtimeDir}, nil
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

// Snapshot observes the requested subjects under the session's admitted build.
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
// accidental cross-snapshot borrowing; it does not authenticate the executor,
// inspect arbitrary binaries, or certify that the executor followed the plan.
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
func (s *Snapshot) Check(ctx context.Context, subject Subject, recorded Fingerprint) (Verdict, error) {
	if s == nil || s.view == nil {
		return Verdict{}, errors.New("gofresh: uninitialized snapshot")
	}
	v, err := s.view.Sibling([]Subject{subject})
	if err != nil {
		return Verdict{}, err
	}
	judgment, err := v.CheckObserved(ctx, recorded, subject)
	if err != nil {
		return Verdict{}, err
	}
	if err := v.Validate(ctx); err != nil {
		return Verdict{}, err
	}
	return judgment, nil
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

// CurrentFacts returns this snapshot's analysis-only fingerprint projection for
// explanations. It carries neither an execution receipt nor runtime observation
// or selected producing proof. It is not a newly produced result.
func (s *Snapshot) CurrentFacts(ctx context.Context, subject Subject) (Fingerprint, error) {
	if ctx == nil {
		return Fingerprint{}, errors.New("gofresh: nil facts context")
	}
	if err := ctx.Err(); err != nil {
		return Fingerprint{}, err
	}
	if s == nil || s.view == nil {
		return Fingerprint{}, errors.New("gofresh: uninitialized snapshot")
	}
	return s.view.Capture(ctx, subject)
}

// CheckInertExtension explicitly requests the native inert-test-variant license.
// It preserves producing evidence and returns the checked endpoint/ledger pair
// only after closing validation. Ordinary Check never requests this transform.
func (s *Snapshot) CheckInertExtension(ctx context.Context, subject Subject, recorded Fingerprint, prior TestVariantLedger) (Fingerprint, TestVariantLedger, Verdict, error) {
	if s == nil || s.view == nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, errors.New("gofresh: uninitialized snapshot")
	}
	v, err := s.view.Sibling([]Subject{subject})
	if err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	fp, ledger, verdict, err := v.CheckObservedInertTestVariantExtension(ctx, recorded, prior, subject)
	if err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	if err := v.Validate(ctx); err != nil {
		return Fingerprint{}, TestVariantLedger{}, Verdict{}, err
	}
	return fp, ledger, verdict, nil
}
