// Package gofresh decides whether a cached result about a Go symbol is still
// trustworthy for the current source tree, or must be recomputed. It fingerprints
// the source a subject depends on and the environment that produced the result
// (closure, guard, runtimeinput), and reports a verdict by comparing a stored
// fingerprint against the current one (spec overview.md). It never runs the symbol
// and never owns the result store: it answers "is this still fresh?" and leaves
// measuring and storing to the caller. Operations use a shared maximal
// package closure so multi-subject checks avoid per-subject whole-program
// analysis; whole-program reachability runs only for the caller-selected
// observability proof.
//
// Setting GOFRESH_TRACE (for example GOFRESH_TRACE=all, GOFRESH_TRACE=toolchain,view,
// or GOFRESH_TRACE=closure:BenchmarkFoo) enables structured operational diagnostic
// tracing across the toolchain, closure, view, and session subsystems without
// altering any normalized environment, guard, closure digest, memo key, or
// recorded runtime-input dependency. Events write to os.Stderr by default or to
// the path named by GOFRESH_TRACE_FILE (JSON Lines when ending in .jsonl or .json,
// single-line key-value text otherwise).
package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// Kind classifies a cached result for guard selection (REQ-fresh-guard-set): a
// CodeResult (a test verdict, a mutation kill) is checked under the code guards
// only; a Measurement (a benchmark) also under the measurement guards.
type Kind = guard.Kind

const (
	CodeResult  = guard.CodeResult
	Measurement = guard.Measurement
)

// Guards holds the environment guard digests for a fingerprint.
type Guards = guard.Guards

// CaptureGuards computes the environment guards applicable to kind in r's
// directory under env as the complete runtime environment.
func CaptureGuards(ctx context.Context, r *gotool.EnvReader, env []string, kind Kind, buildInputs ...string) (Guards, error) {
	trace.RefreshFromEnv()
	if ctx == nil {
		return Guards{}, errors.New("gofresh: nil guard capture context")
	}
	if err := ctx.Err(); err != nil {
		return Guards{}, err
	}
	if r == nil {
		return Guards{}, errors.New("gofresh: nil environment reader")
	}
	return guard.Capture(ctx, r, env, kind, buildInputs...)
}

// TestVariantBindingStrategy versions the base-package binding derivation on
// TestVariantLedger.
const TestVariantBindingStrategy = testvariant.BindingStrategy

// TestVariantLedger and its element types are the declaration-level read
// surface over a package's test-variant compartment, served by
// Snapshot.TestVariantLedger (REQ-closure-test-variant-ledger).
type (
	TestVariantLedger            = testvariant.TestVariantLedger
	TestVariantDeclaration       = testvariant.TestVariantDeclaration
	TestVariantFileHeader        = testvariant.TestVariantFileHeader
	TestVariantFileBindings      = testvariant.TestVariantFileBindings
	TestVariantImport            = testvariant.TestVariantImport
	TestVariantDelta             = testvariant.TestVariantDelta
	TestVariantDeclarationChange = testvariant.TestVariantDeclarationChange
	TestVariantHeaderChange      = testvariant.TestVariantHeaderChange
)

// DiffTestVariantLedgers classifies the delta between a recorded and a current
// compartment ledger; TestVariantDelta.Inert carries the universal Go-semantics
// judgment gofresh renders over it (REQ-closure-test-variant-inertness).
func DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta {
	return testvariant.DiffTestVariantLedgers(before, after)
}

func inertTestVariantLedgersForSubject(before, after TestVariantLedger, subjectSymbol string) bool {
	return testvariant.InertForSubject(before, after, subjectSymbol)
}

// Subject names the symbol whose freshness is tracked — a package import path and a
// symbol within it, either a function name or a "Type.Method" method reference.
type Subject struct {
	Package string
	Symbol  string
}

// setMemoRoot redirects gofresh's persistent memo store — one knob
// covering every memo class (observability proofs, effect and testing
// scans, dynamic-state facts, package scans, listings, per-file scans
// and compartment derivations). Empty restores the user-cache default.
// The store is a cache, never a record: no knob position changes a
// verdict, only what is recomputed, and a hermetic environment that
// forbids user-cache writes redirects it to scratch. Set at process
// start, before any Session runs.
func setMemoRoot(dir string) { closure.SetMemoRoot(dir) }

// DefaultMemoMaxBytes is the default retention ceiling (2 GiB) for the
// persistent memo store across all memo classes.
const DefaultMemoMaxBytes = closure.DefaultMemoMaxBytes

// MemoPruneReport summarizes one retention pass over the persistent memo store.
type MemoPruneReport = closure.MemoPruneReport

// PruneMemos evicts persistent memo entries under <storeRoot>/gofresh until
// retained bytes are at most maxBytes (0 or negative evicts all memo entries).
func PruneMemos(maxBytes int64) (MemoPruneReport, error) { return closure.PruneMemos(maxBytes) }

// PreviewPruneMemos reports the MemoPruneReport that PruneMemos(maxBytes) would
// produce without removing any files or directories.
func PreviewPruneMemos(maxBytes int64) (MemoPruneReport, error) {
	return closure.PreviewPruneMemos(maxBytes)
}

// DynamicStateStrategy identifies the shared-dynamic-state fact derivation
// whose per-package facts the persistent memo serves for version-pinned
// packages (REQ-closure-dynamic-state-memo). Changing fact semantics bumps
// this version like any other strategy change.
const DynamicStateStrategy = "gofresh/dynamic-state@49"

// ClosureStrategy identifies the closure identity derivation — the
// maximal closure's and the test-variant compartment's — as the
// composition of the fold derivations they read (closure.IdentityStrategy):
// a bump to any fold moves it by construction, so a consumer keying a
// judgment to either hash compares within one derivation. An empty
// recorded value is not a derivation: records predating the field exist
// under two folds (the byte fold and the first canonical form), so a
// consumer treats an empty strategy as incomparable and bridges.
const ClosureStrategy = closure.IdentityStrategy

// ObservationRTA identifies the caller-selected declaration-RTA observability
// proof. A standing coupling rides this surface: the audited mapping
// set's shared-dynamic-state discharge (closure.md) is grounded in the
// mapping syscalls keeping their fail-closed classification at the
// observability tiers — admitting mmap/munmap at the symbol tier
// voids that ground and must land with the mapping set re-derived.
// The version pins the engine's interpretation: any admission or
// classification change bumps it, so persistently memoized analyses and
// recorded proofs from the prior interpretation refuse instead of serving
// under semantics they were not computed by.
const ObservationRTA = "gofresh/observation-rta@57"

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

func (m ExecutionModel) singleSubject() bool  { return m == SingleSubjectExecution }
func (m ExecutionModel) packageProcess() bool { return m == PackageExecution }

// SessionPolicy carries the operation's accepted analysis and assertion policy.
// Vouches is the complete, caller-resolved set of canonical import-path.Variable
// identities, as returned by ParseVouchEntries; session construction
// reads no additional repository vouch file. PureSubjects and AssumePure are
// explicit caller assertions, distinct from selected source directives. Callback
// behavior remains its author's responsibility; descriptions and sets are owned copies.
type SessionPolicy struct {
	EvidenceRoot   string
	Vouches        []string
	PureSubjects   []Subject
	AssumePure     func(Subject) bool
	Execution      ExecutionModel
	AnalysisBudget time.Duration
	Runner         gotool.Runner
	Progress       func(Progress)
}

// Session owns one judged operation's immutable build configuration and
// policy. It executes no subject and stores no result. Source generations belong
// to its snapshots, and producing obligations belong to their independent units.
type Session struct {
	engine *engine
	build  BuildDescription
	roots  runtimeinput.Roots
}

// NewSession admits a complete compilation description and analysis policy.
// Snapshots observe source/build generations; BindRuntime separately admits the
// environment of executions using a retained artifact. Construction honors ctx.
func NewSession(ctx context.Context, build BuildDescription, policy SessionPolicy) (session *Session, err error) {
	trace.RefreshFromEnv()
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
	assumePure := policy.AssumePure
	runner := policy.Runner
	if runner.Containment != nil {
		owned := *runner.Containment
		runner.Containment = &owned
	}
	opts := []option{
		withDir(buildDir), withEnv(buildEnv...), withBuildFlags(build.Flags...),
		withBuildInputs(build.Inputs...), withEvidenceRoot(policy.EvidenceRoot),
		withoutRepositoryVouches(), withDynamicStateVouches(vouches...),
		withAssumePure(func(subject Subject) bool {
			return pure[subject] || (assumePure != nil && assumePure(subject))
		}),
		withGoRunner(runner), withProgress(policy.Progress), withAnalysisBudget(policy.AnalysisBudget),
	}
	switch policy.Execution {
	case PackageExecution:
		opts = append(opts, withPackageProcessExecution())
	case SingleSubjectExecution:
		opts = append(opts, withSingleSubjectExecution())
	}
	e, err := newEngineContext(ctx, opts...)
	if err != nil {
		return nil, err
	}
	e.completeBuild = true
	owned := BuildDescription{Directory: e.dir, Environment: slices.Clone(e.env), Flags: slices.Clone(e.buildFlags), Inputs: append([]string{}, e.buildInputs...)}
	trace.Emit(ctx, trace.DomainSession, "session_init", e.dir,
		trace.String("dir", e.dir),
		trace.Bool("complete_build", e.completeBuild),
		trace.Int("execution_model", int(policy.Execution)),
	)
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
	if s == nil || s.session == nil || !validKind(s.kind) {
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
	if viewTestHooks.runtimeGuards != nil {
		viewTestHooks.runtimeGuards(&guards)
	}
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

// Snapshot observes the requested subjects under the session's admitted build.
// It captures no measurement-side guards; BindRuntime admits those separately.
func (s *Session) Snapshot(ctx context.Context, subjects []Subject, kind Kind) (*Snapshot, error) {
	if s == nil || s.engine == nil {
		return nil, errors.New("gofresh: uninitialized session")
	}
	return s.SnapshotFor(ctx, subjects, s.build.Directory, kind)
}

// SnapshotFor observes the requested subjects and moduleDir under the
// session's admitted build with the guards applicable to kind. It captures no
// measurement-side guards; BindRuntime admits those separately.
func (s *Session) SnapshotFor(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*Snapshot, error) {
	if s == nil || s.engine == nil {
		return nil, errors.New("gofresh: uninitialized session")
	}
	v, err := s.engine.newViewFor(ctx, subjects, moduleDir, kind)
	if err != nil {
		return nil, err
	}
	v.session = s
	return v, nil
}

// BuildDescription returns an owned copy for a package represented in the
// snapshot. The executor protects these build dependencies through execution and
// closing, and uses this description rather than rebuilding under runtime env.
func (s *Snapshot) BuildDescription(pkg string) (BuildDescription, error) {
	if s == nil || s.session == nil || !slices.Contains(s.packages, pkg) {
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
	if err := requireSubjects([]Subject{subject}, func(s Subject) bool {
		return slices.Contains(b.snapshot.subjects, s)
	}, SelectedView); err != nil {
		return Fingerprint{}, err
	}
	v, err := b.newView([]Subject{subject})
	if err != nil {
		return Fingerprint{}, err
	}
	return v.Capture(ctx, subject)
}

// engine is immutable analysis configuration. Source, guards, purity directives,
// and derived analysis state live in an explicit Snapshot and never cross view
// generations (REQ-fresh-coherent-view); within one generation, sibling views
// derived from a parent share its recorded facts by contract.
type engine struct {
	// unauditedNotice gates this engine's one unlisted-toolchain
	// announcement (view.go emitUnauditedToolchainNotice).
	unauditedNotice sync.Once
	assumePure      func(Subject) bool
	buildFlags      []string
	buildInputs     []string
	dir             string
	env             []string
	envSet          bool
	// completeBuild selects the explicit session build-description guard.
	// Legacy construction has no complete additional-input declaration.
	completeBuild bool
	// evidenceRoot is the root a subject's runtime-input evidence is
	// anchored at: relative identities are re-hashed under it. Empty
	// means the module directory (withEvidenceRoot).
	evidenceRoot   string
	analysisBudget time.Duration
	// runner spawns every go command the engine runs itself
	// (withGoRunner); the zero value is the plain spawn.
	runner             gotool.Runner
	progress           func(Progress)
	deferredCheckClose bool
	// dynamicStateVouches is the caller's vouch set: canonical
	// "<import path>.<Variable>" identities of version-pinned dependency
	// variables the caller accepts as stable after initialization
	// (REQ-vouch-input). Empty means no vouches.
	dynamicStateVouches map[string]bool
	// withoutRepositoryVouches declines the repository's reviewed vouch
	// file at the engine's root (withoutRepositoryVouches): a consumer
	// that owns its own reviewed set supplies it whole through the
	// option instead of reading two homes.
	withoutRepositoryVouches bool
	// executionModel holds the caller's positive execution-model
	// attestation (withSingleSubjectExecution, withPackageProcessExecution);
	// the zero value is GeneralExecution, which supplies no positive assertion.
	executionModel ExecutionModel
}

// viewTestHooks holds internal observation callbacks and explicitly named
// test controls. Nil or zero disables them. Root tests run sequentially,
// so package scope suffices.
var viewTestHooks struct {
	// observe observes every source/guard/purity observation pass — tests
	// pin how many observations an operation performs.
	observe func()
	// runtimeGuards observes or perturbs an execution-side guard sample in
	// binding/closing tests, independently of source/build observation passes.
	runtimeGuards func(*guard.RuntimeGuards)
	// snapshot observes the env snapshot each precise-analysis bracket
	// derives its configuration from — tests pin that the bracket reuses
	// the view's construction snapshot instead of re-reading go env.
	snapshot func(*gotool.EnvSnapshot)
	// dynamicStateMissLoad observes the batched typed load of
	// version-pinned packages whose dynamic-state facts missed the memo.
	dynamicStateMissLoad func(patterns []string)
	// guardDir observes the directory each guard observation captures
	// in — tests pin that an evidence root moves no guard or load off
	// the module directory (REQ-inputs-evidence-root).
	guardDir func(dir string)
	// typedLoad observes every typed package load an observation pass
	// performs; runtimeWindow every runtime-input window a check opens;
	// maximalBatch every maximal-closure fold — tests pin that a
	// preparation refusal fires before each of them.
	typedLoad     func()
	runtimeWindow func()
	maximalBatch  func()
	// beforeAnalysis observes the point a precise analysis is about to
	// start, after its Hasher exists — tests cancel there to pin the
	// kept-on-cancel report.
	beforeAnalysis func()
	// beforeDischarge observes the point the dynamic-state discharges'
	// reachability analysis is about to start — tests cancel there to
	// pin that an operation's cancellation is never read as a budget
	// cut.
	beforeDischarge func()
	// analysisBound replaces only positive-budget deadline construction in
	// tests. A provenance fixture can expire its selected analysis phase
	// deterministically while default-clock tests exercise real deadlines.
	analysisBound func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	// scanMemoOff disables the view scan memo (REQ-closure-scan-memo) so
	// derivation tests that poison the in-process fact cache between two
	// scans — a seam with no production analogue, since a pinned fact
	// moves only when its key does — exercise the derivation itself.
	scanMemoOff bool
	// factScope observes the derived dynamic-state fact scope — tests
	// pin the execution-model markers that keep option-on and
	// option-off sessions from serving each other's facts.
	factScope func(scope string)
}

// option configures an engine.
type option func(*engine)

// withBuildFlags supplies complete go-command flags used by the producing build,
// such as -tags=integration, -race, or -pgo=profile. The flags select every source
// load and are folded into the build-configuration guard, so the closure and guard
// describe the same binary (REQ-guard-buildconfig).
func withBuildFlags(flags ...string) option {
	return func(e *engine) { e.buildFlags = append([]string(nil), flags...) }
}

// withGoRunner installs the runner every go command the engine spawns
// itself runs through — each pass's environment snapshot (both code
// guards read it), the closure's package listings — so a
// consumer's process boundary and hook reach them
// (REQ-fresh-go-command-policy). The package loader's `go list`
// children spawn through x/tools, outside any runner; the runtime-input
// roots probe is a producer's spawn, under the runner the consumer's
// ProducerIngest names. Without the option the engine spawns plainly.
func withGoRunner(r gotool.Runner) option {
	return func(e *engine) { e.runner = r }
}

// newPassReader mints a pass's environment reader over the engine's
// runner, directory, and analysis environment: one per pass, its
// snapshot taken on the pass's first key.
func (e *engine) newPassReader() *gotool.EnvReader {
	return gotool.NewEnvReader(e.runner, e.dir, e.env)
}

// withBuildInputs supplies opaque build evidence that cannot itself configure a Go
// source load, such as a PGO profile's content digest. It is folded into the
// build-configuration guard (REQ-guard-buildconfig). Go-command flags belong in
// withBuildFlags; presenting one here is refused when newEngine applies the options.
func withBuildInputs(inputs ...string) option {
	return func(e *engine) { e.buildInputs = append([]string(nil), inputs...) }
}

// Progress reports the start of one analysis step, or a fact about an
// operation: Phase is "observe" for a view observation pass, "runtime"
// for each runtime-input observation pass (a check's window performs
// two), "list" for a package's dependency listing, "typecheck" for a
// typed load (the view's shared load or a dynamic-state miss load, Total
// its pattern count; or a package's own testing-effect scan load when
// that memo is cold and no shared load covers the package), "load" for
// a package program load, "hash" for a package's closure fold, "prove" for a package's observability batch
// (one event per attribution slice, Index/Total the slice position),
// "served" once per operation per memo class that stood in for a step —
// Served names the class (an observability proof, an effect scan, a
// testing scan, dynamic-state facts, a package scan, a dependency
// listing, a file scan, a compartment parse) and Index counts the distinct
// packages it served from the persistent store; "cancelled" once per
// operation that returns its caller's context error, Detail saying what
// the operation persisted and a rerun serves; "toolchain-unaudited" and
// "analysis-unavailable" carry their diagnostic payload in Detail, as
// does "listing-unmodelled" (a module file this build cannot parse
// leaves a package's listing spawned every pass) and "budget-exhausted"
// (once per proof pass the analysis budget cut, Detail naming the
// budget and the count of subjects it left unproven). Package
// names the package for the per-package phases; Index and Total give the
// unit's position when the pass knows it (1-based; zero when unknown).
// Events are emitted before the step runs — except the facts about an
// operation ("served", "cancelled", "budget-exhausted"), reported when
// they are known — and carry no completion signal; they are keep-alive
// facts about work, never verdict evidence (REQ-fresh-progress); a
// consumer that prints Detail-bearing events prints only the
// diagnostics.
type Progress struct {
	Phase   string
	Package string
	Index   int
	Total   int
	// Served names the memo class of a "served" summary.
	Served string
	// Detail carries a diagnostic payload for phases that have one -
	// the per-subject analysis-unavailable provenance included, whose
	// walk-order-dependent content must reach the operator without
	// riding any memoized, hashed surface
	// (REQ-closure-observability-memo).
	Detail string
}

// unitPhases is the per-unit phase set: the phases reported before a
// unit of analysis work runs. The other phases are facts about an
// operation ("served", "cancelled", "budget-exhausted") or diagnostics
// ("toolchain-unaudited", "analysis-unavailable", "listing-unmodelled"),
// reported when known and naming no stretch.
var unitPhases = []string{"list", "typecheck", "load", "hash", "observe", "runtime", "prove"}

// UnitPhases returns the per-unit phase set — a consumer's keep-alive
// names a stretch for exactly these (REQ-fresh-progress) — as its own
// copy: the set is the contract, never a consumer's to reorder.
func UnitPhases() []string {
	return slices.Clone(unitPhases)
}

// IsUnit reports whether the event opens a unit of analysis work — a
// member of UnitPhases — as opposed to a fact or a diagnostic.
func (p Progress) IsUnit() bool {
	return slices.Contains(unitPhases, p.Phase)
}

// withProgress supplies a callback invoked synchronously at the start of each
// long-running analysis step. The callback must be fast, must not call back
// into the engine, and must be safe for concurrent invocation — one engine can
// serve concurrent operations. A panicking callback unwinds through the
// operation that emitted the event.
func withProgress(f func(Progress)) option {
	return func(e *engine) { e.progress = f }
}

// Diagnostic renders a diagnostic-bearing event's one line — the phase,
// the package where the event names one, and the detail, a multi-line
// detail (a module file's parse errors are joined by newlines) folded
// onto the line with "; " — and reports false for a keep-alive event,
// which carries no message. A consumer printing diagnostics without a
// rendering of its own prints this one, so such tools' logs spell an
// engine diagnostic one way (REQ-fresh-progress).
func (p Progress) Diagnostic() (string, bool) {
	if p.Detail == "" {
		return "", false
	}
	detail := strings.Join(strings.Split(strings.TrimRight(strings.ReplaceAll(p.Detail, "\r\n", "\n"), "\n"), "\n"), "; ")
	if p.Package == "" {
		return p.Phase + " — " + detail, true
	}
	return p.Phase + " " + p.Package + " — " + detail, true
}

// DiagnosticsTo is the progress sink that writes each diagnostic-bearing
// event's rendering to w as one "gofresh: "-prefixed line and writes
// nothing for a keep-alive event: a consumer's log channel for the
// engine's diagnostics (REQ-fresh-progress). Writes through this sink
// are serialized, so w need not be safe for the concurrent invocation
// SessionPolicy.Progress's callback contract allows — consumers sharing one
// writer share one sink, built beside the writer, not per engine. A
// consumer that also acts on keep-alives composes its own callback,
// taking the keep-alive branch from Diagnostic's false.
func DiagnosticsTo(w io.Writer) func(Progress) {
	var mu sync.Mutex
	return func(p Progress) {
		if line, ok := p.Diagnostic(); ok {
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(w, "gofresh: %s\n", line)
		}
	}
}

// withAnalysisBudget bounds each precise-analysis phase — observability
// proving, whether selected at capture or re-established at
// validation, and the dynamic-state discharges' reachability analysis
// in every observation pass — to d of wall clock. A
// batched operation's shared analysis draws on one budget; each operation
// derives a fresh one. An exhausted budget yields unavailable evidence for the
// affected subjects — captures record the unavailable proof, validation
// reports ErrAnalysisUnavailable — or leaves a culprit the discharge
// could not judge standing (the subject keeps its refusal, its reason
// naming the budget; the pass persists no scan facts of that package;
// a difference between two observations that the cut alone explains
// is the analysis's unavailability, never drift), and it never cancels
// the operation itself, which remains governed solely by the caller's context
// (REQ-fresh-context). Zero means unbounded.
func withAnalysisBudget(d time.Duration) option {
	return func(e *engine) { e.analysisBudget = d }
}

// withAssumePure supplies the caller's purity predicate: a subject for which it
// returns true has all of its unverifiability suppressed (REQ-purity-input,
// REQ-purity-override). Source directives are discovered inside each Snapshot from the
// same selected source as closure analysis (REQ-purity-directive).
func withAssumePure(pred func(Subject) bool) option {
	return func(e *engine) {
		if pred != nil {
			e.assumePure = pred
		}
	}
}

// withDynamicStateVouches supplies the caller's dynamic-state vouch set:
// each identity is the canonical "<import path>.<Variable>" of a
// package-level variable in a version-pinned dependency that the caller
// accepts as stable after initialization, at the caller's responsibility
// (REQ-vouch-input). A vouched variable is exempt from the
// shared-dynamic-state downgrade (REQ-vouch-discharge); the vouches that
// actually discharged culprits reachable from a subject are recorded on
// its fingerprint (REQ-vouch-recorded). A vouch naming a variable in
// mutable-local source confers nothing — code the caller can edit is
// fixed, not vouched (REQ-vouch-dependency-boundary).
func withDynamicStateVouches(identities ...string) option {
	return func(e *engine) {
		if len(identities) == 0 {
			return
		}
		if e.dynamicStateVouches == nil {
			e.dynamicStateVouches = make(map[string]bool, len(identities))
		}
		for _, identity := range identities {
			if identity != "" {
				e.dynamicStateVouches[identity] = true
			}
		}
	}
}

// withoutRepositoryVouches declines the repository's reviewed vouch
// file (RepositoryVouchFile at the engine's root), which the engine
// otherwise reads at construction in union with withDynamicStateVouches
// — an option extends the reviewed set and never removes from it. A
// consumer that owns its own reviewed standing set supplies it whole
// through the option and declines the file, so one set has one home
// (REQ-vouch-input).
func withoutRepositoryVouches() option {
	return func(e *engine) { e.withoutRepositoryVouches = true }
}

// withSingleSubjectExecution attests the caller's execution model: every
// subject is measured in a process of its own, so no sibling subject's
// execution precedes a subject in the same process. The attestation arms
// the audited pooling set's shared-dynamic-state discharge — under it
// every in-process sync.Pool Put site lies in the subject's own rooted
// flow, so pool contents are a function of the analyzed source and the
// subject alone (REQ-closure-shared-dynamic-state). Without the
// attestation, sibling subjects sharing a process can communicate
// through pool contents (a prior subject's Put plants a value a later
// subject's Get dispatches on), so pool Get/Put on a package-level
// carrier keeps the fail-closed shared-dynamic-state judgment. (The
// audited mapping set — golang.org/x/sys/unix's mapper bookkeeping —
// discharges on its own deepened audit in any execution model and
// needs no attestation.) The
// attestation is the caller's responsibility; it changes what the
// derived dynamic-state facts record, so it is part of the persisted
// fact identity and option-on and option-off sessions never serve each
// other's facts.
func withSingleSubjectExecution() option {
	return func(e *engine) { e.executionModel = SingleSubjectExecution }
}

// withPackageProcessExecution attests the package-process execution
// model: every process that runs a measured subject is the subject
// package's OWN test binary — `go test` of that package, under any
// subject schedule. Precisely: the model binds the processes whose
// observations ATTRIBUTE to a measured subject — for a subject in
// package P, the processes measuring it are P's own test binaries.
// Other binaries may link and even execute P's code; their
// observations attribute to their own subjects, measured under their
// own packages' binaries, so they are outside this claim. Under it the shared-dynamic-state judgment gains
// the binary-scoped reachability discharge: a sibling subject in the
// process is itself one of the binary's harness roots, so a culprit no
// harness root's post-initialization flow can reach is init-determined
// for every subject of the binary (REQ-closure-shared-dynamic-state).
// The attestation is weaker than the single-subject one — it bounds
// WHICH binary runs, not how many subjects share it — and the
// single-subject judgment takes precedence where both are set (each
// is sound under its own model; neither dominates the other's
// discharges). A package with no harness roots discharges vacuously —
// nothing executes past initialization in its own test binary — so
// setting the option for subjects actually measured through ANOTHER
// package's binary is the caller's soundness bug, and its cost is
// maximal. It is the
// caller's responsibility, it is part of the persisted fact identity
// (option-on and option-off sessions never serve each other's facts),
// and its load-bearing discharges ride the evidence
// (PackageProcessDischarges) exactly as the single-subject ones do. A
// consumer that runs subjects through any OTHER binary — another
// package's tests importing the subject's package — must not set it.
func withPackageProcessExecution() option {
	return func(e *engine) {
		if e.executionModel != SingleSubjectExecution {
			e.executionModel = PackageExecution
		}
	}
}

// withDeferredCheckClose defers each check's closing base observation —
// the re-observation proving the tree stable across the check's
// runtime-input reads — to the view's validation: the validation's one
// comparison observation closes every deferred interval at once, and a
// change persisting to it refuses there. Verdicts return provisional
// under this option: the caller MUST consume them only under a later
// successful validation of the same view — any validation outcome short
// of success (refusal, a failed observation, unavailable analysis)
// discards every served verdict — the producer-view discipline
// (REQ-fresh-producer-view). The
// change-and-restore residual widens from each check's own close to the
// validation, carried by the caller's execution-span exclusion. For a
// pipeline running many checks against one quiescent view, the deferral
// collapses per-check base observations into validation's single
// comparison observation (REQ-fresh-coherent-view's deferred close).
func withDeferredCheckClose() option {
	return func(e *engine) { e.deferredCheckClose = true }
}

// withDir roots the engine at dir: every package load and go invocation
// resolves there, so a caller can fingerprint a tree it does not run inside.
// The default is the process working directory captured when newEngine returns.
func withDir(dir string) option {
	return func(e *engine) { e.dir = dir }
}

// withEvidenceRoot anchors runtime-input evidence at dir: a subject's
// recorded relative identities are re-hashed under dir instead of the
// module directory, matching a producer that frames its observations at a
// tree root above the module (a workspace member whose oracles read
// root-module files declared as one surface for every member). dir must
// contain the module directory — newEngine refuses otherwise, since a relative
// identity recorded under a root that does not contain the module could
// not name the module's own inputs. Unset, the module directory is the
// root (REQ-inputs-evidence-root). Package loads, Go commands, closure
// analysis, and guards stay at the module directory.
func withEvidenceRoot(dir string) option {
	return func(e *engine) { e.evidenceRoot = dir }
}

// evidenceRootFor is the root a view re-hashes runtime-input identities
// under: the declared evidence root, else the view's module directory.
func (e *engine) evidenceRootFor(moduleDir string) string {
	if e.evidenceRoot != "" {
		return e.evidenceRoot
	}
	return moduleDir
}

// withEnv supplies the complete process environment used by every package load,
// Go command, source analysis, and guard observation. It has exec.Cmd.Env
// semantics rather than patch semantics. newEngine rejects malformed or duplicate
// entries and owns a normalized copy; later caller mutation has no effect. A
// caller attaching runtime-input evidence under this option uses runtimeinput's
// Env-suffixed constructors with the same complete environment.
func withEnv(env ...string) option {
	owned := append([]string(nil), env...)
	return func(e *engine) {
		e.env = append([]string(nil), owned...)
		e.envSet = true
	}
}

// evidenceEnv is the environment runtime-input revalidation computes
// values from when no RuntimeBinding is attached: the analysis environment.
func (e *engine) evidenceEnv() []string {
	return e.env
}

// newEngine builds an engine without a caller cancellation bound. Operation owners
// use newEngineContext so effective build-flag resolution shares their preparation
// context.
func newEngine(opts ...option) (*engine, error) {
	return newEngineContext(context.Background(), opts...)
}

// newEngineContext builds an engine under ctx, including the go-environment query
// that resolves effective build flags. Cancellation returns no engine. The
// context belongs to construction alone; later operations supply their own.
func newEngineContext(ctx context.Context, opts ...option) (eng *engine, err error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil construction context")
	}
	defer func() {
		if cause := ctx.Err(); cause != nil {
			eng, err = nil, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e := &engine{assumePure: func(Subject) bool { return false }}
	for _, o := range opts {
		o(e)
	}
	if !e.envSet {
		e.env = os.Environ()
	}
	normalized, err := gotool.NormalizeEnv(e.env)
	if err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	e.env = normalized
	if _, err := gotool.EnvForPackages(e.env); err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve working directory: %w", err)
		}
		e.dir = cwd
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	root, err := gotool.CanonicalDir(e.dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve engine tree: %w", err)
	}
	e.dir = root
	// The repository's reviewed vouch set joins the caller's: the file at
	// the root the engine is opened at — the root every view it judges
	// shares (coherentDir) — read whole or refused, an absent file the
	// empty set (REQ-vouch-input).
	if !e.withoutRepositoryVouches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reviewed, err := ReadVouchFile(filepath.Join(e.dir, RepositoryVouchFile))
		if err != nil {
			return nil, fmt.Errorf("gofresh: %w", err)
		}
		withDynamicStateVouches(reviewed...)(e)
	}
	if e.evidenceRoot != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidenceRoot, err := gotool.CanonicalDir(e.evidenceRoot)
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve evidence root: %w", err)
		}
		if rel, err := filepath.Rel(evidenceRoot, e.dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("gofresh: evidence root %s does not contain the module directory %s; relative identities recorded under it could not name the module's inputs", evidenceRoot, e.dir)
		}
		e.evidenceRoot = evidenceRoot
	}
	for _, input := range e.buildInputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use WithBuildFlags", input)
		}
	}
	if err := buildflags.Validate(ctx, e.newPassReader(), e.buildFlags); err != nil {
		return nil, err
	}
	return e, nil
}

// capture records the closure hash and code-result guard values for subject, whose code lives
// under moduleDir (the dir `go` resolves the toolchain and build env in). Runtime
// inputs are added by the caller from the run's completion-asserted testlog
// (runtimeinput.FromTestLog), from an incomplete process
// (runtimeinput.Incomplete), by re-admitting a persisted manifest union
// (runtimeinput.Adopt), or by combining several process observations
// (runtimeinput.Merge) under the environment supplied to
// withEnv; revalidation recomputes under that same environment, so
// ingesting under any other is the incoherent mixing the
// runtime-inputs contract forbids — into the returned Fingerprint's
// RuntimeInputs/RuntimeDigest fields. An observation-free run still attaches the
// non-empty manifest those functions return.
func (e *engine) capture(ctx context.Context, subject Subject, moduleDir string) (Fingerprint, error) {
	view, err := e.newView(ctx, []Subject{subject}, moduleDir)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

// captureFor records subject with the guards applicable to kind. Measurements must
// use this method so machine and runtime-configuration evidence is captured.
func (e *engine) captureFor(ctx context.Context, subject Subject, moduleDir string, kind Kind) (Fingerprint, error) {
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, kind)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

// check reports the freshness verdict for a recorded fingerprint against the current
// tree under its recorded result kind. It recomputes the current closure and guards
// (never reconstructing a historical build — REQ-guard-recompute) and, when the
// recording carries a runtime-input manifest, re-hashes it, then decides.
func (e *engine) check(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := recorded.Validate(); err != nil {
		return Verdict{}, err
	}
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.Check(ctx, recorded, subject)
}

// checkObserved checks a caller-selected observation proof under ctx. It never
// infers observation policy for ordinary check calls.
func (e *engine) checkObserved(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := recorded.Validate(); err != nil {
		return Verdict{}, err
	}
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.CheckObserved(ctx, recorded, subject)
}

func (e *engine) guardInputs() []string {
	inputs := make([]string, 0, len(e.buildFlags)+len(e.buildInputs))
	for _, flag := range e.buildFlags {
		inputs = append(inputs, "flag="+flag)
	}
	for _, input := range e.buildInputs {
		inputs = append(inputs, "input="+input)
	}
	return inputs
}

// coherentDir refuses a guards dir that disagrees with the engine's tree
// root: the closure would come from one tree and the environment guards
// from another — an incoherent fingerprint that could serve or stale on the
// wrong tree's facts. Without withDir, the source root is the process cwd.
func (e *engine) coherentDir(moduleDir string) error {
	rootDir := e.dir
	if rootDir == "" {
		var err error
		rootDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("gofresh: resolve process tree: %w", err)
		}
	}
	root, err := os.Stat(rootDir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve engine tree %s: %w", rootDir, err)
	}
	module, err := os.Stat(moduleDir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve guards tree %s: %w", moduleDir, err)
	}
	if os.SameFile(root, module) {
		return nil
	}
	return fmt.Errorf("gofresh: engine rooted at %s asked to capture guards in %s; one tree per fingerprint", rootDir, moduleDir)
}

// completeBuildGoEnvKeys are the resolved `go env -json` settings that determine
// compilation output (beyond GOGCCFLAGS, which is normalized separately, and
// GOWORK, whose on/off workspace mode is recorded without pinning the local
// checkout path). Local checkout and cache paths (GOMOD, GOCACHE, GOTMPDIR,
// GOPATH, GOMODCACHE, GOBIN, GOTOOLDIR, GOROOT, GOENV) are excluded so
// relocating a checkout or isolating a cache does not falsify the build guard.
var completeBuildGoEnvKeys = []string{
	"AR",
	"CC",
	"CGO_CFLAGS",
	"CGO_CPPFLAGS",
	"CGO_CXXFLAGS",
	"CGO_ENABLED",
	"CGO_FFLAGS",
	"CGO_LDFLAGS",
	"CXX",
	"FC",
	"GCCGO",
	"GO111MODULE",
	"GO386",
	"GOAMD64",
	"GOARCH",
	"GOARM",
	"GOARM64",
	"GODEBUG",
	"GOEXPERIMENT",
	"GOFIPS140",
	"GOFLAGS",
	"GOHOSTARCH",
	"GOHOSTOS",
	"GOMIPS",
	"GOMIPS64",
	"GOOS",
	"GOPPC64",
	"GORISCV64",
	"GOVERSION",
	"GOWASM",
	"PKG_CONFIG",
}

// completeBuildOSEnvKeys are the process-environment variables outside `go env`
// that affect cgo/pkg-config resolution and reproducible compilation output.
var completeBuildOSEnvKeys = []string{
	"CGO_CFLAGS_ALLOW",
	"CGO_CFLAGS_DISALLOW",
	"CGO_CPPFLAGS_ALLOW",
	"CGO_CPPFLAGS_DISALLOW",
	"CGO_CXXFLAGS_ALLOW",
	"CGO_CXXFLAGS_DISALLOW",
	"CGO_FFLAGS_ALLOW",
	"CGO_FFLAGS_DISALLOW",
	"CGO_LDFLAGS_ALLOW",
	"CGO_LDFLAGS_DISALLOW",
	"PKG_CONFIG_LIBDIR",
	"PKG_CONFIG_PATH",
	"PKG_CONFIG_SYSROOT_DIR",
	"SOURCE_DATE_EPOCH",
}

// completeBuildEnvironment supplements the ordinary build guard's flag/input
// framing with the build-determining compilation environment and resolved Go
// settings. Ambient shell variables and local checkout or cache directory paths
// are excluded so moving checkouts, isolating caches, or changing non-build
// shell variables does not falsify the build guard. The go command's generated
// work-directory operand is normalized under its documented compiler
// prefix-mapping premise, and a declared GOENV file remains a content-byte
// dependency.
func completeBuildEnvironment(ctx context.Context, snapshot *gotool.EnvSnapshot, dir string, env []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var values map[string]string
	if snapshot == nil {
		return "", fmt.Errorf("gofresh: build description has no environment snapshot")
	}
	if err := json.Unmarshal(snapshot.JSON, &values); err != nil {
		return "", err
	}
	gcc, ok := values["GOGCCFLAGS"]
	if !ok {
		return "", fmt.Errorf("gofresh: build description has no GOGCCFLAGS")
	}
	flags, err := normalizedGCCFlags(gcc)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	write := func(s string) { fmt.Fprintf(h, "%d:", len(s)); _, _ = h.Write([]byte(s)) }
	sequence := func(values []string) {
		fmt.Fprintf(h, "%d:", len(values))
		for _, value := range values {
			write(value)
		}
	}
	write("gofresh/build-environment@2")
	fmt.Fprintf(h, "%d:", len(completeBuildOSEnvKeys))
	for _, key := range completeBuildOSEnvKeys {
		write(key)
		if val, ok := gotool.LookupEnv(env, key); ok {
			write("present")
			write(val)
		} else {
			write("absent")
		}
	}
	fmt.Fprintf(h, "%d:", len(completeBuildGoEnvKeys))
	for _, key := range completeBuildGoEnvKeys {
		write(key)
		write(values[key])
	}
	if gowork := values["GOWORK"]; gowork != "" && gowork != "off" {
		write("gowork=on")
	} else {
		write("gowork=off")
	}
	sequence(flags)
	path := values["GOENV"]
	if path == "" || path == "off" {
		write("no-environment-file")
	} else {
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			write("absent-environment-file")
		} else {
			if err != nil {
				return "", fmt.Errorf("gofresh: build environment file: %w", err)
			}
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("gofresh: build environment file %q is not regular", path)
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("gofresh: build environment file: %w", err)
			}
			write("environment-file")
			write(string(data))
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func normalizedGCCFlags(text string) ([]string, error) {
	flags, err := buildflags.Fields(text)
	if err != nil {
		return nil, fmt.Errorf("gofresh: GOGCCFLAGS: %w", err)
	}
	maps := 0
	for i, flag := range flags {
		for _, prefix := range []string{"-ffile-prefix-map=", "-fdebug-prefix-map="} {
			if !strings.HasPrefix(flag, prefix) {
				continue
			}
			maps++
			operand, mapped := strings.CutSuffix(strings.TrimPrefix(flag, prefix), "=/tmp/go-build")
			if !mapped || !filepath.IsAbs(operand) || !strings.HasPrefix(filepath.Base(operand), "go-build") || maps > 1 {
				return nil, fmt.Errorf("gofresh: GOGCCFLAGS has an unrecognized generated prefix mapping %q", flag)
			}
			flags[i] = prefix + "<generated-work-directory>=/tmp/go-build"
		}
	}
	return flags, nil
}

// prepareOutcomeSupport derives support for exactly this view's contributing
// subject set, before execution. Use a sibling view for a narrower process set.
// The caller runs that exact set under the view's complete runtime environment
// and excludes environment mutation. Unsupported inventories return a capability
// carrying their refusal; they never turn process health into outcome evidence.
// Preparation selects each subject's observation proof for producer validation.
func (v *Snapshot) prepareOutcomeSupport(ctx context.Context, frame runtimeinput.ProducerFrame, process string) (runtimeinput.OutcomeSupport, map[Subject]Fingerprint, error) {
	if v == nil || v.facts == nil || v.engine == nil {
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
