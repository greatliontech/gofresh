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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
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

func refreshTraceFromEnv() {
	trace.Refresh(os.Getenv(trace.EnvTrace), os.Getenv(trace.EnvTraceFile))
}

// CaptureGuards computes the environment guards applicable to kind for build
// under runtimeEnv as the complete runtime environment (a nil runtimeEnv
// inherits build.Environment).
func CaptureGuards(ctx context.Context, build BuildDescription, runtimeEnv []string, kind Kind, prepare ...func(*exec.Cmd)) (Guards, error) {
	refreshTraceFromEnv()
	if ctx == nil {
		return Guards{}, errors.New("gofresh: nil guard capture context")
	}
	if err := ctx.Err(); err != nil {
		return Guards{}, err
	}
	if build.Directory == "" {
		return Guards{}, errors.New("gofresh: empty guard capture directory")
	}
	if build.Environment == nil {
		return Guards{}, errors.New("gofresh: build environment must be explicitly provided")
	}
	if runtimeEnv == nil {
		runtimeEnv = build.Environment
	}
	var snapshot *gotool.EnvSnapshot
	if build.GoEnv != nil {
		var err error
		snapshot, err = gotool.EnvSnapshotFromValues(build.GoEnv)
		if err != nil {
			return Guards{}, err
		}
	}
	reader := gotool.PrimedEnvReader(gotool.Runner{Prepare: firstPrepare(prepare)}, gotool.Coordinate(build.Directory), build.Environment, snapshot)
	inputs := make([]string, 0, len(build.Flags)+len(build.Inputs))
	for _, flag := range build.Flags {
		inputs = append(inputs, "flag="+flag)
	}
	for _, input := range build.Inputs {
		inputs = append(inputs, "input="+input)
	}
	return guard.Capture(ctx, reader, runtimeEnv, kind, inputs...)
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

// Subject names the symbol whose freshness is tracked — a package import path and a
// symbol within it, either a function name or a "Type.Method" method reference.
type Subject struct {
	Package string
	Symbol  string
}

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
const DynamicStateStrategy = "gofresh/dynamic-state@75"

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
const ObservationRTA = "gofresh/observation-rta@65"

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
	// GoEnv is an optional pass-scoped `go env -json` setting map already
	// taken by the caller in the same observation pass for Directory and
	// Environment, avoiding a duplicate `go env` subprocess in CaptureGuards
	// and ResolveToolchainSelection. NewSession ignores it and always takes
	// its own snapshot.
	GoEnv map[string]string
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
	PrepareCommand func(*exec.Cmd)
	Progress       func(Progress)
}

// Session owns one judged operation's immutable build configuration and
// policy. It executes no subject and stores no result. Source generations belong
// to its snapshots, and producing obligations belong to their independent units.
// Source, guards, purity directives, and derived analysis state live in an
// explicit Snapshot and never cross view generations (REQ-fresh-coherent-view);
// within one generation, sibling views derived from a parent share its recorded
// facts by contract.
type Session struct {
	build           BuildDescription
	roots           runtimeinput.Roots
	unauditedNotice sync.Once
	assumePure      func(Subject) bool
	buildFlags      []string
	buildInputs     []string
	dir             string
	env             []string
	// evidenceRoot is the root a subject's runtime-input evidence is
	// anchored at: relative identities are re-hashed under it. Empty
	// means the module directory.
	evidenceRoot   string
	analysisBudget time.Duration
	// runner spawns every go command the session runs itself; the zero
	// value is the plain spawn.
	runner             gotool.Runner
	progress           func(Progress)
	deferredCheckClose bool
	// dynamicStateVouches is the caller's vouch set: canonical
	// "<import path>.<Variable>" identities of version-pinned dependency
	// variables the caller accepts as stable after initialization
	// (REQ-vouch-input). Empty means no vouches.
	dynamicStateVouches map[string]bool
	sortedVouches       []string
	// executionModel holds the caller's positive execution-model
	// attestation; the zero value is GeneralExecution, which supplies no
	// positive assertion.
	executionModel ExecutionModel
}

// NewSession admits a complete compilation description and analysis policy.
// Snapshots observe source/build generations; BindRuntime separately admits the
// environment of executions using a retained artifact. Construction honors ctx.
func NewSession(ctx context.Context, build BuildDescription, policy SessionPolicy) (session *Session, err error) {
	refreshTraceFromEnv()
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
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	buildEnv, err = gotool.EnvForCommand(buildEnv, buildDir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: build environment: %w", err)
	}
	vouches, err := canonicalSessionVouches(policy.Vouches)
	if err != nil {
		return nil, err
	}
	var vouchMap map[string]bool
	if len(vouches) > 0 {
		vouchMap = make(map[string]bool, len(vouches))
		for _, v := range vouches {
			vouchMap[v] = true
		}
	}
	pure := make(map[Subject]bool, len(policy.PureSubjects))
	for _, subject := range policy.PureSubjects {
		if subject.Package == "" || subject.Symbol == "" {
			return nil, errors.New("gofresh: empty purity-assertion subject")
		}
		pure[subject] = true
	}
	assumePure := policy.AssumePure
	var evidenceRoot string
	if policy.EvidenceRoot != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidenceRoot, err = gotool.CanonicalDir(policy.EvidenceRoot)
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve evidence root: %w", err)
		}
		if rel, err := filepath.Rel(evidenceRoot, buildDir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("gofresh: evidence root %s does not contain the module directory %s; relative identities recorded under it could not name the module's inputs", evidenceRoot, buildDir)
		}
	}
	for _, input := range build.Inputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use BuildFlags", input)
		}
	}
	flags := slices.Clone(build.Flags)
	inputs := append([]string{}, build.Inputs...)
	owned := BuildDescription{
		Directory:   buildDir,
		Environment: slices.Clone(buildEnv),
		Flags:       slices.Clone(flags),
		Inputs:      append([]string{}, inputs...),
	}
	s := &Session{
		build:               owned,
		assumePure:          func(subject Subject) bool { return pure[subject] || (assumePure != nil && assumePure(subject)) },
		buildFlags:          flags,
		buildInputs:         inputs,
		dir:                 buildDir,
		env:                 buildEnv,
		evidenceRoot:        evidenceRoot,
		analysisBudget:      policy.AnalysisBudget,
		runner:              gotool.Runner{Prepare: policy.PrepareCommand},
		progress:            policy.Progress,
		dynamicStateVouches: vouchMap,
		sortedVouches:       vouches,
		executionModel:      policy.Execution,
	}
	passReader := s.newPassReader()
	snapshot, err := passReader.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkSnapshotToolchainProvenance(snapshot); err != nil {
		return nil, err
	}
	if err := buildflags.Validate(ctx, passReader, s.buildFlags); err != nil {
		return nil, err
	}
	trace.Emit(ctx, trace.DomainSession, "session_init", s.dir,
		trace.String("dir", s.dir),
		trace.Bool("complete_build", true),
		trace.Int("execution_model", int(policy.Execution)),
	)
	return s, nil
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

// Snapshot observes the requested subjects under the session's admitted build.
// It captures no measurement-side guards; BindRuntime admits those separately.
func (s *Session) Snapshot(ctx context.Context, subjects []Subject, kind Kind) (*Snapshot, error) {
	if s == nil || s.dir == "" {
		return nil, errors.New("gofresh: uninitialized session")
	}
	return s.SnapshotFor(ctx, subjects, s.build.Directory, kind)
}

// SnapshotFor observes the requested subjects and moduleDir under the
// session's admitted build with the guards applicable to kind. It captures no
// measurement-side guards; BindRuntime admits those separately.
func (s *Session) SnapshotFor(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*Snapshot, error) {
	if s == nil || s.dir == "" {
		return nil, errors.New("gofresh: uninitialized session")
	}
	return s.observeSnapshot(ctx, subjects, moduleDir, kind)
}

// newPassReader mints a pass's environment reader over the session's
// runner, directory, and analysis environment: one per pass, its
// snapshot taken on the pass's first key.
func (s *Session) newPassReader() *gotool.EnvReader {
	return gotool.NewEnvReader(s.runner, s.dir, s.env)
}

// evidenceRootFor is the root a view re-hashes runtime-input identities
// under: the declared evidence root, else the view's module directory.
func (s *Session) evidenceRootFor(moduleDir string) string {
	if s.evidenceRoot != "" {
		return s.evidenceRoot
	}
	return moduleDir
}

// evidenceEnv is the environment runtime-input revalidation computes
// values from when no RuntimeBinding is attached: the analysis environment.
func (s *Session) evidenceEnv() []string {
	return s.env
}

func (s *Session) guardInputs() []string {
	inputs := make([]string, 0, len(s.buildFlags)+len(s.buildInputs))
	for _, flag := range s.buildFlags {
		inputs = append(inputs, "flag="+flag)
	}
	for _, input := range s.buildInputs {
		inputs = append(inputs, "input="+input)
	}
	return inputs
}

// coherentDir refuses a guards dir that disagrees with the session's tree
// root: the closure would come from one tree and the environment guards
// from another — an incoherent fingerprint that could serve or stale on the
// wrong tree's facts.
func (s *Session) coherentDir(moduleDir string) error {
	rootDir := s.dir
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
