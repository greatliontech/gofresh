package runtimeinput

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// testlogHeader is the first line the testing runtime writes on opening
// its -test.testlogfile capture; its presence proves the test binary
// opened the file at all. Without it the capture is the producer's own
// untouched temp file - a TestMain that exits without m.Run passes
// cleanly yet never opens the capture - and ingesting those zero bytes
// would seal "no runtime inputs observed" over a run that observed
// freely. The trailing newline is part of the proof: the runtime writes
// the full line, so a capture truncated inside it never ingests.
var testlogHeader = []byte("# test log\n")

// ProducerFrame is the resolved frame one producer process's completed
// observation is captured and ingested under: the tree root and package
// directory with symlinks resolved, and the pre-spawn observation
// bracket - or, when no bracket exists, the fail-closed reason the
// process's incomplete observation carries. Capture and ingest share
// the frame because a bracket interpreted under a different module view
// than its capture refuses (REQ-inputs-producer-facade).
type ProducerFrame struct {
	Root   string
	PkgDir string
	// PkgRel is the package directory module-relative in slash form -
	// the value declarations over the package's own tree surface (scratch
	// namespaces, bracket paths) are stated in.
	PkgRel string
	// bracket is nil exactly when reason is non-empty.
	bracket *Bracket
	reason  string
	span    *outcome.Span
}

// Reason reports why the frame carries no bracket - empty exactly when
// the frame is usable. A non-empty reason still supports Observe, which
// fails closed to an incomplete observation carrying it; the accessor
// exists so producers can also log the refusal at capture time.
func (f ProducerFrame) Reason() string { return f.reason }

// FrameOptions carries the caller-owned frame vocabulary: reviewed
// extra bracket roots, and the caller's tool-bookkeeping exclusions
// beside the always-excluded VCS tree. The exclusion carries the
// caller-side soundness responsibility the exclusion contract assigns
// it.
type FrameOptions struct {
	BracketPaths  []string
	ExcludedPaths []string
}

// CaptureProducerFrame captures the pre-spawn frame every producer
// shares: both directories symlink-resolved before the containment
// check and before framing (go list reports resolved directories, so a
// symlinked tree prefix would otherwise misclassify every package as
// outside the tree and every recorded read as external), the package
// directory declared module-relative under the root, and the bracket
// fingerprinted over it plus the reviewed paths. Three shapes yield no
// bracket, each fail-closed to a reason the ingest turns into an
// incomplete observation: an unresolvable directory, a package outside
// the resolved tree, and a capture error (REQ-inputs-producer-facade).
func CaptureProducerFrame(ctx context.Context, treeRoot, pkgDir string, opts FrameOptions) ProducerFrame {
	root, err := filepath.EvalSymlinks(treeRoot)
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	resolvedPkgDir, err := filepath.EvalSymlinks(pkgDir)
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	rel, err := filepath.Rel(root, resolvedPkgDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ProducerFrame{reason: fmt.Sprintf("package directory %s lies outside the tree; no observation bracket can cover it", pkgDir)}
	}
	roots := append([]string{filepath.ToSlash(rel)}, opts.BracketPaths...)
	bracket, err := CaptureBracket(ctx, root, roots,
		WithBracketExcludedPaths(append([]string{".git"}, opts.ExcludedPaths...)...))
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	return ProducerFrame{Root: root, PkgDir: resolvedPkgDir, PkgRel: filepath.ToSlash(rel), bracket: &bracket, span: new(outcome.Span)}
}

// producerTestHooks lets tests land a cancellation between the facade's
// entry check and the roots resolution.
var producerTestHooks struct {
	beforeRoots func()
}

// ScratchNamespace declares one in-module run-scratch namespace for the
// ingest (REQ-inputs-scratch-namespace): a module-relative directory and
// a single-component name pattern with os.MkdirTemp semantics.
type ScratchNamespace struct {
	Dir     string
	Pattern string
}

// ProducerIngest carries one process's ingest inputs: the caller owns
// the identity, the process env verbatim (a rebuilt env loses fidelity
// the classification depends on - PWD included), its own
// independently supplied completion receipt, analysis-issued outcome support,
// and declaration vocabulary. The facade checks their common execution binding.
type ProducerIngest struct {
	Identity string
	Env      []string
	// Runner spawns the roots probe (`go env -json` in the package
	// directory): the consumer's runner, so its boundary reaches the
	// probe; the zero value is the plain spawn.
	Runner gotool.Runner
	// Roots is the consumer's classification-root memo, held for one
	// judged run — the consumer's one verb invocation, a long-lived
	// server's per-request operation, never a process — as its
	// toolchain Sampler is: one probe per package directory coordinate
	// and environment across every run that judged run ingests. Nil
	// resolves unmemoized — every run pays its probe.
	Roots *Roots
	// Completion and Outcome are independent premises bound to this process,
	// environment and frame. Neither the receipt nor the capture supplies the
	// other's missing evidence.
	Completion CompletionReceipt
	Outcome    OutcomeSupport
	// ScratchRoot declares a per-run scratch root the producer minted
	// for the process and keeps out of the environment it ingests (an
	// environment read of it would record per-run noise); it stands in
	// for the temp root the environment's TMPDIR would otherwise
	// resolve. Every other classification root — the toolchain, the
	// module cache, the build cache, the go command's own temp root
	// (GOTMPDIR), and the temp root itself when this is empty — is
	// resolved from the environment, never declared.
	ScratchRoot string
	// ExcludedPaths extends the facade-owned ingest exclusions - the
	// module-root listing "." (the bracket never covers the root's own
	// listing, so its identity moves under unrelated tooling) and the
	// VCS tree ".git" - with the producer's tool-bookkeeping surfaces.
	ExcludedPaths     []string
	ScratchNamespaces []ScratchNamespace
}

// Observe ingests one process's testlog capture under the frame. Every
// non-completing shape fails closed to an incomplete observation
// carrying its reason - a lost read must never masquerade as the
// "no runtime inputs observed" assertion - in one canonical order: the
// missing or mismatched completion, abnormal completion, missing or mismatched
// outcome support, an unattached, unreadable or missing capture, a headerless
// capture, a log contradicting the supported operation model, a frame with no bracket, an
// environment whose PWD does not name the package directory (all three
// producers spawn in the package directory; a parent-inherited PWD
// would silently misclassify every cwd-anchored read), an environment
// under which the toolchain cannot answer for the classification
// roots, and an ingestion failure. A supported flushed log ingests with its
// method and subject identities bound into the manifest. The returned reason is
// the process's effective incompleteness, empty exactly when the
// observation completed (REQ-inputs-producer-facade).
func (f ProducerFrame) Observe(ctx context.Context, testlogPath string, in ProducerIngest) (Observation, string, error) {
	return f.observe(ctx, testlogPath, in, true)
}

// ObserveInputs finalizes identity-only input guards for a normally completed
// process. It preserves the facade's frame, environment, classification and
// cancellation rules, but never emits outcome support, even when supplied.
// It is not a request for completion-bearing observation evidence and cannot
// authorize observation-based reuse. The returned reason distinguishes an
// incomplete capture from finalized guards, which may themselves be unverifiable
// because an observed identity could not be guarded.
func (f ProducerFrame) ObserveInputs(ctx context.Context, testlogPath string, in ProducerIngest) (Observation, string, error) {
	return f.observe(ctx, testlogPath, in, false)
}

func (f ProducerFrame) observe(ctx context.Context, testlogPath string, in ProducerIngest, requireOutcomes bool) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	// Bind and finalize from one owned environment, even when a runner hook
	// updates the caller's configuration while resolving classification roots.
	in.Env = slices.Clone(in.Env)
	binding, reason := f.completionPremise(in)
	if reason == "" && requireOutcomes {
		reason = in.Outcome.Reason(binding)
	}
	if !requireOutcomes {
		in.Outcome = OutcomeSupport{}
	}
	if reason != "" {
		return f.incomplete(ctx, in, reason)
	}
	log, reason, err := readProducerLog(ctx, testlogPath)
	if err != nil {
		return Observation{}, "", err
	}
	if reason != "" {
		return f.incomplete(ctx, in, reason)
	}
	if requireOutcomes {
		allowed, err := environmentLog(ctx, log)
		if err != nil {
			return Observation{}, "", err
		}
		if !allowed {
			return f.incomplete(ctx, in, "operation-outcome support does not cover the captured operations")
		}
	}
	observation, reason, err := f.captureBytes(ctx, log, in)
	if err != nil || reason != "" {
		return observation, reason, err
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	return observation, "", nil
}

func (f ProducerFrame) incomplete(ctx context.Context, in ProducerIngest, reason string) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	observation, err := Incomplete(f.Root, in.Identity, reason, in.Env)
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	return observation, reason, err
}

func readProducerLog(ctx context.Context, testlogPath string) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if testlogPath == "" {
		return nil, "testlog capture unavailable: no capture file was attached to the process", nil
	}
	file, err := os.Open(testlogPath)
	if file != nil {
		defer file.Close()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if os.IsNotExist(err) {
		return nil, "test process produced no runtime-input log", nil
	}
	if err != nil {
		return nil, fmt.Sprintf("testlog capture unreadable: %q", err.Error()), nil
	}
	log, err := io.ReadAll(captureReader{ctx: ctx, Reader: file})
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if err != nil {
		return nil, fmt.Sprintf("testlog capture unreadable: %q", err.Error()), nil
	}
	if !bytes.HasPrefix(log, testlogHeader) {
		return nil, "capture file carries no test-log header; the test binary never opened it", nil
	}
	return log, "", nil
}

// captureReader checks the caller's context on both sides of each read, so a
// cancellation concurrent with EOF or an I/O failure cannot become stored data.
type captureReader struct {
	ctx context.Context
	io.Reader
}

func (r captureReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.Reader.Read(p)
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return n, err
}

// captureBytes constructs the identity guard with the subject keys Observe has
// already validated against the execution premises and raw operation model.
// With no supplied keys it constructs identity-only evidence. Classification
// itself never authorizes an outcome-support marker.
func (f ProducerFrame) captureBytes(ctx context.Context, log []byte, in ProducerIngest) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	incomplete := func(reason string) (Observation, string, error) { return f.incomplete(ctx, in, reason) }
	if f.bracket == nil {
		reason := f.reason
		if reason == "" {
			reason = "no observation bracket was captured"
		}
		return incomplete(reason)
	}
	// The validated PWD and the PWD the classification later reads come
	// from the same lookup over the same normalized environment - a
	// parallel scan could diverge from the environment policy's key semantics.
	normalized, err := normalizeEnvironment(in.Env)
	if err != nil {
		return Observation{}, "", err
	}
	pwd, _ := gotool.LookupEnv(normalized, "PWD")
	if pwd == "" {
		return incomplete("process environment carries no PWD; cwd-anchored reads cannot classify under the frame")
	}
	if pwd != f.PkgDir {
		if resolved, err := filepath.EvalSymlinks(pwd); err != nil || resolved != f.PkgDir {
			return incomplete(fmt.Sprintf("process environment PWD %q does not name the package directory %s the frame was captured for", pwd, f.PkgDir))
		}
	}
	if producerTestHooks.beforeRoots != nil {
		producerTestHooks.beforeRoots()
	}
	roots, err := resolveRoots(ctx, in.Roots, in.Runner, f.Root, f.PkgDir, normalized)
	if err != nil {
		if ctx.Err() != nil {
			// The caller's cancellation, not an environment fault: no
			// durable record names the environment for it.
			return Observation{}, "", ctx.Err()
		}
		return incomplete(fmt.Sprintf("classification roots unresolved under the process environment: %v", err))
	}
	opts := []TestLogOption{
		WithCompletedProcess(in.Identity),
		WithBracket(*f.bracket),
		WithExcludedPaths(append([]string{".", ".git"}, in.ExcludedPaths...)...),
		func(cfg *testLogConfig) { cfg.outcomeSubjects = in.Outcome.Subjects() },
	}
	if roots.toolchain != "" {
		opts = append(opts, withToolchainRoot(roots.toolchain))
	}
	if roots.moduleCache != "" {
		opts = append(opts, withModuleCacheRoot(roots.moduleCache))
	}
	if roots.buildCache != "" {
		opts = append(opts, withBuildCacheRoot(roots.buildCache))
	}
	for _, root := range roots.ephemeralRoots(in.ScratchRoot, f.Root) {
		opts = append(opts, withEphemeralTempRoot(root))
	}
	for _, namespace := range in.ScratchNamespaces {
		opts = append(opts, WithScratchNamespace(namespace.Dir, namespace.Pattern))
	}
	observation, err := fromTestLog(ctx, log, f.Root, f.PkgDir, in.Env, opts...)
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	if err != nil {
		return incomplete(fmt.Sprintf("testlog ingestion failed: %v", err))
	}
	return observation, "", nil
}
