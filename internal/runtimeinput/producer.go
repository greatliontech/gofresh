package runtimeinput

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// CompletionReceipt records the result owner's terminal harness judgment.
// Normal completion includes ordinarily completed failing tests; it does not
// establish operation outcomes. The zero value grants no completion premise.
type CompletionReceipt struct {
	binding OutcomeBinding
	reason  string
}

// testlogHeader is the first line the testing runtime writes on opening
// its -test.testlogfile capture; its presence proves the test binary
// opened the file at all. Without it the capture is the producer's own
// untouched temp file - a TestMain that exits without m.Run passes
// cleanly yet never opens the capture - and ingesting those zero bytes
// would seal "no runtime inputs observed" over a run that observed
// freely. The trailing newline is part of the proof: the runtime writes
// the full line, so a capture truncated inside it never ingests.
var (
	testlogHeaderLine = []byte("# test log")
	getenvLinePrefix  = []byte("getenv ")
)

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
	span    *outcomeSpan
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

// ResolveProducerFrame resolves symlinked root and package-directory execution
// coordinates and allocates a unique execution span without walking the
// filesystem to capture an observation bracket. Pure units with omitted capture
// use this lightweight frame so normal completion pays zero directory-walk cost
// while abnormal completion still synthesizes canonical incomplete evidence.
func ResolveProducerFrame(treeRoot, pkgDir string) ProducerFrame {
	root, err := filepath.EvalSymlinks(treeRoot)
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	resolvedPkgDir, err := filepath.EvalSymlinks(pkgDir)
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	rel, ok := relUnder(root, resolvedPkgDir)
	if !ok {
		return ProducerFrame{reason: fmt.Sprintf("package directory %s lies outside the tree; no observation bracket can cover it", pkgDir)}
	}
	return ProducerFrame{
		Root:   root,
		PkgDir: resolvedPkgDir,
		PkgRel: filepath.ToSlash(rel),
		reason: "no observation bracket was captured",
		span:   new(outcomeSpan),
	}
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
	rel, ok := relUnder(root, resolvedPkgDir)
	if !ok {
		return ProducerFrame{reason: fmt.Sprintf("package directory %s lies outside the tree; no observation bracket can cover it", pkgDir)}
	}
	roots := append([]string{filepath.ToSlash(rel)}, opts.BracketPaths...)
	bracket, err := CaptureBracket(ctx, root, roots,
		WithBracketExcludedPaths(append([]string{".git"}, opts.ExcludedPaths...)...))
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	return ProducerFrame{Root: root, PkgDir: resolvedPkgDir, PkgRel: filepath.ToSlash(rel), bracket: &bracket, span: new(outcomeSpan)}
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
	// server's per-request operation, never a process: one probe per package directory coordinate
	// and environment across every run that judged run ingests. Nil
	// resolves unmemoized — every run pays its probe.
	Roots *Roots
	// Completion and Outcome are independent premises bound to this process,
	// environment and frame. Neither the receipt nor the capture supplies the
	// other's missing evidence.
	Completion   CompletionReceipt
	Outcome      OutcomeSupport
	TrackedChdir TrackedChdirSupport
	// ScratchRoot declares a per-run scratch root the producer minted
	// for the process. This declares a filesystem-root admission, never an
	// environment projection: Env still carries the value actually delivered
	// to the process. Every other classification root — the toolchain, the
	// module cache, the build cache, the go command's own temp root
	// (GOTMPDIR), and the temp root itself when this is empty — is
	// resolved from the environment, never declared.
	ScratchRoot string
	// ExcludedPaths extends the facade-owned ingest exclusions - the
	// module-root listing "." (the bracket never covers the root's own
	// listing, so its identity moves under unrelated tooling) and the
	// VCS tree ".git" - with the producer's tool-bookkeeping surfaces.
	ExcludedPaths     []string
	ExcludedEnv       []string
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
	normalized, binding, reason := f.completionPremiseNormalized(in)
	if reason == "" && requireOutcomes {
		reason = in.Outcome.Reason(binding)
	}
	if !requireOutcomes {
		in.Outcome = OutcomeSupport{}
	}
	if reason != "" {
		return f.incompleteNormalized(ctx, in, normalized, reason)
	}
	file, br, reason, err := openProducerCapture(ctx, testlogPath)
	if err != nil {
		return Observation{}, "", err
	}
	if reason != "" {
		return f.incompleteNormalized(ctx, in, normalized, reason)
	}
	defer file.Close()

	observation, reason, err := f.captureStream(ctx, br, in, normalized, requireOutcomes)
	if err != nil || reason != "" {
		return observation, reason, err
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	return observation, "", nil
}

func (f ProducerFrame) incomplete(ctx context.Context, in ProducerIngest, reason string) (Observation, string, error) {
	return f.incompleteNormalized(ctx, in, nil, reason)
}

func (f ProducerFrame) incompleteNormalized(ctx context.Context, in ProducerIngest, normalized []string, reason string) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	var observation Observation
	var err error
	if normalized != nil {
		observation, err = incompleteNormalizedContext(ctx, f.Root, in.Identity, reason, normalized)
	} else {
		observation, err = incompleteContext(ctx, f.Root, in.Identity, reason, in.Env)
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	return observation, reason, err
}

// PrepareTrackedChdir binds an analysis-verified tracked-chdir capability to
// this pre-execution frame when the frame carries a valid bracket.
func (f ProducerFrame) PrepareTrackedChdir(safe bool) TrackedChdirSupport {
	if f.bracket == nil {
		return TrackedChdirSupport{}
	}
	return prepareTrackedChdir(f.span, f.Root, f.PkgDir, safe)
}

// Completion records the caller's verified terminal disposition for this frame,
// process and complete environment. Empty reason asserts normal completion and
// a flushed capture; a nonempty reason records abnormal or incomplete execution.
func (f ProducerFrame) Completion(process string, env []string, reason string) (CompletionReceipt, error) {
	binding, err := f.OutcomeBinding(process, env)
	if err != nil {
		return CompletionReceipt{}, err
	}
	return CompletionReceipt{binding: binding, reason: reason}, nil
}

// OutcomeBinding exposes the execution-coordinate binding used by the analysis
// view. Its value is not a support constructor; it supplies execution
// coordinates only.
func (f ProducerFrame) OutcomeBinding(process string, env []string) (OutcomeBinding, error) {
	_, binding, err := f.outcomeBindingNormalized(process, env)
	return binding, err
}

func (f ProducerFrame) outcomeBindingNormalized(process string, env []string) ([]string, OutcomeBinding, error) {
	if err := validateProcess(process); err != nil {
		return nil, OutcomeBinding{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return nil, OutcomeBinding{}, err
	}
	// NormalizeEnv rejects NUL bytes, so this delimiter frames the original
	// bytes injectively, including Linux environment values that are not UTF-8.
	// JSON strings would replace those bytes and equate distinct executions.
	digest := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return normalized, bindOutcome(f.span, process, hex.EncodeToString(digest[:]), f.Root, f.PkgDir), nil
}

// HasOutcomeSupport reports whether a canonical manifest retains support for
// the exact recorded subject identity. Malformed and older records grant none.
func HasOutcomeSupport(encoded, subject string) bool {
	m, err := decode(encoded)
	// Canonical decoding already requires a recognized method whenever the
	// subject set is nonempty; membership is the remaining premise.
	return err == nil && slices.Contains(m.Subjects, subject)
}

// OutcomeSupportSet returns the set of recorded subject identities retained by
// a canonical manifest. Malformed and older records return nil.
func OutcomeSupportSet(encoded string) map[string]bool {
	m, err := decode(encoded)
	if err != nil || len(m.Subjects) == 0 {
		return nil
	}
	out := make(map[string]bool, len(m.Subjects))
	for _, s := range m.Subjects {
		out[s] = true
	}
	return out
}

func (f ProducerFrame) completionPremise(in ProducerIngest) (OutcomeBinding, string) {
	_, binding, reason := f.completionPremiseNormalized(in)
	return binding, reason
}

func (f ProducerFrame) completionPremiseNormalized(in ProducerIngest) ([]string, OutcomeBinding, string) {
	if in.Completion.binding == (OutcomeBinding{}) {
		return nil, OutcomeBinding{}, "process completion receipt unavailable"
	}
	normalized, binding, err := f.outcomeBindingNormalized(in.Identity, in.Env)
	if err != nil {
		return nil, OutcomeBinding{}, fmt.Sprintf("process binding invalid: %v", err)
	}
	if in.Completion.binding != binding {
		return normalized, OutcomeBinding{}, "process completion receipt belongs to a different execution or environment"
	}
	if in.Completion.reason != "" {
		return normalized, OutcomeBinding{}, in.Completion.reason
	}
	return normalized, binding, ""
}

const producerCaptureBufSize = 64 * 1024

func openProducerCapture(ctx context.Context, testlogPath string) (*os.File, *bufio.Reader, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, "", err
	}
	if testlogPath == "" {
		return nil, nil, "testlog capture unavailable: no capture file was attached to the process", nil
	}
	openPath := testlogPath
	if filepath.IsAbs(testlogPath) {
		if resolved, err := filepath.EvalSymlinks(testlogPath); err == nil {
			openPath = resolved
		}
	}
	file, err := os.Open(openPath)
	if err := ctx.Err(); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, nil, "", err
	}
	if os.IsNotExist(err) {
		return nil, nil, "test process produced no runtime-input log", nil
	}
	if err != nil {
		return nil, nil, fmt.Sprintf("testlog capture unreadable: %q", err.Error()), nil
	}
	br := bufio.NewReaderSize(captureReader{ctx: ctx, Reader: file}, producerCaptureBufSize)
	var scratch []byte
	raw, hasNL, eof, readErr := nextTestLogLineBytes(br, &scratch)
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, nil, "", err
	}
	if readErr != nil {
		_ = file.Close()
		return nil, nil, fmt.Sprintf("testlog capture unreadable: %q", readErr.Error()), nil
	}
	if eof || !hasNL || !bytes.Equal(raw, testlogHeaderLine) {
		if drainReason, drainErr := drainAndScreenCapture(ctx, br, false); drainErr != nil {
			_ = file.Close()
			return nil, nil, "", drainErr
		} else if drainReason != "" {
			_ = file.Close()
			return nil, nil, drainReason, nil
		}
		_ = file.Close()
		return nil, nil, "capture file carries no test-log header; the test binary never opened it", nil
	}
	return file, br, "", nil
}

func drainAndScreenCapture(ctx context.Context, br *bufio.Reader, requireEnvOnly bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var scratch []byte
	unsupported := false
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		raw, _, eof, err := nextTestLogLineBytes(br, &scratch)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err != nil {
			return fmt.Sprintf("testlog capture unreadable: %q", err.Error()), nil
		}
		if eof {
			break
		}
		if requireEnvOnly && len(raw) != 0 && !bytes.Equal(raw, testlogHeaderLine) && !bytes.HasPrefix(raw, getenvLinePrefix) {
			unsupported = true
		}
	}
	if unsupported {
		return errUnsupportedOutcomeOp.Error(), nil
	}
	return "", nil
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

// captureStream constructs the identity guard from an opened header-verified
// testlog stream, preserving exact REQ-inputs-producer-facade refusal
// precedence (Steps 4 and 6 outranking Steps 7-9) without whole-file buffering.
func (f ProducerFrame) captureStream(ctx context.Context, br *bufio.Reader, in ProducerIngest, normalized []string, requireOutcomes bool) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	if normalized == nil {
		var err error
		normalized, err = normalizeEnvironment(in.Env)
		if err != nil {
			return Observation{}, "", err
		}
	}
	incomplete := func(reason string) (Observation, string, error) {
		return f.incompleteNormalized(ctx, in, normalized, reason)
	}
	incompleteAfterDrain := func(fallbackReason string) (Observation, string, error) {
		drainReason, drainErr := drainAndScreenCapture(ctx, br, requireOutcomes)
		if drainErr != nil {
			return Observation{}, "", drainErr
		}
		if drainReason != "" {
			return incomplete(drainReason)
		}
		return incomplete(fallbackReason)
	}
	if f.bracket == nil {
		reason := f.reason
		if reason == "" {
			reason = "no observation bracket was captured"
		}
		return incompleteAfterDrain(reason)
	}
	if reason := producerPWDProblem(f.PkgDir, normalized); reason != "" {
		return incompleteAfterDrain(reason)
	}
	fireProducerBeforeRoots()
	roots, err := resolveRoots(ctx, in.Roots, in.Runner, f.Root, f.PkgDir, normalized)
	if err != nil {
		if ctx.Err() != nil {
			// The caller's cancellation, not an environment fault: no
			// durable record names the environment for it.
			return Observation{}, "", ctx.Err()
		}
		return incompleteAfterDrain(fmt.Sprintf("classification roots unresolved under the process environment: %v", err))
	}
	trackedChdir := matchesTrackedChdir(in.TrackedChdir, f.span, f.Root, f.PkgDir)
	opts := []TestLogOption{
		WithCompletedProcess(in.Identity),
		WithBracket(*f.bracket),
		func(cfg *testLogConfig) {
			cfg.outcomeSubjects = in.Outcome.Subjects()
			cfg.trackedChdir = trackedChdir
			cfg.requireEnvOnly = requireOutcomes
		},
	}
	opts = append(opts, producerClassificationOptionsWithEnv(roots, f.Root, in.ScratchRoot, in.ExcludedPaths, in.ExcludedEnv, in.ScratchNamespaces)...)
	observation, err := fromTestLogStream(ctx, br, f.Root, f.PkgDir, normalized, opts...)
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	if err != nil {
		var readErr captureReadError
		if errors.As(err, &readErr) {
			return incomplete(fmt.Sprintf("testlog capture unreadable: %q", readErr.Error()))
		}
		if errors.Is(err, errUnsupportedOutcomeOp) {
			return incomplete(errUnsupportedOutcomeOp.Error())
		}
		return incompleteAfterDrain(fmt.Sprintf("testlog ingestion failed: %v", err))
	}
	return observation, "", nil
}

// producerClassificationOptions is the single assembly of the facade's implicit
// roots and caller declarations. Preflight and ingest read the same policy.
func producerClassificationOptions(roots resolvedRoots, treeRoot, scratchRoot string, excluded []string, namespaces []ScratchNamespace) []TestLogOption {
	return producerClassificationOptionsWithEnv(roots, treeRoot, scratchRoot, excluded, nil, namespaces)
}

func producerClassificationOptionsWithEnv(roots resolvedRoots, treeRoot, scratchRoot string, excluded, excludedEnv []string, namespaces []ScratchNamespace) []TestLogOption {
	opts := []TestLogOption{WithExcludedPaths(append([]string{".", ".git"}, excluded...)...)}
	if len(excludedEnv) > 0 {
		opts = append(opts, WithExcludedEnv(excludedEnv...))
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
	for _, root := range roots.ephemeralRoots(scratchRoot, treeRoot) {
		opts = append(opts, withEphemeralTempRoot(root))
	}
	for _, namespace := range namespaces {
		opts = append(opts, WithScratchNamespace(namespace.Dir, namespace.Pattern))
	}
	return opts
}

func producerPWDProblem(pkgDir string, env []string) string {
	pwd, _ := gotool.LookupEnv(env, "PWD")
	if pwd == "" {
		return "process environment carries no PWD; cwd-anchored reads cannot classify under the frame"
	}
	if pwd != pkgDir {
		if resolved, err := filepath.EvalSymlinks(pwd); err != nil || resolved != pkgDir {
			return fmt.Sprintf("process environment PWD %q does not name the package directory %s the frame was captured for", pwd, pkgDir)
		}
	}
	return ""
}
