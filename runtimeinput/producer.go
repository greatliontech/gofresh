package runtimeinput

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/greatliontech/gofresh/internal/processenv"
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
	bracket, err := CaptureBracketContext(ctx, root, roots,
		WithBracketExcludedPaths(append([]string{".git"}, opts.ExcludedPaths...)...))
	if err != nil {
		return ProducerFrame{reason: fmt.Sprintf("observation bracket capture failed: %v", err)}
	}
	return ProducerFrame{Root: root, PkgDir: resolvedPkgDir, PkgRel: filepath.ToSlash(rel), bracket: &bracket}
}

// ClassificationRoots are the guard-covered and ephemeral roots a
// producer's environment pins: toolchain and module-cache reads
// classify guard-covered, the build cache rides toolchain-mediated
// observational equivalence, and the temp root is ephemeral (its own
// identity and absent deeper reads admit; present deeper reads stay
// observed). Empty fields declare nothing.
type ClassificationRoots struct {
	Toolchain     string
	ModuleCache   string
	BuildCache    string
	EphemeralTemp string
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
// process-health verdict, and the declaration vocabulary; the facade
// owns everything else.
type ProducerIngest struct {
	Identity string
	Env      []string
	// IncompleteReason is the caller's process-health verdict: empty
	// exactly when the process provably completed and flushed its log.
	IncompleteReason string
	Roots            ClassificationRoots
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
// caller's incompleteness verdict, an unattached, unreadable or missing
// capture, a headerless capture, a frame with no bracket, an
// environment whose PWD does not name the package directory (all three
// producers spawn in the package directory; a parent-inherited PWD
// would silently misclassify every cwd-anchored read), and an
// ingestion failure. A provably flushed log ingests as the completed
// observation under the assembled option set. The returned reason is
// the process's effective incompleteness, empty exactly when the
// observation completed (REQ-inputs-producer-facade).
func (f ProducerFrame) Observe(ctx context.Context, testlogPath string, in ProducerIngest) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	incomplete := func(reason string) (Observation, string, error) {
		observation, err := IncompleteEnv(f.Root, in.Identity, reason, in.Env)
		return observation, reason, err
	}
	if in.IncompleteReason != "" {
		return incomplete(in.IncompleteReason)
	}
	if testlogPath == "" {
		return incomplete("testlog capture unavailable: no capture file was attached to the process")
	}
	log, err := os.ReadFile(testlogPath)
	if os.IsNotExist(err) {
		return incomplete("test process produced no runtime-input log")
	}
	if err != nil {
		return incomplete(fmt.Sprintf("testlog capture unreadable: %v", err))
	}
	if !bytes.HasPrefix(log, testlogHeader) {
		return incomplete("capture file carries no test-log header; the test binary never opened it")
	}
	if f.bracket == nil {
		reason := f.reason
		if reason == "" {
			reason = "no observation bracket was captured"
		}
		return incomplete(reason)
	}
	// The validated PWD and the PWD the classification later reads come
	// from the same lookup over the same normalized environment - a
	// parallel scan could diverge from processenv's key semantics.
	normalized, err := normalizeEnvironment(in.Env)
	if err != nil {
		return Observation{}, "", err
	}
	pwd, _ := processenv.Lookup(normalized, "PWD")
	if pwd == "" {
		return incomplete("process environment carries no PWD; cwd-anchored reads cannot classify under the frame")
	}
	if pwd != f.PkgDir {
		if resolved, err := filepath.EvalSymlinks(pwd); err != nil || resolved != f.PkgDir {
			return incomplete(fmt.Sprintf("process environment PWD %q does not name the package directory %s the frame was captured for", pwd, f.PkgDir))
		}
	}
	opts := []TestLogOption{
		WithCompletedProcess(in.Identity),
		WithBracket(*f.bracket),
		WithExcludedPaths(append([]string{".", ".git"}, in.ExcludedPaths...)...),
	}
	if in.Roots.Toolchain != "" {
		opts = append(opts, WithToolchainRoot(in.Roots.Toolchain))
	}
	if in.Roots.ModuleCache != "" {
		opts = append(opts, WithModuleCacheRoot(in.Roots.ModuleCache))
	}
	if in.Roots.BuildCache != "" {
		opts = append(opts, WithBuildCacheRoot(in.Roots.BuildCache))
	}
	if in.Roots.EphemeralTemp != "" {
		opts = append(opts, WithEphemeralTempRoot(in.Roots.EphemeralTemp))
	}
	for _, namespace := range in.ScratchNamespaces {
		opts = append(opts, WithScratchNamespace(namespace.Dir, namespace.Pattern))
	}
	observation, err := FromTestLogEnv(log, f.Root, f.PkgDir, in.Env, opts...)
	if err != nil {
		return incomplete(fmt.Sprintf("testlog ingestion failed: %v", err))
	}
	return observation, "", nil
}
