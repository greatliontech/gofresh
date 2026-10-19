package runtimeinput

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/gotool"
)

// FileInputKind identifies how the producer treats an explicit file read.
// UnknownFileInput is the zero value and grants no eligibility.
type FileInputKind uint8

const (
	// UnknownFileInput grants no eligibility.
	UnknownFileInput FileInputKind = iota
	// RawFileInput can record the selected file's bytes when actually read.
	RawFileInput
	// ElidedFileInput records no file identity under the producer's policy.
	ElidedFileInput
	// ProjectedFileInput binds a derived value instead of the file's raw bytes.
	ProjectedFileInput
	// UnverifiableFileInput cannot satisfy this explicit-file preflight.
	UnverifiableFileInput
)

// FileEligibility is a classification, not observation or outcome evidence.
// Reason names every non-raw disposition; a raw result still needs a successful
// observed read and the ordinary bracket, closing and revalidation checks.
type FileEligibility struct {
	Kind   FileInputKind
	Reason string
}

// FileInputContext supplies the producing configuration for an eligibility
// query. Env is the actual non-nil complete process environment with a matching
// PWD, not the caller's ambient environment. Roots has the same one-judged-run
// lifetime as ProducerIngest.Roots. ScratchRoot is the producer's minted scratch
// root, and ExcludedPaths extends the facade's own exclusions, as in ProducerIngest.
// A selected file must remain present through capture and finalization: it cannot
// be newly minted scratch, so scratch-namespace declarations cannot exempt it.
type FileInputContext struct {
	Env           []string
	Runner        gotool.Runner
	Roots         *Roots
	ScratchRoot   string
	ExcludedPaths []string
}

// FileInputEligibility checks whether an explicit clean absolute regular-file
// path without symlink components is eligible for raw-byte observation under the
// producer facade's absolute evidence-root and process directories. It uses the
// facade's root resolution and predicates, preserving their exceptions.
// Eligibility does not read or hash the file as an observed input. Resolving roots
// can read configuration or toolchain inputs, including the selected file when
// it has both roles; those reads manufacture no consumer observation. No
// classification is overridden. The caller holds the file, environment and root
// topology stable from this query through capture, execution and finalization,
// and repeats the query when that context changes. Cancellation returns no result.
func FileInputEligibility(ctx context.Context, treeRoot, pkgDir, file string, in FileInputContext) (eligibility FileEligibility, err error) {
	if ctx == nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: nil context")
	}
	defer func() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			eligibility, err = FileEligibility{}, ctxErr
		}
	}()
	if err := ctx.Err(); err != nil {
		return FileEligibility{}, err
	}
	refuse := func(reason string) FileEligibility {
		return FileEligibility{Kind: UnverifiableFileInput, Reason: reason}
	}
	if in.Env == nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: exact-input query needs the producing environment")
	}
	if !filepath.IsAbs(treeRoot) || !filepath.IsAbs(pkgDir) {
		return refuse("exact-input tree and package directories must be absolute"), nil
	}
	in.Env = slices.Clone(in.Env)
	in.ExcludedPaths = slices.Clone(in.ExcludedPaths)
	if !utf8.ValidString(file) || strings.ContainsAny(file, "\x00\r\n") || !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return refuse("exact input needs a clean absolute representable file path"), nil
	}
	root, err := filepath.EvalSymlinks(treeRoot)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: resolve exact-input tree: %w", err)
	}
	pkg, err := filepath.EvalSymlinks(pkgDir)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: resolve exact-input package: %w", err)
	}
	if _, inside := relUnder(root, pkg); !inside {
		return refuse("exact-input package is outside the producing tree"), nil
	}
	env, err := normalizeEnvironment(in.Env)
	if err != nil {
		return FileEligibility{}, err
	}
	if reason := producerPWDProblem(pkg, env); reason != "" {
		return refuse(reason), nil
	}
	roots, err := resolveRoots(ctx, in.Roots, in.Runner, root, pkg, env)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: exact-input classification roots: %w", err)
	}
	cfg, err := applyTestLogOptions(producerClassificationOptions(roots, root, in.ScratchRoot, in.ExcludedPaths, nil))
	if err != nil {
		return FileEligibility{}, err
	}
	// An exclusion outranks every per-path refusal, including volatile and
	// unavailable paths. These lexical decisions precede filesystem probes.
	if cfg.excludesRaw(root, file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer observation exclusion omits the file identity"}, nil
	}
	if volatileOSPath(file) {
		return refuse("volatile OS input: " + file), nil
	}
	if nullSink(file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer null-sink admission"}, nil
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil {
		return refuse("exact input does not resolve: " + err.Error()), nil
	}
	if resolved != file {
		return refuse("exact input traverses a symlink"), nil
	}
	info, err := os.Lstat(file)
	if err != nil {
		return refuse("exact input is unavailable: " + err.Error()), nil
	}
	if !info.Mode().IsRegular() {
		return refuse("exact input is not a regular file"), nil
	}
	if guardCovered(file, resolveGuardRoots(cfg.guardRoots), map[string]bool{}) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer guard-covered admission omits the file identity"}, nil
	}
	id, reason := classifyPath(root, file)
	if reason != "" {
		return refuse(reason), nil
	}
	if machineProjected(id) {
		return FileEligibility{Kind: ProjectedFileInput, Reason: "producer stable-machine projection, not raw file bytes"}, nil
	}
	ephemeral, err := resolveEphemeralRoots(cfg.ephemeralRoots, root)
	if err != nil {
		return FileEligibility{}, err
	}
	if !contains(root, file) && ephemeralRoot(file, ephemeral) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer ephemeral-root admission omits the file identity"}, nil
	}
	// A still-existing regular file cannot satisfy absent-at-ingest scratch
	// admission or a namespace's absent-at-both-endpoints condition.
	return FileEligibility{Kind: RawFileInput}, nil
}
