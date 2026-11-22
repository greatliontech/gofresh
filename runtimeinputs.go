package gofresh

import (
	"context"
	"errors"
	"os/exec"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
)

// ScratchNamespace declares one directory-anchored filename glob whose
// absence-at-both-endpoints reads are elided as run-local scratch
// (REQ-inputs-scratch-namespace).
type ScratchNamespace = runtimeinput.ScratchNamespace

// ValidateScratchNamespace checks that dir and pattern form a valid
// module-relative scratch namespace declaration.
func ValidateScratchNamespace(dir, pattern string) error {
	return runtimeinput.ValidateScratchNamespace(dir, pattern)
}

// RuntimeState is the current digest and verifiability state of a runtime-input manifest.
type RuntimeState = runtimeinput.State

// RuntimeInputsDescription is the structured breakdown of a canonical runtime-input manifest.
type RuntimeInputsDescription = runtimeinput.Description

// CurrentRuntimeInputs re-hashes a canonical manifest against the current
// filesystem and environment under moduleDir.
func CurrentRuntimeInputs(ctx context.Context, encoded, moduleDir string, env []string) (RuntimeState, error) {
	return runtimeinput.Current(ctx, encoded, moduleDir, env)
}

// MovedRuntimeInputs returns the sorted human-readable names of recorded inputs
// whose current state under moduleDir and env differs from encoded.
func MovedRuntimeInputs(ctx context.Context, encoded, moduleDir string, env []string) ([]string, error) {
	return runtimeinput.MovedInputs(ctx, encoded, moduleDir, env)
}

// DescribeRuntimeInputs decodes encoded and resolves its path identities against moduleDir.
func DescribeRuntimeInputs(encoded, moduleDir string) (RuntimeInputsDescription, error) {
	return runtimeinput.Describe(encoded, moduleDir)
}

// RuntimeInputPaths returns the materialized filesystem paths recorded in encoded.
func RuntimeInputPaths(encoded, moduleDir string) ([]string, error) {
	return runtimeinput.Paths(encoded, moduleDir)
}

// ModuleRelRuntimeInputPaths returns the module-relative slash paths recorded in encoded.
func ModuleRelRuntimeInputPaths(encoded string) ([]string, error) {
	return runtimeinput.ModuleRelPaths(encoded)
}

// FileInputRoots memoizes classification-root snapshots across
// CheckFileInputEligibility calls within one operation (REQ-inputs-file-eligibility).
// Its zero value is ready for use; a nil pointer resolves unmemoized.
type FileInputRoots struct {
	roots runtimeinput.Roots
}

// FileInputOptions configures standalone CheckFileInputEligibility queries.
type FileInputOptions struct {
	Env            []string
	PrepareCommand func(*exec.Cmd)
	Roots          *FileInputRoots
	ScratchRoot    string
	ExcludedPaths  []string
}

func checkFileInputEligibility(ctx context.Context, treeRoot, pkgDir, file string, fc runtimeinput.FileInputContext) (string, error) {
	refreshTraceFromEnv()
	res, err := runtimeinput.FileInputEligibility(ctx, treeRoot, pkgDir, file, fc)
	if err != nil {
		return "", err
	}
	if res.Kind != runtimeinput.RawFileInput {
		return res.Reason, nil
	}
	return "", nil
}

// CheckFileInputEligibility judges whether file is eligible for raw-byte
// observation under absolute treeRoot, absolute pkgDir, clean absolute file,
// and opts (REQ-inputs-file-eligibility). It returns a non-empty reason string
// when file is not raw-byte eligible.
func CheckFileInputEligibility(ctx context.Context, treeRoot, pkgDir, file string, opts FileInputOptions) (string, error) {
	var roots *runtimeinput.Roots
	if opts.Roots != nil {
		roots = &opts.Roots.roots
	}
	return checkFileInputEligibility(ctx, treeRoot, pkgDir, file, runtimeinput.FileInputContext{
		Env:           opts.Env,
		Runner:        gotool.Runner{Prepare: opts.PrepareCommand},
		Roots:         roots,
		ScratchRoot:   opts.ScratchRoot,
		ExcludedPaths: opts.ExcludedPaths,
	})
}

// CheckFileInputEligibility judges whether file is eligible for raw-byte
// observation under the session's evidence root, command preparation hook, and
// operation-scoped roots memo (REQ-inputs-file-eligibility). It returns a
// non-empty reason string when file is not raw-byte eligible.
func (s *Session) CheckFileInputEligibility(ctx context.Context, pkgDir, file string, env []string, scratchRoot string, excludedPaths ...string) (string, error) {
	if s == nil || s.dir == "" {
		return "", errors.New("gofresh: uninitialized session")
	}
	return checkFileInputEligibility(ctx, s.evidenceRootFor(s.dir), pkgDir, file, runtimeinput.FileInputContext{
		Env:           env,
		Runner:        s.runner,
		Roots:         &s.roots,
		ScratchRoot:   scratchRoot,
		ExcludedPaths: excludedPaths,
	})
}
