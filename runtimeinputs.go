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

// Bracket is a pre-execution filesystem and machine-projection snapshot
// over declared candidate roots (REQ-inputs-value-binding).
type Bracket = runtimeinput.Bracket

// BracketOption configures CaptureBracket.
type BracketOption = runtimeinput.BracketOption

// WithBracketExcludedPaths excludes relative paths or patterns from bracket capture.
func WithBracketExcludedPaths(patterns ...string) BracketOption {
	return runtimeinput.WithBracketExcludedPaths(patterns...)
}

// CaptureBracket captures a pre-execution observation bracket over roots under moduleDir.
func CaptureBracket(ctx context.Context, moduleDir string, roots []string, opts ...BracketOption) (Bracket, error) {
	return runtimeinput.CaptureBracket(ctx, moduleDir, roots, opts...)
}

// Observation is producer-constructed runtime-input evidence (REQ-inputs-completed-observation).
type Observation = runtimeinput.Observation

// RuntimeState is the current digest and verifiability state of a runtime-input manifest.
type RuntimeState = runtimeinput.State

// RuntimeInputsDescription is the structured breakdown of a canonical runtime-input manifest.
type RuntimeInputsDescription = runtimeinput.Description

// CompletedObservationState returns finalized input-guard state from a sealed
// observation backed by at least one contributing process.
func CompletedObservationState(observation Observation) (RuntimeState, error) {
	return runtimeinput.CompletedState(observation)
}

// IncompleteRuntimeObservation constructs canonical evidence for a process whose
// runtime-input observation did not complete.
func IncompleteRuntimeObservation(moduleDir, process, reason string, env []string) (Observation, error) {
	return runtimeinput.Incomplete(moduleDir, process, reason, env)
}

// AbsoluteObservation revalidates observation under moduleDir and env and
// returns equivalent evidence whose path identities are all absolute.
func AbsoluteObservation(observation Observation, moduleDir string, env []string) (Observation, error) {
	return runtimeinput.Absolute(observation, moduleDir, env)
}

// RelativeObservation revalidates observation under moduleDir and env and
// returns equivalent evidence whose in-module path identities are module-relative.
func RelativeObservation(observation Observation, moduleDir string, env []string) (Observation, error) {
	return runtimeinput.Relative(observation, moduleDir, env)
}

// AdoptObservation re-admits a persisted encoded manifest as a completed
// observation under process and env (REQ-inputs-adoption).
func AdoptObservation(encoded, moduleDir, process string, env []string) (Observation, error) {
	return runtimeinput.Adopt(encoded, moduleDir, process, env)
}

// MergeObservations revalidates independently completed runtime-input
// observations against moduleDir under env and returns their deterministic union.
func MergeObservations(moduleDir string, env []string, observations ...Observation) (Observation, error) {
	return runtimeinput.Merge(moduleDir, env, observations...)
}

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

// TestLogOption configures FromTestLog.
type TestLogOption = runtimeinput.TestLogOption

// WithCompletedProcess names the completed producing process for FromTestLog.
func WithCompletedProcess(process string) TestLogOption {
	return runtimeinput.WithCompletedProcess(process)
}

// WithBracket binds a pre-execution observation bracket to FromTestLog.
func WithBracket(bracket Bracket) TestLogOption {
	return runtimeinput.WithBracket(bracket)
}

// WithExcludedPaths excludes relative paths or patterns from FromTestLog ingestion.
func WithExcludedPaths(patterns ...string) TestLogOption {
	return runtimeinput.WithExcludedPaths(patterns...)
}

// WithScratchNamespace declares a scratch namespace for FromTestLog ingestion.
func WithScratchNamespace(dir, pattern string) TestLogOption {
	return runtimeinput.WithScratchNamespace(dir, pattern)
}

// FromTestLog ingests raw Go testlog bytes into a sealed runtime-input observation.
func FromTestLog(data []byte, moduleDir, workingDir string, env []string, opts ...TestLogOption) (Observation, error) {
	return runtimeinput.FromTestLog(data, moduleDir, workingDir, env, opts...)
}

// InputRoots memoizes classification-root snapshots across one judged run
// (REQ-inputs-observation-coherence, REQ-inputs-producer-facade).
// The zero value is ready for use; a nil pointer resolves unmemoized.
type InputRoots = runtimeinput.Roots

// FrameOptions configures CaptureProducerFrame.
type FrameOptions = runtimeinput.FrameOptions

// ProducerFrame is the pre-execution half of the producer facade
// (REQ-inputs-producer-facade).
type ProducerFrame struct {
	Root   string
	PkgDir string
	PkgRel string
	frame  runtimeinput.ProducerFrame
}

// CaptureProducerFrame captures the pre-execution observation frame for pkgDir
// under treeRoot (REQ-inputs-producer-facade).
func CaptureProducerFrame(ctx context.Context, treeRoot, pkgDir string, opts FrameOptions) ProducerFrame {
	f := runtimeinput.CaptureProducerFrame(ctx, treeRoot, pkgDir, opts)
	return ProducerFrame{
		Root:   f.Root,
		PkgDir: f.PkgDir,
		PkgRel: f.PkgRel,
		frame:  f,
	}
}

// Reason returns the frame capture refusal reason, or "" when the frame is usable.
func (f ProducerFrame) Reason() string {
	return f.frame.Reason()
}

// ProducerIngest carries the post-execution parameters for ProducerFrame.ObserveInputs
// and CheckFileInputEligibility (REQ-inputs-identity-facade, REQ-inputs-file-eligibility).
type ProducerIngest struct {
	Identity          string
	Env               []string
	PrepareCommand    func(*exec.Cmd)
	Roots             *InputRoots
	IncompleteReason  string
	ScratchRoot       string
	ExcludedPaths     []string
	ScratchNamespaces []ScratchNamespace
}

// ObserveInputs finalizes identity-only input guards for a completed process
// under the frame without claiming operation-outcome support (REQ-inputs-identity-facade).
func (f ProducerFrame) ObserveInputs(ctx context.Context, testlogPath string, in ProducerIngest) (Observation, string, error) {
	receipt, err := f.frame.Completion(in.Identity, in.Env, in.IncompleteReason)
	if err != nil {
		return Observation{}, "", err
	}
	return f.frame.ObserveInputs(ctx, testlogPath, runtimeinput.ProducerIngest{
		Identity:          in.Identity,
		Env:               in.Env,
		Runner:            gotool.Runner{Prepare: in.PrepareCommand},
		Roots:             in.Roots,
		Completion:        receipt,
		ScratchRoot:       in.ScratchRoot,
		ExcludedPaths:     in.ExcludedPaths,
		ScratchNamespaces: in.ScratchNamespaces,
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
	return CheckFileInputEligibility(ctx, s.evidenceRootFor(s.dir), pkgDir, file, ProducerIngest{
		Env:            env,
		PrepareCommand: s.runner.Prepare,
		Roots:          &s.roots,
		ScratchRoot:    scratchRoot,
		ExcludedPaths:  excludedPaths,
	})
}

// CheckFileInputEligibility judges whether file is eligible for raw-byte
// observation under treeRoot, pkgDir, and in's environment, roots memo,
// command preparation hook, scratch root, and exclusions
// (REQ-inputs-file-eligibility). It returns a non-empty reason string when
// file is not raw-byte eligible.
func CheckFileInputEligibility(ctx context.Context, treeRoot, pkgDir, file string, in ProducerIngest) (string, error) {
	res, err := runtimeinput.FileInputEligibility(ctx, treeRoot, pkgDir, file, runtimeinput.FileInputContext{
		Env:           in.Env,
		Runner:        gotool.Runner{Prepare: in.PrepareCommand},
		Roots:         in.Roots,
		ScratchRoot:   in.ScratchRoot,
		ExcludedPaths: in.ExcludedPaths,
	})
	if err != nil {
		return "", err
	}
	if res.Kind != runtimeinput.RawFileInput {
		return res.Reason, nil
	}
	return "", nil
}
