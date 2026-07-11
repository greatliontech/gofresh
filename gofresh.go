// Package gofresh decides whether a cached result about a Go symbol is still
// trustworthy for the current source tree, or must be recomputed. It fingerprints
// the source a subject depends on and the environment that produced the result
// (closure, guard, runtimeinput), and reports a verdict by comparing a stored
// fingerprint against the current one (spec overview.md). It never runs the symbol
// and never owns the result store: it answers "is this still fresh?" and leaves
// measuring and storing to the caller. Default operations use a shared maximal
// package closure so multi-subject checks avoid per-subject whole-program analysis;
// callers opt into declaration-level RTA only when its additional precision is
// worth the analysis budget.
package gofresh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/buildflags"
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

// Subject names the symbol whose freshness is tracked — a package import path and a
// symbol within it, either a function name or a "Type.Method" method reference.
type Subject struct {
	Package string
	Symbol  string
}

// DeclarationRTA identifies the optional declaration-level RTA refinement. The
// identity is persisted with refined evidence and changes whenever its semantics
// become incompatible.
const DeclarationRTA = "gofresh/declaration-rta@1"

// Refinement is optional narrower closure evidence. Its zero value means the
// recording is maximal-only. A complete value binds its closure hash and
// unverifiability disposition to Strategy (REQ-fresh-fingerprint-data).
type Refinement struct {
	Strategy     string
	Subject      Subject
	Closure      string
	Unverifiable bool
	Reason       string
	Evidence     string
}

// Fingerprint is the recorded evidence a verdict is computed from (data only, no
// wire format — REQ-fresh-fingerprint-data): the subject's maximal source-closure
// hash, optional refinement evidence, guard values, an attributable purity
// assertion, and the caller's runtime-input manifest and digest evidence. The caller
// serializes and stores it alongside its result, and pins any further domain facts of
// its own (REQ-fresh-caller-pins).
type Fingerprint struct {
	MaximalClosure  string
	Refinement      Refinement
	Guards          guard.Guards
	PurityAssertion string // attributable assertion used to override unverifiability; empty means none
	RuntimeInputs   string // encoded manifest; empty only when the caller supplies no observation manifest
	RuntimeDigest   string // digest of the manifest at capture
}

// Status is a verdict's outcome.
type Status string

const (
	Valid        Status = "valid"
	Stale        Status = "stale"
	Unverifiable Status = "unverifiable"
)

// Verdict is the freshness answer for one subject's fingerprint. Reason names the
// first failing guard for Stale, or the unverifiable dependence for Unverifiable.
type Verdict struct {
	Status Status
	Reason string
}

// Engine is immutable analysis configuration. Source, guards, purity directives,
// and derived analysis state live in an explicit View and never cross view
// boundaries (REQ-fresh-coherent-view).
type Engine struct {
	assumePure  func(Subject) bool
	buildFlags  []string
	buildInputs []string
	dir         string
}

// Option configures an Engine.
type Option func(*Engine)

// WithBuildFlags supplies complete go-command flags used by the producing build,
// such as -tags=integration, -race, or -pgo=profile. The flags select every source
// load and are folded into the build-configuration guard, so the closure and guard
// describe the same binary (REQ-guard-buildconfig).
func WithBuildFlags(flags ...string) Option {
	return func(e *Engine) { e.buildFlags = append([]string(nil), flags...) }
}

// WithBuildInputs supplies opaque build evidence that cannot itself configure a Go
// source load, such as a PGO profile's content digest. It is folded into the
// build-configuration guard (REQ-guard-buildconfig). Go-command flags belong in
// WithBuildFlags; presenting one here is refused when New applies the options.
func WithBuildInputs(inputs ...string) Option {
	return func(e *Engine) { e.buildInputs = append([]string(nil), inputs...) }
}

// WithAssumePure supplies the caller's purity predicate: a subject for which it
// returns true has all of its unverifiability suppressed (REQ-purity-input,
// REQ-purity-override). Source directives are discovered inside each View from the
// same selected source as closure analysis (REQ-purity-directive).
func WithAssumePure(pred func(Subject) bool) Option {
	return func(e *Engine) {
		if pred != nil {
			e.assumePure = pred
		}
	}
}

// WithDir roots the engine at dir: every package load and go invocation
// resolves there, so a caller can fingerprint a tree it does not run inside.
// The default is the process working directory captured when New returns.
func WithDir(dir string) Option {
	return func(e *Engine) { e.dir = dir }
}

// New builds an Engine.
func New(opts ...Option) (*Engine, error) {
	e := &Engine{assumePure: func(Subject) bool { return false }}
	for _, o := range opts {
		o(e)
	}
	if e.dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve working directory: %w", err)
		}
		e.dir = cwd
	}
	root, err := canonicalDir(e.dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve engine tree: %w", err)
	}
	e.dir = root
	for _, input := range e.buildInputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use WithBuildFlags", input)
		}
	}
	if err := buildflags.Validate(e.dir, e.buildFlags); err != nil {
		return nil, err
	}
	return e, nil
}

func canonicalDir(dir string) (string, error) {
	raw := dir
	if !filepath.IsAbs(raw) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		raw = cwd + string(os.PathSeparator) + raw
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", err
	}
	originalInfo, err := os.Stat(raw)
	if err != nil {
		return "", err
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if os.SameFile(originalInfo, resolvedInfo) {
		return resolved, nil
	}
	// Preserve kernel path-walk semantics when lexical cleaning across a symlink
	// would identify a different directory (for example, link/..).
	return raw, nil
}

// Capture records the closure hash and guard values for subject, whose code lives
// under moduleDir (the dir `go` resolves the toolchain and build env in). Runtime
// inputs are added by the caller from the run's testlog (runtimeinput.FromTestLog,
// or runtimeinput.Merge for several processes) into the returned Fingerprint's
// RuntimeInputs/RuntimeDigest fields. An observation-free run still attaches the
// non-empty manifest those functions return.
func (e *Engine) Capture(subject Subject, moduleDir string) (Fingerprint, error) {
	view, err := e.NewView([]Subject{subject}, moduleDir)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(subject)
}

// CaptureRefined captures maximal and declaration-RTA evidence under ctx. The
// caller selects refinement explicitly and owns its cancellation or budget.
func (e *Engine) CaptureRefined(ctx context.Context, subject Subject, moduleDir string) (Fingerprint, error) {
	view, err := e.NewView([]Subject{subject}, moduleDir)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.CaptureRefined(ctx, subject)
}

// Check reports the freshness verdict for a recorded fingerprint against the current
// tree, under kind's guard policy. It recomputes the current closure and guards
// (never reconstructing a historical build — REQ-guard-recompute) and, when the
// recording carries a runtime-input manifest, re-hashes it, then decides.
func (e *Engine) Check(recorded Fingerprint, subject Subject, moduleDir string, kind Kind) (Verdict, error) {
	view, err := e.NewView([]Subject{subject}, moduleDir)
	if err != nil {
		return Verdict{}, err
	}
	return view.Check(recorded, subject, kind)
}

// CheckRefined checks maximal evidence first and invokes declaration-RTA under ctx
// only after maximal drift and only when recorded carries compatible refinement
// evidence (REQ-fresh-hierarchical-check).
func (e *Engine) CheckRefined(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string, kind Kind) (Verdict, error) {
	view, err := e.NewView([]Subject{subject}, moduleDir)
	if err != nil {
		return Verdict{}, err
	}
	return view.CheckRefined(ctx, recorded, subject, kind)
}

func (e *Engine) guardInputs() []string {
	inputs := make([]string, 0, len(e.buildFlags)+len(e.buildInputs))
	for _, flag := range e.buildFlags {
		inputs = append(inputs, "flag="+flag)
	}
	for _, input := range e.buildInputs {
		inputs = append(inputs, "input="+input)
	}
	return inputs
}

// decide is the pure verdict function (REQ-fresh-verdict, REQ-fresh-sound): stale on
// the first failing guard; unverifiable when the guards hold but the closure or
// runtime inputs reach an unhashable dependence and no purity override applies;
// valid otherwise. A missing recorded value is a mismatch, never valid
// (REQ-guard-completeness) — except an absent runtime-input manifest, which is the
// caller's assertion that the run observed no runtime inputs
// (REQ-inputs-absent-asserted). commit/dirty are never consulted
// (REQ-fresh-commit-independent).
func decide(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure bool) Verdict {
	// Closure guard: the recorded hash must equal the recomputed current hash.
	if rec.MaximalClosure == "" || rec.MaximalClosure != cl.Hash {
		return Verdict{Stale, "closure"}
	}
	return decideAfterClosure(rec, cl, cur, rt, kind, pure)
}

func decideAfterClosure(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure bool) Verdict {
	if verdict, failed := decideKnownGuards(rec, cur, rt, kind); failed {
		return verdict
	}
	// Guards hold. Absent a purity override, an unhashable observed input or an
	// unverifiable closure dependence makes validity unprovable (REQ-fresh-sound).
	if !pure {
		if rec.RuntimeInputs != "" && rt.Unverifiable {
			return Verdict{Unverifiable, reasonOr(rt.Reason, "runtime inputs")}
		}
		if cl.Unverifiable {
			return Verdict{Unverifiable, reasonOr(cl.Reason, "external dependence")}
		}
	}
	return Verdict{Valid, ""}
}

func decideKnownGuards(rec Fingerprint, cur guard.Guards, rt runtimeinput.State, kind Kind) (Verdict, bool) {
	// A recorded runtime digest without its manifest is a corrupted recording, not
	// an absence assertion: the digest proves the guard applied, and the missing
	// manifest makes it unevaluable — Stale, never valid (REQ-guard-completeness).
	if rec.RuntimeInputs == "" && rec.RuntimeDigest != "" {
		return Verdict{Stale, "runtimeinputs"}, true
	}
	// Runtime-input guard, when the recording carries a manifest.
	if rec.RuntimeInputs != "" {
		if !rt.OK || rec.RuntimeDigest == "" || rec.RuntimeDigest != rt.Digest {
			return Verdict{Stale, "runtimeinputs"}, true
		}
	}
	// Environment guards under the kind policy.
	if mismatch := guard.Compare(rec.Guards, cur, kind); mismatch != "" {
		return Verdict{Stale, mismatch}, true
	}
	return Verdict{}, false
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// coherentDir refuses a guards dir that disagrees with the engine's tree
// root: the closure would come from one tree and the environment guards
// from another — an incoherent fingerprint that could serve or stale on the
// wrong tree's facts. Without WithDir, the source root is the process cwd.
func (e *Engine) coherentDir(moduleDir string) error {
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
