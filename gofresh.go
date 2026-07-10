// Package gofresh decides whether a cached result about a Go symbol is still
// trustworthy for the current source tree, or must be recomputed. It fingerprints
// the source a subject depends on and the environment that produced the result
// (closure, guard, runtimeinput), and reports a verdict by comparing a stored
// fingerprint against the current one (spec overview.md). It never runs the symbol
// and never owns the result store: it answers "is this still fresh?" and leaves
// measuring and storing to the caller.
package gofresh

import (
	"fmt"
	"os"
	"strings"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
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

// Fingerprint is the recorded evidence a verdict is computed from (data only, no
// wire format — REQ-fresh-fingerprint-data): the subject's source-closure hash, the
// guard values, and, when the run observed them, the runtime-input manifest and its
// digest. The caller serializes and stores it alongside its result, and pins any
// further domain facts of its own (REQ-fresh-caller-pins).
type Fingerprint struct {
	Closure       string
	Guards        guard.Guards
	RuntimeInputs string // encoded manifest; empty when no runtime inputs were observed
	RuntimeDigest string // digest of the manifest at capture
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

// Engine composes the closure hasher, guard capture, and purity policy. The hasher
// caches loaded programs for the process; the guard cache memoizes per module dir.
type Engine struct {
	hasher      *closure.Hasher
	guards      *guard.Cache
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

// WithAssumePure supplies the purity predicate: a subject for which it returns true
// has all of its unverifiability suppressed (REQ-purity-input, REQ-purity-override).
// The predicate is fed by a caller's whole-run assertion and by //gofresh:pure
// directives (ScanPureDirectives); gofresh never infers purity itself.
func WithAssumePure(pred func(Subject) bool) Option {
	return func(e *Engine) {
		if pred != nil {
			e.assumePure = pred
		}
	}
}

// WithDir roots the engine at dir: every package load and go invocation
// resolves there, so a caller can fingerprint a tree it does not run inside.
// The default is the process working directory.
func WithDir(dir string) Option {
	return func(e *Engine) { e.dir = dir }
}

// New builds an Engine.
func New(opts ...Option) (*Engine, error) {
	e := &Engine{guards: guard.NewCache(), assumePure: func(Subject) bool { return false }}
	for _, o := range opts {
		o(e)
	}
	for _, input := range e.buildInputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use WithBuildFlags", input)
		}
	}
	h, err := closure.NewAt(e.dir, e.buildFlags...)
	if err != nil {
		return nil, err
	}
	e.hasher = h
	return e, nil
}

// Prime batch-loads the packages a caller is about to Capture or Check subjects
// from, so one whole-program analysis is shared across them instead of one load per
// package (the dominant cost — REQ-closure-analysis). Optional: an unprimed package
// loads on first use.
func (e *Engine) Prime(pkgPaths []string) {
	e.hasher.Prime(pkgPaths)
}

// Capture records the closure hash and guard values for subject, whose code lives
// under moduleDir (the dir `go` resolves the toolchain and build env in). Runtime
// inputs, when a run observed them, are added by the caller from the run's testlog
// (runtimeinput.FromTestLog) into the returned Fingerprint's RuntimeInputs/
// RuntimeDigest fields.
func (e *Engine) Capture(subject Subject, moduleDir string) (Fingerprint, error) {
	if err := e.coherentDir(moduleDir); err != nil {
		return Fingerprint{}, err
	}
	cl, err := e.hasher.Compute(subject.Package, subject.Symbol)
	if err != nil {
		return Fingerprint{}, err
	}
	g, err := e.guards.Capture(moduleDir, e.guardInputs()...)
	if err != nil {
		return Fingerprint{}, err
	}
	return Fingerprint{Closure: cl.Hash, Guards: g}, nil
}

// Check reports the freshness verdict for a recorded fingerprint against the current
// tree, under kind's guard policy. It recomputes the current closure and guards
// (never reconstructing a historical build — REQ-guard-recompute) and, when the
// recording carries a runtime-input manifest, re-hashes it, then decides.
func (e *Engine) Check(recorded Fingerprint, subject Subject, moduleDir string, kind Kind) (Verdict, error) {
	if err := e.coherentDir(moduleDir); err != nil {
		return Verdict{}, err
	}
	cl, err := e.hasher.Compute(subject.Package, subject.Symbol)
	if err != nil {
		return Verdict{}, err
	}
	g, err := e.guards.Capture(moduleDir, e.guardInputs()...)
	if err != nil {
		return Verdict{}, err
	}
	var rt runtimeinput.State
	if recorded.RuntimeInputs != "" {
		// A manifest that cannot be re-evaluated — malformed, or naming a path
		// identity that cannot be materialized against the current tree — is an
		// unevaluable applicable guard: absence of proof, so Stale, never valid
		// (REQ-guard-completeness). Operational failures (e.g. an unresolvable
		// moduleDir) fold into the same conservative Stale rather than erroring —
		// over-approximation is always safe. decide maps !rt.OK to
		// Stale{runtimeinputs}.
		if rt, err = runtimeinput.Current(recorded.RuntimeInputs, moduleDir); err != nil {
			rt = runtimeinput.State{}
		}
	}
	return decide(recorded, cl, g, rt, kind, e.assumePure(subject)), nil
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
	if rec.Closure == "" || rec.Closure != cl.Hash {
		return Verdict{Stale, "closure"}
	}
	// A recorded runtime digest without its manifest is a corrupted recording, not
	// an absence assertion: the digest proves the guard applied, and the missing
	// manifest makes it unevaluable — Stale, never valid (REQ-guard-completeness).
	if rec.RuntimeInputs == "" && rec.RuntimeDigest != "" {
		return Verdict{Stale, "runtimeinputs"}
	}
	// Runtime-input guard, when the recording carries a manifest.
	if rec.RuntimeInputs != "" {
		if !rt.OK || rec.RuntimeDigest == "" || rec.RuntimeDigest != rt.Digest {
			return Verdict{Stale, "runtimeinputs"}
		}
	}
	// Environment guards under the kind policy.
	if mismatch := guard.Compare(rec.Guards, cur, kind); mismatch != "" {
		return Verdict{Stale, mismatch}
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

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// coherentDir refuses a guards dir that disagrees with the engine's tree
// root: the closure would come from one tree and the environment guards
// from another — an incoherent fingerprint that could serve or stale on the
// wrong tree's facts. An engine without WithDir accepts any moduleDir (the
// closure loads in the process cwd, the caller's arrangement).
func (e *Engine) coherentDir(moduleDir string) error {
	if e.dir == "" {
		return nil
	}
	root, err := os.Stat(e.dir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve engine tree %s: %w", e.dir, err)
	}
	module, err := os.Stat(moduleDir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve guards tree %s: %w", moduleDir, err)
	}
	if os.SameFile(root, module) {
		return nil
	}
	return fmt.Errorf("gofresh: engine rooted at %s asked to capture guards in %s; one tree per fingerprint", e.dir, moduleDir)
}
