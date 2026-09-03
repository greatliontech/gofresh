// Package closure computes the closure hash (REQ-closure-coverage): a sound fingerprint
// of the source a subject exercises, used to decide whether a stored result is
// still valid for HEAD.
//
// ComputeMaximalBatch is the hashing entry point: the package test binary's
// mutable-local sources are hashed by content, linked cache modules are pinned
// by module version, and stdlib is cut by the toolchain guard.
// ComputeObservabilityBatch is the precise-analysis entry point: whole-program
// SSA reachability proves every subject-reachable external effect representable
// by the observation stream, or refuses (REQ-closure-observability-analysis).
// Soundness (REQ-fresh-sound): the hashed set is always a superset of the
// source able to affect the subject — never false-valid.
package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/listing"
	"github.com/greatliontech/gofresh/closure/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/processenv"
)

// Closure is the result of analyzing one benchmark (spec REQ-fresh-sound): the hash of its
// closure, and whether that closure reaches an unhashable external dependence
// (Class B, REQ-closure-blindspot) which makes validity unprovable — `unverifiable` rather than
// `valid`/`stale`. Unverifiable is a check-time verdict; the hash is always
// computed (and recorded at run time, REQ-guard-recompute) regardless.
type Closure struct {
	Hash string
	// TestVariants is the subject package's test-variant compartment: 32 hex
	// over the package's own test-only files — the in-package and external
	// test-variant file sets minus the base package's file set — under the
	// same name\x00sha256 discipline as the core hash's file folding. The
	// core Hash excludes those files, so a sibling test edit moves only this
	// compartment; a package with no test files carries the stable
	// EmptyTestVariantClosure identity. Unsalted: subjects of one package
	// share the compartment, which describes the package, not the subject
	// (REQ-closure-test-variant-compartment).
	TestVariants string
	Unverifiable bool
	Reason       string // why unverifiable (e.g. "reaches os.Open (file I/O)")
	// External marks a subject the author declared external-state via
	// //gofresh:external: unverifiability by declaration, never suppressible
	// by a purity assertion or observation evidence (REQ-external-precedence).
	External bool
}

// Hasher computes closure hashes. New resolves GOMODCACHE once for the
// cache-vs-mutable classification; loaded whole-program SSA is cached per package
// (the dominant cost, REQ-closure-analysis) so repeated per-benchmark Compute calls amortize it.
// A Hasher is single-goroutine by contract: nothing on the analysis
// path spawns goroutines, and every unsynchronized map it carries -
// progs, progErrs, memo state, and each program's PkgScopeProbe -
// leans on that invariant.
type Hasher struct {
	// dir roots every package load and go invocation; "" = the process
	// working directory. The analyzed tree is an explicit input.
	dir        string
	modCache   string
	ctx        context.Context
	env        []string
	packageEnv []string
	// buildFlags are the producing go command's executable flags. They select
	// every package and dependency load used to construct this closure.
	buildFlags []string
	// selectionResolved marks the two-axis toolchain-audit verdict as
	// computed by the constructor; the zero value refuses, so a Hasher
	// built without construction can never enable a standard-library
	// admission by omission — the audit's fail-closed ladder survives
	// the zero value.
	selectionResolved bool
	// selectionNotice is the two-axis toolchain-audit rendering for this
	// analysis' build selection, computed once at construction — ""
	// exactly when the selection is audited, so verdict and text are
	// one derivation: every audited-set consultation under this Hasher
	// answers through SelectionAudited, and a tag-swapped selection
	// degrades the stdlib admissions to the ordinary fail-closed
	// classification instead of inheriting the default selection's
	// audit (ToolchainSelectionNotice).
	selectionNotice string
	progs           map[string]*program  // by package import path
	progErrs        map[string]error     // memoized load failures, by package import path
	lists           map[string][]listPkg // parsed `go list -deps -test`, by package import path
	// snapshot is the pass's env snapshot when the caller supplied one —
	// the listing memo's scope identity; nil leaves that memo inert.
	snapshot       *gotool.EnvSnapshot
	maximalTesting map[string]maximalEffectScan    // typed testing-runtime effects by requested package
	maximalEffects map[string]maximalEffectsResult // package external-effect scans by requested package
	maximalFiles   map[string]maximalEffectScan    // per-file effect scans by absolute path
	// contribs memoizes per-node closure contributions within ONE
	// top-level batch call: each public batch entry resets it, so content
	// is re-observed per call (the Hasher's pinned contract) while subjects
	// and groups of one call share each dependency node's reads. Every
	// Hasher starts nil (memoization off) until a batch entry arms it.
	contribs map[string]depContribution
	// testBinaryKeys and variantScope memoize per-package test-binary
	// closure keys and compartment identities under the same call scope
	// and arming discipline as contribs: nil until a batch entry arms
	// them, reset per call.
	testBinaryKeys map[string]string
	variantScope   map[string]testvariant.Identity
	testVariants   map[string]testvariant.Identity     // test-variant compartments by requested package
	fileDigests    map[string]string                   // per-file content digests from the closure's own reads, by absolute path
	contents       map[string]fileBytes                // per-file bytes and digest, read once per batch call (readFile); nil outside one
	fileMemo       *fileMemos                          // the per-file effect-scan and compartment-parse memos
	progress       func(phase, pkgPath string)         // start-of-step keep-alive events; nil disables
	diagnostic     func(phase, pkgPath, detail string) // payload-bearing diagnostics; nil disables
	// unit reports a per-unit step with its position in the pass; nil
	// disables. persisted counts what this Hasher wrote to the memo
	// store during the pass — the kept-on-cancel report reads it.
	unit      func(phase, pkgPath string, index, total int)
	persisted struct{ proofs, scans int }
	// served records, per memo class, the packages a persistent-store
	// hit stood in for during the pass — summarized once per operation,
	// never emitted per hit, so a warm pass over a large tree reports
	// one line per class.
	served map[string]map[string]bool
	// scope is the caller's analysis identity outside the source closure,
	// set once per pass; every guard-scoped memo renders its own scope
	// from it, and the zero value leaves them inert
	// (REQ-closure-observability-memo).
	scope AnalysisScope
	// viewLoad, when set, is the observation pass's shared typed load; the
	// testing-type effect scan reads it instead of performing its own load
	// (REQ-fresh-coherent-view: one load per pass, no same-pass mixture).
	viewLoad *ViewLoad
}

// UseViewLoad supplies the observation pass's shared typed load. The caller
// guarantees it was produced in the same pass, under the same tree root,
// environment, and executable build flags as this Hasher, and that its
// patterns cover every package whose closure this Hasher computes; a package
// the load does not cover falls back to a private load with identical
// semantics.
func (h *Hasher) UseViewLoad(load *ViewLoad) {
	h.viewLoad = load
}

// OnDiagnostic supplies a callback for phases carrying a payload the
// progress line cannot: the per-subject analysis-unavailable
// provenance rides it, never a memoized surface. Unlike progress
// events, diagnostics ARE contract for the operator's field log -
// each event is a distinct fact, delivered synchronously.
func (h *Hasher) OnDiagnostic(f func(phase, pkgPath, detail string)) {
	h.diagnostic = f
}

func (h *Hasher) emitDiagnostic(phase, pkgPath, detail string) {
	if h.diagnostic != nil {
		h.diagnostic(phase, pkgPath, detail)
	}
}

// OnProgress supplies a callback invoked synchronously at the start of each
// long-running analysis step: "load" before a package program load, "prove"
// before a package's observability batch. The callback must be fast; events
// are keep-alive facts about work, never verdict evidence.
func (h *Hasher) OnProgress(f func(phase, pkgPath string)) {
	h.progress = f
}

func (h *Hasher) emitProgress(phase, pkgPath string) {
	if h.progress != nil {
		h.progress(phase, pkgPath)
	}
}

// OnUnit supplies a callback for per-unit steps that know their position
// in the pass — a package's listing or closure fold among the pass's
// packages, the view's typed load with its pattern count, a package's
// own testing-scan load when no shared load covers it. Same
// discipline as OnProgress: fast, synchronous, never calling back in.
func (h *Hasher) OnUnit(f func(phase, pkgPath string, index, total int)) {
	h.unit = f
}

// Unit is the exported face of emitUnit for the observation pass's own
// steps outside this package (the view's typed load).
func (h *Hasher) Unit(phase, pkgPath string, index, total int) {
	h.emitUnit(phase, pkgPath, index, total)
}

func (h *Hasher) emitUnit(phase, pkgPath string, index, total int) {
	if h.unit != nil {
		h.unit(phase, pkgPath, index, total)
	}
}

// Served records that a persistent-store memo hit stood in for a step —
// class names the memo (an observability proof, an effect scan, a
// testing scan, dynamic-state facts, a package scan, a dependency
// listing, a file scan, a compartment parse) — for the operation's one summary
// per class (ServedSummary); in-process cache hits are not recorded.
func (h *Hasher) Served(class, pkgPath string) {
	if h.served == nil {
		h.served = map[string]map[string]bool{}
	}
	if h.served[class] == nil {
		h.served[class] = map[string]bool{}
	}
	h.served[class][pkgPath] = true
}

// ServedSummary returns, per memo class, the distinct packages a
// persistent-store hit served during the pass.
func (h *Hasher) ServedSummary() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(h.served))
	for class, pkgs := range h.served {
		out[class] = make(map[string]bool, len(pkgs))
		for p := range pkgs {
			out[class][p] = true
		}
	}
	return out
}

// Persisted reports what this Hasher wrote to the memo store during the
// pass — observability proof slices and per-package scans — the facts
// a kept-on-cancel report names, since a rerun serves every one of
// them (REQ-closure-observability-memo's slice persistence).
func (h *Hasher) Persisted() (proofs, scans int) {
	return h.persisted.proofs, h.persisted.scans
}

func New() (*Hasher, error) { return NewAt("") }

// NewAt builds a Hasher rooted at dir ("" = the process working directory) and
// the producing build's executable flags: every package load and go invocation
// resolves under both, so the analyzed tree and build selection are explicit
// inputs, never implicit cwd or default-build coupling (REQ-closure-analysis).
func NewAt(dir string, buildFlags ...string) (*Hasher, error) {
	return NewAtContext(context.Background(), dir, buildFlags...)
}

// NewAtContext is NewAt with caller-owned cancellation for closure analysis.
func NewAtContext(ctx context.Context, dir string, buildFlags ...string) (*Hasher, error) {
	return NewAtContextEnv(ctx, dir, os.Environ(), buildFlags...)
}

// NewAtContextEnv builds a Hasher using env as the complete immutable process
// environment for package loading, Go commands, and source selection.
func NewAtContextEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Hasher, error) {
	return NewAtContextEnvSnapshot(ctx, dir, env, nil, buildFlags...)
}

// NewAtContextEnvBracket is NewAtContextEnvSnapshot for a precise-analysis
// bracket that persists memo entries: GOMODCACHE resolves from the
// construction snapshot, but GOFLAGS is validated LIVE — a bracket's loads
// read the go env file at spawn, so an overlay written after view
// construction must refuse here, before any load can derive memo values
// under a key whose GOFLAGS digest predates it
// (REQ-closure-observability-memo's byte-equivalence).
func NewAtContextEnvBracket(ctx context.Context, dir string, env []string, snapshot *gotool.EnvSnapshot, buildFlags ...string) (*Hasher, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	normalized, err := processenv.Normalize(env)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	// The live probe is the pass's own snapshot: GOFLAGS validates from
	// it, and the listing memo scopes by it, so a bracket's entries never
	// persist under an environment the bracket's loads did not run in.
	live, err := gotool.TakeEnvSnapshot(ctx, dir, normalized)
	if err != nil {
		return nil, err
	}
	if err := buildflags.ValidateEnvSnapshot(ctx, dir, normalized, buildFlags, live); err != nil {
		return nil, err
	}
	h, err := NewAtContextEnvSnapshot(ctx, dir, env, snapshot, buildFlags...)
	if err != nil {
		return nil, err
	}
	// The construction snapshot keeps its documented GOMODCACHE contract
	// (classification agrees with the view); the live snapshot scopes
	// the memo, and its identity carries GOMODCACHE, so no entry crosses
	// a moved module cache.
	h.snapshot = live
	return h, nil
}

// NewAtContextEnvSnapshot is NewAtContextEnv resolving GOMODCACHE and
// validating GOFLAGS from the pass's one env snapshot when non-nil.
func NewAtContextEnvSnapshot(ctx context.Context, dir string, env []string, snapshot *gotool.EnvSnapshot, buildFlags ...string) (*Hasher, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	normalized, err := processenv.Normalize(env)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	packageEnv, err := processenv.ForGoPackages(normalized)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	if err := buildflags.ValidateEnvSnapshot(ctx, dir, normalized, buildFlags, snapshot); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	var mc, goflags, goexperiment string
	if snapshot != nil {
		mc, goflags, goexperiment = snapshot.Value("GOMODCACHE"), snapshot.Value("GOFLAGS"), snapshot.Value("GOEXPERIMENT")
	}
	if snapshot == nil {
		// One combined read covers the module cache and the
		// selection-bearing values; a resolution failure refuses
		// construction loudly rather than silently disabling every
		// stdlib admission.
		out, err := gotool.RunInContextEnv(ctx, dir, normalized, "env", "GOMODCACHE", "GOFLAGS", "GOEXPERIMENT")
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(out), "\n")
		if len(lines) < 3 {
			return nil, fmt.Errorf("closure: go env returned %d values, want 3", len(lines))
		}
		mc, goflags, goexperiment = strings.TrimSpace(lines[0]), strings.TrimRight(lines[1], "\r"), strings.TrimRight(lines[2], "\r")
	}
	if mc == "" {
		return nil, errors.New("closure: empty GOMODCACHE")
	}
	return &Hasher{
		dir: dir, modCache: filepath.Clean(mc), ctx: ctx, env: normalized, packageEnv: packageEnv, buildFlags: append([]string(nil), buildFlags...), snapshot: snapshot,
		selectionResolved: true, selectionNotice: ToolchainSelectionNotice(buildFlags, goflags, goexperiment),
		progs: map[string]*program{}, progErrs: map[string]error{}, lists: map[string][]listPkg{}, maximalTesting: map[string]maximalEffectScan{},
		maximalEffects: map[string]maximalEffectsResult{}, maximalFiles: map[string]maximalEffectScan{}, testVariants: map[string]testvariant.Identity{},
		fileDigests: map[string]string{}, fileMemo: newFileMemos(),
	}, nil
}

// FileDigest returns the truncated content digest of one absolute source
// path exactly as this Hasher's own reads — the closure fold's, or the
// listing memo's verification of the same tree — computed it, so a
// consumer naming moved identities never re-reads a file the pass
// already digested.
func (h *Hasher) FileDigest(path string) (string, bool) {
	digest, ok := h.fileDigests[path]
	return digest, ok
}

// BoundAnalysis narrows the context governing this Hasher's subsequent
// analysis work, typically to carry a caller-supplied analysis budget whose
// deadline should bound computation but not the surrounding operation. The
// bound context must descend from the construction context; it is refused
// once any analysis has been memoized, because already-computed results would
// have observed the wider context.
func (h *Hasher) BoundAnalysis(bound context.Context) error {
	if bound == nil {
		return errors.New("closure: nil analysis bound")
	}
	if len(h.progs) != 0 || len(h.progErrs) != 0 || len(h.lists) != 0 || len(h.maximalEffects) != 0 || len(h.testVariants) != 0 {
		return errors.New("closure: analysis already begun; bound the Hasher before its first compute")
	}
	h.ctx = bound
	return nil
}

// The go-list graph vocabulary lives in internal/listing; the aliases keep
// the package-local names every analysis site uses.
type (
	listPkg = listing.Package
	listMod = listing.Module
)

// maximalHash returns the Tier-1 closure hash for the test binary of pkgPath:
// every non-std reachable package hashed whole. This is the maximal sound closure
// (REQ-closure-floor) and the target every blind spot widens to (REQ-closure-blindspot). It needs no SSA, so
// it also serves as the analysis-failure-free floor.
func (h *Hasher) maximalHash(pkgPath string) (string, error) {
	contribs, _, err := h.maximalContributionsAndFiles(pkgPath)
	if err != nil {
		return "", err
	}
	return hashContributions(pkgPath, contribs)
}

func (h *Hasher) maximalContributions(pkgPath string) ([]string, error) {
	contribs, _, err := h.maximalContributionsAndFiles(pkgPath)
	return contribs, err
}

func (h *Hasher) maximalContributionsAndFiles(pkgPath string) ([]string, []string, error) {
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, nil, err
	}
	// The subject package's own test-variant nodes leave the core: their
	// production members ride the base node's contribution, and their
	// test-only members fold into the test-variant compartment instead
	// (REQ-closure-test-variant-compartment). Dependency nodes stay in core
	// whole, test-recompiled variants of dependencies included, so a test
	// import pulling a NEW package still moves the core.
	baseFiles := map[string]bool{}
	compartmentDir := ""
	for _, p := range pkgs {
		if p.ImportPath == pkgPath && p.ForTest == "" {
			for _, f := range p.SourceFiles() {
				baseFiles[f] = true
			}
			compartmentDir = p.Dir
		}
	}
	seen := map[string]bool{}
	seenFile := map[string]bool{}
	seenTestOnly := map[string]bool{}
	var contribs []string
	var sourceFiles []string
	var testOnly []string
	// compiledGo and embeddedData carry go list's file-kind facts into the
	// compartment: only a variant node's GoFiles are Go source the test
	// binary compiles; an embedded member is data whatever its name — a
	// testdata fixture ending in .go included — and must never be parsed
	// as source. The kinds are not a partition: a compiled test file can
	// also be embedded by a sibling (//go:embed helper_test.go), and its
	// bytes then feed unchanged code as data too
	// (REQ-closure-test-variant-compartment).
	compiledGo := map[string]bool{}
	embeddedData := map[string]bool{}
	for _, p := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		if testvariant.OwnVariantOf(p, pkgPath, compartmentDir) {
			if compartmentDir == "" {
				compartmentDir = p.Dir
			}
			for _, f := range p.GoFiles {
				if !baseFiles[f] {
					compiledGo[f] = true
				}
			}
			for _, f := range p.EmbedFiles {
				if !baseFiles[f] {
					embeddedData[f] = true
				}
			}
			for _, f := range p.SourceFiles() {
				if !baseFiles[f] && !seenTestOnly[f] {
					seenTestOnly[f] = true
					testOnly = append(testOnly, f)
				}
			}
			continue
		}
		c, files, err := h.contributionAndFilesFor(pkgPath, p)
		if err != nil {
			return nil, nil, err
		}
		if c != "" && !seen[c] {
			seen[c] = true
			contribs = append(contribs, c)
		}
		for _, file := range files {
			if !seenFile[file] {
				seenFile[file] = true
				sourceFiles = append(sourceFiles, file)
			}
		}
	}
	identity, cached := h.variantScope[pkgPath]
	if !cached {
		var err error
		identity, err = testvariant.ComputeIdentity(compartmentDir, testOnly, compiledGo, embeddedData, h.fileDigests, h, variantParseMemo{h: h, dir: compartmentDir, pkgPath: pkgPath})
		if err != nil {
			return nil, nil, err
		}
		h.flushFileMemos()
		if h.variantScope != nil {
			h.variantScope[pkgPath] = identity
		}
	}
	h.testVariants[pkgPath] = identity
	// The compartment's bytes are part of the view's observed source
	// identities: a producer's provenance and drift naming cover them like
	// any core member (REQ-fresh-view-source-identities).
	for _, f := range identity.Files {
		path := filepath.Join(compartmentDir, f)
		if !seenFile[path] {
			seenFile[path] = true
			sourceFiles = append(sourceFiles, path)
		}
	}
	sort.Strings(contribs)
	sort.Strings(sourceFiles)
	return contribs, sourceFiles, nil
}

// analysisTestHooks is the package's one test-observation surface: each
// field observes a load the tests prove skipped or taken; nil disables.
var analysisTestHooks struct {
	// testingTypeOwnLoad observes the typed testing-effect scan's private
	// fallback load, so tests pin that a shared view load or a memo hit is
	// actually consumed instead.
	testingTypeOwnLoad func(pkgPath string)
	// fileParse observes a per-file effect scan actually parsing, and
	// variantParse a compartment member's ledger derivation, so tests
	// pin that the persistent per-file memos served instead.
	fileParse    func(path string)
	variantParse func(name string)
}

// resetCallScope arms the per-batch-call memos: one call observes one
// tree generation (the Hasher's pinned contract), so each public batch
// entry starts them empty — an edit between calls can never serve a
// prior generation's entry or key a persistent memo under one.
func (h *Hasher) resetCallScope() {
	h.contribs = map[string]depContribution{}
	h.testBinaryKeys = map[string]string{}
	h.variantScope = map[string]testvariant.Identity{}
	// The bytes a call reads are that call's tree generation: the cache
	// is armed here and dropped when the call returns (the batch entries
	// defer it), so no later entry can fold bytes an earlier call saw.
	h.contents = map[string]fileBytes{}
}

// modulePin is the version-pin identity every persistent memo and
// contribution shares: the cache-relative module content dir —
// modpath@version, replace-correct via Module.Dir.
func (h *Hasher) modulePin(mod *listMod) string {
	return filepath.ToSlash(strings.TrimPrefix(filepath.Clean(mod.Dir), h.modCache+string(filepath.Separator)))
}

// pinnedPackage reports the pinned-dependency classification: resolved
// source immutable under the module cache. REQ-closure-mutable-local
// names the package Dir, so classification uses it.
func (h *Hasher) pinnedPackage(p *listPkg) bool {
	return p.Module != nil && !p.Module.Main && h.underCache(p.Dir)
}

func (h *Hasher) contextErr() error {
	if h == nil || h.ctx == nil {
		return nil
	}
	if err := h.ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return nil
}

func hashContributions(pkgPath string, contribs []string) (string, error) {
	if len(contribs) == 0 {
		return "", fmt.Errorf("closure: %s reaches no non-stdlib source", pkgPath)
	}
	sort.Strings(contribs)
	h := sha256.New()
	for i, contribution := range contribs {
		if i > 0 {
			_, _ = h.Write([]byte{'\n'})
		}
		_, _ = h.Write([]byte(contribution))
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// contribution returns this package's contribution to the closure, or "" if it
// is excluded (stdlib, a pseudo-package, or the synthesized test-main).
func (h *Hasher) contribution(p listPkg) (string, error) {
	return h.contributionFor("", p)
}

func (h *Hasher) contributionFor(pkgPath string, p listPkg) (string, error) {
	contribution, _, err := h.contributionAndFilesFor(pkgPath, p)
	return contribution, err
}

// depContribution memoizes one listing node's closure contribution within
// one batch call: the derivation is a pure function of the node (the one
// subject-dependent filter, the generated test main, is applied before the
// memo), so every subject package whose listing shares the node shares one
// derivation and one set of file reads. The files slice is aliased —
// callers treat it as read-only.
type depContribution struct {
	contribution string
	files        []string
}

func (h *Hasher) contributionAndFilesFor(pkgPath string, p listPkg) (string, []string, error) {
	if p.Standard || p.Module == nil || (pkgPath != "" && p.IsGeneratedTestMainFor(pkgPath)) {
		// stdlib cut (REQ-closure-coverage); pseudo-package ("C", whose C source rides in the
		// importing package); or the toolchain-generated test main (boilerplate
		// in a transient dir — deterministic, carries no source information).
		return "", nil, nil
	}
	if c, ok := h.contribs[p.ImportPath]; ok {
		return c.contribution, c.files, nil
	}
	if h.pinnedPackage(&p) {
		// Immutable, version-locked cache dep: pin once by the module's
		// content dir, never read its source. p.Dir and Module.Dir agree
		// on under-cache classification for every reachable config.
		contribution := "cache:" + h.modulePin(p.Module)
		if h.contribs != nil {
			h.contribs[p.ImportPath] = depContribution{contribution: contribution}
		}
		return contribution, nil, nil
	}
	// Mutable-local (main module, local replace, workspace, vendor): hash content
	// so a silent edit moves the hash (REQ-closure-mutable-local).
	files := p.SourceFiles()
	if hasCgoCallbackBlindspot(&p) {
		if root := cgoIncludeRootOutsideDir(&p, h.modCache); root != "" {
			return "", nil, fmt.Errorf("closure: cgo include root outside package dir: %s", root)
		}
		var err error
		files, err = allPackageFiles(p.Dir)
		if err != nil {
			return "", nil, err
		}
		if include, err := cgoEscapingInclude(&p, files); err != nil {
			return "", nil, err
		} else if include != "" {
			return "", nil, fmt.Errorf("closure: cgo include escapes package dir: %s", include)
		}
	}
	if len(p.SFiles) > 0 {
		// Non-toolchain assembly is never analyzed: the package contributes
		// its whole directory, so every .s file and anything it includes
		// from the package tree moves the hash (REQ-closure-blindspot's
		// downgrade arm; the subject is unverifiable regardless via the
		// package's non-standard-assembly effect).
		var err error
		files, err = allPackageFiles(p.Dir)
		if err != nil {
			return "", nil, err
		}
	}
	files = listing.UniqueStrings(files)
	fh, err := h.hashFiles(p.Dir, files)
	if err != nil {
		return "", nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.Join(p.Dir, file))
	}
	contribution := "src:" + p.ImportPath + "=" + fh
	if h.contribs != nil {
		h.contribs[p.ImportPath] = depContribution{contribution: contribution, files: paths}
	}
	return contribution, paths, nil
}

func allPackageFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			if d.Type()&os.ModeSymlink == 0 {
				return nil
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("closure: walk %s: %w", dir, err)
	}
	return files, nil
}

// resolveReal follows symlinks to a path's real target, resolving `..` at the OS
// level so a directory-symlink component cannot be lexically cleaned away. Falls
// back to a lexical clean when the path does not exist.
func resolveReal(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// cgoIncludeRootOutsideDir returns a cgo `-I` search root the caller must fail
// closed on because it can pull in-tree headers the package-dir hash would miss.
// A root is safe only when it is under the package dir (hashed by allPackageFiles)
// or under the module cache (a version-pinned dependency whose C headers ride the
// cache guard, REQ-closure-mutable-local). Any other root — an in-module sibling, a local `replace`/
// `go.work` sibling module, or a directory the analysis cannot prove is a pinned dependency —
// is mutable in-tree source and fails closed. A genuine system `-I` root is
// indistinguishable from a mutable local one, so it fails closed too; system headers
// reached by the C compiler's *default* search (no in-tree `-I`) are still skipped
// via the not-found path in cgoEscapingInclude. The `-I` value is resolved through
// symlink components before the check (a lexical clean would hide a `symlink/..`
// escape). modCache is GOMODCACHE (empty when unknown → fail closed, never skipped).
func cgoIncludeRootOutsideDir(p *listPkg, modCache string) string {
	if p == nil || p.Dir == "" {
		return ""
	}
	pkgDir := resolveReal(p.Dir)
	for _, dir := range cgoIncludeFlagDirs(p) {
		raw := expandCgoIncludeDir(p, dir)
		if !filepath.IsAbs(raw) {
			raw = p.Dir + string(filepath.Separator) + raw
		}
		real := resolveReal(raw)
		if pathWithin(real, pkgDir) {
			continue // under the package dir → hashed by allPackageFiles
		}
		if modCache != "" && pathWithin(real, resolveReal(modCache)) {
			// Module-cache dependency → version-pinned (REQ-closure-mutable-local); its C headers ride the
			// cache guard. We trust the cached tree whole: the module cache is immutable
			// and module zips carry no symlinks, so a header inside it cannot symlink
			// back out to mutable in-tree source.
			continue
		}
		return real
	}
	return ""
}

func cgoIncludeFlagDirs(p *listPkg) []string {
	flags := append([]string{}, p.CgoCPPFLAGS...)
	flags = append(flags, p.CgoCFLAGS...)
	flags = append(flags, p.CgoCXXFLAGS...)
	flags = append(flags, p.CgoFFLAGS...)
	var dirs []string
	for i := 0; i < len(flags); i++ {
		flag := flags[i]
		dir := ""
		switch {
		case flag == "-I" || flag == "-iquote" || flag == "-isystem" || flag == "-idirafter":
			if i+1 >= len(flags) {
				continue
			}
			i++
			dir = flags[i]
		case strings.HasPrefix(flag, "-I") && flag != "-I":
			dir = flag[2:]
		case strings.HasPrefix(flag, "-iquote") && flag != "-iquote":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-iquote"))
		case strings.HasPrefix(flag, "-isystem") && flag != "-isystem":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-isystem"))
		case strings.HasPrefix(flag, "-idirafter") && flag != "-idirafter":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-idirafter"))
		}
		if dir == "" {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

func cgoIncludeSearchDirs(p *listPkg) []string {
	if p == nil || p.Dir == "" {
		return nil
	}
	var dirs []string
	for _, dir := range cgoIncludeFlagDirs(p) {
		dir = cleanCgoIncludeDir(p, expandCgoIncludeDir(p, dir))
		if pathWithin(dir, p.Dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func expandCgoIncludeDir(p *listPkg, dir string) string {
	return strings.ReplaceAll(dir, "${SRCDIR}", p.Dir)
}

func cleanCgoIncludeDir(p *listPkg, dir string) string {
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(p.Dir, dir)
	}
	return filepath.Clean(dir)
}

func cgoEscapingInclude(p *listPkg, files []string) (string, error) {
	if p == nil || p.Dir == "" {
		return "", nil
	}
	includeDirs := cgoIncludeSearchDirs(p)
	for _, rel := range files {
		if !isNativeIncludeSource(rel) {
			continue
		}
		path := filepath.Join(p.Dir, rel)
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		goFile := strings.EqualFold(filepath.Ext(rel), ".go")
		text := string(content)
		if goFile {
			text = stripGoCgoCommentMarkers(text)
			goFile = false
		}
		text = spliceCPreprocessorLines(text)
		if cgoNativeFileHasRawString(rel, text) {
			return "", fmt.Errorf("closure: unsupported cgo raw string in %s", path)
		}
		lines := strings.Split(text, "\n")
		if !goFile {
			lines = stripCBlockComments(lines)
		}
		for _, line := range lines {
			include, quoted, ok := cgoIncludeDirective(line, goFile)
			if !ok {
				continue
			}
			if !quoted {
				// `#include <name>` is an angle-bracket header: resolve it like a
				// quoted include; if it is not found in-tree it is a system/toolchain
				// header (skipped below, REQ-closure-coverage). A bare token that is neither quoted nor
				// angle-bracketed is an opaque macro/computed include whose expansion
				// could reach in-tree source, so fail closed.
				if !strings.HasPrefix(include, "<") || !strings.HasSuffix(include, ">") {
					return "", fmt.Errorf("closure: unresolved cgo include %s", include)
				}
				include = strings.TrimSpace(include[1 : len(include)-1])
				if include == "" {
					return "", fmt.Errorf("closure: empty cgo include directive")
				}
			}
			if include == "_cgo_export.h" {
				continue
			}
			if symlinkDir := symlinkDirInPath(include, filepath.Dir(path)); symlinkDir != "" {
				return symlinkDir, nil
			}
			searchDirs := []string{filepath.Dir(path)}
			if !filepath.IsAbs(include) {
				searchDirs = append(searchDirs, includeDirs...)
			}
			found := false
			for _, dir := range searchDirs {
				if symlinkDir := symlinkDirInPath(include, dir); symlinkDir != "" {
					return symlinkDir, nil
				}
				resolved := include
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(dir, resolved)
				}
				resolved = filepath.Clean(resolved)
				if !pathWithin(resolved, p.Dir) {
					return resolved, nil
				}
				parent := filepath.Dir(resolved)
				if realParent, err := filepath.EvalSymlinks(parent); err == nil && !pathWithin(realParent, p.Dir) {
					return realParent, nil
				}
				if _, err := os.Stat(resolved); err == nil {
					if relResolved, err := filepath.Rel(p.Dir, resolved); err == nil && !isNativeIncludeSource(relResolved) {
						return "", fmt.Errorf("closure: unsupported cgo include source %s", include)
					}
					found = true
					break
				}
			}
			if !found {
				// Not found under the package or its in-package `-I` roots → a
				// system/toolchain header found by the C compiler's default search
				// path (REQ-closure-coverage). Skip; build environment, not hashed. cgoIncludeRootOutsideDir
				// has already refused any in-module `-I` root, so no in-tree source hides here.
				continue
			}
		}
	}
	return "", nil
}

func spliceCPreprocessorLines(text string) string {
	text = strings.ReplaceAll(text, "\\\r\n", "")
	return strings.ReplaceAll(text, "\\\n", "")
}

func stripGoCgoCommentMarkers(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "/*"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "*/"))
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func isNativeIncludeSource(rel string) bool {
	ext := strings.ToLower(filepath.Ext(rel))
	switch ext {
	case ".syso", ".a", ".o", ".obj", ".so", ".dylib", ".dll", ".lib":
		return false
	}
	return true
}

func cgoNativeFileHasRawString(_ string, text string) bool {
	return strings.Contains(text, "R\"")
}

func cgoIncludeDirective(line string, goFile bool) (string, bool, bool) {
	line = strings.TrimSpace(line)
	if goFile {
		line = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "/*"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "*/"))
	}
	line = strings.TrimSpace(stripCLineComments(line))
	if !strings.HasPrefix(line, "#") {
		return "", false, false
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if strings.HasPrefix(line, "include") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "include"))
	} else if strings.HasPrefix(line, "import") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "import"))
	} else {
		return "", false, false
	}
	if !strings.HasPrefix(line, "\"") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", false, false
		}
		return fields[0], false, true
	}
	line = strings.TrimPrefix(line, "\"")
	end := strings.IndexByte(line, '"')
	if end < 0 {
		return "", false, false
	}
	return line[:end], true, true
}

func stripCLineComments(line string) string {
	var b strings.Builder
	inString := false
	escaped := false
	for i := 0; i < len(line); {
		if inString {
			c := line[i]
			b.WriteByte(c)
			i++
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if line[i] == '"' {
			inString = true
			b.WriteByte(line[i])
			i++
			continue
		}
		if i+1 < len(line) && line[i:i+2] == "//" {
			break
		}
		if i+1 < len(line) && line[i:i+2] == "/*" {
			b.WriteByte(' ')
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				break
			}
			i += len("/*") + end + len("*/")
			continue
		}
		b.WriteByte(line[i])
		i++
	}
	return b.String()
}

func stripCBlockComments(lines []string) []string {
	inBlock := false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		var b strings.Builder
		inString := false
		inChar := false
		escaped := false
		for i := 0; i < len(line); {
			if inBlock {
				end := strings.Index(line[i:], "*/")
				if end < 0 {
					break
				}
				i += end + len("*/")
				inBlock = false
				b.WriteByte(' ')
				continue
			}
			c := line[i]
			if inString || inChar {
				b.WriteByte(c)
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if inString && c == '"' {
					inString = false
				}
				if inChar && c == '\'' {
					inChar = false
				}
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				i++
				continue
			}
			if c == '\'' {
				inChar = true
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 < len(line) && line[i:i+2] == "/*" {
				inBlock = true
				b.WriteByte(' ')
				i += len("/*")
				continue
			}
			b.WriteByte(c)
			i++
		}
		out = append(out, b.String())
	}
	return out
}

func symlinkDirInPath(path, base string) string {
	path = filepath.FromSlash(path)
	if !filepath.IsAbs(path) {
		path = filepath.Clean(base) + string(filepath.Separator) + path
	}
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	current := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		current += string(filepath.Separator)
		rest = strings.TrimLeft(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(strings.TrimSuffix(current, string(filepath.Separator)))
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			if targetInfo, err := os.Stat(next); err == nil && targetInfo.IsDir() {
				return next
			}
		}
		current = next
	}
	return ""
}

func pathWithin(path, root string) bool {
	if root == "" {
		return false
	}
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// underCache reports whether dir is inside the module cache (a path segment
// boundary, so "/mod" does not match "/modificator").
func (h *Hasher) underCache(dir string) bool {
	if dir == "" {
		return false
	}
	dir = filepath.Clean(dir)
	return dir == h.modCache || strings.HasPrefix(dir, h.modCache+string(filepath.Separator))
}

func hashFiles(dir string, files []string, digests map[string]string) (string, error) {
	return hashFilesWith(dir, files, digests, readBytes)
}

// hashFiles is the fold over the Hasher's once-per-pass reads: the same
// bytes the effect scan and the compartment ledger consume.
func (h *Hasher) hashFiles(dir string, files []string) (string, error) {
	return hashFilesWith(dir, files, h.fileDigests, h.readFile)
}

func hashFilesWith(dir string, files []string, digests map[string]string, read func(string) (fileBytes, error)) (string, error) {
	sort.Strings(files)
	hasher := sha256.New()
	for _, f := range files {
		path := filepath.Join(dir, f)
		fb, err := read(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		fmt.Fprintf(hasher, "%s\x00%x\n", f, fb.sum)
		if digests != nil {
			// The per-file digest rides to the Hasher's memo so naming
			// consumers reuse the exact bytes this hash was built over
			// instead of re-reading (FileDigest).
			digests[path] = fb.digest()
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))[:32], nil
}

// list runs `go list -json -deps -test` for pkgPath and returns the parsed
// dependency graph. The result is memoized per package path for the life of the
// Hasher: every per-benchmark Compute call in a package (and the maximalHash
// widen path) needs the identical listing, and its inputs are immutable within a
// single process run, so one subprocess+decode is amortized across them (same
// lifetime and rationale as the SSA program cache). Callers treat the slice as
// read-only, so sharing one backing array across them is safe.
func (h *Hasher) list(pkgPath string) ([]listPkg, error) {
	if pkgs, ok := h.lists[pkgPath]; ok {
		return pkgs, nil
	}
	if pkgs, ok := h.loadListing(pkgPath); ok {
		h.Served("listing", pkgPath)
		h.lists[pkgPath] = pkgs
		return pkgs, nil
	}
	h.emitProgress("list", pkgPath)
	args := []string{"list", "-json", "-deps", "-test"}
	args = append(args, h.buildFlags...)
	args = append(args, pkgPath)
	out, err := gotool.RunInContextEnv(h.ctx, h.dir, h.env, args...)
	if err != nil {
		return nil, err
	}
	pkgs, err := listing.Parse(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	h.lists[pkgPath] = pkgs
	h.storeListing(pkgPath, pkgs)
	return pkgs, nil
}
