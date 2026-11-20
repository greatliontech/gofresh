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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
	prog "github.com/greatliontech/gofresh/internal/closure/internal/program"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
)

// program aliases the internal loader's type so every analysis site keeps
// its package-local name.
type program = prog.Program

// AnalyzingFrontend is the version of the Go frontend this process
// analyzes with — runtime.Version() of the analyzing binary, never the
// analyzed selection's toolchain (a guard). Every persistent memo keys
// on it as a cache-miss defense: a miss costs one recomputation, and a
// type-level derivation (proofs, facts, scans) is the analyzing
// frontend's own work. The closure identity does not compose it, by
// design: the canonical member form is a go/scanner token stream and
// the ledger's declarations a go/parser walk over valid Go sources,
// whose tokenization and parse Go's compatibility promise fixes in the
// forward direction (a newer frontend reads older language; new syntax
// appears only in sources that changed), so composing the frontend
// into IdentityStrategy would move every fleet record on each upgrade
// of a consumer's build toolchain for hashes that did not move; the
// reverse direction — a source newer than the frontend — is refused at
// the provenance boundary by the toolchain-skew check, which reads this
// same spelling (REQ-closure-identity-strategy, REQ-fresh-toolchain-skew).
func AnalyzingFrontend() string { return runtime.Version() }

// Closure is the result of analyzing one benchmark (spec REQ-fresh-sound): the hash of its
// closure, and whether that closure reaches an unhashable external dependence
// (Class B, REQ-closure-blindspot) which makes validity unprovable — `unverifiable` rather than
// `valid`/`stale`. Unverifiable is a check-time verdict; the hash is always
// computed (and recorded at run time, REQ-guard-recompute) regardless.
type Closure struct {
	Hash string
	// ToolchainContent and AdmissionPolicy are the construction's independent
	// source and admission dependencies; neither is the reported version.
	ToolchainContent string
	AdmissionPolicy  string
	// TestVariants is the subject package's test-variant compartment: 32 hex
	// over the package's own test-only files — the in-package and external
	// test-variant file sets minus the base package's file set — under the
	// same name\x00sha256 discipline as the core hash's file folding. The
	// core Hash excludes those files, so a sibling test edit moves only this
	// compartment; a package with no test files carries the stable
	// testvariant.EmptyTestVariantClosure identity. Unsalted: subjects of
	// one package share the compartment, which describes the package, not
	// the subject (REQ-closure-test-variant-hash).
	TestVariants string
	Unverifiable bool
	Reason       string // why unverifiable (e.g. "reaches os.Open (file I/O)")
	// Refusal identifies a consumer-tier downgrade at its deciding arm. The
	// zero value leaves the closure's ordinary dependence classification intact.
	Refusal RefusalKind
	// Culprit identifies the deciding package-level variable when Refusal is
	// SharedDynamicStateRefusal.
	Culprit Subject
	// External marks a subject the author declared external-state via
	// //gofresh:external: unverifiability by declaration, never suppressible
	// by a purity assertion or observation evidence (REQ-external-precedence).
	External bool
}

// RefusalKind distinguishes consumer-tier closure refusals whose authority does
// not follow from their human-readable Reason. It is not a persisted proof.
type RefusalKind uint8

const (
	DependenceRefusal RefusalKind = iota
	OpenWorldRefusal
	SharedDynamicStateRefusal
	AmbiguousSubjectRefusal
)

// Hasher computes closure hashes. New resolves GOMODCACHE once for the
// cache-vs-mutable classification; loaded whole-program SSA is cached per package
// (the dominant cost, REQ-closure-analysis) so repeated per-benchmark Compute calls amortize it.
// A Hasher is single-goroutine by contract: every unsynchronized map and
// callback it carries — progs, progErrs, memo state, and each program's
// PkgScopeProbe — is read and mutated exclusively on the caller's goroutine
// (bounded I/O helpers such as directory-stamp checks touch no Hasher state
// from worker goroutines).
type Hasher struct {
	// dir roots every package load and go invocation; "" = the process
	// working directory. The analyzed tree is an explicit input.
	dir        string
	modCache   string
	ctx        context.Context
	env        []string
	packageEnv []string
	// runner spawns every go command of the analysis: the engine's
	// installed runner, so a consumer's boundary reaches the listing.
	runner gotool.Runner
	// buildFlags are the producing go command's executable flags. They select
	// every package and dependency load used to construct this closure.
	buildFlags []string
	// buildVCS is the effective -buildvcs mode ("auto", "true", "false", or
	// "invalid") resolved from GOFLAGS and buildFlags at construction; empty
	// on raw unconstructed Hasher values so VCS-free gates fail closed.
	buildVCS string
	// hasFoldedModMetadata records per requested package whether at least one
	// mutable-local go.mod was folded into the package's runtime/debug metadata.
	hasFoldedModMetadata map[string]bool
	// selectionResolved marks the two-axis toolchain-audit verdict as
	// computed by the constructor; the zero value refuses, so a Hasher
	// built without construction can never enable a standard-library
	// admission by omission — the audit's fail-closed ladder survives
	// the zero value.
	selectionResolved bool
	// selection is the two-axis toolchain-audit verdict this Hasher was
	// built under, stored once: the audited bool, the diagnostic
	// notice, and every refusal's attribution are its readings
	// (REQ-closure-refusal-channels).
	selection selectionDegradation
	// source holds the selected standard-library digests, inventory, and
	// verified pure-delegate set the verdict was judged over.
	source   sourceDigests
	progs    map[string]*program  // by package import path
	progErrs map[string]error     // memoized load failures, by package import path
	lists    map[string][]listPkg // parsed `go list -deps -test`, by package import path
	// snapshot is the pass's env snapshot when the caller supplied one —
	// the listing memo's scope identity; nil leaves that memo inert.
	snapshot                 *gotool.EnvSnapshot
	maximalTesting           map[string]maximalEffectScan            // typed testing-runtime effects by requested package
	maximalTestingUnfiltered map[string]maximalEffectScan            // per-call unfiltered typed testing-runtime effects by requested package
	maximalEffects           map[string]maximalEffectsResult         // package external-effect scans by requested package
	maximalFiles             map[string]maximalEffectScan            // per-file effect scans by absolute path
	maximalParsedFiles       map[string]*parsedMaximalFile           // per-call parsed ASTs and import tables for maximal scans
	harnessVerdict           map[string]*propharness.VerifiedPackage // mechanical property-harness verification verdicts by package dir
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
	variantScope   map[string]compartment.Identity
	testVariants   map[string]compartment.Identity     // test-variant compartments by requested package
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
	viewLoad     *ViewLoad
	packageMates map[string][]Subject
	// listOnMiss, loadProgramOnMiss, and testingPackagesOnMiss allow the
	// in-memory test harness to satisfy this Hasher's listing, SSA program, or
	// testing-type scan load on demand without spawning `go list` or
	// `packages.Load` subprocesses.
	listOnMiss            func(h *Hasher, pkgPath string) ([]listPkg, bool)
	loadProgramOnMiss     func(ctx context.Context, h *Hasher, pkgPath string) (*program, bool, error)
	testingPackagesOnMiss func(h *Hasher, pkgPath string) *program
}

// NewBracketAt is NewAt for a precise-analysis
// bracket that persists memo entries: GOMODCACHE resolves from the
// construction snapshot, but GOFLAGS is validated LIVE — a bracket's loads
// read the go env file at spawn, so an overlay written after view
// construction must refuse here, before any load can derive memo values
// under a key whose GOFLAGS digest predates it
// (REQ-closure-observability-memo's byte-equivalence).
func NewBracketAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Hasher, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if reader == nil {
		return nil, errors.New("closure: nil environment reader")
	}
	// The live probe is the bracket's own pass: a fresh reader over the
	// construction reader's runner, directory, and environment — GOFLAGS
	// validates from it, and the listing memo scopes by it, so a
	// bracket's entries never persist under an environment the bracket's
	// loads did not run in.
	livePass := gotool.NewEnvReader(reader.Runner, reader.Dir, reader.Env)
	h, err := NewAt(ctx, livePass, buildFlags...)
	if err != nil {
		return nil, err
	}
	base, err := reader.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	// The construction snapshot keeps its documented GOMODCACHE contract
	// (classification agrees with the view); the live snapshot scopes
	// the memo, and its identity carries GOMODCACHE, so no entry crosses
	// a moved module cache.
	h.modCache = filepath.Clean(base.Value("GOMODCACHE"))
	return h, nil
}

// NewAt builds a Hasher analyzing the tree at the reader's directory
// ("" = the current directory) under its environment as the complete
// immutable process environment for package loading, Go commands, and
// source selection, every go command through its runner, and under
// buildFlags as the producing build's executable flags: every package
// load and go invocation resolves under both, so the analyzed tree and
// build selection are explicit inputs, never implicit cwd or
// default-build coupling (REQ-closure-analysis). GOMODCACHE, GOFLAGS,
// and GOEXPERIMENT resolve from the reader's one snapshot — the pass's,
// never a probe of the constructor's own.
func NewAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Hasher, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if reader == nil {
		return nil, errors.New("closure: nil environment reader")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	packageEnv, err := gotool.EnvForPackages(normalized)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	if err := buildflags.Validate(ctx, reader, buildFlags); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	// One snapshot covers the module cache and the selection-bearing
	// values; a resolution failure refuses construction loudly rather
	// than silently disabling every stdlib admission.
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	mc := snapshot.Value("GOMODCACHE")
	if mc == "" {
		return nil, errors.New("closure: empty GOMODCACHE")
	}
	buildVCS, bvcsErr := buildflags.EffectiveBuildVCS(snapshot.Value("GOFLAGS"), buildFlags)
	if bvcsErr != nil {
		buildVCS = "invalid"
	}
	// The toolchain-source verdict is resolved at construction: the
	// audited surface's digests under the pass's effective selection
	// (memoized per selection scope), judged against the listing.
	selection, source, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	dir := reader.Dir
	return &Hasher{
		dir: dir, modCache: filepath.Clean(mc), ctx: ctx, env: normalized, packageEnv: packageEnv, runner: reader.Runner,
		buildFlags: append([]string(nil), buildFlags...), buildVCS: buildVCS, hasFoldedModMetadata: map[string]bool{}, snapshot: snapshot,
		selectionResolved: true, selection: selection, source: source,
		progs: map[string]*program{}, progErrs: map[string]error{}, lists: map[string][]listPkg{}, maximalTesting: map[string]maximalEffectScan{},
		maximalEffects: map[string]maximalEffectsResult{}, maximalFiles: map[string]maximalEffectScan{}, testVariants: map[string]compartment.Identity{},
		fileDigests: map[string]string{}, fileMemo: newFileMemos(),
	}, nil
}

// resetCallScope arms the per-batch-call memos: one call observes one
// tree generation (the Hasher's pinned contract), so each public batch
// entry starts them empty — an edit between calls can never serve a
// prior generation's entry or key a persistent memo under one.
func (h *Hasher) resetCallScope() {
	h.contribs = map[string]depContribution{}
	h.testBinaryKeys = map[string]string{}
	h.variantScope = map[string]compartment.Identity{}
	h.hasFoldedModMetadata = map[string]bool{}
	// The bytes a call reads are that call's tree generation: the cache
	// is armed here and dropped when the call returns (the batch entries
	// defer it), so no later entry can fold bytes an earlier call saw.
	h.contents = map[string]fileBytes{}
	h.maximalParsedFiles = map[string]*parsedMaximalFile{}
	h.maximalTestingUnfiltered = map[string]maximalEffectScan{}
	// Clear per-program summaries on any retained SSA programs so subsequent
	// batch calls re-verify non-Go .s/.h members against this call's contents.
	for _, p := range h.progs {
		if p != nil {
			p.Summaries = nil
		}
	}
	for dir := range h.harnessVerdict {
		if dir == "" || strings.HasPrefix(dir, "\x00") || !h.underCache(dir) {
			delete(h.harnessVerdict, dir)
		}
	}
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
	// (REQ-closure-test-variant-hash). Dependency nodes stay in core
	// whole, test-recompiled variants of dependencies included, so a test
	// import pulling a NEW package still moves the core.
	baseFiles := map[string]bool{}
	var baseGo []string
	importNames := map[string]string{}
	compartmentDir := ""
	for _, p := range pkgs {
		// Source imports name the undecorated path even when go list exposes
		// only a test or PGO build copy of that dependency. A synthetic test
		// package can collide with a real source path; disagreement leaves
		// the binding unresolved rather than selecting by listing order.
		path := p.SourcePath()
		if previous, exists := importNames[path]; exists && previous != p.Name {
			importNames[path] = ""
		} else {
			importNames[path] = p.Name
		}
		if p.ImportPath == pkgPath && p.ForTest == "" {
			baseGo = append(baseGo, p.GoFiles...)
			baseGo = append(baseGo, p.CgoFiles...)
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
	// (REQ-closure-test-variant-ledger).
	compiledGo := map[string]bool{}
	embeddedData := map[string]bool{}
	for _, p := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		if compartment.OwnVariantOf(p, pkgPath, compartmentDir) {
			if compartmentDir == "" {
				compartmentDir = p.Dir
			}
			// Membership is the test-only file list — the listing's
			// source files minus the base — and a kind is recorded for a
			// member only, so a kind for a non-member is unrepresentable.
			compiled, embedded, _ := memberKinds(p)
			for _, f := range p.SourceFiles() {
				if baseFiles[f] {
					continue
				}
				if !seenTestOnly[f] {
					seenTestOnly[f] = true
					testOnly = append(testOnly, f)
				}
				if compiled[f] {
					compiledGo[f] = true
				}
				if embedded[f] {
					embeddedData[f] = true
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
	extraContribs, extraFiles, hasFoldedMod, err := h.collectRuntimeDebugModMetadata(pkgPath, pkgs)
	if err != nil {
		return nil, nil, err
	}
	if h.hasFoldedModMetadata == nil {
		h.hasFoldedModMetadata = map[string]bool{}
	}
	h.hasFoldedModMetadata[pkgPath] = hasFoldedMod
	for _, c := range extraContribs {
		if !seen[c] {
			seen[c] = true
			contribs = append(contribs, c)
		}
	}
	for _, file := range extraFiles {
		if !seenFile[file] {
			seenFile[file] = true
			sourceFiles = append(sourceFiles, file)
		}
	}
	identity, cached := h.variantScope[pkgPath]
	if !cached {
		var err error
		identity, err = compartment.ComputeIdentity(compartmentDir, testOnly, compiledGo, embeddedData, h.fileDigests, h, variantParseMemo{h: h, dir: compartmentDir, pkgPath: pkgPath})
		if err != nil {
			return nil, nil, err
		}
		if err := compartment.AddBaseBindings(&identity, baseGo, importNames, h, variantParseMemo{h: h, dir: compartmentDir, pkgPath: pkgPath}); err != nil {
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

func (h *Hasher) readOptionalCompanionFile(path string) (digest string, exists bool, err error) {
	fb, err := h.readFile(path)
	if err == nil {
		if h.fileDigests != nil {
			h.fileDigests[path] = fb.digest()
		}
		return fb.digest(), true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, lstatErr := os.Lstat(path); errors.Is(lstatErr, os.ErrNotExist) {
			return "none", false, nil
		}
	}
	return "", false, fmt.Errorf("closure: read %s: %w", path, err)
}

func (h *Hasher) collectRuntimeDebugModMetadata(pkgPath string, pkgs []listPkg) (extraContribs, extraFiles []string, hasFolded bool, err error) {
	reachesRuntimeDebug := false
	for _, p := range pkgs {
		if p.SourcePath() == "runtime/debug" && (p.Standard || p.Module == nil) {
			reachesRuntimeDebug = true
			break
		}
	}
	if !reachesRuntimeDebug {
		return nil, nil, false, nil
	}
	type modKey struct {
		path  string
		goMod string
	}
	seenMods := map[modKey]bool{}
	for _, p := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, nil, false, err
		}
		if p.Standard || p.Module == nil || (pkgPath != "" && p.IsGeneratedTestMainFor(pkgPath)) || h.pinnedPackage(&p) {
			continue
		}
		mod := p.Module
		if mod.Path == "" || mod.GoMod == "" || mod.GoMod == os.DevNull {
			continue
		}
		goModPath := filepath.Clean(mod.GoMod)
		key := modKey{path: mod.Path, goMod: goModPath}
		if seenMods[key] {
			continue
		}
		seenMods[key] = true
		fb, err := h.readFile(goModPath)
		if err != nil {
			return nil, nil, false, fmt.Errorf("closure: read %s: %w", goModPath, err)
		}
		if h.fileDigests != nil {
			h.fileDigests[goModPath] = fb.digest()
		}
		extraContribs = append(extraContribs, "mod:"+mod.Path+"="+fb.digest())
		extraFiles = append(extraFiles, goModPath)
		hasFolded = true

		goSumPath := strings.TrimSuffix(goModPath, ".mod") + ".sum"
		sumDigest, sumExists, err := h.readOptionalCompanionFile(goSumPath)
		if err != nil {
			return nil, nil, false, err
		}
		extraContribs = append(extraContribs, "modsum:"+mod.Path+"="+sumDigest)
		if sumExists {
			extraFiles = append(extraFiles, goSumPath)
		}

		vendorManifest := filepath.Join(filepath.Dir(goModPath), "vendor", "modules.txt")
		vendorDigest, vendorExists, err := h.readOptionalCompanionFile(vendorManifest)
		if err != nil {
			return nil, nil, false, err
		}
		extraContribs = append(extraContribs, "modvendor:"+mod.Path+"="+vendorDigest)
		if vendorExists {
			extraFiles = append(extraFiles, vendorManifest)
		}
	}
	gowork := ""
	if h.snapshot != nil {
		gowork = strings.TrimSpace(h.snapshot.Value("GOWORK"))
	} else if gw, ok := gotool.LookupEnv(h.env, "GOWORK"); ok {
		gowork = strings.TrimSpace(gw)
	}
	if gowork != "" && gowork != "off" && gowork != os.DevNull {
		if !filepath.IsAbs(gowork) && h.dir != "" {
			gowork = filepath.Join(h.dir, gowork)
		}
		gowork = filepath.Clean(gowork)
		wkFB, err := h.readFile(gowork)
		if err != nil {
			return nil, nil, false, fmt.Errorf("closure: read %s: %w", gowork, err)
		}
		if h.fileDigests != nil {
			h.fileDigests[gowork] = wkFB.digest()
		}
		extraContribs = append(extraContribs, "gowork:"+filepath.Base(gowork)+"="+wkFB.digest())
		extraFiles = append(extraFiles, gowork)

		goworkSum := gowork + ".sum"
		wkSumDigest, wkSumExists, err := h.readOptionalCompanionFile(goworkSum)
		if err != nil {
			return nil, nil, false, err
		}
		extraContribs = append(extraContribs, "goworksum:"+filepath.Base(goworkSum)+"="+wkSumDigest)
		if wkSumExists {
			extraFiles = append(extraFiles, goworkSum)
		}

		workVendorManifest := filepath.Join(filepath.Dir(gowork), "vendor", "modules.txt")
		wkVendorDigest, wkVendorExists, err := h.readOptionalCompanionFile(workVendorManifest)
		if err != nil {
			return nil, nil, false, err
		}
		extraContribs = append(extraContribs, "goworkvendor:"+filepath.Base(gowork)+"="+wkVendorDigest)
		if wkVendorExists {
			extraFiles = append(extraFiles, workVendorManifest)
		}
	}
	return extraContribs, extraFiles, hasFolded, nil
}

func (h *Hasher) pkgHasFoldedModMetadata(pkgPath string) bool {
	if h == nil || pkgPath == "" {
		return false
	}
	if h.hasFoldedModMetadata != nil {
		if folded, known := h.hasFoldedModMetadata[pkgPath]; known {
			return folded
		}
	}
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return false
	}
	_, _, hasFolded, err := h.collectRuntimeDebugModMetadata(pkgPath, pkgs)
	if err != nil {
		return false
	}
	if h.hasFoldedModMetadata == nil {
		h.hasFoldedModMetadata = map[string]bool{}
	}
	h.hasFoldedModMetadata[pkgPath] = hasFolded
	return hasFolded
}

func (h *Hasher) admitsTier1ReadBuildInfo(pkgPath, basePkgName string) bool {
	if h == nil || !h.SelectionAudited() || !h.source.pureDelegates["runtime/debug:ReadBuildInfo"] {
		return false
	}
	if h.buildVCS != "false" || basePkgName != "main" {
		return false
	}
	return h.pkgHasFoldedModMetadata(pkgPath)
}

func (h *Hasher) admitsTier2ReadBuildInfo(pkgPath string) bool {
	if h == nil || !h.SelectionAudited() || !h.source.pureDelegates["runtime/debug:ReadBuildInfo"] {
		return false
	}
	if h.buildVCS != "false" && h.buildVCS != "auto" {
		return false
	}
	return h.pkgHasFoldedModMetadata(pkgPath)
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
		files, err = allPackageFiles(h.contextErr, p.Dir)
		if err != nil {
			return "", nil, err
		}
		if include, err := cgoEscapingIncludeWith(&p, files, h.readFile); err != nil {
			return "", nil, err
		} else if include != "" {
			return "", nil, fmt.Errorf("closure: cgo include escapes package dir: %s", include)
		}
	}
	if len(p.SFiles) > 0 {
		// The maximal tier leaves non-toolchain assembly unanalyzed and folds
		// the package's whole directory into the hash so every .s file and any
		// local header it includes from the package tree moves the closure
		// identity (covering both REQ-closure-blindspot's downgrade floor and
		// Tier-2 mechanical per-TEXT assembly verification).
		var err error
		files, err = allPackageFiles(h.contextErr, p.Dir)
		if err != nil {
			return "", nil, err
		}
	}
	files = listing.UniqueStrings(files)
	// The members whose canonical form is their contribution: compiled
	// Go members that no directive embeds; every other member — data,
	// C, assembly, a compiled member embedded as data too, the rest of
	// a whole-directory fold — contributes its bytes.
	_, _, canonical := memberKinds(p)
	fh, err := h.hashFiles(p.Dir, files, canonical)
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

// IdentityStrategy versions the closure identity as a whole — the
// maximal closure and the test-variant compartment — as the composition
// of the derivations the two hashes read: the fold discipline
// (identityFoldStrategy: which members each hash folds and by bytes or
// by form), the canonical member form (canonicalStrategy), and the
// compartment's ledger derivation (variantParseStrategy, which also
// scopes its memo). Composed, not restated, so a bump to any leg moves
// the identity's version by construction. The value is opaque: a
// consumer keying a judgment to either hash compares two records'
// values for equality only — never parsed for which leg moved.
//
// The analyzing frontend is not a constituent: see AnalyzingFrontend —
// the fold's token stream and parse are fixed across frontends for the
// valid sources it admits; the memos key on the frontend instead — a
// cache-miss defense for the syntax-level ones, a correctness key for
// the type-level ones, whose payloads are the frontend's own.
const IdentityStrategy = identityFoldStrategy + " " + canonicalStrategy + " " + variantParseStrategy

// identityFoldStrategy versions what the two hashes fold beyond the
// per-member forms: the maximal fold's member kinds (compiled, embedded,
// whole directory, plus mutable-local go.mod/go.sum/go.work metadata when
// runtime/debug is in the dependency graph), its mutable-local and
// pinned-dependency rules and the standard-library cut; and the compartment's
// membership rule (the subject package's own test variants and the test-only
// members they add), its per-member byte fold, and its empty sentinel.
const identityFoldStrategy = "gofresh/closure@2"

// memberKinds derives one listing node's member kinds — the compiled
// Go members (GoFiles and CgoFiles) and the embedded data members — the
// one derivation the core contribution and the test-variant compartment
// share. The kinds are not a partition: a member both compiled and
// embedded (a sibling names it in a go:embed directive) is data too,
// and canonical is false for it — its bytes reach unchanged code as
// data, so its bytes are its contribution (REQ-closure-canonical-member,
// REQ-closure-test-variant-ledger).
func memberKinds(p listPkg) (compiled, embedded, canonical map[string]bool) {
	compiled, embedded, canonical = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, set := range [][]string{p.GoFiles, p.CgoFiles} {
		for _, f := range set {
			compiled[f] = true
		}
	}
	for _, f := range p.EmbedFiles {
		embedded[f] = true
	}
	for f := range compiled {
		if !embedded[f] {
			canonical[f] = true
		}
	}
	return compiled, embedded, canonical
}

// hashFiles is the fold over the Hasher's once-per-pass reads: the same
// bytes the effect scan and the compartment ledger consume. Compiled Go
// members fold their canonical digest (REQ-closure-canonical-member);
// every other member its bytes.
func (h *Hasher) hashFiles(dir string, files []string, canonical map[string]bool) (string, error) {
	return hashFilesWith(dir, files, canonical, h.fileDigests, h.readFile, h.canonicalFileDigest)
}

// hashFilesWith folds the members' digests in name order: a member in
// canonicalMembers folds canonical(dir, byteDigest, content) — the
// canonical form a compiled, unembedded Go member contributes — and
// every other member its byte digest; a nil canonical folds bytes for
// all. The per-file digest handed to digests is always the byte digest:
// it names the exact bytes the fold read, for movers' attribution and
// the memo keys.
func hashFilesWith(dir string, files []string, canonicalMembers map[string]bool, digests map[string]string, read func(string) (fileBytes, error), canonical func(dir, byteDigest string, content []byte) string) (string, error) {
	sort.Strings(files)
	hasher := sha256.New()
	for _, f := range files {
		path := filepath.Join(dir, f)
		fb, err := read(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		member := fb.digest()
		if canonicalMembers[f] && canonical != nil {
			member = canonical(dir, member, fb.content)
		}
		fmt.Fprintf(hasher, "%s\x00%s\n", f, member)
		if digests != nil {
			// The per-file digest rides to the Hasher's memo so naming
			// consumers reuse the exact bytes this hash was built over
			// instead of re-reading (FileDigest).
			digests[path] = fb.digest()
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))[:32], nil
}
