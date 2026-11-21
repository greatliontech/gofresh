package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
	"github.com/greatliontech/gofresh/internal/gotool"
)

// SetPackageMates supplies same-package sibling subjects that may opportunistically
// share unused bitmask slots (< 64) when an observability batch already loads and
// analyzes their package's test-binary SSA program.
func (h *Hasher) SetPackageMates(subjects []Subject) {
	if len(subjects) == 0 {
		h.packageMates = nil
		return
	}
	byPkg := make(map[string][]Subject)
	for _, s := range subjects {
		byPkg[s.Package] = append(byPkg[s.Package], s)
	}
	h.packageMates = byPkg
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

// PassReader is the reader a later step of this hasher's pass loads
// under: the hasher's runner, directory, and environment, primed with
// the snapshot the hasher holds — the construction's, or a bracket's
// live one — so the step probes nothing the pass already read.
func (h *Hasher) PassReader() *gotool.EnvReader {
	return gotool.PrimedEnvReader(h.runner, h.dir, h.env, h.snapshot)
}

func (h *Hasher) effectiveGOARCH() string {
	if h == nil {
		return ""
	}
	if h.snapshot != nil {
		if arch := strings.TrimSpace(h.snapshot.Value("GOARCH")); arch != "" {
			return arch
		}
	}
	if arch, ok := gotool.LookupEnv(h.env, "GOARCH"); ok && strings.TrimSpace(arch) != "" {
		return strings.TrimSpace(arch)
	}
	return runtime.GOARCH
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

// analysisTestHookSet is the package's one test-observation surface: each
// field observes a load the tests prove skipped or taken, or overrides a
// standard-library verification verdict for negative-control tests; nil disables.
type analysisTestHookSet struct {
	// testingTypeOwnLoad observes the typed testing-effect scan's private
	// fallback load, so tests pin that a shared view load or a memo hit is
	// actually consumed instead.
	testingTypeOwnLoad func(pkgPath string)
	// fileParse observes a per-file effect scan actually parsing, and
	// variantParse a compartment member's ledger derivation, so tests
	// pin that the persistent per-file memos served instead.
	fileParse func(path string)
	// canonicalParse observes a compiled member's canonical form
	// actually being derived (a byte-digest miss), the memo's one
	// observable.
	canonicalParse func(dir string)
	variantParse   func(name string)
	// packageVerdictOverride lets hermetic tests override or seed a
	// verified-package verdict for a specific memo key without mutating
	// verifiedPackageMemo directly.
	packageVerdictOverride func(memoKey string) (verifiedPackageVerdict, bool)
	walkEntry              func(path string)
	digestRead             func(name string)
	analyzeBatch           func(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error)
	probePkgScope          func(ctx context.Context, prog *program, subjects []Subject) error
}

var (
	closureTestHooksMu sync.Mutex
	closureTestHooks   atomic.Pointer[analysisTestHookSet]
)

func withClosureTestHooks(hooks analysisTestHookSet, fn func()) {
	closureTestHooksMu.Lock()
	defer closureTestHooksMu.Unlock()
	defer closureTestHooks.Store(nil)
	closureTestHooks.Store(&hooks)
	fn()
}

func emitTestingTypeOwnLoadHook(pkgPath string) {
	if h := closureTestHooks.Load(); h != nil && h.testingTypeOwnLoad != nil {
		h.testingTypeOwnLoad(pkgPath)
	}
}

func emitFileParseHook(path string) {
	if h := closureTestHooks.Load(); h != nil && h.fileParse != nil {
		h.fileParse(path)
	}
}

func emitCanonicalParseHook(dir string) {
	if h := closureTestHooks.Load(); h != nil && h.canonicalParse != nil {
		h.canonicalParse(dir)
	}
}

func emitVariantParseHook(name string) {
	if h := closureTestHooks.Load(); h != nil && h.variantParse != nil {
		h.variantParse(name)
	}
}

func hasPackageVerdictOverrideHook() bool {
	h := closureTestHooks.Load()
	return h != nil && h.packageVerdictOverride != nil
}

func lookupPackageVerdictOverrideHook(memoKey string) (verifiedPackageVerdict, bool) {
	if h := closureTestHooks.Load(); h != nil && h.packageVerdictOverride != nil {
		return h.packageVerdictOverride(memoKey)
	}
	return verifiedPackageVerdict{}, false
}

func emitWalkEntryHook(path string) {
	if h := closureTestHooks.Load(); h != nil && h.walkEntry != nil {
		h.walkEntry(path)
	}
}

func hasDigestReadTestHook() bool {
	h := closureTestHooks.Load()
	return h != nil && h.digestRead != nil
}

func emitDigestReadHook(name string) {
	if h := closureTestHooks.Load(); h != nil && h.digestRead != nil {
		h.digestRead(name)
	}
}

func runAnalyzeAttributedBatch(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
	if h := closureTestHooks.Load(); h != nil && h.analyzeBatch != nil {
		return h.analyzeBatch(ctx, audited, pureDelegates, prog, subjects)
	}
	return attributedReachableSetsOnce(ctx, audited, pureDelegates, prog, subjects)
}

func runProbePackageScope(ctx context.Context, prog *program, subjects []Subject) error {
	if h := closureTestHooks.Load(); h != nil && h.probePkgScope != nil {
		return h.probePkgScope(ctx, prog, subjects)
	}
	return defaultProbePackageScope(ctx, prog, subjects)
}

// modulePin is the version-pin identity every persistent memo and
// contribution shares: the cache-relative module content dir —
// modpath@version, replace-correct via Module.Dir.
func (h *Hasher) modulePin(mod *listMod) string {
	return h.ModulePinForDir(mod.Dir)
}

// ModulePinForDir formats modDir's cache-relative module pin identity
// (modpath@version).
func (h *Hasher) ModulePinForDir(modDir string) string {
	if h == nil {
		return ""
	}
	return filepath.ToSlash(strings.TrimPrefix(filepath.Clean(modDir), h.modCache+string(filepath.Separator)))
}

// IsPinnedDir reports whether pkgDir belongs to a non-main module located
// inside h's module cache on a path-segment boundary.
func (h *Hasher) IsPinnedDir(main bool, pkgDir string) bool {
	return h != nil && IsPinnedPackageDir(main, pkgDir, h.modCache)
}

// IsPinnedPackageDir reports whether pkgDir belongs to a non-main module
// located inside modCache on a path-segment boundary.
func IsPinnedPackageDir(main bool, pkgDir, modCache string) bool {
	if main || pkgDir == "" || modCache == "" {
		return false
	}
	pkgDir = filepath.Clean(pkgDir)
	modCache = filepath.Clean(modCache)
	return pkgDir == modCache || strings.HasPrefix(pkgDir, modCache+string(filepath.Separator))
}

// pinnedPackage reports the pinned-dependency classification: resolved
// source immutable under the module cache. REQ-closure-mutable-local
// names the package Dir, so classification uses it.
func (h *Hasher) pinnedPackage(p *listPkg) bool {
	return p.Module != nil && IsPinnedPackageDir(p.Module.Main, p.Dir, h.modCache)
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

func allPackageFiles(check func() error, dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// The check point: the package's own cancellation check
		// (Hasher.contextErr) before every entry, so a cancelled walk
		// ends at the next entry answering the cancellation.
		if err := check(); err != nil {
			return err
		}
		emitWalkEntryHook(path)
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

// underCache reports whether dir is inside the module cache (a path segment
// boundary, so "/mod" does not match "/modificator").
func (h *Hasher) underCache(dir string) bool {
	return IsPinnedPackageDir(false, dir, h.modCache)
}

// list runs `go list -json -deps -test` for pkgPath and returns the parsed
// dependency graph. The result is memoized per package path for the life of the
// Hasher: every per-benchmark Compute call in a package (and the maximalHash
// widen path) needs the identical listing, and its inputs are immutable within a
// single process run, so one subprocess+decode is amortized across them (same
// lifetime and rationale as the SSA program cache). Callers treat the slice as
// read-only, so sharing one backing array across them is safe.
func (h *Hasher) list(pkgPath string) ([]listPkg, error) {
	pkgs, err := h.listUnvalidated(pkgPath)
	if err != nil {
		return nil, err
	}
	if err := h.standardInventoryCovers(pkgs); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// listUnvalidated is the go command's declaration listing and its cache.
// Analyses use list, which additionally admits the listing's source coverage.
func (h *Hasher) listUnvalidated(pkgPath string) ([]listPkg, error) {
	if pkgs, ok := h.lists[pkgPath]; ok {
		return pkgs, nil
	}
	if pkgs, ok := h.loadListing(pkgPath); ok {
		h.Served("listing", pkgPath)
		h.lists[pkgPath] = pkgs
		return pkgs, nil
	}
	h.emitProgress("list", pkgPath)
	if h.listOnMiss != nil {
		if pkgs, ok := h.listOnMiss(h, pkgPath); ok {
			h.lists[pkgPath] = pkgs
			h.storeListing(pkgPath, pkgs)
			return pkgs, nil
		}
	}
	args := []string{"-json", "-deps", "-test"}
	args = append(args, h.buildFlags...)
	args = append(args, pkgPath)
	out, err := h.runner.List(h.ctx, h.dir, h.env, args...)
	if err != nil {
		return nil, err
	}
	pkgs, err := gotool.ParseListing(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	h.lists[pkgPath] = pkgs
	h.storeListing(pkgPath, pkgs)
	return pkgs, nil
}

// standardInventoryCovers reconciles pattern discovery with the packages
// actually imported by the subject. An explicitly importable standard package
// omitted by the wildcard inventory never inherits its content coverage.
func (h *Hasher) standardInventoryCovers(pkgs []listPkg) error {
	if h.ToolchainContent() == "" {
		return nil
	}
	for _, p := range pkgs {
		if !p.Standard {
			continue
		}
		inventory, ok := h.source.inventory[p.SourcePath()]
		if !ok || filepath.Clean(inventory.Dir) != filepath.Clean(p.Dir) || !slices.Equal(inventory.Files, selectedFiles(p)) {
			return fmt.Errorf("closure: selected standard package %s is not covered by the toolchain content inventory", p.ImportPath)
		}
	}
	return nil
}

// ToolchainContent identifies every standard package's selected source files
// in this construction. It is independent of the reported version and of the
// admission policy. Empty means that complete content could not be read.
func (h *Hasher) ToolchainContent() string { return h.source.Content }

// AdmissionPolicy identifies the data governing the source audit, separately
// from derivation versions and memo representation.
func (h *Hasher) AdmissionPolicy() string { return h.source.Policy }

type policyInputs struct {
	verifier    string
	asmVerifier string
	audit       string
	packages    map[string]bool
	linknames   map[string]bool
	seeds       []string
}

// capturePolicyInputs owns every input before keying or deriving a policy.
// Production inventories change only through source edits; tests may replace
// them between calls. The memo holds no aliases into either form.
func capturePolicyInputs() policyInputs {
	packages := map[string]bool{}
	toolchain.AppendPolicyPackages(packages)
	for k, v := range cprep.AllowedPureAsmStandardHeaders {
		packages["pure-asm-hdr-allow:"+k] = v
	}
	linknames := map[string]bool{}
	for k, v := range cprep.AllowedPureLinknameTargets {
		linknames["pure-link2:"+k] = v
	}
	for k, v := range cprep.AllowedPureSingleArgLinknames {
		linknames["pure-link1:"+k] = v
	}
	for k, v := range cprep.AllowedPureAsmCrossPkgSymbols {
		linknames["pure-asm-sym:"+k] = v
	}
	return policyInputs{
		verifier:    toolchainVerifierVersion,
		asmVerifier: asmverify.NonStdAsmVerifierVersion,
		audit:       auditset.Identity(),
		packages:    packages,
		linknames:   linknames,
		seeds:       surfaceSeeds(),
	}
}

func admissionPolicy() string {
	return capturePolicyInputs().derive()
}

func (in policyInputs) derive() string {
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@2", in.verifier, in.asmVerifier, in.audit,
		in.packages, in.linknames, seeds})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
