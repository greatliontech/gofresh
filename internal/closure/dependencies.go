package closure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/toolchain"
)

// UseViewLoad supplies the observation pass's shared typed load. The caller
// guarantees it was produced in the same pass, under the same tree root,
// environment, and executable build flags as this Hasher, and that its
// patterns cover every package whose closure this Hasher computes; a package
// the load does not cover falls back to a private load with identical
// semantics.
func (h *Hasher) UseViewLoad(load *ViewLoad) {
	h.viewLoad = load
}

// SetLoadedPackagesLookup supplies an optional lookup of already-loaded typed
// packages (such as from an owning Tier-2 Prover or in-memory test harness)
// so typed testing-effect and property-harness scans reuse loaded syntax/types
// without spawning redundant go/packages loads.
func (h *Hasher) SetLoadedPackagesLookup(fn func(pkgPath string) []*packages.Package) {
	if h != nil {
		h.loadedPackages = fn
	}
}

// SetHasStartedHook registers an optional predicate reporting whether a
// higher-tier consumer (such as Prover) has begun analysis on this Hasher.
func (h *Hasher) SetHasStartedHook(fn func() bool) {
	if h != nil {
		h.hasStarted = fn
	}
}

// SetResetCallScopeHook registers an optional callback invoked whenever h
// resets its per-batch-call scope so higher-tier wrappers (such as Prover)
// clear retained per-program summaries in lockstep.
func (h *Hasher) SetResetCallScopeHook(fn func()) {
	if h != nil {
		h.onResetCallScope = fn
	}
}

// SetListOnMissForTest installs an in-memory listing fallback for tests.
func (h *Hasher) SetListOnMissForTest(fn func(h *Hasher, pkgPath string) ([]gotool.ListedPackage, bool)) {
	if h != nil {
		h.listOnMiss = fn
	}
}

// SetListedPackagesForTest seeds pkgPath's parsed go-list slice on h for
// in-memory test harnesses.
func (h *Hasher) SetListedPackagesForTest(pkgPath string, metas []gotool.ListedPackage) {
	if h != nil {
		if h.lists == nil {
			h.lists = map[string][]listPkg{}
		}
		h.lists[pkgPath] = metas
	}
}

// LookupListedPackagesForTest returns any already-cached go-list slice on h.
func (h *Hasher) LookupListedPackagesForTest(pkgPath string) ([]gotool.ListedPackage, bool) {
	if h == nil {
		return nil, false
	}
	metas, ok := h.lists[pkgPath]
	return metas, ok
}

// DeleteListedPackagesForTest removes pkgPath's cached go-list slice from h.
func (h *Hasher) DeleteListedPackagesForTest(pkgPath string) {
	if h != nil {
		delete(h.lists, pkgPath)
	}
}

// HasCustomRunner reports whether h was constructed with a custom gotool.Runner
// Prepare hook.
func (h *Hasher) HasCustomRunner() bool {
	return h != nil && h.runner.Prepare != nil
}

// SetSelectionForTest overrides h's toolchain Selection for hermetic tests.
func (h *Hasher) SetSelectionForTest(sel toolchain.Selection) {
	if h != nil {
		h.selection = sel
	}
}

// SeedCallScopeForTest seeds pre-call stale test-binary keys, compartment
// identities, and node contributions so batch-entry reset tests can verify
// ResetCallScope clears every pre-call generation.
func (h *Hasher) SeedCallScopeForTest(pkgPath, testBinaryKey, variantHash, contribution string) {
	if h == nil {
		return
	}
	if testBinaryKey != "" {
		if h.testBinaryKeys == nil {
			h.testBinaryKeys = map[string]string{}
		}
		h.testBinaryKeys[pkgPath] = testBinaryKey
	}
	if variantHash != "" {
		if h.variantScope == nil {
			h.variantScope = map[string]testvariant.Identity{}
		}
		h.variantScope[pkgPath] = testvariant.Identity{Hash: variantHash}
	}
	if contribution != "" {
		if h.contribs == nil {
			h.contribs = map[string]depContribution{}
		}
		h.contribs[pkgPath] = depContribution{contribution: contribution}
	}
}

// HasStaleCallScopeForTest reports whether pkgPath still retains testBinaryKey
// or contribution in h's per-call memo maps.
func (h *Hasher) HasStaleCallScopeForTest(pkgPath, testBinaryKey, contribution string) bool {
	if h == nil {
		return false
	}
	if testBinaryKey != "" && h.testBinaryKeys[pkgPath] == testBinaryKey {
		return true
	}
	if contribution != "" {
		if c, ok := h.contribs[pkgPath]; ok && c.contribution == contribution {
			return true
		}
	}
	return false
}

// OnDiagnostic supplies a callback for phases carrying a payload the
// progress line cannot: the per-subject analysis-unavailable
// provenance rides it, never a memoized surface. Unlike progress
// events, diagnostics ARE contract for the operator's field log -
// each event is a distinct fact, delivered synchronously.
func (h *Hasher) OnDiagnostic(f func(phase, pkgPath, detail string)) {
	h.diagnostic = f
}

// EmitDiagnostic delivers a diagnostic event when OnDiagnostic is armed.
func (h *Hasher) EmitDiagnostic(phase, pkgPath, detail string) {
	h.emitDiagnostic(phase, pkgPath, detail)
}

func (h *Hasher) emitDiagnostic(phase, pkgPath, detail string) {
	if h != nil && h.diagnostic != nil {
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

// EmitProgress delivers a start-of-step progress event when OnProgress is armed.
func (h *Hasher) EmitProgress(phase, pkgPath string) {
	h.emitProgress(phase, pkgPath)
}

func (h *Hasher) emitProgress(phase, pkgPath string) {
	if h != nil && h.progress != nil {
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
	if h != nil && h.unit != nil {
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

// RecordPersistedProof increments the count of persisted observability proof slices.
func (h *Hasher) RecordPersistedProof() {
	if h != nil {
		h.persisted.proofs++
	}
}

// PassReader is the reader a later step of this hasher's pass loads
// under: the hasher's runner, directory, and environment, primed with
// the snapshot the hasher holds — the construction's, or a bracket's
// live one — so the step probes nothing the pass already read.
func (h *Hasher) PassReader() *gotool.EnvReader {
	return gotool.PrimedEnvReader(h.runner, h.dir, h.env, h.snapshot)
}

// Context returns this Hasher's current analysis context.
func (h *Hasher) Context() context.Context {
	if h == nil {
		return nil
	}
	return h.ctx
}

// WithContext temporarily runs fn with h's analysis context set to ctx,
// restoring the prior context on return.
func (h *Hasher) WithContext(ctx context.Context, fn func() error) error {
	if h == nil {
		return fn()
	}
	prev := h.ctx
	h.ctx = ctx
	defer func() { h.ctx = prev }()
	return fn()
}

// Dir returns the tree root directory under which h resolves loads and go commands.
func (h *Hasher) Dir() string {
	if h == nil {
		return ""
	}
	return h.dir
}

// ModCache returns h's cleaned GOMODCACHE path.
func (h *Hasher) ModCache() string {
	if h == nil {
		return ""
	}
	return h.modCache
}

// PackageEnv returns h's normalized environment for go/packages loads.
func (h *Hasher) PackageEnv() []string {
	if h == nil {
		return nil
	}
	return h.packageEnv
}

// BuildFlags returns h's executable build flags.
func (h *Hasher) BuildFlags() []string {
	if h == nil {
		return nil
	}
	return h.buildFlags
}

// Scope returns h's configured AnalysisScope.
func (h *Hasher) Scope() AnalysisScope {
	if h == nil {
		return AnalysisScope{}
	}
	return h.scope
}

// SnapshotGOOS returns the GOOS value recorded in h's environment snapshot, or "".
func (h *Hasher) SnapshotGOOS() string {
	if h == nil || h.snapshot == nil {
		return ""
	}
	return h.snapshot.Value("GOOS")
}

// EffectiveGOARCH returns the effective target GOARCH for h's build configuration.
func (h *Hasher) EffectiveGOARCH() string {
	return h.effectiveGOARCH()
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

// ReadSourceFile reads fullPath from h's per-call content snapshot for
// mutable-local packages, or directly from disk for version-pinned cache
// dependencies.
func (h *Hasher) ReadSourceFile(dir, fullPath string) ([]byte, error) {
	if h == nil || h.underCache(dir) {
		return os.ReadFile(fullPath)
	}
	fb, err := h.readFile(fullPath)
	if err != nil {
		return nil, err
	}
	return fb.content, nil
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
	if (h.hasStarted != nil && h.hasStarted()) || len(h.lists) != 0 || len(h.maximalEffects) != 0 || len(h.testVariants) != 0 {
		return errors.New("closure: analysis already begun; bound the Hasher before its first compute")
	}
	h.ctx = bound
	return nil
}

// analysisTestHookSet is the package's test-observation surface for Tier-1
// loads, file parses, and directory walks; nil disables.
type analysisTestHookSet struct {
	testingTypeOwnLoad func(pkgPath string)
	fileParse          func(path string)
	canonicalParse     func(dir string)
	variantParse       func(name string)
	walkEntry          func(path string)
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

func emitWalkEntryHook(path string) {
	if h := closureTestHooks.Load(); h != nil && h.walkEntry != nil {
		h.walkEntry(path)
	}
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

// PinnedPackage reports whether p's resolved source is immutable under h's module cache.
func (h *Hasher) PinnedPackage(p *listPkg) bool {
	return h.pinnedPackage(p)
}

// pinnedPackage reports the pinned-dependency classification: resolved
// source immutable under the module cache. REQ-closure-mutable-local
// names the package Dir, so classification uses it.
func (h *Hasher) pinnedPackage(p *listPkg) bool {
	return h != nil && p != nil && p.Module != nil && IsPinnedPackageDir(p.Module.Main, p.Dir, h.modCache)
}

// ContextErr checks h's analysis context for cancellation or deadline expiry.
func (h *Hasher) ContextErr() error {
	return h.contextErr()
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
		if check != nil {
			if err := check(); err != nil {
				return err
			}
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

// UnderCache reports whether dir is inside h's module cache on a path-segment boundary.
func (h *Hasher) UnderCache(dir string) bool {
	return h != nil && h.underCache(dir)
}

func (h *Hasher) underCache(dir string) bool {
	return IsPinnedPackageDir(false, dir, h.modCache)
}

// List runs `go list -json -deps -test` for pkgPath (or serves from the listing
// memo) and validates standard-library inventory coverage.
func (h *Hasher) List(pkgPath string) ([]listPkg, error) {
	return h.list(pkgPath)
}

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

func (h *Hasher) standardInventoryCovers(pkgs []listPkg) error {
	return h.selection.CoversStandardPackages(pkgs)
}

// Selection returns h's resolved toolchain-audit Selection.
func (h *Hasher) Selection() toolchain.Selection {
	if h == nil {
		return toolchain.Selection{}
	}
	return h.selection
}

// SelectionAudited reports whether the toolchain-source audit succeeded.
func (h *Hasher) SelectionAudited() bool {
	return h != nil && h.selection.Audited()
}

// SelectionNotice renders the unaudited degradation notice, or "" when audited.
func (h *Hasher) SelectionNotice() string {
	if h == nil {
		return (toolchain.Selection{}).Notice()
	}
	return h.selection.Notice()
}

// SelectionAttribution returns the unaudited selection axis, or "" when audited.
func (h *Hasher) SelectionAttribution() string {
	if h == nil {
		return (toolchain.Selection{}).Attribution()
	}
	return h.selection.Attribution()
}

// PureDelegates returns the verified pure-delegate map when audited, or nil.
func (h *Hasher) PureDelegates() map[string]bool {
	if h == nil {
		return nil
	}
	return h.selection.PureDelegates()
}

// ToolchainContent identifies every standard package's selected source files
// in this construction.
func (h *Hasher) ToolchainContent() string {
	if h == nil {
		return ""
	}
	return h.selection.Content()
}

// AdmissionPolicy identifies the data governing the source audit, separately
// from derivation versions and memo representation.
func (h *Hasher) AdmissionPolicy() string {
	if h == nil {
		return ""
	}
	return h.selection.Policy()
}
