package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

// ComputeMaximalBatch returns the maximal sound closure for every subject. All
// subjects in one package share the selected test binary's complete non-standard
// dependency closure; this deliberately trades declaration precision for bounded
// analysis cost while preserving the no-false-valid floor (REQ-closure-floor).
// The package's own test-variant source is partitioned out of the core hash
// into the Closure's TestVariants compartment
// (REQ-closure-test-variant-hash).
// It also returns the exact mutable source paths whose bytes contribute to
// each subject's maximal closure. Cache-module and standard-library inputs
// remain represented by their existing guards.
func (h *Hasher) ComputeMaximalBatch(subjects []Subject) (map[Subject]Closure, map[Subject][]string, error) {
	facts, sources, err := h.ComputeMaximalFactsBatch(subjects)
	if err != nil {
		return nil, nil, err
	}
	results := make(map[Subject]Closure, len(facts))
	for subject, fact := range facts {
		results[subject] = fact.Closure()
	}
	if err := h.contextErr(); err != nil {
		return nil, nil, err
	}
	return results, sources, nil
}

// ComputeMaximalFactsBatch returns caller-owned maximal identities and complete
// conservative blocker classifications for every subject, together with the
// mutable source paths described by ComputeMaximalBatch.
func (h *Hasher) ComputeMaximalFactsBatch(subjects []Subject) (map[Subject]MaximalFacts, map[Subject][]string, error) {
	if err := h.contextErr(); err != nil {
		return nil, nil, err
	}
	// One call observes one tree generation; a later call re-observes.
	h.resetCallScope()
	defer func() {
		h.contents = nil
		h.maximalParsedFiles = nil
		h.maximalTestingUnfiltered = nil
	}()
	results := make(map[Subject]MaximalFacts, len(subjects))
	sources := make(map[Subject][]string, len(subjects))
	byPackage := make(map[string][]Subject)
	var packages []string
	seen := make(map[Subject]bool, len(subjects))
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		if _, ok := byPackage[subject.Package]; !ok {
			packages = append(packages, subject.Package)
		}
		byPackage[subject.Package] = append(byPackage[subject.Package], subject)
	}
	for i, pkgPath := range packages {
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		h.emitUnit("hash", pkgPath, i+1, len(packages))
		contributions, files, err := h.maximalContributionsAndFiles(pkgPath)
		if err != nil {
			return nil, nil, err
		}
		hash, err := hashContributions(pkgPath, contributions)
		if err != nil {
			return nil, nil, err
		}
		effects, reason, err := h.maximalExternalEffects(pkgPath)
		if err != nil {
			return nil, nil, err
		}
		base := newMaximalFacts(MaximalIdentity{
			ToolchainContent: h.ToolchainContent(),
			AdmissionPolicy:  h.AdmissionPolicy(),
			TestVariants:     h.testVariants[pkgPath].Hash,
		}, effects, AttributeSelection(reason, h.SelectionAttribution()))
		for _, subject := range byPackage[pkgPath] {
			facts := base.Clone()
			facts.Identity.Hash = maximalSubjectHash(hash, subject)
			results[subject] = facts
			sources[subject] = append([]string(nil), files...)
		}
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
	}
	return results, sources, nil
}

func maximalSubjectHash(packageHash string, subject Subject) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s", len(packageHash), packageHash, len(subject.Package), subject.Package, len(subject.Symbol), subject.Symbol))
	return hex.EncodeToString(sum[:])[:32]
}

// maximalEffectsResult memoizes one package's complete external-effect scan
// within a Hasher: the scan depends only on the package's listed sources, so
// every subject sharing the package shares one scan.
type maximalEffectsResult struct {
	effects  []externalEffect
	selected string
}

type packageGraphWalkOptions struct {
	filtered               bool
	base                   *tier2Base
	reachedDecls           map[funcDeclKey]bool
	startupOnlyDecls       map[funcDeclKey]bool
	startupZeroGlobalDecls map[pkgVarKey]bool
	wholeZeroGlobalDecls   map[pkgVarKey]bool
}

func filterScanForTier1ReadBuildInfo(scan maximalEffectScan) maximalEffectScan {
	if len(scan.effects) == 0 {
		return scan
	}
	var filtered []externalEffect
	removed := false
	for _, e := range scan.effects {
		if e.kind == externalEffectUnauditedStandard && e.packagePath == "runtime/debug" && e.symbol == "ReadBuildInfo" {
			removed = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !removed {
		return scan
	}
	scan.effects = filtered
	scan.preferred = preferredEffectReason(append(append([]externalEffect(nil), scan.effects...), scan.importCandidates...))
	if scan.preferred == "" {
		scan.preferred = "reaches runtime/debug (potential external dependence)"
	}
	return scan
}

func (h *Hasher) walkPackageGraphEffects(pkgPath string, opts packageGraphWalkOptions) ([]externalEffect, string, error) {
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, "", err
	}
	basePkgName := ""
	if !opts.filtered {
		for _, p := range pkgs {
			if p.ImportPath == pkgPath && p.ForTest == "" {
				basePkgName = p.Name
				break
			}
		}
	}
	admitTier1ReadBuildInfo := !opts.filtered && h.admitsTier1ReadBuildInfo(pkgPath, basePkgName)

	var effects []externalEffect
	var candidates []externalEffect
	var fallback string
	record := func(scan maximalEffectScan) {
		if admitTier1ReadBuildInfo {
			scan = filterScanForTier1ReadBuildInfo(scan)
		}
		for _, effect := range scan.effects {
			effects = appendExternalEffect(effects, effect)
			if !opts.filtered {
				candidates = appendExternalEffect(candidates, effect)
			}
		}
		if !opts.filtered {
			for _, candidate := range scan.importCandidates {
				candidates = appendExternalEffect(candidates, candidate)
			}
			if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (fallback == "" || scan.preferred < fallback) {
				fallback = scan.preferred
			}
		}
	}

	testingEffects, err := h.maximalTestingTypeEffectsFiltered(opts.base, pkgPath, opts.reachedDecls)
	if err != nil {
		return nil, "", err
	}
	record(testingEffects)

	declaredNames := listedDeclaredNames(pkgs)
	nonStdPaths := listedNonStandardPaths(pkgs)
	overridesKey := scanOverridesKey(declaredNames, nonStdPaths)
	audited := h.SelectionAudited()
	for _, pkg := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, "", err
		}
		if pkg.Standard || pkg.Module == nil || pkg.IsGeneratedTestMainFor(pkgPath) {
			continue
		}
		if opts.filtered {
			if !listPkgHasNativeOrEmbed(&pkg) && opts.base != nil {
				if vp := verifiedHarnessesProg(audited, opts.base.prog)[pkg.ImportPath]; vp != nil {
					record(maximalEffectScan{effects: []externalEffect{propertyHarnessFact(vp)}})
					continue
				}
			}
		} else if vp := h.propertyHarnessAuditedListPkg(pkgPath, &pkg); vp != nil {
			record(maximalEffectScan{effects: []externalEffect{propertyHarnessFact(vp)}})
			continue
		}

		srcPath := pkg.SourcePath()
		pkgHasZeroGlobals := opts.filtered && (hasPkgZeroGlobals(opts.startupZeroGlobalDecls, srcPath) || hasPkgZeroGlobals(opts.wholeZeroGlobalDecls, srcPath))
		if scan, ok, err := h.pinnedEffectScanWithContext(pkg, declaredNames, nonStdPaths, overridesKey); err != nil {
			return nil, "", err
		} else if ok && (!opts.filtered || (!hasFilterableMaximalBlocker(audited, scan.effects) && !(pkgHasZeroGlobals && hasAnyMaximalBlocker(audited, scan.effects)))) {
			record(scan)
			continue
		}

		if opts.filtered {
			record(h.tier2PackageExternalEffects(opts.base, &pkg))
		} else {
			record(maximalPackageExternalEffects(&pkg))
		}

		var pkgScopeShadowed, verifiedLinknameLocals map[string]bool
		pkgConfinedUnsafe := false
		trackedChdirSafe := false
		if opts.filtered {
			pkgScopeShadowed = pkgScopeShadowedUniverseZeroNames(opts.base, srcPath)
			verifiedLinknameLocals = opts.base.verifiedReadOnlyLinknameLocals(srcPath)
			pkgConfinedUnsafe = opts.reachedDecls != nil && opts.base.pkgConfinedUnsafe(pkg.ImportPath, srcPath)
			trackedChdirSafe = opts.reachedDecls != nil && opts.base.binaryTrackedChdirSafe()
		}

		files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
		for _, name := range files {
			if err := h.contextErr(); err != nil {
				return nil, "", err
			}
			fullPath := filepath.Join(pkg.Dir, name)
			unfiltered, err := h.maximalFileEffectsCachedWithContext(pkg.ImportPath, fullPath, declaredNames, nonStdPaths, overridesKey)
			if err != nil {
				return nil, "", err
			}
			if !opts.filtered || (!hasFilterableMaximalBlocker(audited, unfiltered.effects) && !(pkgHasZeroGlobals && hasAnyMaximalBlocker(audited, unfiltered.effects))) {
				record(unfiltered)
				continue
			}
			var content []byte
			if h.underCache(pkg.Dir) {
				content, err = os.ReadFile(fullPath)
			} else {
				var fb fileBytes
				fb, err = h.readFile(fullPath)
				content = fb.content
			}
			if err != nil {
				return nil, "", err
			}
			parsed, err := h.parsedMaximalFile(fullPath, content, declaredNames, nonStdPaths, overridesKey)
			if err != nil {
				return nil, "", err
			}
			scan := maximalFileEffectsParsed(audited, parsed, nonStdPaths, opts.reachedDecls, opts.startupOnlyDecls, srcPath, opts.startupZeroGlobalDecls, opts.wholeZeroGlobalDecls, pkgScopeShadowed, verifiedLinknameLocals, pkgConfinedUnsafe, trackedChdirSafe)
			record(scan)
		}
	}
	if !opts.filtered {
		h.flushFileMemos()
		selected := preferredEffectReason(candidates)
		if selected == "" {
			selected = fallback
		}
		return effects, selected, nil
	}
	return effects, "", nil
}

// maximalExternalEffects returns the package's complete external-effect scan.
// The returned effects slice aliases the Hasher's memo — callers must treat it
// as read-only.
func (h *Hasher) maximalExternalEffects(pkgPath string) ([]externalEffect, string, error) {
	if cached, ok := h.maximalEffects[pkgPath]; ok {
		return cached.effects, cached.selected, nil
	}
	effects, selected, err := h.walkPackageGraphEffects(pkgPath, packageGraphWalkOptions{})
	if err != nil {
		return nil, "", err
	}
	h.maximalEffects[pkgPath] = maximalEffectsResult{effects: effects, selected: selected}
	return effects, selected, nil
}

func (h *Hasher) subjectMaximalExternalEffectsWithZeroGlobals(base *tier2Base, pkgPath string, reachedDecls, startupOnlyDecls map[funcDeclKey]bool, startupZeroGlobalDecls, wholeZeroGlobalDecls map[pkgVarKey]bool) ([]externalEffect, error) {
	tracing := trace.Enabled(h.ctx, trace.DomainClosure, pkgPath)
	var start time.Time
	if tracing {
		start = time.Now()
	}
	effects, _, err := h.walkPackageGraphEffects(pkgPath, packageGraphWalkOptions{
		filtered:               true,
		base:                   base,
		reachedDecls:           reachedDecls,
		startupOnlyDecls:       startupOnlyDecls,
		startupZeroGlobalDecls: startupZeroGlobalDecls,
		wholeZeroGlobalDecls:   wholeZeroGlobalDecls,
	})
	if err != nil {
		return nil, err
	}
	if tracing {
		trace.Emit(h.ctx, trace.DomainClosure, "maximal.subject.done", pkgPath,
			trace.Int("effects", len(effects)),
			trace.Bool("filtered", reachedDecls != nil),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
	}
	return effects, nil
}

func pkgScopeShadowedUniverseZeroNames(base *tier2Base, pkgPath string) map[string]bool {
	if base == nil || pkgPath == "" {
		return nil
	}
	var out map[string]bool
	for tp, idx := range base.idxByTypes {
		if tp == nil || idx == nil || idx.path != pkgPath || tp.Scope() == nil {
			continue
		}
		for _, kw := range []string{"nil", "false"} {
			if tp.Scope().Lookup(kw) != nil {
				if out == nil {
					out = make(map[string]bool, 2)
				}
				out[kw] = true
			}
		}
	}
	return out
}

// maximalFileEffectsCached memoizes one file's effect scan within a Hasher
// and serves it from the persistent per-file memo under the file's content digest.
func (h *Hasher) maximalFileEffectsCached(pkgPath, path string) (maximalEffectScan, error) {
	return h.maximalFileEffectsCachedWithNames(pkgPath, path, nil, "")
}

func (h *Hasher) maximalFileEffectsCachedWithNames(pkgPath, path string, declaredNames map[string]string, overridesKey string) (maximalEffectScan, error) {
	return h.maximalFileEffectsCachedWithContext(pkgPath, path, declaredNames, nil, overridesKey)
}

func (h *Hasher) maximalFileEffectsCachedWithContext(pkgPath, path string, declaredNames map[string]string, nonStdPaths map[string]bool, overridesKey string) (maximalEffectScan, error) {
	cacheKey := path + overridesKey
	if scan, ok := h.maximalFiles[cacheKey]; ok {
		return scan, nil
	}
	dir := filepath.Dir(path)
	if h.underCache(dir) {
		content, err := os.ReadFile(path)
		if err != nil {
			return maximalEffectScan{}, err
		}
		parsed, err := h.parsedMaximalFile(path, content, declaredNames, nonStdPaths, overridesKey)
		if err != nil {
			return maximalEffectScan{}, err
		}
		scan := maximalFileEffectsParsed(h.SelectionAudited(), parsed, nonStdPaths, nil, nil, "", nil, nil, nil, nil, false, false)
		h.maximalFiles[cacheKey] = scan
		return scan, nil
	}
	fb, err := h.readFile(path)
	if err != nil {
		return maximalEffectScan{}, err
	}
	digestKey := fb.digest() + overridesKey
	if scan, ok, stored := h.fileScan(dir, digestKey); ok {
		if stored {
			h.Served("file scan", pkgPath)
		}
		h.maximalFiles[cacheKey] = scan
		return scan, nil
	}
	emitFileParseHook(path)
	parsed, err := h.parsedMaximalFile(path, fb.content, declaredNames, nonStdPaths, overridesKey)
	if err != nil {
		return maximalEffectScan{}, err
	}
	scan := maximalFileEffectsParsed(h.SelectionAudited(), parsed, nonStdPaths, nil, nil, "", nil, nil, nil, nil, false, false)
	h.recordFileScan(dir, digestKey, scan)
	h.maximalFiles[cacheKey] = scan
	return scan, nil
}

// preferEffectReason reports whether candidate displaces current as the
// preferred diagnostic: higher cause rank first, lexicographic least within a rank.
func preferEffectReason(candidate, current externalEffect) bool {
	candidateRank, currentRank := effectCauseRank(candidate), effectCauseRank(current)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	return candidate.reason < current.reason
}

// preferredEffectReason selects the diagnostic over an effect set under preferEffectReason.
func preferredEffectReason(effects []externalEffect) string {
	var best externalEffect
	found := false
	for _, effect := range effects {
		if effect.reason == "" {
			continue
		}
		if !found || preferEffectReason(effect, best) {
			best, found = effect, true
		}
	}
	return best.reason
}

func (h *Hasher) maximalTestingTypeEffects(pkgPath string) (maximalEffectScan, error) {
	return h.maximalTestingTypeEffectsFiltered(nil, pkgPath, nil)
}

func (h *Hasher) viewLoadVariants(pkgPath string) []*packages.Package {
	if h.viewLoad == nil {
		return nil
	}
	var variants []*packages.Package
	for _, pkg := range h.viewLoad.Packages() {
		if pkg.PkgPath == pkgPath || pkg.ForTest == pkgPath {
			variants = append(variants, pkg)
		}
	}
	if len(variants) == 0 {
		return nil
	}
	return variants
}

func (h *Hasher) tier2PackageExternalEffects(base *tier2Base, pkg *listPkg) maximalEffectScan {
	scan := maximalPackageExternalEffects(pkg)
	if base != nil {
		if _, asmAdmitted := base.verifiedPackageAssembly(pkg); asmAdmitted {
			filtered := scan.effects[:0]
			for _, e := range scan.effects {
				if e.detail == "reaches non-standard assembly" || e.detail == "reaches cgo or native source" {
					continue
				}
				filtered = append(filtered, e)
			}
			scan.effects = filtered
			scan.preferred = preferredEffectReason(scan.effects)
		}
	}
	return scan
}

func maximalPackageExternalEffects(pkg *listPkg) maximalEffectScan {
	var scan maximalEffectScan
	if hasExternalCgoMeta(pkg) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
		effect.unrefinable = true
		scan.add(effect)
	}
	if pkg != nil && len(pkg.SysoFiles) != 0 {
		effect := opaqueExternalEffect(externalEffectNative, "reaches non-standard system object")
		effect.unrefinable = true
		scan.add(effect)
	}
	if hasCgoCallbackBlindspot(pkg) {
		scan.add(opaqueExternalEffect(externalEffectNative, "reaches cgo or native source"))
	}
	if pkg != nil && len(pkg.SFiles) != 0 {
		scan.add(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
	}
	scan.preferred = preferredEffectReason(scan.effects)
	return scan
}

func (h *Hasher) maximalTestingTypeEffectsFiltered(base *tier2Base, pkgPath string, reachedDecls map[funcDeclKey]bool) (maximalEffectScan, error) {
	if cached, ok := h.maximalTesting[pkgPath]; ok && (reachedDecls == nil || !hasFilterableMaximalBlocker(h.SelectionAudited(), cached.effects)) {
		return cached, nil
	}
	if reachedDecls != nil && h.maximalTestingUnfiltered != nil {
		if cached, ok := h.maximalTestingUnfiltered[pkgPath]; ok && !hasFilterableMaximalBlocker(h.SelectionAudited(), cached.effects) {
			return cached, nil
		}
	}
	scope := ""
	key := ""
	if reachedDecls == nil {
		scope = h.testingScanScope()
		if scope != "" {
			if k, err := h.testBinaryClosureKey(pkgPath); err == nil {
				key = k
				if scan, ok := loadEffectScan(testingScanDirName, scope, key); ok {
					h.Served("testing scan", pkgPath)
					h.maximalTesting[pkgPath] = scan
					return scan, nil
				}
			}
		}
	}
	var loaded []*packages.Package
	if base != nil && base.prog != nil {
		loaded = base.prog.Pkgs
	}
	if len(loaded) == 0 {
		loaded = h.viewLoadVariants(pkgPath)
	}
	if len(loaded) == 0 {
		emitTestingTypeOwnLoadHook(pkgPath)
		h.emitUnit("typecheck", pkgPath, 0, 1)
		if prog := h.progs[pkgPath]; prog != nil {
			loaded = prog.Pkgs
		}
		if len(loaded) == 0 && h.testingPackagesOnMiss != nil {
			if p := h.testingPackagesOnMiss(h, pkgPath); p != nil {
				loaded = p.Pkgs
			}
		}
	}
	if len(loaded) == 0 {
		var err error
		loaded, err = gotool.LoadPackages(
			h.ctx,
			packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedSyntax|packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports|packages.NeedForTest,
			h.dir,
			h.packageEnv,
			h.buildFlags,
			pkgPath,
		)
		if err != nil {
			return maximalEffectScan{}, err
		}
	}
	var scan maximalEffectScan
	var unfilteredScan maximalEffectScan
	trackedChdirSafe := reachedDecls != nil && base.binaryTrackedChdirSafe()
	audited := h.SelectionAudited()
	for _, pkg := range loaded {
		if pkg.PkgPath != pkgPath && pkg.ForTest != pkgPath {
			continue
		}
		for _, packageErr := range pkg.Errors {
			return maximalEffectScan{}, fmt.Errorf("closure: load %s: %s", pkgPath, packageErr)
		}
		for _, file := range pkg.Syntax {
			var unreachedDecls []ast.Node
			if reachedDecls != nil {
				fileDir := filepath.Clean(pkg.Dir)
				if pkg.Fset != nil {
					if tf := pkg.Fset.File(file.Pos()); tf != nil && tf.Name() != "" {
						fileDir = filepath.Clean(filepath.Dir(tf.Name()))
					}
				}
				pkgClause := ""
				if file.Name != nil {
					pkgClause = file.Name.Name
				}
				unreachedDecls = unreachedASTDecls(fileDir, pkgClause, file, nil, reachedDecls)
			}
			inUnreachedDecl := func(node ast.Node) bool {
				for _, d := range unreachedDecls {
					if node.Pos() >= d.Pos() && node.End() <= d.End() {
						return true
					}
				}
				return false
			}
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				var object types.Object
				if selection := pkg.TypesInfo.Selections[selector]; selection != nil {
					object = selection.Obj()
				} else {
					object = pkg.TypesInfo.Uses[selector.Sel]
				}
				if object == nil || object.Pkg() == nil || object.Pkg().Path() != "testing" {
					return true
				}
				effect, ok := classBEffect("testing", object.Name())
				if ok {
					unfilteredScan.add(effect)
					if !inUnreachedDecl(selector) || packageWideMaximalHazardForPkg(audited, effect, false, trackedChdirSafe) {
						scan.add(effect)
					}
				}
				return true
			})
		}
	}
	scan.preferred = preferredEffectReason(scan.effects)
	if reachedDecls == nil {
		if key != "" {
			storeEffectScan(testingScanDirName, scope, key, scan)
			h.persisted.scans++
		}
		h.maximalTesting[pkgPath] = scan
	} else if h.maximalTestingUnfiltered != nil {
		unfilteredScan.preferred = preferredEffectReason(unfilteredScan.effects)
		h.maximalTestingUnfiltered[pkgPath] = unfilteredScan
	}
	return scan, nil
}

func (h *Hasher) pinnedEffectScan(pkg listPkg) (maximalEffectScan, bool, error) {
	return h.pinnedEffectScanWithNames(pkg, nil, "")
}

func (h *Hasher) pinnedEffectScanWithNames(pkg listPkg, declaredNames map[string]string, overridesKey string) (maximalEffectScan, bool, error) {
	return h.pinnedEffectScanWithContext(pkg, declaredNames, nil, overridesKey)
}

func (h *Hasher) pinnedEffectScanWithContext(pkg listPkg, declaredNames map[string]string, nonStdPaths map[string]bool, overridesKey string) (maximalEffectScan, bool, error) {
	if pkg.Module.Version == "" || !h.pinnedPackage(&pkg) || pkg.Module.Dir == "" {
		return maximalEffectScan{}, false, nil
	}
	pin := h.modulePin(pkg.Module)
	key := effectScanKey(pin+overridesKey, pkg.ImportPath, pkg.GoFiles, pkg.CgoFiles)
	composite := maximalPackageExternalEffects(&pkg)
	deriveComposite := func() {
		if selected := preferredEffectReason(append(append([]externalEffect(nil), composite.effects...), composite.importCandidates...)); selected != "" {
			composite.preferred = selected
		}
	}
	if stored, ok := loadEffectScan(effectScanDirName, h.effectScanScope(), key); ok {
		h.Served("effect scan", pkg.ImportPath)
		composite.merge(stored)
		deriveComposite()
		return composite, true, nil
	}
	var fileFold maximalEffectScan
	files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
	for _, name := range files {
		if err := h.contextErr(); err != nil {
			return maximalEffectScan{}, false, err
		}
		scan, err := h.maximalFileEffectsCachedWithContext(pkg.ImportPath, filepath.Join(pkg.Dir, name), declaredNames, nonStdPaths, overridesKey)
		if err != nil {
			return maximalEffectScan{}, false, err
		}
		fileFold.merge(scan)
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), fileFold.effects...), fileFold.importCandidates...)); selected != "" {
		fileFold.preferred = selected
	}
	storeEffectScan(effectScanDirName, h.effectScanScope(), key, fileFold)
	h.persisted.scans++
	composite.merge(fileFold)
	deriveComposite()
	return composite, true, nil
}

func auditedLinknamesOnly(audited bool, text string) bool {
	return auditedLinknamesWithLocals(audited, text, nil)
}

func auditedLinknamesWithLocals(audited bool, text string, verifiedLocals map[string]bool) bool {
	rest := text
	for {
		iLine := strings.Index(rest, "//go:linkname")
		iBlock := strings.Index(rest, "/*go:linkname")
		i := iLine
		if i < 0 || (iBlock >= 0 && iBlock < i) {
			i = iBlock
		}
		if i < 0 {
			return true
		}
		if !audited {
			// The audited targets are claims about runtime/syscall
			// source; an unlisted surface keeps the opaque-linkage
			// floor for every directive-bearing file
			// (REQ-closure-observability-toolchain-key keying clause).
			return false
		}
		var comment string
		if i == iBlock {
			afterOpen := rest[i+2:]
			end := strings.Index(afterOpen, "*/")
			if end < 0 {
				return false
			}
			comment = rest[i : i+2+end+2]
			if strings.ContainsAny(comment, "\r\n") {
				return false
			}
			rest = afterOpen[end+2:]
		} else {
			line := rest[i:]
			if j := strings.IndexByte(line, '\n'); j >= 0 {
				rest = line[j+1:]
				line = line[:j]
			} else {
				rest = ""
			}
			comment = strings.TrimRight(line, " \t\r")
		}
		local, target, matched, valid := parseGoLinknameDirectiveComment(comment)
		if !matched || !valid || target == "" {
			return false
		}
		_, isROVarTarget := auditset.AuditedReadOnlyVarLinknameTarget(target)
		if !auditset.AuditedLinknameTarget(target) && !(len(verifiedLocals) > 0 && verifiedLocals[local] && isROVarTarget) {
			return false
		}
	}
}

// userTestMainDecl returns the file's user TestMain declaration - a
// top-level func TestMain with exactly one parameter of syntactic type
// *testing.M under the file's own testing import alias - or nil.
func userTestMainDecl(file *ast.File, aliases map[string]string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name != "TestMain" || fd.Type == nil || fd.Type.TypeParams != nil || fd.Type.Params == nil || fd.Type.Results != nil {
			continue
		}
		if len(fd.Type.Params.List) != 1 || len(fd.Type.Params.List[0].Names) > 1 {
			continue
		}
		star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		switch x := star.X.(type) {
		case *ast.SelectorExpr:
			pkgIdent, ok := x.X.(*ast.Ident)
			if !ok || x.Sel == nil || x.Sel.Name != "M" || aliases[pkgIdent.Name] != "testing" {
				continue
			}
		case *ast.Ident:
			if x.Name != "M" || aliases["."] != "testing" {
				continue
			}
		default:
			continue
		}
		return fd
	}
	return nil
}
