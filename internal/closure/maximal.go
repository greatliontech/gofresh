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

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cprep"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
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
	defer h.DropCallBuffers()
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
	return hex.EncodeToString(sum[:16])
}

// maximalEffectsResult memoizes one package's complete external-effect scan
// within a Hasher: the scan depends only on the package's listed sources, so
// every subject sharing the package shares one scan.
type maximalEffectsResult struct {
	effects  []ExternalEffect
	selected string
}

// PackageGraphWalkOptions configures WalkPackageGraphEffects when filtering
// package-scan effects against Tier-2 reachability, startup-zero globals,
// verified property harnesses, assembly, linknames, and confined unsafe/chdir.
type PackageGraphWalkOptions struct {
	Filtered               bool
	LoadedPackages         []*packages.Package
	VerifiedHarnesses      map[string]*propharness.VerifiedPackage
	TrackedChdirSafe       bool
	AsmAdmitted            func(pkg *gotool.ListedPackage) bool
	PkgScopeShadowed       func(srcPath string) map[string]bool
	VerifiedLinknameLocals func(srcPath string) map[string]bool
	PkgConfinedUnsafe      func(importID, srcPath string) bool
	ReachedDecls           map[FuncDeclKey]bool
	StartupOnlyDecls       map[FuncDeclKey]bool
	StartupZeroGlobalDecls map[PkgVarKey]bool
	WholeZeroGlobalDecls   map[PkgVarKey]bool
}

func filterScanForTier1ReadBuildInfo(scan MaximalEffectScan) MaximalEffectScan {
	if len(scan.Effects) == 0 {
		return scan
	}
	var filtered []ExternalEffect
	removed := false
	for _, e := range scan.Effects {
		if e.Kind == ExternalEffectUnauditedStandard && e.PackagePath == "runtime/debug" && e.Symbol == "ReadBuildInfo" {
			removed = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !removed {
		return scan
	}
	scan.Effects = filtered
	scan.Preferred = PreferredEffectReason(append(append([]ExternalEffect(nil), scan.Effects...), scan.ImportCandidates...))
	if scan.Preferred == "" {
		scan.Preferred = "reaches runtime/debug (potential external dependence)"
	}
	return scan
}

// WalkPackageGraphEffects walks pkgPath's non-standard dependency graph and
// collects conservative or declaration/zero-global-filtered external effects.
func (h *Hasher) WalkPackageGraphEffects(pkgPath string, opts PackageGraphWalkOptions) ([]ExternalEffect, string, error) {
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, "", err
	}
	basePkgName := ""
	if !opts.Filtered {
		for _, p := range pkgs {
			if p.ImportPath == pkgPath && p.ForTest == "" {
				basePkgName = p.Name
				break
			}
		}
	}
	admitTier1ReadBuildInfo := !opts.Filtered && h.admitsTier1ReadBuildInfo(pkgPath, basePkgName)

	var effects []ExternalEffect
	var candidates []ExternalEffect
	var fallback string
	record := func(scan MaximalEffectScan) {
		if admitTier1ReadBuildInfo {
			scan = filterScanForTier1ReadBuildInfo(scan)
		}
		for _, effect := range scan.Effects {
			effects = AppendExternalEffect(effects, effect)
			if !opts.Filtered {
				candidates = AppendExternalEffect(candidates, effect)
			}
		}
		if !opts.Filtered {
			for _, candidate := range scan.ImportCandidates {
				candidates = AppendExternalEffect(candidates, candidate)
			}
			if len(scan.Effects) == 0 && len(scan.ImportCandidates) == 0 && scan.Preferred != "" && (fallback == "" || scan.Preferred < fallback) {
				fallback = scan.Preferred
			}
		}
	}

	testingEffects, err := h.maximalTestingTypeEffectsFiltered(opts, pkgPath)
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
		if opts.Filtered {
			if !ListPkgHasNativeOrEmbed(&pkg) && len(opts.VerifiedHarnesses) > 0 {
				if vp := opts.VerifiedHarnesses[pkg.ImportPath]; vp != nil {
					record(MaximalEffectScan{Effects: []ExternalEffect{PropertyHarnessFact(vp)}})
					continue
				}
			}
		} else if vp := h.propertyHarnessAuditedListPkg(pkgPath, &pkg); vp != nil {
			record(MaximalEffectScan{Effects: []ExternalEffect{PropertyHarnessFact(vp)}})
			continue
		}

		srcPath := pkg.SourcePath()
		pkgHasZeroGlobals := opts.Filtered && (hasPkgZeroGlobals(opts.StartupZeroGlobalDecls, srcPath) || hasPkgZeroGlobals(opts.WholeZeroGlobalDecls, srcPath))
		if scan, ok, err := h.pinnedEffectScanWithContext(pkg, declaredNames, nonStdPaths, overridesKey); err != nil {
			return nil, "", err
		} else if ok && (!opts.Filtered || (!HasFilterableMaximalBlocker(audited, scan.Effects) && !(pkgHasZeroGlobals && HasAnyMaximalBlocker(audited, scan.Effects)))) {
			record(scan)
			continue
		}

		if opts.Filtered {
			record(filteredPackageExternalEffects(opts.AsmAdmitted, &pkg))
		} else {
			record(maximalPackageExternalEffects(&pkg))
		}

		var pkgScopeShadowed, verifiedLinknameLocals map[string]bool
		pkgConfinedUnsafe := false
		trackedChdirSafe := false
		if opts.Filtered {
			if opts.PkgScopeShadowed != nil {
				pkgScopeShadowed = opts.PkgScopeShadowed(srcPath)
			}
			if opts.VerifiedLinknameLocals != nil {
				verifiedLinknameLocals = opts.VerifiedLinknameLocals(srcPath)
			}
			if opts.ReachedDecls != nil && opts.PkgConfinedUnsafe != nil {
				pkgConfinedUnsafe = opts.PkgConfinedUnsafe(pkg.ImportPath, srcPath)
			}
			trackedChdirSafe = opts.ReachedDecls != nil && opts.TrackedChdirSafe
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
			if !opts.Filtered || (!HasFilterableMaximalBlocker(audited, unfiltered.Effects) && !(pkgHasZeroGlobals && HasAnyMaximalBlocker(audited, unfiltered.Effects))) {
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
			scan := maximalFileEffectsParsed(audited, parsed, nonStdPaths, opts.ReachedDecls, opts.StartupOnlyDecls, srcPath, opts.StartupZeroGlobalDecls, opts.WholeZeroGlobalDecls, pkgScopeShadowed, verifiedLinknameLocals, pkgConfinedUnsafe, trackedChdirSafe)
			record(scan)
		}
	}
	if !opts.Filtered {
		h.flushFileMemos()
		selected := PreferredEffectReason(candidates)
		if selected == "" {
			selected = fallback
		}
		return effects, selected, nil
	}
	return effects, "", nil
}

// MaximalExternalEffects returns pkgPath's complete unfiltered external-effect
// scan. The returned effects slice aliases h's memo and must be treated as read-only.
func (h *Hasher) MaximalExternalEffects(pkgPath string) ([]ExternalEffect, string, error) {
	return h.maximalExternalEffects(pkgPath)
}

func (h *Hasher) maximalExternalEffects(pkgPath string) ([]ExternalEffect, string, error) {
	if cached, ok := h.maximalEffects[pkgPath]; ok {
		return cached.effects, cached.selected, nil
	}
	effects, selected, err := h.WalkPackageGraphEffects(pkgPath, PackageGraphWalkOptions{})
	if err != nil {
		return nil, "", err
	}
	h.maximalEffects[pkgPath] = maximalEffectsResult{effects: effects, selected: selected}
	return effects, selected, nil
}

// maximalFileEffectsCached memoizes one file's effect scan within a Hasher
// and serves it from the persistent per-file memo under the file's content digest.
func (h *Hasher) maximalFileEffectsCached(pkgPath, path string) (MaximalEffectScan, error) {
	return h.maximalFileEffectsCachedWithNames(pkgPath, path, nil, "")
}

func (h *Hasher) maximalFileEffectsCachedWithNames(pkgPath, path string, declaredNames map[string]string, overridesKey string) (MaximalEffectScan, error) {
	return h.maximalFileEffectsCachedWithContext(pkgPath, path, declaredNames, nil, overridesKey)
}

func (h *Hasher) maximalFileEffectsCachedWithContext(pkgPath, path string, declaredNames map[string]string, nonStdPaths map[string]bool, overridesKey string) (MaximalEffectScan, error) {
	cacheKey := path + overridesKey
	if scan, ok := h.maximalFiles[cacheKey]; ok {
		return scan, nil
	}
	dir := filepath.Dir(path)
	if h.underCache(dir) {
		content, err := os.ReadFile(path)
		if err != nil {
			return MaximalEffectScan{}, err
		}
		parsed, err := h.parsedMaximalFile(path, content, declaredNames, nonStdPaths, overridesKey)
		if err != nil {
			return MaximalEffectScan{}, err
		}
		scan := maximalFileEffectsParsed(h.SelectionAudited(), parsed, nonStdPaths, nil, nil, "", nil, nil, nil, nil, false, false)
		h.maximalFiles[cacheKey] = scan
		return scan, nil
	}
	fb, err := h.readFile(path)
	if err != nil {
		return MaximalEffectScan{}, err
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
		return MaximalEffectScan{}, err
	}
	scan := maximalFileEffectsParsed(h.SelectionAudited(), parsed, nonStdPaths, nil, nil, "", nil, nil, nil, nil, false, false)
	h.recordFileScan(dir, digestKey, scan)
	h.maximalFiles[cacheKey] = scan
	return scan, nil
}

func (h *Hasher) maximalTestingTypeEffects(pkgPath string) (MaximalEffectScan, error) {
	return h.maximalTestingTypeEffectsFiltered(PackageGraphWalkOptions{}, pkgPath)
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

func filteredPackageExternalEffects(asmAdmitted func(*listPkg) bool, pkg *listPkg) MaximalEffectScan {
	scan := maximalPackageExternalEffects(pkg)
	if asmAdmitted != nil && asmAdmitted(pkg) {
		filtered := scan.Effects[:0]
		for _, e := range scan.Effects {
			if e.Detail == "reaches non-standard assembly" || e.Detail == "reaches cgo or native source" {
				continue
			}
			filtered = append(filtered, e)
		}
		scan.Effects = filtered
		scan.Preferred = PreferredEffectReason(scan.Effects)
	}
	return scan
}

func maximalPackageExternalEffects(pkg *listPkg) MaximalEffectScan {
	var scan MaximalEffectScan
	if HasExternalCgoMeta(pkg) {
		effect := OpaqueExternalEffect(ExternalEffectNative, "reaches cgo external library")
		effect.Unrefinable = true
		scan.Add(effect)
	}
	if pkg != nil && len(pkg.SysoFiles) != 0 {
		effect := OpaqueExternalEffect(ExternalEffectNative, "reaches non-standard system object")
		effect.Unrefinable = true
		scan.Add(effect)
	}
	if pkg != nil && pkg.HasCgoCallbackBlindspot() {
		scan.Add(OpaqueExternalEffect(ExternalEffectNative, "reaches cgo or native source"))
	}
	if pkg != nil && len(pkg.SFiles) != 0 {
		scan.Add(OpaqueExternalEffect(ExternalEffectNative, "reaches non-standard assembly"))
	}
	scan.Preferred = PreferredEffectReason(scan.Effects)
	return scan
}

func (h *Hasher) maximalTestingTypeEffectsFiltered(opts PackageGraphWalkOptions, pkgPath string) (MaximalEffectScan, error) {
	reachedDecls := opts.ReachedDecls
	if cached, ok := h.maximalTesting[pkgPath]; ok && (reachedDecls == nil || !HasFilterableMaximalBlocker(h.SelectionAudited(), cached.Effects)) {
		return cached, nil
	}
	if reachedDecls != nil && h.maximalTestingUnfiltered != nil {
		if cached, ok := h.maximalTestingUnfiltered[pkgPath]; ok && !HasFilterableMaximalBlocker(h.SelectionAudited(), cached.Effects) {
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
	loaded := opts.LoadedPackages
	if len(loaded) == 0 {
		loaded = h.viewLoadVariants(pkgPath)
	}
	if len(loaded) == 0 {
		emitTestingTypeOwnLoadHook(pkgPath)
		h.emitUnit("typecheck", pkgPath, 0, 1)
		if h.loadedPackages != nil {
			loaded = h.loadedPackages(pkgPath)
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
			return MaximalEffectScan{}, err
		}
	}
	var scan MaximalEffectScan
	var unfilteredScan MaximalEffectScan
	trackedChdirSafe := reachedDecls != nil && opts.TrackedChdirSafe
	audited := h.SelectionAudited()
	for _, pkg := range loaded {
		if pkg.PkgPath != pkgPath && pkg.ForTest != pkgPath {
			continue
		}
		for _, packageErr := range pkg.Errors {
			return MaximalEffectScan{}, fmt.Errorf("closure: load %s: %s", pkgPath, packageErr)
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
				unreachedDecls = UnreachedASTDecls(fileDir, pkgClause, file, nil, reachedDecls)
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
				effect, ok := ClassBEffect("testing", object.Name())
				if ok {
					unfilteredScan.Add(effect)
					if !inUnreachedDecl(selector) || PackageWideMaximalHazardForPkg(audited, effect, false, trackedChdirSafe) {
						scan.Add(effect)
					}
				}
				return true
			})
		}
	}
	scan.Preferred = PreferredEffectReason(scan.Effects)
	if reachedDecls == nil {
		if key != "" {
			storeEffectScan(testingScanDirName, scope, key, scan)
			h.persisted.scans++
		}
		h.maximalTesting[pkgPath] = scan
	} else if h.maximalTestingUnfiltered != nil {
		unfilteredScan.Preferred = PreferredEffectReason(unfilteredScan.Effects)
		h.maximalTestingUnfiltered[pkgPath] = unfilteredScan
	}
	return scan, nil
}

func (h *Hasher) pinnedEffectScan(pkg listPkg) (MaximalEffectScan, bool, error) {
	return h.pinnedEffectScanWithNames(pkg, nil, "")
}

func (h *Hasher) pinnedEffectScanWithNames(pkg listPkg, declaredNames map[string]string, overridesKey string) (MaximalEffectScan, bool, error) {
	return h.pinnedEffectScanWithContext(pkg, declaredNames, nil, overridesKey)
}

func (h *Hasher) pinnedEffectScanWithContext(pkg listPkg, declaredNames map[string]string, nonStdPaths map[string]bool, overridesKey string) (MaximalEffectScan, bool, error) {
	if pkg.Module.Version == "" || !h.pinnedPackage(&pkg) || pkg.Module.Dir == "" {
		return MaximalEffectScan{}, false, nil
	}
	pin := h.modulePin(pkg.Module)
	key := effectScanKey(pin+overridesKey, pkg.ImportPath, pkg.GoFiles, pkg.CgoFiles)
	composite := maximalPackageExternalEffects(&pkg)
	deriveComposite := func() {
		if selected := PreferredEffectReason(append(append([]ExternalEffect(nil), composite.Effects...), composite.ImportCandidates...)); selected != "" {
			composite.Preferred = selected
		}
	}
	if stored, ok := loadEffectScan(effectScanDirName, h.effectScanScope(), key); ok {
		h.Served("effect scan", pkg.ImportPath)
		composite.Merge(stored)
		deriveComposite()
		return composite, true, nil
	}
	var fileFold MaximalEffectScan
	files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
	for _, name := range files {
		if err := h.contextErr(); err != nil {
			return MaximalEffectScan{}, false, err
		}
		scan, err := h.maximalFileEffectsCachedWithContext(pkg.ImportPath, filepath.Join(pkg.Dir, name), declaredNames, nonStdPaths, overridesKey)
		if err != nil {
			return MaximalEffectScan{}, false, err
		}
		fileFold.Merge(scan)
	}
	if selected := PreferredEffectReason(append(append([]ExternalEffect(nil), fileFold.Effects...), fileFold.ImportCandidates...)); selected != "" {
		fileFold.Preferred = selected
	}
	storeEffectScan(effectScanDirName, h.effectScanScope(), key, fileFold)
	h.persisted.scans++
	composite.Merge(fileFold)
	deriveComposite()
	return composite, true, nil
}

// AuditedLinknamesOnly reports whether every //go:linkname or /*go:linkname*/
// directive in text names an audited standard target.
func AuditedLinknamesOnly(audited bool, text string) bool {
	return auditedLinknamesWithLocals(audited, text, nil)
}

func auditedLinknamesOnly(audited bool, text string) bool {
	return AuditedLinknamesOnly(audited, text)
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
		local, target, matched, valid := cprep.ParseGoLinknameDirectiveComment(comment)
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
