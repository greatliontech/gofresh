package closure

import (
	"context"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

// A property-testing harness package is summarized at walk and package-scan
// boundaries exactly when mechanical first-principles source verification over
// its selected implementation proves the closed property-harness protocol
// (REQ-closure-observability-property-harness). Candidate screening and
// verification contain zero hardcoded third-party module paths, package names,
// environment/flag prefixes, or symbol names. The summary is sound only paired
// with the boundary gate on every static, interface-invoke, and anonymous
// wrapper call into a verified harness: each dynamic-carrying argument must be
// judged closed, unseeded calls to discovered variadic-seed sample methods
// record an explicit entropy effect, and direct invocations of anonymous
// wrapper closures whose first parameter is a harness handle or logger
// interface require an authentic handed-in handle parameter rather than nil or
// locally synthesized state.

func buildPinnedHarnessMemoKey(frontend, toolchainContent, admissionPolicy, pin string, packageEnv, buildFlags, goFiles []string) string {
	return propharness.BuildPinnedMemoKey(frontend, toolchainContent, admissionPolicy, pin, packageEnv, buildFlags, goFiles)
}

// propertyHarnessFact records the observable non-blocking package-scan fact for
// a mechanically verified property-testing harness dependency: verification
// admits observation (via the harness's TB.Logf-surfaced run configuration),
// never hash-only purity.
func propertyHarnessFact(vp *propharness.VerifiedPackage) externalEffect {
	var pkgPath, sym string
	if vp != nil {
		pkgPath = vp.PkgPath
		sym = vp.PrimaryDriver
	}
	effect := symbolExternalEffect(
		externalEffectTestRuntime,
		pkgPath,
		sym,
		"reaches the audited property-testing harness "+pkgPath,
	)
	effect.observable = true
	return effect
}

func isPropertyHarnessFact(effect externalEffect) bool {
	return effect.kind == externalEffectTestRuntime && effect.observable &&
		effect.packagePath != "" && effect.packagePath != "testing"
}

func listPkgHasNativeOrEmbed(pkg *listPkg) bool {
	if pkg == nil {
		return true
	}
	if hasExternalCgoMeta(pkg) || hasCgoCallbackBlindspot(pkg) {
		return true
	}
	return len(pkg.CgoFiles) > 0 ||
		len(pkg.CFiles) > 0 ||
		len(pkg.CXXFiles) > 0 ||
		len(pkg.MFiles) > 0 ||
		len(pkg.HFiles) > 0 ||
		len(pkg.FFiles) > 0 ||
		len(pkg.SFiles) > 0 ||
		len(pkg.SwigFiles) > 0 ||
		len(pkg.SwigCXXFiles) > 0 ||
		len(pkg.SysoFiles) > 0 ||
		len(pkg.EmbedFiles) > 0 ||
		len(pkg.EmbedPatterns) > 0 ||
		len(pkg.TestEmbedPatterns) > 0 ||
		len(pkg.XTestEmbedPatterns) > 0
}

// verifiedHarness returns the mechanically verified harness descriptor for
// pkgPath in the analyzer's loaded program, or nil when pkgPath is not a
// verified harness dependency.
func (a *tier2Analyzer) verifiedHarness(pkgPath string) *propharness.VerifiedPackage {
	if a == nil || a.h == nil || pkgPath == "" || !propharness.MayBeHarnessPkgPath(pkgPath) {
		return nil
	}
	meta := a.metaByPath[pkgPath]
	if meta == nil || meta.Module == nil || listPkgHasNativeOrEmbed(meta) {
		return nil
	}
	return verifiedHarnessesProg(a.h.SelectionAudited(), a.prog)[pkgPath]
}

func (a *tier2Analyzer) propertyHarnessAudited(pkgPath string) bool {
	return a.verifiedHarness(pkgPath) != nil
}

// propertyHarnessAuditedListPkg evaluates the two-stage property-harness
// screen and mechanical verification for a dependency node in the maximal
// package-scan tier. Stage 0 (propharness.MayBeHarnessImports) rejects
// non-harness dependencies in O(len(pkg.Imports)) with zero allocations before
// touching caches or invoking go/packages.
func (h *Hasher) propertyHarnessAuditedListPkg(callerPkgPath string, pkg *listPkg) *propharness.VerifiedPackage {
	if h == nil || !h.SelectionAudited() || pkg == nil || pkg.Module == nil ||
		pkg.ImportPath == callerPkgPath || pkg.SourcePath() == callerPkgPath {
		return nil
	}
	if listPkgHasNativeOrEmbed(pkg) || !propharness.MayBeHarnessImports(pkg.ImportPath, pkg.Imports) {
		return nil
	}
	cacheKey := pkg.Dir
	if cacheKey == "" {
		cacheKey = "\x00" + callerPkgPath + "\x00" + pkg.ImportPath
	}
	if v, ok := h.harnessVerdict[cacheKey]; ok {
		return v
	}
	recordVerdict := func(v *propharness.VerifiedPackage) *propharness.VerifiedPackage {
		if h.harnessVerdict == nil {
			h.harnessVerdict = make(map[string]*propharness.VerifiedPackage, 1)
		}
		h.harnessVerdict[cacheKey] = v
		return v
	}

	isPinned := pkg.Module.Version != "" && h.pinnedPackage(pkg) && pkg.Module.Dir != ""
	loadCandidates := func() ([]*packages.Package, error) {
		var candidates []*packages.Package
		seenPkg := map[*packages.Package]bool{}
		collectFromRoots := func(roots []*packages.Package) {
			if len(roots) == 0 {
				return
			}
			packages.Visit(roots, func(p *packages.Package) bool {
				if p == nil {
					return false
				}
				if p.PkgPath == pkg.ImportPath && p.ForTest == "" && len(p.Syntax) > 0 && p.Types != nil && p.TypesInfo != nil {
					if !seenPkg[p] {
						seenPkg[p] = true
						candidates = append(candidates, p)
					}
				}
				return true
			}, nil)
		}

		if h.viewLoad != nil {
			collectFromRoots(h.viewLoad.Packages())
		}
		if len(candidates) == 0 {
			if p := h.progs[callerPkgPath]; p != nil {
				collectFromRoots(p.Pkgs)
			}
		}
		if len(candidates) == 0 {
			if p := h.progs[pkg.ImportPath]; p != nil {
				collectFromRoots(p.Pkgs)
			}
		}
		if len(candidates) == 0 {
			for _, p := range h.progs {
				if p != nil {
					collectFromRoots(p.Pkgs)
				}
				if len(candidates) > 0 {
					break
				}
			}
		}
		if len(candidates) == 0 && h.testingPackagesOnMiss != nil {
			if p := h.testingPackagesOnMiss(h, callerPkgPath); p != nil {
				collectFromRoots(p.Pkgs)
			}
			if len(candidates) == 0 {
				if p := h.testingPackagesOnMiss(h, pkg.ImportPath); p != nil {
					collectFromRoots(p.Pkgs)
				}
			}
		}
		if len(candidates) == 0 {
			loadDir := h.dir
			pattern := pkg.ImportPath
			if isPinned && pkg.Dir != "" {
				loadDir = pkg.Dir
				pattern = "."
			}
			loaded, err := gotool.LoadPackages(
				h.ctx,
				packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedEmbedFiles|packages.NeedEmbedPatterns|packages.NeedSyntax|packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports|packages.NeedModule|packages.NeedForTest,
				loadDir,
				h.packageEnv,
				h.buildFlags,
				pattern,
			)
			if err != nil {
				return nil, err
			}
			collectFromRoots(loaded)
		}
		return candidates, nil
	}

	if isPinned {
		pinnedKey := buildPinnedHarnessMemoKey(
			AnalyzingFrontend(),
			h.ToolchainContent(),
			h.AdmissionPolicy(),
			h.modulePin(pkg.Module)+"\x00"+pkg.ImportPath,
			h.packageEnv,
			h.buildFlags,
			pkg.GoFiles,
		)
		return recordVerdict(propharness.VerifyPackagePinnedCached(h.ctx, trace.DomainClosure, true, pinnedKey, loadCandidates))
	}

	cands, err := loadCandidates()
	if err != nil || len(cands) == 0 {
		return recordVerdict(nil)
	}
	var verified *propharness.VerifiedPackage
	for _, cand := range cands {
		vp, _ := propharness.VerifyPackageWithIndex(h.ctx, trace.DomainClosure, true, cand, nil)
		if vp == nil {
			return recordVerdict(nil)
		}
		verified = vp
	}
	return recordVerdict(verified)
}

func propertyHarnessSeededSampleCallee(vp *propharness.VerifiedPackage, callee *ssa.Function) (propharness.MethodKey, bool) {
	if vp == nil || callee == nil || len(vp.SeededSampleMethods) == 0 {
		return propharness.MethodKey{}, false
	}
	methodName := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
	var recvNamed *types.Named
	if callee.Signature != nil && callee.Signature.Recv() != nil {
		recvNamed = namedOriginDeref(callee.Signature.Recv().Type())
	}
	if recvNamed == nil {
		fnObj, _ := callee.Object().(*types.Func)
		if fnObj == nil && callee.Origin() != nil {
			fnObj, _ = callee.Origin().Object().(*types.Func)
		}
		if fnObj != nil && fnObj.Signature() != nil && fnObj.Signature().Recv() != nil {
			recvNamed = namedOriginDeref(fnObj.Signature().Recv().Type())
		} else if callee.Signature != nil && callee.Signature.Params().Len() > 0 && strings.HasPrefix(callee.Synthetic, "thunk ") {
			recvNamed = namedOriginDeref(callee.Signature.Params().At(0).Type())
		}
	}
	if recvNamed == nil || recvNamed.Obj() == nil {
		return propharness.MethodKey{}, false
	}
	mk := propharness.MethodKey{Recv: recvNamed.Obj().Name(), Method: methodName}
	return mk, vp.SeededSampleMethods[mk]
}

func harnessSeededSampleHasExplicitSeed(c *ssa.CallCommon) bool {
	if c == nil || c.IsInvoke() {
		return false
	}
	callee := c.StaticCallee()
	if callee == nil || callee.Signature == nil || !callee.Signature.Variadic() || len(c.Args) == 0 {
		return false
	}
	slice, arr, ok := forEachLocalSliceAllocStore(c.Args[len(c.Args)-1], false, nil)
	if !ok || arr == nil || arr.Len() < 1 {
		return false
	}
	low := int64(0)
	if slice.Low != nil {
		v, ok := constInt(slice.Low)
		if !ok || v < 0 {
			return false
		}
		low = v
	}
	high := arr.Len()
	if slice.High != nil {
		v, ok := constInt(slice.High)
		if !ok || v > arr.Len() {
			return false
		}
		high = v
	}
	return high-low >= 1
}

func propertyHarnessUnseededSampleEffect(vp *propharness.VerifiedPackage, mk propharness.MethodKey) externalEffect {
	var pkgPath string
	if vp != nil {
		pkgPath = vp.PkgPath
	}
	qualSym := mk.Recv + "." + mk.Method
	return symbolExternalEffect(
		externalEffectNative,
		pkgPath,
		qualSym,
		"reaches "+pkgPath+"."+qualSym+" without an explicit seed (entropy)",
	)
}

func propertyHarnessClosedResult(call *ssa.Call, fp *freshParamAnalysis) bool {
	if fp == nil || len(fp.verifiedHarnesses) == 0 || call == nil || call.Common() == nil || call.Common().IsInvoke() {
		return false
	}
	callee := call.Common().StaticCallee()
	if callee == nil {
		return false
	}
	vp := fp.verifiedHarnesses[funcPkgPath(callee)]
	if vp == nil {
		return false
	}
	if _, isSample := propertyHarnessSeededSampleCallee(vp, callee); isSample && !harnessSeededSampleHasExplicitSeed(call.Common()) {
		return false
	}
	return propertyHarnessClosedArgs(call.Common(), fp)
}

type verifiedHarnessesSummary struct {
	byPath map[string]*propharness.VerifiedPackage
}

// verifiedHarnessesProg returns the map of dependency package paths in p that
// pass mechanical property-harness verification across every loaded variant
// with zero non-SSA global, assembly, native, or linkname hazards.
func verifiedHarnessesProg(audited bool, p *program) map[string]*propharness.VerifiedPackage {
	if !audited || p == nil || len(p.Pkgs) == 0 {
		return nil
	}
	cacheKey := propharness.PinnedMemoKeyPrefix + "verified"
	if p.Summaries != nil {
		if cached, ok := p.Summaries[cacheKey].(verifiedHarnessesSummary); ok {
			return cached.byPath
		}
	}
	store := func(byPath map[string]*propharness.VerifiedPackage) map[string]*propharness.VerifiedPackage {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		p.Summaries[cacheKey] = verifiedHarnessesSummary{byPath: byPath}
		return byPath
	}

	var variantsByPath map[string][]*packages.Package
	rejected := map[string]bool{}
	packages.Visit(p.Pkgs, func(pkg *packages.Package) bool {
		if pkg == nil {
			return false
		}
		if pkg.PkgPath == p.PkgPath || pkg.PkgPath == p.PkgPath+"_test" || pkg.ForTest == p.PkgPath ||
			(pkg.Name == "main" && pkg.PkgPath == p.PkgPath+".test") {
			return true
		}
		if rejected[pkg.PkgPath] {
			return true
		}
		if !propharness.MayBeHarnessPackage(pkg) {
			if variantsByPath != nil && variantsByPath[pkg.PkgPath] != nil {
				delete(variantsByPath, pkg.PkgPath)
				rejected[pkg.PkgPath] = true
			}
			return true
		}
		if variantsByPath == nil {
			variantsByPath = make(map[string][]*packages.Package, 2)
		}
		variantsByPath[pkg.PkgPath] = append(variantsByPath[pkg.PkgPath], pkg)
		return true
	}, nil)

	if len(variantsByPath) == 0 {
		return store(nil)
	}

	haz := nonSSAGlobalHazardsSummary(audited, p)
	var out map[string]*propharness.VerifiedPackage
	for pkgPath, variants := range variantsByPath {
		if haz != nil {
			if haz.blockedPkgs[pkgPath] || haz.verifiedAsm[pkgPath] != nil {
				continue
			}
			hasLinkname := false
			for k := range haz.linknamedVars {
				if k.pkgPath == pkgPath {
					hasLinkname = true
					break
				}
			}
			if hasLinkname {
				continue
			}
		}
		var verified *propharness.VerifiedPackage
		allOK := true
		for _, cand := range variants {
			vp, _ := propharness.VerifyPackageWithIndex(context.Background(), trace.DomainClosure, audited, cand, nil)
			if vp == nil {
				allOK = false
				break
			}
			verified = vp
		}
		if allOK && verified != nil {
			if out == nil {
				out = make(map[string]*propharness.VerifiedPackage, len(variantsByPath))
			}
			out[pkgPath] = verified
		}
	}
	return store(out)
}

func harnessPkgSet(verified map[string]*propharness.VerifiedPackage) map[string]bool {
	if len(verified) == 0 {
		return nil
	}
	out := make(map[string]bool, len(verified))
	for k := range verified {
		out[k] = true
	}
	return out
}
