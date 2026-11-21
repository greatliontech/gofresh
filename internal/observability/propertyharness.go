package observability

import (
	"context"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

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

func propertyHarnessSeededSampleCallee(vp *propharness.VerifiedPackage, callee *ssa.Function) (propharness.MethodKey, bool) {
	if vp == nil || callee == nil || len(vp.SeededSampleMethods) == 0 {
		return propharness.MethodKey{}, false
	}
	methodName := baseFunctionSymbolName(callee)
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
	slice, arr, ok := forEachLocalSliceAllocStore(c.Args[len(c.Args)-1], nil)
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
	if p.summaries.verifiedHarnesses != nil {
		return p.summaries.verifiedHarnesses.byPath
	}
	store := func(byPath map[string]*propharness.VerifiedPackage) map[string]*propharness.VerifiedPackage {
		p.summaries.verifiedHarnesses = &verifiedHarnessesSummary{byPath: byPath}
		return byPath
	}

	var variantsByPath map[string][]*packages.Package
	rejected := map[string]bool{}
	packages.Visit(p.Pkgs, func(pkg *packages.Package) bool {
		if pkg == nil {
			return false
		}
		if pkg.PkgPath == p.PkgPath || pkg.PkgPath == p.PkgPath+"_test" || pkg.ForTest == p.PkgPath ||
			isGeneratedTestMainLoadedPkg(pkg) {
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
				if k.PkgPath == pkgPath {
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
