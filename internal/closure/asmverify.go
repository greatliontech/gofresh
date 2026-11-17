package closure

import (
	"context"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/trace"
)

const verifiedNonStdAsmMemoSummaryKey = "gofresh/verified-nonstd-asm@5"

func sortedCleanBasenamesKey(files []string) string {
	if len(files) == 0 {
		return ""
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(filepath.Clean(f))
	}
	slices.Sort(names)
	return strings.Join(names, "\x00")
}

func verifyNonStdAssemblyMemo(p *program, goarch, pkgPath, dir string, sFiles, hFiles []string, typeScopes []*types.Package, read func(string) ([]byte, error)) (*asmverify.VerifiedPackage, bool) {
	memoKey := goarch + "\x00" + pkgPath + "\x00" + filepath.Clean(dir) + "\x00" + sortedCleanBasenamesKey(sFiles) + "\x00|\x00" + sortedCleanBasenamesKey(hFiles)
	if p != nil && p.Summaries != nil {
		if memoMap, ok := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*asmverify.VerifiedPackage); ok {
			if cached, found := memoMap[memoKey]; found && cached != nil {
				if !cached.PackageSafe || !asmverify.CheckVerifiedTypeScopes(cached, typeScopes) {
					return &asmverify.VerifiedPackage{}, false
				}
				return cached, true
			}
		}
	}
	vp, ok := asmverify.VerifyNonStdFiles(goarch, pkgPath, dir, sFiles, hFiles, typeScopes, read)
	if !ok || vp == nil {
		vp = &asmverify.VerifiedPackage{}
	}
	if p != nil {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		memoMap, _ := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*asmverify.VerifiedPackage)
		if memoMap == nil {
			memoMap = make(map[string]*asmverify.VerifiedPackage, 4)
			p.Summaries[verifiedNonStdAsmMemoSummaryKey] = memoMap
		}
		memoMap[memoKey] = vp
	}
	if !vp.PackageSafe || !asmverify.CheckVerifiedTypeScopes(vp, typeScopes) {
		return &asmverify.VerifiedPackage{}, false
	}
	return vp, true
}

func (b *tier2Base) verifiedPackageAssembly(pkg *listPkg) (*asmverify.VerifiedPackage, bool) {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkg == nil || len(pkg.SFiles) == 0 {
		return nil, false
	}
	if hasExternalCgoMeta(pkg) || len(pkg.SysoFiles) != 0 || hasNonHeaderNativeSource(pkg) {
		return nil, false
	}
	key := pkg.ImportPath + "\x00" + filepath.Clean(pkg.Dir)
	if b.verifiedAsm != nil {
		if cached, ok := b.verifiedAsm[key]; ok {
			return cached, cached.PackageSafe
		}
	}
	var typeScopes []*types.Package
	srcPath := pkg.SourcePath()
	for tp, idx := range b.idxByTypes {
		if tp != nil && idx != nil && (idx.path == srcPath || idx.path == pkg.ImportPath || (idx.meta != nil && idx.meta.Dir == pkg.Dir)) {
			typeScopes = append(typeScopes, tp)
		}
	}
	if len(pkg.GoFiles) > 0 && len(typeScopes) == 0 {
		if b.verifiedAsm == nil {
			b.verifiedAsm = make(map[string]*asmverify.VerifiedPackage, 4)
		}
		res := &asmverify.VerifiedPackage{}
		b.verifiedAsm[key] = res
		return res, false
	}
	readFn := func(fullPath string) ([]byte, error) {
		if b.h.underCache(pkg.Dir) {
			return os.ReadFile(fullPath)
		}
		fb, err := b.h.readFile(fullPath)
		if err != nil {
			return nil, err
		}
		return fb.content, nil
	}
	var start time.Time
	tracing := trace.Enabled(context.Background(), trace.DomainClosure, srcPath)
	if tracing {
		start = time.Now()
	}
	res, ok := verifyNonStdAssemblyMemo(b.prog, b.h.effectiveGOARCH(), srcPath, pkg.Dir, pkg.SFiles, pkg.HFiles, typeScopes, readFn)
	if !ok || res == nil {
		res = &asmverify.VerifiedPackage{}
	}
	if tracing {
		trace.Emit(context.Background(), trace.DomainClosure, "asmverify.package.done", srcPath,
			trace.Bool("ok", res.PackageSafe && res.AllTextsVerified),
			trace.Bool("package_safe", res.PackageSafe),
			trace.Bool("all_texts_verified", res.AllTextsVerified),
			trace.Int("sfiles", len(pkg.SFiles)),
			trace.Int("hfiles", len(pkg.HFiles)),
			trace.Int("funcs", len(res.Funcs)),
			trace.Int64("duration_ns", time.Since(start).Nanoseconds()),
		)
	}
	if b.verifiedAsm == nil {
		b.verifiedAsm = make(map[string]*asmverify.VerifiedPackage, 4)
	}
	b.verifiedAsm[key] = res
	return res, res.PackageSafe
}

func (b *tier2Base) verifiedPackageAssemblyAllTexts(pkg *listPkg) (*asmverify.VerifiedPackage, bool) {
	vp, safe := b.verifiedPackageAssembly(pkg)
	if !safe || vp == nil || !vp.AllTextsVerified {
		return vp, false
	}
	for fnName, sum := range vp.Funcs {
		if !b.isAsmTextLinkageClean(pkg, fnName, sum.GoCallees) {
			return vp, false
		}
	}
	return vp, true
}

func (a *tier2Analyzer) verifiedPackageAssemblySafe(pkg *listPkg) bool {
	if a == nil || a.base == nil {
		return false
	}
	_, safe := a.base.verifiedPackageAssembly(pkg)
	return safe
}

func (b *tier2Base) verifiedPackageAssemblyFunc(pkg *listPkg, fn *ssa.Function) (asmverify.TextSummary, []*types.Var, bool) {
	if b == nil || fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.TypeParams().Len() > 0 {
		return asmverify.TextSummary{}, nil, false
	}
	if !asmverify.SignatureCarrierFree(fn.Signature) {
		return asmverify.TextSummary{}, nil, false
	}
	vp, safe := b.verifiedPackageAssembly(pkg)
	if !safe || vp == nil {
		return asmverify.TextSummary{}, nil, false
	}
	sum, found := vp.Funcs[fn.Name()]
	if !found || !sum.Verified || !b.isAsmTextLinkageClean(pkg, fn.Name(), sum.GoCallees) {
		return asmverify.TextSummary{}, nil, false
	}
	var depVars []*types.Var
	for _, ref := range sum.ExternalSBRefs {
		vars, refOK := b.classifyAsmExternalGlobal(ref)
		if !refOK {
			return asmverify.TextSummary{}, nil, false
		}
		depVars = append(depVars, vars...)
	}
	if sum.CPUIDArgs > 0 && !asmverify.IsCanonicalCPUIDSignature(fn.Signature, sum.CPUIDArgs) {
		sum.CPUIDArgs = 0
		if sum.ImpureKind == "" {
			sum.ImpureKind = "per-core CPUID register"
		}
	}
	return sum, depVars, true
}

func (a *tier2Analyzer) verifiedPackageAssemblyFunc(pkg *listPkg, fn *ssa.Function) (asmverify.TextSummary, []*types.Var, bool) {
	if a == nil || a.base == nil {
		return asmverify.TextSummary{}, nil, false
	}
	return a.base.verifiedPackageAssemblyFunc(pkg, fn)
}

func (b *tier2Base) binaryUnverifiedAsmReason(candidates []*pkgIndex) string {
	if b == nil || b.prog == nil {
		return ""
	}
	for _, idx := range candidates {
		if idx == nil || idx.meta == nil || len(idx.meta.SFiles) == 0 {
			continue
		}
		vp, safe := b.verifiedPackageAssembly(idx.meta)
		if !safe || vp == nil {
			continue
		}
		// Any unverified TEXT, undischarged ExternalSBRef, or carrier-bearing Go
		// assembly stub in a package-safe package requires single-subject execution
		// so neither a sibling subject in PackageExecution nor another package in
		// GeneralExecution can execute that unverified assembly in the same process.
		hasUnverified := !vp.AllTextsVerified
		if !hasUnverified {
			for fnName, sum := range vp.Funcs {
				if !b.isAsmTextLinkageClean(idx.meta, fnName, sum.GoCallees) {
					hasUnverified = true
					break
				}
				for _, ref := range sum.ExternalSBRefs {
					if _, refOK := b.classifyAsmExternalGlobal(ref); !refOK {
						hasUnverified = true
						break
					}
				}
				if hasUnverified {
					break
				}
			}
		}
		if !hasUnverified && idx.ssa != nil {
			for _, mem := range idx.ssa.Members {
				if fn, isFn := mem.(*ssa.Function); isFn && len(fn.Blocks) == 0 && fn.Synthetic == "" && !parameterizedBody(fn) {
					if _, _, ok := b.verifiedPackageAssemblyFunc(idx.meta, fn); !ok {
						hasUnverified = true
						break
					}
				}
			}
		}
		if hasUnverified {
			return "package scan: reaches unverified non-standard assembly in " + idx.path
		}
	}
	return ""
}

func (a *tier2Analyzer) scanVerifiedAsmBodylessFunction(fn *ssa.Function, idx *pkgIndex, isRoot bool) {
	if a == nil || fn == nil || idx == nil || idx.std || idx.meta == nil || len(idx.meta.SFiles) == 0 || len(fn.Blocks) != 0 {
		return
	}
	sum, depVars, ok := a.verifiedPackageAssemblyFunc(idx.meta, fn)
	if !ok {
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
		return
	}
	for _, v := range depVars {
		a.enqueueObject(v)
	}
	fnName := functionSymbolName(fn)
	if sum.ImpureKind != "" {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" ("+sum.ImpureKind+")"))
		return
	}
	if sum.CPUIDArgs > 0 && isRoot {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" (per-core CPUID register)"))
	}
}

func (a *tier2Analyzer) classifyVerifiedAsmCallee(callee *ssa.Function, calleeIdx *pkgIndex, c *ssa.CallCommon, site ssa.CallInstruction) (externalEffect, bool) {
	if callee == nil || calleeIdx == nil || calleeIdx.meta == nil || len(calleeIdx.meta.SFiles) == 0 {
		return externalEffect{}, false
	}
	sum, _, ok := a.verifiedPackageAssemblyFunc(calleeIdx.meta, callee)
	if !ok {
		a.requestWiden("non-toolchain assembly in " + calleeIdx.id)
		return opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"), true
	}
	fnName := functionSymbolName(callee)
	if sum.ImpureKind != "" {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" ("+sum.ImpureKind+")"), true
	}
	if sum.CPUIDArgs > 0 && asmverify.CPUIDCallReadsPerCoreState(c, site) {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" (per-core CPUID register)"), true
	}
	return externalEffect{}, false
}

func (b *tier2Base) isVerifiedReadOnlyLinknameVar(idx *pkgIndex, obj types.Object, target string) bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || idx == nil || obj == nil {
		return false
	}
	wantKind, ok := auditset.AuditedReadOnlyVarLinknameTarget(target)
	if !ok {
		return false
	}
	checkOne := func(pIdx *pkgIndex, pObj types.Object) bool {
		if pIdx == nil || pObj == nil || pIdx.ssa == nil {
			return false
		}
		v, ok := pObj.(*types.Var)
		if !ok || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return false
		}
		basic, ok := v.Type().Underlying().(*types.Basic)
		if !ok || basic.Kind() != wantKind {
			return false
		}
		if !b.pkgFreeOfUnverifiedNativeWriteHazard(pIdx) {
			return false
		}
		if g := pIdx.ssa.Var(v.Name()); g == nil || !ssaGlobalStrictlyReadOnly(b.prog, g) {
			return false
		}
		if pIdx.pkg != nil && !astPackageVarReadOnly(pIdx.pkg, v, false) {
			return false
		}
		if v.Exported() {
			for _, otherIdx := range b.idxByTypes {
				if otherIdx != nil && otherIdx != pIdx && otherIdx.pkg != nil && !astPackageVarReadOnly(otherIdx.pkg, v, false) {
					return false
				}
			}
		}
		return true
	}
	if !checkOne(idx, obj) {
		return false
	}
	for _, peer := range b.objsByLinkTarget[target] {
		if peer == obj {
			continue
		}
		if peer == nil || peer.Pkg() == nil {
			return false
		}
		peerIdx := b.idxByTypes[peer.Pkg()]
		if peerIdx != nil && peerIdx.std {
			continue
		}
		if !checkOne(peerIdx, peer) {
			return false
		}
	}
	return true
}

func (b *tier2Base) verifiedReadOnlyLinknameLocals(pkgPath string) map[string]bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkgPath == "" {
		return nil
	}
	var out map[string]bool
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.path != pkgPath {
			continue
		}
		for obj, target := range idx.linknames {
			if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
				if out == nil {
					out = make(map[string]bool, 2)
				}
				out[obj.Name()] = true
			}
		}
		if idx.pkg != nil && idx.pkg.Types != nil && idx.pkg.Types.Scope() != nil {
			for name, target := range idx.linknameByName {
				obj := idx.pkg.Types.Scope().Lookup(name)
				if obj == nil {
					continue
				}
				if docTarget := idx.linknames[obj]; docTarget != "" && docTarget != target {
					delete(out, name)
					continue
				}
				if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
					if out == nil {
						out = make(map[string]bool, 2)
					}
					out[name] = true
				}
			}
		}
	}
	return out
}
