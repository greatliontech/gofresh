package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/refconfine"
)

const verifiedUserSentinelGlobalsSummaryKey = "gofresh/user-sentinel-globals@1"

type globalOpClass uint8

const (
	globalOpDebugRef globalOpClass = iota
	globalOpDirectLoad
	globalOpDirectStore
	globalOpEscapeOrMutate
)

func classifyGlobalOperand(instr ssa.Instruction, g *ssa.Global) (globalOpClass, *ssa.Store) {
	switch r := instr.(type) {
	case *ssa.DebugRef:
		return globalOpDebugRef, nil
	case *ssa.UnOp:
		if r.Op == token.MUL && r.X == g {
			return globalOpDirectLoad, nil
		}
		return globalOpEscapeOrMutate, nil
	case *ssa.Store:
		if r.Addr == g && r.Val != g {
			return globalOpDirectStore, r
		}
		return globalOpEscapeOrMutate, nil
	default:
		return globalOpEscapeOrMutate, nil
	}
}

type programGlobalAccumulator struct {
	nonReadOnly   map[*ssa.Global]bool
	mutated       map[*ssa.Global]bool
	errType       types.Type
	errPoisoned   map[*ssa.Global]bool
	errInitStores map[*ssa.Global]int
	trackZero     bool
	userPaths     map[string]bool
	zeroSeen      map[*ssa.Global]bool
	nonZero       map[*ssa.Global]bool
}

func newProgramGlobalAccumulator(trackSentinel, trackZero bool, userPaths map[string]bool) *programGlobalAccumulator {
	acc := &programGlobalAccumulator{
		nonReadOnly: make(map[*ssa.Global]bool),
		mutated:     make(map[*ssa.Global]bool),
		trackZero:   trackZero,
		userPaths:   userPaths,
	}
	if trackSentinel {
		acc.errType = types.Universe.Lookup("error").Type()
		acc.errPoisoned = make(map[*ssa.Global]bool)
		acc.errInitStores = make(map[*ssa.Global]int)
	}
	if trackZero {
		acc.zeroSeen = make(map[*ssa.Global]bool)
		acc.nonZero = make(map[*ssa.Global]bool)
	}
	return acc
}

func (acc *programGlobalAccumulator) record(fn *ssa.Function, initFrame bool, instr ssa.Instruction, g *ssa.Global) {
	if g == nil {
		return
	}
	opClass, store := classifyGlobalOperand(instr, g)
	if opClass == globalOpDebugRef {
		return
	}
	if opClass != globalOpDirectLoad {
		acc.nonReadOnly[g] = true
	}
	if !acc.mutated[g] {
		switch opClass {
		case globalOpDirectLoad:
		case globalOpDirectStore:
			if fn.Pkg != g.Pkg || !initFrame {
				acc.mutated[g] = true
			}
		default:
			acc.mutated[g] = true
		}
	}
	if acc.trackZero && !isStdNonUserFunction(fn, acc.userPaths) && g.Pkg != nil && g.Pkg.Pkg != nil {
		pkgPath := g.Pkg.Pkg.Path()
		if !isStdImportPath(pkgPath) || acc.userPaths[pkgPath] {
			acc.zeroSeen[g] = true
			if !acc.nonZero[g] {
				switch opClass {
				case globalOpDirectLoad:
				case globalOpDirectStore:
					if !isZeroSSAConst(store.Val) {
						acc.nonZero[g] = true
					}
				default:
					acc.nonZero[g] = true
				}
			}
		}
	}
	if acc.errPoisoned != nil && !acc.errPoisoned[g] && g.Pkg != nil && g.Pkg.Pkg != nil {
		if ptr, ok := types.Unalias(g.Type()).(*types.Pointer); ok && types.Identical(ptr.Elem(), acc.errType) {
			switch opClass {
			case globalOpDirectLoad:
			case globalOpDirectStore:
				if fn != g.Pkg.Func("init") {
					acc.errPoisoned[g] = true
				} else if call, ok := store.Val.(*ssa.Call); !ok || call.Common() == nil {
					acc.errPoisoned[g] = true
				} else if callee := call.Common().StaticCallee(); callee == nil || funcPkgPath(callee) != "errors" || callee.Name() != "New" {
					acc.errPoisoned[g] = true
				} else {
					acc.errInitStores[g]++
					if acc.errInitStores[g] > 1 {
						acc.errPoisoned[g] = true
					}
				}
			default:
				acc.errPoisoned[g] = true
			}
		}
	}
}

func (acc *programGlobalAccumulator) errorSentinels() map[*ssa.Global]bool {
	out := make(map[*ssa.Global]bool, len(acc.errInitStores))
	for g, count := range acc.errInitStores {
		if count == 1 && !acc.errPoisoned[g] {
			out[g] = true
		}
	}
	return out
}

func (acc *programGlobalAccumulator) zeroCandidates() map[*ssa.Global]bool {
	out := make(map[*ssa.Global]bool)
	for g := range acc.zeroSeen {
		if !acc.nonZero[g] {
			out[g] = true
		}
	}
	return out
}

func scanProgramGlobals(ordered []*ssa.Function, trackSentinel, trackZero bool, userPaths map[string]bool) *programGlobalAccumulator {
	acc := newProgramGlobalAccumulator(trackSentinel, trackZero, userPaths)
	var ops [16]*ssa.Value
	for _, fn := range ordered {
		if fn == nil {
			continue
		}
		initFrame := initFlowFrame(fn)
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, isDbg := instr.(*ssa.DebugRef); isDbg {
					continue
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op != nil && *op != nil {
						if g, ok := (*op).(*ssa.Global); ok {
							acc.record(fn, initFrame, instr, g)
						}
					}
				}
			}
		}
	}
	return acc
}

func lookupWholeProgramSummary(p *program) *callerReferenceSummary {
	if p == nil {
		return nil
	}
	if s := lookupSummaryForProg(p, true); s != nil && s.wholeProgram {
		return s
	}
	if s := lookupSummaryForProg(p, false); s != nil && s.wholeProgram {
		return s
	}
	return nil
}

func nonReadOnlySSAGlobals(p *program) map[*ssa.Global]bool {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries[nonReadOnlyGlobalsSummaryKey].(map[*ssa.Global]bool); ok && cached != nil {
			return cached
		}
	}
	if summary := lookupWholeProgramSummary(p); summary != nil && summary.nonReadOnlyGlobals != nil {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 2)
		}
		p.Summaries[nonReadOnlyGlobalsSummaryKey] = summary.nonReadOnlyGlobals
		return summary.nonReadOnlyGlobals
	}
	acc := scanProgramGlobals(progOrderedFunctions(p), false, false, nil)
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[nonReadOnlyGlobalsSummaryKey] = acc.nonReadOnly
	if p.MutatedGlobals == nil {
		p.MutatedGlobals = acc.mutated
	}
	return acc.nonReadOnly
}

func ssaGlobalStrictlyReadOnly(p *program, g *ssa.Global) bool {
	if p == nil || g == nil || g.Pkg == nil {
		return false
	}
	return !nonReadOnlySSAGlobals(p)[g]
}

func mutatedGlobalsForProgram(p *program, ssaProg *ssa.Program) map[*ssa.Global]bool {
	if p != nil && p.Prog == ssaProg {
		if p.MutatedGlobals != nil {
			return p.MutatedGlobals
		}
		if summary := lookupWholeProgramSummary(p); summary != nil && summary.mutatedGlobals != nil {
			p.MutatedGlobals = summary.mutatedGlobals
			return p.MutatedGlobals
		}
		acc := scanProgramGlobals(progOrderedFunctions(p), false, false, nil)
		p.MutatedGlobals = acc.mutated
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 2)
		}
		if _, ok := p.Summaries[nonReadOnlyGlobalsSummaryKey]; !ok {
			p.Summaries[nonReadOnlyGlobalsSummaryKey] = acc.nonReadOnly
		}
		return p.MutatedGlobals
	}
	if ssaProg == nil {
		return nil
	}
	all := ssautil.AllFunctions(ssaProg)
	return scanProgramGlobals(orderedFunctionsForProgram(all), false, false, nil).mutated
}

func verifiedUserSentinelGlobals(audited bool, p *program) map[*ssa.Global]bool {
	if !audited || p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries[verifiedUserSentinelGlobalsSummaryKey].(map[*ssa.Global]bool); ok && cached != nil {
			return cached
		}
	}
	blockedPkgs, linknamedVars := nonSSAGlobalHazards(audited, p)
	var rawCandidates map[*ssa.Global]bool
	if summary := lookupSummaryForProg(p, audited); summary != nil && summary.wholeProgram && summary.errorNewSentinelGlobals != nil {
		rawCandidates = summary.errorNewSentinelGlobals
	} else {
		rawCandidates = scanProgramGlobals(progOrderedFunctions(p), true, false, nil).errorSentinels()
	}
	verified := make(map[*ssa.Global]bool, len(rawCandidates))
	for g := range rawCandidates {
		if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
			continue
		}
		pkgPath := g.Pkg.Pkg.Path()
		if blockedPkgs[pkgPath] || linknamedVars[pkgVarKey{pkgPath: pkgPath, name: g.Name()}] {
			continue
		}
		verified[g] = true
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[verifiedUserSentinelGlobalsSummaryKey] = verified
	return verified
}

func isUnmutatedSentinelGlobal(audited bool, p *program, userPaths map[string]bool, g *ssa.Global) bool {
	if !audited || p == nil || g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || g.Pkg.Prog != p.Prog {
		return false
	}
	pkgPath := g.Pkg.Pkg.Path()
	if isStdPkgPath(userPaths, pkgPath) && !isInternalStdPackagePath(pkgPath) {
		return false
	}
	return verifiedUserSentinelGlobals(audited, p)[g]
}

func isUnmutatedStandardSentinelGlobalAny(p *program, g *ssa.Global) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
		return false
	}
	pkgPath := g.Pkg.Pkg.Path()
	if !auditset.StandardSentinelGlobal(pkgPath, g.Name()) {
		return false
	}
	return isUnmutatedStandardSentinelGlobal(p, g, pkgPath, g.Name())
}

func isUnmutatedStandardSentinelGlobal(p *program, g *ssa.Global, wantPkg, wantName string) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || g.Pkg.Prog == nil || g.Pkg.Pkg.Path() != wantPkg || g.Name() != wantName {
		return false
	}
	return !mutatedGlobalsForProgram(p, g.Pkg.Prog)[g]
}

func sentinelGlobalConcreteTypes(g *ssa.Global, out map[types.Type]bool) bool {
	if g == nil || g.Pkg == nil {
		return false
	}
	if ptr, ok := types.Unalias(g.Type()).(*types.Pointer); ok {
		if _, isIface := ptr.Elem().Underlying().(*types.Interface); !isIface {
			out[ptr.Elem()] = true
			return true
		}
	}
	initFn := g.Pkg.Func("init")
	if initFn == nil {
		return false
	}
	found := false
	for _, b := range initFn.Blocks {
		for _, instr := range b.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok || store.Addr != g {
				continue
			}
			if mi, ok := store.Val.(*ssa.MakeInterface); ok && mi.X != nil {
				out[mi.X.Type()] = true
				found = true
			} else if call, ok := store.Val.(*ssa.Call); ok && call.Common() != nil {
				if callee := call.Common().StaticCallee(); callee != nil {
					for _, cb := range callee.Blocks {
						for _, cinstr := range cb.Instrs {
							if ret, ok := cinstr.(*ssa.Return); ok && len(ret.Results) == 1 {
								if mi, ok := ret.Results[0].(*ssa.MakeInterface); ok && mi.X != nil {
									out[mi.X.Type()] = true
									found = true
								}
							}
						}
					}
				}
			}
		}
	}
	return found
}

func (fp *freshParamAnalysis) stdTypeMayDelegateDynamic(t types.Type) bool {
	if t == nil {
		return true
	}
	audited := fp != nil && fp.selectionAudited
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return true
	}
	if _, ok := refconfine.AuditedAtomicPointerElem(audited, named); ok {
		return true
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return true
	}
	pkgPath := named.Obj().Pkg().Path()
	if !isStdPkgPath(fp.userPkgPaths(), pkgPath) {
		return true
	}
	if fp.isAuditedStandardOrDelegate(pkgPath) {
		return true
	}
	switch pkgPath {
	case "context", "math/rand", "net/url", "sync":
		return true
	default:
		return false
	}
}

type nonSSAGlobalHazardSummary struct {
	blockedPkgs          map[string]bool
	linknamedVars        map[pkgVarKey]bool
	linknamesByTarget    map[string][]pkgVarKey
	hasMalformedLinkname bool
	allPkgs              []*packages.Package
	allPkgsByPath        map[string][]*packages.Package
	verifiedAsm          map[string]*asmverify.VerifiedPackage
}

func classifyOtherNativeExt(ext string) (isAsm bool, isCAsmHeader bool, isOtherNative bool) {
	if ext == ".s" {
		return true, false, false
	}
	switch strings.ToLower(ext) {
	case ".h":
		return false, true, false
	case ".s", ".sx", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".f", ".for", ".f90", ".syso", ".swig", ".swigcxx":
		return false, false, true
	default:
		return false, false, false
	}
}

func mergeVerifiedAsmPackage(prev, cur *asmverify.VerifiedPackage) *asmverify.VerifiedPackage {
	if prev == nil {
		return cur
	}
	if cur == nil {
		return prev
	}
	mergedFuncs := make(map[string]asmverify.TextSummary, len(prev.Funcs)+len(cur.Funcs))
	for k, v := range prev.Funcs {
		mergedFuncs[k] = v
	}
	for k, v := range cur.Funcs {
		old, exists := mergedFuncs[k]
		if !exists {
			mergedFuncs[k] = v
			continue
		}
		if !old.Verified || !v.Verified {
			imp := old.ImpureKind
			if v.ImpureKind != "" && (imp == "" || v.ImpureKind < imp) {
				imp = v.ImpureKind
			}
			mergedFuncs[k] = asmverify.TextSummary{Verified: false, ImpureKind: imp}
			continue
		}
		impure := old.ImpureKind
		if v.ImpureKind != "" && (impure == "" || v.ImpureKind < impure) {
			impure = v.ImpureKind
		}
		cpuidArgs := old.CPUIDArgs
		if cpuidArgs != v.CPUIDArgs {
			cpuidArgs = 0
			if impure == "" && (old.CPUIDArgs > 0 || v.CPUIDArgs > 0) {
				impure = "per-core CPUID register"
			}
		}
		if impure != "" {
			cpuidArgs = 0
		}
		ext := slices.Clone(old.ExternalSBRefs)
		for _, r := range v.ExternalSBRefs {
			if !slices.Contains(ext, r) {
				ext = append(ext, r)
			}
		}
		goCallees := slices.Clone(old.GoCallees)
		for _, gc := range v.GoCallees {
			if !slices.Contains(goCallees, gc) {
				goCallees = append(goCallees, gc)
			}
		}
		slices.Sort(goCallees)
		mergedFuncs[k] = asmverify.TextSummary{
			Verified:       true,
			CPUIDArgs:      cpuidArgs,
			ImpureKind:     impure,
			ExternalSBRefs: ext,
			GoCallees:      goCallees,
		}
	}
	rodata := slices.Clone(prev.RodataGoNames)
	for _, gn := range cur.RodataGoNames {
		if !slices.Contains(rodata, gn) {
			rodata = append(rodata, gn)
		}
	}
	return &asmverify.VerifiedPackage{
		PackageSafe:      prev.PackageSafe && cur.PackageSafe,
		AllTextsVerified: prev.AllTextsVerified && cur.AllTextsVerified,
		Funcs:            mergedFuncs,
		RodataGoNames:    rodata,
	}
}

func nonSSAGlobalHazards(audited bool, p *program) (map[string]bool, map[pkgVarKey]bool) {
	sum := nonSSAGlobalHazardsSummary(audited, p)
	if sum == nil {
		return nil, nil
	}
	return sum.blockedPkgs, sum.linknamedVars
}

func nonSSAGlobalHazardsSummary(audited bool, p *program) *nonSSAGlobalHazardSummary {
	if p == nil || len(p.Pkgs) == 0 {
		return nil
	}
	cacheKey := "nonSSAGlobalHazards:unaudited"
	if audited {
		cacheKey = "nonSSAGlobalHazards:audited"
	}
	if cached, ok := p.Summaries[cacheKey].(*nonSSAGlobalHazardSummary); ok && cached != nil {
		return cached
	}
	scopesByPath := map[string][]*types.Package{}
	allPkgsByPath := map[string][]*packages.Package{}
	var allVisited []*packages.Package
	visited := map[*packages.Package]bool{}
	var collectPkgs func(pkg *packages.Package)
	collectPkgs = func(pkg *packages.Package) {
		if pkg == nil || visited[pkg] {
			return
		}
		visited[pkg] = true
		for _, imp := range pkg.Imports {
			collectPkgs(imp)
		}
		if pkg.PkgPath == "" || (pkg.Module == nil && isStdImportPath(pkg.PkgPath)) {
			return
		}
		allVisited = append(allVisited, pkg)
		allPkgsByPath[pkg.PkgPath] = append(allPkgsByPath[pkg.PkgPath], pkg)
		if pkg.Types != nil {
			scopesByPath[pkg.PkgPath] = append(scopesByPath[pkg.PkgPath], pkg.Types)
		}
	}
	for _, root := range p.Pkgs {
		collectPkgs(root)
	}

	blocked := map[string]bool{}
	hardUnsafeNative := map[string]bool{}
	linknamed := map[pkgVarKey]bool{}
	linknamesByTarget := map[string][]pkgVarKey{}
	hasMalformedLinkname := false
	verifiedAsm := map[string]*asmverify.VerifiedPackage{}
	for _, pkg := range allVisited {
		if pkg.Imports["runtime/cgo"] != nil || pkg.Imports["C"] != nil {
			blocked[pkg.PkgPath] = true
			hardUnsafeNative[pkg.PkgPath] = true
		}
		var sFiles, hFiles []string
		hasNonAsmNative := false
		for _, f := range pkg.OtherFiles {
			isAsm, isHdr, isOther := classifyOtherNativeExt(filepath.Ext(f))
			switch {
			case isAsm:
				sFiles = append(sFiles, f)
			case isHdr:
				hFiles = append(hFiles, f)
			case isOther:
				hasNonAsmNative = true
			}
		}
		if hasNonAsmNative || (len(hFiles) > 0 && len(sFiles) == 0) {
			blocked[pkg.PkgPath] = true
			hardUnsafeNative[pkg.PkgPath] = true
		} else if len(sFiles) > 0 {
			scopes := scopesByPath[pkg.PkgPath]
			readFn := os.ReadFile
			if p.ReadSource != nil {
				pkgDir := pkg.Dir
				readFn = func(fullPath string) ([]byte, error) {
					return p.ReadSource(pkgDir, fullPath)
				}
			}
			if !audited || p.GOARCH == "" || pkg.Dir == "" || (len(pkg.GoFiles) > 0 && len(scopes) == 0) {
				blocked[pkg.PkgPath] = true
				hardUnsafeNative[pkg.PkgPath] = true
			} else if vp, asmSafe := verifyNonStdAssemblyMemo(p, p.GOARCH, pkg.PkgPath, pkg.Dir, sFiles, hFiles, scopes, readFn); !asmSafe || vp == nil || !vp.PackageSafe {
				blocked[pkg.PkgPath] = true
				hardUnsafeNative[pkg.PkgPath] = true
			} else {
				if !vp.AllTextsVerified {
					blocked[pkg.PkgPath] = true
				}
				if !hardUnsafeNative[pkg.PkgPath] {
					verifiedAsm[pkg.PkgPath] = mergeVerifiedAsmPackage(verifiedAsm[pkg.PkgPath], vp)
				}
			}
		}
		for _, af := range pkg.Syntax {
			if af == nil {
				continue
			}
			forEachGoLinknameDirective(af.Comments, func(local, target string, valid bool) {
				if !valid {
					blocked[pkg.PkgPath] = true
					hardUnsafeNative[pkg.PkgPath] = true
					hasMalformedLinkname = true
					return
				}
				localKey := pkgVarKey{pkgPath: pkg.PkgPath, name: local}
				linknamed[localKey] = true
				if target != "" {
					dot := strings.LastIndexByte(target, '.')
					linknamed[pkgVarKey{pkgPath: target[:dot], name: target[dot+1:]}] = true
					if !slices.Contains(linknamesByTarget[target], localKey) {
						linknamesByTarget[target] = append(linknamesByTarget[target], localKey)
					}
				}
			})
		}
	}
	for pkgPath := range hardUnsafeNative {
		delete(verifiedAsm, pkgPath)
	}
	summary := &nonSSAGlobalHazardSummary{
		blockedPkgs:          blocked,
		linknamedVars:        linknamed,
		linknamesByTarget:    linknamesByTarget,
		hasMalformedLinkname: hasMalformedLinkname,
		allPkgs:              allVisited,
		allPkgsByPath:        allPkgsByPath,
		verifiedAsm:          verifiedAsm,
	}
	for pkgPath, vp := range verifiedAsm {
		if vp == nil {
			continue
		}
		for fnName, sum := range vp.Funcs {
			if !sum.Verified || !progAsmTextLinkageClean(summary, p, pkgPath, fnName, sum.GoCallees) {
				blocked[pkgPath] = true
				break
			}
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[cacheKey] = summary
	return summary
}

func startupZeroGlobalsForReach(base *tier2Base, reach attributedReachability) map[*ssa.Global]bool {
	audited := base != nil && base.h != nil && base.h.SelectionAudited()
	if reach.baseStartup && base != nil {
		if !base.baseStartupZeroDone {
			base.baseStartupZeroGlobals = filterBaseVerifiedZeroGlobals(base, unmutatedZeroGlobalsForFunctions(audited, base.prog, reach.userPaths, startupInitFunctions(reach)))
			base.baseStartupZeroDone = true
		}
		return base.baseStartupZeroGlobals
	}
	return filterBaseVerifiedZeroGlobals(base, unmutatedZeroGlobalsForFunctions(audited, base.prog, reach.userPaths, startupInitFunctions(reach)))
}

func wholeZeroGlobalsForBase(base *tier2Base, userPaths map[string]bool) map[*ssa.Global]bool {
	if base == nil || base.prog == nil {
		return nil
	}
	if !base.wholeZeroDone {
		audited := base.h != nil && base.h.SelectionAudited()
		if summary := lookupSummaryForProg(base.prog, audited); summary != nil && summary.wholeProgram && summary.zeroCandidateGlobals != nil {
			blockedPkgs, linknamedVars := nonSSAGlobalHazards(audited, base.prog)
			var candidates map[*ssa.Global]bool
			for g := range summary.zeroCandidateGlobals {
				if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
					continue
				}
				pkgPath := g.Pkg.Pkg.Path()
				if blockedPkgs[pkgPath] || linknamedVars[pkgVarKey{pkgPath: pkgPath, name: g.Name()}] {
					continue
				}
				if candidates == nil {
					candidates = make(map[*ssa.Global]bool, len(summary.zeroCandidateGlobals))
				}
				candidates[g] = true
			}
			base.wholeZeroGlobals = filterBaseVerifiedZeroGlobals(base, candidates)
		} else {
			base.wholeZeroGlobals = filterBaseVerifiedZeroGlobals(base, unmutatedZeroGlobalsForFunctions(audited, base.prog, userPaths, progAllFunctions(base.prog)))
		}
		base.wholeZeroDone = true
	}
	return base.wholeZeroGlobals
}

func (b *tier2Base) pkgFreeOfUnverifiedNativeWriteHazard(idx *pkgIndex) bool {
	if b == nil || idx == nil || idx.std || idx.meta == nil {
		return false
	}
	if hasExternalCgoMeta(idx.meta) || len(idx.meta.SysoFiles) != 0 || hasNonHeaderNativeSource(idx.meta) {
		return false
	}
	if len(idx.meta.SFiles) > 0 {
		if _, asmOK := b.verifiedPackageAssemblyAllTexts(idx.meta); !asmOK {
			return false
		}
	} else if len(idx.meta.HFiles) > 0 {
		return false
	}
	return true
}

func filterBaseVerifiedZeroGlobals(base *tier2Base, zeroGlobals map[*ssa.Global]bool) map[*ssa.Global]bool {
	if base == nil || len(zeroGlobals) == 0 {
		return zeroGlobals
	}
	var out map[*ssa.Global]bool
	for g := range zeroGlobals {
		if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
			continue
		}
		pkgPath := g.Pkg.Pkg.Path()
		if len(base.objsByLinkTarget[pkgPath+"."+g.Name()]) > 0 {
			continue
		}
		idx := base.idxByTypes[g.Pkg.Pkg]
		if !base.pkgFreeOfUnverifiedNativeWriteHazard(idx) {
			continue
		}
		if idx.linknameByName[g.Name()] != "" {
			continue
		}
		if obj := g.Object(); obj != nil && idx.linknames[obj] != "" {
			continue
		}
		if out == nil {
			out = make(map[*ssa.Global]bool, len(zeroGlobals))
		}
		out[g] = true
	}
	return out
}

func zeroGlobalDeclKeys(zeroGlobals map[*ssa.Global]bool) map[pkgVarKey]bool {
	if len(zeroGlobals) == 0 {
		return nil
	}
	out := make(map[pkgVarKey]bool, len(zeroGlobals))
	for g := range zeroGlobals {
		if g != nil && g.Pkg != nil && g.Pkg.Pkg != nil && g.Name() != "" {
			out[pkgVarKey{pkgPath: g.Pkg.Pkg.Path(), name: g.Name()}] = true
		}
	}
	return out
}

func isZeroSSAConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	if !ok {
		return false
	}
	if c.Value == nil {
		return true
	}
	switch c.Value.Kind() {
	case constant.Bool:
		return !constant.BoolVal(c.Value)
	case constant.Int, constant.Float, constant.Complex:
		return constant.Sign(c.Value) == 0
	case constant.String:
		return constant.StringVal(c.Value) == ""
	default:
		return false
	}
}

// unmutatedZeroGlobalsForFunctions identifies non-standard package-level
// globals that are referenced in the given reachable function sets (including
// their package initializers) exclusively through direct loads (*g) or zero
// stores, and are free of non-SSA write channels (cgo, unverified assembly, or
// //go:linkname). Because Go zero-initializes package variables and lowers
// package-level initializer expressions into init(), any global with no
// non-zero store and no address escape in the reachable flow is invariant zero
// throughout that flow.
func unmutatedZeroGlobalsForFunctions(audited bool, p *program, userPaths map[string]bool, sets ...map[*ssa.Function]bool) map[*ssa.Global]bool {
	blockedPkgs, linknamedVars := nonSSAGlobalHazards(audited, p)
	seen := map[*ssa.Global]bool{}
	mutated := map[*ssa.Global]bool{}
	visitedFn := map[*ssa.Function]bool{}
	visitedPkgInit := map[*ssa.Package]bool{}
	var ops [16]*ssa.Value
	var scanFn func(fn *ssa.Function)
	scanFn = func(fn *ssa.Function) {
		if fn == nil || visitedFn[fn] || isStdNonUserFunction(fn, userPaths) {
			return
		}
		visitedFn[fn] = true
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, ok := instr.(*ssa.DebugRef); ok {
					continue
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok || g.Pkg == nil || g.Pkg.Pkg == nil {
						continue
					}
					pkgPath := g.Pkg.Pkg.Path()
					if isStdImportPath(pkgPath) && !userPaths[pkgPath] {
						continue
					}
					if blockedPkgs[pkgPath] || linknamedVars[pkgVarKey{pkgPath: pkgPath, name: g.Name()}] {
						mutated[g] = true
						continue
					}
					seen[g] = true
					switch opClass, store := classifyGlobalOperand(instr, g); opClass {
					case globalOpDirectLoad:
					case globalOpDirectStore:
						if !isZeroSSAConst(store.Val) {
							mutated[g] = true
						}
					default:
						mutated[g] = true
					}
				}
			}
		}
	}
	scanPkgInit := func(pkg *ssa.Package) {
		if pkg == nil || visitedPkgInit[pkg] {
			return
		}
		visitedPkgInit[pkg] = true
		initFn := pkg.Func("init")
		if initFn == nil {
			return
		}
		initQueue := []*ssa.Function{initFn}
		seenInit := map[*ssa.Function]bool{initFn: true}
		enqueueInit := func(fn *ssa.Function) {
			if fn == nil || seenInit[fn] || isStdNonUserFunction(fn, userPaths) {
				return
			}
			seenInit[fn] = true
			initQueue = append(initQueue, fn)
		}
		for len(initQueue) > 0 {
			cur := initQueue[0]
			initQueue = initQueue[1:]
			scanFn(cur)
			for _, blk := range cur.Blocks {
				for _, instr := range blk.Instrs {
					if mc, ok := instr.(*ssa.MakeClosure); ok {
						if closureFn, _ := mc.Fn.(*ssa.Function); closureFn != nil {
							enqueueInit(closureFn)
						}
					}
					if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
						if callee := site.Common().StaticCallee(); callee != nil {
							enqueueInit(callee)
						}
					}
				}
			}
		}
	}
	for _, set := range sets {
		for fn := range set {
			if isStdNonUserFunction(fn, userPaths) {
				continue
			}
			scanFn(fn)
			if fn != nil {
				scanPkgInit(fn.Pkg)
			}
		}
	}
	for g := range seen {
		scanPkgInit(g.Pkg)
	}
	var out map[*ssa.Global]bool
	for g := range seen {
		if !mutated[g] {
			if out == nil {
				out = make(map[*ssa.Global]bool)
			}
			out[g] = true
		}
	}
	return out
}

func rtaUnmutatedZeroGlobals(audited bool, p *program, result *rta.Result, mask uint64, userPaths map[string]bool) map[*ssa.Global]bool {
	if result == nil || len(result.Reachable) == 0 {
		return nil
	}
	var funcs map[*ssa.Function]bool
	for fn, masks := range result.Reachable {
		if masks&mask != 0 && !isStdNonUserFunction(fn, userPaths) {
			if funcs == nil {
				funcs = make(map[*ssa.Function]bool)
			}
			funcs[fn] = true
		}
	}
	if len(funcs) == 0 {
		return nil
	}
	return unmutatedZeroGlobalsForFunctions(audited, p, userPaths, funcs)
}
