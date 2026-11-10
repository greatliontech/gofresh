package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
)

type pkgVarKey struct {
	pkgPath string
	name    string
}

func isStdNonUserFunction(fn *ssa.Function, userPaths map[string]bool) bool {
	if fn == nil {
		return true
	}
	pkg := fn.Pkg
	if pkg == nil && fn.Origin() != nil {
		pkg = fn.Origin().Pkg
	}
	if pkg == nil || pkg.Pkg == nil {
		return false
	}
	path := pkg.Pkg.Path()
	return isStdImportPath(path) && !userPaths[path]
}

func startupInitFunctions(reach attributedReachability) map[*ssa.Function]bool {
	if len(reach.startupFunctions) == 0 {
		return nil
	}
	if len(reach.cleanupFunctions) == 0 {
		return reach.startupFunctions
	}
	var out map[*ssa.Function]bool
	for fn := range reach.startupFunctions {
		if isStdNonUserFunction(fn, reach.userPaths) {
			continue
		}
		if !reach.cleanupFunctions[fn] {
			if out == nil {
				out = make(map[*ssa.Function]bool)
			}
			out[fn] = true
		}
	}
	return out
}

func isImmediateSyncMakeClosureCall(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil || site.Common().IsInvoke() {
		return false
	}
	if _, isGo := site.(*ssa.Go); isGo {
		return false
	}
	mc, ok := site.Common().Value.(*ssa.MakeClosure)
	if !ok || mc == nil || mc.Referrers() == nil {
		return false
	}
	for _, ref := range *mc.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Call, *ssa.Defer:
			c := r.(ssa.CallInstruction).Common()
			if c == nil || c.IsInvoke() || c.Value != mc {
				return false
			}
			for _, arg := range c.Args {
				if arg == mc {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func asyncOrDynamicStartupFunctions(reach attributedReachability) map[*ssa.Function]bool {
	if len(reach.startupFunctions) == 0 {
		return nil
	}
	var queue []*ssa.Function
	marked := map[*ssa.Function]bool{}
	enqueue := func(fn *ssa.Function) {
		if fn != nil && !marked[fn] && reach.startupFunctions[fn] {
			marked[fn] = true
			queue = append(queue, fn)
		}
	}
	for site, targets := range reach.startupDynamicTargets {
		if site == nil || !reach.startupFunctions[site.Parent()] || isImmediateSyncMakeClosureCall(site) {
			continue
		}
		for target := range targets {
			enqueue(target)
		}
	}
	for fn := range reach.startupFunctions {
		if fn == nil {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				goSite, ok := instr.(*ssa.Go)
				if !ok || goSite.Common() == nil {
					continue
				}
				if callee := goSite.Common().StaticCallee(); callee != nil {
					enqueue(callee)
				}
				for target := range reach.startupDynamicTargets[goSite] {
					enqueue(target)
				}
			}
		}
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil {
					enqueue(callee)
				}
				for target := range reach.startupDynamicTargets[site] {
					enqueue(target)
				}
			}
		}
	}
	return marked
}

func asyncOrDynamicStartupFunctionsForBase(base *tier2Base, reach attributedReachability) map[*ssa.Function]bool {
	if reach.baseStartup && base != nil {
		if !base.baseStartupAsyncDone {
			base.baseStartupAsyncOrDyn = asyncOrDynamicStartupFunctions(reach)
			base.baseStartupAsyncDone = true
		}
		return base.baseStartupAsyncOrDyn
	}
	return asyncOrDynamicStartupFunctions(reach)
}

func syncStartupOnlyFunctions(reach attributedReachability) map[*ssa.Function]bool {
	return syncStartupOnlyFunctionsForBase(nil, reach)
}

func syncStartupOnlyFunctionsForBase(base *tier2Base, reach attributedReachability) map[*ssa.Function]bool {
	if len(reach.startupFunctions) == 0 {
		return nil
	}
	asyncOrDyn := asyncOrDynamicStartupFunctionsForBase(base, reach)
	var out map[*ssa.Function]bool
	for fn := range reach.startupFunctions {
		if isStdNonUserFunction(fn, reach.userPaths) {
			continue
		}
		if !asyncOrDyn[fn] && !reach.cleanupFunctions[fn] && !reach.subjectFunctions[fn] && !reach.testMainFunctions[fn] && !reach.rootedExtraFunctions[fn] {
			if out == nil {
				out = make(map[*ssa.Function]bool)
			}
			out[fn] = true
		}
	}
	return out
}

func computeRTAAsyncStartupFunctions(result *rta.Result, mask uint64, userPaths map[string]bool) map[*ssa.Function]bool {
	if result == nil || len(result.Reachable) == 0 {
		return nil
	}
	var queue []*ssa.Function
	marked := map[*ssa.Function]bool{}
	enqueue := func(fn *ssa.Function) {
		if fn != nil && !marked[fn] && result.Reachable[fn]&mask != 0 {
			marked[fn] = true
			queue = append(queue, fn)
		}
	}
	for site, targets := range result.Targets {
		if site == nil || result.Reachable[site.Parent()]&mask == 0 || isStdPkgPath(userPaths, funcPkgPath(site.Parent())) || isImmediateSyncMakeClosureCall(site) {
			continue
		}
		for target, tmask := range targets {
			if tmask&mask != 0 {
				enqueue(target)
			}
		}
	}
	for fn, fmask := range result.Reachable {
		if fn == nil || fmask&mask == 0 {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				goSite, ok := instr.(*ssa.Go)
				if !ok || goSite.Common() == nil {
					continue
				}
				if callee := goSite.Common().StaticCallee(); callee != nil {
					enqueue(callee)
				}
				for target, tmask := range result.Targets[goSite] {
					if tmask&mask != 0 {
						enqueue(target)
					}
				}
			}
		}
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil {
					enqueue(callee)
				}
				for target, tmask := range result.Targets[site] {
					if tmask&mask != 0 {
						enqueue(target)
					}
				}
			}
		}
	}
	return marked
}

type nonSSAGlobalHazardSummary struct {
	blockedPkgs   map[string]bool
	linknamedVars map[pkgVarKey]bool
	verifiedAsm   map[string]*asmverify.VerifiedPackage
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
		if pkg.Types != nil {
			scopesByPath[pkg.PkgPath] = append(scopesByPath[pkg.PkgPath], pkg.Types)
		}
	}
	for _, root := range p.Pkgs {
		collectPkgs(root)
	}

	blocked := map[string]bool{}
	linknamed := map[pkgVarKey]bool{}
	verifiedAsm := map[string]*asmverify.VerifiedPackage{}
	for _, pkg := range allVisited {
		if pkg.Imports["runtime/cgo"] != nil || pkg.Imports["C"] != nil {
			blocked[pkg.PkgPath] = true
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
			} else if vp, asmOK := verifyNonStdAssemblyMemo(p, p.GOARCH, pkg.PkgPath, pkg.Dir, sFiles, hFiles, scopes, readFn); !asmOK || vp == nil {
				blocked[pkg.PkgPath] = true
			} else if !blocked[pkg.PkgPath] {
				verifiedAsm[pkg.PkgPath] = vp
			}
		}
		for _, af := range pkg.Syntax {
			if af == nil {
				continue
			}
			for _, cg := range af.Comments {
				for _, c := range cg.List {
					if !strings.Contains(c.Text, "go:linkname") {
						continue
					}
					trimmed := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
					trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "/*"))
					trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "*/"))
					restPlain, okPlain := auditset.BoundedToken(trimmed, "go:linkname", " \t")
					restStd, okStd := auditset.BoundedToken(trimmed, "go:linknamestd", " \t")
					if !okPlain && !okStd {
						if trimmed == "go:linkname" || trimmed == "go:linknamestd" {
							blocked[pkg.PkgPath] = true
						}
						continue
					}
					rest := restPlain
					if okStd {
						rest = restStd
					}
					fields := strings.Fields(rest)
					if len(fields) == 0 {
						blocked[pkg.PkgPath] = true
						continue
					}
					linknamed[pkgVarKey{pkgPath: pkg.PkgPath, name: fields[0]}] = true
					if len(fields) >= 2 {
						if dot := strings.LastIndexByte(fields[1], '.'); dot > 0 && dot+1 < len(fields[1]) {
							linknamed[pkgVarKey{pkgPath: fields[1][:dot], name: fields[1][dot+1:]}] = true
						} else {
							blocked[pkg.PkgPath] = true
						}
					}
				}
			}
		}
	}
	for pkgPath := range blocked {
		delete(verifiedAsm, pkgPath)
	}
	summary := &nonSSAGlobalHazardSummary{blockedPkgs: blocked, linknamedVars: linknamed, verifiedAsm: verifiedAsm}
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
		if summary := lookupSummaryForProg(base.prog, audited); summary != nil && len(summary.allFunctions) == len(progAllFunctions(base.prog)) {
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
		if _, asmOK := b.verifiedPackageAssembly(idx.meta); !asmOK {
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
					switch x := instr.(type) {
					case *ssa.UnOp:
						if x.Op != token.MUL || x.X != g {
							mutated[g] = true
						}
					case *ssa.Store:
						if x.Addr != g || x.Val == g || !isZeroSSAConst(x.Val) {
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

func isBoolSSAConst(v ssa.Value) (bool, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(c.Value), true
}

// boolLattice encodes the powerset 𝒫({false, true}):
//
//	0 = ⊥ (unreachable), 1 = {false}, 2 = {true}, 3 = ⊤ ({false, true}).
//
// Bitwise OR is exact lattice join.
type boolLattice uint8

const (
	boolBot   boolLattice = 0
	boolFalse boolLattice = 1
	boolTrue  boolLattice = 2
	boolTop   boolLattice = 3
)

func evalBoolLatticeNot(v boolLattice) boolLattice {
	var out boolLattice
	if v&boolFalse != 0 {
		out |= boolTrue
	}
	if v&boolTrue != 0 {
		out |= boolFalse
	}
	return out
}

// liveBlocks returns fn.Blocks with basic blocks pruned via sparse conditional
// constant propagation (SCCP) over boolLattice when they are only reachable
// across conditional branches (including short-circuit && / || *ssa.Phi merges)
// that are compile-time boolean constants or require a reachability-invariant
// zero global in zeroGlobals to hold a non-zero value.
func liveBlocks(fn *ssa.Function, zeroGlobals map[*ssa.Global]bool) []*ssa.BasicBlock {
	if fn == nil || len(fn.Blocks) <= 1 {
		if fn == nil {
			return nil
		}
		return fn.Blocks
	}
	checkZeroGlobals := len(zeroGlobals) > 0
	hasPrunableCond := false
	hasZeroGlobalLoad := false
	for _, blk := range fn.Blocks {
		if len(blk.Instrs) > 0 {
			if ifInstr, ok := blk.Instrs[len(blk.Instrs)-1].(*ssa.If); ok && len(blk.Succs) == 2 {
				cond := unwrapBoolSSAConv(ifInstr.Cond)
				if _, ok := isBoolSSAConst(cond); ok {
					hasPrunableCond = true
				} else if phi, isPhi := cond.(*ssa.Phi); isPhi {
					for _, predEdge := range phi.Edges {
						if _, ok := isBoolSSAConst(unwrapBoolSSAConv(predEdge)); ok {
							hasPrunableCond = true
							break
						}
					}
				}
			}
		}
		if checkZeroGlobals && !hasZeroGlobalLoad {
			for _, instr := range blk.Instrs {
				if u, ok := instr.(*ssa.UnOp); ok && u.Op == token.MUL {
					if g, ok := u.X.(*ssa.Global); ok && zeroGlobals[g] {
						hasZeroGlobalLoad = true
						hasPrunableCond = true
						break
					}
				}
			}
		}
	}
	if !hasPrunableCond {
		return fn.Blocks
	}

	type cfgEdge struct {
		pred, succ *ssa.BasicBlock
	}
	edgeLive := make(map[cfgEdge]bool, len(fn.Blocks)*2)
	blockLive := make(map[*ssa.BasicBlock]bool, len(fn.Blocks))
	inQueue := make(map[*ssa.BasicBlock]bool, len(fn.Blocks))
	queue := make([]*ssa.BasicBlock, 0, len(fn.Blocks))
	vals := make(map[ssa.Value]boolLattice)
	var zeroLoads map[ssa.Value]bool
	if hasZeroGlobalLoad {
		zeroLoads = make(map[ssa.Value]bool)
	}

	enqueueBlock := func(b *ssa.BasicBlock) {
		if b != nil && !inQueue[b] {
			blockLive[b] = true
			inQueue[b] = true
			queue = append(queue, b)
		}
	}
	markEdge := func(pred, succ *ssa.BasicBlock) {
		if succ == nil {
			return
		}
		e := cfgEdge{pred: pred, succ: succ}
		if !edgeLive[e] {
			edgeLive[e] = true
			enqueueBlock(succ)
		}
	}
	valOf := func(v ssa.Value) boolLattice {
		if v == nil {
			return boolTop
		}
		if c, ok := isBoolSSAConst(v); ok {
			if c {
				return boolTrue
			}
			return boolFalse
		}
		switch v.(type) {
		case *ssa.Phi, *ssa.UnOp, *ssa.BinOp, *ssa.ChangeType, *ssa.Convert:
			if lv, recorded := vals[v]; recorded {
				return lv
			}
			return boolBot
		default:
			return boolTop
		}
	}
	updateVal := func(v ssa.Value, next boolLattice) {
		prev := vals[v]
		joined := prev | next
		if joined == prev {
			return
		}
		vals[v] = joined
		if refs := v.Referrers(); refs != nil {
			for _, ref := range *refs {
				if ref != nil && ref.Block() != nil && blockLive[ref.Block()] {
					enqueueBlock(ref.Block())
				}
			}
		}
	}

	enqueueBlock(fn.Blocks[0])
	enqueueBlock(fn.Recover)
	for len(queue) > 0 {
		blk := queue[0]
		queue = queue[1:]
		inQueue[blk] = false

		for _, instr := range blk.Instrs {
			switch x := instr.(type) {
			case *ssa.Phi:
				if !isBooleanSSAType(x.Type()) {
					updateVal(x, boolTop)
					continue
				}
				var joined boolLattice
				for i, pred := range blk.Preds {
					if i < len(x.Edges) && edgeLive[cfgEdge{pred: pred, succ: blk}] {
						joined |= valOf(x.Edges[i])
					}
				}
				updateVal(x, joined)
			case *ssa.UnOp:
				switch x.Op {
				case token.MUL:
					if hasZeroGlobalLoad {
						if g, ok := x.X.(*ssa.Global); ok && zeroGlobals[g] {
							zeroLoads[x] = true
							if isBooleanSSAType(x.Type()) {
								updateVal(x, boolFalse)
								continue
							}
						}
					}
					updateVal(x, boolTop)
				case token.NOT:
					updateVal(x, evalBoolLatticeNot(valOf(x.X)))
				default:
					updateVal(x, boolTop)
				}
			case *ssa.BinOp:
				if x.Op == token.EQL || x.Op == token.NEQ {
					if hasZeroGlobalLoad && ((zeroLoads[x.X] && isZeroSSAConst(x.Y)) || (zeroLoads[x.Y] && isZeroSSAConst(x.X))) {
						if x.Op == token.EQL {
							updateVal(x, boolTrue)
						} else {
							updateVal(x, boolFalse)
						}
						continue
					}
					if x.X != nil && isBooleanSSAType(x.X.Type()) {
						vx, vy := valOf(x.X), valOf(x.Y)
						var eq boolLattice
						if (vx&boolFalse != 0 && vy&boolFalse != 0) || (vx&boolTrue != 0 && vy&boolTrue != 0) {
							eq |= boolTrue
						}
						if (vx&boolFalse != 0 && vy&boolTrue != 0) || (vx&boolTrue != 0 && vy&boolFalse != 0) {
							eq |= boolFalse
						}
						if x.Op == token.NEQ {
							eq = evalBoolLatticeNot(eq)
						}
						updateVal(x, eq)
						continue
					}
				}
				updateVal(x, boolTop)
			case *ssa.ChangeType:
				if hasZeroGlobalLoad && zeroLoads[x.X] {
					zeroLoads[x] = true
				}
				if isBooleanSSAType(x.Type()) && x.X != nil && isBooleanSSAType(x.X.Type()) {
					updateVal(x, valOf(x.X))
				} else {
					updateVal(x, boolTop)
				}
			case *ssa.Convert:
				if isBooleanSSAType(x.Type()) && x.X != nil && isBooleanSSAType(x.X.Type()) {
					updateVal(x, valOf(x.X))
				} else {
					updateVal(x, boolTop)
				}
			}
		}

		if len(blk.Instrs) > 0 {
			if ifInstr, ok := blk.Instrs[len(blk.Instrs)-1].(*ssa.If); ok && len(blk.Succs) == 2 {
				cond := valOf(ifInstr.Cond)
				if cond&boolTrue != 0 {
					markEdge(blk, blk.Succs[0])
				}
				if cond&boolFalse != 0 {
					markEdge(blk, blk.Succs[1])
				}
				continue
			}
		}
		for _, succ := range blk.Succs {
			markEdge(blk, succ)
		}
	}

	if len(blockLive) == len(fn.Blocks) {
		return fn.Blocks
	}
	live := make([]*ssa.BasicBlock, 0, len(blockLive))
	for _, blk := range fn.Blocks {
		if blockLive[blk] {
			live = append(live, blk)
		}
	}
	return live
}

func unwrapBoolSSAConv(v ssa.Value) ssa.Value {
	for v != nil {
		switch c := v.(type) {
		case *ssa.ChangeType:
			if isBooleanSSAType(c.Type()) && c.X != nil && isBooleanSSAType(c.X.Type()) {
				v = c.X
				continue
			}
		case *ssa.Convert:
			if isBooleanSSAType(c.Type()) && c.X != nil && isBooleanSSAType(c.X.Type()) {
				v = c.X
				continue
			}
		}
		return v
	}
	return nil
}

func isBooleanSSAType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}
