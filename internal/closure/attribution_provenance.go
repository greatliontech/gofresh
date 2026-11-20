package closure

import (
	"context"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/propharness"
)

func provenanceReachableStartup(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool) (map[*ssa.Function]bool, error) {
	return provenanceBFS(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, true, nil)
}

func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, false, nil, roots, mask, result, harnessAudited, userPaths, false, dropTarget, nil, nil, nil)
	return reach, err
}

func provenanceReachableWithCandidates(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type, sharedProvFP *freshParamAnalysis) (map[*ssa.Function]bool, bool, error) {
	return provenanceBFSWithCandidates(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, false, dropTarget, candidateTypes, initBoxedTypes, sharedProvFP)
}

func provenanceBFS(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, deferUnscannedClosures, dropTarget, nil, nil, nil)
	return reach, err
}

func newProvenanceFP(audited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, pureDelegates map[string]bool, prog *program, summary *callerReferenceSummary, userPaths map[string]bool) *freshParamAnalysis {
	if summary == nil {
		summary = lookupSummaryForProg(prog, audited)
	}
	if verifiedHarnesses == nil && summary != nil {
		verifiedHarnesses = summary.verifiedHarnesses
	}
	fp := &freshParamAnalysis{
		ssaProgramIndex: summary.ssaIndex(audited, verifiedHarnesses, pureDelegates, userPaths, nil),
	}
	fp.resetDynamicMemos()
	if summary != nil {
		fp.inProgramSites = true
	} else if prog != nil {
		fp.prog = prog
		fp.programFunctions = progAllFunctions(prog)
	}
	return fp
}

func lookupCachedBaseStartup(prog *program) *baseStartupReachSummary {
	if prog == nil || prog.Summaries == nil {
		return nil
	}
	if s, ok := prog.Summaries["baseStartupReach:1:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	if s, ok := prog.Summaries["baseStartupReach:0:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	return nil
}

func hasStartupAncestor(fn *ssa.Function, startupFns map[*ssa.Function]bool) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	if initFlowFrame(fn) {
		return true
	}
	if len(startupFns) == 0 {
		return false
	}
	for p := fn.Parent(); p != nil; p = p.Parent() {
		if startupFns[p] {
			return true
		}
	}
	return false
}

func typeCanCarryAnyInitBoxed(t types.Type, initBoxed []types.Type) bool {
	if t == nil || len(initBoxed) == 0 {
		return false
	}
	found := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(cur types.Type) bool {
		iface, ok := cur.(*types.Interface)
		if !ok {
			return true
		}
		if rta.ContainsTypeParam(iface, nil) {
			found = true
			return false
		}
		for _, bt := range initBoxed {
			if bt == nil {
				continue
			}
			if rta.ContainsTypeParam(bt, nil) || types.Implements(bt, iface) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func isMethodlessCarrierFreeType(audited bool, t types.Type) bool {
	if t == nil || typeMayCarryDynamicTop(audited, t) {
		return false
	}
	cur := types.Unalias(t)
	for {
		switch u := cur.(type) {
		case *types.Basic:
			return true
		case *types.Slice:
			cur = types.Unalias(u.Elem())
		case *types.Array:
			cur = types.Unalias(u.Elem())
		default:
			return false
		}
	}
}

func isCarrierFreeCallArg(audited bool, site ssa.CallInstruction, arg ssa.Value) bool {
	if arg == nil || !typeMayCarryDynamicTop(audited, arg.Type()) {
		return true
	}
	if c, ok := arg.(*ssa.Const); ok && c.Value == nil {
		return true
	}
	if mi, ok := arg.(*ssa.MakeInterface); ok && mi.X != nil {
		return isMethodlessCarrierFreeType(audited, mi.X.Type())
	}
	if sl, ok := arg.(*ssa.Slice); ok && sl.Low == nil && sl.High == nil && sl.Max == nil {
		alloc, ok := sl.X.(*ssa.Alloc)
		if !ok || alloc.Referrers() == nil || sl.Referrers() == nil {
			return false
		}
		for _, sref := range *sl.Referrers() {
			switch sref.(type) {
			case *ssa.DebugRef:
			default:
				if sref != site {
					return false
				}
			}
		}
		for _, aref := range *alloc.Referrers() {
			switch ar := aref.(type) {
			case *ssa.DebugRef:
			case *ssa.Slice:
				if ar != sl {
					return false
				}
			case *ssa.IndexAddr:
				if ar.X != alloc || ar.Referrers() == nil {
					return false
				}
				for _, iref := range *ar.Referrers() {
					switch ir := iref.(type) {
					case *ssa.DebugRef:
					case *ssa.Store:
						if ir.Addr != ar || !isCarrierFreeCallArg(audited, site, ir.Val) {
							return false
						}
					default:
						return false
					}
				}
			default:
				return false
			}
		}
		return true
	}
	return false
}

func isCarrierFreeStaticCall(audited bool, site ssa.CallInstruction, callee *ssa.Function) bool {
	if site == nil || site.Common() == nil || callee == nil {
		return false
	}
	c := site.Common()
	if mc, ok := c.Value.(*ssa.MakeClosure); ok {
		for _, b := range mc.Bindings {
			if b != nil && typeMayCarryDynamicTop(audited, b.Type()) {
				return false
			}
		}
	}
	for _, arg := range c.Args {
		if !isCarrierFreeCallArg(audited, site, arg) {
			return false
		}
	}
	for _, ta := range callee.TypeArgs() {
		if typeMayCarryDynamicTop(audited, ta) {
			return false
		}
	}
	return true
}

func provenanceBFSWithCandidates(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type, sharedProvFP *freshParamAnalysis) (map[*ssa.Function]bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	canDispatchNonStd := make(map[*ssa.Function]bool, len(roots))
	scannedWithNonStd := make(map[*ssa.Function]bool)
	var pendingByParent map[*ssa.Function][]*ssa.Function
	if deferUnscannedClosures {
		pendingByParent = make(map[*ssa.Function][]*ssa.Function)
	}
	queue := append([]*ssa.Function(nil), roots...)
	var rootSSAProg *ssa.Program
	if prog != nil {
		rootSSAProg = prog.Prog
	}
	for _, r := range roots {
		if r != nil {
			if rootSSAProg == nil {
				rootSSAProg = r.Prog
			}
			if !isStdPkgPath(userPaths, funcPkgPath(r)) {
				canDispatchNonStd[r] = true
			}
		}
	}
	var syncZeroGlobals, wholeZeroGlobals map[*ssa.Global]bool
	var asyncStartup map[*ssa.Function]bool
	var wholeComputed bool
	if deferUnscannedClosures && len(roots) > 0 && initFlowFrame(roots[0]) {
		syncZeroGlobals = rtaUnmutatedZeroGlobals(audited, prog, result, mask, userPaths)
		if len(syncZeroGlobals) > 0 {
			asyncStartup = computeRTAAsyncStartupFunctions(result, mask, userPaths)
		}
	}
	var verified map[string]*propharness.VerifiedPackage
	if harnessAudited {
		if sharedProvFP != nil && sharedProvFP.verifiedHarnesses != nil {
			verified = sharedProvFP.verifiedHarnesses
		} else {
			verified = verifiedHarnessesProg(audited, prog)
		}
	}
	var sawHarnessCall bool
	var dispatchedTargets map[*ssa.Function]bool
	var harnessCandidateTargets map[*ssa.Function]bool
	var seenCandidateTypes map[types.Type]bool
	var pendingCandidateTypes []types.Type
	enqueueDispatchedMethodsOfType := func(ssaProg *ssa.Program, rootType types.Type) {
		if ssaProg == nil || rootType == nil || len(dispatchedTargets) == 0 {
			return
		}
		walkTypeGraph(rootType, true, seenCandidateTypes, func(cur types.Type) bool {
			named, ok := cur.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
				return true
			}
			pkgPath := named.Obj().Pkg().Path()
			if isStdPkgPath(userPaths, pkgPath) || pkgPath == "testing" || verified[pkgPath] != nil {
				return true
			}
			for _, mt := range []types.Type{named, types.NewPointer(named)} {
				mset := ssaProg.MethodSets.MethodSet(mt)
				for i, n := 0, mset.Len(); i < n; i++ {
					sel := mset.At(i)
					if sel.Obj() == nil {
						continue
					}
					if cm := ssaProg.MethodValue(sel); cm != nil && dispatchedTargets[cm] {
						if harnessCandidateTargets == nil {
							harnessCandidateTargets = make(map[*ssa.Function]bool)
						}
						harnessCandidateTargets[cm] = true
						canDispatchNonStd[cm] = true
						queue = append(queue, cm)
					}
				}
			}
			return true
		})
	}
	noteHarnessCandidateType := func(ssaProg *ssa.Program, t types.Type) {
		if result == nil || t == nil {
			return
		}
		if !sawHarnessCall {
			pendingCandidateTypes = append(pendingCandidateTypes, t)
			return
		}
		enqueueDispatchedMethodsOfType(ssaProg, t)
	}
	activateHarnessDispatchedMethods := func(ssaProg *ssa.Program) {
		if sawHarnessCall || result == nil {
			return
		}
		sawHarnessCall = true
		dispatchedTargets = make(map[*ssa.Function]bool)
		for _, targets := range result.Targets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		for _, targets := range result.HarnessStdTargets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		seenCandidateTypes = make(map[types.Type]bool)
		for _, pt := range pendingCandidateTypes {
			enqueueDispatchedMethodsOfType(ssaProg, pt)
		}
		pendingCandidateTypes = nil
	}
	for _, ct := range candidateTypes {
		noteHarnessCandidateType(rootSSAProg, ct)
	}
	var usedInitBoxed bool
	var baseStartup *baseStartupReachSummary
	var checkedGlobalCarrier map[*ssa.Global]bool
	if len(initBoxedTypes) > 0 {
		baseStartup = lookupCachedBaseStartup(prog)
	}
	seedInitBoxedTypes := func(ssaProg *ssa.Program) {
		if usedInitBoxed {
			return
		}
		usedInitBoxed = true
		for _, bt := range initBoxedTypes {
			noteHarnessCandidateType(ssaProg, bt)
		}
	}
	provFP := sharedProvFP
	provFPInit := provFP != nil
	getProvFP := func() *freshParamAnalysis {
		if provFPInit {
			return provFP
		}
		provFPInit = true
		provFP = newProvenanceFP(audited, verified, nil, prog, nil, userPaths)
		return provFP
	}
	var opsBuf [8]*ssa.Value
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || result.Reachable[fn]&mask == 0 {
			continue
		}
		fnNonStdDispatch := canDispatchNonStd[fn]
		if scanned[fn] && (!fnNonStdDispatch || scannedWithNonStd[fn]) {
			continue
		}
		scanned[fn] = true
		if fnNonStdDispatch {
			scannedWithNonStd[fn] = true
		}
		if deferUnscannedClosures {
			if pending := pendingByParent[fn]; len(pending) > 0 {
				delete(pendingByParent, fn)
				queue = append(queue, pending...)
			}
		}
		fnPath := funcPkgPath(fn)
		fnIsStd := isStdPkgPath(userPaths, fnPath)
		// A harness frame - the standard testing package or an audited
		// property harness - is never subject content; its dispatch
		// targets still traverse, so the caller-supplied callbacks it
		// runs stay subject flow (REQ-closure-observability-analysis).
		harnessFrame := fnPath == "testing" || verified[fnPath] != nil
		if !harnessFrame {
			reachable[fn] = true
			if !usedInitBoxed && len(initBoxedTypes) > 0 && len(fn.FreeVars) > 0 &&
				(baseStartup == nil || hasStartupAncestor(fn, baseStartup.startupFunctions)) {
				for _, fv := range fn.FreeVars {
					if fv != nil && typeCanCarryAnyInitBoxed(fv.Type(), initBoxedTypes) {
						seedInitBoxedTypes(fn.Prog)
						break
					}
				}
			}
		}
		fnZeroGlobals := syncZeroGlobals
		if len(syncZeroGlobals) > 0 && asyncStartup[fn] {
			if !wholeComputed {
				wholeComputed = true
				if prog != nil {
					wholeZeroGlobals = unmutatedZeroGlobalsForFunctions(audited, prog, userPaths, progAllFunctions(prog))
				}
			}
			fnZeroGlobals = wholeZeroGlobals
		}
		for _, block := range liveBlocks(fn, fnZeroGlobals) {
			for _, instruction := range block.Instrs {
				if !harnessFrame {
					if !usedInitBoxed && len(initBoxedTypes) > 0 {
						for _, op := range instruction.Operands(opsBuf[:0]) {
							if op == nil {
								continue
							}
							g, ok := (*op).(*ssa.Global)
							if !ok || g == nil || checkedGlobalCarrier[g] {
								continue
							}
							if checkedGlobalCarrier == nil {
								checkedGlobalCarrier = make(map[*ssa.Global]bool)
							}
							checkedGlobalCarrier[g] = true
							var gPkg string
							if g.Pkg != nil && g.Pkg.Pkg != nil {
								gPkg = g.Pkg.Pkg.Path()
							}
							if gPkg == "testing" || verified[gPkg] != nil {
								continue
							}
							if isStdPkgPath(userPaths, gPkg) && baseStartup != nil && !baseStartup.userTouchedStdGlobals[g] {
								continue
							}
							if typeCanCarryAnyInitBoxed(g.Type(), initBoxedTypes) {
								seedInitBoxedTypes(fn.Prog)
								break
							}
						}
					}
					if mi, isMI := instruction.(*ssa.MakeInterface); isMI && mi.X != nil {
						noteHarnessCandidateType(fn.Prog, mi.X.Type())
						continue
					}
				}
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestingMRun(callee) {
					continue
				}
				if callee != nil {
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || verified[calleePath] != nil
					calleeIsStd := isStdPkgPath(userPaths, calleePath)
					calleeNonStdDispatch := false
					switch {
					case !calleeIsStd:
						calleeNonStdDispatch = true
					case !fnNonStdDispatch:
						calleeNonStdDispatch = false
					case fnIsStd:
						calleeNonStdDispatch = true
					case audited && !calleeHarness && (isSourceOnlyStandardPackage(true, calleePath) || auditedStandardCallee(true, calleePath, functionSymbolName(callee), callee) || (sharedProvFP != nil && isAdmittedPureMathSymbol(true, sharedProvFP.pureDelegates, calleePath, callee))) && isCarrierFreeStaticCall(audited, site, callee):
						calleeNonStdDispatch = false
					default:
						calleeNonStdDispatch = true
					}
					if calleeNonStdDispatch {
						canDispatchNonStd[callee] = true
					}
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame && !initFlowFrame(callee) {
						activateHarnessDispatchedMethods(fn.Prog)
						if mc, ok := site.Common().Value.(*ssa.MakeClosure); ok {
							for _, b := range mc.Bindings {
								if b != nil {
									noteHarnessCandidateType(fn.Prog, b.Type())
								}
							}
						}
						for _, arg := range site.Common().Args {
							if arg != nil {
								noteHarnessCandidateType(fn.Prog, arg.Type())
							}
						}
						for _, ta := range callee.TypeArgs() {
							noteHarnessCandidateType(fn.Prog, ta)
						}
						continue
					}
				}
				var closedSet map[*ssa.Function]bool
				if audited && !deferUnscannedClosures && !harnessFrame && !fnIsStd && callee == nil && len(result.Targets[site]) > 1 {
					fp := getProvFP()
					if site.Common().IsInvoke() {
						if set, ok := closedInvokeTargets(site, fp); ok && len(set) > 0 {
							closedSet = set
						}
					} else if set, ok := closedDynamicTargets(site.Common().Value, fp); ok && len(set) > 0 {
						closedSet = set
					}
				}
				enqueueSiteTargets := func(targets map[*ssa.Function]uint64) {
					for target, targetMask := range targets {
						if targetMask&mask == 0 || isTestingMRun(target) || isTestingBLaunch(target) {
							continue
						}
						if closedSet != nil && !closedSet[target] {
							continue
						}
						if dropTarget != nil && !harnessCandidateTargets[target] && dropTarget(site, target) {
							continue
						}
						targetPath := funcPkgPath(target)
						targetIsStd := isStdPkgPath(userPaths, targetPath)
						if !fnNonStdDispatch && !targetIsStd && !harnessCandidateTargets[target] {
							continue
						}
						targetHarness := targetPath == "testing" || verified[targetPath] != nil
						if !harnessFrame || targetHarness || !targetIsStd {
							if !targetIsStd || fnNonStdDispatch {
								canDispatchNonStd[target] = true
							}
							if deferUnscannedClosures && target.Parent() != nil && target.Synthetic == "" && !scanned[target.Parent()] && !isTestingCleanupCallback(target) {
								pendingByParent[target.Parent()] = append(pendingByParent[target.Parent()], target)
								continue
							}
							queue = append(queue, target)
						}
					}
				}
				enqueueSiteTargets(result.Targets[site])
				if harnessFrame && !initFlowFrame(fn) && len(result.HarnessStdTargets) > 0 {
					enqueueSiteTargets(result.HarnessStdTargets[site])
				}
			}
		}
	}
	return reachable, usedInitBoxed, nil
}

// userModulePaths collects every loaded package path the module graph
// proves user code: both load configs request NeedModule, so in module
// mode a nil Module is exactly the standard library, and these paths
// are the code no path-shape heuristic may classify standard.
func userModulePaths(pkgs []*packages.Package) map[string]bool {
	user := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil {
			user[p.PkgPath] = true
		}
	})
	return user
}

// initFlowFrame reports whether a frame is initializer flow: the
// synthetic package initializer, a compiler-numbered user init body, or
// a function transitively parented under one.
func initFlowFrame(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	top := fn
	for top.Parent() != nil {
		top = top.Parent()
	}
	if top.Signature != nil && top.Signature.Recv() != nil {
		return false
	}
	name := top.Name()
	if name == "init" {
		return top.Synthetic == "package initializer"
	}
	if rest, ok := strings.CutPrefix(name, "init#"); ok {
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return rest != ""
	}
	return false
}

func lessSSAFunctionOrder(a, b *ssa.Function) bool {
	if a == b {
		return false
	}
	if a.Name() != b.Name() {
		return a.Name() < b.Name()
	}
	pa, pb := funcPkgPath(a), funcPkgPath(b)
	if pa != pb {
		return pa < pb
	}
	if a.Pos() != b.Pos() {
		return a.Pos() < b.Pos()
	}
	return a.String() < b.String()
}

func progAllFunctions(p *program) map[*ssa.Function]bool {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.AllFunctions != nil {
		return p.AllFunctions
	}
	p.AllFunctions = ssautil.AllFunctions(p.Prog)
	return p.AllFunctions
}

type orderedFuncKey struct {
	fn      *ssa.Function
	name    string
	pkgPath string
	pos     token.Pos
}

func progOrderedFunctions(p *program) []*ssa.Function {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.OrderedFunctions != nil {
		return p.OrderedFunctions
	}
	p.OrderedFunctions = orderedFunctionsForProgram(progAllFunctions(p))
	return p.OrderedFunctions
}

func progInstancesByOrigin(p *program) map[*ssa.Function][]*ssa.Function {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries["instancesByOrigin"].(map[*ssa.Function][]*ssa.Function); ok && cached != nil {
			return cached
		}
	}
	out := make(map[*ssa.Function][]*ssa.Function)
	for _, fn := range progOrderedFunctions(p) {
		if fn != nil && fn.Origin() != nil && fn.Origin() != fn {
			orig := fn.Origin()
			out[orig] = append(out[orig], fn)
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 4)
	}
	p.Summaries["instancesByOrigin"] = out
	return out
}

func orderedFunctionsForProgram(all map[*ssa.Function]bool) []*ssa.Function {
	keys := make([]orderedFuncKey, 0, len(all))
	for fn := range all {
		if fn != nil {
			keys = append(keys, orderedFuncKey{
				fn:      fn,
				name:    fn.Name(),
				pkgPath: funcPkgPath(fn),
				pos:     fn.Pos(),
			})
		}
	}
	slices.SortFunc(keys, func(a, b orderedFuncKey) int {
		if a.fn == b.fn {
			return 0
		}
		if a.name != b.name {
			if a.name < b.name {
				return -1
			}
			return 1
		}
		if a.pkgPath != b.pkgPath {
			if a.pkgPath < b.pkgPath {
				return -1
			}
			return 1
		}
		if a.pos != b.pos {
			if a.pos < b.pos {
				return -1
			}
			return 1
		}
		sa, sb := a.fn.String(), b.fn.String()
		if sa < sb {
			return -1
		}
		if sa > sb {
			return 1
		}
		return 0
	})
	ordered := make([]*ssa.Function, len(keys))
	for i := range keys {
		ordered[i] = keys[i].fn
	}
	return ordered
}
