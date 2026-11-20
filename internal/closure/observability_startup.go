package closure

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/propharness"
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

func collectAsyncOrDynamicStartup(
	isReachable func(*ssa.Function) bool,
	forEachReachable func(func(*ssa.Function)),
	forEachSiteTargets func(ssa.CallInstruction, func(*ssa.Function)),
	forEachRootDynTargets func(func(*ssa.Function)),
) map[*ssa.Function]bool {
	var queue []*ssa.Function
	marked := map[*ssa.Function]bool{}
	enqueue := func(fn *ssa.Function) {
		if fn != nil && !marked[fn] && isReachable(fn) {
			marked[fn] = true
			queue = append(queue, fn)
		}
	}
	forEachRootDynTargets(enqueue)
	forEachReachable(func(fn *ssa.Function) {
		if fn == nil {
			return
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
				forEachSiteTargets(goSite, enqueue)
			}
		}
	})
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
				forEachSiteTargets(site, enqueue)
			}
		}
	}
	return marked
}

func asyncOrDynamicStartupFunctions(reach attributedReachability) map[*ssa.Function]bool {
	if len(reach.startupFunctions) == 0 {
		return nil
	}
	return collectAsyncOrDynamicStartup(
		func(fn *ssa.Function) bool { return reach.startupFunctions[fn] },
		func(visit func(*ssa.Function)) {
			for fn := range reach.startupFunctions {
				visit(fn)
			}
		},
		func(site ssa.CallInstruction, visit func(*ssa.Function)) {
			for target := range reach.startupDynamicTargets[site] {
				visit(target)
			}
		},
		func(enqueue func(*ssa.Function)) {
			for site, targets := range reach.startupDynamicTargets {
				if site == nil || !reach.startupFunctions[site.Parent()] || isImmediateSyncMakeClosureCall(site) {
					continue
				}
				for target := range targets {
					enqueue(target)
				}
			}
		},
	)
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
	return collectAsyncOrDynamicStartup(
		func(fn *ssa.Function) bool { return result.Reachable[fn]&mask != 0 },
		func(visit func(*ssa.Function)) {
			for fn, fmask := range result.Reachable {
				if fn != nil && fmask&mask != 0 {
					visit(fn)
				}
			}
		},
		func(site ssa.CallInstruction, visit func(*ssa.Function)) {
			for target, tmask := range result.Targets[site] {
				if tmask&mask != 0 {
					visit(target)
				}
			}
		},
		func(enqueue func(*ssa.Function)) {
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
		},
	)
}

func isBoolSSAConst(v ssa.Value) (bool, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(c.Value), true
}

func condMayFoldToBoolConst(v ssa.Value, depth int) bool {
	if v == nil || depth > 4 {
		return false
	}
	for v != nil {
		v = unwrapBoolSSAConv(v)
		if u, ok := v.(*ssa.UnOp); ok && u.Op == token.NOT {
			v = u.X
			continue
		}
		break
	}
	if _, ok := isBoolSSAConst(v); ok {
		return true
	}
	if phi, isPhi := v.(*ssa.Phi); isPhi {
		for _, edge := range phi.Edges {
			if condMayFoldToBoolConst(edge, depth+1) {
				return true
			}
		}
	}
	if bin, isBin := v.(*ssa.BinOp); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) && bin.X != nil && isBooleanSSAType(bin.X.Type()) {
		return condMayFoldToBoolConst(bin.X, depth+1) || condMayFoldToBoolConst(bin.Y, depth+1)
	}
	return false
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
// constant propagation (SCCP) over boolLattice when they are orphan blocks or
// only reachable across conditional branches (including negated and
// short-circuit && / || *ssa.Phi merges) that fold to boolean constants or
// require a reachability-invariant zero global in zeroGlobals to hold a
// non-zero value.
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
	for i, blk := range fn.Blocks {
		if i > 0 && blk != fn.Recover && len(blk.Preds) == 0 {
			hasPrunableCond = true
		}
		if len(blk.Instrs) > 0 {
			if ifInstr, ok := blk.Instrs[len(blk.Instrs)-1].(*ssa.If); ok && len(blk.Succs) == 2 {
				if condMayFoldToBoolConst(ifInstr.Cond, 0) {
					hasPrunableCond = true
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

type baseStartupReachSummary struct {
	startupFunctions      map[*ssa.Function]bool
	startupDynamicTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	initBoxedTypes        []types.Type
	userTouchedStdGlobals map[*ssa.Global]bool
}

func cloneDynamicTargetMap(src map[ssa.CallInstruction]map[*ssa.Function]bool) map[ssa.CallInstruction]map[*ssa.Function]bool {
	out := make(map[ssa.CallInstruction]map[*ssa.Function]bool, len(src))
	for site, targets := range src {
		out[site] = maps.Clone(targets)
	}
	return out
}

func cachedBaseStartupReachability(ctx context.Context, audited bool, prog *program, initRoots, harnessStdInitRoots []*ssa.Function, harnessAudited bool, userPaths map[string]bool) (*baseStartupReachSummary, error) {
	cacheKey := "baseStartupReach:0:0"
	switch {
	case audited && harnessAudited:
		cacheKey = "baseStartupReach:1:1"
	case audited:
		cacheKey = "baseStartupReach:1:0"
	case harnessAudited:
		cacheKey = "baseStartupReach:0:1"
	}
	if prog != nil {
		if cached, ok := prog.Summaries[cacheKey].(*baseStartupReachSummary); ok && cached != nil {
			return cached, nil
		}
	}
	const startupMask uint64 = 1
	initMaskRoots := make(map[*ssa.Function]uint64, len(initRoots))
	for _, fn := range initRoots {
		initMaskRoots[fn] = startupMask
	}
	var verified map[string]*propharness.VerifiedPackage
	if harnessAudited {
		verified = verifiedHarnessesProg(audited, prog)
	}
	var initSeeds *rta.Seeds
	if len(verified) > 0 {
		initSeeds = newHarnessRTASeeds(verified, userPaths, harnessStdInitRoots, startupMask)
	}
	initRes, err := rta.Analyze(ctx, initMaskRoots, initSeeds)
	if err != nil {
		return nil, err
	}
	startupFns, err := provenanceReachableStartup(ctx, audited, prog, initRoots, startupMask, initRes, harnessAudited, userPaths)
	if err != nil {
		return nil, err
	}
	startupTargets := make(map[ssa.CallInstruction]map[*ssa.Function]bool)
	for site, targets := range initRes.Targets {
		callee := site.Common().StaticCallee()
		if !startupFns[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
			continue
		}
		for target, masks := range targets {
			if masks&startupMask != 0 && initRes.Reachable[target]&startupMask != 0 {
				projected := startupTargets[site]
				if projected == nil {
					projected = make(map[*ssa.Function]bool)
					startupTargets[site] = projected
				}
				projected[target] = true
			}
		}
	}
	var initBoxedTypes []types.Type
	var userTouchedStdGlobals map[*ssa.Global]bool
	if harnessAudited {
		orderedStartup := make([]*ssa.Function, 0, len(startupFns))
		for fn := range startupFns {
			if fn != nil {
				orderedStartup = append(orderedStartup, fn)
			}
		}
		sort.Slice(orderedStartup, func(i, j int) bool { return lessSSAFunctionOrder(orderedStartup[i], orderedStartup[j]) })
		seenBoxed := map[types.Type]bool{}
		for _, fn := range orderedStartup {
			fp := funcPkgPath(fn)
			if isStdPkgPath(userPaths, fp) || fp == "testing" || verified[fp] != nil {
				continue
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if mi, isMI := instr.(*ssa.MakeInterface); isMI && mi.X != nil && mi.X.Type() != nil {
						xt := mi.X.Type()
						if !seenBoxed[xt] {
							seenBoxed[xt] = true
							initBoxedTypes = append(initBoxedTypes, xt)
						}
					}
				}
			}
		}
		if len(initBoxedTypes) > 0 {
			userStartupFns := make(map[*ssa.Function]bool)
			var uQueue []*ssa.Function
			for _, fn := range orderedStartup {
				fp := funcPkgPath(fn)
				if !isStdPkgPath(userPaths, fp) && fp != "testing" && verified[fp] == nil {
					userStartupFns[fn] = true
					uQueue = append(uQueue, fn)
				}
			}
			for len(uQueue) > 0 {
				cur := uQueue[0]
				uQueue = uQueue[1:]
				for _, b := range cur.Blocks {
					for _, instr := range b.Instrs {
						site, ok := instr.(ssa.CallInstruction)
						if !ok || site.Common() == nil {
							continue
						}
						if callee := site.Common().StaticCallee(); callee != nil {
							if startupFns[callee] && !userStartupFns[callee] {
								userStartupFns[callee] = true
								uQueue = append(uQueue, callee)
							}
						} else {
							for t := range startupTargets[site] {
								if startupFns[t] && !userStartupFns[t] {
									userStartupFns[t] = true
									uQueue = append(uQueue, t)
								}
							}
						}
					}
				}
			}
			var opsBuf [8]*ssa.Value
			for _, fn := range orderedStartup {
				if !userStartupFns[fn] {
					continue
				}
				fp := funcPkgPath(fn)
				isOwnInit := initFlowFrame(fn)
				for _, b := range fn.Blocks {
					for _, instr := range b.Instrs {
						for _, op := range instr.Operands(opsBuf[:0]) {
							if op == nil {
								continue
							}
							g, ok := (*op).(*ssa.Global)
							if !ok || g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
								continue
							}
							gPkg := g.Pkg.Pkg.Path()
							if !isStdPkgPath(userPaths, gPkg) || (isOwnInit && fp == gPkg) {
								continue
							}
							if userTouchedStdGlobals == nil {
								userTouchedStdGlobals = make(map[*ssa.Global]bool)
							}
							userTouchedStdGlobals[g] = true
						}
					}
				}
			}
		}
	}
	summary := &baseStartupReachSummary{
		startupFunctions:      startupFns,
		startupDynamicTargets: startupTargets,
		initBoxedTypes:        initBoxedTypes,
		userTouchedStdGlobals: userTouchedStdGlobals,
	}
	if prog != nil && ctx.Err() == nil {
		if prog.Summaries == nil {
			prog.Summaries = make(map[string]any, 4)
		}
		prog.Summaries[cacheKey] = summary
	}
	return summary, nil
}

func partitionHarnessInitRoots(prog *program, harnessAudited bool, userPaths map[string]bool) (initRoots, harnessStdInitRoots []*ssa.Function) {
	if prog == nil || prog.Prog == nil {
		return nil, nil
	}
	var verified map[string]*propharness.VerifiedPackage
	if harnessAudited {
		verified = verifiedHarnessesProg(true, prog)
	}
	var nonHarnessReachable map[*types.Package]bool
	if len(verified) > 0 {
		nonHarnessReachable = make(map[*types.Package]bool)
		if len(prog.Pkgs) > 0 {
			var nonHarnessRoots []*packages.Package
			for _, pkg := range prog.Pkgs {
				if pkg == nil || verified[pkg.PkgPath] != nil {
					continue
				}
				if pkg.Module != nil || !isStdPkgPath(userPaths, pkg.PkgPath) || pkg.PkgPath == prog.PkgPath || pkg.PkgPath == prog.PkgPath+"_test" || pkg.ForTest == prog.PkgPath || IsGeneratedTestMainPackage(pkg) {
					nonHarnessRoots = append(nonHarnessRoots, pkg)
				}
			}
			packages.Visit(nonHarnessRoots, func(pkg *packages.Package) bool {
				if pkg == nil || verified[pkg.PkgPath] != nil {
					return false
				}
				if pkg.Types != nil {
					nonHarnessReachable[pkg.Types] = true
				}
				return true
			}, nil)
		} else {
			var queue []*types.Package
			enqueue := func(tp *types.Package) {
				if tp == nil || nonHarnessReachable[tp] || verified[tp.Path()] != nil {
					return
				}
				nonHarnessReachable[tp] = true
				queue = append(queue, tp)
			}
			for _, sp := range prog.Prog.AllPackages() {
				if sp == nil || sp.Pkg == nil {
					continue
				}
				p := sp.Pkg.Path()
				if isGeneratedTestMainPackage(prog, sp) || p == prog.PkgPath || p == prog.PkgPath+"_test" || (verified[p] == nil && !isStdPkgPath(userPaths, p)) {
					enqueue(sp.Pkg)
				}
			}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, imp := range cur.Imports() {
					enqueue(imp)
				}
			}
		}
	}
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		init := p.Func("init")
		if init == nil {
			continue
		}
		if len(verified) > 0 && p.Pkg != nil && verified[p.Pkg.Path()] == nil && !nonHarnessReachable[p.Pkg] {
			harnessStdInitRoots = append(harnessStdInitRoots, init)
			continue
		}
		initRoots = append(initRoots, init)
	}
	return initRoots, harnessStdInitRoots
}

func newHarnessRTASeeds(verified map[string]*propharness.VerifiedPackage, userPaths map[string]bool, harnessStdInitRoots []*ssa.Function, masks uint64) *rta.Seeds {
	var stdRoots map[*ssa.Function]uint64
	if len(harnessStdInitRoots) > 0 && masks != 0 {
		stdRoots = make(map[*ssa.Function]uint64, len(harnessStdInitRoots))
		for _, fn := range harnessStdInitRoots {
			stdRoots[fn] |= masks
		}
	}
	return &rta.Seeds{
		HarnessPkgs:     harnessPkgSet(verified),
		UserPkgs:        userPaths,
		HarnessStdRoots: stdRoots,
	}
}
