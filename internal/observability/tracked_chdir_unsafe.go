package observability

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func fnHasUnconfinedUnsafeForTrackedChdir(fn *ssa.Function, trapArg0Stubs map[*ssa.Function]bool) bool {
	if fn == nil {
		return false
	}
	verifiedVals := map[ssa.Value]bool{}
	for _, p := range fn.Params {
		if p != nil && typeUsesUnsafePointer(p.Type()) && !isOSFileType(p.Type()) {
			if !isBasicUnsafePointerType(p.Type()) || !allReferrersConfinedToSyscallOrRuntimeSink(p, trapArg0Stubs, map[ssa.Value]bool{}, 0) {
				return true
			}
			verifiedVals[p] = true
		}
	}
	for _, fv := range fn.FreeVars {
		if fv != nil && typeUsesUnsafePointer(fv.Type()) && !isOSFileType(fv.Type()) {
			return true
		}
	}
	blocks := liveBlocks(fn, nil)
	liveSet := make(map[*ssa.BasicBlock]bool, len(blocks))
	for _, blk := range blocks {
		liveSet[blk] = true
	}
	var ops [16]*ssa.Value
	for _, blk := range blocks {
		for _, instr := range blk.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil && !site.Common().IsInvoke() {
				if bi, okBI := site.Common().Value.(*ssa.Builtin); okBI {
					if bi.Name() == "Add" || bi.Name() == "Slice" {
						return true
					}
				}
			}
			if v, ok := instr.(ssa.Value); ok && typeUsesUnsafePointer(v.Type()) && !isOSFileType(v.Type()) {
				if !isSafeSyscallUnsafePtrOrigin(v, map[ssa.Value]bool{}) ||
					!allLiveReferrersConfinedToSyscallOrRuntimeSink(v, liveSet, trapArg0Stubs, map[ssa.Value]bool{}, 0) {
					return true
				}
				verifiedVals[v] = true
			}
		}
	}
	for _, blk := range blocks {
		for _, instr := range blk.Instrs {
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil || verifiedVals[*op] {
					continue
				}
				if k, ok := (*op).(*ssa.Const); ok && k.IsNil() {
					continue
				}
				if typeUsesUnsafePointer((*op).Type()) && !isOSFileType((*op).Type()) {
					return true
				}
			}
		}
	}
	return false
}

func isBasicUnsafePointerType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

func isStdRuntimeAddrOnlySink(pkgPath, sym string) bool {
	if pkgPath != "runtime" {
		return false
	}
	switch sym {
	case "KeepAlive", "RaceAcquire", "RaceRelease", "RaceReleaseMerge", "RaceRead", "RaceWrite", "RaceReadRange", "RaceWriteRange":
		return true
	default:
		return false
	}
}

func isSafeSyscallUnsafePtrOrigin(v ssa.Value, seen map[ssa.Value]bool) bool {
	if v == nil {
		return false
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	switch x := v.(type) {
	case *ssa.Const:
		return x.IsNil()
	case *ssa.Convert:
		if x.X == nil {
			return false
		}
		ptr, ok := types.Unalias(x.X.Type()).Underlying().(*types.Pointer)
		return ok && !typeUsesUnsafePointer(ptr.Elem())
	case *ssa.Phi:
		if len(x.Edges) == 0 {
			return false
		}
		for _, e := range x.Edges {
			if !isSafeSyscallUnsafePtrOrigin(e, seen) {
				return false
			}
		}
		return true
	case *ssa.Call:
		if x.Call.IsInvoke() {
			return false
		}
		bi, ok := x.Call.Value.(*ssa.Builtin)
		return ok && (bi.Name() == "StringData" || bi.Name() == "SliceData")
	default:
		return false
	}
}

func allReferrersConfinedToSyscallOrRuntimeSink(v ssa.Value, trapArg0Stubs map[*ssa.Function]bool, seen map[ssa.Value]bool, depth int) bool {
	return allLiveReferrersConfinedToSyscallOrRuntimeSink(v, nil, trapArg0Stubs, seen, depth)
}

func allLiveReferrersConfinedToSyscallOrRuntimeSink(v ssa.Value, liveSet map[*ssa.BasicBlock]bool, trapArg0Stubs map[*ssa.Function]bool, seen map[ssa.Value]bool, depth int) bool {
	if v == nil || depth > 8 {
		return false
	}
	if v.Referrers() == nil {
		return true
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	for _, ref := range *v.Referrers() {
		if liveSet != nil && ref.Block() != nil && !liveSet[ref.Block()] {
			continue
		}
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.Phi:
			if !allLiveReferrersConfinedToSyscallOrRuntimeSink(r, liveSet, trapArg0Stubs, seen, depth) {
				return false
			}
		case *ssa.Convert:
			b, ok := types.Unalias(r.Type()).Underlying().(*types.Basic)
			if !ok || b.Kind() != types.Uintptr || r.Referrers() == nil {
				return false
			}
			for _, uRef := range *r.Referrers() {
				if liveSet != nil && uRef.Block() != nil && !liveSet[uRef.Block()] {
					continue
				}
				if _, isDbg := uRef.(*ssa.DebugRef); isDbg {
					continue
				}
				site, ok := uRef.(ssa.CallInstruction)
				if !ok || site.Common() == nil || site.Common().IsInvoke() {
					return false
				}
				callee := site.Common().StaticCallee()
				if callee == nil {
					return false
				}
				callee = unwrapSyntheticTargetFunc(callee)
				if !trapArg0Stubs[callee] && !isStdRawSyscallFunc(funcPkgPath(callee), baseFunctionSymbolName(callee)) {
					return false
				}
				if len(site.Common().Args) > 0 && site.Common().Args[0] == r {
					return false
				}
			}
		case ssa.CallInstruction:
			if r.Common() == nil || r.Common().IsInvoke() {
				return false
			}
			callee := r.Common().StaticCallee()
			if callee == nil || callee == r.Parent() {
				return false
			}
			callee = unwrapSyntheticTargetFunc(callee)
			if isStdRuntimeAddrOnlySink(funcPkgPath(callee), baseFunctionSymbolName(callee)) {
				continue
			}
			if len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == v {
					p := callee.Params[i]
					if p == nil || !isBasicUnsafePointerType(p.Type()) || !allReferrersConfinedToSyscallOrRuntimeSink(p, trapArg0Stubs, map[ssa.Value]bool{}, depth+1) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func instrBoxesOSFileIntoEmptyInterface(instr ssa.Instruction) bool {
	switch x := instr.(type) {
	case *ssa.MakeInterface:
		iface, ok := types.Unalias(x.Type()).Underlying().(*types.Interface)
		if !ok || iface.NumMethods() != 0 || x.X == nil {
			return false
		}
		return typeExposesOSFileToTemplate(x.X.Type(), map[types.Type]bool{})
	case *ssa.ChangeInterface:
		iface, ok := types.Unalias(x.Type()).Underlying().(*types.Interface)
		if !ok || iface.NumMethods() != 0 || x.X == nil {
			return false
		}
		return typeExposesOSFileToTemplate(x.X.Type(), map[types.Type]bool{})
	default:
		return false
	}
}

func typeExposesOSFileToTemplate(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if isOSFileType(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	if _, isIface := t.Underlying().(*types.Interface); !isIface {
		ms := types.NewMethodSet(t)
		for i := 0; i < ms.Len(); i++ {
			fn, ok := ms.At(i).Obj().(*types.Func)
			if !ok || !fn.Exported() {
				continue
			}
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig.Results() == nil || sig.Results().Len() == 0 || sig.Results().Len() > 2 {
				continue
			}
			if typeExposesOSFileToTemplate(sig.Results().At(0).Type(), seen) {
				return true
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return typeExposesOSFileToTemplate(u.Elem(), seen)
	case *types.Slice:
		return typeExposesOSFileToTemplate(u.Elem(), seen)
	case *types.Array:
		return typeExposesOSFileToTemplate(u.Elem(), seen)
	case *types.Map:
		return typeExposesOSFileToTemplate(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if u.Field(i).Exported() && typeExposesOSFileToTemplate(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func typeContainsInterfaceOrChan(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Interface, *types.Chan, *types.Signature:
		return true
	case *types.Pointer:
		return typeContainsInterfaceOrChan(u.Elem(), seen)
	case *types.Slice:
		return typeContainsInterfaceOrChan(u.Elem(), seen)
	case *types.Array:
		return typeContainsInterfaceOrChan(u.Elem(), seen)
	case *types.Map:
		return typeContainsInterfaceOrChan(u.Key(), seen) || typeContainsInterfaceOrChan(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeContainsInterfaceOrChan(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isRuntimeAsyncSpawnerSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "time", "context":
		return sym == "AfterFunc"
	case "runtime":
		return sym == "SetFinalizer" || sym == "AddCleanup"
	}
	return false
}

func isTestingSerialRunnerFrame(sym string) bool {
	switch sym {
	case "tRunner", "runN", "run1", "runBenchmarks", "RunTests", "MainStart", "Run":
		return true
	}
	return false
}

func extractAsyncCallbackTargets(c *ssa.CallCommon, argIdx int, provFP *freshParamAnalysis, out *[]*ssa.Function) bool {
	if c == nil || argIdx < 0 || argIdx >= len(c.Args) {
		return false
	}
	raw := c.Args[argIdx]
	v := raw
	for v != nil {
		switch u := v.(type) {
		case *ssa.MakeInterface:
			v = u.X
		case *ssa.ChangeInterface:
			v = u.X
		case *ssa.ChangeType:
			v = u.X
		default:
			goto unwrapped
		}
	}
unwrapped:
	if v == nil {
		return false
	}
	if k, ok := v.(*ssa.Const); ok && k.IsNil() {
		return true
	}
	switch x := v.(type) {
	case *ssa.Function:
		*out = append(*out, x)
		return true
	case *ssa.MakeClosure:
		cb, ok := x.Fn.(*ssa.Function)
		if !ok || cb == nil {
			return false
		}
		*out = append(*out, cb)
		return true
	default:
		if provFP == nil {
			return false
		}
		targets, closed := closedDynamicTargets(raw, provFP)
		if !closed || len(targets) == 0 {
			return false
		}
		for cb := range targets {
			if cb != nil {
				*out = append(*out, cb)
			}
		}
		return true
	}
}

func (b *tier2Base) goroutinesReachTestingChdir(binaryFns map[*ssa.Function]bool, prep *preparedProgramRTA, unionMask uint64) (bool, string) {
	var goRoots []*ssa.Function
	var ops [16]*ssa.Value
	for fn := range binaryFns {
		if fn == nil || len(fn.Blocks) == 0 {
			continue
		}
		idx := b.idxForFunction(fn)
		if idx != nil && idx.testMain {
			continue
		}
		fnPkg := funcPkgPath(fn)
		if fnPkg == "testing" && !prep.userPaths["testing"] && baseFunctionSymbolName(fn) != "RunParallel" {
			continue
		}
		isStd := (idx != nil && idx.std) || (idx == nil && isStdPkgPath(prep.userPaths, fnPkg))
		for _, blk := range liveBlocks(fn, nil) {
			for _, instr := range blk.Instrs {
				if goSite, isGo := instr.(*ssa.Go); isGo {
					c := &goSite.Call
					if _, _, ok := matchTestingChdirCallSite(c, prep.userPaths); ok {
						return true, "goroutine_testing_chdir"
					}
					if c.IsInvoke() && c.Method != nil && c.Method.Name() == "Chdir" && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && !prep.userPaths["testing"] {
						return true, "goroutine_testing_chdir"
					}
					if callee := c.StaticCallee(); callee != nil {
						goRoots = append(goRoots, callee)
					}
					for target, tmask := range prep.res.Targets[goSite] {
						if tmask&unionMask != 0 && target != nil {
							goRoots = append(goRoots, target)
						}
					}
					for target, tmask := range prep.res.HarnessStdTargets[goSite] {
						if tmask&unionMask != 0 && target != nil {
							goRoots = append(goRoots, target)
						}
					}
				}
				if isStd {
					continue
				}
				site, isCall := instr.(ssa.CallInstruction)
				var staticCalleeVal ssa.Value
				if isCall && site.Common() != nil && !site.Common().IsInvoke() {
					staticCalleeVal = site.Common().Value
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil || *op == staticCalleeVal {
						continue
					}
					if fnOp, ok := (*op).(*ssa.Function); ok {
						t := unwrapSyntheticTargetFunc(fnOp)
						if isStdPkgPath(prep.userPaths, funcPkgPath(t)) && isRuntimeAsyncSpawnerSymbol(funcPkgPath(t), baseFunctionSymbolName(t)) {
							return true, "detached_async_spawner:" + fn.String()
						}
					}
				}
				if !isCall || site.Common() == nil {
					continue
				}
				c := site.Common()
				checkSpawner := func(callee *ssa.Function) bool {
					if callee == nil {
						return true
					}
					t := unwrapSyntheticTargetFunc(callee)
					tPkg, tSym := funcPkgPath(t), baseFunctionSymbolName(t)
					if isStdPkgPath(prep.userPaths, tPkg) && isRuntimeAsyncSpawnerSymbol(tPkg, tSym) {
						return extractAsyncCallbackTargets(c, 1, prep.provFP, &goRoots)
					}
					return true
				}
				if !checkSpawner(c.StaticCallee()) {
					return true, "unclosed_async_spawner:" + fn.String()
				}
				for target, tmask := range prep.res.Targets[site] {
					if tmask&unionMask != 0 && target != c.StaticCallee() && !checkSpawner(target) {
						return true, "unclosed_async_spawner:" + fn.String()
					}
				}
			}
		}
	}
	if b.coneReachesTestingChdir(goRoots, prep, unionMask) {
		return true, "goroutine_testing_chdir"
	}
	return false, ""
}

func (b *tier2Base) coneReachesTestingChdir(roots []*ssa.Function, prep *preparedProgramRTA, unionMask uint64) bool {
	if len(roots) == 0 {
		return false
	}
	goCone := map[*ssa.Function]bool{}
	seenHarnessCB := map[*ssa.Function]bool{}
	queue := append([]*ssa.Function(nil), roots...)
	for {
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur == nil || goCone[cur] || isTestingMRun(cur) {
				continue
			}
			curUnwrapped := unwrapSyntheticTargetFunc(cur)
			if (funcPkgPath(cur) == "testing" && !prep.userPaths["testing"] && baseFunctionSymbolName(cur) == "Chdir") ||
				(funcPkgPath(curUnwrapped) == "testing" && !prep.userPaths["testing"] && baseFunctionSymbolName(curUnwrapped) == "Chdir") {
				return true
			}
			goCone[cur] = true
			curPkg := funcPkgPath(cur)
			if curPkg == "testing" && !prep.userPaths["testing"] && isTestingSerialRunnerFrame(baseFunctionSymbolName(cur)) {
				continue
			}
			curIdx := b.idxForFunction(cur)
			curIsStd := (curIdx != nil && curIdx.std) || (curIdx == nil && isStdPkgPath(prep.userPaths, curPkg))
			for _, blk := range cur.Blocks {
				for _, instr := range blk.Instrs {
					site, ok := instr.(ssa.CallInstruction)
					if !ok || site.Common() == nil {
						continue
					}
					c := site.Common()
					if c.IsInvoke() && c.Method != nil && c.Method.Name() == "Chdir" && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && !prep.userPaths["testing"] {
						return true
					}
					enqueueCallee := func(callee *ssa.Function) bool {
						if callee == nil {
							return false
						}
						t := unwrapSyntheticTargetFunc(callee)
						if isTestingMRun(t) {
							return false
						}
						tPkg, tSym := funcPkgPath(t), baseFunctionSymbolName(t)
						if tPkg == "testing" && !prep.userPaths["testing"] {
							if tSym == "Chdir" {
								return true
							}
							if tSym == "Run" {
								cbIdx := 2
								if c.IsInvoke() {
									cbIdx = 1
								}
								if !extractAsyncCallbackTargets(c, cbIdx, prep.provFP, &queue) {
									return true
								}
							}
						}
						if !curIsStd && isStdPkgPath(prep.userPaths, tPkg) && isRuntimeAsyncSpawnerSymbol(tPkg, tSym) {
							if !extractAsyncCallbackTargets(c, 1, prep.provFP, &queue) {
								return true
							}
						}
						queue = append(queue, callee)
						if t != callee {
							queue = append(queue, t)
						}
						return false
					}
					if enqueueCallee(c.StaticCallee()) {
						return true
					}
					for target, tmask := range prep.res.Targets[site] {
						if tmask&unionMask != 0 && target != c.StaticCallee() && enqueueCallee(target) {
							return true
						}
					}
					for target, tmask := range prep.res.HarnessStdTargets[site] {
						if tmask&unionMask != 0 && target != c.StaticCallee() && enqueueCallee(target) {
							return true
						}
					}
				}
			}
		}
		nonTestingCone := map[*ssa.Function]bool{}
		for fn := range goCone {
			fnPkg := funcPkgPath(fn)
			if (fnPkg == "testing" && !prep.userPaths["testing"]) || prep.verifiedHarnesses[fnPkg] != nil {
				continue
			}
			nonTestingCone[fn] = true
		}
		cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(true, prep.verifiedHarnesses, b.h.PureDelegates(), prep.userPaths, prep.summary, nil, false, enumerationClosure{}, nonTestingCone, unionMask, prep.res)
		if unclosedCB || unclosedFB {
			return true
		}
		for _, cb := range cbs {
			if !seenHarnessCB[cb] {
				seenHarnessCB[cb] = true
				queue = append(queue, cb)
			}
		}
		for _, fb := range fbs {
			if !seenHarnessCB[fb] {
				seenHarnessCB[fb] = true
				queue = append(queue, fb)
			}
		}
		if len(queue) == 0 {
			break
		}
	}
	return false
}
