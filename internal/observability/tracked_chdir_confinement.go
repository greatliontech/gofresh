package observability

import (
	"context"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/rta"
	"github.com/greatliontech/gofresh/internal/trace"
)

func matchTestingChdirCallSite(c *ssa.CallCommon, userPaths map[string]bool) (recv, dirArg ssa.Value, ok bool) {
	if c == nil || userPaths["testing"] {
		return nil, nil, false
	}
	if c.IsInvoke() {
		if c.Method != nil && c.Method.Name() == "Chdir" && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && len(c.Args) == 1 {
			return c.Value, c.Args[0], true
		}
		return nil, nil, false
	}
	callee := c.StaticCallee()
	if callee == nil {
		return nil, nil, false
	}
	target := unwrapSyntheticTargetFunc(callee)
	if funcPkgPath(target) == "testing" && baseFunctionSymbolName(target) == "Chdir" {
		if len(c.Args) == 2 {
			return c.Args[0], c.Args[1], true
		}
		return nil, nil, false
	}
	return nil, nil, false
}

func unwrapTestingHandleValue(v ssa.Value) ssa.Value {
	seen := map[ssa.Value]bool{}
	for v != nil {
		if seen[v] {
			return nil
		}
		seen[v] = true
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.FieldAddr:
			if x.Field == 0 && x.X != nil {
				if ptr, ok := types.Unalias(x.X.Type()).(*types.Pointer); ok {
					if named, okNamed := types.Unalias(ptr.Elem()).(*types.Named); okNamed && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" {
						v = x.X
						continue
					}
				}
			}
			return v
		case *ssa.UnOp:
			if x.Op == token.MUL {
				if alloc, ok := x.X.(*ssa.Alloc); ok {
					if single := singleStoredAllocValue(alloc); single != nil {
						v = single
						continue
					}
				}
			}
			return v
		default:
			return v
		}
	}
	return nil
}

func singleStoredAllocValue(alloc *ssa.Alloc) ssa.Value {
	if alloc == nil || alloc.Referrers() == nil {
		return nil
	}
	var stored ssa.Value
	for _, ref := range *alloc.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.UnOp:
			if r.Op != token.MUL {
				return nil
			}
		case *ssa.Store:
			if r.Addr != alloc || stored != nil {
				return nil
			}
			stored = r.Val
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || len(r.Bindings) != len(fn.FreeVars) {
				return nil
			}
			for i, b := range r.Bindings {
				if b == alloc && !freeVarCellIsReadOnly(fn.FreeVars[i], map[*ssa.FreeVar]bool{}) {
					return nil
				}
			}
		default:
			return nil
		}
	}
	return stored
}

func freeVarCellIsReadOnly(fv *ssa.FreeVar, seen map[*ssa.FreeVar]bool) bool {
	if fv == nil || fv.Referrers() == nil || seen[fv] {
		return true
	}
	seen[fv] = true
	for _, ref := range *fv.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.UnOp:
			if r.Op != token.MUL {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || len(r.Bindings) != len(fn.FreeVars) {
				return false
			}
			for i, b := range r.Bindings {
				if b == fv && !freeVarCellIsReadOnly(fn.FreeVars[i], seen) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func isSameHandleTestingTempDirCall(baseRecv ssa.Value, call *ssa.Call, userPaths map[string]bool) bool {
	if baseRecv == nil || call == nil || userPaths["testing"] {
		return false
	}
	c := &call.Call
	if c.IsInvoke() {
		if c.Method != nil && c.Method.Name() == "TempDir" && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && len(c.Args) == 0 {
			return unwrapTestingHandleValue(c.Value) == baseRecv
		}
		return false
	}
	callee := c.StaticCallee()
	if callee == nil {
		return false
	}
	target := unwrapSyntheticTargetFunc(callee)
	if funcPkgPath(target) == "testing" && baseFunctionSymbolName(target) == "TempDir" && len(c.Args) == 1 {
		return unwrapTestingHandleValue(c.Args[0]) == baseRecv
	}
	return false
}

func isSameHandleTestingTempDirTarget(fn *ssa.Function, recv, dirArg ssa.Value, userPaths map[string]bool) bool {
	baseRecv := unwrapTestingHandleValue(recv)
	if fn == nil || baseRecv == nil || dirArg == nil {
		return false
	}
	sawTempCall := false
	visiting := map[ssa.Value]bool{}
	done := map[ssa.Value]bool{}
	var walk func(v ssa.Value) bool
	walk = func(v ssa.Value) bool {
		if v == nil {
			return false
		}
		if done[v] {
			return true
		}
		switch x := v.(type) {
		case *ssa.Call:
			if x.Parent() != fn || !isSameHandleTestingTempDirCall(baseRecv, x, userPaths) {
				return false
			}
			done[v] = true
			sawTempCall = true
			return true
		case *ssa.Phi:
			if x.Parent() != fn || len(x.Edges) == 0 {
				return false
			}
			if visiting[x] {
				return true
			}
			visiting[x] = true
			for _, e := range x.Edges {
				if !walk(e) {
					delete(visiting, x)
					return false
				}
			}
			delete(visiting, x)
			done[x] = true
			return true
		case *ssa.UnOp:
			if x.Op == token.MUL {
				if alloc, ok := x.X.(*ssa.Alloc); ok && alloc.Parent() == fn {
					if visiting[alloc] {
						return false
					}
					visiting[alloc] = true
					stored := singleStoredAllocValue(alloc)
					okStored := stored != nil && walk(stored)
					delete(visiting, alloc)
					if okStored {
						done[v] = true
						return true
					}
				}
			}
			return false
		default:
			return false
		}
	}
	return walk(dirArg) && sawTempCall
}

func (b *tier2Base) verifyTestingChdirCallTarget(
	fn *ssa.Function,
	site ssa.CallInstruction,
	recv, dirArg ssa.Value,
	binaryFns map[*ssa.Function]bool,
	prep *preparedProgramRTA,
	unionMask uint64,
	trapArg0Stubs map[*ssa.Function]bool,
	removeOrRenameTraps map[uint64]bool,
	symlinkTraps map[uint64]bool,
	hasSyscallConsts bool,
	getCallerCone func(*ssa.Function) (map[*ssa.Function]bool, bool),
) (bool, string) {
	if !isSameHandleTestingTempDirTarget(fn, recv, dirArg, prep.userPaths) {
		if coneReachesTestingTempOrArtifactDir(b, binaryFns, prep.res, unionMask, prep.userPaths) {
			return false, "non_temp_target_with_tempdir_or_artifactdir"
		}
		if b.coneReachesDirRemoveOrRename(binaryFns, prep.res, unionMask, trapArg0Stubs, removeOrRenameTraps, hasSyscallConsts) {
			return false, "non_temp_target_with_remove_or_rename"
		}
		if b.coneReachesSymlink(binaryFns, prep.res, unionMask, trapArg0Stubs, symlinkTraps, hasSyscallConsts) {
			return false, "non_temp_target_with_symlink"
		}
		if coneReachesProcessSpawn(b, binaryFns, prep.res, unionMask) {
			return false, "non_temp_target_with_spawn"
		}
		return true, ""
	}
	cone, ok := getCallerCone(fn)
	if !ok {
		return false, "caller_cone_unavailable"
	}
	reachesRemove, removeCulprit := b.coneReachesDirRemoveOrRenameWithCulprit(cone, prep.res, unionMask, trapArg0Stubs, removeOrRenameTraps, hasSyscallConsts)
	reachesSpawn, spawnCulprit := coneReachesProcessSpawnWithCulprit(b, cone, prep.res, unionMask)
	if !reachesRemove && !reachesSpawn {
		return true, ""
	}
	if trace.AnyEnabled() {
		ctx := context.Background()
		if b.h != nil && b.h.Context() != nil {
			ctx = b.h.Context()
		}
		if trace.Enabled(ctx, trace.DomainClosure, b.prog.PkgPath) {
			trace.Emit(ctx, trace.DomainClosure, "closure.tracked_chdir.mode1_fallthrough", b.prog.PkgPath,
				trace.String("fn", fn.String()),
				trace.Bool("reaches_remove_or_rename", reachesRemove),
				trace.String("remove_culprit", removeCulprit),
				trace.Bool("reaches_spawn", reachesSpawn),
				trace.String("spawn_culprit", spawnCulprit),
			)
		}
	}
	// Single synchronous unlooped top-level t.Chdir(t.TempDir()) with a benign
	// acyclic prefix, dead/write-only tc uses, no direct fs-remove/symlink/readdir
	// in fn, and only same-handle TempDir Chdir sites across the binary.
	if _, isDirectCall := site.(*ssa.Call); !isDirectCall {
		return false, "mode2_deferred_or_async_chdir"
	}
	baseRecv := unwrapTestingHandleValue(recv)
	tc, okTC := dirArg.(*ssa.Call)
	if !okTC || tc.Parent() != fn || !isGoTestExecutableRoot(fn.Name(), fn) || !isSameHandleTestingTempDirCall(baseRecv, tc, prep.userPaths) {
		return false, "mode2_not_direct_root_tempdir"
	}
	if !tempDirCallConfinedToChdirAndBenignWrites(tc, site, prep.userPaths) {
		return false, "mode2_tempdir_escapes"
	}
	if fnDirectlyCallsRemoveSymlinkOrReadDir(fn, trapArg0Stubs, removeOrRenameTraps, symlinkTraps, hasSyscallConsts) {
		return false, "mode2_fn_direct_fsmut"
	}
	if countTestingChdirSitesInCone(b, cone, prep.res, unionMask, prep.userPaths) != 1 {
		return false, "mode2_multi_chdir_in_cone"
	}
	if b.coneReferencesExactFunc(binaryFns, prep.res, unionMask, fn) {
		return false, "mode2_fn_called_by_go_code"
	}
	if !b.allBinaryTestingChdirSitesUseSameHandleTempDir(binaryFns, prep.res, unionMask, prep.userPaths) {
		return false, "mode2_non_temp_sibling_chdir"
	}
	if !hasBenignAcyclicPrefixToChdir(fn, tc, site, prep.userPaths) {
		return false, "mode2_impure_or_cyclic_prefix"
	}
	return true, ""
}

func tempDirCallConfinedToChdirAndBenignWrites(tc *ssa.Call, chdirSite ssa.CallInstruction, userPaths map[string]bool) bool {
	if tc == nil || tc.Referrers() == nil {
		return false
	}
	for _, ref := range *tc.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case ssa.CallInstruction:
			if r == chdirSite {
				continue
			}
			return false
		case *ssa.Store:
			ia, ok := r.Addr.(*ssa.IndexAddr)
			if !ok || r.Val != tc {
				return false
			}
			alloc, ok := ia.X.(*ssa.Alloc)
			if !ok || !isJoinAllocConsumedOnlyByBenignOSWrite(alloc, userPaths) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isJoinAllocConsumedOnlyByBenignOSWrite(alloc *ssa.Alloc, userPaths map[string]bool) bool {
	if alloc == nil || !isJoinBackingSliceAlloc(alloc, userPaths) {
		return false
	}
	var outputs []ssa.Value
	enqueueJoinSliceOutputs(alloc, &outputs)
	if len(outputs) == 0 {
		return false
	}
	for _, out := range outputs {
		if out == nil || out.Referrers() == nil {
			continue
		}
		for _, ref := range *out.Referrers() {
			if _, isDbg := ref.(*ssa.DebugRef); isDbg {
				continue
			}
			site, ok := ref.(ssa.CallInstruction)
			if !ok || site.Common() == nil || site.Common().IsInvoke() {
				return false
			}
			callee := site.Common().StaticCallee()
			if callee == nil {
				return false
			}
			t := unwrapSyntheticTargetFunc(callee)
			pkg, sym := funcPkgPath(t), baseFunctionSymbolName(t)
			if pkg != "os" || userPaths["os"] || (sym != "WriteFile" && sym != "Mkdir" && sym != "MkdirAll") {
				return false
			}
			for i, arg := range site.Common().Args {
				if arg == out && i != 0 {
					return false
				}
			}
		}
	}
	return true
}

func isJoinBackingSliceAlloc(alloc *ssa.Alloc, userPaths map[string]bool) bool {
	if alloc == nil || alloc.Referrers() == nil {
		return false
	}
	sawJoin := false
	for _, ref := range *alloc.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef, *ssa.IndexAddr:
			continue
		case *ssa.Slice:
			if r.Referrers() == nil {
				return false
			}
			for _, sRef := range *r.Referrers() {
				site, ok := sRef.(ssa.CallInstruction)
				if !ok || site.Common() == nil || site.Common().IsInvoke() {
					return false
				}
				callee := site.Common().StaticCallee()
				if callee == nil {
					return false
				}
				pkg, sym := funcPkgPath(callee), baseFunctionSymbolName(callee)
				if !isStdPkgPath(userPaths, pkg) || (pkg != "path/filepath" && pkg != "path") || sym != "Join" {
					return false
				}
				sawJoin = true
			}
		default:
			return false
		}
	}
	return sawJoin
}

func enqueueJoinSliceOutputs(alloc *ssa.Alloc, queue *[]ssa.Value) {
	if alloc == nil || alloc.Referrers() == nil {
		return
	}
	for _, ref := range *alloc.Referrers() {
		sl, ok := ref.(*ssa.Slice)
		if !ok || sl.Referrers() == nil {
			continue
		}
		for _, sRef := range *sl.Referrers() {
			if callVal, ok := sRef.(ssa.Value); ok {
				*queue = append(*queue, callVal)
			}
		}
	}
}

func fnDirectlyCallsRemoveSymlinkOrReadDir(fn *ssa.Function, trapArg0Stubs map[*ssa.Function]bool, removeOrRenameTraps, symlinkTraps map[uint64]bool, hasSyscallConsts bool) bool {
	if fn == nil {
		return false
	}
	for _, blk := range liveBlocks(fn, nil) {
		for _, instr := range blk.Instrs {
			site, ok := instr.(ssa.CallInstruction)
			if !ok || site.Common() == nil {
				continue
			}
			c := site.Common()
			callee := c.StaticCallee()
			if callee == nil {
				continue
			}
			t := unwrapSyntheticTargetFunc(callee)
			pkg, sym := funcPkgPath(t), baseFunctionSymbolName(t)
			if isDirRemoveOrRenameSymbol(pkg, sym) || isSymlinkCreateSymbol(pkg, sym) {
				return true
			}
			if pkg == "os" && (sym == "ReadDir" || sym == "Open") {
				return true
			}
			if pkg == "path/filepath" && sym == "Glob" {
				return true
			}
			if trapArg0Stubs[t] || isStdRawSyscallFunc(pkg, sym) {
				if !hasSyscallConsts || sym == "SyscallN" || sym == "Call" || len(c.Args) < 1 || !isAllowedSyscallTrapConst(c.Args[0], removeOrRenameTraps) || !isAllowedSyscallTrapConst(c.Args[0], symlinkTraps) {
					return true
				}
			}
		}
	}
	return false
}

func (b *tier2Base) forEachTestingChdirSite(
	fns map[*ssa.Function]bool,
	res *rta.Result,
	unionMask uint64,
	userPaths map[string]bool,
	visit func(fn *ssa.Function, recv, dirArg ssa.Value, matchedDirect bool) bool,
) bool {
	for fn := range fns {
		if fn == nil {
			continue
		}
		idx := b.idxForFunction(fn)
		if idx != nil && (idx.std || idx.testMain) {
			continue
		}
		if idx == nil && isStdPkgPath(userPaths, funcPkgPath(fn)) {
			continue
		}
		for _, blk := range liveBlocks(fn, nil) {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				c := site.Common()
				if recv, dirArg, matched := matchTestingChdirCallSite(c, userPaths); matched {
					if !visit(fn, recv, dirArg, true) {
						return false
					}
					continue
				}
				if res != nil {
					for target, tmask := range res.Targets[site] {
						if tmask&unionMask != 0 && target != nil && target != c.StaticCallee() {
							t := unwrapSyntheticTargetFunc(target)
							if funcPkgPath(t) == "testing" && !userPaths["testing"] && baseFunctionSymbolName(t) == "Chdir" {
								if !visit(fn, nil, nil, false) {
									return false
								}
								break
							}
						}
					}
				}
			}
		}
	}
	return true
}

func (b *tier2Base) allBinaryTestingChdirSitesUseSameHandleTempDir(binaryFns map[*ssa.Function]bool, res *rta.Result, unionMask uint64, userPaths map[string]bool) bool {
	return b.forEachTestingChdirSite(binaryFns, res, unionMask, userPaths, func(fn *ssa.Function, recv, dirArg ssa.Value, matchedDirect bool) bool {
		if !matchedDirect {
			return false
		}
		return isSameHandleTestingTempDirTarget(fn, recv, dirArg, userPaths)
	})
}

func countTestingChdirSitesInCone(b *tier2Base, cone map[*ssa.Function]bool, res *rta.Result, unionMask uint64, userPaths map[string]bool) int {
	count := 0
	b.forEachTestingChdirSite(cone, res, unionMask, userPaths, func(*ssa.Function, ssa.Value, ssa.Value, bool) bool {
		count++
		return true
	})
	return count
}

func hasBenignAcyclicPrefixToChdir(fn *ssa.Function, tc *ssa.Call, site ssa.CallInstruction, userPaths map[string]bool) bool {
	if fn == nil || tc == nil || site == nil || site.Block() == nil || !instructionDominates(tc, site) {
		return false
	}
	targetBlk := site.Block()
	anc := map[*ssa.BasicBlock]bool{}
	stack := []*ssa.BasicBlock{targetBlk}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur == nil || anc[cur] {
			continue
		}
		anc[cur] = true
		for _, pred := range cur.Preds {
			if !anc[pred] {
				stack = append(stack, pred)
			}
		}
	}
	color := map[*ssa.BasicBlock]uint8{}
	var hasCycle func(*ssa.BasicBlock) bool
	hasCycle = func(blk *ssa.BasicBlock) bool {
		color[blk] = 1
		for _, succ := range blk.Succs {
			if !anc[succ] {
				continue
			}
			if color[succ] == 1 {
				return true
			}
			if color[succ] == 0 && hasCycle(succ) {
				return true
			}
		}
		color[blk] = 2
		return false
	}
	for blk := range anc {
		if color[blk] == 0 && hasCycle(blk) {
			return false
		}
	}
	var ops [16]*ssa.Value
	for blk := range anc {
		for _, instr := range blk.Instrs {
			if blk == targetBlk && instr == site {
				break
			}
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil {
					continue
				}
				if g, ok := (*op).(*ssa.Global); ok && typeContainsInterfaceOrChan(g.Type(), map[types.Type]bool{}) {
					return false
				}
			}
			switch x := instr.(type) {
			case *ssa.Go, *ssa.Defer, *ssa.TypeAssert, *ssa.Select:
				return false
			case *ssa.UnOp:
				if x.Op == token.ARROW {
					return false
				}
			case *ssa.MakeInterface:
				if x.X == nil {
					return false
				}
				basic, ok := types.Unalias(x.X.Type()).(*types.Basic)
				if !ok || basic.Info()&(types.IsBoolean|types.IsNumeric|types.IsString) == 0 {
					return false
				}
			case *ssa.ChangeInterface:
				if !isBenignPrefixOriginError(x.X, anc, userPaths, map[ssa.Value]bool{}) {
					return false
				}
			case ssa.CallInstruction:
				if x.Common() == nil || x.Common().IsInvoke() {
					return false
				}
				callee := x.Common().StaticCallee()
				if callee == nil {
					return false
				}
				t := unwrapSyntheticTargetFunc(callee)
				pkg, sym := funcPkgPath(t), baseFunctionSymbolName(t)
				if !isBenignPrefixStdCallee(pkg, sym, userPaths) {
					return false
				}
			}
		}
	}
	return true
}

func isBenignPrefixOriginError(v ssa.Value, anc map[*ssa.BasicBlock]bool, userPaths map[string]bool, seen map[ssa.Value]bool) bool {
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
	case *ssa.Phi:
		if len(x.Edges) == 0 {
			return false
		}
		for _, e := range x.Edges {
			if !isBenignPrefixOriginError(e, anc, userPaths, seen) {
				return false
			}
		}
		return true
	case *ssa.Extract:
		return isBenignPrefixOriginError(x.Tuple, anc, userPaths, seen)
	case *ssa.Call:
		if x.Block() == nil || !anc[x.Block()] || x.Call.IsInvoke() {
			return false
		}
		callee := x.Call.StaticCallee()
		if callee == nil {
			return false
		}
		t := unwrapSyntheticTargetFunc(callee)
		return isBenignPrefixStdCallee(funcPkgPath(t), baseFunctionSymbolName(t), userPaths)
	default:
		return false
	}
}

func isBenignPrefixStdCallee(pkgPath, sym string, userPaths map[string]bool) bool {
	if userPaths[pkgPath] {
		return false
	}
	switch pkgPath {
	case "testing":
		switch sym {
		case "TempDir", "Setenv", "Fatal", "Fatalf", "Fail", "FailNow", "Error", "Errorf", "Skip", "Skipf", "SkipNow", "Log", "Logf", "Helper":
			return true
		}
		return false
	case "path/filepath", "path":
		return sym == "Join" || sym == "Clean" || sym == "FromSlash" || sym == "ToSlash"
	case "os":
		return sym == "WriteFile" || sym == "Mkdir" || sym == "MkdirAll"
	default:
		return false
	}
}

func isDirRemoveOrRenameSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "os":
		return sym == "Remove" || sym == "RemoveAll" || sym == "Rename"
	case "syscall":
		switch sym {
		case "Rmdir", "Unlink", "Unlinkat", "Rename", "Renameat", "Renameat2", "RemoveDirectory", "MoveFile", "DeleteFile":
			return true
		}
	}
	return false
}

func isSymlinkCreateSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "os":
		return sym == "Symlink"
	case "syscall":
		return sym == "Symlink" || sym == "Symlinkat" || sym == "CreateSymbolicLink"
	}
	return false
}

func isProcessSpawnSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "os/exec":
		return sym != "init" && sym != "LookPath"
	case "os":
		return sym == "StartProcess"
	case "syscall":
		return sym == "ForkExec" || sym == "StartProcess" || sym == "CreateProcess" || sym == "CreateProcessAsUser"
	}
	return false
}

func isTestingTempOrArtifactDirSym(sym string) bool {
	return sym == "TempDir" || sym == "ArtifactDir"
}

func (b *tier2Base) coneReachesDirRemoveOrRename(
	cone map[*ssa.Function]bool,
	res *rta.Result,
	unionMask uint64,
	trapArg0Stubs map[*ssa.Function]bool,
	removeOrRenameTraps map[uint64]bool,
	hasSyscallConsts bool,
) bool {
	ok, _ := b.coneReachesDirRemoveOrRenameWithCulprit(cone, res, unionMask, trapArg0Stubs, removeOrRenameTraps, hasSyscallConsts)
	return ok
}

func (b *tier2Base) coneReachesDirRemoveOrRenameWithCulprit(
	cone map[*ssa.Function]bool,
	res *rta.Result,
	unionMask uint64,
	trapArg0Stubs map[*ssa.Function]bool,
	removeOrRenameTraps map[uint64]bool,
	hasSyscallConsts bool,
) (bool, string) {
	return b.coneMatches(cone, res, unionMask, trapArg0Stubs, removeOrRenameTraps, true, hasSyscallConsts, nil, func(t *ssa.Function) bool {
		return isDirRemoveOrRenameSymbol(funcPkgPath(t), baseFunctionSymbolName(t))
	})
}

func (b *tier2Base) coneReachesSymlink(
	cone map[*ssa.Function]bool,
	res *rta.Result,
	unionMask uint64,
	trapArg0Stubs map[*ssa.Function]bool,
	symlinkTraps map[uint64]bool,
	hasSyscallConsts bool,
) bool {
	ok, _ := b.coneMatches(cone, res, unionMask, trapArg0Stubs, symlinkTraps, true, hasSyscallConsts, nil, func(t *ssa.Function) bool {
		return isSymlinkCreateSymbol(funcPkgPath(t), baseFunctionSymbolName(t))
	})
	return ok
}

func coneReachesProcessSpawn(b *tier2Base, cone map[*ssa.Function]bool, res *rta.Result, unionMask uint64) bool {
	ok, _ := coneReachesProcessSpawnWithCulprit(b, cone, res, unionMask)
	return ok
}

func coneReachesProcessSpawnWithCulprit(b *tier2Base, cone map[*ssa.Function]bool, res *rta.Result, unionMask uint64) (bool, string) {
	return b.coneMatches(cone, res, unionMask, nil, nil, false, false, nil, func(t *ssa.Function) bool {
		return isProcessSpawnSymbol(funcPkgPath(t), baseFunctionSymbolName(t))
	})
}

func coneReachesTestingTempOrArtifactDir(b *tier2Base, cone map[*ssa.Function]bool, res *rta.Result, unionMask uint64, userPaths map[string]bool) bool {
	matchInvoke := func(c *ssa.CallCommon) bool {
		return c.Method != nil && isTestingTempOrArtifactDirSym(c.Method.Name()) && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && !userPaths["testing"]
	}
	ok, _ := b.coneMatches(cone, res, unionMask, nil, nil, false, false, matchInvoke, func(t *ssa.Function) bool {
		return funcPkgPath(t) == "testing" && !userPaths["testing"] && isTestingTempOrArtifactDirSym(baseFunctionSymbolName(t))
	})
	return ok
}

func (b *tier2Base) coneReferencesExactFunc(cone map[*ssa.Function]bool, res *rta.Result, unionMask uint64, want *ssa.Function) bool {
	if want == nil {
		return false
	}
	ok, _ := b.coneMatches(cone, res, unionMask, nil, nil, false, false, nil, func(t *ssa.Function) bool {
		return t == want
	})
	return ok
}

func (b *tier2Base) coneMatches(
	cone map[*ssa.Function]bool,
	res *rta.Result,
	unionMask uint64,
	trapArg0Stubs map[*ssa.Function]bool,
	disallowedTraps map[uint64]bool,
	checkTraps bool,
	hasSyscallConsts bool,
	matchInvoke func(*ssa.CallCommon) bool,
	matchFn func(*ssa.Function) bool,
) (bool, string) {
	userPaths := b.userPathsForCone()
	var ops [16]*ssa.Value
	for fn := range cone {
		if fn == nil {
			continue
		}
		idx := b.idxForFunction(fn)
		if idx != nil && (idx.std || idx.testMain) {
			continue
		}
		if idx == nil && isStdPkgPath(userPaths, funcPkgPath(fn)) {
			continue
		}
		for _, blk := range liveBlocks(fn, nil) {
			for _, instr := range blk.Instrs {
				site, isCall := instr.(ssa.CallInstruction)
				var staticCalleeVal ssa.Value
				if isCall && site.Common() != nil && !site.Common().IsInvoke() {
					staticCalleeVal = site.Common().Value
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil || *op == staticCalleeVal {
						continue
					}
					if fnOp, ok := (*op).(*ssa.Function); ok && matchFn(unwrapSyntheticTargetFunc(fnOp)) {
						return true, fn.String() + "->operand:" + fnOp.String()
					}
				}
				if !isCall || site.Common() == nil {
					continue
				}
				c := site.Common()
				if c.IsInvoke() && matchInvoke != nil && matchInvoke(c) {
					return true, fn.String() + "->invoke:" + c.Method.Name()
				}
				checkCallee := func(callee *ssa.Function) bool {
					if callee == nil {
						return false
					}
					t := unwrapSyntheticTargetFunc(callee)
					if matchFn(t) {
						return true
					}
					if checkTraps {
						pkg, sym := funcPkgPath(t), baseFunctionSymbolName(t)
						if trapArg0Stubs[t] || isStdRawSyscallFunc(pkg, sym) {
							if !hasSyscallConsts || sym == "SyscallN" || sym == "Call" || len(c.Args) < 1 || !isAllowedSyscallTrapConst(c.Args[0], disallowedTraps) {
								return true
							}
						}
					}
					return false
				}
				if checkCallee(c.StaticCallee()) {
					return true, fn.String() + "->call:" + c.StaticCallee().String()
				}
				if res != nil {
					for target, tmask := range res.Targets[site] {
						if tmask&unionMask != 0 && target != c.StaticCallee() && checkCallee(target) {
							return true, fn.String() + "->dyn:" + target.String()
						}
					}
				}
			}
		}
	}
	return false, ""
}

func (b *tier2Base) userPathsForCone() map[string]bool {
	if b == nil || b.prog == nil {
		return nil
	}
	return userModulePaths(b.prog.Pkgs)
}


