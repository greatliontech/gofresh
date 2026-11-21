package observability

import (
	"context"
	"go/ast"
	"go/constant"
	"go/types"
	"runtime"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/rta"
	"github.com/greatliontech/gofresh/internal/trace"
)

// binaryTrackedChdirSafe reports whether the analyzed test binary satisfies
// the toolchain and whole-binary call-graph premises required to track
// balanced LIFO testing.Chdir excursions across a shared package-test process.
func (b *tier2Base) binaryTrackedChdirSafe() bool {
	if b == nil || b.prog == nil {
		return false
	}
	if b.binaryChdirDone {
		return b.binaryChdirSafe
	}
	b.binaryChdirDone = true
	ok, reason := b.evaluateBinaryTrackedChdirSafe()
	b.binaryChdirSafe = ok
	if !ok && trace.AnyEnabled() {
		ctx := context.Background()
		if b.h != nil && b.h.Context() != nil {
			ctx = b.h.Context()
		}
		if trace.Enabled(ctx, trace.DomainClosure, b.prog.PkgPath) {
			trace.Emit(ctx, trace.DomainClosure, "closure.tracked_chdir.reject", b.prog.PkgPath,
				trace.String("reason", reason),
			)
		}
	}
	return ok
}

func (b *tier2Base) targetGOOS() string {
	if b != nil && b.h != nil {
		if v := b.h.SnapshotGOOS(); v != "" {
			return v
		}
	}
	return runtime.GOOS
}

func (b *tier2Base) evaluateBinaryTrackedChdirSafe() (bool, string) {
	if b.h == nil || !b.h.SelectionAudited() {
		return false, "unaudited_toolchain"
	}
	ctx := b.h.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, "context_cancelled"
	}

	b.ensureBinaryUnsafeEvaluated()
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.std || idx.testMain {
			continue
		}
		if hasStdPushLinkname(idx) {
			return false, "std_linkname_override:" + idx.path
		}
	}

	for name := range b.prog.Ambiguous {
		if harnessRootName(name) {
			return false, "ambiguous_harness_root:" + name
		}
	}

	const unionMask uint64 = 1
	roots := make(map[*ssa.Function]uint64)
	var testRoots []*ssa.Function
	var subjectProvenance []*ssa.Function
	includeTestMain := b.prog.TestMain != nil
	var rootNames []string
	for name := range b.prog.Roots {
		if strings.ContainsAny(name, ".#") || name == "TestMain" {
			continue
		}
		rootNames = append(rootNames, name)
	}
	sort.Strings(rootNames)
	for _, name := range rootNames {
		root := b.prog.Roots[name]
		if !isGoTestExecutableRoot(name, root) {
			continue
		}
		roots[root] |= unionMask
		testRoots = append(testRoots, root)
		subjectProvenance = append(subjectProvenance, root)
		if subjectRunsThroughHarness(b.prog, root) {
			includeTestMain = true
		}
	}
	var testMasks uint64
	if includeTestMain {
		testMasks = unionMask
		if b.prog.TestMain != nil {
			roots[b.prog.TestMain] |= unionMask
			subjectProvenance = append(subjectProvenance, b.prog.TestMain)
		}
	}

	rootedCallbacks := map[*ssa.Function]bool{}
	var provenance map[*ssa.Function]bool
	prep, ok, err := prepareProgramRTA(
		ctx,
		true,
		b.h.PureDelegates(),
		b.prog,
		roots,
		unionMask,
		testMasks,
		nil,
		true,
		true,
		func(res *rta.Result, p *preparedProgramRTA) (map[*ssa.Function]uint64, *rta.Seeds, bool, error) {
			var err error
			provenance, _, err = provenanceReachableWithCandidates(ctx, true, b.prog, subjectProvenance, unionMask, res, p.harnessAudited, p.userPaths, nil, p.enumCandidateTypes, p.initBoxedTypes, p.provFP)
			if err != nil {
				return nil, nil, false, err
			}
			cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(true, p.verifiedHarnesses, b.h.PureDelegates(), p.userPaths, p.summary, nil, false, enumerationClosure{}, provenance, unionMask, res)
			if unclosedCB || unclosedFB {
				return nil, nil, true, nil
			}
			var deltaRoots map[*ssa.Function]uint64
			var deltaSeeds *rta.Seeds
			for _, cb := range cbs {
				if !rootedCallbacks[cb] {
					rootedCallbacks[cb] = true
					if deltaRoots == nil {
						deltaRoots = make(map[*ssa.Function]uint64)
					}
					deltaRoots[cb] |= unionMask
					subjectProvenance = append(subjectProvenance, cb)
				}
			}
			for _, fb := range fbs {
				if !rootedCallbacks[fb] {
					rootedCallbacks[fb] = true
					if deltaRoots == nil {
						deltaRoots = make(map[*ssa.Function]uint64)
					}
					deltaRoots[fb] |= unionMask
					subjectProvenance = append(subjectProvenance, fb)
					addFuzzCallbackTypeSeed(&deltaSeeds, fb, unionMask)
				}
			}
			return deltaRoots, deltaSeeds, false, nil
		},
	)
	if err != nil || !ok || prep.res == nil {
		return false, "incomplete_binary_reachability"
	}

	if prep.baseStartup != nil && startupReachesTestingChdir(prep.baseStartup) {
		return false, "startup_testing_chdir"
	}
	if b.prog.TestMain != nil && b.coneReachesTestingChdir([]*ssa.Function{b.prog.TestMain}, &prep, unionMask) {
		return false, "testmain_testing_chdir"
	}

	binaryFns := make(map[*ssa.Function]bool, len(prep.res.Reachable)+len(provenance))
	for fn, mask := range prep.res.Reachable {
		if mask != 0 && fn != nil {
			binaryFns[fn] = true
		}
	}
	for fn := range provenance {
		if fn != nil {
			binaryFns[fn] = true
		}
	}

	reachesTemplate := false
	for fn := range binaryFns {
		pkg := funcPkgPath(fn)
		if pkg == "text/template" || pkg == "html/template" {
			reachesTemplate = true
			break
		}
	}

	forbiddenTraps, removeOrRenameTraps, symlinkTraps, hasSyscallConsts := b.resolveTrackedChdirSyscallTraps()
	trapArg0Stubs := map[*ssa.Function]bool{}

	for fn := range binaryFns {
		idx := b.idxForFunction(fn)
		if idx != nil && (idx.std || idx.testMain) {
			continue
		}
		if idx == nil && !isAnalyzableUnnamedWrapper(fn) && isStdImportPath(funcPkgPath(fn)) {
			continue
		}
		if idx != nil {
			if idx.wasmImport {
				return false, "wasmimport:" + idx.path
			}
			if idx.meta != nil && (hasExternalCgoMeta(idx.meta) || idx.meta.HasNonHeaderNativeSource()) {
				return false, "cgo_or_native:" + idx.path
			}
			if idx.pkg != nil && idx.pkg.Types != nil && pkgImportsCgo(idx.pkg.Types) {
				return false, "cgo_import:" + idx.path
			}
			if fnHasLinkname(idx, fn) {
				return false, "reachable_linkname:" + fn.String()
			}
		}
		if len(fn.Blocks) == 0 {
			if fn.Synthetic != "" || parameterizedBody(fn) {
				continue
			}
			if idx != nil && idx.meta != nil {
				if _, _, okAsm := b.verifiedPackageAssemblyFunc(idx.meta, fn); okAsm {
					continue
				}
				if hasSyscallConsts && b.isTrapArg0AssemblySyscallStub(idx.meta, fn) {
					trapArg0Stubs[fn] = true
					continue
				}
			}
			return false, "unverified_bodyless:" + fn.String()
		}
	}

	isWindows := b.targetGOOS() == "windows"
	var rootCones []map[*ssa.Function]bool
	rootConesComputed := false
	getCallerCone := func(targetFn *ssa.Function) (map[*ssa.Function]bool, bool) {
		if !rootConesComputed {
			rootConesComputed = true
			rootSets := make([][]*ssa.Function, len(testRoots))
			for i, tr := range testRoots {
				rootSets[i] = []*ssa.Function{tr}
			}
			var okCones bool
			rootCones, okCones = b.computePerRootRTACones(ctx, rootSets, &prep)
			if !okCones {
				rootCones = nil
				return nil, false
			}
		}
		if rootCones == nil {
			return nil, false
		}
		merged := map[*ssa.Function]bool{}
		matchedAny := false
		for _, cone := range rootCones {
			if cone[targetFn] {
				matchedAny = true
				for f := range cone {
					merged[f] = true
				}
			}
		}
		if !matchedAny {
			return binaryFns, true
		}
		return merged, true
	}

	var ops [16]*ssa.Value
	for fn := range binaryFns {
		idx := b.idxForFunction(fn)
		if idx != nil && (idx.std || idx.testMain) {
			continue
		}
		if idx == nil && !isAnalyzableUnnamedWrapper(fn) && isStdImportPath(funcPkgPath(fn)) {
			continue
		}
		if len(fn.Blocks) == 0 {
			continue
		}
		pkgHasUnsafeHazard := idx == nil || b.pkgUnsafeHazard[idx.id] || b.pkgUnsafeHazard[idx.path]
		if pkgHasUnsafeHazard && fnHasUnconfinedUnsafeForTrackedChdir(fn, trapArg0Stubs) {
			return false, "unconfined_unsafe:" + fn.String()
		}
		for _, blk := range liveBlocks(fn, nil) {
			for _, instr := range blk.Instrs {
				if reachesTemplate && instrBoxesOSFileIntoEmptyInterface(instr) {
					return false, "template_exposes_os_file:" + fn.String()
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
						if reason := forbiddenFunctionValueReason(fnOp, trapArg0Stubs); reason != "" {
							return false, reason + ":" + fn.String()
						}
					}
				}
				if !isCall || site.Common() == nil {
					continue
				}
				c := site.Common()
				if c.IsInvoke() {
					if reason := checkTrackedChdirInvoke(c, isWindows, prep.userPaths); reason != "" {
						return false, reason + ":" + fn.String()
					}
				}
				if callee := c.StaticCallee(); callee != nil {
					if reason := checkTrackedChdirCallee(c, callee, true, isWindows, hasSyscallConsts, forbiddenTraps, trapArg0Stubs); reason != "" {
						return false, reason + ":" + fn.String()
					}
				}
				for target, tmask := range prep.res.Targets[site] {
					if tmask == 0 || target == nil || target == c.StaticCallee() {
						continue
					}
					if reason := checkTrackedChdirCallee(c, target, false, isWindows, hasSyscallConsts, forbiddenTraps, trapArg0Stubs); reason != "" {
						return false, reason + ":" + fn.String()
					}
				}
				if recv, dirArg, isTestingChdir := matchTestingChdirCallSite(c, prep.userPaths); isTestingChdir {
					if okTarget, targetReason := b.verifyTestingChdirCallTarget(fn, site, recv, dirArg, binaryFns, &prep, unionMask, trapArg0Stubs, removeOrRenameTraps, symlinkTraps, hasSyscallConsts, getCallerCone); !okTarget {
						return false, "chdir_target_not_intact_tempdir:" + targetReason + ":" + fn.String()
					}
				}
			}
		}
	}
	if reachesGo, goReason := b.goroutinesReachTestingChdir(binaryFns, &prep, unionMask); reachesGo {
		return false, goReason
	}
	if err := ctx.Err(); err != nil {
		return false, "context_cancelled"
	}
	return true, ""
}

func (b *tier2Base) computePerRootRTACones(
	ctx context.Context,
	rootSets [][]*ssa.Function,
	prep *preparedProgramRTA,
) ([]map[*ssa.Function]bool, bool) {
	cones := make([]map[*ssa.Function]bool, len(rootSets))
	const batchWidth = 64
	for start := 0; start < len(rootSets); start += batchWidth {
		end := start + batchWidth
		if end > len(rootSets) {
			end = len(rootSets)
		}
		batch := rootSets[start:end]
		allMasks := ^uint64(0)
		if len(batch) < batchWidth {
			allMasks = (uint64(1) << len(batch)) - 1
		}
		stepRoots := make(map[*ssa.Function]uint64, len(prep.initRoots)+len(batch)+1)
		for _, initFn := range prep.initRoots {
			if initFn != nil {
				stepRoots[initFn] |= allMasks
			}
		}
		if b.prog.TestMain != nil {
			stepRoots[b.prog.TestMain] |= allMasks
		}
		for i, set := range batch {
			for _, tr := range set {
				if tr != nil {
					stepRoots[tr] |= uint64(1) << i
				}
			}
		}
		var stepSeeds *rta.Seeds
		if prep.harnessAudited {
			stepSeeds = newHarnessRTASeeds(prep.verifiedHarnesses, prep.userPaths, prep.harnessStdInitRoots, allMasks)
		}
		if ct := programCancelCtxType(b.prog.Prog); ct != nil {
			if stepSeeds == nil {
				stepSeeds = &rta.Seeds{}
			}
			stepSeeds.RuntimeTypes = append(stepSeeds.RuntimeTypes, rta.TypeSeed{Type: ct, Masks: allMasks})
		}
		rootedCB := make([]map[*ssa.Function]bool, len(batch))
		for i := range rootedCB {
			rootedCB[i] = map[*ssa.Function]bool{}
		}
		analyzer := rta.NewAnalyzer()
		var res *rta.Result
		for {
			var err error
			res, err = analyzer.Extend(ctx, stepRoots, stepSeeds)
			if err != nil {
				return nil, false
			}
			var deltaRoots map[*ssa.Function]uint64
			var deltaSeeds *rta.Seeds
			for i := range batch {
				mask := uint64(1) << i
				reachI := map[*ssa.Function]bool{}
				for fn, fm := range res.Reachable {
					if fm&mask == 0 || fn == nil {
						continue
					}
					fnPath := funcPkgPath(fn)
					if (fnPath == "testing" && !prep.userPaths["testing"]) || prep.verifiedHarnesses[fnPath] != nil {
						continue
					}
					reachI[fn] = true
				}
				cbs, unclosedCB, fbs, unclosedFB := collectTestingHarnessCallbacks(true, prep.verifiedHarnesses, b.h.PureDelegates(), prep.userPaths, prep.summary, nil, false, enumerationClosure{}, reachI, mask, res)
				if unclosedCB || unclosedFB {
					return nil, false
				}
				for _, cb := range cbs {
					if !rootedCB[i][cb] {
						rootedCB[i][cb] = true
						if deltaRoots == nil {
							deltaRoots = map[*ssa.Function]uint64{}
						}
						deltaRoots[cb] |= mask
					}
				}
				for _, fb := range fbs {
					if !rootedCB[i][fb] {
						rootedCB[i][fb] = true
						if deltaRoots == nil {
							deltaRoots = map[*ssa.Function]uint64{}
						}
						deltaRoots[fb] |= mask
						addFuzzCallbackTypeSeed(&deltaSeeds, fb, mask)
					}
				}
			}
			if len(deltaRoots) == 0 && deltaSeeds == nil {
				break
			}
			stepRoots = deltaRoots
			stepSeeds = deltaSeeds
		}
		for i := range batch {
			mask := uint64(1) << i
			cone := map[*ssa.Function]bool{}
			for fn, fm := range res.Reachable {
				if fm&mask != 0 && fn != nil {
					cone[fn] = true
				}
			}
			cones[start+i] = cone
		}
	}
	return cones, true
}

func isGoTestExecutableRoot(name string, fn *ssa.Function) bool {
	if fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.TypeParams().Len() > 0 {
		return false
	}
	if fn.Signature.Results() != nil && fn.Signature.Results().Len() != 0 {
		return false
	}
	if !harnessRootName(name) {
		return false
	}
	params := fn.Signature.Params()
	if strings.HasPrefix(name, "Example") {
		return params == nil || params.Len() == 0
	}
	if params == nil || params.Len() != 1 {
		return false
	}
	ptr, ok := types.Unalias(params.At(0).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch {
	case strings.HasPrefix(name, "Test"):
		return named.Obj().Name() == "T"
	case strings.HasPrefix(name, "Benchmark"):
		return named.Obj().Name() == "B"
	case strings.HasPrefix(name, "Fuzz"):
		return named.Obj().Name() == "F"
	default:
		return false
	}
}

func startupReachesTestingChdir(startup *baseStartupReachSummary) bool {
	if startup == nil {
		return false
	}
	for fn := range startup.startupFunctions {
		if fn == nil {
			continue
		}
		if funcPkgPath(fn) == "testing" && baseFunctionSymbolName(fn) == "Chdir" {
			return true
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				c := site.Common()
				if c.IsInvoke() && c.Method != nil && c.Method.Name() == "Chdir" && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" {
					return true
				}
				if callee := c.StaticCallee(); callee != nil {
					t := unwrapSyntheticTargetFunc(callee)
					if funcPkgPath(t) == "testing" && baseFunctionSymbolName(t) == "Chdir" {
						return true
					}
				}
				for target := range startup.startupDynamicTargets[site] {
					if target != nil {
						t := unwrapSyntheticTargetFunc(target)
						if funcPkgPath(t) == "testing" && baseFunctionSymbolName(t) == "Chdir" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func hasStdPushLinkname(idx *pkgIndex) bool {
	if idx == nil {
		return false
	}
	checkTarget := func(target string) bool {
		if target == "<conflict>" {
			return true
		}
		dot := strings.LastIndexByte(target, '.')
		if dot <= 0 {
			return false
		}
		return isStdImportPath(target[:dot])
	}
	for obj, target := range idx.linknames {
		if !checkTarget(target) {
			continue
		}
		if fn, ok := obj.(*types.Func); ok {
			if decl := idx.decls[fn]; decl != nil {
				if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Body == nil {
					continue
				}
			}
		}
		return true
	}
	for name, target := range idx.linknameByName {
		if !checkTarget(target) {
			continue
		}
		if idx.pkg != nil && idx.pkg.Types != nil {
			if obj := idx.pkg.Types.Scope().Lookup(name); obj != nil {
				if _, ok := idx.linknames[obj]; ok {
					continue
				}
				if fn, ok := obj.(*types.Func); ok {
					if decl := idx.decls[fn]; decl != nil {
						if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Body == nil {
							continue
						}
					}
				}
			}
		}
		return true
	}
	return false
}

func fnHasLinkname(idx *pkgIndex, fn *ssa.Function) bool {
	if idx == nil || fn == nil {
		return false
	}
	if obj := fn.Object(); obj != nil && idx.linknames[obj] != "" {
		return true
	}
	return idx.linknameByName[fn.Name()] != ""
}

func pkgImportsCgo(tp *types.Package) bool {
	for _, imp := range tp.Imports() {
		if imp != nil && (imp.Path() == "C" || imp.Path() == "runtime/cgo") {
			return true
		}
	}
	return false
}

func (b *tier2Base) resolveTrackedChdirSyscallTraps() (forbidden, removeOrRename, symlink map[uint64]bool, ok bool) {
	var syscallPkg *types.Package
	for tp, idx := range b.idxByTypes {
		if tp != nil && idx != nil && idx.std && idx.path == "syscall" {
			syscallPkg = tp
			break
		}
	}
	if syscallPkg == nil && b.prog != nil && b.prog.Prog != nil {
		if sp := b.prog.Prog.ImportedPackage("syscall"); sp != nil {
			syscallPkg = sp.Pkg
		}
	}
	if syscallPkg == nil || syscallPkg.Scope() == nil {
		return nil, nil, nil, false
	}
	lookupTrap := func(name string) (uint64, bool) {
		obj, ok := syscallPkg.Scope().Lookup(name).(*types.Const)
		if !ok || obj.Val().Kind() != constant.Int {
			return 0, false
		}
		if u, exact := constant.Uint64Val(obj.Val()); exact {
			return u, true
		}
		return 0, false
	}
	chdirTrap, okChdir := lookupTrap("SYS_CHDIR")
	fchdirTrap, okFchdir := lookupTrap("SYS_FCHDIR")
	if !okChdir || !okFchdir {
		return nil, nil, nil, false
	}
	forbidden = map[uint64]bool{
		chdirTrap:  true,
		fchdirTrap: true,
	}
	for _, name := range []string{
		"SYS_CHROOT",
		"SYS_PIVOT_ROOT",
		"SYS_UNSHARE",
		"SYS_EXECVE",
		"SYS_EXECVEAT",
		"SYS_FORK",
		"SYS_VFORK",
		"SYS_CLONE",
		"SYS_CLONE3",
		"SYS___PTHREAD_CHDIR",
		"SYS___PTHREAD_FCHDIR",
	} {
		if u, found := lookupTrap(name); found {
			forbidden[u] = true
		}
	}
	if b.targetGOOS() == "darwin" {
		// XNU bsd/kern/syscalls.master: __pthread_chdir = 348, __pthread_fchdir = 349.
		forbidden[348] = true
		forbidden[349] = true
	}
	removeOrRename = map[uint64]bool{}
	for _, name := range []string{
		"SYS_RMDIR",
		"SYS_UNLINK",
		"SYS_UNLINKAT",
		"SYS_RENAME",
		"SYS_RENAMEAT",
		"SYS_RENAMEAT2",
	} {
		if u, found := lookupTrap(name); found {
			removeOrRename[u] = true
		}
	}
	symlink = map[uint64]bool{}
	for _, name := range []string{
		"SYS_SYMLINK",
		"SYS_SYMLINKAT",
	} {
		if u, found := lookupTrap(name); found {
			symlink[u] = true
		}
	}
	return forbidden, removeOrRename, symlink, true
}

func isAllIntegerSignature(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	if params := sig.Params(); params != nil {
		for i := 0; i < params.Len(); i++ {
			b, ok := types.Unalias(params.At(i).Type()).Underlying().(*types.Basic)
			if !ok || b.Info()&types.IsInteger == 0 {
				return false
			}
		}
	}
	if results := sig.Results(); results != nil {
		for i := 0; i < results.Len(); i++ {
			b, ok := types.Unalias(results.At(i).Type()).Underlying().(*types.Basic)
			if !ok || b.Info()&types.IsInteger == 0 {
				return false
			}
		}
	}
	return true
}

func (b *tier2Base) isTrapArg0AssemblySyscallStub(pkg *listPkg, fn *ssa.Function) bool {
	if b == nil || pkg == nil || fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.TypeParams().Len() > 0 {
		return false
	}
	if !isAllIntegerSignature(fn.Signature) {
		return false
	}
	params := fn.Signature.Params()
	if params == nil || params.Len() == 0 {
		return false
	}
	p0, ok := types.Unalias(params.At(0).Type()).Underlying().(*types.Basic)
	if !ok || p0.Kind() != types.Uintptr {
		return false
	}
	vp, safe := b.verifiedPackageAssembly(pkg)
	if !safe || vp == nil {
		return false
	}
	sum, found := vp.Funcs[fn.Name()]
	return found && sum.ForwardsTrapArg0Syscall && b.isAsmTextLinkageClean(pkg, fn.Name(), nil)
}

func isStdRawSyscallFunc(pkgPath, sym string) bool {
	if pkgPath != "syscall" {
		return false
	}
	switch sym {
	case "Syscall", "Syscall6", "Syscall9", "Syscall12", "Syscall15", "Syscall18", "SyscallN", "RawSyscall", "RawSyscall6", "Call":
		return true
	default:
		return false
	}
}

func isUnattributableReflectiveCallSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "plugin", "testing/quick", "net/rpc", "net/rpc/jsonrpc":
		return true
	case "reflect":
		switch sym {
		case "Call", "CallSlice", "MakeFunc", "MethodByName", "Method":
			return true
		}
	}
	return false
}

func forbiddenFunctionValueReason(fn *ssa.Function, trapArg0Stubs map[*ssa.Function]bool) string {
	if fn == nil {
		return ""
	}
	target := unwrapSyntheticTargetFunc(fn)
	if trapArg0Stubs[target] {
		return "syscall_stub_func_value"
	}
	pkgPath, sym := funcPkgPath(target), baseFunctionSymbolName(target)
	if isUnattributableReflectiveCallSymbol(pkgPath, sym) {
		return "reflective_dispatch_func_value"
	}
	if isStdRawSyscallFunc(pkgPath, sym) {
		return "raw_syscall_func_value"
	}
	switch pkgPath {
	case "os":
		if sym == "Chdir" || sym == "Setenv" || sym == "Unsetenv" || sym == "Clearenv" {
			return "os_dir_or_env_func_value"
		}
	case "syscall":
		switch sym {
		case "Chdir", "Fchdir", "Chroot", "PivotRoot", "Unshare", "Exec", "SetCurrentDirectory", "Setenv", "Unsetenv", "Clearenv":
			return "syscall_dir_or_env_func_value"
		}
	case "testing":
		if sym == "Setenv" || sym == "Chdir" {
			return "testing_chdir_or_setenv_func_value"
		}
	}
	return ""
}

func unwrapSyntheticTargetFunc(fn *ssa.Function) *ssa.Function {
	if fn == nil || fn.Synthetic == "" || len(fn.Blocks) == 0 {
		return fn
	}
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
				if callee := site.Common().StaticCallee(); callee != nil {
					return callee
				}
			}
		}
	}
	return fn
}

func checkTrackedChdirInvoke(c *ssa.CallCommon, isWindows bool, userPaths map[string]bool) string {
	if c == nil || c.Method == nil {
		return ""
	}
	if c.Method.Pkg() != nil && isUnattributableReflectiveCallSymbol(c.Method.Pkg().Path(), c.Method.Name()) {
		return "reflective_dispatch_invoke"
	}
	switch c.Method.Name() {
	case "Chdir":
		if c.Method.Pkg() == nil || c.Method.Pkg().Path() != "testing" || userPaths["testing"] {
			return "non_tb_chdir_invoke"
		}
	case "Fchdir", "Chroot", "PivotRoot", "SetCurrentDirectory":
		return "non_tb_chdir_invoke"
	case "Clearenv":
		return "clearenv_invoke"
	case "Unsetenv":
		if len(c.Args) != 1 || !isAllowedNonPWDConstEnvKey(c.Args[0], isWindows) {
			return "dynamic_or_pwd_unsetenv_invoke"
		}
	case "Setenv":
		if len(c.Args) != 2 || !isAllowedNonPWDConstEnvKey(c.Args[0], isWindows) {
			if c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" {
				return "dynamic_or_pwd_testing_tb_setenv"
			}
			return "dynamic_or_pwd_setenv_invoke"
		}
	}
	return ""
}

func checkTrackedChdirCallee(
	c *ssa.CallCommon,
	callee *ssa.Function,
	isDirectStatic bool,
	isWindows bool,
	hasSyscallConsts bool,
	forbiddenTraps map[uint64]bool,
	trapArg0Stubs map[*ssa.Function]bool,
) string {
	if callee == nil {
		return ""
	}
	callee = unwrapSyntheticTargetFunc(callee)
	if trapArg0Stubs[callee] {
		if !isDirectStatic || !hasSyscallConsts || len(c.Args) < 1 || !isAllowedSyscallTrapConst(c.Args[0], forbiddenTraps) {
			return "forbidden_or_dynamic_asm_syscall"
		}
		return ""
	}
	pkgPath, sym := funcPkgPath(callee), baseFunctionSymbolName(callee)
	if isUnattributableReflectiveCallSymbol(pkgPath, sym) {
		return "reflective_dispatch"
	}
	if isStdRawSyscallFunc(pkgPath, sym) {
		if !isDirectStatic || !hasSyscallConsts || sym == "SyscallN" || sym == "Call" || len(c.Args) < 1 || !isAllowedSyscallTrapConst(c.Args[0], forbiddenTraps) {
			return "forbidden_or_dynamic_std_syscall"
		}
		return ""
	}
	switch pkgPath {
	case "os":
		switch sym {
		case "Chdir":
			return "reaches_os_chdir"
		case "Clearenv":
			return "reaches_os_clearenv"
		case "Setenv", "Unsetenv":
			if !isDirectStatic || callee.Signature == nil || callee.Signature.Recv() != nil || len(c.Args) < 1 || !isAllowedNonPWDConstEnvKey(c.Args[0], isWindows) {
				return "dynamic_or_pwd_os_env"
			}
		}
	case "syscall":
		switch sym {
		case "Chdir", "Fchdir", "Chroot", "PivotRoot", "Unshare", "Exec", "SetCurrentDirectory":
			return "reaches_syscall_chdir"
		case "Clearenv":
			return "reaches_syscall_clearenv"
		case "Setenv", "Unsetenv":
			if !isDirectStatic || callee.Signature == nil || callee.Signature.Recv() != nil || len(c.Args) < 1 || !isAllowedNonPWDConstEnvKey(c.Args[0], isWindows) {
				return "dynamic_or_pwd_syscall_env"
			}
		}
	case "testing":
		if sym == "Setenv" {
			if c.IsInvoke() {
				if len(c.Args) < 1 || !isAllowedNonPWDConstEnvKey(c.Args[0], isWindows) {
					return "dynamic_or_pwd_testing_setenv"
				}
			} else if !isDirectStatic || callee.Signature == nil || callee.Signature.Recv() == nil || len(c.Args) < 2 || !isAllowedNonPWDConstEnvKey(c.Args[1], isWindows) {
				return "dynamic_or_pwd_testing_setenv"
			}
		}
	default:
		if (strings.HasPrefix(pkgPath, "internal/syscall/") || pkgPath == "internal/poll") &&
			(sym == "Chdir" || sym == "Fchdir" || sym == "SetCurrentDirectory") {
			return "reaches_internal_chdir"
		}
	}
	return ""
}

func isAllowedSyscallTrapConst(arg ssa.Value, forbiddenTraps map[uint64]bool) bool {
	k, ok := arg.(*ssa.Const)
	if !ok || k.Value == nil || k.Value.Kind() != constant.Int {
		return false
	}
	trap, exact := constant.Uint64Val(k.Value)
	return exact && !forbiddenTraps[trap]
}

func isAllowedNonPWDConstEnvKey(arg ssa.Value, isWindows bool) bool {
	k, ok := arg.(*ssa.Const)
	if !ok || k.Value == nil || k.Value.Kind() != constant.String {
		return false
	}
	key := constant.StringVal(k.Value)
	if isWindows {
		return !strings.EqualFold(key, "PWD")
	}
	return key != "PWD"
}
