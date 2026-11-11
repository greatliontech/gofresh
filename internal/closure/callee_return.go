package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

func liveCalleeBlocks(fn *ssa.Function) []*ssa.BasicBlock {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}
	seen := make(map[*ssa.BasicBlock]bool, len(fn.Blocks))
	queue := []*ssa.BasicBlock{fn.Blocks[0]}
	seen[fn.Blocks[0]] = true
	for i := 0; i < len(queue); i++ {
		b := queue[i]
		if len(b.Instrs) > 0 {
			if ifInstr, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If); ok && len(b.Succs) == 2 {
				if c, ok := ifInstr.Cond.(*ssa.Const); ok && c.Value != nil && c.Value.Kind() == constant.Bool {
					succ := b.Succs[1]
					if constant.BoolVal(c.Value) {
						succ = b.Succs[0]
					}
					if !seen[succ] {
						seen[succ] = true
						queue = append(queue, succ)
					}
					continue
				}
			}
		}
		for _, succ := range b.Succs {
			if !seen[succ] {
				seen[succ] = true
				queue = append(queue, succ)
			}
		}
	}
	if fn.Recover != nil && !seen[fn.Recover] {
		queue = append(queue, fn.Recover)
	}
	return queue
}

// staticCallResultDynamicValue steps through a static call's returned SSA
// expressions when the callee belongs to the audited standard-library
// surface or is a reached in-module function whose body is already scanned
// in the subject's reachability cone, and every dynamic-carrying argument is
// itself closed under the walk. This closes standard iterator constructors
// (strings.SplitSeq), pure constructors returning interfaces (crypto/sha256.New,
// strings.NewReader, bytes.NewReader), timerless context constructors
// (context.Background, context.WithCancel, context.WithValue,
// context.WithoutCancel), and reached in-module iterator/constructor helpers
// (REQ-closure-observability-dispatch).
func staticCallResultDynamicValue(call *ssa.Call, tupleIndex int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil {
		return false
	}
	fp = contextCancelMethodFP(call, fp)
	if call.Common().IsInvoke() || call.Common().StaticCallee() == nil {
		if fp.invokeSeen[call] {
			if fp.lowlink != nil {
				if d := fp.invokeDepth[call]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
					*fp.lowlink = d
				}
			}
			return fp.selectionAudited
		}
		invokeFP := *fp
		invokeSeen := make(map[ssa.CallInstruction]bool, len(fp.invokeSeen)+1)
		for k, v := range fp.invokeSeen {
			invokeSeen[k] = v
		}
		invokeSeen[call] = true
		invokeFP.invokeSeen = invokeSeen
		invokeDepth := make(map[ssa.CallInstruction]int, len(fp.invokeDepth)+1)
		for k, v := range fp.invokeDepth {
			invokeDepth[k] = v
		}
		depth := fp.baseDepth + len(fp.stackDepth) + 1
		invokeDepth[call] = depth
		invokeFP.invokeDepth = invokeDepth
		invokeFP.baseDepth = depth
		var targets map[*ssa.Function]bool
		var ok bool
		if call.Common().IsInvoke() {
			targets, ok = closedInvokeTargets(call, &invokeFP)
		} else {
			targets, ok = closedDynamicTargets(call.Common().Value, &invokeFP)
		}
		if !ok || (len(targets) == 0 && !fp.selectionAudited) {
			return false
		}
		if len(targets) == 0 {
			if !collect.collecting() {
				markDynamicLeaf(fp)
			}
			return !collect.isSeeds()
		}
		if collect.isSeeds() {
			if !call.Common().IsInvoke() && call.Common().Value != nil {
				walkDynamicValue(call.Common().Value, collect, seen, done, &invokeFP)
			}
			for _, arg := range call.Common().Args {
				if arg == nil {
					return false
				}
				walkDynamicValue(arg, collect, seen, done, &invokeFP)
			}
		}
		var ordered []*ssa.Function
		for callee := range targets {
			ordered = append(ordered, callee)
		}
		slices.SortFunc(ordered, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
		for _, callee := range ordered {
			if call.Common().IsInvoke() && callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil && isAuditedStandardIOWrapperType(callee.Signature.Recv().Type()) {
				if ok, skip := auditedIOWrapperResultDynamicValue(callee, tupleIndex, collect, fp); skip {
					if !ok && !collect.isSeeds() {
						return false
					}
					continue
				}
			}
			callArgs := call.Common().Args
			if call.Common().IsInvoke() {
				callArgs = append([]ssa.Value{call.Common().Value}, callArgs...)
			} else if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil && len(callArgs)+1 == len(callee.Params) {
				callArgs = append([]ssa.Value{nil}, callArgs...)
			}
			if !calleeResultDynamicValue(call, callee, callArgs, tupleIndex, collect, seen, done, &invokeFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	}
	callee := call.Common().StaticCallee()
	if tupleIndex == 1 && callee != nil && funcPkgPath(callee) == "context" && (callee.Name() == "WithCancel" || callee.Name() == "WithCancelCause") {
		fp = withIgnoreContextValuePayload(fp)
	}
	return calleeResultDynamicValue(call, callee, call.Common().Args, tupleIndex, collect, seen, done, fp)
}

func calleeResultDynamicValue(call *ssa.Call, callee *ssa.Function, callArgs []ssa.Value, tupleIndex int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	reject := func(gate string) bool {
		if trace.AnyEnabled() {
			var callerName, calleeName string
			if call != nil && call.Parent() != nil {
				callerName = call.Parent().String()
			}
			if callee != nil {
				calleeName = callee.String()
			}
			trace.Emit(nil, trace.DomainClosure, "closure.callee.reject", calleeName,
				trace.String("caller", callerName),
				trace.Int("tuple_index", tupleIndex),
				trace.String("gate", gate),
			)
		}
		return false
	}
	isAdmittedOSGetwd := callee != nil && fp != nil && fp.selectionAudited && fp.isStdFunc(callee) && funcPkgPath(callee) == "os" && functionSymbolName(callee) == "Getwd" && tupleIndex == 1 && len(callArgs) == 0
	if callee == nil {
		return reject("nil_callee")
	}
	if callee.Synthetic != "" && callee.Origin() == nil && !isPromotedWrapper(callee) && !isBoundMethodWrapper(callee) && !strings.HasPrefix(callee.Synthetic, "wrapper ") && !isAdmittedOSGetwd {
		return reject("synthetic")
	}
	if len(callee.Blocks) == 0 && !isAdmittedOSGetwd {
		return reject("no_blocks")
	}
	if !calleeFreeVarsClosed(callee, fp) {
		return reject("freevars_unclosed")
	}
	if fp.calleeSeen[callee] {
		if fp.lowlink != nil {
			if d := fp.calleeDepth[callee]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
				*fp.lowlink = d
			}
		}
		return fp.selectionAudited
	}
	if callee == fp.enumRoot || callee == fp.subjectRoot {
		if fp.usedSubject != nil {
			*fp.usedSubject = true
		}
	}
	pkgPath := funcPkgPath(callee)
	if fp.isStdFunc(callee) {
		var callerFn *ssa.Function
		if call != nil {
			callerFn = call.Parent()
		}
		callerStd := callerFn != nil && fp.isStdFunc(callerFn)
		admittedStdOrDel := false
		if fp != nil && fp.selectionAudited {
			if callerStd && call != nil && call.Common() != nil && call.Common().StaticCallee() == callee {
				_, hasClassB := classBEffectForFunction(callee)
				_, hasHarness := harnessCalleeEffect(fp.selectionAudited, callee, false)
				symName := functionSymbolName(callee)
				admittedStdOrDel = !hasClassB && !hasHarness && pkgPath != "reflect" && pkgPath != "unsafe" &&
					!osOpenFileMayMutate(callee, pkgPath, symName, call.Common()) &&
					!syscallOpenMayCreate(pkgPath, symName, call.Common())
			} else if collect.isSeeds() || (call != nil && call.Common() != nil && (call.Common().IsInvoke() || call.Common().StaticCallee() == nil)) {
				admittedStdOrDel = fp.isAuditedStandardOrDelegate(pkgPath)
			} else {
				admittedStdOrDel = admitPureDelegateCall(fp.selectionAudited, fp.pureDelegates, pkgPath, callee, call, callerStd, fp)
			}
			if !admittedStdOrDel {
				symName := functionSymbolName(callee)
				if pkgPath == "os" && symName == "Getwd" && tupleIndex == 1 && len(callArgs) == 0 {
					admittedStdOrDel = true
				} else if pkgPath == "path/filepath" && symName == "Abs" && call != nil && call.Common() != nil && call.Common().StaticCallee() == callee && len(callArgs) == 1 {
					admittedStdOrDel = true
				}
			}
		}
		if (!collect.isSeeds() && pkgPath == "math/rand") || (!admittedStdOrDel && !auditedStandardCallee(fp.selectionAudited, pkgPath, functionSymbolName(callee), callee)) {
			return reject("std_unaudited")
		}
	} else {
		if (!fp.functions[callee] && !fp.programFunctions[callee]) || (callee == fp.enumRoot && !fp.selectionAudited) || (callee.Signature.Variadic() && !fp.selectionAudited && !fp.inFieldStore && !fp.inProgramSites) || propharness.IsHarnessPath(pkgPath) {
			return reject("nonstd_inadmissible")
		}
		if fp.enumOnly && !collect.isSeeds() {
			var retType types.Type = call.Type()
			if tupleIndex >= 0 {
				if tup, ok := call.Type().(*types.Tuple); ok && tupleIndex < tup.Len() {
					retType = tup.At(tupleIndex).Type()
				}
			}
			if retType != nil {
				if _, isSig := types.Unalias(retType).Underlying().(*types.Signature); isSig {
					return reject("enum_only_sig")
				}
			}
		}
	}
	if len(callArgs) != len(callee.Params) {
		return reject("arity_mismatch")
	}
	boundRecvCall := call != nil && call.Common() != nil && !call.Common().IsInvoke() && call.Common().StaticCallee() == nil && callee.Signature != nil && callee.Signature.Recv() != nil && len(callArgs) > 0 && callArgs[0] == nil
	calleeFP := *fp
	calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen)+1)
	for k, v := range fp.calleeSeen {
		calleeSeen[k] = v
	}
	calleeSeen[callee] = true
	calleeFP.calleeSeen = calleeSeen
	calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth)+1)
	for k, v := range fp.calleeDepth {
		calleeDepth[k] = v
	}
	depth := fp.baseDepth + len(fp.stackDepth) + 1
	calleeDepth[callee] = depth
	calleeFP.calleeDepth = calleeDepth
	calleeFP.baseDepth = depth
	argCheckFP := *fp
	argCheckFP.baseCarrierNamed = nil
	argCheckFP.calleeSeen = calleeSeen
	argCheckFP.calleeDepth = calleeDepth
	argCheckFP.baseDepth = depth
	argDone := done
	if fp.baseCarrierNamed != nil && done != nil {
		argDone = map[ssa.Value]bool{}
	}
	for i, arg := range callArgs {
		if boundRecvCall && i == 0 {
			continue
		}
		if arg == nil {
			return reject("nil_arg")
		}
		if call.Common().IsInvoke() && i == 0 && !collect.isSeeds() {
			continue
		}
		if fp != nil && fp.ignoreContextValuePayload && !fp.enumOnly && !collect.isSeeds() && !calleeParamMayAffectResult(fp, callee, i) {
			continue
		}
		if !fp.isStdFunc(callee) {
			if named := derefNamedStruct(fp.userPkgPaths(), arg.Type()); named != nil {
				paramSupplies := len(callee.Blocks) == 0 || callee.Synthetic != "" || parameterizedBody(callee) || paramMaySupplyDynamicSeen(fp.selectionAudited, fp.userPkgPaths(), callee.Params[i], nil, make(map[*ssa.Parameter]bool))
				if !collect.collecting() && paramSupplies && typeMayCarryDynamicTop(fp.selectionAudited, named) {
					savedLeaf := false
					if argCheckFP.hasLeaf != nil {
						savedLeaf = *argCheckFP.hasLeaf
					}
					carrierFP := argCheckFP
					carrierFP.baseCarrierNamed = named
					carrierDone := done
					if fp.baseCarrierNamed != named && done != nil {
						carrierDone = map[ssa.Value]bool{}
					}
					if !walkDynamicValue(arg, nil, seen, carrierDone, &carrierFP) {
						return reject("struct_arg_walk")
					}
					if argCheckFP.hasLeaf != nil {
						*argCheckFP.hasLeaf = savedLeaf
					}
					if argCheckFP.enumOnly || isAuditedStdErrorWrapperNamed(named) {
						if named == argCheckFP.enumRecvNamed {
							if argCheckFP.usedSubject != nil {
								*argCheckFP.usedSubject = true
							}
						} else if !enumUserStructClosed(named, &argCheckFP) {
							return reject("struct_arg_enum")
						}
					}
				}
				if collect.isSeeds() && typeMayCarryDynamicTop(fp.selectionAudited, named) {
					walkDynamicValue(arg, collect, seen, argDone, &argCheckFP)
					collectUserStructSeeds(named, collect, &argCheckFP)
				}
				continue
			}
		}
		if !collect.collecting() && typeMayCarryDynamicTop(fp.selectionAudited, arg.Type()) {
			savedLeaf := false
			if argCheckFP.hasLeaf != nil {
				savedLeaf = *argCheckFP.hasLeaf
			}
			if !walkDynamicValue(arg, nil, seen, argDone, &argCheckFP) {
				return reject("arg_walk")
			}
			if argCheckFP.hasLeaf != nil {
				*argCheckFP.hasLeaf = savedLeaf
			}
		} else if collect.isSeeds() {
			walkDynamicValue(arg, collect, seen, argDone, &argCheckFP)
		} else if collect.collecting() && ((i == 0 && funcPkgPath(callee) == "context" && (callee.Name() == "WithValue" || callee.Name() == "WithoutCancel" || (tupleIndex != 1 && (callee.Name() == "WithCancel" || callee.Name() == "WithCancelCause")))) || isAuditedIOWrapperArg(callee, i)) {
			if !walkDynamicValue(arg, collect, seen, argDone, &argCheckFP) {
				return reject("wrapper_arg_walk")
			}
		}
	}
	if fp != nil && fp.selectionAudited && fp.isStdFunc(callee) && pkgPath == "context" && callee.Name() == "Err" && callee.Signature != nil && callee.Signature.Recv() != nil && isAuditedStandardContextRecvType(callee.Signature.Recv().Type()) {
		if callee.Pkg == nil {
			if collect.isSeeds() {
				return true
			}
			return reject("context_err_no_pkg")
		}
		g := callee.Pkg.Var("Canceled")
		if g == nil || !isUnmutatedStandardSentinelGlobal(fp.prog, g, "context", "Canceled") {
			if collect.isSeeds() {
				return true
			}
			return reject("context_err_sentinel_mutated")
		}
		if !collect.collecting() {
			markDynamicLeaf(fp)
			return true
		}
		if collect.types != nil {
			if sentinelGlobalConcreteTypes(g, collect.types) || collect.isSeeds() {
				return true
			}
			return reject("context_err_concrete_types")
		}
		if collect.isSeeds() {
			return true
		}
		return reject("context_err_collect")
	}
	if isAdmittedOSGetwd {
		if callee.Pkg == nil || callee.Pkg.Prog == nil || callee.Pkg.Pkg == nil {
			if collect.isSeeds() {
				return true
			}
			return reject("os_getwd_no_pkg")
		}
		if fp.summary == nil || fp.summary.userMutatesOSWrapperError {
			if collect.isSeeds() {
				return true
			}
			return reject("os_getwd_wrapper_mutated")
		}
		mutated := mutatedGlobalsForProgram(fp.prog, callee.Pkg.Prog)
		for _, errName := range []string{"ErrInvalid", "ErrPermission", "ErrExist", "ErrNotExist", "ErrClosed", "ErrNoDeadline", "ErrDeadlineExceeded"} {
			if g := callee.Pkg.Var(errName); g != nil && mutated[g] {
				if collect.isSeeds() {
					return true
				}
				return reject("os_getwd_sentinel_mutated:" + errName)
			}
		}
		if !collect.collecting() {
			markDynamicLeaf(fp)
			return true
		}
		if collect.types != nil {
			if osGetwdConcreteErrorTypes(callee.Pkg, collect.types) || collect.isSeeds() {
				return true
			}
			return reject("os_getwd_concrete_types")
		}
		if collect.isSeeds() {
			return true
		}
		return reject("os_getwd_concrete_types")
	}
	bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings)+len(callee.Params))
	for k, v := range fp.callBindings {
		bindings[k] = v
	}
	for i, p := range callee.Params {
		if (boundRecvCall && i == 0) || callArgs[i] == p {
			continue
		}
		bindings[p] = callArgs[i]
	}
	calleeFP.callBindings = bindings
	var calleeDone, calleeSeenMap map[ssa.Value]bool
	if !collect.collecting() {
		calleeDone = map[ssa.Value]bool{}
		calleeSeenMap = seen
	} else {
		calleeSeenMap = make(map[ssa.Value]bool, len(seen))
		for k, v := range seen {
			if v && k != nil && k.Parent() != callee {
				calleeSeenMap[k] = true
			}
		}
	}
	hasReturn := false
	for _, block := range liveCalleeBlocks(callee) {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			var res ssa.Value
			if tupleIndex < 0 {
				if len(ret.Results) != 1 {
					if collect.isSeeds() {
						continue
					}
					return reject("return_tuple_arity")
				}
				res = ret.Results[0]
			} else {
				if tupleIndex < 0 || tupleIndex >= len(ret.Results) {
					if collect.isSeeds() {
						continue
					}
					return reject("return_tuple_index")
				}
				res = ret.Results[tupleIndex]
			}
			if block == callee.Recover && isSyntheticRecoverZeroConst(res) {
				continue
			}
			hasReturn = true
			if !walkDynamicValue(res, collect, calleeSeenMap, calleeDone, &calleeFP) && !collect.isSeeds() {
				return reject("return_val_unclosed")
			}
			if res != nil && res.Type() != nil {
				var walkContainer func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool
				if _, isSlice := types.Unalias(res.Type()).Underlying().(*types.Slice); isSlice {
					walkContainer = walkMakeSliceIndexedStoresWithFP
				} else if _, isMap := types.Unalias(res.Type()).Underlying().(*types.Map); isMap {
					walkContainer = walkMakeMapValuesWithFP
				}
				if walkContainer != nil {
					retIdx := tupleIndex
					if retIdx < 0 {
						retIdx = 0
					}
					if !walkCallResultContainerWithFP(call, retIdx, len(ret.Results), map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
						return fp != nil && fp.selectionAudited && (walkDynamicValue(val, collect, seen, done, fp) || collect.isSeeds())
					}, walkContainer) && !collect.isSeeds() {
						return reject("return_container_unclosed")
					}
				}
			}
		}
	}
	if !hasReturn && !collect.isSeeds() {
		return reject("no_return")
	}
	return true
}

func walkCallResultContainerWithFP(site ssa.CallInstruction, retIdx, numResults int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool, walkContainer func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool) bool {
	callVal, ok := site.(ssa.Value)
	if !ok || callVal == nil {
		return true
	}
	if numResults <= 1 {
		return walkContainer(callVal, visited, fp, walkVal)
	}
	if callVal.Referrers() == nil {
		return true
	}
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Extract:
			if r.Tuple != callVal {
				return false
			}
			if r.Index == retIdx && !walkContainer(r, visited, fp, walkVal) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func calleeFreeVarsClosed(callee *ssa.Function, fp *freshParamAnalysis) bool {
	if callee == nil {
		return false
	}
	if len(callee.FreeVars) == 0 {
		return true
	}
	if fp == nil || !fp.selectionAudited {
		return false
	}
	for _, fv := range callee.FreeVars {
		if cellOf(fv, map[ssa.Value]bool{}) != nil {
			continue
		}
		if _, _, ok := attributedFreeVarBindings(fv, fp); !ok {
			return false
		}
	}
	return true
}

func findImportedTypesPackage(ssaProg *ssa.Program, root *types.Package, pkgPath string) *types.Package {
	if ssaProg != nil {
		if pkg := ssaProg.ImportedPackage(pkgPath); pkg != nil && pkg.Pkg != nil {
			return pkg.Pkg
		}
	}
	if root == nil {
		return nil
	}
	if root.Path() == pkgPath {
		return root
	}
	seen := map[*types.Package]bool{root: true}
	queue := []*types.Package{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, imp := range cur.Imports() {
			if imp == nil || seen[imp] {
				continue
			}
			if imp.Path() == pkgPath {
				return imp
			}
			seen[imp] = true
			queue = append(queue, imp)
		}
	}
	return nil
}

func osGetwdConcreteErrorTypes(osPkg *ssa.Package, dst map[types.Type]bool) bool {
	if osPkg == nil || osPkg.Pkg == nil || osPkg.Pkg.Scope() == nil {
		return false
	}
	syscallErrObj := osPkg.Pkg.Scope().Lookup("SyscallError")
	pathErrObj := osPkg.Pkg.Scope().Lookup("PathError")
	if syscallErrObj == nil || syscallErrObj.Type() == nil || pathErrObj == nil || pathErrObj.Type() == nil {
		return false
	}
	errPkg := findImportedTypesPackage(osPkg.Prog, osPkg.Pkg, "errors")
	sysPkg := findImportedTypesPackage(osPkg.Prog, osPkg.Pkg, "syscall")
	if errPkg == nil || errPkg.Scope() == nil || sysPkg == nil || sysPkg.Scope() == nil {
		return false
	}
	errStrObj := errPkg.Scope().Lookup("errorString")
	errnoObj := sysPkg.Scope().Lookup("Errno")
	if errStrObj == nil || errStrObj.Type() == nil || errnoObj == nil || errnoObj.Type() == nil {
		return false
	}
	dst[types.NewPointer(errStrObj.Type())] = true
	dst[types.NewPointer(syscallErrObj.Type())] = true
	dst[types.NewPointer(types.Unalias(pathErrObj.Type()))] = true
	dst[errnoObj.Type()] = true
	return true
}

func isSyntheticRecoverZeroConst(res ssa.Value) bool {
	c, ok := res.(*ssa.Const)
	return ok && c.Value == nil
}

func isAuditedIOWrapperArg(callee *ssa.Function, argIdx int) bool {
	if callee == nil || funcPkgPath(callee) != "io" {
		return false
	}
	switch callee.Name() {
	case "NopCloser", "LimitReader", "MultiReader", "MultiWriter":
		return argIdx == 0
	case "TeeReader":
		return argIdx == 0 || argIdx == 1
	default:
		return false
	}
}

func calleeParamMayAffectResult(fp *freshParamAnalysis, callee *ssa.Function, idx int) bool {
	audited := fp != nil && fp.selectionAudited
	if !audited || callee == nil || idx < 0 || idx >= len(callee.Params) {
		return true
	}
	if funcPkgPath(callee) == "context" && callee.Name() == "WithValue" {
		return idx == 0
	}
	if !fp.isStdFunc(callee) {
		if len(callee.Blocks) == 0 || callee.Synthetic != "" || parameterizedBody(callee) {
			return true
		}
		return paramFlowsOutsideContextValuePayload(fp, callee.Params[idx], make(map[ssa.Value]bool))
	}
	return true
}

func paramFlowsOutsideContextValuePayload(fp *freshParamAnalysis, val ssa.Value, seen map[ssa.Value]bool) bool {
	audited := fp != nil && fp.selectionAudited
	if val == nil {
		return true
	}
	if seen[val] {
		return false
	}
	seen[val] = true
	refs := val.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return true
			}
		case *ssa.Field:
			if r.X != val {
				return true
			}
			if carrierFreeValueUses(audited, r, nil) {
				continue
			}
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.FieldAddr:
			if r.X != val {
				return true
			}
			if carrierFreeFieldAddr(audited, r, nil) {
				continue
			}
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.Store:
			if r.Val != val || r.Addr == val {
				return true
			}
			var alloc *ssa.Alloc
			switch a := r.Addr.(type) {
			case *ssa.Alloc:
				alloc = a
			case *ssa.FieldAddr:
				alloc, _ = a.X.(*ssa.Alloc)
			}
			if alloc == nil || allocFlowsOutsideContextValuePayload(fp, alloc, seen) {
				return true
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.ChangeInterface:
			if r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.Phi:
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return true
			}
			subCallee := r.Common().StaticCallee()
			if subCallee == nil || len(r.Common().Args) != len(subCallee.Params) {
				return true
			}
			for i, arg := range r.Common().Args {
				if arg == val && calleeParamMayAffectResult(fp, subCallee, i) {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func allocFlowsOutsideContextValuePayload(fp *freshParamAnalysis, alloc *ssa.Alloc, seen map[ssa.Value]bool) bool {
	if alloc == nil {
		return true
	}
	if seen[alloc] {
		return false
	}
	seen[alloc] = true
	refs := alloc.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alloc {
				return true
			}
		case *ssa.FieldAddr:
			if r.X != alloc || r.Referrers() == nil {
				return true
			}
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					if fr.Addr != r {
						return true
					}
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r || paramFlowsOutsideContextValuePayload(fp, fr, seen) {
						return true
					}
				default:
					return true
				}
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alloc || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != alloc || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		default:
			return true
		}
	}
	return false
}
