package closure

import (
	"context"
	"go/types"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

func emitHarnessGateReject(fp *freshParamAnalysis, target *ssa.Function, argIdx int, arg ssa.Value, reason, detail string) {
	if !trace.AnyEnabled() {
		return
	}
	var ctx context.Context
	subj := ""
	if fp != nil {
		ctx = fp.traceCtx
		if fp.subjectRoot != nil {
			subj = fp.subjectRoot.Name()
		}
	}
	if !trace.Enabled(ctx, trace.DomainClosure, subj) {
		return
	}
	tgtName := ""
	if target != nil {
		tgtName = target.String()
	}
	argStr := ""
	if arg != nil {
		argStr = arg.String()
	}
	trace.Emit(ctx, trace.DomainClosure, "closure.propharness.gate_reject", subj,
		trace.String("callee", tgtName),
		trace.Int("arg_idx", argIdx),
		trace.String("arg", argStr),
		trace.String("reason", reason),
		trace.String("detail", detail),
	)
}

func isVerifiedHarnessStructHandle(t types.Type, verified map[string]*propharness.VerifiedPackage) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	vp := verified[named.Obj().Pkg().Path()]
	if vp == nil || !vp.HandleStructs[named.Obj().Name()] {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	return ok && propharness.StructHasNoExportedFields(st)
}

// propertyHarnessHandleType reports whether t is a handed-in sealed handle
// type: a discovered HandleStruct pointer/value in verified (requiring zero
// exported fields) or stdlib testing.T/B/TB.
func propertyHarnessHandleType(t types.Type, verified map[string]*propharness.VerifiedPackage) bool {
	if isVerifiedHarnessStructHandle(t, verified) {
		return true
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	if named.Obj().Pkg().Path() == "testing" {
		name := named.Obj().Name()
		return name == "T" || name == "B" || name == "TB"
	}
	return false
}

func propertyHarnessHandleOrIfaceType(t types.Type, verified map[string]*propharness.VerifiedPackage) bool {
	if propertyHarnessHandleType(t, verified) {
		return true
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	vp := verified[named.Obj().Pkg().Path()]
	return vp != nil && vp.HandleIfaces[named.Obj().Name()]
}

func peelHandleIdentity(v ssa.Value) ssa.Value {
	for v != nil {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		case *ssa.TypeAssert:
			if x.CommaOk {
				return v
			}
			v = x.X
		case *ssa.Extract:
			if x.Index == 0 {
				if ta, ok := x.Tuple.(*ssa.TypeAssert); ok {
					v = ta.X
					continue
				}
			}
			return v
		default:
			return v
		}
	}
	return nil
}

func isProgSubjectRoot(prog *program, fn *ssa.Function) bool {
	if prog == nil || fn == nil {
		return false
	}
	for _, r := range prog.Roots {
		if r == fn {
			return true
		}
	}
	return false
}

func hasAnyNonTestMainStaticCaller(fn *ssa.Function, fp *freshParamAnalysis) bool {
	if fn == nil || fp == nil || fp.summary == nil {
		return false
	}
	for _, site := range fp.summary.allStaticSites[fn] {
		if site != nil && site.Parent() != nil && !isGeneratedTestMainPackage(fp.prog, site.Parent().Pkg) {
			return true
		}
	}
	return false
}

func isAuthenticTestingSubtestCallback(fn *ssa.Function, fp *freshParamAnalysis, visiting map[ssa.Value]bool) bool {
	if fn == nil || fp == nil {
		return false
	}
	isTestingRunCall := func(ref ssa.Instruction, passed ssa.Value) bool {
		site, ok := ref.(ssa.CallInstruction)
		if !ok || site.Common() == nil || site.Common().IsInvoke() {
			return false
		}
		callee := site.Common().StaticCallee()
		if callee == nil || funcPkgPath(callee) != "testing" || callee.Name() != "Run" {
			return false
		}
		args := site.Common().Args
		if len(args) != 3 || args[2] != passed {
			return false
		}
		recvNamed := namedOriginDeref(args[0].Type())
		if recvNamed == nil || recvNamed.Obj() == nil || recvNamed.Obj().Pkg() == nil || recvNamed.Obj().Pkg().Path() != "testing" {
			return false
		}
		rn := recvNamed.Obj().Name()
		if rn != "T" && rn != "B" {
			return false
		}
		return authenticHarnessHandleValue(args[0], fp, visiting)
	}

	if len(fn.FreeVars) > 0 {
		var mcs []*ssa.MakeClosure
		if fp.closures != nil {
			mcs = fp.closures[fn]
		} else if fp.summary != nil {
			mcs = fp.summary.closures[fn]
		} else {
			mcs = closureCreations(fn)
		}
		if len(mcs) == 0 {
			return false
		}
		for _, mc := range mcs {
			if mc == nil || mc.Referrers() == nil {
				return false
			}
			sawRun := false
			for _, ref := range *mc.Referrers() {
				if _, isDbg := ref.(*ssa.DebugRef); isDbg {
					continue
				}
				if !isTestingRunCall(ref, mc) {
					return false
				}
				sawRun = true
			}
			if !sawRun {
				return false
			}
		}
		return true
	}

	if fn.Referrers() == nil {
		return false
	}
	sawUse := false
	for _, ref := range *fn.Referrers() {
		if _, isDbg := ref.(*ssa.DebugRef); isDbg {
			continue
		}
		if mc, isMC := ref.(*ssa.MakeClosure); isMC && mc.Fn == fn {
			if mc.Referrers() == nil {
				return false
			}
			for _, mref := range *mc.Referrers() {
				if _, isDbg := mref.(*ssa.DebugRef); isDbg {
					continue
				}
				if !isTestingRunCall(mref, mc) {
					return false
				}
				sawUse = true
			}
			continue
		}
		if !isTestingRunCall(ref, fn) {
			return false
		}
		sawUse = true
	}
	return sawUse
}

func ssaFuncOriginPkgPath(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if p := funcPkgPath(fn); p != "" {
		return p
	}
	if orig := fn.Origin(); orig != nil && orig != fn {
		return funcPkgPath(orig)
	}
	return ""
}

func hasGoTestRunnerPrefix(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	rest := name[len(prefix):]
	if rest == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return !unicode.IsLower(r)
}

func isAuthenticTestingRunnerRoot(prog *program, fn *ssa.Function, paramIdx int, paramType types.Type) bool {
	if prog == nil || fn == nil || fn.Parent() != nil || paramIdx != 0 ||
		!isProgSubjectRoot(prog, fn) || !subjectRunsThroughHarness(prog, fn) {
		return false
	}
	if fn.TypeParams().Len() > 0 {
		return false
	}
	sig := fn.Signature
	if sig == nil || sig.Recv() != nil || sig.Variadic() || sig.Params().Len() != 1 || sig.Results().Len() != 0 {
		return false
	}
	ptr, ok := types.Unalias(paramType).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T":
		return fn.Name() != "TestMain" && hasGoTestRunnerPrefix(fn.Name(), "Test")
	case "B":
		return hasGoTestRunnerPrefix(fn.Name(), "Benchmark")
	default:
		return false
	}
}

func nonHarnessStaticSitesOf(fn *ssa.Function, fp *freshParamAnalysis) []ssa.CallInstruction {
	if fn == nil || fp == nil || fp.summary == nil {
		return nil
	}
	hasSubjectFilter := !fp.inProgramSites && len(fp.functions) > 0
	if hasSubjectFilter {
		fp.markSubjectUsed()
	}
	filterBySubject := hasSubjectFilter && fp.functions[fn]
	var out []ssa.CallInstruction
	for _, site := range fp.summary.allStaticSites[fn] {
		if site == nil || site.Parent() == nil || isGeneratedTestMainPackage(fp.prog, site.Parent().Pkg) {
			continue
		}
		callerPkg := ssaFuncOriginPkgPath(site.Parent())
		if callerPkg == "testing" || fp.verifiedHarnesses[callerPkg] != nil {
			continue
		}
		if filterBySubject && !fp.functions[site.Parent()] {
			continue
		}
		out = append(out, site)
	}
	return out
}

func staticCallArgAtParam(site ssa.CallInstruction, fn *ssa.Function, paramIdx int) (ssa.Value, bool) {
	if site == nil || site.Common() == nil || fn == nil || paramIdx < 0 {
		return nil, false
	}
	c := site.Common()
	if c.IsInvoke() {
		if fn.Signature == nil || fn.Signature.Recv() == nil {
			return nil, false
		}
		if paramIdx == 0 {
			return c.Value, true
		}
		if paramIdx-1 >= len(c.Args) {
			return nil, false
		}
		return c.Args[paramIdx-1], true
	}
	if paramIdx >= len(c.Args) {
		return nil, false
	}
	return c.Args[paramIdx], true
}

func sigNoRecvIdentical(a, b *types.Signature) bool {
	if a == nil || b == nil || a.Variadic() != b.Variadic() ||
		a.Params().Len() != b.Params().Len() || a.Results().Len() != b.Results().Len() {
		return false
	}
	for i := 0; i < a.Params().Len(); i++ {
		if !types.Identical(a.Params().At(i).Type(), b.Params().At(i).Type()) {
			return false
		}
	}
	for i := 0; i < a.Results().Len(); i++ {
		if !types.Identical(a.Results().At(i).Type(), b.Results().At(i).Type()) {
			return false
		}
	}
	return true
}

func nonHarnessDynamicCallMayPassBadHandle(fn *ssa.Function, paramIdx int, fp *freshParamAnalysis, visiting map[ssa.Value]bool) (bool, string) {
	if fn == nil || fn.Signature == nil || fp == nil {
		return true, "nil_fn_or_fp"
	}
	var reachSets []map[*ssa.Function]bool
	if !fp.inProgramSites && (len(fp.functions) > 0 || len(fp.rtaFunctions) > 0) {
		fp.markSubjectUsed()
		if len(fp.functions) > 0 {
			reachSets = append(reachSets, fp.functions)
		}
		if len(fp.rtaFunctions) > 0 {
			reachSets = append(reachSets, fp.rtaFunctions)
		}
	} else if len(fp.programFunctions) > 0 {
		reachSets = append(reachSets, fp.programFunctions)
	} else if fp.prog != nil {
		reachSets = append(reachSets, progAllFunctions(fp.prog))
	}
	if len(reachSets) == 0 {
		return true, "empty_reach_sets"
	}
	hasRecv := fn.Signature.Recv() != nil
	checkedCaller := map[*ssa.Function]bool{}
	for _, reachFns := range reachSets {
		for caller := range reachFns {
			if caller == nil || checkedCaller[caller] || len(caller.Blocks) == 0 || isGeneratedTestMainPackage(fp.prog, caller.Pkg) {
				continue
			}
			checkedCaller[caller] = true
			callerPkg := ssaFuncOriginPkgPath(caller)
			if callerPkg == "testing" || fp.verifiedHarnesses[callerPkg] != nil {
				continue
			}
			for _, blk := range caller.Blocks {
				for _, instr := range blk.Instrs {
					site, ok := instr.(ssa.CallInstruction)
					if !ok || site.Common() == nil {
						continue
					}
					c := site.Common()
					if c.IsInvoke() {
						if !hasRecv || paramIdx < 1 || c.Method == nil || c.Method.Name() != fn.Name() {
							continue
						}
						msig, okMS := c.Method.Type().(*types.Signature)
						if !okMS || !sigNoRecvIdentical(msig, fn.Signature) {
							continue
						}
						if paramIdx-1 >= len(c.Args) {
							return true, "bad_invoke_arity:" + caller.String()
						}
						if okH, det := authenticHarnessHandleValueDetail(c.Args[paramIdx-1], fp, visiting); !okH {
							return true, "bad_invoke_caller:" + caller.String() + ":" + det
						}
						continue
					}
					if c.StaticCallee() != nil {
						continue
					}
					csig, okCS := types.Unalias(c.Value.Type()).Underlying().(*types.Signature)
					if !okCS {
						continue
					}
					if !hasRecv {
						if !sigNoRecvIdentical(csig, fn.Signature) {
							continue
						}
						if paramIdx >= len(c.Args) {
							return true, "bad_dyncall_arity:" + caller.String()
						}
						if okH, det := authenticHarnessHandleValueDetail(c.Args[paramIdx], fp, visiting); !okH {
							return true, "bad_dyncall_caller:" + caller.String() + ":" + det
						}
					} else if paramIdx >= 1 {
						// Method-expression thunks have Signature.Recv() == nil: concrete T.M thunks
						// reject earlier at user_static_site_plus_dyn_ref, non-harness Iface.M thunks
						// reject via their internal c.IsInvoke() + !hasRecv arm above, and harness
						// HarnessIface.M thunks reject as dynamic harness targets on indirect calls
						// and at propertyHarnessClosedArgsForTarget on direct static calls. Only
						// bound-method closures (such as StateMachine.Check stored in a harness map)
						// share fn's receiverless parameter list at dynamic call sites.
						if csig.Params().Len() == fn.Signature.Params().Len() && sigNoRecvIdentical(csig, fn.Signature) {
							if paramIdx-1 >= len(c.Args) {
								return true, "bad_boundcall_arity:" + caller.String()
							}
							if okH, det := authenticHarnessHandleValueDetail(c.Args[paramIdx-1], fp, visiting); !okH {
								return true, "bad_boundcall_caller:" + caller.String() + ":" + det
							}
						}
					}
				}
			}
		}
	}
	return false, ""
}

// authenticHarnessHandleValue proves that v is an authentic handed-in sealed
// harness handle (*H with zero exported fields, or stdlib *testing.T / *testing.B /
// testing.TB) originating from a test-runner root, a verified testing.T/B.Run
// subtest callback, a verified harness callback/state-machine invocation, or an
// attributed helper whose every caller passes an authentic handle — never nil,
// a locally constructed &testing.T{} / &H{}, a shared global load, or a concrete
// user struct implementing an unsealed HandleIface.
func authenticHarnessHandleValue(v ssa.Value, fp *freshParamAnalysis, visiting map[ssa.Value]bool) bool {
	ok, _ := authenticHarnessHandleValueDetail(v, fp, visiting)
	return ok
}

func authenticHarnessHandleValueDetail(v ssa.Value, fp *freshParamAnalysis, visiting map[ssa.Value]bool) (bool, string) {
	if v == nil || fp == nil || len(fp.verifiedHarnesses) == 0 {
		return false, "nil_or_no_verified_harness"
	}
	for v != nil {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			if x.X == nil {
				return false, "make_iface_nil_src"
			}
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		case *ssa.TypeAssert:
			if x.CommaOk {
				return false, "comma_ok_type_assert"
			}
			v = x.X
		case *ssa.Extract:
			if x.Index != 0 {
				return false, "extract_nonzero"
			}
			ta, ok := x.Tuple.(*ssa.TypeAssert)
			if !ok {
				return false, "extract_non_type_assert"
			}
			v = ta.X
		case *ssa.Phi:
			if len(x.Edges) == 0 {
				return false, "empty_phi"
			}
			if visiting == nil {
				visiting = map[ssa.Value]bool{}
			}
			if visiting[x] {
				return true, ""
			}
			visiting[x] = true
			defer delete(visiting, x)
			sawNonSelf := false
			for _, e := range x.Edges {
				if peelHandleIdentity(e) == x {
					continue
				}
				sawNonSelf = true
				if okH, det := authenticHarnessHandleValueDetail(e, fp, visiting); !okH {
					return false, "phi_edge:" + det
				}
			}
			if !sawNonSelf {
				return false, "phi_all_self"
			}
			return true, ""
		case *ssa.FreeVar:
			if !fp.inProgramSites {
				fp.markSubjectUsed()
			}
			bindings, _, ok := attributedFreeVarBindings(x, fp)
			if !ok || len(bindings) == 0 {
				return false, "freevar_unattributed"
			}
			for _, b := range bindings {
				if okH, det := authenticHarnessHandleValueDetail(b, fp, visiting); !okH {
					return false, "freevar_binding:" + det
				}
			}
			return true, ""
		case *ssa.Parameter:
			if !fp.inProgramSites {
				fp.markSubjectUsed()
			}
			fn := x.Parent()
			if fn == nil || !propertyHarnessHandleOrIfaceType(x.Type(), fp.verifiedHarnesses) {
				return false, "param_non_handle_type"
			}
			if fp.verifiedHarnesses[ssaFuncOriginPkgPath(fn)] != nil {
				return true, ""
			}
			paramIdx := slices.Index(fn.Params, x)
			if paramIdx < 0 {
				return false, "param_not_found"
			}
			if visiting == nil {
				visiting = map[ssa.Value]bool{}
			}
			if visiting[x] {
				return true, ""
			}
			visiting[x] = true
			defer delete(visiting, x)

			if args, _, ok := attributedParameterArgs(x, fp); ok && len(args) > 0 {
				sawNonSelf := false
				for _, a := range args {
					if peelHandleIdentity(a) == x {
						continue
					}
					sawNonSelf = true
					if okH, det := authenticHarnessHandleValueDetail(a, fp, visiting); !okH {
						return false, "attr_param_arg:" + det
					}
				}
				if !sawNonSelf {
					return false, "attr_param_all_self"
				}
				return true, ""
			}

			if userSites := nonHarnessStaticSitesOf(fn, fp); len(userSites) > 0 {
				if fp.dynamic[fn] || fp.programValueRef[fn] ||
					(fp.summary != nil && (fp.summary.valueRef[fn] || (len(fn.FreeVars) > 0 && fp.summary.nonClosureRef[fn]))) {
					return false, "user_static_site_plus_dyn_ref"
				}
				if bad, det := nonHarnessDynamicCallMayPassBadHandle(fn, paramIdx, fp, visiting); bad {
					return false, "user_static_site_plus_dyncall:" + det
				}
				sawNonSelf := false
				for _, site := range userSites {
					a, okA := staticCallArgAtParam(site, fn, paramIdx)
					if !okA {
						return false, "user_static_site_arity"
					}
					if peelHandleIdentity(a) == x {
						continue
					}
					sawNonSelf = true
					if okH, det := authenticHarnessHandleValueDetail(a, fp, visiting); !okH {
						return false, "user_static_site_arg:" + det
					}
				}
				if !sawNonSelf {
					return false, "user_static_site_all_self"
				}
				return true, ""
			}

			if !propertyHarnessHandleType(x.Type(), fp.verifiedHarnesses) {
				return false, "param_iface_without_callers"
			}
			if fn == fp.subjectRoot {
				if len(fp.enumSites) == 0 && isAuthenticTestingRunnerRoot(fp.prog, fn, paramIdx, x.Type()) {
					return true, ""
				}
				return false, "subject_root_not_harness"
			}
			if (fp.inProgramSites || fp.subjectRoot != nil) &&
				isAuthenticTestingRunnerRoot(fp.prog, fn, paramIdx, x.Type()) &&
				!hasAnyNonTestMainStaticCaller(fn, fp) {
				if bad, det := nonHarnessDynamicCallMayPassBadHandle(fn, paramIdx, fp, visiting); !bad {
					return true, ""
				} else {
					return false, "prog_root_dyncall:" + det
				}
			}
			if !isVerifiedHarnessStructHandle(x.Type(), fp.verifiedHarnesses) {
				if paramIdx == 0 && isAuthenticTestingSubtestCallback(fn, fp, visiting) {
					return true, ""
				}
				return false, "testing_param_not_subtest_cb"
			}
			if bad, det := nonHarnessDynamicCallMayPassBadHandle(fn, paramIdx, fp, visiting); bad {
				return false, "harness_struct_param_dyncall:" + det
			}
			return true, ""
		default:
			if ins, ok := v.(ssa.Instruction); ok && ins.Parent() != nil && isVerifiedHarnessStructHandle(v.Type(), fp.verifiedHarnesses) {
				if fp.verifiedHarnesses[ssaFuncOriginPkgPath(ins.Parent())] != nil {
					return true, ""
				}
				if call, isCall := v.(*ssa.Call); isCall && call.Common() != nil && !call.Common().IsInvoke() {
					if callee := call.Common().StaticCallee(); callee != nil &&
						fp.verifiedHarnesses[ssaFuncOriginPkgPath(callee)] != nil &&
						propertyHarnessClosedArgsForTarget(call.Common(), callee, fp) {
						return true, ""
					}
				}
			}
			parentStr := ""
			if ins, ok := v.(ssa.Instruction); ok && ins.Parent() != nil {
				parentStr = "@" + ins.Parent().String()
			}
			return false, "non_handle_ssa_val:" + v.String() + parentStr
		}
	}
	return false, "nil_walk"
}

// propertyHarnessClosedValue is the boundary gate's per-value judgment: any
// operand statically typed as a harness handle or handle/logger interface must
// be an authentic handed-in sealed handle (never falling through to nil/const
// closure), and every other operand must be a subject-closed value carrying no
// uncalled named/bound harness callable or a locally built variadic slice of
// judged elements.
func propertyHarnessClosedValue(v ssa.Value, fp *freshParamAnalysis) bool {
	if v != nil && fp != nil && propertyHarnessHandleOrIfaceType(v.Type(), fp.verifiedHarnesses) {
		return authenticHarnessHandleValue(v, fp, nil)
	}
	if authenticHarnessHandleValue(v, fp, nil) {
		return true
	}
	if subjectClosedDynamicValue(v, make(map[ssa.Value]bool), fp) {
		return !closedValueCarriesNamedHarnessCallable(v, fp)
	}
	return harnessVariadicClosed(v, fp)
}

func closedValueCarriesNamedHarnessCallable(v ssa.Value, fp *freshParamAnalysis) bool {
	var verified map[string]*propharness.VerifiedPackage
	if fp != nil {
		verified = fp.verifiedHarnesses
	}
	if v == nil || v.Type() == nil || len(verified) == 0 || !typeMayCarryCallable(v.Type(), verified, map[types.Type]bool{}) {
		return false
	}
	funcs := make(map[*ssa.Function]bool)
	walkDynamicValue(v, &dynamicValueCollector{
		types: map[types.Type]bool{},
		funcs: funcs,
		seeds: true,
	}, map[ssa.Value]bool{}, nil, resetWalkState(fp))
	for fn := range funcs {
		if fn != nil && fn.Parent() == nil && verified[funcPkgPath(fn)] != nil {
			return true
		}
	}
	return false
}

func typeMayCarryCallable(t types.Type, verified map[string]*propharness.VerifiedPackage, seen map[types.Type]bool) bool {
	return refconfine.WalkTypeStructure(t, seen, false, func(u types.Type) (bool, bool) {
		if propertyHarnessHandleType(u, verified) {
			return false, true
		}
		switch tt := u.(type) {
		case *types.Basic:
			return tt.Kind() == types.UnsafePointer, true
		case *types.Signature, *types.Interface, *types.TypeParam:
			return true, true
		case *types.Pointer:
			return typeMayCarryCallable(tt.Elem(), verified, seen), true
		case *types.Slice:
			return typeMayCarryCallable(tt.Elem(), verified, seen), true
		case *types.Chan:
			return typeMayCarryCallable(tt.Elem(), verified, seen), true
		case *types.Map:
			return typeMayCarryCallable(tt.Key(), verified, seen) || typeMayCarryCallable(tt.Elem(), verified, seen), true
		}
		return false, false
	})
}

func harnessVariadicClosed(v ssa.Value, fp *freshParamAnalysis) bool {
	return variadicSliceElementsAll(v, func(val ssa.Value) bool {
		return propertyHarnessClosedValue(val, fp)
	})
}

func targetRequiresAuthenticHandleParam(target *ssa.Function, argIdx int, isInvoke bool, isBoundRecv bool, verified map[string]*propharness.VerifiedPackage) bool {
	if target == nil || target.Signature == nil || len(verified) == 0 {
		return false
	}
	sig := target.Signature
	orig := target.Origin()
	var origSig *types.Signature
	if orig != nil && orig.Signature != nil {
		origSig = orig.Signature
	}

	paramAt := func(s *types.Signature, idx int) types.Type {
		if s == nil || idx < 0 || idx >= s.Params().Len() {
			return nil
		}
		if s.Variadic() && idx == s.Params().Len()-1 {
			return nil
		}
		return s.Params().At(idx).Type()
	}

	var instT, origT types.Type
	switch {
	case isBoundRecv:
		if origSig != nil && origSig.Recv() != nil {
			instT = origSig.Recv().Type()
			origT = instT
		} else if len(target.FreeVars) > 0 {
			instT = target.FreeVars[0].Type()
			origT = instT
		}
	case isInvoke:
		instT = paramAt(sig, argIdx)
		if origSig != nil {
			origT = paramAt(origSig, argIdx)
		} else {
			origT = instT
		}
	case sig.Recv() != nil:
		if argIdx == 0 {
			instT = sig.Recv().Type()
			if origSig != nil && origSig.Recv() != nil {
				origT = origSig.Recv().Type()
			} else {
				origT = instT
			}
		} else {
			instT = paramAt(sig, argIdx-1)
			if origSig != nil {
				origT = paramAt(origSig, argIdx-1)
			} else {
				origT = instT
			}
		}
	case strings.HasPrefix(target.Synthetic, "thunk ") && origSig != nil && origSig.Recv() != nil:
		instT = paramAt(sig, argIdx)
		if argIdx == 0 {
			origT = origSig.Recv().Type()
		} else {
			origT = paramAt(origSig, argIdx-1)
		}
	default:
		instT = paramAt(sig, argIdx)
		if origSig != nil {
			origT = paramAt(origSig, argIdx)
		} else {
			origT = instT
		}
	}
	if instT == nil || origT == nil {
		return false
	}
	return propertyHarnessHandleOrIfaceType(instT, verified) &&
		propertyHarnessHandleOrIfaceType(origT, verified)
}

// propertyHarnessClosedArgs enforces the boundary gate over all dynamic-carrying
// arguments and bound-closure captures of a static call into a verified harness.
func propertyHarnessClosedArgs(c *ssa.CallCommon, fp *freshParamAnalysis) bool {
	if c == nil {
		return false
	}
	return propertyHarnessClosedArgsForTarget(c, c.StaticCallee(), fp)
}

// propertyHarnessClosedArgsForTarget enforces the boundary gate for static,
// interface-invoke, and anonymous-wrapper calls targeting target: parameters
// declared as harness handles or handle/logger interfaces require an authentic
// handed-in sealed handle (never nil, a locally allocated struct, or a custom
// unsealed interface implementation), while all other dynamic-carrying operands
// must satisfy propertyHarnessClosedValue.
func propertyHarnessClosedArgsForTarget(c *ssa.CallCommon, target *ssa.Function, fp *freshParamAnalysis) bool {
	if c == nil || fp == nil || len(fp.verifiedHarnesses) == 0 {
		return false
	}
	if okFmt, fmtDet := seededSampleFlowFormattingSafe(c, target, fp); !okFmt {
		emitHarnessGateReject(fp, target, -1, nil, "seeded_sample_format_hook", fmtDet)
		return false
	}
	if c.IsInvoke() {
		if c.Value == nil {
			return false
		}
		if propertyHarnessHandleOrIfaceType(c.Value.Type(), fp.verifiedHarnesses) {
			if okH, det := authenticHarnessHandleValueDetail(c.Value, fp, nil); !okH {
				emitHarnessGateReject(fp, target, -1, c.Value, "unauthentic_handle_recv", det)
				return false
			}
		}
	} else if mc, ok := c.Value.(*ssa.MakeClosure); ok {
		isBound := target != nil && strings.HasPrefix(target.Synthetic, "bound ")
		for bi, b := range mc.Bindings {
			if b == nil {
				continue
			}
			if (isBound && bi == 0 && targetRequiresAuthenticHandleParam(target, 0, false, true, fp.verifiedHarnesses)) ||
				propertyHarnessHandleOrIfaceType(b.Type(), fp.verifiedHarnesses) {
				if okH, det := authenticHarnessHandleValueDetail(b, fp, nil); !okH {
					emitHarnessGateReject(fp, target, bi, b, "unauthentic_handle_binding", det)
					return false
				}
				continue
			}
			if !refconfine.TypeMayCarryDynamic(fp.selectionAudited, b.Type(), map[types.Type]bool{}) {
				continue
			}
			if !propertyHarnessClosedValue(b, fp) {
				emitHarnessGateReject(fp, target, bi, b, "open_dynamic_binding", "")
				return false
			}
		}
	}
	for i, arg := range c.Args {
		if arg == nil {
			continue
		}
		if targetRequiresAuthenticHandleParam(target, i, c.IsInvoke(), false, fp.verifiedHarnesses) {
			if okH, det := authenticHarnessHandleValueDetail(arg, fp, nil); !okH {
				emitHarnessGateReject(fp, target, i, arg, "unauthentic_handle_arg", det)
				return false
			}
			continue
		}
		if !refconfine.TypeMayCarryDynamic(fp.selectionAudited, arg.Type(), map[types.Type]bool{}) {
			continue
		}
		if !propertyHarnessClosedValue(arg, fp) {
			emitHarnessGateReject(fp, target, i, arg, "open_dynamic_arg", "")
			return false
		}
	}
	return true
}

// admitPropertyHarnessAnonTarget gates direct subject-flow invocations of
// anonymous wrapper closures produced by a verified harness (such as subtest
// or fuzz wrappers).
func (a *tier2Analyzer) admitPropertyHarnessAnonTarget(site ssa.CallInstruction, target *ssa.Function, vp *propharness.VerifiedPackage) bool {
	if a == nil || site == nil || site.Common() == nil || target == nil || target.Signature == nil || vp == nil {
		return false
	}
	return propertyHarnessClosedArgsForTarget(site.Common(), target, a.fresh)
}
