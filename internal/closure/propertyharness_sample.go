package closure

import (
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
)

func isFmtOrErrorMethodName(name string) bool {
	switch name {
	case "String", "GoString", "Error", "Format":
		return true
	default:
		return false
	}
}

func sigContainsFuncTypeClosure(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var hasSig func(types.Type) bool
	hasSig = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Signature:
			return true
		case *types.Pointer:
			return hasSig(u.Elem())
		case *types.Slice:
			return hasSig(u.Elem())
		case *types.Array:
			return hasSig(u.Elem())
		case *types.Map:
			return hasSig(u.Key()) || hasSig(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if hasSig(u.Field(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if hasSig(sig.Params().At(i).Type()) {
			return true
		}
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if hasSig(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func fnSetCallsSeededSample(fns map[*ssa.Function]bool, vp *propharness.VerifiedPackage) bool {
	if len(fns) == 0 || vp == nil || len(vp.SeededSampleMethods) == 0 {
		return false
	}
	for fn := range fns {
		if fn == nil {
			continue
		}
		if _, ok := propertyHarnessSeededSampleCallee(vp, fn); ok {
			return true
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				site, isCall := instr.(ssa.CallInstruction)
				if !isCall || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil {
					if _, ok := propertyHarnessSeededSampleCallee(vp, callee); ok {
						return true
					}
				}
			}
		}
	}
	return false
}

func isSyncInitOnlySSAFunc(fn *ssa.Function, summary *callerReferenceSummary, seen map[*ssa.Function]bool) bool {
	if fn == nil || fn.Parent() != nil {
		return false
	}
	if initFlowFrame(fn) {
		return true
	}
	if summary == nil || summary.valueRef[fn] || len(summary.allStaticSites[fn]) == 0 {
		return false
	}
	if seen[fn] {
		return true
	}
	seen[fn] = true
	for _, site := range summary.allStaticSites[fn] {
		if site == nil || site.Parent() == nil {
			return false
		}
		if _, isGo := site.(*ssa.Go); isGo {
			return false
		}
		if _, isDefer := site.(*ssa.Defer); isDefer {
			return false
		}
		if !isSyncInitOnlySSAFunc(site.Parent(), summary, seen) {
			return false
		}
	}
	return true
}

type initSettledGlobalsSummary struct {
	stores   map[*ssa.Global][]ssa.Value
	poisoned map[*ssa.Global]bool
}

const initSettledGlobalStoresSummaryKey = "gofresh/init-settled-global-stores@1"

func lookupInitSettledGlobalStores(p *program, summary *callerReferenceSummary, glb *ssa.Global) ([]ssa.Value, bool) {
	if p == nil || p.Prog == nil || glb == nil {
		return nil, false
	}
	if p.Summaries != nil && summary != nil {
		if cached, ok := p.Summaries[initSettledGlobalStoresSummaryKey].(initSettledGlobalsSummary); ok {
			if cached.poisoned[glb] {
				return nil, false
			}
			return cached.stores[glb], true
		}
	}
	stores := map[*ssa.Global][]ssa.Value{}
	poisoned := map[*ssa.Global]bool{}
	var ops [16]*ssa.Value
	for _, fn := range progOrderedFunctions(p) {
		if fn == nil {
			continue
		}
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
					if !ok || g == nil || poisoned[g] {
						continue
					}
					switch r := instr.(type) {
					case *ssa.UnOp:
						if r.Op == token.MUL && r.X == g {
							continue
						}
					case *ssa.Store:
						if r.Addr == g && r.Val != g && isSyncInitOnlySSAFunc(fn, summary, map[*ssa.Function]bool{}) {
							stores[g] = append(stores[g], r.Val)
							continue
						}
					}
					poisoned[g] = true
					delete(stores, g)
				}
			}
		}
	}
	res := initSettledGlobalsSummary{stores: stores, poisoned: poisoned}
	if p.Summaries != nil && summary != nil {
		p.Summaries[initSettledGlobalStoresSummaryKey] = res
	}
	if res.poisoned[glb] {
		return nil, false
	}
	return res.stores[glb], true
}

func ssaFormattingMethodIsMutationFree(fn *ssa.Function, userPaths map[string]bool, seen map[*ssa.Function]bool) (bool, string) {
	if fn == nil {
		return false, "nil_fn"
	}
	if seen[fn] {
		return true, ""
	}
	seen[fn] = true
	pkgPath := funcPkgPath(fn)
	if isStdPkgPath(userPaths, pkgPath) {
		sig := fn.Signature
		if sig == nil {
			return false, "std_nil_sig:" + fn.String()
		}
		name := fn.Name()
		if sig.Recv() != nil {
			switch pkgPath {
			case "reflect":
				if syntaxutil.IsReflectType(sig.Recv().Type()) {
					switch name {
					case "Name", "String", "PkgPath", "Kind":
						return true, ""
					}
				}
			case "time":
				if named, okN := types.Unalias(sig.Recv().Type()).(*types.Named); okN &&
					named.Obj() != nil && named.Obj().Name() == "Duration" && name == "String" {
					return true, ""
				}
			}
			return false, "std_method:" + fn.String()
		}
		if sigContainsFuncTypeClosure(sig) {
			return false, "std_func_sig:" + fn.String()
		}
		if pkgPath == "os" && (name == "Getenv" || name == "LookupEnv") {
			return true, ""
		}
		if strings.HasPrefix(name, "Append") || name == "NewBuffer" {
			return false, "std_append:" + fn.String()
		}
		tr := auditset.DeterministicStdCallTraits(pkgPath, name)
		if !tr.InPlaceContainerMutate && (tr.PureScalarOrValue || tr.ValuePlaneClone || tr.ReadOnlySliceInspect) {
			return true, ""
		}
		return false, "std_untrusted:" + fn.String()
	}
	if len(fn.Blocks) == 0 {
		return false, "empty_blocks:" + fn.String() + "(" + fn.Synthetic + ")"
	}
	localAllocs := map[*ssa.Alloc]bool{}
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			if al, isAl := instr.(*ssa.Alloc); isAl {
				localAllocs[al] = true
			}
		}
	}
	isBasicFormatVal := func(v ssa.Value) bool {
		if v == nil {
			return true
		}
		if cnst, isConst := v.(*ssa.Const); isConst && cnst.IsNil() {
			return true
		}
		b, isB := types.Unalias(peelHandleIdentity(v).Type()).(*types.Basic)
		return isB && b.Kind() != types.UnsafePointer
	}
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			switch x := instr.(type) {
			case *ssa.MakeClosure, *ssa.MapUpdate, *ssa.Send, *ssa.Go, *ssa.Defer:
				return false, "mut_op:" + instr.String()
			case *ssa.UnOp:
				if x.Op == token.ARROW {
					return false, "chan_recv:" + instr.String()
				}
			case *ssa.Store:
				if !localAllocRoot(x.Addr, localAllocs) {
					return false, "store:" + instr.String()
				}
			case ssa.CallInstruction:
				c := x.Common()
				if c == nil || c.IsInvoke() {
					return false, "invoke_or_nil:" + instr.String()
				}
				if b, isB := c.Value.(*ssa.Builtin); isB {
					if b.Name() != "len" && b.Name() != "cap" && b.Name() != "ssa:wrapnilchk" {
						return false, "builtin:" + b.Name()
					}
					continue
				}
				callee := c.StaticCallee()
				if callee == nil {
					return false, "dyn_call:" + instr.String()
				}
				if funcPkgPath(callee) == "fmt" && (callee.Name() == "Sprint" || callee.Name() == "Sprintf" || callee.Name() == "Sprintln") {
					for ai, a := range c.Args {
						if callee.Signature.Variadic() && ai == len(c.Args)-1 {
							if cnst, isConst := a.(*ssa.Const); isConst && cnst.IsNil() {
								continue
							}
							if !variadicSliceElementsAll(a, isBasicFormatVal) {
								return false, "fmt_vararg:" + instr.String()
							}
							continue
						}
						if !isBasicFormatVal(a) {
							return false, "fmt_arg:" + instr.String()
						}
					}
					continue
				}
				if okC, whyC := ssaFormattingMethodIsMutationFree(callee, userPaths, seen); !okC {
					return false, whyC
				}
			}
		}
	}
	return true, ""
}

// seededSampleFlowFormattingSafe ensures that whenever an analyzed flow invokes
// any variadic-seed sample method (such as Example(42) / Sample(42)) on a
// verified harness vp, no call into vp in that flow carries a type argument,
// result, closure binding, or call argument (including variadic Log/Logf slice
// elements) whose formatting can execute a state-mutating String, GoString,
// Error, or Format method. Non-mutating formatting methods (such as read-only
// os.Getenv Stringers promoted to Plane-1 reachability) remain observable.
func seededSampleFlowFormattingSafe(c *ssa.CallCommon, target *ssa.Function, fp *freshParamAnalysis) (bool, string) {
	if c == nil || target == nil || target.Signature == nil || fp == nil {
		return false, "nil_call_or_fp"
	}
	vp := fp.verifiedHarnesses[ssaFuncOriginPkgPath(target)]
	if vp == nil {
		return true, ""
	}
	userPaths := fp.userPkgPaths()

	var collectCandidateTypes func(add func(types.Type) bool) bool
	collectCandidateTypes = func(add func(types.Type) bool) bool {
		for _, ta := range target.TypeArgs() {
			if !add(ta) {
				return false
			}
		}
		res := target.Signature.Results()
		for i := 0; i < res.Len(); i++ {
			if !add(res.At(i).Type()) {
				return false
			}
		}
		if mc, ok := c.Value.(*ssa.MakeClosure); ok {
			for _, b := range mc.Bindings {
				if b == nil || propertyHarnessHandleOrIfaceType(b.Type(), fp.verifiedHarnesses) {
					continue
				}
				if !add(peelHandleIdentity(b).Type()) {
					return false
				}
			}
		}
		isVar := target.Signature.Variadic() && !c.IsInvoke()
		for i, arg := range c.Args {
			if arg == nil || targetRequiresAuthenticHandleParam(target, i, c.IsInvoke(), false, fp.verifiedHarnesses) ||
				propertyHarnessHandleOrIfaceType(arg.Type(), fp.verifiedHarnesses) {
				continue
			}
			if cnst, isConst := arg.(*ssa.Const); isConst && cnst.IsNil() {
				continue
			}
			if isVar && i == len(c.Args)-1 {
				peeled, allOK := peelVariadicCallArg(arg, func(elem ssa.Value) bool {
					if elem == nil {
						return true
					}
					if cnst, isConst := elem.(*ssa.Const); isConst && cnst.IsNil() {
						return true
					}
					return add(peelHandleIdentity(elem).Type())
				})
				if !allOK {
					return false
				}
				if peeled {
					continue
				}
			}
			if !add(peelHandleIdentity(arg).Type()) {
				return false
			}
		}
		return true
	}

	seenHookCheck := map[types.Type]bool{}
	var typeMayHaveHook func(types.Type) bool
	typeMayHaveHook = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if propertyHarnessHandleOrIfaceType(t, fp.verifiedHarnesses) || seenHookCheck[t] {
			return false
		}
		seenHookCheck[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Interface, *types.TypeParam:
			return true
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if typeMayHaveHook(targs.At(i)) {
						return true
					}
				}
			}
			if u.Obj() != nil && u.Obj().Pkg() != nil {
				pkgP := u.Obj().Pkg().Path()
				if fp.verifiedHarnesses[pkgP] != nil {
					return false
				}
				if !isStdPkgPath(userPaths, pkgP) {
					mset := types.NewMethodSet(types.NewPointer(u))
					for i := 0; i < mset.Len(); i++ {
						if isFmtOrErrorMethodName(mset.At(i).Obj().Name()) {
							return true
						}
					}
				}
			}
			return typeMayHaveHook(u.Underlying())
		case *types.Pointer:
			return typeMayHaveHook(u.Elem())
		case *types.Slice:
			return typeMayHaveHook(u.Elem())
		case *types.Array:
			return typeMayHaveHook(u.Elem())
		case *types.Map:
			return typeMayHaveHook(u.Key()) || typeMayHaveHook(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if typeMayHaveHook(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Signature:
			for i := 0; i < u.Results().Len(); i++ {
				if typeMayHaveHook(u.Results().At(i).Type()) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}

	hasCandidateHook := false
	collectCandidateTypes(func(t types.Type) bool {
		if typeMayHaveHook(t) {
			hasCandidateHook = true
			return false
		}
		return true
	})
	if !hasCandidateHook {
		return true, ""
	}

	if fp.inProgramSites {
		if !fnSetCallsSeededSample(fp.programFunctions, vp) {
			return true, ""
		}
		fp.markSubjectUsed()
		return false, "program_sites_sample_hook"
	}
	fp.markSubjectUsed()
	flowFns := fp.functions
	if len(flowFns) == 0 {
		flowFns = fp.flowFunctions
	}
	if _, directSample := propertyHarnessSeededSampleCallee(vp, target); !directSample && !fnSetCallsSeededSample(flowFns, vp) {
		return true, ""
	}
	if fp.prog == nil || fp.prog.Prog == nil {
		return false, "nil_prog"
	}

	var concreteTypes map[types.Type]bool
	concreteClosed := false
	concreteWhy := ""
	concreteComputed := false
	ensureConcreteTypes := func() (map[types.Type]bool, bool, string) {
		if concreteComputed {
			return concreteTypes, concreteClosed, concreteWhy
		}
		concreteComputed = true
		concreteTypes = map[types.Type]bool{}
		funcs := map[*ssa.Function]bool{}
		collector := &dynamicValueCollector{
			types: concreteTypes,
			funcs: funcs,
			seeds: true,
		}
		seenSeed := map[ssa.Value]bool{}
		seenGlobals := map[*ssa.Global]bool{}
		okAll := true
		var seedVal func(ssa.Value)
		seedVal = func(v ssa.Value) {
			if !okAll || v == nil || seenSeed[v] {
				return
			}
			seenSeed[v] = true
			unpeeled := v
			v = peelHandleIdentity(v)
			if v == nil || propertyHarnessHandleOrIfaceType(v.Type(), fp.verifiedHarnesses) {
				return
			}
			if cnst, isConst := v.(*ssa.Const); isConst && cnst.IsNil() {
				return
			}
			if unpeeled != v && v.Type() != nil {
				concreteTypes[v.Type()] = true
			}
			if phi, isPhi := v.(*ssa.Phi); isPhi {
				for _, edge := range phi.Edges {
					seedVal(edge)
				}
				return
			}
			if un, isUn := v.(*ssa.UnOp); isUn && un.Op == token.MUL {
				if glb, isG := un.X.(*ssa.Global); isG && glb != nil {
					if seenGlobals[glb] {
						return
					}
					seenGlobals[glb] = true
					vals, okSettled := lookupInitSettledGlobalStores(fp.prog, fp.summary, glb)
					if !okSettled {
						okAll = false
						concreteWhy = "glb_not_init_settled:" + glb.String()
						return
					}
					for _, sv := range vals {
						seedVal(sv)
						if !okAll {
							return
						}
					}
					return
				}
			}
			if callVal, isCall := v.(*ssa.Call); isCall && callVal.Common() != nil && !callVal.Common().IsInvoke() {
				if hc := callVal.Common().StaticCallee(); hc != nil && fp.verifiedHarnesses[ssaFuncOriginPkgPath(hc)] != nil {
					if hmc, okMC := callVal.Common().Value.(*ssa.MakeClosure); okMC {
						for _, hb := range hmc.Bindings {
							seedVal(hb)
						}
					}
					for _, ha := range callVal.Common().Args {
						seedVal(ha)
					}
					return
				}
			}
			if !propertyHarnessClosedValue(v, fp) {
				okAll = false
				concreteWhy = "not_closed_val:" + v.String()
				return
			}
			if !walkDynamicValue(v, collector, map[ssa.Value]bool{}, nil, resetWalkState(fp)) {
				okAll = false
				concreteWhy = "not_walk_seeds:" + v.String()
			}
		}
		if mc, okMC := c.Value.(*ssa.MakeClosure); okMC {
			for _, b := range mc.Bindings {
				seedVal(b)
			}
		}
		isVar := target.Signature.Variadic() && !c.IsInvoke()
		for i, arg := range c.Args {
			if arg == nil || targetRequiresAuthenticHandleParam(target, i, c.IsInvoke(), false, fp.verifiedHarnesses) {
				continue
			}
			if isVar && i == len(c.Args)-1 {
				if peeled, _ := peelVariadicCallArg(arg, func(elem ssa.Value) bool {
					seedVal(elem)
					return okAll
				}); peeled {
					continue
				}
			}
			seedVal(arg)
		}
		scannedFn := map[*ssa.Function]bool{}
		for okAll {
			progressed := false
			for fn := range funcs {
				if fn == nil || scannedFn[fn] || fp.verifiedHarnesses[ssaFuncOriginPkgPath(fn)] != nil {
					continue
				}
				scannedFn[fn] = true
				progressed = true
				for _, blk := range fn.Blocks {
					for _, instr := range blk.Instrs {
						if ret, isRet := instr.(*ssa.Return); isRet {
							for _, rv := range ret.Results {
								seedVal(rv)
							}
						}
					}
				}
			}
			if !progressed {
				break
			}
		}
		concreteClosed = okAll
		return concreteTypes, concreteClosed, concreteWhy
	}

	failDetail := ""
	seenSafe := map[types.Type]bool{}
	var checkSafe func(types.Type) bool
	checkSafe = func(t types.Type) bool {
		if t == nil {
			return true
		}
		t = types.Unalias(t)
		if propertyHarnessHandleOrIfaceType(t, fp.verifiedHarnesses) || seenSafe[t] {
			return true
		}
		seenSafe[t] = true
		switch u := t.(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				failDetail = "unsafe_ptr"
				return false
			}
			return true
		case *types.TypeParam:
			failDetail = "typeparam:" + u.String()
			return false
		case *types.Interface:
			cTypes, okClosed, cWhy := ensureConcreteTypes()
			if !okClosed {
				failDetail = "unclosed_iface_seeds:" + u.String() + ":" + cWhy
				return false
			}
			for ct := range cTypes {
				if ct == nil {
					continue
				}
				implements := types.Implements(ct, u)
				if !implements {
					if ptr, isP := types.Unalias(ct).(*types.Pointer); isP {
						implements = types.Implements(ptr.Elem(), u)
					} else {
						implements = types.Implements(types.NewPointer(ct), u)
					}
				}
				if implements && !checkSafe(ct) {
					return false
				}
			}
			for fn := range flowFns {
				if fn == nil || fn.Name() == "init" || strings.HasPrefix(fn.Name(), "init#") {
					continue
				}
				for _, blk := range fn.Blocks {
					for _, instr := range blk.Instrs {
						if mi, isMI := instr.(*ssa.MakeInterface); isMI && mi.X != nil && types.AssignableTo(mi.X.Type(), u) {
							if !checkSafe(mi.X.Type()) {
								return false
							}
						}
					}
				}
			}
			return true
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if !checkSafe(targs.At(i)) {
						return false
					}
				}
			}
			if u.Obj() != nil && u.Obj().Pkg() != nil {
				pkgP := u.Obj().Pkg().Path()
				if fp.verifiedHarnesses[pkgP] != nil {
					return true
				}
				if !isStdPkgPath(userPaths, pkgP) {
					mset := types.NewMethodSet(types.NewPointer(u))
					for i := 0; i < mset.Len(); i++ {
						sel := mset.At(i)
						if isFmtOrErrorMethodName(sel.Obj().Name()) {
							mFn := fp.prog.Prog.MethodValue(sel)
							if mFn == nil {
								failDetail = "named_method_nil:" + u.String() + "." + sel.Obj().Name()
								return false
							}
							if okM, whyM := ssaFormattingMethodIsMutationFree(mFn, userPaths, map[*ssa.Function]bool{}); !okM {
								failDetail = "named_method:" + u.String() + "." + sel.Obj().Name() + ":" + whyM
								return false
							}
						}
					}
				}
			}
			return checkSafe(u.Underlying())
		case *types.Pointer:
			return checkSafe(u.Elem())
		case *types.Slice:
			return checkSafe(u.Elem())
		case *types.Array:
			return checkSafe(u.Elem())
		case *types.Map:
			return checkSafe(u.Key()) && checkSafe(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !checkSafe(u.Field(i).Type()) {
					return false
				}
			}
			return true
		case *types.Signature:
			for i := 0; i < u.Results().Len(); i++ {
				if !checkSafe(u.Results().At(i).Type()) {
					return false
				}
			}
			return true
		default:
			return true
		}
	}

	if !collectCandidateTypes(checkSafe) {
		return false, failDetail
	}
	return true, ""
}
