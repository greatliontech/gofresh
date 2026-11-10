package rta

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

type reflectWriteKind uint8

const (
	reflectWriteSet reflectWriteKind = iota
	reflectWriteMap
	reflectWriteSlice
	reflectWriteChan
	numReflectWriteKinds
)

type closedMethodCallInfo struct {
	sigs []*types.Signature
	ok   bool
}

func (r *attributedRTA) initReflectMetadata(prog *ssa.Program) {
	reflectPkg := prog.ImportedPackage("reflect")
	if reflectPkg == nil {
		return
	}
	r.hasReflect = true
	r.reflectMethodFuncs = make(map[*ssa.Function]bool, 3)
	r.reflectSingleMethodFuncs = make(map[*ssa.Function]bool, 2)
	r.reflectWriteFuncs = make(map[*ssa.Function]reflectWriteKind, 11)
	if reflectValue, ok := reflectPkg.Members["Value"].(*ssa.Type); ok && reflectValue != nil {
		valType := types.Unalias(reflectValue.Object().Type())
		r.reflectValueCall = prog.LookupMethod(valType, reflectPkg.Pkg, "Call")
		r.reflectValueCallSlice = prog.LookupMethod(valType, reflectPkg.Pkg, "CallSlice")
		for _, mName := range []string{"Method", "MethodByName", "Methods"} {
			if fn := prog.LookupMethod(valType, reflectPkg.Pkg, mName); fn != nil {
				r.reflectMethodFuncs[fn] = true
				if mName != "Methods" {
					r.reflectSingleMethodFuncs[fn] = true
				}
			}
		}
		for _, spec := range []struct {
			name string
			kind reflectWriteKind
		}{
			{"Set", reflectWriteSet},
			{"SetIterKey", reflectWriteSet},
			{"SetIterValue", reflectWriteSet},
			{"SetPointer", reflectWriteSet},
			{"SetMapIndex", reflectWriteMap},
			{"Send", reflectWriteChan},
			{"TrySend", reflectWriteChan},
		} {
			if fn := prog.LookupMethod(valType, reflectPkg.Pkg, spec.name); fn != nil {
				r.reflectWriteFuncs[fn] = spec.kind
			}
		}
	}
	for _, spec := range []struct {
		name string
		kind reflectWriteKind
	}{
		{"Append", reflectWriteSlice},
		{"AppendSlice", reflectWriteSlice},
		{"Copy", reflectWriteSlice},
		{"Select", reflectWriteChan},
	} {
		if fn := reflectPkg.Func(spec.name); fn != nil {
			r.reflectWriteFuncs[fn] = spec.kind
		}
	}
}

func (r *attributedRTA) activeReflectSigMask(S *types.Signature) uint64 {
	direct, _ := r.directReflectMethodSigs.At(S).(uint64)
	if r.reflectMethodMasks == 0 {
		return direct
	}
	unboxOrWrite, _ := r.reflectAssertSigs.At(S).(uint64)
	for k := range numReflectWriteKinds {
		if m := r.reflectWriteMasks[k]; m != 0 {
			sigMasks, _ := r.reflectWriteSigs[k].At(S).(uint64)
			unboxOrWrite |= m & sigMasks
		}
	}
	return direct | (r.reflectMethodMasks & unboxOrWrite)
}

func (r *attributedRTA) flushReflectMethodsForSig(S *types.Signature) {
	active := r.activeReflectSigMask(S)
	if active == 0 {
		return
	}
	methods, _ := r.runtimeMethodFuncs.At(S).(map[*ssa.Function]uint64)
	for fn, fnMasks := range methods {
		if matched := active & fnMasks; matched != 0 {
			r.visitAddrTakenFuncWithSig(fn, S, matched, true)
		}
	}
}

func (r *attributedRTA) addReflectMethodMasks(masks uint64) {
	delta := masks &^ r.reflectMethodMasks
	if delta == 0 {
		return
	}
	r.reflectMethodMasks |= delta
	r.runtimeMethodFuncs.Iterate(func(key types.Type, _ any) {
		r.flushReflectMethodsForSig(key.(*types.Signature))
	})
}

func (r *attributedRTA) addDirectReflectMethodSig(S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 || r.hasTypeParam(S) {
		return
	}
	prev, _ := r.directReflectMethodSigs.At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.directReflectMethodSigs.Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addReflectWriteMasks(kind reflectWriteKind, masks uint64) {
	delta := masks &^ r.reflectWriteMasks[kind]
	if delta == 0 {
		return
	}
	r.reflectWriteMasks[kind] |= delta
	if r.reflectMethodMasks == 0 {
		return
	}
	r.reflectWriteSigs[kind].Iterate(func(key types.Type, _ any) {
		r.flushReflectMethodsForSig(key.(*types.Signature))
	})
}

func (r *attributedRTA) addReflectAssertSig(S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 || r.hasTypeParam(S) {
		return
	}
	prev, _ := r.reflectAssertSigs.At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.reflectAssertSigs.Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addReflectWriteSig(kind reflectWriteKind, S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 || r.hasTypeParam(S) {
		return
	}
	prev, _ := r.reflectWriteSigs[kind].At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.reflectWriteSigs[kind].Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addRuntimeMethodFunc(f *ssa.Function, masks uint64) {
	if f == nil || f.Signature == nil || masks == 0 {
		return
	}
	S := f.Signature
	if S.Recv() != nil {
		S = types.NewSignatureType(nil, nil, nil, S.Params(), S.Results(), S.Variadic())
	}
	methods, _ := r.runtimeMethodFuncs.At(S).(map[*ssa.Function]uint64)
	if methods == nil {
		methods = make(map[*ssa.Function]uint64)
		r.runtimeMethodFuncs.Set(S, methods)
	}
	delta := masks &^ methods[f]
	if delta == 0 {
		return
	}
	fnMasks := methods[f] | delta
	methods[f] = fnMasks
	if matched := r.activeReflectSigMask(S) & fnMasks; matched != 0 {
		r.visitAddrTakenFuncWithSig(f, S, matched, true)
	}
}

func (r *attributedRTA) noteReflectCalleeUse(g *ssa.Function, masks uint64) {
	if !r.hasReflect {
		return
	}
	r.noteReflectBaseUse(r.unwrapWrapper(g), masks)
}

func (r *attributedRTA) noteReflectBaseUse(base *ssa.Function, masks uint64) {
	if base == nil {
		return
	}
	if r.reflectMethodFuncs[base] {
		r.addReflectMethodMasks(masks)
	}
	if kind, ok := r.reflectWriteFuncs[base]; ok {
		r.addReflectWriteMasks(kind, masks)
	}
	if orig := base.Origin(); orig != nil && orig.Name() == "TypeAssert" && r.funcPkgPath(orig) == "reflect" && len(base.TypeArgs()) == 1 {
		targ := base.TypeArgs()[0]
		if sig, ok := types.Unalias(targ).Underlying().(*types.Signature); ok {
			r.addReflectAssertSig(sig, masks)
		} else if !types.IsInterface(types.Unalias(targ).Underlying()) {
			r.addWritableRuntimeType(targ, masks, false)
		}
	}
}

func (r *attributedRTA) noteReflectCallSite(callIns ssa.CallInstruction, g *ssa.Function, masks uint64) {
	if !r.hasReflect {
		return
	}
	base := r.unwrapWrapper(g)
	if base == nil {
		return
	}
	if sc, isCall := callIns.(*ssa.Call); isCall && r.reflectSingleMethodFuncs[base] {
		if sigs, ok := r.closedMethodValueSigs(sc); ok {
			for _, sig := range sigs {
				r.addDirectReflectMethodSig(sig, masks)
			}
			return
		}
	}
	r.noteReflectBaseUse(base, masks)
}

// closedMethodValueSigs inspects the SSA referrer cone of a direct
// (reflect.Value).Method or MethodByName call. When the returned reflect.Value
// never escapes to containers, memory stores, returns, or unanalyzed calls —
// staying strictly inside consumer-only reflect.Value methods (such as IsValid,
// Type, or Call), intra-package non-variadic helpers, and direct Interface() /
// TypeAssert unboxings — it returns ok=true with the exact receiverless
// function signatures asserted from that call.
func (r *attributedRTA) closedMethodValueSigs(sc *ssa.Call) ([]*types.Signature, bool) {
	if sc == nil || sc.Parent() == nil {
		return nil, false
	}
	if cached, found := r.closedMethodCalls[sc]; found {
		return cached.sigs, cached.ok
	}
	sigs, ok := computeClosedMethodValueSigs(sc)
	if r.closedMethodCalls == nil {
		r.closedMethodCalls = make(map[*ssa.Call]closedMethodCallInfo, 4)
	}
	r.closedMethodCalls[sc] = closedMethodCallInfo{sigs: sigs, ok: ok}
	return sigs, ok
}

func computeClosedMethodValueSigs(sc *ssa.Call) ([]*types.Signature, bool) {
	type qItem struct {
		val     ssa.Value
		isIface bool
	}
	visited := map[qItem]bool{{val: sc, isIface: false}: true}
	queue := []qItem{{val: sc, isIface: false}}
	enqueue := func(it qItem) {
		if !visited[it] {
			visited[it] = true
			queue = append(queue, it)
		}
	}
	var sigs []*types.Signature
	const maxSteps = 64
	steps := 0
	for len(queue) > 0 {
		steps++
		if steps > maxSteps {
			return nil, false
		}
		cur := queue[0]
		queue = queue[1:]
		refs := cur.val.Referrers()
		if refs == nil {
			return nil, false
		}
		for _, ref := range *refs {
			if cur.isIface {
				switch ins := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Phi:
					enqueue(qItem{val: ins, isIface: true})
				case *ssa.TypeAssert:
					if ins.X != cur.val {
						return nil, false
					}
					at := types.Unalias(ins.AssertedType)
					if types.IsInterface(at.Underlying()) {
						return nil, false
					}
					if sig, isSig := at.Underlying().(*types.Signature); isSig {
						sigs = append(sigs, sig)
					}
				default:
					return nil, false
				}
				continue
			}
			switch ins := ref.(type) {
			case *ssa.DebugRef:
			case *ssa.Phi:
				enqueue(qItem{val: ins, isIface: false})
			case ssa.CallInstruction:
				c := ins.Common()
				if c == nil || c.IsInvoke() || c.Value == cur.val {
					return nil, false
				}
				callee := c.StaticCallee()
				if callee == nil {
					return nil, false
				}
				base := unwrapWrapperCallee(callee)
				if base == nil {
					return nil, false
				}
				if orig := base.Origin(); orig != nil && orig.Name() == "TypeAssert" && ssaFuncPkgPath(orig) == "reflect" && len(base.TypeArgs()) == 1 {
					if len(c.Args) != 1 || c.Args[0] != cur.val {
						return nil, false
					}
					targ := types.Unalias(base.TypeArgs()[0])
					if types.IsInterface(targ.Underlying()) {
						return nil, false
					}
					if sig, isSig := targ.Underlying().(*types.Signature); isSig {
						sigs = append(sigs, sig)
					}
					continue
				}
				if ssaFuncPkgPath(base) == "reflect" {
					if base.Signature == nil || base.Signature.Recv() == nil || len(c.Args) == 0 || c.Args[0] != cur.val {
						return nil, false
					}
					for _, a := range c.Args[1:] {
						if a == cur.val {
							return nil, false
						}
					}
					switch base.Name() {
					case "Interface":
						if ic, isCall := ins.(*ssa.Call); isCall {
							enqueue(qItem{val: ic, isIface: true})
						}
					case "IsValid", "Kind", "Type", "IsNil", "IsZero", "CanInterface", "CanAddr", "CanSet", "NumMethod", "String", "Call", "CallSlice":
					default:
						return nil, false
					}
					continue
				}
				if callee == base && callee.Synthetic == "" && len(callee.Blocks) > 0 &&
					callee.Pkg != nil && sc.Parent().Pkg != nil && callee.Pkg == sc.Parent().Pkg &&
					(callee.Signature == nil || !callee.Signature.Variadic()) {
					for i, a := range c.Args {
						if a == cur.val {
							if i >= len(callee.Params) {
								return nil, false
							}
							enqueue(qItem{val: callee.Params[i], isIface: false})
						}
					}
					continue
				}
				return nil, false
			default:
				return nil, false
			}
		}
	}
	return sigs, true
}

func (r *attributedRTA) isTypedCallbackTrampolineAssert(f *ssa.Function, instr *ssa.TypeAssert) bool {
	if f == nil || instr == nil {
		return false
	}
	if cached, ok := r.trampolineAsserts[instr]; ok {
		return cached
	}
	res := checkTypedCallbackTrampolineAssert(f, instr)
	if r.trampolineAsserts == nil {
		r.trampolineAsserts = make(map[*ssa.TypeAssert]bool, 4)
	}
	r.trampolineAsserts[instr] = res
	return res
}

// checkTypedCallbackTrampolineAssert reports whether instr asserts a parameter
// of an unexported package-level helper f whose sole intra-package references
// pass f alongside a statically typed function MakeInterface into an unexported
// bodyless runtime trampoline (such as time.AfterFunc -> newTimer -> goFunc).
// Such an assertion can never unbox a caller-supplied untyped reflect.Value.Interface()
// unless the caller already type-asserted that signature before calling into the package.
func checkTypedCallbackTrampolineAssert(f *ssa.Function, instr *ssa.TypeAssert) bool {
	param, ok := instr.X.(*ssa.Parameter)
	if !ok || f == nil || f.Pkg == nil || f.Signature == nil || f.Signature.Recv() != nil || f.Object() == nil || f.Object().Exported() {
		return false
	}
	paramIdx := -1
	for i, p := range f.Params {
		if p == param {
			paramIdx = i
			break
		}
	}
	if paramIdx < 0 {
		return false
	}
	var pkgFuncs []*ssa.Function
	var addFn func(*ssa.Function)
	addFn = func(fn *ssa.Function) {
		if fn == nil {
			return
		}
		pkgFuncs = append(pkgFuncs, fn)
		for _, anon := range fn.AnonFuncs {
			addFn(anon)
		}
	}
	for _, mem := range f.Pkg.Members {
		switch m := mem.(type) {
		case *ssa.Function:
			addFn(m)
		case *ssa.Type:
			if named, ok := types.Unalias(m.Type()).(*types.Named); ok {
				for i, n := 0, named.NumMethods(); i < n; i++ {
					if fn := f.Prog.FuncValue(named.Method(i)); fn != nil && fn.Pkg == f.Pkg {
						addFn(fn)
					}
				}
			}
		}
	}
	var trampolines map[*ssa.Function]bool
	var valueRefBodyless map[*ssa.Function]bool
	sawRef := false
	var ops [16]*ssa.Value
	for _, fn := range pkgFuncs {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				rands := ins.Operands(ops[:0])
				callIns, isCall := ins.(ssa.CallInstruction)
				nonInvokeCall := isCall && callIns.Common() != nil && !callIns.Common().IsInvoke()
				mentionsF := false
				for idx, op := range rands {
					if op == nil || *op == nil {
						continue
					}
					if *op == f {
						mentionsF = true
						continue
					}
					if nonInvokeCall && idx == 0 {
						continue
					}
					if g, isFn := (*op).(*ssa.Function); isFn && g != nil && g.Pkg == f.Pkg && len(g.Blocks) == 0 && g.Object() != nil && !g.Object().Exported() {
						if trampolines[g] {
							return false
						}
						if valueRefBodyless == nil {
							valueRefBodyless = make(map[*ssa.Function]bool, 4)
						}
						valueRefBodyless[g] = true
					}
				}
				if !mentionsF {
					continue
				}
				sawRef = true
				if !nonInvokeCall {
					return false
				}
				c := callIns.Common()
				callee := c.StaticCallee()
				if callee == nil {
					return false
				}
				if callee == f {
					for _, arg := range c.Args {
						if arg == f {
							return false
						}
					}
					if paramIdx >= len(c.Args) || !isMakeInterfaceOfSignature(c.Args[paramIdx]) {
						return false
					}
					continue
				}
				if callee.Pkg != f.Pkg || len(callee.Blocks) != 0 || callee.Object() == nil || callee.Object().Exported() || valueRefBodyless[callee] {
					return false
				}
				sawTypedSig := false
				for _, arg := range c.Args {
					if arg == nil || arg == f || !types.IsInterface(types.Unalias(arg.Type()).Underlying()) {
						continue
					}
					if cnst, isConst := arg.(*ssa.Const); isConst && cnst.IsNil() {
						continue
					}
					if !isMakeInterfaceOfSignature(arg) {
						return false
					}
					sawTypedSig = true
				}
				if !sawTypedSig {
					return false
				}
				if trampolines == nil {
					trampolines = make(map[*ssa.Function]bool, 2)
				}
				trampolines[callee] = true
			}
		}
	}
	return sawRef
}

func isMakeInterfaceOfSignature(v ssa.Value) bool {
	mk, ok := v.(*ssa.MakeInterface)
	if !ok || mk == nil || mk.X == nil || mk.X.Type() == nil {
		return false
	}
	_, isSig := types.Unalias(mk.X.Type()).Underlying().(*types.Signature)
	return isSig
}
