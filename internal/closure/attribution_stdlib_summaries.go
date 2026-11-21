package closure

import (
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

type reflectTypeRef struct {
	typ types.Type
	fn  *ssa.Function
}

type summaryReflectState struct {
	namedSigReferenced  map[*types.Named]bool
	reflectValueTypes   []reflectTypeRef
	reflectMutationFns  []*ssa.Function
	reflectOpenValueFns []*ssa.Function
}

func (rs *summaryReflectState) recordNamedSigRef(ns *types.Named) {
	if ns != nil && rs != nil && rs.namedSigReferenced != nil {
		rs.namedSigReferenced[ns] = true
	}
}

func (summary *callerReferenceSummary) recordStructRef(named *types.Named, fn *ssa.Function) {
	summary.structReferencedByType[named] = true
	if first, ok := summary.structRefFirstFn[named]; !ok {
		summary.structRefFirstFn[named] = fn
	} else if first != fn {
		summary.structRefMultiFn[named] = true
	}
}

func (summary *callerReferenceSummary) poisonStruct(named *types.Named, field int) {
	if named == nil {
		return
	}
	if field < 0 {
		key := structFieldKey{named: named, field: -1}
		if !summary.structPoisoned[key] {
			summary.structPoisoned[key] = true
			if trace.AnyEnabled() {
				trace.Emit(nil, trace.DomainClosure, "closure.struct.poison", named.String(),
					trace.Int("field", -1),
				)
			}
		}
		if st, ok := named.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				summary.structPoisoned[structFieldKey{named: named, field: i}] = true
			}
		}
		return
	}
	key := structFieldKey{named: named, field: field}
	if !summary.structPoisoned[key] {
		summary.structPoisoned[key] = true
		if trace.AnyEnabled() {
			trace.Emit(nil, trace.DomainClosure, "closure.struct.poison", named.String(),
				trace.Int("field", field),
			)
		}
	}
}

func (summary *callerReferenceSummary) poisonContainedTypes(t types.Type, refFn *ssa.Function, rs *summaryReflectState) {
	walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
		if isOSWrapperErrorStruct(sub) {
			summary.userMutatesOSWrapperError = true
		}
		if named := derefNamedStruct(summary.userPaths, sub); named != nil {
			if refFn != nil {
				summary.recordStructRef(named, refFn)
			}
			summary.poisonStruct(named, -1)
		} else if ns := derefNamedSignature(summary.userPaths, sub); ns != nil {
			rs.recordNamedSigRef(ns)
			summary.namedSigPoisoned[ns] = true
		}
		return true
	})
}

func (summary *callerReferenceSummary) poisonEmbeddedCarriers(audited bool, recvOrBoxed types.Type, topNamed *types.Named, refFn *ssa.Function, rs *summaryReflectState) {
	if recvOrBoxed == nil {
		return
	}
	baseT := types.Unalias(recvOrBoxed)
	if ptr, ok := baseT.(*types.Pointer); ok {
		baseT = types.Unalias(ptr.Elem())
	}
	st, ok := baseT.Underlying().(*types.Struct)
	if !ok {
		return
	}
	seenEmbed := make(map[*types.Struct]bool)
	var walkEmbed func(*types.Struct)
	walkEmbed = func(cur *types.Struct) {
		if cur == nil || seenEmbed[cur] {
			return
		}
		seenEmbed[cur] = true
		for i := 0; i < cur.NumFields(); i++ {
			fld := cur.Field(i)
			if !fld.Embedded() {
				continue
			}
			ft := fld.Type()
			if inner := derefNamedStruct(summary.userPaths, ft); inner != nil {
				if refFn != nil {
					summary.recordStructRef(inner, refFn)
				}
				summary.poisonStruct(inner, -1)
			}
			if ns := derefNamedSignature(summary.userPaths, ft); ns != nil {
				rs.recordNamedSigRef(ns)
				summary.namedSigPoisoned[ns] = true
			}
			ftElem := types.Unalias(ft)
			if ptr, ok := ftElem.(*types.Pointer); ok {
				ftElem = types.Unalias(ptr.Elem())
			}
			switch sub := ftElem.Underlying().(type) {
			case *types.Struct:
				walkEmbed(sub)
			case *types.Interface:
			default:
				if topNamed != nil && typeMayCarryDynamicTop(audited, ftElem) {
					summary.poisonStruct(topNamed, -1)
				}
			}
		}
	}
	walkEmbed(st)
}

func (summary *callerReferenceSummary) scanUserTypeParams(fn *ssa.Function, structJudgeable bool, rs *summaryReflectState) {
	userPaths := summary.userPaths
	hasRecv := fn.Signature != nil && fn.Signature.Recv() != nil
	for pIdx, param := range fn.Params {
		if param == nil || param.Type() == nil {
			continue
		}
		if named := derefNamedStruct(userPaths, param.Type()); named != nil {
			summary.recordStructRef(named, fn)
			if !structJudgeable {
				summary.poisonStruct(named, -1)
			}
		} else if namedSig := derefNamedSignature(userPaths, param.Type()); namedSig != nil {
			rs.recordNamedSigRef(namedSig)
			if hasRecv && pIdx == 0 {
				continue
			}
			if !structJudgeable {
				summary.namedSigPoisoned[namedSig] = true
			} else if _, isPtr := types.Unalias(param.Type()).(*types.Pointer); !isPtr {
				summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], param)
			} else {
				summary.namedSigPoisoned[namedSig] = true
			}
		}
	}
}

func (summary *callerReferenceSummary) scanUserTypeAndReflectInstr(
	audited bool,
	fn *ssa.Function,
	instr ssa.Instruction,
	structJudgeable bool,
	nonHarnessUserFrame bool,
	rs *summaryReflectState,
) {
	userPaths := summary.userPaths
	if v, ok := instr.(ssa.Value); ok && v.Type() != nil {
		if _, isAlloc := instr.(*ssa.Alloc); isAlloc && nonHarnessUserFrame && isOSWrapperErrorStruct(v.Type()) {
			summary.userMutatesOSWrapperError = true
		}
		if named := derefNamedStruct(userPaths, v.Type()); named != nil {
			summary.recordStructRef(named, fn)
			poison := !structJudgeable
			switch instr.(type) {
			case *ssa.Convert, *ssa.ChangeType:
				poison = true
			case ssa.CallInstruction:
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
						poison = true
					}
				}
			}
			if poison {
				summary.poisonStruct(named, -1)
			}
		} else if namedSig := derefNamedSignature(userPaths, v.Type()); namedSig != nil {
			rs.recordNamedSigRef(namedSig)
			if isPromotedWrapper(fn) && fn.Signature != nil && fn.Signature.Recv() != nil && derefNamedSignature(userPaths, fn.Signature.Recv().Type()) == namedSig {
				// Synthetic pointer-method-table wrapper (*NamedSig).M:
				// boxing *NamedSig via MakeInterface or referencing w
				// directly poisons namedSig; value MakeInterface records
				// the boxed NamedSig operand below.
			} else if !structJudgeable {
				summary.namedSigPoisoned[namedSig] = true
			} else if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
				switch x := instr.(type) {
				case *ssa.Phi:
				case *ssa.ChangeType:
					if x.X == nil {
						summary.namedSigPoisoned[namedSig] = true
					} else {
						summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], x.X)
					}
				case *ssa.MakeClosure:
					summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
				case *ssa.TypeAssert, *ssa.Extract, *ssa.Lookup, *ssa.Index, *ssa.Field, *ssa.UnOp:
					summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
				case ssa.CallInstruction:
					if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
						if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
							summary.namedSigPoisoned[namedSig] = true
						} else {
							summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
						}
					}
				default:
					summary.namedSigPoisoned[namedSig] = true
				}
			} else if v.Referrers() == nil {
				summary.namedSigPoisoned[namedSig] = true
			} else {
				for _, ref := range *v.Referrers() {
					switch r := ref.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != v {
							summary.namedSigPoisoned[namedSig] = true
						}
					case *ssa.Store:
						if r.Addr != v || r.Val == nil {
							summary.namedSigPoisoned[namedSig] = true
						} else if _, isInstr := r.Val.(ssa.Instruction); !isInstr {
							summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], r.Val)
						}
					default:
						summary.namedSigPoisoned[namedSig] = true
					}
				}
			}
		}
	}
	switch x := instr.(type) {
	case *ssa.Convert:
		if x.X != nil {
			summary.poisonContainedTypes(x.X.Type(), fn, rs)
			if typeContainsOSWrapperErrorStruct(x.X.Type()) {
				summary.userMutatesOSWrapperError = true
			}
		}
		if x.Type() != nil {
			summary.poisonContainedTypes(x.Type(), fn, rs)
			if typeContainsOSWrapperErrorStruct(x.Type()) {
				summary.userMutatesOSWrapperError = true
			}
		}
	case *ssa.ChangeType:
		if x.X != nil {
			if named := derefNamedStruct(userPaths, x.X.Type()); named != nil {
				summary.poisonStruct(named, -1)
			}
			if typeContainsOSWrapperErrorStruct(x.X.Type()) {
				summary.userMutatesOSWrapperError = true
			}
		}
		if x.Type() != nil && typeContainsOSWrapperErrorStruct(x.Type()) {
			summary.userMutatesOSWrapperError = true
		}
	case *ssa.MakeInterface:
		if x.X != nil && x.X.Type() != nil {
			elemT := x.X.Type()
			_, isPtr := types.Unalias(elemT).(*types.Pointer)
			if ptr, ok := types.Unalias(elemT).(*types.Pointer); ok {
				elemT = ptr.Elem()
			}
			if ns := derefNamedSignature(userPaths, x.X.Type()); ns != nil {
				rs.recordNamedSigRef(ns)
				if !structJudgeable || isPtr {
					summary.namedSigPoisoned[ns] = true
				} else {
					summary.namedSigSources[ns] = append(summary.namedSigSources[ns], x.X)
				}
			}
			topNamed := derefNamedStruct(userPaths, x.X.Type())
			for _, inner := range collectValueContainedUserStructs(userPaths, elemT) {
				summary.recordStructRef(inner, fn)
				if structJudgeable && topNamed != nil {
					if inner == topNamed {
						summary.structBoxedValues[inner] = append(summary.structBoxedValues[inner], x.X)
					}
				} else {
					summary.poisonStruct(inner, -1)
				}
			}
			summary.poisonEmbeddedCarriers(audited, x.X.Type(), topNamed, fn, rs)
		}
	}
	if f, ok := instr.(*ssa.Field); ok && f.X != nil {
		if named := derefNamedStruct(userPaths, f.X.Type()); named != nil {
			if !structJudgeable {
				summary.poisonStruct(named, f.Field)
			} else {
				key := structFieldKey{named: named, field: f.Field}
				summary.structFieldReads[key] = append(summary.structFieldReads[key], f)
			}
		}
	}
	if fa, ok := instr.(*ssa.FieldAddr); ok && fa.X != nil {
		if nonHarnessUserFrame && isOSWrapperErrorStruct(fa.X.Type()) {
			if !structJudgeable || fa.Referrers() == nil {
				summary.userMutatesOSWrapperError = true
			} else {
				for _, ref := range *fa.Referrers() {
					switch r := ref.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != fa {
							summary.userMutatesOSWrapperError = true
						}
					default:
						summary.userMutatesOSWrapperError = true
					}
				}
			}
		}
		if named := derefNamedStruct(userPaths, fa.X.Type()); named != nil {
			summary.recordStructRef(named, fn)
			innerNamed := derefNamedStruct(userPaths, fa.Type())
			if innerNamed != nil {
				summary.recordStructRef(innerNamed, fn)
			}
			if !structJudgeable || fa.Referrers() == nil {
				summary.poisonStruct(named, fa.Field)
			} else {
				for _, ref := range *fa.Referrers() {
					switch r := ref.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != fa {
							summary.poisonStruct(named, fa.Field)
						} else {
							key := structFieldKey{named: named, field: fa.Field}
							summary.structFieldReads[key] = append(summary.structFieldReads[key], r)
						}
					case *ssa.Store:
						if r.Addr != fa || r.Val == nil {
							summary.poisonStruct(named, fa.Field)
						} else {
							key := structFieldKey{named: named, field: fa.Field}
							summary.structFieldStores[key] = append(summary.structFieldStores[key], r.Val)
						}
					case *ssa.FieldAddr:
						if innerNamed == nil || r.X != fa {
							summary.poisonStruct(named, fa.Field)
						}
					case ssa.CallInstruction:
						_, isGo := r.(*ssa.Go)
						okCall := false
						if !isGo && innerNamed != nil && r.Common() != nil && !r.Common().IsInvoke() {
							if callee := r.Common().StaticCallee(); callee != nil && len(callee.Blocks) > 0 && (callee.Synthetic == "" || isPromotedWrapper(callee) || (audited && callee.Origin() != nil)) && !parameterizedBody(callee) && len(r.Common().Args) == len(callee.Params) {
								okCall = true
								for i, arg := range r.Common().Args {
									if arg == fa && derefNamedStruct(userPaths, callee.Params[i].Type()) != innerNamed {
										okCall = false
										break
									}
								}
							}
						}
						if !okCall {
							summary.poisonStruct(named, fa.Field)
						}
					default:
						summary.poisonStruct(named, fa.Field)
					}
				}
			}
		}
	}
	if st, ok := instr.(*ssa.Store); ok && st.Val != nil && st.Val.Type() != nil {
		c, isConst := st.Val.(*ssa.Const)
		isZero := isConst && c.Value == nil
		if !isZero {
			if nonHarnessUserFrame && typeContainsOSWrapperErrorStruct(st.Val.Type()) {
				summary.userMutatesOSWrapperError = true
			}
			var topNamed *types.Named
			if _, isPtr := types.Unalias(st.Val.Type()).(*types.Pointer); !isPtr {
				topNamed = derefNamedStruct(userPaths, st.Val.Type())
			}
			for _, inner := range collectValueContainedUserStructs(userPaths, st.Val.Type()) {
				summary.recordStructRef(inner, fn)
				if structJudgeable && topNamed != nil {
					if inner == topNamed {
						summary.structWholeStores[inner] = append(summary.structWholeStores[inner], st.Val)
					}
				} else {
					summary.poisonStruct(inner, -1)
				}
			}
		}
	}
	if nonHarnessUserFrame {
		if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
			c := site.Common()
			if c.IsInvoke() {
				if c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "reflect" {
					mName := c.Method.Name()
					if isReflectMutationSymbol(mName) && (mName != "Addr" || !isAddrOnlyForUnsafePointerConvert(site)) {
						rs.reflectMutationFns = append(rs.reflectMutationFns, fn)
					}
					if mName == "ValueOf" || isReflectOpenProducerSymbol(mName) {
						rs.reflectOpenValueFns = append(rs.reflectOpenValueFns, fn)
					}
				}
			} else if callee := c.StaticCallee(); callee != nil {
				calleePkg := funcPkgPath(callee)
				calleeSym := baseFunctionSymbolName(callee)
				if calleePkg == "os" && calleeSym == "NewSyscallError" {
					summary.userMutatesOSWrapperError = true
				}
				if calleePkg == "reflect" {
					if isReflectMutationSymbol(calleeSym) && (calleeSym != "Addr" || !isAddrOnlyForUnsafePointerConvert(site)) {
						rs.reflectMutationFns = append(rs.reflectMutationFns, fn)
					}
					if calleeSym == "ValueOf" {
						if !isNonMutatingReflectValueRoot(site.Value()) {
							if len(c.Args) == 1 {
								if mi, ok := c.Args[0].(*ssa.MakeInterface); ok && mi.X != nil && mi.X.Type() != nil {
									rs.reflectValueTypes = append(rs.reflectValueTypes, reflectTypeRef{typ: mi.X.Type(), fn: fn})
								} else {
									rs.reflectOpenValueFns = append(rs.reflectOpenValueFns, fn)
								}
							} else {
								rs.reflectOpenValueFns = append(rs.reflectOpenValueFns, fn)
							}
						}
					} else if isReflectOpenProducerSymbol(calleeSym) {
						rs.reflectOpenValueFns = append(rs.reflectOpenValueFns, fn)
					}
				}
				calleeNonStd := !isStdPkgPath(userPaths, calleePkg)
				calleeVP := summary.verifiedHarnesses[calleePkg]
				if (calleeNonStd && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee)) || isStdDeserializerCall(calleePkg, calleeSym) || (calleeVP != nil && calleeVP.ReflectSynthFuncs[calleeSym]) {
					for _, arg := range c.Args {
						if arg != nil {
							summary.poisonContainedTypes(arg.Type(), fn, rs)
						}
					}
					if val := site.Value(); val != nil {
						summary.poisonContainedTypes(val.Type(), fn, rs)
					}
					for _, ta := range callee.TypeArgs() {
						summary.poisonContainedTypes(ta, fn, rs)
					}
				}
			}
		}
	}
}

func (summary *callerReferenceSummary) poisonLiveReflectMutations(rootPkgPath string, rs *summaryReflectState) {
	if rs == nil || len(rs.reflectMutationFns) == 0 {
		return
	}
	userPaths := summary.userPaths
	var reflectLiveMemo map[*ssa.Function]bool
	var reflectVisiting map[*ssa.Function]bool
	var reflectFnLive func(*ssa.Function) (bool, bool)
	reflectFnLive = func(fn *ssa.Function) (bool, bool) {
		if fn == nil {
			return false, false
		}
		if rootPkgPath == "" {
			return true, false
		}
		top := fn
		for top.Parent() != nil {
			top = top.Parent()
		}
		if v, ok := reflectLiveMemo[top]; ok {
			return v, false
		}
		if reflectVisiting[top] {
			return false, true
		}
		if reflectLiveMemo == nil {
			reflectLiveMemo = make(map[*ssa.Function]bool, 16)
			reflectVisiting = make(map[*ssa.Function]bool, 16)
		}
		reflectVisiting[top] = true
		defer delete(reflectVisiting, top)
		pkgPath := funcPkgPath(top)
		if pkgPath == rootPkgPath || pkgPath == rootPkgPath+"_test" || pkgPath == "main" || initFlowFrame(top) || summary.directValueRef[top] || summary.valueRef[top] {
			reflectLiveMemo[top] = true
			return true, false
		}
		if top.Signature != nil && top.Signature.Recv() != nil {
			if recvNamed := derefNamedStruct(userPaths, top.Signature.Recv().Type()); recvNamed == nil || len(summary.structBoxedValues[recvNamed]) > 0 || summary.structPoisoned[structFieldKey{named: recvNamed, field: -1}] {
				reflectLiveMemo[top] = true
				return true, false
			}
		}
		tainted := false
		for _, site := range summary.allStaticSites[top] {
			if site != nil && site.Parent() != nil {
				cLive, cTainted := reflectFnLive(site.Parent())
				if cLive {
					reflectLiveMemo[top] = true
					return true, false
				}
				if cTainted {
					tainted = true
				}
			}
		}
		if !tainted {
			reflectLiveMemo[top] = false
		}
		return false, tainted
	}
	sawReflectMutation := false
	for _, fn := range rs.reflectMutationFns {
		if live, _ := reflectFnLive(fn); live {
			sawReflectMutation = true
			break
		}
	}
	if !sawReflectMutation {
		return
	}
	summary.userMutatesOSWrapperError = true
	sawOpenReflectValue := false
	for _, fn := range rs.reflectOpenValueFns {
		if live, _ := reflectFnLive(fn); live {
			sawOpenReflectValue = true
			break
		}
	}
	var liveReflectTypes []reflectTypeRef
	if !sawOpenReflectValue {
		for _, rv := range rs.reflectValueTypes {
			if live, _ := reflectFnLive(rv.fn); live {
				liveReflectTypes = append(liveReflectTypes, rv)
			}
		}
		if len(liveReflectTypes) == 0 {
			sawOpenReflectValue = true
		} else {
			for _, rv := range liveReflectTypes {
				if typeReachesOpenReflectCarrier(rv.typ) {
					sawOpenReflectValue = true
					break
				}
			}
		}
	}
	if sawOpenReflectValue {
		for named := range summary.structReferencedByType {
			summary.poisonStruct(named, -1)
		}
		for ns := range rs.namedSigReferenced {
			summary.namedSigPoisoned[ns] = true
		}
	} else {
		for _, rv := range liveReflectTypes {
			summary.poisonContainedTypes(rv.typ, rv.fn, rs)
		}
	}
}

func isOSWrapperErrorStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	pkgPath := named.Obj().Pkg().Path()
	name := named.Obj().Name()
	return (pkgPath == "os" && name == "SyscallError") || ((pkgPath == "io/fs" || pkgPath == "os") && name == "PathError")
}

func typeContainsOSWrapperErrorStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	found := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
		if isOSWrapperErrorStruct(sub) {
			found = true
			return false
		}
		return true
	})
	return found
}

func isReflectMutationSymbol(name string) bool {
	switch name {
	case "Set", "SetZero", "SetInt", "SetUint", "SetFloat", "SetComplex", "SetBool",
		"SetBytes", "SetString", "SetPointer", "SetMapIndex", "SetIterKey", "SetIterValue",
		"SetLen", "SetCap", "Addr", "UnsafeAddr", "Pointer", "NewAt", "SliceAt", "Copy",
		"Append", "AppendSlice", "Grow", "Clear":
		return true
	default:
		return false
	}
}

func isReflectOpenProducerSymbol(name string) bool {
	switch name {
	case "New", "NewAt", "SliceAt", "Zero", "MakeSlice", "MakeMap", "MakeMapWithSize",
		"MakeChan", "MakeFunc", "Call", "CallSlice", "Method", "MethodByName", "Select":
		return true
	default:
		return false
	}
}

func typeReachesOpenReflectCarrier(t types.Type) bool {
	open := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
		switch tt := sub.(type) {
		case *types.Interface, *types.TypeParam:
			open = true
			return false
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "reflect" && obj.Name() == "Value" {
				open = true
				return false
			}
		}
		return true
	})
	return open
}

func isAddrOnlyForUnsafePointerConvert(site ssa.CallInstruction) bool {
	if site == nil {
		return false
	}
	val := site.Value()
	if val == nil || val.Referrers() == nil {
		return false
	}
	sawUse := false
	for _, ref := range *val.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case ssa.CallInstruction:
			if r.Common() == nil || r.Common().IsInvoke() {
				return false
			}
			callee := r.Common().StaticCallee()
			if callee == nil || funcPkgPath(callee) != "reflect" {
				return false
			}
			if baseFunctionSymbolName(callee) != "UnsafePointer" {
				return false
			}
			uval := r.Value()
			if uval == nil || uval.Referrers() == nil {
				return false
			}
			for _, uref := range *uval.Referrers() {
				switch conv := uref.(type) {
				case *ssa.DebugRef:
				case *ssa.Convert:
					ptr, ok := types.Unalias(conv.Type()).(*types.Pointer)
					if !ok {
						return false
					}
					basic, ok := types.Unalias(ptr.Elem()).(*types.Basic)
					if !ok || basic.Kind() == types.UnsafePointer || basic.Kind() == types.Uintptr || basic.Kind() == types.Invalid {
						return false
					}
					if conv.Referrers() == nil {
						return false
					}
					sawConvUse := false
					for _, cref := range *conv.Referrers() {
						switch cr := cref.(type) {
						case *ssa.DebugRef:
						case *ssa.Store:
							if cr.Addr != conv {
								return false
							}
							sawConvUse = true
						case *ssa.UnOp:
							if cr.Op != token.MUL || cr.X != conv {
								return false
							}
							sawConvUse = true
						default:
							return false
						}
					}
					if !sawConvUse {
						return false
					}
					sawUse = true
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return sawUse
}

func isNonMutatingReflectValueRoot(val ssa.Value) bool {
	return isNonMutatingReflectValueRootSeen(val, nil)
}

func isNonMutatingReflectValueRootSeen(val ssa.Value, seen map[ssa.Value]bool) bool {
	if val == nil || val.Referrers() == nil {
		return false
	}
	if seen[val] {
		return true
	}
	if seen == nil {
		seen = make(map[ssa.Value]bool, 4)
	}
	seen[val] = true
	for _, ref := range *val.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Phi:
			if !isNonMutatingReflectValueRootSeen(r, seen) {
				return false
			}
		case ssa.CallInstruction:
			c := r.Common()
			if c == nil || c.IsInvoke() || len(c.Args) == 0 || c.Args[0] != val || slices.Contains(c.Args[1:], val) {
				return false
			}
			callee := c.StaticCallee()
			if callee == nil || funcPkgPath(callee) != "reflect" {
				return false
			}
			switch baseFunctionSymbolName(callee) {
			case "Elem", "Indirect", "Field", "FieldByName", "FieldByIndex", "FieldByNameFunc", "Index", "MapIndex", "Slice", "Slice3", "Convert":
				if !isNonMutatingReflectValueRootSeen(r.Value(), seen) {
					return false
				}
			case "Addr":
				if !isAddrOnlyForUnsafePointerConvert(r) {
					return false
				}
			case "Kind", "IsNil", "IsValid", "IsZero", "Int", "Uint", "Float", "Complex", "Bool", "String",
				"Len", "Cap", "NumField", "NumMethod", "Type", "CanAddr", "CanSet", "CanInterface",
				"CanInt", "CanUint", "CanFloat", "CanComplex", "Comparable",
				"OverflowInt", "OverflowUint", "OverflowFloat", "OverflowComplex", "Interface":
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isStdDeserializerCall(pkgPath, sym string) bool {
	switch pkgPath {
	case "encoding/json", "encoding/json/v2", "encoding/json/jsontext",
		"encoding/xml", "encoding/gob", "encoding/binary", "encoding/asn1":
		return true
	case "fmt":
		return strings.HasPrefix(sym, "Scan") || strings.HasPrefix(sym, "Fscan") || strings.HasPrefix(sym, "Sscan")
	default:
		return false
	}
}

func isUnattributableRootedStdSymbol(pkgPath, sym string) bool {
	switch pkgPath {
	case "plugin", "testing/quick", "text/template", "html/template", "net/rpc", "net/rpc/jsonrpc":
		return true
	case "reflect":
		if isReflectMutationSymbol(sym) {
			return true
		}
		switch sym {
		case "Call", "CallSlice", "MakeFunc", "MethodByName", "Method":
			return true
		}
	}
	return false
}

func isOpaqueStructNamed(n *types.Named) bool {
	if n == nil {
		return false
	}
	st, ok := n.Underlying().(*types.Struct)
	return ok && propharness.StructHasNoExportedFields(st)
}

func nonStdTypeUsesUnsafePointer(audited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, userPaths map[string]bool, t types.Type) bool {
	return typeUsesUnsafePointerWith(t, true, nil, func(tt *types.Named, walk func(types.Type) bool) (bool, bool) {
		obj := tt.Obj()
		if obj == nil || obj.Pkg() == nil {
			return false, false
		}
		pkgPath := obj.Pkg().Path()
		if elem, ok := refconfine.AuditedAtomicPointerElem(audited, tt); ok {
			return walk(elem), true
		}
		if (isStdImportPath(pkgPath) && !userPaths[pkgPath]) ||
			(verifiedHarnesses[pkgPath] != nil && isOpaqueStructNamed(tt)) {
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if walk(tt.TypeArgs().At(i)) {
					return true, true
				}
			}
			return false, true
		}
		return false, false
	})
}

func collectValueContainedUserStructs(userPaths map[string]bool, t types.Type) []*types.Named {
	var out []*types.Named
	seen := make(map[types.Type]bool)
	seenNamed := make(map[*types.Named]bool)
	var walk func(types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if _, isPtr := tt.Underlying().(*types.Pointer); isPtr {
				return
			}
			if named := derefNamedStruct(userPaths, tt); named != nil && !seenNamed[named] {
				seenNamed[named] = true
				out = append(out, named)
			}
			walk(tt.Underlying())
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		case *types.Array:
			walk(tt.Elem())
		}
	}
	walk(t)
	return out
}
