package observability

import (
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/refconfine"
)

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed when references are direct static calls
// (or closed struct-receiver uses) with at least one reference in the
// program, and every dynamic-reaching argument or receiver field position
// closes in the caller's or constructor's own frame.
func subjectEnumerationClosure(audited bool, pureDelegates map[string]bool, userPaths map[string]bool, root *ssa.Function, summary *callerReferenceSummary) (enumerationClosure, bool) {
	sites := summary.sites[root]
	valueRef := summary.directValueRef[root]
	hasExternalSite := false
	for _, site := range sites {
		if site != nil && site.Parent() != root {
			hasExternalSite = true
			break
		}
	}
	fp := newEnumFreshParamAnalysis(audited, pureDelegates, userPaths, root, sites, summary)
	if root.Signature != nil && root.Signature.Recv() != nil {
		if !audited || valueRef || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
			return enumerationClosure{}, false
		}
		for _, list := range []*types.TypeParamList{root.TypeParams(), root.Signature.TypeParams(), root.Signature.RecvTypeParams()} {
			for i := 0; list != nil && i < list.Len(); i++ {
				if !refconfine.TypeParamBoundsAwayFromDynamic(audited, list.At(i)) {
					return enumerationClosure{}, false
				}
			}
		}
		hasDynamicExtraParam := false
		for _, param := range root.Params[1:] {
			if typeMayCarryDynamicTop(audited, param.Type()) && paramMaySupplyDynamic(audited, userPaths, param) {
				if _, isSig := types.Unalias(param.Type()).Underlying().(*types.Signature); isSig {
					return enumerationClosure{}, false
				}
				hasDynamicExtraParam = true
			}
		}
		if hasDynamicExtraParam && !hasExternalSite {
			return enumerationClosure{}, false
		}
		named := derefNamedStruct(userPaths, root.Signature.Recv().Type())
		recvMaySupply := paramMaySupplyDynamic(audited, userPaths, root.Params[0])
		if recvMaySupply && named == nil {
			return enumerationClosure{}, false
		}
		if !hasExternalSite && (named == nil || !summary.isStructReferencedOutside(named, root)) {
			return enumerationClosure{}, false
		}
		enc := enumerationClosure{
			sites:       sites,
			addrTaken:   map[*ssa.Function]bool{},
			fieldStores: map[int][]ssa.Value{},
		}
		seedSeen := map[ssa.Value]bool{}
		if hasDynamicExtraParam {
			for _, site := range sites {
				siteArgs := site.Common().Args
				offset := 0
				if site.Common().IsInvoke() {
					offset = -1
				}
				for i := 1; i < len(root.Params); i++ {
					param := root.Params[i]
					if !typeMayCarryDynamicTop(audited, param.Type()) || !paramMaySupplyDynamic(audited, userPaths, param) {
						continue
					}
					argIdx := i + offset
					if argIdx < 0 || argIdx >= len(siteArgs) {
						return enumerationClosure{}, false
					}
					arg := siteArgs[argIdx]
					if !walkDynamicValue(arg, nil, make(map[ssa.Value]bool), nil, fp) {
						return enumerationClosure{}, false
					}
					collectClosedDynamicSeeds(arg, &enc, seedSeen, fp)
				}
			}
		}
		if !recvMaySupply {
			if paramHasMakeInterface(root.Params[0], make(map[*ssa.Parameter]bool)) {
				enc.types = append(enc.types, root.Params[0].Type())
			}
			return enc, true
		}
		if summary.structPoisoned[structFieldKey{named: named, field: -1}] {
			return enumerationClosure{}, false
		}
		_, neededFields, ok := recvStructFieldTargets(audited, userPaths, root)
		if !ok {
			return enumerationClosure{}, false
		}
		fp.enumRecvNamed = named
		fp.resetDynamicMemos()
		for _, site := range sites {
			if site.Common().IsInvoke() && len(summary.structBoxedValues[named]) > 0 {
				continue
			}
			var recvArg ssa.Value
			if site.Common().IsInvoke() {
				recvArg = site.Common().Value
			} else {
				if len(site.Common().Args) == 0 {
					return enumerationClosure{}, false
				}
				recvArg = site.Common().Args[0]
			}
			if !walkDynamicValue(recvArg, nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
		}
		for _, bv := range summary.structBoxedValues[named] {
			if !walkDynamicValue(bv, nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
		}
		if paramHasMakeInterface(root.Params[0], make(map[*ssa.Parameter]bool)) {
			enc.types = append(enc.types, root.Params[0].Type())
		}
		fieldSeedSeen := map[ssa.Value]bool{}
		if wholeStores := summary.structWholeStores[named]; len(wholeStores) > 0 {
			wholeFP := *fp
			wholeFP.inProgramSites = true
			wholeFP.inFieldStore = true
			for _, wv := range wholeStores {
				if !walkDynamicValue(wv, nil, make(map[ssa.Value]bool), nil, &wholeFP) {
					return enumerationClosure{}, false
				}
				collectClosedDynamicSeeds(wv, &enc, fieldSeedSeen, &wholeFP)
			}
		}
		var fieldIdxs []int
		for idx := range neededFields {
			fieldIdxs = append(fieldIdxs, idx)
		}
		sort.Ints(fieldIdxs)
		fieldFP := *fp
		fieldFP.inFieldStore = true
		st, _ := named.Underlying().(*types.Struct)
		for _, idx := range fieldIdxs {
			key := structFieldKey{named: named, field: idx}
			if summary.structPoisoned[key] {
				return enumerationClosure{}, false
			}
			if st != nil && idx >= 0 && idx < st.NumFields() {
				fType := st.Field(idx).Type()
				if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
					if innerNamed := derefNamedStruct(userPaths, fType); innerNamed != nil && typeMayCarryDynamicTop(audited, innerNamed) {
						if !enumUserStructClosed(innerNamed, &fieldFP) {
							return enumerationClosure{}, false
						}
						typesMap := map[types.Type]bool{}
						if enc.addrTaken == nil {
							enc.addrTaken = map[*ssa.Function]bool{}
						}
						collectUserStructSeeds(innerNamed, &dynamicValueCollector{
							types: typesMap,
							funcs: enc.addrTaken,
							seeds: true,
						}, &fieldFP)
						for t := range typesMap {
							enc.types = append(enc.types, t)
						}
					}
				}
			}
			stores := summary.structFieldStores[key]
			for _, val := range stores {
				if !walkDynamicValue(val, nil, make(map[ssa.Value]bool), nil, &fieldFP) {
					return enumerationClosure{}, false
				}
				collectClosedDynamicSeeds(val, &enc, fieldSeedSeen, &fieldFP)
			}
			enc.fieldStores[idx] = stores
		}
		return enc, true
	}
	if valueRef || !hasExternalSite {
		return enumerationClosure{}, false
	}
	enc := enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}
	seedSeen := map[ssa.Value]bool{}
	for _, site := range sites {
		args := site.Common().Args
		if len(args) != len(root.Params) {
			return enumerationClosure{}, false
		}
		for i, param := range root.Params {
			if !typeMayCarryDynamicTop(audited, param.Type()) {
				continue
			}
			if audited && len(root.Blocks) > 0 && root.Synthetic == "" && !parameterizedBody(root) && !paramMaySupplyDynamic(audited, userPaths, param) {
				continue
			}
			if !walkDynamicValue(args[i], nil, make(map[ssa.Value]bool), nil, fp) {
				return enumerationClosure{}, false
			}
			collectClosedDynamicSeeds(args[i], &enc, seedSeen, fp)
		}
	}
	return enc, true
}

func isAuditedStdErrorWrapperNamed(named *types.Named) bool {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "strconv" && named.Obj().Name() == "NumError"
}

func isAuditedStdErrorWrapperType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && isAuditedStdErrorWrapperNamed(named)
}

func derefNamedStruct(userPaths map[string]bool, t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil
	}
	if isStdPkgPath(userPaths, named.Obj().Pkg().Path()) && !isAuditedStdErrorWrapperNamed(named) {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named
}

func derefNamedSignature(userPaths map[string]bool, t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || isStdPkgPath(userPaths, named.Obj().Pkg().Path()) {
		return nil
	}
	if _, ok := named.Underlying().(*types.Signature); !ok {
		return nil
	}
	return named
}

func paramMaySupplyDynamic(audited bool, userPaths map[string]bool, param *ssa.Parameter) bool {
	if param == nil {
		return false
	}
	return paramMaySupplyDynamicSeen(audited, userPaths, param, param.Parent(), make(map[*ssa.Parameter]bool))
}

func paramMaySupplyDynamicSeen(audited bool, userPaths map[string]bool, param *ssa.Parameter, root *ssa.Function, seen map[*ssa.Parameter]bool) bool {
	if param == nil {
		return false
	}
	tupleSeen := make(map[paramTupleKey]bool, len(seen))
	for p, v := range seen {
		if v {
			tupleSeen[paramTupleKey{param: p, tupleIndex: -1}] = true
		}
	}
	res := paramMaySupplyTupleDynamicSeen(audited, userPaths, param, root, -1, tupleSeen)
	if seen != nil {
		for k, v := range tupleSeen {
			if v && k.tupleIndex == -1 {
				seen[k.param] = true
			}
		}
	}
	return res
}

func paramMaySupplyTupleDynamicSeen(audited bool, userPaths map[string]bool, param *ssa.Parameter, root *ssa.Function, tupleIndex int, seen map[paramTupleKey]bool) bool {
	if param == nil {
		return false
	}
	key := paramTupleKey{param: param, tupleIndex: tupleIndex}
	if seen[key] {
		return false
	}
	seen[key] = true
	refs := param.Referrers()
	if refs == nil {
		return true
	}
	if len(*refs) == 0 {
		return false
	}
	fn := param.Parent()
	policy := valueSinkPolicy{
		callee:         fn,
		root:           root,
		tupleIndex:     tupleIndex,
		allowEqCompare: true,
		strictAlloc:    true,
		onRef: func(val ssa.Value, ref ssa.Instruction, _ map[ssa.Value]bool) (bool, bool) {
			if val != param {
				return false, false
			}
			switch r := ref.(type) {
			case *ssa.Phi:
				return !valueOnlyReturnedOutsideTupleIndex(r, fn, tupleIndex, make(map[ssa.Value]bool)), true
			case *ssa.ChangeInterface:
				return true, true
			case *ssa.FieldAddr:
				return r.X != param || !carrierFreeFieldAddrTuple(audited, r, root, fn, tupleIndex), true
			case *ssa.IndexAddr:
				return r.X != param || !carrierFreeReadOnlyAddrTuple(audited, r, root, fn, tupleIndex), true
			case *ssa.UnOp:
				return r.Op != token.MUL || r.X != param || !carrierFreeValueUsesTuple(audited, r, root, fn, tupleIndex), true
			case *ssa.Field:
				return r.X != param || !carrierFreeValueUsesTuple(audited, r, root, fn, tupleIndex), true
			case *ssa.Index:
				return r.X != param || !carrierFreeValueUsesTuple(audited, r, root, fn, tupleIndex), true
			case *ssa.MakeInterface:
				if r.X != param {
					return true, true
				}
				if valueOnlyReturnedOutsideTupleIndex(r, fn, tupleIndex, make(map[ssa.Value]bool)) {
					return false, true
				}
				named := derefNamedStruct(userPaths, param.Type())
				if named == nil || fn == nil || fn.Prog == nil {
					return true, true
				}
				needed := make(map[int]bool)
				paramSeen := make(map[*ssa.Parameter]bool, len(seen))
				for k, v := range seen {
					if v && k.tupleIndex == -1 {
						paramSeen[k.param] = true
					}
				}
				if !interfaceValueStructFieldTargets(audited, userPaths, named, param.Type(), fn.Prog, r, root, needed, paramSeen, make(map[ssa.Value]bool)) || len(needed) > 0 {
					return true, true
				}
				return false, true
			case ssa.CallInstruction:
				if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
					return true, true
				}
				callee := r.Common().StaticCallee()
				if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
					return true, true
				}
				subTupleIndices := callResultSubTupleIndices(r, fn, tupleIndex)
				for i, arg := range r.Common().Args {
					if arg == param {
						for _, subIdx := range subTupleIndices {
							if paramMaySupplyTupleDynamicSeen(audited, userPaths, callee.Params[i], root, subIdx, seen) {
								return true, true
							}
						}
					}
				}
				return false, true
			default:
				return false, false
			}
		},
	}
	return valueFlowsOutsideAllowedSinks(param, policy, make(map[ssa.Value]bool))
}

func carrierFreeFieldAddr(audited bool, fa *ssa.FieldAddr, root *ssa.Function) bool {
	return carrierFreeFieldAddrTuple(audited, fa, root, nil, -1)
}

func carrierFreeFieldAddrTuple(audited bool, fa *ssa.FieldAddr, root, callee *ssa.Function, tupleIndex int) bool {
	if fa == nil || fa.Type() == nil {
		return false
	}
	ptr, ok := types.Unalias(fa.Type()).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	if !refconfine.TypeMayCarryDynamic(audited, ptr.Elem(), make(map[types.Type]bool)) {
		return true
	}
	return carrierFreeReadOnlyAddrTuple(audited, fa, root, callee, tupleIndex)
}

func carrierFreeReadOnlyAddrTuple(audited bool, addr ssa.Value, root, callee *ssa.Function, tupleIndex int) bool {
	if addr == nil || addr.Type() == nil || addr.Referrers() == nil {
		return false
	}
	ptr, ok := types.Unalias(addr.Type()).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	elemCarries := refconfine.TypeMayCarryDynamic(audited, ptr.Elem(), make(map[types.Type]bool))
	for _, ref := range *addr.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != addr {
				return false
			}
			if elemCarries && !carrierFreeValueUsesTuple(audited, r, root, callee, tupleIndex) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != addr || !carrierFreeFieldAddrTuple(audited, r, root, callee, tupleIndex) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != addr || !carrierFreeReadOnlyAddrTuple(audited, r, root, callee, tupleIndex) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func carrierFreeValueUses(audited bool, val ssa.Value, root *ssa.Function) bool {
	return carrierFreeValueUsesTuple(audited, val, root, nil, -1)
}

func carrierFreeValueUsesTuple(audited bool, val ssa.Value, root, callee *ssa.Function, tupleIndex int) bool {
	return carrierFreeValueUsesSeenTuple(audited, val, root, callee, tupleIndex, make(map[ssa.Value]bool))
}

func carrierFreeValueUsesSeenTuple(audited bool, val ssa.Value, root, callee *ssa.Function, tupleIndex int, seen map[ssa.Value]bool) bool {
	if val == nil || val.Type() == nil {
		return false
	}
	if seen[val] {
		return true
	}
	seen[val] = true
	if !refconfine.TypeMayCarryDynamic(audited, val.Type(), make(map[types.Type]bool)) {
		return true
	}
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if !((root != nil && r.Parent() == root) || returnExcludesTupleIndex(r, val, callee, tupleIndex)) {
				return false
			}
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Field:
			if r.X != val || !carrierFreeValueUsesSeenTuple(audited, r, root, callee, tupleIndex, seen) {
				return false
			}
		case *ssa.Index:
			if r.X != val || !carrierFreeValueUsesSeenTuple(audited, r, root, callee, tupleIndex, seen) {
				return false
			}
		case *ssa.Phi:
			if !carrierFreeValueUsesSeenTuple(audited, r, root, callee, tupleIndex, seen) {
				return false
			}
		case *ssa.MakeClosure:
			if !closureCaptureOnlyReturnedOutsideTupleIndex(r, val, callee, tupleIndex) {
				return false
			}
		case *ssa.MakeInterface:
			if !audited || r.X != val || !makeInterfaceOnlyReturnedTuple(r, root, callee, tupleIndex) {
				return false
			}
			if _, isIface := types.Unalias(val.Type()).Underlying().(*types.Interface); isIface {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func makeInterfaceOnlyReturnedTuple(mi *ssa.MakeInterface, root, callee *ssa.Function, tupleIndex int) bool {
	if mi == nil || mi.Referrers() == nil {
		return false
	}
	if valueOnlyReturnedOutsideTupleIndex(mi, callee, tupleIndex, make(map[ssa.Value]bool)) {
		return true
	}
	if root == nil {
		return false
	}
	sawReturn := false
	for _, ref := range *mi.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if r.Parent() != root {
				return false
			}
			sawReturn = true
		default:
			return false
		}
	}
	return sawReturn
}

func recvStructFieldTargets(audited bool, userPaths map[string]bool, root *ssa.Function) (*types.Named, map[int]bool, bool) {
	if !audited || root == nil || root.Signature == nil || root.Signature.Recv() == nil || len(root.Blocks) == 0 || root.Synthetic != "" || parameterizedBody(root) || len(root.Params) == 0 {
		return nil, nil, false
	}
	named := derefNamedStruct(userPaths, root.Signature.Recv().Type())
	if named == nil {
		return nil, nil, false
	}
	needed := make(map[int]bool)
	if !collectParamStructFieldTargets(audited, userPaths, named, root.Params[0], root, needed, make(map[*ssa.Parameter]bool)) {
		return nil, nil, false
	}
	return named, needed, true
}

func collectParamStructFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, param *ssa.Parameter, root *ssa.Function, needed map[int]bool, seen map[*ssa.Parameter]bool) bool {
	if param == nil {
		return false
	}
	return collectStructCarrierFieldTargets(audited, userPaths, named, param, nil, root, needed, seen, make(map[ssa.Value]bool))
}

func collectStructCarrierFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, val ssa.Value, initStore *ssa.Store, root *ssa.Function, needed map[int]bool, seen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
	if val == nil {
		return false
	}
	if param, ok := val.(*ssa.Parameter); ok {
		if seen[param] {
			return true
		}
		seen[param] = true
	} else {
		if valSeen[val] {
			return true
		}
		valSeen[val] = true
	}
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Store:
			if r == initStore {
				continue
			}
			if r.Val == val && r.Addr != val {
				alloc, ok := r.Addr.(*ssa.Alloc)
				if !ok || derefNamedStruct(userPaths, alloc.Type()) != named {
					return false
				}
				if !collectStructCarrierFieldTargets(audited, userPaths, named, alloc, r, root, needed, seen, valSeen) {
					return false
				}
				continue
			}
			return false
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || fn == nil || len(fn.Blocks) == 0 || len(r.Bindings) != len(fn.FreeVars) {
				return false
			}
			for i, b := range r.Bindings {
				if b == val {
					if derefNamedStruct(userPaths, fn.FreeVars[i].Type()) != named ||
						!collectStructCarrierFieldTargets(audited, userPaths, named, fn.FreeVars[i], nil, root, needed, seen, valSeen) {
						return false
					}
				}
			}
		case *ssa.Field:
			if r.X != val {
				return false
			}
			if carrierFreeValueUses(audited, r, root) {
				continue
			}
			needed[r.Field] = true
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != val || r.Referrers() == nil {
				return false
			}
			for _, uref := range *r.Referrers() {
				switch ur := uref.(type) {
				case *ssa.DebugRef:
				case *ssa.Field:
					if ur.X != r {
						return false
					}
					if carrierFreeValueUses(audited, ur, root) {
						continue
					}
					needed[ur.Field] = true
				case *ssa.Store:
					if ur.Val == r && ur.Addr != r {
						if alloc, ok := ur.Addr.(*ssa.Alloc); ok && derefNamedStruct(userPaths, alloc.Type()) == named {
							if !collectStructCarrierFieldTargets(audited, userPaths, named, alloc, ur, root, needed, seen, valSeen) {
								return false
							}
							continue
						}
					}
					return false
				default:
					return false
				}
			}
		case *ssa.FieldAddr:
			if r.X != val {
				return false
			}
			if carrierFreeFieldAddr(audited, r, root) {
				continue
			}
			if r.Referrers() == nil {
				return false
			}
			hasLoad := false
			allDerefOrStore := true
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r {
						allDerefOrStore = false
					} else {
						hasLoad = true
					}
				case *ssa.Store:
					if fr.Addr != r || fr.Val == r {
						allDerefOrStore = false
					}
				default:
					allDerefOrStore = false
				}
			}
			if !allDerefOrStore {
				innerNamed := derefNamedStruct(userPaths, r.Type())
				if innerNamed == nil || !collectStructCarrierFieldTargets(audited, userPaths, innerNamed, r, nil, root, make(map[int]bool), seen, valSeen) {
					return false
				}
				needed[r.Field] = true
			} else if hasLoad {
				needed[r.Field] = true
			}
		case *ssa.MakeInterface:
			if r.X != val {
				return false
			}
			if val.Parent() != nil && val.Parent().Prog != nil &&
				interfaceValueStructFieldTargets(audited, userPaths, named, val.Type(), val.Parent().Prog, r, root, needed, seen, make(map[ssa.Value]bool)) {
				continue
			}
			st, ok := named.Underlying().(*types.Struct)
			if !ok {
				return false
			}
			for i := 0; i < st.NumFields(); i++ {
				if refconfine.TypeMayCarryDynamic(audited, st.Field(i).Type(), make(map[types.Type]bool)) {
					needed[i] = true
				}
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return false
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val {
					if derefNamedStruct(userPaths, callee.Params[i].Type()) != named {
						return false
					}
					if paramMaySupplyDynamicSeen(audited, userPaths, callee.Params[i], root, make(map[*ssa.Parameter]bool)) {
						if !collectStructCarrierFieldTargets(audited, userPaths, named, callee.Params[i], nil, root, needed, seen, valSeen) {
							return false
						}
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func paramHasMakeInterface(param *ssa.Parameter, seen map[*ssa.Parameter]bool) bool {
	if param == nil || seen[param] {
		return false
	}
	seen[param] = true
	refs := param.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.MakeInterface:
			if r.X == param {
				return true
			}
		case ssa.CallInstruction:
			if r.Common() == nil || r.Common().IsInvoke() {
				continue
			}
			callee := r.Common().StaticCallee()
			if callee == nil || len(r.Common().Args) != len(callee.Params) {
				continue
			}
			for i, arg := range r.Common().Args {
				if arg == param && paramHasMakeInterface(callee.Params[i], seen) {
					return true
				}
			}
		}
	}
	return false
}

func interfaceValueStructFieldTargets(audited bool, userPaths map[string]bool, named *types.Named, concreteType types.Type, prog *ssa.Program, val ssa.Value, root *ssa.Function, needed map[int]bool, paramSeen map[*ssa.Parameter]bool, valSeen map[ssa.Value]bool) bool {
	if val == nil || prog == nil {
		return false
	}
	if valSeen[val] {
		return true
	}
	valSeen[val] = true
	refs := val.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Return:
			if root == nil || r.Parent() != root {
				return false
			}
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.ChangeInterface:
			if r.X != val || !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, r, root, needed, paramSeen, valSeen) {
				return false
			}
		case *ssa.TypeAssert:
			if r.X != val {
				return false
			}
			iface, ok := types.Unalias(r.AssertedType).Underlying().(*types.Interface)
			if !ok {
				return false
			}
			if !types.Implements(concreteType, iface) {
				continue
			}
			if !r.CommaOk {
				if !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, r, root, needed, paramSeen, valSeen) {
					return false
				}
				continue
			}
			if r.Referrers() == nil {
				return false
			}
			for _, er := range *r.Referrers() {
				switch ex := er.(type) {
				case *ssa.DebugRef:
				case *ssa.Extract:
					if ex.Tuple != r {
						return false
					}
					if ex.Index == 0 && !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, ex, root, needed, paramSeen, valSeen) {
						return false
					}
				default:
					return false
				}
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || len(fn.Blocks) == 0 {
				return false
			}
			for i, b := range r.Bindings {
				if b == val {
					if i >= len(fn.FreeVars) || !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, fn.FreeVars[i], root, needed, paramSeen, valSeen) {
						return false
					}
				}
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
				return false
			}
			if r.Common().IsInvoke() {
				for _, arg := range r.Common().Args {
					if arg == val {
						return false
					}
				}
				if r.Common().Value != val || r.Common().Method == nil {
					return false
				}
				cmethod := prog.LookupMethod(concreteType, r.Common().Method.Pkg(), r.Common().Method.Name())
				if cmethod == nil || (root != nil && cmethod == root) || len(cmethod.Blocks) == 0 || len(cmethod.Params) == 0 {
					return false
				}
				if paramMaySupplyDynamicSeen(audited, userPaths, cmethod.Params[0], root, make(map[*ssa.Parameter]bool)) {
					if !collectParamStructFieldTargets(audited, userPaths, named, cmethod.Params[0], root, needed, paramSeen) {
						return false
					}
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == val && !interfaceValueStructFieldTargets(audited, userPaths, named, concreteType, prog, callee.Params[i], root, needed, paramSeen, valSeen) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// collectClosedDynamicSeeds walks an already-closed argument value and
// gathers what it can hand the subject: function values become dispatch
// candidates, materialized concrete types enter the runtime-type walk.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool, fp *freshParamAnalysis) {
	if value == nil || enc == nil {
		return
	}
	if seen == nil {
		seen = map[ssa.Value]bool{}
	}
	typesMap := map[types.Type]bool{}
	if enc.addrTaken == nil {
		enc.addrTaken = map[*ssa.Function]bool{}
	}
	collector := &dynamicValueCollector{
		types: typesMap,
		funcs: enc.addrTaken,
		seeds: true,
	}
	walkDynamicValue(value, collector, seen, nil, fp)
	if _, isConst := value.(*ssa.Const); !isConst && value.Type() != nil && fp != nil && fp.selectionAudited {
		if named := derefNamedStruct(fp.userPkgPaths(), value.Type()); named != nil && typeMayCarryDynamicTop(fp.selectionAudited, named) {
			collectUserStructSeeds(named, collector, fp)
		}
	}
	for t := range typesMap {
		enc.types = append(enc.types, t)
	}
}

func rootMayReceiveUnknownDynamic(audited bool, prog *program, root *ssa.Function) bool {
	if root == nil || root.Signature == nil {
		return true
	}
	var extraTypeParams *types.TypeParamList
	if root.Signature.TypeParams() == nil {
		extraTypeParams = root.TypeParams()
	}
	return refconfine.SignatureOpenWorldTerm(audited, root.Signature, extraTypeParams, subjectRunsThroughHarness(prog, root), refconfine.CarrierPolicyClosure) != ""
}

func typeMayCarryDynamicTop(audited bool, t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).(type) {
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	case *types.Interface, *types.Signature:
		return true
	}
	return refconfine.WalkDynamicCarrier(audited, t, make(map[types.Type]bool), refconfine.CarrierPolicyClosure)
}
