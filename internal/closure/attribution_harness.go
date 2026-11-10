package closure

import (
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
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
	if seen[param] {
		return false
	}
	seen[param] = true
	refs := param.Referrers()
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
		case *ssa.FieldAddr:
			if r.X != param || !carrierFreeFieldAddr(audited, r, root) {
				return true
			}
		case *ssa.IndexAddr:
			if r.X != param || !carrierFreeReadOnlyAddr(audited, r, root) {
				return true
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.Field:
			if r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.Index:
			if r.X != param || !carrierFreeValueUses(audited, r, root) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != param {
				return true
			}
			named := derefNamedStruct(userPaths, param.Type())
			if named == nil || param.Parent() == nil || param.Parent().Prog == nil {
				return true
			}
			needed := make(map[int]bool)
			if !interfaceValueStructFieldTargets(audited, userPaths, named, param.Type(), param.Parent().Prog, r, root, needed, seen, make(map[ssa.Value]bool)) || len(needed) > 0 {
				return true
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return true
			}
			callee := r.Common().StaticCallee()
			if callee == nil || (root != nil && callee == root) || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && !(audited && callee.Origin() != nil)) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
				return true
			}
			for i, arg := range r.Common().Args {
				if arg == param && paramMaySupplyDynamicSeen(audited, userPaths, callee.Params[i], root, seen) {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func carrierFreeFieldAddr(audited bool, fa *ssa.FieldAddr, root *ssa.Function) bool {
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
	return carrierFreeReadOnlyAddr(audited, fa, root)
}

func carrierFreeReadOnlyAddr(audited bool, addr ssa.Value, root *ssa.Function) bool {
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
			if elemCarries && !carrierFreeValueUses(audited, r, root) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != addr || !carrierFreeFieldAddr(audited, r, root) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != addr || !carrierFreeReadOnlyAddr(audited, r, root) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func carrierFreeValueUses(audited bool, val ssa.Value, root *ssa.Function) bool {
	return carrierFreeValueUsesSeen(audited, val, root, make(map[ssa.Value]bool))
}

func carrierFreeValueUsesSeen(audited bool, val ssa.Value, root *ssa.Function, seen map[ssa.Value]bool) bool {
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
			if root == nil || r.Parent() != root {
				return false
			}
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.Field:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.Index:
			if r.X != val || !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.Phi:
			if !carrierFreeValueUsesSeen(audited, r, root, seen) {
				return false
			}
		case *ssa.MakeInterface:
			if !audited || r.X != val || !makeInterfaceOnlyReturned(r, root) {
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

func makeInterfaceOnlyReturned(mi *ssa.MakeInterface, root *ssa.Function) bool {
	if mi == nil || mi.Referrers() == nil || root == nil {
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
// It delegates to walkDynamicValue in seeds mode so closedness checking
// and RTA seed collection share a single SSA shape ladder.
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

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.PkgPath+".test"
}

func isPotentialHarnessCallbackSite(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return false
	}
	if c.IsInvoke() {
		return c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && (c.Method.Name() == "Cleanup" || c.Method.Name() == "Fuzz")
	}
	if callee := c.StaticCallee(); callee != nil {
		if funcPkgPath(callee) != "testing" {
			return false
		}
		base := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
		return base == "Cleanup" || base == "Fuzz"
	}
	return true
}

func collectTestingHarnessCallbacks(audited, harnessAudited bool, pureDelegates map[string]bool, userPaths map[string]bool, summary *callerReferenceSummary, subjectRoot *ssa.Function, enumerated bool, enc enumerationClosure, prov map[*ssa.Function]bool, mask uint64, res *rta.Result) (cleanupOut []*ssa.Function, unclosedCleanup bool, fuzzOut []*ssa.Function, unclosedFuzz bool) {
	seenCleanup := make(map[*ssa.Function]bool)
	seenFuzz := make(map[*ssa.Function]bool)
	var lazyFP *freshParamAnalysis
	getFP := func() *freshParamAnalysis {
		if lazyFP != nil {
			return lazyFP
		}
		functions := make(map[*ssa.Function]bool, len(prov))
		dynamicTargets := make(map[ssa.CallInstruction]map[*ssa.Function]bool)
		if res != nil {
			for fn, m := range res.Reachable {
				if m&mask != 0 {
					functions[fn] = true
				}
			}
			for site, targets := range res.Targets {
				if !functions[site.Parent()] {
					continue
				}
				for t, m := range targets {
					if m&mask != 0 && functions[t] {
						proj := dynamicTargets[site]
						if proj == nil {
							proj = make(map[*ssa.Function]bool)
							dynamicTargets[site] = proj
						}
						proj[t] = true
					}
				}
			}
		} else {
			for fn := range prov {
				functions[fn] = true
			}
		}
		var reach attributedReachability
		reach.functions = functions
		reach.dynamicTargets = dynamicTargets
		reach.subjectRoot = subjectRoot
		reach.enumeratedRoot = enumerated
		reach.enumeratedRootSites = enc.sites
		reach.enumeratedFieldStores = enc.fieldStores
		reach.propertyHarnessAudited = harnessAudited
		reach.userPaths = userPaths
		if summary != nil {
			reach.prog = summary.prog
			reach.summary = summary
			reach.structFieldStores = summary.structFieldStores
			reach.structWholeStores = summary.structWholeStores
			reach.structPoisoned = summary.structPoisoned
			reach.structReferencedByType = summary.structReferencedByType
			reach.programSites = summary.sites
			reach.programValueRef = summary.valueRef
			reach.programFunctions = summary.allFunctions
		}
		lazyFP = newFreshParamAnalysis(audited, pureDelegates, reach, func(fn *ssa.Function) bool {
			return isStdPkgPath(userPaths, funcPkgPath(fn))
		})
		return lazyFP
	}
	checkFuzzSig := func(fb *ssa.Function) bool {
		if fb == nil {
			return false
		}
		for idx, p := range fb.Params {
			if p == nil {
				continue
			}
			if idx == 0 && isHarnessPointerType(p.Type()) {
				continue
			}
			if typeMayCarryDynamicTop(audited, p.Type()) {
				return false
			}
		}
		return true
	}
	markUnclosed := func(kind string) {
		if kind == "Fuzz" {
			unclosedFuzz = true
		} else {
			unclosedCleanup = true
		}
	}
	addCallback := func(kind string, cb *ssa.Function) {
		if cb == nil {
			return
		}
		if cb.Parent() == nil && propharness.IsHarnessPath(funcPkgPath(cb)) {
			markUnclosed(kind)
			return
		}
		if kind == "Fuzz" {
			if !checkFuzzSig(cb) {
				unclosedFuzz = true
				return
			}
			if !seenFuzz[cb] {
				seenFuzz[cb] = true
				fuzzOut = append(fuzzOut, cb)
			}
			return
		}
		if !seenCleanup[cb] {
			seenCleanup[cb] = true
			cleanupOut = append(cleanupOut, cb)
		}
	}
	unwrapIface := func(v ssa.Value) ssa.Value {
		for v != nil {
			switch u := v.(type) {
			case *ssa.MakeInterface:
				v = u.X
			case *ssa.ChangeInterface:
				v = u.X
			default:
				return v
			}
		}
		return nil
	}
	handleSite := func(site ssa.CallInstruction) {
		rawArg, kind := testingHarnessCallArg(site, mask, res)
		if kind == "" {
			return
		}
		arg := unwrapIface(rawArg)
		if arg == nil {
			markUnclosed(kind)
			return
		}
		switch x := arg.(type) {
		case *ssa.Function:
			addCallback(kind, x)
		case *ssa.MakeClosure:
			cb, ok := x.Fn.(*ssa.Function)
			if !ok || cb == nil {
				markUnclosed(kind)
				return
			}
			if isBoundMethodWrapper(cb) && len(x.Bindings) > 0 && typeMayCarryDynamicTop(audited, x.Bindings[0].Type()) {
				if !subjectClosedDynamicValue(x.Bindings[0], make(map[ssa.Value]bool), getFP()) {
					markUnclosed(kind)
					return
				}
			}
			addCallback(kind, cb)
		default:
			targets, closed := closedDynamicTargets(rawArg, getFP())
			if !closed || len(targets) == 0 {
				markUnclosed(kind)
				return
			}
			for cb := range targets {
				addCallback(kind, cb)
			}
		}
	}
	if summary != nil && summary.harnessCallbackSites != nil {
		var ordered []*ssa.Function
		for fn := range prov {
			if fn != nil && len(summary.harnessCallbackSites[fn]) > 0 {
				ordered = append(ordered, fn)
			}
		}
		if len(ordered) == 0 {
			return nil, false, nil, false
		}
		sort.Slice(ordered, func(i, j int) bool { return lessSSAFunctionOrder(ordered[i], ordered[j]) })
		for _, fn := range ordered {
			for _, site := range summary.harnessCallbackSites[fn] {
				handleSite(site)
			}
		}
	} else {
		ordered := make([]*ssa.Function, 0, len(prov))
		for fn := range prov {
			if fn != nil {
				ordered = append(ordered, fn)
			}
		}
		sort.Slice(ordered, func(i, j int) bool { return lessSSAFunctionOrder(ordered[i], ordered[j]) })
		for _, fn := range ordered {
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if site, ok := instr.(ssa.CallInstruction); ok {
						handleSite(site)
					}
				}
			}
		}
	}
	sort.Slice(cleanupOut, func(i, j int) bool { return cleanupOut[i].String() < cleanupOut[j].String() })
	sort.Slice(fuzzOut, func(i, j int) bool { return fuzzOut[i].String() < fuzzOut[j].String() })
	return cleanupOut, unclosedCleanup, fuzzOut, unclosedFuzz
}

func testingHarnessCallArg(site ssa.CallInstruction, mask uint64, res *rta.Result) (ssa.Value, string) {
	if site == nil || site.Common() == nil {
		return nil, ""
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return nil, ""
	}
	matchTarget := func(fn *ssa.Function) string {
		if fn == nil || funcPkgPath(fn) != "testing" {
			return ""
		}
		base := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(fn), "$bound"), "$thunk")
		if base == "Cleanup" || base == "Fuzz" {
			return base
		}
		return ""
	}
	if c.IsInvoke() && c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" {
		if c.Method.Name() == "Cleanup" || c.Method.Name() == "Fuzz" {
			return c.Args[len(c.Args)-1], c.Method.Name()
		}
	}
	if callee := c.StaticCallee(); callee != nil {
		if kind := matchTarget(callee); kind != "" {
			return c.Args[len(c.Args)-1], kind
		}
		return nil, ""
	}
	if res == nil {
		return nil, ""
	}
	for target, tmask := range res.Targets[site] {
		if tmask&mask != 0 {
			if kind := matchTarget(target); kind != "" {
				return c.Args[len(c.Args)-1], kind
			}
		}
	}
	return nil, ""
}

func isVerifiedPureRootedAsmStub(audited bool, prog *program, fn *ssa.Function) bool {
	if !audited || prog == nil || fn == nil || len(fn.Blocks) != 0 || fn.Synthetic != "" || parameterizedBody(fn) {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() != nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	if !asmverify.SignatureCarrierFree(fn.Signature) {
		return false
	}
	pkgPath := fn.Pkg.Pkg.Path()
	hazards := nonSSAGlobalHazardsSummary(audited, prog)
	if hazards == nil || hazards.blockedPkgs[pkgPath] || hazards.linknamedVars[pkgVarKey{pkgPath: pkgPath, name: fn.Name()}] {
		return false
	}
	vp := hazards.verifiedAsm[pkgPath]
	if vp == nil || !vp.OK {
		return false
	}
	sum, ok := vp.Funcs[fn.Name()]
	return ok && sum.ImpureKind == ""
}

func rootedProvenanceIncomplete(audited, harnessAudited bool, prog *program, userPaths map[string]bool, sets ...map[*ssa.Function]bool) bool {
	var space [16]*ssa.Value
	for _, set := range sets {
		for fn := range set {
			if fn == nil {
				continue
			}
			pkgPath := funcPkgPath(fn)
			if isStdPkgPath(userPaths, pkgPath) {
				continue
			}
			if len(fn.Blocks) == 0 {
				if fn.Synthetic == "" && !parameterizedBody(fn) && !isVerifiedPureRootedAsmStub(audited, prog, fn) {
					return true
				}
				continue
			}
			for _, p := range fn.Params {
				if p != nil && nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, p.Type()) {
					return true
				}
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if v, ok := instr.(ssa.Value); ok && nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, v.Type()) {
						return true
					}
					for _, op := range instr.Operands(space[:0]) {
						if op == nil || *op == nil {
							continue
						}
						if nonStdTypeUsesUnsafePointer(audited, harnessAudited, userPaths, (*op).Type()) {
							return true
						}
						if g, ok := (*op).(*ssa.Function); ok {
							gPkg := funcPkgPath(g)
							gSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(g), "$bound"), "$thunk")
							if isUnattributableRootedStdSymbol(gPkg, gSym) {
								return true
							}
						}
					}
					site, ok := instr.(ssa.CallInstruction)
					if !ok || site.Common() == nil {
						continue
					}
					c := site.Common()
					if c.IsInvoke() {
						if c.Method != nil && c.Method.Pkg() != nil && isUnattributableRootedStdSymbol(c.Method.Pkg().Path(), c.Method.Name()) {
							return true
						}
						continue
					}
					if b, ok := c.Value.(*ssa.Builtin); ok {
						switch b.Name() {
						case "Add", "Slice", "SliceData", "String", "StringData":
							return true
						}
						continue
					}
					if callee := c.StaticCallee(); callee != nil {
						cPkg := funcPkgPath(callee)
						cSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
						if isUnattributableRootedStdSymbol(cPkg, cSym) {
							return true
						}
						if (userPaths[cPkg] || !isStdImportPath(cPkg)) && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee) && !isVerifiedPureRootedAsmStub(audited, prog, callee) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isReflectMutationSymbol(name string) bool {
	switch name {
	case "Set", "SetZero", "SetInt", "SetUint", "SetFloat", "SetComplex", "SetBool",
		"SetBytes", "SetString", "SetPointer", "SetMapIndex", "SetIterKey", "SetIterValue",
		"SetLen", "SetCap", "Addr", "UnsafeAddr", "Pointer", "NewAt", "Copy",
		"Append", "AppendSlice", "Grow", "Clear":
		return true
	default:
		return false
	}
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

func nonStdTypeUsesUnsafePointer(audited, harnessAudited bool, userPaths map[string]bool, t types.Type) bool {
	seen := make(map[types.Type]bool)
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if ssaOpaqueHandle(cur) || seen[cur] {
			return false
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Basic:
			return tt.Kind() == types.UnsafePointer
		case *types.Named:
			obj := tt.Obj()
			if obj != nil && obj.Pkg() != nil {
				pkgPath := obj.Pkg().Path()
				if pkgPath == "unsafe" && obj.Name() == "Pointer" {
					return true
				}
				if elem, ok := refconfine.AuditedAtomicPointerElem(audited, tt); ok {
					return walk(elem)
				}
				if (isStdImportPath(pkgPath) && !userPaths[pkgPath]) ||
					(harnessAudited && propharness.IsHarnessPath(pkgPath) && isOpaqueStructNamed(tt)) {
					for i := 0; i < tt.TypeArgs().Len(); i++ {
						if walk(tt.TypeArgs().At(i)) {
							return true
						}
					}
					return false
				}
			}
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if walk(tt.TypeArgs().At(i)) {
					return true
				}
			}
			return walk(tt.Underlying())
		case *types.Pointer:
			return walk(tt.Elem())
		case *types.Slice:
			return walk(tt.Elem())
		case *types.Array:
			return walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Map:
			return walk(tt.Key()) || walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					if walk(tuple.At(i).Type()) {
						return true
					}
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				if walk(tt.Field(i).Type()) {
					return true
				}
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				if walk(tt.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(t)
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

func isTestingCleanupCallback(fn *ssa.Function) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	for _, b := range fn.Parent().Blocks {
		for _, instr := range b.Instrs {
			switch x := instr.(type) {
			case *ssa.MakeClosure:
				if x.Fn == fn && x.Referrers() != nil {
					for _, ref := range *x.Referrers() {
						if site, ok := ref.(ssa.CallInstruction); ok && isTestingCleanupCall(site, x) {
							return true
						}
					}
				}
			case ssa.CallInstruction:
				if isTestingCleanupCall(x, fn) {
					return true
				}
			}
		}
	}
	return false
}

func isTestingCleanupCall(site ssa.CallInstruction, arg ssa.Value) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	hasArg := false
	for _, a := range c.Args {
		if a == arg {
			hasArg = true
			break
		}
	}
	if !hasArg {
		return false
	}
	if c.IsInvoke() {
		return c.Method != nil && c.Method.Name() == "Cleanup"
	}
	callee := c.StaticCallee()
	return callee != nil && funcPkgPath(callee) == "testing" && functionSymbolName(callee) == "Cleanup"
}
