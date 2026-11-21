package observability

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func resolveLocalCell(addr ssa.Value, peelField, peelSlice bool, seen map[ssa.Value]bool) *ssa.Alloc {
	switch a := addr.(type) {
	case *ssa.Alloc:
		return a
	case *ssa.FieldAddr:
		if !peelField {
			return nil
		}
		return resolveLocalCell(a.X, peelField, peelSlice, seen)
	case *ssa.IndexAddr:
		return resolveLocalCell(a.X, peelField, peelSlice, seen)
	case *ssa.Slice:
		if !peelSlice {
			return nil
		}
		return resolveLocalCell(a.X, peelField, peelSlice, seen)
	case *ssa.FreeVar:
		if seen[a] {
			return nil
		}
		seen[a] = true
		var cell *ssa.Alloc
		index := slices.Index(a.Parent().FreeVars, a)
		if index < 0 {
			return nil
		}
		for _, mk := range closureCreations(a.Parent()) {
			if index >= len(mk.Bindings) {
				return nil
			}
			bound := resolveLocalCell(mk.Bindings[index], peelField, peelSlice, seen)
			if bound == nil || (cell != nil && bound != cell) {
				return nil
			}
			cell = bound
		}
		return cell
	}
	return nil
}

// cellOf resolves a load's address to the local allocation it names —
// the allocation itself, or a free variable bound to it by every
// closure creation of its function (a free variable bound to different
// cells across creations names none). Nothing else is a cell.
func cellOf(addr ssa.Value, seen map[ssa.Value]bool) *ssa.Alloc {
	return resolveLocalCell(addr, true, false, seen)
}

func structElemCellOf(addr ssa.Value, seen map[ssa.Value]bool) *ssa.Alloc {
	return resolveLocalCell(addr, false, true, seen)
}

// closureCreations lists the MakeClosure instructions creating fn.
func closureCreations(fn *ssa.Function) []*ssa.MakeClosure {
	var creations []*ssa.MakeClosure
	if fn == nil || fn.Parent() == nil {
		return nil
	}
	for _, block := range fn.Parent().Blocks {
		for _, instr := range block.Instrs {
			if mk, ok := instr.(*ssa.MakeClosure); ok && mk.Fn == fn {
				creations = append(creations, mk)
			}
		}
	}
	return creations
}

func localAllocRoot(addr ssa.Value, localAllocs map[*ssa.Alloc]bool) bool {
	for addr != nil {
		switch a := addr.(type) {
		case *ssa.Alloc:
			return localAllocs[a]
		case *ssa.FieldAddr:
			addr = a.X
		case *ssa.IndexAddr:
			if _, isPtr := types.Unalias(a.X.Type()).Underlying().(*types.Pointer); !isPtr {
				return false
			}
			addr = a.X
		default:
			return false
		}
	}
	return false
}

// addressRoot resolves an address through field and index selections
// to the value it roots at — a package-level variable, a local
// allocation, or whatever else the chain ends in.
func addressRoot(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		default:
			return v
		}
	}
}

// confinedLocalStorage reports whether a local allocation, through
// every field and index selection of it, is used only as this frame's
// own storage: loaded, stored into, selected further, or handed to
// the registration write. Its address held anywhere else — stored as
// a value, passed to another callee, captured — is an escape the flag
// machinery could write behind a sibling subject's read.
func confinedLocalStorage(v ssa.Value, seen map[ssa.Value]bool) bool {
	if seen[v] {
		return true
	}
	seen[v] = true
	refs := v.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != v {
				return false
			}
		case *ssa.Store:
			if r.Addr != v || r.Val == v {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != v || !confinedLocalStorage(r, seen) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != v || !confinedLocalStorage(r, seen) {
				return false
			}
		case ssa.CallInstruction:
			if _, launched := r.(*ssa.Go); launched || !flagRegistrationWriteShape(r) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// registrationAddressComputation reports whether every use of an
// address-computation value feeds the sanctioned registration write —
// the &v.field / &v[i] argument shape, or the address a value-family
// result stores through — directly or through further selections.
func registrationAddressComputation(v ssa.Value, seen map[ssa.Value]bool) bool {
	if seen[v] {
		return true
	}
	seen[v] = true
	refs := v.Referrers()
	if refs == nil || len(*refs) == 0 {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case ssa.CallInstruction:
			if !flagRegistrationWriteShape(r) {
				return false
			}
		case *ssa.FieldAddr:
			if !registrationAddressComputation(r, seen) {
				return false
			}
		case *ssa.IndexAddr:
			if !registrationAddressComputation(r, seen) {
				return false
			}
		case *ssa.Store:
			if r.Addr != v || !flagRegistrationWriteShape(r) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func forEachLocalSliceAllocStore(v ssa.Value, visit func(idx *ssa.IndexAddr, val ssa.Value) bool) (*ssa.Slice, *types.Array, bool) {
	slice, ok := v.(*ssa.Slice)
	if !ok || slice.X == nil {
		return nil, nil, false
	}
	alloc, ok := slice.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return nil, nil, false
	}
	var arr *types.Array
	if ptr, ok := types.Unalias(alloc.Type()).Underlying().(*types.Pointer); ok {
		arr, _ = types.Unalias(ptr.Elem()).Underlying().(*types.Array)
	}
	for _, ref := range *alloc.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Slice:
			if r != slice {
				return nil, nil, false
			}
		case *ssa.IndexAddr:
			if r.X != alloc || r.Referrers() == nil {
				return nil, nil, false
			}
			for _, elem := range *r.Referrers() {
				switch e := elem.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					if e.Addr != r || (visit != nil && !visit(r, e.Val)) {
						return nil, nil, false
					}
				default:
					return nil, nil, false
				}
			}
		default:
			return nil, nil, false
		}
	}
	return slice, arr, true
}

func variadicSliceElementsAll(v ssa.Value, pred func(ssa.Value) bool) bool {
	_, _, ok := forEachLocalSliceAllocStore(v, func(_ *ssa.IndexAddr, val ssa.Value) bool {
		return pred == nil || pred(val)
	})
	return ok
}

func peelVariadicCallArg(v ssa.Value, visit func(ssa.Value) bool) (peeled, allOK bool) {
	allOK = true
	_, _, ok := forEachLocalSliceAllocStore(v, func(_ *ssa.IndexAddr, elem ssa.Value) bool {
		if visit != nil && !visit(elem) {
			allOK = false
			return false
		}
		return true
	})
	if !allOK {
		return false, false
	}
	return ok, true
}

func fixedVariadicArgs(site *ssa.Call) ([]ssa.Value, bool) {
	if site == nil || site.Common() == nil || len(site.Common().Args) != 1 {
		return nil, false
	}
	var args []ssa.Value
	seenIdxAddr := map[*ssa.IndexAddr]bool{}
	slice, array, ok := forEachLocalSliceAllocStore(site.Common().Args[0], func(ref *ssa.IndexAddr, val ssa.Value) bool {
		if seenIdxAddr[ref] || val == nil {
			return false
		}
		seenIdxAddr[ref] = true
		if args == nil {
			ptr, ok := ref.X.Type().Underlying().(*types.Pointer)
			if !ok {
				return false
			}
			arr, ok := ptr.Elem().Underlying().(*types.Array)
			if !ok || arr.Len() < 1 || arr.Len() > 64 {
				return false
			}
			args = make([]ssa.Value, int(arr.Len()))
		}
		index, ok := constInt(ref.Index)
		if !ok || index < 0 || index >= int64(len(args)) || args[index] != nil {
			return false
		}
		args[index] = val
		return true
	})
	if !ok || array == nil || array.Len() < 1 || array.Len() > 64 || len(args) != int(array.Len()) {
		return nil, false
	}
	for _, arg := range args {
		if arg == nil {
			return nil, false
		}
	}
	if slice.Referrers() == nil {
		return nil, false
	}
	for _, ref := range *slice.Referrers() {
		if call, ok := ref.(*ssa.Call); !ok || call != site {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return nil, false
			}
		}
	}
	return args, true
}

const excludedAllReturns = -2

type paramTupleKey struct {
	param      *ssa.Parameter
	tupleIndex int
}

// returnExcludesTupleIndex reports whether ret belongs to callee and val is
// absent from the queried tupleIndex result slot (either because all returns
// of callee are excluded via excludedAllReturns, or because tupleIndex selects
// a valid slot of ret.Results whose operand is not val).
func returnExcludesTupleIndex(ret *ssa.Return, val ssa.Value, callee *ssa.Function, tupleIndex int) bool {
	if ret == nil || val == nil || callee == nil || ret.Parent() != callee {
		return false
	}
	if tupleIndex == excludedAllReturns {
		return true
	}
	return tupleIndex >= 0 && tupleIndex < len(ret.Results) && ret.Results[tupleIndex] != val
}

type valueSinkPolicy struct {
	callee         *ssa.Function
	root           *ssa.Function
	tupleIndex     int
	allowEqCompare bool
	strictAlloc    bool
	onRef          func(val ssa.Value, ref ssa.Instruction, seen map[ssa.Value]bool) (flowsOutside, handled bool)
}

func valueFlowsOutsideAllowedSinks(val ssa.Value, policy valueSinkPolicy, seen map[ssa.Value]bool) bool {
	if val == nil || policy.callee == nil {
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
		if _, isDbg := ref.(*ssa.DebugRef); isDbg {
			continue
		}
		if policy.onRef != nil {
			if flows, handled := policy.onRef(val, ref, seen); handled {
				if flows {
					return true
				}
				continue
			}
		}
		switch r := ref.(type) {
		case *ssa.Return:
			if !((policy.root != nil && r.Parent() == policy.root) || returnExcludesTupleIndex(r, val, policy.callee, policy.tupleIndex)) {
				return true
			}
		case *ssa.BinOp:
			if !policy.allowEqCompare || (r.Op != token.EQL && r.Op != token.NEQ) {
				return true
			}
		case *ssa.Phi:
			if valueFlowsOutsideAllowedSinks(r, policy, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != val || valueFlowsOutsideAllowedSinks(r, policy, seen) {
				return true
			}
		case *ssa.ChangeInterface:
			if r.X != val || valueFlowsOutsideAllowedSinks(r, policy, seen) {
				return true
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || fn == nil || r.Fn == val {
				return true
			}
			if policy.onRef == nil && !policy.allowEqCompare {
				if !valueOnlyReturnedOutsideTupleIndex(r, policy.callee, policy.tupleIndex, seen) {
					return true
				}
			} else if !closureCaptureOnlyReturnedOutsideTupleIndex(r, val, policy.callee, policy.tupleIndex) {
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
			if alloc == nil || alloc.Parent() != policy.callee {
				return true
			}
			if policy.strictAlloc {
				if !allocOnlyReturnedOutsideTupleIndex(alloc, policy.callee, policy.tupleIndex, make(map[ssa.Value]bool)) {
					return true
				}
			} else if allocFlowsOutsideAllowedSinks(alloc, policy, seen) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func allocFlowsOutsideAllowedSinks(alloc *ssa.Alloc, policy valueSinkPolicy, seen map[ssa.Value]bool) bool {
	if alloc == nil || policy.callee == nil || alloc.Parent() != policy.callee {
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
		case *ssa.Return:
			if !((policy.root != nil && r.Parent() == policy.root) || returnExcludesTupleIndex(r, alloc, policy.callee, policy.tupleIndex)) {
				return true
			}
		case *ssa.Store:
			if r.Addr != alloc || r.Val == alloc {
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
					if fr.Addr != r || fr.Val == r {
						return true
					}
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r || valueFlowsOutsideAllowedSinks(fr, policy, seen) {
						return true
					}
				default:
					return true
				}
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alloc || valueFlowsOutsideAllowedSinks(r, policy, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != alloc || valueFlowsOutsideAllowedSinks(r, policy, seen) {
				return true
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok || fn == nil || r.Fn == alloc {
				return true
			}
			if policy.onRef == nil && !policy.allowEqCompare {
				if !valueOnlyReturnedOutsideTupleIndex(r, policy.callee, policy.tupleIndex, seen) {
					return true
				}
			} else if !closureCaptureOnlyReturnedOutsideTupleIndex(r, alloc, policy.callee, policy.tupleIndex) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func closureCaptureOnlyReturnedOutsideTupleIndex(mc *ssa.MakeClosure, val ssa.Value, callee *ssa.Function, tupleIndex int) bool {
	if mc == nil || val == nil || callee == nil || (tupleIndex < 0 && tupleIndex != excludedAllReturns) {
		return false
	}
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil || mc.Fn == val {
		return false
	}
	return valueOnlyReturnedOutsideTupleIndex(mc, callee, tupleIndex, make(map[ssa.Value]bool))
}

func valueOnlyReturnedOutsideTupleIndex(val ssa.Value, callee *ssa.Function, tupleIndex int, seen map[ssa.Value]bool) bool {
	if val == nil || callee == nil || (tupleIndex < 0 && tupleIndex != excludedAllReturns) {
		return false
	}
	return !valueFlowsOutsideAllowedSinks(val, valueSinkPolicy{
		callee:         callee,
		tupleIndex:     tupleIndex,
		allowEqCompare: false,
	}, seen)
}

func allocOnlyReturnedOutsideTupleIndex(alloc *ssa.Alloc, callee *ssa.Function, tupleIndex int, seen map[ssa.Value]bool) bool {
	if alloc == nil || callee == nil || alloc.Parent() != callee || (tupleIndex < 0 && tupleIndex != excludedAllReturns) {
		return false
	}
	return !allocFlowsOutsideAllowedSinks(alloc, valueSinkPolicy{
		callee:         callee,
		tupleIndex:     tupleIndex,
		allowEqCompare: false,
	}, seen)
}

func callResultSubTupleIndices(site ssa.CallInstruction, callee *ssa.Function, tupleIndex int) []int {
	call, ok := site.(*ssa.Call)
	if !ok || call == nil || callee == nil || (tupleIndex < 0 && tupleIndex != excludedAllReturns) {
		return []int{-1}
	}
	if tup, isTuple := call.Type().(*types.Tuple); isTuple {
		if tup.Len() == 0 {
			return []int{-1}
		}
		refs := call.Referrers()
		if refs == nil {
			return []int{-1}
		}
		var indices []int
		for _, ref := range *refs {
			switch r := ref.(type) {
			case *ssa.DebugRef:
			case *ssa.Extract:
				if r.Tuple != call || r.Index < 0 || r.Index >= tup.Len() {
					return []int{-1}
				}
				if valueOnlyReturnedOutsideTupleIndex(r, callee, tupleIndex, make(map[ssa.Value]bool)) {
					continue
				}
				if !slices.Contains(indices, r.Index) {
					indices = append(indices, r.Index)
				}
			default:
				return []int{-1}
			}
		}
		if len(indices) == 0 {
			return []int{excludedAllReturns}
		}
		return indices
	}
	if call.Type() != nil && valueOnlyReturnedOutsideTupleIndex(call, callee, tupleIndex, make(map[ssa.Value]bool)) {
		return []int{excludedAllReturns}
	}
	return []int{-1}
}
