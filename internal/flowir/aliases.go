package flowir

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// CollectPlaceBackingVars appends eligible root variables whose storage backs p
// to out, descending into transient base values when p is a transient projection.
func CollectPlaceBackingVars(
	p Place,
	sharesMem func(types.Type) bool,
	eligibleVar func(*types.Var) bool,
	descendClosures bool,
	exemptCalls map[*ast.CallExpr]bool,
	out []*types.Var,
) []*types.Var {
	if p.Obj != nil {
		if eligibleVar == nil || eligibleVar(p.Obj) {
			out = append(out, p.Obj)
		}
		return out
	}
	if p.Root == RootTransient && p.Base != nil {
		return CollectBackingVars(p.Base, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
	}
	return out
}

// CollectBackingVars appends eligible variables whose backing memory can flow
// into v to out, stopping at non-memory-bearing types, fresh zero/make
// allocations, and concrete string <-> []byte/[]rune copying conversions.
func CollectBackingVars(
	v *Value,
	sharesMem func(types.Type) bool,
	eligibleVar func(*types.Var) bool,
	descendClosures bool,
	exemptCalls map[*ast.CallExpr]bool,
	out []*types.Var,
) []*types.Var {
	if v == nil {
		return out
	}
	if v.Kind == ValCall && v.CallAST != nil && exemptCalls[v.CallAST] {
		return out
	}
	if v.Type != nil && sharesMem != nil && !sharesMem(v.Type) {
		return out
	}
	isEligible := func(u *types.Var) bool {
		return u != nil && !u.IsField() && (eligibleVar == nil || eligibleVar(u))
	}
	switch v.Kind {
	case ValPlace:
		if v.Place.Obj != nil {
			if isEligible(v.Place.Obj) && (v.Place.Obj.Type() == nil || sharesMem == nil || sharesMem(v.Place.Obj.Type())) {
				out = append(out, v.Place.Obj)
			}
		} else if v.Place.Root == RootTransient && v.Place.Base != nil {
			out = CollectBackingVars(v.Place.Base, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
		}
		// Index keys and slice bounds are scalar indices and do not supply
		// the projected value's backing storage.
		return out

	case ValAddrOf:
		return CollectPlaceBackingVars(v.AddrPlace, sharesMem, isEligible, descendClosures, exemptCalls, out)

	case ValMethodVal:
		if v.AutoAddr && v.HasRecvPlace {
			out = CollectPlaceBackingVars(v.RecvPlace, sharesMem, isEligible, descendClosures, exemptCalls, out)
		}
		return CollectBackingVars(v.Recv, sharesMem, eligibleVar, descendClosures, exemptCalls, out)

	case ValAllocFresh:
		switch v.AllocKind {
		case AllocMake, AllocBuiltinNewType:
			return out
		case AllocBuiltinNewExpr:
			for _, a := range v.Args {
				out = CollectBackingVars(a, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
			}
			return out
		case AllocCompositeLit:
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if elt.MapKey != nil {
					out = CollectBackingVars(elt.MapKey, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
				}
				if elt.Value != nil {
					out = CollectBackingVars(elt.Value, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
				}
			}
			return out
		}

	case ValMakeClosure:
		if descendClosures && v.Closure != nil {
			for fv := range v.Closure.FreeVars {
				if isEligible(fv) {
					out = append(out, fv)
				}
			}
		}
		return out

	case ValCall:
		if v.CallKind == CallIIFE && v.IIFE != nil {
			for fv := range v.IIFE.FreeVars {
				if isEligible(fv) {
					out = append(out, fv)
				}
			}
			v.IIFE.ForEachSyncOp(func(op *Op) bool {
				if op.Kind == OpReturn {
					for _, r := range op.Results {
						out = CollectBackingVars(r, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
					}
				}
				return true
			})
			for _, rv := range v.IIFE.Results {
				if isEligible(rv) && (rv.Type() == nil || sharesMem == nil || sharesMem(rv.Type())) {
					out = append(out, rv)
				}
			}
		}
		if v.AutoAddrRecv && v.HasRecvPlace {
			out = CollectPlaceBackingVars(v.RecvPlace, sharesMem, isEligible, descendClosures, exemptCalls, out)
		}
		out = CollectBackingVars(v.Recv, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
		out = CollectBackingVars(v.Callee, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
		for _, a := range v.Args {
			out = CollectBackingVars(a, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
		}
		return out

	case ValConvert:
		if !v.IsTypeAssert && v.Arg != nil && syntaxutil.IsFreshStringSliceCopy(v.Arg.Type, v.Type) {
			return out
		}
		return CollectBackingVars(v.Arg, sharesMem, eligibleVar, descendClosures, exemptCalls, out)

	case ValChanRecv:
		return CollectBackingVars(v.Chan, sharesMem, eligibleVar, descendClosures, exemptCalls, out)

	case ValCompositeExpr:
		for _, a := range v.Args {
			out = CollectBackingVars(a, sharesMem, eligibleVar, descendClosures, exemptCalls, out)
		}
		return out
	}
	return out
}

// BuildLocalMemAliases constructs the symmetric local backing-memory sharing
// graph across synchronous operations of body (excluding nested uncalled
// closures and goroutine spawns).
func BuildLocalMemAliases(
	body *Body,
	isLocal func(types.Object) bool,
	sharesMem func(types.Type) bool,
) map[types.Object]map[types.Object]bool {
	return buildMemAliases(body, isLocal, sharesMem, false, false, nil)
}

// BuildScopedMemAliases constructs the symmetric local backing-memory sharing
// graph across body and any nested closures or goroutine spawns without linking
// co-arguments at plain or method call sites.
func BuildScopedMemAliases(
	body *Body,
	isLocal func(types.Object) bool,
	sharesMem func(types.Type) bool,
) map[types.Object]map[types.Object]bool {
	return buildMemAliases(body, isLocal, sharesMem, true, false, nil)
}

// BuildEnclosingMemAliases constructs the symmetric local backing-memory
// sharing graph across body, descending into nested closures and goroutine
// spawns and linking memory-bearing or place-addressed participants at
// non-builtin call sites.
func BuildEnclosingMemAliases(
	body *Body,
	isLocal func(types.Object) bool,
	sharesMem func(types.Type) bool,
) map[types.Object]map[types.Object]bool {
	return buildMemAliases(body, isLocal, sharesMem, true, true, nil)
}

// BuildEnclosingMemAliasesExcept constructs the enclosing backing-memory
// sharing graph across body while skipping call expressions present in
// exemptCalls.
func BuildEnclosingMemAliasesExcept(
	body *Body,
	isLocal func(types.Object) bool,
	sharesMem func(types.Type) bool,
	exemptCalls map[*ast.CallExpr]bool,
) map[types.Object]map[types.Object]bool {
	return buildMemAliases(body, isLocal, sharesMem, true, true, exemptCalls)
}

func buildMemAliases(
	body *Body,
	isLocal func(types.Object) bool,
	sharesMem func(types.Type) bool,
	descendNested bool,
	linkCallParticipants bool,
	exemptCalls map[*ast.CallExpr]bool,
) map[types.Object]map[types.Object]bool {
	adj := map[types.Object]map[types.Object]bool{}
	if body == nil || isLocal == nil || sharesMem == nil {
		return adj
	}
	eligibleVar := func(v *types.Var) bool {
		return v != nil && !v.IsField() && isLocal(v)
	}
	type interiorWrite struct {
		target     *types.Var
		src        *types.Var
		deepNested bool
	}
	type bareBind struct {
		dst          *types.Var
		src          *types.Var
		extractsElem bool
	}

	var allVars []*types.Var
	seenVar := map[*types.Var]bool{}
	noteVar := func(v *types.Var) bool {
		if !eligibleVar(v) {
			return false
		}
		if !seenVar[v] {
			seenVar[v] = true
			allVars = append(allVars, v)
		}
		return true
	}

	viewFwd := map[*types.Var]map[*types.Var]bool{}
	allFwd := map[*types.Var]map[*types.Var]bool{}
	addFwd := func(g map[*types.Var]map[*types.Var]bool, from, to *types.Var) bool {
		if !noteVar(from) || !noteVar(to) || from == to {
			return false
		}
		if g[from] == nil {
			g[from] = map[*types.Var]bool{}
		}
		if g[from][to] {
			return false
		}
		g[from][to] = true
		return true
	}

	var bareBinds []bareBind
	var interiorWrites []interiorWrite
	addBareBind := func(dst, src *types.Var, extractsElem bool) {
		if !noteVar(dst) || !noteVar(src) {
			return
		}
		addFwd(viewFwd, src, dst)
		addFwd(allFwd, src, dst)
		if extractsElem {
			bareBinds = append(bareBinds, bareBind{dst: dst, src: src, extractsElem: true})
		}
	}
	addBidirectional := func(a, b *types.Var) {
		if !noteVar(a) || !noteVar(b) || a == b {
			return
		}
		addFwd(viewFwd, a, b)
		addFwd(viewFwd, b, a)
		addFwd(allFwd, a, b)
		addFwd(allFwd, b, a)
	}
	addInteriorWrite := func(target, src *types.Var, deepNested bool) {
		if !noteVar(target) || !noteVar(src) {
			return
		}
		addFwd(allFwd, src, target)
		interiorWrites = append(interiorWrites, interiorWrite{
			target:     target,
			src:        src,
			deepNested: deepNested,
		})
	}

	collectPlaceAddrVars := func(p Place, out []*types.Var) []*types.Var {
		return CollectPlaceBackingVars(p, sharesMem, eligibleVar, descendNested, exemptCalls, out)
	}
	collectValueSources := func(v *Value, out []*types.Var) []*types.Var {
		return CollectBackingVars(v, sharesMem, eligibleVar, descendNested, exemptCalls, out)
	}

	isBareUnprojectedSource := func(v *Value) bool {
		if v == nil {
			return false
		}
		if v.Kind == ValPlace && len(v.Place.Projs) == 0 {
			return true
		}
		if v.Kind == ValAddrOf && !v.IsArraySlice && v.AddrPlace.IsBareVar() {
			return true
		}
		return false
	}

	linkDstToValue := func(dst Place, val *Value, rangeAssign bool) {
		if val == nil {
			return
		}
		// Only propagate when the written slot itself (or target base on a
		// composite write) can hold shared backing memory.
		if dst.Type != nil && !sharesMem(dst.Type) {
			return
		}
		dstVars := collectPlaceAddrVars(dst, nil)
		if len(dstVars) == 0 {
			return
		}
		// Ensure bare-ident targets also satisfy sharesMem on their variable type.
		if dst.IsBareVar() && dst.Obj.Type() != nil && !sharesMem(dst.Obj.Type()) {
			return
		}
		srcVars := collectValueSources(val, nil)
		if dst.IsBareVar() {
			extracts := rangeAssign || !isBareUnprojectedSource(val)
			for _, dv := range dstVars {
				for _, sv := range srcVars {
					addBareBind(dv, sv, extracts)
				}
			}
			return
		}
		deep := PlaceEntersInterior(dst, false)
		for _, dv := range dstVars {
			for _, sv := range srcVars {
				addInteriorWrite(dv, sv, deep)
			}
		}
	}

	var scanBody func(b *Body)
	var scanValue func(v *Value)

	scanValue = func(v *Value) {
		if v == nil {
			return
		}
		if v.Kind == ValCall && v.CallAST != nil && exemptCalls[v.CallAST] {
			return
		}
		switch v.Kind {
		case ValMakeClosure:
			if descendNested && v.Closure != nil {
				scanBody(v.Closure)
			}
			return
		case ValCall:
			if v.CallKind == CallBuiltin {
				switch v.BuiltinName {
				case "copy":
					if len(v.Args) == 2 && (v.Args[0].Type == nil || sharesMem(v.Args[0].Type)) {
						dstVars := collectValueSources(v.Args[0], nil)
						srcVars := collectValueSources(v.Args[1], nil)
						deep := !(v.Args[0].Kind == ValPlace && v.Args[0].Place.IsBareVar() &&
							v.Args[0].Place.Obj != nil && syntaxutil.IsRefHeaderType(v.Args[0].Place.Obj.Type()))
						for _, dv := range dstVars {
							for _, sv := range srcVars {
								addInteriorWrite(dv, sv, deep)
							}
						}
					}
				case "append":
					if len(v.Args) >= 2 && (v.Args[0].Type == nil || sharesMem(v.Args[0].Type)) {
						dstVars := collectValueSources(v.Args[0], nil)
						deep := !(v.Args[0].Kind == ValPlace && v.Args[0].Place.IsBareVar() &&
							v.Args[0].Place.Obj != nil && syntaxutil.IsRefHeaderType(v.Args[0].Place.Obj.Type()))
						for _, elem := range v.Args[1:] {
							srcVars := collectValueSources(elem, nil)
							for _, dv := range dstVars {
								for _, sv := range srcVars {
									addInteriorWrite(dv, sv, deep)
								}
							}
						}
					}
				}
			} else if linkCallParticipants {
				var participants []*types.Var
				if v.AutoAddrRecv && v.HasRecvPlace {
					participants = collectPlaceAddrVars(v.RecvPlace, participants)
				}
				participants = collectValueSources(v.Recv, participants)
				participants = collectValueSources(v.Callee, participants)
				for _, a := range v.Args {
					participants = collectValueSources(a, participants)
				}
				for i := 0; i < len(participants); i++ {
					for j := i + 1; j < len(participants); j++ {
						addBidirectional(participants[i], participants[j])
					}
				}
			}
			if v.CallKind == CallIIFE && v.IIFE != nil {
				if len(v.Args) > 0 && len(v.IIFE.Params) > 0 {
					v.ForEachArgParam(func(arg *Value, slotType types.Type, _ int, pIdx int, ok bool, packed bool) bool {
						if !ok || pIdx >= len(v.IIFE.Params) || v.IIFE.Params[pIdx] == nil {
							return true
						}
						if slotType != nil && !sharesMem(slotType) {
							return true
						}
						pv := v.IIFE.Params[pIdx]
						if pv.Type() == nil || sharesMem(pv.Type()) {
							extracts := packed || !isBareUnprojectedSource(arg)
							for _, sv := range collectValueSources(arg, nil) {
								addBareBind(pv, sv, extracts)
							}
						}
						return true
					})
				}
				scanBody(v.IIFE)
			}
		}
		v.ForEachChildValue(func(child *Value) bool {
			scanValue(child)
			return true
		})
	}

	scanOp := func(op *Op) {
		switch op.Kind {
		case OpAssign:
			isRange := op.AssignKind == AssignRange
			op.ForEachAssignPair(func(_ int, dst Place, _ bool, src *Value) bool {
				linkDstToValue(dst, src, isRange)
				if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && keyVal != nil {
					if keyVal.Type == nil || sharesMem(keyVal.Type) {
						mapVars := collectPlaceAddrVars(mapPlace, nil)
						keyVars := collectValueSources(keyVal, nil)
						deep := PlaceEntersInterior(dst, false)
						for _, mv := range mapVars {
							for _, kv := range keyVars {
								addInteriorWrite(mv, kv, deep)
							}
						}
					}
				}
				dst.ForEachChildValue(func(cv *Value) bool {
					scanValue(cv)
					return true
				})
				return true
			})
			if (op.AssignKind == AssignMulti || op.AssignKind == AssignPlain) && len(op.Dsts) >= 2 && len(op.Srcs) == 1 &&
				op.Srcs[0] != nil && op.Srcs[0].Kind == ValCall &&
				(op.Srcs[0].CallAST == nil || !exemptCalls[op.Srcs[0].CallAST]) {
				var multiDsts []*types.Var
				for _, dst := range op.Dsts {
					if dst.Type != nil && !sharesMem(dst.Type) {
						continue
					}
					if dst.IsBareVar() && dst.Obj.Type() != nil && !sharesMem(dst.Obj.Type()) {
						continue
					}
					multiDsts = collectPlaceAddrVars(dst, multiDsts)
				}
				for i := 0; i < len(multiDsts); i++ {
					for j := i + 1; j < len(multiDsts); j++ {
						addBidirectional(multiDsts[i], multiDsts[j])
					}
				}
			}
			for _, src := range op.Srcs {
				scanValue(src)
			}
			if op.AssignKind == AssignRange && op.RangeBody != nil {
				scanBody(op.RangeBody)
			}

		case OpTypeSwitchBind:
			if op.SwitchDst != nil && op.SwitchSrc != nil && eligibleVar(op.SwitchDst) &&
				(op.SwitchDst.Type() == nil || sharesMem(op.SwitchDst.Type())) {
				extracts := !isBareUnprojectedSource(op.SwitchSrc)
				for _, sv := range collectValueSources(op.SwitchSrc, nil) {
					addBareBind(op.SwitchDst, sv, extracts)
				}
			}
			scanValue(op.SwitchSrc)

		case OpChanSend:
			if op.SendVal != nil && (op.SendVal.Type == nil || sharesMem(op.SendVal.Type)) {
				chanVars := collectPlaceAddrVars(op.ChanPlace, nil)
				valVars := collectValueSources(op.SendVal, nil)
				deep := !(op.ChanPlace.IsBareVar() && op.ChanPlace.Obj != nil && syntaxutil.IsRefHeaderType(op.ChanPlace.Obj.Type()))
				for _, cv := range chanVars {
					for _, vv := range valVars {
						addInteriorWrite(cv, vv, deep)
					}
				}
			}
			scanValue(op.ChanVal)
			scanValue(op.SendVal)

		case OpReturn:
			for _, r := range op.Results {
				scanValue(r)
			}

		case OpDefer:
			scanValue(op.Call)

		case OpGo:
			if descendNested {
				scanValue(op.Call)
			}

		case OpExpr:
			scanValue(op.Expr)
		}
	}

	scanBody = func(b *Body) {
		if b == nil {
			return
		}
		for i := range b.Ops {
			scanOp(&b.Ops[i])
		}
	}

	scanBody(body)

	reachFrom := func(g map[*types.Var]map[*types.Var]bool, start *types.Var) map[*types.Var]bool {
		vis := map[*types.Var]bool{start: true}
		q := []*types.Var{start}
		for len(q) > 0 {
			cur := q[len(q)-1]
			q = q[:len(q)-1]
			for nx := range g[cur] {
				if !vis[nx] {
					vis[nx] = true
					q = append(q, nx)
				}
			}
		}
		return vis
	}

	for changed := true; changed; {
		changed = false
		if len(bareBinds) > 0 || len(interiorWrites) > 0 {
			allReach := make(map[*types.Var]map[*types.Var]bool, len(allVars))
			viewReach := make(map[*types.Var]map[*types.Var]bool, len(allVars))
			for _, u := range allVars {
				allReach[u] = reachFrom(allFwd, u)
				viewReach[u] = reachFrom(viewFwd, u)
			}
			for _, bb := range bareBinds {
				for _, u := range allVars {
					if allReach[u][bb.src] {
						if addFwd(viewFwd, u, bb.dst) {
							changed = true
						}
						if addFwd(allFwd, u, bb.dst) {
							changed = true
						}
					}
				}
			}
			for _, iw := range interiorWrites {
				anc := viewReach
				if iw.deepNested {
					anc = allReach
				}
				for _, u := range allVars {
					if anc[u][iw.target] {
						if addFwd(allFwd, iw.src, u) {
							changed = true
						}
					}
				}
			}
		}
	}

	for _, u := range allVars {
		desc := reachFrom(allFwd, u)
		if len(desc) <= 1 {
			continue
		}
		group := make([]*types.Var, 0, len(desc))
		for v := range desc {
			group = append(group, v)
		}
		for i := 0; i < len(group); i++ {
			a := group[i]
			for j := i + 1; j < len(group); j++ {
				b := group[j]
				if adj[a] == nil {
					adj[a] = map[types.Object]bool{}
				}
				if adj[b] == nil {
					adj[b] = map[types.Object]bool{}
				}
				adj[a][b] = true
				adj[b][a] = true
			}
		}
	}
	return adj
}
