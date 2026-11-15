package flowir

import (
	"go/ast"
	"go/types"
)

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
	addEdge := func(a, b *types.Var) {
		if !eligibleVar(a) || !eligibleVar(b) || a == b {
			return
		}
		if adj[a] == nil {
			adj[a] = map[types.Object]bool{}
		}
		if adj[b] == nil {
			adj[b] = map[types.Object]bool{}
		}
		adj[a][b] = true
		adj[b][a] = true
	}

	var collectPlaceAddrVars func(p Place, out []*types.Var) []*types.Var
	var collectValueSources func(v *Value, out []*types.Var) []*types.Var

	collectPlaceAddrVars = func(p Place, out []*types.Var) []*types.Var {
		if p.Obj != nil && eligibleVar(p.Obj) {
			out = append(out, p.Obj)
			return out
		}
		if p.Root == RootTransient && p.Base != nil {
			return collectValueSources(p.Base, out)
		}
		return out
	}

	collectValueSources = func(v *Value, out []*types.Var) []*types.Var {
		if v == nil {
			return out
		}
		if v.Kind == ValCall && v.CallAST != nil && exemptCalls[v.CallAST] {
			return out
		}
		if v.Type != nil && !sharesMem(v.Type) {
			return out
		}
		switch v.Kind {
		case ValPlace:
			if v.Place.Obj != nil {
				if eligibleVar(v.Place.Obj) && (v.Place.Obj.Type() == nil || sharesMem(v.Place.Obj.Type())) {
					out = append(out, v.Place.Obj)
				}
			} else if v.Place.Root == RootTransient && v.Place.Base != nil {
				out = collectValueSources(v.Place.Base, out)
			}
			// Index keys and slice bounds are scalar indices and do not supply
			// the projected value's backing storage.
			return out

		case ValAddrOf:
			return collectPlaceAddrVars(v.AddrPlace, out)

		case ValMethodVal:
			if v.AutoAddr && v.HasRecvPlace {
				out = collectPlaceAddrVars(v.RecvPlace, out)
			}
			return collectValueSources(v.Recv, out)

		case ValAllocFresh:
			switch v.AllocKind {
			case AllocMake, AllocBuiltinNewType:
				return out
			case AllocBuiltinNewExpr:
				for _, a := range v.Args {
					out = collectValueSources(a, out)
				}
				return out
			case AllocCompositeLit:
				for i := range v.CompositeElts {
					elt := &v.CompositeElts[i]
					if elt.MapKey != nil {
						out = collectValueSources(elt.MapKey, out)
					}
					if elt.Value != nil {
						out = collectValueSources(elt.Value, out)
					}
				}
				return out
			}

		case ValMakeClosure:
			if descendNested && v.Closure != nil {
				for fv := range v.Closure.FreeVars {
					if eligibleVar(fv) {
						out = append(out, fv)
					}
				}
			}
			return out

		case ValCall:
			if v.CallKind == CallIIFE && v.IIFE != nil {
				for fv := range v.IIFE.FreeVars {
					if eligibleVar(fv) {
						out = append(out, fv)
					}
				}
				v.IIFE.ForEachSyncOp(func(op *Op) bool {
					if op.Kind == OpReturn {
						if op.IsNaked {
							for _, rv := range v.IIFE.Results {
								if eligibleVar(rv) && (rv.Type() == nil || sharesMem(rv.Type())) {
									out = append(out, rv)
								}
							}
						} else {
							for _, r := range op.Results {
								out = collectValueSources(r, out)
							}
						}
					}
					return true
				})
			}
			if v.AutoAddrRecv && v.HasRecvPlace {
				out = collectPlaceAddrVars(v.RecvPlace, out)
			}
			out = collectValueSources(v.Recv, out)
			out = collectValueSources(v.Callee, out)
			for _, a := range v.Args {
				out = collectValueSources(a, out)
			}
			return out

		case ValConvert:
			return collectValueSources(v.Arg, out)

		case ValChanRecv:
			return collectValueSources(v.Chan, out)

		case ValCompositeExpr:
			for _, a := range v.Args {
				out = collectValueSources(a, out)
			}
			return out
		}
		return out
	}

	linkDstToValue := func(dst Place, val *Value) {
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
		for _, dv := range dstVars {
			for _, sv := range srcVars {
				addEdge(dv, sv)
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
						for _, dv := range dstVars {
							for _, sv := range srcVars {
								addEdge(dv, sv)
							}
						}
					}
				case "append":
					if len(v.Args) >= 2 && (v.Args[0].Type == nil || sharesMem(v.Args[0].Type)) {
						dstVars := collectValueSources(v.Args[0], nil)
						for _, elem := range v.Args[1:] {
							srcVars := collectValueSources(elem, nil)
							for _, dv := range dstVars {
								for _, sv := range srcVars {
									addEdge(dv, sv)
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
						addEdge(participants[i], participants[j])
					}
				}
			}
			if v.CallKind == CallIIFE && v.IIFE != nil {
				if len(v.Args) > 0 && len(v.IIFE.Params) > 0 {
					v.ForEachArgParam(func(arg *Value, slotType types.Type, _ int, pIdx int, ok bool, _ bool) bool {
						if !ok || pIdx >= len(v.IIFE.Params) || v.IIFE.Params[pIdx] == nil {
							return true
						}
						if slotType != nil && !sharesMem(slotType) {
							return true
						}
						pv := v.IIFE.Params[pIdx]
						if pv.Type() == nil || sharesMem(pv.Type()) {
							for _, sv := range collectValueSources(arg, nil) {
								addEdge(pv, sv)
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
			op.ForEachAssignPair(func(_ int, dst Place, _ bool, src *Value) bool {
				linkDstToValue(dst, src)
				if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && keyVal != nil {
					if keyVal.Type == nil || sharesMem(keyVal.Type) {
						mapVars := collectPlaceAddrVars(mapPlace, nil)
						keyVars := collectValueSources(keyVal, nil)
						for _, mv := range mapVars {
							for _, kv := range keyVars {
								addEdge(mv, kv)
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
			for _, src := range op.Srcs {
				scanValue(src)
			}
			if op.AssignKind == AssignRange && op.RangeBody != nil {
				scanBody(op.RangeBody)
			}

		case OpTypeSwitchBind:
			if op.SwitchDst != nil && op.SwitchSrc != nil && eligibleVar(op.SwitchDst) &&
				(op.SwitchDst.Type() == nil || sharesMem(op.SwitchDst.Type())) {
				for _, sv := range collectValueSources(op.SwitchSrc, nil) {
					addEdge(op.SwitchDst, sv)
				}
			}
			scanValue(op.SwitchSrc)

		case OpChanSend:
			if op.SendVal != nil && (op.SendVal.Type == nil || sharesMem(op.SendVal.Type)) {
				chanVars := collectPlaceAddrVars(op.ChanPlace, nil)
				valVars := collectValueSources(op.SendVal, nil)
				for _, cv := range chanVars {
					for _, vv := range valVars {
						addEdge(cv, vv)
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
	return adj
}
