package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyMapperActiveMethodBodyFlowIR(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	outerNamed, baseNamed *types.Named,
	mutexField, activeField *types.Var,
	callableFields map[*types.Var]*types.Signature,
) bool {
	b := fc.funcBody(p, fd)
	if b == nil || b.Recv == nil {
		return false
	}
	recvVar := b.Recv
	ptr, ok := types.Unalias(recvVar.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	recvElem := types.Unalias(ptr.Elem())
	if !types.Identical(recvElem, outerNamed) && (baseNamed == nil || !types.Identical(recvElem, baseNamed)) {
		return false
	}
	// Reject reassigning recvVar or taking &recvVar anywhere in b.
	if mapperBodyReassignsOrAddrsRecv(b, recvVar) {
		return false
	}

	regions, ok := refconfine.VerifyBodyLockRegions(p, idx, b, refconfine.LockTarget{
		Kind:      refconfine.LockRecvField,
		RecvVar:   recvVar,
		LockField: mutexField,
		IsRWMutex: false,
	})
	if !ok || regions == nil || len(regions.IsLockTransitionOp) == 0 {
		return false
	}

	syscallAddrs := collectMapperSyscallAddrVarsFlowIR(b, recvVar, callableFields)
	mappedSlices, mappedKeys := collectMapperSliceAndKeyVarsFlowIR(b, syscallAddrs)

	// Verify zero closures/goroutines, at least one synchronous kernel-syscall
	// callableField invocation and activeField mutation, and that every activeField
	// mention occurs synchronously under WriteLocked dominance in one of the three
	// allowed map forms.
	totalActiveMentions := countFieldMentionsInBody(b, activeField)
	validActiveMentions := 0
	sawSyscallCall := false
	sawActiveMutation := false
	validBody := true

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if !validBody {
			return false
		}
		mode, hasMode := regions.OpModes[op]
		if !hasMode {
			validBody = false
			return false
		}
		if op.Kind == flowir.OpGo {
			validBody = false
			return false
		}

		// Forbid closures, IIFEs, and &m.active[...] anywhere in b.
		op.ForEachValue(func(v *flowir.Value) bool {
			if v == nil {
				return true
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				switch cur.Kind {
				case flowir.ValMakeClosure:
					validBody = false
					return false
				case flowir.ValCall:
					if cur.CallKind == flowir.CallIIFE {
						validBody = false
						return false
					}
					if op.Kind != flowir.OpDefer && cur.CallKind == flowir.CallIndirect &&
						cur.Callee != nil && cur.Callee.Kind == flowir.ValPlace &&
						cur.Callee.Place.Obj == recvVar && len(cur.Callee.Place.Projs) == 1 &&
						cur.Callee.Place.Projs[0].Kind == flowir.ProjField &&
						callableFields[cur.Callee.Place.Projs[0].Field] != nil {
						sawSyscallCall = true
					}
					// Builtin delete(m.active, keyVar)
					if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "delete" &&
						len(cur.Args) == 2 && !cur.Ellipsis &&
						isRecvActiveFieldVal(cur.Args[0], recvVar, activeField) {
						if !mode.IsWriteLocked() || cur.Args[1] == nil || cur.Args[1].Kind != flowir.ValPlace ||
							!cur.Args[1].Place.IsBareVar() || mappedKeys[cur.Args[1].Place.Obj] == nil {
							validBody = false
							return false
						}
						sawActiveMutation = true
						validActiveMentions++
					}
				case flowir.ValAddrOf:
					if placeMentionsField(cur.AddrPlace, activeField) {
						validBody = false
						return false
					}
				case flowir.ValPlace:
					// Map index read: m.active[keyVar]
					if isRecvActiveIndexedPlace(cur.Place, recvVar, activeField, mappedKeys) {
						if !mode.IsWriteLocked() {
							validBody = false
							return false
						}
						validActiveMentions++
					}
				}
				return validBody
			})
			return validBody
		})
		if !validBody {
			return false
		}

		// Map store: m.active[keyVar] = valVar
		if op.Kind == flowir.OpAssign {
			for di, dst := range op.Dsts {
				if !placeMentionsField(dst, activeField) {
					continue
				}
				if op.AssignKind != flowir.AssignPlain || len(op.Dsts) != 1 || len(op.Srcs) != 1 || di != 0 ||
					!mode.IsWriteLocked() || !isRecvActiveIndexedPlace(dst, recvVar, activeField, mappedKeys) {
					validBody = false
					return false
				}
				keyVar := dst.Projs[len(dst.Projs)-1].Key.Place.Obj
				src := op.Srcs[0]
				if src == nil || src.Kind != flowir.ValPlace || !src.Place.IsBareVar() ||
					!mappedSlices[src.Place.Obj] || mappedKeys[keyVar] != src.Place.Obj {
					validBody = false
					return false
				}
				sawActiveMutation = true
				validActiveMentions++
			}
		}
		return validBody
	})

	return validBody && sawSyscallCall && sawActiveMutation && validActiveMentions == totalActiveMentions
}

func mapperBodyReassignsOrAddrsRecv(b *flowir.Body, recvVar *types.Var) bool {
	hit := false
	flowir.VisitAllOps(b, func(op *flowir.Op) {
		if hit {
			return
		}
		if op.Kind == flowir.OpAssign {
			for _, dst := range op.Dsts {
				if dst.IsBareVar() && dst.Obj == recvVar {
					hit = true
					return
				}
			}
		}
		op.ForEachValue(func(v *flowir.Value) bool {
			if v == nil {
				return true
			}
			v.WalkValues(func(cv *flowir.Value) bool {
				if cv.Kind == flowir.ValAddrOf && cv.AddrPlace.IsBareVar() && cv.AddrPlace.Obj == recvVar {
					hit = true
					return false
				}
				return true
			})
			return !hit
		})
	})
	return hit
}

func isRecvActiveFieldPlace(pl flowir.Place, recvVar, activeField *types.Var) bool {
	return pl.Obj == recvVar && len(pl.Projs) == 1 &&
		pl.Projs[0].Kind == flowir.ProjField && pl.Projs[0].Field == activeField
}

func isRecvActiveFieldVal(v *flowir.Value, recvVar, activeField *types.Var) bool {
	return v != nil && v.Kind == flowir.ValPlace && isRecvActiveFieldPlace(v.Place, recvVar, activeField)
}

func isRecvActiveIndexedPlace(pl flowir.Place, recvVar, activeField *types.Var, mappedKeys map[*types.Var]*types.Var) bool {
	if pl.Obj != recvVar || len(pl.Projs) != 2 {
		return false
	}
	if pl.Projs[0].Kind != flowir.ProjField || pl.Projs[0].Field != activeField ||
		pl.Projs[1].Kind != flowir.ProjIndex || pl.Projs[1].Key == nil {
		return false
	}
	kv := pl.Projs[1].Key
	return kv.Kind == flowir.ValPlace && kv.Place.IsBareVar() && mappedKeys[kv.Place.Obj] != nil
}

func placeMentionsField(pl flowir.Place, target *types.Var) bool {
	for _, pr := range pl.Projs {
		if pr.Kind == flowir.ProjField && pr.Field == target {
			return true
		}
	}
	return false
}

func countFieldMentionsInBody(b *flowir.Body, target *types.Var) int {
	n := 0
	flowir.VisitAllOps(b, func(op *flowir.Op) {
		if op.Kind == flowir.OpAssign {
			for _, dst := range op.Dsts {
				for _, pr := range dst.Projs {
					if pr.Kind == flowir.ProjField && pr.Field == target {
						n++
					}
				}
			}
		}
		op.ForEachValue(func(v *flowir.Value) bool {
			if v == nil {
				return true
			}
			v.WalkValues(func(cv *flowir.Value) bool {
				switch cv.Kind {
				case flowir.ValPlace:
					for _, pr := range cv.Place.Projs {
						if pr.Kind == flowir.ProjField && pr.Field == target {
							n++
						}
					}
				case flowir.ValAddrOf:
					for _, pr := range cv.AddrPlace.Projs {
						if pr.Kind == flowir.ProjField && pr.Field == target {
							n++
						}
					}
				}
				return true
			})
			return true
		})
	})
	return n
}

func collectMapperSyscallAddrVarsFlowIR(
	b *flowir.Body,
	recvVar *types.Var,
	callableFields map[*types.Var]*types.Signature,
) map[*types.Var]bool {
	addrs := map[*types.Var]bool{}
	dirty := map[*types.Var]bool{}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign {
			return true
		}
		if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Srcs[0] != nil {
			call := op.Srcs[0]
			if call.Kind == flowir.ValCall && call.CallKind == flowir.CallIndirect &&
				call.Callee != nil && call.Callee.Kind == flowir.ValPlace &&
				call.Callee.Place.Obj == recvVar && len(call.Callee.Place.Projs) == 1 &&
				call.Callee.Place.Projs[0].Kind == flowir.ProjField &&
				callableFields[call.Callee.Place.Projs[0].Field] != nil {
				if op.Dsts[0].IsBareVar() && op.Dsts[0].Root == flowir.RootLocal && op.Dsts[0].Obj != nil {
					if addrs[op.Dsts[0].Obj] {
						dirty[op.Dsts[0].Obj] = true
					} else {
						addrs[op.Dsts[0].Obj] = true
					}
					if op.Dsts[1].IsBareVar() && op.Dsts[1].Obj != nil {
						dirty[op.Dsts[1].Obj] = true
					}
					return true
				}
			}
		}
		for _, dst := range op.Dsts {
			if dst.Obj != nil && op.AssignKind != flowir.AssignZeroDecl {
				dirty[dst.Obj] = true
			}
		}
		return true
	})
	for v := range dirty {
		delete(addrs, v)
	}
	return addrs
}

func collectMapperSliceAndKeyVarsFlowIR(b *flowir.Body, syscallAddrs map[*types.Var]bool) (map[*types.Var]bool, map[*types.Var]*types.Var) {
	slices := map[*types.Var]bool{}
	keys := map[*types.Var]*types.Var{}
	hdrAlias := map[*types.Var]*types.Var{}
	hdrDataCand := map[*types.Var]bool{}
	hdrDataWrites := map[*types.Var]int{}
	hdrBadFieldWrite := map[*types.Var]bool{}
	zeroDeclVars := map[*types.Var]bool{}
	writes := map[*types.Var]int{}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign {
			return true
		}
		if op.AssignKind == flowir.AssignZeroDecl {
			for _, dst := range op.Dsts {
				if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
					zeroDeclVars[dst.Obj] = true
				}
			}
			return true
		}
		for i, dst := range op.Dsts {
			if dst.IsBareVar() && dst.Obj != nil {
				writes[dst.Obj]++
				if op.AssignKind == flowir.AssignPlain && i < len(op.Srcs) && op.Srcs[i] != nil {
					rhs := op.Srcs[i]
					if isUnsafeSliceFromAddrFlowIR(rhs, syscallAddrs) {
						slices[dst.Obj] = true
					}
					if op.TopLevelInBody {
						if target := isUnsafeSliceHdrCastFlowIR(rhs); target != nil {
							hdrAlias[dst.Obj] = target
						}
					}
					if slVar := isByteSliceElemAddrFlowIR(rhs); slVar != nil {
						keys[dst.Obj] = slVar
					}
				}
			}
			// Legacy pre-unsafe.Slice pattern: var b []byte; hdr := (*SliceHeader)(unsafe.Pointer(&b)); hdr.Data = unsafe.Pointer(addr)
			if dst.Obj != nil && hdrAlias[dst.Obj] != nil && !dst.IsBareVar() {
				if op.AssignKind == flowir.AssignPlain && i < len(op.Srcs) && op.Srcs[i] != nil &&
					len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && dst.Projs[0].Field != nil {
					switch dst.Projs[0].Field.Name() {
					case "Data":
						hdrDataWrites[dst.Obj]++
						if op.TopLevelInBody && isUnsafePointerOfAddrFlowIR(op.Srcs[i], syscallAddrs) {
							hdrDataCand[dst.Obj] = true
						}
					case "Len", "Cap":
					default:
						hdrBadFieldWrite[dst.Obj] = true
					}
				} else {
					hdrBadFieldWrite[dst.Obj] = true
				}
			}
		}
		return true
	})
	for hdrVar, target := range hdrAlias {
		if hdrDataCand[hdrVar] && hdrDataWrites[hdrVar] == 1 && !hdrBadFieldWrite[hdrVar] &&
			writes[hdrVar] == 1 && zeroDeclVars[target] && writes[target] == 0 {
			slices[target] = true
		}
	}
	for v, c := range writes {
		if c > 1 {
			delete(slices, v)
			delete(keys, v)
		}
	}
	return slices, keys
}

func isUnsafeSliceFromAddrFlowIR(v *flowir.Value, syscallAddrs map[*types.Var]bool) bool {
	if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallBuiltin ||
		v.BuiltinName != "Slice" || len(v.Args) != 2 || v.Ellipsis || v.Args[0] == nil {
		return false
	}
	arg0 := v.Args[0]
	if arg0.Kind != flowir.ValConvert || arg0.IsTypeAssert || arg0.Arg == nil {
		return false
	}
	return isUnsafePointerOfAddrFlowIR(arg0.Arg, syscallAddrs)
}

func isUnsafePointerOfAddrFlowIR(v *flowir.Value, syscallAddrs map[*types.Var]bool) bool {
	if v == nil || v.Kind != flowir.ValConvert || v.IsTypeAssert || !syntaxutil.IsUnsafePointerType(v.Type) || v.Arg == nil {
		return false
	}
	return v.Arg.Kind == flowir.ValPlace && v.Arg.Place.IsBareVar() && syscallAddrs[v.Arg.Place.Obj]
}

func isUnsafeSliceHdrCastFlowIR(v *flowir.Value) *types.Var {
	if v == nil || v.Kind != flowir.ValConvert || v.IsTypeAssert || v.Arg == nil {
		return nil
	}
	up := v.Arg
	if up.Kind != flowir.ValConvert || up.IsTypeAssert || !syntaxutil.IsUnsafePointerType(up.Type) || up.Arg == nil {
		return nil
	}
	addr := up.Arg
	if addr.Kind != flowir.ValAddrOf || addr.IsArraySlice || !addr.AddrPlace.IsBareVar() || !addr.AddrPlace.IsLocalRoot() {
		return nil
	}
	return addr.AddrPlace.Obj
}

func isByteSliceElemAddrFlowIR(v *flowir.Value) *types.Var {
	if v == nil || v.Kind != flowir.ValAddrOf || v.IsArraySlice || !v.AddrPlace.IsLocalRoot() ||
		v.AddrPlace.Obj == nil || len(v.AddrPlace.Projs) != 1 || v.AddrPlace.Projs[0].Kind != flowir.ProjIndex {
		return nil
	}
	return v.AddrPlace.Obj
}

func pkgHasStructDerefWriteFlowIR(p *packages.Package, fc *pkgFlowCache, targets ...*types.Named) bool {
	if fc == nil || fc.base == nil {
		return false
	}
	matchPtr := func(t types.Type) bool {
		st := syntaxutil.DerefNamedStruct(t)
		if st == nil {
			return false
		}
		for _, want := range targets {
			if want != nil && types.Identical(st, want) {
				return true
			}
		}
		return false
	}
	hit := false
	scanBody := func(b *flowir.Body) {
		if hit {
			return
		}
		flowir.VisitAllOps(b, func(op *flowir.Op) {
			if hit || op.Kind != flowir.OpAssign {
				return
			}
			for _, dst := range op.Dsts {
				if len(dst.Projs) > 0 && dst.Projs[len(dst.Projs)-1].Kind == flowir.ProjDeref &&
					matchPtr(dst.Projs[len(dst.Projs)-1].BaseType) {
					hit = true
					return
				}
			}
		})
	}
	for _, gd := range fc.base.GenDecls {
		scanBody(fc.body(p, gd))
	}
	for _, fd := range fc.base.FuncDecls {
		scanBody(fc.funcBody(p, fd))
	}
	return hit
}

func isBytePtrByteSliceMap(t types.Type) bool {
	m, ok := types.Unalias(t).Underlying().(*types.Map)
	if !ok {
		return false
	}
	kp, ok := types.Unalias(m.Key()).(*types.Pointer)
	if !ok {
		return false
	}
	kb, ok := types.Unalias(kp.Elem()).Underlying().(*types.Basic)
	if !ok || kb.Kind() != types.Byte {
		return false
	}
	vs, ok := types.Unalias(m.Elem()).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	vb, ok := types.Unalias(vs.Elem()).Underlying().(*types.Basic)
	return ok && vb.Kind() == types.Byte
}
