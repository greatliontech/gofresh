package freshalloc

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// TypeCanCarryExtractedObject reports whether root can carry a pointer,
// reference, channel, function, interface, uintptr, or unsafe.Pointer value.
func TypeCanCarryExtractedObject(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				hit = true
			}
		case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
			hit = true
		case *types.Array:
			if u.Len() > 0 {
				walk(u.Elem())
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

// IsRuntimeInterfaceType reports whether t is a concrete (non-type-parameter)
// interface type.
func IsRuntimeInterfaceType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return false
	}
	return types.IsInterface(t)
}

// isScalarElemSliceOrMap reports whether t is a concrete slice or map whose
// elements (and keys, for maps) carry no extracted object references.
func isScalarElemSliceOrMap(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Slice:
		return !TypeCanCarryExtractedObject(u.Elem())
	case *types.Map:
		return !TypeCanCarryExtractedObject(u.Key()) && !TypeCanCarryExtractedObject(u.Elem())
	default:
		return false
	}
}

// HasTupleFirstArg reports whether v is a single-argument non-variadic call
// forwarding a multi-value tuple return.
func HasTupleFirstArg(v *flowir.Value) bool {
	if v == nil || len(v.Args) != 1 || v.Ellipsis || v.Args[0] == nil || v.Args[0].Type == nil {
		return false
	}
	_, isTuple := types.Unalias(v.Args[0].Type).(*types.Tuple)
	return isTuple
}

// CollectEscapedIntraPkgFuncs returns intra-package functions referenced in p
// outside direct non-MethodExpr call positions.
func CollectEscapedIntraPkgFuncs(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Func]bool {
	escaped := map[*types.Func]bool{}
	if p == nil || p.TypesInfo == nil || idx == nil {
		return escaped
	}
	for uid, obj := range p.TypesInfo.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || fn == nil || fn.Pkg() != p.Types {
			continue
		}
		parent := idx.ParentUnparen(uid)
		if call, isCall := parent.(*ast.CallExpr); isCall && ast.Unparen(call.Fun) == uid {
			continue
		}
		if sel, isSel := parent.(*ast.SelectorExpr); isSel && sel.Sel == uid {
			if call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr); isCall && ast.Unparen(call.Fun) == sel {
				if sInfo := p.TypesInfo.Selections[sel]; sInfo == nil || sInfo.Kind() != types.MethodExpr {
					continue
				}
			}
		}
		escaped[fn.Origin()] = true
	}
	return escaped
}

// RecordNamedStructsInto records every origin *types.Named struct reachable
// from t into dst.
func RecordNamedStructsInto(t types.Type, dst map[*types.Named]bool, seen map[types.Type]bool) {
	if t == nil {
		return
	}
	t = types.Unalias(t)
	if seen[t] {
		return
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			dst[named.Origin()] = true
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		RecordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Slice:
		RecordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Array:
		RecordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Chan:
		RecordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Map:
		RecordNamedStructsInto(u.Key(), dst, seen)
		RecordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			RecordNamedStructsInto(u.Field(i).Type(), dst, seen)
		}
	case *types.Signature:
		for i := 0; i < u.Params().Len(); i++ {
			RecordNamedStructsInto(u.Params().At(i).Type(), dst, seen)
		}
		for i := 0; i < u.Results().Len(); i++ {
			RecordNamedStructsInto(u.Results().At(i).Type(), dst, seen)
		}
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			RecordNamedStructsInto(u.At(i).Type(), dst, seen)
		}
	}
}

// CollectUnexportedStructCandFields returns non-address-taken, non-embedded
// unexported fields matching keepType on non-generic, non-converted unexported
// structs declared in p.Types.
func CollectUnexportedStructCandFields(
	p *packages.Package,
	addrFields map[*types.Var]bool,
	convertedStructs map[*types.Named]bool,
	keepType func(types.Type) bool,
) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.Types == nil || keepType == nil {
		return out
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.Exported() || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named == nil || named.TypeParams() != nil || convertedStructs[named] {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			fld := st.Field(i)
			if fld != nil && !fld.Exported() && !fld.Embedded() && !addrFields[fld] && keepType(fld.Type()) {
				out[fld] = true
			}
		}
	}
	return out
}

func collectNonCandParamAndResultVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
) (excludedFresh map[*types.Var]bool, excludedIface map[*types.Var]bool, candFreshFuncs map[*types.Func]bool, candIfaceFuncs map[*types.Func]bool) {
	excludedFresh = map[*types.Var]bool{}
	excludedIface = map[*types.Var]bool{}
	candFreshFuncs = map[*types.Func]bool{}
	candIfaceFuncs = map[*types.Func]bool{}
	if p == nil || p.TypesInfo == nil || idx == nil {
		return excludedFresh, excludedIface, candFreshFuncs, candIfaceFuncs
	}
	escapedFuncs := CollectEscapedIntraPkgFuncs(p, idx)
	excludeInto := func(dst map[*types.Var]bool, fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			for _, nm := range fld.Names {
				if v, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && v != nil {
					dst[v] = true
				}
			}
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch fnNode := n.(type) {
			case *ast.FuncDecl:
				excludeInto(excludedFresh, fnNode.Recv)
				excludeInto(excludedIface, fnNode.Recv)
				if fnNode.Type != nil {
					excludeInto(excludedFresh, fnNode.Type.Results)
					excludeInto(excludedIface, fnNode.Type.Results)
					var fnObj *types.Func
					if fnNode.Name != nil {
						fnObj, _ = p.TypesInfo.Defs[fnNode.Name].(*types.Func)
					}
					nonGenericFree := fnNode.Recv == nil &&
						(fnNode.Type.TypeParams == nil || len(fnNode.Type.TypeParams.List) == 0) &&
						fnObj != nil && fnNode.Body != nil && !escapedFuncs[fnObj.Origin()]
					if nonGenericFree {
						if sig, okS := fnObj.Type().(*types.Signature); !okS || sig.Recv() != nil || sig.TypeParams().Len() > 0 {
							nonGenericFree = false
						}
					}
					if nonGenericFree && !fnObj.Exported() {
						candFreshFuncs[fnObj.Origin()] = true
					} else {
						excludeInto(excludedFresh, fnNode.Type.Params)
					}
					if nonGenericFree {
						candIfaceFuncs[fnObj.Origin()] = true
					} else {
						excludeInto(excludedIface, fnNode.Type.Params)
					}
				}
			case *ast.FuncLit:
				if fnNode.Type != nil {
					excludeInto(excludedFresh, fnNode.Type.Params)
					excludeInto(excludedFresh, fnNode.Type.Results)
					excludeInto(excludedIface, fnNode.Type.Params)
					excludeInto(excludedIface, fnNode.Type.Results)
				}
			}
			return true
		})
	}
	return excludedFresh, excludedIface, candFreshFuncs, candIfaceFuncs
}

// OwnedContainerSummary holds the FlowIR greatest fixed point of fresh-owned
// scalar-element containers and caller-supplied interface variables across a
// package.
type OwnedContainerSummary struct {
	FreshVars            map[*types.Var]bool
	FreshFields          map[*types.Var]bool
	IsFreshOwnedVal      func(*flowir.Value) bool
	IsCallerSafeIfaceVal func(*flowir.Value) bool
}

// ComputeFreshOwnedContainers computes the mutual greatest fixed point over fc
// of fresh-owned scalar-element local variables, unexported struct fields, and
// caller-supplied interface variables.
func ComputeFreshOwnedContainers(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fc *flowir.PkgCache,
	isTrueStdPkg func(*types.Package) bool,
) OwnedContainerSummary {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || fc == nil || fc.Info == nil {
		return OwnedContainerSummary{
			FreshVars:            map[*types.Var]bool{},
			FreshFields:          map[*types.Var]bool{},
			IsFreshOwnedVal:      func(*flowir.Value) bool { return false },
			IsCallerSafeIfaceVal: func(*flowir.Value) bool { return false },
		}
	}
	excludedFreshVars, excludedIfaceVars, candFreshParamFuncs, candIfaceParamFuncs := collectNonCandParamAndResultVars(p, idx)
	addrVars := map[*types.Var]bool{}
	typeSwitchVars := map[*types.Var]bool{}
	addrFields := map[*types.Var]bool{}
	convertedStructs := map[*types.Named]bool{}

	recordAddrPlace := func(pl flowir.Place) {
		if pl.Obj != nil {
			addrVars[pl.Obj] = true
		}
		if len(pl.Projs) > 0 {
			last := pl.Projs[len(pl.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil {
				addrFields[last.Field] = true
			}
		}
	}
	fc.ForEachOp(func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		if op.Kind == flowir.OpTypeSwitchBind && op.SwitchDst != nil {
			typeSwitchVars[op.SwitchDst] = true
		}
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValAddrOf:
					recordAddrPlace(v.AddrPlace)
				case flowir.ValMethodVal:
					if v.AutoAddr && v.HasRecvPlace {
						recordAddrPlace(v.RecvPlace)
					}
				case flowir.ValCall:
					if v.AutoAddrRecv && v.HasRecvPlace {
						recordAddrPlace(v.RecvPlace)
					}
				case flowir.ValConvert:
					if !v.IsTypeAssert && v.Type != nil && v.Arg != nil && v.Arg.Type != nil &&
						!types.Identical(v.Type, v.Arg.Type) {
						seen := map[types.Type]bool{}
						RecordNamedStructsInto(v.Type, convertedStructs, seen)
						RecordNamedStructsInto(v.Arg.Type, convertedStructs, seen)
					}
				}
				return true
			})
			return true
		})
		return true
	})

	freshVars := map[*types.Var]bool{}
	callerSafeIfaceVars := map[*types.Var]bool{}
	for _, obj := range p.TypesInfo.Defs {
		lv, ok := obj.(*types.Var)
		if !ok || lv == nil || lv.IsField() || lv.Pkg() != p.Types || lv.Parent() == p.Types.Scope() || addrVars[lv] {
			continue
		}
		if !excludedFreshVars[lv] && !typeSwitchVars[lv] && isScalarElemSliceOrMap(lv.Type()) {
			freshVars[lv] = true
		}
		if !excludedIfaceVars[lv] && IsRuntimeInterfaceType(lv.Type()) {
			callerSafeIfaceVars[lv] = true
		}
	}

	freshFields := CollectUnexportedStructCandFields(p, addrFields, convertedStructs, isScalarElemSliceOrMap)

	var isFreshOwnedVal func(val *flowir.Value) bool
	isFreshOwnedVal = func(val *flowir.Value) bool {
		if val == nil || val.Type == nil {
			return false
		}
		if val.IsNil || (val.Raw != nil && syntaxutil.IsTypedNilSliceConv(p, val.Raw)) {
			return true
		}
		switch val.Kind {
		case flowir.ValAllocFresh:
			switch val.AllocKind {
			case flowir.AllocMake, flowir.AllocBuiltinNewType, flowir.AllocCompositeLit:
				return isScalarElemSliceOrMap(val.Type)
			}
		case flowir.ValConvert:
			if !val.IsTypeAssert && val.Arg != nil && val.Arg.Type != nil && isScalarElemSliceOrMap(val.Type) {
				if b, isB := syntaxutil.UnderlyingType(val.Arg.Type).(*types.Basic); isB && (b.Info()&types.IsString) != 0 {
					return true
				}
			}
		case flowir.ValPlace:
			pl := val.Place
			if pl.IsBareVar() {
				return freshVars[pl.Obj]
			}
			if len(pl.Projs) == 1 {
				switch pl.Projs[0].Kind {
				case flowir.ProjField:
					return pl.Projs[0].Field != nil && freshFields[pl.Projs[0].Field]
				case flowir.ProjSlice:
					return pl.Obj != nil && freshVars[pl.Obj]
				}
			}
		case flowir.ValCall:
			if val.CallKind == flowir.CallBuiltin && val.BuiltinName == "append" && !HasTupleFirstArg(val) && len(val.Args) >= 1 {
				return isFreshOwnedVal(val.Args[0])
			}
			if val.CallKind == flowir.CallPlain && !val.IsMethodExprCall && val.CalleeFunc != nil &&
				isTrueStdPkg != nil && isTrueStdPkg(val.CalleeFunc.Pkg()) && isScalarElemSliceOrMap(val.Type) {
				pkgPath := val.CalleeFunc.Pkg().Path()
				fnName := val.CalleeFunc.Origin().Name()
				if pkgPath == "fmt" && (fnName == "Append" || fnName == "Appendf" || fnName == "Appendln") {
					return !HasTupleFirstArg(val) && len(val.Args) >= 1 && isFreshOwnedVal(val.Args[0])
				}
				traits := auditset.DeterministicStdCallTraits(pkgPath, fnName)
				if (traits.ValuePlaneClone || traits.ReadOnlySliceCopy || traits.PureScalarOrValue) && !traits.InPlaceContainerMutate {
					allSafe := true
					for _, arg := range val.Args {
						if arg == nil || (TypeCanCarryExtractedObject(arg.Type) && !isFreshOwnedVal(arg)) {
							allSafe = false
							break
						}
					}
					return allSafe
				}
			}
		}
		return false
	}

	var isCallerSafeIfaceVal func(val *flowir.Value) bool
	isCallerSafeIfaceVal = func(val *flowir.Value) bool {
		if val == nil || !IsRuntimeInterfaceType(val.Type) {
			return false
		}
		if val.IsNil {
			return true
		}
		switch val.Kind {
		case flowir.ValPlace:
			return val.Place.IsBareVar() && callerSafeIfaceVars[val.Place.Obj]
		case flowir.ValConvert:
			return val.Arg != nil && IsRuntimeInterfaceType(val.Arg.Type) && isCallerSafeIfaceVal(val.Arg)
		default:
			return false
		}
	}

	for changed := true; changed; {
		changed = false
		fc.ForEachOp(func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
			if op.Kind == flowir.OpTypeSwitchBind && op.SwitchDst != nil && callerSafeIfaceVars[op.SwitchDst] {
				if op.SwitchSrc == nil || !isCallerSafeIfaceVal(op.SwitchSrc) {
					delete(callerSafeIfaceVars, op.SwitchDst)
					changed = true
				}
			}
			if op.Kind == flowir.OpAssign {
				for i, dst := range op.Dsts {
					if dst.Obj != nil && freshVars[dst.Obj] {
						if dst.IsBareVar() {
							okWrite := op.AssignKind == flowir.AssignZeroDecl ||
								(op.AssignKind == flowir.AssignPlain && len(op.Dsts) == len(op.Srcs) && isFreshOwnedVal(op.Srcs[i]))
							if !okWrite {
								delete(freshVars, dst.Obj)
								changed = true
							}
						} else if len(dst.Projs) != 1 || dst.Projs[0].Kind != flowir.ProjIndex {
							delete(freshVars, dst.Obj)
							changed = true
						}
					}
					if dst.Obj != nil && callerSafeIfaceVars[dst.Obj] {
						okIface := false
						if dst.IsBareVar() {
							switch {
							case op.AssignKind == flowir.AssignZeroDecl:
								okIface = true
							case op.AssignKind == flowir.AssignPlain && len(op.Dsts) == len(op.Srcs) && isCallerSafeIfaceVal(op.Srcs[i]):
								okIface = true
							case (op.AssignKind == flowir.AssignMulti || op.AssignKind == flowir.AssignPlain) &&
								len(op.Dsts) == 2 && len(op.Srcs) == 1 && i == 0 && op.Srcs[0] != nil &&
								op.Srcs[0].Kind == flowir.ValConvert && op.Srcs[0].IsTypeAssert && isCallerSafeIfaceVal(op.Srcs[0].Arg):
								okIface = true
							}
						}
						if !okIface {
							delete(callerSafeIfaceVars, dst.Obj)
							changed = true
						}
					}
					if len(dst.Projs) > 0 {
						last := dst.Projs[len(dst.Projs)-1]
						if last.Kind == flowir.ProjField && last.Field != nil && freshFields[last.Field] {
							okField := len(dst.Projs) == 1 && op.AssignKind == flowir.AssignPlain &&
								len(op.Dsts) == len(op.Srcs) && isFreshOwnedVal(op.Srcs[i])
							if !okField {
								delete(freshFields, last.Field)
								changed = true
							}
						}
					}
				}
			}
			op.ForEachValue(func(root *flowir.Value) bool {
				root.WalkValues(func(v *flowir.Value) bool {
					if v == nil {
						return false
					}
					if v.Kind == flowir.ValAllocFresh && v.AllocKind == flowir.AllocCompositeLit {
						for i := range v.CompositeElts {
							elt := &v.CompositeElts[i]
							if elt.Field != nil && freshFields[elt.Field] && !isFreshOwnedVal(elt.Value) {
								delete(freshFields, elt.Field)
								changed = true
							}
						}
					}
					if v.Kind == flowir.ValCall && v.CalleeFunc != nil {
						fnOrig := v.CalleeFunc.Origin()
						if candFreshParamFuncs[fnOrig] || candIfaceParamFuncs[fnOrig] {
							if sig, okS := fnOrig.Type().(*types.Signature); okS && sig.Params() != nil {
								tupleCall := HasTupleFirstArg(v)
								for pi := 0; pi < sig.Params().Len(); pi++ {
									pv := sig.Params().At(pi)
									if candFreshParamFuncs[fnOrig] && freshVars[pv] {
										if v.IsMethodExprCall || tupleCall {
											delete(freshVars, pv)
											changed = true
										} else if sig.Variadic() && pi == sig.Params().Len()-1 {
											if v.Ellipsis && (pi >= len(v.Args) || !isFreshOwnedVal(v.Args[pi])) {
												delete(freshVars, pv)
												changed = true
											}
										} else if pi >= len(v.Args) || !isFreshOwnedVal(v.Args[pi]) {
											delete(freshVars, pv)
											changed = true
										}
									}
									if candIfaceParamFuncs[fnOrig] && callerSafeIfaceVars[pv] {
										if v.IsMethodExprCall || tupleCall || (sig.Variadic() && pi == sig.Params().Len()-1) ||
											pi >= len(v.Args) || !isCallerSafeIfaceVal(v.Args[pi]) {
											delete(callerSafeIfaceVars, pv)
											changed = true
										}
									}
								}
							}
						}
					}
					return true
				})
				return true
			})
			return true
		})
	}
	return OwnedContainerSummary{
		FreshVars:            freshVars,
		FreshFields:          freshFields,
		IsFreshOwnedVal:      isFreshOwnedVal,
		IsCallerSafeIfaceVal: isCallerSafeIfaceVal,
	}
}
