package freshstruct

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func typeCanCarryExtractedObject(root types.Type) bool {
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

func isRuntimeInterfaceType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return false
	}
	return types.IsInterface(t)
}

func typeOrPtrHasMethods(t types.Type) bool {
	if t == nil || isRuntimeInterfaceType(t) {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return true
	}
	if types.NewMethodSet(t).Len() > 0 {
		return true
	}
	if _, isPtr := t.Underlying().(*types.Pointer); !isPtr {
		return types.NewMethodSet(types.NewPointer(t)).Len() > 0
	}
	return false
}

func typeHasExternalMethod(curPkg *types.Package, t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if ptr, isPtr := t.Underlying().(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	if isRuntimeInterfaceType(t) {
		return false
	}
	if _, isTP := t.(*types.TypeParam); isTP {
		return true
	}
	ms := types.NewMethodSet(types.NewPointer(t))
	for i := 0; i < ms.Len(); i++ {
		fn := ms.At(i).Obj()
		if fn != nil && fn.Pkg() != curPkg {
			return true
		}
	}
	return false
}

func isGoInternalPkgPath(pkgPath string) bool {
	return pkgPath == "internal" ||
		strings.HasPrefix(pkgPath, "internal/") ||
		strings.HasSuffix(pkgPath, "/internal") ||
		strings.Contains(pkgPath, "/internal/")
}

func ifaceSealsOutStdlib(t types.Type, isTrueStdPkg func(*types.Package) bool) bool {
	if !isRuntimeInterfaceType(t) {
		return false
	}
	iface, isIf := syntaxutil.UnderlyingType(t).(*types.Interface)
	if !isIf || iface.NumMethods() == 0 {
		return false
	}
	seen := map[types.Type]bool{}
	var mentionsNonStdSealedNamed func(cur types.Type) bool
	mentionsNonStdSealedNamed = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return false
		}
		seen[cur] = true
		if named, ok := cur.(*types.Named); ok && named.Obj() != nil {
			qPkg := named.Obj().Pkg()
			if qPkg != nil && !isTrueStdPkg(qPkg) && (!named.Obj().Exported() || isGoInternalPkgPath(qPkg.Path())) {
				return true
			}
		}
		switch u := cur.Underlying().(type) {
		case *types.Pointer:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Slice:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Array:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Chan:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Map:
			return mentionsNonStdSealedNamed(u.Key()) || mentionsNonStdSealedNamed(u.Elem())
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				if mentionsNonStdSealedNamed(u.Params().At(i).Type()) {
					return true
				}
			}
			for i := 0; i < u.Results().Len(); i++ {
				if mentionsNonStdSealedNamed(u.Results().At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m == nil {
			continue
		}
		if !m.Exported() && m.Pkg() != nil && !isTrueStdPkg(m.Pkg()) {
			return true
		}
		clear(seen)
		if mentionsNonStdSealedNamed(m.Type()) {
			return true
		}
	}
	return false
}

func isPureByteWriterIface(p *packages.Package, t types.Type) bool {
	if !isRuntimeInterfaceType(t) {
		return false
	}
	if syntaxutil.IsTrueStdlibInPkg(p, "fmt") && syntaxutil.IsNamedInPkg(t, "fmt", "State") {
		return true
	}
	iface, isIf := syntaxutil.UnderlyingType(t).(*types.Interface)
	if !isIf || iface.NumMethods() == 0 {
		return false
	}
	isErrType := func(rt types.Type) bool {
		if rt == nil {
			return false
		}
		named, ok := types.Unalias(rt).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() == nil && named.Obj().Name() == "error"
	}
	isBasicKind := func(rt types.Type, kind types.BasicKind) bool {
		if rt == nil {
			return false
		}
		b, ok := types.Unalias(rt).(*types.Basic)
		return ok && b.Kind() == kind
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m == nil || !m.Exported() {
			return false
		}
		msig, okS := m.Type().(*types.Signature)
		if !okS || msig.Variadic() || msig.TypeParams().Len() > 0 {
			return false
		}
		switch m.Name() {
		case "Write":
			if msig.Params().Len() != 1 || !syntaxutil.IsByteSliceType(msig.Params().At(0).Type()) ||
				msig.Results().Len() != 2 || !isBasicKind(msig.Results().At(0).Type(), types.Int) || !isErrType(msig.Results().At(1).Type()) {
				return false
			}
		case "WriteString":
			if msig.Params().Len() != 1 || !isBasicKind(msig.Params().At(0).Type(), types.String) ||
				msig.Results().Len() != 2 || !isBasicKind(msig.Results().At(0).Type(), types.Int) || !isErrType(msig.Results().At(1).Type()) {
				return false
			}
		case "WriteByte":
			if msig.Params().Len() != 1 || !isBasicKind(msig.Params().At(0).Type(), types.Byte) ||
				msig.Results().Len() != 1 || !isErrType(msig.Results().At(0).Type()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

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
		return !typeCanCarryExtractedObject(u.Elem())
	case *types.Map:
		return !typeCanCarryExtractedObject(u.Key()) && !typeCanCarryExtractedObject(u.Elem())
	default:
		return false
	}
}

func placeCrossesRefIndirection(pl flowir.Place) bool {
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		switch pr.Kind {
		case flowir.ProjDeref:
			return true
		case flowir.ProjField:
			if pr.Indirect {
				return true
			}
		case flowir.ProjIndex:
			if pr.BaseType == nil {
				return true
			}
			bt := types.Unalias(pr.BaseType)
			if _, isTP := bt.(*types.TypeParam); isTP {
				return true
			}
			if _, isArr := bt.Underlying().(*types.Array); !isArr {
				return true
			}
		}
	}
	return false
}

func collectEscapedIntraPkgFuncs(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Func]bool {
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

func recordNamedStructsInto(t types.Type, dst map[*types.Named]bool, seen map[types.Type]bool) {
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
		recordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Slice:
		recordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Array:
		recordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Chan:
		recordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Map:
		recordNamedStructsInto(u.Key(), dst, seen)
		recordNamedStructsInto(u.Elem(), dst, seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			recordNamedStructsInto(u.Field(i).Type(), dst, seen)
		}
	case *types.Signature:
		for i := 0; i < u.Params().Len(); i++ {
			recordNamedStructsInto(u.Params().At(i).Type(), dst, seen)
		}
		for i := 0; i < u.Results().Len(); i++ {
			recordNamedStructsInto(u.Results().At(i).Type(), dst, seen)
		}
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			recordNamedStructsInto(u.At(i).Type(), dst, seen)
		}
	}
}

func collectUnexportedStructCandFields(
	p *packages.Package,
	addrFields map[*types.Var]bool,
	convertedStructs map[*types.Named]bool,
	keepType func(types.Type) bool,
) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.Types == nil {
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
	escapedFuncs := collectEscapedIntraPkgFuncs(p, idx)
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

func hasTupleFirstArg(v *flowir.Value) bool {
	if v == nil || len(v.Args) != 1 || v.Ellipsis || v.Args[0] == nil || v.Args[0].Type == nil {
		return false
	}
	_, isTuple := types.Unalias(v.Args[0].Type).(*types.Tuple)
	return isTuple
}

func computeFreshOwnedContainers(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fc *flowir.PkgCache,
	isTrueStdPkg func(*types.Package) bool,
) (map[*types.Var]bool, map[*types.Var]bool, func(*flowir.Value) bool, func(*flowir.Value) bool) {
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
	forEachPkgFlowOp(p, fc, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
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
						recordNamedStructsInto(v.Type, convertedStructs, seen)
						recordNamedStructsInto(v.Arg.Type, convertedStructs, seen)
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
		if !excludedIfaceVars[lv] && isRuntimeInterfaceType(lv.Type()) {
			callerSafeIfaceVars[lv] = true
		}
	}

	freshFields := collectUnexportedStructCandFields(p, addrFields, convertedStructs, isScalarElemSliceOrMap)

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
			if val.CallKind == flowir.CallBuiltin && val.BuiltinName == "append" && !hasTupleFirstArg(val) && len(val.Args) >= 1 {
				return isFreshOwnedVal(val.Args[0])
			}
			if val.CallKind == flowir.CallPlain && !val.IsMethodExprCall && val.CalleeFunc != nil &&
				isTrueStdPkg(val.CalleeFunc.Pkg()) && isScalarElemSliceOrMap(val.Type) {
				pkgPath := val.CalleeFunc.Pkg().Path()
				fnName := val.CalleeFunc.Origin().Name()
				if pkgPath == "fmt" && (fnName == "Append" || fnName == "Appendf" || fnName == "Appendln") {
					return !hasTupleFirstArg(val) && len(val.Args) >= 1 && isFreshOwnedVal(val.Args[0])
				}
				traits := auditset.DeterministicStdCallTraits(pkgPath, fnName)
				if (traits.ValuePlaneClone || traits.ReadOnlySliceCopy || traits.PureScalarOrValue) && !traits.InPlaceContainerMutate {
					allSafe := true
					for _, arg := range val.Args {
						if arg == nil || (typeCanCarryExtractedObject(arg.Type) && !isFreshOwnedVal(arg)) {
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
		if val == nil || !isRuntimeInterfaceType(val.Type) {
			return false
		}
		if val.IsNil {
			return true
		}
		switch val.Kind {
		case flowir.ValPlace:
			return val.Place.IsBareVar() && callerSafeIfaceVars[val.Place.Obj]
		case flowir.ValConvert:
			return val.Arg != nil && isRuntimeInterfaceType(val.Arg.Type) && isCallerSafeIfaceVal(val.Arg)
		default:
			return false
		}
	}

	for changed := true; changed; {
		changed = false
		forEachPkgFlowOp(p, fc, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
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
								tupleCall := hasTupleFirstArg(v)
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
	return freshVars, freshFields, isFreshOwnedVal, isCallerSafeIfaceVal
}
