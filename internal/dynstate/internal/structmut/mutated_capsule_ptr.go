package structmut

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func collectSafeCapsuleWrapperUnsafePtrConvs(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	foreignReflectFields map[*types.Var]bool,
) (map[*ast.CallExpr]bool, map[*ast.CallExpr]bool, map[*types.Var]bool, map[*types.Func]bool, map[*ast.CallExpr]bool) {
	safe := map[*ast.CallExpr]bool{}
	safeLoadCasts := map[*ast.CallExpr]bool{}
	closedFields := map[*types.Var]bool{}
	applyGatedMethods := map[*types.Func]bool{}
	safeRawUintptrConvs := map[*ast.CallExpr]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || len(foreignReflectFields) == 0 {
		return safe, safeLoadCasts, closedFields, applyGatedMethods, safeRawUintptrConvs
	}
	instantiatedNamed := map[*types.Named]bool{}
	markValueContainedNamed := func(t types.Type) {
		syntaxutil.ForEachValueContainedStructType(t, func(vt types.Type) {
			if n, isN := types.Unalias(vt).(*types.Named); isN {
				instantiatedNamed[n] = true
			}
		})
	}
	isInsideCompileTimeUnsafeLayout := func(node ast.Node) bool {
		for cur := idx.ParentMap[node]; cur != nil; cur = idx.ParentMap[cur] {
			call, isC := cur.(*ast.CallExpr)
			if !isC {
				continue
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(call.Fun)); b != nil {
				switch b.Name() {
				case "Sizeof", "Alignof", "Offsetof":
					return true
				}
			}
		}
		return false
	}
	for _, obj := range p.TypesInfo.Defs {
		if v, ok := obj.(*types.Var); ok && v != nil && !v.IsField() {
			markValueContainedNamed(v.Type())
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CompositeLit:
				if !isInsideCompileTimeUnsafeLayout(x) {
					markValueContainedNamed(p.TypesInfo.TypeOf(x))
				}
			case *ast.CallExpr:
				if syntaxutil.IsBuiltinNewType(p.TypesInfo, x) {
					if ptr, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
						markValueContainedNamed(ptr.Elem())
					}
				} else if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil && b.Name() == "make" {
					switch u := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x)).(type) {
					case *types.Slice:
						markValueContainedNamed(u.Elem())
					case *types.Map:
						markValueContainedNamed(u.Key())
						markValueContainedNamed(u.Elem())
					case *types.Chan:
						markValueContainedNamed(u.Elem())
					}
				}
			}
			return true
		})
	}

	verifiedOffsetTypes := map[*types.Named]bool{}
	checkedOffsetTypes := map[*types.Named]bool{}
	isReflectStructFieldOffsetType := func(offNamed *types.Named) bool {
		if offNamed == nil || offNamed.Obj() == nil || offNamed.Obj().Pkg() != p.Types || offNamed.Obj().Exported() {
			return false
		}
		if checkedOffsetTypes[offNamed] {
			return verifiedOffsetTypes[offNamed]
		}
		checkedOffsetTypes[offNamed] = true
		basic, isB := offNamed.Underlying().(*types.Basic)
		if !isB || (basic.Info()&types.IsInteger) == 0 {
			return false
		}
		isZeroOrBitNotZero := func(expr ast.Expr) bool {
			expr = ast.Unparen(expr)
			if un, isUn := expr.(*ast.UnaryExpr); isUn && un.Op == token.XOR {
				expr = ast.Unparen(un.X)
			}
			if c, isC := expr.(*ast.CallExpr); isC && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
				if p.TypesInfo.Types[ast.Unparen(c.Fun)].IsType() {
					expr = ast.Unparen(c.Args[0])
				}
			}
			tv := p.TypesInfo.Types[expr]
			if tv.Value == nil || tv.Value.Kind() != constant.Int {
				return false
			}
			v, okV := constant.Int64Val(tv.Value)
			return okV && v == 0
		}
		okOff := true
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !okOff || n == nil {
					return false
				}
				switch x := n.(type) {
				case *ast.CallExpr:
					tv := p.TypesInfo.Types[ast.Unparen(x.Fun)]
					if tv.IsType() && types.Identical(types.Unalias(tv.Type), offNamed) {
						if len(x.Args) != 1 || x.Ellipsis.IsValid() {
							okOff = false
							return false
						}
						arg := ast.Unparen(x.Args[0])
						if isZeroOrBitNotZero(arg) {
							return true
						}
						sel, isS := arg.(*ast.SelectorExpr)
						if !isS || sel.Sel == nil || sel.Sel.Name != "Offset" {
							okOff = false
							return false
						}
						sInfo := p.TypesInfo.Selections[sel]
						if sInfo == nil || sInfo.Kind() != types.FieldVal || !syntaxutil.IsNamedInPkg(sInfo.Recv(), "reflect", "StructField") {
							okOff = false
							return false
						}
					}
				case *ast.BasicLit:
					if tv := p.TypesInfo.Types[x]; tv.Type != nil && types.Identical(types.Unalias(tv.Type), offNamed) && !isZeroOrBitNotZero(x) {
						okOff = false
						return false
					}
				}
				return true
			})
		}
		verifiedOffsetTypes[offNamed] = okOff
		return okOff
	}

	enclMethodHasOwnerRecv := func(node ast.Node, ownerNamed *types.Named) bool {
		fd := idx.EnclFunc[node]
		if fd == nil || fd != idx.SyncEnclFuncDecl(node) || fd.Recv == nil || len(fd.Recv.List) != 1 {
			return false
		}
		rt := p.TypesInfo.TypeOf(fd.Recv.List[0].Type)
		if rt == nil {
			return false
		}
		rt = types.Unalias(rt)
		if ptr, isP := rt.(*types.Pointer); isP {
			rt = types.Unalias(ptr.Elem())
		}
		return types.Identical(rt, ownerNamed)
	}

	var isClosedRawPtrField func(fld *types.Var, ownerNamed, rootWrapperOwner *types.Named, requireReflectOffset bool, visiting map[*types.Var]bool, candidateClosed map[*types.Var]bool) bool
	isClosedRawPtrField = func(fld *types.Var, ownerNamed, rootWrapperOwner *types.Named, requireReflectOffset bool, visiting map[*types.Var]bool, candidateClosed map[*types.Var]bool) bool {
		if fld == nil || !fld.IsField() || fld.Embedded() || fld.Pkg() != p.Types || !syntaxutil.IsUnsafePointerType(fld.Type()) {
			return false
		}
		if ownerNamed == nil || ownerNamed.Obj() == nil || ownerNamed.Obj().Pkg() != p.Types || ownerNamed.Obj().Exported() {
			return false
		}
		if visiting[fld] {
			return true
		}
		visiting[fld] = true
		defer delete(visiting, fld)
		for _, uid := range idx.UsesOf[fld] {
			if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == uid {
				continue
			}
			sel, isSel := idx.ParentMap[uid].(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid || refconfine.IdentOrExprIsWritten(idx, sel) || !enclMethodHasOwnerRecv(sel, ownerNamed) {
				return false
			}
			par := idx.ParentUnparen(sel)
			switch pn := par.(type) {
			case *ast.BinaryExpr:
				if pn.Op != token.EQL && pn.Op != token.NEQ {
					return false
				}
			case *ast.KeyValueExpr:
				if ast.Unparen(pn.Value) != sel {
					return false
				}
				cl, isCL := idx.ParentMap[pn].(*ast.CompositeLit)
				if !isCL {
					return false
				}
				dstOwner := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl))
				kid, isKID := ast.Unparen(pn.Key).(*ast.Ident)
				if !isKID {
					return false
				}
				dstFld, _ := p.TypesInfo.Uses[kid].(*types.Var)
				if !isClosedRawPtrField(dstFld, dstOwner, rootWrapperOwner, requireReflectOffset, visiting, candidateClosed) {
					return false
				}
			case *ast.CallExpr:
				tv := p.TypesInfo.Types[ast.Unparen(pn.Fun)]
				if !tv.IsType() {
					callee := syntaxutil.ResolveCalledFuncObj(p, pn.Fun)
					if callee == nil || callee.Pkg() == nil || pn.Ellipsis.IsValid() {
						return false
					}
					switch callee.Pkg().Path() {
					case "reflect":
						if !syntaxutil.IsTrueStdlibInPkg(p, "reflect") || callee.Name() != "NewAt" ||
							len(pn.Args) != 2 || ast.Unparen(pn.Args[1]) != sel {
							return false
						}
					case "sync/atomic":
						if !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
							return false
						}
						switch callee.Name() {
						case "StorePointer":
							if len(pn.Args) != 2 || ast.Unparen(pn.Args[1]) != sel {
								return false
							}
						case "CompareAndSwapPointer":
							if len(pn.Args) != 3 || ast.Unparen(pn.Args[2]) != sel {
								return false
							}
						default:
							return false
						}
					default:
						return false
					}
					continue
				}
				if ptrT, isP := types.Unalias(tv.Type).Underlying().(*types.Pointer); isP {
					elemT := types.Unalias(ptrT.Elem())
					if syntaxutil.ContainsUintptr(elemT) {
						return false
					}
					typeCarriesDynamicOrUnsafe := func(t types.Type) bool {
						return refconfine.WalkDynamicCarrier(true, t, map[types.Type]bool{}, refconfine.CarrierPolicyConsumer) ||
							syntaxutil.ContainsUnsafePointer(t)
					}
					switch u := elemT.Underlying().(type) {
					case *types.Struct, *types.Interface, *types.Array, *types.Signature, *types.Chan:
						return false
					case *types.Pointer:
						if typeCarriesDynamicOrUnsafe(elemT) {
							return false
						}
					case *types.Slice:
						isSelfOwnerSlice := types.Identical(types.Unalias(u.Elem()), ownerNamed) ||
							types.Identical(types.Unalias(u.Elem()), rootWrapperOwner)
						if !isSelfOwnerSlice && typeCarriesDynamicOrUnsafe(elemT) {
							return false
						}
					case *types.Map:
						if typeCarriesDynamicOrUnsafe(u.Key()) {
							return false
						}
					}
				} else if syntaxutil.IsUnsafePointerType(tv.Type) {
					as, isAS := idx.ParentUnparen(pn).(*ast.AssignStmt)
					if !isAS || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != pn {
						return false
					}
				} else if basic, isB := types.Unalias(tv.Type).Underlying().(*types.Basic); isB && basic.Kind() == types.Uintptr {
					bin, isBin := idx.ParentUnparen(pn).(*ast.BinaryExpr)
					if !isBin || (bin.Op != token.ADD && bin.Op != token.SUB) {
						return false
					}
					upCall, isUP := idx.ParentUnparen(bin).(*ast.CallExpr)
					if !isUP || len(upCall.Args) != 1 || upCall.Ellipsis.IsValid() {
						return false
					}
					upTV := p.TypesInfo.Types[ast.Unparen(upCall.Fun)]
					if !upTV.IsType() || !syntaxutil.IsUnsafePointerType(upTV.Type) {
						return false
					}
					isDirectPureScalarPtrCast := false
					if ownerNamed != rootWrapperOwner {
						if castCall, isCC := idx.ParentUnparen(upCall).(*ast.CallExpr); isCC && len(castCall.Args) == 1 && !castCall.Ellipsis.IsValid() && ast.Unparen(castCall.Args[0]) == upCall {
							ctv := p.TypesInfo.Types[ast.Unparen(castCall.Fun)]
							if ctv.IsType() && ctv.Type != nil {
								if cp, isCP := types.Unalias(ctv.Type).Underlying().(*types.Pointer); isCP {
									if isZeroSizedPaddingType(cp.Elem()) {
										isDirectPureScalarPtrCast = true
									} else if cb, isCB := types.Unalias(cp.Elem()).Underlying().(*types.Basic); isCB &&
										(cb.Info()&(types.IsInteger|types.IsBoolean|types.IsFloat)) != 0 && cb.Kind() != types.Uintptr {
										isDirectPureScalarPtrCast = true
									}
								}
							}
						}
					}
					if requireReflectOffset && !isDirectPureScalarPtrCast {
						other := bin.Y
						if ast.Unparen(bin.Y) == pn {
							other = bin.X
						}
						other = ast.Unparen(other)
						if oc, isOC := other.(*ast.CallExpr); isOC && len(oc.Args) == 1 && !oc.Ellipsis.IsValid() {
							otv := p.TypesInfo.Types[ast.Unparen(oc.Fun)]
							if otv.IsType() {
								if ob, isOB := types.Unalias(otv.Type).Underlying().(*types.Basic); isOB && ob.Kind() == types.Uintptr {
									other = ast.Unparen(oc.Args[0])
								}
							}
						}
						offNamed, isON := types.Unalias(p.TypesInfo.TypeOf(other)).(*types.Named)
						if !isON || !isReflectStructFieldOffsetType(offNamed) {
							return false
						}
					}
				} else {
					return false
				}
			default:
				return false
			}
		}
		if candidateClosed != nil {
			candidateClosed[fld] = true
		}
		return true
	}

	verifyWrapperBasePtrOffsetDiscipline := func(conv *ast.CallExpr, dstOwner *types.Named, dstFld *types.Var) (bool, map[*types.Func]bool) {
		return runWrapperBasePtrOffsetDiscipline(p, idx, foreignReflectFields, instantiatedNamed, isInsideCompileTimeUnsafeLayout, isReflectStructFieldOffsetType, conv, dstOwner, dstFld)
	}

	isNilOrMatchingUnsafeConv := func(expr ast.Expr, wantPtr *types.Pointer) bool {
		expr = ast.Unparen(expr)
		if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
			return true
		}
		c, isC := expr.(*ast.CallExpr)
		if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
			return false
		}
		tv := p.TypesInfo.Types[ast.Unparen(c.Fun)]
		if !tv.IsType() || !syntaxutil.IsUnsafePointerType(tv.Type) {
			return false
		}
		if syntaxutil.IsNilIdent(p.TypesInfo, c.Args[0]) {
			return true
		}
		argT := p.TypesInfo.TypeOf(c.Args[0])
		return argT != nil && types.Identical(types.Unalias(argT), types.Unalias(wantPtr))
	}

	isDirectCastOrNilCompare := func(node ast.Expr, par ast.Node, wantPtr *types.Pointer) bool {
		switch pn := par.(type) {
		case *ast.BinaryExpr:
			if pn.Op != token.EQL && pn.Op != token.NEQ {
				return false
			}
			if ast.Unparen(pn.X) == node {
				return syntaxutil.IsNilIdent(p.TypesInfo, pn.Y)
			}
			if ast.Unparen(pn.Y) == node {
				return syntaxutil.IsNilIdent(p.TypesInfo, pn.X)
			}
			return false
		case *ast.CallExpr:
			if len(pn.Args) != 1 || pn.Ellipsis.IsValid() || ast.Unparen(pn.Args[0]) != node {
				return false
			}
			tv := p.TypesInfo.Types[ast.Unparen(pn.Fun)]
			return tv.IsType() && tv.Type != nil && types.Identical(types.Unalias(tv.Type), types.Unalias(wantPtr))
		}
		return false
	}

	isMonomorphicAtomicSlotConv := func(conv *ast.CallExpr, wPtr *types.Pointer) bool {
		if !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
			return false
		}
		call, isCall := idx.ParentUnparen(conv).(*ast.CallExpr)
		if !isCall || call.Ellipsis.IsValid() || len(call.Args) < 2 {
			return false
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "sync/atomic" {
			return false
		}
		switch callee.Name() {
		case "StorePointer":
			if len(call.Args) != 2 || ast.Unparen(call.Args[1]) != conv {
				return false
			}
		case "CompareAndSwapPointer":
			if len(call.Args) != 3 || (ast.Unparen(call.Args[1]) != conv && ast.Unparen(call.Args[2]) != conv) {
				return false
			}
		default:
			return false
		}
		uAnd, isU := ast.Unparen(call.Args[0]).(*ast.UnaryExpr)
		if !isU || uAnd.Op != token.AND {
			return false
		}
		sSel, isS := ast.Unparen(uAnd.X).(*ast.SelectorExpr)
		if !isS {
			return false
		}
		sInfo := p.TypesInfo.Selections[sSel]
		if sInfo == nil || sInfo.Kind() != types.FieldVal {
			return false
		}
		slot, _ := sInfo.Obj().(*types.Var)
		if slot == nil || slot.Exported() || slot.Embedded() || slot.Pkg() != p.Types || !syntaxutil.IsUnsafePointerType(slot.Type()) {
			return false
		}
		var pendingLoads []*ast.CallExpr
		for _, uid := range idx.UsesOf[slot] {
			usel, okS := idx.ParentMap[uid].(*ast.SelectorExpr)
			if !okS || usel.Sel != uid {
				return false
			}
			uu, okU := idx.ParentUnparen(usel).(*ast.UnaryExpr)
			if !okU || uu.Op != token.AND || ast.Unparen(uu.X) != usel {
				return false
			}
			ac, okC := idx.ParentUnparen(uu).(*ast.CallExpr)
			if !okC || ac.Ellipsis.IsValid() || len(ac.Args) == 0 || ast.Unparen(ac.Args[0]) != uu {
				return false
			}
			afn := syntaxutil.ResolveCalledFuncObj(p, ac.Fun)
			if afn == nil || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" {
				return false
			}
			switch afn.Name() {
			case "StorePointer":
				if len(ac.Args) != 2 || !isNilOrMatchingUnsafeConv(ac.Args[1], wPtr) {
					return false
				}
			case "CompareAndSwapPointer":
				if len(ac.Args) != 3 || !isNilOrMatchingUnsafeConv(ac.Args[1], wPtr) || !isNilOrMatchingUnsafeConv(ac.Args[2], wPtr) {
					return false
				}
			case "LoadPointer":
				if len(ac.Args) != 1 {
					return false
				}
				par := idx.ParentUnparen(ac)
				if isDirectCastOrNilCompare(ac, par, wPtr) {
					if cc, isCC := par.(*ast.CallExpr); isCC {
						pendingLoads = append(pendingLoads, cc)
					}
					continue
				}
				as, isAS := par.(*ast.AssignStmt)
				if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != ac {
					return false
				}
				lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
				if !isID {
					return false
				}
				lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
				if lv == nil || idx.DefCounts[lv] != 1 {
					return false
				}
				for _, luid := range idx.UsesOf[lv] {
					lpar := idx.ParentUnparen(luid)
					if identIsWrittenAddrOrAutoAddr(p, idx, lv, luid) ||
						!isDirectCastOrNilCompare(luid, lpar, wPtr) {
						return false
					}
					if cc, isCC := lpar.(*ast.CallExpr); isCC {
						pendingLoads = append(pendingLoads, cc)
					}
				}
			default:
				return false
			}
		}
		for _, lc := range pendingLoads {
			safeLoadCasts[lc] = true
		}
		return true
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			conv, isC := n.(*ast.CallExpr)
			if !isC || len(conv.Args) != 1 || conv.Ellipsis.IsValid() {
				return true
			}
			tv := p.TypesInfo.Types[ast.Unparen(conv.Fun)]
			if !tv.IsType() || !syntaxutil.IsUnsafePointerType(tv.Type) {
				return true
			}
			wPtr, isP := types.Unalias(p.TypesInfo.TypeOf(conv.Args[0])).(*types.Pointer)
			if !isP {
				return true
			}
			wNamed, isN := types.Unalias(wPtr.Elem()).(*types.Named)
			if !isN || wNamed.Obj() == nil || wNamed.Obj().Pkg() != p.Types || wNamed.Obj().Exported() {
				return true
			}
			wSt, isSt := wNamed.Underlying().(*types.Struct)
			if !isSt {
				return true
			}
			hasForeignField := false
			for i := 0; i < wSt.NumFields(); i++ {
				if foreignReflectFields[wSt.Field(i)] {
					hasForeignField = true
					break
				}
			}
			if !hasForeignField {
				return true
			}
			if isMonomorphicAtomicSlotConv(conv, wPtr) {
				safe[conv] = true
				return true
			}
			if !instantiatedNamed[wNamed] {
				if kv, isKV := idx.ParentUnparen(conv).(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Value) == conv {
					if cl, isCL := idx.ParentMap[kv].(*ast.CompositeLit); isCL {
						dstOwner := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl))
						if kid, isKID := ast.Unparen(kv.Key).(*ast.Ident); isKID {
							dstFld, _ := p.TypesInfo.Uses[kid].(*types.Var)
							candClosed := map[*types.Var]bool{}
							if isClosedRawPtrField(dstFld, dstOwner, dstOwner, true, map[*types.Var]bool{}, candClosed) {
								if okDisc, gated := verifyWrapperBasePtrOffsetDiscipline(conv, dstOwner, dstFld); okDisc {
									safe[conv] = true
									for cf := range candClosed {
										closedFields[cf] = true
									}
									for gf := range gated {
										applyGatedMethods[gf] = true
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	if len(closedFields) > 0 {
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				upCall, isC := n.(*ast.CallExpr)
				if !isC || len(upCall.Args) != 1 || upCall.Ellipsis.IsValid() {
					return true
				}
				upTV := p.TypesInfo.Types[ast.Unparen(upCall.Fun)]
				if !upTV.IsType() || !syntaxutil.IsUnsafePointerType(upTV.Type) {
					return true
				}
				arg := ast.Unparen(upCall.Args[0])
				argBasic, isAB := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(arg)).(*types.Basic)
				if !isAB || argBasic.Kind() != types.Uintptr {
					return true
				}
				if parCast, isPC := idx.ParentUnparen(upCall).(*ast.CallExpr); isPC && len(parCast.Args) == 1 && ast.Unparen(parCast.Args[0]) == upCall {
					ptv := p.TypesInfo.Types[ast.Unparen(parCast.Fun)]
					if ptv.IsType() && ptv.Type != nil {
						if pp, isPP := types.Unalias(ptv.Type).Underlying().(*types.Pointer); isPP && isZeroSizedPaddingType(pp.Elem()) {
							safeRawUintptrConvs[upCall] = true
							return true
						}
					}
				}
				if bin, isBin := arg.(*ast.BinaryExpr); isBin && (bin.Op == token.ADD || bin.Op == token.SUB) {
					for _, side := range []ast.Expr{bin.X, bin.Y} {
						sc, isSC := ast.Unparen(side).(*ast.CallExpr)
						if !isSC || len(sc.Args) != 1 || sc.Ellipsis.IsValid() {
							continue
						}
						stv := p.TypesInfo.Types[ast.Unparen(sc.Fun)]
						sb, isSB := syntaxutil.UnderlyingType(stv.Type).(*types.Basic)
						if !stv.IsType() || !isSB || sb.Kind() != types.Uintptr {
							continue
						}
						if sel, isS := ast.Unparen(sc.Args[0]).(*ast.SelectorExpr); isS && sel.Sel != nil {
							if fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var); fld != nil && closedFields[fld] {
								safeRawUintptrConvs[upCall] = true
								return true
							}
						}
					}
				}
				if rvCall, isRC := arg.(*ast.CallExpr); isRC && len(rvCall.Args) == 0 && !rvCall.Ellipsis.IsValid() {
					if rfn := syntaxutil.ResolveCalledFuncObj(p, rvCall.Fun); rfn != nil && rfn.Pkg() != nil && rfn.Pkg().Path() == "reflect" && rfn.Name() == "Pointer" {
						if kv, isKV := idx.ParentUnparen(upCall).(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Value) == upCall {
							if kid, isKID := ast.Unparen(kv.Key).(*ast.Ident); isKID {
								if fld, _ := p.TypesInfo.Uses[kid].(*types.Var); fld != nil && closedFields[fld] {
									safeRawUintptrConvs[upCall] = true
									return true
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	return safe, safeLoadCasts, closedFields, applyGatedMethods, safeRawUintptrConvs
}
