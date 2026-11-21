package freshstruct

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) isZeroConstOffset(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	tv := wpd.p.TypesInfo.Types[expr]
	if tv.Value != nil && tv.Value.Kind() == constant.Int {
		iv, okI := constant.Int64Val(tv.Value)
		return okI && iv == 0
	}
	if c, isC := expr.(*ast.CallExpr); isC && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
		if wpd.p.TypesInfo.Types[ast.Unparen(c.Fun)].IsType() {
			atv := wpd.p.TypesInfo.Types[ast.Unparen(c.Args[0])]
			if atv.Value != nil && atv.Value.Kind() == constant.Int {
				iv, okI := constant.Int64Val(atv.Value)
				return okI && iv == 0
			}
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isZeroOffsetExpr(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	on, isON := types.Unalias(wpd.p.TypesInfo.TypeOf(expr)).(*types.Named)
	if !isON || !wpd.applyOffsetSet[on] {
		return false
	}
	if wpd.isZeroConstOffset(expr) {
		return true
	}
	id, isID := expr.(*ast.Ident)
	if !isID {
		return false
	}
	v, _ := wpd.p.TypesInfo.Uses[id].(*types.Var)
	if v == nil || v.Pkg() != wpd.p.Types || wpd.idx.DefCounts[v] != 1 {
		return false
	}
	for _, uid := range wpd.idx.UsesOf[v] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, v, uid) {
			return false
		}
	}
	if vs := wpd.idx.VarSpecs[v]; vs != nil && len(vs.Names) == len(vs.Values) {
		for i, nm := range vs.Names {
			if wpd.p.TypesInfo.Defs[nm] == v {
				return wpd.isZeroConstOffset(vs.Values[i])
			}
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isReflectNewCall(expr ast.Expr) bool {
	c, isC := ast.Unparen(expr).(*ast.CallExpr)
	if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
		return false
	}
	cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, c.Fun)
	return cfn != nil && cfn.Pkg() != nil && cfn.Pkg().Path() == "reflect" && cfn.Name() == "New"
}

func (wpd *wrapperPtrDiscipline) isReflectNewInterfaceCall(expr ast.Expr) bool {
	c, isC := ast.Unparen(expr).(*ast.CallExpr)
	if !isC || len(c.Args) != 0 || c.Ellipsis.IsValid() {
		return false
	}
	sel, isS := ast.Unparen(c.Fun).(*ast.SelectorExpr)
	if !isS || sel.Sel == nil || sel.Sel.Name != "Interface" {
		return false
	}
	return wpd.isReflectNewCall(sel.X)
}

func (wpd *wrapperPtrDiscipline) isReflectNewIfaceExpr(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if wpd.isReflectNewInterfaceCall(expr) {
		return true
	}
	id, isID := expr.(*ast.Ident)
	if !isID {
		return false
	}
	v, _ := wpd.p.TypesInfo.Uses[id].(*types.Var)
	if v == nil || v.Parent() == wpd.p.Types.Scope() || wpd.idx.DefCounts[v] != 1 {
		return false
	}
	for _, uid := range wpd.idx.UsesOf[v] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, v, uid) {
			return false
		}
	}
	enclScope := declaringFuncOrLitBody(wpd.idx, id, v.Pos())
	if enclScope == nil {
		return false
	}
	matched := false
	ast.Inspect(enclScope, func(bn ast.Node) bool {
		if matched || bn == nil {
			return false
		}
		switch x := bn.(type) {
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if wpd.p.TypesInfo.Defs[nm] == v && i < len(x.Values) && wpd.isReflectNewInterfaceCall(x.Values[i]) {
					matched = true
					return false
				}
			}
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE && len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					if lid, isLID := ast.Unparen(lhs).(*ast.Ident); isLID && wpd.p.TypesInfo.Defs[lid] == v && wpd.isReflectNewInterfaceCall(x.Rhs[i]) {
						matched = true
						return false
					}
				}
			}
		}
		return true
	})
	return matched
}

func (wpd *wrapperPtrDiscipline) isStructOrCapsuleReflectTypeExpr(expr ast.Expr, visiting map[types.Object]bool) bool {
	if expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(wpd.p.TypesInfo, expr) {
		return true
	}
	if !syntaxutil.IsNamedInPkg(wpd.p.TypesInfo.TypeOf(expr), "reflect", "Type") {
		return false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() {
			return false
		}
		efn := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
		if efn == nil || efn.Pkg() == nil || efn.Pkg().Path() != "reflect" {
			return false
		}
		switch efn.Name() {
		case "Elem", "Key":
			esel, isES := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			return len(e.Args) == 0 && isES && wpd.isStructOrCapsuleReflectTypeExpr(esel.X, visiting)
		case "PtrTo", "PointerTo", "SliceOf":
			return len(e.Args) == 1 && wpd.isStructOrCapsuleReflectTypeExpr(e.Args[0], visiting)
		}
		return false
	case *ast.SelectorExpr:
		sInfo := wpd.p.TypesInfo.Selections[e]
		if sInfo == nil || sInfo.Kind() != types.FieldVal {
			return false
		}
		sfld, _ := sInfo.Obj().(*types.Var)
		if sfld == nil || !sfld.IsField() {
			return false
		}
		ownerN := syntaxutil.DerefNamedStruct(sInfo.Recv())
		if syntaxutil.IsNamedInPkg(ownerN, "reflect", "StructField") {
			return true
		}
		if ownerN == nil || ownerN.Obj() == nil || ownerN.Obj().Pkg() != wpd.p.Types || wpd.reboundStructs[ownerN] {
			return false
		}
		if wpd.capsuleStructs[ownerN] && sfld.Exported() {
			return wpd.isVerifiedCapsuleGoReflectTypeField(ownerN, sfld)
		}
		if sfld.Exported() {
			return false
		}
		isVerifiedExtCapsuleStruct := false
		if ownerN.Obj().Exported() {
			// Exported capsule structs whose unexported reflect.Type field is
			// populated by an external-only InitHelper or legacy exported-any descriptor field must
			// have zero intra-package non-empty CompositeLits so intra-package callers cannot forge them.
			hasIntraLit := false
			for _, ffile := range wpd.p.Syntax {
				ast.Inspect(ffile, func(bn ast.Node) bool {
					if hasIntraLit || bn == nil {
						return false
					}
					if cl, isCL := bn.(*ast.CompositeLit); isCL && len(cl.Elts) > 0 && syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(cl)) == ownerN {
						hasIntraLit = true
						return false
					}
					return true
				})
			}
			if !hasIntraLit {
				isVerifiedExtCapsuleStruct = true
			} else if !wpd.capsuleStructs[ownerN] {
				return false
			}
		}
		if visiting[sfld] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[sfld] {
			if parSel, isPS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isPS && parSel.Sel == uid {
				if u, isU := wpd.idx.ParentUnparen(parSel).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			} else if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
				return false
			}
		}
		visiting[sfld] = true
		defer delete(visiting, sfld)
		var isExtLegacyTypeExpr func(re ast.Expr, locVis map[*types.Var]bool) bool
		isExtLegacyTypeExpr = func(re ast.Expr, locVis map[*types.Var]bool) bool {
			if re == nil {
				return false
			}
			re = ast.Unparen(re)
			switch rx := re.(type) {
			case *ast.CallExpr:
				if rx.Ellipsis.IsValid() {
					return false
				}
				rf := syntaxutil.ResolveCalledFuncObj(wpd.p, rx.Fun)
				if rf == nil || rf.Pkg() == nil || rf.Pkg().Path() != "reflect" {
					return false
				}
				if rf.Name() == "Elem" && len(rx.Args) == 0 {
					rsel, isRS := ast.Unparen(rx.Fun).(*ast.SelectorExpr)
					return isRS && isExtLegacyTypeExpr(rsel.X, locVis)
				}
				if rf.Name() == "TypeOf" && len(rx.Args) == 1 {
					asel, isAS := ast.Unparen(rx.Args[0]).(*ast.SelectorExpr)
					if !isAS {
						return false
					}
					aInfo := wpd.p.TypesInfo.Selections[asel]
					if aInfo == nil || aInfo.Kind() != types.FieldVal {
						return false
					}
					afld, _ := aInfo.Obj().(*types.Var)
					return afld != nil && afld.Exported() && isEmptyInterfaceType(afld.Type()) &&
						syntaxutil.DerefNamedStruct(aInfo.Recv()) == ownerN
				}
			case *ast.Ident:
				lv, _ := wpd.p.TypesInfo.Uses[rx].(*types.Var)
				if lv == nil || lv.Parent() == wpd.p.Types.Scope() {
					return false
				}
				if locVis[lv] {
					return true
				}
				enclSc := declaringFuncOrLitBody(wpd.idx, rx, lv.Pos())
				if enclSc == nil || cachedScopeHasGoto(wpd.p, wpd.idx, enclSc) {
					return false
				}
				locVis[lv] = true
				defer delete(locVis, lv)
				sawW := false
				okW := true
				ast.Inspect(enclSc, func(bn ast.Node) bool {
					if !okW || bn == nil {
						return false
					}
					switch sx := bn.(type) {
					case *ast.ValueSpec:
						for i, nm := range sx.Names {
							if wpd.p.TypesInfo.Defs[nm] == lv && len(sx.Values) > 0 {
								if i >= len(sx.Values) || !isExtLegacyTypeExpr(sx.Values[i], locVis) {
									okW = false
									return false
								}
								sawW = true
							}
						}
					case *ast.AssignStmt:
						for i, lhs := range sx.Lhs {
							lid, isID := ast.Unparen(lhs).(*ast.Ident)
							if !isID || (wpd.p.TypesInfo.Defs[lid] != lv && wpd.p.TypesInfo.Uses[lid] != lv) {
								continue
							}
							if len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) || !isExtLegacyTypeExpr(sx.Rhs[i], locVis) {
								okW = false
								return false
							}
							sawW = true
						}
					}
					return true
				})
				return okW && sawW
			}
			return false
		}
		sawWrite := false
		fldOK := true
		for _, ffile := range wpd.p.Syntax {
			ast.Inspect(ffile, func(bn ast.Node) bool {
				if !fldOK || bn == nil {
					return false
				}
				switch x := bn.(type) {
				case *ast.CompositeLit:
					clNamed := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x))
					if clNamed == nil {
						return true
					}
					clSt, isSt := clNamed.Underlying().(*types.Struct)
					if !isSt || len(x.Elts) == 0 {
						return true
					}
					if _, isKV0 := x.Elts[0].(*ast.KeyValueExpr); isKV0 {
						for _, elt := range x.Elts {
							kv, isKV := elt.(*ast.KeyValueExpr)
							if !isKV {
								fldOK = false
								return false
							}
							kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
							if isID && wpd.p.TypesInfo.Uses[kid] == sfld {
								if !wpd.isStructOrCapsuleReflectTypeExpr(kv.Value, visiting) {
									fldOK = false
									return false
								}
								sawWrite = true
							}
						}
					} else {
						for i, elt := range x.Elts {
							if i < clSt.NumFields() && clSt.Field(i) == sfld {
								if !wpd.isStructOrCapsuleReflectTypeExpr(elt, visiting) {
									fldOK = false
									return false
								}
								sawWrite = true
							}
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
						if !isS || lsel.Sel == nil || wpd.p.TypesInfo.Uses[lsel.Sel] != sfld {
							continue
						}
						if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) {
							fldOK = false
							return false
						}
						if wpd.isStructOrCapsuleReflectTypeExpr(x.Rhs[i], visiting) {
							sawWrite = true
							continue
						}
						if isVerifiedExtCapsuleStruct {
							if isExtLegacyTypeExpr(x.Rhs[i], map[*types.Var]bool{}) {
								sawWrite = true
								continue
							}
							enclFD := wpd.idx.EnclFunc[x]
							if enclFD != nil && enclFD.Name != nil {
								if enclFn, _ := wpd.p.TypesInfo.Defs[enclFD.Name].(*types.Func); enclFn != nil && enclFn.Exported() && len(wpd.idx.UsesOf[enclFn]) == 0 {
									if rid, isRID := ast.Unparen(x.Rhs[i]).(*ast.Ident); isRID {
										rv, _ := wpd.p.TypesInfo.Uses[rid].(*types.Var)
										esig, okES := enclFn.Type().(*types.Signature)
										if rv != nil && okES && esig.Recv() == nil {
											for pi := 0; pi < esig.Params().Len(); pi++ {
												if esig.Params().At(pi) == rv {
													sawWrite = true
													break
												}
											}
											if sawWrite {
												continue
											}
										}
									}
								}
							}
						}
						fldOK = false
						return false
					}
				}
				return true
			})
		}
		return fldOK && sawWrite
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[e].(*types.Var)
		if v == nil || v.Pkg() != wpd.p.Types || v.Parent() == wpd.p.Types.Scope() {
			return false
		}
		if visiting[v] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[v] {
			if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
				return false
			}
		}
		visiting[v] = true
		defer delete(visiting, v)
		for fn, fd := range wpd.idx.FuncDecls {
			if fn == nil || fd == nil {
				continue
			}
			sig, okS := fn.Type().(*types.Signature)
			if !okS {
				continue
			}
			for pi := 0; pi < sig.Params().Len(); pi++ {
				if sig.Params().At(pi) == v {
					if sig.Recv() != nil || len(wpd.idx.UsesOf[fn]) == 0 {
						return false
					}
					if fn.Exported() && !wpd.isInternalCapsulePkg {
						return false
					}
					for _, uid := range wpd.idx.UsesOf[v] {
						if refconfine.IdentIsWrittenOrAddrTaken(wpd.idx, uid) {
							return false
						}
					}
					for _, cuid := range wpd.idx.UsesOf[fn] {
						cc := refconfine.EnclosingCallOfCalleeIdent(wpd.idx, cuid)
						if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) || !wpd.isStructOrCapsuleReflectTypeExpr(cc.Args[pi], visiting) {
							return false
						}
					}
					return true
				}
			}
		}
		enclScope := declaringFuncOrLitBody(wpd.idx, e, v.Pos())
		if enclScope == nil || cachedScopeHasGoto(wpd.p, wpd.idx, enclScope) {
			return false
		}
		sawWrite := false
		localOK := true
		ast.Inspect(enclScope, func(bn ast.Node) bool {
			if !localOK || bn == nil {
				return false
			}
			switch x := bn.(type) {
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					if wpd.p.TypesInfo.Defs[nm] == v && len(x.Values) > 0 {
						if i >= len(x.Values) || !wpd.isStructOrCapsuleReflectTypeExpr(x.Values[i], visiting) {
							localOK = false
							return false
						}
						sawWrite = true
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					if wpd.p.TypesInfo.Defs[lid] == v || wpd.p.TypesInfo.Uses[lid] == v {
						if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isStructOrCapsuleReflectTypeExpr(x.Rhs[i], visiting) {
							localOK = false
							return false
						}
						sawWrite = true
					}
				}
			}
			return true
		})
		return localOK && sawWrite
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isSafeReflectZeroInterfaceOrQueryArg(rhs ast.Expr, visiting map[types.Object]bool) bool {
	if rhs == nil {
		return false
	}
	rhs = ast.Unparen(rhs)
	if ic, isIC := rhs.(*ast.CallExpr); isIC && len(ic.Args) == 0 && !ic.Ellipsis.IsValid() {
		if isel, isIS := ast.Unparen(ic.Fun).(*ast.SelectorExpr); isIS && isel.Sel != nil && isel.Sel.Name == "Interface" {
			if zc, isZC := ast.Unparen(isel.X).(*ast.CallExpr); isZC && len(zc.Args) == 1 && !zc.Ellipsis.IsValid() {
				zfn := syntaxutil.ResolveCalledFuncObj(wpd.p, zc.Fun)
				if zfn != nil && zfn.Pkg() != nil && zfn.Pkg().Path() == "reflect" && zfn.Name() == "Zero" &&
					wpd.isStructOrCapsuleReflectTypeExpr(zc.Args[0], map[types.Object]bool{}) {
					return true
				}
			}
		}
	}
	return wpd.isSafeExportedTypeQueryIfaceArg(rhs, visiting)
}

func (wpd *wrapperPtrDiscipline) isSafeExportedTypeQueryIfaceArg(argExpr ast.Expr, visiting map[types.Object]bool) bool {
	if argExpr == nil {
		return false
	}
	argExpr = ast.Unparen(argExpr)
	if !types.IsInterface(wpd.p.TypesInfo.TypeOf(argExpr)) {
		return false
	}
	switch ae := argExpr.(type) {
	case *ast.Ident:
		pv, _ := wpd.p.TypesInfo.Uses[ae].(*types.Var)
		if pv == nil || pv.Pkg() != wpd.p.Types || pv.Parent() == wpd.p.Types.Scope() {
			return false
		}
		if visiting[pv] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[pv] {
			if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, pv, uid) {
				return false
			}
		}
		visiting[pv] = true
		defer delete(visiting, pv)
		for fn, fd := range wpd.idx.FuncDecls {
			if fn == nil || fd == nil || !fn.Exported() {
				continue
			}
			sig, okS := fn.Type().(*types.Signature)
			if !okS {
				continue
			}
			for pi := 0; pi < sig.Params().Len(); pi++ {
				if sig.Params().At(pi) == pv {
					if sig.Recv() != nil && wpd.p.Types != nil {
						pScope := wpd.p.Types.Scope()
						for _, nm := range pScope.Names() {
							tn, okTN := pScope.Lookup(nm).(*types.TypeName)
							if !okTN || tn == nil {
								continue
							}
							if ifc, isIf := tn.Type().Underlying().(*types.Interface); isIf {
								for mi := 0; mi < ifc.NumMethods(); mi++ {
									if ifc.Method(mi).Name() == fn.Name() {
										return false
									}
								}
							}
						}
					}
					for _, cuid := range wpd.idx.UsesOf[fn] {
						cc := refconfine.EnclosingCallOfCalleeIdent(wpd.idx, cuid)
						if cc == nil || cc.Ellipsis.IsValid() {
							return false
						}
						argIdx := pi
						if csel, isCS := ast.Unparen(cc.Fun).(*ast.SelectorExpr); isCS {
							if cInfo := wpd.p.TypesInfo.Selections[csel]; cInfo != nil && cInfo.Kind() == types.MethodExpr {
								argIdx = pi + 1
							}
						}
						if argIdx >= len(cc.Args) || !wpd.isSafeExportedTypeQueryIfaceArg(cc.Args[argIdx], visiting) {
							return false
						}
					}
					return true
				}
			}
		}
		return false
	case *ast.SelectorExpr:
		sInfo := wpd.p.TypesInfo.Selections[ae]
		if sInfo == nil || sInfo.Kind() != types.FieldVal {
			return false
		}
		sfld, _ := sInfo.Obj().(*types.Var)
		sNamed := syntaxutil.DerefNamedStruct(sInfo.Recv())
		if sfld == nil || !sfld.IsField() || sfld.Exported() || sfld.Pkg() != wpd.p.Types ||
			sNamed == nil || sNamed.Obj() == nil || sNamed.Obj().Pkg() != wpd.p.Types || sNamed.Obj().Exported() || wpd.reboundStructs[sNamed] {
			return false
		}
		if visiting[sfld] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[sfld] {
			if parSel, isPS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isPS && parSel.Sel == uid {
				if u, isU := wpd.idx.ParentUnparen(parSel).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			} else if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
				return false
			}
		}
		visiting[sfld] = true
		defer delete(visiting, sfld)
		sawWrite := false
		okFld := true
		for _, ffile := range wpd.p.Syntax {
			ast.Inspect(ffile, func(bn ast.Node) bool {
				if !okFld || bn == nil {
					return false
				}
				switch x := bn.(type) {
				case *ast.CompositeLit:
					clNamed := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x))
					if clNamed != sNamed || len(x.Elts) == 0 {
						return true
					}
					clSt, isSt := clNamed.Underlying().(*types.Struct)
					if !isSt {
						return true
					}
					if _, isKV0 := x.Elts[0].(*ast.KeyValueExpr); isKV0 {
						for _, elt := range x.Elts {
							kv, isKV := elt.(*ast.KeyValueExpr)
							if !isKV {
								okFld = false
								return false
							}
							kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
							if isID && wpd.p.TypesInfo.Uses[kid] == sfld {
								if !wpd.isSafeReflectZeroInterfaceOrQueryArg(kv.Value, visiting) {
									okFld = false
									return false
								}
								sawWrite = true
							}
						}
					} else {
						for i, elt := range x.Elts {
							if i < clSt.NumFields() && clSt.Field(i) == sfld {
								if !wpd.isSafeReflectZeroInterfaceOrQueryArg(elt, visiting) {
									okFld = false
									return false
								}
								sawWrite = true
							}
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
						if !isS || lsel.Sel == nil || wpd.p.TypesInfo.Uses[lsel.Sel] != sfld {
							continue
						}
						if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isSafeReflectZeroInterfaceOrQueryArg(x.Rhs[i], visiting) {
							okFld = false
							return false
						}
						sawWrite = true
					}
				}
				return true
			})
		}
		return okFld && sawWrite
	case *ast.IndexExpr:
		msel, isS := ast.Unparen(ae.X).(*ast.SelectorExpr)
		if !isS {
			return false
		}
		sInfo := wpd.p.TypesInfo.Selections[msel]
		if sInfo == nil || sInfo.Kind() != types.FieldVal {
			return false
		}
		mfld, _ := sInfo.Obj().(*types.Var)
		mNamed := syntaxutil.DerefNamedStruct(sInfo.Recv())
		if mfld == nil || !mfld.IsField() || mfld.Exported() || mfld.Pkg() != wpd.p.Types ||
			mNamed == nil || !wpd.capsuleStructs[mNamed] || wpd.reboundStructs[mNamed] {
			return false
		}
		if _, isMap := syntaxutil.UnderlyingType(mfld.Type()).(*types.Map); !isMap {
			return false
		}
		if visiting[mfld] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[mfld] {
			if parSel, isPS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isPS && parSel.Sel == uid {
				if u, isU := wpd.idx.ParentUnparen(parSel).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			} else if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
				return false
			}
		}
		visiting[mfld] = true
		defer delete(visiting, mfld)
		sawMapWrite := false
		okMap := true
		for _, ffile := range wpd.p.Syntax {
			ast.Inspect(ffile, func(bn ast.Node) bool {
				if !okMap || bn == nil {
					return false
				}
				switch x := bn.(type) {
				case *ast.KeyValueExpr:
					if kid, isID := ast.Unparen(x.Key).(*ast.Ident); isID && wpd.p.TypesInfo.Uses[kid] == mfld {
						if cl, isCL := ast.Unparen(x.Value).(*ast.CompositeLit); isCL && len(cl.Elts) > 0 {
							okMap = false
							return false
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						switch ln := ast.Unparen(lhs).(type) {
						case *ast.SelectorExpr:
							if ln.Sel != nil && wpd.p.TypesInfo.Uses[ln.Sel] == mfld {
								if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) {
									okMap = false
									return false
								}
								mc, isMC := ast.Unparen(x.Rhs[i]).(*ast.CallExpr)
								mid, isMID := (*ast.Ident)(nil), false
								if isMC {
									mid, isMID = ast.Unparen(mc.Fun).(*ast.Ident)
								}
								bObj, isB := (*types.Builtin)(nil), false
								if isMID {
									bObj, isB = wpd.p.TypesInfo.Uses[mid].(*types.Builtin)
								}
								if !isB || bObj.Name() != "make" {
									okMap = false
									return false
								}
							}
						case *ast.IndexExpr:
							if lsel, isLS := ast.Unparen(ln.X).(*ast.SelectorExpr); isLS && lsel.Sel != nil && wpd.p.TypesInfo.Uses[lsel.Sel] == mfld {
								if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isSafeReflectZeroInterfaceOrQueryArg(x.Rhs[i], visiting) {
									okMap = false
									return false
								}
								sawMapWrite = true
							}
						}
					}
				}
				return true
			})
		}
		return okMap && sawMapWrite
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isSafeLegacyReflectValueSource(rvExpr ast.Expr, visiting map[types.Object]bool) bool {
	if rvExpr == nil {
		return false
	}
	rvExpr = ast.Unparen(rvExpr)
	if !syntaxutil.IsNamedInPkg(wpd.p.TypesInfo.TypeOf(rvExpr), "reflect", "Value") {
		return false
	}
	switch re := rvExpr.(type) {
	case *ast.CallExpr:
		if re.Ellipsis.IsValid() {
			return false
		}
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, re.Fun)
		if callee == nil {
			return false
		}
		if wpd.methodClass[callee] == ptrMethodAsValue {
			return len(re.Args) == 1 && wpd.isStructOrCapsuleReflectTypeExpr(re.Args[0], map[types.Object]bool{})
		}
		if callee.Pkg() != nil && callee.Pkg().Path() == "reflect" {
			switch callee.Name() {
			case "ValueOf":
				return len(re.Args) == 1 && wpd.isSafeExportedTypeQueryIfaceArg(re.Args[0], visiting)
			case "New", "Zero":
				return len(re.Args) == 1 && wpd.isStructOrCapsuleReflectTypeExpr(re.Args[0], map[types.Object]bool{})
			case "Elem":
				sel, isS := ast.Unparen(re.Fun).(*ast.SelectorExpr)
				return len(re.Args) == 0 && isS && wpd.isSafeLegacyReflectValueSource(sel.X, visiting)
			case "Value":
				sel, isS := ast.Unparen(re.Fun).(*ast.SelectorExpr)
				return len(re.Args) == 0 && isS && syntaxutil.IsNamedInPkg(syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(sel.X)), "reflect", "MapIter")
			}
		}
		return false
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[re].(*types.Var)
		if v == nil || v.Pkg() != wpd.p.Types || v.Parent() == wpd.p.Types.Scope() {
			return false
		}
		if visiting[v] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[v] {
			if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
				return false
			}
		}
		visiting[v] = true
		defer delete(visiting, v)
		for fn, fd := range wpd.idx.FuncDecls {
			if fn == nil || fd == nil {
				continue
			}
			sig, okS := fn.Type().(*types.Signature)
			if !okS {
				continue
			}
			for pi := 0; pi < sig.Params().Len(); pi++ {
				if sig.Params().At(pi) != v {
					continue
				}
				if sig.Recv() == nil {
					if fn.Exported() || len(wpd.idx.UsesOf[fn]) == 0 {
						return false
					}
					for _, uid := range wpd.idx.UsesOf[v] {
						if refconfine.IdentIsWrittenOrAddrTaken(wpd.idx, uid) {
							return false
						}
					}
					for _, cuid := range wpd.idx.UsesOf[fn] {
						cc := refconfine.EnclosingCallOfCalleeIdent(wpd.idx, cuid)
						if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) || !wpd.isSafeLegacyReflectValueSource(cc.Args[pi], visiting) {
							return false
						}
					}
					return true
				}
				if pi != 0 || fd.Body == nil || len(fd.Body.List) == 0 || cachedScopeHasGoto(wpd.p, wpd.idx, fd.Body) ||
					fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
					return false
				}
				cRecv, _ := wpd.p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
				cNamed := syntaxutil.DerefNamedStruct(sig.Recv().Type())
				if cRecv == nil || cNamed == nil || cNamed.Obj() == nil || cNamed.Obj().Pkg() != wpd.p.Types || cNamed.Obj().Exported() || wpd.reboundStructs[cNamed] {
					return false
				}
				for _, ruid := range wpd.idx.UsesOf[cRecv] {
					if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, cRecv, ruid) {
						return false
					}
				}
				ifs, isIf := fd.Body.List[0].(*ast.IfStmt)
				if !isIf || ifs.Init != nil || ifs.Else != nil || ifs.Body == nil || len(ifs.Body.List) == 0 {
					return false
				}
				es, isES := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ExprStmt)
				if !isES {
					return false
				}
				pc, isPC := ast.Unparen(es.X).(*ast.CallExpr)
				if !isPC {
					return false
				}
				pid, isPID := ast.Unparen(pc.Fun).(*ast.Ident)
				if !isPID {
					return false
				}
				bObj, isB := wpd.p.TypesInfo.Uses[pid].(*types.Builtin)
				if !isB || bObj.Name() != "panic" {
					return false
				}
				bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
				if !isBin || bin.Op != token.NEQ {
					return false
				}
				checkConvGuard := func(vtExpr, gtExpr ast.Expr) bool {
					vc, isVC := ast.Unparen(vtExpr).(*ast.CallExpr)
					if !isVC || len(vc.Args) != 0 || vc.Ellipsis.IsValid() {
						return false
					}
					vsel, isVS := ast.Unparen(vc.Fun).(*ast.SelectorExpr)
					if !isVS || vsel.Sel == nil || vsel.Sel.Name != "Type" {
						return false
					}
					vid, isVID := ast.Unparen(vsel.X).(*ast.Ident)
					if !isVID || wpd.p.TypesInfo.Uses[vid] != v {
						return false
					}
					gsel, isGS := ast.Unparen(gtExpr).(*ast.SelectorExpr)
					if !isGS {
						return false
					}
					rid, isRID := ast.Unparen(gsel.X).(*ast.Ident)
					return isRID && wpd.p.TypesInfo.Uses[rid] == cRecv && wpd.isStructOrCapsuleReflectTypeExpr(gsel, map[types.Object]bool{})
				}
				if !checkConvGuard(bin.X, bin.Y) && !checkConvGuard(bin.Y, bin.X) {
					return false
				}
				reassignedOK := true
				ast.Inspect(fd.Body, func(bn ast.Node) bool {
					if !reassignedOK || bn == nil {
						return false
					}
					switch x := bn.(type) {
					case *ast.AssignStmt:
						for i, lhs := range x.Lhs {
							lid, isID := ast.Unparen(lhs).(*ast.Ident)
							if !isID || (wpd.p.TypesInfo.Uses[lid] != v && wpd.p.TypesInfo.Defs[lid] != v) {
								continue
							}
							if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) {
								reassignedOK = false
								return false
							}
							rc, isRC := ast.Unparen(x.Rhs[i]).(*ast.CallExpr)
							if !isRC || rc.Ellipsis.IsValid() {
								reassignedOK = false
								return false
							}
							rf := syntaxutil.ResolveCalledFuncObj(wpd.p, rc.Fun)
							if rf == nil || rf.Pkg() == nil || rf.Pkg().Path() != "reflect" {
								reassignedOK = false
								return false
							}
							if rf.Name() == "Addr" && len(rc.Args) == 0 {
								if rsel, isRS := ast.Unparen(rc.Fun).(*ast.SelectorExpr); isRS {
									if rid, isRID := ast.Unparen(rsel.X).(*ast.Ident); isRID && wpd.p.TypesInfo.Uses[rid] == v {
										continue
									}
								}
							}
							if rf.Name() == "Zero" && len(rc.Args) == 1 {
								continue
							}
							reassignedOK = false
							return false
						}
					case *ast.RangeStmt:
						for _, rk := range []ast.Expr{x.Key, x.Value} {
							if rid, isID := ast.Unparen(rk).(*ast.Ident); isID && (wpd.p.TypesInfo.Uses[rid] == v || wpd.p.TypesInfo.Defs[rid] == v) {
								reassignedOK = false
								return false
							}
						}
					}
					return true
				})
				return reassignedOK
			}
		}
		enclScope := declaringFuncOrLitBody(wpd.idx, re, v.Pos())
		if enclScope == nil || cachedScopeHasGoto(wpd.p, wpd.idx, enclScope) {
			return false
		}
		sawWrite := false
		localOK := true
		ast.Inspect(enclScope, func(bn ast.Node) bool {
			if !localOK || bn == nil {
				return false
			}
			switch x := bn.(type) {
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					if wpd.p.TypesInfo.Defs[nm] == v {
						if len(x.Values) == 0 || i >= len(x.Values) || !wpd.isSafeLegacyReflectValueSource(x.Values[i], visiting) {
							localOK = false
							return false
						}
						sawWrite = true
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID || (wpd.p.TypesInfo.Defs[lid] != v && wpd.p.TypesInfo.Uses[lid] != v) {
						continue
					}
					if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isSafeLegacyReflectValueSource(x.Rhs[i], visiting) {
						localOK = false
						return false
					}
					sawWrite = true
				}
			case *ast.RangeStmt:
				for _, rk := range []ast.Expr{x.Key, x.Value} {
					if rid, isID := ast.Unparen(rk).(*ast.Ident); isID && (wpd.p.TypesInfo.Defs[rid] == v || wpd.p.TypesInfo.Uses[rid] == v) {
						localOK = false
						return false
					}
				}
			}
			return true
		})
		return localOK && sawWrite
	}
	return false
}
