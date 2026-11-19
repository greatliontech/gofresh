package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) verifyCallSiteSinks() (bool, map[*types.Func]bool) {

	okDisc := true
	for _, file := range wpd.p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !okDisc || n == nil {
				return false
			}
			if mc, isMC := n.(*ast.CallExpr); isMC {
				if mfn := syntaxutil.ResolveCalledFuncObj(wpd.p, mc.Fun); mfn != nil && wpd.ownerMethods[mfn] {
					sel, isS := ast.Unparen(mc.Fun).(*ast.SelectorExpr)
					if !isS || mc.Ellipsis.IsValid() {
						okDisc = false
						return false
					}
					recvX := ast.Unparen(sel.X)
					rp := wpd.exprProv(recvX)
					deadDeleg := wpd.isDeadSelfRecvDelegation(mc, recvX)
					switch wpd.methodClass[mfn] {
					case ptrMethodIsNil:
						if ac, isAC := recvX.(*ast.CallExpr); isAC {
							if afn := syntaxutil.ResolveCalledFuncObj(wpd.p, ac.Fun); afn != nil && wpd.methodClass[afn] == ptrMethodAtomicLoad && len(ac.Args) == 0 {
								if asel, isAS := ast.Unparen(ac.Fun).(*ast.SelectorExpr); isAS && wpd.isInterfaceToPtrOnAnyParam(asel.X) {
									break
								}
							}
						}
						if (rp & provRaw) != 0 {
							okDisc = false
							return false
						}
					case ptrMethodApplyOffset:
						if len(mc.Args) != 1 {
							okDisc = false
							return false
						}
						if wpd.isProvenNonZeroOffset(mc.Args[0], map[types.Object]bool{}) {
							if (!deadDeleg && rp == 0) || (rp&^(provBase|provAtomicLoaded|provFresh)) != 0 {
								okDisc = false
								return false
							}
						} else if wpd.isZeroOffsetExpr(mc.Args[0]) {
							rc, isRC := recvX.(*ast.CallExpr)
							if !isRC || len(rc.Args) != 1 || rc.Ellipsis.IsValid() {
								okDisc = false
								return false
							}
							rcallee := syntaxutil.ResolveCalledFuncObj(wpd.p, rc.Fun)
							if rcallee == nil || !wpd.ptrCtorOfValue[rcallee] {
								okDisc = false
								return false
							}
							rvp := wpd.evalRVProv(rc.Args[0])
							if rvp == 0 || (rvp&^(rvFresh|rvOneofElem)) != 0 {
								okDisc = false
								return false
							}
						} else {
							okDisc = false
							return false
						}
					case ptrMethodAsIface:
						if (!deadDeleg && rp == 0) || (rp&provRaw) != 0 {
							okDisc = false
							return false
						}
						if (rp &^ (provApplied | provAtomicLoaded | provFresh)) != 0 {
							if len(mc.Args) != 1 || !wpd.isPairedBaseAsIfaceCall(recvX, mc.Args[0], true) {
								okDisc = false
								return false
							}
						}
					case ptrMethodAsValue:
						if enclFn, enclFL := wpd.enclCallable(mc); enclFL == nil && enclFn != nil && wpd.methodClass[enclFn] == ptrMethodAsIface {
							break
						}
						if (!deadDeleg && rp == 0) || (rp&provRaw) != 0 {
							okDisc = false
							return false
						}
						if (rp &^ (provApplied | provAtomicLoaded | provFresh)) != 0 {
							if len(mc.Args) != 1 || !wpd.isStructOrCapsuleReflectTypeExpr(mc.Args[0], map[types.Object]bool{}) ||
								!wpd.isReadOnlyReflectValueExpr(mc, map[*types.Var]bool{}) {
								okDisc = false
								return false
							}
							if _, _, _, usesCapGoType := wpd.exprRootCapsuleGoReflectTypeSelector(mc.Args[0], false); usesCapGoType &&
								!wpd.isPairedBaseAsIfaceCall(recvX, mc.Args[0], false) {
								okDisc = false
								return false
							}
						}
					case ptrMethodElemLoad:
						if (!deadDeleg && rp == 0) || (rp&^(provApplied|provFresh)) != 0 {
							okDisc = false
							return false
						}
					case ptrMethodAtomicLoad:
						if len(mc.Args) == 0 && wpd.isInterfaceToPtrOnAnyParam(recvX) {
							if parSel, isPS := wpd.idx.ParentUnparen(mc).(*ast.SelectorExpr); isPS && ast.Unparen(parSel.X) == mc {
								if parCall, isPC := wpd.idx.ParentUnparen(parSel).(*ast.CallExpr); isPC && ast.Unparen(parCall.Fun) == parSel {
									if pfn := syntaxutil.ResolveCalledFuncObj(wpd.p, parCall.Fun); pfn != nil && wpd.methodClass[pfn] == ptrMethodIsNil {
										break
									}
								}
							}
						}
						if (!deadDeleg && rp == 0) || (rp&^(provApplied|provFresh)) != 0 {
							okDisc = false
							return false
						}
						if len(mc.Args) == 1 {
							vp := wpd.exprProv(mc.Args[0])
							if (!deadDeleg && vp == 0) || (vp&provRaw) != 0 {
								okDisc = false
								return false
							}
						}
					case ptrMethodPointerSlice:
						if (!deadDeleg && rp == 0) || (rp&(provBase|provRaw)) != 0 {
							okDisc = false
							return false
						}
					case ptrMethodAppendPointerSlice:
						if len(mc.Args) != 1 || (!deadDeleg && rp == 0) || (rp&(provBase|provRaw)) != 0 {
							okDisc = false
							return false
						}
						vp := wpd.exprProv(mc.Args[0])
						if (!deadDeleg && vp == 0) || (vp&provRaw) != 0 {
							okDisc = false
							return false
						}
					case ptrMethodSetPointer:
						if len(mc.Args) != 1 {
							okDisc = false
							return false
						}
						if wpd.isInterfaceToPtrOnAnyParam(recvX) && wpd.isInterfaceToPtrOnAnyParam(mc.Args[0]) {
							break
						}
						if (!deadDeleg && rp == 0) || (rp&^(provApplied|provFresh)) != 0 {
							okDisc = false
							return false
						}
						vp := wpd.exprProv(mc.Args[0])
						if (!deadDeleg && vp == 0) || (vp&provRaw) != 0 {
							okDisc = false
							return false
						}
					default:
						if (!deadDeleg && rp == 0) || (rp&^(provApplied|provFresh)) != 0 {
							okDisc = false
							return false
						}
					}
				}
			}
			if wpd.isInsideContextSensitiveFunc(n) {
				return true
			}
			expr, isE := n.(ast.Expr)
			if !isE || ast.Unparen(expr) != expr {
				return true
			}
			tv := wpd.p.TypesInfo.Types[expr]
			if tv.IsType() || !tv.IsValue() || tv.Type == nil {
				return true
			}
			if tup, isTup := tv.Type.(*types.Tuple); isTup {
				if !wpd.tupleMentionsDstOwner(tup) {
					return true
				}
				par := wpd.idx.ParentUnparen(expr)
				switch pn := par.(type) {
				case *ast.ExprStmt:
					return true
				case *ast.ValueSpec:
					if len(pn.Values) != 1 || ast.Unparen(pn.Values[0]) != expr || len(pn.Names) != tup.Len() {
						okDisc = false
						return false
					}
					for ti := 0; ti < tup.Len(); ti++ {
						et := types.Unalias(tup.At(ti).Type())
						if types.Identical(et, wpd.dstOwner) && !wpd.isValidDstOwnerLHS(pn.Names[ti]) {
							okDisc = false
							return false
						}
						if wpd.isOwnerSliceType(et) && pn.Names[ti].Name != "_" {
							dv := wpd.defsOrUsesVar(pn.Names[ti])
							if dv == nil || !wpd.isOwnerSliceType(types.Unalias(dv.Type())) {
								okDisc = false
								return false
							}
						}
					}
					return true
				case *ast.AssignStmt:
					if (pn.Tok != token.ASSIGN && pn.Tok != token.DEFINE) || len(pn.Rhs) != 1 || ast.Unparen(pn.Rhs[0]) != expr || len(pn.Lhs) != tup.Len() {
						okDisc = false
						return false
					}
					for ti := 0; ti < tup.Len(); ti++ {
						et := types.Unalias(tup.At(ti).Type())
						if types.Identical(et, wpd.dstOwner) && !wpd.isValidDstOwnerLHS(pn.Lhs[ti]) {
							okDisc = false
							return false
						}
						if wpd.isOwnerSliceType(et) {
							lid, isID := ast.Unparen(pn.Lhs[ti]).(*ast.Ident)
							if !isID || (lid.Name != "_" && (wpd.defsOrUsesVar(lid) == nil || !wpd.isOwnerSliceType(types.Unalias(wpd.defsOrUsesVar(lid).Type())))) {
								okDisc = false
								return false
							}
						}
					}
					return true
				case *ast.ReturnStmt:
					fn, fl := wpd.enclCallable(pn)
					var sig *types.Signature
					if fn != nil {
						sig, _ = fn.Type().(*types.Signature)
					} else if fl != nil {
						sig, _ = wpd.p.TypesInfo.TypeOf(fl).(*types.Signature)
					}
					if sig == nil || len(pn.Results) != 1 || sig.Results().Len() != tup.Len() {
						okDisc = false
						return false
					}
					for ti := 0; ti < tup.Len(); ti++ {
						et := types.Unalias(tup.At(ti).Type())
						rt := types.Unalias(sig.Results().At(ti).Type())
						if (types.Identical(et, wpd.dstOwner) && !types.Identical(rt, wpd.dstOwner)) ||
							(wpd.isOwnerSliceType(et) && !wpd.isOwnerSliceType(rt)) {
							okDisc = false
							return false
						}
					}
					return true
				case *ast.CallExpr:
					if pn.Ellipsis.IsValid() || len(pn.Args) != 1 || ast.Unparen(pn.Args[0]) != expr || !wpd.isKnownIntraPkgCallee(pn) {
						okDisc = false
						return false
					}
					sig, okS := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(pn.Fun)).(*types.Signature)
					if !okS || sig.Variadic() || sig.Params().Len() != tup.Len() {
						okDisc = false
						return false
					}
					for ti := 0; ti < tup.Len(); ti++ {
						et := types.Unalias(tup.At(ti).Type())
						pt := types.Unalias(sig.Params().At(ti).Type())
						if (types.Identical(et, wpd.dstOwner) && !types.Identical(pt, wpd.dstOwner)) ||
							(wpd.isOwnerSliceType(et) && !wpd.isOwnerSliceType(pt)) {
							okDisc = false
							return false
						}
					}
					return true
				default:
					okDisc = false
					return false
				}
			}
			if wpd.isOwnerSliceType(tv.Type) {
				par := wpd.idx.ParentUnparen(expr)
				switch pn := par.(type) {
				case *ast.ExprStmt:
					return true
				case *ast.ValueSpec:
					if len(pn.Values) == len(pn.Names) {
						for i, val := range pn.Values {
							if ast.Unparen(val) == expr {
								if pn.Names[i].Name == "_" {
									return true
								}
								dv := wpd.defsOrUsesVar(pn.Names[i])
								if dv != nil && wpd.isOwnerSliceType(types.Unalias(dv.Type())) {
									return true
								}
							}
						}
					}
					okDisc = false
					return false
				case *ast.AssignStmt:
					if pn.Tok == token.ASSIGN || pn.Tok == token.DEFINE {
						for _, lhs := range pn.Lhs {
							if ast.Unparen(lhs) == expr {
								lid, isID := expr.(*ast.Ident)
								if !isID || (lid.Name != "_" && (wpd.defsOrUsesVar(lid) == nil || !wpd.isOwnerSliceType(types.Unalias(wpd.defsOrUsesVar(lid).Type())))) {
									okDisc = false
									return false
								}
								return true
							}
						}
					}
					if len(pn.Lhs) == len(pn.Rhs) {
						for i, rhs := range pn.Rhs {
							if ast.Unparen(rhs) == expr {
								lid, isID := ast.Unparen(pn.Lhs[i]).(*ast.Ident)
								if isID && (lid.Name == "_" || (wpd.defsOrUsesVar(lid) != nil && wpd.isOwnerSliceType(types.Unalias(wpd.defsOrUsesVar(lid).Type())))) {
									return true
								}
							}
						}
					}
					okDisc = false
					return false
				case *ast.RangeStmt:
					if ast.Unparen(pn.X) == expr {
						return true
					}
					okDisc = false
					return false
				case *ast.IndexExpr:
					if ast.Unparen(pn.X) == expr {
						return true
					}
					okDisc = false
					return false
				case *ast.CallExpr:
					if pn.Ellipsis.IsValid() || ast.Unparen(pn.Fun) == expr {
						okDisc = false
						return false
					}
					if bid, isBID := ast.Unparen(pn.Fun).(*ast.Ident); isBID {
						if bObj, isB := wpd.p.TypesInfo.Uses[bid].(*types.Builtin); isB && (bObj.Name() == "len" || bObj.Name() == "cap") && len(pn.Args) == 1 {
							return true
						}
					}
					if !wpd.isKnownIntraPkgCallee(pn) {
						okDisc = false
						return false
					}
					sig, okS := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(pn.Fun)).(*types.Signature)
					if !okS || sig.Variadic() {
						okDisc = false
						return false
					}
					for ai, arg := range pn.Args {
						if ast.Unparen(arg) == expr {
							if ai >= sig.Params().Len() || !wpd.isOwnerSliceType(types.Unalias(sig.Params().At(ai).Type())) {
								okDisc = false
								return false
							}
							return true
						}
					}
					okDisc = false
					return false
				default:
					okDisc = false
					return false
				}
			}
			if !types.Identical(types.Unalias(tv.Type), wpd.dstOwner) {
				return true
			}
			par := wpd.idx.ParentUnparen(expr)
			switch pn := par.(type) {
			case *ast.ExprStmt:
				return true
			case *ast.ValueSpec:
				if len(pn.Values) == len(pn.Names) {
					for i, val := range pn.Values {
						if ast.Unparen(val) == expr {
							if wpd.isValidDstOwnerLHS(pn.Names[i]) {
								return true
							}
						}
					}
				}
				okDisc = false
				return false
			case *ast.AssignStmt:
				if pn.Tok == token.ASSIGN || pn.Tok == token.DEFINE {
					for _, lhs := range pn.Lhs {
						if ast.Unparen(lhs) == expr {
							if !wpd.isValidDstOwnerLHS(lhs) {
								okDisc = false
								return false
							}
							return true
						}
					}
				}
				if len(pn.Lhs) != len(pn.Rhs) {
					okDisc = false
					return false
				}
				for i, rhs := range pn.Rhs {
					if ast.Unparen(rhs) == expr {
						if wpd.isValidDstOwnerLHS(pn.Lhs[i]) {
							return true
						}
					}
				}
				okDisc = false
				return false
			case *ast.RangeStmt:
				if (pn.Key != nil && ast.Unparen(pn.Key) == expr && wpd.isValidDstOwnerLHS(pn.Key)) ||
					(pn.Value != nil && ast.Unparen(pn.Value) == expr && wpd.isValidDstOwnerLHS(pn.Value)) {
					return true
				}
				okDisc = false
				return false
			case *ast.ReturnStmt:
				fn, fl := wpd.enclCallable(pn)
				var sig *types.Signature
				if fn != nil {
					sig, _ = fn.Type().(*types.Signature)
				} else if fl != nil {
					sig, _ = wpd.p.TypesInfo.TypeOf(fl).(*types.Signature)
				}
				if sig == nil || len(pn.Results) != sig.Results().Len() {
					okDisc = false
					return false
				}
				for ri, res := range pn.Results {
					if ast.Unparen(res) == expr {
						if !types.Identical(types.Unalias(sig.Results().At(ri).Type()), wpd.dstOwner) {
							okDisc = false
							return false
						}
						return true
					}
				}
				okDisc = false
				return false
			case *ast.KeyValueExpr:
				if ast.Unparen(pn.Value) != expr {
					okDisc = false
					return false
				}
				cl, isCL := wpd.idx.ParentUnparen(pn).(*ast.CompositeLit)
				if !isCL {
					okDisc = false
					return false
				}
				if _, isSt := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(cl)).(*types.Struct); !isSt {
					okDisc = false
					return false
				}
				kid, isKID := ast.Unparen(pn.Key).(*ast.Ident)
				if !isKID {
					okDisc = false
					return false
				}
				fobj := wpd.p.TypesInfo.Uses[kid]
				if fobj == nil || !types.Identical(types.Unalias(fobj.Type()), wpd.dstOwner) {
					okDisc = false
					return false
				}
				return true
			case *ast.CompositeLit:
				st, isSt := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(pn)).(*types.Struct)
				if !isSt {
					okDisc = false
					return false
				}
				for i, elt := range pn.Elts {
					if ast.Unparen(elt) == expr && i < st.NumFields() {
						fobj := st.Field(i)
						if types.Identical(types.Unalias(fobj.Type()), wpd.dstOwner) {
							return true
						}
					}
				}
				okDisc = false
				return false
			case *ast.SelectorExpr:
				if ast.Unparen(pn.X) != expr {
					okDisc = false
					return false
				}
				if sInfo := wpd.p.TypesInfo.Selections[pn]; sInfo != nil && sInfo.Kind() == types.FieldVal {
					if sInfo.Obj() == wpd.dstFld {
						if fn, fl := wpd.enclCallable(pn); fl == nil && fn != nil && wpd.ownerMethods[fn] {
							if mfd := wpd.idx.FuncDecls[fn]; mfd != nil && mfd.Recv != nil && len(mfd.Recv.List) == 1 && len(mfd.Recv.List[0].Names) == 1 {
								rv, _ := wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
								if rid, isRID := expr.(*ast.Ident); isRID && rv != nil && wpd.p.TypesInfo.Uses[rid] == rv {
									return true
								}
							}
						}
						okDisc = false
						return false
					}
					if fn, fl := wpd.enclCallable(pn); fl == nil && fn != nil && !fn.Exported() && len(wpd.idx.UsesOf[fn]) == 0 {
						return true
					}
					okDisc = false
					return false
				}
				oc, isOC := wpd.idx.ParentUnparen(pn).(*ast.CallExpr)
				if !isOC || ast.Unparen(oc.Fun) != pn {
					okDisc = false
					return false
				}
				mfn := syntaxutil.ResolveCalledFuncObj(wpd.p, oc.Fun)
				if mfn == nil || !wpd.ownerMethods[mfn] {
					okDisc = false
					return false
				}
				return true
			case *ast.CallExpr:
				if pn.Ellipsis.IsValid() || ast.Unparen(pn.Fun) == expr {
					okDisc = false
					return false
				}
				sig, okS := syntaxutil.UnderlyingType(wpd.p.TypesInfo.TypeOf(pn.Fun)).(*types.Signature)
				if !okS {
					okDisc = false
					return false
				}
				for ai, arg := range pn.Args {
					if ast.Unparen(arg) == expr {
						pi := ai
						if sig.Variadic() && ai >= sig.Params().Len()-1 {
							pi = sig.Params().Len() - 1
						}
						if pi >= sig.Params().Len() {
							okDisc = false
							return false
						}
						pt := types.Unalias(sig.Params().At(pi).Type())
						if sig.Variadic() && pi == sig.Params().Len()-1 {
							if !wpd.isOwnerSliceType(pt) {
								okDisc = false
								return false
							}
						} else if !types.Identical(pt, wpd.dstOwner) {
							okDisc = false
							return false
						}
						break
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(wpd.p, pn.Fun)
				if callee != nil {
					if wpd.idx.FuncDecls[callee] == nil {
						okDisc = false
						return false
					}
					return true
				}
				if !wpd.isKnownIntraPkgCallee(pn) {
					okDisc = false
					return false
				}
				return true
			default:
				okDisc = false
				return false
			}
		})
	}
	if !okDisc {
		return false, nil
	}
	gated := map[*types.Func]bool{}
	for mfn := range wpd.ownerMethods {
		if (wpd.methodClass[mfn] == ptrMethodRawDeref || wpd.methodClass[mfn] == ptrMethodPointerSlice || wpd.methodClass[mfn] == ptrMethodAppendPointerSlice) &&
			len(wpd.idx.UsesOf[mfn]) > 0 {
			gated[mfn] = true
		}
	}
	return true, gated

}

func (wpd *wrapperPtrDiscipline) extractOneStmtFieldGetter(expr ast.Expr) (*types.Var, *types.Var, bool) {
	expr = ast.Unparen(expr)
	if sel, isS := expr.(*ast.SelectorExpr); isS {
		if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal && len(sInfo.Index()) == 1 {
			fld, _ := sInfo.Obj().(*types.Var)
			rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
			if fld != nil && isRID {
				if rv, _ := wpd.p.TypesInfo.Uses[rid].(*types.Var); rv != nil {
					return rv, fld, true
				}
			}
		}
		return nil, nil, false
	}
	mc, isMC := expr.(*ast.CallExpr)
	if !isMC || len(mc.Args) != 0 || mc.Ellipsis.IsValid() {
		return nil, nil, false
	}
	msel, isMS := ast.Unparen(mc.Fun).(*ast.SelectorExpr)
	if !isMS {
		return nil, nil, false
	}
	rid, isRID := ast.Unparen(msel.X).(*ast.Ident)
	if !isRID {
		return nil, nil, false
	}
	rv, _ := wpd.p.TypesInfo.Uses[rid].(*types.Var)
	mfn := syntaxutil.ResolveCalledFuncObj(wpd.p, mc.Fun)
	if rv == nil || mfn == nil || mfn.Pkg() != wpd.p.Types {
		return nil, nil, false
	}
	mfd := wpd.idx.FuncDecls[mfn]
	if mfd == nil || mfd.Body == nil || len(mfd.Body.List) != 1 || mfd.Recv == nil || len(mfd.Recv.List) != 1 || len(mfd.Recv.List[0].Names) != 1 {
		return nil, nil, false
	}
	mRecv, _ := wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
	ret, isRet := mfd.Body.List[0].(*ast.ReturnStmt)
	if mRecv == nil || !isRet || len(ret.Results) != 1 {
		return nil, nil, false
	}
	fsel, isFS := ast.Unparen(ret.Results[0]).(*ast.SelectorExpr)
	if !isFS {
		return nil, nil, false
	}
	fInfo := wpd.p.TypesInfo.Selections[fsel]
	if fInfo == nil || fInfo.Kind() != types.FieldVal || len(fInfo.Index()) != 1 {
		return nil, nil, false
	}
	frid, isFRID := ast.Unparen(fsel.X).(*ast.Ident)
	fld, _ := fInfo.Obj().(*types.Var)
	if !isFRID || wpd.p.TypesInfo.Uses[frid] != mRecv || fld == nil {
		return nil, nil, false
	}
	return rv, fld, true
}

func (wpd *wrapperPtrDiscipline) methodLoadsForeignCapsuleField(mfn *types.Func, capNamed *types.Named, visiting map[*types.Func]bool) bool {
	if mfn == nil || mfn.Pkg() != wpd.p.Types {
		return false
	}
	if visiting[mfn] {
		return true
	}
	mfd := wpd.idx.FuncDecls[mfn]
	if mfd == nil || mfd.Body == nil || blockHasGoto(mfd.Body) || mfd.Recv == nil || len(mfd.Recv.List) != 1 || len(mfd.Recv.List[0].Names) != 1 {
		return false
	}
	mRecv, _ := wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
	if mRecv == nil {
		return false
	}
	for _, ruid := range wpd.idx.UsesOf[mRecv] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, mRecv, ruid) {
			return false
		}
	}
	visiting[mfn] = true
	defer delete(visiting, mfn)
	var isRecvForeignCapExpr func(re ast.Expr, varVis map[*types.Var]bool) bool
	isRecvForeignCapExpr = func(re ast.Expr, varVis map[*types.Var]bool) bool {
		if re == nil {
			return false
		}
		re = ast.Unparen(re)
		if syntaxutil.IsNilIdent(wpd.p.TypesInfo, re) {
			return true
		}
		switch rx := re.(type) {
		case *ast.SelectorExpr:
			sInfo := wpd.p.TypesInfo.Selections[rx]
			if sInfo == nil || sInfo.Kind() != types.FieldVal {
				return false
			}
			fld, _ := sInfo.Obj().(*types.Var)
			rid, isRID := ast.Unparen(rx.X).(*ast.Ident)
			return fld != nil && wpd.foreignReflectFields[fld] && isRID && wpd.p.TypesInfo.Uses[rid] == mRecv
		case *ast.CallExpr:
			if len(rx.Args) == 1 && !rx.Ellipsis.IsValid() && wpd.p.TypesInfo.Types[ast.Unparen(rx.Fun)].IsType() {
				if !types.Identical(types.Unalias(wpd.p.TypesInfo.Types[ast.Unparen(rx.Fun)].Type), types.NewPointer(capNamed)) {
					return false
				}
				lc, isLC := ast.Unparen(rx.Args[0]).(*ast.CallExpr)
				if !isLC || len(lc.Args) != 1 || lc.Ellipsis.IsValid() {
					return false
				}
				lfn := syntaxutil.ResolveCalledFuncObj(wpd.p, lc.Fun)
				if lfn == nil || lfn.Pkg() == nil || lfn.Pkg().Path() != "sync/atomic" || lfn.Name() != "LoadPointer" {
					return false
				}
				// Unwrap (*unsafe.Pointer)(unsafe.Pointer(&mRecv.fld))
				slotConv, isSC := ast.Unparen(lc.Args[0]).(*ast.CallExpr)
				if !isSC || len(slotConv.Args) != 1 {
					return false
				}
				upConv, isUP := ast.Unparen(slotConv.Args[0]).(*ast.CallExpr)
				if !isUP || len(upConv.Args) != 1 {
					return false
				}
				uand, isUA := ast.Unparen(upConv.Args[0]).(*ast.UnaryExpr)
				if !isUA || uand.Op != token.AND {
					return false
				}
				fsel, isFS := ast.Unparen(uand.X).(*ast.SelectorExpr)
				if !isFS {
					return false
				}
				fInfo := wpd.p.TypesInfo.Selections[fsel]
				if fInfo == nil || fInfo.Kind() != types.FieldVal {
					return false
				}
				fld, _ := fInfo.Obj().(*types.Var)
				rid, isRID := ast.Unparen(fsel.X).(*ast.Ident)
				return fld != nil && wpd.foreignReflectFields[fld] && isRID && wpd.p.TypesInfo.Uses[rid] == mRecv
			}
			if len(rx.Args) == 0 && !rx.Ellipsis.IsValid() {
				csel, isCS := ast.Unparen(rx.Fun).(*ast.SelectorExpr)
				if !isCS {
					return false
				}
				rid, isRID := ast.Unparen(csel.X).(*ast.Ident)
				cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, rx.Fun)
				return isRID && wpd.p.TypesInfo.Uses[rid] == mRecv && wpd.methodLoadsForeignCapsuleField(cfn, capNamed, visiting)
			}
		case *ast.Ident:
			lv, _ := wpd.p.TypesInfo.Uses[rx].(*types.Var)
			if lv == nil || lv.Parent() == wpd.p.Types.Scope() {
				return false
			}
			if varVis[lv] {
				return true
			}
			for _, uid := range wpd.idx.UsesOf[lv] {
				if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			}
			varVis[lv] = true
			defer delete(varVis, lv)
			sawW := false
			okW := true
			ast.Inspect(mfd.Body, func(bn ast.Node) bool {
				if !okW || bn == nil {
					return false
				}
				switch sx := bn.(type) {
				case *ast.ValueSpec:
					for i, nm := range sx.Names {
						if wpd.p.TypesInfo.Defs[nm] == lv {
							if len(sx.Values) == 0 || i >= len(sx.Values) || !isRecvForeignCapExpr(sx.Values[i], varVis) {
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
						if len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) || !isRecvForeignCapExpr(sx.Rhs[i], varVis) {
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
	sawRet := false
	okRet := true
	ast.Inspect(mfd.Body, func(bn ast.Node) bool {
		if !okRet || bn == nil {
			return false
		}
		if _, isFL := bn.(*ast.FuncLit); isFL {
			return false
		}
		ret, isR := bn.(*ast.ReturnStmt)
		if !isR {
			return true
		}
		sawRet = true
		if len(ret.Results) != 1 || !isRecvForeignCapExpr(ret.Results[0], map[*types.Var]bool{}) {
			okRet = false
			return false
		}
		return false
	})
	return sawRet && okRet
}

func (wpd *wrapperPtrDiscipline) exprRootCapsuleGoReflectTypeSelector(typeArg ast.Expr, requireElem bool) (*ast.SelectorExpr, *types.Named, *types.Var, bool) {
	cur := ast.Unparen(typeArg)
	sawElem := false
	for {
		ec, isEC := cur.(*ast.CallExpr)
		if !isEC || len(ec.Args) != 0 || ec.Ellipsis.IsValid() {
			break
		}
		efn := syntaxutil.ResolveCalledFuncObj(wpd.p, ec.Fun)
		esel, isES := ast.Unparen(ec.Fun).(*ast.SelectorExpr)
		if efn == nil || efn.Pkg() == nil || efn.Pkg().Path() != "reflect" || efn.Name() != "Elem" || !isES {
			return nil, nil, nil, false
		}
		sawElem = true
		cur = ast.Unparen(esel.X)
	}
	if requireElem && !sawElem {
		return nil, nil, nil, false
	}
	fsel, isFS := cur.(*ast.SelectorExpr)
	if !isFS {
		return nil, nil, nil, false
	}
	sInfo := wpd.p.TypesInfo.Selections[fsel]
	if sInfo == nil || sInfo.Kind() != types.FieldVal || len(sInfo.Index()) != 1 {
		return nil, nil, nil, false
	}
	sfld, _ := sInfo.Obj().(*types.Var)
	ownerN := syntaxutil.DerefNamedStruct(sInfo.Recv())
	if sfld == nil || ownerN == nil || !wpd.capsuleStructs[ownerN] {
		return nil, nil, nil, false
	}
	return fsel, ownerN, sfld, true
}

func (wpd *wrapperPtrDiscipline) isPairedBaseAsIfaceCall(recvX ast.Expr, typeArg ast.Expr, requireElem bool) bool {
	fsel, ownerN, sfld, okRoot := wpd.exprRootCapsuleGoReflectTypeSelector(typeArg, requireElem)
	if !okRoot || !wpd.isVerifiedCapsuleGoReflectTypeField(ownerN, sfld) {
		return false
	}
	infoExpr := ast.Unparen(fsel.X)
	// Case A: recvX is baseVar.pointer() on *messageState (seedBaseMethods) and infoExpr loads baseVar's foreignReflectFields.
	if rc, isRC := ast.Unparen(recvX).(*ast.CallExpr); isRC && len(rc.Args) == 0 && !rc.Ellipsis.IsValid() {
		rcallee := syntaxutil.ResolveCalledFuncObj(wpd.p, rc.Fun)
		if rcallee != nil && wpd.seedBaseMethods[rcallee] {
			rsel, isRS := ast.Unparen(rc.Fun).(*ast.SelectorExpr)
			rid, isRID := (*ast.Ident)(nil), false
			if isRS {
				rid, isRID = ast.Unparen(rsel.X).(*ast.Ident)
			}
			baseVar := (*types.Var)(nil)
			if isRID {
				baseVar, _ = wpd.p.TypesInfo.Uses[rid].(*types.Var)
			}
			if baseVar == nil {
				return false
			}
			for _, buid := range wpd.idx.UsesOf[baseVar] {
				if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, baseVar, buid) {
					return false
				}
			}
			if isel, isIS := infoExpr.(*ast.SelectorExpr); isIS {
				if sInfo := wpd.p.TypesInfo.Selections[isel]; sInfo != nil && sInfo.Kind() == types.FieldVal {
					fld, _ := sInfo.Obj().(*types.Var)
					iid, isIID := ast.Unparen(isel.X).(*ast.Ident)
					return fld != nil && wpd.foreignReflectFields[fld] && isIID && wpd.p.TypesInfo.Uses[iid] == baseVar
				}
			}
			if ic, isIC := infoExpr.(*ast.CallExpr); isIC && len(ic.Args) == 0 && !ic.Ellipsis.IsValid() {
				isel, isIS := ast.Unparen(ic.Fun).(*ast.SelectorExpr)
				if !isIS {
					return false
				}
				iid, isIID := ast.Unparen(isel.X).(*ast.Ident)
				ifn := syntaxutil.ResolveCalledFuncObj(wpd.p, ic.Fun)
				return isIID && wpd.p.TypesInfo.Uses[iid] == baseVar && wpd.methodLoadsForeignCapsuleField(ifn, ownerN, map[*types.Func]bool{})
			}
			return false
		}
	}
	// Case B: recvX and infoExpr read (ptrFld, capFld) on the same unmutated {p, mi} pair-struct variable.
	baseVar, ptrFld, okPtr := wpd.extractOneStmtFieldGetter(recvX)
	infoVar, capFld, okCap := wpd.extractOneStmtFieldGetter(infoExpr)
	if !okPtr || !okCap || baseVar == nil || baseVar != infoVar {
		return false
	}
	for _, buid := range wpd.idx.UsesOf[baseVar] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, baseVar, buid) {
			return false
		}
	}
	wNamed := syntaxutil.DerefNamedStruct(baseVar.Type())
	return wpd.isVerifiedCapsulePairStruct(wNamed, ptrFld, capFld, ownerN)
}

func (wpd *wrapperPtrDiscipline) isKnownIntraPkgCallee(pn *ast.CallExpr) bool {
	if wpd.p.TypesInfo.Types[ast.Unparen(pn.Fun)].IsType() {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(wpd.p, pn.Fun)
	if callee != nil {
		return wpd.idx.FuncDecls[callee] != nil && !wpd.contextSensitiveFuncs[callee]
	}
	funExpr := ast.Unparen(pn.Fun)
	if _, isFL := funExpr.(*ast.FuncLit); isFL {
		return true
	}
	if sel, isS := funExpr.(*ast.SelectorExpr); isS {
		if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal {
			fobj := sInfo.Obj()
			return !wpd.unknownSourceFields[fobj] && (len(wpd.funcLitsForField[fobj]) > 0 || len(wpd.funcObjsForField[fobj]) > 0)
		}
	} else if cid, isID := funExpr.(*ast.Ident); isID {
		if lv, _ := wpd.p.TypesInfo.Uses[cid].(*types.Var); lv != nil {
			return !wpd.unknownSourceLocals[lv] && (len(wpd.funcLitsForLocal[lv]) > 0 || len(wpd.funcObjsForLocal[lv]) > 0)
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) isValidDstOwnerLHS(lhs ast.Expr) bool {
	lhs = ast.Unparen(lhs)
	if lid, isID := lhs.(*ast.Ident); isID {
		if lid.Name == "_" {
			return true
		}
		lv := wpd.defsOrUsesVar(lid)
		return lv != nil && types.Identical(types.Unalias(lv.Type()), wpd.dstOwner)
	}
	if sel, isS := lhs.(*ast.SelectorExpr); isS {
		sInfo := wpd.p.TypesInfo.Selections[sel]
		return sInfo != nil && sInfo.Kind() == types.FieldVal && types.Identical(types.Unalias(sInfo.Obj().Type()), wpd.dstOwner)
	}
	if ix, isIX := lhs.(*ast.IndexExpr); isIX {
		if sid, isID := ast.Unparen(ix.X).(*ast.Ident); isID {
			sv := wpd.defsOrUsesVar(sid)
			return sv != nil && wpd.isOwnerSliceType(types.Unalias(sv.Type()))
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) tupleMentionsDstOwner(tup *types.Tuple) bool {
	if tup == nil {
		return false
	}
	for i := 0; i < tup.Len(); i++ {
		et := types.Unalias(tup.At(i).Type())
		if types.Identical(et, wpd.dstOwner) || wpd.isOwnerSliceType(et) {
			return true
		}
	}
	return false
}
