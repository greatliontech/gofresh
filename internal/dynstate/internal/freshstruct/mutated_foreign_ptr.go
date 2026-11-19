package freshstruct

import (
	"context"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type foreignPtrConvClass struct {
	isCapsuleWrapper bool
	capStruct        syntaxutil.TypeRef
	capParam         syntaxutil.ParamKey
	isAtomicPtrCopy  bool
	atomicCopyFn     syntaxutil.FuncKey
}

func extractForeignWrapperCapStruct(
	p *packages.Package,
	elemNamed *types.Named,
	wantPkg *types.Package,
) (*types.Named, *types.Named, syntaxutil.TypeRef, bool) {
	if p == nil || elemNamed == nil || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != p.Types || elemNamed.TypeParams() != nil {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	st, isSt := elemNamed.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	var firstField *types.Var
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if isZeroSizedPaddingType(f.Type()) {
			continue
		}
		firstField = f
		break
	}
	if firstField == nil || firstField.Embedded() {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	wPub, isWP := types.Unalias(firstField.Type()).(*types.Named)
	if !isWP || wPub.Obj() == nil || wPub.Obj().Pkg() != wantPkg || wPub.TypeParams() != nil {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	wSt, isWSt := wPub.Underlying().(*types.Struct)
	if !isWSt || wSt.NumFields() == 0 {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	var capField *types.Var
	for i := 0; i < wSt.NumFields(); i++ {
		wf := wSt.Field(i)
		if wf.Exported() && !(wf.Embedded() && isZeroSizedPaddingType(wf.Type())) {
			return nil, nil, syntaxutil.TypeRef{}, false
		}
		if isZeroSizedPaddingType(wf.Type()) {
			if capField != nil {
				return nil, nil, syntaxutil.TypeRef{}, false
			}
			continue
		}
		if capField != nil || wf.Embedded() {
			return nil, nil, syntaxutil.TypeRef{}, false
		}
		capField = wf
	}
	if capField == nil {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	capPtr, isCP := types.Unalias(capField.Type()).(*types.Pointer)
	if !isCP {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	capNamed, isCN := types.Unalias(capPtr.Elem()).(*types.Named)
	if !isCN || capNamed.Obj() == nil || capNamed.Obj().Pkg() != wantPkg {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	ref := syntaxutil.TypeRef{Pkg: wantPkg.Path(), Name: capNamed.Obj().Name()}
	if !ref.Valid() {
		return nil, nil, syntaxutil.TypeRef{}, false
	}
	return wPub, capNamed, ref, true
}

func isVerifiedForeignCapsuleSetterCall(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	clusterCapsuleElemTypes map[*types.Var][]*types.Named,
	call *ast.CallExpr,
	capNamed, wPriv *types.Named,
) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || call == nil || capNamed == nil || wPriv == nil || capNamed.Obj() == nil {
		return false
	}
	qPkg := capNamed.Obj().Pkg()
	if qPkg == nil || qPkg == p.Types {
		return false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	extractClusterIndexedMsgElem := func(expr ast.Expr) *types.Named {
		expr = ast.Unparen(expr)
		if id, isID := expr.(*ast.Ident); isID {
			v, _ := p.TypesInfo.Uses[id].(*types.Var)
			if v == nil || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() || idx.DefCounts[v] != 1 {
				return nil
			}
			for _, u := range idx.UsesOf[v] {
				if identIsWrittenAddrOrAutoAddr(p, idx, v, u) {
					return nil
				}
			}
			var rhs ast.Expr
			if vs := idx.VarSpecs[v]; vs != nil && len(vs.Names) == 1 && len(vs.Values) == 1 {
				rhs = vs.Values[0]
			} else {
				encl := innermostFuncOrLitBody(idx, id)
				if encl != nil {
					ast.Inspect(encl, func(n ast.Node) bool {
						as, isAS := n.(*ast.AssignStmt)
						if isAS && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
							if lid, okL := ast.Unparen(as.Lhs[0]).(*ast.Ident); okL && p.TypesInfo.Defs[lid] == v {
								rhs = as.Rhs[0]
								return false
							}
						}
						return true
					})
				}
			}
			if rhs == nil {
				return nil
			}
			expr = ast.Unparen(rhs)
		}
		un, isUn := expr.(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return nil
		}
		ie, isIE := ast.Unparen(un.X).(*ast.IndexExpr)
		if !isIE {
			return nil
		}
		sliceVar := syntaxutil.LookupPkgScopeVar(p, ie.X)
		if sliceVar == nil {
			return nil
		}
		elemTypes, okCluster := clusterCapsuleElemTypes[sliceVar]
		if !okCluster {
			return nil
		}
		tv := p.TypesInfo.Types[ie.Index]
		if tv.Value == nil || tv.Value.Kind() != constant.Int {
			return nil
		}
		k, okK := constant.Int64Val(tv.Value)
		if !okK || k < 0 || int(k) >= len(elemTypes) {
			return nil
		}
		return elemTypes[int(k)]
	}

	var msCall *ast.CallExpr
	recvExpr := ast.Unparen(sel.X)
	if c, isC := recvExpr.(*ast.CallExpr); isC {
		msCall = c
	} else if rid, isRID := recvExpr.(*ast.Ident); isRID {
		mv, _ := p.TypesInfo.Uses[rid].(*types.Var)
		if mv != nil && mv.Pkg() == p.Types && mv.Parent() != p.Types.Scope() && idx.DefCounts[mv] == 1 {
			cleanMV := true
			for _, mu := range idx.UsesOf[mv] {
				if identIsWrittenAddrOrAutoAddr(p, idx, mv, mu) {
					cleanMV = false
					break
				}
			}
			if cleanMV {
				encl := innermostFuncOrLitBody(idx, rid)
				if encl != nil {
					ast.Inspect(encl, func(bn ast.Node) bool {
						as, isAS := bn.(*ast.AssignStmt)
						if isAS && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
							if lid, okL := ast.Unparen(as.Lhs[0]).(*ast.Ident); okL && p.TypesInfo.Defs[lid] == mv {
								msCall, _ = ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
								return false
							}
						}
						return true
					})
				}
			}
		}
	}
	if msCall == nil || len(msCall.Args) != 1 || msCall.Ellipsis.IsValid() {
		return false
	}
	msCallee := syntaxutil.ResolveCalledFuncObj(p, msCall.Fun)
	if msCallee == nil || msCallee.Origin().Pkg() != qPkg {
		return false
	}
	ptrConv, isPC := ast.Unparen(msCall.Args[0]).(*ast.CallExpr)
	if !isPC || len(ptrConv.Args) != 1 || ptrConv.Ellipsis.IsValid() {
		return false
	}
	ptrTV := p.TypesInfo.Types[ast.Unparen(ptrConv.Fun)]
	if !ptrTV.IsType() || !syntaxutil.IsUnsafePointerType(ptrTV.Type) {
		return false
	}
	recvPtrT, isRP := types.Unalias(p.TypesInfo.TypeOf(ptrConv.Args[0])).(*types.Pointer)
	if !isRP {
		return false
	}
	recvElem, isRN := types.Unalias(recvPtrT.Elem()).(*types.Named)
	wantElem := extractClusterIndexedMsgElem(call.Args[0])
	if !isRN || recvElem == nil || wantElem == nil || !types.Identical(recvElem, wantElem) {
		return false
	}
	wPub, gotCap, _, okW := extractForeignWrapperCapStruct(p, recvElem, qPkg)
	return okW && gotCap == capNamed && types.IdenticalIgnoreTags(wPriv.Underlying(), wPub.Underlying())
}

func classifyForeignUnsafePtrConvs(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	exempted map[ast.Node]bool,
	clusterCapsuleElemTypes map[*types.Var][]*types.Named,
) (map[*ast.CallExpr]foreignPtrConvClass, bool) {
	classes := map[*ast.CallExpr]foreignPtrConvClass{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return classes, false
	}
	verifiedCapSetters := map[*types.Named]bool{}
	checkedCapSetters := map[*types.Named]bool{}
	verifyPkgCapsuleSetterPairing := func(capNamed, wPriv *types.Named) bool {
		if checkedCapSetters[capNamed] {
			return verifiedCapSetters[capNamed]
		}
		checkedCapSetters[capNamed] = true
		capPtr := types.NewPointer(capNamed)
		okPair := true
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !okPair || n == nil || exempted[n] {
					return false
				}
				switch x := n.(type) {
				case *ast.CompositeLit:
					if len(x.Elts) > 0 && syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == capNamed {
						okPair = false
						return false
					}
				case *ast.SelectorExpr:
					if selInfo := p.TypesInfo.Selections[x]; selInfo != nil {
						if selInfo.Kind() == types.FieldVal {
							if syntaxutil.DerefNamedStruct(selInfo.Recv()) == capNamed && refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, x) {
								okPair = false
								return false
							}
						} else if selInfo.Kind() == types.MethodVal || selInfo.Kind() == types.MethodExpr {
							if sig, okS := syntaxutil.UnderlyingType(selInfo.Type()).(*types.Signature); okS {
								for pi := 0; pi < sig.Params().Len(); pi++ {
									if types.Identical(types.Unalias(sig.Params().At(pi).Type()), capPtr) {
										parCall, isPC := idx.ParentUnparen(x).(*ast.CallExpr)
										if !isPC || ast.Unparen(parCall.Fun) != x {
											okPair = false
											return false
										}
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
					if callee == nil {
						if sig, okS := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Fun)).(*types.Signature); okS {
							for pi := 0; pi < sig.Params().Len(); pi++ {
								if types.Identical(types.Unalias(sig.Params().At(pi).Type()), capPtr) {
									okPair = false
									return false
								}
							}
						}
						return true
					}
					sig, okS := callee.Type().(*types.Signature)
					if !okS || sig.Recv() == nil {
						return true
					}
					takesCap := false
					for pi := 0; pi < sig.Params().Len(); pi++ {
						if types.Identical(types.Unalias(sig.Params().At(pi).Type()), capPtr) {
							takesCap = true
							break
						}
					}
					if !takesCap {
						return true
					}
					if types.IsInterface(sig.Recv().Type()) ||
						syntaxutil.DerefNamedStruct(sig.Recv().Type()) != wPriv ||
						!isVerifiedForeignCapsuleSetterCall(p, idx, clusterCapsuleElemTypes, x, capNamed, wPriv) {
						okPair = false
						return false
					}
				}
				return true
			})
		}
		verifiedCapSetters[capNamed] = okPair
		return okPair
	}

	unconfinedForeignUnsafe := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil || exempted[n] {
				return false
			}
			conv, isC := n.(*ast.CallExpr)
			if !isC {
				return true
			}
			tv := p.TypesInfo.Types[ast.Unparen(conv.Fun)]
			if !tv.IsType() {
				callee := syntaxutil.ResolveCalledFuncObj(p, conv.Fun)
				if callee != nil && callee.Origin().Pkg() != nil && callee.Origin().Pkg() != p.Types &&
					!syntaxutil.IsTrueStdlibInPkg(p, callee.Origin().Pkg().Path()) {
					for _, a := range conv.Args {
						at := p.TypesInfo.TypeOf(a)
						if at != nil && types.Identical(types.Unalias(at), types.Typ[types.UnsafePointer]) {
							unconfinedForeignUnsafe = true
							break
						}
					}
				}
				return true
			}
			if len(conv.Args) != 1 || conv.Ellipsis.IsValid() || !syntaxutil.IsUnsafePointerType(tv.Type) {
				return true
			}
			dstNamed, isDN := types.Unalias(tv.Type).(*types.Named)
			if !isDN || dstNamed.Obj() == nil || dstNamed.Obj().Pkg() == nil || dstNamed.Obj().Pkg() == p.Types {
				return true
			}
			if syntaxutil.IsNilIdent(p.TypesInfo, conv.Args[0]) {
				return true
			}
			qPkg := dstNamed.Obj().Pkg()
			outerCall, isOC := idx.ParentUnparen(conv).(*ast.CallExpr)
			if !isOC || outerCall.Ellipsis.IsValid() {
				unconfinedForeignUnsafe = true
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, outerCall.Fun)
			if callee == nil || callee.Origin().Pkg() != qPkg {
				unconfinedForeignUnsafe = true
				return true
			}
			fk, okFK := syntaxutil.CallableFactKey(callee)
			if !okFK {
				unconfinedForeignUnsafe = true
				return true
			}
			sig, okS := callee.Type().(*types.Signature)
			if !okS {
				unconfinedForeignUnsafe = true
				return true
			}
			if len(outerCall.Args) == 1 && ast.Unparen(outerCall.Args[0]) == conv && sig.Results().Len() == 1 {
				argPtr, isAP := types.Unalias(p.TypesInfo.TypeOf(conv.Args[0])).(*types.Pointer)
				retPtr, isRP := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
				if isAP && isRP {
					elemNamed, isEN := types.Unalias(argPtr.Elem()).(*types.Named)
					wPriv, isWP := types.Unalias(retPtr.Elem()).(*types.Named)
					if isEN && isWP && wPriv.Obj() != nil && wPriv.Obj().Pkg() == qPkg {
						if wPub, capNamed, capRef, okW := extractForeignWrapperCapStruct(p, elemNamed, qPkg); okW &&
							types.IdenticalIgnoreTags(wPriv.Underlying(), wPub.Underlying()) &&
							verifyPkgCapsuleSetterPairing(capNamed, wPriv) {
							classes[conv] = foreignPtrConvClass{
								isCapsuleWrapper: true,
								capStruct:        capRef,
								capParam:         syntaxutil.ParamKey{Func: fk, Index: 0},
							}
							return true
						}
					}
				}
			}
			if len(outerCall.Args) == 2 && sig.Results().Len() == 0 &&
				(ast.Unparen(outerCall.Args[0]) == conv || ast.Unparen(outerCall.Args[1]) == conv) {
				c0, ok0 := ast.Unparen(outerCall.Args[0]).(*ast.CallExpr)
				c1, ok1 := ast.Unparen(outerCall.Args[1]).(*ast.CallExpr)
				if ok0 && ok1 && len(c0.Args) == 1 && len(c1.Args) == 1 && !c0.Ellipsis.IsValid() && !c1.Ellipsis.IsValid() {
					tv0 := p.TypesInfo.Types[ast.Unparen(c0.Fun)]
					tv1 := p.TypesInfo.Types[ast.Unparen(c1.Fun)]
					if tv0.IsType() && tv1.IsType() &&
						types.Identical(types.Unalias(tv0.Type), dstNamed) &&
						types.Identical(types.Unalias(tv1.Type), dstNamed) {
						t0 := p.TypesInfo.TypeOf(c0.Args[0])
						t1 := p.TypesInfo.TypeOf(c1.Args[0])
						if t0 != nil && t1 != nil && types.Identical(types.Unalias(t0), types.Unalias(t1)) {
							if pOuter, okPO := types.Unalias(t0).(*types.Pointer); okPO {
								if _, okPI := types.Unalias(pOuter.Elem()).(*types.Pointer); okPI {
									classes[conv] = foreignPtrConvClass{
										isAtomicPtrCopy: true,
										atomicCopyFn:    fk,
									}
									return true
								}
							}
						}
					}
				}
			}
			unconfinedForeignUnsafe = true
			return true
		})
	}
	return classes, unconfinedForeignUnsafe
}

// PkgCastsUnsafePtrToMutatedStruct reports whether p converts any unsafe.Pointer-underlying
// expression to a pointer *T that transitively reaches a non-capsule struct in mutatedStructs.
func PkgCastsUnsafePtrToMutatedStruct(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	mutatedStructs []syntaxutil.TypeRef,
	foreignReflectFields map[*types.Var]bool,
) bool {
	return PkgCastsUnsafePtrToMutatedStructCtx(nil, p, idx, mutatedStructs, foreignReflectFields)
}

// PkgCastsUnsafePtrToMutatedStructCtx reports whether p converts any
// unsafe.Pointer-underlying expression to a pointer *T reaching mutatedStructs,
// emitting trace.DomainDynstate provenance on the triggering cast when ctx tracing is active.
func PkgCastsUnsafePtrToMutatedStructCtx(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	mutatedStructs []syntaxutil.TypeRef,
	foreignReflectFields map[*types.Var]bool,
) bool {
	if p == nil || p.TypesInfo == nil || len(mutatedStructs) == 0 {
		return false
	}
	traceTarget := pkgTraceTarget(p)
	_, safeLoadCasts, closedFields, applyGatedMethods, _ := collectSafeCapsuleWrapperUnsafePtrConvs(p, idx, foreignReflectFields)
	mutSet := make(map[syntaxutil.TypeRef]bool, len(mutatedStructs))
	for _, m := range mutatedStructs {
		mutSet[m] = true
	}
	isCapsuleOnlyWrapper := func(t types.Type) bool {
		st, isSt := types.Unalias(t).Underlying().(*types.Struct)
		if !isSt || st.NumFields() == 0 {
			return false
		}
		sawForeign := false
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if isZeroSizedPaddingType(f.Type()) {
				continue
			}
			if foreignReflectFields[f] {
				sawForeign = true
				continue
			}
			return false
		}
		return sawForeign
	}
	reachesMutated := func(root types.Type) bool {
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
			if isZeroSizedPaddingType(t) {
				return
			}
			if !isCapsuleOnlyWrapper(t) {
				if ref, ok := syntaxutil.TypeRefOfStruct(t); ok && mutSet[ref] {
					hit = true
					return
				}
			}
			switch u := t.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem())
			case *types.Slice:
				walk(u.Elem())
			case *types.Array:
				if u.Len() > 0 {
					walk(u.Elem())
				}
			case *types.Map:
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					f := u.Field(i)
					if foreignReflectFields[f] || isZeroSizedPaddingType(f.Type()) {
						continue
					}
					walk(f.Type())
				}
			}
		}
		walk(root)
		return hit
	}
	found := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if found || n == nil {
				return false
			}
			call, isC := n.(*ast.CallExpr)
			if !isC || len(call.Args) != 1 || call.Ellipsis.IsValid() {
				return true
			}
			tv := p.TypesInfo.Types[ast.Unparen(call.Fun)]
			if !tv.IsType() || tv.Type == nil {
				return true
			}
			dstPtr, isP := types.Unalias(tv.Type).Underlying().(*types.Pointer)
			if !isP {
				return true
			}
			if safeLoadCasts[call] || refconfine.IsTypedAtomicLoadResultCast(p, idx, call) {
				return true
			}
			if sel, isSel := ast.Unparen(call.Args[0]).(*ast.SelectorExpr); isSel && sel.Sel != nil {
				if fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var); fld != nil && closedFields[fld] {
					if _, isSt := types.Unalias(dstPtr.Elem()).Underlying().(*types.Struct); !isSt {
						if !reachesMutated(dstPtr.Elem()) {
							return true
						}
						if enclFD := idx.EnclFunc[call]; enclFD != nil && enclFD.Name != nil {
							if enclFn, _ := p.TypesInfo.Defs[enclFD.Name].(*types.Func); enclFn != nil && applyGatedMethods[enclFn] {
								return true
							}
						}
					}
				}
			}
			argT := p.TypesInfo.TypeOf(call.Args[0])
			if syntaxutil.IsUnsafePointerType(argT) && reachesMutated(dstPtr.Elem()) {
				emitCapsuleReject(ctx, p, traceTarget, dstPtr.Elem().String(), "unsafe_ptr_cast_reaches_mutated_struct", call)
				found = true
				return false
			}
			return true
		})
	}
	return found
}
