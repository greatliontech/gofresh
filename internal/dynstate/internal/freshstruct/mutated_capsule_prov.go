package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) isSafeCapsuleGoReflectTypeInitExpr(expr ast.Expr, visiting map[types.Object]bool) bool {
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
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" {
			return false
		}
		switch callee.Name() {
		case "TypeOf":
			return len(e.Args) == 1 && wpd.isSafeExportedTypeQueryIfaceArg(e.Args[0], visiting)
		case "Type":
			sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			return len(e.Args) == 0 && isS && wpd.isSafeLegacyReflectValueSource(sel.X, visiting)
		}
		return false
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
					if sig.Recv() != nil || fn.Exported() || len(wpd.idx.UsesOf[fn]) == 0 {
						return false
					}
					for _, uid := range wpd.idx.UsesOf[v] {
						if refconfine.IdentIsWrittenOrAddrTaken(wpd.idx, uid) {
							return false
						}
					}
					for _, cuid := range wpd.idx.UsesOf[fn] {
						cc := refconfine.EnclosingCallOfCalleeIdent(wpd.idx, cuid)
						if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) || !wpd.isSafeCapsuleGoReflectTypeInitExpr(cc.Args[pi], visiting) {
							return false
						}
					}
					return true
				}
			}
		}
		enclScope := declaringFuncOrLitBody(wpd.idx, e, v.Pos())
		if enclScope == nil || blockHasGoto(enclScope) {
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
						if len(x.Values) == 0 || i >= len(x.Values) || !wpd.isSafeCapsuleGoReflectTypeInitExpr(x.Values[i], visiting) {
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
					if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isSafeCapsuleGoReflectTypeInitExpr(x.Rhs[i], visiting) {
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

func (wpd *wrapperPtrDiscipline) isExternalOnlyBuilderGoTypeInit(as *ast.AssignStmt, rhs ast.Expr) bool {
	enclFD := wpd.idx.EnclFunc[as]
	if enclFD == nil || enclFD.Name == nil || enclFD.Recv == nil || len(enclFD.Recv.List) != 1 || len(enclFD.Recv.List[0].Names) != 1 {
		return false
	}
	enclFn, _ := wpd.p.TypesInfo.Defs[enclFD.Name].(*types.Func)
	if enclFn == nil || !enclFn.Exported() || len(wpd.idx.UsesOf[enclFn]) > 0 {
		return false
	}
	bRecv, _ := wpd.p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]].(*types.Var)
	bNamed := syntaxutil.DerefNamedStruct(bRecv.Type())
	if bRecv == nil || bNamed == nil || bNamed.Obj() == nil || bNamed.Obj().Pkg() != wpd.p.Types || !bNamed.Obj().Exported() ||
		wpd.capsuleStructs[bNamed] || wpd.reboundStructs[bNamed] || wpd.instantiatedNamed[bNamed] {
		return false
	}
	tc, isTC := ast.Unparen(rhs).(*ast.CallExpr)
	if !isTC || len(tc.Args) != 1 || tc.Ellipsis.IsValid() {
		return false
	}
	tfn := syntaxutil.ResolveCalledFuncObj(wpd.p, tc.Fun)
	if tfn == nil || tfn.Pkg() == nil || tfn.Pkg().Path() != "reflect" || tfn.Name() != "TypeOf" {
		return false
	}
	ix, isIX := ast.Unparen(tc.Args[0]).(*ast.IndexExpr)
	if !isIX {
		return false
	}
	gsel, isGS := ast.Unparen(ix.X).(*ast.SelectorExpr)
	if !isGS {
		return false
	}
	gInfo := wpd.p.TypesInfo.Selections[gsel]
	if gInfo == nil || gInfo.Kind() != types.FieldVal {
		return false
	}
	gfld, _ := gInfo.Obj().(*types.Var)
	rid, isRID := ast.Unparen(gsel.X).(*ast.Ident)
	if gfld == nil || !gfld.Exported() || !isRID || wpd.p.TypesInfo.Uses[rid] != bRecv {
		return false
	}
	gsl, isSl := syntaxutil.UnderlyingType(gfld.Type()).(*types.Slice)
	return isSl && isEmptyInterfaceType(gsl.Elem())
}

func (wpd *wrapperPtrDiscipline) isVerifiedCapsuleGoReflectTypeField(ownerN *types.Named, sfld *types.Var) bool {
	if ownerN == nil || !wpd.capsuleStructs[ownerN] || wpd.reboundStructs[ownerN] ||
		sfld == nil || !sfld.IsField() || !sfld.Exported() || sfld.Pkg() != wpd.p.Types ||
		!syntaxutil.IsNamedInPkg(sfld.Type(), "reflect", "Type") {
		return false
	}
	ck := capGoTypeKey{owner: ownerN, fld: sfld}
	if wpd.verifiedCapGoTypeDone[ck] {
		return wpd.verifiedCapGoTypeMemo[ck]
	}
	if wpd.visitingCapGoType[ck] {
		return true
	}
	var findDeclStruct func(cur *types.Named) (*types.Named, int)
	findDeclStruct = func(cur *types.Named) (*types.Named, int) {
		if cur == nil || !wpd.capsuleStructs[cur] || wpd.reboundStructs[cur] {
			return nil, -1
		}
		st, isSt := cur.Underlying().(*types.Struct)
		if !isSt {
			return nil, -1
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f == sfld {
				return cur, i
			}
			if f.Embedded() && !f.Exported() {
				if emb, isEN := types.Unalias(f.Type()).(*types.Named); isEN {
					if dn, di := findDeclStruct(emb); dn != nil {
						return dn, di
					}
				}
			}
		}
		return nil, -1
	}
	declNamed, fldIdx := findDeclStruct(ownerN)
	if declNamed == nil || fldIdx < 0 {
		return false
	}
	for _, uid := range wpd.idx.UsesOf[sfld] {
		if parSel, isPS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isPS && parSel.Sel == uid {
			par := wpd.idx.ParentUnparen(parSel)
			if u, isU := par.(*ast.UnaryExpr); isU && u.Op == token.AND {
				return false
			}
			if _, isInc := par.(*ast.IncDecStmt); isInc {
				return false
			}
		} else if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
			return false
		}
	}
	wpd.visitingCapGoType[ck] = true
	okFld := true
	for _, ffile := range wpd.p.Syntax {
		ast.Inspect(ffile, func(bn ast.Node) bool {
			if !okFld || bn == nil {
				return false
			}
			switch x := bn.(type) {
			case *ast.CompositeLit:
				if syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x)) != declNamed || len(x.Elts) == 0 {
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
						if isID && wpd.p.TypesInfo.Uses[kid] == sfld &&
							!wpd.isSafeCapsuleGoReflectTypeInitExpr(kv.Value, map[types.Object]bool{}) {
							okFld = false
							return false
						}
					}
				} else if fldIdx < len(x.Elts) {
					if !wpd.isSafeCapsuleGoReflectTypeInitExpr(x.Elts[fldIdx], map[types.Object]bool{}) {
						okFld = false
						return false
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !isS || lsel.Sel == nil || wpd.p.TypesInfo.Uses[lsel.Sel] != sfld {
						continue
					}
					if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) ||
						!wpd.isExternalOnlyBuilderGoTypeInit(x, x.Rhs[i]) {
						okFld = false
						return false
					}
				}
			}
			return true
		})
	}
	delete(wpd.visitingCapGoType, ck)
	if len(wpd.visitingCapGoType) == 0 {
		wpd.verifiedCapGoTypeDone[ck] = true
		wpd.verifiedCapGoTypeMemo[ck] = okFld
	}
	return okFld
}

func (wpd *wrapperPtrDiscipline) isTypeGuardedIfaceArg(call *ast.CallExpr, arg ast.Expr) bool {
	id, isID := ast.Unparen(arg).(*ast.Ident)
	if !isID {
		return false
	}
	paramV, _ := wpd.p.TypesInfo.Uses[id].(*types.Var)
	fd := wpd.idx.EnclFunc[call]
	if paramV == nil || fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	fnObj, _ := wpd.p.TypesInfo.Defs[fd.Name].(*types.Func)
	if fnObj == nil {
		return false
	}
	sig, okS := fnObj.Type().(*types.Signature)
	if !okS {
		return false
	}
	isParam := false
	for pi := 0; pi < sig.Params().Len(); pi++ {
		if sig.Params().At(pi) == paramV {
			isParam = true
			break
		}
	}
	if !isParam {
		return false
	}
	recvV, _ := wpd.p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if recvV == nil {
		return false
	}
	recvPtr, isRP := types.Unalias(recvV.Type()).(*types.Pointer)
	if !isRP {
		return false
	}
	ownerN, isON := types.Unalias(recvPtr.Elem()).(*types.Named)
	if !isON || !wpd.capsuleStructs[ownerN] || wpd.reboundStructs[ownerN] {
		return false
	}
	for _, puid := range wpd.idx.UsesOf[paramV] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, paramV, puid) {
			return false
		}
	}
	for _, ruid := range wpd.idx.UsesOf[recvV] {
		if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, recvV, ruid) {
			return false
		}
	}
	for _, stmt := range fd.Body.List {
		if stmt.Pos() >= call.Pos() {
			break
		}
		ifs, isIf := stmt.(*ast.IfStmt)
		if !isIf || ifs.Init != nil || ifs.Else != nil || ifs.Body == nil || len(ifs.Body.List) == 0 {
			continue
		}
		lastSt := ifs.Body.List[len(ifs.Body.List)-1]
		es, isES := lastSt.(*ast.ExprStmt)
		if !isES {
			continue
		}
		pc, isPC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isPC {
			continue
		}
		pid, isPID := ast.Unparen(pc.Fun).(*ast.Ident)
		if !isPID {
			continue
		}
		bObj, isB := wpd.p.TypesInfo.Uses[pid].(*types.Builtin)
		if !isB || bObj.Name() != "panic" {
			continue
		}
		bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.NEQ {
			continue
		}
		checkPair := func(typeOfExpr, fldExpr ast.Expr) bool {
			tc, isTC := ast.Unparen(typeOfExpr).(*ast.CallExpr)
			if !isTC || len(tc.Args) != 1 || tc.Ellipsis.IsValid() {
				return false
			}
			tfn := syntaxutil.ResolveCalledFuncObj(wpd.p, tc.Fun)
			if tfn == nil || tfn.Pkg() == nil || tfn.Pkg().Path() != "reflect" || tfn.Name() != "TypeOf" {
				return false
			}
			aid, isAID := ast.Unparen(tc.Args[0]).(*ast.Ident)
			if !isAID || wpd.p.TypesInfo.Uses[aid] != paramV {
				return false
			}
			fsel, isFS := ast.Unparen(fldExpr).(*ast.SelectorExpr)
			if !isFS {
				return false
			}
			sInfo := wpd.p.TypesInfo.Selections[fsel]
			if sInfo == nil || sInfo.Kind() != types.FieldVal || len(sInfo.Index()) != 1 {
				return false
			}
			sfld, _ := sInfo.Obj().(*types.Var)
			rid, isRID := ast.Unparen(fsel.X).(*ast.Ident)
			return isRID && wpd.p.TypesInfo.Uses[rid] == recvV && wpd.isVerifiedCapsuleGoReflectTypeField(ownerN, sfld)
		}
		if checkPair(bin.X, bin.Y) || checkPair(bin.Y, bin.X) {
			return true
		}
	}
	return false
}

func (wpd *wrapperPtrDiscipline) enclCallable(node ast.Node) (*types.Func, *ast.FuncLit) {
	for cur := wpd.idx.ParentMap[node]; cur != nil; cur = wpd.idx.ParentMap[cur] {
		switch fn := cur.(type) {
		case *ast.FuncLit:
			return nil, fn
		case *ast.FuncDecl:
			if fn.Name != nil {
				fobj, _ := wpd.p.TypesInfo.Defs[fn.Name].(*types.Func)
				return fobj, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

func (wpd *wrapperPtrDiscipline) isInsideContextSensitiveFunc(node ast.Node) bool {
	fn, fl := wpd.enclCallable(node)
	return fl == nil && fn != nil && wpd.contextSensitiveFuncs[fn]
}

func (wpd *wrapperPtrDiscipline) addVarProv(v *types.Var, pr ptrProv) bool {
	if v == nil || pr == 0 {
		return false
	}
	if (wpd.varProv[v] | pr) != wpd.varProv[v] {
		wpd.varProv[v] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) addSliceVarProv(v *types.Var, pr ptrProv) bool {
	if v == nil || pr == 0 {
		return false
	}
	if (wpd.sliceVarProv[v] | pr) != wpd.sliceVarProv[v] {
		wpd.sliceVarProv[v] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) addFieldProv(f types.Object, pr ptrProv) bool {
	if f == nil || pr == 0 {
		return false
	}
	if (wpd.fieldProv[f] | pr) != wpd.fieldProv[f] {
		wpd.fieldProv[f] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) addRVVarProv(v *types.Var, pr rvProv) bool {
	if v == nil || pr == 0 {
		return false
	}
	if (wpd.rvVarProv[v] | pr) != wpd.rvVarProv[v] {
		wpd.rvVarProv[v] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) addFnRetProv(fn *types.Func, ri int, nres int, pr ptrProv) bool {
	if fn == nil || pr == 0 || ri < 0 || ri >= nres {
		return false
	}
	sl := wpd.fnReturnProv[fn]
	if len(sl) < nres {
		nsl := make([]ptrProv, nres)
		copy(nsl, sl)
		sl = nsl
		wpd.fnReturnProv[fn] = sl
	}
	if (sl[ri] | pr) != sl[ri] {
		sl[ri] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) addLitRetProv(fl *ast.FuncLit, ri int, nres int, pr ptrProv) bool {
	if fl == nil || pr == 0 || ri < 0 || ri >= nres {
		return false
	}
	sl := wpd.litReturnProv[fl]
	if len(sl) < nres {
		nsl := make([]ptrProv, nres)
		copy(nsl, sl)
		sl = nsl
		wpd.litReturnProv[fl] = sl
	}
	if (sl[ri] | pr) != sl[ri] {
		sl[ri] |= pr
		return true
	}
	return false
}

func (wpd *wrapperPtrDiscipline) getFnRetSlot(fn *types.Func, ri int) ptrProv {
	sl := wpd.fnReturnProv[fn]
	if ri >= 0 && ri < len(sl) {
		return sl[ri]
	}
	return 0
}

func (wpd *wrapperPtrDiscipline) getLitRetSlot(fl *ast.FuncLit, ri int) ptrProv {
	sl := wpd.litReturnProv[fl]
	if ri >= 0 && ri < len(sl) {
		return sl[ri]
	}
	return 0
}

func (wpd *wrapperPtrDiscipline) evalRVProv(expr ast.Expr) rvProv {
	if expr == nil {
		return rvRaw
	}
	expr = ast.Unparen(expr)
	if !syntaxutil.IsNamedInPkg(wpd.p.TypesInfo.TypeOf(expr), "reflect", "Value") {
		return rvRaw
	}
	switch e := expr.(type) {
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[e].(*types.Var)
		if v == nil {
			return rvRaw
		}
		return wpd.rvVarProv[v]
	case *ast.CallExpr:
		if wpd.isReflectNewCall(e) {
			return rvFresh
		}
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
		if callee == nil {
			return rvRaw
		}
		if wpd.methodClass[callee] == ptrMethodAsValue {
			sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			if !isS || len(e.Args) != 1 || e.Ellipsis.IsValid() {
				return rvRaw
			}
			rp := wpd.exprProv(sel.X)
			var out rvProv
			if (rp & (provApplied | provFresh)) != 0 {
				out |= rvOneofElem
			}
			if (rp & (provBase | provAtomicLoaded | provRaw)) != 0 {
				out |= rvRaw
			}
			return out
		}
		if callee.Pkg() != nil && callee.Pkg().Path() == "reflect" {
			sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			if !isS {
				return rvRaw
			}
			switch callee.Name() {
			case "Elem":
				if len(e.Args) == 0 {
					return wpd.evalRVProv(sel.X)
				}
			case "Value":
				if len(e.Args) == 0 && syntaxutil.IsNamedInPkg(syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(sel.X)), "reflect", "MapIter") {
					return rvMapOrConv
				}
			case "MapIndex":
				if len(e.Args) == 1 && !e.Ellipsis.IsValid() {
					return rvMapOrConv
				}
			}
			return rvRaw
		}
		if callee.Pkg() == wpd.p.Types {
			if sig, okS := callee.Type().(*types.Signature); okS && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
				return rvMapOrConv
			}
		}
	}
	return rvRaw
}

func (wpd *wrapperPtrDiscipline) sliceExprProv(expr ast.Expr) ptrProv {
	if expr == nil {
		return provRaw
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(wpd.p.TypesInfo, expr) {
		return 0
	}
	if !wpd.isOwnerSliceType(wpd.p.TypesInfo.TypeOf(expr)) {
		return provRaw
	}
	switch e := expr.(type) {
	case *ast.CompositeLit:
		if len(e.Elts) == 0 {
			return 0
		}
		return provRaw
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[e].(*types.Var)
		if v == nil {
			return provRaw
		}
		return wpd.sliceVarProv[v]
	case *ast.CallExpr:
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
		if callee != nil && wpd.methodClass[callee] == ptrMethodPointerSlice {
			sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
			if !isS || len(e.Args) != 0 {
				return provRaw
			}
			rp := wpd.exprProv(sel.X)
			var out ptrProv
			if (rp & (provApplied | provAtomicLoaded | provFresh)) != 0 {
				out |= provBase
			}
			if (rp & (provBase | provRaw)) != 0 {
				out |= provRaw
			}
			return out
		}
	}
	return provRaw
}

func (wpd *wrapperPtrDiscipline) callTupleSlotProv(e *ast.CallExpr, ri int) ptrProv {
	callee := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
	if callee != nil {
		if ri == 0 {
			if wpd.seedBaseMethods[callee] {
				return provBase
			}
			if wpd.methodClass[callee] == ptrMethodApplyOffset {
				sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
				if !isS || len(e.Args) != 1 || e.Ellipsis.IsValid() {
					return provRaw
				}
				if wpd.isProvenNonZeroOffset(e.Args[0], map[types.Object]bool{}) {
					rp := wpd.exprProv(sel.X)
					var out ptrProv
					if (rp & (provBase | provAtomicLoaded | provFresh)) != 0 {
						out |= provApplied
					}
					if (rp & (provApplied | provRaw)) != 0 {
						out |= provRaw
					}
					return out
				}
				if wpd.isZeroOffsetExpr(e.Args[0]) {
					rc, isRC := ast.Unparen(sel.X).(*ast.CallExpr)
					if !isRC || len(rc.Args) != 1 || rc.Ellipsis.IsValid() {
						return provRaw
					}
					rcallee := syntaxutil.ResolveCalledFuncObj(wpd.p, rc.Fun)
					if rcallee == nil || !wpd.ptrCtorOfValue[rcallee] {
						return provRaw
					}
					rvp := wpd.evalRVProv(rc.Args[0])
					var out ptrProv
					if (rvp & (rvFresh | rvOneofElem)) != 0 {
						out |= provApplied
					}
					if (rvp & (rvMapOrConv | rvRaw)) != 0 {
						out |= provRaw
					}
					return out
				}
				return provRaw
			}
			if wpd.methodClass[callee] == ptrMethodElemLoad {
				sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
				if !isS || len(e.Args) != 0 {
					return provRaw
				}
				rp := wpd.exprProv(sel.X)
				var out ptrProv
				if (rp & (provApplied | provFresh)) != 0 {
					out |= provBase
				}
				if (rp & (provBase | provAtomicLoaded | provRaw)) != 0 {
					out |= provRaw
				}
				return out
			}
			if wpd.methodClass[callee] == ptrMethodAtomicLoad {
				sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr)
				if !isS || e.Ellipsis.IsValid() || len(e.Args) > 1 {
					return provRaw
				}
				rp := wpd.exprProv(sel.X)
				var out ptrProv
				if (rp & (provApplied | provFresh)) != 0 {
					out |= provAtomicLoaded
				}
				if (rp & (provBase | provAtomicLoaded | provRaw)) != 0 {
					out |= provRaw
				}
				if len(e.Args) == 1 {
					vp := wpd.exprProv(e.Args[0])
					if (vp & provRaw) != 0 {
						out |= provRaw
					}
				}
				return out
			}
			if wpd.ptrCtorOfValue[callee] {
				if len(e.Args) != 1 || e.Ellipsis.IsValid() {
					return provRaw
				}
				rvp := wpd.evalRVProv(e.Args[0])
				var out ptrProv
				if (rvp & rvFresh) != 0 {
					out |= provFresh
				}
				if (rvp & rvMapOrConv) != 0 {
					out |= provBase
				}
				if (rvp & (rvOneofElem | rvRaw)) != 0 {
					out |= provRaw
				}
				return out
			}
			if wpd.ptrCtorOfIface[callee] {
				if len(e.Args) != 1 || e.Ellipsis.IsValid() {
					return provRaw
				}
				if wpd.isReflectNewIfaceExpr(e.Args[0]) {
					return provFresh
				}
				if wpd.isTypeGuardedIfaceArg(e, e.Args[0]) {
					return provBase
				}
				return provRaw
			}
			if wpd.ptrCtorInterfaceToPtr[callee] {
				return provRaw
			}
		}
		if wpd.idx.FuncDecls[callee] != nil {
			return wpd.getFnRetSlot(callee, ri)
		}
		return provRaw
	}
	funExpr := ast.Unparen(e.Fun)
	if fl, isFL := funExpr.(*ast.FuncLit); isFL {
		return wpd.getLitRetSlot(fl, ri)
	}
	if sel, isS := funExpr.(*ast.SelectorExpr); isS {
		if sInfo := wpd.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.FieldVal {
			fobj := sInfo.Obj()
			if wpd.unknownSourceFields[fobj] || (len(wpd.funcLitsForField[fobj]) == 0 && len(wpd.funcObjsForField[fobj]) == 0) {
				return provRaw
			}
			var out ptrProv
			for _, fl := range wpd.funcLitsForField[fobj] {
				out |= wpd.getLitRetSlot(fl, ri)
			}
			for _, tfn := range wpd.funcObjsForField[fobj] {
				if wpd.contextSensitiveFuncs[tfn] {
					return provRaw
				}
				out |= wpd.getFnRetSlot(tfn, ri)
			}
			return out
		}
	} else if cid, isID := funExpr.(*ast.Ident); isID {
		if lv, _ := wpd.p.TypesInfo.Uses[cid].(*types.Var); lv != nil {
			if wpd.unknownSourceLocals[lv] || (len(wpd.funcLitsForLocal[lv]) == 0 && len(wpd.funcObjsForLocal[lv]) == 0) {
				return provRaw
			}
			var out ptrProv
			for _, fl := range wpd.funcLitsForLocal[lv] {
				out |= wpd.getLitRetSlot(fl, ri)
			}
			for _, tfn := range wpd.funcObjsForLocal[lv] {
				if wpd.contextSensitiveFuncs[tfn] {
					return provRaw
				}
				out |= wpd.getFnRetSlot(tfn, ri)
			}
			return out
		}
	}
	return provRaw
}

func (wpd *wrapperPtrDiscipline) exprProv(expr ast.Expr) ptrProv {
	if expr == nil {
		return provRaw
	}
	expr = ast.Unparen(expr)
	if !types.Identical(types.Unalias(wpd.p.TypesInfo.TypeOf(expr)), wpd.dstOwner) {
		return provRaw
	}
	switch e := expr.(type) {
	case *ast.CompositeLit:
		if len(e.Elts) == 0 {
			return 0
		}
		return provRaw
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[e].(*types.Var)
		if v == nil {
			return provRaw
		}
		return wpd.varProv[v]
	case *ast.SelectorExpr:
		if sInfo := wpd.p.TypesInfo.Selections[e]; sInfo != nil && sInfo.Kind() == types.FieldVal {
			return wpd.fieldProv[sInfo.Obj()]
		}
		return provRaw
	case *ast.IndexExpr:
		if wpd.isOwnerSliceType(wpd.p.TypesInfo.TypeOf(e.X)) {
			return wpd.sliceExprProv(e.X)
		}
		return provRaw
	case *ast.CallExpr:
		return wpd.callTupleSlotProv(e, 0)
	}
	return provRaw
}

func (wpd *wrapperPtrDiscipline) defsOrUsesVar(id *ast.Ident) *types.Var {
	if id == nil || id.Name == "_" {
		return nil
	}
	if v, ok := wpd.p.TypesInfo.Defs[id].(*types.Var); ok && v != nil {
		return v
	}
	v, _ := wpd.p.TypesInfo.Uses[id].(*types.Var)
	return v
}
