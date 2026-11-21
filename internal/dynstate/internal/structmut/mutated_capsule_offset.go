package structmut

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (wpd *wrapperPtrDiscipline) initOffsetAndCapsuleStructs() {
	wpd.applyOffsetSet = map[*types.Named]bool{}
	for _, offT := range wpd.applyOffsetTypes {
		wpd.applyOffsetSet[offT] = true
	}
	wpd.capsuleStructs = map[*types.Named]bool{}
	for fld := range wpd.foreignReflectFields {
		if fld == nil {
			continue
		}
		if ptr, isP := types.Unalias(fld.Type()).(*types.Pointer); isP {
			if elem, isN := types.Unalias(ptr.Elem()).(*types.Named); isN {
				wpd.addCapsuleStruct(elem)
			}
		}
	}
	wpd.zeroInstantiatedStructs = map[*types.Named]bool{}
	wpd.reboundStructs = map[*types.Named]bool{}
	for _, file := range wpd.p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ValueSpec:
				if len(x.Values) == 0 {
					for _, nm := range x.Names {
						if v, _ := wpd.p.TypesInfo.Defs[nm].(*types.Var); v != nil {
							if sn, isN := types.Unalias(v.Type()).(*types.Named); isN {
								wpd.zeroInstantiatedStructs[sn] = true
							}
						}
					}
				}
			case *ast.CompositeLit:
				if len(x.Elts) == 0 && !wpd.isInsideCompileTimeUnsafeLayout(x) {
					if sn := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x)); sn != nil {
						wpd.zeroInstantiatedStructs[sn] = true
					}
				}
			case *ast.CallExpr:
				if syntaxutil.IsBuiltinNewType(wpd.p.TypesInfo, x) {
					if sn := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x)); sn != nil {
						wpd.zeroInstantiatedStructs[sn] = true
					}
				} else if tv := wpd.p.TypesInfo.Types[ast.Unparen(x.Fun)]; tv.IsType() && len(x.Args) == 1 && !syntaxutil.IsNilIdent(wpd.p.TypesInfo, x.Args[0]) {
					dstN := syntaxutil.DerefNamedStruct(tv.Type)
					srcN := syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(x.Args[0]))
					dstT := types.Unalias(tv.Type)
					srcT := types.Unalias(wpd.p.TypesInfo.TypeOf(x.Args[0]))
					_, dstSt := syntaxutil.DerefAnyStructType(dstT)
					_, srcSt := syntaxutil.DerefAnyStructType(srcT)
					if dstSt != nil && srcSt != nil && !types.Identical(dstT, srcT) {
						if dstN != nil {
							wpd.reboundStructs[dstN] = true
						}
						if srcN != nil {
							wpd.reboundStructs[srcN] = true
						}
					}
				}
			}
			return true
		})
	}
	wpd.verifiedEmbHopMemo = map[*types.Var]bool{}
	wpd.verifiedEmbHopDone = map[*types.Var]bool{}
	wpd.provenNonZeroMemo = map[types.Object]bool{}
	wpd.provenNonZeroDone = map[types.Object]bool{}

}

func (wpd *wrapperPtrDiscipline) isBitNotZeroExpr(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if c, isC := expr.(*ast.CallExpr); isC && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
		if wpd.p.TypesInfo.Types[ast.Unparen(c.Fun)].IsType() {
			expr = ast.Unparen(c.Args[0])
		}
	}
	un, isUn := expr.(*ast.UnaryExpr)
	if !isUn || un.Op != token.XOR {
		return false
	}
	inner := ast.Unparen(un.X)
	if c, isC := inner.(*ast.CallExpr); isC && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
		if wpd.p.TypesInfo.Types[ast.Unparen(c.Fun)].IsType() {
			inner = ast.Unparen(c.Args[0])
		}
	}
	tv := wpd.p.TypesInfo.Types[inner]
	if tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	iv, okI := constant.Int64Val(tv.Value)
	return okI && iv == 0
}

func (wpd *wrapperPtrDiscipline) isStructFieldOffsetConv(expr ast.Expr) bool {
	c, isC := ast.Unparen(expr).(*ast.CallExpr)
	if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
		return false
	}
	tv := wpd.p.TypesInfo.Types[ast.Unparen(c.Fun)]
	if !tv.IsType() {
		return false
	}
	on, isON := types.Unalias(tv.Type).(*types.Named)
	if !isON || !wpd.applyOffsetSet[on] {
		return false
	}
	sel, isS := ast.Unparen(c.Args[0]).(*ast.SelectorExpr)
	if !isS || sel.Sel == nil || sel.Sel.Name != "Offset" {
		return false
	}
	sInfo := wpd.p.TypesInfo.Selections[sel]
	return sInfo != nil && sInfo.Kind() == types.FieldVal && syntaxutil.IsNamedInPkg(sInfo.Recv(), "reflect", "StructField")
}

func (wpd *wrapperPtrDiscipline) addCapsuleStruct(named *types.Named) {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() != wpd.p.Types || wpd.capsuleStructs[named] {
		return
	}
	st, okSt := named.Underlying().(*types.Struct)
	if !okSt {
		return
	}
	wpd.capsuleStructs[named] = true
	for i := 0; i < st.NumFields(); i++ {
		sf := st.Field(i)
		if sf.Embedded() && !sf.Exported() {
			if emb, isN := types.Unalias(sf.Type()).(*types.Named); isN {
				wpd.addCapsuleStruct(emb)
			}
		}
	}
}

func (wpd *wrapperPtrDiscipline) isCapsuleInitStruct(named *types.Named) bool {
	return wpd.capsuleStructs[named]
}

func (wpd *wrapperPtrDiscipline) isNonZeroStructExpr(expr ast.Expr, targetNamed *types.Named, structVisiting map[types.Object]bool) bool {
	if expr == nil || targetNamed == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if !types.Identical(types.Unalias(wpd.p.TypesInfo.TypeOf(expr)), targetNamed) {
		return false
	}
	switch se := expr.(type) {
	case *ast.CompositeLit:
		return len(se.Elts) > 0
	case *ast.CallExpr:
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, se.Fun)
		if callee == nil || callee.Exported() || callee.Pkg() != wpd.p.Types {
			return false
		}
		if structVisiting[callee] {
			return true
		}
		fd := wpd.idx.FuncDecls[callee]
		if fd == nil || fd.Body == nil || cachedScopeHasGoto(wpd.p, wpd.idx, fd.Body) {
			return false
		}
		structVisiting[callee] = true
		sawRet := false
		okFn := true
		ast.Inspect(fd.Body, func(bn ast.Node) bool {
			if !okFn || bn == nil {
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
			if len(ret.Results) != 1 || !wpd.isNonZeroStructExpr(ret.Results[0], targetNamed, structVisiting) {
				okFn = false
				return false
			}
			return false
		})
		delete(structVisiting, callee)
		return sawRet && okFn
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[se].(*types.Var)
		if v == nil || v.Pkg() != wpd.p.Types {
			return false
		}
		if structVisiting[v] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[v] {
			if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
				return false
			}
			if sel, isS := wpd.idx.ParentUnparen(uid).(*ast.SelectorExpr); isS && ast.Unparen(sel.X) == uid &&
				refconfine.SelectionHasPointerReceiver(wpd.p.TypesInfo.Selections[sel]) {
				return false
			}
		}
		structVisiting[v] = true
		defer delete(structVisiting, v)
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
						if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) || !wpd.isNonZeroStructExpr(cc.Args[pi], targetNamed, structVisiting) {
							return false
						}
					}
					return true
				}
			}
		}
		if v.Parent() == wpd.p.Types.Scope() {
			if wpd.idx.DefCounts[v] != 1 {
				return false
			}
			for _, uid := range wpd.idx.UsesOf[v] {
				if refconfine.IdentIsWrittenOrAddrTaken(wpd.idx, uid) {
					return false
				}
			}
			vs := wpd.idx.VarSpecs[v]
			if vs == nil || len(vs.Names) != len(vs.Values) {
				return false
			}
			for i, nm := range vs.Names {
				if wpd.p.TypesInfo.Defs[nm] == v {
					return wpd.isNonZeroStructExpr(vs.Values[i], targetNamed, structVisiting)
				}
			}
			return false
		}
		enclScope := declaringFuncOrLitBody(wpd.idx, se, v.Pos())
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
						if len(x.Values) == 0 || i >= len(x.Values) || !wpd.isNonZeroStructExpr(x.Values[i], targetNamed, structVisiting) {
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
						if (x.Tok != token.ASSIGN && x.Tok != token.DEFINE) || len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) ||
							!wpd.isNonZeroStructExpr(x.Rhs[i], targetNamed, structVisiting) {
							localOK = false
							return false
						}
						sawWrite = true
					}
				}
			case *ast.RangeStmt:
				for _, re := range []ast.Expr{x.Key, x.Value} {
					if rid, isID := ast.Unparen(re).(*ast.Ident); isID && (wpd.p.TypesInfo.Defs[rid] == v || wpd.p.TypesInfo.Uses[rid] == v) {
						localOK = false
						return false
					}
				}
			}
			return true
		})
		return sawWrite && localOK
	}
	return false
}

func (wpd *wrapperPtrDiscipline) verifyNonZeroEmbeddedStructField(hopParent *types.Named, hopIdx int, hopFld *types.Var, hopNamed *types.Named) bool {
	if wpd.verifiedEmbHopDone[hopFld] {
		return wpd.verifiedEmbHopMemo[hopFld]
	}
	for _, uid := range wpd.idx.UsesOf[hopFld] {
		par := wpd.idx.ParentUnparen(uid)
		if u, isU := par.(*ast.UnaryExpr); isU && u.Op == token.AND {
			wpd.verifiedEmbHopDone[hopFld] = true
			wpd.verifiedEmbHopMemo[hopFld] = false
			return false
		}
		if sel, isS := par.(*ast.SelectorExpr); isS && sel.Sel == uid {
			if outerSel, isOS := wpd.idx.ParentUnparen(sel).(*ast.SelectorExpr); isOS && ast.Unparen(outerSel.X) == sel &&
				refconfine.SelectionHasPointerReceiver(wpd.p.TypesInfo.Selections[outerSel]) {
				wpd.verifiedEmbHopDone[hopFld] = true
				wpd.verifiedEmbHopMemo[hopFld] = false
				return false
			}
		}
	}
	sawHopWrite := false
	hopOK := true
	for _, sfile := range wpd.p.Syntax {
		ast.Inspect(sfile, func(sn ast.Node) bool {
			if !hopOK || sn == nil {
				return false
			}
			switch sx := sn.(type) {
			case *ast.CompositeLit:
				if syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(sx)) != hopParent || len(sx.Elts) == 0 {
					return true
				}
				foundInLit := false
				if _, isKV0 := sx.Elts[0].(*ast.KeyValueExpr); isKV0 {
					for _, elt := range sx.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							hopOK = false
							return false
						}
						kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
						if isID && wpd.p.TypesInfo.Uses[kid] == hopFld {
							foundInLit = true
							if !wpd.isNonZeroStructExpr(kv.Value, hopNamed, map[types.Object]bool{}) {
								hopOK = false
								return false
							}
							sawHopWrite = true
						}
					}
				} else if hopIdx < len(sx.Elts) {
					foundInLit = true
					if !wpd.isNonZeroStructExpr(sx.Elts[hopIdx], hopNamed, map[types.Object]bool{}) {
						hopOK = false
						return false
					}
					sawHopWrite = true
				}
				if !foundInLit {
					hopOK = false
					return false
				}
			case *ast.AssignStmt:
				for i, lhs := range sx.Lhs {
					lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !isS || lsel.Sel == nil || wpd.p.TypesInfo.Uses[lsel.Sel] != hopFld {
						continue
					}
					if sx.Tok != token.ASSIGN || len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) ||
						!wpd.isNonZeroStructExpr(sx.Rhs[i], hopNamed, map[types.Object]bool{}) {
						hopOK = false
						return false
					}
					sawHopWrite = true
				}
			}
			return true
		})
	}
	res := sawHopWrite && hopOK
	wpd.verifiedEmbHopDone[hopFld] = true
	wpd.verifiedEmbHopMemo[hopFld] = res
	return res
}

func (wpd *wrapperPtrDiscipline) isProvenNonZeroOffset(expr ast.Expr, visiting map[types.Object]bool) bool {
	if expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	on, isON := types.Unalias(wpd.p.TypesInfo.TypeOf(expr)).(*types.Named)
	if !isON || !wpd.applyOffsetSet[on] {
		return false
	}
	if wpd.isBitNotZeroExpr(expr) || wpd.isStructFieldOffsetConv(expr) {
		return true
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		callee := syntaxutil.ResolveCalledFuncObj(wpd.p, e.Fun)
		if callee == nil || callee.Exported() || callee.Pkg() != wpd.p.Types {
			return false
		}
		if wpd.provenNonZeroDone[callee] {
			return wpd.provenNonZeroMemo[callee]
		}
		if visiting[callee] {
			return true
		}
		fd := wpd.idx.FuncDecls[callee]
		if fd == nil || fd.Body == nil || cachedScopeHasGoto(wpd.p, wpd.idx, fd.Body) {
			return false
		}
		visiting[callee] = true
		sawRet := false
		okFn := true
		ast.Inspect(fd.Body, func(bn ast.Node) bool {
			if !okFn || bn == nil {
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
			if len(ret.Results) != 1 || !wpd.isProvenNonZeroOffset(ret.Results[0], visiting) {
				okFn = false
				return false
			}
			return false
		})
		delete(visiting, callee)
		res := sawRet && okFn
		if len(visiting) == 0 {
			wpd.provenNonZeroDone[callee] = true
			wpd.provenNonZeroMemo[callee] = res
		}
		return res
	case *ast.Ident:
		v, _ := wpd.p.TypesInfo.Uses[e].(*types.Var)
		if v == nil || v.Pkg() != wpd.p.Types {
			return false
		}
		if wpd.provenNonZeroDone[v] {
			return wpd.provenNonZeroMemo[v]
		}
		if visiting[v] {
			return true
		}
		for _, uid := range wpd.idx.UsesOf[v] {
			if u, isU := wpd.idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
				return false
			}
			if _, isInc := wpd.idx.ParentUnparen(uid).(*ast.IncDecStmt); isInc {
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
						if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) || !wpd.isProvenNonZeroOffset(cc.Args[pi], visiting) {
							return false
						}
					}
					if len(visiting) == 1 {
						wpd.provenNonZeroDone[v] = true
						wpd.provenNonZeroMemo[v] = true
					}
					return true
				}
			}
		}
		if v.Parent() == wpd.p.Types.Scope() {
			if wpd.idx.DefCounts[v] != 1 {
				return false
			}
			for _, uid := range wpd.idx.UsesOf[v] {
				if refconfine.IdentIsWrittenOrAddrTaken(wpd.idx, uid) {
					return false
				}
			}
			vs := wpd.idx.VarSpecs[v]
			if vs == nil || len(vs.Names) != len(vs.Values) {
				return false
			}
			for i, nm := range vs.Names {
				if wpd.p.TypesInfo.Defs[nm] == v {
					res := wpd.isProvenNonZeroOffset(vs.Values[i], visiting)
					if len(visiting) == 1 {
						wpd.provenNonZeroDone[v] = true
						wpd.provenNonZeroMemo[v] = res
					}
					return res
				}
			}
			return false
		}
		enclScope := declaringFuncOrLitBody(wpd.idx, e, v.Pos())
		if enclScope == nil || cachedScopeHasGoto(wpd.p, wpd.idx, enclScope) {
			return false
		}
		sawWrite := false
		hasZeroVarDecl := false
		localOK := true
		ast.Inspect(enclScope, func(bn ast.Node) bool {
			if !localOK || bn == nil {
				return false
			}
			switch x := bn.(type) {
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					if wpd.p.TypesInfo.Defs[nm] == v {
						if len(x.Values) == 0 {
							hasZeroVarDecl = true
						} else if i >= len(x.Values) || !wpd.isProvenNonZeroOffset(x.Values[i], visiting) {
							localOK = false
							return false
						} else {
							sawWrite = true
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					if wpd.p.TypesInfo.Defs[lid] == v || wpd.p.TypesInfo.Uses[lid] == v {
						if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
							localOK = false
							return false
						}
						if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !wpd.isProvenNonZeroOffset(x.Rhs[i], visiting) {
							localOK = false
							return false
						}
						sawWrite = true
					}
				}
			case *ast.RangeStmt:
				for _, re := range []ast.Expr{x.Key, x.Value} {
					if rid, isID := ast.Unparen(re).(*ast.Ident); isID && (wpd.p.TypesInfo.Defs[rid] == v || wpd.p.TypesInfo.Uses[rid] == v) {
						localOK = false
						return false
					}
				}
			}
			return true
		})
		if !sawWrite || !localOK {
			return false
		}
		if hasZeroVarDecl {
			if cachedScopeHasGotoOrLabel(wpd.p, wpd.idx, enclScope) {
				return false
			}
			for _, uid := range wpd.idx.UsesOf[v] {
				if innermostFuncOrLitBody(wpd.idx, uid) != enclScope {
					return false
				}
				if cc, isCC := wpd.idx.ParentUnparen(uid).(*ast.CallExpr); isCC {
					if cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, cc.Fun); cfn != nil && wpd.methodClass[cfn] == ptrMethodApplyOffset {
						return false
					}
				}
			}
			hasDefaultAssign := false
			ast.Inspect(enclScope, func(bn ast.Node) bool {
				sw, isSw := bn.(*ast.SwitchStmt)
				if !isSw || sw.Body == nil {
					return true
				}
				for _, raw := range sw.Body.List {
					cc, isCC := raw.(*ast.CaseClause)
					if !isCC || cc.List != nil {
						continue
					}
					for _, st := range cc.Body {
						if as, isAS := st.(*ast.AssignStmt); isAS && len(as.Lhs) == 1 {
							if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID && wpd.p.TypesInfo.Uses[lid] == v {
								hasDefaultAssign = true
							}
						}
					}
				}
				return true
			})
			if !hasDefaultAssign {
				return false
			}
		}
		if len(visiting) == 1 {
			wpd.provenNonZeroDone[v] = true
			wpd.provenNonZeroMemo[v] = true
		}
		return true
	case *ast.SelectorExpr:
		sInfo := wpd.p.TypesInfo.Selections[e]
		if sInfo == nil || sInfo.Kind() != types.FieldVal {
			return false
		}
		selIdx := sInfo.Index()
		sfld, _ := sInfo.Obj().(*types.Var)
		recvNamed := syntaxutil.DerefNamedStruct(sInfo.Recv())
		if len(selIdx) == 0 || sfld == nil || !sfld.IsField() || sfld.Exported() || sfld.Pkg() != wpd.p.Types ||
			recvNamed == nil || recvNamed.Obj() == nil || recvNamed.Obj().Pkg() != wpd.p.Types || wpd.reboundStructs[recvNamed] {
			return false
		}
		if !wpd.isCapsuleInitStruct(recvNamed) && (recvNamed.Obj().Exported() || wpd.zeroInstantiatedStructs[recvNamed]) {
			return false
		}
		curNamed := recvNamed
		for hi := 0; hi < len(selIdx)-1; hi++ {
			curSt, okSt := curNamed.Underlying().(*types.Struct)
			hopIdx := selIdx[hi]
			if !okSt || hopIdx < 0 || hopIdx >= curSt.NumFields() {
				return false
			}
			hopFld := curSt.Field(hopIdx)
			if hopFld == nil || hopFld.Exported() || hopFld.Pkg() != wpd.p.Types {
				return false
			}
			if _, isPtr := types.Unalias(hopFld.Type()).(*types.Pointer); isPtr {
				return false
			}
			hopNamed, isHN := types.Unalias(hopFld.Type()).(*types.Named)
			if !isHN || hopNamed.Obj() == nil || hopNamed.Obj().Pkg() != wpd.p.Types || wpd.reboundStructs[hopNamed] {
				return false
			}
			if !wpd.isCapsuleInitStruct(hopNamed) && (hopNamed.Obj().Exported() || wpd.zeroInstantiatedStructs[hopNamed]) {
				return false
			}
			if !wpd.isCapsuleInitStruct(curNamed) && !wpd.verifyNonZeroEmbeddedStructField(curNamed, hopIdx, hopFld, hopNamed) {
				return false
			}
			curNamed = hopNamed
		}
		declNamed := curNamed
		sSt, okSt := declNamed.Underlying().(*types.Struct)
		sIdx := selIdx[len(selIdx)-1]
		if !okSt || sIdx < 0 || sIdx >= sSt.NumFields() || sSt.Field(sIdx) != sfld {
			return false
		}
		if wpd.provenNonZeroDone[sfld] {
			return wpd.provenNonZeroMemo[sfld]
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
		sawFldWrite := false
		fldOK := true
		for _, sfile := range wpd.p.Syntax {
			ast.Inspect(sfile, func(sn ast.Node) bool {
				if !fldOK || sn == nil {
					return false
				}
				switch sx := sn.(type) {
				case *ast.CompositeLit:
					if syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(sx)) != declNamed || len(sx.Elts) == 0 {
						return true
					}
					foundInLit := false
					if _, isKV0 := sx.Elts[0].(*ast.KeyValueExpr); isKV0 {
						for _, elt := range sx.Elts {
							kv, isKV := elt.(*ast.KeyValueExpr)
							if !isKV {
								fldOK = false
								return false
							}
							kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
							if isID && wpd.p.TypesInfo.Uses[kid] == sfld {
								foundInLit = true
								if !wpd.isProvenNonZeroOffset(kv.Value, visiting) {
									fldOK = false
									return false
								}
								sawFldWrite = true
							}
						}
					} else if sIdx < len(sx.Elts) {
						foundInLit = true
						if !wpd.isProvenNonZeroOffset(sx.Elts[sIdx], visiting) {
							fldOK = false
							return false
						}
						sawFldWrite = true
					}
					if !foundInLit && !wpd.isCapsuleInitStruct(declNamed) {
						fldOK = false
						return false
					}
				case *ast.AssignStmt:
					for i, lhs := range sx.Lhs {
						lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
						if !isS || lsel.Sel == nil || wpd.p.TypesInfo.Uses[lsel.Sel] != sfld {
							continue
						}
						if sx.Tok != token.ASSIGN || len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) || !wpd.isProvenNonZeroOffset(sx.Rhs[i], visiting) {
							fldOK = false
							return false
						}
						sawFldWrite = true
					}
				}
				return true
			})
		}
		delete(visiting, sfld)
		res := sawFldWrite && fldOK
		if len(visiting) == 0 {
			wpd.provenNonZeroDone[sfld] = true
			wpd.provenNonZeroMemo[sfld] = res
		}
		return res
	}
	return false
}
