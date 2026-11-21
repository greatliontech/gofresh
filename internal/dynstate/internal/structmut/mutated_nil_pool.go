package structmut

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isProvablyNilVarExpr(p *packages.Package, idx *refconfine.PkgIndex, expr ast.Expr) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || expr == nil {
		return false
	}
	uid, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := p.TypesInfo.Uses[uid].(*types.Var)
	if !ok || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() {
		return false
	}
	if !isNilableGoType(v.Type()) || idx.DefCounts[v] != 1 {
		return false
	}
	for _, u := range idx.UsesOf[v] {
		if identIsWrittenAddrOrAutoAddr(p, idx, v, u) {
			return false
		}
	}
	enclBody := innermostFuncOrLitBody(idx, uid)
	if enclBody == nil || cachedScopeHasGotoOrLabel(p, idx, enclBody) {
		return false
	}
	var prev ast.Node = uid
	for cur := idx.ParentMap[uid]; cur != nil; cur = idx.ParentMap[cur] {
		switch node := cur.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if prev == node.Body && condImpliesVarNil(p, node.Cond, v) {
				return true
			}
			if node.Else != nil && prev == node.Else && condImpliesVarNonNil(p, node.Cond, v) {
				return true
			}
		case *ast.BlockStmt:
			curIdx := -1
			for i, st := range node.List {
				if st == prev {
					curIdx = i
					break
				}
			}
			for i := 0; i < curIdx; i++ {
				ifs, isIf := node.List[i].(*ast.IfStmt)
				if isIf && ifs.Else == nil && condImpliesVarNonNil(p, ifs.Cond, v) && stmtAlwaysTerminates(p, ifs.Body) {
					return true
				}
			}
			if node == enclBody {
				return false
			}
		}
		prev = cur
	}
	return false
}

func isNilableGoType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
		return true
	}
	return false
}

func identIsWrittenAddrOrAutoAddr(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var, u *ast.Ident) bool {
	if refconfine.IdentIsWrittenOrAddrTaken(idx, u) {
		return true
	}
	if p != nil && p.TypesInfo != nil && idx != nil && v != nil && u != nil {
		if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
			if sel, isSel := idx.ParentUnparen(u).(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == u {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && refconfine.SelectionHasPointerReceiver(selInfo) {
					return true
				}
			}
		}
	}
	return false
}

func isZeroSizedPaddingType(root types.Type) bool {
	seen := map[types.Type]bool{}
	var check func(t types.Type) bool
	check = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Array:
			return u.Len() == 0
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !check(u.Field(i).Type()) {
					return false
				}
			}
			return true
		}
		return false
	}
	return check(root)
}

func innermostFuncOrLitBody(idx *refconfine.PkgIndex, n ast.Node) *ast.BlockStmt {
	for cur := n; cur != nil; cur = idx.ParentMap[cur] {
		switch fn := cur.(type) {
		case *ast.FuncLit:
			return fn.Body
		case *ast.FuncDecl:
			return fn.Body
		}
	}
	return nil
}

func declaringFuncOrLitBody(idx *refconfine.PkgIndex, n ast.Node, declPos token.Pos) *ast.BlockStmt {
	for cur := n; cur != nil; cur = idx.ParentMap[cur] {
		switch fn := cur.(type) {
		case *ast.FuncLit:
			if fn.Body != nil && (!declPos.IsValid() || (fn.Pos() <= declPos && declPos < fn.End())) {
				return fn.Body
			}
		case *ast.FuncDecl:
			if fn.Body != nil && (!declPos.IsValid() || (fn.Pos() <= declPos && declPos < fn.End())) {
				return fn.Body
			}
		}
	}
	return nil
}

func cachedScopeHasGoto(p *packages.Package, idx *refconfine.PkgIndex, blk *ast.BlockStmt) bool {
	if blk == nil || idx == nil {
		return true
	}
	fc := idx.FlowCache(p)
	if fc == nil {
		return true
	}
	b := fc.Body(blk)
	return b == nil || b.HasGoto
}

func cachedScopeHasGotoOrLabel(p *packages.Package, idx *refconfine.PkgIndex, blk *ast.BlockStmt) bool {
	if blk == nil || idx == nil {
		return true
	}
	fc := idx.FlowCache(p)
	if fc == nil {
		return true
	}
	b := fc.Body(blk)
	return b == nil || b.HasGotoOrLabel()
}

func isConstBoolVal(p *packages.Package, expr ast.Expr, want bool) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	tv, ok := p.TypesInfo.Types[ast.Unparen(expr)]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && constant.BoolVal(tv.Value) == want
}

func isUnreachableConstIfBranch(p *packages.Package, idx *refconfine.PkgIndex, n ast.Node) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || n == nil {
		return false
	}
	ifs, isIf := idx.ParentMap[n].(*ast.IfStmt)
	if !isIf {
		return false
	}
	if ifs.Body == n && isConstBoolVal(p, ifs.Cond, false) && !syntaxutil.NodeHasGotoOrLabel(n) {
		return true
	}
	if ifs.Else != nil && ifs.Else == n && isConstBoolVal(p, ifs.Cond, true) && !syntaxutil.NodeHasGotoOrLabel(n) {
		return true
	}
	return false
}

func isVarNilComparison(p *packages.Package, expr ast.Expr, v *types.Var, op token.Token) bool {
	be, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || be.Op != op {
		return false
	}
	checkPair := func(varSide, nilSide ast.Expr) bool {
		id, isID := ast.Unparen(varSide).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != v {
			return false
		}
		return syntaxutil.IsNilIdent(p.TypesInfo, nilSide)
	}
	return checkPair(be.X, be.Y) || checkPair(be.Y, be.X)
}

func condImpliesVarNil(p *packages.Package, cond ast.Expr, v *types.Var) bool {
	if cond == nil || v == nil {
		return false
	}
	cond = ast.Unparen(cond)
	if isVarNilComparison(p, cond, v, token.EQL) {
		return true
	}
	switch e := cond.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return condImpliesVarNonNil(p, e.X, v)
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return condImpliesVarNil(p, e.X, v) || condImpliesVarNil(p, e.Y, v)
		case token.LOR:
			return (isConstBoolVal(p, e.X, false) && condImpliesVarNil(p, e.Y, v)) ||
				(isConstBoolVal(p, e.Y, false) && condImpliesVarNil(p, e.X, v)) ||
				(condImpliesVarNil(p, e.X, v) && condImpliesVarNil(p, e.Y, v))
		}
	}
	return false
}

func condImpliesVarNonNil(p *packages.Package, cond ast.Expr, v *types.Var) bool {
	if cond == nil || v == nil {
		return false
	}
	cond = ast.Unparen(cond)
	if isVarNilComparison(p, cond, v, token.NEQ) {
		return true
	}
	switch e := cond.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return condImpliesVarNil(p, e.X, v)
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LOR:
			return condImpliesVarNonNil(p, e.X, v) || condImpliesVarNonNil(p, e.Y, v)
		case token.LAND:
			return (isConstBoolVal(p, e.X, true) && condImpliesVarNonNil(p, e.Y, v)) ||
				(isConstBoolVal(p, e.Y, true) && condImpliesVarNonNil(p, e.X, v)) ||
				(condImpliesVarNonNil(p, e.X, v) && condImpliesVarNonNil(p, e.Y, v))
		}
	}
	return false
}

func stmtAlwaysTerminates(p *packages.Package, stmt ast.Stmt) bool {
	if stmt == nil {
		return false
	}
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, isCall := ast.Unparen(s.X).(*ast.CallExpr)
		if !isCall {
			return false
		}
		id, isID := ast.Unparen(call.Fun).(*ast.Ident)
		if !isID || p == nil || p.TypesInfo == nil {
			return false
		}
		b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
		return isB && b.Name() == "panic"
	case *ast.BlockStmt:
		for _, elt := range s.List {
			if stmtAlwaysTerminates(p, elt) {
				return true
			}
		}
		return false
	case *ast.IfStmt:
		return s.Else != nil && stmtAlwaysTerminates(p, s.Body) && stmtAlwaysTerminates(p, s.Else)
	}
	return false
}

func collectTypeAssertedSyncPools(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		return out
	}
	checkTypeAssertSite := func(ta *ast.TypeAssertExpr) (types.Type, bool) {
		if ta == nil || ta.Type == nil {
			return nil, false
		}
		taT := p.TypesInfo.TypeOf(ta.Type)
		if taT == nil || isEmptyInterfaceType(taT) || syntaxutil.TypeMentionsTypeParam(taT) {
			return nil, false
		}
		return taT, true
	}
	verifyNewFuncLit := func(fl *ast.FuncLit, putTypes *[]types.Type) bool {
		if fl == nil || fl.Body == nil || cachedScopeHasGotoOrLabel(p, idx, fl.Body) {
			return false
		}
		sawReturn := false
		okLit := true
		ast.Inspect(fl.Body, func(n ast.Node) bool {
			if !okLit || n == nil {
				return false
			}
			if _, isNested := n.(*ast.FuncLit); isNested {
				return false
			}
			ret, isRet := n.(*ast.ReturnStmt)
			if !isRet {
				return true
			}
			sawReturn = true
			if len(ret.Results) != 1 {
				okLit = false
				return false
			}
			res := ret.Results[0]
			if syntaxutil.IsNilIdent(p.TypesInfo, res) {
				return false
			}
			if !freshalloc.IsFreshInlineValue(p, res) || exprCarriesNonFreshInterface(p, res) {
				okLit = false
				return false
			}
			rt := p.TypesInfo.TypeOf(res)
			if rt == nil || isEmptyInterfaceType(rt) || syntaxutil.TypeMentionsTypeParam(rt) {
				okLit = false
				return false
			}
			*putTypes = append(*putTypes, rt)
			return false
		})
		return okLit && sawReturn
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.Exported() || idx.DefCounts[v] != 1 || !syntaxutil.IsNamedInPkg(v.Type(), "sync", "Pool") {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil {
			continue
		}
		var putTypes []types.Type
		if len(vs.Values) > 0 {
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			cl, isCL := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
			if !isCL || len(cl.Elts) > 1 {
				continue
			}
			if len(cl.Elts) == 1 {
				kv, isKV := cl.Elts[0].(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				kid, isKID := ast.Unparen(kv.Key).(*ast.Ident)
				if !isKID || kid.Name != "New" {
					continue
				}
				fl, isFL := ast.Unparen(kv.Value).(*ast.FuncLit)
				if !isFL || !verifyNewFuncLit(fl, &putTypes) {
					continue
				}
			}
		}
		uses := idx.UsesOf[v]
		if len(uses) == 0 {
			continue
		}
		clean := true
		var getTypes []types.Type
		for _, uid := range uses {
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || ast.Unparen(sel.X) != uid || sel.Sel == nil {
				clean = false
				break
			}
			call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
			if !isCall || ast.Unparen(call.Fun) != sel || call.Ellipsis.IsValid() {
				clean = false
				break
			}
			switch sel.Sel.Name {
			case "Put":
				if !isExprStmtNode(idx.ParentUnparen(call)) || len(call.Args) != 1 {
					clean = false
					break
				}
				if !syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
					argT := p.TypesInfo.TypeOf(call.Args[0])
					if argT == nil || isEmptyInterfaceType(argT) || syntaxutil.TypeMentionsTypeParam(argT) {
						clean = false
						break
					}
					putTypes = append(putTypes, argT)
				}
			case "Get":
				if len(call.Args) != 0 {
					clean = false
					break
				}
				switch par := idx.ParentUnparen(call).(type) {
				case *ast.TypeAssertExpr:
					if ast.Unparen(par.X) != call {
						clean = false
						break
					}
					taT, okTA := checkTypeAssertSite(par)
					if !okTA {
						clean = false
						break
					}
					getTypes = append(getTypes, taT)
				case *ast.AssignStmt:
					if par.Tok != token.DEFINE || len(par.Lhs) != 1 || len(par.Rhs) != 1 || ast.Unparen(par.Rhs[0]) != call {
						clean = false
						break
					}
					lhs0, isID := ast.Unparen(par.Lhs[0]).(*ast.Ident)
					if !isID {
						clean = false
						break
					}
					if lhs0.Name == "_" {
						break
					}
					resVar, okDef := p.TypesInfo.Defs[lhs0].(*types.Var)
					if !okDef || resVar == nil || idx.DefCounts[resVar] != 1 {
						clean = false
						break
					}
					for _, ruid := range idx.UsesOf[resVar] {
						ta, isTA := idx.ParentUnparen(ruid).(*ast.TypeAssertExpr)
						if !isTA || ast.Unparen(ta.X) != ruid {
							clean = false
							break
						}
						taT, okTA := checkTypeAssertSite(ta)
						if !okTA {
							clean = false
							break
						}
						getTypes = append(getTypes, taT)
					}
				default:
					clean = false
				}
			default:
				clean = false
			}
			if !clean {
				break
			}
		}
		if !clean || len(getTypes) == 0 {
			continue
		}
		canonT := types.Unalias(getTypes[0])
		for _, gt := range getTypes[1:] {
			if !types.Identical(canonT, types.Unalias(gt)) {
				clean = false
				break
			}
		}
		if !clean {
			continue
		}
		for _, pt := range putTypes {
			if !types.Identical(canonT, types.Unalias(pt)) {
				clean = false
				break
			}
		}
		if clean {
			out[v] = true
		}
	}
	return out
}

func valueStorageRootLocalVar(p *packages.Package, expr ast.Expr) *types.Var {
	if p == nil || p.Types == nil || p.TypesInfo == nil || expr == nil {
		return nil
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() == nil || v.Parent() == p.Types.Scope() {
				return nil
			}
			vt := types.Unalias(v.Type())
			if _, isPtr := vt.(*types.Pointer); isPtr {
				return nil
			}
			if _, isTP := vt.(*types.TypeParam); isTP {
				return nil
			}
			if st, isSt := vt.Underlying().(*types.Struct); !isSt || st.NumFields() == 0 {
				return nil
			}
			return v
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Indirect() || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
				return nil
			}
			if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
				return nil
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			if _, isArr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e.X)).(*types.Array); !isArr {
				return nil
			}
			cur = ast.Unparen(e.X)
		default:
			return nil
		}
	}
}

func collectAddrTakenLocalValueStructs(p *packages.Package) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return out
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if v := valueStorageRootLocalVar(p, x.X); v != nil {
						out[v] = true
					}
				}
			case *ast.SliceExpr:
				if _, isArr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.X)).(*types.Array); isArr {
					if v := valueStorageRootLocalVar(p, x.X); v != nil {
						out[v] = true
					}
				}
			case *ast.SelectorExpr:
				if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && refconfine.SelectionHasPointerReceiver(selInfo) {
					if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(x.X)).(*types.Pointer); !isPtr {
						if v := valueStorageRootLocalVar(p, x.X); v != nil {
							out[v] = true
						}
					}
				}
			}
			return true
		})
	}
	return out
}

func isUnaddressedLocalValueStructSlotWrite(p *packages.Package, idx *refconfine.PkgIndex, at ast.Node, lhs ast.Expr, addrTaken map[*types.Var]bool) bool {
	if p == nil || idx == nil || at == nil || lhs == nil || idx.EnclFunc[at] == nil {
		return false
	}
	v := valueStorageRootLocalVar(p, lhs)
	return v != nil && !addrTaken[v]
}

func conversionRebindsUnionStruct(dstT, srcT types.Type, uSt *types.Struct) bool {
	if dstT == nil || srcT == nil || uSt == nil {
		return false
	}
	type pair struct {
		d types.Type
		s types.Type
	}
	seen := map[pair]bool{}
	var walk func(d, s types.Type) bool
	walk = func(d, s types.Type) bool {
		if d == nil || s == nil {
			return false
		}
		d = types.Unalias(d)
		s = types.Unalias(s)
		pk := pair{d: d, s: s}
		if seen[pk] {
			return false
		}
		seen[pk] = true
		du := d.Underlying()
		su := s.Underlying()
		if du == nil || su == nil {
			return false
		}
		if (types.IdenticalIgnoreTags(du, uSt) || types.IdenticalIgnoreTags(su, uSt)) && du != su {
			return true
		}
		switch dt := du.(type) {
		case *types.Pointer:
			if st, ok := su.(*types.Pointer); ok {
				return walk(dt.Elem(), st.Elem())
			}
		case *types.Slice:
			if st, ok := su.(*types.Slice); ok {
				return walk(dt.Elem(), st.Elem())
			}
		case *types.Array:
			if st, ok := su.(*types.Array); ok {
				return walk(dt.Elem(), st.Elem())
			}
		case *types.Chan:
			if st, ok := su.(*types.Chan); ok {
				return walk(dt.Elem(), st.Elem())
			}
		case *types.Map:
			if st, ok := su.(*types.Map); ok {
				return walk(dt.Key(), st.Key()) || walk(dt.Elem(), st.Elem())
			}
		case *types.Struct:
			if st, ok := su.(*types.Struct); ok && dt != uSt && st != uSt && dt.NumFields() == st.NumFields() {
				for i := 0; i < dt.NumFields(); i++ {
					if walk(dt.Field(i).Type(), st.Field(i).Type()) {
						return true
					}
				}
			}
		}
		return false
	}
	return walk(dstT, srcT)
}

func pkgExposesUnsafePointerBoundary(p *packages.Package) bool {
	if p == nil || p.Types == nil {
		return false
	}
	sigExposes := func(sig *types.Signature) bool {
		if sig == nil {
			return false
		}
		for i := 0; i < sig.Results().Len(); i++ {
			if syntaxutil.ContainsUnsafePointer(sig.Results().At(i).Type()) {
				return true
			}
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if syntaxutil.ContainsUnsafePointer(sig.Params().At(i).Type()) {
				return true
			}
		}
		return false
	}
	return pkgExportedAPIReaches(
		p,
		syntaxutil.ContainsUnsafePointer,
		syntaxutil.ContainsUnsafePointer,
		sigExposes,
	)
}
