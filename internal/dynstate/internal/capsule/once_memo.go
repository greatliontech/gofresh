package capsule

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func rootPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	for {
		if v := syntaxutil.LookupPkgScopeVar(p, cur); v != nil {
			return v
		}
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				cur = ast.Unparen(e.X)
				continue
			}
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
			continue
		}
		return nil
	}
}

func bodyMutatesAnyPackageGlobal(p *packages.Package, body *ast.BlockStmt, mutatedVars map[string]bool) bool {
	return bodyMutatesAnyPackageGlobalWithAllowed(p, body, mutatedVars, nil, nil)
}

func bodyMutatesAnyPackageGlobalWithAllowed(
	p *packages.Package,
	body *ast.BlockStmt,
	mutatedVars map[string]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	enclFD *ast.FuncDecl,
) bool {
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if v := rootPkgScopeVar(p, lhs); v != nil && v.Pkg() == p.Types {
					if enclFD != nil && confinedCacheMaps[v][enclFD] {
						continue
					}
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if v := rootPkgScopeVar(p, x.X); v != nil && v.Pkg() == p.Types {
				bad = true
				return false
			}
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				if (x.Key != nil && rootPkgScopeVar(p, x.Key) != nil) ||
					(x.Value != nil && rootPkgScopeVar(p, x.Value) != nil) {
					bad = true
					return false
				}
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						if rootPkgScopeVar(p, x.Args[0]) != nil {
							bad = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	_ = mutatedVars
	return bad
}

func isDirectCallFuncLit(idx *refconfine.PkgIndex, lit *ast.FuncLit) bool {
	call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
	return isCall && ast.Unparen(call.Fun) == lit
}

func isDirectPanicArgWithoutRecover(p *packages.Package, idx *refconfine.PkgIndex, expr ast.Expr) bool {
	call, isC := idx.ParentUnparen(expr).(*ast.CallExpr)
	if !isC || len(call.Args) != 1 || call.Ellipsis.IsValid() || ast.Unparen(call.Args[0]) != expr {
		return false
	}
	cid, isID := ast.Unparen(call.Fun).(*ast.Ident)
	if !isID {
		return false
	}
	b, isB := p.TypesInfo.Uses[cid].(*types.Builtin)
	if !isB || b.Name() != "panic" {
		return false
	}
	var scopeBody *ast.BlockStmt
	for cur := idx.ParentMap[call]; cur != nil; cur = idx.ParentMap[cur] {
		if lit, isLit := cur.(*ast.FuncLit); isLit {
			scopeBody = lit.Body
			break
		}
		if fd, isFD := cur.(*ast.FuncDecl); isFD {
			scopeBody = fd.Body
			break
		}
	}
	if scopeBody == nil {
		return false
	}
	hasRecover := false
	ast.Inspect(scopeBody, func(n ast.Node) bool {
		if hasRecover || n == nil {
			return false
		}
		rc, okRC := n.(*ast.CallExpr)
		if !okRC {
			return true
		}
		rid, okRID := ast.Unparen(rc.Fun).(*ast.Ident)
		if !okRID {
			return true
		}
		if rb, okRB := p.TypesInfo.Uses[rid].(*types.Builtin); okRB && rb.Name() == "recover" {
			hasRecover = true
			return false
		}
		return true
	})
	return !hasRecover
}

// matchLocalSyncOnceDoCallback unifies local `once.Do(func() { ... })` callback
// verification for both memoized getter closures (`reqCachedVar != nil`) and
// statement-form local memoizer closures (`reqCachedVar == nil`).
func matchLocalSyncOnceDoCallback(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	doCall *ast.CallExpr,
	outerPos token.Pos,
	reqCachedVar *types.Var,
	allowCachedSubmut bool,
) (*ast.FuncLit, *types.Var, bool) {
	if doCall == nil || len(doCall.Args) != 1 {
		return nil, nil, false
	}
	doSel, isSel := ast.Unparen(doCall.Fun).(*ast.SelectorExpr)
	if !isSel || doSel.Sel.Name != "Do" {
		return nil, nil, false
	}
	doFn, isFn := p.TypesInfo.Uses[doSel.Sel].(*types.Func)
	if !isFn || doFn.Pkg() == nil || doFn.Pkg().Path() != "sync" || doFn.Name() != "Do" {
		return nil, nil, false
	}
	onceID, isOID := ast.Unparen(doSel.X).(*ast.Ident)
	if !isOID {
		return nil, nil, false
	}
	onceVar, _ := p.TypesInfo.Uses[onceID].(*types.Var)
	if onceVar == nil || onceVar.IsField() || onceVar.Parent() == p.Types.Scope() ||
		!syntaxutil.IsNamedInPkg(onceVar.Type(), "sync", "Once") || idx.DefCounts[onceVar] != 1 {
		return nil, nil, false
	}
	for _, ouid := range idx.UsesOf[onceVar] {
		if ouid != onceID {
			return nil, nil, false
		}
	}
	innerLit, isIL := ast.Unparen(doCall.Args[0]).(*ast.FuncLit)
	if !isIL || innerLit.Body == nil || bodyMutatesAnyPackageGlobal(p, innerLit.Body, nil) {
		return nil, nil, false
	}

	innerDefs := map[*types.Var]bool{}
	ast.Inspect(innerLit.Body, func(sn ast.Node) bool {
		if sid, isSID := sn.(*ast.Ident); isSID {
			if dv, okDV := p.TypesInfo.Defs[sid].(*types.Var); okDV && dv != nil && dv != reqCachedVar {
				innerDefs[dv] = true
			}
		}
		return true
	})

	if reqCachedVar != nil {
		if reqCachedVar.IsField() || reqCachedVar.Parent() == p.Types.Scope() || reqCachedVar.Pos() >= outerPos {
			return nil, nil, false
		}
		outerMutated := false
		ast.Inspect(innerLit.Body, func(sn ast.Node) bool {
			if outerMutated || sn == nil {
				return false
			}
			sid, isSID := sn.(*ast.Ident)
			if !isSID {
				return true
			}
			uv, isV := p.TypesInfo.Uses[sid].(*types.Var)
			if !isV || uv == nil || uv.IsField() || uv == reqCachedVar || innerDefs[uv] {
				return true
			}
			if freshalloc.IdentReachesMutatedOrAddrPrefix(p, idx, sid) {
				outerMutated = true
				return false
			}
			if bCall, isBC := idx.ParentUnparen(sid).(*ast.CallExpr); isBC && len(bCall.Args) > 0 && ast.Unparen(bCall.Args[0]) == sid {
				if cid, isCID := ast.Unparen(bCall.Fun).(*ast.Ident); isCID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							outerMutated = true
							return false
						}
					}
				}
			}
			return true
		})
		if outerMutated {
			return nil, nil, false
		}
		return innerLit, reqCachedVar, true
	}

	writtenOuter := map[*types.Var]bool{}
	badOuter := false
	ast.Inspect(innerLit.Body, func(sn ast.Node) bool {
		if badOuter || sn == nil {
			return false
		}
		sid, isSID := sn.(*ast.Ident)
		if !isSID {
			return true
		}
		uv, okUV := p.TypesInfo.Uses[sid].(*types.Var)
		if !okUV || uv == nil || uv.IsField() || uv.Pkg() != p.Types || uv.Parent() == p.Types.Scope() || innerDefs[uv] {
			return true
		}
		if refconfine.IdentOrExprIsWritten(idx, sid) {
			writtenOuter[uv] = true
			return true
		}
		if !allowCachedSubmut && freshalloc.IdentReachesMutatedOrAddrPrefix(p, idx, sid) {
			badOuter = true
			return false
		}
		return true
	})
	if badOuter || len(writtenOuter) != 1 {
		return nil, nil, false
	}
	var cachedVar *types.Var
	for cv := range writtenOuter {
		cachedVar = cv
	}
	if cachedVar.Pos() >= outerPos {
		return nil, nil, false
	}
	return innerLit, cachedVar, true
}

func isMemoizedOnceGetterClosure(p *packages.Package, idx *refconfine.PkgIndex, lit *ast.FuncLit) (*ast.BlockStmt, bool) {
	if lit.Type.Params != nil && len(lit.Type.Params.List) > 0 {
		return nil, false
	}
	if lit.Type.Results == nil || len(lit.Type.Results.List) != 1 || lit.Body == nil || len(lit.Body.List) != 2 {
		return nil, false
	}
	exprStmt, isES := lit.Body.List[0].(*ast.ExprStmt)
	retStmt, isRet := lit.Body.List[1].(*ast.ReturnStmt)
	if !isES || !isRet || len(retStmt.Results) != 1 {
		return nil, false
	}
	doCall, isCall := ast.Unparen(exprStmt.X).(*ast.CallExpr)
	if !isCall {
		return nil, false
	}
	retExpr := ast.Unparen(retStmt.Results[0])
	if un, isUn := retExpr.(*ast.UnaryExpr); isUn && un.Op == token.AND {
		retExpr = ast.Unparen(un.X)
	}
	cachedID, isCID := retExpr.(*ast.Ident)
	if !isCID {
		return nil, false
	}
	cachedVar, _ := p.TypesInfo.Uses[cachedID].(*types.Var)
	if cachedVar == nil {
		return nil, false
	}
	innerLit, _, ok := matchLocalSyncOnceDoCallback(p, idx, doCall, lit.Pos(), cachedVar, true)
	if !ok {
		return nil, false
	}
	for _, uid := range idx.UsesOf[cachedVar] {
		if uid.Pos() < innerLit.Body.Pos() || uid.Pos() >= innerLit.Body.End() {
			if uid != cachedID {
				return nil, false
			}
		}
	}
	return innerLit.Body, true
}

func isSafeSyncOnceMemoType(t types.Type, isConeImmPtr func(types.Type) bool) bool {
	if t == nil {
		return false
	}
	if iface, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
		return iface.NumMethods() > 0
	}
	return !refconfine.TypeCarriesMutableRefWith(t, isConeImmPtr)
}

func findLocalSyncOnceMemoizerCandidates(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
) map[*ast.FuncLit]*types.Var {
	if fd == nil || fd.Body == nil || idx.FlowCache(p).FuncBody(fd).HasGotoAnywhere() {
		return nil
	}
	uninitLocals := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		vs, okVS := n.(*ast.ValueSpec)
		if !okVS || len(vs.Values) != 0 {
			return true
		}
		for _, nm := range vs.Names {
			if v, okV := p.TypesInfo.Defs[nm].(*types.Var); okV && v != nil && idx.DefCounts[v] == 1 && !idx.InFuncLit[nm] && !idx.InGoStmt[nm] {
				uninitLocals[v] = true
			}
		}
		return true
	})

	var out map[*ast.FuncLit]*types.Var
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, okAs := n.(*ast.AssignStmt)
		if !okAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		initID, okID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !okID || idx.InFuncLit[initID] || idx.InGoStmt[initID] {
			return true
		}
		initVar, _ := p.TypesInfo.Defs[initID].(*types.Var)
		if initVar == nil || idx.DefCounts[initVar] != 1 {
			return true
		}
		outerLit, okOL := ast.Unparen(as.Rhs[0]).(*ast.FuncLit)
		if !okOL || outerLit.Body == nil || len(outerLit.Body.List) != 1 {
			return true
		}
		if (outerLit.Type.Params != nil && len(outerLit.Type.Params.List) > 0) ||
			(outerLit.Type.Results != nil && len(outerLit.Type.Results.List) > 0) {
			return true
		}
		es, okES := outerLit.Body.List[0].(*ast.ExprStmt)
		if !okES {
			return true
		}
		doCall, okDC := ast.Unparen(es.X).(*ast.CallExpr)
		if !okDC {
			return true
		}
		for _, iuid := range idx.UsesOf[initVar] {
			icall, okIC := idx.ParentUnparen(iuid).(*ast.CallExpr)
			if !okIC || ast.Unparen(icall.Fun) != iuid || len(icall.Args) != 0 {
				return true
			}
			if _, okIES := idx.ParentMap[icall].(*ast.ExprStmt); !okIES {
				return true
			}
		}
		innerLit, cachedVar, ok := matchLocalSyncOnceDoCallback(p, idx, doCall, outerLit.Pos(), nil, false)
		if !ok || !uninitLocals[cachedVar] {
			return true
		}

		isInitCallStmt := func(st ast.Stmt) bool {
			ies, ok := st.(*ast.ExprStmt)
			if !ok {
				return false
			}
			ic, ok := ast.Unparen(ies.X).(*ast.CallExpr)
			if !ok || len(ic.Args) != 0 {
				return false
			}
			iid, ok := ast.Unparen(ic.Fun).(*ast.Ident)
			return ok && p.TypesInfo.Uses[iid] == initVar
		}

		allUsesDominated := true
		for _, cuid := range idx.UsesOf[cachedVar] {
			if innerLit.Body.Pos() <= cuid.Pos() && cuid.Pos() < innerLit.Body.End() {
				if un, isUn := idx.ParentUnparen(cuid).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					allUsesDominated = false
					break
				}
				continue
			}
			if refconfine.IdentIsWrittenOrAddrTaken(idx, cuid) {
				allUsesDominated = false
				break
			}
			if ta, isTA := idx.ParentUnparen(cuid).(*ast.TypeAssertExpr); isTA && ast.Unparen(ta.X) == cuid {
				allUsesDominated = false
				break
			}
			dominated := false
			for cur := idx.ParentMap[cuid]; cur != nil; cur = idx.ParentMap[cur] {
				if blk, isBlk := cur.(*ast.BlockStmt); isBlk {
					for _, bst := range blk.List {
						if bst.Pos() >= cuid.Pos() {
							break
						}
						if isInitCallStmt(bst) && bst.End() <= cuid.Pos() {
							dominated = true
							break
						}
						switch bst.(type) {
						case *ast.ReturnStmt, *ast.BranchStmt, *ast.LabeledStmt:
							break
						}
					}
					if dominated {
						break
					}
				}
				if _, isLit := cur.(*ast.FuncLit); isLit {
					break
				}
				if _, isFD := cur.(*ast.FuncDecl); isFD {
					break
				}
			}
			if !dominated {
				allUsesDominated = false
				break
			}
		}
		if allUsesDominated {
			if out == nil {
				out = map[*ast.FuncLit]*types.Var{}
			}
			out[innerLit] = cachedVar
		}
		return true
	})
	return out
}

