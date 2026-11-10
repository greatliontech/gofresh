package protoaudit

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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

// matchLocalSyncOnceDoCallback unifies the shared `once.Do(func() { ... })`
// callback structural verification for both:
//   - Shape 1 (`isMemoizedOnceGetterClosure`): `func() R { once.Do(func() { ... }); return cached }`
//     where `reqCachedVar != nil` names the returned outer local variable.
//   - Shape 2 (`findLocalSyncOnceMemoizerCandidates`): `init := func() { once.Do(func() { ... }) }`
//     where `reqCachedVar == nil` and the callback writes to a single outer local variable.
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
			if freshstruct.IdentReachesMutatedOrAddrPrefix(p, idx, sid) {
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
		if !allowCachedSubmut && freshstruct.IdentReachesMutatedOrAddrPrefix(p, idx, sid) {
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
	if fd == nil || fd.Body == nil || freshstruct.FuncBodyHasGoto(fd.Body) {
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

func typeMentionsNamedStruct(root types.Type, target *types.Named) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if t == target {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func matchLocalBuilderOnlyAdapter(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	cs *types.Named,
	checkNormalField func(types.Type) bool,
) (builderGuard syntaxutil.TypeRef, methodGuards []syntaxutil.FuncKey, exemptFields []*types.Var, ok bool) {
	if cs == nil || cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	if types.NewMethodSet(types.NewPointer(cs)).Len() != types.NewMethodSet(cs).Len() {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	cst, okSt := cs.Underlying().(*types.Struct)
	if !okSt || cst.NumFields() == 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}

	for _, name := range p.Types.Scope().Names() {
		switch obj := p.Types.Scope().Lookup(name).(type) {
		case *types.Var:
			if typeMentionsNamedStruct(obj.Type(), cs) {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
		case *types.TypeName:
			if obj.Type() == cs || obj.IsAlias() {
				continue
			}
			if st, isS := obj.Type().Underlying().(*types.Struct); isS {
				for i := 0; i < st.NumFields(); i++ {
					if typeMentionsNamedStruct(st.Field(i).Type(), cs) {
						return syntaxutil.TypeRef{}, nil, nil, false
					}
				}
			}
		}
	}

	sawLit := false
	validUses := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !validUses || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND && syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
					validUses = false
					return false
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" && syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
						validUses = false
						return false
					}
				}
			case *ast.CompositeLit:
				if types.Unalias(p.TypesInfo.TypeOf(x)) == cs {
					sawLit = true
					kv, isKV := idx.ParentUnparen(x).(*ast.KeyValueExpr)
					if !isKV || ast.Unparen(kv.Value) != x {
						validUses = false
						return false
					}
					bLit, isBL := idx.ParentUnparen(kv).(*ast.CompositeLit)
					if !isBL {
						validUses = false
						return false
					}
					bSel, isBS := idx.ParentUnparen(bLit).(*ast.SelectorExpr)
					if !isBS || ast.Unparen(bSel.X) != bLit || bSel.Sel.Name != "Build" {
						validUses = false
						return false
					}
					bCall, isBC := idx.ParentUnparen(bSel).(*ast.CallExpr)
					if !isBC || ast.Unparen(bCall.Fun) != bSel || len(bCall.Args) != 0 {
						validUses = false
						return false
					}
					bNamed, isBN := types.Unalias(p.TypesInfo.TypeOf(bLit)).(*types.Named)
					if !isBN || bNamed.Obj() == nil || bNamed.Obj().Pkg() == nil || bNamed.Obj().Pkg() == p.Types || syntaxutil.IsStandardLibraryPkgPath(bNamed.Obj().Pkg().Path()) {
						validUses = false
						return false
					}
					ref := syntaxutil.TypeRef{Pkg: bNamed.Obj().Pkg().Path(), Name: bNamed.Obj().Name()}
					if !ref.Valid() || (!builderGuard.IsZero() && builderGuard != ref) {
						validUses = false
						return false
					}
					builderGuard = ref
				}
			}
			return true
		})
	}
	if !validUses || !sawLit || builderGuard.IsZero() {
		return syntaxutil.TypeRef{}, nil, nil, false
	}

	methodSet := map[syntaxutil.FuncKey]bool{}
	for i := 0; i < cst.NumFields(); i++ {
		f := cst.Field(i)
		if f.Exported() {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		if checkNormalField(f.Type()) {
			continue
		}
		ptr, isP := types.Unalias(f.Type()).(*types.Pointer)
		if !isP {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		elemN, isEN := types.Unalias(ptr.Elem()).(*types.Named)
		if !isEN || elemN.Obj() == nil || elemN.Obj().Pkg() == nil || elemN.Obj().Pkg() == p.Types || syntaxutil.IsStandardLibraryPkgPath(elemN.Obj().Pkg().Path()) {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		if _, isElemSt := elemN.Underlying().(*types.Struct); !isElemSt {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		for _, fuid := range idx.UsesOf[f] {
			fsel, isFS := idx.ParentUnparen(fuid).(*ast.SelectorExpr)
			if !isFS || fsel.Sel != fuid {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			msel, isMS := idx.ParentUnparen(fsel).(*ast.SelectorExpr)
			if !isMS || ast.Unparen(msel.X) != fsel {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			si := p.TypesInfo.Selections[msel]
			if si == nil || si.Kind() != types.MethodVal || syntaxutil.SelectionCrossesEmbeddedPointer(si) {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			mfn, okM := si.Obj().(*types.Func)
			if !okM || mfn == nil || mfn.Pkg() != elemN.Obj().Pkg() || !mfn.Exported() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			mcall, isMC := idx.ParentUnparen(msel).(*ast.CallExpr)
			if !isMC || ast.Unparen(mcall.Fun) != msel || mcall.Ellipsis.IsValid() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			for _, marg := range mcall.Args {
				if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(marg)) {
					return syntaxutil.TypeRef{}, nil, nil, false
				}
			}
			mk := syntaxutil.FuncKey{Pkg: elemN.Obj().Pkg().Path(), Name: elemN.Obj().Name() + "." + mfn.Name()}
			if !mk.Valid() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			methodSet[mk] = true
		}
		exemptFields = append(exemptFields, f)
	}
	if len(exemptFields) == 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	for mk := range methodSet {
		methodGuards = append(methodGuards, mk)
	}
	slices.SortFunc(methodGuards, syntaxutil.FuncKey.Compare)
	return builderGuard, methodGuards, exemptFields, true
}

func verifyOnceInitConeImmutability(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ownerRef syntaxutil.TypeRef,
	onceFn *types.Func,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	verifiedMsgRoots map[*types.Named]bool,
	mutatedVars map[string]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, bool) {
	if onceFn == nil || !ownerRef.Valid() {
		return nil, nil, false
	}
	fullInitCone := map[*types.Func]bool{onceFn: true}
	coneConstructedStructs := map[*types.Named]bool{}
	coneCrossDescStructs := map[*types.Named]bool{}
	var coneLits []*ast.FuncLit
	memoCandidatesByFn := map[*types.Func]map[*ast.FuncLit]*types.Var{}
	queue := []*types.Func{onceFn}
	valid := true

	addConeStruct := func(stN *types.Named) {
		if stN == nil || family[stN] || childProtected[stN] || verifiedMsgRoots[stN] {
			return
		}
		if stN.Obj() != nil && stN.Obj().Pkg() != nil && stN.Obj().Pkg() != p.Types && !syntaxutil.IsStandardLibraryPkgPath(stN.Obj().Pkg().Path()) {
			coneCrossDescStructs[stN] = true
			return
		}
		coneConstructedStructs[stN] = true
	}

	isBaseImmPtr := func(tp types.Type) bool {
		ptr, ok := types.Unalias(tp).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (family[elem] || childProtected[elem] || verifiedMsgRoots[elem])
	}

	for len(queue) > 0 && valid {
		curFn := queue[0]
		queue = queue[1:]
		fd := idx.FuncDecls[curFn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, false
		}
		memoCands := findLocalSyncOnceMemoizerCandidates(p, idx, fd)
		if len(memoCands) > 0 {
			memoCandidatesByFn[curFn] = memoCands
		}
		isMemoLit := func(lit *ast.FuncLit) bool {
			cv := memoCands[lit]
			return cv != nil && isSafeSyncOnceMemoType(cv.Type(), isBaseImmPtr)
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt:
				valid = false
				return false
			case *ast.FuncLit:
				if !isDirectCallFuncLit(idx, x) {
					coneLits = append(coneLits, x)
					if !isMemoLit(x) {
						hasMemoInner := false
						var nestedLits []*ast.FuncLit
						ast.Inspect(x.Body, func(sn ast.Node) bool {
							if sn == nil {
								return false
							}
							if _, isG := sn.(*ast.GoStmt); isG {
								valid = false
								return false
							}
							if il, ok := sn.(*ast.FuncLit); ok && il != x {
								if !isDirectCallFuncLit(idx, il) {
									nestedLits = append(nestedLits, il)
								}
								if isMemoLit(il) {
									hasMemoInner = true
								}
							}
							return true
						})
						if !valid {
							return false
						}
						if !hasMemoInner {
							coneLits = append(coneLits, nestedLits...)
							return false
						}
					}
				}
				return true
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if isDirectPanicArgWithoutRecover(p, idx, x) {
						return true
					}
					if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
						if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
							stN := syntaxutil.DerefNamedStruct(ptr)
							if stN == nil {
								valid = false
								return false
							}
							addConeStruct(stN)
						}
					}
				}
			case *ast.CompositeLit:
				if lt := p.TypesInfo.TypeOf(x); lt != nil {
					if _, isPtr := types.Unalias(lt).(*types.Pointer); !isPtr {
						if _, isSt := types.Unalias(lt).Underlying().(*types.Struct); isSt {
							if refconfine.TypeCarriesMutableRef(lt) && types.NewMethodSet(lt).Len() > 0 {
								stN := syntaxutil.DerefNamedStruct(lt)
								if stN == nil {
									valid = false
									return false
								}
								addConeStruct(stN)
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						if !isDirectPanicArgWithoutRecover(p, idx, x) {
							if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
								if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
									stN := syntaxutil.DerefNamedStruct(ptr)
									if stN == nil {
										valid = false
										return false
									}
									addConeStruct(stN)
								}
							}
						}
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
					} else if callee.Pkg() == p.Types && !fullInitCone[callee] {
						fullInitCone[callee] = true
						queue = append(queue, callee)
					}
				}
			}
			return true
		})
	}
	if !valid {
		return nil, nil, false
	}

	isConeImmStruct := func(st *types.Named) bool {
		return st != nil && (family[st] || childProtected[st] || verifiedMsgRoots[st] || coneConstructedStructs[st] || coneCrossDescStructs[st])
	}
	isConeImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && isConeImmStruct(elem)
	}

	condSet := map[syntaxutil.ConditionalStructMutation]bool{}
	for extSt := range coneCrossDescStructs {
		extRef := syntaxutil.TypeRef{Pkg: extSt.Obj().Pkg().Path(), Name: extSt.Obj().Name()}
		if !extRef.Valid() {
			return nil, nil, false
		}
		condSet[syntaxutil.ConditionalStructMutation{
			Struct:                  ownerRef,
			GuardStruct:             extRef,
			RequireDescBuilderGuard: true,
		}] = true
	}

	var coneGuards []syntaxutil.TypeRef
	if len(coneConstructedStructs) > 0 {
		isEmbeddedNonEmptyIface := func(f *types.Var) bool {
			if !f.Embedded() {
				return false
			}
			iface, ok := types.Unalias(f.Type()).Underlying().(*types.Interface)
			return ok && iface.NumMethods() > 0
		}
		checkConeFieldType := func(root types.Type, rootSamePkgStruct bool) bool {
			seenFieldTypes := map[types.Type]bool{}
			var walk func(t types.Type, inSamePkgStruct bool) bool
			walk = func(t types.Type, inSamePkgStruct bool) bool {
				if t == nil {
					return false
				}
				t = types.Unalias(t)
				if seenFieldTypes[t] {
					return true
				}
				seenFieldTypes[t] = true
				if n, isN := t.(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						return types.NewMethodSet(types.NewPointer(n)).Len() == types.NewMethodSet(n).Len()
					}
				}
				switch u := t.Underlying().(type) {
				case *types.Interface, *types.Signature:
					return true
				case *types.Basic:
					return !(inSamePkgStruct && u.Kind() == types.UnsafePointer)
				case *types.Chan, *types.TypeParam:
					return false
				case *types.Pointer:
					elem, isEN := types.Unalias(u.Elem()).(*types.Named)
					return isEN && isConeImmStruct(elem)
				case *types.Slice:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Array:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Map:
					return walk(u.Key(), inSamePkgStruct) && walk(u.Elem(), inSamePkgStruct)
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						f := u.Field(i)
						if inSamePkgStruct && f.Exported() && !isEmbeddedNonEmptyIface(f) {
							return false
						}
						subSamePkg := inSamePkgStruct
						if subN, isSN := types.Unalias(f.Type()).(*types.Named); isSN && subN.Obj() != nil {
							subSamePkg = subN.Obj().Pkg() == p.Types
						}
						if !walk(f.Type(), subSamePkg) {
							return false
						}
					}
					return true
				}
				return true
			}
			return walk(root, rootSamePkgStruct)
		}

		adapterExemptFields := map[*types.Var]bool{}
		for cs := range coneConstructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, false
			}
			cst, okS := cs.Underlying().(*types.Struct)
			if !okS {
				return nil, nil, false
			}
			normalOK := true
			for i := 0; i < cst.NumFields(); i++ {
				f := cst.Field(i)
				if (f.Exported() && !isEmbeddedNonEmptyIface(f)) || !checkConeFieldType(f.Type(), true) {
					normalOK = false
					break
				}
			}
			if !normalOK {
				bGuard, mGuards, exFields, okAdapter := matchLocalBuilderOnlyAdapter(p, idx, cs, func(ft types.Type) bool {
					return checkConeFieldType(ft, true)
				})
				if !okAdapter {
					return nil, nil, false
				}
				condSet[syntaxutil.ConditionalStructMutation{
					Struct:                  ownerRef,
					GuardStruct:             bGuard,
					RequireDescBuilderGuard: true,
				}] = true
				for _, mk := range mGuards {
					condSet[syntaxutil.ConditionalStructMutation{
						Struct:                   ownerRef,
						RequireNonMutatingMethod: mk,
					}] = true
				}
				for _, ef := range exFields {
					adapterExemptFields[ef] = true
				}
			}
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, false
			}
			coneGuards = append(coneGuards, ref)
		}
		if refconfine.PkgHasAnyMutationOnStructs(p, coneConstructedStructs, nil) {
			return nil, nil, false
		}
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index:                         idx,
			IsImmutablePtr:                isConeImmPtr,
			AllowReturnFromUnexportedFunc: true,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel {
					return false, false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false, false
				}
				if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && adapterExemptFields[fObj] {
					return false, false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if coneConstructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if n, isN := types.Unalias(ft).(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						return false, false
					}
				}
				if refconfine.IsDirectMutableRefWith(ft, isConeImmPtr) {
					return true, true
				}
				if refconfine.TypeCarriesMutableRefWith(ft, isConeImmPtr) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
			},
		}) {
			return nil, nil, false
		}
		sort.Slice(coneGuards, func(i, j int) bool { return coneGuards[i].Key() < coneGuards[j].Key() })
	}

	if len(coneLits) > 0 {
		memoAllowedWrite := map[*ast.FuncLit]*types.Var{}
		for _, cands := range memoCandidatesByFn {
			for lit, cv := range cands {
				if isSafeSyncOnceMemoType(cv.Type(), isConeImmPtr) {
					memoAllowedWrite[lit] = cv
				}
			}
		}

		capturedRefIdents := map[*ast.Ident]bool{}
		for _, lit := range coneLits {
			allowedCachedVar := memoAllowedWrite[lit]
			ast.Inspect(lit.Body, func(n ast.Node) bool {
				if !valid || n == nil {
					return false
				}
				if nl, isNL := n.(*ast.FuncLit); isNL && nl != lit && !isDirectCallFuncLit(idx, nl) {
					return false
				}
				uid, isID := n.(*ast.Ident)
				if !isID {
					return true
				}
				v, isV := p.TypesInfo.Uses[uid].(*types.Var)
				if !isV || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() || v.Pos() >= lit.Pos() {
					return true
				}
				if refconfine.IdentOrExprIsWritten(idx, uid) {
					if allowedCachedVar != nil && v == allowedCachedVar {
						return true
					}
					valid = false
					return false
				}
				if un, isUn := idx.ParentUnparen(uid).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					if !isConeImmPtr(p.TypesInfo.TypeOf(un)) {
						valid = false
						return false
					}
				}
				if refconfine.TypeCarriesMutableRefWith(v.Type(), isConeImmPtr) {
					capturedRefIdents[uid] = true
				}
				return true
			})
			if !valid {
				return nil, nil, false
			}
		}
		if len(capturedRefIdents) > 0 {
			if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
				Index:                         idx,
				IsImmutablePtr:                isConeImmPtr,
				AllowReturnFromUnexportedFunc: true,
				AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
					return syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(containerExpr), "reflect", "StructField")
				},
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					id, isID := ast.Unparen(expr).(*ast.Ident)
					if !isID || !capturedRefIdents[id] {
						return false, false
					}
					vt := p.TypesInfo.TypeOf(id)
					if refconfine.IsDirectMutableRefWith(vt, isConeImmPtr) {
						return true, true
					}
					if refconfine.TypeCarriesMutableRefWith(vt, isConeImmPtr) {
						return false, true
					}
					return false, false
				},
				AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
					return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
				},
			}) {
				return nil, nil, false
			}
		}
	}

	var conds []syntaxutil.ConditionalStructMutation
	for cm := range condSet {
		conds = append(conds, cm)
	}
	slices.SortFunc(conds, syntaxutil.ConditionalStructMutation.Compare)
	return coneGuards, conds, true
}

func verifyAtomicCASPointerStruct(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	rootNamed *types.Named,
) (*ast.FuncDecl, map[ast.Node]bool, []syntaxutil.TypeRef) {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() != p.Types || named.Obj().Exported() || named.TypeParams().Len() > 0 || types.NewMethodSet(named).Len() != 0 {
		return nil, nil, nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() != 1 || st.Field(0).Exported() {
		return nil, nil, nil
	}
	b, ok := types.Unalias(st.Field(0).Type()).Underlying().(*types.Basic)
	if !ok || b.Kind() != types.UnsafePointer {
		return nil, nil, nil
	}
	pset := types.NewMethodSet(types.NewPointer(named))
	if pset.Len() != 1 {
		return nil, nil, nil
	}
	m, ok := pset.At(0).Obj().(*types.Func)
	if !ok || m.Pkg() != p.Types {
		return nil, nil, nil
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil, nil, nil
	}
	retPtr, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
	if !ok {
		return nil, nil, nil
	}
	retNamed, ok := types.Unalias(retPtr.Elem()).(*types.Named)
	if !ok || retNamed.Obj() == nil || retNamed.Obj().Pkg() != p.Types || retNamed.Obj().Exported() || retNamed.TypeParams().Len() > 0 {
		return nil, nil, nil
	}
	if _, isSt := retNamed.Underlying().(*types.Struct); !isSt {
		return nil, nil, nil
	}
	fd := idx.FuncDecls[m]
	if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobal(p, fd.Body, nil) {
		return nil, nil, nil
	}

	unmutatedRootParams := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if !syntaxutil.IsPtrToNamed(pv.Type(), rootNamed) {
			continue
		}
		clean := true
		for _, uid := range idx.UsesOf[pv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				clean = false
				break
			}
		}
		if clean {
			unmutatedRootParams[pv] = true
		}
	}

	isValidCASAllocLit := func(expr ast.Expr) bool {
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL || syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl)) != retNamed {
			return false
		}
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			val := ast.Unparen(kv.Value)
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if syntaxutil.IsPtrToNamed(vt, rootNamed) {
				pid, isID := val.(*ast.Ident)
				if !isID {
					return false
				}
				pv, _ := p.TypesInfo.Uses[pid].(*types.Var)
				if pv == nil || !unmutatedRootParams[pv] {
					return false
				}
				continue
			}
			if refconfine.TypeContainsRefOrPointer(vt) {
				return false
			}
		}
		return true
	}

	allocLocals := map[*types.Var]bool{}
	loadLocals := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID {
			return true
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.DefCounts[lv] != 1 {
			return true
		}
		if isValidCASAllocLit(as.Rhs[0]) {
			allocLocals[lv] = true
		} else if rc, isRC := ast.Unparen(as.Rhs[0]).(*ast.CallExpr); isRC && len(rc.Args) == 1 {
			if cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr); isCS {
				if afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func); isFn && afn.Pkg() != nil && afn.Pkg().Path() == "sync/atomic" && afn.Name() == "LoadPointer" {
					loadLocals[lv] = true
				}
			}
		}
		return true
	})
	for lv := range allocLocals {
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				delete(allocLocals, lv)
				break
			}
		}
	}
	for lv := range loadLocals {
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				delete(loadLocals, lv)
				break
			}
		}
	}

	fld := st.Field(0)
	casAddrExempt := map[ast.Node]bool{}
	allowedUnsafeConvs := map[*ast.CallExpr]bool{}
	sawCAS := false
	for _, id := range idx.UsesOf[fld] {
		if !idx.IsSyncInFuncDecl(id, fd) {
			return nil, nil, nil
		}
		sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, nil, nil
		}
		un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return nil, nil, nil
		}
		call, isCall := idx.ParentUnparen(un).(*ast.CallExpr)
		if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != un {
			return nil, nil, nil
		}
		selFun, isSF := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSF {
			return nil, nil, nil
		}
		afn, isFn := p.TypesInfo.Uses[selFun.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" {
			return nil, nil, nil
		}
		switch afn.Name() {
		case "LoadPointer":
			if len(call.Args) != 1 {
				return nil, nil, nil
			}
		case "CompareAndSwapPointer":
			if len(call.Args) != 3 || !syntaxutil.IsNilIdent(p.TypesInfo, call.Args[1]) {
				return nil, nil, nil
			}
			conv, isConv := ast.Unparen(call.Args[2]).(*ast.CallExpr)
			if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() {
				return nil, nil, nil
			}
			wExpr := ast.Unparen(conv.Args[0])
			if !isValidCASAllocLit(wExpr) {
				wid, isID := wExpr.(*ast.Ident)
				if !isID {
					return nil, nil, nil
				}
				wv, _ := p.TypesInfo.Uses[wid].(*types.Var)
				if wv == nil || !allocLocals[wv] {
					return nil, nil, nil
				}
			}
			allowedUnsafeConvs[conv] = true
			sawCAS = true
		default:
			return nil, nil, nil
		}
		casAddrExempt[un] = true
	}
	if !sawCAS {
		return nil, nil, nil
	}

	returnsValid := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !returnsValid || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.FuncLit, *ast.GoStmt:
			returnsValid = false
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) != 1 {
			returnsValid = false
			return false
		}
		conv, isConv := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !syntaxutil.IsPtrToNamed(p.TypesInfo.Types[conv.Fun].Type, retNamed) {
			returnsValid = false
			return false
		}
		src := ast.Unparen(conv.Args[0])
		if rid, isID := src.(*ast.Ident); isID {
			rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
			if rv == nil || !loadLocals[rv] {
				returnsValid = false
				return false
			}
			return true
		}
		rc, isRC := src.(*ast.CallExpr)
		if !isRC || len(rc.Args) != 1 {
			returnsValid = false
			return false
		}
		cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr)
		if !isCS {
			returnsValid = false
			return false
		}
		afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "LoadPointer" {
			returnsValid = false
			return false
		}
		return true
	})
	if !returnsValid {
		return nil, nil, nil
	}

	casTargets := map[*types.Named]bool{named: true, retNamed: true}
	casPtrConvs := map[*ast.CallExpr]bool{}
	convValid := true
	expanded := true
	for expanded && convValid {
		expanded = false
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !convValid || n == nil {
					return false
				}
				conv, isConv := n.(*ast.CallExpr)
				if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || allowedUnsafeConvs[conv] {
					return true
				}
				argT := types.Unalias(p.TypesInfo.TypeOf(conv.Args[0]))
				srcPtr, isSrcPtr := argT.(*types.Pointer)
				if !isSrcPtr {
					return true
				}
				srcNamed, isSN := types.Unalias(srcPtr.Elem()).(*types.Named)
				if !isSN || !casTargets[srcNamed] {
					return true
				}
				dstT := types.Unalias(p.TypesInfo.Types[conv.Fun].Type)
				dstPtr, isDstPtr := dstT.(*types.Pointer)
				if !isDstPtr {
					convValid = false
					return false
				}
				dstSt, isDN := types.Unalias(dstPtr.Elem()).(*types.Named)
				if !isDN || dstSt == nil || dstSt.Obj() == nil || dstSt.Obj().Pkg() != p.Types || dstSt.Obj().Exported() || dstSt.TypeParams().Len() > 0 {
					convValid = false
					return false
				}
				if _, isStruct := dstSt.Underlying().(*types.Struct); !isStruct {
					convValid = false
					return false
				}
				casPtrConvs[conv] = true
				if !casTargets[dstSt] {
					casTargets[dstSt] = true
					expanded = true
				}
				return true
			})
		}
	}
	if !convValid {
		return nil, nil, nil
	}

	allCASProtected := map[*types.Named]bool{named: true}
	checkedCASSub := map[*types.Named]bool{}
	var verifyCASStruct func(cn *types.Named, isSub bool) bool
	verifyCASStruct = func(cn *types.Named, isSub bool) bool {
		if cn == nil || cn.Obj() == nil || cn.Obj().Pkg() != p.Types || cn.Obj().Exported() || cn.TypeParams().Len() > 0 {
			return false
		}
		if isSub {
			if checkedCASSub[cn] {
				return true
			}
		} else if allCASProtected[cn] {
			return true
		}
		cst, okS := cn.Underlying().(*types.Struct)
		if !okS {
			return false
		}
		if isSub {
			if types.NewMethodSet(types.NewPointer(cn)).Len() != types.NewMethodSet(cn).Len() {
				return false
			}
			checkedCASSub[cn] = true
		} else {
			allCASProtected[cn] = true
		}
		for i := 0; i < cst.NumFields(); i++ {
			cf := cst.Field(i)
			if cf.Exported() {
				return false
			}
			ft := types.Unalias(cf.Type())
			if !isSub && syntaxutil.IsPtrToNamed(ft, rootNamed) {
				continue
			}
			elem := ft
			zeroLenArray := false
			for {
				ar, isAr := elem.Underlying().(*types.Array)
				if !isAr {
					break
				}
				if ar.Len() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					zeroLenArray = true
					break
				}
				elem = types.Unalias(ar.Elem())
			}
			if zeroLenArray && types.NewMethodSet(types.NewPointer(ft)).Len() == 0 {
				continue
			}
			if subSt, isSt := elem.Underlying().(*types.Struct); isSt {
				if subN, isSubN := elem.(*types.Named); isSubN {
					if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(subN)).Len() == 0 {
						continue
					}
					if !verifyCASStruct(subN, true) {
						return false
					}
					continue
				}
				if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					continue
				}
				return false
			}
			if !refconfine.TypeContainsRefOrPointer(elem) {
				continue
			}
			if isSub && elem == ft {
				if ub, isB := elem.Underlying().(*types.Basic); isB && ub.Kind() == types.UnsafePointer {
					continue
				}
			}
			return false
		}
		return true
	}
	for ct := range casTargets {
		if ct == named {
			continue
		}
		if !verifyCASStruct(ct, false) {
			return nil, nil, nil
		}
	}
	if refconfine.PkgHasAnyMutationOnStructs(p, allCASProtected, casAddrExempt) {
		return nil, nil, nil
	}

	casExempt := make(map[ast.Node]bool, len(casAddrExempt)+len(allowedUnsafeConvs)+len(casPtrConvs))
	for n := range casAddrExempt {
		casExempt[n] = true
	}
	for c := range allowedUnsafeConvs {
		casExempt[c] = true
	}
	for c := range casPtrConvs {
		casExempt[c] = true
	}

	guards := make([]syntaxutil.TypeRef, 0, len(allCASProtected))
	for ct := range allCASProtected {
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: ct.Obj().Name()}
		if !ref.Valid() {
			return nil, nil, nil
		}
		guards = append(guards, ref)
	}
	sort.Slice(guards, func(i, j int) bool { return guards[i].Key() < guards[j].Key() })
	return fd, casExempt, guards
}
