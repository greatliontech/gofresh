package freshalloc

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isDirectFreshConstructExpr(p *packages.Package, expr ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return isFreshConstructableRootType(p.TypesInfo.TypeOf(e)) && cl != nil
			}
		}
	case *ast.CallExpr:
		if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
			return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
		}
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "make" {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
				if b.Name() == "append" && len(e.Args) >= 1 && syntaxutil.IsTypedNilSliceConv(p, e.Args[0]) && appendArgsAreFresh(p, e, freshReturnFuncs) {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
			}
		}
		if callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func appendArgsAreFresh(p *packages.Package, call *ast.CallExpr, freshReturnFuncs map[*types.Func]bool) bool {
	return appendArgsAreFreshWithDeferred(p, call, freshReturnFuncs, nil, nil)
}

func appendArgsAreFreshWithDeferred(
	p *packages.Package,
	call *ast.CallExpr,
	freshReturnFuncs map[*types.Func]bool,
	field *types.Var,
	deferred *[]deferredFieldAssignVar,
) bool {
	if call == nil || len(call.Args) < 1 {
		return false
	}
	var checkpoint int
	if deferred != nil {
		checkpoint = len(*deferred)
	}
	rollback := func() bool {
		if deferred != nil {
			*deferred = (*deferred)[:checkpoint]
		}
		return false
	}
	if call.Ellipsis.IsValid() {
		if len(call.Args) != 2 || !isFreshFieldAssignRHSWithDeferred(p, nil, call.Args[1], freshReturnFuncs, field, deferred) {
			return rollback()
		}
		return true
	}
	for _, elemArg := range call.Args[1:] {
		if et := p.TypesInfo.TypeOf(elemArg); isRefOrContainerType(et) && !isFreshFieldAssignRHSWithDeferred(p, nil, elemArg, freshReturnFuncs, field, deferred) {
			return rollback()
		}
	}
	return true
}

func isSelfAppendFreshRHS(p *packages.Package, lhs, rhs ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
	if !isCall || len(call.Args) < 1 || lhs == nil || !syntaxutil.SameFieldTargetExpr(p, lhs, call.Args[0]) {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
	return isB && b.Name() == "append" && appendArgsAreFresh(p, call, freshReturnFuncs)
}

func lookupIdentOrDerefIdentVar(info *types.Info, expr ast.Expr) *types.Var {
	if info == nil || expr == nil {
		return nil
	}
	cur := ast.Unparen(expr)
	if st, isStar := cur.(*ast.StarExpr); isStar {
		cur = ast.Unparen(st.X)
	}
	id, isID := cur.(*ast.Ident)
	if !isID {
		return nil
	}
	v, _ := info.Uses[id].(*types.Var)
	return v
}

type deferredAppendElemVar struct {
	v        *types.Var
	pos      token.Pos
	elemType types.Type
}

type deferredFieldAssignVar struct {
	field    *types.Var
	v        *types.Var
	addrExpr ast.Expr
	pos      token.Pos
}

func recordAppendElemNonFreshFields(
	p *packages.Package,
	rhs ast.Expr,
	freshReturnFuncs map[*types.Func]bool,
	nonFresh map[*types.Var]bool,
	deferred *[]deferredAppendElemVar,
) {
	call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
	if !isCall || len(call.Args) < 2 {
		return
	}
	cid, isCID := ast.Unparen(call.Fun).(*ast.Ident)
	if !isCID {
		return
	}
	b, isB := p.TypesInfo.Uses[cid].(*types.Builtin)
	if !isB || b.Name() != "append" {
		return
	}
	if call.Ellipsis.IsValid() {
		arg1 := call.Args[1]
		if cl := unwrapCompositeLit(arg1); cl != nil {
			recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, nonFresh)
		} else if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(arg1)).(*types.Slice); isSl {
			if v := lookupIdentOrDerefIdentVar(p.TypesInfo, arg1); v != nil && deferred != nil {
				*deferred = append(*deferred, deferredAppendElemVar{v: v, pos: arg1.Pos(), elemType: sl.Elem()})
			} else {
				markValueContainedRefFieldsNonFresh(sl.Elem(), nonFresh)
			}
		}
		return
	}
	for _, elemArg := range call.Args[1:] {
		if cl := unwrapCompositeLit(elemArg); cl != nil {
			recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, nonFresh)
		} else if v := lookupIdentOrDerefIdentVar(p.TypesInfo, elemArg); v != nil && deferred != nil {
			*deferred = append(*deferred, deferredAppendElemVar{v: v, pos: elemArg.Pos(), elemType: p.TypesInfo.TypeOf(elemArg)})
		} else {
			markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(elemArg), nonFresh)
		}
	}
}

func isFreshFieldAssignRHS(p *packages.Package, lhs, rhs ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	return isFreshFieldAssignRHSWithDeferred(p, lhs, rhs, freshReturnFuncs, nil, nil)
}

func isFreshFieldAssignRHSWithDeferred(
	p *packages.Package,
	lhs, rhs ast.Expr,
	freshReturnFuncs map[*types.Func]bool,
	field *types.Var,
	deferred *[]deferredFieldAssignVar,
) bool {
	rhs = ast.Unparen(rhs)
	if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || syntaxutil.IsTypedNilSliceConv(p, rhs) {
		return true
	}
	switch e := rhs.(type) {
	case *ast.Ident:
		if deferred != nil && field != nil {
			if rhsV := syntaxutil.LookupIdentVar(p.TypesInfo, e); rhsV != nil && rhsV.Parent() != p.Types.Scope() {
				*deferred = append(*deferred, deferredFieldAssignVar{field: field, v: rhsV, pos: e.Pos()})
				return true
			}
		}
	case *ast.CompositeLit:
		return compositeLitElementsAreFreshWithDeferred(p, e, freshReturnFuncs, field, deferred)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return compositeLitElementsAreFreshWithDeferred(p, cl, freshReturnFuncs, field, deferred)
			}
			if deferred != nil && field != nil {
				*deferred = append(*deferred, deferredFieldAssignVar{field: field, addrExpr: e.X, pos: e.Pos()})
				return true
			}
		}
	case *ast.CallExpr:
		if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
			return true
		}
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "make" {
					return true
				}
				if b.Name() == "append" && len(e.Args) >= 1 &&
					(syntaxutil.IsTypedNilSliceConv(p, e.Args[0]) || (lhs != nil && syntaxutil.SameFieldTargetExpr(p, lhs, e.Args[0]))) &&
					appendArgsAreFreshWithDeferred(p, e, freshReturnFuncs, field, deferred) {
					return true
				}
			}
		}
		if callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func markValueContainedRefFieldsNonFresh(t types.Type, out map[*types.Var]bool) {
	seen := map[types.Type]bool{}
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if isRefOrContainerType(f.Type()) {
					out[f] = true
				}
				walk(f.Type())
			}
		case *types.Array:
			walk(u.Elem())
		}
	}
	walk(t)
}

func compositeLitElementsAreFreshWithDeferred(
	p *packages.Package,
	cl *ast.CompositeLit,
	freshReturnFuncs map[*types.Func]bool,
	field *types.Var,
	deferred *[]deferredFieldAssignVar,
) bool {
	if cl == nil {
		return false
	}
	var checkpoint int
	if deferred != nil {
		checkpoint = len(*deferred)
	}
	rollback := func() bool {
		if deferred != nil {
			*deferred = (*deferred)[:checkpoint]
		}
		return false
	}
	switch syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(cl)).(type) {
	case *types.Map, *types.Slice, *types.Array:
		for _, elt := range cl.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
				if kt := p.TypesInfo.TypeOf(kv.Key); isRefOrContainerType(kt) && !isFreshFieldAssignRHSWithDeferred(p, nil, kv.Key, freshReturnFuncs, field, deferred) {
					return rollback()
				}
			}
			vt := p.TypesInfo.TypeOf(val)
			if isRefOrContainerType(vt) && !isFreshFieldAssignRHSWithDeferred(p, nil, val, freshReturnFuncs, field, deferred) {
				return rollback()
			}
		}
	}
	return true
}

func recordCompositeLitNonFreshFields(p *packages.Package, cl *ast.CompositeLit, freshReturnFuncs map[*types.Func]bool, nonFresh map[*types.Var]bool) {
	recordCompositeLitNonFreshFieldsWithDeferred(p, cl, freshReturnFuncs, nonFresh, nil, nil)
}

func recordCompositeLitNonFreshFieldsWithDeferred(
	p *packages.Package,
	cl *ast.CompositeLit,
	freshReturnFuncs map[*types.Func]bool,
	nonFresh map[*types.Var]bool,
	sum *freshFuncSummary,
	deferredFields *[]deferredFieldAssignVar,
) {
	if cl == nil {
		return
	}
	t := p.TypesInfo.TypeOf(cl)
	if _, st := syntaxutil.DerefAnyStructType(t); st != nil {
		for i, elt := range cl.Elts {
			var fObj *types.Var
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
				if kid, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
					fObj, _ = p.TypesInfo.Uses[kid].(*types.Var)
				}
			} else if i < st.NumFields() {
				fObj = st.Field(i)
			}
			if fObj == nil {
				continue
			}
			if isRefOrContainerType(fObj.Type()) {
				var dfTarget *[]deferredFieldAssignVar
				if sum != nil {
					dfTarget = deferredFields
				}
				if !isFreshFieldAssignRHSWithDeferred(p, nil, val, freshReturnFuncs, fObj, dfTarget) {
					nonFresh[fObj] = true
				}
			}
			if subCL := unwrapCompositeLit(val); subCL != nil {
				recordCompositeLitNonFreshFieldsWithDeferred(p, subCL, freshReturnFuncs, nonFresh, sum, deferredFields)
			} else if _, subSt := syntaxutil.DerefAnyStructType(fObj.Type()); subSt != nil && !isRefOrContainerType(fObj.Type()) {
				markValueContainedRefFieldsNonFresh(fObj.Type(), nonFresh)
			}
		}
		return
	}
	switch syntaxutil.UnderlyingType(t).(type) {
	case *types.Slice, *types.Array, *types.Map:
		for _, elt := range cl.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
				if keyCL := unwrapCompositeLit(kv.Key); keyCL != nil {
					recordCompositeLitNonFreshFieldsWithDeferred(p, keyCL, freshReturnFuncs, nonFresh, sum, deferredFields)
				} else {
					markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(kv.Key), nonFresh)
				}
			}
			if subCL := unwrapCompositeLit(val); subCL != nil {
				recordCompositeLitNonFreshFieldsWithDeferred(p, subCL, freshReturnFuncs, nonFresh, sum, deferredFields)
			} else {
				markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(val), nonFresh)
			}
		}
	}
}

func unwrapIndexChainBase(expr ast.Expr) ast.Expr {
	cur := ast.Unparen(expr)
	for {
		ix, isIx := cur.(*ast.IndexExpr)
		if !isIx {
			return cur
		}
		cur = ast.Unparen(ix.X)
	}
}

func markAssignLHSFieldNonFresh(p *packages.Package, l ast.Expr, nonFresh map[*types.Var]bool) {
	if sel, isSel := unwrapIndexChainBase(l).(*ast.SelectorExpr); isSel {
		if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
			if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
				if isRefOrContainerType(fObj.Type()) {
					nonFresh[fObj] = true
				}
				markValueContainedRefFieldsNonFresh(fObj.Type(), nonFresh)
			}
		}
	}
}

func inspectClosureForFieldFreshness(
	p *packages.Package,
	body *ast.BlockStmt,
	freshReturnFuncs map[*types.Func]bool,
	nonFresh map[*types.Var]bool,
	coneCallees map[*types.Func]bool,
) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.CompositeLit:
			recordCompositeLitNonFreshFields(p, s, freshReturnFuncs, nonFresh)
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				markAssignLHSFieldNonFresh(p, s.X, nonFresh)
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN {
				if s.Key != nil {
					markAssignLHSFieldNonFresh(p, s.Key, nonFresh)
				}
				if s.Value != nil {
					markAssignLHSFieldNonFresh(p, s.Value, nonFresh)
				}
			}
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				for _, l := range s.Lhs {
					markAssignLHSFieldNonFresh(p, l, nonFresh)
				}
				return true
			}
			for i, l := range s.Lhs {
				rhs := s.Rhs[i]
				if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
						if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
							if isRefOrContainerType(fObj.Type()) && !isFreshFieldAssignRHS(p, l, rhs, freshReturnFuncs) {
								nonFresh[fObj] = true
							} else if _, subSt := syntaxutil.DerefAnyStructType(fObj.Type()); subSt != nil && unwrapCompositeLit(rhs) == nil {
								markValueContainedRefFieldsNonFresh(fObj.Type(), nonFresh)
							}
						}
					}
				} else if ix, isIx := ast.Unparen(l).(*ast.IndexExpr); isIx {
					ixType := p.TypesInfo.TypeOf(ix)
					if sel, isSel := unwrapIndexChainBase(ix).(*ast.SelectorExpr); isSel {
						if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && isRefOrContainerType(ixType) && !isFreshFieldAssignRHS(p, ix, rhs, freshReturnFuncs) {
								nonFresh[fObj] = true
							}
						}
					}
					if unwrapCompositeLit(rhs) == nil {
						markValueContainedRefFieldsNonFresh(ixType, nonFresh)
					}
				}
			}
		case *ast.CallExpr:
			if callee := syntaxutil.ResolveCalledFuncObj(p, s.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
				coneCallees[callee.Origin()] = true
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(s.Fun)); b != nil {
				switch b.Name() {
				case "delete", "clear", "copy":
					if len(s.Args) >= 1 {
						markAssignLHSFieldNonFresh(p, s.Args[0], nonFresh)
					}
				}
			}
		}
		return true
	})
}

func unwrapCompositeLit(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if cl, ok := expr.(*ast.CompositeLit); ok {
		return cl
	}
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.AND {
		if cl, okC := ast.Unparen(un.X).(*ast.CompositeLit); okC {
			return cl
		}
	}
	return nil
}
