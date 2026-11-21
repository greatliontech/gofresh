package capsule

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isBuilderFamilyReadConfinedType(
	t types.Type,
	builderFamily map[*types.Named]bool,
	memo map[*types.Named]bool,
	visiting map[*types.Named]bool,
) bool {
	if t == nil {
		return false
	}
	named, isN := types.Unalias(t).(*types.Named)
	if !isN || !builderFamily[named] || named.Obj() == nil {
		return false
	}
	if res, ok := memo[named]; ok {
		return res
	}
	if visiting[named] {
		return false
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		memo[named] = false
		return false
	}
	visiting[named] = true
	defer delete(visiting, named)
	for i := 0; i < st.NumFields(); i++ {
		sf := st.Field(i)
		if !refconfine.TypeCarriesMutableRef(sf.Type()) {
			continue
		}
		if !sf.Exported() && !sf.Embedded() {
			continue
		}
		if !isBuilderFamilyReadConfinedType(sf.Type(), builderFamily, memo, visiting) {
			memo[named] = false
			return false
		}
	}
	memo[named] = true
	return true
}

func isZeroSizedStatelessField(f *types.Var) bool {
	if f == nil {
		return false
	}
	t := f.Type()
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		if u.NumFields() != 0 {
			return false
		}
	case *types.Array:
		if u.Len() != 0 {
			return false
		}
	default:
		return false
	}
	return types.NewMethodSet(types.NewPointer(t)).Len() == 0
}

func collectImmutableIfaceFields(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	builderFamily map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) map[*types.Var]bool {
	cand := map[*types.Var]bool{}
	fieldOwner := map[*types.Var]*types.Named{}
	for ownerNamed := range builderFamily {
		st, ok := ownerNamed.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			var elemT types.Type
			switch u := types.Unalias(f.Type()).Underlying().(type) {
			case *types.Slice:
				elemT = u.Elem()
			case *types.Map:
				elemT = u.Elem()
			}
			if elemT == nil {
				continue
			}
			if iface, okI := types.Unalias(elemT).Underlying().(*types.Interface); okI && iface.NumMethods() > 0 {
				cand[f] = true
				fieldOwner[f] = ownerNamed
			}
		}
	}
	if len(cand) == 0 {
		return nil
	}

	unkeyedOwners := map[*types.Named]bool{}
	rangeValField := map[*types.Var]*types.Var{}
	writtenVars := map[*types.Var]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.CompositeLit:
				if len(s.Elts) > 0 {
					if named, isN := types.Unalias(p.TypesInfo.TypeOf(s)).(*types.Named); isN && builderFamily[named] {
						for _, elt := range s.Elts {
							if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
								unkeyedOwners[named] = true
								break
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok != token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
						if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
							writtenVars[v] = true
						}
					}
				}
			case *ast.RangeStmt:
				if s.Tok == token.DEFINE && s.Value != nil {
					if vid, isID := ast.Unparen(s.Value).(*ast.Ident); isID {
						if vv, _ := p.TypesInfo.Defs[vid].(*types.Var); vv != nil && idx.DefCounts[vv] == 1 {
							if xSel, isSel := ast.Unparen(s.X).(*ast.SelectorExpr); isSel {
								if sf, _ := p.TypesInfo.Uses[xSel.Sel].(*types.Var); sf != nil && cand[sf] {
									rangeValField[vv] = sf
								}
							}
						}
					}
				} else if s.Tok == token.ASSIGN {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if id, isID := ast.Unparen(e).(*ast.Ident); isID && id != nil {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	for v := range writtenVars {
		delete(rangeValField, v)
	}
	for f, owner := range fieldOwner {
		if unkeyedOwners[owner] {
			delete(cand, f)
		}
	}

	isMakeCall := func(e ast.Expr) bool {
		c, isC := ast.Unparen(e).(*ast.CallExpr)
		if !isC || len(c.Args) == 0 {
			return false
		}
		id, isID := ast.Unparen(c.Fun).(*ast.Ident)
		if !isID {
			return false
		}
		b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
		return isB && b.Name() == "make"
	}
	validElem := func(e ast.Expr) bool {
		e = ast.Unparen(e)
		if e == nil {
			return false
		}
		if isImmPtr(p.TypesInfo.TypeOf(e)) {
			return true
		}
		if id, isID := e.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
				if srcF := rangeValField[v]; srcF != nil && cand[srcF] {
					return true
				}
			}
		}
		return false
	}

	changed := true
	for changed {
		changed = false
		for f := range cand {
			okField := true
			for _, uid := range idx.UsesOf[f] {
				if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
					rhs := ast.Unparen(kv.Value)
					if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || isMakeCall(rhs) {
						continue
					}
					if cl, isCL := rhs.(*ast.CompositeLit); isCL {
						for _, elt := range cl.Elts {
							val := elt
							if ekv, isEKV := elt.(*ast.KeyValueExpr); isEKV {
								val = ekv.Value
							}
							if !validElem(val) {
								okField = false
								break
							}
						}
						if okField {
							continue
						}
					}
					okField = false
					break
				}
				sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid {
					okField = false
					break
				}
				par := idx.ParentUnparen(sel)
				if un, isUn := par.(*ast.UnaryExpr); isUn && un.Op == token.AND {
					okField = false
					break
				}
				if _, isSl := par.(*ast.SliceExpr); isSl {
					okField = false
					break
				}
				if call, isCall := par.(*ast.CallExpr); isCall && len(call.Args) >= 1 && ast.Unparen(call.Args[0]) == sel {
					if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
						if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && (b.Name() == "copy" || b.Name() == "delete" || b.Name() == "clear") {
							okField = false
							break
						}
					}
				}
				if refconfine.IdentOrExprIsWritten(idx, sel) {
					as, isAs := par.(*ast.AssignStmt)
					if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
						okField = false
						break
					}
					rhs := ast.Unparen(as.Rhs[0])
					if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || isMakeCall(rhs) {
						continue
					}
					apCall, isAC := rhs.(*ast.CallExpr)
					if !isAC || len(apCall.Args) < 2 || apCall.Ellipsis.IsValid() {
						okField = false
						break
					}
					apID, isID := ast.Unparen(apCall.Fun).(*ast.Ident)
					if !isID {
						okField = false
						break
					}
					if b, isB := p.TypesInfo.Uses[apID].(*types.Builtin); !isB || b.Name() != "append" || !syntaxutil.SameFieldTargetExpr(p, sel, apCall.Args[0]) {
						okField = false
						break
					}
					for _, arg := range apCall.Args[1:] {
						if !validElem(arg) {
							okField = false
							break
						}
					}
					if !okField {
						break
					}
					continue
				}
				if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == sel {
					ixPar := idx.ParentUnparen(ix)
					if un, isUn := ixPar.(*ast.UnaryExpr); isUn && un.Op == token.AND {
						okField = false
						break
					}
					if refconfine.IdentOrExprIsWritten(idx, ix) {
						as, isAs := ixPar.(*ast.AssignStmt)
						if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != ix || !validElem(as.Rhs[0]) {
							okField = false
							break
						}
					}
					continue
				}
			}
			if !okField {
				delete(cand, f)
				changed = true
			}
		}
	}
	return cand
}

func structEmbedsUnexported(st *types.Struct, target *types.Named) bool {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() && !f.Exported() && types.Unalias(f.Type()) == target {
			return true
		}
	}
	return false
}

func isLockedOnceInitMethodAllowTailUnlock(
	p *packages.Package,
	fd *ast.FuncDecl,
	named *types.Named,
	muField, doneField *types.Var,
) bool {
	if isLockedOnceInitMethod(p, fd, named, muField, doneField) {
		return true
	}
	stmts := fd.Body.List
	if len(stmts) < 3 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	recvVar, ok := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || recvVar == nil || !syntaxutil.IsPtrToNamed(recvVar.Type(), named) {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[0], recvVar, muField, "Lock", false) || !isFieldMutexCallStmt(p, stmts[len(stmts)-1], recvVar, muField, "Unlock", false) {
		return false
	}
	for _, mid := range stmts[1 : len(stmts)-1] {
		bad := false
		ast.Inspect(mid, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt, *ast.DeferStmt:
				bad = true
				return false
			case *ast.ExprStmt:
				if isFieldMutexCallStmt(p, x, recvVar, muField, "Unlock", false) || isFieldMutexCallStmt(p, x, recvVar, muField, "Lock", false) {
					bad = true
					return false
				}
			}
			return true
		})
		if bad {
			return false
		}
	}
	sawAtomicStore := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if sawAtomicStore || n == nil {
			return false
		}
		call, okC := n.(*ast.CallExpr)
		if !okC || len(call.Args) != 2 {
			return true
		}
		if isAtomicUint32Call(p, call, "StoreUint32") && isAddrOfRecvField(p, call.Args[0], recvVar, doneField) {
			if tv := p.TypesInfo.Types[call.Args[1]]; tv.Value != nil {
				if v, okI := constant.Uint64Val(tv.Value); okI && v > 0 {
					sawAtomicStore = true
					return false
				}
			}
		}
		return true
	})
	return sawAtomicStore
}

func classifyOnceDoCallback(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	lit *ast.FuncLit,
	builderFamily map[*types.Named]bool,
) (*types.Named, bool) {
	call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != lit {
		return nil, false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "Do" {
		return nil, false
	}
	fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "sync" || fn.Name() != "Do" {
		return nil, false
	}
	onceSel, isOS := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !isOS || !syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(onceSel), "sync", "Once") {
		return nil, false
	}
	rid, isRID := ast.Unparen(onceSel.X).(*ast.Ident)
	if !isRID {
		return nil, false
	}
	rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
	if rv == nil {
		return nil, false
	}
	recvSt := syntaxutil.DerefNamedStruct(rv.Type())
	if recvSt == nil || !builderFamily[recvSt] {
		return nil, false
	}
	var enclFD *ast.FuncDecl
	for cur := idx.ParentMap[call]; cur != nil; cur = idx.ParentMap[cur] {
		if _, isInnerLit := cur.(*ast.FuncLit); isInnerLit {
			return nil, false
		}
		if fd, isFD := cur.(*ast.FuncDecl); isFD {
			enclFD = fd
			break
		}
	}
	if enclFD == nil || enclFD.Recv == nil || len(enclFD.Recv.List) != 1 || len(enclFD.Recv.List[0].Names) != 1 {
		return nil, false
	}
	if p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]] != rv {
		return nil, false
	}
	if bodyMutatesAnyPackageGlobal(p, lit.Body, nil) {
		return nil, false
	}
	return recvSt, true
}

func isPureSortSliceComparator(p *packages.Package, idx *refconfine.PkgIndex, lit *ast.FuncLit) bool {
	call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 2 || ast.Unparen(call.Args[1]) != lit {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "sort" || callee.Name() != "Slice" {
		return false
	}
	return lit.Body != nil && !bodyHasAnyAssignment(p, lit.Body)
}

func isSyncPoolNewConstructor(p *packages.Package, idx *refconfine.PkgIndex, lit *ast.FuncLit) bool {
	kv, isKV := idx.ParentUnparen(lit).(*ast.KeyValueExpr)
	if !isKV || ast.Unparen(kv.Value) != lit {
		return false
	}
	kid, isID := kv.Key.(*ast.Ident)
	if !isID || kid.Name != "New" {
		return false
	}
	cl, isCL := idx.ParentUnparen(kv).(*ast.CompositeLit)
	if !isCL || !syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(cl), "sync", "Pool") {
		return false
	}
	if lit.Body == nil || len(lit.Body.List) != 1 {
		return false
	}
	ret, isRet := lit.Body.List[0].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 {
		return false
	}
	nc, isNC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isNC || len(nc.Args) != 1 {
		return false
	}
	nid, isNID := ast.Unparen(nc.Fun).(*ast.Ident)
	if !isNID {
		return false
	}
	b, isB := p.TypesInfo.Uses[nid].(*types.Builtin)
	return isB && b.Name() == "new"
}

func bodyHasAnyAssignment(p *packages.Package, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt, *ast.GoStmt, *ast.DeferStmt:
			found = true
			return false
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				found = true
				return false
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

func verifySyncPoolGlobalUses(_ *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	for _, uid := range idx.UsesOf[v] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || ast.Unparen(sel.X) != uid || (sel.Sel.Name != "Get" && sel.Sel.Name != "Put") {
			return false
		}
		call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel {
			return false
		}
	}
	return true
}

func isReadOnlyPtrCallArg(p *packages.Package, idx *refconfine.PkgIndex, un *ast.UnaryExpr) bool {
	call, isCall := idx.ParentUnparen(un).(*ast.CallExpr)
	if !isCall {
		return false
	}
	argIdx := -1
	for i, a := range call.Args {
		if ast.Unparen(a) == un {
			argIdx = i
			break
		}
	}
	if argIdx < 0 {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() != p.Types {
		return false
	}
	fd := idx.FuncDecls[callee.Origin()]
	sig, okSig := callee.Origin().Type().(*types.Signature)
	if fd == nil || fd.Body == nil || !okSig || sig.Variadic() || argIdx >= sig.Params().Len() {
		return false
	}
	pv := sig.Params().At(argIdx)
	for _, uid := range idx.UsesOf[pv] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.ParentUnparen(uid)
		if star, isStar := par.(*ast.StarExpr); isStar && ast.Unparen(star.X) == uid {
			if refconfine.IdentOrExprIsWritten(idx, star) {
				return false
			}
		}
	}
	return true
}

func isPureReceiverScalarSetter(p *packages.Package, _ *refconfine.PkgIndex, fd *ast.FuncDecl, recvStruct *types.Named) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 || fd.Body == nil {
		return false
	}
	rv, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if rv == nil || !syntaxutil.IsPtrToNamed(rv.Type(), recvStruct) {
		return false
	}
	for _, stmt := range fd.Body.List {
		as, isAs := stmt.(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) {
			return false
		}
		for i, lhs := range as.Lhs {
			sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			rid, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID || p.TypesInfo.Uses[rid] != rv {
				return false
			}
			lt := p.TypesInfo.TypeOf(sel)
			if lt == nil || refconfine.TypeContainsRefOrPointer(lt) {
				return false
			}
			rhs := ast.Unparen(as.Rhs[i])
			if p.TypesInfo.Types[rhs].Value != nil {
				continue
			}
			if pid, isPID := rhs.(*ast.Ident); isPID {
				if pv, isV := p.TypesInfo.Uses[pid].(*types.Var); isV && pv != nil && !pv.IsField() && pv.Parent() != p.Types.Scope() && !refconfine.TypeContainsRefOrPointer(pv.Type()) {
					continue
				}
			}
			return false
		}
	}
	return len(fd.Body.List) > 0
}

func bodyMutatesAnyNonInitGlobal(p *packages.Package, body *ast.BlockStmt, inInit bool, mutatedVars map[string]bool) bool {
	if inInit {
		return false
	}
	return bodyMutatesAnyPackageGlobal(p, body, mutatedVars)
}
