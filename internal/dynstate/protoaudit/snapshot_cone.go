package protoaudit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func collectSnapshotGuardedValueFields(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	descFamily map[*types.Named]bool,
	extraGuards map[syntaxutil.TypeRef]bool,
	initAndBuildConeFDs map[*ast.FuncDecl]bool,
	pf *freshstruct.PkgFreshConstructors,
) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	unkeyedNamedLits := map[*types.Named]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			cl, isCL := n.(*ast.CompositeLit)
			if !isCL || len(cl.Elts) == 0 {
				return true
			}
			named, isN := types.Unalias(p.TypesInfo.TypeOf(cl)).(*types.Named)
			if !isN || !descFamily[named] {
				return true
			}
			for _, elt := range cl.Elts {
				if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
					unkeyedNamedLits[named] = true
					break
				}
			}
			return true
		})
	}
	for ownerNamed := range descFamily {
		if ownerNamed.Obj() == nil || ownerNamed.Obj().Exported() || unkeyedNamedLits[ownerNamed] {
			continue
		}
		ownerSt, ok := ownerNamed.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		snapFields := map[*types.Var]bool{}
		for i := 0; i < ownerSt.NumFields(); i++ {
			f := ownerSt.Field(i)
			if !f.Exported() && syntaxutil.IsByteSliceType(f.Type()) {
				snapFields[f] = true
			}
		}
		if len(snapFields) == 0 {
			continue
		}
		for i := 0; i < ownerSt.NumFields(); i++ {
			vf := ownerSt.Field(i)
			if vf.Exported() || snapFields[vf] {
				continue
			}
			extNamed, okN := types.Unalias(vf.Type()).(*types.Named)
			if !okN || extNamed.Obj() == nil || extNamed.Obj().Pkg() == nil || extNamed.Obj().Pkg() == p.Types {
				continue
			}
			extRef, _, extSt, okRef := syntaxutil.TypeRefOfStructFull(extNamed)
			if !okRef || !extRef.Valid() || !extraGuards[extRef] {
				continue
			}
			allUnexported := true
			for j := 0; j < extSt.NumFields(); j++ {
				f := extSt.Field(j)
				if f.Exported() && !isZeroSizedStatelessField(f) {
					allUnexported = false
					break
				}
			}
			if !allUnexported {
				continue
			}
			if types.NewMethodSet(types.NewPointer(extNamed)).Len() != types.NewMethodSet(extNamed).Len() {
				continue
			}
			var getterFD *ast.FuncDecl
			var getterRecv *types.Var
			valid := true
			var getterUses []*ast.Ident
			type ctorKV struct {
				fd *ast.FuncDecl
				kv *ast.KeyValueExpr
			}
			var ctorKVs []ctorKV
			var coneUses []*ast.Ident
			for _, uid := range idx.UsesOf[vf] {
				syncFD := idx.SyncEnclFuncDecl(uid)
				if syncFD == nil {
					valid = false
					break
				}
				if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
					ctorKVs = append(ctorKVs, ctorKV{fd: syncFD, kv: kv})
					continue
				}
				if initAndBuildConeFDs[syncFD] {
					coneUses = append(coneUses, uid)
					continue
				}
				sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid || refconfine.IdentOrExprIsWritten(idx, sel) {
					valid = false
					break
				}
				if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					valid = false
					break
				}
				if getterFD == nil {
					if syncFD.Name == nil || syncFD.Name.IsExported() || syncFD.Recv == nil || len(syncFD.Recv.List) != 1 || len(syncFD.Recv.List[0].Names) != 1 || syncFD.Body == nil {
						valid = false
						break
					}
					rv, _ := p.TypesInfo.Defs[syncFD.Recv.List[0].Names[0]].(*types.Var)
					if rv == nil || !syntaxutil.IsPtrToNamed(rv.Type(), ownerNamed) {
						valid = false
						break
					}
					getterFD = syncFD
					getterRecv = rv
				} else if syncFD != getterFD {
					valid = false
					break
				}
				rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
				if !isRID || p.TypesInfo.Uses[rid] != getterRecv {
					valid = false
					break
				}
				getterUses = append(getterUses, uid)
			}
			if !valid || getterFD == nil {
				continue
			}
			sf, okGetter := isSnapshotGuardedValueGetter(p, getterFD, getterRecv, vf, snapFields, getterUses)
			if !okGetter || sf == nil {
				continue
			}
			ctorFuncs := map[*types.Func]bool{}
			for _, ck := range ctorKVs {
				if !verifySnapshotValueConstructor(p, idx, pf, ck.fd, ownerNamed, vf, sf, ck.kv) {
					valid = false
					break
				}
				if fn, _ := p.TypesInfo.Defs[ck.fd.Name].(*types.Func); fn != nil {
					ctorFuncs[fn] = true
				}
			}
			if !valid {
				continue
			}
			if !verifyConeSnapshotUses(p, idx, initAndBuildConeFDs, ownerNamed, vf, ctorFuncs, coneUses) {
				continue
			}
			out[vf] = true
		}
	}
	return out
}

func verifySnapshotValueConstructor(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	pf *freshstruct.PkgFreshConstructors,
	fd *ast.FuncDecl,
	ownerNamed *types.Named,
	_, sf *types.Var,
	kv *ast.KeyValueExpr,
) bool {
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 3 || fd.Recv != nil {
		return false
	}
	fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
	sig, _ := p.TypesInfo.Defs[fd.Name].Type().(*types.Signature)
	if fn == nil || sig == nil || sig.Results().Len() != 1 || !types.Identical(types.Unalias(sig.Results().At(0).Type()), ownerNamed) {
		return false
	}
	paramSet := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		paramSet[sig.Params().At(i)] = true
	}
	valID, isVID := ast.Unparen(kv.Value).(*ast.Ident)
	if !isVID {
		return false
	}
	vParam, _ := p.TypesInfo.Uses[valID].(*types.Var)
	if vParam == nil || !paramSet[vParam] {
		return false
	}
	defStmt, isDef := fd.Body.List[0].(*ast.AssignStmt)
	if !isDef || defStmt.Tok != token.DEFINE || len(defStmt.Lhs) != 1 || len(defStmt.Rhs) != 1 {
		return false
	}
	dvDefID, isDID := ast.Unparen(defStmt.Lhs[0]).(*ast.Ident)
	if !isDID {
		return false
	}
	dvVar, _ := p.TypesInfo.Defs[dvDefID].(*types.Var)
	if dvVar == nil {
		return false
	}
	cl, isCL := ast.Unparen(defStmt.Rhs[0]).(*ast.CompositeLit)
	if !isCL || idx.ParentMap[kv] != cl {
		return false
	}
	for _, elt := range cl.Elts {
		ekv, okKV := elt.(*ast.KeyValueExpr)
		if !okKV {
			return false
		}
		if kid, okID := ast.Unparen(ekv.Key).(*ast.Ident); okID && p.TypesInfo.Uses[kid] == sf {
			return false
		}
	}
	ifStmt, isIf := fd.Body.List[1].(*ast.IfStmt)
	if !isIf || ifStmt.Init == nil || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	initAs, isIAs := ifStmt.Init.(*ast.AssignStmt)
	if !isIAs || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 2 || len(initAs.Rhs) != 1 {
		return false
	}
	bID, okB := ast.Unparen(initAs.Lhs[0]).(*ast.Ident)
	okID, okO := ast.Unparen(initAs.Lhs[1]).(*ast.Ident)
	if !okB || !okO {
		return false
	}
	bVar, _ := p.TypesInfo.Defs[bID].(*types.Var)
	okVar, _ := p.TypesInfo.Defs[okID].(*types.Var)
	if bVar == nil || okVar == nil || !syntaxutil.IsByteSliceType(bVar.Type()) {
		return false
	}
	ta, isTA := ast.Unparen(initAs.Rhs[0]).(*ast.TypeAssertExpr)
	if !isTA || ta.Type == nil || !syntaxutil.IsByteSliceType(p.TypesInfo.TypeOf(ta.Type)) {
		return false
	}
	ifaceCall, isIC := ast.Unparen(ta.X).(*ast.CallExpr)
	if !isIC || len(ifaceCall.Args) != 0 {
		return false
	}
	ifaceSel, isIS := ast.Unparen(ifaceCall.Fun).(*ast.SelectorExpr)
	if !isIS || ifaceSel.Sel.Name != "Interface" {
		return false
	}
	if xid, isXID := ast.Unparen(ifaceSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != vParam {
		return false
	}
	if cid, isCID := ast.Unparen(ifStmt.Cond).(*ast.Ident); !isCID || p.TypesInfo.Uses[cid] != okVar {
		return false
	}
	cpAs, isCAs := ifStmt.Body.List[0].(*ast.AssignStmt)
	if !isCAs || cpAs.Tok != token.ASSIGN || len(cpAs.Lhs) != 1 || len(cpAs.Rhs) != 1 {
		return false
	}
	lhsSel, isLS := ast.Unparen(cpAs.Lhs[0]).(*ast.SelectorExpr)
	if !isLS || p.TypesInfo.Uses[lhsSel.Sel] != sf || !pf.IsFreshMutationTarget(fd, lhsSel) {
		return false
	}
	if xid, isXID := ast.Unparen(lhsSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != dvVar {
		return false
	}
	apCall, isAC := ast.Unparen(cpAs.Rhs[0]).(*ast.CallExpr)
	if !isAC || len(apCall.Args) != 2 || !apCall.Ellipsis.IsValid() {
		return false
	}
	apID, isAID := ast.Unparen(apCall.Fun).(*ast.Ident)
	if !isAID {
		return false
	}
	if b, isBuiltin := p.TypesInfo.Uses[apID].(*types.Builtin); !isBuiltin || b.Name() != "append" {
		return false
	}
	if !syntaxutil.IsTypedNilSliceConv(p, apCall.Args[0]) || !syntaxutil.IsByteSliceType(p.TypesInfo.TypeOf(apCall.Args[0])) {
		return false
	}
	if arg1ID, isA1 := ast.Unparen(apCall.Args[1]).(*ast.Ident); !isA1 || p.TypesInfo.Uses[arg1ID] != bVar {
		return false
	}
	retStmt, isRet := fd.Body.List[2].(*ast.ReturnStmt)
	if !isRet || len(retStmt.Results) != 1 {
		return false
	}
	retID, isRID := ast.Unparen(retStmt.Results[0]).(*ast.Ident)
	return isRID && p.TypesInfo.Uses[retID] == dvVar
}

func verifyConeSnapshotUses(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initAndBuildConeFDs map[*ast.FuncDecl]bool,
	ownerNamed *types.Named,
	_ *types.Var,
	ctorFuncs map[*types.Func]bool,
	coneUses []*ast.Ident,
) bool {
	snapshotProducing := map[*types.Func]bool{}
	for fn := range ctorFuncs {
		snapshotProducing[fn] = true
	}
	changed := true
	for changed {
		changed = false
		for fd := range initAndBuildConeFDs {
			if fd == nil || fd.Name == nil || fd.Body == nil || fd.Recv != nil {
				continue
			}
			fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if fn == nil || fn.Exported() || snapshotProducing[fn] {
				continue
			}
			sig, _ := fn.Type().(*types.Signature)
			if sig == nil || sig.Results().Len() != 1 || !types.Identical(types.Unalias(sig.Results().At(0).Type()), ownerNamed) {
				continue
			}
			hasRet := false
			allSnapshot := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !allSnapshot || n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					allSnapshot = false
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				hasRet = true
				if len(ret.Results) != 1 {
					allSnapshot = false
					return false
				}
				rc, isRC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
				if !isRC {
					allSnapshot = false
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
				if callee == nil || !snapshotProducing[callee] {
					allSnapshot = false
					return false
				}
				return true
			})
			if hasRet && allSnapshot {
				snapshotProducing[fn] = true
				changed = true
			}
		}
	}

	for _, file := range p.Syntax {
		badHolderWrite := false
		ast.Inspect(file, func(n ast.Node) bool {
			if badHolderWrite || n == nil {
				return false
			}
			as, isAs := n.(*ast.AssignStmt)
			if !isAs {
				return true
			}
			for i, lhs := range as.Lhs {
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel {
					continue
				}
				hf, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
				if hf == nil || !hf.IsField() || !types.Identical(types.Unalias(hf.Type()), ownerNamed) {
					continue
				}
				syncFD := idx.SyncEnclFuncDecl(as)
				if syncFD == nil || !initAndBuildConeFDs[syncFD] || len(as.Lhs) != len(as.Rhs) || i >= len(as.Rhs) {
					badHolderWrite = true
					return false
				}
				rc, isRC := ast.Unparen(as.Rhs[i]).(*ast.CallExpr)
				if !isRC {
					badHolderWrite = true
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
				if callee == nil || !snapshotProducing[callee] {
					badHolderWrite = true
					return false
				}
			}
			return true
		})
		if badHolderWrite {
			return false
		}
	}
	if len(coneUses) == 0 {
		return true
	}

	writtenHolders := map[*types.Var]bool{}
	resolvedHolders := map[*types.Var]bool{}
	for _, uid := range coneUses {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return false
		}
		if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			return false
		}
		holderSel, isHS := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !isHS {
			return false
		}
		holderField, _ := p.TypesInfo.Uses[holderSel.Sel].(*types.Var)
		if holderField == nil || !holderField.IsField() || !types.Identical(types.Unalias(holderField.Type()), ownerNamed) {
			return false
		}
		par := idx.ParentUnparen(sel)
		if as, isAs := par.(*ast.AssignStmt); isAs {
			if as.Tok == token.ASSIGN && len(as.Lhs) == 1 && ast.Unparen(as.Lhs[0]) == sel {
				writtenHolders[holderField] = true
				continue
			}
			if as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == sel {
				ifStmt, isIf := idx.ParentMap[as].(*ast.IfStmt)
				if !isIf || ifStmt.Init != as || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) != 1 {
					return false
				}
				vID, okVID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
				if !okVID {
					return false
				}
				vVar, _ := p.TypesInfo.Defs[vID].(*types.Var)
				if vVar == nil {
					return false
				}
				condCall, isCC := ast.Unparen(ifStmt.Cond).(*ast.CallExpr)
				if !isCC || len(condCall.Args) != 0 {
					return false
				}
				condSel, isCS := ast.Unparen(condCall.Fun).(*ast.SelectorExpr)
				if !isCS || condSel.Sel.Name != "IsValid" {
					return false
				}
				if xid, isXID := ast.Unparen(condSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != vVar {
					return false
				}
				resAs, isRAs := ifStmt.Body.List[0].(*ast.AssignStmt)
				if !isRAs || resAs.Tok != token.ASSIGN || len(resAs.Lhs) != 1 || len(resAs.Rhs) != 1 {
					return false
				}
				if !syntaxutil.SameFieldTargetExpr(p, resAs.Lhs[0], holderSel) {
					return false
				}
				resCall, isRC := ast.Unparen(resAs.Rhs[0]).(*ast.CallExpr)
				if !isRC {
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, resCall.Fun)
				if callee == nil || !snapshotProducing[callee] {
					return false
				}
				resolvedHolders[holderField] = true
				continue
			}
		}
		return false
	}
	for hf := range writtenHolders {
		if !resolvedHolders[hf] {
			return false
		}
	}
	return true
}

func isSnapshotGuardedValueGetter(
	p *packages.Package,
	fd *ast.FuncDecl,
	rv *types.Var,
	vf *types.Var,
	snapFields map[*types.Var]bool,
	getterUses []*ast.Ident,
) (*types.Var, bool) {
	stmts := fd.Body.List
	if len(stmts) < 2 || len(getterUses) != 2 {
		return nil, false
	}
	retStmt, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet || len(retStmt.Results) != 1 {
		return nil, false
	}
	retSel, isRS := ast.Unparen(retStmt.Results[0]).(*ast.SelectorExpr)
	if !isRS || p.TypesInfo.Uses[retSel.Sel] != vf {
		return nil, false
	}
	if rid, isID := ast.Unparen(retSel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	ifStmt, isIf := stmts[len(stmts)-2].(*ast.IfStmt)
	if !isIf || ifStmt.Init != nil || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) == 0 {
		return nil, false
	}
	lastBodyStmt, isES := ifStmt.Body.List[len(ifStmt.Body.List)-1].(*ast.ExprStmt)
	if !isES {
		return nil, false
	}
	panicCall, isPC := ast.Unparen(lastBodyStmt.X).(*ast.CallExpr)
	if !isPC {
		return nil, false
	}
	pid, isPID := ast.Unparen(panicCall.Fun).(*ast.Ident)
	if !isPID {
		return nil, false
	}
	if pb, isB := p.TypesInfo.Uses[pid].(*types.Builtin); !isB || pb.Name() != "panic" {
		return nil, false
	}
	andExpr, isAnd := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
	if !isAnd || andExpr.Op != token.LAND {
		return nil, false
	}
	lenCmp, isCmp := ast.Unparen(andExpr.X).(*ast.BinaryExpr)
	if !isCmp || lenCmp.Op != token.GTR {
		return nil, false
	}
	if tv := p.TypesInfo.Types[lenCmp.Y]; tv.Value == nil {
		return nil, false
	} else if z, okZ := constant.Int64Val(tv.Value); !okZ || z != 0 {
		return nil, false
	}
	lenCall, isLC := ast.Unparen(lenCmp.X).(*ast.CallExpr)
	if !isLC || len(lenCall.Args) != 1 {
		return nil, false
	}
	lid, isLID := ast.Unparen(lenCall.Fun).(*ast.Ident)
	if !isLID {
		return nil, false
	}
	if lb, isB := p.TypesInfo.Uses[lid].(*types.Builtin); !isB || lb.Name() != "len" {
		return nil, false
	}
	snapSel1, isSS1 := ast.Unparen(lenCall.Args[0]).(*ast.SelectorExpr)
	if !isSS1 {
		return nil, false
	}
	sf, _ := p.TypesInfo.Uses[snapSel1.Sel].(*types.Var)
	if sf == nil || !snapFields[sf] {
		return nil, false
	}
	if rid, isID := ast.Unparen(snapSel1.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	notExpr, isNot := ast.Unparen(andExpr.Y).(*ast.UnaryExpr)
	if !isNot || notExpr.Op != token.NOT {
		return nil, false
	}
	eqCall, isEC := ast.Unparen(notExpr.X).(*ast.CallExpr)
	if !isEC || len(eqCall.Args) != 2 {
		return nil, false
	}
	eqFn := syntaxutil.ResolveCalledFuncObj(p, eqCall.Fun)
	if eqFn == nil || eqFn.Pkg() == nil || eqFn.Pkg().Path() != "bytes" || eqFn.Name() != "Equal" {
		return nil, false
	}
	isSnapExpr := func(e ast.Expr) bool {
		s, ok := ast.Unparen(e).(*ast.SelectorExpr)
		if !ok || p.TypesInfo.Uses[s.Sel] != sf {
			return false
		}
		r, okR := ast.Unparen(s.X).(*ast.Ident)
		return okR && p.TypesInfo.Uses[r] == rv
	}
	var bytesArg ast.Expr
	if isSnapExpr(eqCall.Args[0]) {
		bytesArg = eqCall.Args[1]
	} else if isSnapExpr(eqCall.Args[1]) {
		bytesArg = eqCall.Args[0]
	} else {
		return nil, false
	}
	bCall, isBC := ast.Unparen(bytesArg).(*ast.CallExpr)
	if !isBC || len(bCall.Args) != 0 || !syntaxutil.IsByteSliceType(p.TypesInfo.TypeOf(bCall)) {
		return nil, false
	}
	bSel, isBS := ast.Unparen(bCall.Fun).(*ast.SelectorExpr)
	if !isBS || bSel.Sel.Name != "Bytes" {
		return nil, false
	}
	valSel, isVS := ast.Unparen(bSel.X).(*ast.SelectorExpr)
	if !isVS || p.TypesInfo.Uses[valSel.Sel] != vf {
		return nil, false
	}
	if rid, isID := ast.Unparen(valSel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	if (getterUses[0] == valSel.Sel && getterUses[1] == retSel.Sel) ||
		(getterUses[1] == valSel.Sel && getterUses[0] == retSel.Sel) {
		return sf, true
	}
	return nil, false
}
