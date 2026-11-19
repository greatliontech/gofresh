package capsule

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

func collectFastOnceWrapperMethods(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	rootNamed *types.Named,
	onceFn *types.Func,
	flagField *types.Var,
) map[*types.Func]bool {
	out := map[*types.Func]bool{}
	if rootNamed == nil || onceFn == nil || flagField == nil {
		return out
	}
	pset := types.NewMethodSet(types.NewPointer(rootNamed))
	for i := 0; i < pset.Len(); i++ {
		m, ok := pset.At(i).Obj().(*types.Func)
		if !ok || m == onceFn || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		sig, okSig := m.Type().(*types.Signature)
		if !okSig || sig.Params().Len() != 0 {
			continue
		}
		fd := idx.FuncDecls[m]
		if fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
			continue
		}
		recvVar, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
		if recvVar == nil || !syntaxutil.IsPtrToNamed(recvVar.Type(), rootNamed) {
			continue
		}
		if stmtsEstablishOnceInitOnVar(p, fd.Body, recvVar, nil, 0, fd.Body.End(), flagField, onceFn, nil) {
			out[m] = true
		}
	}
	return out
}

func localPtrDominatedByOnceInit(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	recvExpr ast.Expr,
	beforePos token.Pos,
	rootNamed *types.Named,
	flagField *types.Var,
	onceFn *types.Func,
	fastInitMethods map[*types.Func]bool,
) bool {
	if fd == nil || fd.Body == nil || rootNamed == nil || onceFn == nil || flagField == nil {
		return false
	}
	targetVar, getterFn, ok := extractRootTargetAndGetter(p, idx, rootNamed, onceConeSetForGetter(p, idx, onceFn), recvExpr)
	if !ok || targetVar == nil {
		return false
	}

	isSigVar := false
	if fn, okFn := p.TypesInfo.Defs[fd.Name].(*types.Func); okFn && fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() == targetVar {
				isSigVar = true
			}
			for i := 0; i < sig.Params().Len(); i++ {
				if sig.Params().At(i) == targetVar {
					isSigVar = true
				}
			}
		}
	}
	var defEnd token.Pos
	if !isSigVar {
		foundTopDef := false
		for _, st := range fd.Body.List {
			as, isAs := st.(*ast.AssignStmt)
			if !isAs || as.Tok != token.DEFINE {
				continue
			}
			for _, lhs := range as.Lhs {
				if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && p.TypesInfo.Defs[lid] == targetVar {
					if foundTopDef {
						return false
					}
					foundTopDef = true
					defEnd = st.End()
				}
			}
		}
		if !foundTopDef {
			return false
		}
	}

	mutatedOrAliased := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if mutatedOrAliased || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.BranchStmt:
			if s.Tok == token.GOTO {
				mutatedOrAliased = true
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				lid, isID := ast.Unparen(lhs).(*ast.Ident)
				if !isID {
					continue
				}
				if s.Tok == token.ASSIGN && p.TypesInfo.Uses[lid] == targetVar {
					mutatedOrAliased = true
					return false
				}
				if s.Tok == token.DEFINE && isSigVar && p.TypesInfo.Defs[lid] == targetVar {
					mutatedOrAliased = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if syntaxutil.IsIdentUsingObj(p.TypesInfo, s.X, targetVar) {
				mutatedOrAliased = true
				return false
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN &&
				((s.Key != nil && syntaxutil.IsIdentUsingObj(p.TypesInfo, s.Key, targetVar)) ||
					(s.Value != nil && syntaxutil.IsIdentUsingObj(p.TypesInfo, s.Value, targetVar))) {
				mutatedOrAliased = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND && syntaxutil.IsIdentUsingObj(p.TypesInfo, s.X, targetVar) {
				mutatedOrAliased = true
				return false
			}
		case *ast.Ident:
			if (p.TypesInfo.Uses[s] == targetVar || p.TypesInfo.Defs[s] == targetVar) && (idx.InFuncLit[s] || idx.InGoStmt[s]) {
				mutatedOrAliased = true
				return false
			}
			if getterFn != nil && p.TypesInfo.Uses[s] == targetVar && s.Pos() <= beforePos {
				sel, isSel := idx.ParentUnparen(s).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != s || p.TypesInfo.Uses[sel.Sel] != getterFn {
					mutatedOrAliased = true
					return false
				}
				call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != sel || len(call.Args) != 0 {
					mutatedOrAliased = true
					return false
				}
			}
		}
		return true
	})
	if mutatedOrAliased {
		return false
	}

	return stmtsEstablishOnceInitOnVar(p, fd.Body, targetVar, getterFn, defEnd, beforePos, flagField, onceFn, fastInitMethods)
}

func onceConeSetForGetter(p *packages.Package, idx *refconfine.PkgIndex, onceFn *types.Func) map[*types.Func]bool {
	if onceFn == nil {
		return nil
	}
	return refconfine.ComputeExclusiveHelperCone(p, idx, onceFn)
}

func extractRootTargetAndGetter(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	rootNamed *types.Named,
	onceCone map[*types.Func]bool,
	expr ast.Expr,
) (*types.Var, *types.Func, bool) {
	expr = ast.Unparen(expr)
	if id, isID := expr.(*ast.Ident); isID {
		v, ok := p.TypesInfo.Uses[id].(*types.Var)
		if !ok || v == nil || v.IsField() || v.Parent() == p.Types.Scope() || !syntaxutil.IsPtrToNamed(v.Type(), rootNamed) {
			return nil, nil, false
		}
		return v, nil, true
	}
	call, isCall := expr.(*ast.CallExpr)
	if !isCall || len(call.Args) != 0 {
		return nil, nil, false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel {
		return nil, nil, false
	}
	id, isID := ast.Unparen(sel.X).(*ast.Ident)
	if !isID {
		return nil, nil, false
	}
	v, okV := p.TypesInfo.Uses[id].(*types.Var)
	if !okV || v == nil || v.IsField() || v.Parent() == p.Types.Scope() {
		return nil, nil, false
	}
	fn, okF := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !okF || fn == nil || !isPureLocalRootGetterMethod(p, idx, rootNamed, v.Type(), fn, onceCone) {
		return nil, nil, false
	}
	return v, fn, true
}

func isPureLocalRootGetterMethod(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	rootNamed *types.Named,
	recvType types.Type,
	fn *types.Func,
	onceCone map[*types.Func]bool,
) bool {
	if fn == nil || fn.Exported() || fn.Pkg() != p.Types {
		return false
	}
	wrapNamed := syntaxutil.DerefNamedStruct(recvType)
	if wrapNamed == nil || wrapNamed.Obj() == nil || wrapNamed.Obj().Pkg() != p.Types || wrapNamed.Obj().Exported() {
		return false
	}
	if _, isPtr := types.Unalias(recvType).(*types.Pointer); !isPtr {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	if !syntaxutil.IsPtrToNamed(sig.Recv().Type(), wrapNamed) || !syntaxutil.IsPtrToNamed(sig.Results().At(0).Type(), rootNamed) {
		return false
	}
	fd := idx.FuncDecls[fn]
	if fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	mRecv, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if mRecv == nil {
		return false
	}
	stmts := fd.Body.List
	if len(stmts) == 1 {
		ret, isRet := stmts[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 {
			return false
		}
		sel, isSel := ast.Unparen(ret.Results[0]).(*ast.SelectorExpr)
		if !isSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, mRecv) {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		fld, _ := selInfo.Obj().(*types.Var)
		if fld == nil || fld.Exported() || !syntaxutil.IsPtrToNamed(fld.Type(), rootNamed) {
			return false
		}
		return !unexportedWrapperFieldMutatedInPkg(p, idx, fld, false, nil)
	}
	if len(stmts) != 2 && len(stmts) != 3 {
		return false
	}
	as, isAs := stmts[0].(*ast.AssignStmt)
	if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	locID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
	if !isID {
		return false
	}
	locVar, _ := p.TypesInfo.Defs[locID].(*types.Var)
	if locVar == nil || !syntaxutil.IsPtrToNamed(locVar.Type(), rootNamed) {
		return false
	}
	lcall, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
	if !isCall || len(lcall.Args) != 0 {
		return false
	}
	lsel, isLSel := ast.Unparen(lcall.Fun).(*ast.SelectorExpr)
	if !isLSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, lsel.X, mRecv) {
		return false
	}
	loadFn, _ := p.TypesInfo.Uses[lsel.Sel].(*types.Func)
	fld := atomicLoadRootPtrField(p, idx, wrapNamed, rootNamed, loadFn)
	if fld == nil {
		return false
	}
	if len(stmts) == 3 {
		ifs, isIf := stmts[1].(*ast.IfStmt)
		if !isIf || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL ||
			!((syntaxutil.IsIdentUsingObj(p.TypesInfo, bin.X, locVar) && syntaxutil.IsNilIdent(p.TypesInfo, bin.Y)) ||
				(syntaxutil.IsNilIdent(p.TypesInfo, bin.X) && syntaxutil.IsIdentUsingObj(p.TypesInfo, bin.Y, locVar))) {
			return false
		}
		es, isES := ifs.Body.List[0].(*ast.ExprStmt)
		if !isES {
			return false
		}
		pcall, isPC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isPC {
			return false
		}
		pid, isPID := ast.Unparen(pcall.Fun).(*ast.Ident)
		if !isPID {
			return false
		}
		b, isB := p.TypesInfo.Uses[pid].(*types.Builtin)
		if !isB || b.Name() != "panic" {
			return false
		}
	}
	ret, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 || !syntaxutil.IsIdentUsingObj(p.TypesInfo, ret.Results[0], locVar) {
		return false
	}
	return !unexportedWrapperFieldMutatedInPkg(p, idx, fld, true, onceCone)
}

func atomicLoadRootPtrField(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	wrapNamed, rootNamed *types.Named,
	fn *types.Func,
) *types.Var {
	if fn == nil || fn.Pkg() != p.Types {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil
	}
	if !syntaxutil.IsPtrToNamed(sig.Recv().Type(), wrapNamed) || !syntaxutil.IsPtrToNamed(sig.Results().At(0).Type(), rootNamed) {
		return nil
	}
	fd := idx.FuncDecls[fn]
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 1 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return nil
	}
	recvVar, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if recvVar == nil {
		return nil
	}
	ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 {
		return nil
	}
	conv, isConv := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !syntaxutil.IsPtrToNamed(p.TypesInfo.Types[conv.Fun].Type, rootNamed) {
		return nil
	}
	lcall, isLC := ast.Unparen(conv.Args[0]).(*ast.CallExpr)
	if !isLC || len(lcall.Args) != 1 {
		return nil
	}
	lsel, isLS := ast.Unparen(lcall.Fun).(*ast.SelectorExpr)
	if !isLS {
		return nil
	}
	afn, isAF := p.TypesInfo.Uses[lsel.Sel].(*types.Func)
	if !isAF || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "LoadPointer" {
		return nil
	}
	cur := ast.Unparen(lcall.Args[0])
	for range 2 {
		c, isC := cur.(*ast.CallExpr)
		if !isC || len(c.Args) != 1 || !p.TypesInfo.Types[c.Fun].IsType() {
			break
		}
		cur = ast.Unparen(c.Args[0])
	}
	un, isUn := cur.(*ast.UnaryExpr)
	if !isUn || un.Op != token.AND {
		return nil
	}
	fsel, isFS := ast.Unparen(un.X).(*ast.SelectorExpr)
	if !isFS || !syntaxutil.IsIdentUsingObj(p.TypesInfo, fsel.X, recvVar) {
		return nil
	}
	selInfo := p.TypesInfo.Selections[fsel]
	if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
		return nil
	}
	fld, _ := selInfo.Obj().(*types.Var)
	if fld == nil || fld.Exported() || !syntaxutil.IsPtrToNamed(fld.Type(), rootNamed) {
		return nil
	}
	return fld
}

func unexportedWrapperFieldMutatedInPkg(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fld *types.Var,
	allowDetachedAtomicStore bool,
	onceCone map[*types.Func]bool,
) bool {
	holders := map[*types.Named]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i) == fld {
				holders[named] = true
				break
			}
		}
	}
	overwritten := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if overwritten || n == nil {
				return false
			}
			as, isAs := n.(*ast.AssignStmt)
			if !isAs {
				return true
			}
			for _, lhs := range as.Lhs {
				if star, isStar := ast.Unparen(lhs).(*ast.StarExpr); isStar {
					if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(star.X)); st != nil && holders[st] {
						overwritten = true
						return false
					}
				}
			}
			return true
		})
	}
	if overwritten {
		return true
	}

	for _, id := range idx.UsesOf[fld] {
		if kv, isKV := idx.ParentUnparen(id).(*ast.KeyValueExpr); isKV && kv.Key == id {
			continue
		}
		sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return true
		}
		if refconfine.IdentOrExprIsWritten(idx, sel) {
			return true
		}
		if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			if refconfine.IsPureAtomicLoadArg(p, idx, un) {
				continue
			}
			if allowDetachedAtomicStore && isDetachedAtomicStoreOnField(p, idx, un, onceCone) {
				continue
			}
			return true
		}
	}
	return false
}

func isDetachedAtomicStoreOnField(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	addrExpr *ast.UnaryExpr,
	onceCone map[*types.Func]bool,
) bool {
	arg := ast.Expr(addrExpr)
	par := idx.ParentUnparen(addrExpr)
	for range 2 {
		conv, isConv := par.(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || ast.Unparen(conv.Args[0]) != arg || !p.TypesInfo.Types[conv.Fun].IsType() {
			break
		}
		arg = conv
		par = idx.ParentUnparen(conv)
	}
	call, isCall := par.(*ast.CallExpr)
	if !isCall || len(call.Args) != 2 || ast.Unparen(call.Args[0]) != arg {
		return false
	}
	csel, isCS := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isCS {
		return false
	}
	afn, isAF := p.TypesInfo.Uses[csel.Sel].(*types.Func)
	if !isAF || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "StorePointer" {
		return false
	}
	encl := idx.SyncEnclFuncDecl(addrExpr)
	if encl == nil {
		return false
	}
	enclFn, _ := p.TypesInfo.Defs[encl.Name].(*types.Func)
	if enclFn == nil || onceCone[enclFn] {
		return false
	}
	return len(idx.UsesOf[enclFn]) == 0
}

func stmtsEstablishOnceInitOnVar(
	p *packages.Package,
	body *ast.BlockStmt,
	targetVar *types.Var,
	getterFn *types.Func,
	afterPos, beforePos token.Pos,
	flagField *types.Var,
	onceFn *types.Func,
	fastInitMethods map[*types.Func]bool,
) bool {
	if body == nil || freshstruct.FuncBodyHasGoto(body) {
		return false
	}
	matchesTargetRecv := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if getterFn == nil {
			return syntaxutil.IsIdentUsingObj(p.TypesInfo, expr, targetVar)
		}
		gcall, ok := expr.(*ast.CallExpr)
		if !ok || len(gcall.Args) != 0 {
			return false
		}
		gsel, ok := ast.Unparen(gcall.Fun).(*ast.SelectorExpr)
		if !ok || !syntaxutil.IsIdentUsingObj(p.TypesInfo, gsel.X, targetVar) {
			return false
		}
		return p.TypesInfo.Uses[gsel.Sel] == getterFn
	}
	isZeroArgInitCallOnVar := func(st ast.Stmt) bool {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := ast.Unparen(es.X).(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !matchesTargetRecv(sel.X) {
			return false
		}
		fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
		if !ok || fn == nil {
			return false
		}
		return fn == onceFn || fastInitMethods[fn]
	}

	stmts := body.List
	for i, st := range stmts {
		if afterPos != token.NoPos && st.Pos() < afterPos {
			continue
		}
		if st.End() > beforePos {
			break
		}
		if isZeroArgInitCallOnVar(st) {
			return true
		}
		if getterFn != nil {
			continue
		}
		ifs, ok := st.(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			continue
		}
		holdsAtZero, okCond := condHoldsAtZeroUint32Load(p, ifs.Cond, targetVar, flagField)
		if !okCond {
			continue
		}
		if holdsAtZero && isZeroArgInitCallOnVar(ifs.Body.List[0]) {
			return true
		}
		if !holdsAtZero {
			if _, isRet := ifs.Body.List[0].(*ast.ReturnStmt); isRet && i+1 < len(stmts) && stmts[i+1].End() <= beforePos && isZeroArgInitCallOnVar(stmts[i+1]) {
				return true
			}
		}
	}
	return false
}

func condHoldsAtZeroUint32Load(p *packages.Package, cond ast.Expr, targetVar, flagField *types.Var) (bool, bool) {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return false, false
	}
	isFlagLoad := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		return ok && len(call.Args) == 1 && isAtomicUint32Call(p, call, "LoadUint32") && isAddrOfRecvField(p, call.Args[0], targetVar, flagField)
	}
	constUint := func(expr ast.Expr) (uint64, bool) {
		tv, ok := p.TypesInfo.Types[expr]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int || constant.Sign(tv.Value) < 0 {
			return 0, false
		}
		return constant.Uint64Val(tv.Value)
	}
	op := bin.Op
	var c uint64
	var okC bool
	if isFlagLoad(bin.X) {
		c, okC = constUint(bin.Y)
	} else if isFlagLoad(bin.Y) {
		c, okC = constUint(bin.X)
		switch op {
		case token.LSS:
			op = token.GTR
		case token.LEQ:
			op = token.GEQ
		case token.GTR:
			op = token.LSS
		case token.GEQ:
			op = token.LEQ
		}
	}
	if !okC {
		return false, false
	}
	switch op {
	case token.EQL:
		return c == 0, true
	case token.NEQ:
		return c != 0, true
	case token.LSS:
		return c > 0, true
	case token.LEQ:
		return true, true
	case token.GTR:
		return false, true
	case token.GEQ:
		return c == 0, true
	default:
		return false, false
	}
}

