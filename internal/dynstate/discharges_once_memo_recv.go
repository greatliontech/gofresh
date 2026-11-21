package dynstate

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyOnceMemoMethodRecvConfinement(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	pkgConf *packageConfinementSummary,
	ownerNamed *types.Named,
	mfn *types.Func,
	mfd *ast.FuncDecl,
	isGetter bool,
	doStmt *ast.ExprStmt,
	doLit *ast.FuncLit,
	onceField *types.Var,
	memoFields map[*types.Var]bool,
	inputFields map[*types.Var]bool,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	sig, ok := mfn.Type().(*types.Signature)
	if !ok || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Recv() == nil {
		return false
	}
	recvVar := sig.Recv()
	if !syntaxutil.IsPtrToNamed(recvVar.Type(), ownerNamed) {
		return false
	}
	for ri := 0; ri < sig.Results().Len(); ri++ {
		rt := sig.Results().At(ri).Type()
		if typeReachesNamedOrSyncOnce(rt, ownerNamed) {
			return false
		}
	}
	b := fc.funcBody(p, mfd)
	if b == nil {
		return false
	}
	if isGetter {
		if doStmt == nil || slices.Index(mfd.Body.List, ast.Stmt(doStmt)) < 0 {
			return false
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			if op.StmtAST != nil && op.StmtAST.Pos() < doStmt.Pos() && flowir.OpMentionsVars(op, memoFields) {
				return false
			}
		}
	}
	return verifyOnceMemoRecvUsesInBody(
		audited,
		p,
		fc,
		pkgConf,
		ownerNamed,
		recvVar,
		onceField,
		isGetter,
		memoFields,
		inputFields,
		nil,
		doLit,
		b,
		inputParamDeps,
	)
}

func recordOrVerifyOnceMemoParamDep(
	ownPath string,
	pkgConf *packageConfinementSummary,
	pk syntaxutil.ParamKey,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	provenLocal, conditional := pkgConf.classifyParam(ownPath, pk)
	if provenLocal {
		return true
	}
	if conditional {
		inputParamDeps[pk] = true
		return true
	}
	return false
}

func isConfinedDirectCallClosureVar(p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, lv *types.Var) bool {
	if lv == nil || idx.DefCounts[lv] != 1 || fc.varHasExplicitWriteOrAddr(p, lv) {
		return false
	}
	for _, uid := range idx.UsesOf[lv] {
		if !idx.CalleeIdents[uid] {
			return false
		}
	}
	return true
}

func verifyOnceMemoCtorCallArg(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	arg ast.Expr,
) bool {
	if arg == nil {
		return false
	}
	arg = ast.Unparen(arg)
	argT := p.TypesInfo.TypeOf(arg)
	if argT == nil || refconfine.TypeMayCarryUnknownDynamic(audited, argT) || refconfine.TypeCarriesSignature(argT) {
		return false
	}
	if !refconfine.TypeCarriesMutableRef(argT) && !syntaxutil.ContainsUintptr(argT) {
		return true
	}
	if isPureConstantOrCompositeDataValue(fc.exprValue(p, arg)) {
		return true
	}
	id, isID := arg.(*ast.Ident)
	if !isID {
		return false
	}
	v, _ := p.TypesInfo.Uses[id].(*types.Var)
	if v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() || v.Exported() {
		return false
	}
	return verifyReadOnlyCarrierFreeGlobalVar(audited, p, fc, idx, v, id, false)
}

func verifyReadOnlyCarrierFreeGlobalVar(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	v *types.Var,
	exemptIdent *ast.Ident,
	requirePureInit bool,
) bool {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 || hasVarGofreshDirective(idx, v) {
		return false
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) || refconfine.TypeCarriesSignature(v.Type()) {
		return false
	}
	vs := idx.VarSpecs[v]
	if vs == nil || len(vs.Names) != 1 {
		return false
	}
	if len(vs.Values) > 1 {
		return false
	}
	if len(vs.Values) == 1 && !isPureConstantOrCompositeDataValue(fc.exprValue(p, vs.Values[0])) {
		return false
	}
	if requirePureInit && len(vs.Values) == 0 {
		return false
	}
	if fc.varHasExplicitWriteOrAddr(p, v) {
		return false
	}
	if !refconfine.TypeCarriesMutableRef(v.Type()) {
		return true
	}
	otherUses := map[*ast.Ident]bool{}
	for _, uid := range idx.UsesOf[v] {
		if uid == exemptIdent {
			continue
		}
		otherUses[uid] = true
	}
	if len(otherUses) == 0 {
		return true
	}
	return refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		AllowReturnFromUnexportedFunc: false,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, isID := ast.Unparen(expr).(*ast.Ident)
			if !isID || !otherUses[id] {
				return false, false
			}
			return refconfine.IsDirectMutableRef(v.Type()), true
		},
	})
}

func allIntraPkgVarUsesAreDirectMethodCalls(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var, exemptUseIdents map[*ast.Ident]bool) bool {
	for _, uid := range idx.UsesOf[v] {
		if exemptUseIdents[uid] {
			continue
		}
		if !isDirectNonPromotedMethodCallIdent(p, idx, uid) {
			return false
		}
	}
	return true
}

func isReadOnlyInputSliceStdlibCallee(p *packages.Package, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || !syntaxutil.IsTrueStdlibInPkg(p, fn.Pkg().Path()) {
		return false
	}
	traits := auditset.DeterministicStdCallTraits(fn.Pkg().Path(), fn.Name())
	return traits.ReadOnlySliceInspect || traits.ReadOnlySliceCopy
}

func lookupAnyPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
			return v
		}
	case *ast.SelectorExpr:
		if p.TypesInfo.Selections[e] == nil {
			if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
				return v
			}
		}
	}
	return nil
}

func lookupRootPkgScopeVarAnyPkg(p *packages.Package, expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	for {
		if v := lookupAnyPkgScopeVar(p, cur); v != nil {
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

func typeReachesNamedOrSyncOnce(root types.Type, target *types.Named) bool {
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
		if named, ok := t.(*types.Named); ok {
			orig := named.Origin()
			if orig == target || syntaxutil.IsNamedInPkg(orig, "sync", "Once") {
				hit = true
				return
			}
			for i := 0; i < named.TypeArgs().Len(); i++ {
				walk(named.TypeArgs().At(i))
			}
		}
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

func typeReachesStruct(root types.Type, target *types.Named) bool {
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
		if named, ok := t.(*types.Named); ok && named.Origin() == target {
			hit = true
			return
		}
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
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func isScalarBasicType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	if !ok || b.Kind() == types.Uintptr {
		return false
	}
	return (b.Info() & (types.IsBoolean | types.IsInteger | types.IsFloat | types.IsComplex | types.IsString)) != 0
}

func isBasicStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && (b.Info()&types.IsString) != 0
}
