package dynstate

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func singlePointerToPkgScopeNamedStruct(t types.Type) (*types.Named, *types.Struct, bool) {
	if t == nil {
		return nil, nil, false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return nil, nil, false
	}
	return directPkgScopeNamedStruct(ptr.Elem())
}

func directPkgScopeNamedStruct(t types.Type) (*types.Named, *types.Struct, bool) {
	if t == nil {
		return nil, nil, false
	}
	u := types.Unalias(t)
	if _, isPtr := u.(*types.Pointer); isPtr {
		return nil, nil, false
	}
	named, ok := u.(*types.Named)
	if !ok || named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil, nil, false
	}
	if named.Obj().Parent() != named.Obj().Pkg().Scope() {
		return nil, nil, false
	}
	if named.TypeParams().Len() > 0 || named.TypeArgs().Len() > 0 {
		return nil, nil, false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return nil, nil, false
	}
	return named, st, true
}

func isNonStdModuleStruct(p *packages.Package, named *types.Named) (syntaxutil.TypeRef, bool) {
	if p == nil || p.Types == nil || named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return syntaxutil.TypeRef{}, false
	}
	pkgPath := named.Obj().Pkg().Path()
	if pkgPath == p.Types.Path() {
		if p.Module == nil {
			return syntaxutil.TypeRef{}, false
		}
	} else if imp := p.Imports[pkgPath]; imp != nil {
		if imp.Module == nil {
			return syntaxutil.TypeRef{}, false
		}
	} else if !syntaxutil.HasModuleImportPathShape(pkgPath) {
		return syntaxutil.TypeRef{}, false
	}
	ref := syntaxutil.TypeRef{Pkg: pkgPath, Name: named.Obj().Name()}
	if !ref.Valid() || ref.IsUnnamed() {
		return syntaxutil.TypeRef{}, false
	}
	return ref, true
}

func resolvePkgScopeVarExpr(p *packages.Package, expr ast.Expr) (*types.Var, *ast.Ident, bool) {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return nil, nil, false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := p.TypesInfo.Uses[e].(*types.Var)
		if !ok || v == nil || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return nil, nil, false
		}
		return v, e, true
	case *ast.SelectorExpr:
		if p.TypesInfo.Selections[e] != nil || e.Sel == nil {
			return nil, nil, false
		}
		v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var)
		if !ok || v == nil || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return nil, nil, false
		}
		return v, e.Sel, true
	default:
		return nil, nil, false
	}
}

func isDirectNonPromotedMethodCallIdent(p *packages.Package, idx *refconfine.PkgIndex, uid *ast.Ident) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || uid == nil {
		return false
	}
	mSel, ok := idx.ParentUnparen(uid).(*ast.SelectorExpr)
	if !ok || ast.Unparen(mSel.X) != uid {
		return false
	}
	selInfo := p.TypesInfo.Selections[mSel]
	if selInfo == nil || selInfo.Kind() != types.MethodVal || len(selInfo.Index()) != 1 {
		return false
	}
	call, ok := idx.ParentUnparen(mSel).(*ast.CallExpr)
	return ok && ast.Unparen(call.Fun) == mSel
}

// deriveReadOnlyVarAliases collects non-directive single-definition *NamedStruct
// package-variable aliases (`var A = Target` or `var A = &Target`), computing
// DirectMethodsOnly via greatest fixed point and returning the verified alias
// facts together with the RHS identifier uses exempted from NonMethodVarUses.
func deriveReadOnlyVarAliases(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	singleSubjectSet map[string]bool,
	claimedVars map[*types.Var]bool,
) ([]syntaxutil.ReadOnlyVarAlias, map[*ast.Ident]bool) {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil {
		return nil, nil
	}
	target := dynstateTarget(p)
	if !onceMemoConsumerPkgClean(p, idx) {
		emitDischargeReject(ctx, target, "read_only_var_alias", target, "pkg_directives_or_cgo_unclean", "")
		return nil, nil
	}

	type aliasCand struct {
		v          *types.Var
		key        string
		targetKey  string
		formAIdent *ast.Ident
		isFormA    bool
	}
	var cands []aliasCand
	candByVar := map[*types.Var]*aliasCand{}

	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.IsField() || claimedVars[v] {
			continue
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		varKey := syntaxutil.DynamicVarKey(v)
		if singleSubjectSet[varKey] || hasVarGofreshDirective(idx, v) {
			continue
		}
		named, _, ok := singlePointerToPkgScopeNamedStruct(v.Type())
		if !ok {
			continue
		}
		if _, okMod := isNonStdModuleStruct(p, named); !okMod {
			continue
		}
		initVal, ok := fc.singleWritePkgGlobalInit(p, v)
		if !ok || initVal == nil || initVal.Raw == nil {
			continue
		}

		rhs := ast.Unparen(initVal.Raw)
		var targetVar *types.Var
		var formAIdent *ast.Ident
		isFormA := false
		if un, isUn := rhs.(*ast.UnaryExpr); isUn && un.Op == token.AND {
			tv, _, okT := resolvePkgScopeVarExpr(p, un.X)
			if !okT || tv == v {
				continue
			}
			if _, isPtr := types.Unalias(tv.Type()).(*types.Pointer); isPtr {
				continue
			}
			if !types.Identical(named, types.Unalias(tv.Type())) {
				continue
			}
			targetVar = tv
		} else {
			tv, tid, okT := resolvePkgScopeVarExpr(p, rhs)
			if !okT || tv == v {
				continue
			}
			if !types.Identical(types.Unalias(v.Type()), types.Unalias(tv.Type())) {
				continue
			}
			targetVar = tv
			formAIdent = tid
			isFormA = true
		}

		targetKey := syntaxutil.DynamicVarKey(targetVar)
		if !syntaxutil.ValidQualifiedVarKey(varKey) || !syntaxutil.ValidQualifiedVarKey(targetKey) || varKey == targetKey {
			continue
		}
		cands = append(cands, aliasCand{
			v:          v,
			key:        varKey,
			targetKey:  targetKey,
			formAIdent: formAIdent,
			isFormA:    isFormA,
		})
	}
	if len(cands) == 0 {
		return nil, nil
	}

	formAOwnerByIdent := map[*ast.Ident]*types.Var{}
	directMethodsOnly := map[*types.Var]bool{}
	for i := range cands {
		c := &cands[i]
		candByVar[c.v] = c
		if c.isFormA {
			directMethodsOnly[c.v] = true
			if c.formAIdent != nil {
				formAOwnerByIdent[c.formAIdent] = c.v
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for _, c := range cands {
			if !directMethodsOnly[c.v] {
				continue
			}
			for _, uid := range idx.UsesOf[c.v] {
				if isDirectNonPromotedMethodCallIdent(p, idx, uid) {
					continue
				}
				if ownerAlias := formAOwnerByIdent[uid]; ownerAlias != nil && directMethodsOnly[ownerAlias] {
					continue
				}
				delete(directMethodsOnly, c.v)
				changed = true
				break
			}
		}
	}

	exemptIdents := map[*ast.Ident]bool{}
	out := make([]syntaxutil.ReadOnlyVarAlias, 0, len(cands))
	for _, c := range cands {
		dmo := directMethodsOnly[c.v]
		if dmo && c.formAIdent != nil {
			exemptIdents[c.formAIdent] = true
		}
		a := syntaxutil.ReadOnlyVarAlias{
			Key:               c.key,
			Target:            c.targetKey,
			DirectMethodsOnly: dmo,
		}
		if a.Valid() {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, syntaxutil.ReadOnlyVarAlias.Compare)
	if len(exemptIdents) == 0 {
		exemptIdents = nil
	}
	return out, exemptIdents
}

// deriveStaticCompositeGlobals mechanically identifies closed composite-literal
// package globals rooted at a non-empty non-standard named struct (by value or
// single-level pointer) whose complete reachable struct/element schema is
// covered by GuardTypes and confined against direct and subplace mutations.
func deriveStaticCompositeGlobals(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	singleSubjectSet map[string]bool,
	claimedVars map[*types.Var]bool,
) []syntaxutil.StaticCompositeGlobalFact {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil {
		return nil
	}
	target := dynstateTarget(p)
	if !onceMemoConsumerPkgClean(p, idx) {
		emitDischargeReject(ctx, target, "static_composite", target, "pkg_directives_or_cgo_unclean", "")
		return nil
	}

	writeInfos := fc.varWriteInfos(p)
	var out []syntaxutil.StaticCompositeGlobalFact
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.IsField() || claimedVars[v] || idx.DefCounts[v] != 1 {
			continue
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		varKey := syntaxutil.DynamicVarKey(v)
		if singleSubjectSet[varKey] || hasVarGofreshDirective(idx, v) {
			continue
		}
		var rootNamed *types.Named
		isPtrRoot := false
		if rn, _, okPtr := singlePointerToPkgScopeNamedStruct(v.Type()); okPtr {
			rootNamed = rn
			isPtrRoot = true
		} else if rn, _, okVal := directPkgScopeNamedStruct(v.Type()); okVal {
			rootNamed = rn
		}
		if rootNamed == nil {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "multi_var_or_missing_init", "", v.Pos())
			continue
		}
		stWrite := writeInfos[v]
		if stWrite == nil || stWrite.Defs != 1 || stWrite.InitVal == nil || stWrite.HasZeroDecl ||
			stWrite.HasNonPlainDef || stWrite.HasPostDefWrite || stWrite.HasChanSend || stWrite.HasBuiltinMut {
			emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "mutated_or_non_plain_global", "", v.Pos())
			continue
		}

		var comp *ast.CompositeLit
		if isPtrRoot {
			un, isUn := ast.Unparen(vs.Values[0]).(*ast.UnaryExpr)
			if !isUn || un.Op != token.AND {
				emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "ptr_root_not_addr_composite_lit", "", vs.Values[0].Pos())
				continue
			}
			comp, _ = ast.Unparen(un.X).(*ast.CompositeLit)
		} else {
			comp, _ = ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
		}
		if comp == nil {
			continue
		}

		guardSet := map[syntaxutil.TypeRef]bool{}
		schemaChecked := map[*types.Named]bool{}
		inProgress := map[*types.Named]bool{}
		if !verifyStaticCompositeStructSchema(audited, p, rootNamed, guardSet, schemaChecked, inProgress) {
			emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "schema_rejected", rootNamed.Obj().Name(), v.Pos())
			continue
		}
		if !verifyStaticCompositeStructLit(audited, p, rootNamed, comp) {
			emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "composite_lit_rejected", rootNamed.Obj().Name(), comp.Pos())
			continue
		}
		if !verifyStaticCompositeGlobalUses(p, idx, v, isPtrRoot) {
			emitDischargeRejectAt(ctx, p, target, "static_composite", varKey, "intra_pkg_use_unconfined", rootNamed.Obj().Name(), v.Pos())
			continue
		}

		guards := make([]syntaxutil.TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guards = append(guards, g)
		}
		slices.SortFunc(guards, syntaxutil.TypeRef.Compare)
		fact := syntaxutil.StaticCompositeGlobalFact{
			Key:        varKey,
			GuardTypes: guards,
		}
		if fact.Valid() {
			out = append(out, fact)
		}
	}
	slices.SortFunc(out, syntaxutil.StaticCompositeGlobalFact.Compare)
	return out
}

func verifyStaticCompositeStructSchema(
	audited bool,
	p *packages.Package,
	named *types.Named,
	guardSet map[syntaxutil.TypeRef]bool,
	checked map[*types.Named]bool,
	inProgress map[*types.Named]bool,
) bool {
	if named == nil {
		return false
	}
	if checked[named] {
		return true
	}
	if inProgress[named] {
		return false
	}
	ref, okMod := isNonStdModuleStruct(p, named)
	if !okMod {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return false
	}
	if types.NewMethodSet(types.NewPointer(named)).Len() != 0 {
		return false
	}
	inProgress[named] = true
	defer delete(inProgress, named)
	guardSet[ref] = true

	for i := 0; i < st.NumFields(); i++ {
		ft := types.Unalias(st.Field(i).Type())
		if !verifyStaticCompositeFieldSchema(audited, p, ft, guardSet, checked, inProgress) {
			return false
		}
	}
	checked[named] = true
	return true
}

func verifyStaticCompositeFieldSchema(
	audited bool,
	p *packages.Package,
	ft types.Type,
	guardSet map[syntaxutil.TypeRef]bool,
	checked map[*types.Named]bool,
	inProgress map[*types.Named]bool,
) bool {
	if ft == nil {
		return false
	}
	ft = types.Unalias(ft)
	if subNamed, _, okSub := directPkgScopeNamedStruct(ft); okSub {
		return verifyStaticCompositeStructSchema(audited, p, subNamed, guardSet, checked, inProgress)
	}
	switch u := ft.Underlying().(type) {
	case *types.Basic:
		return isScalarBasicType(ft)
	case *types.Signature:
		return u.TypeParams().Len() == 0
	case *types.Interface:
		return true
	case *types.Slice:
		elemNamed, _, okElem := directPkgScopeNamedStruct(u.Elem())
		if !okElem {
			return false
		}
		return verifyStaticCompositeStructSchema(audited, p, elemNamed, guardSet, checked, inProgress)
	case *types.Array:
		elemNamed, _, okElem := directPkgScopeNamedStruct(u.Elem())
		if !okElem {
			return false
		}
		return verifyStaticCompositeStructSchema(audited, p, elemNamed, guardSet, checked, inProgress)
	default:
		return false
	}
}

func verifyStaticCompositeStructLit(
	audited bool,
	p *packages.Package,
	expectedNamed *types.Named,
	comp *ast.CompositeLit,
) bool {
	if p == nil || p.TypesInfo == nil || expectedNamed == nil || comp == nil {
		return false
	}
	litT := p.TypesInfo.TypeOf(comp)
	if litT == nil || !types.Identical(types.Unalias(litT), expectedNamed) {
		return false
	}
	st, ok := expectedNamed.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return false
	}
	if len(comp.Elts) == 0 {
		return true
	}

	_, firstKV := comp.Elts[0].(*ast.KeyValueExpr)
	if firstKV {
		for _, elt := range comp.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
			if !isID {
				return false
			}
			fld, _ := p.TypesInfo.Uses[kid].(*types.Var)
			if fld == nil || !fld.IsField() {
				return false
			}
			if !verifyStaticCompositeFieldValue(audited, p, fld.Type(), kv.Value) {
				return false
			}
		}
		return true
	}

	if len(comp.Elts) != st.NumFields() {
		return false
	}
	for i, elt := range comp.Elts {
		if _, isKV := elt.(*ast.KeyValueExpr); isKV {
			return false
		}
		if !verifyStaticCompositeFieldValue(audited, p, st.Field(i).Type(), elt) {
			return false
		}
	}
	return true
}

func verifyStaticCompositeFieldValue(
	audited bool,
	p *packages.Package,
	fieldType types.Type,
	expr ast.Expr,
) bool {
	if expr == nil || fieldType == nil {
		return false
	}
	ft := types.Unalias(fieldType)
	val := ast.Unparen(expr)

	if subNamed, _, okSub := directPkgScopeNamedStruct(ft); okSub {
		subComp, okComp := val.(*ast.CompositeLit)
		return okComp && verifyStaticCompositeStructLit(audited, p, subNamed, subComp)
	}

	switch u := ft.Underlying().(type) {
	case *types.Basic:
		if !isScalarBasicType(ft) {
			return false
		}
		tv := p.TypesInfo.Types[val]
		return tv.Value != nil

	case *types.Signature:
		if u.TypeParams().Len() > 0 {
			return false
		}
		if syntaxutil.IsNilIdent(p.TypesInfo, val) || isSafeTypedNilConversion(p, val) {
			return true
		}
		// Unwrap any chain of signature-to-signature type conversions (e.g. MethodHandler(fn)).
		for {
			call, isCall := val.(*ast.CallExpr)
			if !isCall || len(call.Args) != 1 || call.Ellipsis.IsValid() {
				break
			}
			tvFun := p.TypesInfo.Types[ast.Unparen(call.Fun)]
			if !tvFun.IsType() || tvFun.Type == nil {
				break
			}
			sigConv, isSig := tvFun.Type.Underlying().(*types.Signature)
			if !isSig || sigConv.TypeParams().Len() > 0 {
				break
			}
			val = ast.Unparen(call.Args[0])
		}
		return isBareTopLevelNonGenericFuncExpr(p, val)

	case *types.Interface:
		if syntaxutil.IsNilIdent(p.TypesInfo, val) || isSafeTypedNilConversion(p, val) {
			return true
		}
		tv := p.TypesInfo.Types[val]
		return tv.Value != nil && tv.Type != nil &&
			!refconfine.TypeMayCarryUnknownDynamic(audited, tv.Type) &&
			!syntaxutil.ContainsUintptr(tv.Type)

	case *types.Slice:
		elemNamed, _, okElem := directPkgScopeNamedStruct(u.Elem())
		if !okElem {
			return false
		}
		if syntaxutil.IsNilIdent(p.TypesInfo, val) || syntaxutil.IsTypedNilSliceConv(p, val) {
			return true
		}
		slComp, okComp := val.(*ast.CompositeLit)
		return okComp && verifyStaticCompositeSeqLit(audited, p, elemNamed, slComp)

	case *types.Array:
		elemNamed, _, okElem := directPkgScopeNamedStruct(u.Elem())
		if !okElem {
			return false
		}
		arrComp, okComp := val.(*ast.CompositeLit)
		return okComp && verifyStaticCompositeSeqLit(audited, p, elemNamed, arrComp)

	default:
		return false
	}
}

func verifyStaticCompositeSeqLit(
	audited bool,
	p *packages.Package,
	elemNamed *types.Named,
	seqComp *ast.CompositeLit,
) bool {
	for _, elt := range seqComp.Elts {
		itemExpr := elt
		if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
			if p.TypesInfo.Types[kv.Key].Value == nil {
				return false
			}
			itemExpr = kv.Value
		}
		itemComp, isComp := ast.Unparen(itemExpr).(*ast.CompositeLit)
		if !isComp || !verifyStaticCompositeStructLit(audited, p, elemNamed, itemComp) {
			return false
		}
	}
	return true
}

func isBareTopLevelNonGenericFuncExpr(p *packages.Package, expr ast.Expr) bool {
	var fn *types.Func
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if _, hasInst := p.TypesInfo.Instances[e]; hasInst {
			return false
		}
		fn, _ = p.TypesInfo.Uses[e].(*types.Func)
	case *ast.SelectorExpr:
		if p.TypesInfo.Selections[e] != nil || e.Sel == nil {
			return false
		}
		if _, hasInst := p.TypesInfo.Instances[e.Sel]; hasInst {
			return false
		}
		fn, _ = p.TypesInfo.Uses[e.Sel].(*types.Func)
	default:
		return false
	}
	if fn == nil || fn.Origin() != fn || fn.Pkg() == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() == nil && sig.TypeParams().Len() == 0
}

func isSafeTypedNilConversion(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	tvFun := p.TypesInfo.Types[ast.Unparen(call.Fun)]
	if !tvFun.IsType() || tvFun.Type == nil || !syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
		return false
	}
	dst := types.Unalias(tvFun.Type)
	if syntaxutil.ContainsUnsafePointer(dst) {
		return false
	}
	switch dst.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
		return true
	default:
		return false
	}
}

func verifyStaticCompositeGlobalUses(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	v *types.Var,
	isPtrRoot bool,
) bool {
	for _, uid := range idx.UsesOf[v] {
		if !verifyStaticCompositeUseChain(p, idx, uid, isPtrRoot) {
			return false
		}
	}
	return true
}

func verifyStaticCompositeUseChain(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	uid *ast.Ident,
	isPtrRoot bool,
) bool {
	// Walk outward through parenthesis, deref, field selector, and index steps,
	// checking every step against writes, slicing, address-takes, and calls.
	var cur ast.Expr = uid
	isRoot := true
	for {
		par := idx.ParentMap[cur]
		for {
			paren, isParen := par.(*ast.ParenExpr)
			if !isParen {
				break
			}
			cur = paren
			par = idx.ParentMap[cur]
		}
		switch x := par.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if ast.Unparen(lhs) == cur {
					return false
				}
			}
			if !isRoot {
				return isScalarBasicType(p.TypesInfo.TypeOf(cur))
			}
			return true

		case *ast.IncDecStmt:
			if ast.Unparen(x.X) == cur {
				return false
			}
			return true

		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN && ((x.Key != nil && ast.Unparen(x.Key) == cur) || (x.Value != nil && ast.Unparen(x.Value) == cur)) {
				return false
			}
			return true

		case *ast.SliceExpr:
			if ast.Unparen(x.X) == cur {
				return false
			}
			return true

		case *ast.UnaryExpr:
			if x.Op == token.AND && ast.Unparen(x.X) == cur {
				if isRoot {
					// Whole-root &v is safe iff v is a by-value GuardStruct (*GuardStruct);
					// &ptrRoot produces **GuardStruct, which is not tracked in MutatedStructTypes.
					return !isPtrRoot
				}
				// Subplace &sub is safe iff sub is a by-value non-empty non-std GuardStruct.
				subNamed, _, okSub := directPkgScopeNamedStruct(p.TypesInfo.TypeOf(cur))
				if !okSub {
					return false
				}
				_, okMod := isNonStdModuleStruct(p, subNamed)
				return okMod
			}
			return true

		case *ast.StarExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				isRoot = false
				continue
			}
			return true

		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				selInfo := p.TypesInfo.Selections[x]
				if selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					isRoot = false
					continue
				}
				return false
			}
			return true

		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				isRoot = false
				continue
			}
			return true

		case *ast.CallExpr:
			if ast.Unparen(x.Fun) == cur {
				// Direct call to a verified non-generic function field (e.g. v.Handler(...)) is safe.
				return !isRoot
			}
			if tv := p.TypesInfo.Types[ast.Unparen(x.Fun)]; tv.IsType() {
				if isRoot {
					iface, okIf := syntaxutil.UnderlyingType(tv.Type).(*types.Interface)
					return okIf && iface.NumMethods() == 0
				}
				return isScalarBasicType(p.TypesInfo.TypeOf(cur))
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
				switch b.Name() {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return true
				case "delete", "clear", "copy", "append", "Slice", "SliceData":
					return false
				}
			}
			if isRoot {
				return true
			}
			return isScalarBasicType(p.TypesInfo.TypeOf(cur))

		default:
			if isRoot {
				return true
			}
			return isScalarBasicType(p.TypesInfo.TypeOf(cur))
		}
	}
}
