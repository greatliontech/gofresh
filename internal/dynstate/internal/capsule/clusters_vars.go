package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyTypedNilAnySliceElemAssign(
	p *packages.Package,
	as *ast.AssignStmt,
	makeSliceVars map[*types.Var]*types.Struct,
) (*types.Var, *ast.Ident, bool) {
	if len(makeSliceVars) == 0 || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return nil, nil, false
	}
	sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || !sel.Sel.IsExported() {
		return nil, nil, false
	}
	fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
	if fld == nil || !fld.Exported() || !syntaxutil.IsAnySliceType(fld.Type()) {
		return nil, nil, false
	}
	ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
	if !ok || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
		return nil, nil, false
	}
	sliceID, ok := ast.Unparen(ie.X).(*ast.Ident)
	if !ok {
		return nil, nil, false
	}
	sv, _ := p.TypesInfo.Uses[sliceID].(*types.Var)
	if sv == nil || makeSliceVars[sv] == nil {
		return nil, nil, false
	}
	comp, ok := ast.Unparen(as.Rhs[0]).(*ast.CompositeLit)
	if !ok || !syntaxutil.IsAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return nil, nil, false
	}
	for _, elt := range comp.Elts {
		if !syntaxutil.IsTypedNilStructPtrInPkg(p, elt, p.Types) {
			return nil, nil, false
		}
	}
	return sv, sliceID, true
}

func verifyPreBuildProjectionClosureIfStmt(
	p *packages.Package,
	ifs *ast.IfStmt,
	makeSliceVars map[*types.Var]*types.Struct,
) ([]*types.Var, []*ast.Ident, []*ast.AssignStmt, bool) {
	if len(makeSliceVars) == 0 || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) == 0 {
		return nil, nil, nil, false
	}
	condClean := true
	ast.Inspect(ifs.Cond, func(n ast.Node) bool {
		if !condClean || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			condClean = false
			return false
		}
		return true
	})
	if !condClean {
		return nil, nil, nil, false
	}
	var svs []*types.Var
	var ids []*ast.Ident
	var assigns []*ast.AssignStmt
	for _, st := range ifs.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return nil, nil, nil, false
		}
		sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || !sel.Sel.IsExported() {
			return nil, nil, nil, false
		}
		fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		if fld == nil || !fld.Exported() {
			return nil, nil, nil, false
		}
		if _, isSig := syntaxutil.UnderlyingType(fld.Type()).(*types.Signature); !isSig {
			return nil, nil, nil, false
		}
		ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
		if !ok || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
			return nil, nil, nil, false
		}
		sliceID, ok := ast.Unparen(ie.X).(*ast.Ident)
		if !ok {
			return nil, nil, nil, false
		}
		sv, _ := p.TypesInfo.Uses[sliceID].(*types.Var)
		if sv == nil || makeSliceVars[sv] == nil {
			return nil, nil, nil, false
		}
		lit, ok := ast.Unparen(as.Rhs[0]).(*ast.FuncLit)
		if !ok || !isPureFieldProjectionFuncLit(p, lit) {
			return nil, nil, nil, false
		}
		svs = append(svs, sv)
		ids = append(ids, sliceID)
		assigns = append(assigns, as)
	}
	return svs, ids, assigns, true
}

func isPureFieldProjectionFuncLit(p *packages.Package, lit *ast.FuncLit) bool {
	if lit == nil || lit.Body == nil {
		return false
	}
	clean := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr, *ast.GoStmt, *ast.SendStmt, *ast.FuncLit:
			clean = false
			return false
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE {
				clean = false
				return false
			}
			for _, rhs := range x.Rhs {
				if _, isTA := ast.Unparen(rhs).(*ast.TypeAssertExpr); !isTA {
					clean = false
					return false
				}
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && v != nil && !v.IsField() {
				if v.Parent() == p.Types.Scope() || v.Pos() < lit.Pos() {
					clean = false
					return false
				}
			}
		}
		return true
	})
	return clean
}

func verifyClusterGuardVarUses(_ *packages.Package, idx *refconfine.PkgIndex, guardVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	for _, id := range idx.UsesOf[guardVar] {
		if allowedInit[id] {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(idx, id) {
			return false
		}
	}
	return true
}

func verifyClusterTypeSampleSliceVar(p *packages.Package, idx *refconfine.PkgIndex, sampleVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	if idx.DefCounts[sampleVar] != 1 {
		return false
	}
	vs := idx.VarSpecs[sampleVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok || !syntaxutil.IsAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return false
	}
	for _, elt := range comp.Elts {
		if !isSafeTypeSampleElement(p, elt) {
			return false
		}
	}
	for _, id := range idx.UsesOf[sampleVar] {
		if !allowedInit[id] {
			return false
		}
	}
	return true
}

func isSafeTypeSampleElement(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	dstType := types.Unalias(p.TypesInfo.Types[call.Fun].Type)
	if _, isPtr := dstType.(*types.Pointer); isPtr {
		return syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0])
	}
	if basic, isBasic := dstType.Underlying().(*types.Basic); isBasic && (basic.Info()&types.IsConstType) != 0 {
		tv := p.TypesInfo.Types[call.Args[0]]
		return tv.Value != nil && !refconfine.TypeMayCarryUnknownDynamic(true, dstType)
	}
	return false
}

func verifyClusterMakeSliceVar(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initFD *ast.FuncDecl,
	sliceVar *types.Var,
	allowedInit map[*ast.Ident]bool,
) bool {
	if idx.DefCounts[sliceVar] != 1 {
		return false
	}
	vs := idx.VarSpecs[sliceVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 || !syntaxutil.IsMakeFixedSliceCall(p, vs.Values[0]) {
		return false
	}
	for _, id := range idx.UsesOf[sliceVar] {
		if allowedInit[id] {
			continue
		}
		if idx.EnclFunc[id] == initFD {
			return false
		}
		ie, ok := idx.ParentUnparen(id).(*ast.IndexExpr)
		if !ok || ast.Unparen(ie.X) != id || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
			return false
		}
		iePar := idx.ParentUnparen(ie)
		if as, isAs := iePar.(*ast.AssignStmt); isAs {
			for _, lhs := range as.Lhs {
				if ast.Unparen(lhs) == ie {
					return false
				}
			}
		}
		if inc, isInc := iePar.(*ast.IncDecStmt); isInc && ast.Unparen(inc.X) == ie {
			return false
		}
		if rng, isRng := iePar.(*ast.RangeStmt); isRng && rng.Tok == token.ASSIGN &&
			((rng.Key != nil && ast.Unparen(rng.Key) == ie) || (rng.Value != nil && ast.Unparen(rng.Value) == ie)) {
			return false
		}
	}
	return true
}

func verifyClusterStaticSliceAndBoundVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	staticVar *types.Var,
	elemSt *types.Struct,
	allowedInit map[*ast.Ident]bool,
) ([]*types.Var, []string, bool) {
	if idx.DefCounts[staticVar] != 1 {
		return nil, nil, false
	}
	vs := idx.VarSpecs[staticVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return nil, nil, false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok {
		return nil, nil, false
	}

	exportedFields := map[string]*types.Var{}
	commonNonNil := map[string]bool{}
	for i := 0; i < elemSt.NumFields(); i++ {
		f := elemSt.Field(i)
		if f.Exported() {
			exportedFields[f.Name()] = f
			if isNilComparableType(f.Type()) {
				commonNonNil[f.Name()] = true
			}
		}
	}

	for _, elt := range comp.Elts {
		sub, isSub := ast.Unparen(elt).(*ast.CompositeLit)
		if !isSub {
			return nil, nil, false
		}
		elemNonNil, okElem := verifyStaticCapsuleLiteralElement(p, exportedFields, sub)
		if !okElem {
			return nil, nil, false
		}
		for nm := range commonNonNil {
			if !elemNonNil[nm] {
				delete(commonNonNil, nm)
			}
		}
	}

	var nonNilNames []string
	for nm := range commonNonNil {
		nonNilNames = append(nonNilNames, nm)
	}
	sort.Strings(nonNilNames)

	var boundVars []*types.Var
	seenVars := map[*types.Var]bool{}
	for _, id := range idx.UsesOf[staticVar] {
		if allowedInit[id] {
			continue
		}
		if idx.EnclFunc[id] != nil || idx.InFuncLit[id] || idx.InGoStmt[id] {
			return nil, nil, false
		}
		ie, ok := idx.ParentUnparen(id).(*ast.IndexExpr)
		if !ok || ast.Unparen(ie.X) != id || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
			return nil, nil, false
		}
		un, ok := idx.ParentUnparen(ie).(*ast.UnaryExpr)
		if !ok || un.Op != token.AND {
			return nil, nil, false
		}
		spec, ok := idx.ParentUnparen(un).(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 || ast.Unparen(spec.Values[0]) != un {
			return nil, nil, false
		}
		ev, ok := p.TypesInfo.Defs[spec.Names[0]].(*types.Var)
		if !ok || ev == nil || ev.Parent() != p.Types.Scope() || idx.DefCounts[ev] != 1 {
			return nil, nil, false
		}
		if !verifyReadOnlyPtrVarUses(p, idx, ev) {
			return nil, nil, false
		}
		if !seenVars[ev] {
			seenVars[ev] = true
			boundVars = append(boundVars, ev)
		}
	}
	return boundVars, nonNilNames, true
}

func verifyStaticCapsuleLiteralElement(
	p *packages.Package,
	exportedFields map[string]*types.Var,
	comp *ast.CompositeLit,
) (map[string]bool, bool) {
	nonNil := map[string]bool{}
	seen := map[string]bool{}
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok || seen[kID.Name] {
			return nil, false
		}
		seen[kID.Name] = true
		fld := exportedFields[kID.Name]
		if fld == nil {
			return nil, false
		}
		val := ast.Unparen(kv.Value)
		if !isSafeStaticCapsuleFieldExpr(p, val) {
			return nil, false
		}
		if isProvablyNonNilStaticCapsuleFieldVal(p, fld.Type(), val) {
			nonNil[kID.Name] = true
		}
	}
	return nonNil, true
}

func isSafeStaticCapsuleFieldExpr(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
		return true
	}
	if tv := p.TypesInfo.Types[expr]; tv.Value != nil && !refconfine.TypeMayCarryUnknownDynamic(true, tv.Type) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	dst := types.Unalias(p.TypesInfo.Types[call.Fun].Type)
	switch dst.Underlying().(type) {
	case *types.Pointer, *types.Slice:
		return syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0])
	case *types.Basic:
		tv := p.TypesInfo.Types[call.Args[0]]
		return tv.Value != nil
	}
	return false
}

func isProvablyNonNilStaticCapsuleFieldVal(p *packages.Package, fieldType types.Type, val ast.Expr) bool {
	if !types.IsInterface(fieldType) {
		return false
	}
	val = ast.Unparen(val)
	if syntaxutil.IsNilIdent(p.TypesInfo, val) {
		return false
	}
	if tv := p.TypesInfo.Types[val]; tv.Value != nil {
		return true
	}
	call, ok := val.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	dst := types.Unalias(p.TypesInfo.Types[call.Fun].Type)
	return !types.IsInterface(dst)
}

func verifyReadOnlyPtrVarUses(_ *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	for _, id := range idx.UsesOf[v] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, id) {
			return false
		}
		par := idx.ParentUnparen(id)
		if star, isStar := par.(*ast.StarExpr); isStar {
			if refconfine.IdentOrExprIsWritten(idx, star) {
				return false
			}
		}
	}
	return true
}
