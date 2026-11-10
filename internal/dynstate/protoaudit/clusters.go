package protoaudit

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func deriveProtoClusters(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initOnly map[string]bool,
	exempted map[ast.Node]bool,
) ([]ProtoClusterFact, []ProtoExtAlias) {
	var clusters []ProtoClusterFact
	claimedVars := map[*types.Var]bool{}

	var fnObjs []*types.Func
	for fn := range idx.FuncDecls {
		if fn.Pkg() == p.Types && !fn.Exported() {
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil && sig.TypeParams().Len() == 0 &&
				sig.Params().Len() == 0 && sig.Results().Len() == 0 && fn.Name() != "init" {
				if initOnly[fn.Name()] {
					fnObjs = append(fnObjs, fn)
				}
			}
		}
	}
	sort.Slice(fnObjs, func(i, j int) bool { return fnObjs[i].Name() < fnObjs[j].Name() })

	for _, fn := range fnObjs {
		fd := idx.FuncDecls[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		cluster, clusterVars, initExempt, ok := verifyProtoClusterInitFunc(audited, p, idx, fn, fd, initOnly)
		if !ok {
			continue
		}
		overlap := false
		for _, v := range clusterVars {
			if claimedVars[v] {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		for _, v := range clusterVars {
			claimedVars[v] = true
		}
		for n := range initExempt {
			exempted[n] = true
		}
		clusters = append(clusters, cluster)
	}

	var aliases []ProtoExtAlias
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || claimedVars[v] || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if idx.DefCounts[v] != 1 {
			continue
		}
		ptr, isPtr := types.Unalias(v.Type()).(*types.Pointer)
		if !isPtr || syntaxutil.DerefNamedStruct(ptr.Elem()) == nil {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		sel, isSel := ast.Unparen(vs.Values[0]).(*ast.SelectorExpr)
		if !isSel {
			continue
		}
		targetVar, isVar := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		if !isVar || targetVar.Pkg() == nil || targetVar.Pkg() == p.Types || targetVar.IsField() {
			continue
		}
		if !types.Identical(types.Unalias(v.Type()), types.Unalias(targetVar.Type())) {
			continue
		}
		if !verifyReadOnlyPtrVarUses(p, idx, v) {
			continue
		}
		aliases = append(aliases, ProtoExtAlias{
			Key:    syntaxutil.DynamicVarKey(v),
			Target: syntaxutil.DynamicVarKey(targetVar),
		})
	}
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].Key != aliases[j].Key {
			return aliases[i].Key < aliases[j].Key
		}
		return aliases[i].Target < aliases[j].Target
	})
	return clusters, aliases
}

func verifyProtoClusterInitFunc(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fn *types.Func,
	fd *ast.FuncDecl,
	initOnly map[string]bool,
) (ProtoClusterFact, []*types.Var, map[ast.Node]bool, bool) {
	stmts := fd.Body.List
	if len(stmts) < 3 {
		return ProtoClusterFact{}, nil, nil, false
	}

	guardIf, ok := stmts[0].(*ast.IfStmt)
	if !ok || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 {
		return ProtoClusterFact{}, nil, nil, false
	}
	if ret, isRet := guardIf.Body.List[0].(*ast.ReturnStmt); !isRet || len(ret.Results) != 0 {
		return ProtoClusterFact{}, nil, nil, false
	}
	guardBin, ok := ast.Unparen(guardIf.Cond).(*ast.BinaryExpr)
	if !ok || guardBin.Op != token.NEQ {
		return ProtoClusterFact{}, nil, nil, false
	}
	var fileVar *types.Var
	if syntaxutil.IsNilIdent(p.TypesInfo, guardBin.Y) {
		fileVar = syntaxutil.LookupPkgScopeVar(p, guardBin.X)
	} else if syntaxutil.IsNilIdent(p.TypesInfo, guardBin.X) {
		fileVar = syntaxutil.LookupPkgScopeVar(p, guardBin.Y)
	}
	if fileVar == nil || idx.DefCounts[fileVar] != 1 || !types.IsInterface(fileVar.Type()) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if fvs := idx.VarSpecs[fileVar]; fvs == nil || len(fvs.Values) != 0 {
		return ProtoClusterFact{}, nil, nil, false
	}

	buildIdx := -1
	var outVar *types.Var
	var builderComp *ast.CompositeLit
	var builderRef syntaxutil.TypeRef
	for i := 1; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		call, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			continue
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Build" {
			continue
		}
		comp, isComp := ast.Unparen(sel.X).(*ast.CompositeLit)
		if !isComp {
			continue
		}
		ref, _, validRef := syntaxutil.TypeRefOfNamedStruct(p.TypesInfo.TypeOf(comp))
		if !validRef {
			return ProtoClusterFact{}, nil, nil, false
		}
		if buildIdx != -1 {
			return ProtoClusterFact{}, nil, nil, false
		}
		ov := syntaxutil.LookupIdentVar(p.TypesInfo, as.Lhs[0])
		if ov == nil || ov.Parent() == p.Types.Scope() {
			return ProtoClusterFact{}, nil, nil, false
		}
		buildIdx = i
		outVar = ov
		builderComp = comp
		builderRef = ref
	}
	if buildIdx == -1 || buildIdx+1 >= len(stmts) {
		return ProtoClusterFact{}, nil, nil, false
	}

	var goTypesVar, depIdxsVar, enumTypesVar, msgTypesVar, extTypesVar *types.Var
	var enumRef, msgRef, extRef syntaxutil.TypeRef
	allowedInitUses := map[*types.Var]map[*ast.Ident]bool{}
	allowUse := func(v *types.Var, id *ast.Ident) {
		if allowedInitUses[v] == nil {
			allowedInitUses[v] = map[*ast.Ident]bool{}
		}
		allowedInitUses[v][id] = true
	}

	for _, elt := range builderComp.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			return ProtoClusterFact{}, nil, nil, false
		}
		kID, isID := kv.Key.(*ast.Ident)
		if !isID {
			return ProtoClusterFact{}, nil, nil, false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "File":
			if !verifyDescBuilderSubLit(p, val) {
				return ProtoClusterFact{}, nil, nil, false
			}
		case "GoTypes":
			id, isVID := val.(*ast.Ident)
			v := syntaxutil.LookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || goTypesVar != nil || !syntaxutil.IsAnySliceType(v.Type()) {
				return ProtoClusterFact{}, nil, nil, false
			}
			goTypesVar = v
			allowUse(v, id)
		case "DependencyIndexes":
			v := syntaxutil.LookupPkgScopeVar(p, val)
			if v == nil || v.Exported() || depIdxsVar != nil || refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
				return ProtoClusterFact{}, nil, nil, false
			}
			depIdxsVar = v
		case "EnumInfos":
			id, isVID := val.(*ast.Ident)
			v := syntaxutil.LookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || enumTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := syntaxutil.SliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			enumTypesVar = v
			enumRef = ref
			allowUse(v, id)
		case "MessageInfos":
			id, isVID := val.(*ast.Ident)
			v := syntaxutil.LookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || msgTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := syntaxutil.SliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			msgTypesVar = v
			msgRef = ref
			allowUse(v, id)
		case "ExtensionInfos":
			v, id, okExt := syntaxutil.ExtractSliceVarOrSubslice(p, val)
			if !okExt || v.Exported() || extTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := syntaxutil.SliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			extTypesVar = v
			extRef = ref
			allowUse(v, id)
		default:
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	fileAssign, ok := stmts[buildIdx+1].(*ast.AssignStmt)
	if !ok || fileAssign.Tok != token.ASSIGN || len(fileAssign.Lhs) != 1 || len(fileAssign.Rhs) != 1 {
		return ProtoClusterFact{}, nil, nil, false
	}
	fileLHSID, isFLHS := ast.Unparen(fileAssign.Lhs[0]).(*ast.Ident)
	if !isFLHS || p.TypesInfo.Uses[fileLHSID] != fileVar {
		return ProtoClusterFact{}, nil, nil, false
	}
	outSel, isOutSel := ast.Unparen(fileAssign.Rhs[0]).(*ast.SelectorExpr)
	if !isOutSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, outSel.X, outVar) || outSel.Sel.Name != "File" {
		return ProtoClusterFact{}, nil, nil, false
	}
	allowUse(fileVar, guardBinIdent(p, guardBin, fileVar))
	allowUse(fileVar, fileLHSID)

	initExempt := map[ast.Node]bool{}

	for i := 1; i < buildIdx; i++ {
		st := stmts[i]
		switch s := st.(type) {
		case *ast.DeclStmt:
			if !isEmptyLocalStructTypeDecl(s) {
				return ProtoClusterFact{}, nil, nil, false
			}
		case *ast.ExprStmt:
			call, isCall := ast.Unparen(s.X).(*ast.CallExpr)
			if !isCall || len(call.Args) != 0 {
				return ProtoClusterFact{}, nil, nil, false
			}
			cid, isCID := ast.Unparen(call.Fun).(*ast.Ident)
			if !isCID {
				return ProtoClusterFact{}, nil, nil, false
			}
			callee, isFn := p.TypesInfo.Uses[cid].(*types.Func)
			if !isFn || callee.Pkg() != p.Types || callee.Exported() || !initOnly[callee.Name()] {
				return ProtoClusterFact{}, nil, nil, false
			}
		case *ast.AssignStmt:
			msgID, okWrap := verifyOneofWrappersAssign(p, s, msgTypesVar)
			if !okWrap {
				return ProtoClusterFact{}, nil, nil, false
			}
			allowUse(msgTypesVar, msgID)
			initExempt[s] = true
		case *ast.IfStmt:
			msgIDs, assignStmts, okExp := verifyLegacyExporterIfStmt(p, s, msgTypesVar)
			if !okExp {
				return ProtoClusterFact{}, nil, nil, false
			}
			for _, mid := range msgIDs {
				allowUse(msgTypesVar, mid)
			}
			for _, as := range assignStmts {
				initExempt[as] = true
			}
		default:
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	for i := buildIdx + 2; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !syntaxutil.IsNilIdent(p.TypesInfo, as.Rhs[0]) {
			return ProtoClusterFact{}, nil, nil, false
		}
		lhsID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		lhsVar := syntaxutil.LookupPkgScopeVar(p, as.Lhs[0])
		if !isID || lhsVar == nil || lhsVar.Exported() {
			return ProtoClusterFact{}, nil, nil, false
		}
		if lhsVar == goTypesVar {
			allowUse(goTypesVar, lhsID)
			continue
		}
		if lhsVar == depIdxsVar || !refconfine.TypeMayCarryUnknownDynamic(audited, lhsVar.Type()) {
			continue
		}
		return ProtoClusterFact{}, nil, nil, false
	}

	if !verifyProtoFileVarUses(p, idx, fileVar, allowedInitUses[fileVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if goTypesVar != nil && !verifyProtoGoTypesVar(p, idx, goTypesVar, allowedInitUses[goTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if enumTypesVar != nil && !verifyProtoInfoSliceVar(p, idx, fd, enumTypesVar, allowedInitUses[enumTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if msgTypesVar != nil && !verifyProtoInfoSliceVar(p, idx, fd, msgTypesVar, allowedInitUses[msgTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	var boundExtVars []*types.Var
	if extTypesVar != nil {
		var okExt bool
		boundExtVars, okExt = verifyProtoExtTypesAndVars(p, idx, fd, extTypesVar, allowedInitUses[extTypesVar])
		if !okExt {
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	var allVars []*types.Var
	var varKeys []string
	addClusterVar := func(v *types.Var) {
		if v == nil || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			return
		}
		allVars = append(allVars, v)
		varKeys = append(varKeys, syntaxutil.DynamicVarKey(v))
	}
	addClusterVar(fileVar)
	addClusterVar(goTypesVar)
	addClusterVar(enumTypesVar)
	addClusterVar(msgTypesVar)
	addClusterVar(extTypesVar)
	for _, ev := range boundExtVars {
		addClusterVar(ev)
	}
	if len(varKeys) == 0 {
		return ProtoClusterFact{}, nil, nil, false
	}
	sort.Strings(varKeys)

	return ProtoClusterFact{
		InitFn:      syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: fn.Name()},
		Vars:        varKeys,
		BuilderType: builderRef,
		EnumType:    enumRef,
		MsgType:     msgRef,
		ExtType:     extRef,
	}, allVars, initExempt, true
}

func guardBinIdent(p *packages.Package, bin *ast.BinaryExpr, want *types.Var) *ast.Ident {
	if id, ok := ast.Unparen(bin.X).(*ast.Ident); ok && p.TypesInfo.Uses[id] == want {
		return id
	}
	if id, ok := ast.Unparen(bin.Y).(*ast.Ident); ok && p.TypesInfo.Uses[id] == want {
		return id
	}
	return nil
}

func verifyDescBuilderSubLit(p *packages.Package, expr ast.Expr) bool {
	comp, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	clean := true
	ast.Inspect(comp, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			clean = false
			return false
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Parent() == p.Types.Scope() {
				if refconfine.TypeMayCarryUnknownDynamic(true, v.Type()) {
					clean = false
					return false
				}
			}
		}
		return true
	})
	return clean
}

func isEmptyLocalStructTypeDecl(ds *ast.DeclStmt) bool {
	gd, ok := ds.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.TYPE || len(gd.Specs) != 1 {
		return false
	}
	ts, ok := gd.Specs[0].(*ast.TypeSpec)
	if !ok {
		return false
	}
	st, ok := ts.Type.(*ast.StructType)
	return ok && (st.Fields == nil || len(st.Fields.List) == 0)
}

func verifyOneofWrappersAssign(p *packages.Package, as *ast.AssignStmt, msgTypesVar *types.Var) (*ast.Ident, bool) {
	if msgTypesVar == nil || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return nil, false
	}
	sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "OneofWrappers" {
		return nil, false
	}
	ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
	if !ok || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
		return nil, false
	}
	msgID, ok := ast.Unparen(ie.X).(*ast.Ident)
	if !ok || p.TypesInfo.Uses[msgID] != msgTypesVar {
		return nil, false
	}
	comp, ok := ast.Unparen(as.Rhs[0]).(*ast.CompositeLit)
	if !ok || !syntaxutil.IsAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return nil, false
	}
	for _, elt := range comp.Elts {
		if !syntaxutil.IsTypedNilStructPtrInPkg(p, elt, p.Types) {
			return nil, false
		}
	}
	return msgID, true
}

func verifyLegacyExporterIfStmt(p *packages.Package, ifs *ast.IfStmt, msgTypesVar *types.Var) ([]*ast.Ident, []*ast.AssignStmt, bool) {
	if msgTypesVar == nil || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) == 0 {
		return nil, nil, false
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
		return nil, nil, false
	}
	var ids []*ast.Ident
	var assigns []*ast.AssignStmt
	for _, st := range ifs.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return nil, nil, false
		}
		sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Exporter" {
			return nil, nil, false
		}
		ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
		if !ok || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
			return nil, nil, false
		}
		msgID, ok := ast.Unparen(ie.X).(*ast.Ident)
		if !ok || p.TypesInfo.Uses[msgID] != msgTypesVar {
			return nil, nil, false
		}
		lit, ok := ast.Unparen(as.Rhs[0]).(*ast.FuncLit)
		if !ok || !isPureLegacyExporterFuncLit(p, lit) {
			return nil, nil, false
		}
		ids = append(ids, msgID)
		assigns = append(assigns, as)
	}
	return ids, assigns, true
}

func isPureLegacyExporterFuncLit(p *packages.Package, lit *ast.FuncLit) bool {
	if lit.Body == nil {
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
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Parent() == p.Types.Scope() {
				clean = false
				return false
			}
		}
		return true
	})
	return clean
}

func verifyProtoFileVarUses(_ *packages.Package, idx *refconfine.PkgIndex, fileVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	for _, id := range idx.UsesOf[fileVar] {
		if allowedInit[id] {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(idx, id) {
			return false
		}
	}
	return true
}

func verifyProtoGoTypesVar(p *packages.Package, idx *refconfine.PkgIndex, goTypesVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	if idx.DefCounts[goTypesVar] != 1 {
		return false
	}
	vs := idx.VarSpecs[goTypesVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok || !syntaxutil.IsAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return false
	}
	for _, elt := range comp.Elts {
		if !isSafeGoTypesElement(p, elt) {
			return false
		}
	}
	for _, id := range idx.UsesOf[goTypesVar] {
		if !allowedInit[id] {
			return false
		}
	}
	return true
}

func isSafeGoTypesElement(p *packages.Package, expr ast.Expr) bool {
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

func verifyProtoInfoSliceVar(
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

func verifyProtoExtTypesAndVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	_ *ast.FuncDecl,
	extTypesVar *types.Var,
	allowedInit map[*ast.Ident]bool,
) ([]*types.Var, bool) {
	if idx.DefCounts[extTypesVar] != 1 {
		return nil, false
	}
	vs := idx.VarSpecs[extTypesVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return nil, false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	for _, elt := range comp.Elts {
		sub, isSub := ast.Unparen(elt).(*ast.CompositeLit)
		if !isSub || !verifyExtInfoLiteralElement(p, sub) {
			return nil, false
		}
	}

	var boundVars []*types.Var
	seenVars := map[*types.Var]bool{}
	for _, id := range idx.UsesOf[extTypesVar] {
		if allowedInit[id] {
			continue
		}
		if idx.EnclFunc[id] != nil || idx.InFuncLit[id] || idx.InGoStmt[id] {
			return nil, false
		}
		ie, ok := idx.ParentUnparen(id).(*ast.IndexExpr)
		if !ok || ast.Unparen(ie.X) != id || !syntaxutil.IsNonNegConstInt(p.TypesInfo, ie.Index) {
			return nil, false
		}
		un, ok := idx.ParentUnparen(ie).(*ast.UnaryExpr)
		if !ok || un.Op != token.AND {
			return nil, false
		}
		spec, ok := idx.ParentUnparen(un).(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 || ast.Unparen(spec.Values[0]) != un {
			return nil, false
		}
		ev, ok := p.TypesInfo.Defs[spec.Names[0]].(*types.Var)
		if !ok || ev == nil || ev.Parent() != p.Types.Scope() || idx.DefCounts[ev] != 1 {
			return nil, false
		}
		if !verifyReadOnlyPtrVarUses(p, idx, ev) {
			return nil, false
		}
		if !seenVars[ev] {
			seenVars[ev] = true
			boundVars = append(boundVars, ev)
		}
	}
	return boundVars, true
}

func verifyExtInfoLiteralElement(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "ExtendedType", "ExtensionType":
			if !isSafeExtTypeExpr(p, val) {
				return false
			}
		case "Field", "Name", "Tag", "Filename":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isSafeExtTypeExpr(p *packages.Package, expr ast.Expr) bool {
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
