package capsule

import (
	"context"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func deriveInitSettledClusters(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initOnly map[string]bool,
	exempted map[ast.Node]bool,
) ([]syntaxutil.InitSettledClusterFact, map[*types.Var]bool, map[*types.Var][]*types.Named) {
	var clusters []syntaxutil.InitSettledClusterFact
	claimedVars := map[*types.Var]bool{}
	clusterCapsuleElemTypes := map[*types.Var][]*types.Named{}

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
		cluster, clusterVars, initExempt, ok := verifyInitSettledClusterFunc(ctx, audited, p, idx, fn, fd, initOnly)
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
		extractClusterCapsuleElemTypes(p, idx, fd, clusterCapsuleElemTypes)
		clusters = append(clusters, cluster)
	}
	slices.SortFunc(clusters, syntaxutil.InitSettledClusterFact.Compare)
	return clusters, claimedVars, clusterCapsuleElemTypes
}

func extractClusterCapsuleElemTypes(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	out map[*types.Var][]*types.Named,
) {
	if p == nil || p.TypesInfo == nil || idx == nil || fd == nil || fd.Body == nil {
		return
	}
	var builderComp *ast.CompositeLit
	for _, st := range fd.Body.List {
		as, isAs := st.(*ast.AssignStmt)
		if !isAs || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		call, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			continue
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil || !sel.Sel.IsExported() {
			continue
		}
		if comp, isComp := ast.Unparen(sel.X).(*ast.CompositeLit); isComp {
			builderComp = comp
			break
		}
	}
	if builderComp == nil {
		return
	}
	builderNamed := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(builderComp))
	if builderNamed == nil {
		return
	}
	builderSt, okSt := builderNamed.Underlying().(*types.Struct)
	if !okSt {
		return
	}

	var sampleSliceFieldName string
	for i := 0; i < builderSt.NumFields(); i++ {
		f := builderSt.Field(i)
		if f.Exported() && syntaxutil.IsAnySliceType(f.Type()) {
			if sampleSliceFieldName != "" {
				return
			}
			sampleSliceFieldName = f.Name()
		}
	}
	if sampleSliceFieldName == "" {
		return
	}

	fieldVars := map[string]*types.Var{}
	for _, elt := range builderComp.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			continue
		}
		kid, isID := kv.Key.(*ast.Ident)
		if !isID {
			continue
		}
		fieldVars[kid.Name] = syntaxutil.LookupPkgScopeVar(p, kv.Value)
	}
	sampleVar := fieldVars[sampleSliceFieldName]
	if sampleVar == nil {
		return
	}
	gvs := idx.VarSpecs[sampleVar]
	if gvs == nil || len(gvs.Values) != 1 {
		return
	}
	gcomp, isGC := ast.Unparen(gvs.Values[0]).(*ast.CompositeLit)
	if !isGC {
		return
	}

	fixedMakeLen := func(v *types.Var) (int, bool) {
		if v == nil {
			return 0, true
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Values) != 1 {
			return 0, false
		}
		c, isC := ast.Unparen(vs.Values[0]).(*ast.CallExpr)
		if !isC || len(c.Args) != 2 {
			return 0, false
		}
		tv := p.TypesInfo.Types[c.Args[1]]
		if tv.Value == nil || tv.Value.Kind() != constant.Int {
			return 0, false
		}
		n, okN := constant.Int64Val(tv.Value)
		if !okN || n < 0 {
			return 0, false
		}
		return int(n), true
	}

	offset := 0
	seenMakeSliceVars := map[*types.Var]bool{}
	for i := 0; i < builderSt.NumFields(); i++ {
		f := builderSt.Field(i)
		if !f.Exported() {
			continue
		}
		_, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type())
		if !okElem {
			continue
		}
		elemSt, okES := elemNamed.Underlying().(*types.Struct)
		if !okES || !syntaxutil.StructHasExportedReflectTypeField(elemSt) {
			continue
		}
		sliceVar := fieldVars[f.Name()]
		if sliceVar != nil {
			if seenMakeSliceVars[sliceVar] {
				for k := range seenMakeSliceVars {
					delete(out, k)
				}
				return
			}
			seenMakeSliceVars[sliceVar] = true
		}
		n, okLen := fixedMakeLen(sliceVar)
		if !okLen || offset+n > len(gcomp.Elts) {
			return
		}
		if sliceVar != nil && n > 0 {
			res := make([]*types.Named, n)
			for k := 0; k < n; k++ {
				elt := ast.Unparen(gcomp.Elts[offset+k])
				c, isC := elt.(*ast.CallExpr)
				if !isC || len(c.Args) != 1 || !syntaxutil.IsNilIdent(p.TypesInfo, c.Args[0]) {
					continue
				}
				tv := p.TypesInfo.Types[ast.Unparen(c.Fun)]
				if !tv.IsType() || tv.Type == nil {
					continue
				}
				ptr, isP := types.Unalias(tv.Type).(*types.Pointer)
				if !isP {
					continue
				}
				if named, isN := types.Unalias(ptr.Elem()).(*types.Named); isN && named.Obj() != nil && named.Obj().Pkg() == p.Types {
					res[k] = named
				}
			}
			out[sliceVar] = res
		}
		offset += n
	}
}

func verifyInitSettledClusterFunc(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fn *types.Func,
	fd *ast.FuncDecl,
	initOnly map[string]bool,
) (syntaxutil.InitSettledClusterFact, []*types.Var, map[ast.Node]bool, bool) {
	stmts := fd.Body.List
	if len(stmts) < 3 {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	guardIf, ok := stmts[0].(*ast.IfStmt)
	if !ok || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	if ret, isRet := guardIf.Body.List[0].(*ast.ReturnStmt); !isRet || len(ret.Results) != 0 {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	guardBin, ok := ast.Unparen(guardIf.Cond).(*ast.BinaryExpr)
	if !ok || guardBin.Op != token.NEQ {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	var guardVar *types.Var
	if syntaxutil.IsNilIdent(p.TypesInfo, guardBin.Y) {
		guardVar = syntaxutil.LookupPkgScopeVar(p, guardBin.X)
	} else if syntaxutil.IsNilIdent(p.TypesInfo, guardBin.X) {
		guardVar = syntaxutil.LookupPkgScopeVar(p, guardBin.Y)
	}
	if guardVar == nil || idx.DefCounts[guardVar] != 1 || !types.IsInterface(guardVar.Type()) {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	if fvs := idx.VarSpecs[guardVar]; fvs == nil || len(fvs.Values) != 0 {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	buildIdx := -1
	var outVar *types.Var
	var builderComp *ast.CompositeLit
	var builderRef syntaxutil.TypeRef
	var builderSt *types.Struct
	var buildMethodName string
	for i := 1; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		call, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 || call.Ellipsis.IsValid() {
			continue
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil || !syntaxutil.ValidExportedIdent(sel.Sel.Name) {
			continue
		}
		comp, isComp := ast.Unparen(sel.X).(*ast.CompositeLit)
		if !isComp {
			continue
		}
		ref, bNamed, validRef := syntaxutil.TypeRefOfNamedStruct(p.TypesInfo.TypeOf(comp))
		if !validRef || bNamed == nil {
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		bSt, okBSt := bNamed.Underlying().(*types.Struct)
		if !okBSt {
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		if buildIdx != -1 {
			emitCapsuleReject(ctx, p, fn.Name(), "multiple_cluster_builder_calls", as)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		ov := syntaxutil.LookupIdentVar(p.TypesInfo, as.Lhs[0])
		if ov == nil || ov.Parent() == p.Types.Scope() {
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		buildIdx = i
		outVar = ov
		builderComp = comp
		builderRef = ref
		builderSt = bSt
		buildMethodName = sel.Sel.Name
	}
	if buildIdx == -1 || buildIdx+1 >= len(stmts) {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	builderFields := map[string]*types.Var{}
	for i := 0; i < builderSt.NumFields(); i++ {
		f := builderSt.Field(i)
		if f.Exported() {
			builderFields[f.Name()] = f
		}
	}

	var sampleSliceVar *types.Var
	nonDynamicBuilderVars := map[*types.Var]bool{}
	makeSliceVars := map[*types.Var]*types.Struct{}
	seenSliceVars := map[*types.Var]bool{}
	type sliceVarEntry struct {
		fieldName string
		v         *types.Var
		elemRef   syntaxutil.TypeRef
		elemSt    *types.Struct
		isStatic  bool
	}
	var sliceEntries []sliceVarEntry
	seenBuilderKeys := map[string]bool{}
	allowedInitUses := map[*types.Var]map[*ast.Ident]bool{}
	allowUse := func(v *types.Var, id *ast.Ident) {
		if v == nil || id == nil {
			return
		}
		if allowedInitUses[v] == nil {
			allowedInitUses[v] = map[*ast.Ident]bool{}
		}
		allowedInitUses[v][id] = true
	}

	for _, elt := range builderComp.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			emitCapsuleReject(ctx, p, fn.Name(), "unkeyed_cluster_builder_field", elt)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		kID, isID := kv.Key.(*ast.Ident)
		if !isID || seenBuilderKeys[kID.Name] {
			emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_builder_field_key", kv)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		seenBuilderKeys[kID.Name] = true
		bf := builderFields[kID.Name]
		if bf == nil {
			emitCapsuleReject(ctx, p, fn.Name(), "unknown_cluster_builder_field", kv)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		val := ast.Unparen(kv.Value)

		if syntaxutil.IsAnySliceType(bf.Type()) {
			id, isVID := val.(*ast.Ident)
			v := syntaxutil.LookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || sampleSliceVar != nil || !syntaxutil.IsAnySliceType(v.Type()) {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_sample_slice_var", kv)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			sampleSliceVar = v
			allowUse(v, id)
			continue
		}

		if _, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(bf.Type()); okElem {
			elemSt, okESt := elemNamed.Underlying().(*types.Struct)
			if !okESt {
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			v, id, okSlice := syntaxutil.ExtractSliceVarOrSubslice(p, val)
			if !okSlice || v == nil || v.Exported() {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_capsule_slice_var", kv)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			if seenSliceVars[v] {
				emitCapsuleReject(ctx, p, fn.Name(), "duplicate_cluster_capsule_slice_var", kv)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			seenSliceVars[v] = true
			elemRef, okRef := syntaxutil.SliceElemStructRef(v.Type())
			if !okRef {
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			vs := idx.VarSpecs[v]
			if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_capsule_slice_decl", kv)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			isMake := syntaxutil.IsMakeFixedSliceCall(p, vs.Values[0])
			if isMake {
				if _, isDirectID := val.(*ast.Ident); !isDirectID {
					emitCapsuleReject(ctx, p, fn.Name(), "subslice_on_make_capsule_slice", kv)
					return syntaxutil.InitSettledClusterFact{}, nil, nil, false
				}
				makeSliceVars[v] = elemSt
			}
			allowUse(v, id)
			sliceEntries = append(sliceEntries, sliceVarEntry{
				fieldName: kID.Name,
				v:         v,
				elemRef:   elemRef,
				elemSt:    elemSt,
				isStatic:  !isMake,
			})
			continue
		}

		if _, isSubSt := syntaxutil.UnderlyingType(bf.Type()).(*types.Struct); isSubSt {
			if !verifySubBuilderLit(p, idx, val) {
				emitCapsuleReject(ctx, p, fn.Name(), "impure_cluster_sub_builder_lit", kv)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			continue
		}

		v := syntaxutil.LookupPkgScopeVar(p, val)
		if v != nil && !v.Exported() && !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			nonDynamicBuilderVars[v] = true
			continue
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, bf.Type()) && verifySubBuilderScalarOrSliceExpr(p, idx, val) {
			continue
		}
		emitCapsuleReject(ctx, p, fn.Name(), "unsupported_cluster_builder_field", kv)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	guardAssign, ok := stmts[buildIdx+1].(*ast.AssignStmt)
	if !ok || guardAssign.Tok != token.ASSIGN || len(guardAssign.Lhs) != 1 || len(guardAssign.Rhs) != 1 {
		emitCapsuleReject(ctx, p, fn.Name(), "missing_cluster_guard_assign", stmts[buildIdx+1])
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	guardLHSID, isGLHS := ast.Unparen(guardAssign.Lhs[0]).(*ast.Ident)
	if !isGLHS || p.TypesInfo.Uses[guardLHSID] != guardVar {
		emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_guard_lhs", guardAssign)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	outSel, isOutSel := ast.Unparen(guardAssign.Rhs[0]).(*ast.SelectorExpr)
	if !isOutSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, outSel.X, outVar) || outSel.Sel == nil || !syntaxutil.ValidExportedIdent(outSel.Sel.Name) {
		emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_guard_rhs", guardAssign)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	outIfaceFieldName := outSel.Sel.Name
	allowUse(guardVar, guardBinIdent(p, guardBin, guardVar))
	allowUse(guardVar, guardLHSID)

	initExempt := map[ast.Node]bool{}
	for i := 1; i < buildIdx; i++ {
		st := stmts[i]
		switch s := st.(type) {
		case *ast.DeclStmt:
			if !isEmptyLocalStructTypeDecl(s) {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_pre_build_decl", s)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
		case *ast.ExprStmt:
			call, isCall := ast.Unparen(s.X).(*ast.CallExpr)
			if !isCall || len(call.Args) != 0 {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_pre_build_call", s)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			cid, isCID := ast.Unparen(call.Fun).(*ast.Ident)
			if !isCID {
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			callee, isFn := p.TypesInfo.Uses[cid].(*types.Func)
			if !isFn || callee.Pkg() != p.Types || callee.Exported() || !initOnly[callee.Name()] {
				emitCapsuleReject(ctx, p, fn.Name(), "non_init_only_cluster_pre_build_call", s)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
		case *ast.AssignStmt:
			sv, sid, okWrap := verifyTypedNilAnySliceElemAssign(p, s, makeSliceVars)
			if !okWrap {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_pre_build_assign", s)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			allowUse(sv, sid)
			initExempt[s] = true
		case *ast.IfStmt:
			svs, sids, assignStmts, okProj := verifyPreBuildProjectionClosureIfStmt(p, s, makeSliceVars)
			if !okProj {
				emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_pre_build_if", s)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			for j := range svs {
				allowUse(svs[j], sids[j])
			}
			for _, as := range assignStmts {
				initExempt[as] = true
			}
		default:
			emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_pre_build_stmt", s)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
	}

	for i := buildIdx + 2; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !syntaxutil.IsNilIdent(p.TypesInfo, as.Rhs[0]) {
			emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_post_build_stmt", stmts[i])
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		lhsID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		lhsVar := syntaxutil.LookupPkgScopeVar(p, as.Lhs[0])
		if !isID || lhsVar == nil || lhsVar.Exported() {
			emitCapsuleReject(ctx, p, fn.Name(), "invalid_cluster_post_build_nil_clear", as)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		if lhsVar == sampleSliceVar {
			allowUse(sampleSliceVar, lhsID)
			continue
		}
		if nonDynamicBuilderVars[lhsVar] || !refconfine.TypeMayCarryUnknownDynamic(audited, lhsVar.Type()) {
			continue
		}
		emitCapsuleReject(ctx, p, fn.Name(), "illegal_cluster_post_build_var_write", as)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	if !verifyClusterGuardVarUses(p, idx, guardVar, allowedInitUses[guardVar]) {
		emitCapsuleReject(ctx, p, fn.Name(), "mutated_or_addressed_cluster_guard_var", nil)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	if sampleSliceVar != nil && !verifyClusterTypeSampleSliceVar(p, idx, sampleSliceVar, allowedInitUses[sampleSliceVar]) {
		emitCapsuleReject(ctx, p, fn.Name(), "unsafe_cluster_sample_slice_var", nil)
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}

	var sliceBindings []syntaxutil.ClusterCapsuleSliceBinding
	var boundStaticPtrVars []*types.Var
	for _, se := range sliceEntries {
		if !se.isStatic {
			if !verifyClusterMakeSliceVar(p, idx, fd, se.v, allowedInitUses[se.v]) {
				emitCapsuleReject(ctx, p, fn.Name(), "unsafe_cluster_make_slice_var", nil)
				return syntaxutil.InitSettledClusterFact{}, nil, nil, false
			}
			sliceBindings = append(sliceBindings, syntaxutil.ClusterCapsuleSliceBinding{
				Field:       se.fieldName,
				CapsuleType: se.elemRef,
			})
			continue
		}
		bvars, nonNilNames, okStatic := verifyClusterStaticSliceAndBoundVars(p, idx, se.v, se.elemSt, allowedInitUses[se.v])
		if !okStatic {
			emitCapsuleReject(ctx, p, fn.Name(), "unsafe_cluster_static_slice_var", nil)
			return syntaxutil.InitSettledClusterFact{}, nil, nil, false
		}
		boundStaticPtrVars = append(boundStaticPtrVars, bvars...)
		sliceBindings = append(sliceBindings, syntaxutil.ClusterCapsuleSliceBinding{
			Field:               se.fieldName,
			CapsuleType:         se.elemRef,
			StaticLiteral:       true,
			NonNilExportedNames: nonNilNames,
		})
	}
	slices.SortFunc(sliceBindings, syntaxutil.ClusterCapsuleSliceBinding.Compare)

	var allVars []*types.Var
	var varKeys []string
	addClusterVar := func(v *types.Var) {
		if v == nil || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			return
		}
		allVars = append(allVars, v)
		varKeys = append(varKeys, syntaxutil.DynamicVarKey(v))
	}
	addClusterVar(guardVar)
	addClusterVar(sampleSliceVar)
	for _, se := range sliceEntries {
		addClusterVar(se.v)
	}
	for _, ev := range boundStaticPtrVars {
		addClusterVar(ev)
	}
	if len(varKeys) == 0 {
		return syntaxutil.InitSettledClusterFact{}, nil, nil, false
	}
	sort.Strings(varKeys)

	return syntaxutil.InitSettledClusterFact{
		InitFn:        syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: fn.Name()},
		Vars:          varKeys,
		BuilderType:   builderRef,
		BuildMethod:   buildMethodName,
		OutIfaceField: outIfaceFieldName,
		SliceBindings: sliceBindings,
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

func verifySubBuilderLit(p *packages.Package, idx *refconfine.PkgIndex, expr ast.Expr) bool {
	comp, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	return verifySubBuilderScalarOrSliceExpr(p, idx, comp)
}

func verifySubBuilderScalarOrSliceExpr(p *packages.Package, idx *refconfine.PkgIndex, expr ast.Expr) bool {
	allowedInner := map[*ast.CallExpr]bool{}
	clean := true
	ast.Inspect(expr, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			clean = false
			return false
		case *ast.CallExpr:
			if allowedInner[x] {
				return true
			}
			if !isPureSubBuilderCallExpr(p, idx, x, allowedInner) {
				clean = false
				return false
			}
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

func isPureSubBuilderCallExpr(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	call *ast.CallExpr,
	allowedInner map[*ast.CallExpr]bool,
) bool {
	if call == nil || call.Ellipsis.IsValid() || p == nil || p.TypesInfo == nil {
		return false
	}
	if tv := p.TypesInfo.Types[call.Fun]; tv.IsType() {
		return len(call.Args) == 1 && tv.Type != nil && !refconfine.TypeMayCarryUnknownDynamic(true, tv.Type)
	}
	fun := syntaxutil.UnwrapCallee(call.Fun)
	var obj types.Object
	switch f := fun.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[f]
	case *ast.SelectorExpr:
		if sel, ok := p.TypesInfo.Selections[f]; ok {
			obj = sel.Obj()
		} else {
			obj = p.TypesInfo.Uses[f.Sel]
		}
	}
	switch callee := obj.(type) {
	case *types.Builtin:
		switch callee.Name() {
		case "len", "cap":
			return len(call.Args) == 1
		case "Slice":
			if len(call.Args) != 2 {
				return false
			}
			sl, okSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call)).(*types.Slice)
			if !okSl {
				return false
			}
			basicElem, okBasic := syntaxutil.UnderlyingType(sl.Elem()).(*types.Basic)
			if !okBasic || basicElem.Kind() != types.Byte {
				return false
			}
			inner, okInner := ast.Unparen(call.Args[0]).(*ast.CallExpr)
			if !okInner || inner.Ellipsis.IsValid() || len(inner.Args) != 1 {
				return false
			}
			innerFun := syntaxutil.UnwrapCallee(inner.Fun)
			var innerObj types.Object
			switch f := innerFun.(type) {
			case *ast.Ident:
				innerObj = p.TypesInfo.Uses[f]
			case *ast.SelectorExpr:
				innerObj = p.TypesInfo.Uses[f.Sel]
			}
			bInner, okB := innerObj.(*types.Builtin)
			if !okB || bInner.Name() != "StringData" {
				return false
			}
			sv, strLen, okStr := immutableClusterStringLen(p, idx, inner.Args[0])
			if !okStr || !isBoundedClusterSliceLenExpr(p, idx, call.Args[1], sv, strLen) {
				return false
			}
			allowedInner[inner] = true
			return true
		}
	case *types.Func:
		if callee.Pkg() == nil || callee.Pkg().Path() != "reflect" {
			return false
		}
		sig, okSig := callee.Type().(*types.Signature)
		if !okSig {
			return false
		}
		if sig.Recv() == nil {
			return (callee.Name() == "TypeOf" && len(call.Args) == 1) ||
				(callee.Name() == "TypeFor" && len(call.Args) == 0)
		}
		if !syntaxutil.IsReflectType(sig.Recv().Type()) {
			return false
		}
		switch callee.Name() {
		case "PkgPath", "Name", "String", "Kind", "Size", "Align", "Comparable":
			return len(call.Args) == 0
		}
	}
	return false
}

func immutableClusterStringLen(p *packages.Package, idx *refconfine.PkgIndex, expr ast.Expr) (*types.Var, int64, bool) {
	expr = ast.Unparen(expr)
	basic, okBasic := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(expr)).(*types.Basic)
	if !okBasic || (basic.Info()&types.IsString) == 0 {
		return nil, 0, false
	}
	if tv := p.TypesInfo.Types[expr]; tv.Value != nil && tv.Value.Kind() == constant.String {
		return nil, int64(len(constant.StringVal(tv.Value))), true
	}
	if idx == nil {
		return nil, 0, false
	}
	sv := syntaxutil.LookupPkgScopeVar(p, expr)
	if sv == nil || sv.Exported() || idx.DefCounts[sv] != 1 {
		return nil, 0, false
	}
	vs := idx.VarSpecs[sv]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return nil, 0, false
	}
	initTV := p.TypesInfo.Types[vs.Values[0]]
	if initTV.Value == nil || initTV.Value.Kind() != constant.String {
		return nil, 0, false
	}
	for _, u := range idx.UsesOf[sv] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, u) {
			return nil, 0, false
		}
	}
	return sv, int64(len(constant.StringVal(initTV.Value))), true
}

func isBoundedClusterSliceLenExpr(p *packages.Package, idx *refconfine.PkgIndex, lenExpr ast.Expr, sv *types.Var, strLen int64) bool {
	lenExpr = ast.Unparen(lenExpr)
	if tv := p.TypesInfo.Types[lenExpr]; tv.Value != nil && tv.Value.Kind() == constant.Int {
		n, exact := constant.Int64Val(tv.Value)
		return exact && n >= 0 && n <= strLen
	}
	if sv != nil {
		if call, isC := lenExpr.(*ast.CallExpr); isC && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
			if id, isID := syntaxutil.UnwrapCallee(call.Fun).(*ast.Ident); isID {
				if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "len" {
					return syntaxutil.LookupPkgScopeVar(p, call.Args[0]) == sv
				}
			}
		}
	}
	return false
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

