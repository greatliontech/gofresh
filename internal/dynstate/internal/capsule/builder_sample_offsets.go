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

type lenAliasGuard struct {
	capField string
	endPos   token.Pos
}

type sampleOffsetAnalyzer struct {
	p                 *packages.Package
	idx               *refconfine.PkgIndex
	recvVar           *types.Var
	sampleSliceField  *types.Var
	fbOutVar          *types.Var
	fbOutSliceFields  map[*types.Var]bool
	capsuleSpecs      []syntaxutil.BuilderSliceSpec
	capsuleFieldByVar map[*types.Var]int
	sampleDerivedVars map[*types.Var]ast.Expr
	singleDefIntExpr  map[*types.Var]ast.Expr
	subSliceAliases   map[*types.Var]lenAliasGuard
}

func newSampleOffsetAnalyzer(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	buildFD *ast.FuncDecl,
	recvVar *types.Var,
	sampleSliceField *types.Var,
	fbOutVar *types.Var,
	fbOutSliceFields map[*types.Var]bool,
	capsuleSpecs []syntaxutil.BuilderSliceSpec,
	capsuleFieldByVar map[*types.Var]int,
) *sampleOffsetAnalyzer {
	a := &sampleOffsetAnalyzer{
		p:                 p,
		idx:               idx,
		recvVar:           recvVar,
		sampleSliceField:  sampleSliceField,
		fbOutVar:          fbOutVar,
		fbOutSliceFields:  fbOutSliceFields,
		capsuleSpecs:      capsuleSpecs,
		capsuleFieldByVar: capsuleFieldByVar,
		sampleDerivedVars: map[*types.Var]ast.Expr{},
		singleDefIntExpr:  map[*types.Var]ast.Expr{},
		subSliceAliases:   map[*types.Var]lenAliasGuard{},
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
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
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				return true
			}
		}
		if a.isSampleSliceExpr(as.Rhs[0]) {
			a.sampleDerivedVars[lv] = as.Rhs[0]
			return true
		}
		if b, isB := syntaxutil.UnderlyingType(lv.Type()).(*types.Basic); isB && b.Info()&types.IsInteger != 0 {
			a.singleDefIntExpr[lv] = as.Rhs[0]
		}
		return true
	})

	for _, stmt := range buildFD.Body.List {
		ifs, isIf := stmt.(*ast.IfStmt)
		if !isIf || ifs.Init != nil || ifs.Else != nil || ifs.Body == nil || len(ifs.Body.List) == 0 {
			continue
		}
		lastS, isES := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ExprStmt)
		if !isES {
			continue
		}
		pc, isPC := ast.Unparen(lastS.X).(*ast.CallExpr)
		if !isPC {
			continue
		}
		pid, isPID := ast.Unparen(pc.Fun).(*ast.Ident)
		if !isPID {
			continue
		}
		if pb, isB := p.TypesInfo.Uses[pid].(*types.Builtin); !isB || pb.Name() != "panic" {
			continue
		}
		bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.NEQ {
			continue
		}
		b1, f1, ok1 := a.extractLenField(bin.X)
		b2, f2, ok2 := a.extractLenField(bin.Y)
		if !ok1 || !ok2 {
			continue
		}
		if b1 == recvVar && b2 == fbOutVar && fbOutSliceFields[f2] {
			if specIdx, okCap := capsuleFieldByVar[f1]; okCap {
				a.subSliceAliases[f2] = lenAliasGuard{capField: capsuleSpecs[specIdx].Field, endPos: ifs.End()}
			}
		} else if b2 == recvVar && b1 == fbOutVar && fbOutSliceFields[f1] {
			if specIdx, okCap := capsuleFieldByVar[f2]; okCap {
				a.subSliceAliases[f1] = lenAliasGuard{capField: capsuleSpecs[specIdx].Field, endPos: ifs.End()}
			}
		}
	}
	return a
}

func (a *sampleOffsetAnalyzer) isSampleSliceExpr(expr ast.Expr) bool {
	if a.sampleSliceField == nil {
		return false
	}
	cur := ast.Unparen(expr)
	for {
		if se, isSE := cur.(*ast.SliceExpr); isSE {
			cur = ast.Unparen(se.X)
			continue
		}
		break
	}
	if sel, isSel := cur.(*ast.SelectorExpr); isSel && a.p.TypesInfo.Uses[sel.Sel] == a.sampleSliceField {
		if id, isID := ast.Unparen(sel.X).(*ast.Ident); isID && a.p.TypesInfo.Uses[id] == a.recvVar {
			return true
		}
	}
	if id, isID := cur.(*ast.Ident); isID {
		if v, _ := a.p.TypesInfo.Uses[id].(*types.Var); v != nil && a.sampleDerivedVars[v] != nil {
			return true
		}
	}
	return false
}

func (a *sampleOffsetAnalyzer) extractLenField(expr ast.Expr) (*types.Var, *types.Var, bool) {
	c, isC := ast.Unparen(expr).(*ast.CallExpr)
	if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
		return nil, nil, false
	}
	cid, isID := ast.Unparen(c.Fun).(*ast.Ident)
	if !isID {
		return nil, nil, false
	}
	b, isB := a.p.TypesInfo.Uses[cid].(*types.Builtin)
	if !isB || b.Name() != "len" {
		return nil, nil, false
	}
	sel, isSel := ast.Unparen(c.Args[0]).(*ast.SelectorExpr)
	if !isSel {
		return nil, nil, false
	}
	baseID, isBID := ast.Unparen(sel.X).(*ast.Ident)
	if !isBID {
		return nil, nil, false
	}
	baseVar, _ := a.p.TypesInfo.Uses[baseID].(*types.Var)
	fldVar, _ := a.p.TypesInfo.Uses[sel.Sel].(*types.Var)
	if baseVar == nil || fldVar == nil {
		return nil, nil, false
	}
	return baseVar, fldVar, true
}

func (a *sampleOffsetAnalyzer) parseOffsetExpr(expr ast.Expr, usePos token.Pos, depth int) (map[string]int, *types.Var, bool) {
	if depth > 8 {
		return nil, nil, false
	}
	if expr == nil {
		return map[string]int{}, nil, true
	}
	expr = ast.Unparen(expr)
	if tv := a.p.TypesInfo.Types[expr]; tv.Value != nil && tv.Value.Kind() == constant.Int {
		iv, okI := constant.Int64Val(tv.Value)
		if okI && iv == 0 {
			return map[string]int{}, nil, true
		}
		return nil, nil, false
	}
	if baseVar, fldVar, okLen := a.extractLenField(expr); okLen {
		if baseVar == a.recvVar {
			if specIdx, okCap := a.capsuleFieldByVar[fldVar]; okCap {
				return map[string]int{a.capsuleSpecs[specIdx].Field: 1}, nil, true
			}
		}
		if a.fbOutVar != nil && baseVar == a.fbOutVar {
			if al, okAl := a.subSliceAliases[fldVar]; okAl && al.endPos <= usePos {
				return map[string]int{al.capField: 1}, nil, true
			}
		}
		return nil, nil, false
	}
	if id, isID := expr.(*ast.Ident); isID {
		v, _ := a.p.TypesInfo.Uses[id].(*types.Var)
		if v == nil || v.IsField() || v.Parent() == a.p.Types.Scope() {
			return nil, nil, false
		}
		if rhs, hasDef := a.singleDefIntExpr[v]; hasDef && v.Pos() < usePos {
			if lens, iv, okDef := a.parseOffsetExpr(rhs, usePos, depth+1); okDef {
				return lens, iv, true
			}
		}
		return map[string]int{}, v, true
	}
	if bin, isBin := expr.(*ast.BinaryExpr); isBin && bin.Op == token.ADD {
		l1, v1, ok1 := a.parseOffsetExpr(bin.X, usePos, depth+1)
		l2, v2, ok2 := a.parseOffsetExpr(bin.Y, usePos, depth+1)
		if !ok1 || !ok2 || (v1 != nil && v2 != nil) {
			return nil, nil, false
		}
		merged := make(map[string]int, len(l1)+len(l2))
		for k, c := range l1 {
			merged[k] += c
		}
		for k, c := range l2 {
			merged[k] += c
		}
		iv := v1
		if iv == nil {
			iv = v2
		}
		return merged, iv, true
	}
	return nil, nil, false
}

func (a *sampleOffsetAnalyzer) verifyReflectTypeWrite(lhsIx *ast.IndexExpr, rhsTypeOf ast.Expr, usePos token.Pos) bool {
	if a.sampleSliceField == nil {
		return false
	}
	capSel, isCS := ast.Unparen(lhsIx.X).(*ast.SelectorExpr)
	if !isCS {
		return false
	}
	if rid, isRID := ast.Unparen(capSel.X).(*ast.Ident); !isRID || a.p.TypesInfo.Uses[rid] != a.recvVar {
		return false
	}
	capFieldVar, _ := a.p.TypesInfo.Uses[capSel.Sel].(*types.Var)
	specIdx, okSpec := a.capsuleFieldByVar[capFieldVar]
	if !okSpec || !a.capsuleSpecs[specIdx].TakesSample {
		return false
	}
	lhsLens, lhsIdxVar, okLHS := a.parseOffsetExpr(lhsIx.Index, usePos, 0)
	if !okLHS || len(lhsLens) != 0 {
		return false
	}
	tCall, isTC := ast.Unparen(rhsTypeOf).(*ast.CallExpr)
	if !isTC || len(tCall.Args) != 1 || tCall.Ellipsis.IsValid() {
		return false
	}
	sampleIx, isSI := ast.Unparen(tCall.Args[0]).(*ast.IndexExpr)
	if !isSI {
		return false
	}
	totalLens, rhsIdxVar, okRHS := a.parseOffsetExpr(sampleIx.Index, usePos, 0)
	if !okRHS || rhsIdxVar != lhsIdxVar {
		return false
	}
	cur := ast.Unparen(sampleIx.X)
	reachedBase := false
	for guard := 0; guard < 16; guard++ {
		if se, isSE := cur.(*ast.SliceExpr); isSE {
			if se.Slice3 {
				return false
			}
			lowLens, lowVar, okLow := a.parseOffsetExpr(se.Low, usePos, 0)
			if !okLow || lowVar != nil {
				return false
			}
			for k, c := range lowLens {
				totalLens[k] += c
			}
			cur = ast.Unparen(se.X)
			continue
		}
		if id, isID := cur.(*ast.Ident); isID {
			v, _ := a.p.TypesInfo.Uses[id].(*types.Var)
			if v != nil && a.sampleDerivedVars[v] != nil {
				cur = ast.Unparen(a.sampleDerivedVars[v])
				continue
			}
		}
		if sel, isSel := cur.(*ast.SelectorExpr); isSel && a.p.TypesInfo.Uses[sel.Sel] == a.sampleSliceField {
			if rid, isRID := ast.Unparen(sel.X).(*ast.Ident); isRID && a.p.TypesInfo.Uses[rid] == a.recvVar {
				reachedBase = true
			}
		}
		break
	}
	if !reachedBase {
		return false
	}
	wantLens := map[string]int{}
	for k := 0; k < specIdx; k++ {
		if a.capsuleSpecs[k].TakesSample {
			wantLens[a.capsuleSpecs[k].Field] = 1
		}
	}
	if len(totalLens) != len(wantLens) {
		return false
	}
	for k, want := range wantLens {
		if totalLens[k] != want {
			return false
		}
	}
	return true
}

func isSafeBuilderCapsuleAssignment(
	p *packages.Package,
	lhs, rhs ast.Expr,
	writePos token.Pos,
	capsuleElemStructs map[*types.Named]bool,
	checkDesc func(ast.Expr) bool,
	verifySampleReflectTypeWrite func(*ast.IndexExpr, ast.Expr, token.Pos) bool,
) (bool, string) {
	lhs = ast.Unparen(lhs)
	rhs = ast.Unparen(rhs)
	switch l := lhs.(type) {
	case *ast.SelectorExpr:
		selInfo := p.TypesInfo.Selections[l]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
			return false, "invalid_sample_builder_capsule_write"
		}
		fld, _ := selInfo.Obj().(*types.Var)
		if fld == nil || !fld.Exported() {
			return false, "invalid_sample_builder_capsule_write"
		}
		lhsIx, isIx := ast.Unparen(l.X).(*ast.IndexExpr)
		if !isIx {
			return false, "invalid_sample_builder_capsule_write"
		}
		if syntaxutil.IsReflectType(fld.Type()) {
			if !syntaxutil.IsReflectTypeOfCall(p, rhs) {
				return false, "invalid_sample_builder_reflect_type_rhs"
			}
			if !verifySampleReflectTypeWrite(lhsIx, rhs, writePos) {
				return false, "misaligned_sample_slice_offset"
			}
			return true, ""
		}
		if syntaxutil.ExprIsFuncLit(rhs) || !checkDesc(rhs) {
			return false, "invalid_sample_builder_capsule_write"
		}
		return true, ""
	case *ast.IndexExpr:
		comp, ok := rhs.(*ast.CompositeLit)
		if !ok {
			return false, "invalid_sample_builder_capsule_write"
		}
		st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(comp))
		if st == nil || !capsuleElemStructs[st] {
			return false, "invalid_sample_builder_capsule_write"
		}
		stUnderlying, okSt := st.Underlying().(*types.Struct)
		if !okSt || !syntaxutil.StructHasExportedReflectTypeField(stUnderlying) {
			// Whole-element composite-literal overwrites are allowed only on
			// TakesSample (make-allocated) capsule slices; non-sample slices may
			// bind pre-populated StaticLiteral globals whose exported guard fields
			// must never be zeroed by Build().
			return false, "invalid_sample_builder_capsule_write"
		}
		sawReflectTypeField := false
		for _, elt := range comp.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false, "invalid_sample_builder_capsule_write"
			}
			kID, isID := kv.Key.(*ast.Ident)
			if !isID {
				return false, "invalid_sample_builder_capsule_write"
			}
			fld, _ := p.TypesInfo.Uses[kID].(*types.Var)
			if fld == nil || !fld.Exported() {
				return false, "invalid_sample_builder_capsule_write"
			}
			if syntaxutil.IsReflectType(fld.Type()) {
				sawReflectTypeField = true
				if !syntaxutil.IsReflectTypeOfCall(p, kv.Value) {
					return false, "invalid_sample_builder_reflect_type_rhs"
				}
				if !verifySampleReflectTypeWrite(l, kv.Value, writePos) {
					return false, "misaligned_sample_slice_offset"
				}
			} else {
				if syntaxutil.ExprIsFuncLit(kv.Value) || !checkDesc(kv.Value) {
					return false, "invalid_sample_builder_capsule_write"
				}
			}
		}
		if !sawReflectTypeField {
			return false, "invalid_sample_builder_capsule_write"
		}
		return true, ""
	}
	return false, "invalid_sample_builder_capsule_write"
}

func builderHelperStructFieldsSafe(named *types.Named, allowResolverFields bool) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		case *types.Signature, *types.Chan, *types.Map, *types.Pointer, *types.TypeParam:
			ok = false
		case *types.Interface:
			if !allowResolverFields {
				ok = false
			}
		case *types.Slice:
			if syntaxutil.IsAnySliceType(t) {
				if !allowResolverFields {
					ok = false
				}
				return
			}
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(named)
	return ok
}

func isDeterministicImmutableBuilderGlobal(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	if idx.DefCounts[v] != 1 {
		return false
	}
	for _, uid := range idx.UsesOf[v] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.ParentUnparen(uid)
		if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid {
			if refconfine.IdentOrExprIsWritten(idx, ix) {
				return false
			}
			continue
		}
		if !refconfine.TypeContainsRefOrPointer(v.Type()) {
			continue
		}
		return false
	}
	if !refconfine.TypeContainsRefOrPointer(v.Type()) {
		return true
	}
	mp, isMap := types.Unalias(v.Type()).Underlying().(*types.Map)
	if !isMap || refconfine.TypeContainsRefOrPointer(mp.Key()) || !syntaxutil.IsReflectType(mp.Elem()) {
		return false
	}
	vs := idx.VarSpecs[v]
	if vs == nil {
		return false
	}
	valIdx := -1
	for i, nm := range vs.Names {
		if p.TypesInfo.Defs[nm] == v {
			valIdx = i
			break
		}
	}
	if valIdx < 0 || valIdx >= len(vs.Values) {
		return false
	}
	cl, isCL := ast.Unparen(vs.Values[valIdx]).(*ast.CompositeLit)
	if !isCL {
		return false
	}
	for _, elt := range cl.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV || p.TypesInfo.Types[kv.Key].Value == nil || !syntaxutil.IsReflectTypeOfCall(p, kv.Value) {
			return false
		}
		rc := ast.Unparen(kv.Value).(*ast.CallExpr)
		if len(rc.Args) != 1 || !isSafeStaticCapsuleFieldExpr(p, rc.Args[0]) {
			return false
		}
	}
	return true
}
