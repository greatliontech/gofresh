package capsule

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifySampleCapsuleBuilderType(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ownerRef syntaxutil.TypeRef,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
) (syntaxutil.InitBuilderFact, map[ast.Node]bool, map[*ast.Ident]bool, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}

	var sampleSliceField *types.Var
	var capsuleSpecs []syntaxutil.BuilderSliceSpec
	capsuleFieldByVar := map[*types.Var]int{}
	capsuleElemStructs := map[*types.Named]bool{}
	builderExportedStructFields := map[*types.Var]*types.Named{}
	hasTakesSample := false

	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			continue
		}
		if syntaxutil.IsAnySliceType(f.Type()) {
			if sampleSliceField != nil {
				return syntaxutil.InitBuilderFact{}, nil, nil, false
			}
			sampleSliceField = f
			continue
		}
		if elemRef, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type()); okElem {
			elemSt, okSt := elemNamed.Underlying().(*types.Struct)
			if !okSt || !elemRef.Valid() {
				return syntaxutil.InitBuilderFact{}, nil, nil, false
			}
			takesSample := syntaxutil.StructHasExportedReflectTypeField(elemSt)
			if takesSample {
				hasTakesSample = true
			}
			capsuleFieldByVar[f] = len(capsuleSpecs)
			capsuleSpecs = append(capsuleSpecs, syntaxutil.BuilderSliceSpec{
				Field:       f.Name(),
				ElemType:    elemRef,
				TakesSample: takesSample,
			})
			capsuleElemStructs[elemNamed] = true
			continue
		}
		if fnamed, isN := types.Unalias(f.Type()).(*types.Named); isN {
			if _, isSt := fnamed.Underlying().(*types.Struct); isSt {
				builderExportedStructFields[f] = fnamed
			}
		}
	}

	if len(capsuleSpecs) == 0 || (hasTakesSample && sampleSliceField == nil) || named.NumMethods() != 1 {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	buildFn := named.Method(0)
	if !buildFn.Exported() || buildFn.Pkg() != p.Types {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 || sig.Recv() == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	outIfaceField := syntaxutil.SoleExportedNonEmptyIfaceField(outSt)
	if outIfaceField == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	buildFD := idx.FuncDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	if hasTakesSample && freshstruct.FuncBodyHasGoto(buildFD.Body) {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "sample_builder_body_has_goto", buildFD)
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}
	recvVar := sig.Recv()
	outIfaceName := outIfaceField.Name()
	var namedResultOutVar *types.Var
	if sig.Results().At(0).Name() != "" {
		namedResultOutVar = sig.Results().At(0)
	}

	var subBuilderFieldName string
	var subBuilderRef syntaxutil.TypeRef
	var fbOutVar *types.Var
	var fbOutIfaceField *types.Var
	fbOutSliceFields := map[*types.Var]bool{}
	subCallBad := false
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if subCallBad || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 || call.Ellipsis.IsValid() {
			return true
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil || !sel.Sel.IsExported() {
			return true
		}
		subSel, isSubSel := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !isSubSel {
			return true
		}
		rid, isID := ast.Unparen(subSel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[rid] != recvVar {
			return true
		}
		subFieldObj, _ := p.TypesInfo.Uses[subSel.Sel].(*types.Var)
		subNamed := builderExportedStructFields[subFieldObj]
		if subNamed == nil || subNamed.Obj() == nil || subNamed.Obj().Pkg() == nil {
			return true
		}
		subCallee, okSC := p.TypesInfo.Uses[sel.Sel].(*types.Func)
		if !okSC || subCallee == nil || !subCallee.Exported() {
			subCallBad = true
			return false
		}
		subSig, okSS := subCallee.Type().(*types.Signature)
		if !okSS || subSig.Params().Len() != 0 || subSig.Results().Len() != 1 {
			subCallBad = true
			return false
		}
		ref := syntaxutil.TypeRef{Pkg: subNamed.Obj().Pkg().Path(), Name: subNamed.Obj().Name()}
		if !ref.Valid() || fbOutVar != nil {
			subCallBad = true
			return false
		}
		as, isAs := idx.ParentUnparen(call).(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			subCallBad = true
			return false
		}
		lid, isLID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isLID {
			subCallBad = true
			return false
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.DefCounts[lv] != 1 {
			subCallBad = true
			return false
		}
		fbSt, isSt := types.Unalias(lv.Type()).Underlying().(*types.Struct)
		if !isSt {
			subCallBad = true
			return false
		}
		fbIf := syntaxutil.SoleExportedNonEmptyIfaceField(fbSt)
		if fbIf == nil {
			subCallBad = true
			return false
		}
		for i := 0; i < fbSt.NumFields(); i++ {
			ff := fbSt.Field(i)
			if ff.Exported() {
				if _, _, okElem := syntaxutil.SliceElemNamedStruct(ff.Type()); okElem {
					fbOutSliceFields[ff] = true
				}
			}
		}
		if len(fbOutSliceFields) == 0 {
			subCallBad = true
			return false
		}
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				subCallBad = true
				return false
			}
		}
		subBuilderFieldName = subFieldObj.Name()
		subBuilderRef = ref
		fbOutVar = lv
		fbOutIfaceField = fbIf
		return true
	})
	if subCallBad {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_sub_builder_invocation", buildFD)
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}

	isSubBuilderSliceElemAddr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		ix, isIx := ast.Unparen(un.X).(*ast.IndexExpr)
		if !isIx {
			return false
		}
		sel, isSel := ast.Unparen(ix.X).(*ast.SelectorExpr)
		if !isSel {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != fbOutVar {
			return false
		}
		fObj, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		return fbOutSliceFields[fObj]
	}

	isSubBuilderOutIfaceExpr := func(expr ast.Expr) bool {
		if fbOutVar == nil || fbOutIfaceField == nil {
			return false
		}
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel || p.TypesInfo.Uses[sel.Sel] != fbOutIfaceField {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		return isID && p.TypesInfo.Uses[id] == fbOutVar
	}

	directDescStructs := map[*types.Named]bool{}
	isVerifiedDirectDescAlloc := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL {
			return false
		}
		stNamed := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl))
		if stNamed == nil || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || stNamed.Obj().Exported() || stNamed.TypeParams().Len() > 0 {
			return false
		}
		for _, elt := range cl.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
			}
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if !refconfine.TypeContainsRefOrPointer(vt) || syntaxutil.IsByteSliceType(vt) {
				continue
			}
			return false
		}
		directDescStructs[stNamed] = true
		return true
	}

	checkDescValue := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
			return false
		}
		if fbOutVar != nil {
			return isSubBuilderSliceElemAddr(expr)
		}
		vt := p.TypesInfo.TypeOf(expr)
		if vt != nil && vt != types.Typ[types.UntypedNil] && !refconfine.TypeContainsRefOrPointer(vt) {
			return true
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	checkOutIfaceValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderOutIfaceExpr(expr)
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	offsetAnalyzer := newSampleOffsetAnalyzer(p, idx, buildFD, recvVar, sampleSliceField, fbOutVar, fbOutSliceFields, capsuleSpecs, capsuleFieldByVar)
	isSampleSliceExpr := offsetAnalyzer.isSampleSliceExpr
	verifySampleReflectTypeWrite := offsetAnalyzer.verifyReflectTypeWrite
	isNilDefaultRecvIfaceAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != sel {
			return false
		}
		lhs := ast.Unparen(as.Lhs[0])
		if !types.IsInterface(p.TypesInfo.TypeOf(lhs)) {
			return false
		}
		cur := lhs
		for {
			s, okS := cur.(*ast.SelectorExpr)
			if !okS {
				return false
			}
			if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
				if p.TypesInfo.Uses[id] != recvVar {
					return false
				}
				break
			}
			cur = ast.Unparen(s.X)
		}
		blk, isBlk := idx.ParentMap[as].(*ast.BlockStmt)
		if !isBlk || len(blk.List) != 1 {
			return false
		}
		ifStmt, isIf := idx.ParentMap[blk].(*ast.IfStmt)
		if !isIf || ifStmt.Body != blk || ifStmt.Else != nil {
			return false
		}
		bin, isBin := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL {
			return false
		}
		return syntaxutil.IsNilIdent(p.TypesInfo, bin.Y) || syntaxutil.IsNilIdent(p.TypesInfo, bin.X)
	}

	isSampleAssertedIfaceAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
			return false
		}
		ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !isTA || ta.Type == nil || !types.IsInterface(p.TypesInfo.TypeOf(ta)) {
			return false
		}
		ix, isIx := ast.Unparen(ta.X).(*ast.IndexExpr)
		return isIx && isSampleSliceExpr(ix.X)
	}

	sawOutInit := false
	outValid := true
	checkOutCompositeLit := func(cl *ast.CompositeLit) bool {
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := kv.Key.(*ast.Ident)
			if !isID || kid.Name != outIfaceName || !checkOutIfaceValue(kv.Value) {
				return false
			}
			sawOutInit = true
		}
		return true
	}
	if namedResultOutVar != nil {
		for _, uid := range idx.UsesOf[namedResultOutVar] {
			par := idx.ParentUnparen(uid)
			if sel, isSel := par.(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == uid {
				if as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt); isAs {
					onLHS := false
					for li, l := range as.Lhs {
						if ast.Unparen(l) == sel {
							onLHS = true
							if sel.Sel.Name != outIfaceName || li >= len(as.Rhs) || !checkOutIfaceValue(as.Rhs[li]) {
								outValid = false
							} else {
								sawOutInit = true
							}
						}
					}
					if onLHS {
						continue
					}
				}
				continue
			}
			if _, isRet := par.(*ast.ReturnStmt); isRet {
				continue
			}
			outValid = false
		}
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if !outValid || n == nil {
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) == 0 {
			if namedResultOutVar == nil {
				outValid = false
				return false
			}
			return true
		}
		if len(ret.Results) != 1 {
			outValid = false
			return false
		}
		res := ast.Unparen(ret.Results[0])
		if rid, isID := res.(*ast.Ident); isID {
			if namedResultOutVar == nil || p.TypesInfo.Uses[rid] != namedResultOutVar {
				outValid = false
				return false
			}
			return true
		}
		cl, isCL := res.(*ast.CompositeLit)
		if !isCL || len(cl.Elts) == 0 || !checkOutCompositeLit(cl) {
			outValid = false
			return false
		}
		return true
	})
	if !outValid || !sawOutInit {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_sample_builder_output", buildFD)
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}

	buildCone := map[*types.Func]bool{buildFn: true}
	constructedStructs := map[*types.Named]bool{}
	coneQueue := []*types.Func{buildFn}
	validBuild := true
	enqueueConstructedStruct := func(stNamed *types.Named) {
		if stNamed == nil || stNamed == named || stNamed == outNamed || capsuleElemStructs[stNamed] || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || constructedStructs[stNamed] {
			return
		}
		constructedStructs[stNamed] = true
		pset := types.NewMethodSet(types.NewPointer(stNamed))
		for mi := 0; mi < pset.Len(); mi++ {
			mfn, okM := pset.At(mi).Obj().(*types.Func)
			if !okM || mfn == nil {
				validBuild = false
				return
			}
			msig, okSig := mfn.Type().(*types.Signature)
			if !okSig || msig.Recv() == nil {
				validBuild = false
				return
			}
			if types.IsInterface(msig.Recv().Type()) {
				continue
			}
			mfn = mfn.Origin()
			if mfn.Pkg() != p.Types {
				validBuild = false
				return
			}
			if !buildCone[mfn] {
				buildCone[mfn] = true
				coneQueue = append(coneQueue, mfn)
			}
		}
	}
	for k := range directDescStructs {
		enqueueConstructedStruct(k)
	}
	for len(coneQueue) > 0 && validBuild {
		curFn := coneQueue[0]
		coneQueue = coneQueue[1:]
		fd := idx.FuncDecls[curFn]
		if fd == nil || fd.Body == nil {
			validBuild = false
			break
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.FuncLit:
				validBuild = false
				return false
			case *ast.CompositeLit:
				enqueueConstructedStruct(syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)))
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						enqueueConstructedStruct(syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)))
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
					} else if callee.Pkg() == p.Types && !buildCone[callee] {
						buildCone[callee] = true
						coneQueue = append(coneQueue, callee)
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "impure_sample_builder_cone", buildFD)
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}

	exempt := map[ast.Node]bool{}
	helperCandidates := map[*types.Func]bool{}
	validHelperCallIdents := map[*ast.Ident]bool{}
	rejReason := "invalid_sample_builder_capsule_write"
	var rejNode ast.Node
	for fn := range buildCone {
		fd := idx.FuncDecls[fn]
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					if v.Pkg() == p.Types {
						if v.Exported() || mutatedVars[syntaxutil.DynamicVarKey(v)] || !isDeterministicImmutableBuilderGlobal(p, idx, v) {
							validBuild = false
							rejReason = "impure_sample_builder_global_use"
							rejNode = x
							return false
						}
					} else {
						sel, isSel := idx.ParentUnparen(x).(*ast.SelectorExpr)
						if !isSel || sel.Sel != x || fn != buildFn || (!isNilDefaultRecvIfaceAssign(sel) && !isSampleAssertedIfaceAssign(sel)) {
							validBuild = false
							rejReason = "impure_cross_pkg_global_use"
							rejNode = x
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					if !refconfine.TouchesAnyNamedStruct(p, lhs, capsuleElemStructs) {
						continue
					}
					if fn != buildFn || li >= len(x.Rhs) {
						validBuild = false
						rejNode = x
						return false
					}
					okWrite, writeRej := isSafeBuilderCapsuleAssignment(p, lhs, x.Rhs[li], x.Pos(), capsuleElemStructs, checkDescValue, verifySampleReflectTypeWrite)
					if !okWrite {
						validBuild = false
						rejReason = writeRej
						rejNode = x
						return false
					}
					exempt[x] = true
					if comp, okComp := ast.Unparen(x.Rhs[li]).(*ast.CompositeLit); okComp {
						exempt[comp] = true
					}
				}
			case *ast.IncDecStmt:
				if refconfine.TouchesAnyNamedStruct(p, x.X, capsuleElemStructs) {
					validBuild = false
					rejNode = x
					return false
				}
			case *ast.CallExpr:
				if fn == buildFn && len(x.Args) >= 2 && !x.Ellipsis.IsValid() {
					var calleeID *ast.Ident
					switch fun := ast.Unparen(x.Fun).(type) {
					case *ast.SelectorExpr:
						calleeID = fun.Sel
					case *ast.Ident:
						calleeID = fun
					}
					if calleeID != nil {
						if selFn, isFn := p.TypesInfo.Uses[calleeID].(*types.Func); isFn && selFn != nil {
							selFn = selFn.Origin()
							if selFn.Exported() && selFn.Pkg() != nil {
								if fnSig, okSig := selFn.Type().(*types.Signature); okSig && fnSig.Recv() == nil {
									if un, isUn := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND && refconfine.TouchesAnyNamedStruct(p, un.X, capsuleElemStructs) {
										if !checkDescValue(x.Args[1]) {
											validBuild = false
											rejNode = x
											return false
										}
										for _, extra := range x.Args[2:] {
											et := p.TypesInfo.TypeOf(extra)
											if et == nil || (!syntaxutil.IsReflectType(et) && refconfine.TypeContainsRefOrPointer(et)) {
												validBuild = false
												rejNode = x
												return false
											}
										}
										helperCandidates[selFn] = true
										validHelperCallIdents[calleeID] = true
										exempt[un] = true
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		emitCapsuleReject(ctx, p, ownerRef.Key(), rejReason, rejNode)
		return syntaxutil.InitBuilderFact{}, nil, nil, false
	}

	guardSet := map[syntaxutil.TypeRef]bool{}
	if len(constructedStructs) > 0 {
		for cs := range constructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "exported_sample_builder_helper_struct", nil)
				return syntaxutil.InitBuilderFact{}, nil, nil, false
			}
			if !builderHelperStructFieldsSafe(cs, fbOutVar != nil) {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "unsafe_sample_builder_helper_struct", nil)
				return syntaxutil.InitBuilderFact{}, nil, nil, false
			}
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return syntaxutil.InitBuilderFact{}, nil, nil, false
			}
			guardSet[ref] = true
		}
		if refconfine.PkgHasAnyMutationOnStructs(p, constructedStructs, nil) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "mutated_sample_builder_helper_struct", nil)
			return syntaxutil.InitBuilderFact{}, nil, nil, false
		}
		capsuleElemPkgs := map[*types.Package]bool{}
		for capSt := range capsuleElemStructs {
			if capSt.Obj() != nil && capSt.Obj().Pkg() != nil {
				capsuleElemPkgs[capSt.Obj().Pkg()] = true
			}
		}
		sampleCarrierFields := map[*types.Var]bool{}
		if sampleSliceField != nil {
			for cs := range constructedStructs {
				if cst, okS := cs.Underlying().(*types.Struct); okS {
					for i := 0; i < cst.NumFields(); i++ {
						f := cst.Field(i)
						if !f.Exported() && syntaxutil.IsAnySliceType(f.Type()) {
							onlySamples := false
							validUses := true
							for _, uid := range idx.UsesOf[f] {
								if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
									gsel, isGS := ast.Unparen(kv.Value).(*ast.SelectorExpr)
									if !isGS || p.TypesInfo.Uses[gsel.Sel] != sampleSliceField {
										validUses = false
										break
									}
									if rid, isID := ast.Unparen(gsel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != recvVar {
										validUses = false
										break
									}
									onlySamples = true
								}
							}
							if validUses && onlySamples {
								sampleCarrierFields[f] = true
							}
						}
					}
				}
			}
		}
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index:                         idx,
			AllowReturnFromUnexportedFunc: true,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel {
					return false, false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false, false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if constructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if refconfine.IsDirectMutableRef(ft) {
					return true, true
				}
				if refconfine.TypeCarriesMutableRef(ft) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
				if argIdx != 0 || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return false
				}
				if syntaxutil.IsReflectTypeOfCall(p, call) {
					return true
				}
				ix, isIx := ast.Unparen(arg).(*ast.IndexExpr)
				if !isIx {
					return false
				}
				xsel, isXS := ast.Unparen(ix.X).(*ast.SelectorExpr)
				if !isXS {
					return false
				}
				fv, _ := p.TypesInfo.Uses[xsel.Sel].(*types.Var)
				if fv == nil || !sampleCarrierFields[fv] {
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || !capsuleElemPkgs[callee.Pkg()] {
					return false
				}
				csig, okSig := callee.Type().(*types.Signature)
				if !okSig || csig.Recv() == nil || csig.Results().Len() != 1 || !types.IsInterface(csig.Results().At(0).Type()) {
					return false
				}
				recvSt, okSt := types.Unalias(csig.Recv().Type()).Underlying().(*types.Struct)
				return okSt && recvSt.NumFields() == 0
			},
		}) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "unconfined_sample_builder_helper_struct", nil)
			return syntaxutil.InitBuilderFact{}, nil, nil, false
		}
	}

	var guardTypes []syntaxutil.TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]syntaxutil.TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	}

	var allowedHelpers []syntaxutil.FuncKey
	for selFn := range helperCandidates {
		allInBuild := true
		for _, id := range idx.UsesOf[selFn] {
			if !validHelperCallIdents[id] {
				allInBuild = false
				break
			}
		}
		if allInBuild {
			for _, id := range idx.UsesOf[selFn] {
				exempt[id] = true
			}
			allowedHelpers = append(allowedHelpers, syntaxutil.FuncKey{Pkg: selFn.Pkg().Path(), Name: selFn.Name()})
		}
	}
	slices.SortFunc(allowedHelpers, syntaxutil.FuncKey.Compare)

	sampleFieldName := ""
	if sampleSliceField != nil {
		sampleFieldName = sampleSliceField.Name()
	}
	fact := syntaxutil.InitBuilderFact{
		Type:                 ownerRef,
		BuildMethod:          buildFn.Name(),
		OutIfaceField:        outIfaceName,
		SubBuilderField:      subBuilderFieldName,
		SubBuilder:           subBuilderRef,
		TypeSampleSliceField: sampleFieldName,
		CapsuleSliceFields:   capsuleSpecs,
		AllowedHelpers:       allowedHelpers,
		GuardTypes:           guardTypes,
	}
	return fact, exempt, validHelperCallIdents, true
}

