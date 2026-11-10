package protoaudit

import (
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

func deriveProtoRuntimeTypes(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	mutatedVars map[string]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]ProtoRuntimeTypeFact, []syntaxutil.ConditionalStructMutation) {
	type candidate struct {
		ref   syntaxutil.TypeRef
		named *types.Named
		st    *types.Struct
	}
	var candidates []candidate
	for _, name := range p.Types.Scope().Names() {
		tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
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
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: tn.Name()}
		if !ref.Valid() {
			continue
		}
		candidates = append(candidates, candidate{ref: ref, named: named, st: st})
	}

	var out []ProtoRuntimeTypeFact
	var conds []syntaxutil.ConditionalStructMutation
	builderExempt := map[ast.Node]bool{}
	builderHelperIdents := map[*ast.Ident]bool{}
	if confinedCacheMaps == nil {
		confinedCacheMaps = freshstruct.FindMutexConfinedConstructorCaches(p, idx)
	}

	for _, c := range candidates {
		if dbNodes, dbByFunc, dbGuards, okDB := verifyProtoDescBuilderType(p, idx, c.named, c.st, mutatedVars, exemptReadFields); okDB {
			for n := range dbNodes {
				exempted[n] = true
			}
			for fd, fam := range dbByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleDescBuilder,
				GuardTypes: dbGuards,
			})
		}
	}

	for _, c := range candidates {
		if bNodes, helperIdents, subBuilder, allowedHelpers, bGuards, okB := verifyProtoBuilderType(p, idx, c.named, c.st, mutatedVars); okB {
			for n := range bNodes {
				exempted[n] = true
				builderExempt[n] = true
			}
			for id := range helperIdents {
				builderHelperIdents[id] = true
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:           c.ref,
				Role:           ProtoRoleBuilder,
				SubBuilder:     subBuilder,
				AllowedHelpers: allowedHelpers,
				GuardTypes:     bGuards,
			})
		}
	}

	verifiedMsgRoots := map[*types.Named]bool{}
	for _, c := range candidates {
		if mNodes, mByFunc, mGuards, mConds, okM := verifyProtoMessageType(p, idx, freshCache, c.named, c.st, mutatedVars, builderExempt, verifiedMsgRoots, confinedCacheMaps); okM {
			verifiedMsgRoots[c.named] = true
			for n := range mNodes {
				exempted[n] = true
			}
			for fd, fam := range mByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, mConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleMessage,
				GuardTypes: mGuards,
			})
		}
	}
	for _, c := range candidates {
		if eNodes, eByFunc, initHelper, eGuards, eConds, okE := verifyProtoExtensionType(p, idx, freshCache, c.named, c.st, mutatedVars, builderExempt, builderHelperIdents, verifiedMsgRoots, confinedCacheMaps); okE {
			for n := range eNodes {
				exempted[n] = true
			}
			for fd, fam := range eByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, eConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleExtension,
				InitHelper: initHelper,
				GuardTypes: eGuards,
			})
		}
	}
	for _, c := range candidates {
		if verifyProtoEnumType(p, idx, c.named, c.st, builderExempt, verifiedMsgRoots) {
			out = append(out, ProtoRuntimeTypeFact{Type: c.ref, Role: ProtoRoleEnum})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type.Key() != out[j].Type.Key() {
			return out[i].Type.Key() < out[j].Type.Key()
		}
		return out[i].Role < out[j].Role
	})
	return out, conds
}

func verifyProtoBuilderType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
) (map[ast.Node]bool, map[*ast.Ident]bool, syntaxutil.TypeRef, []syntaxutil.FuncKey, []syntaxutil.TypeRef, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	hasGoTypes := false
	infoElemStructs := map[*types.Named]bool{}
	builderExportedStructFields := map[*types.Var]*types.Named{}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		switch f.Name() {
		case "GoTypes":
			if !f.Exported() || !syntaxutil.IsAnySliceType(f.Type()) {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			hasGoTypes = true
		case "EnumInfos", "MessageInfos", "ExtensionInfos":
			if !f.Exported() {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			_, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type())
			if !okElem {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			infoElemStructs[elemNamed] = true
		default:
			if f.Exported() {
				if fnamed, isN := types.Unalias(f.Type()).(*types.Named); isN {
					if _, isSt := fnamed.Underlying().(*types.Struct); isSt {
						builderExportedStructFields[f] = fnamed
					}
				}
			}
		}
	}
	if !hasGoTypes || len(infoElemStructs) == 0 || named.NumMethods() != 1 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	buildFn := named.Method(0)
	if buildFn.Name() != "Build" {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok || !syntaxutil.StructHasExportedIfaceField(outSt, "File") {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	buildFD := idx.FuncDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil || sig.Recv() == nil {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	recvVar := sig.Recv()
	var namedResultOutVar *types.Var
	if sig.Results().At(0).Name() != "" {
		namedResultOutVar = sig.Results().At(0)
	}

	var subBuilderRef syntaxutil.TypeRef
	var fbOutVar *types.Var
	fbOutSliceFields := map[*types.Var]bool{}
	subCallBad := false
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if subCallBad || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			return true
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Build" {
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
		if !isSt || !syntaxutil.StructHasExportedIfaceField(fbSt, "File") {
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
		subBuilderRef = ref
		fbOutVar = lv
		return true
	})
	if subCallBad {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
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

	isSubBuilderFileExpr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "File" {
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
		if fbOutVar != nil {
			return isSubBuilderSliceElemAddr(expr)
		}
		vt := p.TypesInfo.TypeOf(expr)
		if vt != nil && !refconfine.TypeContainsRefOrPointer(vt) {
			return true
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	checkOutFileValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderFileExpr(expr)
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	goTypesDerivedVars := map[*types.Var]bool{}
	isGoTypesExpr := func(expr ast.Expr) bool {
		cur := ast.Unparen(expr)
		for {
			if se, isSE := cur.(*ast.SliceExpr); isSE {
				cur = ast.Unparen(se.X)
				continue
			}
			break
		}
		if sel, isSel := cur.(*ast.SelectorExpr); isSel && sel.Sel.Name == "GoTypes" {
			if id, isID := ast.Unparen(sel.X).(*ast.Ident); isID && p.TypesInfo.Uses[id] == recvVar {
				return true
			}
		}
		if id, isID := cur.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil && goTypesDerivedVars[v] {
				return true
			}
		}
		return false
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
			if lv, _ := p.TypesInfo.Defs[lid].(*types.Var); lv != nil && idx.DefCounts[lv] == 1 && isGoTypesExpr(as.Rhs[0]) {
				reassigned := false
				for _, uid := range idx.UsesOf[lv] {
					if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
						reassigned = true
						break
					}
				}
				if !reassigned {
					goTypesDerivedVars[lv] = true
				}
			}
		}
		return true
	})

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

	isDescoptsGoTypeAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
			return false
		}
		ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !isTA || ta.Type == nil || !types.IsInterface(p.TypesInfo.TypeOf(ta)) {
			return false
		}
		ix, isIx := ast.Unparen(ta.X).(*ast.IndexExpr)
		return isIx && isGoTypesExpr(ix.X)
	}

	sawOutFileInit := false
	outValid := true
	checkOutCompositeLit := func(cl *ast.CompositeLit) bool {
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := kv.Key.(*ast.Ident)
			if !isID || kid.Name != "File" || !checkOutFileValue(kv.Value) {
				return false
			}
			sawOutFileInit = true
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
							if sel.Sel.Name != "File" || li >= len(as.Rhs) || !checkOutFileValue(as.Rhs[li]) {
								outValid = false
							} else {
								sawOutFileInit = true
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
	if !outValid || !sawOutFileInit {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	buildCone := map[*types.Func]bool{buildFn: true}
	constructedStructs := map[*types.Named]bool{}
	coneQueue := []*types.Func{buildFn}
	validBuild := true
	enqueueConstructedStruct := func(stNamed *types.Named) {
		if stNamed == nil || stNamed == named || stNamed == outNamed || infoElemStructs[stNamed] || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || constructedStructs[stNamed] {
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
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	exempt := map[ast.Node]bool{}
	helperCandidates := map[*types.Func]bool{}
	validHelperCallIdents := map[*ast.Ident]bool{}
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
							return false
						}
					} else {
						sel, isSel := idx.ParentUnparen(x).(*ast.SelectorExpr)
						if !isSel || sel.Sel != x || fn != buildFn || (!isNilDefaultRecvIfaceAssign(sel) && !isDescoptsGoTypeAssign(sel)) {
							validBuild = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					if !refconfine.TouchesAnyNamedStruct(p, lhs, infoElemStructs) {
						continue
					}
					if fn != buildFn || li >= len(x.Rhs) || !isSafeBuilderInfoAssignment(p, lhs, x.Rhs[li], infoElemStructs, checkDescValue) {
						validBuild = false
						return false
					}
					exempt[x] = true
				}
			case *ast.IncDecStmt:
				if refconfine.TouchesAnyNamedStruct(p, x.X, infoElemStructs) {
					validBuild = false
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
									if un, isUn := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND && refconfine.TouchesAnyNamedStruct(p, un.X, infoElemStructs) {
										if !checkDescValue(x.Args[1]) {
											validBuild = false
											return false
										}
										for _, extra := range x.Args[2:] {
											et := p.TypesInfo.TypeOf(extra)
											if et == nil || (!syntaxutil.IsReflectType(et) && refconfine.TypeContainsRefOrPointer(et)) {
												validBuild = false
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
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	guardSet := map[syntaxutil.TypeRef]bool{}
	if len(constructedStructs) > 0 {
		for cs := range constructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			if !builderHelperStructFieldsSafe(cs, fbOutVar != nil) {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			guardSet[ref] = true
		}
		if refconfine.PkgHasAnyMutationOnStructs(p, constructedStructs, nil) {
			return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
		}
		infoElemPkgs := map[*types.Package]bool{}
		for infoSt := range infoElemStructs {
			if infoSt.Obj() != nil && infoSt.Obj().Pkg() != nil {
				infoElemPkgs[infoSt.Obj().Pkg()] = true
			}
		}
		goTypesCarrierFields := map[*types.Var]bool{}
		for cs := range constructedStructs {
			if cst, okS := cs.Underlying().(*types.Struct); okS {
				for i := 0; i < cst.NumFields(); i++ {
					f := cst.Field(i)
					if !f.Exported() && syntaxutil.IsAnySliceType(f.Type()) {
						onlyGoTypes := false
						validUses := true
						for _, uid := range idx.UsesOf[f] {
							if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
								gsel, isGS := ast.Unparen(kv.Value).(*ast.SelectorExpr)
								if !isGS || gsel.Sel.Name != "GoTypes" {
									validUses = false
									break
								}
								if rid, isID := ast.Unparen(gsel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != recvVar {
									validUses = false
									break
								}
								onlyGoTypes = true
							}
						}
						if validUses && onlyGoTypes {
							goTypesCarrierFields[f] = true
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
				if fv == nil || !goTypesCarrierFields[fv] {
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || !infoElemPkgs[callee.Pkg()] {
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
			return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
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
			allowedHelpers = append(allowedHelpers, syntaxutil.FuncKey{Pkg: selFn.Pkg().Path(), Name: selFn.Name()})
		}
	}
	slices.SortFunc(allowedHelpers, syntaxutil.FuncKey.Compare)
	return exempt, validHelperCallIdents, subBuilderRef, allowedHelpers, guardTypes, true
}

func isSafeBuilderInfoAssignment(
	p *packages.Package,
	lhs, rhs ast.Expr,
	infoElemStructs map[*types.Named]bool,
	checkDesc func(ast.Expr) bool,
) bool {
	lhs = ast.Unparen(lhs)
	rhs = ast.Unparen(rhs)
	switch l := lhs.(type) {
	case *ast.SelectorExpr:
		if l.Sel.Name == "GoReflectType" {
			return syntaxutil.IsReflectTypeOfCall(p, rhs)
		}
		if l.Sel.Name == "Desc" {
			return !syntaxutil.ExprIsFuncLit(rhs) && checkDesc(rhs)
		}
		return false
	case *ast.IndexExpr:
		comp, ok := rhs.(*ast.CompositeLit)
		if !ok {
			return false
		}
		st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(comp))
		if st == nil || !infoElemStructs[st] {
			return false
		}
		for _, elt := range comp.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kID, isID := kv.Key.(*ast.Ident)
			if !isID {
				return false
			}
			switch kID.Name {
			case "GoReflectType":
				if !syntaxutil.IsReflectTypeOfCall(p, kv.Value) {
					return false
				}
			case "Desc":
				if syntaxutil.ExprIsFuncLit(kv.Value) || !checkDesc(kv.Value) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return false
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
		if len(rc.Args) != 1 || !isSafeExtTypeExpr(p, rc.Args[0]) {
			return false
		}
	}
	return true
}
