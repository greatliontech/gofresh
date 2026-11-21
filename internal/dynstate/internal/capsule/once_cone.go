package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func typeMentionsNamedStruct(root types.Type, target *types.Named) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if t == target {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
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

func matchLocalBuilderOnlyAdapter(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	cs *types.Named,
	checkNormalField func(types.Type) bool,
) (builderGuard syntaxutil.TypeRef, methodGuards []syntaxutil.FuncKey, exemptFields []*types.Var, ok bool) {
	if cs == nil || cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	if types.NewMethodSet(types.NewPointer(cs)).Len() != types.NewMethodSet(cs).Len() {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	cst, okSt := cs.Underlying().(*types.Struct)
	if !okSt || cst.NumFields() == 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}

	for _, name := range p.Types.Scope().Names() {
		switch obj := p.Types.Scope().Lookup(name).(type) {
		case *types.Var:
			if typeMentionsNamedStruct(obj.Type(), cs) {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
		case *types.TypeName:
			if obj.Type() == cs || obj.IsAlias() {
				continue
			}
			if st, isS := obj.Type().Underlying().(*types.Struct); isS {
				for i := 0; i < st.NumFields(); i++ {
					if typeMentionsNamedStruct(st.Field(i).Type(), cs) {
						return syntaxutil.TypeRef{}, nil, nil, false
					}
				}
			}
		}
	}

	sawLit := false
	validUses := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !validUses || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND && syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
					validUses = false
					return false
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" && syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
						validUses = false
						return false
					}
				}
			case *ast.CompositeLit:
				if types.Unalias(p.TypesInfo.TypeOf(x)) == cs {
					sawLit = true
					kv, isKV := idx.ParentUnparen(x).(*ast.KeyValueExpr)
					if !isKV || ast.Unparen(kv.Value) != x {
						validUses = false
						return false
					}
					bLit, isBL := idx.ParentUnparen(kv).(*ast.CompositeLit)
					if !isBL {
						validUses = false
						return false
					}
					bSel, isBS := idx.ParentUnparen(bLit).(*ast.SelectorExpr)
					if !isBS || ast.Unparen(bSel.X) != bLit || bSel.Sel == nil || !bSel.Sel.IsExported() {
						validUses = false
						return false
					}
					bFn, okBFn := p.TypesInfo.Uses[bSel.Sel].(*types.Func)
					if !okBFn || bFn == nil || !bFn.Exported() {
						validUses = false
						return false
					}
					bSig, okBSig := bFn.Type().(*types.Signature)
					if !okBSig || bSig.Params().Len() != 0 || bSig.Results().Len() != 1 {
						validUses = false
						return false
					}
					bNamed, isBN := types.Unalias(p.TypesInfo.TypeOf(bLit)).(*types.Named)
					if !isBN || bNamed.Obj() == nil || bNamed.Obj().Pkg() == nil || bNamed.Obj().Pkg() == p.Types || !syntaxutil.HasModuleImportPathShape(bNamed.Obj().Pkg().Path()) {
						validUses = false
						return false
					}
					ref := syntaxutil.TypeRef{Pkg: bNamed.Obj().Pkg().Path(), Name: bNamed.Obj().Name()}
					if !ref.Valid() || (!builderGuard.IsZero() && builderGuard != ref) {
						validUses = false
						return false
					}
					builderGuard = ref
				}
			}
			return true
		})
	}
	if !validUses || !sawLit || builderGuard.IsZero() {
		return syntaxutil.TypeRef{}, nil, nil, false
	}

	methodSet := map[syntaxutil.FuncKey]bool{}
	for i := 0; i < cst.NumFields(); i++ {
		f := cst.Field(i)
		if f.Exported() {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		if checkNormalField(f.Type()) {
			continue
		}
		ptr, isP := types.Unalias(f.Type()).(*types.Pointer)
		if !isP {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		elemN, isEN := types.Unalias(ptr.Elem()).(*types.Named)
		if !isEN || elemN.Obj() == nil || elemN.Obj().Pkg() == nil || elemN.Obj().Pkg() == p.Types || !syntaxutil.HasModuleImportPathShape(elemN.Obj().Pkg().Path()) {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		if _, isElemSt := elemN.Underlying().(*types.Struct); !isElemSt {
			return syntaxutil.TypeRef{}, nil, nil, false
		}
		for _, fuid := range idx.UsesOf[f] {
			fsel, isFS := idx.ParentUnparen(fuid).(*ast.SelectorExpr)
			if !isFS || fsel.Sel != fuid {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			msel, isMS := idx.ParentUnparen(fsel).(*ast.SelectorExpr)
			if !isMS || ast.Unparen(msel.X) != fsel {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			si := p.TypesInfo.Selections[msel]
			if si == nil || si.Kind() != types.MethodVal || syntaxutil.SelectionCrossesEmbeddedPointer(si) {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			mfn, okM := si.Obj().(*types.Func)
			if !okM || mfn == nil || mfn.Pkg() != elemN.Obj().Pkg() || !mfn.Exported() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			mcall, isMC := idx.ParentUnparen(msel).(*ast.CallExpr)
			if !isMC || ast.Unparen(mcall.Fun) != msel || mcall.Ellipsis.IsValid() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			for _, marg := range mcall.Args {
				if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(marg)) {
					return syntaxutil.TypeRef{}, nil, nil, false
				}
			}
			mk := syntaxutil.FuncKey{Pkg: elemN.Obj().Pkg().Path(), Name: elemN.Obj().Name() + "." + mfn.Name()}
			if !mk.Valid() {
				return syntaxutil.TypeRef{}, nil, nil, false
			}
			methodSet[mk] = true
		}
		exemptFields = append(exemptFields, f)
	}
	if len(exemptFields) == 0 {
		return syntaxutil.TypeRef{}, nil, nil, false
	}
	for mk := range methodSet {
		methodGuards = append(methodGuards, mk)
	}
	slices.SortFunc(methodGuards, syntaxutil.FuncKey.Compare)
	return builderGuard, methodGuards, exemptFields, true
}

func verifyOnceInitConeImmutability(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ownerRef syntaxutil.TypeRef,
	onceFn *types.Func,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	verifiedCapsuleRoots map[*types.Named]bool,
	mutatedVars map[string]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, bool) {
	if onceFn == nil || !ownerRef.Valid() {
		return nil, nil, false
	}
	fullInitCone := map[*types.Func]bool{onceFn: true}
	coneConstructedStructs := map[*types.Named]bool{}
	coneCrossStructs := map[*types.Named]bool{}
	var coneLits []*ast.FuncLit
	memoCandidatesByFn := map[*types.Func]map[*ast.FuncLit]*types.Var{}
	queue := []*types.Func{onceFn}
	valid := true

	addConeStruct := func(stN *types.Named) {
		if stN == nil || family[stN] || childProtected[stN] || verifiedCapsuleRoots[stN] {
			return
		}
		if stN.Obj() != nil && stN.Obj().Pkg() != nil && stN.Obj().Pkg() != p.Types && syntaxutil.HasModuleImportPathShape(stN.Obj().Pkg().Path()) {
			coneCrossStructs[stN] = true
			return
		}
		coneConstructedStructs[stN] = true
	}

	isBaseImmPtr := func(tp types.Type) bool {
		ptr, ok := types.Unalias(tp).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (family[elem] || childProtected[elem] || verifiedCapsuleRoots[elem])
	}

	for len(queue) > 0 && valid {
		curFn := queue[0]
		queue = queue[1:]
		fd := idx.FuncDecls[curFn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, false
		}
		memoCands := findLocalSyncOnceMemoizerCandidates(p, idx, fd)
		if len(memoCands) > 0 {
			memoCandidatesByFn[curFn] = memoCands
		}
		isMemoLit := func(lit *ast.FuncLit) bool {
			cv := memoCands[lit]
			return cv != nil && isSafeSyncOnceMemoType(cv.Type(), isBaseImmPtr)
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt:
				valid = false
				return false
			case *ast.FuncLit:
				if !isDirectCallFuncLit(idx, x) {
					coneLits = append(coneLits, x)
					if !isMemoLit(x) {
						hasMemoInner := false
						var nestedLits []*ast.FuncLit
						ast.Inspect(x.Body, func(sn ast.Node) bool {
							if sn == nil {
								return false
							}
							if _, isG := sn.(*ast.GoStmt); isG {
								valid = false
								return false
							}
							if il, ok := sn.(*ast.FuncLit); ok && il != x {
								if !isDirectCallFuncLit(idx, il) {
									nestedLits = append(nestedLits, il)
								}
								if isMemoLit(il) {
									hasMemoInner = true
								}
							}
							return true
						})
						if !valid {
							return false
						}
						if !hasMemoInner {
							coneLits = append(coneLits, nestedLits...)
							return false
						}
					}
				}
				return true
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if isDirectPanicArgWithoutRecover(p, idx, x) {
						return true
					}
					if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
						if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
							stN := syntaxutil.DerefNamedStruct(ptr)
							if stN == nil {
								valid = false
								return false
							}
							addConeStruct(stN)
						}
					}
				}
			case *ast.CompositeLit:
				if lt := p.TypesInfo.TypeOf(x); lt != nil {
					if _, isPtr := types.Unalias(lt).(*types.Pointer); !isPtr {
						if _, isSt := types.Unalias(lt).Underlying().(*types.Struct); isSt {
							if refconfine.TypeCarriesMutableRef(lt) && types.NewMethodSet(lt).Len() > 0 {
								stN := syntaxutil.DerefNamedStruct(lt)
								if stN == nil {
									valid = false
									return false
								}
								addConeStruct(stN)
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						if !isDirectPanicArgWithoutRecover(p, idx, x) {
							if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
								if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
									stN := syntaxutil.DerefNamedStruct(ptr)
									if stN == nil {
										valid = false
										return false
									}
									addConeStruct(stN)
								}
							}
						}
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
					} else if callee.Pkg() == p.Types && !fullInitCone[callee] {
						fullInitCone[callee] = true
						queue = append(queue, callee)
					}
				}
			}
			return true
		})
	}
	if !valid {
		return nil, nil, false
	}

	isConeImmStruct := func(st *types.Named) bool {
		return st != nil && (family[st] || childProtected[st] || verifiedCapsuleRoots[st] || coneConstructedStructs[st] || coneCrossStructs[st])
	}
	isConeImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && isConeImmStruct(elem)
	}

	condSet := map[syntaxutil.ConditionalStructMutation]bool{}
	for extSt := range coneCrossStructs {
		extRef := syntaxutil.TypeRef{Pkg: extSt.Obj().Pkg().Path(), Name: extSt.Obj().Name()}
		if !extRef.Valid() {
			return nil, nil, false
		}
		condSet[syntaxutil.ConditionalStructMutation{
			Struct:                       ownerRef,
			GuardStruct:                  extRef,
			RequireImmutableCapsuleGuard: true,
		}] = true
	}

	var coneGuards []syntaxutil.TypeRef
	if len(coneConstructedStructs) > 0 {
		isEmbeddedNonEmptyIface := func(f *types.Var) bool {
			if !f.Embedded() {
				return false
			}
			iface, ok := types.Unalias(f.Type()).Underlying().(*types.Interface)
			return ok && iface.NumMethods() > 0
		}
		checkConeFieldType := func(root types.Type, rootSamePkgStruct bool) bool {
			seenFieldTypes := map[types.Type]bool{}
			var walk func(t types.Type, inSamePkgStruct bool) bool
			walk = func(t types.Type, inSamePkgStruct bool) bool {
				if t == nil {
					return false
				}
				t = types.Unalias(t)
				if seenFieldTypes[t] {
					return true
				}
				seenFieldTypes[t] = true
				if n, isN := t.(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						return types.NewMethodSet(types.NewPointer(n)).Len() == types.NewMethodSet(n).Len()
					}
				}
				switch u := t.Underlying().(type) {
				case *types.Interface, *types.Signature:
					return true
				case *types.Basic:
					return !(inSamePkgStruct && u.Kind() == types.UnsafePointer)
				case *types.Chan, *types.TypeParam:
					return false
				case *types.Pointer:
					elem, isEN := types.Unalias(u.Elem()).(*types.Named)
					return isEN && isConeImmStruct(elem)
				case *types.Slice:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Array:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Map:
					return walk(u.Key(), inSamePkgStruct) && walk(u.Elem(), inSamePkgStruct)
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						f := u.Field(i)
						if inSamePkgStruct && f.Exported() && !isEmbeddedNonEmptyIface(f) {
							return false
						}
						subSamePkg := inSamePkgStruct
						if subN, isSN := types.Unalias(f.Type()).(*types.Named); isSN && subN.Obj() != nil {
							subSamePkg = subN.Obj().Pkg() == p.Types
						}
						if !walk(f.Type(), subSamePkg) {
							return false
						}
					}
					return true
				}
				return true
			}
			return walk(root, rootSamePkgStruct)
		}

		adapterExemptFields := map[*types.Var]bool{}
		for cs := range coneConstructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, false
			}
			cst, okS := cs.Underlying().(*types.Struct)
			if !okS {
				return nil, nil, false
			}
			normalOK := true
			for i := 0; i < cst.NumFields(); i++ {
				f := cst.Field(i)
				if (f.Exported() && !isEmbeddedNonEmptyIface(f)) || !checkConeFieldType(f.Type(), true) {
					normalOK = false
					break
				}
			}
			if !normalOK {
				bGuard, mGuards, exFields, okAdapter := matchLocalBuilderOnlyAdapter(p, idx, cs, func(ft types.Type) bool {
					return checkConeFieldType(ft, true)
				})
				if !okAdapter {
					return nil, nil, false
				}
				condSet[syntaxutil.ConditionalStructMutation{
					Struct:                       ownerRef,
					GuardStruct:                  bGuard,
					RequireImmutableCapsuleGuard: true,
				}] = true
				for _, mk := range mGuards {
					condSet[syntaxutil.ConditionalStructMutation{
						Struct:                   ownerRef,
						RequireNonMutatingMethod: mk,
					}] = true
				}
				for _, ef := range exFields {
					adapterExemptFields[ef] = true
				}
			}
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, false
			}
			coneGuards = append(coneGuards, ref)
		}
		if refconfine.PkgHasAnyMutationOnStructs(p, coneConstructedStructs, nil) {
			return nil, nil, false
		}
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index:                         idx,
			IsImmutablePtr:                isConeImmPtr,
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
				if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && adapterExemptFields[fObj] {
					return false, false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if coneConstructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if n, isN := types.Unalias(ft).(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						return false, false
					}
				}
				if refconfine.IsDirectMutableRefWith(ft, isConeImmPtr) {
					return true, true
				}
				if refconfine.TypeCarriesMutableRefWith(ft, isConeImmPtr) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
			},
		}) {
			return nil, nil, false
		}
		sort.Slice(coneGuards, func(i, j int) bool { return coneGuards[i].Key() < coneGuards[j].Key() })
	}

	if len(coneLits) > 0 {
		memoAllowedWrite := map[*ast.FuncLit]*types.Var{}
		for _, cands := range memoCandidatesByFn {
			for lit, cv := range cands {
				if isSafeSyncOnceMemoType(cv.Type(), isConeImmPtr) {
					memoAllowedWrite[lit] = cv
				}
			}
		}

		capturedRefIdents := map[*ast.Ident]bool{}
		for _, lit := range coneLits {
			allowedCachedVar := memoAllowedWrite[lit]
			ast.Inspect(lit.Body, func(n ast.Node) bool {
				if !valid || n == nil {
					return false
				}
				if nl, isNL := n.(*ast.FuncLit); isNL && nl != lit && !isDirectCallFuncLit(idx, nl) {
					return false
				}
				uid, isID := n.(*ast.Ident)
				if !isID {
					return true
				}
				v, isV := p.TypesInfo.Uses[uid].(*types.Var)
				if !isV || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() || v.Pos() >= lit.Pos() {
					return true
				}
				if refconfine.IdentOrExprIsWritten(idx, uid) {
					if allowedCachedVar != nil && v == allowedCachedVar {
						return true
					}
					valid = false
					return false
				}
				if un, isUn := idx.ParentUnparen(uid).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					if !isConeImmPtr(p.TypesInfo.TypeOf(un)) {
						valid = false
						return false
					}
				}
				if refconfine.TypeCarriesMutableRefWith(v.Type(), isConeImmPtr) {
					capturedRefIdents[uid] = true
				}
				return true
			})
			if !valid {
				return nil, nil, false
			}
		}
		if len(capturedRefIdents) > 0 {
			if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
				Index:                         idx,
				IsImmutablePtr:                isConeImmPtr,
				AllowReturnFromUnexportedFunc: true,
				AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
					return syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(containerExpr), "reflect", "StructField")
				},
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					id, isID := ast.Unparen(expr).(*ast.Ident)
					if !isID || !capturedRefIdents[id] {
						return false, false
					}
					vt := p.TypesInfo.TypeOf(id)
					if refconfine.IsDirectMutableRefWith(vt, isConeImmPtr) {
						return true, true
					}
					if refconfine.TypeCarriesMutableRefWith(vt, isConeImmPtr) {
						return false, true
					}
					return false, false
				},
				AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
					return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
				},
			}) {
				return nil, nil, false
			}
		}
	}

	var conds []syntaxutil.ConditionalStructMutation
	for cm := range condSet {
		conds = append(conds, cm)
	}
	slices.SortFunc(conds, syntaxutil.ConditionalStructMutation.Compare)
	return coneGuards, conds, true
}
