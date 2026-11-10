package protoaudit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyProtoStructFieldsAndCollectChildren(
	p *packages.Package,
	family map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedMsgRoots map[*types.Named]bool,
	allowExportedAnySlice bool,
) (map[*types.Named]bool, bool) {
	checkExportedFields := func(st *types.Struct, allowAnySlice bool) bool {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if !f.Exported() {
				continue
			}
			if _, isPtr := types.Unalias(f.Type()).(*types.Pointer); !isPtr {
				if subSt, isSt := types.Unalias(f.Type()).Underlying().(*types.Struct); isSt && subSt.NumFields() > 0 {
					return false
				}
			}
			if refconfine.TypeCarriesMutableRef(f.Type()) && !(allowAnySlice && syntaxutil.IsAnySliceType(f.Type())) {
				return false
			}
		}
		return true
	}
	for famNamed := range family {
		st, ok := famNamed.Underlying().(*types.Struct)
		if !ok || !checkExportedFields(st, allowExportedAnySlice) {
			return nil, false
		}
	}

	childProtected := map[*types.Named]bool{}
	seen := map[types.Type]bool{}
	valid := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !valid {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if syntaxutil.IsNamedInPkg(t, "sync", "Mutex") {
			return
		}
		if n, isN := t.(*types.Named); isN && casHelperStructs[n] != nil {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface, *types.Signature:
			return
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				valid = false
			}
		case *types.Chan, *types.TypeParam:
			valid = false
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			elemNamed, isEN := elem.(*types.Named)
			if !isEN || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != p.Types {
				valid = false
				return
			}
			elemSt, isSt := elemNamed.Underlying().(*types.Struct)
			if !isSt {
				valid = false
				return
			}
			if family[elemNamed] || verifiedMsgRoots[elemNamed] {
				return
			}
			if elemNamed.Obj().Exported() || !checkExportedFields(elemSt, false) {
				valid = false
				return
			}
			childProtected[elemNamed] = true
			walk(elem)
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
	for famNamed := range family {
		if st, ok := famNamed.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				walk(st.Field(i).Type())
			}
		}
	}
	if !valid {
		return nil, false
	}
	return childProtected, true
}

func verifyProtoEnumType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	st *types.Struct,
	builderExempt map[ast.Node]bool,
	verifiedMsgRoots map[*types.Named]bool,
) bool {
	if st.NumFields() == 0 {
		return false
	}
	family := map[*types.Named]bool{named: true}
	childProtected, okFields := verifyProtoStructFieldsAndCollectChildren(p, family, nil, verifiedMsgRoots, false)
	if !okFields || len(childProtected) > 0 {
		return false
	}
	allProtected := map[*types.Named]bool{named: true}
	if refconfine.PkgHasAnyMutationOnStructs(p, allProtected, builderExempt) {
		return false
	}
	isImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (allProtected[elem] || verifiedMsgRoots[elem])
	}
	return refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		IsImmutablePtr:                isImmPtr,
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
			if refconfine.IsInsideExemptWriteOrAddr(idx, sel, builderExempt) {
				return false, false
			}
			hit := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if allProtected[hop] {
					hit = true
				}
			})
			if !hit {
				return false, false
			}
			ft := selInfo.Type()
			if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
		},
	})
}

func verifyProtoMessageType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	verifiedMsgRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, bool) {
	exempt, exemptByFunc, _, guardTypes, coneConds, ok := verifyProtoLockedRoleType(
		p, idx, freshCache, named, st, mutatedVars, builderExempt, nil, verifiedMsgRoots, confinedCacheMaps, true, false,
	)
	return exempt, exemptByFunc, guardTypes, coneConds, ok
}

func verifyProtoExtensionType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	builderHelperIdents map[*ast.Ident]bool,
	verifiedMsgRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, syntaxutil.FuncKey, []syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, bool) {
	return verifyProtoLockedRoleType(
		p, idx, freshCache, named, st, mutatedVars, builderExempt, builderHelperIdents, verifiedMsgRoots, confinedCacheMaps, false, true,
	)
}

func verifyProtoLockedRoleType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	builderHelperIdents map[*ast.Ident]bool,
	verifiedMsgRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	allowEmbeddedAndCAS bool,
	allowBuilderInitHelper bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, syntaxutil.FuncKey, []syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, bool) {
	muField, flagField := findUnexportedMutexAndUint32(st)
	if muField == nil || flagField == nil {
		return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
	}

	family := map[*types.Named]bool{named: true}
	var casHelperStructs map[*types.Named]*ast.FuncDecl
	var casNodesExempt map[ast.Node]bool
	var casGuardTypes []syntaxutil.TypeRef
	if allowEmbeddedAndCAS {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Embedded() && !f.Exported() {
				if emb, ok := types.Unalias(f.Type()).(*types.Named); ok && emb.Obj() != nil && emb.Obj().Pkg() == p.Types {
					if embSt, isSt := emb.Underlying().(*types.Struct); isSt {
						family[emb] = true
						for j := 0; j < embSt.NumFields(); j++ {
							sf := embSt.Field(j)
							if sub, okSub := types.Unalias(sf.Type()).(*types.Named); okSub && sub.Obj() != nil && sub.Obj().Pkg() == p.Types {
								if fdCAS, exCAS, guardsCAS := verifyAtomicCASPointerStruct(p, idx, sub, named); fdCAS != nil {
									if casHelperStructs == nil {
										casHelperStructs = map[*types.Named]*ast.FuncDecl{}
									}
									if casNodesExempt == nil {
										casNodesExempt = map[ast.Node]bool{}
									}
									casHelperStructs[sub] = fdCAS
									for n := range exCAS {
										casNodesExempt[n] = true
									}
									casGuardTypes = append(casGuardTypes, guardsCAS...)
								}
							}
						}
					}
				}
			}
		}
	}

	childProtected, okFields := verifyProtoStructFieldsAndCollectChildren(p, family, casHelperStructs, verifiedMsgRoots, allowEmbeddedAndCAS)
	if !okFields {
		return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
	}

	var onceFn *types.Func
	pset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < pset.Len(); i++ {
		m, ok := pset.At(i).Obj().(*types.Func)
		if !ok || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		fd := idx.FuncDecls[m]
		if fd != nil && fd.Body != nil && isLockedOnceInitMethod(p, fd, named, muField, flagField) {
			if onceFn != nil {
				return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
			}
			onceFn = m
		}
	}
	if onceFn == nil {
		return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
	}

	ownerRef := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: named.Obj().Name()}
	onceCone := refconfine.ComputeExclusiveHelperCone(p, idx, onceFn)
	coneGuards, coneConds, okCone := verifyOnceInitConeImmutability(p, idx, ownerRef, onceFn, family, childProtected, verifiedMsgRoots, mutatedVars, confinedCacheMaps)
	if !okCone {
		return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
	}

	var builderInitFn *types.Func
	if allowBuilderInitHelper {
		for fn, fd := range idx.FuncDecls {
			if fn.Pkg() != p.Types || !fn.Exported() || fd.Recv != nil || fd.Body == nil {
				continue
			}
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig.Params().Len() < 1 || !syntaxutil.IsPtrToNamed(sig.Params().At(0).Type(), named) {
				continue
			}
			allUsesInBuilder := true
			for _, id := range idx.UsesOf[fn] {
				if !builderHelperIdents[id] {
					allUsesInBuilder = false
					break
				}
			}
			if allUsesInBuilder && verifyExtensionBuilderInitFunc(p, fd, named) {
				if builderInitFn != nil {
					return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
				}
				builderInitFn = fn
			}
		}
	}

	exempt := map[ast.Node]bool{}
	for n := range casNodesExempt {
		exempt[n] = true
	}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for fn := range onceCone {
		fd := idx.FuncDecls[fn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
		}
		for famSt := range family {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
		for chSt := range childProtected {
			addExemptStructInFunc(exemptByFunc, fd, chSt)
		}
	}
	for casSt, fdCAS := range casHelperStructs {
		addExemptStructInFunc(exemptByFunc, fdCAS, casSt)
	}
	var initHelper syntaxutil.FuncKey
	if builderInitFn != nil {
		for famSt := range family {
			addExemptStructInFunc(exemptByFunc, idx.FuncDecls[builderInitFn], famSt)
		}
		for chSt := range childProtected {
			addExemptStructInFunc(exemptByFunc, idx.FuncDecls[builderInitFn], chSt)
		}
		initHelper = syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: builderInitFn.Name()}
	}

	guardTypes, okDisc := verifyLockedStructFamilyDiscipline(p, idx, freshCache, named, family, childProtected, casHelperStructs, verifiedMsgRoots, muField, flagField, onceFn, onceCone, builderInitFn, exempt, builderExempt)
	if !okDisc {
		return nil, nil, syntaxutil.FuncKey{}, nil, nil, false
	}
	if len(casGuardTypes) > 0 || len(coneGuards) > 0 {
		gmap := make(map[syntaxutil.TypeRef]bool, len(guardTypes)+len(casGuardTypes)+len(coneGuards))
		for _, g := range guardTypes {
			gmap[g] = true
		}
		for _, g := range casGuardTypes {
			gmap[g] = true
		}
		for _, g := range coneGuards {
			gmap[g] = true
		}
		guardTypes = make([]syntaxutil.TypeRef, 0, len(gmap))
		for g := range gmap {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	}
	return exempt, exemptByFunc, initHelper, guardTypes, coneConds, true
}

func verifyExtensionBuilderInitFunc(p *packages.Package, fd *ast.FuncDecl, extNamed *types.Named) bool {
	if fd.Type == nil || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 || len(fd.Type.Params.List[0].Names) == 0 {
		return false
	}
	if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
		return false
	}
	param0, _ := p.TypesInfo.Defs[fd.Type.Params.List[0].Names[0]].(*types.Var)
	if param0 == nil || !syntaxutil.IsPtrToNamed(param0.Type(), extNamed) {
		return false
	}
	ok := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !ok || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if id, isID := ast.Unparen(lhs).(*ast.Ident); isID && id.Name == "_" {
					continue
				}
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, param0) {
					ok = false
					return false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal || !syntaxutil.IsPtrToNamed(selInfo.Recv(), extNamed) || selInfo.Obj().Exported() {
					ok = false
					return false
				}
			}
		case *ast.CallExpr, *ast.IncDecStmt, *ast.GoStmt, *ast.FuncLit:
			ok = false
			return false
		}
		return true
	})
	return ok
}

func findUnexportedMutexAndUint32(st *types.Struct) (muField, flagField *types.Var) {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() || f.Embedded() {
			continue
		}
		if syntaxutil.IsNamedInPkg(f.Type(), "sync", "Mutex") {
			if muField != nil {
				return nil, nil
			}
			muField = f
			continue
		}
		if b, ok := types.Unalias(f.Type()).Underlying().(*types.Basic); ok && b.Kind() == types.Uint32 {
			if flagField == nil {
				flagField = f
			}
		}
	}
	return muField, flagField
}

func isLockedOnceInitMethod(
	p *packages.Package,
	fd *ast.FuncDecl,
	recvNamed *types.Named,
	muField, flagField *types.Var,
) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	if fd.Type == nil || (fd.Type.Results != nil && len(fd.Type.Results.List) > 0) {
		return false
	}
	recvVar, ok := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || recvVar == nil || !syntaxutil.IsPtrToNamed(recvVar.Type(), recvNamed) {
		return false
	}
	stmts := fd.Body.List
	if len(stmts) < 4 {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[0], recvVar, muField, "Lock", false) {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[1], recvVar, muField, "Unlock", true) {
		return false
	}
	guardIf, ok := stmts[2].(*ast.IfStmt)
	if !ok || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 {
		return false
	}
	if ret, isRet := guardIf.Body.List[0].(*ast.ReturnStmt); !isRet || len(ret.Results) != 0 {
		return false
	}
	if !exprMentionsFieldOnRecv(p, guardIf.Cond, recvVar, flagField) {
		return false
	}
	hasAtomicStore := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if hasAtomicStore || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 2 {
			return true
		}
		if isAtomicUint32Call(p, call, "StoreUint32") && isAddrOfRecvField(p, call.Args[0], recvVar, flagField) {
			if tv := p.TypesInfo.Types[call.Args[1]]; tv.Value != nil {
				if v, okI := constant.Uint64Val(tv.Value); okI && v > 0 {
					hasAtomicStore = true
					return false
				}
			}
		}
		return true
	})
	return hasAtomicStore
}

func isReflectZeroInterfaceCall(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Interface" {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
		return false
	}
	zCall, ok := ast.Unparen(sel.X).(*ast.CallExpr)
	if !ok || len(zCall.Args) != 1 {
		return false
	}
	zSel, ok := ast.Unparen(zCall.Fun).(*ast.SelectorExpr)
	if !ok || zSel.Sel == nil {
		return false
	}
	zFn, ok := p.TypesInfo.Uses[zSel.Sel].(*types.Func)
	return ok && zFn.Pkg() != nil && zFn.Pkg().Path() == "reflect" && zFn.Name() == "Zero"
}

func isSafeProtectedIfaceElemValue(
	p *packages.Package,
	val ast.Expr,
	allProtected map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) bool {
	if syntaxutil.IsNilIdent(p.TypesInfo, val) || isReflectZeroInterfaceCall(p, val) {
		return true
	}
	valT := p.TypesInfo.TypeOf(val)
	if valT == nil {
		return false
	}
	if types.IsInterface(valT) {
		ix, isIX := ast.Unparen(val).(*ast.IndexExpr)
		if !isIX {
			return false
		}
		hitSt, fld := lhsRootFamilyField(p, ix.X, allProtected)
		return hitSt != nil && fld != nil && !fld.Exported()
	}
	return !refconfine.TypeCarriesMutableRefWith(valT, isImmPtr)
}

func verifyLockedStructFamilyDiscipline(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	rootNamed *types.Named,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedMsgRoots map[*types.Named]bool,
	muField, flagField *types.Var,
	onceFn *types.Func,
	onceCone map[*types.Func]bool,
	builderInitFn *types.Func,
	exempt map[ast.Node]bool,
	builderExempt map[ast.Node]bool,
) ([]syntaxutil.TypeRef, bool) {
	allProtected := map[*types.Named]bool{}
	for st := range family {
		allProtected[st] = true
		if len(casHelperStructs) > 0 {
			if uSt, okSt := st.Underlying().(*types.Struct); okSt {
				for i := 0; i < uSt.NumFields(); i++ {
					f := uSt.Field(i)
					casSt, isN := types.Unalias(f.Type()).(*types.Named)
					if !isN || casHelperStructs[casSt] == nil {
						continue
					}
					if f.Exported() {
						return nil, false
					}
					for _, id := range idx.UsesOf[f] {
						sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
						if !isSel || sel.Sel != id {
							return nil, false
						}
						msel, isMS := idx.ParentUnparen(sel).(*ast.SelectorExpr)
						if !isMS || ast.Unparen(msel.X) != sel {
							return nil, false
						}
						call, isCall := idx.ParentUnparen(msel).(*ast.CallExpr)
						if !isCall || ast.Unparen(call.Fun) != msel {
							return nil, false
						}
					}
				}
			}
		}
	}
	for st := range childProtected {
		allProtected[st] = true
	}
	isImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (allProtected[elem] || verifiedMsgRoots[elem])
	}

	for _, id := range idx.UsesOf[muField] {
		encl := idx.SyncEnclFuncDecl(id)
		if encl == nil {
			return nil, false
		}
		fn, _ := p.TypesInfo.Defs[encl.Name].(*types.Func)
		if fn == nil || !onceCone[fn] {
			return nil, false
		}
		sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, false
		}
		msel, isMSel := idx.ParentUnparen(sel).(*ast.SelectorExpr)
		if !isMSel || ast.Unparen(msel.X) != sel || (msel.Sel.Name != "Lock" && msel.Sel.Name != "Unlock") {
			return nil, false
		}
		call, isCall := idx.ParentUnparen(msel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != msel {
			return nil, false
		}
	}

	if freshCache == nil {
		freshCache = freshstruct.NewFreshLocalsCache(p, idx)
	}
	fastInitMethods := collectFastOnceWrapperMethods(p, idx, rootNamed, onceFn, flagField)
	guardSet := map[syntaxutil.TypeRef]bool{}
	for st := range allProtected {
		if st == rootNamed || st.Obj() == nil {
			continue
		}
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: st.Obj().Name()}
		if !ref.Valid() {
			return nil, false
		}
		guardSet[ref] = true
	}
	allowExportedWriteInCone := hasDeprecatedExtensionFields(family)

	checkFamilyWriteExpr := func(expr ast.Expr, inAllowedWriter bool, freshVars map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if star, isStar := ast.Unparen(expr).(*ast.StarExpr); isStar {
			if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(star.X)); st != nil {
				if family[st] {
					return false
				}
				if childProtected[st] {
					return inAllowedWriter || freshstruct.IsRootedAtFreshLocal(p, star.X, freshVars, freshEsc)
				}
			}
		}
		hitSt, fld := lhsRootFamilyField(p, expr, allProtected)
		if hitSt == nil {
			return true
		}
		if freshstruct.IsRootedAtFreshLocal(p, expr, freshVars, freshEsc) {
			return true
		}
		if !inAllowedWriter {
			return false
		}
		if family[hitSt] && fld != nil && fld.Exported() && !allowExportedWriteInCone {
			return false
		}
		return true
	}

	valid := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			syncEncl := idx.SyncEnclFuncDecl(n)
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			freshVars, freshEsc := freshCache.Get(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				if builderExempt[x] {
					return true
				}
				for li, lhs := range x.Lhs {
					if !checkFamilyWriteExpr(lhs, inAllowedWriter, freshVars, freshEsc) {
						valid = false
						return false
					}
					if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX && !freshstruct.IsRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
						if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
							if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
								if len(x.Lhs) != len(x.Rhs) || !isSafeProtectedIfaceElemValue(p, x.Rhs[li], allProtected, isImmPtr) {
									valid = false
									return false
								}
							}
						}
					}
				}
			case *ast.IncDecStmt:
				if !checkFamilyWriteExpr(x.X, inAllowedWriter, freshVars, freshEsc) {
					valid = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkFamilyWriteExpr(x.Key, inAllowedWriter, freshVars, freshEsc)) ||
						(x.Value != nil && !checkFamilyWriteExpr(x.Value, inAllowedWriter, freshVars, freshEsc)) {
						valid = false
						return false
					}
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if ix, isIX := ast.Unparen(be).(*ast.IndexExpr); isIX && !freshstruct.IsRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
							if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
								if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
									valid = false
									return false
								}
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkFamilyWriteExpr(x.Args[0], inAllowedWriter, freshVars, freshEsc) {
								valid = false
								return false
							}
							if (b.Name() == "append" || b.Name() == "copy") && !freshstruct.IsRootedAtFreshLocal(p, x.Args[0], freshVars, freshEsc) {
								if hitSt, _ := lhsRootFamilyField(p, x.Args[0], allProtected); hitSt != nil {
									if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.Args[0])).(*types.Slice); isSl && types.IsInterface(sl.Elem()) {
										if b.Name() == "copy" {
											if len(x.Args) < 2 {
												valid = false
												return false
											}
											if srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected); srcHit == nil || srcFld == nil || srcFld.Exported() {
												valid = false
												return false
											}
										} else if x.Ellipsis.IsValid() {
											if len(x.Args) != 2 {
												valid = false
												return false
											}
											srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected)
											if srcHit == nil || srcFld == nil || srcFld.Exported() {
												valid = false
												return false
											}
										} else {
											for _, elemArg := range x.Args[1:] {
												if !isSafeProtectedIfaceElemValue(p, elemArg, allProtected, isImmPtr) {
													valid = false
													return false
												}
											}
										}
									}
								}
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op != token.AND {
					return true
				}
				if builderExempt[x] || freshstruct.IsRootedAtFreshLocal(p, x.X, freshVars, freshEsc) {
					return true
				}
				if sel, isSel := ast.Unparen(x.X).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal && !syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
						hitFamily := false
						syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
							if family[st] {
								hitFamily = true
							}
						})
						if hitFamily {
							fld, _ := selInfo.Obj().(*types.Var)
							if fld == flagField {
								call, isCall := idx.ParentUnparen(x).(*ast.CallExpr)
								if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != x {
									valid = false
									return false
								}
								if isAtomicUint32Call(p, call, "LoadUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								if inAllowedWriter && isAtomicUint32Call(p, call, "StoreUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								valid = false
								return false
							}
							if fld != nil && !fld.Exported() && !inAllowedWriter &&
								syncEncl != nil && !idx.InFuncLit[x] && !idx.InGoStmt[x] {
								if fldNamed, isFN := types.Unalias(fld.Type()).(*types.Named); isFN && casHelperStructs[fldNamed] != nil {
									valid = false
									return false
								}
								if _, isPtr := types.Unalias(fld.Type()).(*types.Pointer); !isPtr {
									if subRef, _, subSt, okSub := syntaxutil.TypeRefOfStructFull(fld.Type()); okSub && subRef.Valid() && subSt.NumFields() > 0 &&
										funcEstablishesOnceInitBefore(p, idx, syncEncl, sel.X, x.Pos(), rootNamed, flagField, onceFn, fastInitMethods) {
										guardOK := true
										syntaxutil.ForEachValueContainedStructType(fld.Type(), func(vt types.Type) {
											if vRef, _, vSt, okV := syntaxutil.TypeRefOfStructFull(vt); okV && vSt.NumFields() > 0 {
												if !vRef.Valid() {
													guardOK = false
													return
												}
												guardSet[vRef] = true
											}
										})
										if guardOK {
											guardSet[subRef] = true
											if exempt != nil {
												exempt[x] = true
											}
											return true
										}
									}
								}
							}
							valid = false
							return false
						}
					}
				}
				if hitSt, _ := lhsRootFamilyField(p, x.X, allProtected); hitSt != nil {
					valid = false
					return false
				}
			}
			return true
		})
	}
	if !valid {
		return nil, false
	}

	if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			hitSt, fld := lhsRootFamilyField(p, containerExpr, allProtected)
			return hitSt != nil && fld != nil && !fld.Exported()
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false, false
			}
			if refconfine.IsInsideExemptWriteOrAddr(idx, sel, builderExempt) {
				return false, false
			}
			syncEncl := idx.SyncEnclFuncDecl(sel)
			freshVars, freshEsc := freshCache.Get(syncEncl)
			if freshstruct.IsRootedAtFreshLocal(p, sel, freshVars, freshEsc) {
				return false, false
			}
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			fld, _ := selInfo.Obj().(*types.Var)
			hitProtected := false
			hitExportedFamily := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if allProtected[hop] {
					hitProtected = true
				}
				if family[hop] && fld != nil && fld.Exported() {
					hitExportedFamily = true
				}
			})
			if !hitProtected {
				return false, false
			}
			if inAllowedWriter && !(hitExportedFamily && !allowExportedWriteInCone) {
				return false, false
			}
			ft := selInfo.Type()
			if fn, isFN := types.Unalias(ft).(*types.Named); isFN && casHelperStructs[fn] != nil {
				return false, false
			}
			if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && syntaxutil.IsReflectTypeOfCall(p, call)
		},
	}) {
		return nil, false
	}
	var guardTypes []syntaxutil.TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]syntaxutil.TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	}
	return guardTypes, true
}

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

func funcEstablishesOnceInitBefore(
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

func hasDeprecatedExtensionFields(family map[*types.Named]bool) bool {
	for n := range family {
		st, ok := n.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		hasExt, hasTag := false, false
		for i := 0; i < st.NumFields(); i++ {
			switch st.Field(i).Name() {
			case "ExtendedType":
				hasExt = true
			case "ExtensionType":
				hasTag = true
			}
		}
		if hasExt && hasTag {
			return true
		}
	}
	return false
}

func lhsRootFamilyField(p *packages.Package, expr ast.Expr, family map[*types.Named]bool) (*types.Named, *types.Var) {
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				var matched *types.Named
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if matched == nil && family[st] {
						matched = st
					}
				})
				if matched != nil {
					fld, _ := selInfo.Obj().(*types.Var)
					return matched, fld
				}
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		default:
			return nil, nil
		}
	}
}

func isFieldMutexCallStmt(p *packages.Package, st ast.Stmt, recvVar, muField *types.Var, method string, wantDefer bool) bool {
	var callExpr ast.Expr
	if wantDefer {
		ds, ok := st.(*ast.DeferStmt)
		if !ok {
			return false
		}
		callExpr = ds.Call
	} else {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			return false
		}
		callExpr = es.X
	}
	call, ok := ast.Unparen(callExpr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	msel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || msel.Sel.Name != method {
		return false
	}
	fn, ok := p.TypesInfo.Uses[msel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
		return false
	}
	fsel, ok := ast.Unparen(msel.X).(*ast.SelectorExpr)
	return ok && syntaxutil.IsIdentUsingObj(p.TypesInfo, fsel.X, recvVar) && p.TypesInfo.Uses[fsel.Sel] == muField
}

func exprMentionsFieldOnRecv(p *packages.Package, expr ast.Expr, recvVar, fld *types.Var) bool {
	hit := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, recvVar) && p.TypesInfo.Uses[sel.Sel] == fld {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func isAtomicUint32Call(p *packages.Package, call *ast.CallExpr, name string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic"
}

func isAddrOfRecvField(p *packages.Package, expr ast.Expr, recvVar, fld *types.Var) bool {
	un, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	sel, ok := ast.Unparen(un.X).(*ast.SelectorExpr)
	return ok && syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, recvVar) && p.TypesInfo.Uses[sel.Sel] == fld
}
