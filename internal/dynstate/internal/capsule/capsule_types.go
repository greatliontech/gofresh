package capsule

import (
	"context"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyCapsuleFieldsAndCollectChildren(
	p *packages.Package,
	family map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedCapsuleRoots map[*types.Named]bool,
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
			if family[elemNamed] || verifiedCapsuleRoots[elemNamed] {
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

func verifyReadOnlyCapsuleType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	st *types.Struct,
	builderExempt map[ast.Node]bool,
	verifiedCapsuleRoots map[*types.Named]bool,
) bool {
	if st.NumFields() == 0 {
		return false
	}
	family := map[*types.Named]bool{named: true}
	childProtected, okFields := verifyCapsuleFieldsAndCollectChildren(p, family, nil, verifiedCapsuleRoots, false)
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
		return ok && (allProtected[elem] || verifiedCapsuleRoots[elem])
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

func verifyLockedOnceCapsuleType(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	ownerRef syntaxutil.TypeRef,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	builderHelperIdents map[*ast.Ident]bool,
	verifiedCapsuleRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) (syntaxutil.LazyOnceCapsuleType, map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []syntaxutil.ConditionalStructMutation, bool) {
	muField, flagField := findUnexportedMutexAndUint32(st)
	if muField == nil || flagField == nil {
		return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
	}

	family := map[*types.Named]bool{named: true}
	var casHelperStructs map[*types.Named]*ast.FuncDecl
	var casNodesExempt map[ast.Node]bool
	var casGuardTypes []syntaxutil.TypeRef
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() && !f.Exported() {
			if emb, ok := types.Unalias(f.Type()).(*types.Named); ok && emb.Obj() != nil && emb.Obj().Pkg() == p.Types {
				if _, isSt := emb.Underlying().(*types.Struct); isSt {
					family[emb] = true
				}
			}
		}
	}
	for famNamed := range family {
		famSt, okSt := famNamed.Underlying().(*types.Struct)
		if !okSt {
			continue
		}
		for j := 0; j < famSt.NumFields(); j++ {
			sf := famSt.Field(j)
			if sf.Exported() {
				continue
			}
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
					if subRef, okSubRef := syntaxutil.TypeRefOfStruct(sub); okSubRef {
						casGuardTypes = append(casGuardTypes, subRef)
					}
					casGuardTypes = append(casGuardTypes, guardsCAS...)
				}
			}
		}
	}

	childProtected, okFields := verifyCapsuleFieldsAndCollectChildren(p, family, casHelperStructs, verifiedCapsuleRoots, true)
	if !okFields {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_capsule_fields", nil)
		return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
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
				emitCapsuleReject(ctx, p, ownerRef.Key(), "multiple_once_init_methods", fd)
				return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
			}
			onceFn = m
		}
	}
	if onceFn == nil {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "missing_once_init_method", nil)
		return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
	}

	onceCone := refconfine.ComputeExclusiveHelperCone(p, idx, onceFn)
	coneGuards, coneConds, okCone := verifyOnceInitConeImmutability(p, idx, ownerRef, onceFn, family, childProtected, verifiedCapsuleRoots, mutatedVars, confinedCacheMaps)
	if !okCone {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "impure_once_init_cone", idx.FuncDecls[onceFn])
		return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
	}

	var builderInitFn *types.Func
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
		if allUsesInBuilder && verifyCapsuleBuilderInitFunc(p, fd, named) {
			if builderInitFn != nil {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "multiple_capsule_init_helpers", fd)
				return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
			}
			builderInitFn = fn
		}
	}
	if builderInitFn != nil {
		if _, okNoAny := verifyCapsuleFieldsAndCollectChildren(p, family, casHelperStructs, verifiedCapsuleRoots, false); !okNoAny {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "init_helper_capsule_exported_any_slice", idx.FuncDecls[builderInitFn])
			return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
		}
	}

	exempt := map[ast.Node]bool{}
	for n := range casNodesExempt {
		exempt[n] = true
	}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	addProtectedAndValueChildrenExempt := func(fd *ast.FuncDecl, root *types.Named) {
		addExemptStructInFunc(exemptByFunc, fd, root)
		syntaxutil.ForEachValueContainedStructType(root, func(vt types.Type) {
			vtNamed, isN := types.Unalias(vt).(*types.Named)
			if !isN || vtNamed.Obj() == nil || vtNamed.Obj().Pkg() != p.Types || vtNamed.Obj().Exported() || casHelperStructs[vtNamed] != nil {
				return
			}
			addExemptStructInFunc(exemptByFunc, fd, vtNamed)
		})
	}
	for fn := range onceCone {
		fd := idx.FuncDecls[fn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "global_mutation_in_once_cone", fd)
			return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
		}
		for famSt := range family {
			addProtectedAndValueChildrenExempt(fd, famSt)
		}
		for chSt := range childProtected {
			addProtectedAndValueChildrenExempt(fd, chSt)
		}
	}
	for casSt, fdCAS := range casHelperStructs {
		addExemptStructInFunc(exemptByFunc, fdCAS, casSt)
	}
	var initHelper syntaxutil.FuncKey
	if builderInitFn != nil {
		for famSt := range family {
			addProtectedAndValueChildrenExempt(idx.FuncDecls[builderInitFn], famSt)
		}
		for chSt := range childProtected {
			addProtectedAndValueChildrenExempt(idx.FuncDecls[builderInitFn], chSt)
		}
		initHelper = syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: builderInitFn.Name()}
	}

	guardTypes, expGuardFields, rejReason, rejNode, okDisc := verifyLockedStructFamilyDiscipline(
		p, idx, freshCache, named, family, childProtected, casHelperStructs, verifiedCapsuleRoots,
		muField, flagField, onceFn, onceCone, builderInitFn, exempt, builderExempt,
	)
	if !okDisc {
		emitCapsuleReject(ctx, p, ownerRef.Key(), rejReason, rejNode)
		return syntaxutil.LazyOnceCapsuleType{}, nil, nil, nil, false
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
	fact := syntaxutil.LazyOnceCapsuleType{
		Type:                     ownerRef,
		HasExportedReflectType:   syntaxutil.StructHasExportedReflectTypeField(st),
		InitHelper:               initHelper,
		GuardTypes:               guardTypes,
		ExportedWriteGuardFields: expGuardFields,
	}
	return fact, exempt, exemptByFunc, coneConds, true
}

func verifyCapsuleBuilderInitFunc(p *packages.Package, fd *ast.FuncDecl, capNamed *types.Named) bool {
	if fd.Type == nil || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 || len(fd.Type.Params.List[0].Names) == 0 {
		return false
	}
	if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
		return false
	}
	param0, _ := p.TypesInfo.Defs[fd.Type.Params.List[0].Names[0]].(*types.Var)
	if param0 == nil || !syntaxutil.IsPtrToNamed(param0.Type(), capNamed) {
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
				if selInfo == nil || selInfo.Kind() != types.FieldVal || !syntaxutil.IsPtrToNamed(selInfo.Recv(), capNamed) || selInfo.Obj().Exported() {
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
