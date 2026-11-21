package dynstate

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyOnceMemoConstructor(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgFresh *freshalloc.PkgFreshConstructors,
	fd *ast.FuncDecl,
	sig *types.Signature,
	named *types.Named,
	inputFields map[*types.Var]bool,
) bool {
	ctorBody := fc.funcBody(p, fd)
	if !pkgFresh.ReturnsFreshAllocation(fd) || ctorBody == nil || ctorBody.HasGoto {
		return false
	}
	paramSet := map[*types.Var]bool{}
	mutableParams := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if refconfine.TypeMayCarryUnknownDynamic(audited, pv.Type()) ||
			refconfine.TypeCarriesSignature(pv.Type()) ||
			typeReachesNamedOrSyncOnce(pv.Type(), named) {
			return false
		}
		paramSet[pv] = true
		if refconfine.TypeCarriesMutableRef(pv.Type()) {
			mutableParams[pv] = true
		}
	}

	b := fc.funcBody(p, fd)
	if b == nil {
		return false
	}
	var matchAllowedInputInit func(val *flowir.Value) (*ast.Ident, bool)
	matchAllowedInputInit = func(val *flowir.Value) (*ast.Ident, bool) {
		if val == nil {
			return nil, false
		}
		switch val.Kind {
		case flowir.ValScalarLitOrConst:
			return nil, true
		case flowir.ValPlace:
			if val.Place.Root == flowir.RootConstOrNil {
				return nil, true
			}
			if !val.Place.IsBareVar() || !paramSet[val.Place.Obj] {
				return nil, false
			}
			if mutableParams[val.Place.Obj] {
				id, ok := ast.Unparen(val.Place.Raw).(*ast.Ident)
				return id, ok
			}
			return nil, true
		case flowir.ValConvert:
			if val.IsTypeAssert || val.Arg == nil {
				return nil, false
			}
			if !refconfine.TypeCarriesMutableRef(val.Arg.Type) && !refconfine.TypeCarriesMutableRef(val.Type) {
				return matchAllowedInputInit(val.Arg)
			}
			if (syntaxutil.IsByteSliceType(val.Type) && isBasicStringType(val.Arg.Type)) ||
				(isBasicStringType(val.Type) && syntaxutil.IsByteSliceType(val.Arg.Type)) {
				return matchAllowedInputInit(val.Arg)
			}
			return nil, false
		case flowir.ValCall:
			if val.CallKind == flowir.CallPlain && !val.IsMethodExprCall && val.CalleeFunc != nil && val.CalleeFunc.Pkg() != nil {
				pkgPath := val.CalleeFunc.Pkg().Path()
				if syntaxutil.IsTrueStdlibInPkg(p, pkgPath) && auditset.DeterministicStdCallTraits(pkgPath, val.CalleeFunc.Name()).ReadOnlySliceCopy &&
					!val.Ellipsis && len(val.Args) == 1 {
					return matchAllowedInputInit(val.Args[0])
				}
			}
			if val.CallKind == flowir.CallBuiltin && val.BuiltinName == "append" && val.Ellipsis && len(val.Args) == 2 {
				if val.Args[0] != nil && syntaxutil.IsTypedNilSliceConv(p, val.Args[0].Raw) {
					return matchAllowedInputInit(val.Args[1])
				}
			}
		}
		return nil, false
	}

	allowedParamUses := map[*ast.Ident]bool{}
	checkCompositeInit := func(alloc *flowir.Value) bool {
		if alloc == nil || alloc.Kind != flowir.ValAllocFresh || alloc.AllocKind != flowir.AllocCompositeLit ||
			!syntaxutil.IsPtrToNamed(alloc.Type, named) {
			return false
		}
		for _, elt := range alloc.CompositeElts {
			if elt.Field == nil || !inputFields[elt.Field] {
				return false
			}
			id, ok := matchAllowedInputInit(elt.Value)
			if !ok {
				return false
			}
			if id != nil {
				allowedParamUses[id] = true
			}
		}
		return true
	}

	var ctorLocal *types.Var
	returnedDirectLit := false
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case flowir.OpReturn:
			if len(op.Results) != 1 {
				return false
			}
			res := op.Results[0]
			if res.Kind == flowir.ValAllocFresh && res.AllocKind == flowir.AllocCompositeLit {
				if ctorLocal != nil || !checkCompositeInit(res) {
					return false
				}
				returnedDirectLit = true
				continue
			}
			if res.Kind == flowir.ValPlace && res.Place.IsBareVar() && res.Place.Root == flowir.RootLocal &&
				ctorLocal != nil && res.Place.Obj == ctorLocal {
				continue
			}
			return false
		case flowir.OpAssign:
			if op.AssignKind != flowir.AssignPlain || len(op.Dsts) != 1 || len(op.Srcs) != 1 {
				return false
			}
			dst := op.Dsts[0]
			src := op.Srcs[0]
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
				if returnedDirectLit || ctorLocal != nil || !checkCompositeInit(src) {
					return false
				}
				ctorLocal = dst.Obj
				continue
			}
			if dst.Root == flowir.RootLocal && ctorLocal != nil && dst.Obj == ctorLocal &&
				len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && inputFields[dst.Projs[0].Field] {
				id, ok := matchAllowedInputInit(src)
				if !ok {
					return false
				}
				if id != nil {
					allowedParamUses[id] = true
				}
				continue
			}
			return false
		default:
			return false
		}
	}

	// Every use of any mutable-reach parameter in C must be one of the allowed inputField initializers.
	for pv := range mutableParams {
		for _, uid := range idx.UsesOf[pv] {
			if !allowedParamUses[uid] {
				return false
			}
		}
	}
	return true
}

func verifyOnceMemoResultClosure(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	pkgFresh *freshalloc.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	ownerNamed *types.Named,
	ownerRef syntaxutil.TypeRef,
	getterFD *ast.FuncDecl,
	memoFields map[*types.Var]bool,
	memoRHSByField map[*types.Var][]ast.Expr,
) ([]syntaxutil.TypeRef, map[syntaxutil.TypeRef]bool, map[*types.Named]bool, bool) {
	guardSet := map[syntaxutil.TypeRef]bool{ownerRef: true}
	visitedStructs := map[*types.Named]bool{}
	unexpRefStructs := map[*types.Named]bool{}
	var unexportedRefFields []struct {
		owner *types.Named
		field *types.Var
	}

	var checkExportedClosureType func(t types.Type, allowTopError bool) bool
	var checkReachableStruct func(sn *types.Named) bool

	checkReachableStruct = func(sn *types.Named) bool {
		if sn == nil || sn.Obj() == nil || sn.Obj().Pkg() == nil || sn.TypeArgs().Len() > 0 {
			return false
		}
		sn = sn.Origin()
		if sn == ownerNamed || syntaxutil.IsNamedInPkg(sn, "sync", "Once") {
			return false
		}
		st, ok := sn.Underlying().(*types.Struct)
		if !ok || st.NumFields() == 0 {
			return false
		}
		ref := syntaxutil.TypeRef{Pkg: sn.Obj().Pkg().Path(), Name: sn.Obj().Name()}
		if !ref.Valid() {
			return false
		}
		guardSet[ref] = true
		if visitedStructs[sn] {
			return true
		}
		visitedStructs[sn] = true

		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if typeReachesNamedOrSyncOnce(f.Type(), ownerNamed) {
				return false
			}
			if f.Exported() {
				if !checkExportedClosureType(f.Type(), false) {
					return false
				}
				continue
			}
			// Unexported fields require defining-package visibility to prove freshness + confinement.
			if sn.Obj().Pkg() != p.Types {
				return false
			}
			if !checkUnexportedClosureType(f.Type(), checkReachableStruct) {
				return false
			}
			if refconfine.TypeCarriesMutableRef(f.Type()) {
				unexpRefStructs[sn] = true
				unexportedRefFields = append(unexportedRefFields, struct {
					owner *types.Named
					field *types.Var
				}{owner: sn, field: f})
			}
		}
		return true
	}

	checkExportedClosureType = func(t types.Type, allowTopError bool) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if allowTopError && syntaxutil.IsErrorType(t) {
			return true
		}
		if named, ok := t.(*types.Named); ok {
			if _, isSt := named.Underlying().(*types.Struct); isSt {
				return checkReachableStruct(named)
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return u.Kind() != types.UnsafePointer && u.Kind() != types.Uintptr && u.Kind() != types.Invalid
		case *types.Pointer:
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		case *types.Slice:
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		case *types.Array:
			if isScalarBasicType(u.Elem()) {
				return true
			}
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		default:
			return false
		}
	}

	for mf := range memoFields {
		if !checkExportedClosureType(mf.Type(), true) {
			return nil, nil, nil, false
		}
	}
	if getterFn, ok := p.TypesInfo.Defs[getterFD.Name].(*types.Func); ok && getterFn != nil {
		if sig, okSig := getterFn.Type().(*types.Signature); okSig {
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if !checkExportedClosureType(sig.Results().At(ri).Type(), true) {
					return nil, nil, nil, false
				}
			}
		}
	}

	// Prove every unexported reference/container field in T's reachable struct closure
	// is freshly constructed in each memo RHS compute cone AND read-only confined across p.
	for _, entry := range unexportedRefFields {
		uf := entry.field
		for mf, rhsList := range memoRHSByField {
			if !typeReachesStruct(mf.Type(), entry.owner) {
				continue
			}
			for _, rhs := range rhsList {
				call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
				if !isCall {
					return nil, nil, nil, false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || callee.Pkg() != p.Types {
					return nil, nil, nil, false
				}
				cfd := funcDecls[callee]
				if cfd == nil || !pkgFresh.ReturnsFreshAllocation(cfd) || !pkgFresh.IsFieldFreshInCone(cfd, uf) {
					return nil, nil, nil, false
				}
			}
		}

		readSels := map[*ast.SelectorExpr]bool{}
		for _, uid := range idx.UsesOf[uf] {
			if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
				continue
			}
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid {
				return nil, nil, nil, false
			}
			syncFD := idx.SyncEnclFuncDecl(sel)
			fresh, freshEsc := freshCache.Get(syncFD)
			if freshalloc.IsRootedAtFreshLocal(p, sel, fresh, freshEsc) || pkgFresh.IsFreshMutationTarget(syncFD, sel) {
				continue
			}
			if refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, sel) {
				return nil, nil, nil, false
			}
			readSels[sel] = true
		}
		if len(readSels) > 0 {
			if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
				Index:                         idx,
				AllowReturnFromUnexportedFunc: false,
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
					if !isSel || !readSels[sel] {
						return false, false
					}
					return refconfine.IsDirectMutableRef(p.TypesInfo.TypeOf(sel)), true
				},
			}) {
				return nil, nil, nil, false
			}
		}
	}

	out := make([]syntaxutil.TypeRef, 0, len(guardSet))
	for ref := range guardSet {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b syntaxutil.TypeRef) int {
		if a.Key() < b.Key() {
			return -1
		}
		if a.Key() > b.Key() {
			return 1
		}
		return 0
	})
	return out, guardSet, unexpRefStructs, true
}

func checkUnexportedClosureType(t types.Type, checkStruct func(*types.Named) bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			return checkStruct(named)
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Pointer:
		if isScalarBasicType(u.Elem()) {
			return true
		}
		elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
		return ok && checkStruct(elemNamed)
	case *types.Slice:
		return checkUnexportedClosureType(u.Elem(), checkStruct)
	case *types.Array:
		return checkUnexportedClosureType(u.Elem(), checkStruct)
	case *types.Map:
		return isScalarBasicType(u.Key()) && checkUnexportedClosureType(u.Elem(), checkStruct)
	default:
		return false
	}
}
