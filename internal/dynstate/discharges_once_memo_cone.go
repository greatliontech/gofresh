package dynstate

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyOnceMemoConstructor(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgFresh *freshstruct.PkgFreshConstructors,
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
				if isTrueStdlibInPkg(p, pkgPath) && auditset.DeterministicStdCallTraits(pkgPath, val.CalleeFunc.Name()).ReadOnlySliceCopy &&
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
	freshCache *freshstruct.FreshLocalsCache,
	pkgFresh *freshstruct.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	ownerNamed *types.Named,
	ownerRef syntaxutil.TypeRef,
	getterFD *ast.FuncDecl,
	memoFields map[*types.Var]bool,
	memoRHSByField map[*types.Var][]ast.Expr,
) ([]syntaxutil.TypeRef, map[syntaxutil.TypeRef]bool, map[*types.Named]bool, bool, bool) {
	guardSet := map[syntaxutil.TypeRef]bool{ownerRef: true}
	visitedStructs := map[*types.Named]bool{}
	unexpRefStructs := map[*types.Named]bool{}
	var unexportedRefFields []struct {
		owner *types.Named
		field *types.Var
	}
	needsErrorProof := false

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
		if allowTopError && isUniverseErrorType(t) {
			needsErrorProof = true
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
			return nil, nil, nil, false, false
		}
	}
	if getterFn, ok := p.TypesInfo.Defs[getterFD.Name].(*types.Func); ok && getterFn != nil {
		if sig, okSig := getterFn.Type().(*types.Signature); okSig {
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if !checkExportedClosureType(sig.Results().At(ri).Type(), true) {
					return nil, nil, nil, false, false
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
					return nil, nil, nil, false, false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || callee.Pkg() != p.Types {
					return nil, nil, nil, false, false
				}
				cfd := funcDecls[callee]
				if cfd == nil || !pkgFresh.ReturnsFreshAllocation(cfd) || !pkgFresh.IsFieldFreshInCone(cfd, uf) {
					return nil, nil, nil, false, false
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
				return nil, nil, nil, false, false
			}
			syncFD := idx.SyncEnclFuncDecl(sel)
			fresh, freshEsc := freshCache.Get(syncFD)
			if freshstruct.IsRootedAtFreshLocal(p, sel, fresh, freshEsc) || pkgFresh.IsFreshMutationTarget(syncFD, sel) {
				continue
			}
			if refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, sel) {
				return nil, nil, nil, false, false
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
				return nil, nil, nil, false, false
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
	return out, guardSet, unexpRefStructs, needsErrorProof, true
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

func verifyOnceMemoComputeCone(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgConf *packageConfinementSummary,
	funcDecls map[*types.Func]*ast.FuncDecl,
	isSettledConeGlobal func(*types.Var) bool,
	ownerNamed *types.Named,
	getterRecv *types.Var,
	inputFields map[*types.Var]bool,
	memoFields map[*types.Var]bool,
	memoAssigns []*ast.AssignStmt,
	doLit *ast.FuncLit,
	needsErrorProof bool,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	doSig, _ := p.TypesInfo.TypeOf(doLit).(*types.Signature)
	doIR := fc.litBody(p, doLit)
	if doSig == nil || doIR == nil {
		return false
	}

	coneFuncs, localClosures, _, ok := verifyDeterministicComputeCone(
		p,
		fc,
		idx,
		funcDecls,
		doSig,
		doIR,
		conePolicy{
			audited:           audited,
			allowMapRange:     false,
			allowedGlobalRead: isSettledConeGlobal,
		},
	)
	if !ok {
		return false
	}

	// Verify getterRecv references inside doLit.Body (memoAssigns LHS + confined inputField reads).
	if !verifyOnceMemoRecvUsesInBody(
		audited,
		p,
		fc,
		pkgConf,
		ownerNamed,
		getterRecv,
		nil,
		true,
		memoFields,
		inputFields,
		memoAssigns,
		doLit,
		doIR,
		inputParamDeps,
	) {
		return false
	}

	_ = needsErrorProof
	return verifyFlowIRErrorOrigins(
		p,
		fc,
		doSig,
		doIR,
		coneFuncs,
		localClosures,
		errorOriginConfig{
			memoFields:  memoFields,
			memoAssigns: memoAssigns,
		},
	)
}

func typeReachesUniverseError(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if isUniverseErrorType(t) {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, ok := t.(*types.Named); ok {
			for i := 0; i < named.TypeArgs().Len(); i++ {
				walk(named.TypeArgs().At(i))
			}
		}
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
		}
	}
	walk(root)
	return hit
}

func verifyOnceMemoSiblingMethod(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgFresh *freshstruct.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	isSettledConeGlobal func(*types.Var) bool,
	ownerNamed *types.Named,
	getterFn *types.Func,
	ptrMethodSet map[*types.Func]*ast.FuncDecl,
	guardSet map[syntaxutil.TypeRef]bool,
	unexpRefStructs map[*types.Named]bool,
	mfn *types.Func,
	mfd *ast.FuncDecl,
) bool {
	mSig, ok := mfn.Type().(*types.Signature)
	mBody := fc.funcBody(p, mfd)
	if !ok || mBody == nil || mSig.TypeParams().Len() > 0 || mSig.RecvTypeParams().Len() > 0 {
		return false
	}

	trusted := make(map[*types.Func]bool, 1+len(ptrMethodSet))
	trusted[getterFn] = true
	for pm := range ptrMethodSet {
		trusted[pm] = true
	}

	sibConeFuncs, localClosures, sawErrorSink, ok := verifyDeterministicComputeCone(
		p,
		fc,
		idx,
		funcDecls,
		mSig,
		mBody,
		conePolicy{
			audited:                audited,
			allowMapRange:          true,
			disallowedLitStructs:   unexpRefStructs,
			allowConfinedIfaceVars: true,
			trustedPeerFuncs:       trusted,
			allowedGlobalRead:      isSettledConeGlobal,
		},
	)
	if !ok {
		return false
	}

	allowRootErrParams := !mfn.Exported() && isUnexportedInternalOnlyPtrMethod(p, idx, ptrMethodSet, mfn)
	errCfg := errorOriginConfig{
		trustedErrCallees:              trusted,
		allowConfinedNonErrIfaceParams: true,
		allowRootErrParams:             allowRootErrParams,
	}

	// Verify every result slot of mfn: error origins + guarded or fresh-per-call closure.
	checkedErrors := false
	for ri := 0; ri < mSig.Results().Len(); ri++ {
		rt := mSig.Results().At(ri).Type()
		if refconfine.TypeCarriesSignature(rt) || typeReachesNamedOrSyncOnce(rt, ownerNamed) {
			return false
		}
		if isScalarOrScalarArrayType(rt) {
			continue
		}
		if isUniverseErrorType(rt) {
			if !checkedErrors {
				if !verifyFlowIRErrorOrigins(p, fc, mSig, mBody, sibConeFuncs, localClosures, errCfg) {
					return false
				}
				checkedErrors = true
			}
			continue
		}
		if refconfine.TypeMayCarryUnknownDynamic(audited, rt) {
			return false
		}
		if isSingleGuardSetStructOrPtr(rt, guardSet) {
			continue
		}
		if ri == 0 && siblingReturnsFreshStructValue(audited, pkgFresh, mfd, rt, ownerNamed) {
			continue
		}
		if sl, isSL := types.Unalias(rt).Underlying().(*types.Slice); isSL && isScalarBasicType(sl.Elem()) {
			if funcSlotReturnsFreshScalarSlice(p, fc, idx, funcDecls, mfd, ri, map[*ast.FuncDecl]bool{}) {
				continue
			}
		}
		return false
	}
	if sawErrorSink && !checkedErrors {
		if !verifyFlowIRErrorOrigins(p, fc, mSig, mBody, sibConeFuncs, localClosures, errCfg) {
			return false
		}
	}
	return true
}

func isUnexportedInternalOnlyPtrMethod(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ptrMethodSet map[*types.Func]*ast.FuncDecl,
	mfn *types.Func,
) bool {
	if mfn == nil || mfn.Exported() {
		return false
	}
	ptrDeclSet := make(map[*ast.FuncDecl]bool, len(ptrMethodSet))
	for _, fd := range ptrMethodSet {
		if fd != nil {
			ptrDeclSet[fd] = true
		}
	}
	for _, uid := range idx.UsesOf[mfn] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return false
		}
		si := p.TypesInfo.Selections[sel]
		if si == nil || si.Kind() != types.MethodVal {
			return false
		}
		call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel {
			return false
		}
		enclFD := idx.SyncEnclFuncDecl(call)
		if enclFD == nil || !ptrDeclSet[enclFD] {
			return false
		}
	}
	return true
}

func isScalarOrScalarArrayType(t types.Type) bool {
	if isScalarBasicType(t) {
		return true
	}
	if arr, ok := types.Unalias(t).Underlying().(*types.Array); ok {
		return isScalarOrScalarArrayType(arr.Elem())
	}
	return false
}

func isSingleGuardSetStructOrPtr(t types.Type, guardSet map[syntaxutil.TypeRef]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.TypeArgs().Len() > 0 {
		return false
	}
	named = named.Origin()
	if _, isSt := named.Underlying().(*types.Struct); !isSt {
		return false
	}
	ref := syntaxutil.TypeRef{Pkg: named.Obj().Pkg().Path(), Name: named.Obj().Name()}
	return ref.Valid() && guardSet[ref]
}

func siblingReturnsFreshStructValue(
	audited bool,
	pkgFresh *freshstruct.PkgFreshConstructors,
	mfd *ast.FuncDecl,
	rt types.Type,
	ownerNamed *types.Named,
) bool {
	if pkgFresh == nil || mfd == nil || !pkgFresh.ReturnsFreshAllocation(mfd) {
		return false
	}
	t := types.Unalias(rt)
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		ft := f.Type()
		if refconfine.TypeMayCarryUnknownDynamic(audited, ft) ||
			refconfine.TypeCarriesSignature(ft) ||
			typeReachesNamedOrSyncOnce(ft, ownerNamed) {
			return false
		}
		if !refconfine.TypeCarriesMutableRef(ft) {
			continue
		}
		if !pkgFresh.IsFieldFreshInCone(mfd, f) {
			return false
		}
		// Nested elements inside a fresh container field must themselves carry no
		// unverified inner mutable references (e.g. []KnobUsage where KnobUsage is pure strings).
		switch u := types.Unalias(ft).Underlying().(type) {
		case *types.Slice:
			if refconfine.TypeCarriesMutableRef(u.Elem()) || syntaxutil.ContainsUintptr(u.Elem()) {
				return false
			}
		case *types.Map:
			if !isScalarBasicType(u.Key()) || refconfine.TypeCarriesMutableRef(u.Elem()) || syntaxutil.ContainsUintptr(u.Elem()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func funcSlotReturnsFreshScalarSlice(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	funcDecls map[*types.Func]*ast.FuncDecl,
	fd *ast.FuncDecl,
	slotIdx int,
	seen map[*ast.FuncDecl]bool,
) bool {
	if fd == nil || fd.Body == nil || slotIdx < 0 || seen[fd] {
		return false
	}
	b := fc.funcBody(p, fd)
	if b == nil || b.HasGoto {
		return false
	}
	fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
	if fn == nil {
		return false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || slotIdx >= sig.Results().Len() {
		return false
	}
	sl, isSL := types.Unalias(sig.Results().At(slotIdx).Type()).Underlying().(*types.Slice)
	if !isSL || !isScalarBasicType(sl.Elem()) {
		return false
	}

	seen[fd] = true
	defer delete(seen, fd)

	var allOps []*flowir.Op
	var collectOps func(cur *flowir.Body)
	collectOps = func(cur *flowir.Body) {
		if cur == nil {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			allOps = append(allOps, op)
			if op.RangeBody != nil {
				collectOps(op.RangeBody)
			}
		}
	}
	collectOps(b)

	isDirectIntraPkgCallFreshSlot := func(v *flowir.Value, cSlot int, forbidVar *types.Var) bool {
		if v == nil || v.Kind != flowir.ValCall || v.CalleeFunc == nil ||
			v.CalleeFunc.Origin() != v.CalleeFunc || v.CalleeFunc.Pkg() != p.Types {
			return false
		}
		switch v.CallKind {
		case flowir.CallPlain:
			if v.IsMethodExprCall {
				return false
			}
		case flowir.CallMethod:
			if v.Selection != nil && types.IsInterface(v.Selection.Recv()) {
				return false
			}
		default:
			return false
		}
		if forbidVar != nil {
			if v.Recv != nil && flowir.ValueMentionsVar(v.Recv, forbidVar) {
				return false
			}
			for _, a := range v.Args {
				if a != nil && flowir.ValueMentionsVar(a, forbidVar) {
					return false
				}
			}
		}
		return funcSlotReturnsFreshScalarSlice(p, fc, idx, funcDecls, funcDecls[v.CalleeFunc], cSlot, seen)
	}

	var isFreshSliceExpr func(v *flowir.Value, selfVar *types.Var, freshLocals map[*types.Var]bool) (*ast.Ident, bool)
	isFreshSliceExpr = func(v *flowir.Value, selfVar *types.Var, freshLocals map[*types.Var]bool) (*ast.Ident, bool) {
		if v == nil {
			return nil, false
		}
		switch v.Kind {
		case flowir.ValScalarLitOrConst:
			if syntaxutil.IsNilIdent(p.TypesInfo, v.Raw) {
				return nil, true
			}
			return nil, false
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootConstOrNil {
				return nil, true
			}
			if v.Place.IsBareVar() && v.Place.Root == flowir.RootLocal && v.Place.Obj != nil {
				if (selfVar != nil && v.Place.Obj == selfVar) || freshLocals[v.Place.Obj] {
					id, ok := ast.Unparen(v.Place.Raw).(*ast.Ident)
					return id, ok
				}
			}
			return nil, false
		case flowir.ValConvert:
			if !v.IsTypeAssert && v.Arg != nil && syntaxutil.IsNilIdent(p.TypesInfo, v.Arg.Raw) {
				return nil, true
			}
			return nil, false
		case flowir.ValAllocFresh:
			if v.AllocKind == flowir.AllocMake || v.AllocKind == flowir.AllocCompositeLit {
				return nil, true
			}
			return nil, false
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" && len(v.Args) >= 1 {
				for _, a := range v.Args[1:] {
					if selfVar != nil && a != nil && flowir.ValueMentionsVar(a, selfVar) {
						return nil, false
					}
				}
				if v.Args[0] != nil && syntaxutil.IsTypedNilSliceConv(p, v.Args[0].Raw) {
					return nil, true
				}
				return isFreshSliceExpr(v.Args[0], selfVar, freshLocals)
			}
			if v.CalleeSig != nil && v.CalleeSig.Results().Len() == 1 && isDirectIntraPkgCallFreshSlot(v, 0, selfVar) {
				return nil, true
			}
		}
		return nil, false
	}

	isAllowedLocalSliceReadIdent := func(uid *ast.Ident) bool {
		par := idx.ParentUnparen(uid)
		call, isCall := par.(*ast.CallExpr)
		if !isCall || call.Ellipsis.IsValid() || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != uid {
			return false
		}
		if bn := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(call.Fun)); bn != nil {
			return bn.Name() == "len" || bn.Name() == "cap"
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if callee == nil || callee.Pkg() == nil {
			return false
		}
		pkgPath := callee.Pkg().Path()
		return isTrueStdlibInPkg(p, pkgPath) && auditset.DeterministicStdCallTraits(pkgPath, callee.Name()).InPlaceContainerMutate
	}

	candidates := map[*types.Var]bool{}
	for _, op := range allOps {
		if op.Kind != flowir.OpAssign {
			continue
		}
		for _, dst := range op.Dsts {
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
				if lvSl, okSL := types.Unalias(dst.Obj.Type()).Underlying().(*types.Slice); okSL && isScalarBasicType(lvSl.Elem()) {
					candidates[dst.Obj] = true
				}
			}
		}
	}

	for {
		evicted := false
		for lv := range candidates {
			consumedReads := map[*ast.Ident]bool{}
			writesOK := true
			for _, op := range allOps {
				switch op.Kind {
				case flowir.OpAssign:
					for di, dst := range op.Dsts {
						if dst.Obj != lv {
							continue
						}
						if !dst.IsBareVar() {
							writesOK = false
							break
						}
						switch op.AssignKind {
						case flowir.AssignZeroDecl:
						case flowir.AssignPlain:
							if di >= len(op.Srcs) {
								writesOK = false
								break
							}
							rid, ok := isFreshSliceExpr(op.Srcs[di], lv, candidates)
							if !ok {
								writesOK = false
								break
							}
							if rid != nil {
								consumedReads[rid] = true
							}
							if lid, ok := ast.Unparen(dst.Raw).(*ast.Ident); ok {
								consumedReads[lid] = true
							}
						case flowir.AssignMulti:
							if len(op.Srcs) != 1 || !isDirectIntraPkgCallFreshSlot(op.Srcs[0], di, lv) {
								writesOK = false
								break
							}
							if lid, ok := ast.Unparen(dst.Raw).(*ast.Ident); ok {
								consumedReads[lid] = true
							}
						default:
							writesOK = false
						}
					}
				case flowir.OpReturn:
					if slotIdx < len(op.Results) && op.Results[slotIdx] != nil {
						if rid, ok := isFreshSliceExpr(op.Results[slotIdx], nil, candidates); ok && rid != nil && p.TypesInfo.Uses[rid] == lv {
							consumedReads[rid] = true
						}
					}
				}
				if !writesOK {
					break
				}
			}
			if writesOK {
				for _, uid := range idx.UsesOf[lv] {
					if consumedReads[uid] || isAllowedLocalSliceReadIdent(uid) {
						continue
					}
					writesOK = false
					break
				}
			}
			if !writesOK {
				delete(candidates, lv)
				evicted = true
			}
		}
		if !evicted {
			break
		}
	}

	sawReturn := false
	for _, op := range allOps {
		if op.Kind != flowir.OpReturn {
			continue
		}
		sawReturn = true
		if len(op.Results) == 1 && sig.Results().Len() > 1 {
			if !isDirectIntraPkgCallFreshSlot(op.Results[0], slotIdx, nil) {
				return false
			}
			continue
		}
		if slotIdx >= len(op.Results) {
			return false
		}
		if _, ok := isFreshSliceExpr(op.Results[slotIdx], nil, candidates); !ok {
			return false
		}
	}
	return sawReturn
}
