package capsule

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyRawCapsuleBuilderType(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ownerRef syntaxutil.TypeRef,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	exemptReadFields map[*types.Var]bool,
) (syntaxutil.InitBuilderFact, map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []syntaxutil.ConditionalStructMutation, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	hasRawBytes := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			continue
		}
		if syntaxutil.IsAnySliceType(f.Type()) {
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		if _, _, okElem := syntaxutil.SliceElemNamedStruct(f.Type()); okElem {
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		if syntaxutil.IsByteSliceType(f.Type()) {
			hasRawBytes = true
		}
	}
	if !hasRawBytes {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	var buildFn *types.Func
	psetBuilder := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < psetBuilder.Len(); i++ {
		m, okM := psetBuilder.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types {
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		if !m.Exported() {
			continue
		}
		if buildFn != nil {
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		buildFn = m
	}
	if buildFn == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	outIfaceField := syntaxutil.SoleExportedNonEmptyIfaceField(outSt)
	if outIfaceField == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	buildFD := idx.FuncDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	builderFamily := map[*types.Named]bool{}
	for i := 0; i < outSt.NumFields(); i++ {
		f := outSt.Field(i)
		if f.Exported() {
			if _, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type()); okElem && elemNamed.Obj() != nil && elemNamed.Obj().Pkg() == p.Types {
				builderFamily[elemNamed] = true
			}
		}
	}
	if len(builderFamily) == 0 {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	buildReach := map[*types.Func]bool{buildFn: true}
	bQueue := []*types.Func{buildFn}
	for len(bQueue) > 0 {
		cur := bQueue[0]
		bQueue = bQueue[1:]
		cfd := idx.FuncDecls[cur]
		if cfd == nil || cfd.Body == nil {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "missing_raw_builder_helper_body", nil)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if call, isCall := n.(*ast.CallExpr); isCall {
				if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil {
					callee = callee.Origin()
					if sigC, okSig := callee.Type().(*types.Signature); okSig && sigC.Recv() != nil && types.IsInterface(sigC.Recv().Type()) {
						return true
					}
					if callee.Pkg() == p.Types && !buildReach[callee] {
						buildReach[callee] = true
						bQueue = append(bQueue, callee)
					}
				}
			}
			return true
		})
	}

	outIfaceName := outIfaceField.Name()
	rootStructs := map[*types.Named]bool{}
	outRootValid := true
	for fn := range buildReach {
		cfd := idx.FuncDecls[fn]
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if !outRootValid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CompositeLit:
				if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == outNamed && outNamed != nil {
					for _, elt := range x.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							outRootValid = false
							return false
						}
						kid, isID := kv.Key.(*ast.Ident)
						if isID && kid.Name == outIfaceName {
							fs := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(kv.Value))
							if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
								outRootValid = false
								return false
							}
							rootStructs[fs] = true
							builderFamily[fs] = true
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != outIfaceName {
						continue
					}
					if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(sel.X)) == outNamed && outNamed != nil {
						if li >= len(x.Rhs) {
							outRootValid = false
							return false
						}
						fs := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x.Rhs[li]))
						if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
							outRootValid = false
							return false
						}
						rootStructs[fs] = true
						builderFamily[fs] = true
					}
				}
			}
			return true
		})
	}
	if !outRootValid || len(rootStructs) != 1 {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_raw_builder_output_root", buildFD)
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	var rootNamed *types.Named
	for rn := range rootStructs {
		rootNamed = rn
	}
	rootStructRef := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: rootNamed.Obj().Name()}
	if !rootStructRef.Valid() {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	extraGuards := map[syntaxutil.TypeRef]bool{}
	immutableSlicePtrTypes := map[*types.Named]bool{}
	seenWalk := map[types.Type]bool{}
	fieldsValid := true
	var walkType func(owner *types.Named, t types.Type)
	walkType = func(owner *types.Named, t types.Type) {
		if t == nil || !fieldsValid {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "sync", "Mutex") {
			if owner != rootNamed {
				fieldsValid = false
			}
			return
		}
		if syntaxutil.IsNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() == p.Types {
				if _, isSt := n.Underlying().(*types.Struct); isSt {
					if n.TypeParams().Len() > 0 {
						fieldsValid = false
						return
					}
					if !builderFamily[n] {
						builderFamily[n] = true
						if stN, okS := n.Underlying().(*types.Struct); okS {
							for i := 0; i < stN.NumFields(); i++ {
								walkType(n, stN.Field(i).Type())
							}
						}
					}
					return
				}
				if _, isSl := n.Underlying().(*types.Slice); isSl {
					immutableSlicePtrTypes[n] = true
				}
			} else if ref, _, subSt, okRef := syntaxutil.TypeRefOfStructFull(n); okRef && subSt.NumFields() > 0 && ref.Valid() {
				extraGuards[ref] = true
				return
			}
		}
		if seenWalk[t] {
			return
		}
		seenWalk[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				fieldsValid = false
			}
		case *types.Chan, *types.TypeParam:
			fieldsValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			en, isEN := elem.(*types.Named)
			if !isEN || en.Obj() == nil || en.Obj().Pkg() != p.Types {
				fieldsValid = false
				return
			}
			if _, isSt := en.Underlying().(*types.Struct); !isSt {
				fieldsValid = false
				return
			}
			walkType(owner, elem)
		case *types.Slice:
			walkType(owner, u.Elem())
		case *types.Array:
			walkType(owner, u.Elem())
		case *types.Map:
			walkType(owner, u.Key())
			walkType(owner, u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkType(owner, u.Field(i).Type())
			}
		}
	}
	initialFamily := make([]*types.Named, 0, len(builderFamily))
	for fn := range builderFamily {
		initialFamily = append(initialFamily, fn)
	}
	for _, fn := range initialFamily {
		if stN, okS := fn.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				walkType(fn, stN.Field(i).Type())
			}
		}
	}
	if !fieldsValid {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_raw_builder_family_fields", nil)
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	for slNamed := range immutableSlicePtrTypes {
		psetSl := types.NewMethodSet(types.NewPointer(slNamed))
		for i := 0; i < psetSl.Len(); i++ {
			mfn, okM := psetSl.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "mutating_slice_ptr_method", nil)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
			mfd := idx.FuncDecls[mfn]
			if mfd == nil || mfd.Body == nil || bodyHasAnyAssignment(p, mfd.Body) {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "mutating_slice_ptr_method", mfd)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
		}
	}

	rootSt, ok := rootNamed.Underlying().(*types.Struct)
	if !ok {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	var rootMuField, rootOnceField *types.Var
	for famNamed := range builderFamily {
		if famNamed == rootNamed || structEmbedsUnexported(rootSt, famNamed) {
			if fst, okS := famNamed.Underlying().(*types.Struct); okS {
				mu, done := findUnexportedMutexAndUint32(fst)
				if mu != nil {
					rootMuField = mu
				}
				if done != nil {
					rootOnceField = done
				}
			}
		}
	}
	if rootMuField == nil || rootOnceField == nil {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "missing_raw_builder_root_once_lock", nil)
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	var rootOnceFn *types.Func
	psetRoot := types.NewMethodSet(types.NewPointer(rootNamed))
	for i := 0; i < psetRoot.Len(); i++ {
		m, okM := psetRoot.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		mfd := idx.FuncDecls[m]
		if mfd != nil && mfd.Body != nil && isLockedOnceInitMethodAllowTailUnlock(p, mfd, rootNamed, rootMuField, rootOnceField) {
			if rootOnceFn != nil {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "multiple_raw_builder_root_once_methods", mfd)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
			rootOnceFn = m
		}
	}
	if rootOnceFn == nil {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "missing_raw_builder_root_once_method", nil)
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}

	receiverOnceDoBlocks := map[*ast.BlockStmt]*types.Named{}
	memoOnceDoBlocks := map[*ast.BlockStmt]bool{}
	allowedBuildLitBlocks := map[*ast.BlockStmt]bool{}
	for _, file := range p.Syntax {
		litOK := true
		var badLit ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if !litOK || n == nil {
				return false
			}
			if _, isGo := n.(*ast.GoStmt); isGo {
				litOK = false
				badLit = n
				return false
			}
			lit, isLit := n.(*ast.FuncLit)
			if !isLit {
				return true
			}
			if memoOnceDoBlocks[lit.Body] {
				return true
			}
			if recvStruct, okDo := classifyOnceDoCallback(p, idx, lit, builderFamily); okDo {
				if recvStruct != nil {
					receiverOnceDoBlocks[lit.Body] = recvStruct
				}
				return true
			}
			if innerBody, okMemo := isMemoizedOnceGetterClosure(p, idx, lit); okMemo {
				memoOnceDoBlocks[innerBody] = true
				allowedBuildLitBlocks[lit.Body] = true
				allowedBuildLitBlocks[innerBody] = true
				return true
			}
			if isPureSortSliceComparator(p, idx, lit) || isSyncPoolNewConstructor(p, idx, lit) {
				return true
			}
			litOK = false
			badLit = lit
			return false
		})
		if !litOK {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "impure_raw_builder_closure_or_goroutine", badLit)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
	}

	var initFDs []*ast.FuncDecl
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Recv == nil && fd.Name.Name == "init" && fd.Body != nil {
				initFDs = append(initFDs, fd)
			}
		}
	}
	initConeFDs := refconfine.ComputeExclusiveConeFromRoots(p, idx, initFDs, nil, nil)
	rootFuncs := map[*types.Func]bool{buildFn: true, rootOnceFn: true}
	initAndBuildConeFDs := refconfine.ComputeExclusiveConeFromRoots(p, idx, initFDs, rootFuncs, allowedBuildLitBlocks)
	onceOnlyConeFDs := refconfine.ComputeExclusiveConeFromRoots(p, idx, nil, map[*types.Func]bool{rootOnceFn: true}, allowedBuildLitBlocks)

	initOnlyRefGlobals := map[*types.Var]bool{}
	for _, name := range p.Types.Scope().Names() {
		v, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || v == nil {
			continue
		}
		if syntaxutil.IsNamedInPkg(v.Type(), "sync", "Pool") {
			if v.Exported() || !verifySyncPoolGlobalUses(p, idx, v) {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "unsafe_sync_pool_global", nil)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
			continue
		}
		for _, uid := range idx.UsesOf[v] {
			enclFD := idx.SyncEnclFuncDecl(uid)
			if initConeFDs[enclFD] {
				continue
			}
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "post_init_global_mutation", uid)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
			par := idx.ParentUnparen(uid)
			if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid && refconfine.IdentOrExprIsWritten(idx, ix) {
				emitCapsuleReject(ctx, p, ownerRef.Key(), "post_init_global_mutation", uid)
				return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
			}
			if cid, isCall := par.(*ast.CallExpr); isCall && len(cid.Args) > 0 && ast.Unparen(cid.Args[0]) == uid {
				if fnID, isID := ast.Unparen(cid.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[fnID].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") {
						emitCapsuleReject(ctx, p, ownerRef.Key(), "post_init_global_mutation", uid)
						return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
					}
				}
			}
		}
		if refconfine.TypeCarriesMutableRef(v.Type()) {
			initOnlyRefGlobals[v] = true
		}
	}
	for _, file := range p.Syntax {
		extOK := true
		var badExt ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if !extOK || n == nil {
				return false
			}
			id, isID := n.(*ast.Ident)
			if !isID {
				return true
			}
			v, isVar := p.TypesInfo.Uses[id].(*types.Var)
			if !isVar || v == nil || v.IsField() || v.Pkg() == nil || v.Pkg() == p.Types || v.Parent() != v.Pkg().Scope() {
				return true
			}
			sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
			if !isSel || sel.Sel != id {
				return true
			}
			if refconfine.IdentOrExprIsWritten(idx, sel) {
				extOK = false
				badExt = sel
				return false
			}
			if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				if !isReadOnlyPtrCallArg(p, idx, un) {
					extOK = false
					badExt = un
					return false
				}
			}
			return true
		})
		if !extOK {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "cross_pkg_global_mutation_or_addr", badExt)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
	}

	rootOnceFD := idx.FuncDecls[rootOnceFn]
	exempt := map[ast.Node]bool{}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for _, uid := range idx.UsesOf[rootMuField] {
		if !idx.IsSyncInFuncDecl(uid, rootOnceFD) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "mutex_use_outside_once_cone", uid)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
	}
	for _, uid := range idx.UsesOf[rootOnceField] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "illegal_once_flag_use", uid)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		if idx.IsSyncInFuncDecl(uid, rootOnceFD) {
			if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				exempt[un] = true
			}
			continue
		}
		un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND || !refconfine.IsPureAtomicLoadArg(p, idx, un) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "illegal_once_flag_addr", uid)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		exempt[un] = true
	}

	unexportedScalarSetterFDs := map[*ast.FuncDecl]*types.Named{}
	for famSt := range builderFamily {
		if famSt.Obj().Exported() {
			continue
		}
		pset := types.NewMethodSet(types.NewPointer(famSt))
		for i := 0; i < pset.Len(); i++ {
			mfn, okM := pset.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types || !mfn.Exported() {
				continue
			}
			mfd := idx.FuncDecls[mfn]
			if mfd == nil || mfd.Body == nil {
				continue
			}
			if isPureReceiverScalarSetter(p, idx, mfd, famSt) {
				allCallsInBuild := true
				for _, cid := range idx.UsesOf[mfn] {
					encl := idx.SyncEnclFuncDecl(cid)
					if !initAndBuildConeFDs[encl] {
						allCallsInBuild = false
						break
					}
				}
				if allCallsInBuild {
					unexportedScalarSetterFDs[mfd] = famSt
				}
			}
		}
	}

	for fd := range initAndBuildConeFDs {
		if fd != nil && fd.Body != nil && bodyMutatesAnyNonInitGlobal(p, fd.Body, initConeFDs[fd], mutatedVars) {
			emitCapsuleReject(ctx, p, ownerRef.Key(), "global_mutation_in_builder_cone", fd)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
		for famSt := range builderFamily {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
	}
	for fd, famSt := range unexportedScalarSetterFDs {
		addExemptStructInFunc(exemptByFunc, fd, famSt)
	}

	enclosingOnceBlock := func(n ast.Node) (*ast.BlockStmt, *types.Named, bool) {
		cur := n
		for cur != nil {
			if blk, isBlk := cur.(*ast.BlockStmt); isBlk {
				if recvSt, okR := receiverOnceDoBlocks[blk]; okR {
					return blk, recvSt, false
				}
				if memoOnceDoBlocks[blk] {
					c2 := idx.ParentMap[blk]
					for c2 != nil {
						if fd, isFD := c2.(*ast.FuncDecl); isFD {
							return blk, nil, initAndBuildConeFDs[fd]
						}
						c2 = idx.ParentMap[c2]
					}
					return nil, nil, false
				}
			}
			if _, isLit := cur.(*ast.FuncLit); isLit {
				return nil, nil, false
			}
			cur = idx.ParentMap[cur]
		}
		return nil, nil, false
	}

	pf := freshstruct.ComputePackageFreshConstructors(p, idx, nil)
	fastRootInitMethods := collectFastOnceWrapperMethods(p, idx, rootNamed, rootOnceFn, rootOnceField)

	onceMutatedSubStructs := map[*types.Named]bool{}
	recordOnceMutatedSubStruct := func(fd *ast.FuncDecl, expr ast.Expr) {
		if expr == nil || pf.IsFreshMutationTarget(fd, expr) {
			return
		}
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel {
			return
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal {
			return
		}
		ownerN := syntaxutil.DerefNamedStruct(selInfo.Recv())
		if ownerN != nil && ownerN != rootNamed && builderFamily[ownerN] {
			onceMutatedSubStructs[ownerN] = true
		}
	}
	for fd := range onceOnlyConeFDs {
		if fd == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					recordOnceMutatedSubStruct(fd, lhs)
				}
			case *ast.IncDecStmt:
				recordOnceMutatedSubStruct(fd, x.X)
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							recordOnceMutatedSubStruct(fd, x.Args[0])
						}
					}
				}
			}
			return true
		})
	}

	extractValueHopRootPtrExpr := func(sel *ast.SelectorExpr) (ast.Expr, bool) {
		cur := ast.Expr(sel)
		for {
			s, isS := ast.Unparen(cur).(*ast.SelectorExpr)
			if !isS {
				return nil, false
			}
			si := p.TypesInfo.Selections[s]
			if si == nil || si.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(si) {
				return nil, false
			}
			base := ast.Unparen(s.X)
			if syntaxutil.IsPtrToNamed(p.TypesInfo.TypeOf(base), rootNamed) {
				return base, true
			}
			if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(base)).(*types.Pointer); isPtr {
				return nil, false
			}
			cur = base
		}
	}

	isAllowedFamilyAddrTake := func(syncFD *ast.FuncDecl, un *ast.UnaryExpr) (bool, string) {
		if exempt[un] {
			return true, ""
		}
		inner := ast.Unparen(un.X)
		switch in := inner.(type) {
		case *ast.CompositeLit:
			if litSt := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(in)); litSt != nil && builderFamily[litSt] {
				return true, ""
			}
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[in]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false, "illegal_raw_builder_family_addr"
			}
			ft := types.Unalias(selInfo.Type())
			if fn, isN := ft.(*types.Named); isN && (builderFamily[fn] || immutableSlicePtrTypes[fn]) {
				if onceMutatedSubStructs[fn] {
					if rootExpr, okRoot := extractValueHopRootPtrExpr(in); okRoot {
						if syncFD == nil || idx.InFuncLit[un] || idx.InGoStmt[un] ||
							!localPtrDominatedByOnceInit(p, idx, syncFD, rootExpr, un.Pos(), rootNamed, rootOnceField, rootOnceFn, fastRootInitMethods) {
							return false, "substruct_addr_not_dominated_by_once_init"
						}
					}
				}
				return true, ""
			}
		case *ast.IndexExpr:
			if elemN := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(in)); elemN != nil && builderFamily[elemN] {
				return true, ""
			}
		}
		return false, "illegal_raw_builder_family_addr"
	}

	checkFamilyMutExpr := func(stmtNode ast.Node, expr ast.Expr) bool {
		if !refconfine.TouchesAnyNamedStruct(p, expr, builderFamily) {
			return true
		}
		syncFD := idx.SyncEnclFuncDecl(stmtNode)
		if syncFD != nil {
			if initAndBuildConeFDs[syncFD] {
				exempt[stmtNode] = true
				return true
			}
			if setterSt, okS := unexportedScalarSetterFDs[syncFD]; okS && refconfine.TouchesAnyNamedStruct(p, expr, map[*types.Named]bool{setterSt: true}) {
				exempt[stmtNode] = true
				return true
			}
			if pf.IsFreshMutationTarget(syncFD, expr) {
				exempt[stmtNode] = true
				return true
			}
		}
		_, recvSt, isMemoBuild := enclosingOnceBlock(stmtNode)
		if isMemoBuild {
			exempt[stmtNode] = true
			return true
		}
		if recvSt != nil {
			if refconfine.TouchesAnyNamedStruct(p, expr, map[*types.Named]bool{recvSt: true}) {
				exempt[stmtNode] = true
				return true
			}
		}
		return false
	}

	for _, file := range p.Syntax {
		mutOK := true
		mutRej := "raw_builder_family_mutation_outside_cone"
		var mutNode ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if !mutOK || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if !checkFamilyMutExpr(x, lhs) {
						mutOK = false
						mutNode = x
						return false
					}
				}
			case *ast.IncDecStmt:
				if !checkFamilyMutExpr(x, x.X) {
					mutOK = false
					mutNode = x
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkFamilyMutExpr(x, x.Key)) || (x.Value != nil && !checkFamilyMutExpr(x, x.Value)) {
						mutOK = false
						mutNode = x
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && refconfine.TouchesAnyNamedStruct(p, x.X, builderFamily) {
					syncFD := idx.SyncEnclFuncDecl(x)
					if syncFD != nil {
						if initAndBuildConeFDs[syncFD] {
							exempt[x] = true
							return true
						}
						if pf.IsFreshAddrOrValue(syncFD, x.X) {
							exempt[x] = true
							return true
						}
					}
					_, recvSt, isMemoBuild := enclosingOnceBlock(x)
					if isMemoBuild || recvSt != nil {
						exempt[x] = true
						return true
					}
					if okAddr, addrReason := isAllowedFamilyAddrTake(syncFD, x); okAddr {
						exempt[x] = true
						return true
					} else {
						mutOK = false
						mutRej = addrReason
						mutNode = x
						return false
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkFamilyMutExpr(x, x.Args[0]) {
								mutOK = false
								mutNode = x
								return false
							}
						}
					}
				}
			}
			return true
		})
		if !mutOK {
			emitCapsuleReject(ctx, p, ownerRef.Key(), mutRej, mutNode)
			return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
		}
	}

	snapshotGuardedFields, snapConds := collectSnapshotGuardedValueFields(
		p, idx, rootStructRef, builderFamily, extraGuards, initAndBuildConeFDs, pf,
	)

	guardTypes, okConf := verifyRawBuilderConfinementAndGuards(
		ctx, p, idx, ownerRef, named, outNamed, builderFamily, immutableSlicePtrTypes,
		snapshotGuardedFields, initOnlyRefGlobals, initConeFDs, initAndBuildConeFDs,
		unexportedScalarSetterFDs, enclosingOnceBlock, exempt, exemptReadFields, pf,
	)
	if !okConf {
		return syntaxutil.InitBuilderFact{}, nil, nil, nil, false
	}
	fact := syntaxutil.InitBuilderFact{
		Type:                    ownerRef,
		BuildMethod:             buildFn.Name(),
		OutIfaceField:           outIfaceName,
		GuardTypes:              guardTypes,
		CoversImmutableCapsules: true,
	}
	return fact, exempt, exemptByFunc, snapConds, true
}
