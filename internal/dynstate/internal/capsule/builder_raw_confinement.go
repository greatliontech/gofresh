package capsule

import (
	"context"
	"go/ast"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyRawBuilderConfinementAndGuards(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ownerRef syntaxutil.TypeRef,
	named *types.Named,
	outNamed *types.Named,
	builderFamily map[*types.Named]bool,
	immutableSlicePtrTypes map[*types.Named]bool,
	snapshotGuardedFields map[*types.Var]bool,
	initOnlyRefGlobals map[*types.Var]bool,
	initConeFDs map[*ast.FuncDecl]bool,
	initAndBuildConeFDs map[*ast.FuncDecl]bool,
	unexportedScalarSetterFDs map[*ast.FuncDecl]*types.Named,
	enclosingOnceBlock func(ast.Node) (*ast.BlockStmt, *types.Named, bool),
	exempt map[ast.Node]bool,
	exemptReadFields map[*types.Var]bool,
	pf *freshstruct.PkgFreshConstructors,
) ([]syntaxutil.TypeRef, bool) {
	nonSnapshotExtraGuards := map[syntaxutil.TypeRef]bool{}
	seenNonSnap := map[types.Type]bool{}
	nonSnapValid := true
	var walkNonSnapshotType func(t types.Type)
	walkNonSnapshotType = func(t types.Type) {
		if t == nil || !nonSnapValid {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "sync", "Mutex") || syntaxutil.IsNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed || builderFamily[n] || immutableSlicePtrTypes[n] {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg() != p.Types {
				switch subU := n.Underlying().(type) {
				case *types.Struct:
					if subU.NumFields() > 0 {
						ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
						if !ref.Valid() {
							nonSnapValid = false
							return
						}
						nonSnapshotExtraGuards[ref] = true
					}
				case *types.Slice, *types.Map:
					ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
					if !ref.Valid() {
						nonSnapValid = false
						return
					}
					nonSnapshotExtraGuards[ref] = true
				}
			}
		}
		if seenNonSnap[t] {
			return
		}
		seenNonSnap[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				nonSnapValid = false
			}
		case *types.Chan, *types.TypeParam:
			nonSnapValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			en, isEN := types.Unalias(u.Elem()).(*types.Named)
			if !isEN || (!builderFamily[en] && !immutableSlicePtrTypes[en]) {
				nonSnapValid = false
				return
			}
		case *types.Slice:
			walkNonSnapshotType(u.Elem())
		case *types.Array:
			walkNonSnapshotType(u.Elem())
		case *types.Map:
			walkNonSnapshotType(u.Key())
			walkNonSnapshotType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkNonSnapshotType(u.Field(i).Type())
			}
		}
	}
	for famSt := range builderFamily {
		if stN, okS := famSt.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				f := stN.Field(i)
				if snapshotGuardedFields[f] {
					continue
				}
				walkNonSnapshotType(f.Type())
			}
		}
	}
	if !nonSnapValid {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "invalid_non_snapshot_field_type", nil)
		return nil, false
	}

	isImmPtr := func(t types.Type) bool {
		ptr, okP := types.Unalias(t).(*types.Pointer)
		if !okP {
			return false
		}
		en, okN := types.Unalias(ptr.Elem()).(*types.Named)
		return okN && (builderFamily[en] || immutableSlicePtrTypes[en])
	}
	immutableIfaceFields := collectImmutableIfaceFields(p, idx, builderFamily, isImmPtr)
	if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			sel, isSel := ast.Unparen(containerExpr).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			fv, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
			return fv != nil && immutableIfaceFields[fv]
		},
		AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
			if callee == nil || call.Ellipsis.IsValid() {
				return false
			}
			orig := callee.Origin()
			sig, okSig := orig.Type().(*types.Signature)
			if !okSig || sig.Recv() == nil {
				return false
			}
			recvT := types.Unalias(sig.Recv().Type())
			if _, isPtr := recvT.(*types.Pointer); isPtr {
				return false
			}
			rn, isRN := recvT.(*types.Named)
			if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
				return false
			}
			if _, isSl := rn.Underlying().(*types.Slice); !isSl {
				return false
			}
			sliceRef := syntaxutil.TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
			if !nonSnapshotExtraGuards[sliceRef] {
				return false
			}
			for _, a := range call.Args {
				if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(a)) {
					return false
				}
			}
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if refconfine.TypeContainsRefOrPointer(sig.Results().At(ri).Type()) {
					return false
				}
			}
			return true
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			if id, isID := ast.Unparen(expr).(*ast.Ident); isID {
				if v, isV := p.TypesInfo.Uses[id].(*types.Var); isV && initOnlyRefGlobals[v] {
					if initConeFDs[idx.SyncEnclFuncDecl(id)] {
						return false, false
					}
					ft := v.Type()
					if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
						return true, true
					}
					if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
						return false, true
					}
				}
				return false, false
			}
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || selInfo.Obj().Exported() {
				return false, false
			}
			if fv, isFV := selInfo.Obj().(*types.Var); isFV && snapshotGuardedFields[fv] {
				return false, false
			}
			if refconfine.IsInsideExemptWriteOrAddr(idx, sel, exempt) {
				return false, false
			}
			syncFD := idx.SyncEnclFuncDecl(sel)
			if syncFD != nil && (initAndBuildConeFDs[syncFD] || unexportedScalarSetterFDs[syncFD] != nil || pf.IsFreshAddrOrValue(syncFD, sel) || pf.IsFreshMutationTarget(syncFD, sel)) {
				return false, false
			}
			if _, recvSt, isMemoBuild := enclosingOnceBlock(sel); isMemoBuild || recvSt != nil {
				return false, false
			}
			hit := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if builderFamily[hop] {
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
		AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			return callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "bytes" && callee.Name() == "Equal"
		},
	}) {
		emitCapsuleReject(ctx, p, ownerRef.Key(), "unconfined_raw_builder_ref_field", nil)
		return nil, false
	}

	guardMap := map[syntaxutil.TypeRef]bool{}
	for famSt := range builderFamily {
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: famSt.Obj().Name()}
		if !ref.Valid() {
			return nil, false
		}
		guardMap[ref] = true
	}
	for g := range nonSnapshotExtraGuards {
		guardMap[g] = true
	}
	guardTypes := make([]syntaxutil.TypeRef, 0, len(guardMap))
	for g := range guardMap {
		guardTypes = append(guardTypes, g)
	}
	sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	if exemptReadFields != nil {
		memo := map[*types.Named]bool{}
		visiting := map[*types.Named]bool{}
		for famSt := range builderFamily {
			st, okS := famSt.Underlying().(*types.Struct)
			if !okS {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				if f.Exported() && isBuilderFamilyReadConfinedType(f.Type(), builderFamily, memo, visiting) {
					exemptReadFields[f] = true
				}
			}
		}
	}
	return guardTypes, true
}
