package freshstruct

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func forEachBodyAndClosureOp(
	fn *types.Func,
	fl *ast.FuncLit,
	declBody *flowir.Body,
	curBody *flowir.Body,
	visit func(enclFn *types.Func, enclLit *ast.FuncLit, enclDeclBody *flowir.Body, op *flowir.Op) bool,
) bool {
	if curBody == nil {
		return true
	}
	if declBody == nil {
		declBody = curBody
	}
	for i := range curBody.Ops {
		op := &curBody.Ops[i]
		if !visit(fn, fl, declBody, op) {
			return false
		}
		stop := false
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if stop || v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValMakeClosure:
					if v.Closure != nil && !forEachBodyAndClosureOp(nil, v.Lit, v.Closure, v.Closure, visit) {
						stop = true
						return false
					}
				case flowir.ValCall:
					if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
						var iifeLit *ast.FuncLit
						if v.CallAST != nil {
							iifeLit, _ = syntaxutil.UnparenExpr(v.CallAST.Fun).(*ast.FuncLit)
						}
						if !forEachBodyAndClosureOp(nil, iifeLit, v.IIFE, v.IIFE, visit) {
							stop = true
							return false
						}
					}
				}
				return true
			})
			return !stop
		})
		if stop {
			return false
		}
		if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
			if !forEachBodyAndClosureOp(fn, fl, declBody, op.RangeBody, visit) {
				return false
			}
		}
	}
	return true
}

func forEachPkgFlowOp(
	p *packages.Package,
	fc *flowir.PkgCache,
	visit func(enclFn *types.Func, enclLit *ast.FuncLit, enclDeclBody *flowir.Body, op *flowir.Op) bool,
) bool {
	if p == nil || p.TypesInfo == nil || fc == nil {
		return true
	}
	for _, fd := range fc.FuncDecls {
		if fd == nil || fd.Body == nil {
			continue
		}
		var fn *types.Func
		if fd.Name != nil {
			fn, _ = p.TypesInfo.Defs[fd.Name].(*types.Func)
		}
		b := fc.FuncBody(fd)
		if !forEachBodyAndClosureOp(fn, nil, b, b, visit) {
			return false
		}
	}
	for _, gd := range fc.GenDecls {
		if gd == nil {
			continue
		}
		b := fc.Body(gd)
		if !forEachBodyAndClosureOp(nil, nil, b, b, visit) {
			return false
		}
	}
	return true
}

// CollectMutatedStructTypes summarizes every non-exempted struct/container
// mutation and conditional struct mutation across p.Syntax.
func CollectMutatedStructTypes(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation) {
	mut, conds, _ := CollectMutatedStructTypesWithIfaces(p, idx, freshCache, confinedCacheMaps, exempted, exemptFamilyByFunc, exemptReadFields)
	return mut, conds
}

// CollectMutatedStructTypesWithIfaces summarizes every non-exempted
// struct/container mutation, conditional struct mutation, and reflected/erased
// non-empty interface method-set key across p.Syntax.
func CollectMutatedStructTypesWithIfaces(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	return CollectMutatedStructTypesWithCapsuleFields(p, idx, freshCache, confinedCacheMaps, exempted, exemptFamilyByFunc, exemptReadFields, nil, nil)
}

// CollectMutatedStructTypesWithCapsuleFields summarizes every non-exempted
// struct/container mutation, conditional struct mutation, and reflected/erased
// non-empty interface method-set key across p.Syntax, tagging unexported
// capsule back-pointer traversals in foreignReflectFields with ForeignReflectPkg.
func CollectMutatedStructTypesWithCapsuleFields(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
	foreignReflectFields map[*types.Var]bool,
	clusterCapsuleElemTypes map[*types.Var][]*types.Named,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	return CollectMutatedStructTypesWithCapsuleFieldsCtx(nil, p, idx, freshCache, confinedCacheMaps, exempted, exemptFamilyByFunc, exemptReadFields, foreignReflectFields, clusterCapsuleElemTypes)
}

type ctxBoxedIfaceKey struct {
	ctxKey    string
	methodSet string
}

type nestedBoxIfaceKey struct {
	boxKey            string
	methodSet         string
	opaqueGuardStruct syntaxutil.TypeRef
}

type pendingBoxedKey struct {
	ref       syntaxutil.TypeRef
	methodSet string
}

type pendingForeignBoxedKey struct {
	ref        syntaxutil.TypeRef
	methodSet  string
	foreignPkg string
}

type unsafeCarrierBoxKey struct {
	boxKey         string
	opaqueOwnerPkg string
}

type capsuleCallGuard struct {
	capStruct    syntaxutil.TypeRef
	capParam     syntaxutil.ParamKey
	atomicCopyFn syntaxutil.FuncKey
}

type foreignIfaceKey struct {
	guard     capsuleCallGuard
	methodSet string
}

type mutatedStructCollector struct {
	ctx                  context.Context
	p                    *packages.Package
	idx                  *refconfine.PkgIndex
	freshCache           *FreshLocalsCache
	confinedCacheMaps    map[*types.Var]map[*ast.FuncDecl]bool
	exempted             map[ast.Node]bool
	exemptFamilyByFunc   map[*ast.FuncDecl]map[*types.Named]bool
	exemptReadFields        map[*types.Var]bool
	foreignReflectFields    map[*types.Var]bool
	clusterCapsuleElemTypes map[*types.Var][]*types.Named

	traceTarget                        string
	seen                               map[syntaxutil.TypeRef]bool
	condSeen                           map[syntaxutil.ConditionalStructMutation]bool
	reflectedIfaceSets                 map[string]bool
	anyErasedNonEmptyIfaces            map[string]bool
	directReflectedNonEmptyIfaces      map[string]bool
	deferredParamAnyIfaces             map[string]map[syntaxutil.ParamKey]bool
	deferredParamAnyUnexportedIfaces   map[string]map[syntaxutil.ParamKey]bool
	ctxBoxedExported                   map[ctxBoxedIfaceKey]bool
	ctxBoxedAll                        map[ctxBoxedIfaceKey]bool
	nestedExportedIfacesInBox          map[nestedBoxIfaceKey]bool
	nestedAllIfacesInBox               map[nestedBoxIfaceKey]bool
	nestedAnyInConcreteBoxes           map[string]bool
	nestedUnexportedAnyInConcreteBoxes map[string]bool
	sawReflectValueOfAny               bool
	sawStdMutatingEmptyIfaceCall       bool
	sawCarrierPanic                    bool
	sawReflectValueCrossPkgArg         bool
	sawReflectMutOrEscape              bool
	sawRawUintptrToUnsafePtr           bool
	sawFmtPointerIdentityOnAny         bool
	pkgCrossesAnyBoundary              bool
	funcParamVars                      map[*types.Var]bool
	pendingBoxed                       map[pendingBoxedKey]bool
	pendingForeignBoxed                map[pendingForeignBoxedKey]bool
	directFlagROStructs                map[syntaxutil.TypeRef]bool
	unsafePtrCarrierBoxes              map[unsafeCarrierBoxKey]bool
	safeEfaceUnsafePtrConvs            map[*ast.CallExpr]bool
	hasEfaceUnion                      bool
	pkgFresh                           *PkgFreshConstructors
	addrTakenLocalValStructs           map[*types.Var]bool
	foreignUnsafeIfaces                map[foreignIfaceKey]bool
	atomicPtrCopyGuards                map[syntaxutil.FuncKey]bool
	safeCapsuleWrapUnsafeConvs         map[*ast.CallExpr]bool
	safeRawUintptrConvs                map[*ast.CallExpr]bool
	foreignPtrConvClasses              map[*ast.CallExpr]foreignPtrConvClass
	unconfinedForeignUnsafe            bool
	sawUnsafeIfaceHeaderBypass         bool
	confinedSyncMaps                   map[*types.Var]bool
	confinedSyncMapFields              map[*types.Var]bool
	confinedSyncPools                  map[*types.Var]bool
	confinedContextKeys                map[*types.Named]bool
	confinedContextLookups             map[*types.Named]bool
	mismatchedContextIfaceKeys         map[*types.Named]bool
	typeDispatchOnlyAnyParams          map[*types.Var]bool
	directReflectedUnexportedIfaces    map[string]bool
	anyErasedUnexportedIfaces          map[string]bool
	fmtPointerErasedIfaces             map[string]bool
	directCallFuns                     map[ast.Node]bool
}

// CollectMutatedStructTypesWithCapsuleFieldsCtx summarizes struct mutations,
// conditional mutations, and reflected interface facts across p.Syntax with
// ctx-scoped trace.DomainDynstate provenance emission.
func CollectMutatedStructTypesWithCapsuleFieldsCtx(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
	foreignReflectFields map[*types.Var]bool,
	clusterCapsuleElemTypes map[*types.Var][]*types.Named,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil, nil, nil
	}
	if freshCache == nil {
		freshCache = NewFreshLocalsCache(p, idx)
	}
	msc := &mutatedStructCollector{
		ctx:                                ctx,
		p:                                  p,
		idx:                                idx,
		freshCache:                         freshCache,
		confinedCacheMaps:                  confinedCacheMaps,
		exempted:                           exempted,
		exemptFamilyByFunc:                 exemptFamilyByFunc,
		exemptReadFields:                   exemptReadFields,
		foreignReflectFields:               foreignReflectFields,
		clusterCapsuleElemTypes:            clusterCapsuleElemTypes,
		traceTarget:                        pkgTraceTarget(p),
		seen:                               map[syntaxutil.TypeRef]bool{},
		condSeen:                           map[syntaxutil.ConditionalStructMutation]bool{},
		reflectedIfaceSets:                 map[string]bool{},
		anyErasedNonEmptyIfaces:            map[string]bool{},
		directReflectedNonEmptyIfaces:      map[string]bool{},
		deferredParamAnyIfaces:             map[string]map[syntaxutil.ParamKey]bool{},
		deferredParamAnyUnexportedIfaces:   map[string]map[syntaxutil.ParamKey]bool{},
		ctxBoxedExported:                   map[ctxBoxedIfaceKey]bool{},
		ctxBoxedAll:                        map[ctxBoxedIfaceKey]bool{},
		nestedExportedIfacesInBox:          map[nestedBoxIfaceKey]bool{},
		nestedAllIfacesInBox:               map[nestedBoxIfaceKey]bool{},
		nestedAnyInConcreteBoxes:           map[string]bool{},
		nestedUnexportedAnyInConcreteBoxes: map[string]bool{},
		funcParamVars:                      collectFuncParamVars(p),
		pendingBoxed:                       map[pendingBoxedKey]bool{},
		pendingForeignBoxed:                map[pendingForeignBoxedKey]bool{},
		directCallFuns:                     map[ast.Node]bool{},
	}
	if pkgExposesEmptyIfaceBoundary(p) {
		msc.markCrossesAnyBoundary("exported_api_exposes_any", nil, nil)
	}
	msc.directFlagROStructs = map[syntaxutil.TypeRef]bool{}
	msc.unsafePtrCarrierBoxes = map[unsafeCarrierBoxKey]bool{}
	msc.safeEfaceUnsafePtrConvs = collectSafeEfaceHeaderUnsafePtrConvs(msc.p, msc.idx)
	msc.hasEfaceUnion = len(msc.safeEfaceUnsafePtrConvs) > 0
	if msc.hasEfaceUnion && pkgExposesUnsafePointerBoundary(msc.p) {
		msc.markCrossesAnyBoundary("eface_union_exposes_unsafe_ptr", nil, nil)
	}

	msc.pkgFresh = ComputePackageFreshConstructors(msc.p, msc.idx, msc.confinedCacheMaps)
	for cm := range msc.pkgFresh.condGuards {
		if cm.Valid() {
			msc.condSeen[cm] = true
		}
	}

	msc.addrTakenLocalValStructs = collectAddrTakenLocalValueStructs(msc.p)

	msc.foreignUnsafeIfaces = map[foreignIfaceKey]bool{}
	msc.atomicPtrCopyGuards = map[syntaxutil.FuncKey]bool{}
	msc.safeCapsuleWrapUnsafeConvs, _, _, _, msc.safeRawUintptrConvs = collectSafeCapsuleWrapperUnsafePtrConvs(msc.p, msc.idx, msc.foreignReflectFields)
	msc.foreignPtrConvClasses, msc.unconfinedForeignUnsafe = classifyForeignUnsafePtrConvs(msc.p, msc.idx, msc.exempted, msc.clusterCapsuleElemTypes)
	for _, cls := range msc.foreignPtrConvClasses {
		if cls.isAtomicPtrCopy && cls.atomicCopyFn.Valid() {
			msc.atomicPtrCopyGuards[cls.atomicCopyFn] = true
		}
	}
	msc.sawUnsafeIfaceHeaderBypass = false
	if msc.unconfinedForeignUnsafe {
		msc.sawUnsafeIfaceHeaderBypass = true
		msc.sawReflectValueOfAny = true
		msc.sawReflectMutOrEscape = true
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
		msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
		msc.markCrossesAnyBoundary("unconfined_foreign_unsafe", nil, nil)
	}

	msc.confinedSyncMaps, msc.confinedSyncMapFields = collectTypeAssertedSyncMaps(msc.p, msc.idx)
	msc.confinedSyncPools = collectTypeAssertedSyncPools(msc.p, msc.idx)
	msc.confinedContextKeys, msc.confinedContextLookups, msc.mismatchedContextIfaceKeys = collectConfinedContextKeyTypes(msc.p, msc.idx)
	msc.typeDispatchOnlyAnyParams = collectTypeDispatchOnlyAnyParams(msc.p, msc.idx)

	for capVar, elemSlice := range msc.clusterCapsuleElemTypes {
		fallbackCapPkg := ""
		if capVar != nil {
			if sl, isSl := syntaxutil.UnderlyingType(capVar.Type()).(*types.Slice); isSl {
				if elemNamed := syntaxutil.DerefNamedStruct(sl.Elem()); elemNamed != nil && elemNamed.Obj() != nil &&
					elemNamed.Obj().Pkg() != nil && elemNamed.Obj().Pkg() != msc.p.Types && !msc.isTrueStdPkg(elemNamed.Obj().Pkg()) {
					fallbackCapPkg = elemNamed.Obj().Pkg().Path()
				}
			}
		}
		for _, msgNamed := range elemSlice {
			if msgNamed != nil {
				capPkg := msc.extractForeignCapsuleWrapperPkg(msgNamed)
				if capPkg == "" {
					capPkg = fallbackCapPkg
				}
				if capPkg != "" {
					msc.recordForeignCapsuleMsgIfaces(msgNamed, capPkg)
				}
			}
		}
	}

	msc.directReflectedUnexportedIfaces = map[string]bool{}
	msc.anyErasedUnexportedIfaces = map[string]bool{}
	msc.fmtPointerErasedIfaces = map[string]bool{}

	msc.scanSyntaxFiles()
	return msc.scanTypesInfoAndFinalize()
}

func (msc *mutatedStructCollector) resolveStructAt(at ast.Node, t types.Type) (syntaxutil.TypeRef, bool) {
	ref, named, st, ok := syntaxutil.TypeRefOfStructFull(t)
	if !ok || st == nil || (named == nil && st.NumFields() == 0) || !ref.Valid() {
		return syntaxutil.TypeRef{}, false
	}
	if named != nil {
		if syncFD := msc.idx.SyncEnclFuncDecl(at); syncFD != nil && msc.exemptFamilyByFunc[syncFD][named] {
			return syntaxutil.TypeRef{}, false
		}
	}
	return ref, true
}

func (msc *mutatedStructCollector) markMutated(ref syntaxutil.TypeRef, reason string, at ast.Node) {
	if !msc.seen[ref] {
		msc.seen[ref] = true
		emitStructMutated(msc.ctx, msc.p, msc.traceTarget, ref, reason, at)
	}
}

func (msc *mutatedStructCollector) recordStructAt(at ast.Node, t types.Type) {
	if ref, ok := msc.resolveStructAt(at, t); ok {
		msc.markMutated(ref, "direct_or_escaped_mutation", at)
	}
}

func (msc *mutatedStructCollector) recordStructSink(at ast.Node, t types.Type, _ string) {
	msc.recordStructAt(at, t)
}

func (msc *mutatedStructCollector) recordNamedContainerAt(at ast.Node, t types.Type) {
	if t == nil {
		return
	}
	n, isN := types.Unalias(t).(*types.Named)
	if !isN || n.Obj() == nil || n.Obj().Pkg() == nil || n.Obj().Parent() != n.Obj().Pkg().Scope() {
		return
	}
	switch n.Underlying().(type) {
	case *types.Slice, *types.Map:
		ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
		if ref.Valid() {
			msc.markMutated(ref, "named_container_mutation", at)
		}
	}
}

func (msc *mutatedStructCollector) isMethodlessStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, isSt := t.Underlying().(*types.Struct); !isSt {
		return false
	}
	return types.NewMethodSet(types.NewPointer(t)).Len() == 0
}

func (msc *mutatedStructCollector) recordEscapedArgTypesWithSink(at ast.Node, root types.Type, includeUnexportedFields bool, methodlessOnly bool, sink func(ast.Node, types.Type, string)) {
	syncFD := msc.idx.SyncEnclFuncDecl(at)
	type visitKey struct {
		t                 types.Type
		addressable       bool
		crossedForeignPkg string
	}
	visited := map[visitKey]bool{}
	var walk func(t types.Type, addressable bool, crossedForeignPkg string)
	walk = func(t types.Type, addressable bool, crossedForeignPkg string) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if named, isNamed := t.(*types.Named); isNamed && syncFD != nil && msc.exemptFamilyByFunc[syncFD][named] {
			return
		}
		vk := visitKey{t: t, addressable: addressable, crossedForeignPkg: crossedForeignPkg}
		if visited[vk] {
			return
		}
		visited[vk] = true
		if addressable {
			if _, isSt := t.Underlying().(*types.Struct); isSt && (!methodlessOnly || msc.isMethodlessStruct(t)) {
				sink(at, t, crossedForeignPkg)
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem(), true, crossedForeignPkg)
		case *types.Slice:
			if !methodlessOnly {
				msc.recordNamedContainerAt(at, t)
			}
			walk(u.Elem(), true, crossedForeignPkg)
		case *types.Map:
			if !methodlessOnly {
				msc.recordNamedContainerAt(at, t)
			}
			walk(u.Key(), false, crossedForeignPkg)
			walk(u.Elem(), true, crossedForeignPkg)
		case *types.Chan:
			walk(u.Elem(), false, crossedForeignPkg)
		case *types.Array:
			walk(u.Elem(), addressable, crossedForeignPkg)
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type(), false, crossedForeignPkg)
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type(), false, crossedForeignPkg)
			}
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if msc.exemptReadFields[f] {
					continue
				}
				nextForeignPkg := crossedForeignPkg
				if nextForeignPkg == "" {
					if msc.foreignReflectFields[f] {
						nextForeignPkg = msc.p.Types.Path()
					} else if !f.Exported() && !f.Embedded() && f.Pkg() != nil && f.Pkg() != msc.p.Types {
						if tNamed, isTN := t.(*types.Named); isTN && tNamed.Obj() != nil && tNamed.Obj().Pkg() == f.Pkg() {
							opaqueContainer := true
							for si := 0; si < u.NumFields(); si++ {
								sf := u.Field(si)
								if sf.Exported() && !(sf.Embedded() && isZeroSizedPaddingType(sf.Type())) {
									opaqueContainer = false
									break
								}
							}
							if opaqueContainer {
								if ptr, isP := types.Unalias(f.Type()).(*types.Pointer); isP {
									if elemN, isN := types.Unalias(ptr.Elem()).(*types.Named); isN && elemN.Obj() != nil && elemN.Obj().Pkg() == f.Pkg() {
										nextForeignPkg = f.Pkg().Path()
									}
								}
							}
						}
					}
				}
				if !includeUnexportedFields && !f.Exported() && !f.Embedded() {
					if addressable && (!methodlessOnly || msc.isMethodlessStruct(t)) {
						syntaxutil.ForEachValueContainedStructType(f.Type(), func(vt types.Type) {
							if !methodlessOnly || msc.isMethodlessStruct(vt) {
								sink(at, vt, nextForeignPkg)
							}
						})
					} else if !methodlessOnly && refconfine.TypeCarriesMutableRef(f.Type()) {
						if tNamed, isTN := t.(*types.Named); isTN && tNamed.Obj() != nil && !tNamed.Obj().Exported() {
							sink(at, t, crossedForeignPkg)
						}
					}
					continue
				}
				walk(f.Type(), addressable, nextForeignPkg)
			}
		}
	}
	walk(root, false, "")
}

func (msc *mutatedStructCollector) recordDirectReflectiveArgTypes(at ast.Node, root types.Type) {
	msc.recordEscapedArgTypesWithSink(at, root, false, false, msc.recordStructSink)
	msc.recordEscapedArgTypesWithSink(at, root, true, false, func(node ast.Node, vt types.Type, _ string) {
		if ref, ok := msc.resolveStructAt(node, vt); ok {
			msc.directFlagROStructs[ref] = true
		}
	})
}

func (msc *mutatedStructCollector) recordPendingBoxedEntry(ref syntaxutil.TypeRef, methodSet string, crossedForeignPkg string) {
	pk := pendingBoxedKey{ref: ref, methodSet: methodSet}
	if crossedForeignPkg != "" {
		if !msc.pendingBoxed[pk] {
			msc.pendingForeignBoxed[pendingForeignBoxedKey{ref: ref, methodSet: methodSet, foreignPkg: crossedForeignPkg}] = true
		}
	} else {
		msc.pendingBoxed[pk] = true
	}
}

func (msc *mutatedStructCollector) typeCrossesAnyOrEfaceUnion(t types.Type) bool {
	return typeMentionsEmptyInterfaceWith(t, true) || (msc.hasEfaceUnion && syntaxutil.ContainsUnsafePointer(t))
}

func (msc *mutatedStructCollector) recordPendingNonEmptyIfaceBox(at ast.Node, syncEncl *ast.FuncDecl, srcT types.Type) {
	if srcT == nil {
		return
	}
	msc.inspectBoxedConcreteMethodCapabilities(srcT)
	hasUnsafePtr, unsafeOwnerPkg := containsUnsafePointerWithOpaqueOwner(msc.p.Types, srcT)
	if hasUnsafePtr && msc.hasEfaceUnion {
		msc.markCrossesAnyBoundary("boxed_nonempty_eface_union_unsafe_ptr", srcT, at)
	}
	msetKey := syntaxutil.ConcreteMethodSetKey(srcT)
	if msetKey == "" {
		return
	}
	flagROKey := syntaxutil.ReflectFlagROBypassPrefix + msetKey
	hasAnyWithUnexp, anyOwnerPkg := typeMentionsEmptyIfaceWithOpaqueOwner(msc.p.Types, srcT)
	if hasUnsafePtr || hasAnyWithUnexp {
		carrierOwner := ""
		if hasUnsafePtr && !hasAnyWithUnexp {
			carrierOwner = unsafeOwnerPkg
		} else if !hasUnsafePtr && hasAnyWithUnexp {
			carrierOwner = anyOwnerPkg
		} else if unsafeOwnerPkg != "" && unsafeOwnerPkg == anyOwnerPkg {
			carrierOwner = unsafeOwnerPkg
		}
		msc.unsafePtrCarrierBoxes[unsafeCarrierBoxKey{boxKey: flagROKey, opaqueOwnerPkg: carrierOwner}] = true
	}
	if typeMentionsEmptyInterfaceWith(srcT, false) {
		msc.nestedAnyInConcreteBoxes[msetKey] = true
	} else if hasAnyWithUnexp {
		msc.nestedUnexportedAnyInConcreteBoxes[msetKey] = true
	}
	fam := msc.exemptFamilyByFunc[syncEncl]
	forEachNestedNonEmptyIface(srcT, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
		if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
			nk := nestedBoxIfaceKey{boxKey: msetKey, methodSet: k}
			msc.nestedExportedIfacesInBox[nk] = true
			msc.nestedAllIfacesInBox[nk] = true
		}
	})
	forEachNestedNonEmptyIfaceWithGuard(msc.p.Types, srcT, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface, opaqueGuardStruct syntaxutil.TypeRef) {
		if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
			if msc.nestedExportedIfacesInBox[nestedBoxIfaceKey{boxKey: msetKey, methodSet: k}] {
				return
			}
			msc.nestedAllIfacesInBox[nestedBoxIfaceKey{boxKey: msetKey, methodSet: k, opaqueGuardStruct: opaqueGuardStruct}] = true
		}
	})
	msc.recordEscapedArgTypesWithSink(at, srcT, false, true, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
		if ref, ok := msc.resolveStructAt(node, vt); ok {
			msc.recordPendingBoxedEntry(ref, msetKey, crossedForeignPkg)
		}
	})
	msc.recordEscapedArgTypesWithSink(at, srcT, true, true, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
		if ref, ok := msc.resolveStructAt(node, vt); ok {
			msc.recordPendingBoxedEntry(ref, flagROKey, crossedForeignPkg)
		}
	})
}

func (msc *mutatedStructCollector) recordAnyBoxedArgTypes(at ast.Node, syncEncl *ast.FuncDecl, root types.Type) {
	msc.recordEscapedArgTypesWithSink(at, root, false, false, msc.recordStructSink)
	msc.recordEscapedArgTypesWithSink(at, root, true, false, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
		if ref, ok := msc.resolveStructAt(node, vt); ok && !msc.seen[ref] {
			msc.recordPendingBoxedEntry(ref, syntaxutil.ReflectFlagROBypassAnyKey, crossedForeignPkg)
		}
	})
	if root != nil && !types.IsInterface(root) {
		msc.recordPendingNonEmptyIfaceBox(at, syncEncl, root)
	}
}

func (msc *mutatedStructCollector) recordGenericArgTypes(at ast.Node, root types.Type) {
	msc.recordEscapedArgTypesWithSink(at, root, true, false, msc.recordStructSink)
}

func (msc *mutatedStructCollector) getFresh(fd *ast.FuncDecl) (map[*types.Var]bool, map[*types.Var]token.Pos) {
	return msc.freshCache.Get(fd)
}

func (msc *mutatedStructCollector) isFreshMutTarget(fd *ast.FuncDecl, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
	if IsRootedAtFreshLocal(msc.p, expr, fresh, freshEsc) {
		return true
	}
	return msc.pkgFresh.IsFreshMutationTarget(fd, expr)
}

func (msc *mutatedStructCollector) isFreshAddrTarget(fd *ast.FuncDecl, inner ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
	if IsFreshInlineValue(msc.p, inner) || IsRootedAtFreshLocal(msc.p, inner, fresh, freshEsc) {
		return true
	}
	return msc.pkgFresh.IsFreshAddrOrValue(fd, inner)
}

func (msc *mutatedStructCollector) isFreshReflectOrBoxTarget(fd *ast.FuncDecl, inner ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
	if !msc.isFreshAddrTarget(fd, inner, fresh, freshEsc) {
		return false
	}
	return !exprCarriesNonFreshInterface(msc.p, inner)
}

func (msc *mutatedStructCollector) recordMutatedExpr(at ast.Node, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
	syncFD := msc.idx.SyncEnclFuncDecl(at)
	if msc.isFreshMutTarget(syncFD, expr, fresh, freshEsc) {
		return
	}
	if syncFD != nil && refconfine.IsByValueFieldChainOnExemptFamily(msc.p, expr, msc.exemptFamilyByFunc[syncFD]) {
		return
	}
	cur := ast.Unparen(expr)
	first := true
	for {
		switch e := cur.(type) {
		case *ast.StarExpr:
			if first {
				syntaxutil.ForEachValueContainedStructType(msc.p.TypesInfo.TypeOf(e.X), func(vt types.Type) {
					msc.recordStructAt(at, vt)
				})
				if ptr, isPtr := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
					elem := types.Unalias(ptr.Elem())
					syntaxutil.ForEachValueContainedStructType(elem, func(vt types.Type) {
						msc.recordStructAt(at, vt)
					})
					if sl, isSl := elem.Underlying().(*types.Slice); isSl {
						syntaxutil.ForEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
							msc.recordStructAt(at, vt)
						})
					}
				}
			}
			return
		case *ast.SelectorExpr:
			if selInfo := msc.p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				syntaxutil.ForEachSelectionHopStructType(selInfo, func(vt types.Type) {
					msc.recordStructAt(at, vt)
				})
				if first {
					syntaxutil.ForEachValueContainedStructType(selInfo.Type(), func(vt types.Type) {
						msc.recordStructAt(at, vt)
					})
				}
				if syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
					return
				}
				if _, isPtr := types.Unalias(msc.p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
					return
				}
				cur = ast.Unparen(e.X)
				first = false
				continue
			}
			if v, ok := msc.p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() {
				if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
					msc.recordNamedContainerAt(at, v.Type())
					syntaxutil.ForEachValueContainedStructType(v.Type(), func(vt types.Type) {
						msc.recordStructAt(at, vt)
					})
				}
			}
			return
		case *ast.Ident:
			if v, ok := msc.p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() &&
				v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
				if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
					msc.recordNamedContainerAt(at, v.Type())
					syntaxutil.ForEachValueContainedStructType(v.Type(), func(vt types.Type) {
						msc.recordStructAt(at, vt)
					})
				}
			}
			return
		case *ast.IndexExpr:
			if first {
				syntaxutil.ForEachValueContainedStructType(msc.p.TypesInfo.TypeOf(e), func(vt types.Type) {
					msc.recordStructAt(at, vt)
				})
			}
			msc.recordNamedContainerAt(at, msc.p.TypesInfo.TypeOf(e.X))
			cur = ast.Unparen(e.X)
			first = false
			continue
		case *ast.SliceExpr:
			msc.recordNamedContainerAt(at, msc.p.TypesInfo.TypeOf(e.X))
			cur = ast.Unparen(e.X)
			first = false
			continue
		default:
			return
		}
	}
}

func (msc *mutatedStructCollector) recordMutatedSlotWrite(at ast.Node, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
	if isUnaddressedLocalValueStructSlotWrite(msc.p, msc.idx, at, expr, msc.addrTakenLocalValStructs) {
		return
	}
	msc.recordMutatedExpr(at, expr, fresh, freshEsc)
}

func (msc *mutatedStructCollector) isZeroGuard(g capsuleCallGuard) bool {
	return g.capStruct.IsZero() && g.atomicCopyFn.IsZero()
}
