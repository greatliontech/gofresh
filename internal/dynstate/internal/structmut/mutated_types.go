// Package structmut summarizes non-exempted struct/container mutations,
// conditional struct mutations, reflected/erased interface method sets, and
// capsule-wrapper unsafe pointer disciplines across a package's syntax.
package structmut

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/capsule"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// DeriveCapsuleAndStructFacts derives capsule/builder/cluster facts via package
// capsule and combines them with non-exempted struct/interface mutation facts.
func DeriveCapsuleAndStructFacts(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
	extraExemptNodes map[ast.Node]bool,
) (
	[]syntaxutil.InitSettledClusterFact,
	[]syntaxutil.InitBuilderFact,
	[]syntaxutil.LazyOnceCapsuleType,
	[]syntaxutil.TypeRef,
	[]syntaxutil.ConditionalStructMutation,
	[]syntaxutil.ReflectedIfaceFact,
	map[*types.Var]bool,
) {
	return DeriveCapsuleAndStructFactsCtx(nil, audited, p, idx, freshCache, confinedCacheMaps, initOnly, mutatedVars, extraExemptNodes)
}

// DeriveCapsuleAndStructFactsCtx derives capsule/builder/cluster facts via
// package capsule and combines them with non-exempted struct/interface mutation
// facts under ctx-scoped trace.DomainDynstate provenance emission.
func DeriveCapsuleAndStructFactsCtx(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
	extraExemptNodes map[ast.Node]bool,
) (
	[]syntaxutil.InitSettledClusterFact,
	[]syntaxutil.InitBuilderFact,
	[]syntaxutil.LazyOnceCapsuleType,
	[]syntaxutil.TypeRef,
	[]syntaxutil.ConditionalStructMutation,
	[]syntaxutil.ReflectedIfaceFact,
	map[*types.Var]bool,
) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil, nil, nil, nil, nil, nil, nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if initOnly == nil {
		initOnly = idx.InitOnly
	}
	if freshCache == nil {
		freshCache = freshalloc.NewFreshLocalsCache(p, idx)
	}
	if confinedCacheMaps == nil {
		confinedCacheMaps = freshalloc.FindMutexConfinedConstructorCaches(p, idx)
	}
	capFacts := capsule.DerivePackageFactsCtx(ctx, audited, p, idx, freshCache, confinedCacheMaps, initOnly, mutatedVars, extraExemptNodes)
	mutatedStructs, condMutations, reflectedIfaces := CollectMutatedStructTypesWithCapsuleCtx(ctx, p, idx, freshCache, confinedCacheMaps, capFacts)
	capsules := slices.Clone(capFacts.Capsules)
	if len(capsules) > 0 && pkgCastsUnsafePtrToMutatedStructCtx(ctx, p, idx, mutatedStructs, capFacts.ForeignReflectFields) {
		for i := range capsules {
			if capsules[i].CapsuleReflectSafe {
				capsule.EmitCapsuleReject(ctx, p, capsules[i].Type.Key(), "unsafe_ptr_cast_to_mutated_struct", nil)
			}
			capsules[i].CapsuleReflectSafe = false
			capsules[i].SafePtrWrapperParams = nil
			capsules[i].SafeAtomicPtrCopyFuncs = nil
		}
	}
	if len(capFacts.CondMutations) > 0 {
		seenCond := make(map[syntaxutil.ConditionalStructMutation]bool, len(condMutations)+len(capFacts.CondMutations))
		merged := make([]syntaxutil.ConditionalStructMutation, 0, len(condMutations)+len(capFacts.CondMutations))
		for _, cm := range condMutations {
			if cm.Valid() && !seenCond[cm] {
				seenCond[cm] = true
				merged = append(merged, cm)
			}
		}
		for _, cm := range capFacts.CondMutations {
			if cm.Valid() && !seenCond[cm] {
				seenCond[cm] = true
				merged = append(merged, cm)
			}
		}
		slices.SortFunc(merged, syntaxutil.ConditionalStructMutation.Compare)
		condMutations = merged
	}
	return capFacts.Clusters, capFacts.Builders, capsules, mutatedStructs, condMutations, reflectedIfaces, capFacts.ClaimedVars
}

// CollectMutatedStructTypesWithCapsuleCtx summarizes non-exempted
// struct/container mutations, conditional struct mutations, and reflected
// interface method-set keys using immutable capsule.PackageFacts directly.
func CollectMutatedStructTypesWithCapsuleCtx(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	capFacts *capsule.PackageFacts,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation, []syntaxutil.ReflectedIfaceFact) {
	if capFacts == nil {
		return collectMutatedStructTypesWithCapsuleFieldsCtx(ctx, p, idx, freshCache, confinedCacheMaps, nil, nil, nil, nil, nil)
	}
	return collectMutatedStructTypesWithCapsuleFieldsCtx(
		ctx, p, idx, freshCache, confinedCacheMaps,
		capFacts.ExemptNodes,
		capFacts.ExemptFamilyByFunc,
		capFacts.ExemptReadFields,
		capFacts.ForeignReflectFields,
		capFacts.ClusterCapsuleElemTypes,
	)
}

func collectMutatedStructTypes(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation) {
	mut, conds, _ := collectMutatedStructTypesWithCapsuleFieldsCtx(nil, p, idx, freshCache, confinedCacheMaps, exempted, exemptFamilyByFunc, exemptReadFields, nil, nil)
	return mut, conds
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
	ctx                     context.Context
	p                       *packages.Package
	idx                     *refconfine.PkgIndex
	freshCache              *freshalloc.FreshLocalsCache
	confinedCacheMaps       map[*types.Var]map[*ast.FuncDecl]bool
	exempted                map[ast.Node]bool
	exemptFamilyByFunc      map[*ast.FuncDecl]map[*types.Named]bool
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
	pkgFresh                           *freshalloc.PkgFreshConstructors
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

func collectMutatedStructTypesWithCapsuleFieldsCtx(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
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
		freshCache = freshalloc.NewFreshLocalsCache(p, idx)
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
		funcParamVars:                      freshalloc.CollectFuncParamVars(p),
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

	msc.pkgFresh = freshalloc.ComputePackageFreshConstructors(msc.p, msc.idx, msc.confinedCacheMaps)
	for cm := range msc.pkgFresh.ConditionalGuards() {
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
	if freshalloc.IsRootedAtFreshLocal(msc.p, expr, fresh, freshEsc) {
		return true
	}
	return msc.pkgFresh.IsFreshMutationTarget(fd, expr)
}

func (msc *mutatedStructCollector) isFreshAddrTarget(fd *ast.FuncDecl, inner ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
	if freshalloc.IsFreshInlineValue(msc.p, inner) || freshalloc.IsRootedAtFreshLocal(msc.p, inner, fresh, freshEsc) {
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
