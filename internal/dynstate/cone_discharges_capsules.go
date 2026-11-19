package dynstate

import (
	"context"
	"slices"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

type capsuleTypeInfo struct {
	HasExportedReflectType   bool
	InitHelper               syntaxutil.FuncKey
	GuardTypes               map[syntaxutil.TypeRef]bool
	ExportedWriteGuardFields map[string]bool
	CapsuleReflectSafe       bool
	SafePtrWrapperParams     map[syntaxutil.ParamKey]bool
	SafeAtomicPtrCopyFuncs   map[syntaxutil.FuncKey]bool
}

type builderVariantKey struct {
	Type                    syntaxutil.TypeRef
	CoversImmutableCapsules bool
}

type builderTypeInfo struct {
	BuildMethod          string
	OutIfaceField        string
	SubBuilderField      string
	SubBuilder           syntaxutil.TypeRef
	TypeSampleSliceField string
	CapsuleSliceFields   []syntaxutil.BuilderSliceSpec
	AllowedHelpers       map[syntaxutil.FuncKey]bool
	GuardTypes           map[syntaxutil.TypeRef]bool
}

func intersectPkgCapsuleTypes(pkgPath string, pkgFacts []Fact) map[syntaxutil.TypeRef]capsuleTypeInfo {
	return intersectPackageVariants(
		pkgFacts,
		func(fact Fact) map[syntaxutil.TypeRef]capsuleTypeInfo {
			cur := make(map[syntaxutil.TypeRef]capsuleTypeInfo, len(fact.LazyOnceCapsuleTypes))
			for _, ct := range fact.LazyOnceCapsuleTypes {
				if ct.Type.Pkg != pkgPath {
					continue
				}
				gt := make(map[syntaxutil.TypeRef]bool, len(ct.GuardTypes))
				for _, g := range ct.GuardTypes {
					gt[g] = true
				}
				eg := make(map[string]bool, len(ct.ExportedWriteGuardFields))
				for _, f := range ct.ExportedWriteGuardFields {
					eg[f] = true
				}
				swp := make(map[syntaxutil.ParamKey]bool, len(ct.SafePtrWrapperParams))
				for _, pk := range ct.SafePtrWrapperParams {
					swp[pk] = true
				}
				sac := make(map[syntaxutil.FuncKey]bool, len(ct.SafeAtomicPtrCopyFuncs))
				for _, fk := range ct.SafeAtomicPtrCopyFuncs {
					sac[fk] = true
				}
				cur[ct.Type] = capsuleTypeInfo{
					HasExportedReflectType:   ct.HasExportedReflectType,
					InitHelper:               ct.InitHelper,
					GuardTypes:               gt,
					ExportedWriteGuardFields: eg,
					CapsuleReflectSafe:       ct.CapsuleReflectSafe,
					SafePtrWrapperParams:     swp,
					SafeAtomicPtrCopyFuncs:   sac,
				}
			}
			return cur
		},
		func(prev, next capsuleTypeInfo) (capsuleTypeInfo, bool) {
			if prev.HasExportedReflectType != next.HasExportedReflectType || prev.InitHelper != next.InitHelper {
				return capsuleTypeInfo{}, false
			}
			for g := range next.GuardTypes {
				prev.GuardTypes[g] = true
			}
			for f := range next.ExportedWriteGuardFields {
				prev.ExportedWriteGuardFields[f] = true
			}
			prev.CapsuleReflectSafe = prev.CapsuleReflectSafe && next.CapsuleReflectSafe
			if !prev.CapsuleReflectSafe {
				clear(prev.SafePtrWrapperParams)
				clear(prev.SafeAtomicPtrCopyFuncs)
			} else {
				for pk := range prev.SafePtrWrapperParams {
					if !next.SafePtrWrapperParams[pk] {
						delete(prev.SafePtrWrapperParams, pk)
					}
				}
				for fk := range prev.SafeAtomicPtrCopyFuncs {
					if !next.SafeAtomicPtrCopyFuncs[fk] {
						delete(prev.SafeAtomicPtrCopyFuncs, fk)
					}
				}
			}
			return prev, true
		},
	)
}

func intersectPkgInitBuilders(pkgPath string, pkgFacts []Fact) map[builderVariantKey]builderTypeInfo {
	return intersectPackageVariants(
		pkgFacts,
		func(fact Fact) map[builderVariantKey]builderTypeInfo {
			cur := make(map[builderVariantKey]builderTypeInfo, len(fact.InitBuilders))
			for _, bf := range fact.InitBuilders {
				if bf.Type.Pkg != pkgPath {
					continue
				}
				ah := make(map[syntaxutil.FuncKey]bool, len(bf.AllowedHelpers))
				for _, h := range bf.AllowedHelpers {
					ah[h] = true
				}
				gt := make(map[syntaxutil.TypeRef]bool, len(bf.GuardTypes))
				for _, g := range bf.GuardTypes {
					gt[g] = true
				}
				cur[builderVariantKey{Type: bf.Type, CoversImmutableCapsules: bf.CoversImmutableCapsules}] = builderTypeInfo{
					BuildMethod:          bf.BuildMethod,
					OutIfaceField:        bf.OutIfaceField,
					SubBuilderField:      bf.SubBuilderField,
					SubBuilder:           bf.SubBuilder,
					TypeSampleSliceField: bf.TypeSampleSliceField,
					CapsuleSliceFields:   slices.Clone(bf.CapsuleSliceFields),
					AllowedHelpers:       ah,
					GuardTypes:           gt,
				}
			}
			return cur
		},
		func(prev, next builderTypeInfo) (builderTypeInfo, bool) {
			if prev.BuildMethod != next.BuildMethod ||
				prev.OutIfaceField != next.OutIfaceField ||
				prev.SubBuilderField != next.SubBuilderField ||
				prev.SubBuilder != next.SubBuilder ||
				prev.TypeSampleSliceField != next.TypeSampleSliceField ||
				!slices.Equal(prev.CapsuleSliceFields, next.CapsuleSliceFields) {
				return builderTypeInfo{}, false
			}
			for h := range prev.AllowedHelpers {
				if !next.AllowedHelpers[h] {
					delete(prev.AllowedHelpers, h)
				}
			}
			for g := range next.GuardTypes {
				prev.GuardTypes[g] = true
			}
			return prev, true
		},
	)
}

func hasValidImmutableCapsuleGuardCovering(
	commonBuildersByPkg map[string]map[builderVariantKey]builderTypeInfo,
	mutatedStructs map[syntaxutil.TypeRef]bool,
	guardStruct syntaxutil.TypeRef,
) bool {
	for k, cand := range commonBuildersByPkg[guardStruct.Pkg] {
		if !k.CoversImmutableCapsules {
			continue
		}
		if guardStruct != k.Type && !cand.GuardTypes[guardStruct] {
			continue
		}
		clean := true
		for g := range cand.GuardTypes {
			if mutatedStructs[g] {
				clean = false
				break
			}
		}
		if clean {
			return true
		}
	}
	return false
}

func collectSafeCapsuleReflectSets(
	pkgPaths []string,
	commonCapsulesByPkg map[string]map[syntaxutil.TypeRef]capsuleTypeInfo,
	mutatedStructs map[syntaxutil.TypeRef]bool,
) (
	map[string]map[syntaxutil.TypeRef]bool,
	map[string]map[syntaxutil.TypeRef]bool,
	map[syntaxutil.TypeRef]map[syntaxutil.ParamKey]bool,
	map[syntaxutil.FuncKey]bool,
) {
	safeCapsuleGuardStructs := map[string]map[syntaxutil.TypeRef]bool{}
	nestedSafeCapsuleStructs := map[string]map[syntaxutil.TypeRef]bool{}
	safePtrWrapperParams := map[syntaxutil.TypeRef]map[syntaxutil.ParamKey]bool{}
	safeAtomicPtrCopyFuncs := map[syntaxutil.FuncKey]bool{}

	for _, pkgPath := range pkgPaths {
		hasPrimary := false
		anyPrimaryUnsafeOrMut := false
		for tRef, ci := range commonCapsulesByPkg[pkgPath] {
			if !ci.CapsuleReflectSafe || !ci.InitHelper.IsZero() || len(ci.ExportedWriteGuardFields) > 0 {
				continue
			}
			hasPrimary = true
			if mutatedStructs[tRef] {
				anyPrimaryUnsafeOrMut = true
				break
			}
			for g := range ci.GuardTypes {
				if mutatedStructs[g] {
					anyPrimaryUnsafeOrMut = true
					break
				}
			}
			if anyPrimaryUnsafeOrMut {
				break
			}
		}
		for tRef, ci := range commonCapsulesByPkg[pkgPath] {
			if !ci.CapsuleReflectSafe {
				continue
			}
			if hasPrimary && !anyPrimaryUnsafeOrMut {
				if nestedSafeCapsuleStructs[pkgPath] == nil {
					nestedSafeCapsuleStructs[pkgPath] = map[syntaxutil.TypeRef]bool{}
				}
				nestedSafeCapsuleStructs[pkgPath][tRef] = true
				for g := range ci.GuardTypes {
					nestedSafeCapsuleStructs[pkgPath][g] = true
				}
			}
			if mutatedStructs[tRef] {
				continue
			}
			guardMut := false
			for g := range ci.GuardTypes {
				if mutatedStructs[g] {
					guardMut = true
					break
				}
			}
			if guardMut {
				continue
			}
			if safeCapsuleGuardStructs[pkgPath] == nil {
				safeCapsuleGuardStructs[pkgPath] = map[syntaxutil.TypeRef]bool{}
			}
			safeCapsuleGuardStructs[pkgPath][tRef] = true
			for g := range ci.GuardTypes {
				safeCapsuleGuardStructs[pkgPath][g] = true
			}
			if nestedSafeCapsuleStructs[pkgPath] == nil {
				nestedSafeCapsuleStructs[pkgPath] = map[syntaxutil.TypeRef]bool{}
			}
			nestedSafeCapsuleStructs[pkgPath][tRef] = true
			for g := range ci.GuardTypes {
				nestedSafeCapsuleStructs[pkgPath][g] = true
			}
			if len(ci.SafePtrWrapperParams) > 0 {
				if safePtrWrapperParams[tRef] == nil {
					safePtrWrapperParams[tRef] = map[syntaxutil.ParamKey]bool{}
				}
				for pk := range ci.SafePtrWrapperParams {
					safePtrWrapperParams[tRef][pk] = true
				}
			}
			for fk := range ci.SafeAtomicPtrCopyFuncs {
				safeAtomicPtrCopyFuncs[fk] = true
			}
		}
	}
	return safeCapsuleGuardStructs, nestedSafeCapsuleStructs, safePtrWrapperParams, safeAtomicPtrCopyFuncs
}

func resolveVerifiedClusterDischarges(
	ctx context.Context,
	coneTargetFor func(string) string,
	intersectDeclaredVarSet func(func(pkgPath string, fact Fact) map[string]bool) map[string]bool,
	pkgPaths []string,
	allFacts map[string][]Fact,
	anyMalformedMutatedStruct bool,
	anyMalformedDirectVarWrite bool,
	mutatedStructs map[syntaxutil.TypeRef]bool,
	directVarWritten map[string]bool,
	refRegions map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool,
	initOnlyFn map[syntaxutil.FuncKey]bool,
	commonCapsulesByPkg map[string]map[syntaxutil.TypeRef]capsuleTypeInfo,
	commonBuildersByPkg map[string]map[builderVariantKey]builderTypeInfo,
) map[string]bool {
	verifiedCapsules := map[syntaxutil.TypeRef]capsuleTypeInfo{}
	verifiedBuilders := map[builderVariantKey]builderTypeInfo{}

	if !anyMalformedMutatedStruct {
		for _, commonCaps := range commonCapsulesByPkg {
			for tRef, info := range commonCaps {
				if mutatedStructs[tRef] {
					if tgt := coneTargetFor(tRef.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
						emitDischargeReject(ctx, tgt, "capsule_type", tRef.Key(), "capsule_struct_mutated", tRef.Key())
					}
					continue
				}
				guardMutated := false
				for g := range info.GuardTypes {
					if mutatedStructs[g] {
						guardMutated = true
						if tgt := coneTargetFor(tRef.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
							emitDischargeReject(ctx, tgt, "capsule_type", tRef.Key(), "guard_type_mutated", g.Key())
						}
						break
					}
				}
				if !guardMutated {
					verifiedCapsules[tRef] = info
				}
			}
		}
		for _, commonBlds := range commonBuildersByPkg {
			for k, info := range commonBlds {
				guardMutated := false
				for g := range info.GuardTypes {
					if mutatedStructs[g] {
						guardMutated = true
						if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
							emitDischargeReject(ctx, tgt, "init_builder", k.Type.Key(), "guard_type_mutated", g.Key())
						}
						break
					}
				}
				if !guardMutated {
					verifiedBuilders[k] = info
				}
			}
		}
	}

	for k, info := range verifiedBuilders {
		if !k.CoversImmutableCapsules && !info.SubBuilder.IsZero() {
			if _, ok := verifiedBuilders[builderVariantKey{Type: info.SubBuilder, CoversImmutableCapsules: true}]; !ok {
				if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
					emitDischargeReject(ctx, tgt, "init_builder", k.Type.Key(), "unverified_sub_builder", info.SubBuilder.Key())
				}
				delete(verifiedBuilders, k)
			}
		}
	}

	builderAllowedHelperByPkg := map[string]map[syntaxutil.FuncKey]bool{}
	for k, info := range verifiedBuilders {
		if !k.CoversImmutableCapsules && len(info.AllowedHelpers) > 0 {
			if builderAllowedHelperByPkg[k.Type.Pkg] == nil {
				builderAllowedHelperByPkg[k.Type.Pkg] = map[syntaxutil.FuncKey]bool{}
			}
			for h := range info.AllowedHelpers {
				builderAllowedHelperByPkg[k.Type.Pkg][h] = true
			}
		}
	}
	nonBuilderReferencedFn := map[syntaxutil.FuncKey]bool{}
	for _, pkgPath := range pkgPaths {
		for _, fact := range allFacts[pkgPath] {
			for _, edge := range fact.FuncRefs {
				if edge.Callee.Valid() && !builderAllowedHelperByPkg[pkgPath][edge.Callee] {
					nonBuilderReferencedFn[edge.Callee] = true
				}
			}
		}
	}
	for tRef, info := range verifiedCapsules {
		if !info.InitHelper.IsZero() && nonBuilderReferencedFn[info.InitHelper] {
			if tgt := coneTargetFor(tRef.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
				emitDischargeReject(ctx, tgt, "capsule_type", tRef.Key(), "non_builder_init_helper_ref", info.InitHelper.Display())
			}
			delete(verifiedCapsules, tRef)
		}
	}

	return intersectDeclaredVarSet(func(pkgPath string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		tgt := coneTargetFor(pkgPath)
		traced := trace.Enabled(ctx, trace.DomainDynstate, tgt)
		m := map[string]bool{}
		for _, c := range fact.InitSettledClusters {
			if c.InitFn.Pkg != pkgPath || refRegions[c.InitFn] == nil || !initOnlyFn[c.InitFn] {
				if traced {
					emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "init_fn_not_init_only", "")
				}
				continue
			}
			bf, okBuilder := verifiedBuilders[builderVariantKey{Type: c.BuilderType, CoversImmutableCapsules: false}]
			if !okBuilder || bf.BuildMethod != c.BuildMethod || bf.OutIfaceField != c.OutIfaceField {
				if traced {
					emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "unverified_builder", c.BuilderType.Key())
				}
				continue
			}
			specByField := make(map[string]syntaxutil.BuilderSliceSpec, len(bf.CapsuleSliceFields))
			for _, spec := range bf.CapsuleSliceFields {
				specByField[spec.Field] = spec
			}
			slicesOK := true
			for _, sb := range c.SliceBindings {
				spec, okSpec := specByField[sb.Field]
				if !okSpec || sb.CapsuleType != spec.ElemType {
					slicesOK = false
					if traced {
						emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "mismatched_builder_slice_field", sb.Field)
					}
					break
				}
				capInfo, okCap := verifiedCapsules[sb.CapsuleType]
				if !okCap {
					slicesOK = false
					if traced {
						emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "unverified_capsule_type", sb.CapsuleType.Key())
					}
					break
				}
				if spec.TakesSample != capInfo.HasExportedReflectType || (sb.StaticLiteral && capInfo.HasExportedReflectType) {
					slicesOK = false
					if traced {
						emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "sample_reflect_type_mismatch", sb.CapsuleType.Key())
					}
					break
				}
				for reqGuard := range capInfo.ExportedWriteGuardFields {
					if !slices.Contains(sb.NonNilExportedNames, reqGuard) {
						slicesOK = false
						if traced {
							emitDischargeReject(ctx, tgt, "init_cluster", c.InitFn.Display(), "missing_exported_write_guard_field", sb.CapsuleType.Key()+"."+reqGuard)
						}
						break
					}
				}
				if !slicesOK {
					break
				}
			}
			if !slicesOK {
				continue
			}
			for _, key := range c.Vars {
				if !directVarWritten[key] {
					m[key] = true
				} else if traced {
					emitDischargeReject(ctx, tgt, "init_cluster", key, "direct_var_written", "")
				}
			}
		}
		return m
	})
}
