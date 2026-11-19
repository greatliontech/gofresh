package dynstate

import (
	"context"
	"sort"

	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

type coneDischarges struct {
	standardPkg            map[string]bool
	pinnedPkg              map[string]bool
	mutableLocalPkg        map[string]bool
	mappingDischargedVars  map[string]bool
	memoDischargedVars     map[string]bool
	onceMemoDischargedVars map[string]bool
	staticCompositeVars    map[string]bool
	harnessDischargedVars  map[string]bool
	directiveCovered       map[string]bool
	protoVerifiedVars      map[string]bool
}

func (d coneDischarges) isAttestationFreeDischarged(pkgPath, key string, malformedVars map[string]bool) bool {
	return (d.pinnedPkg[pkgPath] || d.mutableLocalPkg[pkgPath]) && !malformedVars[key] &&
		(d.mappingDischargedVars[key] || d.memoDischargedVars[key] ||
			d.onceMemoDischargedVars[key] || d.staticCompositeVars[key] ||
			d.harnessDischargedVars[key])
}

func (d coneDischarges) isProtoAttestedDischarged(pkgPath, key string, singleSubject bool, malformedVars map[string]bool) bool {
	return singleSubject && (d.pinnedPkg[pkgPath] || d.mutableLocalPkg[pkgPath]) &&
		!malformedVars[key] && d.protoVerifiedVars[key]
}

func deriveConeDischarges(
	ctx context.Context,
	viewPackage string,
	meta []GraphPackage,
	pkgPaths []string,
	allFacts map[string][]Fact,
	refRegions map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool,
	initOnlyFn map[syntaxutil.FuncKey]bool,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	pkgHasMalformedFact map[string]bool,
	malformedFactVars map[string]bool,
	mutatedStructs map[syntaxutil.TypeRef]bool,
	allCondStructMutations []syntaxutil.ConditionalStructMutation,
	directVarWritten map[string]bool,
	nonMethodVarUsed map[string]bool,
	anyMalformedMutatedStruct bool,
	anyMalformedDirectVarWrite bool,
	anyMalformedNonMethodVarUse bool,
) coneDischarges {
	coneTargetFor := func(pkg string) string {
		if viewPackage != "" {
			return viewPackage
		}
		return pkg
	}
	out := coneDischarges{
		standardPkg:     map[string]bool{},
		pinnedPkg:       map[string]bool{},
		mutableLocalPkg: map[string]bool{},
	}
	for _, node := range meta {
		switch node.Class {
		case StandardPackage:
			out.standardPkg[node.PkgPath] = true
		case PinnedPackage:
			out.pinnedPkg[node.PkgPath] = true
		case MutableLocalPackage:
			out.mutableLocalPkg[node.PkgPath] = true
		}
	}
	isKnownCleanNonStdPkg := func(p string) bool {
		return (out.pinnedPkg[p] || out.mutableLocalPkg[p]) && !out.standardPkg[p] && !pkgHasMalformedFact[p]
	}

	pkgCannotRetainCarrier := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		pkgFacts := allFacts[pkgPath]
		if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
			continue
		}
		allOK := true
		for _, fact := range pkgFacts {
			if !fact.NoPostInitCarrierWrites {
				allOK = false
				break
			}
		}
		if allOK {
			pkgCannotRetainCarrier[pkgPath] = true
		}
	}
	for changed := len(pkgCannotRetainCarrier) > 0; changed; {
		changed = false
		for pkgPath := range pkgCannotRetainCarrier {
			drop := false
			for _, fact := range allFacts[pkgPath] {
				for _, dep := range fact.CarrierImportCalls {
					if !pkgCannotRetainCarrier[dep] {
						drop = true
						break
					}
				}
				if drop {
					break
				}
			}
			if drop {
				delete(pkgCannotRetainCarrier, pkgPath)
				changed = true
			}
		}
	}

	commonRolesByPkg := map[string]map[rtRoleKey]rtRoleInfo{}
	nonMutatingMethods := map[syntaxutil.FuncKey]bool{}
	if !anyMalformedMutatedStruct {
		for _, pkgPath := range pkgPaths {
			pkgFacts := allFacts[pkgPath]
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
				continue
			}
			commonMethods := intersectPackageVariants(
				pkgFacts,
				func(fact Fact) map[syntaxutil.FuncKey]struct{} {
					cur := make(map[syntaxutil.FuncKey]struct{}, len(fact.NonMutatingMethods))
					for _, m := range fact.NonMutatingMethods {
						if m.Pkg == pkgPath {
							cur[m] = struct{}{}
						}
					}
					return cur
				},
				func(prev, _ struct{}) (struct{}, bool) { return prev, true },
			)
			for m := range commonMethods {
				nonMutatingMethods[m] = true
			}

			commonRolesByPkg[pkgPath] = intersectPackageVariants(
				pkgFacts,
				func(fact Fact) map[rtRoleKey]rtRoleInfo {
					cur := make(map[rtRoleKey]rtRoleInfo, len(fact.ProtoRuntimeTypes))
					for _, rt := range fact.ProtoRuntimeTypes {
						if rt.Type.Pkg != pkgPath {
							continue
						}
						ah := make(map[syntaxutil.FuncKey]bool, len(rt.AllowedHelpers))
						for _, h := range rt.AllowedHelpers {
							ah[h] = true
						}
						gt := make(map[syntaxutil.TypeRef]bool, len(rt.GuardTypes))
						for _, g := range rt.GuardTypes {
							gt[g] = true
						}
						swp := make(map[syntaxutil.ParamKey]bool, len(rt.SafePtrWrapperParams))
						for _, pk := range rt.SafePtrWrapperParams {
							swp[pk] = true
						}
						sac := make(map[syntaxutil.FuncKey]bool, len(rt.SafeAtomicPtrCopyFuncs))
						for _, fk := range rt.SafeAtomicPtrCopyFuncs {
							sac[fk] = true
						}
						cur[rtRoleKey{Type: rt.Type, Role: rt.Role}] = rtRoleInfo{
							SubBuilder:             rt.SubBuilder,
							InitHelper:             rt.InitHelper,
							AllowedHelpers:         ah,
							GuardTypes:             gt,
							CapsuleReflectSafe:     rt.CapsuleReflectSafe,
							SafePtrWrapperParams:   swp,
							SafeAtomicPtrCopyFuncs: sac,
						}
					}
					return cur
				},
				func(prev, next rtRoleInfo) (rtRoleInfo, bool) {
					if prev.InitHelper != next.InitHelper || prev.SubBuilder != next.SubBuilder {
						return rtRoleInfo{}, false
					}
					for h := range prev.AllowedHelpers {
						if !next.AllowedHelpers[h] {
							delete(prev.AllowedHelpers, h)
						}
					}
					for g := range next.GuardTypes {
						prev.GuardTypes[g] = true
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
	}

	hasValidDescBuilderCovering := func(guardStruct syntaxutil.TypeRef) bool {
		for k, cand := range commonRolesByPkg[guardStruct.Pkg] {
			if k.Role != protoaudit.ProtoRoleDescBuilder {
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

	importsByPkg := make(map[string][]string, len(meta))
	knownNonStdInMeta := make(map[string]bool, len(meta))
	if len(allCondStructMutations) > 0 {
		for _, node := range meta {
			importsByPkg[node.PkgPath] = append(importsByPkg[node.PkgPath], node.Imports...)
			if node.Class == PinnedPackage || node.Class == MutableLocalPackage {
				knownNonStdInMeta[node.PkgPath] = true
			}
		}
	}

	for len(allCondStructMutations) > 0 {
		safeCapsuleGuardStructs := map[string]map[syntaxutil.TypeRef]bool{}
		nestedSafeCapsuleStructs := map[string]map[syntaxutil.TypeRef]bool{}
		safePtrWrapperParams := map[syntaxutil.TypeRef]map[syntaxutil.ParamKey]bool{}
		safeAtomicPtrCopyFuncs := map[syntaxutil.FuncKey]bool{}
		if !anyMalformedMutatedStruct {
			for _, pkgPath := range pkgPaths {
				anyMsgRoleUnsafeOrMut := false
				for rk, ri := range commonRolesByPkg[pkgPath] {
					if rk.Role != protoaudit.ProtoRoleMessage {
						continue
					}
					if !ri.CapsuleReflectSafe || mutatedStructs[rk.Type] {
						anyMsgRoleUnsafeOrMut = true
						break
					}
					for g := range ri.GuardTypes {
						if mutatedStructs[g] {
							anyMsgRoleUnsafeOrMut = true
							break
						}
					}
					if anyMsgRoleUnsafeOrMut {
						break
					}
				}
				for rk, ri := range commonRolesByPkg[pkgPath] {
					if (rk.Role != protoaudit.ProtoRoleMessage && rk.Role != protoaudit.ProtoRoleExtension) ||
						!ri.CapsuleReflectSafe {
						continue
					}
					if !anyMsgRoleUnsafeOrMut {
						if nestedSafeCapsuleStructs[pkgPath] == nil {
							nestedSafeCapsuleStructs[pkgPath] = map[syntaxutil.TypeRef]bool{}
						}
						nestedSafeCapsuleStructs[pkgPath][rk.Type] = true
						for g := range ri.GuardTypes {
							nestedSafeCapsuleStructs[pkgPath][g] = true
						}
					}
					if mutatedStructs[rk.Type] {
						continue
					}
					guardMut := false
					for g := range ri.GuardTypes {
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
					safeCapsuleGuardStructs[pkgPath][rk.Type] = true
					for g := range ri.GuardTypes {
						safeCapsuleGuardStructs[pkgPath][g] = true
					}
					if nestedSafeCapsuleStructs[pkgPath] == nil {
						nestedSafeCapsuleStructs[pkgPath] = map[syntaxutil.TypeRef]bool{}
					}
					nestedSafeCapsuleStructs[pkgPath][rk.Type] = true
					for g := range ri.GuardTypes {
						nestedSafeCapsuleStructs[pkgPath][g] = true
					}
					if len(ri.SafePtrWrapperParams) > 0 {
						if safePtrWrapperParams[rk.Type] == nil {
							safePtrWrapperParams[rk.Type] = map[syntaxutil.ParamKey]bool{}
						}
						for pk := range ri.SafePtrWrapperParams {
							safePtrWrapperParams[rk.Type][pk] = true
						}
					}
					for fk := range ri.SafeAtomicPtrCopyFuncs {
						safeAtomicPtrCopyFuncs[fk] = true
					}
				}
			}
		}

		isInactiveCapsuleOrCopyScoped := func(rf syntaxutil.ReflectedIfaceFact) bool {
			return (!rf.UnlessSafeCapsuleStruct.IsZero() && safePtrWrapperParams[rf.UnlessSafeCapsuleStruct][rf.UnlessSafeCapsuleParam]) ||
				(!rf.UnlessSafeAtomicPtrCopy.IsZero() && safeAtomicPtrCopyFuncs[rf.UnlessSafeAtomicPtrCopy])
		}
		localFlagROBypassPkgs := map[string]bool{}
		for _, pkgPath := range pkgPaths {
			if out.standardPkg[pkgPath] {
				continue
			}
			pkgFacts := allFacts[pkgPath]
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
				localFlagROBypassPkgs[pkgPath] = true
				continue
			}
			for _, fact := range pkgFacts {
				for _, rf := range fact.ReflectedIfaceMethodSets {
					if isInactiveCapsuleOrCopyScoped(rf) {
						continue
					}
					if rf.MethodSet == syntaxutil.ReflectFlagROLocalBypassKey {
						localFlagROBypassPkgs[pkgPath] = true
						break
					}
				}
				if localFlagROBypassPkgs[pkgPath] {
					break
				}
			}
		}
		anyConeLocalFlagROBypass := len(localFlagROBypassPkgs) > 0
		actualReflectAny := map[string]bool{}
		actualReflectAnyFlagRO := map[string]bool{}
		reachSeedReflectAny := map[string]bool{}
		reachSeedReflectAnyFlagRO := map[string]bool{}
		leaksAnyUpwardPkgs := map[string]bool{}
		rvBoundaryEscapePkgs := map[string]bool{}
		anyConeReflectAny := false
		anyConeFlagROBypass := false
		type ctxBoxedEntry struct {
			pkg string
			rf  syntaxutil.ReflectedIfaceFact
		}
		var unsafeCarrierBoxed []ctxBoxedEntry
		for _, pkgPath := range pkgPaths {
			if out.standardPkg[pkgPath] {
				continue
			}
			pkgFacts := allFacts[pkgPath]
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
				actualReflectAny[pkgPath] = true
				actualReflectAnyFlagRO[pkgPath] = true
				reachSeedReflectAny[pkgPath] = true
				reachSeedReflectAnyFlagRO[pkgPath] = true
				leaksAnyUpwardPkgs[pkgPath] = true
				rvBoundaryEscapePkgs[pkgPath] = true
				anyConeReflectAny = true
				anyConeFlagROBypass = true
				continue
			}
			for _, fact := range pkgFacts {
				for _, rf := range fact.ReflectedIfaceMethodSets {
					if isInactiveCapsuleOrCopyScoped(rf) {
						continue
					}
					if rf.ReflectValueBoundaryEscape {
						rvBoundaryEscapePkgs[pkgPath] = true
					}
					if rf.UnsafePtrCarrierBoxed != "" {
						if rf.Valid() {
							unsafeCarrierBoxed = append(unsafeCarrierBoxed, ctxBoxedEntry{pkg: pkgPath, rf: rf})
						}
						continue
					}
					if rf.ContextValueBoxed != "" || rf.NestedInConcreteBox != "" {
						continue
					}
					switch rf.MethodSet {
					case syntaxutil.EmptyIfaceMethodSetKey:
						if rf.ReflectsEmptyIfaceLocally || !rf.LeaksEmptyIfaceUpward {
							reachSeedReflectAny[pkgPath] = true
							actualReflectAny[pkgPath] = true
							anyConeReflectAny = true
						}
						if rf.LeaksEmptyIfaceUpward {
							leaksAnyUpwardPkgs[pkgPath] = true
						}
					case syntaxutil.ReflectFlagROBypassAnyKey:
						actualReflectAny[pkgPath] = true
						actualReflectAnyFlagRO[pkgPath] = true
						reachSeedReflectAny[pkgPath] = true
						reachSeedReflectAnyFlagRO[pkgPath] = true
						anyConeReflectAny = true
						anyConeFlagROBypass = true
					}
				}
			}
		}
		makeReachPred := func(direct map[string]bool) func(string, map[string]bool) bool {
			memo := map[string]bool{}
			done := map[string]bool{}
			var reach func(pkg string, visiting map[string]bool) bool
			reach = func(pkg string, visiting map[string]bool) bool {
				if !knownNonStdInMeta[pkg] || direct[pkg] {
					return true
				}
				if done[pkg] {
					return memo[pkg]
				}
				if visiting[pkg] {
					return false
				}
				visiting[pkg] = true
				hit := false
				for _, imp := range importsByPkg[pkg] {
					if !out.standardPkg[imp] && reach(imp, visiting) {
						hit = true
						break
					}
				}
				delete(visiting, pkg)
				done[pkg] = true
				memo[pkg] = hit
				return hit
			}
			return reach
		}

		var coneReflectedIfaces []string
		coneReflectedProviders := map[string]map[string]bool{}
		seenRefIface := map[string]bool{}
		addConeReflectedWith := func(ms, prov, reason, detail string) {
			if ms == "" {
				return
			}
			if !seenRefIface[ms] {
				seenRefIface[ms] = true
				coneReflectedIfaces = append(coneReflectedIfaces, ms)
			}
			if coneReflectedProviders[ms] == nil {
				coneReflectedProviders[ms] = map[string]bool{}
			}
			if !coneReflectedProviders[ms][prov] {
				coneReflectedProviders[ms][prov] = true
				if tgt := coneTargetFor(prov); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
					trace.Emit(ctx, trace.DomainDynstate, "dynstate.iface.cone_active", tgt,
						trace.String("method_set", ms),
						trace.String("provider", prov),
						trace.String("reason", reason),
						trace.String("detail", detail),
					)
				}
			}
		}
		addConeReflected := func(ms, prov string) {
			addConeReflectedWith(ms, prov, "direct_or_erased", "")
		}
		promotedUnsafeCarriers := make([]bool, len(unsafeCarrierBoxed))
		for resolveChanged := true; resolveChanged; {
			resolveChanged = false
			if anyConeReflectAny {
				for pkgPath := range leaksAnyUpwardPkgs {
					reachSeedReflectAny[pkgPath] = true
				}
			}
			if anyConeFlagROBypass {
				for pkgPath := range leaksAnyUpwardPkgs {
					reachSeedReflectAnyFlagRO[pkgPath] = true
				}
			}
			pkgReachesReflectAny := makeReachPred(reachSeedReflectAny)
			pkgReachesReflectAnyFlagRO := makeReachPred(reachSeedReflectAnyFlagRO)

			var ctxBoxed []ctxBoxedEntry
			for _, pkgPath := range pkgPaths {
				for _, fact := range allFacts[pkgPath] {
					for _, rf := range fact.ReflectedIfaceMethodSets {
						if !rf.Valid() || rf.UnsafePtrCarrierBoxed != "" || isInactiveCapsuleOrCopyScoped(rf) {
							continue
						}
						if rf.ContextValueBoxed != "" || rf.NestedInConcreteBox != "" {
							ctxBoxed = append(ctxBoxed, ctxBoxedEntry{pkg: pkgPath, rf: rf})
							continue
						}
						if rf.MethodSet == syntaxutil.EmptyIfaceMethodSetKey {
							if rf.ReflectValueBoundaryEscape && anyConeLocalFlagROBypass {
								if !anyConeReflectAny || !anyConeFlagROBypass {
									anyConeReflectAny = true
									anyConeFlagROBypass = true
									resolveChanged = true
								}
								for bp := range localFlagROBypassPkgs {
									if !actualReflectAny[bp] || !actualReflectAnyFlagRO[bp] || !reachSeedReflectAny[bp] || !reachSeedReflectAnyFlagRO[bp] {
										actualReflectAny[bp] = true
										actualReflectAnyFlagRO[bp] = true
										reachSeedReflectAny[bp] = true
										reachSeedReflectAnyFlagRO[bp] = true
										resolveChanged = true
									}
									addConeReflected(syntaxutil.ReflectFlagROBypassAnyKey, bp)
								}
							}
							continue
						}
						if rf.MethodSet == syntaxutil.ReflectFlagROBypassAnyKey || rf.MethodSet == syntaxutil.ReflectRawUintptrToPtrKey {
							addConeReflected(rf.MethodSet, pkgPath)
							continue
						}
						if rf.MethodSet == syntaxutil.ContextKeyTheftMethodSetKey {
							thiefActive := len(rf.UnlessParamLeakFree) == 0
							for _, pk := range rf.UnlessParamLeakFree {
								if !paramLeakFree[pk] {
									thiefActive = true
									break
								}
							}
							if thiefActive {
								if anyConeReflectAny {
									addConeReflected(syntaxutil.ContextKeyTheftMethodSetKey, "*")
								}
								if anyConeFlagROBypass {
									addConeReflected(syntaxutil.ContextKeyTheftFlagROKey, "*")
								}
							}
							continue
						}
						if rf.UnexportedIfaceField {
							viaErased := len(rf.UnlessParamLeakFree) == 0 && rf.ErasedToEmptyIface && anyConeFlagROBypass
							viaRV := len(rf.UnlessParamLeakFree) == 0 && rf.ReflectValueBoundaryEscape && anyConeLocalFlagROBypass
							if len(rf.UnlessParamLeakFree) > 0 {
								for _, pk := range rf.UnlessParamLeakFree {
									if !paramLeakFree[pk] {
										if rf.ErasedToEmptyIface && pkgReachesReflectAnyFlagRO(pk.Func.Pkg, map[string]bool{}) {
											viaErased = true
										}
										if rf.ReflectValueBoundaryEscape && anyConeLocalFlagROBypass && pkgReachesReflectAny(pk.Func.Pkg, map[string]bool{}) {
											viaRV = true
										}
									}
								}
							}
							if viaErased {
								for bp := range actualReflectAnyFlagRO {
									addConeReflected(rf.MethodSet, bp)
									addConeReflected(syntaxutil.ReflectFlagROBypassPrefix+rf.MethodSet, bp)
								}
							}
							if viaRV {
								for bp := range localFlagROBypassPkgs {
									addConeReflected(rf.MethodSet, bp)
									addConeReflected(syntaxutil.ReflectFlagROBypassPrefix+rf.MethodSet, bp)
								}
							}
							continue
						}
						active := len(rf.UnlessParamLeakFree) == 0
						flagROViaErased := len(rf.UnlessParamLeakFree) == 0 && rf.ErasedToEmptyIface && anyConeFlagROBypass
						flagROViaRV := len(rf.UnlessParamLeakFree) == 0 && rf.ReflectValueBoundaryEscape && anyConeLocalFlagROBypass
						if len(rf.UnlessParamLeakFree) > 0 {
							for _, pk := range rf.UnlessParamLeakFree {
								if !paramLeakFree[pk] {
									if pkgReachesReflectAny(pk.Func.Pkg, map[string]bool{}) {
										active = true
									}
									if rf.ErasedToEmptyIface && pkgReachesReflectAnyFlagRO(pk.Func.Pkg, map[string]bool{}) {
										flagROViaErased = true
									}
								}
							}
							if active && rf.ReflectValueBoundaryEscape && anyConeLocalFlagROBypass {
								flagROViaRV = true
							}
						}
						if active {
							addConeReflected(rf.MethodSet, pkgPath)
							if rf.ErasedToEmptyIface {
								for ap := range actualReflectAny {
									addConeReflected(rf.MethodSet, ap)
								}
							}
						}
						if flagROViaErased {
							for bp := range actualReflectAnyFlagRO {
								addConeReflected(syntaxutil.ReflectFlagROBypassPrefix+rf.MethodSet, bp)
							}
						}
						if flagROViaRV {
							for bp := range localFlagROBypassPkgs {
								addConeReflected(syntaxutil.ReflectFlagROBypassPrefix+rf.MethodSet, bp)
							}
						}
					}
				}
			}
			for ctxChanged := len(ctxBoxed) > 0; ctxChanged; {
				ctxChanged = false
				for _, cb := range ctxBoxed {
					if cb.rf.NestedInConcreteBox != "" {
						flagBoxKey := syntaxutil.ReflectFlagROBypassPrefix + cb.rf.NestedInConcreteBox
						plainProvs := map[string]bool{}
						flagProvs := map[string]bool{}
						isExemptOpaqueGuardProv := func(prov string) bool {
							if !cb.rf.NestedOpaqueStruct.IsZero() {
								return cb.rf.NestedOpaqueStruct.Pkg == prov && nestedSafeCapsuleStructs[prov][cb.rf.NestedOpaqueStruct]
							}
							return cb.pkg == prov && len(safeCapsuleGuardStructs[prov]) > 0
						}
						for _, ms := range coneReflectedIfaces {
							if !cb.rf.UnexportedIfaceField && syntaxutil.MethodSetSubset(ms, cb.rf.NestedInConcreteBox) {
								for prov := range coneReflectedProviders[ms] {
									if !isExemptOpaqueGuardProv(prov) {
										plainProvs[prov] = true
									}
								}
							}
							if syntaxutil.MethodSetSubset(ms, flagBoxKey) {
								for prov := range coneReflectedProviders[ms] {
									if !isExemptOpaqueGuardProv(prov) {
										flagProvs[prov] = true
									}
								}
							}
						}
						plainHit := !cb.rf.UnexportedIfaceField && len(plainProvs) > 0
						flagHit := len(flagProvs) > 0
						if cb.rf.MethodSet == syntaxutil.EmptyIfaceMethodSetKey {
							if plainHit {
								if !anyConeReflectAny || !reachSeedReflectAny[cb.pkg] {
									anyConeReflectAny = true
									reachSeedReflectAny[cb.pkg] = true
									resolveChanged = true
								}
								if anyConeLocalFlagROBypass || anyConeFlagROBypass {
									if !anyConeFlagROBypass || !reachSeedReflectAnyFlagRO[cb.pkg] {
										anyConeFlagROBypass = true
										reachSeedReflectAnyFlagRO[cb.pkg] = true
										resolveChanged = true
									}
								}
								for prov := range plainProvs {
									if !actualReflectAny[prov] || !reachSeedReflectAny[prov] {
										actualReflectAny[prov] = true
										reachSeedReflectAny[prov] = true
										resolveChanged = true
									}
									if anyConeLocalFlagROBypass || anyConeFlagROBypass {
										if !anyConeFlagROBypass || !actualReflectAnyFlagRO[prov] || !reachSeedReflectAnyFlagRO[prov] {
											anyConeFlagROBypass = true
											actualReflectAnyFlagRO[prov] = true
											reachSeedReflectAnyFlagRO[prov] = true
											resolveChanged = true
										}
										if !seenRefIface[syntaxutil.ReflectFlagROBypassAnyKey] {
											ctxChanged = true
										}
										addConeReflectedWith(syntaxutil.ReflectFlagROBypassAnyKey, prov, "nested_any_plain", cb.pkg)
									}
								}
							}
							if flagHit {
								if !anyConeReflectAny || !anyConeFlagROBypass || !reachSeedReflectAny[cb.pkg] || !reachSeedReflectAnyFlagRO[cb.pkg] {
									anyConeReflectAny = true
									anyConeFlagROBypass = true
									reachSeedReflectAny[cb.pkg] = true
									reachSeedReflectAnyFlagRO[cb.pkg] = true
									resolveChanged = true
								}
								for prov := range flagProvs {
									if !actualReflectAny[prov] || !actualReflectAnyFlagRO[prov] || !reachSeedReflectAny[prov] || !reachSeedReflectAnyFlagRO[prov] {
										actualReflectAny[prov] = true
										actualReflectAnyFlagRO[prov] = true
										reachSeedReflectAny[prov] = true
										reachSeedReflectAnyFlagRO[prov] = true
										resolveChanged = true
									}
									if !seenRefIface[syntaxutil.ReflectFlagROBypassAnyKey] {
										ctxChanged = true
									}
									addConeReflectedWith(syntaxutil.ReflectFlagROBypassAnyKey, prov, "nested_any_flag", cb.pkg)
								}
							}
							continue
						}
						if plainHit || flagHit {
							for prov := range plainProvs {
								if !coneReflectedProviders[cb.rf.MethodSet][prov] {
									ctxChanged = true
								}
								addConeReflectedWith(cb.rf.MethodSet, prov, "nested_in_box_plain", cb.pkg)
							}
							for prov := range flagProvs {
								if !coneReflectedProviders[cb.rf.MethodSet][prov] {
									ctxChanged = true
								}
								addConeReflectedWith(cb.rf.MethodSet, prov, "nested_in_box_flag", cb.pkg)
							}
						}
						plainEscapesRV := false
						for prov := range plainProvs {
							if prov == "*" || rvBoundaryEscapePkgs[prov] || leaksAnyUpwardPkgs[prov] {
								plainEscapesRV = true
								break
							}
						}
						if flagHit || (plainHit && plainEscapesRV && (anyConeFlagROBypass || anyConeLocalFlagROBypass)) {
							flagKey := syntaxutil.ReflectFlagROBypassPrefix + cb.rf.MethodSet
							for prov := range flagProvs {
								if !coneReflectedProviders[flagKey][prov] {
									ctxChanged = true
								}
								addConeReflectedWith(flagKey, prov, "nested_in_box_flag", cb.pkg)
							}
							if plainHit && plainEscapesRV {
								for bp := range localFlagROBypassPkgs {
									if len(safeCapsuleGuardStructs[bp]) == 0 {
										if !coneReflectedProviders[flagKey][bp] {
											ctxChanged = true
										}
										addConeReflectedWith(flagKey, bp, "nested_in_box_rv_escape", cb.pkg)
									}
								}
								for bp := range actualReflectAnyFlagRO {
									if len(safeCapsuleGuardStructs[bp]) == 0 {
										if !coneReflectedProviders[flagKey][bp] {
											ctxChanged = true
										}
										addConeReflectedWith(flagKey, bp, "nested_in_box_rv_escape", cb.pkg)
									}
								}
							}
						}
						continue
					}
					if cb.rf.ContextValueBoxed == syntaxutil.ReflectRawUintptrToPtrKey {
						if seenRefIface[syntaxutil.ReflectRawUintptrToPtrKey] {
							if cb.rf.MethodSet == syntaxutil.EmptyIfaceMethodSetKey {
								if !anyConeReflectAny || !anyConeFlagROBypass ||
									!actualReflectAny[cb.pkg] || !actualReflectAnyFlagRO[cb.pkg] ||
									!reachSeedReflectAny[cb.pkg] || !reachSeedReflectAnyFlagRO[cb.pkg] {
									anyConeReflectAny = true
									anyConeFlagROBypass = true
									actualReflectAny[cb.pkg] = true
									actualReflectAnyFlagRO[cb.pkg] = true
									reachSeedReflectAny[cb.pkg] = true
									reachSeedReflectAnyFlagRO[cb.pkg] = true
									resolveChanged = true
								}
								if !seenRefIface[syntaxutil.ReflectFlagROBypassAnyKey] {
									ctxChanged = true
								}
								addConeReflected(syntaxutil.ReflectFlagROBypassAnyKey, cb.pkg)
							} else {
								flagKey := syntaxutil.ReflectFlagROBypassPrefix + cb.rf.MethodSet
								if !seenRefIface[cb.rf.MethodSet] || !seenRefIface[flagKey] {
									ctxChanged = true
								}
								addConeReflected(cb.rf.MethodSet, "*")
								addConeReflected(flagKey, "*")
							}
						}
						continue
					}
					ctxFlagRO := syntaxutil.ReflectFlagROBypassPrefix + cb.rf.ContextValueBoxed
					ctxBypassed := seenRefIface[ctxFlagRO]
					if !ctxBypassed {
						for _, ms := range coneReflectedIfaces {
							if syntaxutil.MethodSetSubset(ms, ctxFlagRO) {
								ctxBypassed = true
								break
							}
						}
					}
					if (seenRefIface[syntaxutil.ContextKeyTheftMethodSetKey] && !cb.rf.UnexportedIfaceField) ||
						seenRefIface[syntaxutil.ContextKeyTheftFlagROKey] || ctxBypassed {
						if !seenRefIface[cb.rf.MethodSet] {
							ctxChanged = true
						}
						addConeReflected(cb.rf.MethodSet, "*")
					}
					if seenRefIface[syntaxutil.ContextKeyTheftFlagROKey] ||
						(seenRefIface[syntaxutil.ContextKeyTheftMethodSetKey] && !cb.rf.UnexportedIfaceField && anyConeLocalFlagROBypass) ||
						(ctxBypassed && (anyConeFlagROBypass || anyConeLocalFlagROBypass)) {
						flagKey := syntaxutil.ReflectFlagROBypassPrefix + cb.rf.MethodSet
						if !seenRefIface[flagKey] {
							ctxChanged = true
						}
						addConeReflected(flagKey, "*")
					}
				}
			}
			for ui, ub := range unsafeCarrierBoxed {
				if promotedUnsafeCarriers[ui] {
					continue
				}
				ownerPkg := ub.pkg
				if ub.rf.NestedOpaqueOwnerPkg != "" {
					ownerPkg = ub.rf.NestedOpaqueOwnerPkg
				}
				matched := false
				matchedProvs := map[string]bool{}
				for _, ms := range coneReflectedIfaces {
					if syntaxutil.MethodSetSubset(ms, ub.rf.UnsafePtrCarrierBoxed) {
						for prov := range coneReflectedProviders[ms] {
							if len(safeCapsuleGuardStructs[prov]) == 0 || ownerPkg != prov {
								matched = true
								matchedProvs[prov] = true
							}
						}
					}
				}
				if matched {
					promotedUnsafeCarriers[ui] = true
					resolveChanged = true
					anyConeReflectAny = true
					anyConeFlagROBypass = true
					reachSeedReflectAny[ub.pkg] = true
					reachSeedReflectAnyFlagRO[ub.pkg] = true
					if len(matchedProvs) == 0 {
						matchedProvs[ub.pkg] = true
					}
					for prov := range matchedProvs {
						actualReflectAny[prov] = true
						actualReflectAnyFlagRO[prov] = true
						reachSeedReflectAny[prov] = true
						reachSeedReflectAnyFlagRO[prov] = true
						addConeReflectedWith(syntaxutil.ReflectFlagROBypassAnyKey, prov, "unsafe_carrier_box", ub.pkg+"|owner="+ownerPkg)
					}
				}
			}
		}

		changed := false
		for _, cm := range allCondStructMutations {
			if mutatedStructs[cm.Struct] {
				continue
			}
			triggerReason := ""
			triggerDetail := ""
			if cm.GuardPkg != "" && !pkgCannotRetainCarrier[cm.GuardPkg] {
				triggerReason = "guard_pkg_retains_carrier"
				triggerDetail = cm.GuardPkg
			}
			if triggerReason == "" && !cm.GuardStruct.IsZero() && !cm.RequireDescBuilderGuard && mutatedStructs[cm.GuardStruct] {
				triggerReason = "guard_struct_mutated"
				triggerDetail = cm.GuardStruct.Key()
			}
			if triggerReason == "" && cm.RequireDescBuilderGuard && !hasValidDescBuilderCovering(cm.GuardStruct) {
				triggerReason = "missing_desc_builder_guard"
				triggerDetail = cm.GuardStruct.Key()
			}
			if triggerReason == "" && !cm.RequireNonMutatingMethod.IsZero() && !nonMutatingMethods[cm.RequireNonMutatingMethod] {
				triggerReason = "method_mutates"
				triggerDetail = cm.RequireNonMutatingMethod.Display()
			}
			if triggerReason == "" && cm.BoxedConcreteMethodSet == "" && cm.ForeignReflectPkg != "" && !safeCapsuleGuardStructs[cm.ForeignReflectPkg][cm.Struct] {
				triggerReason = "foreign_reflect_pkg_unsafe"
				triggerDetail = cm.ForeignReflectPkg
			}
			if triggerReason == "" && !cm.UnlessSafeCapsuleStruct.IsZero() && !safePtrWrapperParams[cm.UnlessSafeCapsuleStruct][cm.UnlessSafeCapsuleParam] {
				triggerReason = "unsafe_ptr_wrapper_param"
				triggerDetail = cm.UnlessSafeCapsuleStruct.Key()
			}
			if triggerReason == "" && !cm.UnlessSafeAtomicPtrCopy.IsZero() && !safeAtomicPtrCopyFuncs[cm.UnlessSafeAtomicPtrCopy] {
				triggerReason = "unsafe_atomic_ptr_copy"
				triggerDetail = cm.UnlessSafeAtomicPtrCopy.Display()
			}
			if triggerReason == "" && cm.BoxedConcreteMethodSet != "" {
				for _, ifaceMS := range coneReflectedIfaces {
					if !syntaxutil.MethodSetSubset(ifaceMS, cm.BoxedConcreteMethodSet) {
						continue
					}
					if ifaceMS != syntaxutil.ReflectFlagROBypassAnyKey && ifaceMS != syntaxutil.ReflectRawUintptrToPtrKey {
						provs := coneReflectedProviders[ifaceMS]
						if !provs["*"] && len(provs) == 1 {
							var onlyProv string
							for pv := range provs {
								onlyProv = pv
							}
							guardPkg := cm.ForeignReflectPkg
							if guardPkg == "" && !cm.Struct.IsUnnamed() {
								guardPkg = cm.Struct.Pkg
							}
							if (guardPkg == "" || guardPkg == onlyProv) && safeCapsuleGuardStructs[onlyProv][cm.Struct] {
								continue
							}
						}
					}
					triggerReason = "boxed_iface_reflected"
					triggerDetail = ifaceMS
					break
				}
			}
			if triggerReason != "" {
				mutatedStructs[cm.Struct] = true
				changed = true
				if tgt := coneTargetFor(cm.Struct.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
					var provList []string
					if triggerReason == "boxed_iface_reflected" {
						for prov := range coneReflectedProviders[triggerDetail] {
							provList = append(provList, prov)
						}
						sort.Strings(provList)
					}
					trace.Emit(ctx, trace.DomainDynstate, "dynstate.cond_mut.trigger", tgt,
						trace.String("struct", cm.Struct.Key()),
						trace.String("reason", triggerReason),
						trace.String("detail", triggerDetail),
						trace.String("foreign_pkg", cm.ForeignReflectPkg),
						trace.Strings("providers", provList),
					)
				}
			}
		}
		if !changed {
			break
		}
	}

	populateResolvedConeDischarges(
		ctx,
		coneTargetFor,
		isKnownCleanNonStdPkg,
		pkgPaths,
		allFacts,
		pkgHasMalformedFact,
		malformedFactVars,
		anyMalformedMutatedStruct,
		anyMalformedDirectVarWrite,
		anyMalformedNonMethodVarUse,
		mutatedStructs,
		directVarWritten,
		nonMethodVarUsed,
		paramLeakFree,
		refRegions,
		initOnlyFn,
		commonRolesByPkg,
		&out,
	)
	return out
}
