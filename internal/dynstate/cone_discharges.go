package dynstate

import (
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
)

// walkImportCone traverses listing imports depth-first starting from roots,
// calling visit on each newly seen node present in imports. When visit returns
// false, traversal does not descend into that node's imports.
func walkImportCone(roots []string, imports func(string) ([]string, bool), visit func(string) bool) {
	seen := make(map[string]bool, len(roots))
	var step func(string)
	step = func(listing string) {
		if seen[listing] {
			return
		}
		imps, ok := imports(listing)
		if !ok {
			return
		}
		seen[listing] = true
		if !visit(listing) {
			return
		}
		for _, imp := range imps {
			step(imp)
		}
	}
	for _, root := range roots {
		step(root)
	}
}

func intersectPackageVariants[K comparable, V any](
	pkgFacts []Fact,
	extract func(Fact) map[K]V,
	merge func(prev, next V) (V, bool),
) map[K]V {
	if len(pkgFacts) == 0 {
		return nil
	}
	common := extract(pkgFacts[0])
	for fi := 1; fi < len(pkgFacts); fi++ {
		cur := extract(pkgFacts[fi])
		for k, prev := range common {
			next, ok := cur[k]
			if !ok {
				delete(common, k)
				continue
			}
			if merged, keep := merge(prev, next); keep {
				common[k] = merged
			} else {
				delete(common, k)
			}
		}
	}
	return common
}

func intersectDeclaredVariants[V any](
	pkgPaths []string,
	allFacts map[string][]Fact,
	pkgHasMalformed map[string]bool,
	malformedVars map[string]bool,
	extract func(pkgPath string, fact Fact) map[string]V,
	equal func(a, b V) bool,
) map[string]V {
	res := map[string]V{}
	for _, pkgPath := range pkgPaths {
		if pkgHasMalformed[pkgPath] {
			continue
		}
		perKeyVal := map[string]V{}
		perKeyValid := map[string]bool{}
		for _, fact := range allFacts[pkgPath] {
			present := extract(pkgPath, fact)
			for _, key := range fact.Declares {
				val, ok := present[key]
				if prevValid, seen := perKeyValid[key]; seen {
					if !prevValid || !ok || !equal(perKeyVal[key], val) {
						perKeyValid[key] = false
					}
				} else if ok {
					perKeyValid[key] = true
					perKeyVal[key] = val
				} else {
					perKeyValid[key] = false
				}
			}
		}
		for key, valid := range perKeyValid {
			if valid && !malformedVars[key] {
				res[key] = perKeyVal[key]
			}
		}
	}
	return res
}

type coneDischarges struct {
	pinnedPkg             map[string]bool
	mutableLocalPkg       map[string]bool
	mappingDischargedVars map[string]bool
	memoDischargedVars    map[string]bool
	harnessDischargedVars map[string]bool
	directiveCovered      map[string]bool
	protoVerifiedVars     map[string]bool
	grpcVerifiedVars      map[string]bool
}

func deriveConeDischarges(
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
	out := coneDischarges{
		pinnedPkg:       map[string]bool{},
		mutableLocalPkg: map[string]bool{},
	}
	for _, node := range meta {
		switch node.Class {
		case PinnedPackage:
			out.pinnedPkg[node.PkgPath] = true
		case MutableLocalPackage:
			out.mutableLocalPkg[node.PkgPath] = true
		}
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

	type rtRoleKey struct {
		Type syntaxutil.TypeRef
		Role string
	}
	type rtRoleInfo struct {
		SubBuilder     syntaxutil.TypeRef
		InitHelper     syntaxutil.FuncKey
		AllowedHelpers map[syntaxutil.FuncKey]bool
		GuardTypes     map[syntaxutil.TypeRef]bool
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
						cur[rtRoleKey{Type: rt.Type, Role: rt.Role}] = rtRoleInfo{
							SubBuilder:     rt.SubBuilder,
							InitHelper:     rt.InitHelper,
							AllowedHelpers: ah,
							GuardTypes:     gt,
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

	for len(allCondStructMutations) > 0 {
		changed := false
		for _, cm := range allCondStructMutations {
			if mutatedStructs[cm.Struct] {
				continue
			}
			triggered := false
			if cm.GuardPkg != "" && !pkgCannotRetainCarrier[cm.GuardPkg] {
				triggered = true
			}
			if !triggered && !cm.GuardStruct.IsZero() && !cm.RequireDescBuilderGuard && mutatedStructs[cm.GuardStruct] {
				triggered = true
			}
			if !triggered && cm.RequireDescBuilderGuard && !hasValidDescBuilderCovering(cm.GuardStruct) {
				triggered = true
			}
			if !triggered && !cm.RequireNonMutatingMethod.IsZero() && !nonMutatingMethods[cm.RequireNonMutatingMethod] {
				triggered = true
			}
			if triggered {
				mutatedStructs[cm.Struct] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	intersectDeclaredVarSet := func(extract func(pkgPath string, fact Fact) map[string]bool) map[string]bool {
		return intersectDeclaredVariants(
			pkgPaths,
			allFacts,
			pkgHasMalformedFact,
			malformedFactVars,
			extract,
			func(a, b bool) bool { return a == b },
		)
	}

	verifiedOnceMemoCtors := map[syntaxutil.TypeRef]map[syntaxutil.FuncKey]bool{}
	if !anyMalformedMutatedStruct {
		type onceMemoAgg struct {
			ctors     map[syntaxutil.FuncKey]bool
			guards    map[syntaxutil.TypeRef]bool
			inputDeps map[syntaxutil.ParamKey]bool
		}
		for _, pkgPath := range pkgPaths {
			pkgFacts := allFacts[pkgPath]
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] || (!out.pinnedPkg[pkgPath] && !out.mutableLocalPkg[pkgPath]) {
				continue
			}
			common := intersectPackageVariants(
				pkgFacts,
				func(fact Fact) map[syntaxutil.TypeRef]*onceMemoAgg {
					cur := make(map[syntaxutil.TypeRef]*onceMemoAgg, len(fact.OnceMemoTypes))
					for _, mt := range fact.OnceMemoTypes {
						if mt.Type.Pkg != pkgPath {
							continue
						}
						agg := &onceMemoAgg{
							ctors:     make(map[syntaxutil.FuncKey]bool, len(mt.Constructors)),
							guards:    make(map[syntaxutil.TypeRef]bool, len(mt.GuardTypes)),
							inputDeps: make(map[syntaxutil.ParamKey]bool, len(mt.InputParamDeps)),
						}
						for _, c := range mt.Constructors {
							agg.ctors[c] = true
						}
						for _, g := range mt.GuardTypes {
							agg.guards[g] = true
						}
						for _, pk := range mt.InputParamDeps {
							agg.inputDeps[pk] = true
						}
						cur[mt.Type] = agg
					}
					return cur
				},
				func(prev, next *onceMemoAgg) (*onceMemoAgg, bool) {
					for c := range prev.ctors {
						if !next.ctors[c] {
							delete(prev.ctors, c)
						}
					}
					for g := range next.guards {
						prev.guards[g] = true
					}
					for pk := range next.inputDeps {
						prev.inputDeps[pk] = true
					}
					return prev, true
				},
			)
			for tRef, agg := range common {
				if len(agg.ctors) == 0 || mutatedStructs[tRef] {
					continue
				}
				clean := true
				for g := range agg.guards {
					if mutatedStructs[g] {
						clean = false
						break
					}
				}
				if clean {
					for pk := range agg.inputDeps {
						if !paramLeakFree[pk] {
							clean = false
							break
						}
					}
				}
				if clean {
					verifiedOnceMemoCtors[tRef] = agg.ctors
				}
			}
		}
	}

	out.mappingDischargedVars = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.MappingDischarges))
		for _, key := range fact.MappingDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		return m
	})
	out.memoDischargedVars = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.MemoDischarges)+len(fact.OnceMemoCandidates))
		for _, key := range fact.MemoDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		if !anyMalformedNonMethodVarUse && !anyMalformedMutatedStruct {
			for _, cand := range fact.OnceMemoCandidates {
				if directVarWritten[cand.Key] || nonMethodVarUsed[cand.Key] {
					continue
				}
				if ctors := verifiedOnceMemoCtors[cand.Type]; ctors[cand.Constructor] {
					m[cand.Key] = true
				}
			}
		}
		return m
	})
	out.harnessDischargedVars = intersectDeclaredVarSet(func(pkgPath string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite || !propharness.IsHarnessPath(pkgPath) {
			return nil
		}
		m := make(map[string]bool, len(fact.HarnessDischarges))
		for _, key := range fact.HarnessDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		return m
	})
	out.directiveCovered = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		directed := make(map[string]bool, len(fact.SingleSubjectVars))
		for _, key := range fact.SingleSubjectVars {
			directed[key] = true
		}
		return directed
	})

	verifiedRoles := map[rtRoleKey]rtRoleInfo{}
	if !anyMalformedMutatedStruct {
		for _, common := range commonRolesByPkg {
			for k, info := range common {
				if k.Role != protoaudit.ProtoRoleBuilder && k.Role != protoaudit.ProtoRoleDescBuilder && mutatedStructs[k.Type] {
					continue
				}
				guardMutated := false
				for g := range info.GuardTypes {
					if mutatedStructs[g] {
						guardMutated = true
						break
					}
				}
				if !guardMutated {
					verifiedRoles[k] = info
				}
			}
		}
	}
	for k, info := range verifiedRoles {
		if k.Role == protoaudit.ProtoRoleBuilder && !info.SubBuilder.IsZero() {
			if _, ok := verifiedRoles[rtRoleKey{Type: info.SubBuilder, Role: protoaudit.ProtoRoleDescBuilder}]; !ok {
				delete(verifiedRoles, k)
			}
		}
	}

	builderAllowedHelperByPkg := map[string]map[syntaxutil.FuncKey]bool{}
	for k, info := range verifiedRoles {
		if k.Role == protoaudit.ProtoRoleBuilder && len(info.AllowedHelpers) > 0 {
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
	for k, info := range verifiedRoles {
		if k.Role == protoaudit.ProtoRoleExtension && !info.InitHelper.IsZero() && nonBuilderReferencedFn[info.InitHelper] {
			delete(verifiedRoles, k)
		}
	}
	hasVerifiedRole := func(t syntaxutil.TypeRef, role string) bool {
		_, ok := verifiedRoles[rtRoleKey{Type: t, Role: role}]
		return ok
	}

	out.protoVerifiedVars = intersectDeclaredVarSet(func(pkgPath string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := map[string]bool{}
		for _, c := range fact.ProtoClusters {
			if c.InitFn.Pkg != pkgPath || refRegions[c.InitFn] == nil || !initOnlyFn[c.InitFn] {
				continue
			}
			if !hasVerifiedRole(c.BuilderType, protoaudit.ProtoRoleBuilder) {
				continue
			}
			if !c.EnumType.IsZero() && !hasVerifiedRole(c.EnumType, protoaudit.ProtoRoleEnum) {
				continue
			}
			if !c.MsgType.IsZero() && !hasVerifiedRole(c.MsgType, protoaudit.ProtoRoleMessage) {
				continue
			}
			if !c.ExtType.IsZero() && !hasVerifiedRole(c.ExtType, protoaudit.ProtoRoleExtension) {
				continue
			}
			for _, key := range c.Vars {
				if !directVarWritten[key] {
					m[key] = true
				}
			}
		}
		return m
	})

	if !anyMalformedDirectVarWrite {
		extAliasTargets := intersectDeclaredVariants(
			pkgPaths,
			allFacts,
			pkgHasMalformedFact,
			malformedFactVars,
			func(_ string, fact Fact) map[string]string {
				byKey := make(map[string]string, len(fact.ProtoExtAliases))
				for _, a := range fact.ProtoExtAliases {
					if !directVarWritten[a.Key] {
						byKey[a.Key] = a.Target
					}
				}
				return byKey
			},
			func(a, b string) bool { return a == b },
		)
		for changed := len(extAliasTargets) > 0; changed; {
			changed = false
			for key, target := range extAliasTargets {
				if !out.protoVerifiedVars[key] && out.protoVerifiedVars[target] {
					out.protoVerifiedVars[key] = true
					changed = true
				}
			}
		}
	}

	out.grpcVerifiedVars = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedMutatedStruct || anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.GrpcServiceVars))
		for _, gv := range fact.GrpcServiceVars {
			if mutatedStructs[gv.SvcDesc] {
				continue
			}
			if !gv.MethodDesc.IsZero() && mutatedStructs[gv.MethodDesc] {
				continue
			}
			if !gv.StreamDesc.IsZero() && mutatedStructs[gv.StreamDesc] {
				continue
			}
			if directVarWritten[gv.Key] {
				continue
			}
			m[gv.Key] = true
		}
		return m
	})
	return out
}

func buildViewConeState(
	q ConeQuery,
	pkgPaths []string,
	allFacts map[string][]Fact,
	notOpaque map[string]bool,
	mutated map[string]bool,
	escaped map[string]bool,
	envCarrying map[string]bool,
	unattributedMark map[string]bool,
	siteFns map[string]map[string]bool,
	pkgHasMalformedFact map[string]bool,
	malformedFactVars map[string]bool,
	d coneDischarges,
) ConeState {
	var state ConeState
	vouchDischarged := map[string][]string{}
	attestedDischarged := map[string][]string{}
	dischargedSeen := map[string]bool{}

	vouchedOut := func(pkgPath, key string) bool {
		if !q.Vouches[key] || !d.pinnedPkg[pkgPath] {
			return false
		}
		if seen := "vouch\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			vouchDischarged[pkgPath] = append(vouchDischarged[pkgPath], key)
		}
		return true
	}
	auditedSourceOut := func(pkgPath, key string) bool {
		return (d.pinnedPkg[pkgPath] || d.mutableLocalPkg[pkgPath]) && !malformedFactVars[key] &&
			(d.mappingDischargedVars[key] || d.memoDischargedVars[key] || d.harnessDischargedVars[key])
	}
	directiveDischargedOut := func(pkgPath, key string) bool {
		if !q.SingleSubject || !d.mutableLocalPkg[pkgPath] || !d.directiveCovered[key] || malformedFactVars[key] {
			return false
		}
		if seen := "directive\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	protoGrpcDischargedOut := func(pkgPath, key string) bool {
		if !q.SingleSubject || (!d.pinnedPkg[pkgPath] && !d.mutableLocalPkg[pkgPath]) || malformedFactVars[key] {
			return false
		}
		if !d.protoVerifiedVars[key] && !d.grpcVerifiedVars[key] {
			return false
		}
		if seen := "proto\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	isDischarged := func(pkgPath, key string) bool {
		return vouchedOut(pkgPath, key) || auditedSourceOut(pkgPath, key) || directiveDischargedOut(pkgPath, key) || protoGrpcDischargedOut(pkgPath, key)
	}

	pkgCulprits := map[string][]Culprit{}
	culpritSeen := map[string]bool{}
	channelFor := func(pkgPath, key string) CulpritChannel {
		if d.mutableLocalPkg[pkgPath] {
			switch {
			case q.PackageProcess && d.directiveCovered[key]:
				return ChannelRestructureUnbackedDirective
			case q.PackageProcess:
				return ChannelRestructureDirectiveSingleSubjectOnly
			default:
				return ChannelRestructureOrDirective
			}
		}
		if envCarrying[key] {
			return ChannelCallerVouchEnvFree
		}
		return ChannelCallerVouch
	}
	recordCulprit := func(pkgPath, key string, verb CulpritVerb) {
		if seen := pkgPath + "\x00" + key; !culpritSeen[seen] {
			culpritSeen[seen] = true
			pkgCulprits[pkgPath] = append(pkgCulprits[pkgPath], Culprit{
				PkgPath: pkgPath,
				Key:     key,
				Verb:    verb,
				Channel: channelFor(pkgPath, key),
			})
		}
	}

	for _, pkgPath := range pkgPaths {
		var escapedKeys, envKeys []string
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if !syntaxutil.ValidFactKey(key) {
					continue
				}
				isMut := mutated[key]
				isEsc := escaped[key] && notOpaque[key]
				isEnv := envCarrying[key]
				if !isMut && !isEsc && !isEnv {
					continue
				}
				if isDischarged(pkgPath, key) {
					continue
				}
				if isMut {
					recordCulprit(pkgPath, key, CulpritMutated)
				} else if isEsc {
					escapedKeys = append(escapedKeys, key)
				} else if isEnv {
					envKeys = append(envKeys, key)
				}
			}
		}
		for _, key := range escapedKeys {
			recordCulprit(pkgPath, key, CulpritEscapes)
		}
		for _, key := range envKeys {
			recordCulprit(pkgPath, key, CulpritEnvCarrying)
		}
	}

	evidenceDischarged := map[string][]string{}
	evidenceSeen := map[string]bool{}
	if q.SingleSubject {
		for _, pkgPath := range pkgPaths {
			if pkgHasMalformedFact[pkgPath] {
				continue
			}
			for _, fact := range allFacts[pkgPath] {
				for _, key := range fact.PoolDischarges {
					if malformedFactVars[key] {
						continue
					}
					if seen := pkgPath + "\x00" + key; !evidenceSeen[seen] {
						evidenceSeen[seen] = true
						evidenceDischarged[pkgPath] = append(evidenceDischarged[pkgPath], key)
					}
				}
			}
		}
	}
	for pkgPath, keys := range attestedDischarged {
		for _, key := range keys {
			if seen := pkgPath + "\x00" + key; !evidenceSeen[seen] {
				evidenceSeen[seen] = true
				evidenceDischarged[pkgPath] = append(evidenceDischarged[pkgPath], key)
			}
		}
	}

	imports := make(map[string][]string, len(q.Meta))
	classes := make(map[string]PackageClass, len(q.Meta))
	pkgPathOf := make(map[string]string, len(q.Meta))
	var roots []string
	for _, node := range q.Meta {
		imports[node.ImportPath] = node.Imports
		classes[node.ImportPath] = node.Class
		pkgPathOf[node.ImportPath] = node.PkgPath
		root := node.PkgPath
		if node.ForTest != "" {
			root = node.ForTest
		} else if node.TestMain {
			continue
		}
		if root == q.ViewPackage {
			roots = append(roots, node.ImportPath)
		}
	}
	slices.SortFunc(roots, func(a, b string) int {
		aExt := pkgPathOf[a] != q.ViewPackage
		bExt := pkgPathOf[b] != q.ViewPackage
		if aExt != bExt {
			if !aExt {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	roots = slices.Compact(roots)

	vouchAcc := map[string]bool{}
	evidenceAcc := map[string]bool{}
	walkImportCone(
		roots,
		func(listing string) ([]string, bool) {
			imps, ok := imports[listing]
			return imps, ok
		},
		func(listing string) bool {
			if classes[listing] == StandardPackage {
				return false
			}
			pkgPath := pkgPathOf[listing]
			if culprits := pkgCulprits[pkgPath]; len(culprits) > 0 {
				if state.Downgraded == "" {
					pkg, sym := culprits[0].SubjectParts()
					state.Downgraded = culprits[0].ReasonBody()
					state.CulpritPkg = pkg
					state.CulpritSym = sym
				}
				state.RootCulprits = append(state.RootCulprits, culprits...)
			}
			for _, key := range vouchDischarged[pkgPath] {
				vouchAcc[key] = true
			}
			for _, key := range evidenceDischarged[pkgPath] {
				evidenceAcc[key] = true
			}
			return true
		},
	)

	if len(state.RootCulprits) > 0 {
		state.CulpritSites = make(map[string]CulpritSiteSet, len(state.RootCulprits))
		for _, culprit := range state.RootCulprits {
			if _, done := state.CulpritSites[culprit.Key]; done {
				continue
			}
			fns := siteFns[culprit.Key]
			state.CulpritSites[culprit.Key] = CulpritSiteSet{
				Fns:          fns,
				Unattributed: unattributedMark[culprit.Key] || len(fns) == 0,
			}
		}
	}
	if len(vouchAcc) > 0 {
		keys := make([]string, 0, len(vouchAcc))
		for key := range vouchAcc {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		state.VouchDischarges = strings.Join(keys, ",")
	}
	if len(evidenceAcc) > 0 {
		keys := make([]string, 0, len(evidenceAcc))
		for key := range evidenceAcc {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		state.AttestationDischarges = strings.Join(keys, ",")
	}
	return state
}
