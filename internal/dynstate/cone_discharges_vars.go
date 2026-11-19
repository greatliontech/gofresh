package dynstate

import (
	"context"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
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

type rtRoleKey struct {
	Type syntaxutil.TypeRef
	Role string
}

type rtRoleInfo struct {
	SubBuilder             syntaxutil.TypeRef
	InitHelper             syntaxutil.FuncKey
	AllowedHelpers         map[syntaxutil.FuncKey]bool
	GuardTypes             map[syntaxutil.TypeRef]bool
	CapsuleReflectSafe     bool
	SafePtrWrapperParams   map[syntaxutil.ParamKey]bool
	SafeAtomicPtrCopyFuncs map[syntaxutil.FuncKey]bool
}

func populateResolvedConeDischarges(
	ctx context.Context,
	coneTargetFor func(string) string,
	isKnownCleanNonStdPkg func(string) bool,
	pkgPaths []string,
	allFacts map[string][]Fact,
	pkgHasMalformedFact map[string]bool,
	malformedFactVars map[string]bool,
	anyMalformedMutatedStruct bool,
	anyMalformedDirectVarWrite bool,
	anyMalformedNonMethodVarUse bool,
	mutatedStructs map[syntaxutil.TypeRef]bool,
	directVarWritten map[string]bool,
	nonMethodVarUsed map[string]bool,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	refRegions map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool,
	initOnlyFn map[syntaxutil.FuncKey]bool,
	commonRolesByPkg map[string]map[rtRoleKey]rtRoleInfo,
	out *coneDischarges,
) {
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
					if !isKnownCleanNonStdPkg(g.Pkg) || mutatedStructs[g] {
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

	var validAliases map[string]syntaxutil.ReadOnlyVarAlias
	if !anyMalformedDirectVarWrite {
		validAliases = intersectDeclaredVariants(
			pkgPaths,
			allFacts,
			pkgHasMalformedFact,
			malformedFactVars,
			func(_ string, fact Fact) map[string]syntaxutil.ReadOnlyVarAlias {
				byKey := make(map[string]syntaxutil.ReadOnlyVarAlias, len(fact.ReadOnlyVarAliases))
				for _, a := range fact.ReadOnlyVarAliases {
					if !directVarWritten[a.Key] {
						byKey[a.Key] = a
					}
				}
				return byKey
			},
			func(a, b syntaxutil.ReadOnlyVarAlias) bool { return a == b },
		)
	}

	effectiveNonMethodUsed := make(map[string]bool, len(nonMethodVarUsed))
	for k := range nonMethodVarUsed {
		effectiveNonMethodUsed[k] = true
	}
	for _, pkgPath := range pkgPaths {
		for _, fact := range allFacts[pkgPath] {
			for _, a := range fact.ReadOnlyVarAliases {
				if !a.Valid() {
					continue
				}
				va, ok := validAliases[a.Key]
				if !ok || va != a || !va.DirectMethodsOnly {
					effectiveNonMethodUsed[a.Key] = true
					effectiveNonMethodUsed[a.Target] = true
				}
			}
		}
	}
	for changed := len(validAliases) > 0; changed; {
		changed = false
		for key, a := range validAliases {
			if effectiveNonMethodUsed[key] && !effectiveNonMethodUsed[a.Target] {
				effectiveNonMethodUsed[a.Target] = true
				changed = true
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
		m := make(map[string]bool, len(fact.MemoDischarges))
		for _, key := range fact.MemoDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		return m
	})
	out.onceMemoDischargedVars = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite || anyMalformedNonMethodVarUse || anyMalformedMutatedStruct {
			return nil
		}
		m := make(map[string]bool, len(fact.OnceMemoCandidates))
		for _, cand := range fact.OnceMemoCandidates {
			if directVarWritten[cand.Key] || effectiveNonMethodUsed[cand.Key] {
				continue
			}
			if ctors := verifiedOnceMemoCtors[cand.Type]; ctors[cand.Constructor] {
				m[cand.Key] = true
			}
		}
		return m
	})
	out.staticCompositeVars = intersectDeclaredVarSet(func(pkgPath string, fact Fact) map[string]bool {
		if anyMalformedMutatedStruct || anyMalformedDirectVarWrite {
			return nil
		}
		tgt := coneTargetFor(pkgPath)
		traced := trace.Enabled(ctx, trace.DomainDynstate, tgt)
		m := make(map[string]bool, len(fact.StaticCompositeGlobals))
		for _, sg := range fact.StaticCompositeGlobals {
			if directVarWritten[sg.Key] {
				if traced {
					emitDischargeReject(ctx, tgt, "static_composite_cone", sg.Key, "direct_var_written", "")
				}
				continue
			}
			clean := true
			for _, g := range sg.GuardTypes {
				if !isKnownCleanNonStdPkg(g.Pkg) || mutatedStructs[g] {
					clean = false
					if traced {
						emitDischargeReject(ctx, tgt, "static_composite_cone", sg.Key, "guard_type_mutated_or_unknown", g.Key())
					}
					break
				}
			}
			if clean {
				m[sg.Key] = true
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
					if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
						emitDischargeReject(ctx, tgt, "proto_role", k.Type.Key()+":"+k.Role, "role_struct_mutated", k.Type.Key())
					}
					continue
				}
				guardMutated := false
				for g := range info.GuardTypes {
					if mutatedStructs[g] {
						guardMutated = true
						if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
							emitDischargeReject(ctx, tgt, "proto_role", k.Type.Key()+":"+k.Role, "guard_type_mutated", g.Key())
						}
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
				if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
					emitDischargeReject(ctx, tgt, "proto_role", k.Type.Key()+":"+k.Role, "unverified_sub_builder", info.SubBuilder.Key())
				}
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
			if tgt := coneTargetFor(k.Type.Pkg); trace.Enabled(ctx, trace.DomainDynstate, tgt) {
				emitDischargeReject(ctx, tgt, "proto_role", k.Type.Key()+":"+k.Role, "non_builder_init_helper_ref", info.InitHelper.Display())
			}
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
		tgt := coneTargetFor(pkgPath)
		traced := trace.Enabled(ctx, trace.DomainDynstate, tgt)
		m := map[string]bool{}
		for _, c := range fact.ProtoClusters {
			if c.InitFn.Pkg != pkgPath || refRegions[c.InitFn] == nil || !initOnlyFn[c.InitFn] {
				if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", c.InitFn.Display(), "init_fn_not_init_only", "")
				}
				continue
			}
			if !hasVerifiedRole(c.BuilderType, protoaudit.ProtoRoleBuilder) {
				if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", c.InitFn.Display(), "unverified_builder_role", c.BuilderType.Key())
				}
				continue
			}
			if !c.EnumType.IsZero() && !hasVerifiedRole(c.EnumType, protoaudit.ProtoRoleEnum) {
				if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", c.InitFn.Display(), "unverified_enum_role", c.EnumType.Key())
				}
				continue
			}
			if !c.MsgType.IsZero() && !hasVerifiedRole(c.MsgType, protoaudit.ProtoRoleMessage) {
				if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", c.InitFn.Display(), "unverified_message_role", c.MsgType.Key())
				}
				continue
			}
			if !c.ExtType.IsZero() && !hasVerifiedRole(c.ExtType, protoaudit.ProtoRoleExtension) {
				if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", c.InitFn.Display(), "unverified_extension_role", c.ExtType.Key())
				}
				continue
			}
			for _, key := range c.Vars {
				if !directVarWritten[key] {
					m[key] = true
				} else if traced {
					emitDischargeReject(ctx, tgt, "proto_cluster", key, "direct_var_written", "")
				}
			}
		}
		return m
	})

	for changed := len(validAliases) > 0; changed; {
		changed = false
		for key, a := range validAliases {
			if !out.protoVerifiedVars[key] && out.protoVerifiedVars[a.Target] {
				out.protoVerifiedVars[key] = true
				changed = true
			}
			if !out.staticCompositeVars[key] && out.staticCompositeVars[a.Target] {
				out.staticCompositeVars[key] = true
				changed = true
			}
			// Backward closure of effectiveNonMethodUsed already revoked a.Target whenever
			// !a.DirectMethodsOnly, effectiveNonMethodUsed[key], or anyMalformedNonMethodVarUse holds.
			if !out.onceMemoDischargedVars[key] && out.onceMemoDischargedVars[a.Target] {
				out.onceMemoDischargedVars[key] = true
				changed = true
			}
		}
	}
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
		return d.isAttestationFreeDischarged(pkgPath, key, malformedFactVars)
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
	protoDischargedOut := func(pkgPath, key string) bool {
		if !d.isProtoAttestedDischarged(pkgPath, key, q.SingleSubject, malformedFactVars) {
			return false
		}
		if seen := "proto\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	isDischarged := func(pkgPath, key string) bool {
		return vouchedOut(pkgPath, key) || auditedSourceOut(pkgPath, key) || directiveDischargedOut(pkgPath, key) || protoDischargedOut(pkgPath, key)
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
