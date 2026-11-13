package dynstate

import (
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// Compose runs the shared-dynamic-state judgment for one view package over the
// facts of that package's own test-binary graph (REQ-closure-shared-dynamic-state,
// REQ-closure-scan-memo).
func Compose(meta []GraphPackage, allFacts map[string][]Fact, viewPackage string, vouches map[string]bool, singleSubject, packageProcess bool) ConeState {
	var start time.Time
	tracing := trace.Enabled(nil, trace.DomainDynstate, viewPackage)
	if tracing {
		start = time.Now()
	}
	var state ConeState
	mutated := map[string]bool{}
	escaped := map[string]bool{}
	envCarrying := map[string]bool{}
	unattributedMark := map[string]bool{}
	envCallable := map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.Mutates {
				mutated[key] = true
			}
			for _, key := range fact.Escapes {
				escaped[key] = true
			}
			if !singleSubject {
				for _, key := range fact.PoolMutates {
					mutated[key] = true
				}
				for _, key := range fact.PoolEscapes {
					escaped[key] = true
				}
			}
			for _, key := range fact.EnvCarrying {
				envCarrying[key] = true
			}
			for _, key := range fact.EnvCallable {
				envCallable[key] = true
			}
		}
	}
	malformedFactVars := map[string]bool{}
	markDeclaresMutated := func(fact Fact) {
		for _, key := range fact.Declares {
			mutated[key] = true
			unattributedMark[key] = true
			malformedFactVars[key] = true
		}
	}
	resolution := NewDeferralResolution(allFacts, markDeclaresMutated)
	envFreeResolved := resolution.EnvFreeResolved
	readOnly := resolution.ReadOnly
	paramLeakFree := resolution.ParamLeakFree
	refRegions := map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool{}

	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					for _, key := range fact.Declares {
						envCarrying[key] = true
					}
					if syntaxutil.ValidFactKey(use.Key) {
						envCarrying[use.Key] = true
						mutated[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !envFreeResolved[use.Callee] {
					envCarrying[use.Key] = true
				}
			}
			for _, use := range fact.MethodUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						mutated[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !readOnly[use.Method] {
					mutated[use.Key] = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !resolution.ReceiverRetention[use.Method] {
					escaped[use.Key] = true
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !paramLeakFree[use.Param] {
					escaped[use.Key] = true
				}
			}
			for _, use := range fact.InitParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !paramLeakFree[use.Param] && !resolution.ParamRetentionFree[use.Param] {
					escaped[use.Key] = true
				}
			}
			for _, use := range fact.FieldParamUses {
				if !use.Valid(0) {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Owner) {
						escaped[use.Owner] = true
						unattributedMark[use.Owner] = true
					}
					continue
				}
				if ok, _ := resolution.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
					escaped[use.Owner] = true
				}
			}
			for _, use := range fact.ElemParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if ok, _ := resolution.FieldPopulationProves(use.Owner, syntaxutil.ElemPositionField, use.Index); !ok {
					escaped[use.Key] = true
				}
			}
			for _, edge := range fact.FuncRefs {
				if !edge.Valid() {
					markDeclaresMutated(fact)
					if edge.Callee.Valid() {
						if refRegions[edge.Callee] == nil {
							refRegions[edge.Callee] = map[syntaxutil.RefRegion]bool{}
						}
						refRegions[edge.Callee][syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}] = true
					}
					continue
				}
				if refRegions[edge.Callee] == nil {
					refRegions[edge.Callee] = map[syntaxutil.RefRegion]bool{}
				}
				refRegions[edge.Callee][edge.Region] = true
			}
		}
	}

	initOnlyFn := map[syntaxutil.FuncKey]bool{}
	syntaxutil.SolveLeastFixedPoint(initOnlyFn, refRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit {
			return true
		}
		return region.Kind == syntaxutil.RegionFunc && initOnlyFn[region.Caller]
	})
	initReachFn := map[syntaxutil.FuncKey]bool{}
	syntaxutil.SolveReachFixedPoint(initReachFn, refRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit || region.Kind == syntaxutil.RegionProg {
			return true
		}
		return (region.Kind == syntaxutil.RegionFunc || region.Kind == syntaxutil.RegionLitFunc) && initReachFn[region.Caller]
	})

	for key := range mutated {
		unattributedMark[key] = true
	}
	for key := range escaped {
		unattributedMark[key] = true
	}
	for key := range envCarrying {
		if envCallable[key] {
			unattributedMark[key] = true
		}
	}
	siteFns := map[string]map[string]bool{}
	attributeSite := func(key string, fn syntaxutil.FuncKey) {
		if siteFns[key] == nil {
			siteFns[key] = map[string]bool{}
		}
		siteFns[key][fn.SiteKey()] = true
	}
	applyAttributedUse := func(fact Fact, use syntaxutil.AttributedUse, applyMarks bool) {
		if !use.Valid() {
			markDeclaresMutated(fact)
			if syntaxutil.ValidFactKey(use.Key) {
				mutated[use.Key] = true
				unattributedMark[use.Key] = true
			}
			return
		}
		if !applyMarks {
			return
		}
		fn, key := use.Func, use.Key
		if !use.Literal && use.Escape {
			escaped[key] = true
			attributeSite(key, fn)
			return
		}
		if use.Literal {
			if use.HasMethod {
				if readOnly[use.Method] {
					return
				}
				mutated[key] = true
			} else if use.Escape {
				escaped[key] = true
			} else {
				mutated[key] = true
			}
			if initReachFn[fn] || strings.Contains(fn.Name, ".") {
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if refRegions[fn] != nil && initOnlyFn[fn] {
			return
		}
		if use.HasMethod {
			if !readOnly[use.Method] {
				mutated[key] = true
				attributeSite(key, fn)
			}
		} else {
			mutated[key] = true
			attributeSite(key, fn)
		}
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.AttributedUses {
				applyAttributedUse(fact, use, true)
			}
			for _, use := range fact.PoolAttributedUses {
				applyAttributedUse(fact, use, !singleSubject)
			}
		}
	}
	for key, fns := range BlockedExportedSeams(allFacts, markDeclaresMutated) {
		mutated[key] = true
		for fn := range fns {
			if !fn.Valid() || initReachFn[fn] || strings.Contains(fn.Name, ".") {
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
		}
	}
	linkAdj := CarrierLinkGraph(allFacts, func(fact Fact) {
		markDeclaresMutated(fact)
		for _, link := range fact.CarrierLinks {
			if !link.Valid() {
				if syntaxutil.ValidFactKey(link.From) {
					mutated[link.From] = true
					unattributedMark[link.From] = true
				}
				if syntaxutil.ValidFactKey(link.To) {
					mutated[link.To] = true
					unattributedMark[link.To] = true
				}
			}
		}
	})
	if len(linkAdj) > 0 {
		propagateWithUnattributed := func(set map[string]bool) {
			if len(set) == 0 {
				return
			}
			queue := make([]string, 0, len(set))
			for k := range set {
				if linkAdj[k] != nil {
					queue = append(queue, k)
				}
			}
			for len(queue) > 0 {
				cur := queue[len(queue)-1]
				queue = queue[:len(queue)-1]
				for next := range linkAdj[cur] {
					if !set[next] {
						set[next] = true
						unattributedMark[next] = true
						queue = append(queue, next)
					}
				}
			}
		}
		propagateWithUnattributed(mutated)
		propagateWithUnattributed(escaped)
		propagateWithUnattributed(envCarrying)
	}
	notOpaque := resolution.NotOpaque
	discharges := deriveSourceAndAttestedDischarges(meta, allFacts, refRegions, initOnlyFn, malformedFactVars, markDeclaresMutated)
	pinnedPkg := discharges.pinnedPkg
	mutableLocalPkg := discharges.mutableLocalPkg
	pkgHasMalformedFact := discharges.pkgHasMalformedFact
	mappingDischargedVars := discharges.mappingDischargedVars
	memoDischargedVars := discharges.memoDischargedVars
	directiveCovered := discharges.directiveCovered
	protoVerifiedVars := discharges.protoVerifiedVars
	grpcVerifiedVars := discharges.grpcVerifiedVars

	vouchDischarged := map[string][]string{}
	dischargedSeen := map[string]bool{}
	vouchedOut := func(pkgPath, key string) bool {
		if !vouches[key] || !pinnedPkg[pkgPath] {
			return false
		}
		if seen := pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			vouchDischarged[pkgPath] = append(vouchDischarged[pkgPath], key)
		}
		return true
	}
	attestedDischarged := map[string][]string{}
	auditedSourceOut := func(pkgPath, key string) bool {
		return (pinnedPkg[pkgPath] || mutableLocalPkg[pkgPath]) && !malformedFactVars[key] &&
			(mappingDischargedVars[key] || memoDischargedVars[key])
	}
	directiveDischargedOut := func(pkgPath, key string) bool {
		if !singleSubject || !mutableLocalPkg[pkgPath] || !directiveCovered[key] || malformedFactVars[key] {
			return false
		}
		if seen := "directive\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	protoGrpcDischargedOut := func(pkgPath, key string) bool {
		if !singleSubject || (!pinnedPkg[pkgPath] && !mutableLocalPkg[pkgPath]) || malformedFactVars[key] {
			return false
		}
		if !protoVerifiedVars[key] && !grpcVerifiedVars[key] {
			return false
		}
		if seen := "proto\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	pkgCulprits := map[string][]Culprit{}
	culpritSeen := map[string]bool{}
	channelFor := func(pkgPath, key string) CulpritChannel {
		if mutableLocalPkg[pkgPath] {
			switch {
			case packageProcess && directiveCovered[key]:
				return ChannelRestructureUnbackedDirective
			case packageProcess:
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
	pkgPaths := make([]string, 0, len(allFacts))
	for pkgPath := range allFacts {
		pkgPaths = append(pkgPaths, pkgPath)
	}
	sort.Strings(pkgPaths)
	isDischarged := func(pkgPath, key string) bool {
		return vouchedOut(pkgPath, key) || auditedSourceOut(pkgPath, key) || directiveDischargedOut(pkgPath, key) || protoGrpcDischargedOut(pkgPath, key)
	}
	for _, pkgPath := range pkgPaths {
		var escapedKeys, envKeys []string
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
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
	imports := make(map[string][]string, len(meta))
	classes := make(map[string]PackageClass, len(meta))
	pkgPathOf := make(map[string]string, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		classes[node.ImportPath] = node.Class
		pkgPathOf[node.ImportPath] = node.PkgPath
	}
	var walk func(listing string, seen map[string]bool) (string, string, string)
	walk = func(listing string, seen map[string]bool) (string, string, string) {
		if seen[listing] {
			return "", "", ""
		}
		seen[listing] = true
		if classes[listing] == StandardPackage {
			return "", "", ""
		}
		if culprits := pkgCulprits[pkgPathOf[listing]]; len(culprits) > 0 {
			pkg, sym := culprits[0].SubjectParts()
			return culprits[0].ReasonBody(), pkg, sym
		}
		for _, imported := range imports[listing] {
			if _, ok := pkgPathOf[imported]; !ok {
				continue
			}
			if culprit, pkg, sym := walk(imported, seen); culprit != "" {
				return culprit, pkg, sym
			}
		}
		return "", "", ""
	}
	walkSeen := map[string]bool{}
	for _, node := range meta {
		root := node.PkgPath
		if node.ForTest != "" {
			root = node.ForTest
		} else if node.TestMain {
			continue
		}
		if root != viewPackage || state.Downgraded != "" {
			continue
		}
		if culprit, pkg, sym := walk(node.ImportPath, walkSeen); culprit != "" {
			state.Downgraded = culprit
			state.CulpritPkg = pkg
			state.CulpritSym = sym
		}
	}
	if len(pkgCulprits) > 0 && state.Downgraded != "" {
		state.CulpritSites = map[string]CulpritSiteSet{}
		var collectOrdered func(listing string, seen map[string]bool, acc *[]Culprit)
		collectOrdered = func(listing string, seen map[string]bool, acc *[]Culprit) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if classes[listing] == StandardPackage {
				return
			}
			*acc = append(*acc, pkgCulprits[pkgPathOf[listing]]...)
			for _, imported := range imports[listing] {
				if _, ok := pkgPathOf[imported]; !ok {
					continue
				}
				collectOrdered(imported, seen, acc)
			}
		}
		seen := map[string]bool{}
		for _, node := range meta {
			root := node.PkgPath
			if node.ForTest != "" {
				root = node.ForTest
			} else if node.TestMain {
				continue
			}
			if root != viewPackage {
				continue
			}
			var acc []Culprit
			collectOrdered(node.ImportPath, seen, &acc)
			state.RootCulprits = append(state.RootCulprits, acc...)
		}
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
	collectReachable := func(source map[string][]string) string {
		acc := map[string]bool{}
		seen := map[string]bool{}
		var collect func(listing string)
		collect = func(listing string) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if classes[listing] == StandardPackage {
				return
			}
			for _, key := range source[pkgPathOf[listing]] {
				acc[key] = true
			}
			for _, imported := range imports[listing] {
				if _, ok := pkgPathOf[imported]; !ok {
					continue
				}
				collect(imported)
			}
		}
		for _, node := range meta {
			root := node.PkgPath
			if node.ForTest != "" {
				root = node.ForTest
			} else if node.TestMain {
				continue
			}
			if root != viewPackage {
				continue
			}
			collect(node.ImportPath)
		}
		if len(acc) == 0 {
			return ""
		}
		keys := make([]string, 0, len(acc))
		for key := range acc {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}
	if len(vouchDischarged) > 0 {
		state.VouchDischarges = collectReachable(vouchDischarged)
	}
	evidenceDischarged := map[string][]string{}
	evidenceSeen := map[string]bool{}
	if singleSubject {
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
	if len(evidenceDischarged) > 0 {
		state.AttestationDischarges = collectReachable(evidenceDischarged)
	}
	if tracing {
		trace.Emit(nil, trace.DomainDynstate, "dynstate.compose.done", viewPackage,
			trace.Int("cone_pkgs", len(allFacts)),
			trace.Bool("downgraded", state.Downgraded != ""),
			trace.Int("culprits", len(state.RootCulprits)),
			trace.Int64("dur_ns", time.Since(start).Nanoseconds()),
		)
	}
	return state
}

type sourceAndAttestedDischarges struct {
	pinnedPkg             map[string]bool
	mutableLocalPkg       map[string]bool
	pkgHasMalformedFact   map[string]bool
	mappingDischargedVars map[string]bool
	memoDischargedVars    map[string]bool
	directiveCovered      map[string]bool
	protoVerifiedVars     map[string]bool
	grpcVerifiedVars      map[string]bool
}

func isFactDischargeMalformed(fact Fact) bool {
	bad := false
	for _, key := range fact.PoolDischarges {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, key := range fact.PoolMutates {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, key := range fact.PoolEscapes {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, key := range fact.SingleSubjectVars {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, key := range fact.MappingDischarges {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, key := range fact.MemoDischarges {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	for _, c := range fact.ProtoClusters {
		if !c.Valid() {
			bad = true
		}
	}
	for _, a := range fact.ProtoExtAliases {
		if !a.Valid() {
			bad = true
		}
	}
	for _, rt := range fact.ProtoRuntimeTypes {
		if !rt.Valid() {
			bad = true
		}
	}
	for _, gv := range fact.GrpcServiceVars {
		if !gv.Valid() {
			bad = true
		}
	}
	for _, tr := range fact.MutatedStructTypes {
		if !tr.Valid() {
			bad = true
		}
	}
	for _, cm := range fact.ConditionalStructMutations {
		if !cm.Valid() {
			bad = true
		}
	}
	if !fact.NoPostInitCarrierWrites && len(fact.CarrierImportCalls) > 0 {
		bad = true
	}
	for _, dep := range fact.CarrierImportCalls {
		if !syntaxutil.ValidNonEmptyPkgKey(dep) {
			bad = true
		}
	}
	for _, m := range fact.NonMutatingMethods {
		if !m.Valid() {
			bad = true
		}
	}
	for _, key := range fact.DirectVarWrites {
		if !syntaxutil.ValidQualifiedVarKey(key) {
			bad = true
		}
	}
	return bad
}

func deriveSourceAndAttestedDischarges(
	meta []GraphPackage,
	allFacts map[string][]Fact,
	refRegions map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool,
	initOnlyFn map[syntaxutil.FuncKey]bool,
	malformedFactVars map[string]bool,
	onMalformedFact func(Fact),
) sourceAndAttestedDischarges {
	out := sourceAndAttestedDischarges{
		pinnedPkg:           map[string]bool{},
		mutableLocalPkg:     map[string]bool{},
		pkgHasMalformedFact: map[string]bool{},
	}
	for _, node := range meta {
		switch node.Class {
		case PinnedPackage:
			out.pinnedPkg[node.PkgPath] = true
		case MutableLocalPackage:
			out.mutableLocalPkg[node.PkgPath] = true
		}
	}

	mutatedStructs := map[syntaxutil.TypeRef]bool{}
	directVarWritten := map[string]bool{}
	anyMalformedMutatedStruct := false
	anyMalformedDirectVarWrite := false
	var allCondStructMutations []syntaxutil.ConditionalStructMutation
	for pkgPath, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
			if isFactDischargeMalformed(fact) {
				out.pkgHasMalformedFact[pkgPath] = true
				for _, sibling := range pkgFacts {
					if onMalformedFact != nil {
						onMalformedFact(sibling)
					}
				}
			}
			for _, tr := range fact.MutatedStructTypes {
				if tr.Valid() {
					mutatedStructs[tr] = true
				} else {
					anyMalformedMutatedStruct = true
				}
			}
			for _, cm := range fact.ConditionalStructMutations {
				if cm.Valid() {
					allCondStructMutations = append(allCondStructMutations, cm)
				} else {
					anyMalformedMutatedStruct = true
				}
			}
			if !fact.NoPostInitCarrierWrites && len(fact.CarrierImportCalls) > 0 {
				anyMalformedMutatedStruct = true
			}
			for _, dep := range fact.CarrierImportCalls {
				if !syntaxutil.ValidNonEmptyPkgKey(dep) {
					anyMalformedMutatedStruct = true
				}
			}
			for _, m := range fact.NonMutatingMethods {
				if !m.Valid() || m.Pkg != pkgPath {
					anyMalformedMutatedStruct = true
				}
			}
			for _, key := range fact.DirectVarWrites {
				if syntaxutil.ValidQualifiedVarKey(key) {
					directVarWritten[key] = true
				} else {
					anyMalformedDirectVarWrite = true
				}
			}
		}
	}

	pkgCannotRetainCarrier := map[string]bool{}
	for pkgPath, pkgFacts := range allFacts {
		if len(pkgFacts) == 0 || out.pkgHasMalformedFact[pkgPath] {
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
	for {
		changed := false
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
		if !changed {
			break
		}
	}
	nonMutatingMethods := map[syntaxutil.FuncKey]bool{}
	if !anyMalformedMutatedStruct {
		for pkgPath, pkgFacts := range allFacts {
			if len(pkgFacts) == 0 || out.pkgHasMalformedFact[pkgPath] {
				continue
			}
			var common map[syntaxutil.FuncKey]bool
			for fi, fact := range pkgFacts {
				cur := make(map[syntaxutil.FuncKey]bool, len(fact.NonMutatingMethods))
				for _, m := range fact.NonMutatingMethods {
					if m.Pkg == pkgPath {
						cur[m] = true
					}
				}
				if fi == 0 {
					common = cur
					continue
				}
				for m := range common {
					if !cur[m] {
						delete(common, m)
					}
				}
			}
			for m := range common {
				nonMutatingMethods[m] = true
			}
		}
	}
	type descBuilderCandidate struct {
		builderType syntaxutil.TypeRef
		guardTypes  map[syntaxutil.TypeRef]bool
	}
	descBuilderCandidates := map[string][]descBuilderCandidate{}
	if !anyMalformedMutatedStruct {
		for pkgPath, pkgFacts := range allFacts {
			if len(pkgFacts) == 0 || out.pkgHasMalformedFact[pkgPath] {
				continue
			}
			var common map[syntaxutil.TypeRef]map[syntaxutil.TypeRef]bool
			for fi, fact := range pkgFacts {
				cur := map[syntaxutil.TypeRef]map[syntaxutil.TypeRef]bool{}
				for _, rt := range fact.ProtoRuntimeTypes {
					if rt.Type.Pkg != pkgPath || rt.Role != protoaudit.ProtoRoleDescBuilder {
						continue
					}
					gt := make(map[syntaxutil.TypeRef]bool, len(rt.GuardTypes))
					for _, g := range rt.GuardTypes {
						gt[g] = true
					}
					cur[rt.Type] = gt
				}
				if fi == 0 {
					common = cur
					continue
				}
				for bType, prevGT := range common {
					nextGT, ok := cur[bType]
					if !ok {
						delete(common, bType)
						continue
					}
					for g := range nextGT {
						prevGT[g] = true
					}
				}
			}
			for bType, gt := range common {
				descBuilderCandidates[pkgPath] = append(descBuilderCandidates[pkgPath], descBuilderCandidate{
					builderType: bType,
					guardTypes:  gt,
				})
			}
		}
	}
	hasValidDescBuilderCovering := func(guardStruct syntaxutil.TypeRef) bool {
		for _, cand := range descBuilderCandidates[guardStruct.Pkg] {
			if guardStruct != cand.builderType && !cand.guardTypes[guardStruct] {
				continue
			}
			clean := true
			for g := range cand.guardTypes {
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
		res := map[string]bool{}
		for pkgPath, pkgFacts := range allFacts {
			if out.pkgHasMalformedFact[pkgPath] {
				continue
			}
			perKey := map[string]bool{}
			for _, fact := range pkgFacts {
				present := extract(pkgPath, fact)
				for _, key := range fact.Declares {
					if covered, seen := perKey[key]; seen {
						perKey[key] = covered && present[key]
					} else {
						perKey[key] = present[key]
					}
				}
			}
			for key, covered := range perKey {
				if covered && !malformedFactVars[key] {
					res[key] = true
				}
			}
		}
		return res
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
	out.directiveCovered = intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		directed := make(map[string]bool, len(fact.SingleSubjectVars))
		for _, key := range fact.SingleSubjectVars {
			directed[key] = true
		}
		return directed
	})

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
	verifiedRoles := map[rtRoleKey]rtRoleInfo{}
	for pkgPath, pkgFacts := range allFacts {
		if len(pkgFacts) == 0 || out.pkgHasMalformedFact[pkgPath] {
			continue
		}
		var common map[rtRoleKey]rtRoleInfo
		for fi, fact := range pkgFacts {
			cur := map[rtRoleKey]rtRoleInfo{}
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
			if fi == 0 {
				common = cur
				continue
			}
			for k, prev := range common {
				next, ok := cur[k]
				if !ok || prev.InitHelper != next.InitHelper || prev.SubBuilder != next.SubBuilder {
					delete(common, k)
					continue
				}
				for h := range prev.AllowedHelpers {
					if !next.AllowedHelpers[h] {
						delete(prev.AllowedHelpers, h)
					}
				}
				for g := range next.GuardTypes {
					prev.GuardTypes[g] = true
				}
			}
		}
		for k, info := range common {
			if anyMalformedMutatedStruct {
				continue
			}
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
			if guardMutated {
				continue
			}
			verifiedRoles[k] = info
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
	for pkgPath, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
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

	extAliasTargets := map[string]string{}
	if !anyMalformedDirectVarWrite {
		for pkgPath, pkgFacts := range allFacts {
			if out.pkgHasMalformedFact[pkgPath] {
				continue
			}
			perKeyTarget := map[string]string{}
			perKeyValid := map[string]bool{}
			for _, fact := range pkgFacts {
				byKey := make(map[string]string, len(fact.ProtoExtAliases))
				for _, a := range fact.ProtoExtAliases {
					byKey[a.Key] = a.Target
				}
				for _, key := range fact.Declares {
					target, ok := byKey[key]
					if prevValid, seen := perKeyValid[key]; seen {
						if !prevValid || !ok || perKeyTarget[key] != target {
							perKeyValid[key] = false
						}
					} else if ok {
						perKeyValid[key] = true
						perKeyTarget[key] = target
					} else {
						perKeyValid[key] = false
					}
				}
			}
			for key, ok := range perKeyValid {
				if ok && !malformedFactVars[key] && !directVarWritten[key] {
					extAliasTargets[key] = perKeyTarget[key]
				}
			}
		}
	}
	for changed := len(extAliasTargets) > 0; changed; {
		changed = false
		for key, target := range extAliasTargets {
			if !out.protoVerifiedVars[key] && out.protoVerifiedVars[target] {
				out.protoVerifiedVars[key] = true
				changed = true
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

// NonVouchDischargedVars returns the set of declared dynamic-state variable keys
// discharged by mechanical source audits or active execution-model attestations
// (excluding caller vouches, whose derivation chains remain observable on
// request under REQ-explain-chain).
func NonVouchDischargedVars(meta []GraphPackage, allFacts map[string][]Fact, singleSubject bool) map[string]bool {
	malformedFactVars := map[string]bool{}
	markMalformed := func(fact Fact) {
		for _, key := range fact.Declares {
			malformedFactVars[key] = true
		}
	}
	NewDeferralResolution(allFacts, markMalformed)
	BlockedExportedSeams(allFacts, markMalformed)
	CarrierLinkGraph(allFacts, markMalformed)
	refRegions := map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			bad := false
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.MethodUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.InitParamUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.FieldParamUses {
				if !use.Valid(0) {
					bad = true
				}
			}
			for _, use := range fact.ElemParamUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.AttributedUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, use := range fact.PoolAttributedUses {
				if !use.Valid() {
					bad = true
				}
			}
			for _, edge := range fact.FuncRefs {
				if !edge.Valid() {
					bad = true
					if edge.Callee.Valid() {
						if refRegions[edge.Callee] == nil {
							refRegions[edge.Callee] = map[syntaxutil.RefRegion]bool{}
						}
						refRegions[edge.Callee][syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}] = true
					}
					continue
				}
				if refRegions[edge.Callee] == nil {
					refRegions[edge.Callee] = map[syntaxutil.RefRegion]bool{}
				}
				refRegions[edge.Callee][edge.Region] = true
			}
			if bad {
				markMalformed(fact)
			}
		}
	}
	initOnlyFn := map[syntaxutil.FuncKey]bool{}
	syntaxutil.SolveLeastFixedPoint(initOnlyFn, refRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit {
			return true
		}
		return region.Kind == syntaxutil.RegionFunc && initOnlyFn[region.Caller]
	})

	d := deriveSourceAndAttestedDischarges(meta, allFacts, refRegions, initOnlyFn, malformedFactVars, markMalformed)
	discharged := map[string]bool{}
	for pkgPath, pkgFacts := range allFacts {
		inGraph := d.pinnedPkg[pkgPath] || d.mutableLocalPkg[pkgPath]
		if !inGraph || d.pkgHasMalformedFact[pkgPath] {
			continue
		}
		for _, fact := range pkgFacts {
			for _, key := range fact.Declares {
				if malformedFactVars[key] {
					continue
				}
				if d.mappingDischargedVars[key] || d.memoDischargedVars[key] {
					discharged[key] = true
					continue
				}
				if singleSubject && d.mutableLocalPkg[pkgPath] && d.directiveCovered[key] {
					discharged[key] = true
					continue
				}
				if singleSubject && (d.protoVerifiedVars[key] || d.grpcVerifiedVars[key]) {
					discharged[key] = true
				}
			}
		}
	}
	return discharged
}
