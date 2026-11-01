package gofresh

import (
	"context"
	"encoding/json"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"sync"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/dynstate"
)

// dynamicStateFact is one package's contribution to the shared-dynamic-state
// downgrade (REQ-closure-shared-dynamic-state) plus its method-directive
// declarations: everything the analysis needs from the package's syntax, so a
// version-pinned package's syntax never loads twice per key.
type dynamicStateFact = dynstate.Fact

// dynamicStateFactOf derives one typed package's fact. Pure function of the
// package's selected syntax and type environment plus the caller-attested
// single-subject-process execution model — the attestation changes what the
// fact records (the audited pooling set's discharge), so it is part of every
// fact-cache identity the fact is stored under
// (REQ-closure-dynamic-state-memo).
func dynamicStateFactOf(audited bool, p *packages.Package, singleSubject bool) dynamicStateFact {
	return dynstate.FactOf(audited, p, singleSubject)
}

const dynamicStateDirName = "dynamicstate"

func loadDynamicStateFacts(scope, bucket string) map[string]json.RawMessage {
	if scope == "" {
		return nil
	}
	var facts map[string]json.RawMessage
	if !cachefile.Load(dynamicStateDirName, scope, bucket, &facts) {
		return nil
	}
	return facts
}

func storeDynamicStateFacts(scope, bucket string, facts map[string]json.RawMessage) {
	if scope == "" {
		return
	}
	cachefile.Merge(dynamicStateDirName, scope, bucket, facts)
}

// processFactCache serves version-pinned package facts within one process.
// Keyed by (scope, bucket, package path) — the same complete identity the
// persistent memo trusts, so a hit is sound wherever the persistent entry
// would be.
var processFactCache sync.Map

// viewDynamicState is the per-pass dynamic-state derivation over one view's
// metadata graph: fresh facts for every mutable-local node from the pass's
// own typed load, memoized facts for version-pinned modules (persistent under
// factScope, in-process always), standard-library nodes skipped — inert by
// construction: their declaration side is excluded and toolchain source
// cannot reach module variables (imports are acyclic).
type viewDynamicState struct {
	cones                 map[string]map[string][]dynamicStateFact
	downgraded            map[string]string
	culprits              map[string]Subject
	vouchDischarges       map[string]string
	attestationDischarges map[string]string
	rootCulprits          map[string][]dynCulprit
	culpritSites          map[string]map[string]culpritSiteSet
}

// coneDynamicState is one view package's composed dynamic-state judgment over
// its own test-binary cone.
type coneDynamicState struct {
	downgraded            string
	culprit               Subject
	vouchDischarges       string
	attestationDischarges string
	rootCulprits          []dynCulprit
	culpritSites          map[string]culpritSiteSet
}

// dischargeUnreachableCulprits applies the single-subject reachability
// scoping of the shared-dynamic-state judgment (REQ-closure-shared-dynamic-state).
func dischargeUnreachableCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) (cut map[Subject]bool, err error) {
	var downgraded []Subject
	for subject := range scan.known {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].key].unattributed {
			downgraded = append(downgraded, subject)
		}
	}
	if len(downgraded) == 0 {
		return nil, nil
	}
	requests := make([]closure.Subject, len(downgraded))
	for i, subject := range downgraded {
		requests[i] = closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
	}
	rooted, err := hasher.ComputeRootedFunctions(analysisCtx, requests)
	if err != nil {
		return dischargeCut(ctx, analysisCtx, downgraded, err)
	}
	for i, subject := range downgraded {
		proof := rooted[requests[i]]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, subject.Package)
		if surviving == "" {
			delete(scan.downgradeReason, subject)
			delete(scan.downgradeCulprit, subject)
		} else {
			scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
			scan.downgradeCulprit[subject] = culprit
		}
		if len(dischargedKeys) > 0 {
			d := scan.discharges[subject]
			for _, key := range strings.Split(d.singleSubject, ",") {
				if key != "" {
					dischargedKeys[key] = true
				}
			}
			d.singleSubject = joinDischargedKeys(dischargedKeys)
			scan.discharges[subject] = d
		}
	}
	return nil, nil
}

// dischargeCut classifies a reachability analysis's failure
// (REQ-fresh-context, REQ-closure-shared-dynamic-state-reachability).
func dischargeCut(ctx, analysisCtx context.Context, downgraded []Subject, err error) (map[Subject]bool, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("gofresh: dynamic-state discharge cancelled: %w", ctx.Err())
	}
	if analysisCtx.Err() != nil {
		cut := make(map[Subject]bool, len(downgraded))
		for _, subject := range downgraded {
			cut[subject] = true
		}
		return cut, nil
	}
	return nil, err
}

// dischargeBinaryUnreachableCulprits applies the BINARY-scoped
// reachability judgment of the shared-dynamic-state invariant
// (REQ-closure-shared-dynamic-state).
func dischargeBinaryUnreachableCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) (cut map[Subject]bool, err error) {
	packageSubjects := map[string][]Subject{}
	var downgraded []Subject
	for subject := range scan.known {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].key].unattributed {
			packageSubjects[subject.Package] = append(packageSubjects[subject.Package], subject)
			downgraded = append(downgraded, subject)
		}
	}
	if len(packageSubjects) == 0 {
		return nil, nil
	}
	paths := make([]string, 0, len(packageSubjects))
	for path := range packageSubjects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	inventories, err := hasher.ComputeBinaryRootedFunctions(analysisCtx, paths)
	if err != nil {
		return dischargeCut(ctx, analysisCtx, downgraded, err)
	}
	for _, path := range paths {
		proof := inventories[path]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, path)
		for _, subject := range packageSubjects[path] {
			if surviving == "" {
				delete(scan.downgradeReason, subject)
				delete(scan.downgradeCulprit, subject)
			} else {
				scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
				scan.downgradeCulprit[subject] = culprit
			}
			if len(dischargedKeys) > 0 {
				d := scan.discharges[subject]
				d.packageProcess = joinDischargedKeys(dischargedKeys)
				scan.discharges[subject] = d
			}
		}
	}
	return nil, nil
}

// dischargeCulprits walks one package's root culprits against a
// complete rooted-flow inventory (REQ-closure-shared-dynamic-state).
func dischargeCulprits(proof closure.RootedFunctions, state *viewDynamicState, pkgPath string) (surviving string, culpritSubj Subject, discharged map[string]bool) {
	discharged = map[string]bool{}
	for _, culprit := range state.rootCulprits[pkgPath] {
		sites := state.culpritSites[pkgPath][culprit.key]
		if sites.unattributed {
			return culprit.reasonBody(), culprit.subject(), discharged
		}
		for fn := range sites.fns {
			if proof.Fns[fn] {
				return culprit.reasonBody(), culprit.subject(), discharged
			}
		}
		discharged[culprit.key] = true
	}
	return "", Subject{}, discharged
}

func joinDischargedKeys(discharged map[string]bool) string {
	keys := make([]string, 0, len(discharged))
	for key := range discharged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

var auditedSourceListing = dynstate.AuditedSourceListing

func generatedProtoHeader(text string) string {
	return dynstate.GeneratedProtoHeader(text)
}

type culpritVerb = dynstate.CulpritVerb
type culpritChannel = dynstate.CulpritChannel

type dynCulprit struct {
	pkgPath string
	key     string
	verb    culpritVerb
	channel culpritChannel
}

func (c dynCulprit) reasonBody() string {
	return (dynstate.Culprit{PkgPath: c.pkgPath, Key: c.key, Verb: c.verb, Channel: c.channel}).ReasonBody()
}

func (c dynCulprit) subject() Subject {
	pkg, sym := (dynstate.Culprit{PkgPath: c.pkgPath, Key: c.key, Verb: c.verb, Channel: c.channel}).SubjectParts()
	return Subject{Package: pkg, Symbol: sym}
}

type culpritSiteSet struct {
	fns          map[string]bool
	unattributed bool
}

func (s *viewDynamicState) methodDirectives(viewPackage string, m *types.Func) (pureKey, externalKey string) {
	if s == nil {
		return "", ""
	}
	return dynstate.MethodDirectives(s.cones, viewPackage, m)
}

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope string, buildFlags []string, load *closure.ViewLoad, viewPackages []string, vouches map[string]bool, singleSubject, packageProcess bool) (*viewDynamicState, error) {
	meta, err := hasher.GraphMetadata(viewPackages...)
	if err != nil {
		return nil, err
	}
	state := &viewDynamicState{downgraded: map[string]string{}, culprits: map[string]Subject{}, cones: map[string]map[string][]dynamicStateFact{}}
	factsByListing := map[string]dynamicStateFact{}
	record := func(listing, _ string, fact dynamicStateFact) {
		factsByListing[listing] = fact
	}

	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	matched := map[string]bool{}
	for _, pkg := range load.Packages() {
		listing := pkg.PkgPath
		if pkg.ForTest != "" {
			listing = pkg.PkgPath + " [" + pkg.ForTest + ".test]"
		}
		node, ok := nodesByListing[listing]
		if !ok || node.Class != closure.MutableLocalPackage || node.TestMain {
			continue
		}
		matched[listing] = true
		record(listing, pkg.PkgPath, dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject))
	}
	var testedWithIntermediates []string
	seenTested := map[string]bool{}
	for _, node := range meta {
		if node.Class == closure.StandardPackage || matched[node.ImportPath] || node.TestMain || node.ForTest == "" {
			continue
		}
		if node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test" {
			continue
		}
		if !seenTested[node.ForTest] {
			seenTested[node.ForTest] = true
			testedWithIntermediates = append(testedWithIntermediates, node.ForTest)
		}
	}
	if len(testedWithIntermediates) > 0 {
		sort.Strings(testedWithIntermediates)
		hasher.Unit("typecheck", "", 0, len(testedWithIntermediates))
		graphLoad, err := closure.LoadViewGraph(ctx, hasher.PassReader(), buildFlags, testedWithIntermediates...)
		if err != nil {
			return nil, err
		}
		packages.Visit(graphLoad.Packages(), nil, func(pkg *packages.Package) {
			if pkg.ForTest == "" {
				return
			}
			listing := pkg.PkgPath + " [" + pkg.ForTest + ".test]"
			node, ok := nodesByListing[listing]
			if !ok || node.Class == closure.StandardPackage || matched[listing] {
				return
			}
			matched[listing] = true
			record(listing, pkg.PkgPath, dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject))
		})
	}
	for _, node := range meta {
		if node.TestMain || node.Class == closure.StandardPackage || matched[node.ImportPath] {
			continue
		}
		if node.Class == closure.PinnedPackage && node.ForTest == "" {
			continue
		}
		return nil, fmt.Errorf("gofresh: dynamic-state scan did not cover package %s", node.ImportPath)
	}

	buckets, unkeyable := pinnedBuckets(meta)
	var missing []closure.GraphPackage
	persisted := map[string]map[string]json.RawMessage{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage || node.ForTest != "" || node.TestMain {
			continue
		}
		if factScope == "" || unkeyable[node.Pin] {
			missing = append(missing, node)
			continue
		}
		bucket := buckets[node.Pin]
		cacheKey := factScope + "\x00" + bucket + "\x00" + node.PkgPath
		if cached, ok := processFactCache.Load(cacheKey); ok {
			record(node.ImportPath, node.PkgPath, cached.(dynamicStateFact))
			continue
		}
		if persisted[bucket] == nil {
			if facts := loadDynamicStateFacts(factScope, bucket); facts != nil {
				persisted[bucket] = facts
			} else {
				persisted[bucket] = map[string]json.RawMessage{}
			}
		}
		if raw, ok := persisted[bucket][node.PkgPath]; ok {
			var fact dynamicStateFact
			if json.Unmarshal(raw, &fact) == nil {
				hasher.Served("dynamic-state facts", node.PkgPath)
				processFactCache.Store(cacheKey, fact)
				record(node.ImportPath, node.PkgPath, fact)
				continue
			}
		}
		missing = append(missing, node)
	}
	if len(missing) > 0 {
		patterns := make([]string, 0, len(missing))
		for _, node := range missing {
			patterns = append(patterns, node.PkgPath)
		}
		sort.Strings(patterns)
		if viewTestHooks.dynamicStateMissLoad != nil {
			viewTestHooks.dynamicStateMissLoad(patterns)
		}
		hasher.Unit("typecheck", "", 0, len(patterns))
		missLoad, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
		if err != nil {
			return nil, err
		}
		derived := map[string]dynamicStateFact{}
		for _, pkg := range missLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynamicStateFactOf(hasher.SelectionAudited(), pkg, singleSubject)
		}
		store := map[string]map[string]json.RawMessage{}
		for _, node := range missing {
			fact, ok := derived[node.PkgPath]
			if !ok {
				return nil, fmt.Errorf("gofresh: dynamic-state scan did not load pinned package %s", node.PkgPath)
			}
			record(node.ImportPath, node.PkgPath, fact)
			if factScope == "" || unkeyable[node.Pin] {
				continue
			}
			bucket := buckets[node.Pin]
			processFactCache.Store(factScope+"\x00"+bucket+"\x00"+node.PkgPath, fact)
			if raw, err := json.Marshal(fact); err == nil {
				if store[bucket] == nil {
					store[bucket] = map[string]json.RawMessage{}
				}
				store[bucket][node.PkgPath] = raw
			}
		}
		for bucket, facts := range store {
			storeDynamicStateFacts(factScope, bucket, facts)
		}
	}

	for _, viewPackage := range viewPackages {
		coneMeta, coneFacts := dynamicStateCone(meta, nodesByListing, factsByListing, viewPackage)
		state.cones[viewPackage] = coneFacts
		cone := composeDynamicState(coneMeta, coneFacts, viewPackage, vouches, singleSubject, packageProcess)
		if cone.downgraded != "" {
			state.downgraded[viewPackage] = cone.downgraded
			state.culprits[viewPackage] = cone.culprit
		}
		if cone.vouchDischarges != "" {
			if state.vouchDischarges == nil {
				state.vouchDischarges = map[string]string{}
			}
			state.vouchDischarges[viewPackage] = cone.vouchDischarges
		}
		if cone.attestationDischarges != "" {
			if state.attestationDischarges == nil {
				state.attestationDischarges = map[string]string{}
			}
			state.attestationDischarges[viewPackage] = cone.attestationDischarges
		}
		if len(cone.rootCulprits) > 0 {
			if state.rootCulprits == nil {
				state.rootCulprits = map[string][]dynCulprit{}
				state.culpritSites = map[string]map[string]culpritSiteSet{}
			}
			state.rootCulprits[viewPackage] = cone.rootCulprits
			state.culpritSites[viewPackage] = cone.culpritSites
		}
	}
	return state, nil
}

func composeDynamicState(meta []closure.GraphPackage, allFacts map[string][]dynamicStateFact, viewPackage string, vouches map[string]bool, singleSubject, packageProcess bool) coneDynamicState {
	composed := dynstate.Compose(meta, allFacts, viewPackage, vouches, singleSubject, packageProcess)
	out := coneDynamicState{
		downgraded:            composed.Downgraded,
		culprit:               Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym},
		vouchDischarges:       composed.VouchDischarges,
		attestationDischarges: composed.AttestationDischarges,
	}
	if len(composed.RootCulprits) > 0 {
		out.rootCulprits = make([]dynCulprit, len(composed.RootCulprits))
		for i, c := range composed.RootCulprits {
			out.rootCulprits[i] = dynCulprit{
				pkgPath: c.PkgPath,
				key:     c.Key,
				verb:    c.Verb,
				channel: c.Channel,
			}
		}
		out.culpritSites = make(map[string]culpritSiteSet, len(composed.CulpritSites))
		for k, s := range composed.CulpritSites {
			out.culpritSites[k] = culpritSiteSet{
				fns:          s.Fns,
				unattributed: s.Unattributed,
			}
		}
	}
	return out
}

func dynamicStateCone(meta []closure.GraphPackage, byListing map[string]closure.GraphPackage, factsByListing map[string]dynamicStateFact, viewPackage string) ([]closure.GraphPackage, map[string][]dynamicStateFact) {
	return dynstate.Cone(meta, byListing, factsByListing, viewPackage)
}

func pinnedBuckets(meta []closure.GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	return dynstate.PinnedBuckets(meta)
}

func newDeferralResolution(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) *dynstate.DeferralResolution {
	return dynstate.NewDeferralResolution(allFacts, malformed)
}

func resolveEnvAudit(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) *dynstate.EnvAuditResolution {
	return dynstate.ResolveEnvAudit(allFacts, malformed)
}

func carrierLinkGraph(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) map[string]map[string]bool {
	return dynstate.CarrierLinkGraph(allFacts, malformed)
}
