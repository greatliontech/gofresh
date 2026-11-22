package gofresh

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/observability"
)

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
var processFactCache cachefile.SyncMemo[dynstate.Fact]

type modelDynamicState struct {
	downgraded            map[string]string
	culprits              map[string]Subject
	vouchDischarges       map[string]string
	attestationDischarges map[string]string
	rootCulprits          map[string][]dynstate.Culprit
	culpritSites          map[string]map[string]dynstate.CulpritSiteSet
}

func newModelDynamicState() *modelDynamicState {
	return &modelDynamicState{
		downgraded: map[string]string{},
		culprits:   map[string]Subject{},
	}
}

func recordComposedInModel(ms *modelDynamicState, viewPackage string, composed dynstate.ConeState) {
	if composed.Downgraded != "" {
		ms.downgraded[viewPackage] = composed.Downgraded
		ms.culprits[viewPackage] = Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym}
	}
	if composed.VouchDischarges != "" {
		if ms.vouchDischarges == nil {
			ms.vouchDischarges = map[string]string{}
		}
		ms.vouchDischarges[viewPackage] = composed.VouchDischarges
	}
	if composed.AttestationDischarges != "" {
		if ms.attestationDischarges == nil {
			ms.attestationDischarges = map[string]string{}
		}
		ms.attestationDischarges[viewPackage] = composed.AttestationDischarges
	}
	if len(composed.RootCulprits) > 0 {
		if ms.rootCulprits == nil {
			ms.rootCulprits = map[string][]dynstate.Culprit{}
			ms.culpritSites = map[string]map[string]dynstate.CulpritSiteSet{}
		}
		ms.rootCulprits[viewPackage] = composed.RootCulprits
		ms.culpritSites[viewPackage] = composed.CulpritSites
	}
}

// viewDynamicState is the per-pass dynamic-state derivation over one view's
// metadata graph: fresh facts for every mutable-local node from the pass's
// own typed load, memoized facts for version-pinned modules (persistent under
// factScope, in-process always), standard-library nodes skipped — inert by
// construction: their declaration side is excluded and toolchain source
// cannot reach module variables (imports are acyclic).
type viewDynamicState struct {
	cones                 map[string]map[string][]dynstate.Fact
	downgraded            map[string]string
	culprits              map[string]Subject
	vouchDischarges       map[string]string
	attestationDischarges map[string]string
	rootCulprits          map[string][]dynstate.Culprit
	culpritSites          map[string]map[string]dynstate.CulpritSiteSet
	drifted               map[string]bool
	byModel               [3]*modelDynamicState
	hasModel              [3]bool
}

func populateSubjectScanModels(scan *subjectScan, state *viewDynamicState) {
	populateOne := func(dst *modelScanState, src *modelDynamicState) {
		for subject := range scan.known {
			if scan.staticDecl[subject] {
				continue
			}
			if reason := src.downgraded[subject.Package]; reason != "" {
				dst.downgradeReason[subject] = sharedDynamicStatePrefix + reason
				if culprit := src.culprits[subject.Package]; culprit != (Subject{}) {
					dst.downgradeCulprit[subject] = culprit
				}
			}
			if discharges := src.vouchDischarges[subject.Package]; discharges != "" {
				dst.vouchDischarges[subject] = discharges
			}
			if attested := src.attestationDischarges[subject.Package]; attested != "" {
				dst.discharges[subject] = attestationDischarges{singleSubject: attested}
			}
		}
	}
	anyModel := false
	for m := range state.hasModel {
		if state.hasModel[m] && state.byModel[m] != nil {
			anyModel = true
			scan.hasModel[m] = true
			scan.byModel[m] = newModelScanState()
			populateOne(scan.byModel[m], state.byModel[m])
		}
	}
	legacy := &modelDynamicState{
		downgraded:            state.downgraded,
		culprits:              state.culprits,
		vouchDischarges:       state.vouchDischarges,
		attestationDischarges: state.attestationDischarges,
		rootCulprits:          state.rootCulprits,
		culpritSites:          state.culpritSites,
	}
	baseOut := &modelScanState{
		downgradeReason:  scan.downgradeReason,
		downgradeCulprit: scan.downgradeCulprit,
		vouchDischarges:  scan.vouchDischarges,
		discharges:       scan.discharges,
	}
	populateOne(baseOut, legacy)
	if !anyModel {
		scan.hasModel[GeneralExecution] = true
		scan.byModel[GeneralExecution] = baseOut
	}
}

// dischargeTestBinaryCulprits runs both single-subject and binary-scoped
// reachability culprit discharges over a single Prover pass per downgraded
// package so PackageExecution and SingleSubjectExecution snapshots project into
// each other without extra package reloads or SSA builds.
func dischargeTestBinaryCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) error {
	soloDS := state.byModel[SingleSubjectExecution]
	soloMS := scan.byModel[SingleSubjectExecution]
	pkgDS := state.byModel[PackageExecution]
	pkgMS := scan.byModel[PackageExecution]
	if soloDS == nil || soloMS == nil || pkgDS == nil || pkgMS == nil {
		return nil
	}

	var soloDowngraded []Subject
	for subject := range scan.known {
		if scan.staticDecl[subject] {
			continue
		}
		if culprits := soloDS.rootCulprits[subject.Package]; soloMS.downgradeReason[subject] != "" && len(culprits) > 0 && !soloDS.culpritSites[subject.Package][culprits[0].Key].Unattributed {
			soloDowngraded = append(soloDowngraded, subject)
		}
	}

	packageSubjects := map[string][]Subject{}
	var pkgDowngraded []Subject
	for subject := range scan.known {
		if scan.staticDecl[subject] {
			continue
		}
		if culprits := pkgDS.rootCulprits[subject.Package]; pkgMS.downgradeReason[subject] != "" && len(culprits) > 0 && !pkgDS.culpritSites[subject.Package][culprits[0].Key].Unattributed {
			packageSubjects[subject.Package] = append(packageSubjects[subject.Package], subject)
			pkgDowngraded = append(pkgDowngraded, subject)
		}
	}
	if len(soloDowngraded) == 0 && len(packageSubjects) == 0 {
		return nil
	}
	sortSubjects := func(list []Subject) {
		slices.SortFunc(list, func(a, b Subject) int {
			return cmp.Or(cmp.Compare(a.Package, b.Package), cmp.Compare(a.Symbol, b.Symbol))
		})
	}
	sortSubjects(soloDowngraded)
	sortSubjects(pkgDowngraded)
	for path, list := range packageSubjects {
		sortSubjects(list)
		packageSubjects[path] = list
	}

	soloRequests := make([]closure.Subject, len(soloDowngraded))
	for i, subject := range soloDowngraded {
		soloRequests[i] = closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
	}
	pkgPaths := make([]string, 0, len(packageSubjects))
	for path := range packageSubjects {
		pkgPaths = append(pkgPaths, path)
	}
	sort.Strings(pkgPaths)

	rooted, binaryInventories, err := observability.NewProver(hasher).ComputeRootedAndBinaryFunctions(analysisCtx, soloRequests, pkgPaths)
	if err != nil {
		cutSolo, cutErr := dischargeCut(ctx, analysisCtx, soloDowngraded, err)
		if cutErr != nil {
			return cutErr
		}
		cutPkg, _ := dischargeCut(ctx, analysisCtx, pkgDowngraded, err)
		scan.cutByModel[SingleSubjectExecution] = cutSolo
		scan.cutByModel[PackageExecution] = cutPkg
		return nil
	}

	for i, subject := range soloDowngraded {
		proof := rooted[soloRequests[i]]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulpritsModel(proof, soloDS, subject.Package)
		applyModelRootedCulpritDischarge(soloMS, subject, surviving, culprit, dischargedKeys, true)
	}
	for _, path := range pkgPaths {
		proof := binaryInventories[path]
		if !proof.Complete {
			continue
		}
		surviving, culprit, dischargedKeys := dischargeCulpritsModel(proof, pkgDS, path)
		for _, subject := range packageSubjects[path] {
			applyModelRootedCulpritDischarge(pkgMS, subject, surviving, culprit, dischargedKeys, false)
		}
	}
	return nil
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

func applyRootedCulpritDischarge(scan *subjectScan, subject Subject, surviving string, culprit Subject, dischargedKeys map[string]bool, singleSubject bool) {
	ms := &modelScanState{
		downgradeReason:  scan.downgradeReason,
		downgradeCulprit: scan.downgradeCulprit,
		vouchDischarges:  scan.vouchDischarges,
		discharges:       scan.discharges,
	}
	applyModelRootedCulpritDischarge(ms, subject, surviving, culprit, dischargedKeys, singleSubject)
}

func applyModelRootedCulpritDischarge(ms *modelScanState, subject Subject, surviving string, culprit Subject, dischargedKeys map[string]bool, singleSubject bool) {
	if surviving == "" {
		delete(ms.downgradeReason, subject)
		delete(ms.downgradeCulprit, subject)
	} else {
		ms.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
		ms.downgradeCulprit[subject] = culprit
	}
	if len(dischargedKeys) == 0 {
		return
	}
	d := ms.discharges[subject]
	if singleSubject {
		d.singleSubject = mergeDischargedKeys(d.singleSubject, dischargedKeys)
	} else {
		d.packageProcess = joinDischargedKeys(dischargedKeys)
	}
	ms.discharges[subject] = d
}

func mergeDischargedKeys(existing string, added map[string]bool) string {
	if existing == "" {
		return joinDischargedKeys(added)
	}
	merged := make(map[string]bool, len(added)+4)
	for key := range added {
		merged[key] = true
	}
	for _, key := range strings.Split(existing, ",") {
		if key != "" {
			merged[key] = true
		}
	}
	return joinDischargedKeys(merged)
}

// dischargeCulprits walks one package's root culprits against a
// complete rooted-flow inventory (REQ-closure-shared-dynamic-state).
func dischargeCulprits(proof observability.RootedFunctions, state *viewDynamicState, pkgPath string) (surviving string, culpritSubj Subject, discharged map[string]bool) {
	return dischargeCulpritsModel(proof, &modelDynamicState{
		rootCulprits: state.rootCulprits,
		culpritSites: state.culpritSites,
	}, pkgPath)
}

func dischargeCulpritsModel(proof observability.RootedFunctions, state *modelDynamicState, pkgPath string) (surviving string, culpritSubj Subject, discharged map[string]bool) {
	discharged = map[string]bool{}
	for _, culprit := range state.rootCulprits[pkgPath] {
		sites := state.culpritSites[pkgPath][culprit.Key]
		if sites.Unattributed {
			pkg, sym := culprit.SubjectParts()
			return culprit.ReasonBody(), Subject{Package: pkg, Symbol: sym}, discharged
		}
		for fn := range sites.Fns {
			if proof.Fns[fn] {
				pkg, sym := culprit.SubjectParts()
				return culprit.ReasonBody(), Subject{Package: pkg, Symbol: sym}, discharged
			}
		}
		discharged[culprit.Key] = true
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

func loadedPackageMatchesFiles(pkg *packages.Package, expected map[string]bool) bool {
	if pkg == nil || len(pkg.Errors) > 0 {
		return false
	}
	seen := make(map[string]bool, len(expected))
	for _, list := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.OtherFiles, pkg.EmbedFiles} {
		for _, path := range list {
			clean := filepath.Clean(path)
			if !expected[clean] {
				return false
			}
			seen[clean] = true
		}
	}
	return len(seen) == len(expected)
}

func loadedPackageMatchesImports(hasher *closure.Hasher, pkg *packages.Package, node closure.GraphPackage, nodesByListing map[string]closure.GraphPackage) bool {
	if pkg == nil {
		return false
	}
	expectedPaths := make(map[string]bool, len(node.Imports))
	for _, imp := range node.Imports {
		if imp == "C" || imp == "unsafe" {
			continue
		}
		impNode, exists := nodesByListing[imp]
		if !exists {
			return false
		}
		expectedPaths[impNode.PkgPath] = true
		impPkg := pkg.Imports[impNode.PkgPath]
		if impPkg == nil {
			return false
		}
		pkgDir, modDir := closure.LoadedPackageDirs(impPkg)
		gotClass, gotPin := hasher.ClassifyLoadedPackage(impPkg)
		if gotClass != impNode.Class {
			return false
		}
		switch impNode.Class {
		case closure.PinnedPackage:
			if modDir == "" || pkgDir == "" || gotPin != impNode.Pin {
				return false
			}
		case closure.MutableLocalPackage:
			if pkgDir == "" {
				return false
			}
		}
	}
	for impPath := range pkg.Imports {
		if impPath != "C" && impPath != "unsafe" && !expectedPaths[impPath] {
			return false
		}
	}
	return true
}

func coneLocalFilesMatch(hasher *closure.Hasher, listing string, pkg *packages.Package, loaded map[string]*packages.Package, nodesByListing map[string]closure.GraphPackage, expectedFiles map[string]map[string]bool) bool {
	if !loadedPackageMatchesFiles(pkg, expectedFiles[listing]) || !loadedPackageMatchesImports(hasher, pkg, nodesByListing[listing], nodesByListing) {
		return false
	}
	visited := map[string]bool{listing: true}
	ok := true
	var walk func(string)
	walk = func(cur string) {
		if !ok {
			return
		}
		for _, imp := range nodesByListing[cur].Imports {
			if visited[imp] {
				continue
			}
			visited[imp] = true
			node, exists := nodesByListing[imp]
			if !exists {
				continue
			}
			if node.Class == closure.MutableLocalPackage && !node.TestMain {
				impPkg := loaded[imp]
				if !loadedPackageMatchesFiles(impPkg, expectedFiles[imp]) || !loadedPackageMatchesImports(hasher, impPkg, node, nodesByListing) {
					ok = false
					return
				}
			}
			walk(imp)
		}
	}
	walk(listing)
	return ok
}

func verifySourceScanDrift(hasher *closure.Hasher, scanScope string, load *closure.ViewLoad, meta []closure.GraphPackage, viewPackages []string, preKeys map[string]string, expectedFiles map[string]map[string]bool) map[string]bool {
	drifted := map[string]bool{}
	if scanScope == "" || load == nil {
		return drifted
	}
	var postKeys map[string]string
	if len(preKeys) > 0 {
		postKeys, _ = hasher.MutableFactKeys(scanScope, meta, true, viewPackages...)
	}
	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	requestedViewPkg := make(map[string]bool, len(viewPackages))
	for _, vp := range viewPackages {
		requestedViewPkg[vp] = true
	}
	loadedLocal := map[string]*packages.Package{}
	matched := map[string]bool{}
	allDrifted := false
	for _, pkg := range load.Packages() {
		if gotool.IsGeneratedTestMainPackage(pkg) {
			continue
		}
		listing := gotool.LoadedListingID(pkg)
		node, ok := nodesByListing[listing]
		if !ok {
			if pkg.ForTest != "" && requestedViewPkg[pkg.ForTest] {
				drifted[pkg.ForTest] = true
			} else if pkg.Module != nil {
				allDrifted = true
			}
			continue
		}
		if node.Class != closure.MutableLocalPackage || node.TestMain {
			continue
		}
		matched[listing] = true
		loadedLocal[listing] = pkg
	}
	if allDrifted {
		for _, vp := range viewPackages {
			drifted[vp] = true
		}
		return drifted
	}
	driftedListings := map[string]bool{}
	for listing, pkg := range loadedLocal {
		key := preKeys[listing]
		verified := key != "" && key == postKeys[listing] && coneLocalFilesMatch(hasher, listing, pkg, loadedLocal, nodesByListing, expectedFiles)
		if !verified {
			driftedListings[listing] = true
		}
	}
	for _, node := range meta {
		if node.TestMain || node.Class != closure.MutableLocalPackage {
			continue
		}
		if node.ForTest != "" && node.PkgPath != node.ForTest && node.PkgPath != node.ForTest+"_test" {
			continue
		}
		if !matched[node.ImportPath] {
			driftedListings[node.ImportPath] = true
		}
	}
	for _, vp := range viewPackages {
		if drifted[vp] {
			continue
		}
		for _, node := range meta {
			if node.TestMain || (node.PkgPath != vp && node.ForTest != vp) {
				continue
			}
			if driftedListings[node.ImportPath] {
				drifted[vp] = true
				break
			}
		}
	}
	return drifted
}

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope string, buildFlags []string, load *closure.ViewLoad, meta []closure.GraphPackage, viewPackages []string, vouches map[string]bool, singleSubject, packageProcess bool, localFacts *localFactMemo, preFactKeys map[string]string, expectedFiles map[string]map[string]bool) (*viewDynamicState, error) {
	state := &viewDynamicState{downgraded: map[string]string{}, culprits: map[string]Subject{}, cones: map[string]map[string][]dynstate.Fact{}}
	if singleSubject || packageProcess {
		state.hasModel = [3]bool{true, true, true}
		state.byModel[GeneralExecution] = newModelDynamicState()
		state.byModel[PackageExecution] = newModelDynamicState()
		state.byModel[SingleSubjectExecution] = newModelDynamicState()
	} else {
		state.hasModel[GeneralExecution] = true
		state.byModel[GeneralExecution] = newModelDynamicState()
	}

	factsByListing := map[string]dynstate.Fact{}
	record := func(listing, _ string, fact dynstate.Fact) {
		factsByListing[listing] = fact
	}
	var postFactKeys map[string]string
	if len(preFactKeys) > 0 {
		postFactKeys, _ = hasher.MutableFactKeys(factScope, meta, true, viewPackages...)
	}
	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	driftedListings := map[string]bool{}
	driftedForTest := map[string]bool{}
	allViewPackagesDrifted := false
	deriveLocalFact := func(listing string, pkg *packages.Package, verifiedKeys map[string]string, loaded map[string]*packages.Package) dynstate.Fact {
		key := preFactKeys[listing]
		verified := key != "" && !allViewPackagesDrifted && !driftedForTest[pkg.PkgPath] && key == verifiedKeys[listing] && coneLocalFilesMatch(hasher, listing, pkg, loaded, nodesByListing, expectedFiles)
		if (key != "" && !verified) || !loadedPackageMatchesImports(hasher, pkg, nodesByListing[listing], nodesByListing) {
			driftedListings[listing] = true
		}
		if localFacts != nil && verified {
			if cached, ok := localFacts.load(key); ok {
				emitLocalFactLoadViewHook(listing, true)
				hasher.Served("dynamic-state facts", pkg.PkgPath)
				return cached
			}
			emitLocalFactLoadViewHook(listing, false)
			fact := dynstate.FactOfWithHooksCtx(ctx, hasher.SelectionAudited(), pkg, false, nil)
			localFacts.store(key, fact)
			return fact
		}
		emitLocalFactLoadViewHook(listing, false)
		return dynstate.FactOfWithHooksCtx(ctx, hasher.SelectionAudited(), pkg, false, nil)
	}

	requestedViewPkg := make(map[string]bool, len(viewPackages))
	for _, vp := range viewPackages {
		requestedViewPkg[vp] = true
	}
	extraVariantFacts := map[string][]*packages.Package{}
	loadedLocal := map[string]*packages.Package{}
	type localPkgEntry struct {
		listing string
		pkg     *packages.Package
	}
	var rootLocals []localPkgEntry
	matched := map[string]bool{}
	for _, pkg := range load.Packages() {
		if gotool.IsGeneratedTestMainPackage(pkg) {
			continue
		}
		listing := gotool.LoadedListingID(pkg)
		node, ok := nodesByListing[listing]
		if !ok {
			if pkg.ForTest != "" {
				if requestedViewPkg[pkg.ForTest] {
					driftedForTest[pkg.ForTest] = true
					extraVariantFacts[pkg.ForTest] = append(extraVariantFacts[pkg.ForTest], pkg)
				}
			} else if pkg.Module != nil {
				allViewPackagesDrifted = true
			}
			continue
		}
		if node.Class != closure.MutableLocalPackage || node.TestMain {
			continue
		}
		matched[listing] = true
		loadedLocal[listing] = pkg
		rootLocals = append(rootLocals, localPkgEntry{listing: listing, pkg: pkg})
	}
	for _, entry := range rootLocals {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		record(entry.listing, entry.pkg.PkgPath, deriveLocalFact(entry.listing, entry.pkg, postFactKeys, loadedLocal))
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
		var interPostKeys map[string]string
		if len(preFactKeys) > 0 {
			interPostKeys, _ = hasher.MutableFactKeys(factScope, meta, true, viewPackages...)
		}
		graphLoaded := make(map[string]*packages.Package, len(loadedLocal))
		for k, v := range loadedLocal {
			graphLoaded[k] = v
		}
		var interEntries []localPkgEntry
		packages.Visit(graphLoad.Packages(), nil, func(pkg *packages.Package) {
			if gotool.IsGeneratedTestMainPackage(pkg) {
				return
			}
			listing := gotool.LoadedListingID(pkg)
			node, ok := nodesByListing[listing]
			if !ok {
				if pkg.ForTest != "" && seenTested[pkg.ForTest] && pkg.Module != nil {
					driftedForTest[pkg.ForTest] = true
					extraVariantFacts[pkg.ForTest] = append(extraVariantFacts[pkg.ForTest], pkg)
				}
				return
			}
			if node.Class == closure.MutableLocalPackage && !node.TestMain {
				graphLoaded[listing] = pkg
			}
			if pkg.ForTest == "" || node.Class == closure.StandardPackage || matched[listing] {
				return
			}
			matched[listing] = true
			interEntries = append(interEntries, localPkgEntry{listing: listing, pkg: pkg})
		})
		for _, entry := range interEntries {
			if ctx != nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if nodesByListing[entry.listing].Class == closure.MutableLocalPackage {
				record(entry.listing, entry.pkg.PkgPath, deriveLocalFact(entry.listing, entry.pkg, interPostKeys, graphLoaded))
			} else {
				record(entry.listing, entry.pkg.PkgPath, dynstate.FactOfWithHooksCtx(ctx, hasher.SelectionAudited(), entry.pkg, false, nil))
			}
		}
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

	buckets, unkeyable := dynstate.PinnedBuckets(meta)
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
			record(node.ImportPath, node.PkgPath, cached)
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
			var fact dynstate.Fact
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
		emitDynamicStateMissLoadViewHook(patterns)
		hasher.Unit("typecheck", "", 0, len(patterns))
		missLoad, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
		if err != nil {
			return nil, err
		}
		derived := map[string]dynstate.Fact{}
		for _, pkg := range missLoad.Packages() {
			if ctx != nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynstate.FactOfWithHooksCtx(ctx, hasher.SelectionAudited(), pkg, false, nil)
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

	type preparedViewCone struct {
		viewPackage  string
		coneMeta     []closure.GraphPackage
		coneFacts    map[string][]dynstate.Fact
		genComposed  dynstate.ConeState
		pkgComposed  dynstate.ConeState
		soloComposed dynstate.ConeState
	}
	prepared := make([]preparedViewCone, len(viewPackages))
	for i, viewPackage := range viewPackages {
		coneMeta, coneFacts := dynstate.Cone(meta, nodesByListing, factsByListing, viewPackage)
		if extra := extraVariantFacts[viewPackage]; len(extra) > 0 {
			seenExtra := map[string]bool{}
			for _, node := range coneMeta {
				seenExtra[node.PkgPath] = true
			}
			for _, pkg := range extra {
				if ctx != nil {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
				}
				coneFacts[pkg.PkgPath] = append(coneFacts[pkg.PkgPath], dynstate.FactOfWithHooksCtx(ctx, hasher.SelectionAudited(), pkg, false, nil))
				if !seenExtra[pkg.PkgPath] {
					seenExtra[pkg.PkgPath] = true
					coneMeta = append(coneMeta, closure.GraphPackage{
						ImportPath: pkg.PkgPath,
						PkgPath:    pkg.PkgPath,
						ForTest:    pkg.ForTest,
						Class:      closure.MutableLocalPackage,
					})
				}
			}
		}
		drifted := allViewPackagesDrifted || driftedForTest[viewPackage]
		if !drifted {
			for _, node := range coneMeta {
				if driftedListings[node.ImportPath] {
					drifted = true
					break
				}
			}
		}
		if drifted {
			if state.drifted == nil {
				state.drifted = map[string]bool{}
			}
			state.drifted[viewPackage] = true
		}
		state.cones[viewPackage] = coneFacts
		prepared[i] = preparedViewCone{
			viewPackage: viewPackage,
			coneMeta:    coneMeta,
			coneFacts:   coneFacts,
		}
	}

	composeOne := func(item *preparedViewCone) {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		item.genComposed = dynstate.ComposeCtx(ctx, item.coneMeta, item.coneFacts, item.viewPackage, vouches, false, false)
		if singleSubject || packageProcess {
			if ctx != nil && ctx.Err() != nil {
				return
			}
			item.pkgComposed = dynstate.ComposeCtx(ctx, item.coneMeta, item.coneFacts, item.viewPackage, vouches, false, true)
			if ctx != nil && ctx.Err() != nil {
				return
			}
			item.soloComposed = dynstate.ComposeCtx(ctx, item.coneMeta, item.coneFacts, item.viewPackage, vouches, true, false)
		}
	}
	if len(prepared) <= 1 {
		for i := range prepared {
			composeOne(&prepared[i])
		}
	} else {
		workers := min(max(runtime.GOMAXPROCS(0), 1), len(prepared))
		var nextIdx atomic.Int64
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				for {
					if ctx != nil && ctx.Err() != nil {
						return
					}
					idx := int(nextIdx.Add(1) - 1)
					if idx >= len(prepared) {
						return
					}
					composeOne(&prepared[idx])
				}
			}()
		}
		wg.Wait()
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	activeModel := execModelFromBools(singleSubject, packageProcess)
	for i := range prepared {
		item := &prepared[i]
		viewPackage := item.viewPackage
		recordComposedInModel(state.byModel[GeneralExecution], viewPackage, item.genComposed)
		if singleSubject || packageProcess {
			recordComposedInModel(state.byModel[PackageExecution], viewPackage, item.pkgComposed)
			recordComposedInModel(state.byModel[SingleSubjectExecution], viewPackage, item.soloComposed)
		}

		activeDS := state.byModel[activeModel]
		if reason := activeDS.downgraded[viewPackage]; reason != "" {
			state.downgraded[viewPackage] = reason
			state.culprits[viewPackage] = activeDS.culprits[viewPackage]
		}
		if vd := activeDS.vouchDischarges[viewPackage]; vd != "" {
			if state.vouchDischarges == nil {
				state.vouchDischarges = map[string]string{}
			}
			state.vouchDischarges[viewPackage] = vd
		}
		if ad := activeDS.attestationDischarges[viewPackage]; ad != "" {
			if state.attestationDischarges == nil {
				state.attestationDischarges = map[string]string{}
			}
			state.attestationDischarges[viewPackage] = ad
		}
		if len(activeDS.rootCulprits[viewPackage]) > 0 {
			if state.rootCulprits == nil {
				state.rootCulprits = map[string][]dynstate.Culprit{}
				state.culpritSites = map[string]map[string]dynstate.CulpritSiteSet{}
			}
			state.rootCulprits[viewPackage] = activeDS.rootCulprits[viewPackage]
			state.culpritSites[viewPackage] = activeDS.culpritSites[viewPackage]
		}
	}
	return state, nil
}
