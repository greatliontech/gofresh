package gofresh

import (
	"context"
	"encoding/json"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
)

// sharedDynamicStatePrefix opens every shared-dynamic-state downgrade
// diagnostic. The verdict uses the closure's typed refusal origin, never this
// spelling, to keep shared state outside the observation lift.
const sharedDynamicStatePrefix = "package graph shares mutated dynamic state: "

// scanFactsDirName is the view scan memo's sibling store directory:
// one entry per (scope, package scan key) holding the package's scan
// outputs (REQ-closure-scan-memo).
const scanFactsDirName = "scanfacts"

func loadScanFacts(scope, key string, payload any) bool {
	if scope == "" || key == "" {
		return false
	}
	return cachefile.Load(scanFactsDirName, scope, key, payload)
}

func storeScanFacts(scope, key string, payload any) {
	if scope == "" || key == "" {
		return
	}
	cachefile.Store(scanFactsDirName, scope, key, payload)
}

// scanViewSubjects performs one observation pass's whole subject scan: the
// metadata graph names every node and its mutability class, one typed load
// covers the view packages' variants and every mutable-local graph package,
// the dynamic-state derivation serves version-pinned facts from the memo, and
// the subject walk reads that one load (REQ-fresh-coherent-view). The typed
// load is installed on the hasher for the pass's sibling consumers. An empty
// factScope disables fact persistence, never the derivation. budget bounds
// the reachability discharges' precise analysis (zero: unbounded); a pass
// the budget cuts leaves every culprit standing and persists no scan facts
// of a package it cut — cut is the set of subjects it left undischarged
// (REQ-fresh-context, REQ-closure-shared-dynamic-state-reachability).
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	return scanViewSubjectsWithMemo(ctx, hasher, scope, buildFlags, budget, true, pkgPaths...)
}

func scanViewSubjectsWithMemo(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, useScanMemo bool, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	scope = hasher.SetAnalysisScope(scope)
	// The scope is the one source of the attestations and the vouches:
	// what keys a memo is what the derivation applies.
	factScope := scope.Facts()
	singleSubject, packageProcess := scope.SingleSubject, scope.PackageProcess
	vouches := make(map[string]bool, len(scope.Vouches))
	for _, v := range scope.Vouches {
		vouches[v] = true
	}
	// The scan memo: a view package whose scan the persistent store
	// already holds under this scope and its current package scan key
	// serves its subjects' outputs whole and takes no part in the typed
	// load, the derivation, or the discharges below — every output is a
	// pure function of the package's typed test-binary program, which
	// the key pins byte for byte (REQ-closure-scan-memo). A key that
	// cannot derive, or an entry that cannot load, recomputes.
	scanScope := scope.Scan()
	if !useScanMemo || isScanMemoOffViewHook() {
		scanScope = ""
	}
	served := map[string]packageScanEntry{}
	keys := map[string]string{}
	var misses []string
	for _, pkgPath := range pkgPaths {
		key, err := hasher.PackageScanKey(pkgPath)
		if err == nil {
			keys[pkgPath] = key
			var entry packageScanEntry
			if loadScanFacts(scanScope, key, &entry) && entry.Version == scanEntryVersion {
				served[pkgPath] = entry
				hasher.Served("scan", pkgPath)
				continue
			}
		}
		misses = append(misses, pkgPath)
	}
	if len(misses) == 0 {
		return scanFromEntries(served), nil, nil, nil
	}
	// Every listing, load, and derivation below reads the misses' graph
	// alone; a served package's cone costs the pass nothing.
	pkgPaths = misses
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
	// A test variant of a module-cache-resident view package: the view
	// packages are the only test-expanded ones, and a subject package
	// inside the read-only cache has no runnable tests to vouch for it —
	// refused from the listing, before the typed load below is paid, and
	// named rather than surfaced as a coverage gap. A pinned view package
	// with no test files carries no variant and derives through the
	// pinned-fact path as before.
	for _, node := range meta {
		if node.Class == closure.PinnedPackage && node.ForTest != "" && requested[node.ForTest] && (node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test") {
			return nil, nil, nil, fmt.Errorf("gofresh: view package %s resolves into the module cache; module-cache-resident subjects are unsupported", node.ForTest)
		}
	}
	patterns := append([]string(nil), pkgPaths...)
	seenPattern := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		seenPattern[pkgPath] = true
	}
	for _, node := range meta {
		// Plain mutable-local graph packages load as patterns; test
		// variants of the view packages load through the view patterns, and
		// an intermediate recompilation ("r [a.test]") is scanned from its
		// own compilation via the dependency-expanded fallback load in
		// deriveViewDynamicState — a plain stand-in would miss variant-only
		// resolution and need not even compile.
		if node.Class != closure.MutableLocalPackage || node.TestMain || node.ForTest != "" || seenPattern[node.PkgPath] {
			continue
		}
		seenPattern[node.PkgPath] = true
		patterns = append(patterns, node.PkgPath)
	}
	emitTypedLoadViewHook()
	hasher.Unit("typecheck", "", 0, len(patterns))
	load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
	if err != nil {
		return nil, nil, nil, err
	}
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, buildFlags, load, meta, pkgPaths, vouches, singleSubject, scope.PackageProcess)
	if err != nil {
		return nil, nil, nil, err
	}
	scan, err := scanSubjectsFromLoaded(hasher.SelectionAudited(), load.Packages(), state, pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	// The discharges' reachability analysis is precise analysis under
	// the caller's budget: bounded here alone — the listing, the typed
	// load, the derivation, and the closure fold stay under the
	// operation's own context (REQ-fresh-context).
	analysisCtx, cancelBudget := analysisBound(ctx, budget)
	defer cancelBudget()
	var cut map[Subject]bool
	emitBeforeDischargeViewHook()
	if singleSubject {
		// The attestation-gated reachability scoping: per downgraded
		// subject, a culprit whose every marking site is provably
		// outside the subject's rooted flow discharges — no proof, no
		// discharge (REQ-closure-shared-dynamic-state).
		if cut, err = dischargeUnreachableCulprits(ctx, analysisCtx, hasher, state, scan); err != nil {
			return nil, nil, nil, err
		}
	} else if packageProcess {
		// The package-process attestation's binary-scoped reachability
		// judgment: every measured process is the subject package's own
		// test binary, so sibling subjects are themselves harness roots
		// of the analyzed binary, and a culprit no harness root's
		// post-init flow can reach is init-determined for every subject
		// of the binary — no proof, no discharge
		// (REQ-closure-shared-dynamic-state).
		if cut, err = dischargeBinaryUnreachableCulprits(ctx, analysisCtx, hasher, state, scan); err != nil {
			return nil, nil, nil, err
		}
	}
	// Persist each missed package's outputs now that the discharges have
	// finished shaping them, then fold the served packages' in. A package
	// the budget cut persists nothing: its undischarged shape is the
	// budget's, not the program's, and the next pass derives it cold;
	// the other missed packages' facts are the program's and persist.
	cutPackages := map[string]bool{}
	for subject := range cut {
		cutPackages[subject.Package] = true
	}
	for _, pkgPath := range pkgPaths {
		if key := keys[pkgPath]; key != "" && !cutPackages[pkgPath] {
			storeScanFacts(scanScope, key, entryOf(scan, pkgPath))
		}
	}
	mergeEntries(scan, served)
	return scan, load, cut, nil
}

// scanEntryVersion versions the persisted scan entry — its shape and the
// text of every field it persists (a downgrade reason is scan output, so
// a change to its composition bumps the version); a bump recomputes
// rather than serving an older entry's text or misreading its shape.
const scanEntryVersion = 6

// subjectScanEntry is one subject's scan outputs as persisted.
type subjectScanEntry struct {
	Pure bool `json:"pure,omitempty"`
	// OpenWorld is the conferring term of an open-world subject — the
	// type parameter, receiver, or parameter whose type carries
	// dynamic reach — and empty for a closed one: one field, so an open
	// subject without its term is unrepresentable
	// (REQ-closure-refusal-channels).
	OpenWorld                string  `json:"openWorld,omitempty"`
	External                 bool    `json:"external,omitempty"`
	DowngradeReason          string  `json:"downgradeReason,omitempty"`
	DowngradeCulprit         Subject `json:"downgradeCulprit,omitempty"`
	VouchDischarges          string  `json:"vouchDischarges,omitempty"`
	AttestationDischarges    string  `json:"attestationDischarges,omitempty"`
	PackageProcessDischarges string  `json:"packageProcessDischarges,omitempty"`
	Ambiguous                string  `json:"ambiguous,omitempty"`
}

// packageScanEntry is one view package's scan outputs as persisted: every
// subject the scan knew in the package, by symbol.
type packageScanEntry struct {
	Version  int                         `json:"version"`
	Subjects map[string]subjectScanEntry `json:"subjects"`
}

// attestationDischarges holds the positive execution-model attestations'
// load-bearing discharge sets for one subject: carried as one comparable value
// across subjectScan, observationFacts, and Snapshot.Sibling so no attestation axis
// can be omitted when copying or clearing subject facts.
type attestationDischarges struct {
	singleSubject  string
	packageProcess string
}

// entryOf projects the scan's outputs for one package into its entry.
func entryOf(scan *subjectScan, pkgPath string) packageScanEntry {
	entry := packageScanEntry{Version: scanEntryVersion, Subjects: map[string]subjectScanEntry{}}
	for subject := range scan.known {
		if subject.Package != pkgPath {
			continue
		}
		d := scan.discharges[subject]
		entry.Subjects[subject.Symbol] = subjectScanEntry{
			Pure: scan.pure[subject], OpenWorld: scan.openWorld[subject], External: scan.external[subject],
			DowngradeReason: scan.downgradeReason[subject], DowngradeCulprit: scan.downgradeCulprit[subject],
			VouchDischarges:       scan.vouchDischarges[subject],
			AttestationDischarges: d.singleSubject, PackageProcessDischarges: d.packageProcess,
			Ambiguous: scan.ambiguous[subject],
		}
	}
	return entry
}

// mergeEntries folds served packages' entries into a scan.
func mergeEntries(scan *subjectScan, served map[string]packageScanEntry) {
	for pkgPath, entry := range served {
		for symbol, e := range entry.Subjects {
			subject := Subject{Package: pkgPath, Symbol: symbol}
			scan.known[subject] = true
			if e.Pure {
				scan.pure[subject] = true
			}
			if e.OpenWorld != "" {
				scan.openWorld[subject] = e.OpenWorld
			}
			if e.External {
				scan.external[subject] = true
			}
			if e.DowngradeReason != "" {
				scan.downgradeReason[subject] = e.DowngradeReason
			}
			if e.DowngradeCulprit != (Subject{}) {
				scan.downgradeCulprit[subject] = e.DowngradeCulprit
			}
			if e.VouchDischarges != "" {
				scan.vouchDischarges[subject] = e.VouchDischarges
			}
			if e.AttestationDischarges != "" || e.PackageProcessDischarges != "" {
				scan.discharges[subject] = attestationDischarges{
					singleSubject:  e.AttestationDischarges,
					packageProcess: e.PackageProcessDischarges,
				}
			}
			if e.Ambiguous != "" {
				scan.ambiguous[subject] = e.Ambiguous
			}
		}
	}
}

// scanFromEntries builds a scan entirely from served entries.
func scanFromEntries(served map[string]packageScanEntry) *subjectScan {
	scan := &subjectScan{
		pure: map[Subject]bool{}, known: map[Subject]bool{}, openWorld: map[Subject]string{}, external: map[Subject]bool{},
		downgradeReason: map[Subject]string{}, downgradeCulprit: map[Subject]Subject{},
		vouchDischarges: map[Subject]string{}, discharges: map[Subject]attestationDischarges{},
		ambiguous: map[Subject]string{},
	}
	mergeEntries(scan, served)
	return scan
}

// subjectScan is one observation pass's subject-walk result: enumeration,
// directive purity, per-subject dynamic-signature marks, and the subjects
// whose identity collapsed distinct declarations.
type subjectScan struct {
	pure  map[Subject]bool
	known map[Subject]bool
	// openWorld maps each open-world subject to the term conferring its
	// openness (REQ-closure-analysis's openness rule), the refusal's
	// named identity; a closed subject is absent
	// (REQ-closure-refusal-channels).
	openWorld map[Subject]string
	external  map[Subject]bool
	// downgradeReason maps each subject of a shared-dynamic-state
	// downgraded package to the refusal reason naming the owning package
	// and variable (REQ-closure-shared-dynamic-state-reason).
	downgradeReason  map[Subject]string
	downgradeCulprit map[Subject]Subject
	// vouchDischarges maps each subject to the canonical sorted
	// comma-joined caller-vouch identities that discharged would-be
	// culprits reachable from its package (REQ-vouch-recorded).
	vouchDischarges map[Subject]string
	// discharges maps each subject to the positive execution-model
	// attestations' load-bearing discharge sets (single-subject and
	// package-process) reachable from its package (REQ-vouch-recorded).
	discharges map[Subject]attestationDischarges
	// ambiguous holds, per subject whose identity is declared more than
	// once across the package and its test variants, the message naming
	// both declarations. Capture is refused for exactly these subjects —
	// no directive or assertion can be attributed to one declaration —
	// while sibling subjects scan normally (REQ-purity-directive).
	ambiguous map[Subject]string
}

func (s *subjectScan) directivePure(subject Subject) bool { return s.pure[subject] }

// scanSubjectsFromLoaded derives the subject walk — subject enumeration,
// directives, per-subject dynamic-signature marks — from an observation
// pass's already-loaded packages, applying the pass's dynamic-state
// derivation for the shared-dynamic-state downgrade and promoted-method
// directives (REQ-fresh-coherent-view, REQ-closure-shared-dynamic-state).
func scanSubjectsFromLoaded(audited bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	return scanSubjectsFromLoadedWith(audited, true, pkgs, state, pkgPaths...)
}

func scanSubjectsFromLoadedWith(audited, computeOpenWorld bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	scan := &subjectScan{
		pure:             map[Subject]bool{},
		known:            map[Subject]bool{},
		openWorld:        map[Subject]string{},
		external:         map[Subject]bool{},
		downgradeReason:  map[Subject]string{},
		downgradeCulprit: map[Subject]Subject{},
		vouchDischarges:  map[Subject]string{},
		discharges:       map[Subject]attestationDischarges{},
		ambiguous:        map[Subject]string{},
	}
	var cones map[string]map[string][]dynstate.Fact
	if state != nil {
		cones = state.cones
	}
	declarations := map[Subject]string{}
	err := dynstate.WalkLoadedSubjects(audited, computeOpenWorld, pkgs, cones, pkgPaths, func(s dynstate.ScannedSymbol) {
		subject := Subject{Package: s.Package, Symbol: s.Symbol}
		if previous := declarations[subject]; previous != "" && previous != s.Declaration {
			scan.ambiguous[subject] = fmt.Sprintf("declared at both %s and %s", previous, s.Declaration)
		} else {
			declarations[subject] = s.Declaration
			scan.known[subject] = true
		}
		if s.Pure {
			scan.pure[subject] = true
		}
		if s.External {
			scan.external[subject] = true
		}
		if s.OpenWorld != "" {
			scan.openWorld[subject] = s.OpenWorld
		}
	})
	if err != nil {
		return nil, err
	}
	for subject := range scan.ambiguous {
		delete(scan.pure, subject)
		delete(scan.external, subject)
	}
	if state != nil {
		for subject := range scan.known {
			if reason := state.downgraded[subject.Package]; reason != "" {
				scan.downgradeReason[subject] = sharedDynamicStatePrefix + reason
				if culprit := state.culprits[subject.Package]; culprit != (Subject{}) {
					scan.downgradeCulprit[subject] = culprit
				}
			}
			if discharges := state.vouchDischarges[subject.Package]; discharges != "" {
				scan.vouchDischarges[subject] = discharges
			}
			if attested := state.attestationDischarges[subject.Package]; attested != "" {
				scan.discharges[subject] = attestationDischarges{singleSubject: attested}
			}
		}
	}
	return scan, nil
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
var processFactCache cachefile.SyncMemo[dynstate.Fact]

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
}

func (s *viewDynamicState) methodDirectives(viewPackage string, m *types.Func) (pureKey, externalKey string) {
	if s == nil {
		return "", ""
	}
	return dynstate.MethodDirectives(s.cones, viewPackage, m)
}

// dischargeUnreachableCulprits applies the single-subject reachability
// scoping of the shared-dynamic-state judgment (REQ-closure-shared-dynamic-state).
func dischargeUnreachableCulprits(ctx, analysisCtx context.Context, hasher *closure.Hasher, state *viewDynamicState, scan *subjectScan) (cut map[Subject]bool, err error) {
	var downgraded []Subject
	for subject := range scan.known {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].Key].Unattributed {
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
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].Key].Unattributed {
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

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope string, buildFlags []string, load *closure.ViewLoad, meta []closure.GraphPackage, viewPackages []string, vouches map[string]bool, singleSubject, packageProcess bool) (*viewDynamicState, error) {
	state := &viewDynamicState{downgraded: map[string]string{}, culprits: map[string]Subject{}, cones: map[string]map[string][]dynstate.Fact{}}
	factsByListing := map[string]dynstate.Fact{}
	record := func(listing, _ string, fact dynstate.Fact) {
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
		record(listing, pkg.PkgPath, dynstate.FactOf(hasher.SelectionAudited(), pkg, singleSubject))
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
			record(listing, pkg.PkgPath, dynstate.FactOf(hasher.SelectionAudited(), pkg, singleSubject))
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
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynstate.FactOf(hasher.SelectionAudited(), pkg, singleSubject)
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
		coneMeta, coneFacts := dynstate.Cone(meta, nodesByListing, factsByListing, viewPackage)
		state.cones[viewPackage] = coneFacts
		composed := dynstate.Compose(coneMeta, coneFacts, viewPackage, vouches, singleSubject, packageProcess)
		if composed.Downgraded != "" {
			state.downgraded[viewPackage] = composed.Downgraded
			state.culprits[viewPackage] = Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym}
		}
		if composed.VouchDischarges != "" {
			if state.vouchDischarges == nil {
				state.vouchDischarges = map[string]string{}
			}
			state.vouchDischarges[viewPackage] = composed.VouchDischarges
		}
		if composed.AttestationDischarges != "" {
			if state.attestationDischarges == nil {
				state.attestationDischarges = map[string]string{}
			}
			state.attestationDischarges[viewPackage] = composed.AttestationDischarges
		}
		if len(composed.RootCulprits) > 0 {
			if state.rootCulprits == nil {
				state.rootCulprits = map[string][]dynstate.Culprit{}
				state.culpritSites = map[string]map[string]dynstate.CulpritSiteSet{}
			}
			state.rootCulprits[viewPackage] = composed.RootCulprits
			state.culpritSites[viewPackage] = composed.CulpritSites
		}
	}
	return state, nil
}
