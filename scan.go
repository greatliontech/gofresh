package gofresh

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
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

// scanViewSubjects performs one observation pass's subject scan across the
// metadata graph, one coherent typed load, memoized version-pinned facts, and
// budget-bounded reachability discharges (REQ-fresh-coherent-view,
// REQ-fresh-context, REQ-closure-shared-dynamic-state-reachability).
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, useScanMemo bool, localFacts *localFactMemo, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	return scanViewSubjectsWithMode(ctx, hasher, scope, buildFlags, budget, useScanMemo, localFacts, false, execModelFromBools(scope.SingleSubject, scope.PackageProcess), pkgPaths...)
}

func scanViewSubjectsWithMode(ctx context.Context, hasher *closure.Hasher, scope closure.AnalysisScope, buildFlags []string, budget time.Duration, useScanMemo bool, localFacts *localFactMemo, sourceOnly bool, activeModel ExecutionModel, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, map[Subject]bool, error) {
	scope = hasher.SetAnalysisScope(scope)
	var scanScope string
	if useScanMemo && !isScanMemoOffViewHook() {
		if sourceOnly {
			scanScope = scope.SourceScan()
		} else {
			scanScope = scope.Scan()
		}
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
		return scanFromEntriesForModel(served, activeModel), nil, nil, nil
	}
	pkgPaths = misses
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
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
		if node.Class != closure.MutableLocalPackage || node.TestMain || node.ForTest != "" || seenPattern[node.PkgPath] {
			continue
		}
		seenPattern[node.PkgPath] = true
		patterns = append(patterns, node.PkgPath)
	}

	if sourceOnly {
		var preKeys map[string]string
		var expectedFiles map[string]map[string]bool
		if scanScope != "" {
			preKeys, expectedFiles = hasher.MutableFactKeys(scanScope, meta, false, pkgPaths...)
		}
		var scanInputs closure.TreeDigestSnapshot
		if scanScope != "" {
			scanInputs = hasher.SnapshotScanInputs(pkgPaths...)
		}
		emitTypedLoadViewHook()
		hasher.Unit("typecheck", "", 0, len(patterns))
		load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
		if err != nil {
			return nil, nil, nil, err
		}
		postLoadDiskUnchanged := scanScope != "" && scanInputs.MatchesDisk()
		hasher.UseViewLoad(load)
		drifted := verifySourceScanDrift(hasher, scanScope, load, meta, pkgPaths, preKeys, expectedFiles)
		scan, err := scanSubjectsFromLoadedWith(hasher.SelectionAudited(), false, load.Packages(), nil, pkgPaths...)
		if err != nil {
			return nil, nil, nil, err
		}
		emitBeforeDischargeViewHook()
		diskUnchanged := postLoadDiskUnchanged && scanInputs.MatchesDisk()
		for _, pkgPath := range pkgPaths {
			if key := keys[pkgPath]; key != "" && diskUnchanged && !drifted[pkgPath] && scan.loadErr[pkgPath] == "" {
				storeScanFacts(scanScope, key, entryOf(scan, pkgPath))
			}
		}
		mergeEntries(scan, served, activeModel)
		return scan, load, nil, nil
	}

	factScope := scope.Facts()
	singleSubject, packageProcess := scope.SingleSubject, scope.PackageProcess
	vouches := make(map[string]bool, len(scope.Vouches))
	for _, v := range scope.Vouches {
		vouches[v] = true
	}
	var preFactKeys map[string]string
	var expectedFiles map[string]map[string]bool
	if (localFacts != nil || scanScope != "") && factScope != "" {
		preFactKeys, expectedFiles = hasher.MutableFactKeys(factScope, meta, false, pkgPaths...)
	}
	var scanInputs closure.TreeDigestSnapshot
	if scanScope != "" {
		scanInputs = hasher.SnapshotScanInputs(pkgPaths...)
	}
	emitTypedLoadViewHook()
	hasher.Unit("typecheck", "", 0, len(patterns))
	load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, patterns...)
	if err != nil {
		return nil, nil, nil, err
	}
	postLoadDiskUnchanged := scanScope != "" && scanInputs.MatchesDisk()
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, buildFlags, load, meta, pkgPaths, vouches, singleSubject, packageProcess, localFacts, preFactKeys, expectedFiles)
	if err != nil {
		return nil, nil, nil, err
	}
	scan, err := scanSubjectsFromLoaded(hasher.SelectionAudited(), load.Packages(), state, pkgPaths...)
	if err != nil {
		return nil, nil, nil, err
	}
	analysisCtx, cancelBudget := analysisBound(ctx, budget)
	defer cancelBudget()
	emitBeforeDischargeViewHook()
	if singleSubject || packageProcess {
		if err := dischargeTestBinaryCulprits(ctx, analysisCtx, hasher, state, scan); err != nil {
			return nil, nil, nil, err
		}
	}
	scan.activateModel(activeModel)
	cut := scan.cutByModel[activeModel]
	cutPackages := map[string]bool{}
	for m := range scan.cutByModel {
		for subject := range scan.cutByModel[m] {
			cutPackages[subject.Package] = true
		}
	}
	diskUnchanged := postLoadDiskUnchanged && scanInputs.MatchesDisk()
	for _, pkgPath := range pkgPaths {
		if key := keys[pkgPath]; key != "" && diskUnchanged && !cutPackages[pkgPath] && !state.drifted[pkgPath] && scan.loadErr[pkgPath] == "" {
			storeScanFacts(scanScope, key, entryOf(scan, pkgPath))
		}
	}
	mergeEntries(scan, served, activeModel)
	return scan, load, cut, nil
}

// scanEntryVersion versions the persisted scan entry — its shape and the
// text of every field it persists.
const scanEntryVersion = 10

type modelSubjectScanEntry struct {
	DowngradeReason          string  `json:"downgradeReason,omitempty"`
	DowngradeCulprit         Subject `json:"downgradeCulprit,omitempty"`
	VouchDischarges          string  `json:"vouchDischarges,omitempty"`
	AttestationDischarges    string  `json:"attestationDischarges,omitempty"`
	PackageProcessDischarges string  `json:"packageProcessDischarges,omitempty"`
}

// subjectScanEntry is one subject's scan outputs as persisted.
type subjectScanEntry struct {
	StaticDecl bool   `json:"staticDecl,omitempty"`
	Pure       bool   `json:"pure,omitempty"`
	OpenWorld  string `json:"openWorld,omitempty"`
	External   bool   `json:"external,omitempty"`
	Ambiguous  string `json:"ambiguous,omitempty"`
	modelSubjectScanEntry
	GeneralModel       *modelSubjectScanEntry `json:"generalModel,omitempty"`
	PackageModel       *modelSubjectScanEntry `json:"packageModel,omitempty"`
	SingleSubjectModel *modelSubjectScanEntry `json:"singleSubjectModel,omitempty"`
}

// packageScanEntry is one view package's scan outputs as persisted: every
// subject the scan knew in the package, by symbol.
type packageScanEntry struct {
	Version   int                         `json:"version"`
	HasModels [3]bool                     `json:"hasModels,omitempty"`
	Subjects  map[string]subjectScanEntry `json:"subjects"`
}

// attestationDischarges holds the positive execution-model attestations'
// load-bearing discharge sets for one subject: carried as one comparable value
// across subjectScan, observationFacts, and Snapshot.Sibling so no attestation axis
// can be omitted when copying or clearing subject facts.
type attestationDischarges struct {
	singleSubject  string
	packageProcess string
}

type modelScanState struct {
	downgradeReason  map[Subject]string
	downgradeCulprit map[Subject]Subject
	vouchDischarges  map[Subject]string
	discharges       map[Subject]attestationDischarges
}

func newModelScanState() *modelScanState {
	return &modelScanState{
		downgradeReason:  map[Subject]string{},
		downgradeCulprit: map[Subject]Subject{},
		vouchDischarges:  map[Subject]string{},
		discharges:       map[Subject]attestationDischarges{},
	}
}

func encodeModelSubjectEntry(ms *modelScanState, s Subject) *modelSubjectScanEntry {
	if ms == nil {
		return nil
	}
	d := ms.discharges[s]
	e := modelSubjectScanEntry{
		DowngradeReason:          ms.downgradeReason[s],
		DowngradeCulprit:         ms.downgradeCulprit[s],
		VouchDischarges:          ms.vouchDischarges[s],
		AttestationDischarges:    d.singleSubject,
		PackageProcessDischarges: d.packageProcess,
	}
	if e == (modelSubjectScanEntry{}) {
		return nil
	}
	return &e
}

func decodeModelSubjectEntry(ms *modelScanState, s Subject, e *modelSubjectScanEntry) {
	if ms == nil || e == nil {
		return
	}
	if e.DowngradeReason != "" {
		ms.downgradeReason[s] = e.DowngradeReason
	}
	if e.DowngradeCulprit != (Subject{}) {
		ms.downgradeCulprit[s] = e.DowngradeCulprit
	}
	if e.VouchDischarges != "" {
		ms.vouchDischarges[s] = e.VouchDischarges
	}
	if e.AttestationDischarges != "" || e.PackageProcessDischarges != "" {
		ms.discharges[s] = attestationDischarges{
			singleSubject:  e.AttestationDischarges,
			packageProcess: e.PackageProcessDischarges,
		}
	}
}

// entryOf projects the scan's outputs for one package into its entry.
func entryOf(scan *subjectScan, pkgPath string) packageScanEntry {
	entry := packageScanEntry{
		Version:   scanEntryVersion,
		HasModels: scan.hasModel,
		Subjects:  map[string]subjectScanEntry{},
	}
	for subject := range scan.known {
		if subject.Package != pkgPath {
			continue
		}
		d := scan.discharges[subject]
		se := subjectScanEntry{
			StaticDecl: scan.staticDecl[subject],
			Pure:       scan.pure[subject],
			OpenWorld:  scan.openWorld[subject],
			External:   scan.external[subject],
			Ambiguous:  scan.ambiguous[subject],
			modelSubjectScanEntry: modelSubjectScanEntry{
				DowngradeReason:          scan.downgradeReason[subject],
				DowngradeCulprit:         scan.downgradeCulprit[subject],
				VouchDischarges:          scan.vouchDischarges[subject],
				AttestationDischarges:    d.singleSubject,
				PackageProcessDischarges: d.packageProcess,
			},
		}
		if scan.hasModel[GeneralExecution] {
			se.GeneralModel = encodeModelSubjectEntry(scan.byModel[GeneralExecution], subject)
		}
		if scan.hasModel[PackageExecution] {
			se.PackageModel = encodeModelSubjectEntry(scan.byModel[PackageExecution], subject)
		}
		if scan.hasModel[SingleSubjectExecution] {
			se.SingleSubjectModel = encodeModelSubjectEntry(scan.byModel[SingleSubjectExecution], subject)
		}
		entry.Subjects[subject.Symbol] = se
	}
	return entry
}

// mergeEntries folds served packages' entries into a scan.
func mergeEntries(scan *subjectScan, served map[string]packageScanEntry, activeModel ExecutionModel) {
	if len(served) == 0 {
		return
	}
	firstPkg := len(scan.known) == 0
	for pkgPath, entry := range served {
		if firstPkg {
			scan.hasModel = entry.HasModels
			firstPkg = false
		} else {
			for m := range scan.hasModel {
				scan.hasModel[m] = scan.hasModel[m] && entry.HasModels[m]
			}
		}
		for m := range entry.HasModels {
			if entry.HasModels[m] && scan.byModel[m] == nil {
				scan.byModel[m] = newModelScanState()
			}
		}
		for symbol, e := range entry.Subjects {
			subject := Subject{Package: pkgPath, Symbol: symbol}
			scan.known[subject] = true
			if e.StaticDecl {
				scan.staticDecl[subject] = true
			}
			if e.Pure {
				scan.pure[subject] = true
			}
			if e.OpenWorld != "" {
				scan.openWorld[subject] = e.OpenWorld
			}
			if e.External {
				scan.external[subject] = true
			}
			if e.Ambiguous != "" {
				scan.ambiguous[subject] = e.Ambiguous
			}
			if entry.HasModels[GeneralExecution] {
				decodeModelSubjectEntry(scan.byModel[GeneralExecution], subject, e.GeneralModel)
			}
			if entry.HasModels[PackageExecution] {
				decodeModelSubjectEntry(scan.byModel[PackageExecution], subject, e.PackageModel)
			}
			if entry.HasModels[SingleSubjectExecution] {
				decodeModelSubjectEntry(scan.byModel[SingleSubjectExecution], subject, e.SingleSubjectModel)
			}
			if !entry.HasModels[activeModel] {
				base := e.modelSubjectScanEntry
				if base.DowngradeReason != "" {
					scan.downgradeReason[subject] = base.DowngradeReason
				}
				if base.DowngradeCulprit != (Subject{}) {
					scan.downgradeCulprit[subject] = base.DowngradeCulprit
				}
				if base.VouchDischarges != "" {
					scan.vouchDischarges[subject] = base.VouchDischarges
				}
				if base.AttestationDischarges != "" || base.PackageProcessDischarges != "" {
					scan.discharges[subject] = attestationDischarges{
						singleSubject:  base.AttestationDischarges,
						packageProcess: base.PackageProcessDischarges,
					}
				}
			}
		}
	}
	if scan.hasModel[activeModel] && scan.byModel[activeModel] != nil {
		scan.activateModel(activeModel)
	}
}

// scanFromEntries builds a scan entirely from served entries.
func scanFromEntries(served map[string]packageScanEntry) *subjectScan {
	return scanFromEntriesForModel(served, GeneralExecution)
}

func scanFromEntriesForModel(served map[string]packageScanEntry, activeModel ExecutionModel) *subjectScan {
	scan := newEmptySubjectScan()
	mergeEntries(scan, served, activeModel)
	return scan
}

func newEmptySubjectScan() *subjectScan {
	return &subjectScan{
		staticDecl:       map[Subject]bool{},
		pure:             map[Subject]bool{},
		known:            map[Subject]bool{},
		openWorld:        map[Subject]string{},
		external:         map[Subject]bool{},
		downgradeReason:  map[Subject]string{},
		downgradeCulprit: map[Subject]Subject{},
		vouchDischarges:  map[Subject]string{},
		discharges:       map[Subject]attestationDischarges{},
		ambiguous:        map[Subject]string{},
		loadErr:          map[string]string{},
	}
}

// subjectScan holds one observation pass's subject-walk outputs across
// callability, directive purity, open-world terms (REQ-closure-refusal-channels),
// shared-dynamic-state downgrades (REQ-closure-shared-dynamic-state-reason),
// load-bearing vouches/attestations (REQ-vouch-recorded), and duplicate
// variant declarations (REQ-purity-directive).
type subjectScan struct {
	staticDecl       map[Subject]bool
	pure             map[Subject]bool
	known            map[Subject]bool
	openWorld        map[Subject]string
	external         map[Subject]bool
	downgradeReason  map[Subject]string
	downgradeCulprit map[Subject]Subject
	vouchDischarges  map[Subject]string
	discharges       map[Subject]attestationDischarges
	ambiguous        map[Subject]string
	loadErr          map[string]string
	byModel          [3]*modelScanState
	hasModel         [3]bool
	cutByModel       [3]map[Subject]bool
}

func (s *subjectScan) directivePure(subject Subject) bool { return s.pure[subject] }

func (s *subjectScan) activateModel(m ExecutionModel) {
	ms := s.byModel[m]
	if ms == nil {
		return
	}
	s.downgradeReason = maps.Clone(ms.downgradeReason)
	s.downgradeCulprit = maps.Clone(ms.downgradeCulprit)
	s.vouchDischarges = maps.Clone(ms.vouchDischarges)
	s.discharges = maps.Clone(ms.discharges)
}

// scanSubjectsFromLoaded derives the subject walk — subject enumeration,
// directives, per-subject dynamic-signature marks — from an observation
// pass's already-loaded packages, applying the pass's dynamic-state
// derivation for the shared-dynamic-state downgrade and promoted-method
// directives (REQ-fresh-coherent-view, REQ-closure-shared-dynamic-state).
func scanSubjectsFromLoaded(audited bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	return scanSubjectsFromLoadedWith(audited, true, pkgs, state, pkgPaths...)
}

func scanSubjectsFromLoadedWith(audited, computeOpenWorld bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	scan := newEmptySubjectScan()
	var cones map[string]map[string][]dynstate.Fact
	if state != nil {
		cones = state.cones
	}
	requestedPackages := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requestedPackages[pkgPath] = true
	}
	for _, p := range pkgs {
		if p == nil || gotool.IsGeneratedTestMainPackage(p) {
			continue
		}
		viewPkg := p.PkgPath
		if p.ForTest != "" && (p.PkgPath == p.ForTest || p.PkgPath == p.ForTest+"_test") {
			viewPkg = p.ForTest
		}
		if !requestedPackages[viewPkg] || scan.loadErr[viewPkg] != "" {
			continue
		}
		packages.Visit([]*packages.Package{p}, nil, func(imp *packages.Package) {
			if scan.loadErr[viewPkg] == "" && imp != nil && len(imp.Errors) > 0 {
				scan.loadErr[viewPkg] = imp.Errors[0].Error()
			}
		})
	}
	declarations := map[Subject]string{}
	callableSeen := map[Subject]bool{}
	err := dynstate.WalkLoadedSubjects(audited, computeOpenWorld, pkgs, cones, pkgPaths, func(s dynstate.ScannedSymbol) {
		subject := Subject{Package: s.Package, Symbol: s.Symbol}
		if previous := declarations[subject]; previous != "" && previous != s.Declaration {
			scan.ambiguous[subject] = fmt.Sprintf("declared at both %s and %s", previous, s.Declaration)
		} else {
			declarations[subject] = s.Declaration
			scan.known[subject] = true
		}
		if s.Callable {
			callableSeen[subject] = true
			delete(scan.staticDecl, subject)
		} else if !callableSeen[subject] {
			scan.staticDecl[subject] = true
		}
		if s.Pure {
			scan.pure[subject] = true
		}
		if s.External {
			scan.external[subject] = true
		}
		if s.Callable && s.OpenWorld != "" {
			scan.openWorld[subject] = s.OpenWorld
		}
	})
	if err != nil {
		return nil, err
	}
	// Propagate enclosing-type ambiguity (for example, an aliased type declared
	// in both pkg and pkg_test) onto member declarations <Type>.<Member>.
	for subject := range scan.known {
		if recv, _, ok := strings.Cut(subject.Symbol, "."); ok && !strings.HasPrefix(subject.Symbol, "init#") {
			if detail := scan.ambiguous[Subject{Package: subject.Package, Symbol: recv}]; detail != "" && scan.ambiguous[subject] == "" {
				scan.ambiguous[subject] = detail
			}
		}
	}
	for subject := range scan.ambiguous {
		delete(scan.pure, subject)
		delete(scan.external, subject)
	}
	if state != nil {
		populateSubjectScanModels(scan, state)
	}
	return scan, nil
}
