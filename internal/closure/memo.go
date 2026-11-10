package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/trace"
)

func emitMemoLoadTrace(dirName, key string, hit bool, count int) {
	if !trace.Enabled(nil, trace.DomainCache, dirName) {
		return
	}
	trace.Emit(nil, trace.DomainCache, "closure.memo.load", dirName,
		trace.String("key", key),
		trace.Bool("hit", hit),
		trace.Int("count", count),
	)
}

func emitMemoStoreTrace(dirName, key string, count int) {
	if !trace.Enabled(nil, trace.DomainCache, dirName) {
		return
	}
	trace.Emit(nil, trace.DomainCache, "closure.memo.store", dirName,
		trace.String("key", key),
		trace.Int("count", count),
	)
}

// SetAnalysisScope arms every persistent closure memo that needs the
// caller's guards — the observability proofs, the typed testing-effect
// scan, and the rooted-function inventories — under scope, the analysis
// identity outside the source closure: the Hasher reads its
// proof-strategy version and its code guards (the fact strategy, the
// attestations, and the vouches key the derivations the observation
// pass performs beside the Hasher), and each memo key adds the package
// test-binary closure hash, completing the pure function's input
// identity (REQ-closure-observability-memo,
// REQ-closure-testing-scan-memo). The zero scope leaves those memos
// inert — every pass recomputes. Those
// memos live under the consumer-controlled store root (the user cache
// by default; SetMemoRoot); a missing, unreadable, or corrupt entry
// recomputes silently - the key IS the freshness, so no entry is ever
// trusted beyond it. The returned scope carries this hasher's own source and
// policy dependencies for sibling derivations such as dynamic-state facts.
func (h *Hasher) SetAnalysisScope(scope AnalysisScope) AnalysisScope {
	scope.toolchainContent, scope.admissionPolicy = h.ToolchainContent(), h.AdmissionPolicy()
	if !h.SelectionAudited() && scope.admissionPolicy != "" {
		scope.admissionPolicy += "|unaudited"
	}
	h.scope = scope
	return scope
}

// SetMemoRoot redirects the persistent memo store - one knob covering
// every memo class: effect scans, observability proofs, dynamic-state
// facts, package scans, listings, and per-file derivations. The empty
// string restores the user cache directory default. Set at process
// start, before any analysis runs. The store is a cache, never a
// record: no knob position changes a verdict, only what is recomputed
// (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo).
func SetMemoRoot(dir string) {
	cachefile.SetRoot(dir)
}

// DefaultMemoMaxBytes is the default retention ceiling (2 GiB) for the
// persistent memo store across all memo classes.
const DefaultMemoMaxBytes = cachefile.DefaultMaxBytes

// MemoPruneReport summarizes one retention pass over the persistent memo store.
type MemoPruneReport = cachefile.PruneReport

// PruneMemos evicts persistent memo entries under <storeRoot>/gofresh until
// retained bytes are at most maxBytes (0 or negative evicts all memo entries).
func PruneMemos(maxBytes int64) (MemoPruneReport, error) {
	return cachefile.Prune(maxBytes)
}

// PreviewPruneMemos reports the MemoPruneReport that PruneMemos(maxBytes) would
// produce without removing any files or directories.
func PreviewPruneMemos(maxBytes int64) (MemoPruneReport, error) {
	return cachefile.PreviewPrune(maxBytes)
}

// observabilityDirName is the observability memo's sibling store
// directory under the shared cache-file mechanism.
const observabilityDirName = "observability"

// loadMemo returns the persisted proofs for (scope, closureKey), empty
// on any failure - the memo is a cache, never a record.
func loadMemo(scope, closureKey string) map[string]Observability {
	var proofs map[string]Observability
	if !cachefile.Load(observabilityDirName, scope, closureKey, &proofs) {
		emitMemoLoadTrace(observabilityDirName, closureKey, false, 0)
		return nil
	}
	emitMemoLoadTrace(observabilityDirName, closureKey, true, len(proofs))
	return proofs
}

// storeMemo merges proofs into the (scope, closureKey) entry with an
// atomic replace; failures are silent - a lost store costs one
// recomputation, never a wrong proof.
func storeMemo(scope, closureKey string, proofs map[string]Observability) {
	cachefile.Merge(observabilityDirName, scope, closureKey, proofs)
	emitMemoStoreTrace(observabilityDirName, closureKey, len(proofs))
}

// testBinaryClosureKey is the memo-key identity of everything the
// package's analyzed test binary is built from: the core closure hash
// joined with the test-variant compartment identity. The compartment
// rides as its own axis because the partition keeps test-only bytes out
// of the core contributions (REQ-closure-test-variant-hash) while
// the analyzed program compiles them all the same — a key equating the
// test binary with the core alone serves stale proofs after test-only
// edits (REQ-closure-observability-memo). Raw mutable-source spelling also
// participates because payloads can include file names and positions.
func (h *Hasher) testBinaryClosureKey(pkgPath string) (string, error) {
	if key, ok := h.testBinaryKeys[pkgPath]; ok {
		return key, nil
	}
	mh, err := h.maximalHash(pkgPath)
	if err != nil {
		return "", err
	}
	// maximalHash derives and records the compartment identity for the
	// package as a side effect, so the axis is in hand.
	spelling, err := h.sourceSpellingKey(pkgPath)
	if err != nil {
		return "", err
	}
	key := mh + "\x00" + h.testVariants[pkgPath].Hash + "\x00" + spelling
	if h.testBinaryKeys != nil {
		h.testBinaryKeys[pkgPath] = key
	}
	return key, nil
}

// sourceSpellingKey binds position-bearing memo payloads to the raw source
// and its names without changing public canonical closure equivalence.
// Standard source is in the hasher's content dependency; cache modules are
// immutable under their version pins. Mutable source is read in this pass.
func (h *Hasher) sourceSpellingKey(pkgPath string) (string, error) {
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return "", err
	}
	files := map[string]string{}
	for _, pkg := range pkgs {
		if pkg.Standard || pkg.Module == nil || h.pinnedPackage(&pkg) || pkg.IsGeneratedTestMainFor(pkgPath) {
			continue
		}
		for _, name := range pkg.SourceFiles() {
			if err := h.contextErr(); err != nil {
				return "", err
			}
			path := filepath.Join(pkg.Dir, name)
			if _, seen := files[path]; seen {
				continue
			}
			data, err := h.readFile(path)
			if err != nil {
				return "", err
			}
			files[path] = data.digest()
		}
	}
	data, _ := json.Marshal(files)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// PackageScanKey is the complete content identity of one view package's
// typed test-binary program — the maximal closure hash, test-variant
// compartment identity and raw mutable-source spelling — the key a scan is
// a pure function under (REQ-closure-scan-memo). It is the observability
// and testing-scan memos' key, exported for the view's scan memo.
func (h *Hasher) PackageScanKey(pkgPath string) (string, error) {
	return h.testBinaryClosureKey(pkgPath)
}

// groupMemo resolves one package group's memo: the closure key keying
// it and the already-proven subjects. A key-derivation failure
// disables the memo for the group - fail-open to recomputation.
func (h *Hasher) groupMemo(pkgPath string) (closureHash string, proofs map[string]Observability) {
	if h.scope.Proofs() == "" {
		return "", nil
	}
	key, err := h.testBinaryClosureKey(pkgPath)
	if err != nil {
		return "", nil
	}
	return key, loadMemo(h.scope.Proofs(), key)
}

const (
	rootedDirName       = "rooted"
	binaryRootedDirName = "binaryrooted"
)

func loadRootedMemo(scope, closureKey string) map[string]RootedFunctions {
	var inventories map[string]RootedFunctions
	if !cachefile.Load(rootedDirName, scope, closureKey, &inventories) {
		emitMemoLoadTrace(rootedDirName, closureKey, false, 0)
		return nil
	}
	for k, inv := range inventories {
		if inv.Complete && inv.Fns == nil {
			inv.Fns = map[string]bool{}
			inventories[k] = inv
		}
	}
	emitMemoLoadTrace(rootedDirName, closureKey, true, len(inventories))
	return inventories
}

func storeRootedMemo(scope, closureKey string, inventories map[string]RootedFunctions) {
	cachefile.Merge(rootedDirName, scope, closureKey, inventories)
	emitMemoStoreTrace(rootedDirName, closureKey, len(inventories))
}

func (h *Hasher) rootedGroupMemo(pkgPath string) (closureHash string, inventories map[string]RootedFunctions) {
	if h.scope.Rooted() == "" {
		return "", nil
	}
	key, err := h.testBinaryClosureKey(pkgPath)
	if err != nil {
		return "", nil
	}
	return key, loadRootedMemo(h.scope.Rooted(), key)
}

func loadBinaryRootedMemo(scope, closureKey string) (RootedFunctions, bool) {
	var inventory RootedFunctions
	if !cachefile.Load(binaryRootedDirName, scope, closureKey, &inventory) {
		emitMemoLoadTrace(binaryRootedDirName, closureKey, false, 0)
		return RootedFunctions{}, false
	}
	if inventory.Complete && inventory.Fns == nil {
		inventory.Fns = map[string]bool{}
	}
	emitMemoLoadTrace(binaryRootedDirName, closureKey, true, len(inventory.Fns))
	return inventory, true
}

func storeBinaryRootedMemo(scope, closureKey string, inventory RootedFunctions) {
	cachefile.Store(binaryRootedDirName, scope, closureKey, inventory)
	emitMemoStoreTrace(binaryRootedDirName, closureKey, len(inventory.Fns))
}

func (h *Hasher) binaryRootedMemo(pkgPath string) (closureHash string, inventory RootedFunctions, ok bool) {
	if h.scope.Rooted() == "" {
		return "", RootedFunctions{}, false
	}
	key, err := h.testBinaryClosureKey(pkgPath)
	if err != nil {
		return "", RootedFunctions{}, false
	}
	inv, ok := loadBinaryRootedMemo(h.scope.Rooted(), key)
	return key, inv, ok
}

// effectScanStrategy versions the per-file effect scan's semantics: the
// classification tables, the directive markers, and the preferred-reason
// derivation. Any change that can move an effect set or a preferred
// diagnostic bumps it, so persisted scans from the prior interpretation
// refuse instead of serving (REQ-closure-effect-scan-memo).
// @10 adds the audited linkname-target floor (audited-only linkname
// files drop exactly the opaque-linkage effect). ObservationRTA was
// deliberately NOT bumped with @10: no observation proof could have
// existed for a file the opaque-linkage effect blocked, so no recorded
// proof could serve under semantics it predated. @11 admits
// encoding/base32 into the scan's source-only consultation and parses
// //go:linknamestd as its own directive under the linkname floor's
// grammar with the floor keyed to the audited toolchain releases —
// the floor changes ride this surface alone (the same
// no-prior-proof argument as @10: a file the floor blocked had no
// servable proof), while ObservationRTA@27 carries base32 and the
// keying for the walk tiers. @12 admits math/big whole into the
// audited-pure package set: the per-file scan's unaudited-dependence
// marker and selector classification both consult the set, so a scan
// persisted under the narrower set must refuse rather than serve
// (ObservationRTA@28 carries the same widening for the walk tiers).
// @13 admits time's fixed-argument construction and value computation
// (ObservationRTA@29 carries the same widening for the walk tiers).
// @14 composes the discharge channel into the ambient-effect reasons
// the fold persists (ObservationRTA@30 carries the same text for the
// walk tiers).
// @15 admits net/url's escaping and composition and path/filepath's
// lexical operations, both by symbol (ObservationRTA@31 carries the
// same widening for the walk tiers).
// @16 stops classifying b.N and b.Loop as package-wide configuration
// reads: benchmark pacing is a harness fact the walk records
// (ObservationRTA@32 carries the admission for the walk tiers).
// @17 classifies crypto/rand's operations as the entropy class at the
// fold and binds an unnamed major-versioned import's declared name as a
// secondary beside its last element, two imports binding one identifier
// refusing the file (ObservationRTA@34 carries the same for the walk
// tiers).
// @18 admits the flag package's FlagSet forms at the fold
// (ObservationRTA@35 carries the same for the walk tiers).
// @19 admits sync.Map's Load, Store, and LoadOrStore (and the type
// name) at the fold as the audited memo set.
// @20 admits reflect's Elem at the fold beside the runtime-type set:
// the fold's selector match is unresolved, so a field or method
// selector through an import alias a local shadows (`r.Elem` under
// `import r "reflect"`) spells reflect.Elem to it (ObservationRTA@38
// carries the audit for the walk tiers).
// @21 admits reflect's descriptor-view surface, the Kind and ChanDir
// constants, and the StructField/StructTag shapes at the fold as a
// per-package symbol table like its peers (ObservationRTA@40 carries
// the same for the walk tiers). The unresolved alias match now spells
// sixty-odd names through a shadowed import alias; that is sound
// because the fold is a refusal-only backstop consulted after the
// walks — a shadow adds false resolutions and removes none of the
// file's real ones, so no proof the walks refuse is ever granted.
// @28 admits runtime.GOOS, runtime.GOARCH, strconv.ErrRange, and
// strconv.ErrSyntax into the audited symbol set and exempts blank
// `import _ "unsafe"` (a compiler pseudo-package with no init function,
// whose //go:linkname directives are classified independently; dot-imports
// remain blocked).
const effectScanStrategy = "gofresh/effect-scan@28"

// effectScanScope is the memo's full scope: the strategy version, the
// analyzing frontend, complete selected source and admission policy. A Boolean
// admission is not their identity, including under the default selection
// (REQ-closure-effect-scan-memo). Missing dependencies leave the memo inert.
func (h *Hasher) effectScanScope() string {
	if h.ToolchainContent() == "" || h.AdmissionPolicy() == "" {
		return ""
	}
	scope := effectScanStrategy + " " + AnalyzingFrontend() + "|" + h.ToolchainContent() + "|" + h.AdmissionPolicy()
	if !h.SelectionAudited() {
		scope += "|unaudited"
	}
	return scope
}

// testingScanStrategy versions the typed testing-effect scan's semantics:
// the testing classification table and the selection walk. Any change that
// can move the scan's effect set or preferred diagnostic bumps it, so
// persisted scans from the prior interpretation refuse instead of serving
// (REQ-closure-testing-scan-memo).
// @4 stops classifying b.N and b.Loop: benchmark pacing records nothing
// at the fold (ObservationRTA@32, effect-scan@16).
const testingScanStrategy = "gofresh/testing-scan@6"

// testingScanScope completes the typed scan's analysis identity outside
// the source closure: its own strategy version plus the code guards —
// toolchain and build configuration — the type environment depends on,
// read from the caller's analysis scope
// (REQ-closure-testing-scan-memo). Empty when the caller set no guards:
// the memo stays disabled.
func (h *Hasher) testingScanScope() string {
	return h.scope.TestingScan()
}

// effectScanPayload is one package's persisted effect scan — the shared
// cache-file envelope carries the scope and key.
type effectScanPayload struct {
	Effects []effectScanEffect `json:"effects"`
	// ImportCandidates are the scan's diagnostic-only plain-import
	// candidates: preferred-reason participants that bear no verdict.
	ImportCandidates []effectScanEffect `json:"importCandidates,omitempty"`
	Selected         string             `json:"selected"`
}

// effectScanEffect mirrors externalEffect for persistence; the memo owns
// the wire shape so the in-memory struct stays private.
type effectScanEffect struct {
	Kind        int    `json:"kind"`
	PackagePath string `json:"packagePath,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Reason      string `json:"reason"`
	Unrefinable bool   `json:"unrefinable,omitempty"`
	Observable  bool   `json:"observable,omitempty"`
}

func encodeEffects(effects []externalEffect) []effectScanEffect {
	out := make([]effectScanEffect, len(effects))
	for i, e := range effects {
		out[i] = effectScanEffect{Kind: int(e.kind), PackagePath: e.packagePath, Symbol: e.symbol, Detail: e.detail, Reason: e.reason, Unrefinable: e.unrefinable, Observable: e.observable}
	}
	return out
}

func decodeEffects(encoded []effectScanEffect) []externalEffect {
	if len(encoded) == 0 {
		return nil
	}
	out := make([]externalEffect, len(encoded))
	for i, e := range encoded {
		out[i] = externalEffect{kind: externalEffectKind(e.Kind), packagePath: e.PackagePath, symbol: e.Symbol, detail: e.Detail, reason: e.Reason, unrefinable: e.Unrefinable, observable: e.Observable}
	}
	return out
}

// effectScanKey is the complete input identity of one pinned package's
// per-file effect-scan fold: the module version pin, the package import
// path, and the identity — with the Go/cgo partition — of the file set the
// current listing selects (REQ-closure-effect-scan-memo — no type
// environment participates; the scan is syntactic per file).
func effectScanKey(pin, importPath string, goFiles, cgoFiles []string) string {
	sum := sha256.Sum256([]byte(pin + "\x00" + importPath + "\x00" + strings.Join(goFiles, "\x00") + "\x01" + strings.Join(cgoFiles, "\x00")))
	return hex.EncodeToString(sum[:])
}

// effectScanDirName and testingScanDirName are the two sibling store
// directories one scan-memo mechanism serves: the syntactic per-file fold
// (REQ-closure-effect-scan-memo) and the typed testing-effect scan
// (REQ-closure-testing-scan-memo).
const (
	effectScanDirName  = "effectscan"
	testingScanDirName = "testingscan"
)

// loadEffectScan returns the persisted scan for (scope, key) in dirName;
// ok is false on any failure — the memo is a cache, never a record.
func loadEffectScan(dirName, scope, key string) (maximalEffectScan, bool) {
	if scope == "" {
		return maximalEffectScan{}, false
	}
	var payload effectScanPayload
	if !cachefile.Load(dirName, scope, key, &payload) {
		emitMemoLoadTrace(dirName, key, false, 0)
		return maximalEffectScan{}, false
	}
	emitMemoLoadTrace(dirName, key, true, len(payload.Effects))
	return maximalEffectScan{effects: decodeEffects(payload.Effects), importCandidates: decodeEffects(payload.ImportCandidates), preferred: payload.Selected}, true
}

// storeEffectScan persists one package's scan in dirName with an atomic
// replace; failures are silent — a lost store costs one recomputation,
// never a wrong scan.
func storeEffectScan(dirName, scope, key string, scan maximalEffectScan) {
	if scope == "" {
		return
	}
	cachefile.Store(dirName, scope, key, effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred})
	emitMemoStoreTrace(dirName, key, len(scan.effects))
}
