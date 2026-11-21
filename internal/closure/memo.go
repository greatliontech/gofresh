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

// EmitMemoLoadTrace emits a cache-domain trace event for a persistent memo load.
func EmitMemoLoadTrace(dirName, key string, hit bool, count int) {
	if !trace.Enabled(nil, trace.DomainCache, dirName) {
		return
	}
	trace.Emit(nil, trace.DomainCache, "closure.memo.load", dirName,
		trace.String("key", key),
		trace.Bool("hit", hit),
		trace.Int("count", count),
	)
}

// EmitMemoStoreTrace emits a cache-domain trace event for a persistent memo store.
func EmitMemoStoreTrace(dirName, key string, count int) {
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
// and testing-scan memos' key, exported for the view's scan memo and Tier-2
// observability/rooted memos.
func (h *Hasher) PackageScanKey(pkgPath string) (string, error) {
	return h.testBinaryClosureKey(pkgPath)
}

// effectScanStrategy versions the per-file effect scan's semantics: the
// classification tables, the directive markers, and the preferred-reason
// derivation. Any change that can move an effect set or a preferred
// diagnostic bumps it, so persisted scans from the prior interpretation
// refuse instead of serving (REQ-closure-effect-scan-memo).
const effectScanStrategy = "gofresh/effect-scan@32"

// effectScanScope is the memo's full scope: the strategy version, the
// analyzing frontend, complete selected source and admission policy.
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
// the testing classification table and the selection walk
// (REQ-closure-testing-scan-memo).
const testingScanStrategy = "gofresh/testing-scan@6"

func (h *Hasher) testingScanScope() string {
	return h.scope.TestingScan()
}

type effectScanPayload struct {
	Effects          []effectScanEffect `json:"effects"`
	ImportCandidates []effectScanEffect `json:"importCandidates,omitempty"`
	Selected         string             `json:"selected"`
}

type effectScanEffect struct {
	Kind        int    `json:"kind"`
	PackagePath string `json:"packagePath,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Reason      string `json:"reason"`
	Unrefinable bool   `json:"unrefinable,omitempty"`
	Observable  bool   `json:"observable,omitempty"`
}

func encodeEffects(effects []ExternalEffect) []effectScanEffect {
	out := make([]effectScanEffect, len(effects))
	for i, e := range effects {
		out[i] = effectScanEffect{Kind: int(e.Kind), PackagePath: e.PackagePath, Symbol: e.Symbol, Detail: e.Detail, Reason: e.Reason, Unrefinable: e.Unrefinable, Observable: e.Observable}
	}
	return out
}

func decodeEffects(encoded []effectScanEffect) []ExternalEffect {
	if len(encoded) == 0 {
		return nil
	}
	out := make([]ExternalEffect, len(encoded))
	for i, e := range encoded {
		out[i] = ExternalEffect{Kind: ExternalEffectKind(e.Kind), PackagePath: e.PackagePath, Symbol: e.Symbol, Detail: e.Detail, Reason: e.Reason, Unrefinable: e.Unrefinable, Observable: e.Observable}
	}
	return out
}

func effectScanKey(pin, importPath string, goFiles, cgoFiles []string) string {
	sum := sha256.Sum256([]byte(pin + "\x00" + importPath + "\x00" + strings.Join(goFiles, "\x00") + "\x01" + strings.Join(cgoFiles, "\x00")))
	return hex.EncodeToString(sum[:])
}

const (
	effectScanDirName  = "effectscan"
	testingScanDirName = "testingscan"
)

func loadEffectScan(dirName, scope, key string) (MaximalEffectScan, bool) {
	if scope == "" {
		return MaximalEffectScan{}, false
	}
	var payload effectScanPayload
	if !cachefile.Load(dirName, scope, key, &payload) {
		EmitMemoLoadTrace(dirName, key, false, 0)
		return MaximalEffectScan{}, false
	}
	EmitMemoLoadTrace(dirName, key, true, len(payload.Effects))
	return MaximalEffectScan{Effects: decodeEffects(payload.Effects), ImportCandidates: decodeEffects(payload.ImportCandidates), Preferred: payload.Selected}, true
}

func storeEffectScan(dirName, scope, key string, scan MaximalEffectScan) {
	if scope == "" {
		return
	}
	cachefile.Store(dirName, scope, key, effectScanPayload{Effects: encodeEffects(scan.Effects), ImportCandidates: encodeEffects(scan.ImportCandidates), Selected: scan.Preferred})
	EmitMemoStoreTrace(dirName, key, len(scan.Effects))
}
