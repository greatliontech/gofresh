package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
)

// SetAnalysisScope arms every persistent closure memo that needs the
// caller's guards — the observability proofs and the typed
// testing-effect scan — under scope, the analysis identity outside the
// source closure: the Hasher reads its proof-strategy version and its
// code guards (the fact strategy, the attestations, and the vouches key
// the derivations the observation pass performs beside the Hasher), and
// each memo key adds the package test-binary closure hash, completing
// the pure function's input identity (REQ-closure-observability-memo,
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

// SetMemoMaxBytes sets the automatic byte retention ceiling for the persistent
// memo store. Zero restores DefaultMemoMaxBytes; a negative value disables
// automatic pruning on Store while leaving explicit PruneMemos calls available.
// Eviction changes only cold recomputation cost, never a verdict.
func SetMemoMaxBytes(maxBytes int64) {
	cachefile.SetMaxBytes(maxBytes)
}

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
		return nil
	}
	return proofs
}

// storeMemo merges proofs into the (scope, closureKey) entry with an
// atomic replace; failures are silent - a lost store costs one
// recomputation, never a wrong proof.
func storeMemo(scope, closureKey string, proofs map[string]Observability) {
	cachefile.Merge(observabilityDirName, scope, closureKey, proofs)
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

// scanFactsDirName is the view scan memo's sibling store directory:
// one entry per (scope, package scan key) holding the package's scan
// outputs (REQ-closure-scan-memo).
const scanFactsDirName = "scanfacts"

// LoadScanFacts returns the persisted scan outputs for (scope, key) into
// payload; false on any failure — the memo is a cache, never a record.
func LoadScanFacts(scope, key string, payload any) bool {
	if scope == "" || key == "" {
		return false
	}
	return cachefile.Load(scanFactsDirName, scope, key, payload)
}

// StoreScanFacts persists one package's scan outputs under (scope, key)
// with an atomic replace; failures are silent.
func StoreScanFacts(scope, key string, payload any) {
	if scope == "" || key == "" {
		return
	}
	cachefile.Store(scanFactsDirName, scope, key, payload)
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
