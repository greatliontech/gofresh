package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// SetMemoScope enables the persistent observability memo under scope -
// the analysis identity outside the source closure: the caller supplies
// the proof-strategy version and the code guards, and the memo key adds
// the package test-binary closure hash, completing the pure function's
// input identity (REQ-closure-observability-memo). An empty scope
// disables memoization. The memo lives under the user cache directory;
// a missing, unreadable, or corrupt entry recomputes silently - the key
// IS the freshness, so no entry is ever trusted beyond it.
func (h *Hasher) SetMemoScope(scope string) {
	h.memoScope = scope
}

// memoEntry is one package-closure version's persisted proofs.
type memoEntry struct {
	Scope   string                   `json:"scope"`
	Closure string                   `json:"closure"`
	Proofs  map[string]Observability `json:"proofs"`
}

func memoDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "gofresh", "observability"), nil
}

func memoPath(scope, closureHash string) (string, error) {
	dir, err := memoDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(scope + "\x00" + closureHash))
	return filepath.Join(dir, hex.EncodeToString(sum[:12])+".json"), nil
}

// loadMemo returns the persisted proofs for (scope, closureHash), empty
// on any failure - the memo is a cache, never a record.
func loadMemo(scope, closureHash string) map[string]Observability {
	path, err := memoPath(scope, closureHash)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entry memoEntry
	if json.Unmarshal(data, &entry) != nil || entry.Scope != scope || entry.Closure != closureHash {
		return nil
	}
	return entry.Proofs
}

// storeMemo merges proofs into the (scope, closureHash) entry with an
// atomic replace; failures are silent - a lost store costs one
// recomputation, never a wrong proof.
func storeMemo(scope, closureHash string, proofs map[string]Observability) {
	if len(proofs) == 0 {
		return
	}
	path, err := memoPath(scope, closureHash)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	merged := loadMemo(scope, closureHash)
	if merged == nil {
		merged = make(map[string]Observability, len(proofs))
	}
	for symbol, proof := range proofs {
		merged[symbol] = proof
	}
	data, err := json.Marshal(memoEntry{Scope: scope, Closure: closureHash, Proofs: merged})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".memo-*")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
	}
}

// groupMemo resolves one package group's memo: the closure hash keying
// it and the already-proven subjects. A hash-derivation failure
// disables the memo for the group - fail-open to recomputation.
func (h *Hasher) groupMemo(pkgPath string) (closureHash string, proofs map[string]Observability) {
	if h.memoScope == "" {
		return "", nil
	}
	mh, err := h.maximalHash(pkgPath)
	if err != nil {
		return "", nil
	}
	return mh, loadMemo(h.memoScope, mh)
}

