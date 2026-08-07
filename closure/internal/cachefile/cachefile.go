// Package cachefile is the persistent memos' one storage mechanism: an
// entry lives under the consumer-controlled store root (the user cache
// by default) at gofresh/<dirName>/<sha256(scope||key)[:12]>.json,
// restates its scope and key so a renamed or corrupted file is detectable,
// and writes atomically. No entry is trusted beyond its key — the key IS
// the freshness. Every memo is a cache, never a record: a missing,
// unreadable, corrupt, or mismatched entry recomputes silently, and the
// cache is deletable wholesale at any time.
package cachefile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// The consumer-controlled store location: one knob covering every memo
// class (effect scans, observability proofs, dynamic-state facts). The
// zero state serves the user cache directory; a redirect points the
// whole store elsewhere; disabled skips persistence entirely. A cache
// is never a record, so no knob position can change a verdict - only
// what is recomputed.
var (
	configMu sync.RWMutex
	rootDir  string
	disabled bool
)

// SetRoot redirects the persistent memo store to dir; the empty string
// restores the user cache directory default. Re-enables a disabled
// store.
func SetRoot(dir string) {
	configMu.Lock()
	defer configMu.Unlock()
	rootDir = dir
	disabled = false
}

// Disable turns persistence off process-wide: loads miss, stores are
// dropped. Only recomputation cost changes.
func Disable() {
	configMu.Lock()
	defer configMu.Unlock()
	disabled = true
}

func storeRoot() (string, bool, error) {
	configMu.RLock()
	defer configMu.RUnlock()
	if disabled {
		return "", false, nil
	}
	if rootDir != "" {
		return rootDir, true, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", false, err
	}
	return cache, true, nil
}

// Envelope is the on-disk entry shape.
type Envelope struct {
	Scope   string          `json:"scope"`
	Key     string          `json:"key"`
	Payload json.RawMessage `json:"payload"`
}

// Path is the entry location for (dirName, scope, key).
func Path(dirName, scope, key string) (string, error) {
	cache, enabled, err := storeRoot()
	if err != nil {
		return "", err
	}
	if !enabled {
		return "", os.ErrNotExist
	}
	sum := sha256.Sum256([]byte(scope + "\x00" + key))
	return filepath.Join(cache, "gofresh", dirName, hex.EncodeToString(sum[:12])+".json"), nil
}

// Load unmarshals the (dirName, scope, key) entry's payload into payload;
// false on any failure.
func Load(dirName, scope, key string, payload any) bool {
	path, err := Path(dirName, scope, key)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var envelope Envelope
	if json.Unmarshal(data, &envelope) != nil || envelope.Scope != scope || envelope.Key != key {
		return false
	}
	return json.Unmarshal(envelope.Payload, payload) == nil
}

// Merge merges additions into the (dirName, scope, key) entry's map
// payload and stores the result — the accumulate discipline the
// observability and dynamic-state memos share.
func Merge[T any](dirName, scope, key string, additions map[string]T) {
	if len(additions) == 0 {
		return
	}
	var merged map[string]T
	if !Load(dirName, scope, key, &merged) || merged == nil {
		merged = make(map[string]T, len(additions))
	}
	for k, v := range additions {
		merged[k] = v
	}
	Store(dirName, scope, key, merged)
}

// Store persists payload under (dirName, scope, key) with an atomic
// replace; failures are silent — a lost store costs one recomputation,
// never a wrong result.
func Store(dirName, scope, key string, payload any) {
	path, err := Path(dirName, scope, key)
	if err != nil {
		return
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	data, err := json.Marshal(Envelope{Scope: scope, Key: key, Payload: encoded})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cache-*")
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
