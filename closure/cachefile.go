package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// The persistent memos share one cache-file mechanism: an entry lives
// under the user cache at gofresh/<dirName>/<sha256(scope||key)[:12]>.json,
// restates its scope and key so a renamed or corrupted file is detectable,
// and writes atomically. No entry is trusted beyond its key — the key IS
// the freshness. Every memo is a cache, never a record: a missing,
// unreadable, corrupt, or mismatched entry recomputes silently, and the
// cache is deletable wholesale at any time.

type cacheEnvelope struct {
	Scope   string          `json:"scope"`
	Key     string          `json:"key"`
	Payload json.RawMessage `json:"payload"`
}

func cacheEntryPath(dirName, scope, key string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(scope + "\x00" + key))
	return filepath.Join(cache, "gofresh", dirName, hex.EncodeToString(sum[:12])+".json"), nil
}

// loadCacheEntry unmarshals the (dirName, scope, key) entry's payload into
// payload; false on any failure.
func loadCacheEntry(dirName, scope, key string, payload any) bool {
	path, err := cacheEntryPath(dirName, scope, key)
	if err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var envelope cacheEnvelope
	if json.Unmarshal(data, &envelope) != nil || envelope.Scope != scope || envelope.Key != key {
		return false
	}
	return json.Unmarshal(envelope.Payload, payload) == nil
}

// mergeCacheEntry merges additions into the (dirName, scope, key) entry's
// map payload and stores the result — the accumulate discipline the
// observability and dynamic-state memos share.
func mergeCacheEntry[T any](dirName, scope, key string, additions map[string]T) {
	if len(additions) == 0 {
		return
	}
	var merged map[string]T
	if !loadCacheEntry(dirName, scope, key, &merged) || merged == nil {
		merged = make(map[string]T, len(additions))
	}
	for k, v := range additions {
		merged[k] = v
	}
	storeCacheEntry(dirName, scope, key, merged)
}

// storeCacheEntry persists payload under (dirName, scope, key) with an
// atomic replace; failures are silent — a lost store costs one
// recomputation, never a wrong result.
func storeCacheEntry(dirName, scope, key string, payload any) {
	path, err := cacheEntryPath(dirName, scope, key)
	if err != nil {
		return
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	data, err := json.Marshal(cacheEnvelope{Scope: scope, Key: key, Payload: encoded})
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
