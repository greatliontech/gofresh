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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBytes bounds the persistent memo store under <root>/gofresh at
// 2 GiB by default. A single active repository and toolchain working set
// occupies well under a few hundred megabytes across all memo classes, whereas
// unbounded accumulation across superseded source and toolchain keys grew past
// 16 GiB in field measurements (2026-10-15). Eviction removes only cache files
// and never changes a freshness verdict; a miss recomputes on demand.
const DefaultMaxBytes int64 = 2 << 30

// PruneReport summarizes one retention pass over the persistent memo store.
type PruneReport struct {
	Root           string
	UsedBytes      int64
	ReclaimedBytes int64
	RemainingBytes int64
	RemovedEntries int
	SkippedEntries int
}

// The consumer-controlled store location and byte ceiling: one knob per axis
// covering every memo class. The zero root serves the user cache directory; a
// redirect points the whole store elsewhere — scratch, for an environment that
// forbids user-cache writes. A cache is never a record, so no knob position or
// eviction can change a verdict - only what is recomputed.
var (
	configMu sync.RWMutex
	rootDir  string
	maxBytes = DefaultMaxBytes

	pruneMu    sync.Mutex
	knownRoot  string
	knownBytes int64
	knownValid bool
	nextSeq    uint64
	writeSeq   = map[string]uint64{}
)

// SetRoot redirects the persistent memo store to dir; the empty string
// restores the user cache directory default.
func SetRoot(dir string) {
	configMu.Lock()
	rootDir = dir
	configMu.Unlock()

	pruneMu.Lock()
	knownValid = false
	clear(writeSeq)
	pruneMu.Unlock()
}

// SetMaxBytes sets the automatic byte retention ceiling for the persistent
// memo store. Zero restores DefaultMaxBytes; a negative value disables
// automatic pruning on Store while leaving explicit Prune calls available.
func SetMaxBytes(limit int64) {
	if limit == 0 {
		limit = DefaultMaxBytes
	}
	configMu.Lock()
	maxBytes = limit
	configMu.Unlock()

	pruneMu.Lock()
	knownValid = false
	pruneMu.Unlock()
}

// MaxBytes returns the configured automatic retention ceiling in bytes, or a
// negative value when automatic retention is disabled.
func MaxBytes() int64 {
	configMu.RLock()
	defer configMu.RUnlock()
	return maxBytes
}

func storeRoot() (string, error) {
	configMu.RLock()
	defer configMu.RUnlock()
	if rootDir != "" {
		return rootDir, nil
	}
	return os.UserCacheDir()
}

// Envelope is the on-disk entry shape.
type Envelope struct {
	Scope   string          `json:"scope"`
	Key     string          `json:"key"`
	Payload json.RawMessage `json:"payload"`
}

// Path is the entry location for (dirName, scope, key).
func Path(dirName, scope, key string) (string, error) {
	cache, err := storeRoot()
	if err != nil {
		return "", err
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
		return
	}
	recordWriteAndEnforce(filepath.Dir(filepath.Dir(path)), path, int64(len(data)))
}

func recordWriteAndEnforce(gofreshRoot, path string, size int64) {
	limit := MaxBytes()
	pruneMu.Lock()
	defer pruneMu.Unlock()
	nextSeq++
	writeSeq[path] = nextSeq
	if limit < 0 {
		return
	}
	if knownValid && knownRoot == gofreshRoot && knownBytes+size <= limit {
		knownBytes += size
		return
	}
	_, _ = pruneDirLocked(gofreshRoot, limit, path)
}

// Prune evicts persistent memo entries under <storeRoot>/gofresh until the
// retained bytes are at most maxBytes (0 or negative evicts all memo entries).
// Active temporary writes (.cache-*) are preserved; obsolete memo directories
// and abandoned keys participate alongside active classes. Unreadable or
// unremovable entries are counted in SkippedEntries without aborting collection.
func Prune(maxBytes int64) (PruneReport, error) {
	cache, err := storeRoot()
	if err != nil {
		return PruneReport{}, err
	}
	gofreshRoot := filepath.Join(cache, "gofresh")
	target := max(maxBytes, 0)
	pruneMu.Lock()
	defer pruneMu.Unlock()
	return pruneDirLocked(gofreshRoot, target, "")
}

type diskEntry struct {
	path    string
	size    int64
	modTime time.Time
	seq     uint64
}

func pruneDirLocked(gofreshRoot string, targetBytes int64, preservePath string) (PruneReport, error) {
	report := PruneReport{Root: gofreshRoot}
	if _, err := os.Stat(gofreshRoot); err != nil {
		if os.IsNotExist(err) {
			knownRoot = gofreshRoot
			knownBytes = 0
			knownValid = true
			return report, nil
		}
		return report, err
	}

	var (
		entries []diskEntry
		dirs    []string
	)
	walkErr := filepath.WalkDir(gofreshRoot, func(path string, d fs.DirEntry, err error) error {
		if path == gofreshRoot {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			report.SkippedEntries++
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		if !strings.HasSuffix(name, ".json") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			report.SkippedEntries++
			return nil
		}
		size := info.Size()
		report.UsedBytes += size
		entries = append(entries, diskEntry{
			path:    path,
			size:    size,
			modTime: info.ModTime(),
			seq:     writeSeq[path],
		})
		return nil
	})
	if walkErr != nil {
		return report, walkErr
	}

	report.RemainingBytes = report.UsedBytes
	if report.RemainingBytes > targetBytes {
		slices.SortFunc(entries, func(a, b diskEntry) int {
			aPreserve := a.path == preservePath && targetBytes >= a.size
			bPreserve := b.path == preservePath && targetBytes >= b.size
			if aPreserve != bPreserve {
				if aPreserve {
					return 1
				}
				return -1
			}
			if !a.modTime.Equal(b.modTime) {
				if a.modTime.Before(b.modTime) {
					return -1
				}
				return 1
			}
			if a.seq != b.seq {
				if a.seq < b.seq {
					return -1
				}
				return 1
			}
			return strings.Compare(a.path, b.path)
		})
		for _, entry := range entries {
			if report.RemainingBytes <= targetBytes {
				break
			}
			if err := os.Remove(entry.path); err != nil && !os.IsNotExist(err) {
				report.SkippedEntries++
				continue
			} else if err == nil {
				report.RemovedEntries++
			}
			delete(writeSeq, entry.path)
			report.ReclaimedBytes += entry.size
			report.RemainingBytes -= entry.size
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
	knownRoot = gofreshRoot
	knownBytes = report.RemainingBytes
	knownValid = true
	return report, nil
}
