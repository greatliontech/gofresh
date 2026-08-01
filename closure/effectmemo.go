package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// effectScanStrategy versions the per-file effect scan's semantics: the
// classification tables, the directive markers, and the preferred-reason
// derivation. Any change that can move an effect set or a preferred
// diagnostic bumps it, so persisted scans from the prior interpretation
// refuse instead of serving (REQ-closure-effect-scan-memo).
const effectScanStrategy = "gofresh/effect-scan@1"

// effectScanScope is the memo's full scope: the strategy version plus the
// toolchain identity. The per-file scan is a pure function of the file
// bytes and of the parser linked into this binary, so a toolchain change
// refuses prior generations exactly as a strategy bump does.
func effectScanScope() string {
	return effectScanStrategy + " " + runtime.Version()
}

// effectScanEntry is one pinned package's persisted file-effect scan.
type effectScanEntry struct {
	Scope    string             `json:"scope"`
	Key      string             `json:"key"`
	Effects  []effectScanEffect `json:"effects"`
	Selected string             `json:"selected"`
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

func effectScanDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "gofresh", "effectscan"), nil
}

func effectScanPath(scope, key string) (string, error) {
	dir, err := effectScanDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(scope + "\x00" + key))
	return filepath.Join(dir, hex.EncodeToString(sum[:12])+".json"), nil
}

// loadEffectScan returns the persisted scan for (scope, key); ok is false
// on any failure — the memo is a cache, never a record.
func loadEffectScan(scope, key string) (maximalEffectScan, bool) {
	path, err := effectScanPath(scope, key)
	if err != nil {
		return maximalEffectScan{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return maximalEffectScan{}, false
	}
	var entry effectScanEntry
	if json.Unmarshal(data, &entry) != nil || entry.Scope != scope || entry.Key != key {
		return maximalEffectScan{}, false
	}
	return maximalEffectScan{effects: decodeEffects(entry.Effects), preferred: entry.Selected}, true
}

// storeEffectScan persists one pinned package's scan with an atomic
// replace; failures are silent — a lost store costs one recomputation,
// never a wrong scan.
func storeEffectScan(scope, key string, scan maximalEffectScan) {
	path, err := effectScanPath(scope, key)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(effectScanEntry{Scope: scope, Key: key, Effects: encodeEffects(scan.effects), Selected: scan.preferred})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".effectscan-*")
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
