package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
)

// effectScanStrategy versions the per-file effect scan's semantics: the
// classification tables, the directive markers, and the preferred-reason
// derivation. Any change that can move an effect set or a preferred
// diagnostic bumps it, so persisted scans from the prior interpretation
// refuse instead of serving (REQ-closure-effect-scan-memo).
const effectScanStrategy = "gofresh/effect-scan@8"

// effectScanScope is the memo's full scope: the strategy version plus the
// toolchain identity. The per-file scan is a pure function of the file
// bytes and of the parser linked into this binary, so a toolchain change
// refuses prior generations exactly as a strategy bump does.
func effectScanScope() string {
	return effectScanStrategy + " " + runtime.Version()
}

// testingScanStrategy versions the typed testing-effect scan's semantics:
// the testing classification table and the selection walk. Any change that
// can move the scan's effect set or preferred diagnostic bumps it, so
// persisted scans from the prior interpretation refuse instead of serving
// (REQ-closure-testing-scan-memo).
const testingScanStrategy = "gofresh/testing-scan@3"

// testingScanScope completes the typed scan's analysis identity outside
// the source closure: its own strategy version plus the caller-supplied
// memo scope, which carries the code guards — toolchain and build
// configuration — the type environment depends on
// (REQ-closure-testing-scan-memo). Empty when the caller set no scope:
// the memo stays disabled.
func (h *Hasher) testingScanScope() string {
	if h.memoScope == "" {
		return ""
	}
	return testingScanStrategy + "|" + h.memoScope
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

// effectScanDirName and testingScanDirName are the two sibling user-cache
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
	var payload effectScanPayload
	if !cachefile.Load(dirName, scope, key, &payload) {
		return maximalEffectScan{}, false
	}
	return maximalEffectScan{effects: decodeEffects(payload.Effects), importCandidates: decodeEffects(payload.ImportCandidates), preferred: payload.Selected}, true
}

// storeEffectScan persists one package's scan in dirName with an atomic
// replace; failures are silent — a lost store costs one recomputation,
// never a wrong scan.
func storeEffectScan(dirName, scope, key string, scan maximalEffectScan) {
	cachefile.Store(dirName, scope, key, effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred})
}
