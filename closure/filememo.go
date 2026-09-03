package closure

import (
	"crypto/sha256"
	"os"
	"runtime"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/closure/internal/digest"
	"github.com/greatliontech/gofresh/closure/internal/testvariant"
)

// The per-file memos serve the two syntactic derivations the closure
// fold performs over every mutable-local source file — the file's
// effect scan and its compartment-ledger parse — under the file's own
// content digest: each is a pure function of the bytes (and, for the
// scan, the selection-audit verdict the scope carries), so a hit under
// an equal digest is byte-equivalent to re-parsing. The bytes themselves
// are read and digested every pass — that read is the fold's freshness
// — and only the parse is served. Entries batch per package directory:
// one cache file per (scope, directory) maps digests to derivations, and
// a pass merges its misses in once per package
// (REQ-closure-effect-scan-memo, REQ-closure-test-variant-compartment).

// fileScanDirName and variantParseDirName are the two memos' user-cache
// directories.
const (
	fileScanDirName     = "filescan"
	variantParseDirName = "variantparse"
)

// variantParseStrategy versions the compartment ledger's per-file
// derivation — the declaration partition, the positional folds, the
// reference lists, the header identity. Any change that can move a
// ledger entry bumps it, so persisted parses from the prior
// interpretation refuse instead of serving.
const variantParseStrategy = "gofresh/variant-parse@1"

// variantParseScope is the parse memo's scope: the strategy and the
// toolchain identity whose parser produced the syntax.
func variantParseScope() string {
	return variantParseStrategy + " " + runtime.Version()
}

// fileBytes is one file's content read once per pass, with its digest.
type fileBytes struct {
	content []byte
	sum     [32]byte
}

// digest is the shared truncated content-digest form of the bytes.
func (f fileBytes) digest() string { return digest.FromSum(f.sum) }

// readBytes reads one file and digests it — the one read-and-sum every
// consumer shares.
func readBytes(path string) (fileBytes, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return fileBytes{}, err
	}
	return fileBytes{content: content, sum: sha256.Sum256(content)}, nil
}

// readFile reads one absolute path once per batch call: the closure
// fold, the effect scan, and the compartment ledger all consume the same
// bytes, so one read and one digest serve every consumer of the call.
func (h *Hasher) readFile(path string) (fileBytes, error) {
	if fb, ok := h.contents[path]; ok {
		return fb, nil
	}
	fb, err := readBytes(path)
	if err != nil {
		return fileBytes{}, err
	}
	if h.contents != nil {
		h.contents[path] = fb
	}
	return fb, nil
}

// variantParsePayload is one compartment file's persisted derivation.
type variantParsePayload struct {
	Declarations []testvariant.TestVariantDeclaration `json:"declarations,omitempty"`
	Header       testvariant.TestVariantFileHeader    `json:"header"`
}

// fileMemos is a Hasher's view of the two per-file memos: entries loaded
// per directory on first use, and the pass's misses pending their merge.
type fileMemos struct {
	scans, pendingScans   map[string]map[string]effectScanPayload
	parses, pendingParses map[string]map[string]variantParsePayload
}

func newFileMemos() *fileMemos {
	return &fileMemos{
		scans: map[string]map[string]effectScanPayload{}, pendingScans: map[string]map[string]effectScanPayload{},
		parses: map[string]map[string]variantParsePayload{}, pendingParses: map[string]map[string]variantParsePayload{},
	}
}

// fileScan serves one file's effect scan under its digest — from the
// persistent store (stored true), or from a byte-identical sibling
// derived earlier in this pass and still pending its merge.
func (h *Hasher) fileScan(dir, digest string) (scan maximalEffectScan, ok, stored bool) {
	if h.fileMemo == nil {
		return maximalEffectScan{}, false, false
	}
	entries, loaded := h.fileMemo.scans[dir]
	if !loaded {
		entries = map[string]effectScanPayload{}
		cachefile.Load(fileScanDirName, h.effectScanScope(), dir, &entries)
		h.fileMemo.scans[dir] = entries
	}
	payload, ok := entries[digest]
	stored = ok
	if !ok {
		payload, ok = h.fileMemo.pendingScans[dir][digest]
	}
	if !ok {
		return maximalEffectScan{}, false, false
	}
	return maximalEffectScan{effects: decodeEffects(payload.Effects), importCandidates: decodeEffects(payload.ImportCandidates), preferred: payload.Selected}, true, stored
}

// recordFileScan queues one freshly derived scan for the directory's
// merge.
func (h *Hasher) recordFileScan(dir, digest string, scan maximalEffectScan) {
	if h.fileMemo == nil {
		return
	}
	if h.fileMemo.pendingScans[dir] == nil {
		h.fileMemo.pendingScans[dir] = map[string]effectScanPayload{}
	}
	h.fileMemo.pendingScans[dir][digest] = effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred}
}

// Parsed and Record implement testvariant.ParseMemo over the parse memo,
// keyed by the file's name within its directory and its content digest.
type variantParseMemo struct {
	h            *Hasher
	dir, pkgPath string
}

func (m variantParseMemo) Parsed(name, digest string) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, bool) {
	if m.h.fileMemo == nil {
		return nil, testvariant.TestVariantFileHeader{}, false
	}
	entries, ok := m.h.fileMemo.parses[m.dir]
	if !ok {
		entries = map[string]variantParsePayload{}
		cachefile.Load(variantParseDirName, variantParseScope(), m.dir, &entries)
		m.h.fileMemo.parses[m.dir] = entries
	}
	// No pending consult: a compartment's members are distinct names,
	// and the fold flushes after each identity, so no member is asked
	// twice before its merge.
	payload, ok := entries[name+"\x00"+digest]
	if !ok {
		return nil, testvariant.TestVariantFileHeader{}, false
	}
	m.h.Served("compartment parse", m.pkgPath)
	return payload.Declarations, payload.Header, true
}

func (m variantParseMemo) Record(name, digest string, declarations []testvariant.TestVariantDeclaration, header testvariant.TestVariantFileHeader) {
	if analysisTestHooks.variantParse != nil {
		analysisTestHooks.variantParse(name)
	}
	if m.h.fileMemo == nil {
		return
	}
	if m.h.fileMemo.pendingParses[m.dir] == nil {
		m.h.fileMemo.pendingParses[m.dir] = map[string]variantParsePayload{}
	}
	m.h.fileMemo.pendingParses[m.dir][name+"\x00"+digest] = variantParsePayload{Declarations: declarations, Header: header}
}

// flushFileMemos merges the pass's pending derivations into their
// directories' entries — once per package, after its fold.
func (h *Hasher) flushFileMemos() {
	if h.fileMemo == nil {
		return
	}
	stored := false
	for dir, additions := range h.fileMemo.pendingScans {
		cachefile.Merge(fileScanDirName, h.effectScanScope(), dir, additions)
		for k, v := range additions {
			h.fileMemo.scans[dir][k] = v
		}
		stored = true
	}
	for dir, additions := range h.fileMemo.pendingParses {
		cachefile.Merge(variantParseDirName, variantParseScope(), dir, additions)
		for k, v := range additions {
			h.fileMemo.parses[dir][k] = v
		}
		stored = true
	}
	if stored {
		// One package's per-file derivations count as one persisted scan.
		h.persisted.scans++
	}
	h.fileMemo.pendingScans = map[string]map[string]effectScanPayload{}
	h.fileMemo.pendingParses = map[string]map[string]variantParsePayload{}
}

// ReadFile implements testvariant.Source over the Hasher's once-per-pass
// reads.
func (h *Hasher) ReadFile(path string) ([]byte, [32]byte, error) {
	fb, err := h.readFile(path)
	return fb.content, fb.sum, err
}
