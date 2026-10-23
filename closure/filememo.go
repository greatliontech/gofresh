package closure

import (
	"crypto/sha256"
	"os"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/closure/internal/compartment"
	"github.com/greatliontech/gofresh/closure/internal/digest"
	"github.com/greatliontech/gofresh/closure/testvariant"
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
// (REQ-closure-effect-scan-memo, REQ-closure-test-variant-ledger).

// fileScanDirName and variantParseDirName are the two memos' store
// directories.
const (
	fileScanDirName     = "filescan"
	variantParseDirName = "variantparse"
)

// variantParseStrategy versions the compartment ledger's per-file
// derivation — the declaration partition, the positional folds, the
// reference lists, the header identity. Any change that can move a
// ledger entry bumps it, so persisted parses from the prior
// interpretation refuse instead of serving — and IdentityStrategy
// (closure.go) moves with it.
const variantParseStrategy = "gofresh/variant-parse@2"

// variantParseScope is the parse memo's scope: the strategy and the
// analyzing frontend's version, whose parser produced the syntax.
func variantParseScope() string {
	return variantParseStrategy + " " + AnalyzingFrontend()
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

// dirMemo holds one per-directory persistent memo's load-on-first-use,
// serve-from-store-or-pending, record-pending, and merge-on-flush state,
// while each caller supplies its complete scope and payload-specific key.
type dirMemo[T any] struct {
	dirName string
	loaded  map[string]map[string]T
	pending map[string]map[string]T
}

func newDirMemo[T any](dirName string) dirMemo[T] {
	return dirMemo[T]{
		dirName: dirName,
		loaded:  map[string]map[string]T{},
		pending: map[string]map[string]T{},
	}
}

func (m *dirMemo[T]) lookup(scope, dir, key string, checkPending bool) (val T, ok, fromStore bool) {
	if scope == "" {
		return val, false, false
	}
	entries, ok := m.loaded[dir]
	if !ok {
		entries = map[string]T{}
		cachefile.Load(m.dirName, scope, dir, &entries)
		m.loaded[dir] = entries
	}
	if val, ok = entries[key]; ok {
		return val, true, true
	}
	if checkPending {
		if val, ok = m.pending[dir][key]; ok {
			return val, true, false
		}
	}
	return val, false, false
}

func (m *dirMemo[T]) record(scope, dir, key string, val T) {
	if scope == "" {
		return
	}
	if m.pending[dir] == nil {
		m.pending[dir] = map[string]T{}
	}
	m.pending[dir][key] = val
}

func (m *dirMemo[T]) flush(scope string) bool {
	if len(m.pending) == 0 {
		return false
	}
	for dir, additions := range m.pending {
		cachefile.Merge(m.dirName, scope, dir, additions)
		if m.loaded[dir] == nil {
			m.loaded[dir] = map[string]T{}
		}
		for k, v := range additions {
			m.loaded[dir][k] = v
		}
	}
	m.pending = map[string]map[string]T{}
	return true
}

// fileMemos is a Hasher's view of the three per-file memos: entries loaded
// per directory on first use, and the pass's misses pending their merge.
type fileMemos struct {
	scans     dirMemo[effectScanPayload]
	parses    dirMemo[variantParsePayload]
	canonical dirMemo[string]
}

func newFileMemos() *fileMemos {
	return &fileMemos{
		scans:     newDirMemo[effectScanPayload](fileScanDirName),
		parses:    newDirMemo[variantParsePayload](variantParseDirName),
		canonical: newDirMemo[string](canonicalDirName),
	}
}

// fileScan serves one file's effect scan under its digest — from the
// persistent store (stored true), or from a byte-identical sibling
// derived earlier in this pass and still pending its merge.
func (h *Hasher) fileScan(dir, digest string) (scan maximalEffectScan, ok, stored bool) {
	if h.fileMemo == nil {
		return maximalEffectScan{}, false, false
	}
	payload, ok, stored := h.fileMemo.scans.lookup(h.effectScanScope(), dir, digest, true)
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
	h.fileMemo.scans.record(h.effectScanScope(), dir, digest, effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred})
}

// The two seams the compartment computation reads through: the Hasher
// is its Source, variantParseMemo its ParseMemo.
var (
	_ compartment.Source    = (*Hasher)(nil)
	_ compartment.ParseMemo = variantParseMemo{}
)

// Parsed and Record implement compartment.ParseMemo over the parse memo,
// keyed by the file's name within its directory and its content digest.
type variantParseMemo struct {
	h            *Hasher
	dir, pkgPath string
}

func (m variantParseMemo) Parsed(name, digest string) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, bool) {
	if m.h.fileMemo == nil {
		return nil, testvariant.TestVariantFileHeader{}, false
	}
	// No pending consult: a compartment's members are distinct names,
	// and the fold flushes after each identity, so no member is asked
	// twice before its merge.
	payload, ok, _ := m.h.fileMemo.parses.lookup(variantParseScope(), m.dir, name+"\x00"+digest, false)
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
	m.h.fileMemo.parses.record(variantParseScope(), m.dir, name+"\x00"+digest, variantParsePayload{Declarations: declarations, Header: header})
}

// flushFileMemos merges the pass's pending derivations into their
// directories' entries — once per package, after its fold.
func (h *Hasher) flushFileMemos() {
	if h.fileMemo == nil {
		return
	}
	s := h.fileMemo.scans.flush(h.effectScanScope())
	p := h.fileMemo.parses.flush(variantParseScope())
	c := h.fileMemo.canonical.flush(canonicalScope())
	if s || p || c {
		// One package's per-file derivations count as one persisted scan.
		h.persisted.scans++
	}
}

// ReadFile implements compartment.Source over the Hasher's once-per-pass
// reads.
func (h *Hasher) ReadFile(path string) ([]byte, [32]byte, error) {
	fb, err := h.readFile(path)
	return fb.content, fb.sum, err
}

// TestVariantLedger returns the declaration ledger of pkgPath's test-variant
// compartment, computed from the same file reads as the compartment hash and
// memoized for the Hasher's lifetime. The returned value is caller-owned.
func (h *Hasher) TestVariantLedger(pkgPath string) (testvariant.TestVariantLedger, error) {
	if identity, ok := h.testVariants[pkgPath]; ok {
		return identity.Ledger.Clone(), nil
	}
	// This path discards the contributions it computes — the ledger and
	// compartment derive from the walk's own file reads, and the content
	// cache is nil outside a batch call, so every read here is fresh —
	// so a stale armed memo entry from a prior batch call is unobservable
	// here; a future consumer of contributions on this path must reset
	// h.contribs like the batch entries do.
	if _, _, err := h.maximalContributionsAndFiles(pkgPath); err != nil {
		return testvariant.TestVariantLedger{}, err
	}
	return h.testVariants[pkgPath].Ledger.Clone(), nil
}
