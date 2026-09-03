package closure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/digest"
	"github.com/greatliontech/gofresh/closure/internal/testvariant"
)

// fileMemoModule writes a package whose plain files carry an effect, and
// whose test file declares a subject beside a helper type.
func fileMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":    "module example.com/fm\n\ngo 1.26\n",
		"p.go":      "package fm\n\nimport \"os\"\n\nfunc P() string { return os.Getenv(\"X\") }\n",
		"helper.go": "package fm\n\nfunc helper() int { return 1 }\n",
		"p_test.go": "package fm\n\nimport \"testing\"\n\ntype fixture struct{ n int }\n\nfunc TestP(t *testing.T) { _ = P(); _ = fixture{helper()} }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var fileMemoSubjects = []Subject{{Package: "example.com/fm", Symbol: "P"}, {Package: "example.com/fm", Symbol: "TestP"}}

// foldOnce computes the fixture's closures with a fresh Hasher and
// returns them beside the files the pass parsed for its effect scans and
// the compartment members it derived.
func foldOnce(t *testing.T, dir string, memo bool) (map[Subject]Closure, []string, []string) {
	t.Helper()
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !memo {
		h.fileMemo = nil
	}
	var parsed, derived []string
	analysisTestHooks.fileParse = func(path string) { parsed = append(parsed, filepath.Base(path)) }
	analysisTestHooks.variantParse = func(name string) { derived = append(derived, name) }
	defer func() { analysisTestHooks.fileParse, analysisTestHooks.variantParse = nil, nil }()
	got, err := h.ComputeMaximalBatch(fileMemoSubjects)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parsed)
	sort.Strings(derived)
	summary := h.ServedSummary()
	if memo && len(parsed) == 0 && !summary["file scan"]["example.com/fm"] {
		t.Fatal("no file scan parsed and none served")
	}
	return got, parsed, derived
}

// A warm pass parses nothing: every file's effect scan and every
// compartment member's derivation serve under the file's content digest,
// and the closures equal an unmemoized fold's
// (REQ-closure-effect-scan-memo, REQ-closure-test-variant-compartment).
func TestFileMemosServeEveryParseOnAWarmPass(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the closure fold over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	reference, _, _ := foldOnce(t, dir, false)
	cold, parsed, derived := foldOnce(t, dir, true)
	if want := []string{"helper.go", "p.go", "p_test.go"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("cold pass parsed %v, want %v", parsed, want)
	}
	if want := []string{"p_test.go"}; !reflect.DeepEqual(derived, want) {
		t.Fatalf("cold pass derived %v, want %v", derived, want)
	}
	if !reflect.DeepEqual(cold, reference) {
		t.Fatalf("memoized cold fold differs from the unmemoized one:\n got %+v\nwant %+v", cold, reference)
	}
	warm, parsed, derived := foldOnce(t, dir, true)
	if len(parsed) != 0 || len(derived) != 0 {
		t.Fatalf("warm pass parsed %v and derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(warm, reference) {
		t.Fatalf("served fold differs from the unmemoized one:\n got %+v\nwant %+v", warm, reference)
	}
	if !reference[fileMemoSubjects[0]].Unverifiable {
		t.Fatal("fixture no longer carries the effect the file scan must reproduce")
	}
}

// An edit misses exactly the edited file: its scan re-parses, its
// derivation re-derives when it is a compartment member, every other
// file still serves, and the fold equals an unmemoized one; a corrupt
// entry recomputes.
func TestFileMemosMissOnlyTheEditedFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the closure fold over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := fileMemoModule(t)
	foldOnce(t, dir, true)
	edit := func(name string) {
		full := filepath.Join(dir, name)
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// edit\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	edit("helper.go")
	reference, _, _ := foldOnce(t, dir, false)
	got, parsed, derived := foldOnce(t, dir, true)
	if !reflect.DeepEqual(parsed, []string{"helper.go"}) || len(derived) != 0 {
		t.Fatalf("after a plain-file edit: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after the edit differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
	edit("p_test.go")
	reference, _, _ = foldOnce(t, dir, false)
	got, parsed, derived = foldOnce(t, dir, true)
	if !reflect.DeepEqual(parsed, []string{"p_test.go"}) || !reflect.DeepEqual(derived, []string{"p_test.go"}) {
		t.Fatalf("after a test-file edit: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after the test edit differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
	for _, sub := range []string{fileScanDirName, variantParseDirName} {
		entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", sub, "*.json"))
		if len(entries) == 0 {
			t.Fatalf("no %s entries persisted", sub)
		}
		for _, e := range entries {
			if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, parsed, derived = foldOnce(t, dir, true)
	if len(parsed) != 3 || len(derived) != 1 {
		t.Fatalf("after corruption: parsed %v, derived %v", parsed, derived)
	}
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf("fold after corruption differs from the unmemoized one:\n got %+v\nwant %+v", got, reference)
	}
}

// Every scan of the effect-scan corpus survives the persisted form:
// encoded, marshalled, unmarshalled, decoded, it is the same scan.
func TestFileScanPayloadRoundTripsTheCorpus(t *testing.T) {
	dir := t.TempDir()
	parsed := 0
	for name, content := range effectScanCorpusFiles() {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		scan, err := maximalFileEffects(true, path)
		if err != nil {
			continue
		}
		parsed++
		raw, err := json.Marshal(effectScanPayload{Effects: encodeEffects(scan.effects), ImportCandidates: encodeEffects(scan.importCandidates), Selected: scan.preferred})
		if err != nil {
			t.Fatal(err)
		}
		var payload effectScanPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		back := maximalEffectScan{effects: decodeEffects(payload.Effects), importCandidates: decodeEffects(payload.ImportCandidates), preferred: payload.Selected}
		if !reflect.DeepEqual(back, scan) {
			t.Fatalf("%s: round trip changed the scan:\n got %+v\nwant %+v", name, back, scan)
		}
	}
	if parsed < 10 {
		t.Fatalf("the corpus yielded %d parsed scans; the round trip covers too little", parsed)
	}
}

// A package scan key derived twice over an unchanged tree — the
// preparation path, outside any batch call — derives every compartment
// member once: the second derivation serves the first's parses.
func TestCompartmentParsesServeOnTheScanKeyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the closure fold over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	var derived []string
	analysisTestHooks.variantParse = func(name string) { derived = append(derived, name) }
	defer func() { analysisTestHooks.variantParse = nil }()
	keys := make([]string, 2)
	for i := range keys {
		h, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		if keys[i], err = h.PackageScanKey("example.com/fm"); err != nil {
			t.Fatal(err)
		}
	}
	if keys[0] != keys[1] {
		t.Fatalf("scan keys differ over an unchanged tree: %s vs %s", keys[0], keys[1])
	}
	if !reflect.DeepEqual(derived, []string{"p_test.go"}) {
		t.Fatalf("derivations = %v, want the first pass's one", derived)
	}
}

// recordingMemo round-trips every recorded derivation through JSON and
// serves it back, so a served ledger is exactly the persisted form.
type recordingMemo struct{ entries map[string][]byte }

func (m *recordingMemo) Parsed(name, digest string) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, bool) {
	raw, ok := m.entries[name+"\x00"+digest]
	if !ok {
		return nil, testvariant.TestVariantFileHeader{}, false
	}
	var payload variantParsePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		panic(err)
	}
	return payload.Declarations, payload.Header, true
}

func (m *recordingMemo) Record(name, digest string, declarations []testvariant.TestVariantDeclaration, header testvariant.TestVariantFileHeader) {
	raw, err := json.Marshal(variantParsePayload{Declarations: declarations, Header: header})
	if err != nil {
		panic(err)
	}
	m.entries[name+"\x00"+digest] = raw
}

// A compartment identity built from served derivations equals one built
// by parsing, ledger and hash alike — the dual member (compiled and
// embedded) included, whose whole-content header is applied on the
// served path exactly as on the parsed one.
func TestCompartmentParseRoundTripsThroughThePersistedForm(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a_test.go": "package p\n\nimport \"testing\"\n\nconst (\n\tA = iota\n\tB\n)\n\ntype T struct{ n int }\n\nfunc (t T) M() int { return t.n }\n\nvar x = B\n\nfunc init() { x++ }\n\nfunc TestA(t *testing.T) { _ = T{}.M() }\n",
		"b_test.go": "package p_test\n\nimport \"testing\"\n\n//go:embed data.txt\nvar data string\n\nfunc TestB(t *testing.T) { _ = data }\n",
		"data.txt":  "data\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"a_test.go", "b_test.go", "data.txt"}
	compiled := map[string]bool{"a_test.go": true, "b_test.go": true}
	embedded := map[string]bool{"data.txt": true, "b_test.go": true}
	want, err := testvariant.ComputeIdentity(dir, names, compiled, embedded, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	memo := &recordingMemo{entries: map[string][]byte{}}
	if _, err := testvariant.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo); err != nil {
		t.Fatal(err)
	}
	if len(memo.entries) != 2 {
		t.Fatalf("recorded %d derivations, want the two compiled members", len(memo.entries))
	}
	got, err := testvariant.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("served identity differs:\n got %+v\nwant %+v", got, want)
	}
	dual := false
	for _, header := range got.Ledger.FileHeaders {
		if header.File == "b_test.go" {
			dual = header.Embedded && header.Hash == digestOf(t, filepath.Join(dir, "b_test.go"))
		}
	}
	if !dual {
		t.Fatalf("the served dual member lost its whole-content header: %+v", got.Ledger.FileHeaders)
	}
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest.Content(content)
}

// A module-cache file takes no per-file entry and no place in the call's
// content cache — its package-level entry is its store — while a
// mutable-local file takes both; and a byte-identical sibling derived in
// the same pass serves from the pending merge without a store serve on
// record.
func TestFileScanGatesModuleCacheFilesAndPendingSiblings(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cacheRoot := t.TempDir()
	pinnedDir := filepath.Join(cacheRoot, "example.com", "dep@v1.0.0")
	if err := os.MkdirAll(pinnedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	localDir := t.TempDir()
	src := "package p\n\nimport \"os\"\n\nfunc F() string { return os.Getenv(\"X\") }\n"
	pinned := filepath.Join(pinnedDir, "dep.go")
	first, second := filepath.Join(localDir, "a.go"), filepath.Join(localDir, "b.go")
	for _, path := range []string{pinned, first, second} {
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Hasher{selectionResolved: true, modCache: cacheRoot, maximalFiles: map[string]maximalEffectScan{}, fileMemo: newFileMemos(), contents: map[string]fileBytes{}}
	var parsed []string
	analysisTestHooks.fileParse = func(path string) { parsed = append(parsed, filepath.Base(path)) }
	defer func() { analysisTestHooks.fileParse = nil }()
	want, err := maximalFileEffects(true, pinned)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.maximalFileEffectsCached("example.com/dep", pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned scan = %+v, want %+v", got, want)
	}
	if _, cached := h.contents[pinned]; cached || len(h.fileMemo.pendingScans) != 0 {
		t.Fatalf("a module-cache file entered the content cache (%t) or the per-file memo (%d dirs pending)", cached, len(h.fileMemo.pendingScans))
	}
	for _, path := range []string{first, second} {
		if got, err := h.maximalFileEffectsCached("example.com/local", path); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: scan = %+v (err %v), want %+v", path, got, err, want)
		}
	}
	if _, cached := h.contents[first]; !cached || len(h.fileMemo.pendingScans[localDir]) != 1 {
		t.Fatalf("the mutable-local files did not enter the content cache (%t) and one pending entry (%d)", cached, len(h.fileMemo.pendingScans[localDir]))
	}
	if !reflect.DeepEqual(parsed, []string{"a.go"}) {
		t.Fatalf("parsed %v, want the first sibling alone", parsed)
	}
	if len(h.ServedSummary()["file scan"]) != 0 {
		t.Fatalf("a pending-sibling hit was reported as a store serve: %v", h.ServedSummary())
	}
}
