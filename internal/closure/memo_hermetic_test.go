package closure

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/toolchain"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
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
	got, parsed, derived, _ := foldOnceWithCanonical(t, dir, memo)
	return got, parsed, derived
}

func foldOnceWithCanonical(t *testing.T, dir string, memo bool) (map[Subject]Closure, []string, []string, []string) {
	t.Helper()
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !memo {
		h.fileMemo = nil
	}
	var (
		parsed, derived, canonical []string
		got                        map[Subject]Closure
	)
	withClosureTestHooks(analysisTestHookSet{
		fileParse:      func(path string) { parsed = append(parsed, filepath.Base(path)) },
		variantParse:   func(name string) { derived = append(derived, name) },
		canonicalParse: func(d string) { canonical = append(canonical, filepath.Base(d)) },
	}, func() {
		got, _, err = h.ComputeMaximalBatch(fileMemoSubjects)
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parsed)
	sort.Strings(derived)
	summary := h.ServedSummary()
	if memo && len(parsed) == 0 && !summary["file scan"]["example.com/fm"] {
		t.Fatal("no file scan parsed and none served")
	}
	return got, parsed, derived, canonical
}

// A warm pass parses nothing: every file's effect scan and every
// compartment member's derivation serve under the file's content digest,
// and the closures equal an unmemoized fold's
// (REQ-closure-effect-scan-memo, REQ-closure-test-variant-ledger).
func TestFileMemosServeEveryParseOnAWarmPass(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	reference, _, _ := foldOnce(t, dir, false)
	cold, parsed, derived := foldOnce(t, dir, true)
	if want := []string{"helper.go", "p.go", "p_test.go"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("cold pass parsed %v, want %v", parsed, want)
	}
	if want := []string{"helper.go", "p.go", "p_test.go"}; !reflect.DeepEqual(derived, want) {
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
// binding derivation re-derives for base and compartment members, every other
// file still serves, and the fold equals an unmemoized one; a corrupt
// entry recomputes.
func TestFileMemosMissOnlyTheEditedFile(t *testing.T) {
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
	if !reflect.DeepEqual(parsed, []string{"helper.go"}) || !reflect.DeepEqual(derived, []string{"helper.go"}) {
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
	if len(parsed) != 3 || len(derived) != 3 {
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
		raw, err := json.Marshal(effectScanPayload{Effects: encodeEffects(scan.Effects), ImportCandidates: encodeEffects(scan.ImportCandidates), Selected: scan.Preferred})
		if err != nil {
			t.Fatal(err)
		}
		var payload effectScanPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		back := maximalEffectScan{Effects: decodeEffects(payload.Effects), ImportCandidates: decodeEffects(payload.ImportCandidates), Preferred: payload.Selected}
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	var derived []string
	keys := make([]string, 2)
	withClosureTestHooks(analysisTestHookSet{
		variantParse: func(name string) { derived = append(derived, name) },
	}, func() {
		for i := range keys {
			h, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			if keys[i], err = h.PackageScanKey("example.com/fm"); err != nil {
				t.Fatal(err)
			}
		}
	})
	if keys[0] != keys[1] {
		t.Fatalf("scan keys differ over an unchanged tree: %s vs %s", keys[0], keys[1])
	}
	sort.Strings(derived)
	if !reflect.DeepEqual(derived, []string{"helper.go", "p.go", "p_test.go"}) {
		t.Fatalf("derivations = %v, want each base and test file once", derived)
	}
}

// recordingMemo round-trips every recorded derivation through JSON and
// serves it back, so a served ledger is exactly the persisted form.
type recordingMemo struct{ entries map[string][]byte }

func (m *recordingMemo) parse(name, digest string, content []byte) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, error) {
	if raw, ok := m.entries[name+"\x00"+digest]; ok {
		var payload variantParsePayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, testvariant.TestVariantFileHeader{}, err
		}
		return payload.Declarations, payload.Header, nil
	}
	declarations, header, err := testvariant.ParseFile(name, content)
	if err != nil {
		return nil, testvariant.TestVariantFileHeader{}, err
	}
	raw, err := json.Marshal(variantParsePayload{Declarations: declarations, Header: header})
	if err != nil {
		return nil, testvariant.TestVariantFileHeader{}, err
	}
	m.entries[name+"\x00"+digest] = raw
	return declarations, header, nil
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
	if _, err := testvariant.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo.parse); err != nil {
		t.Fatal(err)
	}
	if len(memo.entries) != 2 {
		t.Fatalf("recorded %d derivations, want the two compiled members", len(memo.entries))
	}
	got, err := testvariant.ComputeIdentity(dir, names, compiled, embedded, nil, nil, memo.parse)
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
	return shortDigest(content)
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
	h := &Hasher{selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil), modCache: cacheRoot, maximalFiles: map[string]maximalEffectScan{}, fileMemo: newFileMemos(), contents: map[string]fileBytes{}}
	var parsed []string
	withClosureTestHooks(analysisTestHookSet{
		fileParse: func(path string) { parsed = append(parsed, filepath.Base(path)) },
	}, func() {
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
		if _, cached := h.contents[pinned]; cached || len(h.fileMemo.scans.pending) != 0 {
			t.Fatalf("a module-cache file entered the content cache (%t) or the per-file memo (%d dirs pending)", cached, len(h.fileMemo.scans.pending))
		}
		for _, path := range []string{first, second} {
			if got, err := h.maximalFileEffectsCached("example.com/local", path); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: scan = %+v (err %v), want %+v", path, got, err, want)
			}
		}
	})
	if _, cached := h.contents[first]; !cached || len(h.fileMemo.scans.pending[localDir]) != 1 {
		t.Fatalf("the mutable-local files did not enter the content cache (%t) and one pending entry (%d)", cached, len(h.fileMemo.scans.pending[localDir]))
	}
	if !reflect.DeepEqual(parsed, []string{"a.go"}) {
		t.Fatalf("parsed %v, want the first sibling alone", parsed)
	}
	if len(h.ServedSummary()["file scan"]) != 0 {
		t.Fatalf("a pending-sibling hit was reported as a store serve: %v", h.ServedSummary())
	}
}

// TestContributionMemoServesWhatAMissDerives pins the memo's core property
// on both arms: with the memo armed, a second derivation of one node is a
// hit that returns exactly what the miss returned — contribution and files
// alike (REQ-closure-batch-equivalence: sharing changes cost, never
// evidence).
func TestContributionMemoServesWhatAMissDerives(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/memo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package memo\n\nfunc M() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.contribs = map[string]depContribution{}
	cacheDir := filepath.Join(h.modCache, "example.com", "dep@v1.0.0")
	for _, tc := range []struct {
		name string
		pkg  listPkg
		want string
	}{
		{"mutable", listPkg{ImportPath: "example.com/memo", Dir: dir, GoFiles: []string{"m.go"}, Module: &listMod{Main: true, Dir: dir}}, ""},
		{"cache", listPkg{ImportPath: "example.com/dep", Dir: cacheDir, Module: &listMod{Main: false, Dir: cacheDir}}, "cache:example.com/dep@v1.0.0"},
	} {
		miss, missFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s miss: %v", tc.name, err)
		}
		// The cache leg pins the exact pin bytes and that pinned source is
		// never read: a mis-classification or a shifted pin would silently
		// move every closure hash.
		if tc.want != "" && (miss != tc.want || missFiles != nil) {
			t.Fatalf("%s: contribution %q files %v, want %q with no files", tc.name, miss, missFiles, tc.want)
		}
		if _, ok := h.contribs[tc.pkg.ImportPath]; !ok {
			t.Fatalf("%s: the armed memo recorded nothing", tc.name)
		}
		hit, hitFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s hit: %v", tc.name, err)
		}
		if hit != miss {
			t.Fatalf("%s: hit contribution %q, miss %q", tc.name, hit, miss)
		}
		if !reflect.DeepEqual(hitFiles, missFiles) {
			t.Fatalf("%s: hit files %v, miss %v", tc.name, hitFiles, missFiles)
		}
		// A served hit and a silent re-derivation are equal by design; a
		// planted sentinel discriminates them — the next call must return
		// the memo's entry, not re-derive.
		h.contribs[tc.pkg.ImportPath] = depContribution{contribution: "sentinel:" + tc.name, files: []string{"sentinel"}}
		served, servedFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s sentinel: %v", tc.name, err)
		}
		if served != "sentinel:"+tc.name || !reflect.DeepEqual(servedFiles, []string{"sentinel"}) {
			t.Fatalf("%s: memo lookup bypassed: got %q/%v", tc.name, served, servedFiles)
		}
		h.contribs = map[string]depContribution{}
	}
}

// TestModulePinIsCacheRelativeAndSlashCanonical pins the pin identity's
// exact bytes: the cache-relative module content dir, Clean-normalized.
// The pin feeds every closure hash and persistent memo key, so a silent
// shift here invalidates all of them wholesale.
func TestModulePinIsCacheRelativeAndSlashCanonical(t *testing.T) {
	h := &Hasher{modCache: filepath.Join(string(filepath.Separator), "cache", "mod")}
	root := h.modCache
	for _, tc := range []struct {
		name string
		dir  string
		want string
	}{
		{"under cache", filepath.Join(root, "example.com", "dep@v1.0.0"), "example.com/dep@v1.0.0"},
		{"trailing separator cleans", filepath.Join(root, "example.com", "dep@v1.0.0") + string(filepath.Separator), "example.com/dep@v1.0.0"},
		{"outside cache keeps its identity", filepath.Join(string(filepath.Separator), "elsewhere", "dep"), "/elsewhere/dep"},
		{"the cache root itself is not relativized", root, filepath.ToSlash(root)},
	} {
		if got := h.modulePin(&listMod{Dir: tc.dir}); got != tc.want {
			t.Fatalf("%s: modulePin(%q) = %q, want %q", tc.name, tc.dir, got, tc.want)
		}
	}
}

func pinnedFixture(t *testing.T, h *Hasher) (listPkg, string) {
	t.Helper()
	moduleDir := filepath.Join(h.modCache, "example.com", "pinned@v1.2.3")
	pkgDir := filepath.Join(moduleDir, "eff")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The directives populate the wire shape's detail and unrefinable
	// fields, so the serve test's DeepEqual pins the full round trip.
	source := "package eff\n\nimport \"os\"\n\n//go:wasmimport host log\n//go:linkname E\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "eff.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := listPkg{
		ImportPath: "example.com/pinned/eff",
		Dir:        pkgDir,
		GoFiles:    []string{"eff.go"},
		Module:     &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: moduleDir, Main: false},
	}
	return pkg, pkgDir
}

// TestEffectScanMemoServesPinnedPackagesWithoutReads pins the memo's core
// property (REQ-closure-effect-scan-memo): a pinned package's scan derived
// once serves from the persistent memo with no file reads — proven by
// deleting the files and serving the identical scan from a fresh Hasher.
func TestEffectScanMemoServesPinnedPackagesWithoutReads(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Steer the fake module cache under the temp tree.
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if derived.Preferred == "" || len(derived.Effects) == 0 {
		t.Fatalf("derived scan carries no facts: %+v", derived)
	}
	// Every guard leg runs while the fixture's files are still readable,
	// so a weakened guard genuinely derives and serves rather than
	// escaping through a read error. A module reporting no version takes
	// the read path even when its files sit inside the module cache: its
	// pin would carry no signal. (Reachable listings report no version
	// only for the main and workspace modules; the leg is witnessed here
	// in its own right.)
	unversioned := pkg
	unversioned.Module = &listMod{Path: "example.com/pinned", Dir: filepath.Dir(pkgDir), Main: false}
	if _, handled, err := h.pinnedEffectScan(unversioned); err != nil || handled {
		t.Fatalf("unversioned in-cache package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A version-labeled module living outside the module cache (a local
	// replace) and a module without a content dir likewise read.
	dirless := pkg
	dirless.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Main: false}
	if _, handled, err := h.pinnedEffectScan(dirless); err != nil || handled {
		t.Fatalf("dirless module = handled %v, err %v; want unhandled, nil", handled, err)
	}
	if err := os.RemoveAll(pkgDir); err != nil {
		t.Fatal(err)
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, derived) {
		t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
	}
	// A mutable-local package never enters this memo — with a real,
	// readable file, so a weakened guard would genuinely derive and
	// serve rather than escape through a read error.
	localDir := filepath.Join(dir, "local")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "eff.go"), []byte("package eff\n\nimport \"os\"\n\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := pkg
	local.Module = &listMod{Main: true, Dir: dir}
	local.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(local); err != nil || handled {
		t.Fatalf("mutable-local package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A synthetic version label on a module outside the cache still reads:
	// the cache-membership leg holds on its own.
	replaced := pkg
	replaced.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: localDir, Main: false}
	replaced.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(replaced); err != nil || handled {
		t.Fatalf("local-replace package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// Package-level facts ride the live listing, never the memo: the same
	// key serves a different composite when the build configuration moves
	// a metadata fact (an assembly file selected only under some tags),
	// still with no file reads.
	asm := pkg
	asm.SFiles = []string{"impl_asm.s"}
	withAsm, handled, err := h2.pinnedEffectScan(asm)
	if err != nil || !handled {
		t.Fatalf("assembly-carrying serve = handled %v, err %v", handled, err)
	}
	assembly := opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly").Reason
	if !hasEffectReason(withAsm.Effects, assembly) {
		t.Fatalf("assembly fact missing from the served composite: %+v", withAsm)
	}
	if hasEffectReason(served.Effects, assembly) {
		t.Fatalf("assembly fact leaked into the assembly-free composite: %+v", served)
	}
}

// TestEffectScanMemoFoldMatchesInlineFold pins the byte-equivalence clause
// (REQ-closure-effect-scan-memo) against the inline loop's flat fold on a
// fixture that discriminates: a duplicate effect across two files, competing
// preferred diagnostics, and a package-level fact folding in first. Both the
// miss-path derivation and the memo hit must equal the flat per-item fold.
func TestEffectScanMemoFoldMatchesInlineFold(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	if err := os.WriteFile(filepath.Join(pkgDir, "more.go"), []byte("package eff\n\nimport \"os\"\n\nfunc F() { _, _ = os.Open(\"y\"); _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "netimp.go"), []byte("package eff\n\nimport \"net\"\n\nfunc G() { _ = net.Dial }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg.GoFiles = append(pkg.GoFiles, "more.go", "netimp.go")
	pkg.SFiles = []string{"impl_asm.s"}

	flat := maximalPackageExternalEffects(&pkg)
	pkgFactCount := len(flat.Effects)
	var rawEffects int
	var preferreds []string
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		rawEffects += len(scan.Effects)
		preferreds = append(preferreds, scan.Preferred)
		for _, effect := range scan.Effects {
			flat.Effects = appendExternalEffect(flat.Effects, effect)
		}
		for _, candidate := range scan.ImportCandidates {
			flat.ImportCandidates = appendExternalEffect(flat.ImportCandidates, candidate)
		}
		if len(scan.Effects) == 0 && len(scan.ImportCandidates) == 0 && scan.Preferred != "" && (flat.Preferred == "" || scan.Preferred < flat.Preferred) {
			flat.Preferred = scan.Preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flat.Effects...), flat.ImportCandidates...)); selected != "" {
		flat.Preferred = selected
	}
	if rawEffects <= len(flat.Effects)-pkgFactCount {
		t.Fatalf("fixture does not discriminate dedup: %d raw file effects, %d folded", rawEffects, len(flat.Effects)-pkgFactCount)
	}
	if len(preferreds) != 3 || preferreds[0] == preferreds[1] || preferreds[1] == preferreds[2] || preferreds[0] == preferreds[2] {
		t.Fatalf("fixture does not discriminate the preferred fold: %v", preferreds)
	}

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(derived, flat) {
		t.Fatalf("miss-path composite diverged from the flat fold:\n got %+v\nwant %+v", derived, flat)
	}
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, flat) {
		t.Fatalf("memo hit diverged from the flat fold:\n got %+v\nwant %+v", served, flat)
	}
	// The stored fold carries no package-level facts: deriving under a
	// configuration that selects the assembly file and then serving under
	// one that does not must drop the assembly fact, not replay it.
	var flatNoAsm maximalEffectScan
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, effect := range scan.Effects {
			flatNoAsm.Effects = appendExternalEffect(flatNoAsm.Effects, effect)
		}
		for _, candidate := range scan.ImportCandidates {
			flatNoAsm.ImportCandidates = appendExternalEffect(flatNoAsm.ImportCandidates, candidate)
		}
		if len(scan.Effects) == 0 && len(scan.ImportCandidates) == 0 && scan.Preferred != "" && (flatNoAsm.Preferred == "" || scan.Preferred < flatNoAsm.Preferred) {
			flatNoAsm.Preferred = scan.Preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flatNoAsm.Effects...), flatNoAsm.ImportCandidates...)); selected != "" {
		flatNoAsm.Preferred = selected
	}
	noAsm := pkg
	noAsm.SFiles = nil
	servedNoAsm, handled, err := h2.pinnedEffectScan(noAsm)
	if err != nil || !handled {
		t.Fatalf("assembly-free serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(servedNoAsm, flatNoAsm) {
		t.Fatalf("assembly-free memo hit diverged from the flat file fold:\n got %+v\nwant %+v", servedNoAsm, flatNoAsm)
	}
}

// TestEffectScanMemoMissesOnScopeAndFileSetChange pins the key's
// completeness: a strategy-scope change, the toolchain identity, a file-set
// change, and the Go/cgo partition each miss, and a corrupt entry
// recomputes silently.
func TestEffectScanMemoMissesOnScopeAndFileSetChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	scan := maximalEffectScan{
		Preferred:        "reaches net (network I/O)",
		Effects:          []externalEffect{{Kind: externalEffectFileIO, Reason: "reaches os.ReadFile (file I/O)"}},
		ImportCandidates: []externalEffect{{Kind: externalEffectNetwork, PackagePath: "net", Reason: "reaches net (network I/O)"}},
	}
	key := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go"}, nil)
	scope := (&Hasher{selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}).effectScanScope()
	storeEffectScan(effectScanDirName, scope, key, scan)
	if got, ok := loadEffectScan(effectScanDirName, scope, key); !ok || !reflect.DeepEqual(got, scan) {
		t.Fatalf("round trip = %+v ok=%v", got, ok)
	}
	if _, ok := loadEffectScan(effectScanDirName, scope+"-bumped", key); ok {
		t.Fatal("a bumped scan strategy served a prior generation's scan")
	}
	if _, ok := loadEffectScan(effectScanDirName, effectScanStrategy, key); ok {
		t.Fatal("the bare strategy without the analyzing frontend served")
	}
	if _, ok := loadEffectScan(testingScanDirName, scope, key); ok {
		t.Fatal("the sibling testing-scan directory served the effect-scan entry")
	}
	otherFiles := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go", "extra.go"}, nil)
	if _, ok := loadEffectScan(effectScanDirName, scope, otherFiles); ok {
		t.Fatal("a changed file set served the prior set's scan")
	}
	migrated := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", nil, []string{"eff.go"})
	if _, ok := loadEffectScan(effectScanDirName, scope, migrated); ok {
		t.Fatal("a file migrating between the Go and cgo lists served the prior partition's scan")
	}
	path, err := cachefile.Path(effectScanDirName, scope, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadEffectScan(effectScanDirName, scope, key); ok {
		t.Fatal("a corrupt entry served")
	}
}

// A package whose files carry only potential-external fallbacks - no
// effects, no plain always-external candidates - selects the
// lexicographically least fallback, package-wide
// (REQ-closure-observability-cause-order).
func TestPinnedFallbackSelectsLexicographicLeast(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	for name, source := range map[string]string{
		"only_time.go": "package eff\n\nvar _ = timeJan\n",
		"only_fmt.go":  "package eff\n\nimport \"fmt\"\n\nfunc S(v int) string { return fmt.Sprintf(\"%d\", v) }\n",
		"decl_time.go": "package eff\n\nimport \"time\"\n\nvar timeJan = time.January\n",
	} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg.GoFiles = []string{"decl_time.go", "only_fmt.go", "only_time.go"}
	composite, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if len(composite.Effects) != 0 || len(composite.ImportCandidates) != 0 {
		t.Fatalf("fallback fixture grew effects or candidates: %+v", composite)
	}
	if composite.Preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("fallback selection = %q, want the lexicographic least", composite.Preferred)
	}
}

// The persisted effect scan's strategy version is a golden: a bump is a
// conscious change of every persisted effect memo's identity.
func TestEffectScanStrategyVersion(t *testing.T) {
	if effectScanStrategy != "gofresh/effect-scan@32" {
		t.Fatalf("effect-scan strategy = %q, want @32", effectScanStrategy)
	}
}

func testingScanModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tscan\n\ngo 1.26\n")
	writeFile(t, dir, "scan.go", "package tscan\n\nfunc Pure(x int) int { return x + 1 }\n")
	writeFile(t, dir, "scan_test.go", `package tscan

import "testing"

func TestPure(t *testing.T) {
	_ = t.TempDir()
	if Pure(1) != 2 {
		t.Fatal("pure")
	}
}
`)
	return dir
}

// withTestingScanLoadCount observes the typed scan's own program load; a
// memo hit must never reach it.
func withTestingScanLoadCount(fn func(loads *int)) {
	loads := 0
	withClosureTestHooks(analysisTestHookSet{
		testingTypeOwnLoad: func(string) { loads++ },
	}, func() {
		fn(&loads)
	})
}

// TestTestingScanMemoServesWithoutTypeLoad pins the memo's core property
// (REQ-closure-testing-scan-memo): a scan derived once serves from the
// persistent memo with no type-environment load and byte-equivalent
// results — an effect-free scan included — and without a caller scope the
// memo stays disabled.
func TestTestingScanMemoServesWithoutTypeLoad(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	if err := os.MkdirAll(filepath.Join(dir, "plain"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "plain/plain.go", "package plain\n\nfunc P() int { return 0 }\n")
	withTestingScanLoadCount(func(loads *int) {
		first, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		first.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		derived, err := first.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("derivation loads = %d, want 1", *loads)
		}
		if len(derived.Effects) == 0 || derived.Preferred == "" {
			t.Fatalf("derived scan carries no testing facts: %+v", derived)
		}

		second, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		second.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		served, err := second.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("memo hit loaded the type environment: loads = %d", *loads)
		}
		if !reflect.DeepEqual(served, derived) {
			t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
		}

		// Without a caller-supplied scope the memo is disabled: the scan
		// loads even though a matching entry exists under some scope.
		bare, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		bareScan, err := bare.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 2 {
			t.Fatalf("scope-less scan loads = %d, want 2", *loads)
		}
		if !reflect.DeepEqual(bareScan, derived) {
			t.Fatalf("scope-less scan diverged:\n got %+v\nwant %+v", bareScan, derived)
		}

		// An effect-free scan round-trips as a hit: the recorded absence of
		// testing effects serves without a load.
		third, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		third.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		emptyDerived, err := third.maximalTestingTypeEffects("example.com/tscan/plain")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatalf("effect-free derivation loads = %d, want 3", *loads)
		}
		if len(emptyDerived.Effects) != 0 || emptyDerived.Preferred != "" {
			t.Fatalf("plain package scan carries facts: %+v", emptyDerived)
		}
		fourth, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		fourth.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		emptyServed, err := fourth.maximalTestingTypeEffects("example.com/tscan/plain")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatalf("effect-free memo hit loaded the type environment: loads = %d", *loads)
		}
		if !reflect.DeepEqual(emptyServed, emptyDerived) {
			t.Fatalf("effect-free served scan diverged:\n got %+v\nwant %+v", emptyServed, emptyDerived)
		}

		// A key-derivation failure disables the memo for the package —
		// fail-open to recomputation: the scan still derives, serves nothing
		// from the memo, and persists nothing. The poisoned session list
		// cache fails the closure hash while the scan's own load stays
		// healthy — a single-sided failure.
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		memoDir := filepath.Join(cache, "gofresh", testingScanDirName)
		before, err := os.ReadDir(memoDir)
		if err != nil {
			t.Fatal(err)
		}
		broken, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		broken.SetAnalysisScope(AnalysisScope{ProofStrategy: "strategy@1", Toolchain: "toolchain", BuildConfig: "build"})
		broken.lists["example.com/tscan"] = []listPkg{{
			ImportPath: "example.com/tscan",
			Dir:        filepath.Join(dir, "missing"),
			GoFiles:    []string{"gone.go"},
			Module:     &listMod{Path: "example.com/tscan", Main: true, Dir: dir},
		}}
		brokenScan, err := broken.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatalf("fail-open derivation errored: %v", err)
		}
		if *loads != 4 {
			t.Fatalf("fail-open scan loads = %d, want 4 (a failed key must not serve)", *loads)
		}
		if !reflect.DeepEqual(brokenScan, derived) {
			t.Fatalf("fail-open scan diverged:\n got %+v\nwant %+v", brokenScan, derived)
		}
		after, err := os.ReadDir(memoDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("a failed key derivation persisted an entry: %d -> %d files", len(before), len(after))
		}
	})
}

// TestTestingScanMemoMissesOnScopeAndSourceChange pins the key's
// completeness (REQ-closure-testing-scan-memo): a scope change and a
// test-only source change each miss — the scan reads test-variant
// source, so the compartment axis participates — and a corrupt entry
// recomputes silently.
func TestTestingScanMemoMissesOnScopeAndSourceChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := testingScanModule(t)
	withTestingScanLoadCount(func(loads *int) {
		first, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		first.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		before, err := first.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 1 {
			t.Fatalf("derivation loads = %d, want 1", *loads)
		}

		otherScope, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		otherScope.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-b", BuildConfig: "build"})
		if _, err := otherScope.maximalTestingTypeEffects("example.com/tscan"); err != nil {
			t.Fatal(err)
		}
		if *loads != 2 {
			t.Fatal("a different scope served from the memo")
		}

		// A test-only edit moves the key and the scan alike.
		testSrc, err := os.ReadFile(filepath.Join(dir, "scan_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scan_test.go"), append(testSrc, []byte("\nfunc TestExtra(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		moved, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		moved.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		after, err := moved.maximalTestingTypeEffects("example.com/tscan")
		if err != nil {
			t.Fatal(err)
		}
		if *loads != 3 {
			t.Fatal("a test-only source change served from the memo")
		}
		if !hasEffectReason(after.Effects, "reaches testing.Setenv (process or path mutation)") {
			t.Fatalf("post-edit scan misses the new testing effect: %+v", after)
		}
		if reflect.DeepEqual(after, before) {
			t.Fatal("post-edit scan equals the pre-edit scan")
		}

		// Corrupt entries recompute silently.
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(cache, "gofresh", testingScanDirName))
		if err != nil || len(entries) == 0 {
			t.Fatalf("memo entries = %v, err %v", entries, err)
		}
		for _, entry := range entries {
			if err := os.WriteFile(filepath.Join(cache, "gofresh", testingScanDirName, entry.Name()), []byte("corrupt"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		recomputed, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		recomputed.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "scope-a", BuildConfig: "build"})
		if _, err := recomputed.maximalTestingTypeEffects("example.com/tscan"); err != nil {
			t.Fatal(err)
		}
		if *loads != 4 {
			t.Fatal("a corrupt entry served")
		}
	})
}

func TestNewAtRejectsExternalPackageDriver(t *testing.T) {
	env := environmentWith("GOPACKAGESDRIVER=custom")
	if _, err := newAtEnv(context.Background(), t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "GOPACKAGESDRIVER") {
		t.Fatalf("external package driver accepted: %v", err)
	}
}

func TestSyntheticTestPackageCannotReplaceAnImportBinding(t *testing.T) {
	const pkg = "example.com/bindings"
	dir := writeTestVariantModule(t, map[string]string{
		"p.go":        "package p\n",
		"ext_test.go": "package p_test\nimport \"example.com/bindings_test\"\nfunc Example() { declared.Value() }\n",
	})
	module := &listMod{Path: pkg, Main: true, Dir: dir}
	real := listPkg{ImportPath: pkg + "_test", Name: "declared", Dir: filepath.Join(dir, "dependency")}
	synthetic := listPkg{ImportPath: pkg + "_test [" + pkg + ".test]", ForTest: pkg, Name: "p_test", Dir: dir, Module: module, GoFiles: []string{"ext_test.go"}}
	for _, copies := range [][]listPkg{{real, synthetic, real}, {synthetic, real, synthetic}} {
		h := &Hasher{lists: map[string][]listPkg{pkg: append([]listPkg{
			{ImportPath: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"p.go"}},
		}, copies...)}, testVariants: map[string]testvariant.Identity{}}
		ledger, err := h.TestVariantLedger(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if len(ledger.FileHeaders) != 1 || len(ledger.FileHeaders[0].Bindings.Imports) != 1 {
			t.Fatalf("missing external-test binding evidence: %+v", ledger)
		}
		if got := ledger.FileHeaders[0].Bindings.Imports[0]; got.Path != pkg+"_test" || got.Name != "" {
			t.Fatalf("conflicting declaration was resolved by listing order: %+v", got)
		}
		if testvariant.DiffTestVariantLedgers(ledger, ledger).Inert() {
			t.Fatal("conflicting import-name evidence authorized inertness")
		}
	}
}

func TestListingEntriesTrackSymlinkTargetKinds(t *testing.T) {
	dir, target := t.TempDir(), filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(dir, "input.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	read := func() listingEntry {
		t.Helper()
		entries, err := listingEntries(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("entries: %+v %v", entries, err)
		}
		return entries[0]
	}
	missing := read()
	if !missing.Dangling || missing.regular() {
		t.Fatalf("dangling: %+v", missing)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := read()
	if directory == missing || directory.Dangling || directory.regular() || directory.TargetType != os.ModeDir {
		t.Fatalf("directory: %+v", directory)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular := read()
	if regular == directory || regular == missing || !regular.regular() {
		t.Fatalf("regular: %+v", regular)
	}
	if again := read(); again != regular {
		t.Fatal("unchanged entry moved")
	}
}

// Equal admission Booleans cannot alias different source or policy inputs, and
// an unaudited selection never shares an effectScanScope or AnalysisScope with
// an audited selection over identical content and policy.
func TestEffectScanScopeDiscriminatesContentAndPolicy(t *testing.T) {
	h := Hasher{selection: toolchain.SelectionForTest(true, "", "", "content-a", "policy-a", nil, nil)}
	base := h.effectScanScope()
	if base != effectScanStrategy+" "+runtime.Version()+"|content-a|policy-a" {
		t.Fatalf("effect scope lost a dependency: %q", base)
	}
	unaudited := Hasher{selection: toolchain.SelectionForTest(true, "moved", "", "content-a", "policy-a", nil, nil)}
	if unaudited.effectScanScope() == base {
		t.Fatal("unaudited selection shared effectScanScope with audited selection")
	}
	caller := AnalysisScope{ProofStrategy: "proof", FactStrategy: "facts", Toolchain: "tc", BuildConfig: "bc"}
	if auditedScope, unauditedScope := h.SetAnalysisScope(caller), unaudited.SetAnalysisScope(caller); auditedScope.Proofs() == unauditedScope.Proofs() || auditedScope.Facts() == unauditedScope.Facts() {
		t.Fatal("unaudited selection shared AnalysisScope with audited selection")
	}
	for _, sel := range []toolchain.Selection{
		toolchain.SelectionForTest(true, "", "", "content-b", "policy-a", nil, nil),
		toolchain.SelectionForTest(true, "", "", "content-a", "policy-b", nil, nil),
	} {
		h.selection = sel
		if h.effectScanScope() == base {
			t.Fatal("different dependencies share a scope")
		}
	}
	for _, sel := range []toolchain.Selection{
		toolchain.SelectionForTest(true, "", "", "content-a", "", nil, nil),
		toolchain.SelectionForTest(true, "", "", "", "policy-a", nil, nil),
		toolchain.SelectionForTest(true, "", "", "", "", nil, nil),
	} {
		h.selection = sel
		if h.effectScanScope() != "" {
			t.Fatal("incomplete dependencies armed the memo")
		}
	}
}

// The audit ladder survives the zero value: a Hasher built without
// construction refuses every admission AND explains itself — the
// verdict/text biconditional holds in the unresolved world too.
func TestZeroHasherRefusesSelectionAudit(t *testing.T) {
	var h Hasher
	if h.SelectionAudited() {
		t.Fatal("zero-value Hasher reports an audited selection — fail-open by omission")
	}
	if notice := h.SelectionNotice(); notice == "" || !strings.Contains(notice, "unresolved") {
		t.Fatalf("unresolved verdict has no explaining notice: %q", notice)
	}
	// The third reading refuses with the same verdict: a refusal
	// composed under the zero value names the unresolved axis, never
	// an empty attribution beside a refused audit
	// (REQ-closure-refusal-channels).
	if attribution := h.SelectionAttribution(); attribution == "" || !strings.Contains(attribution, "unresolved") {
		t.Fatalf("unresolved verdict's attribution %q does not name the unresolved axis", attribution)
	}
	requireBareAxis(t, "unresolved", h.SelectionNotice(), h.SelectionAttribution())
}

// TestPackageFileWalkEndsAtTheNextEntry pins the package-file walk's
// check point (REQ-closure-observability-toolchain-key: the walk checks
// the package's cancellation check at every entry): over a planted tree
// a context cancelled at the walk's second entry ends it at the third —
// the entries seen are exactly the two before the cancellation's check
// fired — answering the cancellation with nothing listed; a context
// cancelled before the walk ends it at the root entry; the live walk
// lists the three files.
func TestPackageFileWalkEndsAtTheNextEntry(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Hasher{ctx: ctx}
	const stopAt = 2
	seen := 0
	var files []string
	var err error
	withClosureTestHooks(analysisTestHookSet{
		walkEntry: func(path string) {
			seen++
			if seen == stopAt {
				cancel()
			}
		},
	}, func() {
		files, err = allPackageFiles(h.contextErr, dir)
	})
	if !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a walk cancelled at entry %d answered %v with %d files, want the cancellation and nothing listed", stopAt, err, len(files))
	}
	if seen != stopAt {
		t.Fatalf("the walk visited %d entries with the cancellation at entry %d, want exactly that many: the next entry's check ends it", seen, stopAt)
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if files, err := allPackageFiles((&Hasher{ctx: cancelled}).contextErr, dir); !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a pre-cancelled walk answered %v with %d files, want the cancellation at the root entry", err, len(files))
	}
	live, err := allPackageFiles((&Hasher{ctx: context.Background()}).contextErr, dir)
	if err != nil || len(live) != 3 {
		t.Fatalf("the live walk answered %v with %d files, want the three", err, len(live))
	}
}

func FuzzClosureCoverageAndMutableLocalIdentity(f *testing.F) {
	f.Add("pkg/a", "v1.2.3", "func F() int { return 1 }", "// normal comment", true, false)
	f.Add("pkg/b", "v0.1.0", "func G() string { return \"x\" }", "//go:noinline", false, true)
	f.Add("pkg/c", "v2.0.0", "var X = 42", "// Code generated by tool; DO NOT EDIT.", false, false)

	f.Fuzz(func(t *testing.T, subPkg, ver, decl, comment string, inModCache, isMain bool) {
		cleanSub := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'a'
		}, subPkg)
		if cleanSub == "" {
			cleanSub = "p"
		}
		cleanVer := "v1.0.0"
		if strings.HasPrefix(ver, "v") && len(ver) < 16 && !strings.ContainsAny(ver, "/\\ \t\n") {
			cleanVer = ver
		}

		// 1. Canonical member digest & strategy coupling (REQ-closure-identity-strategy).
		if !strings.Contains(IdentityStrategy, canonicalStrategy) || !strings.Contains(IdentityStrategy, variantParseStrategy) {
			t.Fatalf("IdentityStrategy %q does not compose %q and %q", IdentityStrategy, canonicalStrategy, variantParseStrategy)
		}
		srcBase := "package p\n\n" + decl + "\n"
		d1, ok1 := canonicalDigest([]byte(srcBase))
		if ok1 {
			// Non-retained comment and whitespace changes leave the canonical digest invariant,
			// whereas directive or generated-marker comments move it when retained.
			withSpace := "package p\n\n\t\n" + decl + "\n"
			if d2, ok2 := canonicalDigest([]byte(withSpace)); !ok2 || d1 != d2 {
				t.Fatalf("whitespace moved canonical digest: %q vs %q", d1, d2)
			}
			singleLine := strings.ReplaceAll(strings.ReplaceAll(comment, "\n", " "), "\r", " ")
			if !strings.HasPrefix(singleLine, "//") {
				singleLine = "// " + singleLine
			}
			withComment := "package p\n" + singleLine + "\n" + decl + "\n"
			dComment, okC := canonicalDigest([]byte(withComment))
			if okC {
				if !retainedComment(singleLine) && dComment != d1 {
					t.Fatalf("non-retained comment %q moved canonical digest", singleLine)
				}
				if retainedComment(singleLine) && dComment == d1 {
					t.Fatalf("retained directive/generated comment %q did not move canonical digest", singleLine)
				}
			}
			withDirective := "package p\n//go:noinline\n" + decl + "\n"
			if dDir, okDir := canonicalDigest([]byte(withDirective)); !okDir || dDir == d1 {
				t.Fatalf("retained //go:noinline directive did not move canonical digest: %q", dDir)
			}
		}

		// 2. Blindspot resolved vs downgraded linkname floor (REQ-closure-blindspot).
		auditedLinkSrc := "package p\n//go:linkname a runtime.getAuxv\n"
		unauditedLinkSrc := "package p\n//go:linkname a runtime.unapproved\n"
		if scanAud, err := maximalFileEffectsContent(true, "link.go", []byte(auditedLinkSrc)); err != nil || len(scanAud.Effects) != 0 {
			t.Fatalf("audited linkname target did not drop opaque-linkage floor: %+v, err=%v", scanAud.Effects, err)
		}
		if scanDowngraded, err := maximalFileEffectsContent(false, "link.go", []byte(auditedLinkSrc)); err != nil || !strings.Contains(scanDowngraded.Preferred, "go:linkname") {
			t.Fatalf("downgraded toolchain did not restore opaque-linkage floor on audited linkname: %+v, err=%v", scanDowngraded, err)
		}
		if scanUnaud, err := maximalFileEffectsContent(true, "link.go", []byte(unauditedLinkSrc)); err != nil || !strings.Contains(scanUnaud.Preferred, "go:linkname") {
			t.Fatalf("unaudited linkname target did not keep opaque-linkage floor: %+v, err=%v", scanUnaud, err)
		}

		// 3. Coverage, mutable-local vs module-cache classification, test-variant compartment,
		// and per-subject vs view-wide source files (REQ-closure-coverage, REQ-closure-mutable-local,
		// REQ-closure-view-maximal).
		root := t.TempDir()
		modCache := filepath.Join(root, "modcache")
		workDir := filepath.Join(root, "work")
		pkgDir := filepath.Join(workDir, cleanSub)
		modDir := workDir
		if inModCache {
			modDir = filepath.Join(modCache, "example.com", "dep@"+cleanVer)
			pkgDir = filepath.Join(modDir, cleanSub)
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		goFile := "member.go"
		testFile := "member_test.go"
		embedFile := "data.txt"
		if err := os.WriteFile(filepath.Join(pkgDir, goFile), []byte("package p\nfunc M() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, testFile), []byte("package p\nimport \"testing\"\nfunc TestM(t *testing.T) {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, embedFile), []byte("payload\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		h := &Hasher{
			ctx:      context.Background(),
			modCache: modCache,
			contribs: map[string]depContribution{},
			contents: map[string]fileBytes{},
		}
		lp := listPkg{
			ImportPath: "example.com/dep/" + cleanSub,
			Dir:        pkgDir,
			GoFiles:    []string{goFile},
			EmbedFiles: []string{embedFile},
			Module: &listMod{
				Path:    "example.com/dep",
				Version: cleanVer,
				Dir:     modDir,
				Main:    isMain,
			},
		}
		compiled, embedded, canonical := memberKinds(lp)
		if !compiled[goFile] || !canonical[goFile] || !embedded[embedFile] || canonical[embedFile] {
			t.Fatalf("memberKinds misclassified compiled/embedded/canonical: %v %v %v", compiled, embedded, canonical)
		}
		emptyComp, err := testvariant.ComputeIdentity(pkgDir, nil, nil, nil, nil, h.readFileSum, nil)
		if err != nil || emptyComp.Hash == "" {
			t.Fatalf("empty testvariant.ComputeIdentity = (%+v, %v)", emptyComp, err)
		}
		compId, err := testvariant.ComputeIdentity(pkgDir, []string{testFile}, map[string]bool{testFile: true}, nil, map[string]string{}, h.readFileSum, nil)
		if err != nil || compId.Hash == "" || compId.Hash == emptyComp.Hash || !slices.Equal(compId.Files, []string{testFile}) {
			t.Fatalf("testvariant.ComputeIdentity = (%+v, %v), want non-empty test-variant hash over [%s]", compId, err, testFile)
		}

		isPinned := h.pinnedPackage(&lp)
		wantPinned := inModCache && !isMain
		if isPinned != wantPinned {
			t.Fatalf("pinnedPackage = %v, want %v (inModCache=%v, isMain=%v)", isPinned, wantPinned, inModCache, isMain)
		}

		contrib1, files1, err := h.contributionAndFilesFor("example.com/subj", lp)
		if err != nil {
			t.Fatalf("contributionAndFilesFor: %v", err)
		}
		if isPinned {
			if !strings.HasPrefix(contrib1, "cache:") || len(files1) != 0 {
				t.Fatalf("pinned package contribution = %q (files=%v), want cache: prefix and no source files", contrib1, files1)
			}
		} else {
			if !strings.HasPrefix(contrib1, "src:") || len(files1) != 2 {
				t.Fatalf("mutable-local package contribution = %q (files=%v), want src: prefix and 2 source files", contrib1, files1)
			}
			// Editing the test-only compartment file leaves the core contribution hash unchanged,
			// while moving the test-variant compartment hash.
			if err := os.WriteFile(filepath.Join(pkgDir, testFile), []byte("package p\nimport \"testing\"\nfunc TestM(t *testing.T) { t.Log(1) }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			h.resetCallScope()
			contribAfterTestEdit, _, err := h.contributionAndFilesFor("example.com/subj", lp)
			if err != nil || contribAfterTestEdit != contrib1 {
				t.Fatalf("test-variant edit moved core contribution: %q vs %q (err=%v)", contribAfterTestEdit, contrib1, err)
			}
			compId2, err := testvariant.ComputeIdentity(pkgDir, []string{testFile}, map[string]bool{testFile: true}, nil, map[string]string{}, h.readFileSum, nil)
			if err != nil || compId2.Hash == compId.Hash {
				t.Fatalf("test-variant edit did not move compartment hash: %q", compId.Hash)
			}

			// Silent edit in mutable-local core source file moves its contribution hash.
			h.resetCallScope()
			if err := os.WriteFile(filepath.Join(pkgDir, goFile), []byte("package p\nfunc M() { println(1) }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			contrib2, _, err := h.contributionAndFilesFor("example.com/subj", lp)
			if err != nil {
				t.Fatal(err)
			}
			if contrib2 == contrib1 {
				t.Fatalf("editing mutable-local source file did not move contribution: %q", contrib1)
			}
		}

		// Standard library and generated testmain packages are excluded from non-stdlib fold.
		stdPkg := lp
		stdPkg.Standard = true
		if c, _, err := h.contributionAndFilesFor("example.com/subj", stdPkg); err != nil || c != "" {
			t.Fatalf("stdlib package was not excluded: %q, %v", c, err)
		}
	})
}

// The typed testing scan's memo serves the classification table, so
// the strategy moves with it (REQ-closure-testing-scan-memo).
func TestTestingScanStrategyVersion(t *testing.T) {
	t.Parallel()
	if testingScanStrategy != "gofresh/testing-scan@6" {
		t.Fatalf("testing-scan strategy = %q, want @6 — the harness lifecycle Context read rejoined the table", testingScanStrategy)
	}
}
