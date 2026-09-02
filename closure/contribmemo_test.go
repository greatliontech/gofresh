package closure

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestContributionMemoServesWhatAMissDerives pins the memo's core property
// on both arms: with the memo armed, a second derivation of one node is a
// hit that returns exactly what the miss returned — contribution and files
// alike (REQ-closure-batch-equivalence: sharing changes cost, never
// evidence).
func TestContributionMemoServesWhatAMissDerives(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/memo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package memo\n\nfunc M() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
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

// TestBatchEntriesDiscardStaleContributionEntries pins the call scope: a
// batch entry must start from an empty memo, or an edit between calls
// could serve a prior generation's contribution.
func TestBatchEntriesDiscardStaleContributionEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA and proves observability")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/memo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package memo\n\nfunc M() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/memo", Symbol: "M"}
	h.contribs = map[string]depContribution{"example.com/memo": {contribution: "src:example.com/memo=stale"}}
	batched, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	independent := computeAt(t, dir, subject)
	if batched[subject] != independent[subject] {
		t.Fatalf("batch served a pre-call memo generation: %+v vs %+v", batched[subject], independent[subject])
	}
	h2, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.contribs = map[string]depContribution{"example.com/memo": {contribution: "src:example.com/memo=stale"}}
	if _, err := h2.ComputeObservabilityBatch([]Subject{{Package: "example.com/memo", Symbol: "M"}}); err != nil {
		t.Fatal(err)
	}
	if c, ok := h2.contribs["example.com/memo"]; ok && c.contribution == "src:example.com/memo=stale" {
		t.Fatal("observability batch served or retained a pre-call memo generation")
	}
}
