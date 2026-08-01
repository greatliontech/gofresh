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
	}{
		{"mutable", listPkg{ImportPath: "example.com/memo", Dir: dir, GoFiles: []string{"m.go"}, Module: &listMod{Main: true, Dir: dir}}},
		{"cache", listPkg{ImportPath: "example.com/dep", Dir: cacheDir, Module: &listMod{Main: false, Dir: cacheDir}}},
	} {
		miss, missFiles, err := h.contributionAndFilesFor("", tc.pkg)
		if err != nil {
			t.Fatalf("%s miss: %v", tc.name, err)
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

// TestBatchEntriesDiscardStaleContributionEntries pins the call scope: a
// batch entry must start from an empty memo, or an edit between calls
// could serve a prior generation's contribution.
func TestBatchEntriesDiscardStaleContributionEntries(t *testing.T) {
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
