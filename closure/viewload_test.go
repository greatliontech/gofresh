package closure

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A shared view load must fully substitute for the testing-type effect scan's
// private load — same effects, no second typed load inside the pass
// (REQ-fresh-coherent-view: one load per observation pass).
func TestViewLoadSubstitutesForTestingTypeScanLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/viewload\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package viewload\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib_test.go"), []byte("package viewload\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tt.TempDir()\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/viewload"
	subjects := []Subject{{Package: pkg, Symbol: "TestF"}}

	unshared, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := unshared.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}

	load, err := LoadViewPackagesEnv(context.Background(), dir, os.Environ(), nil, pkg)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	shared.UseViewLoad(load)
	var privateLoads []string
	testingTypeOwnLoadHook = func(pkgPath string) { privateLoads = append(privateLoads, pkgPath) }
	defer func() { testingTypeOwnLoadHook = nil }()
	got, err := shared.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateLoads) != 0 {
		t.Fatalf("testing-type scan performed private loads despite a covering view load: %v", privateLoads)
	}
	for _, subject := range subjects {
		if got[subject] != want[subject] {
			t.Fatalf("shared view load changed the closure for %s:\n  unshared %+v\n  shared   %+v", subject.Symbol, want[subject], got[subject])
		}
	}
	if !got[subjects[0]].Unverifiable {
		t.Fatal("fixture should be unverifiable through its testing-runtime effect (t.TempDir); the testing-type scan did not run")
	}
}

// A view load that does not cover the requested package falls back to the
// private load with identical semantics rather than failing or silently
// skipping the scan.
func TestViewLoadMissFallsBackToPrivateTestingTypeLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/viewloadmiss\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package viewloadmiss\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib_test.go"), []byte("package viewloadmiss\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tt.TempDir()\n\t_ = F()\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "other.go"), []byte("package other\n\nfunc G() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/viewloadmiss"
	subjects := []Subject{{Package: pkg, Symbol: "TestF"}}

	load, err := LoadViewPackagesEnv(context.Background(), dir, os.Environ(), nil, "example.com/viewloadmiss/other")
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.UseViewLoad(load)
	var privateLoads []string
	testingTypeOwnLoadHook = func(pkgPath string) { privateLoads = append(privateLoads, pkgPath) }
	defer func() { testingTypeOwnLoadHook = nil }()
	got, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateLoads) != 1 || privateLoads[0] != pkg {
		t.Fatalf("expected exactly one private fallback load of %s, got %v", pkg, privateLoads)
	}
	if !got[subjects[0]].Unverifiable {
		t.Fatal("fallback path lost the testing-runtime effect")
	}
}
