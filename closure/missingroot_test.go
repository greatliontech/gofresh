package closure

import (
	"strings"
	"testing"
)

// A production symbol whose package has only an external test variant cannot be
// rooted in the loaded test-binary program. Refined analysis must degrade that
// subject alone — to the maximal package closure, widened and unverifiable —
// while a rootable sibling in the same batch analyzes normally
// (REQ-closure-batch-equivalence, REQ-closure-floor).
func TestComputeBatchDegradesMissingRootSubjectLocally(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/external\n\ngo 1.26\n")
	writeFile(t, dir, "external.go", "package external\n\nfunc Ok() bool { return true }\n")
	writeFile(t, dir, "external_test.go", `package external_test

import (
	"testing"

	"example.com/external"
)

func TestExternal(t *testing.T) {
	if !external.Ok() {
		t.Fatal("not ok")
	}
}
`)
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/external"
	unrootable := Subject{Package: pkg, Symbol: "Ok"}
	sibling := Subject{Package: pkg, Symbol: "TestExternal"}
	batch, err := h.ComputeBatch([]Subject{unrootable, sibling})
	if err != nil {
		t.Fatalf("ComputeBatch: %v", err)
	}
	// The degradation's floor-hash listing must not defeat the per-group
	// release discipline: an un-primed batch leaves no retained list entry.
	if _, retained := h.lists[pkg]; retained {
		t.Fatal("list cache retained after an un-primed batch; want per-group release")
	}
	degraded := batch[unrootable]
	if !degraded.Widened || !degraded.Unverifiable {
		t.Fatalf("unrootable closure = %+v, want widened unverifiable degradation", degraded)
	}
	if !strings.Contains(degraded.Reason, "refined analysis unavailable") || !strings.Contains(degraded.Reason, "Ok not found in "+pkg) {
		t.Fatalf("unrootable reason = %q, want unavailable-evidence attribution", degraded.Reason)
	}
	maximal, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.Hash != maximal {
		t.Fatalf("unrootable hash = %q, want the maximal package closure %q", degraded.Hash, maximal)
	}
	analyzed := batch[sibling]
	if analyzed.Hash == "" || strings.Contains(analyzed.Reason, "refined analysis unavailable") {
		t.Fatalf("sibling closure = %+v, want normal analysis undisturbed by the unrootable subject", analyzed)
	}
	single, err := h.Compute(pkg, "Ok")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if single != degraded {
		t.Fatalf("independent analysis = %+v, batched = %+v, want identical degradation", single, degraded)
	}
	singleSibling, err := h.Compute(pkg, "TestExternal")
	if err != nil {
		t.Fatalf("Compute(sibling): %v", err)
	}
	if singleSibling != analyzed {
		t.Fatalf("independent sibling analysis = %+v, batched = %+v, want identical results", singleSibling, analyzed)
	}
}
