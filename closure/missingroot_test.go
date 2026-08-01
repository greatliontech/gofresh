package closure

import (
	"strings"
	"testing"
)

// A production symbol whose package has only an external test variant cannot be
// rooted in the loaded test-binary program. That is a subject-local fact: precise
// analysis errors naming exactly that subject, the observability proof degrades
// to an unavailable-evidence refusal for that subject alone, and a rootable
// sibling of the same package analyzes normally (REQ-closure-analysis's
// missing-root subject-local degradation arm).
func TestMissingRootDegradesSubjectLocally(t *testing.T) {
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
	if _, err := computeTier2Result(h, pkg, unrootable.Symbol); err == nil || !strings.Contains(err.Error(), "Ok not found in "+pkg) {
		t.Fatalf("unrootable subject analysis error = %v, want an error naming the subject", err)
	}
	analyzed, err := computeTier2Result(h, pkg, sibling.Symbol)
	if err != nil {
		t.Fatalf("sibling analysis disturbed by the unrootable subject: %v", err)
	}
	if len(analyzed.contribs) == 0 {
		t.Fatalf("sibling analysis = %+v, want normal analysis undisturbed by the unrootable subject", analyzed)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{unrootable, sibling})
	if err != nil {
		t.Fatalf("missing root failed the whole observability batch: %v", err)
	}
	degraded := proofs[unrootable]
	if degraded.Observable || !strings.Contains(degraded.Reason, "observation analysis unavailable") || !strings.Contains(degraded.Reason, "Ok not found in "+pkg) {
		t.Fatalf("unrootable proof = %+v, want unavailable-evidence attribution", degraded)
	}
	if p := proofs[sibling]; strings.Contains(p.Reason, "unavailable") {
		t.Fatalf("sibling proof degraded by the unrootable subject: %+v", p)
	}
}
