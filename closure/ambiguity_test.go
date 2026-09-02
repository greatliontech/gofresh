package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A top-level name declared by both the package's in-package test variant
// and its external test package tombstones that root alone: the requested
// ambiguous subject fails precise analysis with an error naming the
// collision and degrades to a refusing observability proof naming it,
// while sibling subjects of the same package analyze normally
// (REQ-closure-analysis's subject-local ambiguity arm).
func TestAmbiguousRootDegradesSubjectLocally(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA and proves observability")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/ambroot\n\ngo 1.26\n",
		"lib.go":           "package ambroot\n\nfunc Compute(x int) int { return x * 2 }\n",
		"internal_test.go": "package ambroot\n\nimport \"testing\"\n\nfunc mustHelper(t *testing.T) int {\n\tt.Helper()\n\treturn 21\n}\n\nfunc TestInternal(t *testing.T) {\n\tif Compute(mustHelper(t)) != 42 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"external_test.go": "package ambroot_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/ambroot\"\n)\n\nfunc mustHelper(t *testing.T) int {\n\tt.Helper()\n\treturn 5\n}\n\nfunc TestExternal(t *testing.T) {\n\tif ambroot.Compute(mustHelper(t)) != 10 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/ambroot"
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	sibling := Subject{Package: pkg, Symbol: "Compute"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := computeTier2Result(h, pkg, ambiguous.Symbol); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous subject analysis error = %v, want an error naming the collision", err)
	}
	sib, err := computeTier2Result(h, pkg, sibling.Symbol)
	if err != nil {
		t.Fatalf("sibling subject failed because of the collision: %v", err)
	}
	if sib.unverifiable || strings.Contains(sib.reason, "ambiguous") {
		t.Fatalf("sibling subject degraded by the collision: %+v", sib)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{ambiguous, sibling})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofs[ambiguous]; p.Observable || !strings.Contains(p.Reason, "ambiguous") {
		t.Fatalf("ambiguous subject proof = %+v, want a refusal naming the collision", p)
	}
	if p := proofs[sibling]; strings.Contains(p.Reason, "ambiguous") {
		t.Fatalf("sibling proof polluted by the collision: %+v", p)
	}
}
