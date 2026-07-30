package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A top-level name declared by both the package's in-package test variant
// and its external test package tombstones that root alone: the requested
// ambiguous subject degrades to the widened unverifiable floor
// (refinement) and a refusing proof (observability), each naming the
// collision, while sibling subjects of the same package analyze normally
// (REQ-closure-analysis's subject-local ambiguity arm,
// REQ-closure-batch-equivalence).
func TestAmbiguousRootDegradesSubjectLocally(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/ambroot\n\ngo 1.26\n",
		"lib.go": "package ambroot\n\nfunc Compute(x int) int { return x * 2 }\n",
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
	refined, err := h.ComputeBatch([]Subject{ambiguous, sibling})
	if err != nil {
		t.Fatalf("ambiguous root failed the whole batch: %v", err)
	}
	got := refined[ambiguous]
	if !got.Widened || !got.Unverifiable || !strings.Contains(got.Reason, "ambiguous") {
		t.Fatalf("ambiguous subject refinement = %+v, want the widened unverifiable floor naming the collision", got)
	}
	sib := refined[sibling]
	if sib.Unverifiable || strings.Contains(sib.Reason, "ambiguous") {
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
