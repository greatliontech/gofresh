package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sync.Map's Load, Store, and LoadOrStore are the audited memo set:
// process-memory operations a subject may reach observably. Its other
// operations keep the unaudited-standard refusal — Range walks an
// order seeded at runtime (REQ-closure-shared-dynamic-state).
func TestSyncMapMemoOperationsAreAuditedAndRangeIsNot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/syncmemo\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"memo", "package memo\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tv, _ := m.LoadOrStore(\"k\", 2)\n\tw, _ := m.Load(\"k\")\n\treturn v.(int) + w.(int)\n}\n", ""},
		{"ranged", "package ranged\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tn := 0\n\tm.Range(func(k, v any) bool {\n\t\tn++\n\t\treturn true\n\t})\n\treturn n\n}\n", "reaches unaudited standard operation sync.Range"},
		// A function-local map: the fold records no effect for the
		// declaration (the type name is the memo set's), and the walk
		// then refuses the subject's own reach — a sync.Map value holds
		// unsafe pointers — whatever operation follows. The type-name
		// admission opens nothing: the walk stands behind it.
		{"local", "package local\n\nimport \"sync\"\n\nfunc Subject() int {\n\tvar m sync.Map\n\tm.Store(\"k\", 1)\n\tv, _ := m.Load(\"k\")\n\treturn v.(int)\n}\n", "unsafe pointer reachable"},
		{"localranged", "package localranged\n\nimport \"sync\"\n\nfunc Subject() int {\n\tvar m sync.Map\n\tn := 0\n\tm.Range(func(k, v any) bool { return true })\n\treturn n\n}\n", "unsafe pointer reachable"},
		{"deleted", "package deleted\n\nimport \"sync\"\n\nvar m sync.Map\n\nfunc Subject() int {\n\tm.Store(\"k\", 1)\n\tm.Delete(\"k\")\n\treturn 1\n}\n", "reaches unaudited standard operation sync.Delete"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/syncmemo/" + tc.pkg, Symbol: "Subject"})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/syncmemo/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.Contains(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
	}
}
