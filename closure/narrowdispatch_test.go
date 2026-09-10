package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A computed call through a closed cell — the recursive local closure's
// idiom — takes the cell's stored closures as its targets, at startup
// and in subject flow alike, so a standard closure of the same
// signature in the mask never classifies. A cell any other use opens —
// a store of an unclosed value, its address passed, a store through a
// capturing closure of an unclosed value — keeps the enumeration's
// targets and the computed-call refusal
// (REQ-closure-observability-analysis's narrowed dispatch).
func TestClosedCellNarrowsComputedCallTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/narrow\n\ngo 1.26\n")
	const recursive = "\tvar visit func(string) bool\n\tvisit = func(s string) bool {\n\t\tif s == \"\" {\n\t\t\treturn true\n\t\t}\n\t\treturn visit(s[1:])\n\t}\n"
	cases := []struct{ pkg, source, refusal string }{
		// The idiom in an initializer, its result read by the subject.
		// The blank import of an audited-pure package links the standard
		// library's own closures of the signature into the mask (the
		// FIPS module reaches internal/godebugs) — the class the
		// whole-mask projection dragged in.
		{"startup", "package startup\n\nimport _ \"crypto/sha256\"\n\nfunc walk(s string) bool {\n" + recursive + "\treturn visit(s)\n}\n\nvar ok = walk(\"abc\")\n\nfunc Subject() bool { return ok }\n", ""},
		// The idiom in the subject's own flow.
		{"subject", "package subject\n\nimport _ \"crypto/sha256\"\n\nfunc Subject() bool {\n" + recursive + "\treturn visit(\"abc\")\n}\n", ""},
		// A second store of an unclosed value — a package-level function
		// variable's load — opens the cell.
		{"openstore", "package openstore\n\nvar hook func(string) bool\n\nfunc Subject() bool {\n" + recursive + "\tvisit = hook\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// The cell's address passed opens it.
		{"openaddr", "package openaddr\n\nfunc set(p *func(string) bool) {}\n\nfunc Subject() bool {\n" + recursive + "\tset(&visit)\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// A captured cell holding a standard function value names a
		// body no walk scans: the held set resolves nothing at the
		// subject tier's scan of the drained frame, and the computed
		// call keeps its refusal (an uncaptured local is no cell — SSA
		// lifts it and the call is static).
		{"stdheld", "package stdheld\n\nimport \"strings\"\n\nfunc walk(s string) bool {\n\tvar pick func(string, string) bool\n\tpick = strings.HasPrefix\n\tvia := func() bool { return pick(s, \"a\") }\n\treturn via()\n}\n\nvar ok = walk(\"abc\")\n\nfunc Subject() bool { return ok }\n", "computed function call"},
		// A drained frame's held closure is scanned by the route that
		// resolves through it: its effect classifies (a path mutation —
		// an effect no tier admits, where an environment read would be
		// a priced observable input at the subject tier).
		{"drained", "package drained\n\nimport \"os\"\n\nfunc helper(n int) bool {\n\tvar visit func(int) bool\n\tvisit = func(n int) bool {\n\t\tif n == 0 {\n\t\t\treturn os.Remove(\"x\") == nil\n\t\t}\n\t\treturn visit(n - 1)\n\t}\n\treturn visit(n)\n}\n\nvar handler = helper\n\nfunc Subject() bool { return handler != nil }\n", "os.Remove"},
		// A drained frame's nested closure called statically is scanned
		// as the frame's own content.
		{"drainedstatic", "package drainedstatic\n\nimport \"os\"\n\nfunc helper() bool {\n\tf := func() bool { return os.Remove(\"x\") == nil }\n\treturn f()\n}\n\nvar handler = helper\n\nfunc Subject() bool { return handler != nil }\n", "os.Remove"},
		// A store of the cell's own load is the walk's one cycle: refused.
		{"selfstore", "package selfstore\n\nfunc Subject() bool {\n" + recursive + "\tvisit = visit\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// A capturing closure storing an unclosed value opens it.
		{"opencapture", "package opencapture\n\nvar hook func(string) bool\n\nfunc Subject() bool {\n" + recursive + "\tswap := func() { visit = hook }\n\tswap()\n\treturn visit(\"abc\")\n}\n", "computed function call"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/narrow/" + tc.pkg, Symbol: "Subject"})
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
		proof := proofs[Subject{Package: "example.com/narrow/" + tc.pkg, Symbol: "Subject"}]
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
