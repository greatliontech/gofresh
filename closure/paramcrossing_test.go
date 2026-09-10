package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A callee's function-typed parameter closes through the subject's
// attributed call sites for every closed-world subject — the iterator's
// yield bound by a range statement, by a direct call, by an iterator
// literal; an initializer's own call to the callee is startup flow
// outside the subject's frames, judged by the startup walk — while the
// crossing refuses where provenance is absent: a variadic callee (its
// non-variadic twin closes), a capturing callee, a callee that is also
// a dynamic target anywhere in the mask, a subject-frame site passing a
// value the walk cannot close
// (REQ-closure-observability-analysis's subject-determined operand).
func TestCalleeParameterClosesThroughAttributedSites(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	const seq = "func seq(yield func(int) bool) {\n\tfor i := 0; i < 3; i++ {\n\t\tif !yield(i) {\n\t\t\treturn\n\t\t}\n\t}\n}\n"
	const closure = "func(v int) bool { total += v; return true }"
	// One table: every fixture is judged, every judgment has a fixture.
	cases := []struct{ pkg, source, refusal string }{
		{"ranged", "package ranged\n\n" + seq + "\nfunc Subject() int {\n\ttotal := 0\n\tfor v := range seq {\n\t\ttotal += v\n\t}\n\treturn total\n}\n", ""},
		{"called", "package called\n\n" + seq + "\nfunc Subject() int {\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", ""},
		{"literal", "package literal\n\nfunc Subject() int {\n\ttotal := 0\n\tfor v := range func(yield func(int) bool) {\n\t\tfor i := 0; i < 3; i++ {\n\t\t\tif !yield(i) {\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t} {\n\t\ttotal += v\n\t}\n\treturn total\n}\n", ""},
		// An initializer's own call is startup flow outside the subject's frames.
		{"initbound", "package initbound\n\n" + seq + "\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc init() {\n\tseq(hooks[\"a\"])\n}\n\nfunc Subject() int {\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", ""},
		// A variadic callee refuses at its parameter; its non-variadic twin closes.
		{"variadicparam", "package variadicparam\n\nfunc each(y func(int) bool, rest ...int) { y(1) }\n\nfunc Subject() int {\n\ttotal := 0\n\teach(" + closure + ", 1, 2)\n\treturn total\n}\n", "computed function call in example.com/cross/variadicparam.each calling parameter y"},
		{"fixedparam", "package fixedparam\n\nfunc each(y func(int) bool, rest int) { y(rest) }\n\nfunc Subject() int {\n\ttotal := 0\n\teach(" + closure + ", 1)\n\treturn total\n}\n", ""},
		// A capturing callee refuses: its closure over captured state would run unjudged.
		{"capturing", "package capturing\n\nfunc Subject() int {\n\tlimit := 3\n\tseq := func(yield func(int) bool) {\n\t\tfor i := 0; i < limit; i++ {\n\t\t\tif !yield(i) {\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t}\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", "computed function call in example.com/cross/capturing.Subject$1 calling parameter yield"},
		// A callee also reached as a dynamic target refuses at its parameter: its provenance is not its static sites alone — the clause's discipline, pinned here by a verdict flip (the dynamic dispatch passes a map-loaded callback the static site never shows; the whole-mask target drag still scans that callback's body, so the flip is provenance, not a missed effect). The subject's bool parameter carries no dynamic reach, so the subject stays closed-world and the refusal is the callee's.
		{"dyntargeted", "package dyntargeted\n\n" + seq + "\nfunc other(yield func(int) bool) { yield(7) }\n\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc Subject(pick bool) int {\n\ttotal := 0\n\tseq(" + closure + ")\n\tother(" + closure + ")\n\trun := seq\n\tif pick {\n\t\trun = other\n\t}\n\trun(hooks[\"a\"])\n\treturn total\n}\n", "computed function call in example.com/cross/dyntargeted.other calling parameter yield"},
		// A subject-frame site passing a value the walk cannot close refuses.
		{"unclosedarg", "package unclosedarg\n\n" + seq + "\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc Subject() int {\n\tseq(hooks[\"a\"])\n\treturn 1\n}\n", "computed function call in example.com/cross/unclosedarg.seq calling parameter yield"},
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/cross\n\ngo 1.26\n")
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		subjects = append(subjects, Subject{Package: "example.com/cross/" + tc.pkg, Symbol: "Subject"})
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/cross/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" && (!proof.Observable || proof.Reason != "") {
			t.Errorf("%s = %+v, want observable", tc.pkg, proof)
		}
		if tc.refusal != "" && (proof.Observable || !strings.Contains(proof.Reason, tc.refusal)) {
			t.Errorf("%s = %+v, want refused naming %q", tc.pkg, proof, tc.refusal)
		}
	}
}
