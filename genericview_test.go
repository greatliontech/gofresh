package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBoundedViewFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/boundedview\n\ngo 1.26\n",
		"lib.go": `package boundedview

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T { return a + b }

func Value[T any]() int { return 1 }

func UseBoth() int {
	Value[int]()
	return int(Sum(1, 2))
}
`,
		"lib_test.go": "package boundedview\n\nimport \"testing\"\n\nfunc TestUse(t *testing.T) {\n\tif UseBoth() != 3 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The view tier gives the same openness answer as the closure tier
// (REQ-closure-analysis's parameterized-subject arm): a constraint-
// bounded generic analyzes closed — it produces a usable observed
// disposition — while an unbounded zero-parameter generic reads open on
// the type-parameter list itself, which a params-only walk misses, and
// refuses open-world.
func TestViewTierGenericOpennessMatchesConstraints(t *testing.T) {
	dir := writeBoundedViewFixture(t)
	const pkg = "example.com/boundedview"
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	bounded := Subject{Package: pkg, Symbol: "Sum"}
	unbounded := Subject{Package: pkg, Symbol: "Value"}
	view, err := engine.NewView(context.Background(), []Subject{bounded, unbounded}, dir)
	if err != nil {
		t.Fatal(err)
	}
	boundedPrint, err := view.CaptureObserved(context.Background(), bounded)
	if err != nil {
		t.Fatal(err)
	}
	if !boundedPrint.ObservationProof.Observable || strings.Contains(boundedPrint.ObservationProof.Reason, "caller-supplied dynamic") {
		t.Fatalf("bounded generic read open at the view tier: %+v", boundedPrint.ObservationProof)
	}
	verdict, err := view.CheckObserved(context.Background(), boundedPrint, bounded)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("bounded generic verdict = %+v, want valid", verdict)
	}
	unboundedPrint, err := view.CaptureObserved(context.Background(), unbounded)
	if err != nil {
		t.Fatal(err)
	}
	unboundedVerdict, err := view.CheckObserved(context.Background(), unboundedPrint, unbounded)
	if err != nil {
		t.Fatal(err)
	}
	if unboundedVerdict.Status != Unverifiable {
		t.Fatalf("zero-parameter any-generic verdict = %+v, want unverifiable (open on the type-parameter list)", unboundedVerdict)
	}
}
