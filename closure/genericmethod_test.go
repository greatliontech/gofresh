package closure

import (
	"os"
	"path/filepath"
	"testing"
)

// go1.27 generic METHODS (math/rand/v2's Rand.N is the stdlib shape)
// must analyze like any parameterized subject — the field failure was
// "unsupported analysis shape: Int" wherever a closure reached one.
func TestAttributedAnalysisCoversGenericMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/gm\n\ngo 1.27\n",
		"lib.go": `package gm

type Ring struct{ n uint64 }

func (r *Ring) next() uint64 { r.n++; return r.n }

// N mirrors math/rand/v2's go1.27 generic-method shape.
func (r *Ring) N[Int ~int | ~int64](n Int) Int {
	return Int(r.next() % uint64(n))
}

func Use() int { r := &Ring{}; return int(r.N(7)) }
`,
		"lib_test.go": `package gm

import "testing"

func TestUse(t *testing.T) {
	if Use() != 1 {
		t.Fatal(Use())
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/gm"
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := computeTier2Result(h, pkg, "Use"); err != nil {
		t.Fatalf("precise analysis over a generic-method closure: %v", err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "Use"}})
	if err != nil {
		t.Fatalf("observability over a generic-method closure: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("dispositions = %+v, want one", proofs)
	}
}

// The stdlib field shape: a closure reaching math/rand/v2 (whose
// Rand.N is a generic method on go1.27) must not lose its whole
// target to one edge.
func TestAttributedAnalysisSurvivesStdlibGenericMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/gms\n\ngo 1.27\n",
		"lib.go": `package gms

import "math/rand/v2"

func Draw() int {
	r := rand.New(rand.NewPCG(1, 2))
	return int(r.N(7))
}
`,
		"lib_test.go": `package gms

import "testing"

func TestDraw(t *testing.T) {
	if Draw() < 0 || Draw() >= 7 {
		t.Fatal("out of range")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/gms"
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := computeTier2Result(h, pkg, "Draw"); err != nil {
		t.Fatalf("precise analysis reaching stdlib generic methods: %v", err)
	}
	if _, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "Draw"}}); err != nil {
		t.Fatalf("observability reaching stdlib generic methods: %v", err)
	}
}
