package closure

import (
	"strings"
	"testing"
)

// Init functions root positionally - init#<file>#<ordinal>, the
// declaration ledger's identity: 0-based within the declaring file in
// declaration order, file-scoped so inits elsewhere in the package
// never shift a key. The precise per-subject analysis (tier 2 and the
// observability proof) resolves those roots exactly like named
// functions; an ordinal naming no declaration errors with the subject
// named.
func TestInitSubjectRootsResolvePositionally(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/initroot\n\ngo 1.26\n")
	writeFile(t, dir, "a.go", `package initroot

var registry []string

func wireA() { registry = append(registry, "a") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`)
	writeFile(t, dir, "aa.go", "package initroot\n\nfunc init() { registry = append(registry, \"aa\") }\n")
	writeFile(t, dir, "a_test.go", `package initroot

import "testing"

func TestRegistry(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry empty")
	}
}
`)
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/initroot"
	for _, symbol := range []string{"init#a.go#0", "init#a.go#1", "init#aa.go#0"} {
		if _, err := computeTier2Result(h, pkg, symbol); err != nil {
			t.Fatalf("tier-2 analysis for %s: %v", symbol, err)
		}
	}
	// Reach is not asserted per init: package initialization is in every
	// subject's reachable set by design (the blanket init rooting), so
	// init subjects share reach - the root's load-bearing role is
	// resolution, and the wiring content rides every subject's closure.
	if _, err := computeTier2Result(h, pkg, "init#a.go#2"); err == nil || !strings.Contains(err.Error(), "init#a.go#2 not found in "+pkg) {
		t.Fatalf("past-the-end ordinal = %v, want a not-found error naming the subject", err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: pkg, Symbol: "init#a.go#0"},
		{Package: pkg, Symbol: "init#aa.go#0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for subject, proof := range proofs {
		if strings.Contains(proof.Reason, "not found") {
			t.Fatalf("observability proof for %s degraded to not-found: %+v", subject.Symbol, proof)
		}
	}
}
