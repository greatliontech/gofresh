package closure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
)

func writeGenericFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/generic\n\ngo 1.26\n",
		"lib.go": body,
		"lib_test.go": `package generic

import "testing"

func TestKey(t *testing.T) {
	if UseInt() == "" {
		t.Fatal("empty key")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const genericFixtureBody = `package generic

import "fmt"

// Key boxes its type parameter into an interface - the exact shape whose
// runtime-type walk must handle a parameterized subject.
func Key[K comparable](k K) string {
	var boxed any = k
	return fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }
`

// A parameterized subject analyzes through its materialized instantiations:
// no panic, a real observability disposition, and a refined closure that
// moves when the generic body moves (REQ-closure-analysis: instantiations
// dispatch concretely; a parameterized body is not a runtime dispatch
// surface, but its source is still the subject's content).
func TestAttributedAnalysisCoversGenericSubjects(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Key"}

	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	refined, err := h.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatalf("refinement over a generic subject: %v", err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatalf("observability over a generic subject: %v", err)
	}
	proof, ok := proofs[subject]
	if !ok {
		t.Fatalf("no observability disposition for the generic subject: %+v", proofs)
	}
	// A parameterized subject is open to caller-chosen instantiations, so
	// its observability refuses on the open subject world - the same
	// verdict signature-level dynamism gets everywhere.
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("generic subject disposition = %+v, want the open-world refusal", proof)
	}

	edited := writeGenericFixture(t, `package generic

import "fmt"

func Key[K comparable](k K) string {
	var boxed any = k
	return "edited: " + fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }
`)
	h2, err := NewAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	refinedEdited, err := h2.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if refined[subject].Hash == refinedEdited[subject].Hash {
		t.Fatal("editing the generic body did not move the refined closure - the origin's content left the subject")
	}
}

// A parameterized subject's instantiation-reachable effects stay visible:
// dropping the instantiations from traversal would let an effectful generic
// read as observable - the flattering direction.
func TestAttributedAnalysisSeesEffectsThroughInstantiations(t *testing.T) {
	dir := writeGenericFixture(t, `package generic

import (
	"fmt"
	"os"
)

func Key[K comparable](k K) string {
	var boxed any = k
	return fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }

// Effectful reaches ambient state through its instantiated body.
func Effectful[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return os.Getenv("GENERIC_EFFECT")
}

func UseEffect() string { return Effectful[int](1) }
`)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Effectful"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := proofs[subject]
	if !ok {
		t.Fatalf("no disposition: %+v", proofs)
	}
	if proof.Observable {
		t.Fatal("an effectful generic subject read as observable - instantiation traversal lost its effects")
	}
}

// A parameterized subject nothing instantiates still analyzes: its own
// source remains its content, and the analysis neither panics nor errors.
func TestAttributedAnalysisCoversUninstantiatedGenericSubjects(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody+`
// Orphan has no instantiation anywhere in the binary.
func Orphan[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return "orphan"
}
`)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Orphan"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	refined, err := h.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatalf("refinement over an uninstantiated generic subject: %v", err)
	}
	if refined[subject].Hash == "" {
		t.Fatal("uninstantiated generic subject lost its closure")
	}
	if _, err := h.ComputeObservabilityBatch([]Subject{subject}); err != nil {
		t.Fatalf("observability over an uninstantiated generic subject: %v", err)
	}
	// The origin declaration is the subject's own content even with no
	// instantiation to traverse: a body edit moves the refined closure.
	edited := writeGenericFixture(t, genericFixtureBody+`
// Orphan has no instantiation anywhere in the binary.
func Orphan[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return "orphan edited"
}
`)
	h2, err := NewAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	refinedEdited, err := h2.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if refined[subject].Hash == refinedEdited[subject].Hash {
		t.Fatal("editing the uninstantiated generic body did not move its refined closure - the origin fold lost the subject's own content")
	}
}

// The attributed analysis converts an unsupported shape into an error
// instead of panicking the embedding process: a parameterized body handed
// directly to the analyzer - the shape the instantiation-rooting fix keeps
// out of production paths - degrades to per-subject unavailability upstream,
// never a crash.
func TestAttributedAnalysisConvertsUnsupportedShapesToErrors(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody)
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached("example.com/generic")
	if err != nil {
		t.Fatal(err)
	}
	origin := prog.roots["Key"]
	if origin == nil {
		t.Fatal("generic origin not rooted")
	}
	if _, err := analyzeAttributed(context.Background(), map[*ssa.Function]uint64{origin: 1}); err == nil {
		t.Fatal("a parameterized body walked without error")
	}
}

// A zero-parameter generic subject is forced open-world: a signature walk
// alone reads it closed, which would grant observability while its
// instantiations run arbitrary caller-chosen shapes, and would serve a
// refined hash missing every callee (REQ-closure-analysis's
// parameterized-subject arm; the reviewer-demonstrated gap).
func TestZeroParameterGenericSubjectIsForcedOpenWorld(t *testing.T) {
	const body = `package generic

import "os"

func helper() {
	_ = os.WriteFile("/tmp/generic-fixture-x", []byte("x"), 0o644)
}

// Value takes no parameters at all: only TypeParams carry its genericity.
func Value[T any]() int {
	helper()
	return 1
}

func UseInt() string {
	Value[int]()
	return "v"
}
`
	dir := writeGenericFixture(t, body)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Value"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof := proofs[subject]
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("zero-parameter generic disposition = %+v, want the forced open-world refusal", proof)
	}
	before, err := h.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	edited := writeGenericFixture(t, strings.Replace(body, `[]byte("x")`, `[]byte("edited")`, 1))
	h2, err := NewAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	after, err := h2.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("a callee edit did not move the zero-parameter generic's refined closure - closed-world reading served a stale hash")
	}
}

// A generic METHOD subject is forced open-world through the receiver's type
// parameters - the RecvTypeParams arm of parameterizedBody - and its
// callee edits move the refined closure exactly as for generic functions.
func TestGenericMethodSubjectIsForcedOpenWorld(t *testing.T) {
	const body = `package generic

import "os"

func helper() {
	_ = os.WriteFile("/tmp/generic-fixture-m", []byte("m"), 0o644)
}

type Counter[T any] struct{ n int }

func (c Counter[T]) N() int {
	helper()
	return c.n
}

func UseInt() string {
	var c Counter[int]
	c.N()
	return "c"
}
`
	dir := writeGenericFixture(t, body)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Counter.N"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof := proofs[subject]
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("generic method disposition = %+v, want the forced open-world refusal", proof)
	}
	before, err := h.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	edited := writeGenericFixture(t, strings.Replace(body, `[]byte("m")`, `[]byte("edited")`, 1))
	h2, err := NewAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	after, err := h2.ComputeBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("a callee edit did not move the generic method's refined closure")
	}
}
