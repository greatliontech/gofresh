package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBoundedFixture is a module with one constraint-bounded generic
// subject: Sum's Number constraint (~int | ~float64) is methodless and
// every term excludes dynamic carriers, helper is reached only through
// Sum's body, and UseSum materializes the int instantiation.
func writeBoundedFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/bounded\n\ngo 1.26\n",
		"lib.go": body,
		"lib_test.go": `package bounded

import "testing"

func TestUse(t *testing.T) {
	if UseSum() != 3 {
		t.Fatal("broken")
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

const boundedBody = `package bounded

type Number interface{ ~int | ~float64 }

const fixtureConstant = 1

func helper(x int) int { return x + fixtureConstant }

func Sum[T Number](a, b T) T {
	_ = helper(1)
	return a + b
}

func UseSum() int { return Sum(1, 2) }

func Unrelated() string { return "quiet" }
`

// A constraint-bounded generic subject analyzes closed: observability
// answers instead of refusing on the open subject world, refinement does
// not widen, an edit to a helper reached only through the instantiation
// moves the refined hash (the purity-override audit: instantiation-
// reachable content is in the hash), a generic-body edit moves it (the
// origin fold), and an unrelated edit leaves it alone — the serving
// precision the open-world wall cost (REQ-closure-analysis's
// parameterized-subject arm).
func TestConstraintBoundedGenericSubjectAnalyzesClosed(t *testing.T) {
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) (Closure, Observability) {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		refined, err := h.ComputeBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return refined[subject], proofs[subject]
	}

	base, proof := compute(boundedBody)
	if base.Widened || base.Unverifiable {
		t.Fatalf("bounded generic widened: %+v", base)
	}
	if strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("bounded generic refused as open world: %+v", proof)
	}

	helperEdit, _ := compute(strings.Replace(boundedBody, "x + fixtureConstant", "x + fixtureConstant + 1", 1))
	if helperEdit.Hash == base.Hash {
		t.Fatal("helper edit reached only through the instantiation did not move the refined hash")
	}

	bodyEdit, _ := compute(strings.Replace(boundedBody, "return a + b", "return b + a", 1))
	if bodyEdit.Hash == base.Hash {
		t.Fatal("generic-body edit did not move the refined hash")
	}

	unrelatedEdit, _ := compute(strings.Replace(boundedBody, `return "quiet"`, `return "quieter"`, 1))
	if unrelatedEdit.Hash != base.Hash {
		t.Fatal("unrelated edit moved the bounded generic's refined hash: the precision the narrowing exists for is absent")
	}
}

// Unbounded or method-bearing constraints keep the open world: any and
// comparable bound nothing, a constraint method is a dispatch surface
// the narrowing does not cover, and a specific interface term makes the
// parameter itself a dynamic carrier (REQ-closure-analysis).
func TestUnboundedConstraintsStayOpenWorld(t *testing.T) {
	for name, decl := range map[string]string{
		"comparable":     "func Sum[T comparable](a, b T) T {\n\t_ = helper(1)\n\treturn a\n}\n\nfunc UseSum() int { return Sum(1, 2) + 2 }",
		"method-bearing": "type Stringy interface {\n\t~int\n\tString() string\n}\n\ntype myInt int\n\nfunc (m myInt) String() string { return \"m\" }\n\nfunc Sum[T Stringy](a, b T) int {\n\t_ = helper(1)\n\t_ = a.String()\n\treturn 3\n}\n\nfunc UseSum() int { return Sum(myInt(1), myInt(2)) }",
		"dirty-union":    "type IntOrFunc interface{ ~int | ~func() }\n\nfunc Sum[T IntOrFunc](a, b T) int {\n\t_ = helper(1)\n\treturn 3\n}\n\nfunc UseSum() int { return Sum(1, 2) + 0 }",
		"interface-term": "type Readerish interface{ interface{ Read([]byte) (int, error) } }\n\nfunc Sum[T Readerish](a, b T) int {\n\t_ = helper(1)\n\treturn 3\n}\n\nfunc UseSum() int { return 3 }",
	} {
		body := "package bounded\n\nconst fixtureConstant = 1\n\nfunc helper(x int) int { return x + fixtureConstant }\n\n" + decl + "\n\nfunc Unrelated() string { return \"quiet\" }\n"
		dir := writeBoundedFixture(t, body)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The refusal reason carries the widen cause when the open
		// origin's own body also widens (a method-bearing constraint's
		// dispatch site); either text is the open-world wall standing.
		if p := proofs[subject]; p.Observable || !(strings.Contains(p.Reason, "open subject world") || strings.Contains(p.Reason, "reachability is not closed")) {
			t.Fatalf("%s: constraint read bounded, want the open-world refusal: %+v", name, p)
		}
	}
}

// A bounded generic with no in-binary instantiation keeps the origin
// fold's own closure: its declaration and static callees still move the
// hash (the fold's pre-existing load), it does not widen, and — pinned
// by TestBoundedGenericRootsInstantiationFlow's negative arm —
// instantiation-only content stays out (REQ-closure-analysis).
func TestBoundedGenericWithoutInstantiationKeepsOriginFold(t *testing.T) {
	orphan := strings.Replace(boundedBody, "func UseSum() int { return Sum(1, 2) }", "func UseSum() int { return 3 }", 1)
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) Closure {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		refined, err := h.ComputeBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return refined[subject]
	}
	base := compute(orphan)
	if base.Widened || base.Unverifiable {
		t.Fatalf("uninstantiated bounded generic widened: %+v", base)
	}
	bodyEdit := compute(strings.Replace(orphan, "return a + b", "return b + a", 1))
	if bodyEdit.Hash == base.Hash {
		t.Fatal("generic-body edit did not move the origin fold")
	}
}

// Batching a bounded generic beside an ordinary subject yields exactly
// the solo analysis: instantiation roots attribute under the subject's
// own mask, never a sibling's (REQ-closure-batch-equivalence).
func TestBoundedGenericBatchEquivalence(t *testing.T) {
	dir := writeBoundedFixture(t, boundedBody)
	sum := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	unrelated := Subject{Package: "example.com/bounded", Symbol: "Unrelated"}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := h.ComputeBatch([]Subject{sum, unrelated})
	if err != nil {
		t.Fatal(err)
	}
	solo, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	soloSum, err := solo.ComputeBatch([]Subject{sum})
	if err != nil {
		t.Fatal(err)
	}
	if batch[sum].Hash != soloSum[sum].Hash {
		t.Fatalf("batch %q != solo %q for the bounded generic", batch[sum].Hash, soloSum[sum].Hash)
	}
	if batch[unrelated].Unverifiable || strings.Contains(batch[unrelated].Reason, "open") {
		t.Fatalf("sibling polluted by the generic's instantiation roots: %+v", batch[unrelated])
	}
}

// flowBody dispatches through a boxed T inside the generic body: the
// origin's site is open over T (unresolvable, a widen), while the
// Tagged instantiation's site resolves concretely to TagUniq. The
// unwidened base therefore pins BOTH halves of the mechanism - the
// instantiation rooting that resolves the site and the origin scan
// yielding to it - and the TagUniq edit-move pins that the resolved
// content is in the hash (the purity-override audit). TagUniq's body
// sits BELOW every other declaration so a position shift cannot fake
// the edit-move signal.
const flowBody = `package bounded

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T {
	if s, ok := any(a).(interface{ TagUniq() string }); ok {
		_ = s.TagUniq()
	}
	return a + b
}

func UseSum() int {
	_ = Sum(Tagged(1), Tagged(2))
	return 3
}

func Unrelated() string { return "quiet" }

type Tagged int

func (t Tagged) TagUniq() string { return "tag" }
`

func TestBoundedGenericRootsInstantiationFlow(t *testing.T) {
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) Closure {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		refined, err := h.ComputeBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return refined[subject]
	}
	base := compute(flowBody)
	if base.Widened || base.Unverifiable {
		t.Fatalf("instantiation-rooted dispatch did not resolve: %+v", base)
	}
	tagEdit := compute(strings.Replace(flowBody, `return "tag"`, `return "gat"`, 1))
	if tagEdit.Hash == base.Hash {
		t.Fatal("instantiation-reached method body is missing from the refined hash: a purity-asserted serve would go stale-valid")
	}
}

// The observability effect walk sees instantiation-reached sites: a
// dispatch target reached only through a boxed T carrying a
// subject-tier-only refusal (a computed function call — invisible to the
// maximal AST backstop) must refuse the proof; granting from the origin
// alone would answer without ever seeing the site
// (REQ-closure-analysis's parameterized-subject arm,
// REQ-closure-observability-analysis).
func TestBoundedGenericObservabilitySeesInstantiationEffects(t *testing.T) {
	const effectBody = `package bounded

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T {
	if s, ok := any(a).(interface{ TagUniq() string }); ok {
		_ = s.TagUniq()
	}
	return a + b
}

func UseSum() int {
	_ = Sum(Tagged(1), Tagged(2))
	return 3
}

var fns = map[string]func() string{"a": func() string { return "a" }}

type Tagged int

func (t Tagged) TagUniq() string { return fns["a"]() }
`
	dir := writeBoundedFixture(t, effectBody)
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofs[subject]; p.Observable || !strings.Contains(p.Reason, "computed function call") {
		t.Fatalf("instantiation-reached computed call invisible to the proof: %+v", p)
	}
}

// Self- and mutually-referential constraints are legal Go; the bounding
// walk must terminate on them (the cycle guard), answering conservatively
// open - a recursive type set is never proven bounded
// (REQ-closure-analysis's parameterized-subject arm).
func TestRecursiveConstraintsTerminateOpen(t *testing.T) {
	for name, decl := range map[string]string{
		"self":   "func Sum[A interface{ ~[]A }](a A) int {\n\t_ = helper(1)\n\treturn 1\n}\n\nfunc UseSum() int { return 1 + fixtureConstant - fixtureConstant }",
		"mutual": "func Sum[A interface{ ~[]B }, B interface{ ~[]A }](a A, b B) int {\n\t_ = helper(1)\n\treturn 1\n}\n\nfunc UseSum() int { return 1 + fixtureConstant - fixtureConstant }",
	} {
		body := "package bounded\n\nconst fixtureConstant = 1\n\nfunc helper(x int) int { return x + fixtureConstant }\n\n" + decl + "\n\nfunc Unrelated() string { return \"quiet\" }\n"
		dir := writeBoundedFixture(t, body)
		h, err := NewAt(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p := proofs[subject]; p.Observable || !(strings.Contains(p.Reason, "open subject world") || strings.Contains(p.Reason, "reachability is not closed")) {
			t.Fatalf("%s: recursive constraint did not answer conservatively open: %+v", name, p)
		}
	}
}
