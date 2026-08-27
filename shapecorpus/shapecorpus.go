// Package shapecorpus is the fleet's shared language-shape canary
// corpus: the shapes every tool's frontend must parse and judge, in
// one exported home so the four consumers' canaries cannot drift
// (a per-repo copy went asymmetric within one chunk). Each tool
// wraps the corpus with its own harness — analysis, candidate
// generation, symbol resolution, measurement capture — and runs it
// under the CI matrix's next-rc leg, so a new Go release's shape
// breakage fails as a named canary instead of a field session.
// Additions ride the language: a new release's parse-sensitive
// construct joins here once, and every tool's canary carries it.
//
// Content drift between consumers is unrepresentable; version lag is
// not — a consumer pinned to an older gofresh release runs an older
// corpus until its next bump, and a new entry protects no tool until
// every consumer has bumped past it.
package shapecorpus

// Entry is one language shape: a self-contained package source with
// a plain Subject() function (every harness's default anchor), the
// shape-carrying symbol for harnesses that must touch the shape
// itself (resolution, hashing), and the benchmark spelling for
// measurement harnesses.
type Entry struct {
	// Name labels the shape; harnesses use it as the subtest name.
	Name string
	// Source is the package body, package name "shape".
	Source string
	// ShapeSymbol names the declaration carrying the shape, in the
	// pkg-relative "Name" or "Recv.Name" spelling; harnesses that
	// hash or resolve declarations use it so the shape reaches their
	// own walk, not only the loader's.
	ShapeSymbol string
	// SubjectObservable is the gofresh observability disposition the
	// corpus pins for Subject(): a flip in EITHER direction on a
	// release is a red canary, where an any-disposition tolerance was
	// probe-confirmed blind. Updating a pin is a deliberate act:
	// diagnose the flip first, and land the new pin in the change set
	// that changes the disposition — never as a canary-suite fix.
	SubjectObservable bool
	// SubjectReason, when the subject refuses, is a substring its
	// refusal reason must carry — the pinned cause, so a new failure
	// class cannot hide behind an expected refusal.
	SubjectReason string
}

// Entries returns the corpus in a stable order.
func Entries() []Entry {
	return []Entry{
		{
			Name: "generic method with pointer receiver",
			Source: `package shape

type Box[T any] struct{ v T }

func (b *Box[T]) Get() T { return b.v }

func Subject() int { b := &Box[int]{v: 1}; return b.Get() }
`,
			ShapeSymbol:       "Box.Get",
			SubjectObservable: true,
		},
		{
			Name: "method value on instantiated generic",
			Source: `package shape

type Box[T any] struct{ v T }

func (b *Box[T]) Get() T { return b.v }

func Subject() int {
	b := &Box[int]{v: 1}
	f := b.Get
	return f()
}
`,
			ShapeSymbol:       "Box.Get",
			SubjectObservable: true,
		},
		{
			Name: "nested generic with local type",
			Source: `package shape

type Iface interface{ M() }

type impl struct{}

func (impl) M() {}

func Inner[U any](v U) any { var a any = v; return a }

func Outer[T any](t T, i Iface) any {
	type local struct {
		Iface
		x T
	}
	return Inner(local{i, t})
}

func Subject() bool { return Outer[int](1, impl{}) != nil }
`,
			ShapeSymbol:       "Outer",
			SubjectObservable: true,
		},
		{
			Name: "elided address-of in pointer-element literal",
			Source: `package shape

type holder struct{ rows []int }

func take(ps []*holder) int { return len(ps) }

func Subject() int { rows := []int{1}; return take([]*holder{{rows: rows}}) }
`,
			ShapeSymbol:       "take",
			SubjectObservable: true,
		},
		{
			Name: "generic type alias",
			Source: `package shape

type Vec[T any] = []T

func Sum(v Vec[int]) int { return len(v) }

func Subject() int { var v Vec[int] = []int{1}; return Sum(v) }
`,
			ShapeSymbol:       "Sum",
			SubjectObservable: true,
		},
		{
			Name: "constrained parameterized alias",
			Source: `package shape

type Set[T comparable] = map[T]struct{}

func Has(s Set[int], k int) bool { _, ok := s[k]; return ok }

func Subject() bool { return Has(Set[int]{1: {}}, 1) }
`,
			ShapeSymbol:       "Has",
			SubjectObservable: true,
		},
		{
			Name: "union constraint",
			Source: `package shape

type Numeric interface{ ~int | ~int64 }

func Double[T Numeric](v T) T { return v + v }

func Subject() int { return Double(2) }
`,
			ShapeSymbol:       "Double",
			SubjectObservable: true,
		},
		{
			Name: "range over function iterator",
			Source: `package shape

func seq(yield func(int) bool) {
	for i := 0; i < 3; i++ {
		if !yield(i) {
			return
		}
	}
}

func Subject() int {
	total := 0
	for v := range seq {
		total += v
	}
	return total
}
`,
			ShapeSymbol: "seq",
			// The subject reads open-world today: ranging a function
			// treats yield as a computed call on a parameter, which
			// the enumeration cannot close. The pin keeps the
			// DISPOSITION honest — a release flipping it in either
			// direction is a red canary.
			SubjectObservable: false,
			SubjectReason:     "not closed",
		},
		{
			Name: "range over integer",
			Source: `package shape

func Subject() int {
	total := 0
	for i := range 10 {
		total += i
	}
	return total
}
`,
			ShapeSymbol:       "Subject",
			SubjectObservable: true,
		},
		{
			Name: "inline interface in signature",
			Source: `package shape

func take(v interface{ Err() string }) string { return v.Err() }

type e struct{}

func (e) Err() string { return "x" }

func Subject() string { return take(e{}) }
`,
			ShapeSymbol:       "take",
			SubjectObservable: true,
		},
		{
			Name: "min max clear builtins",
			Source: `package shape

func Subject() int {
	m := map[int]int{1: 1}
	clear(m)
	return min(1, max(2, 3)) + len(m)
}
`,
			ShapeSymbol:       "Subject",
			SubjectObservable: true,
		},
		{
			Name: "instantiated function value",
			Source: `package shape

func id[T any](v T) T { return v }

func Subject() int { f := id[int]; return f(1) }
`,
			ShapeSymbol:       "id",
			SubjectObservable: true,
		},
	}
}

// corpusModFile is the fixture module file, shared by both layouts so
// the language version cannot drift between them; it tracks the
// current release, so canaries judge the shapes under the toolchain
// the fleet ships on.
const corpusModFile = "module example.com/shape\n\ngo 1.27\n"

// TestFiles returns the fixture layout for analysis harnesses:
// module file (language version current), the source, and a plain
// test anchor. The benchmark spelling lives in BenchFiles alone -
// testing.B's runtime-configuration reads (b.Loop, b.N) flag the
// package scan, which would poison every observability disposition
// the corpus pins.
func (e Entry) TestFiles() map[string]string {
	return map[string]string{
		"go.mod":   corpusModFile,
		"shape.go": e.Source,
		"shape_test.go": `package shape

import "testing"

func TestSubject(t *testing.T) { _ = Subject() }
`,
	}
}

// BenchFiles returns the fixture layout for measurement harnesses:
// the same source with a BenchmarkSubject anchor.
func (e Entry) BenchFiles() map[string]string {
	return map[string]string{
		"go.mod":   corpusModFile,
		"shape.go": e.Source,
		"shape_test.go": `package shape

import "testing"

func BenchmarkSubject(b *testing.B) {
	for b.Loop() {
		_ = Subject()
	}
}
`,
	}
}
