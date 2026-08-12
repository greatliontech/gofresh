package dyncaller

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// RunCheck is the enumeration-closed shape: a dynamic-carrying subject
// whose only references are direct static calls passing closed values.
func RunCheck(check func(int) int, n int) int {
	return check(n)
}

// RunEffect is called with a closure that mutates the filesystem: the
// closure body is analyzed view content whose blocking effect belongs
// to the subject.
func RunEffect(check func(int) int, n int) int {
	return check(n)
}

// RunEscaped is also referenced as a value (stored to a package
// variable), so it keeps the open world.
func RunEscaped(check func(int) int, n int) int {
	return check(n)
}

// RunUncalled has no references at all: absence of provenance.
func RunUncalled(check func(int) int, n int) int {
	return check(n)
}

// RunMixed has one caller passing a value the caller-frame walk cannot
// close (its own parameter).
func RunMixed(check func(int) int, n int) int {
	return check(n)
}

// Sizer is the interface-parameter shape: the enumerated caller
// materializes a concrete type, so the subject's invoke resolves to it.
// The method is unexported on purpose: an exported name would make
// every same-named standard-library method an RTA dispatch candidate.
type Sizer interface {
	size() int
}

type wordSizer struct{ s string }

func (w wordSizer) size() int { return len(strings.Fields(w.s)) }

type fileSizer struct{ path string }

func (f fileSizer) size() int {
	_ = os.WriteFile(f.path, []byte("x"), 0o600)
	return 1
}

func Measure(s Sizer) int {
	return s.size()
}

// MeasureFile's enumerated caller hands it a type whose method mutates
// the filesystem: the blocking effect is the subject's own.
func MeasureFile(s Sizer) int {
	return s.size()
}

var escaped = RunEscaped

// namedHook is held by a package-level variable; a computed call
// through the variable dispatches a value with a stable identity. The
// signature is distinct from every other fixture subject's — dyninit's
// included, which documents that distinctness — so the address-taken
// value enters no sibling subject's dispatch candidates under any mask
// (docs/issues/enumeration-targets-over-approximated.md).
func namedHook(b byte) byte { return b }

var hook = namedHook

// RunViaVar calls through a package-level function variable: the
// refusal names the variable it dispatches.
func RunViaVar(b byte) byte { return hook(b) }

// RunDead has zero references and never moves its parameter: only the
// absence-of-provenance arm refuses it.
func RunDead(check func(int) int, n int) int {
	return n
}

// boxed carries a value whose concrete type the caller-frame walk
// cannot pin: FormatLoaded must keep the open world, because its
// parameter flows into fmt's reflective formatting where no dispatch
// site exists to refuse per-site.
var boxed any = strings.NewReplacer()

func FormatLoaded(v any) string {
	return fmt.Sprintf("%v", v)
}

// FormatLocal is the positive std-flow shape: the enumerated caller
// materializes the concrete type, so the reflective argument premise
// holds and the subject closes with no dispatch at all.
func FormatLocal(v any) string {
	return fmt.Sprintf("%v", v)
}

// Runner.RunM is referenced once directly and once as a method value:
// the synthetic wrapper re-dispatches it where no enumeration can
// judge, so the wrapper's existence keeps the open world.
type Runner struct{}

func (Runner) RunM(check func(int) int, n int) int {
	return check(n)
}

// Counter.RunP is a pointer-receiver method with only direct calls: a
// receiver-bearing subject keeps the open world outright, because an
// interface invoke of it would leave no reference the scan can see.
type Counter struct{ n int }

func (c *Counter) RunP(check func(int) int, n int) int {
	c.n++
	return check(n)
}

// RunGen is called from a generic helper: neither the parameterized
// origin nor its synthetic instantiations can be judged as callers.
func RunGen(check func(int) int, n int) int {
	return check(n)
}

func callGen[T any](f func(int) int, n int) int {
	return RunGen(f, n)
}

// RunGo's enumerated callers include a go statement: provenance is
// concurrency-independent, so the site judges like any other.
func RunGo(check func(int) int, n int) int {
	return check(n)
}

// RunCallArg's caller passes a call result at the dynamic position:
// the caller-frame walk cannot see through the call, so it refuses.
func RunCallArg(check func(int) int, n int) int {
	return check(n)
}

func mkCheck() func(int) int {
	return func(n int) int { return n }
}

func TestRunCheck(t *testing.T) {
	if RunCheck(func(n int) int { return n + 1 }, 1) != 2 {
		t.Fatal("wrong")
	}
	if RunCheck(func(n int) int { return n * 2 }, 2) != 4 {
		t.Fatal("wrong")
	}
}

func TestRunEffect(t *testing.T) {
	dir := t.TempDir()
	got := RunEffect(func(n int) int {
		_ = os.WriteFile(dir+"/out.txt", []byte("x"), 0o600)
		return n
	}, 1)
	if got != 1 {
		t.Fatal("wrong")
	}
}

// The direct call and the value use live in different functions: the
// direct caller (and the closure parent it binds) is clean, so the
// package-level value reference alone must keep the open world.
func TestRunEscapedDirect(t *testing.T) {
	if RunEscaped(func(n int) int { return n }, 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestRunEscaped(t *testing.T) {
	if escaped(func(n int) int { return n }, 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestFormatLoaded(t *testing.T) {
	if FormatLoaded(boxed) == "" {
		t.Fatal("wrong")
	}
}

func TestFormatLocal(t *testing.T) {
	if FormatLocal(wordSizer{s: "a b"}) == "" {
		t.Fatal("wrong")
	}
}

func TestRunPointerMethod(t *testing.T) {
	c := &Counter{}
	if c.RunP(func(n int) int { return n }, 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestRunGen(t *testing.T) {
	if callGen[int](func(n int) int { return n }, 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestRunGo(t *testing.T) {
	done := make(chan int, 1)
	go RunGo(func(n int) int { done <- n; return n }, 1)
	if RunGo(func(n int) int { return n + 1 }, 1) != 2 {
		t.Fatal("wrong")
	}
	if <-done != 1 {
		t.Fatal("wrong")
	}
}

func TestRunCallArg(t *testing.T) {
	if RunCallArg(mkCheck(), 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestRunMethod(t *testing.T) {
	var r Runner
	if r.RunM(func(n int) int { return n }, 1) != 1 {
		t.Fatal("wrong")
	}
	m := r.RunM
	if m(func(n int) int { return n + 1 }, 1) != 2 {
		t.Fatal("wrong")
	}
}

func TestRunMixed(t *testing.T) {
	helperMixed(t, func(n int) int { return n })
}

func helperMixed(t *testing.T, f func(int) int) {
	if RunMixed(f, 1) != 1 {
		t.Fatal("wrong")
	}
}

func TestMeasure(t *testing.T) {
	if Measure(wordSizer{s: "a b"}) != 2 {
		t.Fatal("wrong")
	}
}

func TestMeasureFile(t *testing.T) {
	if MeasureFile(fileSizer{path: t.TempDir() + "/out.txt"}) != 1 {
		t.Fatal("wrong")
	}
}
