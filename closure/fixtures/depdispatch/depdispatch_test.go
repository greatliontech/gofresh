// Package depdispatch pins the subject-determined dispatch admission:
// an unresolved interface invoke inside a helper body stops widening
// the subject world when the operand's dynamic types derive wholly
// from subject-attributed flow and every enumerated target is analyzed
// content - the targets' own effects then decide the verdict.
package depdispatch

import (
	"os"
	"testing"
)

type sizer interface{ size() int }

type word struct{ s string }

func (w word) size() int { return len(w.s) }

type filer struct{ path string }

func (f filer) size() int {
	_ = os.WriteFile(f.path, []byte("x"), 0o600)
	return 1
}

// measureVia dispatches on its parameter: the operand closes by
// crossing to the subject-attributed call sites.
func measureVia(s sizer) int { return s.size() }

// RunLocalDispatch hands measureVia a locally constructed value: the
// operand is subject-determined, the enumerated target set is analyzed
// and pure, and the subject closes observable.
func RunLocalDispatch(n int) int { return measureVia(word{s: "xy"}) + n }

// RunEffectDispatch hands in a value whose method mutates the
// filesystem: the admission holds on shape, and the target's own
// effect refuses the subject.
func RunEffectDispatch(n int) int { return measureVia(filer{path: "x"}) + n }

// shared is process-shared mutable state: a load feeding the operand
// refuses the admission and the open-world refusal stands.
var shared sizer = word{s: "z"}

func RunSharedDispatch(n int) int { return measureVia(shared) + n }

func TestRunLocalDispatch(t *testing.T) {
	if RunLocalDispatch(1) != 3 {
		t.Fatal("wrong")
	}
}

func TestRunSharedDispatch(t *testing.T) {
	if RunSharedDispatch(1) != 2 {
		t.Fatal("wrong")
	}
}

// never has no implementation anywhere in the program: the dispatch
// site's enumerated target set is empty, and an empty set never admits
// - absence of provenance is refused, never a vacuous pass.
type never interface{ nope() int }

func dispatchNever(v never) int {
	if v == nil {
		return 0
	}
	return v.nope()
}

func RunNilDispatch(n int) int { return dispatchNever(nil) + n }

func TestRunNilDispatch(t *testing.T) {
	if RunNilDispatch(1) != 1 {
		t.Fatal("wrong")
	}
}
