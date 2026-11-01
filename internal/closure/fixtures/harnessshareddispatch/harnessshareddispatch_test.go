package harnessshareddispatch

import (
	"os"
	"testing"
)

// shared is the subject-tier form of the wrapper channel: sibling
// runtime flow plants an implementation, and the consuming subjects
// dispatch it through the synthetic wrapper family — the bound method
// value and the method-expression thunk — whose receiver provenance
// must refuse exactly as a direct invoke's operand would.
var shared testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSSHAREDDISPATCH_SECRET") }

func TestPlant(t *testing.T) {
	shared = envTB{t}
}

func TestUseBound(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if shared != nil {
		f := shared.Fatal
		f("bound")
	}
}

func TestUseThunk(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if shared != nil {
		f := testing.TB.Fatal
		f(shared, "thunk")
	}
}

// TestUsePhi carries the wrapper through a phi so the call operand is
// a merge of closure values: the binding obligation rides the value
// walk, not the call site's syntax.
func TestUsePhi(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if shared != nil {
		f := shared.Fatal
		if len("x") == 1 {
			f = shared.Fatal
		}
		f("phi")
	}
}

// TestUseThunkLocal is the closed-receiver control: the thunk's
// receiver argument derives from the subject's own flow, so the
// dispatch keeps the wrapped method's ordinary classification.
func TestUseThunkLocal(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	var tb testing.TB = t
	f := testing.TB.Fatal
	if len("x") == 0 {
		f(tb, "never")
	}
}

// TestUseThunkPhi carries the method-expression thunk through a phi:
// a thunk VALUE is never closed — its receiver arrives at call sites
// the value walk cannot see — so the computed call must refuse.
func TestUseThunkPhi(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if shared != nil {
		f := testing.TB.Fatal
		if len("x") == 1 {
			f = testing.TB.Fatal
		}
		f(shared, "thunk phi")
	}
}

// TestUseLaunder washes the planted wrapper through the empty
// interface and a type assertion: the interface hop must not launder
// the binding obligation.
func TestUseLaunder(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if shared != nil {
		var x any = shared.Fatal
		f := x.(func(...any))
		f("laundered")
	}
}
