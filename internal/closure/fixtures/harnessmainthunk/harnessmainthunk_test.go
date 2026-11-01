package harnessmainthunk

import (
	"os"
	"testing"
)

// planted is the method-expression form of the post-run channel: the
// thunk is a static callee and the planted value rides as its receiver
// argument, so the argument carries the dispatch provenance.
var planted testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSMAINTHUNK_SECRET") }

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		f := testing.TB.Fatal
		f(planted, "late")
	}
}

func TestPlant(t *testing.T) {
	planted = envTB{t}
}

func TestRead(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
