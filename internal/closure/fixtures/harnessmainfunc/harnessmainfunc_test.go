package harnessmainfunc

import (
	"os"
	"testing"
)

// token's package-local signature keeps standard-library function values
// out of the planted variable's enumerated flow, so the refusal below is
// the operand-provenance widen itself, never an incidental std target.
type token struct{ n int }

// planted is the function-value form of the post-run channel: a test
// plants a closure, TestMain calls it after m.Run — a computed call,
// not an interface invoke, refused on the same operand provenance.
var planted func(token) token

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		_ = planted(token{n: 1})
	}
}

func TestPlant(t *testing.T) {
	planted = func(v token) token { _ = os.Getenv("HARNESSMAINFUNC_SECRET"); return v }
}

func TestRead(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}
