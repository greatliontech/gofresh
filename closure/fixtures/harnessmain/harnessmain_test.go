package harnessmain

import (
	"os"
	"testing"
)

// planted is the post-run channel: a test plants an implementation, and
// TestMain dispatches it after m.Run — the one startup flow that can
// carry a test-planted value, refused because the startup walk cannot
// enumerate the dispatch.
var planted testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSMAIN_SECRET") }

func TestMain(m *testing.M) {
	_ = m.Run()
	if planted != nil {
		planted.Fatal("late")
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
