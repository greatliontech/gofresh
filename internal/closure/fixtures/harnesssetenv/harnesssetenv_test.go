package harnesssetenv

import (
	"os"
	"testing"
)

func TestSetenvStaysBlocked(t *testing.T) {
	t.Setenv("HARNESSLOG_FIXTURE", "1")
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
}

// TestCleanRead reaches no ambient surface itself: its refusal can come
// only from the package-scan backstop over the sibling's Setenv, so the
// row pins the blocker boundary one exemption too wide would erase.
func TestCleanRead(t *testing.T) {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty baseline")
	}
}
