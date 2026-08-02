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
