package harnesserrshared

import (
	"os"
	"testing"
)

// sharedErr is the universe-interface form of the planted channel: the
// wrapper wraps error.Error — a method with no declaring package — and
// its receiver provenance must refuse exactly like any other interface
// wrapper over shared mutable state.
var sharedErr error

type envErr struct{}

func (envErr) Error() string { return os.Getenv("HARNESSERRSHARED_SECRET") }

func TestPlant(t *testing.T) {
	sharedErr = envErr{}
}

func TestUseErrBound(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Fatal(err)
	}
	if sharedErr != nil {
		f := sharedErr.Error
		_ = f()
	}
}
