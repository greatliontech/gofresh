package dyninit

import "testing"

// RunInit is called from a package-variable initializer: the synthetic
// initializer body cannot be judged as a caller, so the reference
// refuses even beside a clean test caller. The package holds nothing
// else, so a wrong admission here would read observable — the arm's
// only net. Its parameter signature is also distinct from the dyncaller
// package's subjects: an initializer closure is address-taken under
// every mask, and a matching signature would enter sibling subjects'
// dispatch candidates
// (docs/issues/enumeration-targets-over-approximated.md).
func RunInit(check func(string) string, s string) string {
	return check(s)
}

var initResult = RunInit(func(s string) string { return s }, "x")

func TestRunInit(t *testing.T) {
	if initResult != "x" || RunInit(func(s string) string { return s }, "x") != "x" {
		t.Fatal("wrong")
	}
}
