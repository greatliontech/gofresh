package flaglookupsubject

import (
	"flag"
	"testing"
)

// A subject-flow flag lookup keeps the exclusion, and its refusal
// names the lookup - the flag package's internal usage prints are
// help-path only and never outrank the real cause.
func TestProd(t *testing.T) {
	if Prod() == 0 || flag.Lookup("flaglookupsubject.x") != nil {
		t.Fatal()
	}
}
