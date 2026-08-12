package flagparsemain

import (
	"flag"
	"os"
	"testing"
)

// Parse is the read side of the registration channel - the registered
// pointers' values change here, a channel the test log cannot audit -
// so it keeps its refusal even in test-main flow.
func TestMain(m *testing.M) {
	_ = flag.String("flagparsemain.mode", "fast", "fixture flag")
	flag.Parse()
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
