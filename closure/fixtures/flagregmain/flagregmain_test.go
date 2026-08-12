package flagregmain

import (
	"flag"
	"os"
	"testing"
)

// Registration in user test-main flow is the same process-local
// registry mutation - the covert channel is the read side, not the
// registration: the call's own reference to the registered variable
// and the store of a returned pointer are the sanctioned write shapes,
// and nothing here ever reads either back.
var (
	mode  string
	mode2 *string
)

func TestMain(m *testing.M) {
	flag.StringVar(&mode, "flagregmain.mode", "fast", "fixture flag")
	mode2 = flag.String("flagregmain.mode2", "slow", "fixture flag")
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
