package initfmtvalue

import (
	"bytes"
	"fmt"
	"testing"
)

var banner string

// format carries fmt.Fprintf through a package-level value so the init
// call site stays a dynamic reach — a single-assignment local would
// SSA-resolve to a static call and take the static leg's admission.
var format = fmt.Fprintf

func init() {
	var b bytes.Buffer
	_, _ = format(&b, "ready %d", 1)
	banner = b.String()
}

func TestAfterInitValueFormat(t *testing.T) {
	if banner == "" {
		t.Fatal("empty")
	}
}
