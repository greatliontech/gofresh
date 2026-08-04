package initfmthelper

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

var banner string

func init() {
	var b bytes.Buffer
	describe(&b, 1)
	banner = b.String()
}

// describe receives its writer across a call boundary: startup flow
// carries no subject-attributed parameter analysis, so the crossing
// refuses and the Fprintf keeps its effect even though every caller
// passes a local buffer.
func describe(w io.Writer, n int) {
	fmt.Fprintf(w, "ready %d", n)
}

func TestAfterInitHelperFormat(t *testing.T) {
	if banner == "" {
		t.Fatal("empty")
	}
}
