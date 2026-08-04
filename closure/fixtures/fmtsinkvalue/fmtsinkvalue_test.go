package fmtsinkvalue

import (
	"bytes"
	"fmt"
	"testing"
)

// format carries fmt.Fprintf through a package-level value so the
// subject's call site stays a dynamic reach — the writer-sink admission
// applies to static calls only, whatever the arguments carry.
var format = fmt.Fprintf

func TestValueFormatBuffer(t *testing.T) {
	var b bytes.Buffer
	_, _ = format(&b, "value %d", 1)
	if b.Len() == 0 {
		t.Fatal("empty")
	}
}
