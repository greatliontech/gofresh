package initfmtsink

import (
	"bytes"
	"fmt"
	"testing"
)

var banner string

func init() {
	var b bytes.Buffer
	fmt.Fprintf(&b, "ready %d", 1)
	banner = b.String()
}

func TestAfterInitFormat(t *testing.T) {
	if banner == "" {
		t.Fatal("empty")
	}
}
