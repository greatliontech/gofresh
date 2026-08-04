package fmtsinkstdout

import (
	"fmt"
	"os"
	"testing"
)

func TestFprintfStdout(t *testing.T) {
	fmt.Fprintf(os.Stdout, "value %d", 1)
}
