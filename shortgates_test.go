package gofresh

import (
	"testing"

	"github.com/greatliontech/gofresh/shortgates"
)

// The fast tier's gates are inert under a plain `go test`: every gate in
// the repository's test files is a skipping statement of a Test or Fuzz
// body, never in a helper, an uninvoked closure, or a fixture string
// (github.com/greatliontech/gofresh/shortgates states the rules and pins
// its own arms).
func TestShortGatesLiveInTestBodiesAndSkip(t *testing.T) {
	shortgates.Pin(t, ".")
}
