package ambiguousroot

import "testing"

func TestSize(t *testing.T) {
	if Size() != 1 {
		t.Fatal()
	}
}
