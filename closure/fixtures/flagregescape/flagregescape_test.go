package flagregescape

import "testing"

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
