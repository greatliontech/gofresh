package flagregalias

import "testing"

func TestProd(t *testing.T) {
	if Prod() {
		t.Fatal()
	}
}
