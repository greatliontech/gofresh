package flagregstruct

import "testing"

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}

func TestProdRead(t *testing.T) {
	if ProdRead() < 0 {
		t.Fatal()
	}
}

func TestProdEscape(t *testing.T) {
	if ProdEscape() < 0 {
		t.Fatal()
	}
}
