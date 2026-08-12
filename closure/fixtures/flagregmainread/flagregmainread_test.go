package flagregmainread

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if *verbose {
		code = 0
	}
	os.Exit(code)
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
