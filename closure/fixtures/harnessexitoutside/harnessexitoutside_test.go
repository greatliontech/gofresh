package harnessexitoutside

import (
	"os"
	"testing"
)

// The os.Exit epilogue admission is scoped to the TestMain declaration:
// an os.Exit in a helper outside it keeps the package-scan finding even
// in a TestMain-bearing file.
func hardStop() {
	os.Exit(3)
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		hardStop()
	}
}
