package ambiguousroot_test

import (
	"testing"

	"github.com/greatliontech/gofresh/internal/closure/fixtures/ambiguousroot"
)

func TestSize(t *testing.T) {
	if ambiguousroot.Size() != 1 {
		t.Fatal()
	}
}
