package observablemutation

import (
	"os"
	"testing"
)

func TestRemove(*testing.T) {
	_ = os.Remove("fixture.txt")
}
