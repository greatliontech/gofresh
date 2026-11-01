package observableopenfile

import (
	"os"
	"testing"
)

func TestOpenFile(*testing.T) {
	_, _ = os.OpenFile("fixture.txt", os.O_RDONLY, 0)
}
