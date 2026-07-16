package observablecallbackbad

import (
	"os"
	"testing"
)

func TestSubtestRead(t *testing.T) {
	t.Run("child", func(*testing.T) {
		_, _ = os.ReadFile("fixture.txt")
	})
}
