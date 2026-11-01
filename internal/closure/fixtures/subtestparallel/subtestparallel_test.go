package subtestparallel

import (
	"os"
	"testing"
)

func TestParallelChild(t *testing.T) {
	t.Run("child", func(t *testing.T) {
		t.Parallel()
		_, _ = os.ReadFile("fixture.txt")
	})
}
