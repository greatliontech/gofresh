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

func TestNestedSubtestRead(t *testing.T) {
	t.Run("outer", func(t *testing.T) {
		t.Run("inner", func(*testing.T) {
			_, _ = os.ReadFile("fixture.txt")
		})
	})
}

var never bool

func TestConstructedMRun(t *testing.T) {
	if never {
		_ = new(testing.M).Run()
	}
}
