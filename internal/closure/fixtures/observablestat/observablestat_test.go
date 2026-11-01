package observablestat

import (
	"os"
	"testing"
)

func TestStat(*testing.T) {
	_, _ = os.Stat("fixture.txt")
}
