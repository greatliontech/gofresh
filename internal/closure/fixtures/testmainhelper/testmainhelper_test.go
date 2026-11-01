package testmainhelper

import (
	"os"
	"testing"
)

func run(m *testing.M) int {
	return m.Run()
}

func TestMain(m *testing.M) {
	run(m)
}

func TestRead(*testing.T) {
	_, _ = os.ReadFile("fixture.txt")
}
