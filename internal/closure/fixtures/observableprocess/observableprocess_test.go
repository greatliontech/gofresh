package observableprocess

import (
	"os/exec"
	"testing"
)

func TestCommand(*testing.T) {
	_ = exec.Command("true").Run()
}
