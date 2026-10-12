package gofresh_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// TestToolVersionModule keeps the independently published metadata module in
// the repository's plain and CI test inventory. The module has no dependencies
// and its own tests directly exercise the formatter's metadata cases.
func TestToolVersionModule(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "test", "-count=1", "./...")
	cmd.Dir = "toolversion"
	cmd.Env = gotool.SetEnv(os.Environ(), "GOWORK", "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("toolversion module: %v\n%s", err, out)
	}
}
