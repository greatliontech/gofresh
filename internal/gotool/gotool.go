// Package gotool runs the go command line tool, surfacing stderr on failure.
package gotool

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Run executes `go <args>` in the current directory. See RunIn.
func Run(args ...string) ([]byte, error) { return RunIn("", args...) }

// RunIn executes `go <args>` in dir ("" = current directory) and returns stdout.
// On failure the error includes the command and go's stderr. The directory
// matters: a go.mod `toolchain` directive / GOTOOLCHAIN is resolved relative to
// it, so provenance capture and `go test` must run in the same dir to describe
// the same toolchain.
func RunIn(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("go %s: %w: %s",
				strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
