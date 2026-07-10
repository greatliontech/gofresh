// Package buildflags validates and resolves the Go flags that select source for
// freshness analysis.
package buildflags

import (
	"fmt"
	"os"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// Validate refuses flags whose selected source gofresh cannot represent. Explicit
// flags and effective GOFLAGS are checked together so analysis never silently falls
// back to disk source for an overlay-backed build.
func Validate(dir string, explicit []string) error {
	for _, flag := range explicit {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	goFlags, err := EffectiveGOFLAGS(dir)
	if err != nil {
		return err
	}
	for _, flag := range strings.Fields(goFlags) {
		flag = strings.Trim(flag, `"'`)
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	return nil
}

// EffectiveGOFLAGS returns the flags the go command inherits. An explicitly set,
// even empty, process value wins; otherwise go env resolves persistent GOENV state.
func EffectiveGOFLAGS(dir string) (string, error) {
	if flags := os.Getenv("GOFLAGS"); flags != "" {
		return flags, nil
	}
	out, err := gotool.RunIn(dir, "env", "GOFLAGS")
	if err != nil {
		return "", fmt.Errorf("build flags: resolve GOFLAGS: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func isOverlayFlag(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	return name == "overlay" || strings.HasPrefix(name, "overlay=")
}

func unsupportedOverlay(flag string) error {
	return fmt.Errorf("build flags: %s is unsupported because freshness analysis hashes disk source", flag)
}
