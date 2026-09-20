// Package buildflags validates and resolves the Go flags that select source for
// freshness analysis.
package buildflags

import (
	"context"
	"fmt"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
)

// Validate refuses flags whose selected source gofresh cannot represent,
// the effective GOFLAGS read from the pass's reader — its one snapshot,
// never a probe of its own. Explicit flags and effective GOFLAGS are
// checked together so analysis never silently falls back to disk source
// for an overlay-backed build.
func Validate(ctx context.Context, reader *gotool.EnvReader, explicit []string) error {
	for _, flag := range explicit {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	goFlags, err := reader.Value(ctx, "GOFLAGS")
	if err != nil {
		return fmt.Errorf("build flags: resolve GOFLAGS: %w", err)
	}
	for _, flag := range strings.Fields(goFlags) {
		flag = strings.Trim(flag, `"'`)
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	return nil
}

func isOverlayFlag(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	return name == "overlay" || strings.HasPrefix(name, "overlay=")
}

func unsupportedOverlay(flag string) error {
	return fmt.Errorf("build flags: %s is unsupported because freshness analysis hashes disk source", flag)
}
