// Package buildflags validates and resolves the Go flags that select source for
// freshness analysis.
package buildflags

import (
	"context"
	"fmt"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// ValidateEnv refuses flags whose selected source gofresh cannot represent,
// under env as a complete process environment and the caller's context.
// Explicit flags and effective GOFLAGS are checked together so analysis never
// silently falls back to disk source for an overlay-backed build.
func ValidateEnv(ctx context.Context, dir string, env, explicit []string) error {
	for _, flag := range explicit {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	goFlags, err := EffectiveGOFLAGSEnv(ctx, dir, env)
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

// EffectiveGOFLAGSEnv returns the GOFLAGS selected by a complete environment
// under the caller's context.
func EffectiveGOFLAGSEnv(ctx context.Context, dir string, env []string) (string, error) {
	out, err := gotool.RunInContextEnv(ctx, dir, env, "env", "GOFLAGS")
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
