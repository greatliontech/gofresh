// Package testenv preserves toolchain settings across fixture-owned environment
// changes. Go's build cache is not a gofresh proof cache: isolating the latter
// must not silently give every test process a cold compiler cache as well.
package testenv

import (
	"context"

	"github.com/greatliontech/gofresh/gotool"
)

// GoBuildCache resolves the effective Go build cache from an explicit environment
// before a test changes XDG_CACHE_HOME. The caller pins the returned selection.
// Only Go determines the default, including any GOENV configuration.
func GoBuildCache(ctx context.Context, env []string) (string, error) {
	return gotool.GoBuildCache(ctx, env)
}
