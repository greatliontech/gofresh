// Package testenv preserves toolchain settings across fixture-owned environment
// changes. Go's build cache is not a gofresh proof cache: isolating the latter
// must not silently give every test process a cold compiler cache as well.
package testenv

import (
	"context"
	"fmt"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

// GoBuildCache resolves the effective Go build cache from an explicit environment
// before a test changes XDG_CACHE_HOME. The caller pins the returned selection.
// Only Go determines the default, including any GOENV configuration.
func GoBuildCache(ctx context.Context, env []string) (string, error) {
	normalized, err := gotool.NormalizeEnv(env)
	if err != nil {
		return "", err
	}
	return goBuildCache(normalized, func() (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		reader := gotool.NewEnvReader(gotool.Runner{Containment: &gotool.Containment{}}, "", normalized)
		snapshot, err := reader.Snapshot(ctx)
		if err != nil {
			return "", err
		}
		return snapshot.Value("GOCACHE"), nil
	})
}

func goBuildCache(env []string, lookup func() (string, error)) (string, error) {
	if cache, _ := gotool.LookupEnv(env, "GOCACHE"); cache != "" {
		return cache, nil
	}
	cache, err := lookup()
	if err != nil {
		return "", fmt.Errorf("test environment: determine Go build cache: %w", err)
	}
	if cache == "" {
		return "", fmt.Errorf("test environment: go env supplied no GOCACHE")
	}
	return cache, nil
}
