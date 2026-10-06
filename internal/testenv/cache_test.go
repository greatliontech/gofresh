package testenv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

func TestConfiguredCacheIsPreserved(t *testing.T) {
	for _, configured := range []string{t.TempDir(), "off"} {
		t.Run(configured, func(t *testing.T) {
			cache, err := goBuildCache([]string{"GOCACHE=" + configured}, func() (string, error) {
				t.Fatal("explicit cache caused a toolchain query")
				return "", nil
			})
			if err != nil || cache != configured {
				t.Fatalf("cache = %q, err = %v", cache, err)
			}
		})
	}
}

func TestFailedCacheLookupDoesNotInventASelection(t *testing.T) {
	for _, cause := range []error{nil, errors.New("toolchain unavailable")} {
		cache, err := goBuildCache([]string{}, func() (string, error) { return "", cause })
		if err == nil || err.Error() == "" || (cause != nil && !errors.Is(err, cause)) || cache != "" {
			t.Fatalf("lookup %v: cache = %q, err = %v", cause, cache, err)
		}
	}
}

func TestBuildCacheUsesSuppliedEnvironment(t *testing.T) {
	for _, env := range [][]string{{"GOCACHE=a", "GOCACHE=b"}, {"malformed"}} {
		want := "malformed"
		if len(env) == 2 {
			want = "duplicate key"
		}
		got, err := GoBuildCache(t.Context(), env)
		if err == nil || got != "" || !strings.Contains(err.Error(), want) {
			t.Fatalf("invalid environment %q: cache = %q, err = %v", env, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := GoBuildCache(ctx, []string{"GOCACHE=", "GOENV=off"})
	if err == nil || got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query: cache = %q, err = %v", got, err)
	}
	ambient := t.TempDir()
	t.Setenv("GOCACHE", ambient)
	configured := t.TempDir()
	goenv := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(goenv, []byte("GOCACHE="+configured+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "GOCACHE") && !strings.EqualFold(key, "GOENV") {
			env = append(env, entry)
		}
	}
	env = append(env, "GOENV="+goenv)
	for _, explicit := range []string{"", t.TempDir(), "off"} {
		want := explicit
		if want == "" {
			want = configured
		}
		got, err := GoBuildCache(t.Context(), append(env[:len(env):len(env)], "GOCACHE="+explicit))
		if err != nil || got != want {
			t.Fatalf("explicit %q: cache = %q, want %q; err = %v", explicit, got, want, err)
		}
	}
	if got := os.Getenv("GOCACHE"); got != ambient {
		t.Fatalf("ambient cache changed to %q, want %q", got, ambient)
	}
}

func TestBuildCacheSurvivesMemoCacheIsolation(t *testing.T) {
	t.Setenv("GOCACHE", "")
	// The native command is the independent oracle for the effective selection,
	// rather than deriving a cache path from platform-specific conventions.
	readCache := func() string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		out, err := (gotool.Runner{Containment: &gotool.Containment{}}).Run(ctx, "", os.Environ(), "env", "GOCACHE")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	want := readCache()
	cache, err := GoBuildCache(t.Context(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	private := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", private)
	if got := readCache(); got != want || os.Getenv("XDG_CACHE_HOME") != private {
		t.Fatalf("build cache = %q, want %q; memo root = %q", got, want, os.Getenv("XDG_CACHE_HOME"))
	}
}
