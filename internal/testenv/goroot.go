package testenv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

var (
	hostGOROOTMu sync.Mutex
	hostGOROOT   string
)

func resolveOrigGOROOT(t testing.TB, env []string) string {
	t.Helper()
	var runner gotool.Runner
	for i := len(env) - 1; i >= 0; i-- {
		if val, ok := strings.CutPrefix(env[i], "GOROOT="); ok {
			if strings.TrimSpace(val) != "" {
				snapshot, err := runner.TakeEnvSnapshot(context.Background(), t.TempDir(), env)
				if err != nil {
					t.Fatal(err)
				}
				return snapshot.Value("GOROOT")
			}
			break
		}
	}
	hostGOROOTMu.Lock()
	defer hostGOROOTMu.Unlock()
	if hostGOROOT != "" {
		return hostGOROOT
	}
	snapshot, err := runner.TakeEnvSnapshot(context.Background(), t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	hostGOROOT = snapshot.Value("GOROOT")
	return hostGOROOT
}

// OverlayGOROOT constructs an isolated GOROOT copy of the host toolchain with
// the specified GOROOT-relative overlay files written on top.
func OverlayGOROOT(t testing.TB, env []string, overlays map[string]string) string {
	t.Helper()
	origRoot := resolveOrigGOROOT(t, env)
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dstRoot := filepath.Join(tmp, "goroot")
	buildGOROOTOverlayAt(t, origRoot, dstRoot, overlays)
	return dstRoot
}

func buildGOROOTOverlayAt(t testing.TB, origRoot, dstRoot string, overlays map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dstRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTree := func(srcDir, dstDir string, skip func(rel string, d os.DirEntry) (skipDir, skipFile bool)) {
		if err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(srcDir, path)
			if err != nil {
				return err
			}
			if rel != "." && skip != nil {
				sd, sf := skip(rel, d)
				if sd {
					return filepath.SkipDir
				}
				if sf {
					return nil
				}
			}
			dst := filepath.Join(dstDir, rel)
			if d.IsDir() {
				return os.MkdirAll(dst, 0o755)
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.WriteFile(dst, data, info.Mode().Perm())
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, topFile := range []string{"VERSION", "go.env"} {
		src := filepath.Join(origRoot, topFile)
		if data, err := os.ReadFile(src); err == nil {
			if err := os.WriteFile(filepath.Join(dstRoot, topFile), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if origBin := filepath.Join(origRoot, "bin"); func() bool { _, err := os.Stat(origBin); return err == nil }() {
		dstBin := filepath.Join(dstRoot, "bin")
		if err := os.Symlink(origBin, dstBin); err != nil {
			copyTree(origBin, dstBin, nil)
		}
	}
	if origPkg := filepath.Join(origRoot, "pkg"); func() bool { _, err := os.Stat(origPkg); return err == nil }() {
		dstPkg := filepath.Join(dstRoot, "pkg")
		if err := os.MkdirAll(dstPkg, 0o755); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(origPkg)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			src := filepath.Join(origPkg, entry.Name())
			dst := filepath.Join(dstPkg, entry.Name())
			if entry.Name() == "include" && entry.IsDir() {
				copyTree(src, dst, nil)
				continue
			}
			if err := os.Symlink(src, dst); err != nil {
				copyTree(src, dst, nil)
			}
		}
	}
	if origLib := filepath.Join(origRoot, "lib"); func() bool { _, err := os.Stat(origLib); return err == nil }() {
		copyTree(origLib, filepath.Join(dstRoot, "lib"), nil)
	}
	copyTree(filepath.Join(origRoot, "src"), filepath.Join(dstRoot, "src"), func(rel string, d os.DirEntry) (bool, bool) {
		slash := filepath.ToSlash(rel)
		if d.IsDir() && (slash == "cmd" || d.Name() == "testdata") {
			return true, false
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), "_test.go") {
			return false, true
		}
		return false, false
	})
	for rel, content := range overlays {
		cleanRel := filepath.ToSlash(filepath.Clean(rel))
		if !filepath.IsLocal(rel) || cleanRel == "." || cleanRel == "bin" || strings.HasPrefix(cleanRel, "bin/") || cleanRel == "pkg" || cleanRel == "pkg/include" || (strings.HasPrefix(cleanRel, "pkg/") && !strings.HasPrefix(cleanRel, "pkg/include/")) {
			t.Fatalf("overlay path %q crosses symlinked or non-local GOROOT directory", rel)
		}
		target := filepath.Join(dstRoot, filepath.FromSlash(cleanRel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

var (
	sharedOverlaysMu   sync.Mutex
	sharedOverlayRoots = map[string]string{}
	sharedOverlayDirs  []string
)

func overlayCacheKey(key, origRoot string, overlays map[string]string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", key, origRoot)
	keys := make([]string, 0, len(overlays))
	for k := range overlays {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s\x00%d:%s\x00", k, len(overlays[k]), overlays[k])
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// SharedGOROOTOverlay constructs or reuses a process-wide read-only GOROOT
// overlay keyed by (key, origRoot, overlays). Callers that mutate the returned
// GOROOT after construction must use OverlayGOROOT instead.
func SharedGOROOTOverlay(t testing.TB, key string, env []string, overlays map[string]string) string {
	t.Helper()
	origRoot := resolveOrigGOROOT(t, env)
	cacheKey := overlayCacheKey(key, origRoot, overlays)
	sharedOverlaysMu.Lock()
	defer sharedOverlaysMu.Unlock()
	if existing, ok := sharedOverlayRoots[cacheKey]; ok {
		if _, err := os.Stat(existing); err == nil {
			return existing
		}
	}
	rawTmp, err := os.MkdirTemp("", "gofresh-shared-goroot-*")
	if err != nil {
		t.Fatal(err)
	}
	sharedOverlayDirs = append(sharedOverlayDirs, rawTmp)
	tmp, err := filepath.EvalSymlinks(rawTmp)
	if err != nil {
		t.Fatal(err)
	}
	dstRoot := filepath.Join(tmp, "goroot")
	buildGOROOTOverlayAt(t, origRoot, dstRoot, overlays)
	sharedOverlayRoots[cacheKey] = dstRoot
	return dstRoot
}

// SharedGOROOTOverlayEnv constructs or reuses a process-wide read-only GOROOT
// overlay and returns a normalized environment rooted at that GOROOT with
// GOCACHE explicitly pinned.
func SharedGOROOTOverlayEnv(t testing.TB, key string, baseEnv []string, overlays map[string]string) (string, []string) {
	t.Helper()
	dstRoot := SharedGOROOTOverlay(t, key, baseEnv, overlays)
	preserved, err := gotool.PreserveBuildCache(context.Background(), baseEnv)
	if err != nil {
		t.Fatal(err)
	}
	preserved = gotool.SetEnv(preserved, "GOROOT", dstRoot)
	preserved = gotool.SetEnv(preserved, "GOTOOLCHAIN", "local")
	return dstRoot, preserved
}

// CleanupShared removes all process-wide shared GOROOT overlays and temporary
// test artifacts created during the test binary run.
func CleanupShared() {
	sharedOverlaysMu.Lock()
	dirs := sharedOverlayDirs
	sharedOverlayDirs = nil
	clear(sharedOverlayRoots)
	sharedOverlaysMu.Unlock()
	for _, dir := range dirs {
		_ = os.RemoveAll(dir)
	}
}

// OverlayGOROOTEnv constructs an isolated GOROOT overlay and returns a
// normalized environment rooted at that GOROOT with GOCACHE explicitly pinned.
func OverlayGOROOTEnv(t testing.TB, baseEnv []string, overlays map[string]string) (string, []string) {
	t.Helper()
	dstRoot := OverlayGOROOT(t, baseEnv, overlays)
	preserved, err := gotool.PreserveBuildCache(context.Background(), baseEnv)
	if err != nil {
		t.Fatal(err)
	}
	preserved = gotool.SetEnv(preserved, "GOROOT", dstRoot)
	preserved = gotool.SetEnv(preserved, "GOTOOLCHAIN", "local")
	return dstRoot, preserved
}

const unauditedBadStdSource = "//go:build badstd\n\npackage strings\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshUnapproved\nfunc gofreshUnapproved() {}\n"

// UnauditedTagGOROOT constructs or reuses a read-only GOROOT copy of the host
// toolchain with a tag-gated file in package strings (`//go:build badstd`) that
// declares an unapproved single-argument push linkname.
func UnauditedTagGOROOT(t testing.TB, env []string) string {
	t.Helper()
	return SharedGOROOTOverlay(t, "badstd", env, map[string]string{
		"src/strings/gofresh_badstd.go": unauditedBadStdSource,
	})
}

// UnauditedTagGOROOTEnv constructs or reuses a read-only GOROOT copy with the
// `badstd` overlay and returns a normalized environment rooted at that GOROOT
// with GOCACHE explicitly pinned.
func UnauditedTagGOROOTEnv(t testing.TB, baseEnv []string) (string, []string) {
	t.Helper()
	return SharedGOROOTOverlayEnv(t, "badstd", baseEnv, map[string]string{
		"src/strings/gofresh_badstd.go": unauditedBadStdSource,
	})
}
