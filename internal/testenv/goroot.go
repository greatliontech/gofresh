package testenv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// OverlayGOROOT constructs an isolated GOROOT copy of the host toolchain with
// the specified GOROOT-relative overlay files written on top.
func OverlayGOROOT(t testing.TB, env []string, overlays map[string]string) string {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	origRoot := snapshot.Value("GOROOT")
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dstRoot := filepath.Join(tmp, "goroot")
	if err := os.MkdirAll(dstRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTree := func(srcDir, dstDir string, allowHardlink bool, skip func(rel string, d os.DirEntry) (skipDir, skipFile bool)) {
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
			if allowHardlink {
				if err := os.Link(path, dst); err == nil {
					return nil
				}
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
			copyTree(origBin, dstBin, true, nil)
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
				copyTree(src, dst, false, nil)
				continue
			}
			if err := os.Symlink(src, dst); err != nil {
				copyTree(src, dst, true, nil)
			}
		}
	}
	if origLib := filepath.Join(origRoot, "lib"); func() bool { _, err := os.Stat(origLib); return err == nil }() {
		copyTree(origLib, filepath.Join(dstRoot, "lib"), true, nil)
	}
	copyTree(filepath.Join(origRoot, "src"), filepath.Join(dstRoot, "src"), true, func(rel string, d os.DirEntry) (bool, bool) {
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
	return dstRoot
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

// UnauditedTagGOROOT constructs an isolated GOROOT copy of the host toolchain
// with a tag-gated file in package strings (`//go:build badstd`) that declares
// an unapproved single-argument push linkname.
func UnauditedTagGOROOT(t testing.TB, env []string) string {
	t.Helper()
	return OverlayGOROOT(t, env, map[string]string{
		"src/strings/gofresh_badstd.go": unauditedBadStdSource,
	})
}

// UnauditedTagGOROOTEnv constructs an isolated GOROOT copy with the `badstd`
// overlay and returns a normalized environment rooted at that GOROOT with
// GOCACHE explicitly pinned.
func UnauditedTagGOROOTEnv(t testing.TB, baseEnv []string) (string, []string) {
	t.Helper()
	return OverlayGOROOTEnv(t, baseEnv, map[string]string{
		"src/strings/gofresh_badstd.go": unauditedBadStdSource,
	})
}
