package testenv

import (
	"context"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
)

func TestOverlayGOROOTUnlinksHardlinkedSourceBeforeWrite(t *testing.T) {
	t.Parallel()
	env := os.Environ()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	hostGOROOT := snapshot.Value("GOROOT")

	firstOverlay := OverlayGOROOT(t, env, nil)
	origBytes, err := os.ReadFile(filepath.Join(firstOverlay, "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	hostTextflag, err := os.Stat(filepath.Join(hostGOROOT, "pkg", "include", "textflag.h"))
	if err != nil {
		t.Fatal(err)
	}
	overlayTextflag, err := os.Stat(filepath.Join(firstOverlay, "pkg", "include", "textflag.h"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(hostTextflag, overlayTextflag) {
		t.Fatal("OverlayGOROOT hardlinked pkg/include/textflag.h to host GOROOT")
	}
	hostStrings, err := os.Stat(filepath.Join(hostGOROOT, "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	overlayStrings, err := os.Stat(filepath.Join(firstOverlay, "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(hostStrings, overlayStrings) {
		t.Fatal("OverlayGOROOT hardlinked src/strings/strings.go to host GOROOT")
	}

	// Verify same-filesystem overlay construction (both under t.TempDir()) also
	// copies regular files rather than hardlinking inodes when EXDEV cannot mask os.Link.
	sameFSOverlay := OverlayGOROOT(t, gotool.SetEnv(env, "GOROOT", firstOverlay), nil)
	sameFSTextflag, err := os.Stat(filepath.Join(sameFSOverlay, "pkg", "include", "textflag.h"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(overlayTextflag, sameFSTextflag) {
		t.Fatal("same-filesystem OverlayGOROOT hardlinked pkg/include/textflag.h")
	}
	sameFSStrings, err := os.Stat(filepath.Join(sameFSOverlay, "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(overlayStrings, sameFSStrings) {
		t.Fatal("same-filesystem OverlayGOROOT hardlinked src/strings/strings.go")
	}

	overlaid := OverlayGOROOT(t, env, map[string]string{
		"src/strings/strings.go": "package strings\n// overlaid\n",
	})
	gotBytes, err := os.ReadFile(filepath.Join(overlaid, "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != "package strings\n// overlaid\n" {
		t.Fatalf("overlaid strings.go = %q", string(gotBytes))
	}
	controlBytes, err := os.ReadFile(filepath.Join(OverlayGOROOT(t, env, nil), "src", "strings", "strings.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(controlBytes) != string(origBytes) {
		t.Fatal("OverlayGOROOT mutated hardlinked host GOROOT file in place")
	}
}

func TestSharedGOROOTOverlayReusesDirectoryAndCleanupRemovesIt(t *testing.T) {
	env := os.Environ()
	overlays := map[string]string{
		"src/strings/gofresh_shared_probe.go": "//go:build sharedprobe\n\npackage strings\n",
	}
	first := SharedGOROOTOverlay(t, "probe", env, overlays)
	second := SharedGOROOTOverlay(t, "probe", env, overlays)
	if first != second {
		t.Fatalf("SharedGOROOTOverlay returned distinct paths %q and %q for identical key", first, second)
	}
	if _, err := os.Stat(filepath.Join(first, "src", "strings", "gofresh_shared_probe.go")); err != nil {
		t.Fatalf("expected overlaid file in shared GOROOT: %v", err)
	}
	CleanupShared()
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("expected CleanupShared to remove %q, got err=%v", first, err)
	}
}

func TestAssertAllFieldsPopulatedAndParseAndTypecheckDAG(t *testing.T) {
	t.Parallel()
	type sample struct {
		Name  string
		Count int
		Skip  string
	}
	AssertAllFieldsPopulated(t, sample{Name: "ok", Count: 1}, "Skip")
	AssertAllFieldsPopulated(t, &sample{Name: "ok", Count: 1}, "Skip")

	pkgs := ParseAndTypecheckDAG(t, t.TempDir(), map[string]map[string]string{
		"example.com/dep": {
			"dep.go": "package dep\nfunc Value() int { return 42 }\n",
		},
		"example.com/app": {
			"app.go":      "package app\nimport \"example.com/dep\"\nfunc Answer() int { return dep.Value() }\n",
			"app_test.go": "package app\nimport \"testing\"\nfunc TestAnswer(t *testing.T) { _ = Answer() }\n",
			"ext_test.go": "package app_test\nimport (\n\t\"testing\"\n\t\"example.com/app\"\n)\nfunc TestExt(t *testing.T) { _ = app.Answer() }\n",
		},
	})
	if len(pkgs) != 3 {
		t.Fatalf("len(pkgs) = %d, want 3 (dep, app, app_test)", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Dir == "" {
			t.Fatalf("pkg %s has empty Dir", p.ID)
		}
	}
}

func TestParseAndTypecheckDAGWithStdlibIsolatesArchSizes(t *testing.T) {
	t.Parallel()
	baseEnv := gotool.SetEnv(os.Environ(), "GOOS", "linux")
	files := map[string]map[string]string{
		"example.com/arch": {
			"arch.go": "package arch\nimport (\n\t\"strconv\"\n\t\"unsafe\"\n)\nconst WordBytes = int(unsafe.Sizeof(int(0)))\nconst StdIntBits = strconv.IntSize\n",
		},
	}
	pkgs64 := ParseAndTypecheckDAGWithStdlib(t, gotool.SetEnv(baseEnv, "GOARCH", "amd64"), t.TempDir(), files)
	pkgs32 := ParseAndTypecheckDAGWithStdlib(t, gotool.SetEnv(baseEnv, "GOARCH", "386"), t.TempDir(), files)
	if len(pkgs64) != 1 || len(pkgs32) != 1 {
		t.Fatalf("pkg counts = (%d, %d), want (1, 1)", len(pkgs64), len(pkgs32))
	}
	if got := pkgs64[0].TypesSizes.Sizeof(types.Typ[types.Int]); got != 8 {
		t.Fatalf("amd64 sizeof(int) = %d, want 8", got)
	}
	if got := pkgs32[0].TypesSizes.Sizeof(types.Typ[types.Int]); got != 4 {
		t.Fatalf("386 sizeof(int) = %d, want 4", got)
	}
	c64 := pkgs64[0].Types.Scope().Lookup("WordBytes").(*types.Const).Val().ExactString()
	c32 := pkgs32[0].Types.Scope().Lookup("WordBytes").(*types.Const).Val().ExactString()
	if c64 != "8" || c32 != "4" {
		t.Fatalf("WordBytes = (amd64=%s, 386=%s), want (8, 4)", c64, c32)
	}
	b64 := pkgs64[0].Types.Scope().Lookup("StdIntBits").(*types.Const).Val().ExactString()
	b32 := pkgs32[0].Types.Scope().Lookup("StdIntBits").(*types.Const).Val().ExactString()
	if b64 != "64" || b32 != "32" {
		t.Fatalf("StdIntBits = (amd64=%s, 386=%s), want (64, 32)", b64, b32)
	}
	if got := envLastValue([]string{"GOARCH=amd64", "GOARCH=386"}, "GOARCH"); got != "386" {
		t.Fatalf("envLastValue = %q, want 386", got)
	}
	normA, err := gotool.NormalizeEnv(gotool.SetEnv(baseEnv, "GOARCH", "amd64"))
	if err != nil {
		t.Fatalf("NormalizeEnv(amd64): %v", err)
	}
	normB, err := gotool.NormalizeEnv(gotool.SetEnv(baseEnv, "GOARCH", "386"))
	if err != nil {
		t.Fatalf("NormalizeEnv(386): %v", err)
	}
	if stdlibEnvCacheKey(normA) == stdlibEnvCacheKey(normB) {
		t.Fatal("stdlibEnvCacheKey collided across distinct GOARCH values")
	}
}
