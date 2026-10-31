package testenv

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
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
