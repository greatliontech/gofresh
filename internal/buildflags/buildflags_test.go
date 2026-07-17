package buildflags

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsOverlay(t *testing.T) {
	for _, flags := range [][]string{
		{"-overlay=overlay.json"}, {"-overlay", "overlay.json"},
		{"--overlay=overlay.json"}, {"--overlay", "overlay.json"},
	} {
		if err := ValidateEnv(context.Background(), t.TempDir(), os.Environ(), flags); err == nil || !strings.Contains(err.Error(), "-overlay") {
			t.Fatalf("ValidateEnv(context.Background(), %v) = %v, want overlay refusal", flags, err)
		}
	}
}

func TestValidateRejectsPersistentOverlay(t *testing.T) {
	dir := t.TempDir()
	goenv := filepath.Join(dir, "goenv")
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-overlay=overlay.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOFLAGS", "")

	if err := ValidateEnv(context.Background(), dir, os.Environ(), []string{"-tags=special"}); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("Validate with persistent overlay = %v, want refusal", err)
	}
}
