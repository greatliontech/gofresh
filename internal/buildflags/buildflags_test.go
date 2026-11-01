package buildflags

import (
	"context"
	"github.com/greatliontech/gofresh/internal/gotool"
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
		if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), os.Environ()), flags); err == nil || !strings.Contains(err.Error(), "-overlay") {
			t.Fatalf("Validate(%v) = %v, want overlay refusal", flags, err)
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

	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), []string{"-tags=special"}); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("Validate with persistent overlay = %v, want refusal", err)
	}
}

func TestValidateHandlesQuotedAndMalformedGOFLAGS(t *testing.T) {
	dir := t.TempDir()
	// A quoted flag value containing "-overlay=foo" as a substring of another
	// flag's argument is not an overlay flag.
	envNonOverlay := gotool.SetEnv(os.Environ(), "GOFLAGS", `"-ldflags=-X main.v=-overlay=foo"`)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envNonOverlay), nil); err != nil {
		t.Fatalf("Validate(quoted non-overlay GOFLAGS) = %v, want nil", err)
	}

	// A quoted overlay flag with spaces in its path is still rejected.
	envQuotedOverlay := gotool.SetEnv(os.Environ(), "GOFLAGS", `"-overlay=/tmp/with space/overlay.json"`)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envQuotedOverlay), nil); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("Validate(quoted overlay GOFLAGS) = %v, want overlay refusal", err)
	}

	// Malformed quoting in GOFLAGS recorded in an EnvSnapshot is rejected.
	shimDir := t.TempDir()
	shimPath := filepath.Join(shimDir, "go")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\nprintf '{\"GOVERSION\":\"go1.26.0\",\"GOFLAGS\":\"'\"'\"'-tags=unterminated\"}\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	envMalformed := gotool.SetEnv(os.Environ(), "PATH", shimDir)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envMalformed), nil); err == nil || !strings.Contains(err.Error(), "parse GOFLAGS") {
		t.Fatalf("Validate(malformed GOFLAGS) = %v, want parse GOFLAGS error", err)
	}
}
