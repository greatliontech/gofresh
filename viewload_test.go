package gofresh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// One observation pass performs exactly one typed package load — the subject
// scan and the closure tier's testing-type effect scan share it — so view
// construction's paired observations perform exactly two
// (REQ-fresh-coherent-view: no same-pass mixture, passes stay independent).
// The count is taken at the go-command boundary: every typed load drives
// exactly one `go list … -json=<fields> …` invocation. That one-call-per-Load
// shape is golang.org/x/tools/go/packages driver behavior, not a gofresh
// property — if an x/tools upgrade changes how many list calls one Load
// issues, this count moves without any sharing regression; recalibrate the
// expected count against a single packages.Load before suspecting the code.
func TestViewObservationPassPerformsOneTypedLoad(t *testing.T) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shimDir := t.TempDir()
	logPath := filepath.Join(shimDir, "typed-loads.log")
	script := "#!/bin/sh\nfor arg in \"$@\"; do\n\tcase \"$arg\" in\n\t-json=*) echo typed-load >> " + logPath + " ;;\n\tesac\ndone\nexec " + realGo + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/oneload\n\ngo 1.26\n",
		"lib.go":      "package oneload\n\nfunc F() int { return 1 }\n",
		"lib_test.go": "package oneload\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewViewFor(context.Background(), []Subject{{Package: "example.com/oneload", Symbol: "F"}}, dir, CodeResult); err != nil {
		t.Fatal(err)
	}

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no typed loads logged at all: %v", err)
	}
	if got := strings.Count(string(logged), "typed-load"); got != 2 {
		t.Fatalf("view construction drove %d typed package loads, want exactly 2 (one per paired observation pass)", got)
	}
}

// One observation pass performs one `go env -json` read (the snapshot) and
// derives GOFLAGS validation and GOMODCACHE from it; only `go version`
// stays a live probe (its string carries the host platform). Construction's
// pair therefore shows exactly two env reads and two version probes, and
// zero single-key env execs (the batched-probe contract). The env-json
// matcher is x/tools-version-coupled: some driver versions issue key-scoped
// `go env -json GOMOD` calls that would match the same arm - if this count
// moves on an x/tools upgrade, recalibrate against a single packages.Load
// before suspecting the batching.
func TestViewObservationPassBatchesToolchainProbes(t *testing.T) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shimDir := t.TempDir()
	logPath := filepath.Join(shimDir, "probes.log")
	script := "#!/bin/sh\ncase \"$1 $2\" in\n\"env -json\") echo env-json >> " + logPath + " ;;\n\"env GOFLAGS\") echo env-goflags >> " + logPath + " ;;\n\"env GOMODCACHE\") echo env-gomodcache >> " + logPath + " ;;\n\"version \") echo version >> " + logPath + " ;;\nesac\nexec " + realGo + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/probes\n\ngo 1.26\n",
		"lib.go":      "package probes\n\nfunc F() int { return 1 }\n",
		"lib_test.go": "package probes\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	// Engine construction performs its own one-time validation probe; the
	// batched-probe contract is per observation pass, so the count window
	// opens here.
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewViewFor(context.Background(), []Subject{{Package: "example.com/probes", Symbol: "F"}}, dir, CodeResult); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no probes logged: %v", err)
	}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		counts[line]++
	}
	if counts["env-json"] != 2 || counts["version"] != 2 || counts["env-goflags"] != 0 || counts["env-gomodcache"] != 0 {
		t.Fatalf("construction probe counts = %v, want env-json:2 version:2 and no single-key env execs", counts)
	}
}
