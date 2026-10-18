//go:build linux && !android

package assemblycapture

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func sealFixture(t *testing.T, s *Selection) {
	t.Helper()
	parsed := map[string][]byte{}
	var roots []string
	for _, p := range s.Packages() {
		if p.Root {
			roots = append(roots, p.ID)
		}
		if p.Path == "unsafe" {
			continue
		}
		for _, path := range p.GoFiles {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			parsed[path] = data
		}
	}
	if err := s.Seal(t.Context(), parsed, roots); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireCurrentFinalAssembly(t *testing.T) {
	if testing.Short() {
		t.Skip("cold tool-boundary acquisition")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture assembly is amd64")
	}
	dir := t.TempDir()
	put(t, filepath.Join(dir, "go.mod"), "module example.com/capture\n\ngo 1.27.0\n")
	put(t, filepath.Join(dir, "ops.go"), "package capture\nconst Stage = 1\nfunc Swap(p *uint64, old, next uint64) bool\n")
	put(t, filepath.Join(dir, "ops.s"), `#include "textflag.h"
#include "go_asm.h"
#ifdef const_Stage
#define CHOICE SETEQ
#else
#define CHOICE SETNE
#endif
TEXT ·Swap(SB), NOSPLIT, $0-25
MOVQ p+0(FP), BX
MOVQ old+8(FP), AX
MOVQ next+16(FP), CX
LOCK
CMPXCHGQ CX, (BX)
CHOICE ret+24(FP)
RET
`)
	originalOutput := filepath.Join(dir, "original-output")
	put(t, originalOutput, "independently owned output")
	flags := []string{"-asmflags=all=-D PRECEDENCE=bad", "-asmflags=example.com/capture=-D PRECEDENCE=good", "-gcflags=example.com/capture=-N -l", "-o", originalOutput}
	s, err := BeginSelection(t.Context(), gotool.Runner{}, Request{Dir: dir, Env: os.Environ(), Flags: flags, Roots: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}
	sealFixture(t, s)
	packet, err := Acquire(t.Context(), s, "example.com/capture", Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !packet.BoundTo(s, "example.com/capture") || packet.BoundTo(&Selection{}, "example.com/capture") {
		t.Fatal("selection owner identity lost")
	}
	t.Logf("cumulative protected input usage: %+v", packet.Usage())
	providers := packet.Providers()
	if len(providers) != 1 {
		t.Fatalf("provider roster: %+v", providers)
	}
	text := providerText(providers[0])
	if !strings.Contains(text, "SETEQ ret") || strings.Contains(text, "SETNE") {
		t.Fatalf("final generated header not captured:\n%s", text)
	}
	if !slices.Contains(providers[0].Invocation.Defines, "PRECEDENCE=good") || slices.Contains(providers[0].Invocation.Defines, "PRECEDENCE=bad") {
		t.Fatalf("per-package precedence changed: %v", providers[0].Invocation.Defines)
	}
	if len(packet.compilers) != 1 || !slices.Contains(packet.compilers[0].Args, "-N") || !slices.Contains(packet.compilers[0].Args, "-l") {
		t.Fatalf("compiler options changed: %+v", packet.compilers)
	}
	foundHeader := false
	for name, data := range packet.Files() {
		if filepath.Base(name) == "go_asm.h" {
			foundHeader = true
			if !strings.Contains(string(data), "const_Stage") {
				t.Fatalf("captured preliminary empty header: %q", data)
			}
		}
	}
	if !foundHeader {
		t.Fatal("generated header omitted")
	}
	if data, err := os.ReadFile(originalOutput); err != nil || string(data) != "independently owned output" {
		t.Fatalf("acquisition replaced original output: %q/%v", data, err)
	}
	providers[0].Lines[0].Tokens[0] = "CORRUPTED"
	providers[0].Invocation.Args[0] = "CORRUPTED"
	if strings.Contains(providerText(packet.Providers()[0]), "CORRUPTED") || packet.Providers()[0].Invocation.Args[0] == "CORRUPTED" {
		t.Fatal("packet projection aliases owner")
	}
	put(t, filepath.Join(dir, "ops.go"), "package capture\nconst Stage = 2\nfunc Swap(p *uint64, old, next uint64) bool\n")
	if err = s.Validate(t.Context()); err == nil {
		t.Fatal("source-owner drift accepted")
	}
}

func TestCaptureRefusesMissingActionsAndUnsealedOwner(t *testing.T) {
	ctx := t.Context()
	if _, err := Acquire(ctx, &Selection{}, "ops", Limits{}); err == nil {
		t.Fatal("unsealed owner accepted")
	}
	c := &captureServer{selection: &Selection{}, provider: Package{ID: "ops", Assembly: []string{"a.s"}}}
	if _, err := c.finish(); err == nil {
		t.Fatal("empty/cache-only action roster accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Acquire(cancelled, nil, "ops", Limits{}); err != context.Canceled {
		t.Fatalf("cancel=%v", err)
	}
}

func TestCaptureRejectsPreexistingInterposition(t *testing.T) {
	for _, flags := range [][]string{{"-toolexec=wrapper"}, {"-toolexec", "wrapper"}} {
		s := &Selection{request: Request{Flags: flags}, goenv: map[string]string{}}
		if err := s.validateRequest(); err == nil {
			t.Fatal("user interposition silently replaced")
		}
	}
	s := &Selection{goenv: map[string]string{"GOFLAGS": "'-toolexec=with spaces'"}}
	if err := s.validateRequest(); err == nil {
		t.Fatal("GOFLAGS interposition silently replaced")
	}
}
