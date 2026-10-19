package nativeproof

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// Intel's CMPXCHG operation writes the accumulator only in the unequal arm.
// The ordinary 32-bit register-write zero extension applies to that write, not
// to the equal arm's memory write. This independent assembly fixture decides
// both full-RAX outputs; neither the semantic kernel nor its byte oracle is used.
func TestTransitionCMPXCHG32AssemblyAccumulator(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes an independent amd64 assembly fixture")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("requires amd64 instruction execution")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/cmpxchgoracle\n\ngo 1.27\n",
		"main.go": `package main
import "fmt"
func cas(p *uint32, accumulator, source uint64) uint64
func main() {
 for _, current := range []uint32{7, 8, 0x80000000, 0xffffffff} {
  for _, equal := range []bool{true, false} {
   expected := current
   if !equal { expected ^= 1 }
   old := uint64(expected) | 0xabcdef0100000000
   memory := current
   result := cas(&memory, old, 0xfedcba9876543210)
   want, after := uint64(current), current
   if equal { want, after = old, 0x76543210 }
   if result != want || memory != after { panic(fmt.Sprintf("equal=%v rax=%x memory=%x want=%x/%x", equal, result, memory, want, after)) }
  }
 }
 fmt.Println("success preserves high RAX; failure zero-extends EAX")
}
`,
		"cas_amd64.s": `#include "textflag.h"
TEXT ·cas(SB), NOSPLIT, $0-32
 MOVQ p+0(FP), CX
 MOVQ accumulator+8(FP), AX
 MOVQ source+16(FP), DX
 LOCK
 CMPXCHGL DX, (CX)
 MOVQ AX, ret+24(FP)
 RET
`,
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := os.Environ()
	for key, value := range map[string]string{"GOOS": runtime.GOOS, "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, key, value)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	binary := filepath.Join(dir, "oracle")
	if _, err := runner.Run(t.Context(), dir, env, "build", "-o", binary, "."); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "success preserves high RAX; failure zero-extends EAX" {
		t.Fatalf("assembly oracle: %s %v", output, err)
	}
}
