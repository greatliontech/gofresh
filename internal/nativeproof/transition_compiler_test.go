package nativeproof

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"golang.org/x/arch/x86/x86asm"
)

// Discovery follows actual direct transfers from the format entry and proposes
// the boundary after two stack spills. Its instruction count is only a search
// limit; exhausting it fails the test, never supplies a certificate. No symbol,
// version, fixed address or digest is supplied as semantic authority.
func discoverEntrySpillCut(t testing.TB, im *Image) uint64 {
	t.Helper()
	pc, spills := im.entry, 0
	seen := map[uint64]bool{}
	for n := 0; n < 128; n++ {
		if seen[pc] {
			t.Fatal("candidate discovery encountered a cycle")
		}
		seen[pc] = true
		bytes, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(bytes, 64)
		if err != nil {
			t.Fatal(err)
		}
		next := pc + uint64(i.Len)
		if i.Op == x86asm.MOV {
			if mem, ok := i.Args[0].(x86asm.Mem); ok && mem.Base == x86asm.RSP && mem.Index == 0 && i.MemBytes == 8 {
				spills++
			}
		}
		if spills == 2 {
			return next
		}
		if i.Op == x86asm.JMP {
			rel, ok := i.Args[0].(x86asm.Rel)
			if !ok {
				t.Fatal("indirect entry transfer")
			}
			next += uint64(rel)
		}
		pc = next
	}
	t.Fatal("no candidate entry spill boundary discovered")
	return 0
}

func TestTransitionOptimizedArtifacts(t *testing.T) {
	if testing.Short() {
		t.Skip("builds one ordinary optimized ELF and reads the selected compiler")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected native compiler must be linux/amd64")
	}
	fixture, _, _ := buildCompilerFixture(t)
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	toolDir, err := runner.Run(t.Context(), "", os.Environ(), "env", "GOTOOLDIR")
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(toolDir)), "compile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct {
		name string
		data []byte
	}{{"ordinary-optimized", fixture}, {"selected-compiler", compiler}} {
		t.Run(artifact.name, func(t *testing.T) {
			im, err := NewImage(t.Context(), artifact.data)
			if err != nil {
				t.Fatal(err)
			}
			cut := discoverEntrySpillCut(t, im)
			c, err := proveTransition(t, im, cut, transitionFace())
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if b.Registers[RSP].Pointer.Offset != -48 || b.Registers[RSI].Pointer.Offset != 8 || b.Registers[RBX].Pointer.Offset != 8 || len(b.Accesses) != 3 {
				t.Fatal("unexpected actual spill relation", b.Accesses)
			}
			assertTransitionOracle(t, im, b, 40)
			t.Logf("actual ELF entry=%#x validated unexecuted cut=%#x, %d executed instructions; conditional native state only", b.Entry, b.Boundary.PC, len(b.Instructions))
		})
	}
}
