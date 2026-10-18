package nativeproof

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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
			// Locate the next candidate from this artifact's checked boundary,
			// then consume the opaque predecessor. No state or interface is
			// reconstructed from its public projection.
			if !bytes.Equal(b.Boundary.Bytes, []byte{0xbd, 0, 0, 0, 0}) || b.Boundary.Instruction.Op != x86asm.MOV || b.Boundary.Instruction.Args[0] != x86asm.EBP {
				t.Fatal("selected startup boundary is not the expected base-pointer initialization")
			}
			nextCut := b.Boundary.PC + uint64(len(b.Boundary.Bytes))
			proposal, err := ProposeTransition(t.Context(), im, nextCut, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			continued, err := CheckTransitionContinuation(t.Context(), c, proposal)
			if err != nil {
				t.Fatal(err)
			}
			next, ok := continued.Bound()
			if !ok || next.ImageDigest != b.ImageDigest || next.Entry != b.Entry || next.Boundary.PC != nextCut || next.Origin != b.Origin || next.InitialRegisters != b.InitialRegisters || !reflect.DeepEqual(next.Interface, b.Interface) || !reflect.DeepEqual(next.InitialMemory, b.InitialMemory) || !reflect.DeepEqual(next.Words, b.Words) {
				t.Fatal("actual continuation lost the predecessor's image or input binding")
			}
			for reg := RAX; reg <= R15; reg++ {
				if reg == RBP {
					if next.Registers[reg].Pointer.Origin.Valid() || next.Preserved[reg] != 0 {
						t.Fatal("base-pointer initialization retained pointer or preservation authority")
					}
					for _, scratch := range []uint64{0, ^uint64(0)} {
						if evalRelationTerm(t, next.Registers[reg].Value, nil, scratch) != 0 {
							t.Fatal("actual MOV EBP,0 did not produce full-width zero")
						}
					}
				} else if next.Registers[reg] != b.Registers[reg] || next.Preserved[reg] != b.Preserved[reg] {
					t.Fatal("base-pointer initialization changed another register", reg)
				}
			}
			if !reflect.DeepEqual(next.Memory, b.Memory) || !reflect.DeepEqual(next.Accesses, b.Accesses) || next.Flags != b.Flags || len(next.Instructions) != len(b.Instructions)+1 || !slices.Equal(next.Instructions[:len(b.Instructions)], b.Instructions) || next.Instructions[len(b.Instructions)] != (Span{b.Boundary.PC, nextCut}) {
				t.Fatal("actual continuation changed the frame or failed to execute the former cut exactly once")
			}
			assertTransitionOracle(t, im, next, 40)
			// The following RIP-relative address construction is retained as an
			// unexecuted operation. Its target's symbol supplies no storage fact.
			mem, memory := next.Boundary.Instruction.Args[1].(x86asm.Mem)
			if next.Boundary.Instruction.Op != x86asm.LEA || !memory || mem.Base != x86asm.RIP {
				t.Fatal("selected next boundary is not the expected RIP-relative address construction")
			}
			after := nextCut + uint64(len(next.Boundary.Bytes))
			_, err = ProposeTransition(t.Context(), im, after, TransitionLimits{})
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.PC != nextCut || refusal.Premise != "transition-form" {
				t.Fatal("next operation did not retain its explicit form obligation", err)
			}
			// Supply the otherwise complete candidate inventory ourselves as well:
			// a proposer refusal cannot stand in for the checker's refusal.
			attempt := proposal
			attempt.Cut, attempt.Nodes = after, slices.Clone(proposal.Nodes)
			for i := range attempt.Nodes {
				attempt.Nodes[i].Successors = slices.Clone(attempt.Nodes[i].Successors)
				if attempt.Nodes[i].PC == nextCut {
					attempt.Nodes[i].Successors = []uint64{after}
				}
			}
			raw, err := im.instructionBytes(after)
			if err != nil {
				t.Fatal(err)
			}
			boundary, err := x86asm.Decode(raw, 64)
			if err != nil || boundary.Len <= 0 {
				t.Fatal("following candidate boundary is unavailable", err)
			}
			attempt.Nodes = append(attempt.Nodes, Node{PC: after, Size: uint8(boundary.Len)})
			unsupported, err := CheckTransitionContinuation(t.Context(), continued, attempt)
			if _, valid := unsupported.Bound(); valid || !errors.As(err, &refusal) || refusal.PC != nextCut || refusal.Premise != "transition-form" {
				t.Fatal("checker accepted the unsupported next operation or lost its refusal boundary", err)
			}
			still, _ := c.Bound()
			if !reflect.DeepEqual(still, b) {
				t.Fatal("actual continuation changed its retained predecessor")
			}
			t.Logf("actual continuation executes [%#x,%#x); next RIP-relative instruction remains unexecuted", b.Boundary.PC, nextCut)
		})
	}
}
