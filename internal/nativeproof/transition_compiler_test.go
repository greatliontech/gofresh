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
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
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
			if requireStackPointer(t, b.Registers[RSP].Pointer).Offset != -48 || requireStackPointer(t, b.Registers[RSI].Pointer).Offset != 8 || requireStackPointer(t, b.Registers[RBX].Pointer).Offset != 8 || len(b.Accesses) != 3 {
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
					if next.Registers[reg].Pointer != nil || next.Preserved[reg] != 0 {
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
			fetches := straightFetches(t, next)
			if !reflect.DeepEqual(next.Memory, b.Memory) || !reflect.DeepEqual(next.Accesses, b.Accesses) || next.Flags != b.Flags || len(next.Instructions) != len(b.Instructions)+1 || !slices.Equal(next.Instructions[:len(b.Instructions)], b.Instructions) || fetches[len(b.Instructions)] != (Span{b.Boundary.PC, nextCut}) {
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
			// RIP LEA now has a checked rule and needs no data-access footprint.
			// The following stack-relative LEA still exceeds this old root's
			// envelope. Continuation cannot strengthen that quantified premise.
			raw, err := im.instructionBytes(after)
			if err != nil {
				t.Fatal(err)
			}
			stackLEA, err := x86asm.Decode(raw, 64)
			stackIntent, parseErr := to.Parse(raw, after)
			if err != nil || parseErr != nil || stackLEA.Op != x86asm.LEA || stackIntent.Intent.Operation != to.LEA || stackIntent.Intent.Base != 4 || stackIntent.Intent.SignedDisp != -65536 {
				t.Fatal("following candidate is not the stack-relative LEA", err)
			}
			end := after + uint64(stackLEA.Len)
			attempt := proposal
			attempt.Cut, attempt.Nodes = end, slices.Clone(proposal.Nodes)
			for i := range attempt.Nodes {
				attempt.Nodes[i].Successors = slices.Clone(attempt.Nodes[i].Successors)
				if attempt.Nodes[i].PC == nextCut {
					attempt.Nodes[i].Successors = []uint64{after}
				}
			}
			raw, err = im.instructionBytes(end)
			if err != nil {
				t.Fatal(err)
			}
			boundary, err := x86asm.Decode(raw, 64)
			if err != nil || boundary.Len <= 0 {
				t.Fatal("following candidate boundary is unavailable", err)
			}
			attempt.Nodes = append(attempt.Nodes, Node{PC: after, Size: uint8(stackLEA.Len), Successors: []uint64{end}}, Node{PC: end, Size: uint8(boundary.Len)})
			proposed, err := ProposeTransition(t.Context(), im, end, TransitionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			stateSameInventory(t, proposed, attempt)
			unsupported, err := CheckTransitionContinuation(t.Context(), continued, attempt)
			var refusal *Refusal
			if _, valid := unsupported.Bound(); valid || !errors.As(err, &refusal) || refusal.PC != after || refusal.Premise != "transition-envelope" {
				t.Fatal("checker strengthened the inherited envelope or lost its refusal boundary", err)
			}
			still, _ := c.Bound()
			if !reflect.DeepEqual(still, b) {
				t.Fatal("actual continuation changed its retained predecessor")
			}
			t.Logf("actual continuation executes [%#x,%#x); next RIP-relative instruction remains unexecuted", b.Boundary.PC, nextCut)
			checkOptimizedImagePrefix(t, im, nextCut)
		})
	}
}

// Decoded bytes locate the candidate image address and CPU-query cut. Neither
// compiler names nor symbols supply a memory value, storage relation or theorem.
func checkOptimizedImagePrefix(t testing.TB, im *Image, ripPC uint64) {
	t.Helper()
	pc, address, cut := ripPC, uint64(0), uint64(0)
	for n := 0; n < 32; n++ {
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(raw, 64)
		if err != nil || i.Len <= 0 {
			t.Fatal("candidate decode", err)
		}
		if pc == ripPC {
			mem, ok := i.Args[1].(x86asm.Mem)
			if i.Op != x86asm.LEA || !ok || mem.Base != x86asm.RIP {
				t.Fatal("candidate lost RIP address")
			}
			intent, err := to.Parse(raw, pc)
			if err != nil || intent.Intent.Operation != to.LEARIP {
				t.Fatal("candidate RIP encoding", err)
			}
			var valid bool
			address, valid = relative(pc+uint64(i.Len), intent.Intent.SignedDisp)
			if !valid {
				t.Fatal("candidate wraps")
			}
		}
		if i.Op == x86asm.CPUID {
			cut = pc
			break
		}
		pc += uint64(i.Len)
	}
	if cut == 0 {
		t.Fatal("no CPU-query candidate; discovery budget is not an endpoint")
	}
	face := transitionFace()
	face.Envelope.Start = -65584
	face.Origin.Min = 65584
	face.ImageRegions = []Span{{address, address + 32}}
	// Re-derive from the ELF entry under the broader ORIGINAL envelope/domain.
	// The earlier narrow certificate cannot be extended into these assumptions.
	root := continuationRoot(t, im, ripPC, face, TransitionLimits{})
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	image, ok := b.Registers[RDI].Pointer.(ImagePointer)
	if !ok || image.Address != address || image.owner != &im.data[0] {
		t.Fatal("actual image address/provenance differs")
	}
	if requireStackPointer(t, b.Registers[RSP].Pointer).Offset != -48 || requireStackPointer(t, b.Registers[RBX].Pointer).Offset != -65584 {
		t.Fatal("actual stack-relative values differ")
	}
	for _, reg := range []Register{RBP, RAX} {
		if b.Registers[reg].Pointer != nil || stateEval(t, b.Registers[reg].Value, nil) != 0 {
			t.Fatal("actual zero result differs")
		}
	}
	count := 0
	for _, cell := range b.Memory {
		if !cell.Image {
			continue
		}
		count++
		off := cell.Offset - int64(address)
		want := int64(-65584)
		if off >= 8 && off < 16 {
			want = -48
		}
		if off < 0 || off >= 32 || cell.Pointer != (OriginPointer{b.Origin, want}) || cell.PointerLane != uint8(off%8) {
			t.Fatalf("actual image word/lane differs at offset %d: pointer=%+v lane=%d, want stack offset %d", off, cell.Pointer, cell.PointerLane, want)
		}
		for _, s := range []uint64{1 << 32, 1 << 40, 1 << 46} {
			if stateEval(t, cell.Value, map[br.Term]uint64{b.Origin: s}) != uint64(byte((s+uint64(want))>>(8*(off%8)))) {
				t.Fatal("actual image byte relation differs")
			}
		}
	}
	if count != 32 || len(b.Accesses) != 7 {
		t.Fatal("actual image footprint/access count differs")
	}
	for j, off := range []int64{16, 24, 0, 8} {
		a := b.Accesses[j+3]
		if !a.Image || a.Kind != FrameWrite || a.Bytes != (RelativeSpan{int64(address) + off, int64(address) + off + 8}) {
			t.Fatal("actual image store order differs")
		}
	}
	if b.Boundary.Instruction.Op != x86asm.CPUID || !bytes.Equal(b.Boundary.Bytes, []byte{0x0f, 0xa2}) {
		t.Fatal("actual CPU-query boundary differs")
	}
	direct, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, c)
	assertCPUQueryExecutionRefused(t, im, face, p, c)
	assertImagePrefixMissingPremises(t, im, face, p, ripPC)
	// The selected bytes use CMP EAX,0, not TEST. Neither form is executed by
	// this query-only continuation; the image determines the boundary evidence.
	assertCPUQueryConditionalStep(t, im, face, p, x86asm.CMP)
	checkOptimizedGuarded(t, im, face, cut)
	t.Logf("conditional image prefix reaches unexecuted CPU query %#x; arbitrary image inputs, 32 overwritten bytes at %#x", cut, address)
}
