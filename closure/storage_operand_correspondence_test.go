package closure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// The stores execute, but the decoded atomic is the unexecuted cut. In
// particular, this fixture needs no source reference or native CAS32 semantics.
func storageOperandNarrowNative(t testing.TB, highA, highD uint32, variant string) (globalNativeFixture, nativeproof.TransitionCertificate) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40} // SUB RSP,64
	mov := func(register byte, value uint64) {
		code = append(code, 0x48, 0xb8+register)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	mov(0, 7)
	code = append(code, 0x89, 0x44, 0x24, 48) // MOV [RSP+48],EAX: Pair.X
	mov(0, 1)
	code = append(code, 0x89, 0x44, 0x24, 52)       // MOV [RSP+52],EAX: Pair.Y
	code = append(code, 0x48, 0x8d, 0x4c, 0x24, 48) // LEA RCX,[RSP+48]: Pair base
	compare, replacement := uint64(1), uint64(2)
	if variant == "wrong-eax" {
		compare = 3
	}
	if variant == "wrong-edx" {
		replacement = 3
	}
	// Full-width seeds deliberately keep different nonzero high halves. An
	// accidental RAX/RDX comparison must not substitute for EAX/EDX equality.
	mov(0, uint64(highA)<<32|compare)
	mov(2, uint64(highD)<<32|replacement)
	cut := base + uint64(len(code))
	code = append(code, 0xf0)
	if variant == "wrong-width" {
		code = append(code, 0x48)
	}
	displacement := byte(4)
	if variant == "sibling-pointer" {
		displacement = 0
	}
	code = append(code, 0x0f, 0xb1, 0x51, displacement, 0xc3) // LOCK CMPXCHG [RCX+disp8],EDX/RDX
	f := globalNativeImage(t, [2]uint64{data + 8, data + 80}, [3]uint64{}, data+8, data, nil, "")
	f.cut = cut
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face.Envelope = nativeproof.RelativeSpan{Start: -64, End: 16}
	f.face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}, Readable: true, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
	}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base}
	return f, globalNativeProof(t, f, false)
}

func TestStorageOperandCorrespondenceNarrowLocal(t *testing.T) {
	source := relationFixture(t, `type Pair struct{ X,Y uint32 };func sink(*uint32,uint32,uint32);func F(){var p Pair;p.X=7;p.Y=1;sink(&p.Y,1,2)}`, 64)
	root := source.prog.Roots["F"]
	var call *ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if candidate, ok := instruction.(*ssa.Call); ok {
				call = candidate
			}
		}
	}
	if call == nil || len(call.Call.StaticCallee().Blocks) != 0 {
		t.Fatal("fixture must stop at an actual bodyless call")
	}
	prefix := globalPrefix(t, source, call)
	packet := prefix.checkedPacket()
	if packet == nil || len(packet.trace.allocations) != 1 || len(packet.trace.accesses) != 2 || len(packet.trace.calls) != 0 || len(packet.trace.atomics) != 0 {
		t.Fatal("source prefix must contain only its allocation and ordinary writes")
	}
	object := packet.trace.allocations[0].location.object
	for sample, high := range [][2]uint32{{0x81234567, 0xfedcba98}, {0xffffffff, 0x80000000}} {
		t.Run(fmt.Sprint(sample), func(t *testing.T) {
			for _, variant := range []string{"prepared", "wrong-eax", "wrong-edx", "sibling-pointer", "wrong-width"} {
				t.Run(variant, func(t *testing.T) {
					fixture, native := storageOperandNarrowNative(t, high[0], high[1], variant)
					bound, owned := native.BoundFor(fixture.image)
					if !owned || bound.Boundary.PC != fixture.cut || bound.Boundary.Instruction.Op != x86asm.CMPXCHG || len(bound.PrimitiveEffects) != 0 || len(bound.Accesses) != 2 {
						t.Fatal("native baseline must stop before executing the atomic")
					}
					for index, access := range bound.Accesses {
						want := nativeproof.RelativeSpan{Start: -16 + int64(4*index), End: -12 + int64(4*index)}
						if access.Image || access.Kind != nativeproof.FrameWrite || access.Bytes != want {
							t.Fatal("native baseline lost the ordinary local materialization")
						}
					}
					for _, cell := range bound.InitialMemory {
						if !cell.Image && cell.Offset >= -16 && cell.Offset < -8 && cell.Value.View().Op != br.Variable {
							t.Fatal("local native input was initialized instead of arbitrary")
						}
					}
					for index, register := range []nativeproof.Register{nativeproof.RAX, nativeproof.RDX} {
						value, err := br.Eval(t.Context(), bound.Registers[register].Value, nil, br.Limits{})
						if err != nil || uint32(value>>32) != high[index] {
							t.Fatalf("full register lost its nonzero high bits: value=%#x error=%v", value, err)
						}
					}
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: nativeproof.TransitionLocation{Offset: -16}}}}
					proof, err := checkGlobalOperandCorrespondence(t.Context(), source, root, call, fixture.image, fixture.entry, fixture.cut, prefix, native, rho)
					if variant == "prepared" {
						if err != nil || proof == nil {
							t.Fatalf("narrow operand preparation refused: %v", err)
						}
						footprint, represented := proof.account.layout.locationFootprint(prefix.operands[0].location)
						if !represented || footprint.Image || footprint.Bytes != (nativeproof.RelativeSpan{Start: -12, End: -8}) || len(proof.account.inputs) != 0 || len(proof.account.atomics) != 0 || len(proof.account.matched) != 2 || len(proof.account.equalities) == 0 {
							t.Fatal("proof lost subobject/materialization evidence or invented local input/atomic semantics")
						}
						return
					}
					if err == nil || proof != nil {
						t.Fatal("incorrect actual narrow operands accepted")
					}
					switch variant {
					case "wrong-eax", "wrong-edx":
						var refusal *br.Refusal
						if !errors.As(err, &refusal) || refusal.Code != br.Unsupported {
							t.Fatalf("low operand did not fail its equality: %v", err)
						}
					case "sibling-pointer":
						if !strings.Contains(err.Error(), "native operand has another storage origin or subobject") {
							t.Fatalf("sibling pointer refused for an unrelated premise: %v", err)
						}
					case "wrong-width":
						if !strings.Contains(err.Error(), "native operand width or address mode differs") {
							t.Fatalf("wide operand refused for an unrelated premise: %v", err)
						}
					}
				})
			}
		})
	}
}
