package closure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func storageOperandNativeImage(t testing.TB, code []byte, cut uint64) (globalNativeFixture, nativeproof.TransitionCertificate) {
	t.Helper()
	const base, data = uint64(0x401000), uint64(0x700000)
	fixture := globalNativeImage(t, [2]uint64{data + 8, data + 80}, [3]uint64{}, data+8, data, nil, "")
	fixture.cut = cut
	copy(fixture.raw[4096:], code)
	binary.LittleEndian.PutUint64(fixture.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(fixture.raw[64+40:], uint64(len(code)))
	var err error
	fixture.image, err = nativeproof.NewImage(t.Context(), fixture.raw)
	if err != nil {
		t.Fatal(err)
	}
	fixture.face.Envelope = nativeproof.RelativeSpan{Start: -64, End: 16}
	fixture.face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}, Readable: true, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
	}
	fixture.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}}
	fixture.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base}
	return fixture, globalNativeProof(t, fixture, false)
}

func narrowOperandNative(t testing.TB, kind x86asm.Op, form, fault string) (globalNativeFixture, nativeproof.TransitionCertificate) {
	t.Helper()
	const base = uint64(0x401000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40, 0xb8, 1, 2, 3, 4, 0x89, 0x44, 0x24, 48, 0x48, 0x8d, 0x5c, 0x24, 48}
	mask := byte(0xf0)
	if fault == "mask" {
		mask ^= 1
	}
	register := byte(0) // AL
	if form != "immediate" {
		value := uint64(0xa7b6c5d4e3f20100) | uint64(mask)
		if form == "high-byte" {
			register = 4 // AH
			value = 0xa7b6c5d4e3f20019 | uint64(mask)<<8
		}
		code = append(code, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	cut := base + uint64(len(code))
	displacement := byte(1)
	if fault == "sibling" {
		displacement = 0
	}
	code = append(code, 0xf0)
	if form == "immediate" {
		opcode, extension := byte(0x80), byte(1) // byte OR immediate
		if kind == x86asm.AND {
			extension = 4
		}
		if fault == "width" {
			opcode = 0x83 // a genuine dword instruction, still unexecuted
		}
		code = append(code, opcode, 0x40|extension<<3|3, displacement, mask)
	} else {
		opcode := byte(0x08)
		if kind == x86asm.AND {
			opcode = 0x20
		}
		code = append(code, opcode, 0x40|register<<3|3, displacement)
	}
	code = append(code, 0xc3)
	return storageOperandNativeImage(t, code, cut)
}

func TestNarrowOperandCorrespondenceByteLogical(t *testing.T) {
	source := relationFixture(t, `type B byte;func Op(*byte,byte);func F(){var m [4]B;m[0]=1;m[1]=2;m[2]=3;m[3]=4;Op((*byte)(&m[1]),0xf0)}`, 64)
	root := source.prog.Roots["F"]
	calls := localEffectCalls(t, root, "Op")
	if len(calls) != 1 {
		t.Fatal("fixture lost its actual call boundary")
	}
	prefix := globalPrefix(t, source, calls[0])
	object := prefix.operands[0].location.object
	for _, kind := range []x86asm.Op{x86asm.OR, x86asm.AND} {
		for _, form := range []string{"immediate", "low-byte", "high-byte"} {
			for _, fault := range []string{"", "mask", "sibling", "width"} {
				if fault == "width" && form != "immediate" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%s", kind, form, fault), func(t *testing.T) {
					fixture, native := narrowOperandNative(t, kind, form, fault)
					bound, owned := native.BoundFor(fixture.image)
					if !owned || bound.Boundary.PC != fixture.cut || bound.Boundary.Instruction.Op != kind || len(bound.PrimitiveEffects) != 0 || len(bound.Accesses) != 1 {
						t.Fatal("native preparation must stop before the byte operation")
					}
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: object, base: nativeproof.TransitionLocation{Offset: -16}}}}
					proof, err := checkGlobalOperandCorrespondence(t.Context(), source, root, calls[0], fixture.image, fixture.entry, fixture.cut, prefix, native, rho)
					if fault == "" {
						if err != nil || proof == nil {
							t.Fatalf("actual byte operand preparation refused: %v", err)
						}
						if len(proof.account.atomics) != 0 || len(proof.account.materialized) != 0 || len(proof.account.eliminated) != 0 || len(proof.account.matched) != len(proof.account.accesses) {
							t.Fatalf("unexpected operand account: atomics=%d materialized=%v eliminated=%v matched=%v source-accesses=%d", len(proof.account.atomics), proof.account.materialized, proof.account.eliminated, proof.account.matched, len(proof.account.accesses))
						}
						for _, match := range proof.account.matched {
							if match.native != 0 {
								t.Fatal("ordinary array construction lost its actual combined store")
							}
						}
						return
					}
					if proof != nil || err == nil {
						t.Fatal("different actual byte operands acquired correspondence")
					}
					switch fault {
					case "mask":
						var refusal *br.Refusal
						if !errors.As(err, &refusal) || refusal.Code != br.Unsupported {
							t.Fatalf("mask did not fail its exact scalar equality: %v", err)
						}
					case "sibling":
						if !strings.Contains(err.Error(), "native operand has another storage origin or subobject") {
							t.Fatalf("sibling pointer failed an unrelated obligation: %v", err)
						}
					case "width":
						if !strings.Contains(err.Error(), "byte logical operand shape differs") {
							t.Fatalf("dword operand failed an unrelated obligation: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestNarrowOperandCorrespondenceImmediateStore(t *testing.T) {
	for _, width := range []int{1, 4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			text := fmt.Sprintf("func Put(*uint%d,uint%d);func F(){var x uint%d;Put(&x,^uint%d(0))}", width*8, width*8, width*8, width*8)
			source := relationFixture(t, text, 64)
			root := source.prog.Roots["F"]
			calls := localEffectCalls(t, root, "Put")
			if len(calls) != 1 {
				t.Fatal("fixture lost its actual store call boundary")
			}
			prefix := globalPrefix(t, source, calls[0])
			for _, wrong := range []bool{false, true} {
				t.Run(fmt.Sprint(wrong), func(t *testing.T) {
					code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40}
					cut := uint64(0x401000 + len(code))
					if width == 8 {
						code = append(code, 0x48)
					}
					opcode, immediateSize := byte(0xc7), 4
					if width == 1 {
						opcode, immediateSize = 0xc6, 1
					}
					code = append(code, opcode, 0x44, 0x24, 48)
					for lane := range immediateSize {
						value := byte(0xff)
						if wrong && lane == 0 {
							value--
						}
						code = append(code, value)
					}
					code = append(code, 0xc3)
					fixture, native := storageOperandNativeImage(t, code, cut)
					bound, owned := native.BoundFor(fixture.image)
					if !owned || len(bound.Accesses) != 0 || len(bound.PrimitiveEffects) != 0 || bound.Boundary.Instruction.Op != x86asm.MOV || bound.Boundary.Instruction.MemBytes != width {
						t.Fatal("unexecuted store acquired execution or initialization")
					}
					rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: prefix.operands[0].location.object, base: nativeproof.TransitionLocation{Offset: -16}}}}
					proof, err := checkGlobalOperandCorrespondence(t.Context(), source, root, calls[0], fixture.image, fixture.entry, fixture.cut, prefix, native, rho)
					if !wrong {
						if err != nil || proof == nil || len(proof.account.materialized) != 0 || len(proof.account.accesses) != 0 {
							t.Fatalf("immediate store preparation demanded old bytes: %v", err)
						}
					} else {
						var refusal *br.Refusal
						if proof != nil || !errors.As(err, &refusal) || refusal.Code != br.Unsupported {
							t.Fatalf("wrong immediate escaped the scalar equality: %v", err)
						}
					}
				})
			}
		})
	}
}
