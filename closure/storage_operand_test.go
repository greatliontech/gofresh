package closure

import (
	"math"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestStorageBoundaryCoordinates(t *testing.T) {
	builder := br.NewBuilder(8)
	origin, err := builder.Input(br.Bits(64), br.NewScope(), 0)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := builder.Input(br.Bits(64), br.NewScope(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		pointer nativeproof.TransitionPointer
		memory  x86asm.Mem
		want    nativeproof.TransitionLocation
		valid   bool
	}{
		{"stack-subobject", nativeproof.OriginPointer{Origin: origin, Offset: -24}, x86asm.Mem{Base: x86asm.RCX, Disp: 3}, nativeproof.TransitionLocation{Offset: -21}, true},
		{"image-subobject", nativeproof.ImagePointer{Address: 0x700008}, x86asm.Mem{Base: x86asm.RCX, Disp: 4}, nativeproof.TransitionLocation{Image: true, Offset: 0x70000c}, true},
		{"rip-next-address", nil, x86asm.Mem{Base: x86asm.RIP, Disp: 0x1000}, nativeproof.TransitionLocation{Image: true, Offset: 0x402007}, true},
		{"foreign-origin", nativeproof.OriginPointer{Origin: foreign, Offset: -24}, x86asm.Mem{Base: x86asm.RCX}, nativeproof.TransitionLocation{}, false},
		{"unproved-bits", nil, x86asm.Mem{Base: x86asm.RCX}, nativeproof.TransitionLocation{}, false},
		{"partial-base", nativeproof.ImagePointer{Address: 0x700008}, x86asm.Mem{Base: x86asm.ECX}, nativeproof.TransitionLocation{}, false},
		{"unaccounted-index", nativeproof.ImagePointer{Address: 0x700008}, x86asm.Mem{Base: x86asm.RCX, Index: x86asm.RAX, Scale: 1}, nativeproof.TransitionLocation{}, false},
		{"segment-base", nativeproof.ImagePointer{Address: 0x700008}, x86asm.Mem{Base: x86asm.RCX, Segment: x86asm.FS}, nativeproof.TransitionLocation{}, false},
		{"image-underflow", nativeproof.ImagePointer{Address: 1}, x86asm.Mem{Base: x86asm.RCX, Disp: -2}, nativeproof.TransitionLocation{}, false},
		{"image-ceiling", nativeproof.ImagePointer{Address: (1 << 47) - 1}, x86asm.Mem{Base: x86asm.RCX, Disp: 1}, nativeproof.TransitionLocation{}, false},
		{"signed-overflow", nativeproof.OriginPointer{Origin: origin, Offset: math.MaxInt64}, x86asm.Mem{Base: x86asm.RCX, Disp: 1}, nativeproof.TransitionLocation{}, false},
		{"signed-underflow", nativeproof.OriginPointer{Origin: origin, Offset: math.MinInt64}, x86asm.Mem{Base: x86asm.RCX, Disp: -1}, nativeproof.TransitionLocation{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			bound := nativeproof.TransitionBound{Origin: origin, Boundary: nativeproof.CutBoundary{PC: 0x401000, Bytes: make([]byte, 7)}}
			bound.Registers[nativeproof.RCX].Pointer = test.pointer
			got, valid := storageBoundaryLocation(bound, test.memory)
			if valid != test.valid || valid && got != test.want {
				t.Fatalf("coordinate=%+v valid=%t; want %+v valid=%t", got, valid, test.want, test.valid)
			}
		})
	}
}
