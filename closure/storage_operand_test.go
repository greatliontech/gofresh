package closure

import (
	"math"
	"testing"

	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestStorageBoundaryCoordinates(t *testing.T) {
	_, bound := storageGeometryFixture(t, 0)
	_, foreign := storageGeometryFixture(t, 0)
	stack := bound.Registers[nativeproof.RCX].Pointer
	image := bound.Registers[nativeproof.R14].Pointer
	for _, test := range []struct {
		name    string
		pointer nativeproof.TransitionPointer
		memory  x86asm.Mem
		want    nativeproof.StorageSelector
		width   int64
	}{
		{"stack-subobject", stack, x86asm.Mem{Base: x86asm.RCX, Disp: 3}, nativeproof.StackOffset(-21), 1},
		{"image-subobject", image, x86asm.Mem{Base: x86asm.RCX, Disp: 4}, nativeproof.ImageAddress(0x1004), 4},
		{"fs-owned-view", image, x86asm.Mem{Segment: x86asm.FS, Disp: 4}, nativeproof.ImageAddress(0x1004), 4},
		{"fs-foreign-view", foreign.Registers[nativeproof.R14].Pointer, x86asm.Mem{Segment: x86asm.FS}, nil, 1},
		{"rip-next-address", nil, x86asm.Mem{Base: x86asm.RIP, Disp: 0x1000 - 0x401007}, nativeproof.ImageAddress(0x1000), 8},
		{"foreign-origin", foreign.Registers[nativeproof.RCX].Pointer, x86asm.Mem{Base: x86asm.RCX}, nil, 1},
		{"foreign-image", foreign.Registers[nativeproof.R14].Pointer, x86asm.Mem{Base: x86asm.RCX}, nil, 1},
		{"unproved-bits", nil, x86asm.Mem{Base: x86asm.RCX}, nil, 1},
		{"partial-base", image, x86asm.Mem{Base: x86asm.ECX}, nil, 1},
		{"unaccounted-index", image, x86asm.Mem{Base: x86asm.RCX, Index: x86asm.RAX, Scale: 1}, nil, 1},
		{"segment-with-base", image, x86asm.Mem{Base: x86asm.RCX, Segment: x86asm.FS}, nil, 1},
		{"image-underflow", image, x86asm.Mem{Base: x86asm.RCX, Disp: -0x1001}, nil, 1},
		{"image-ceiling", image, x86asm.Mem{Base: x86asm.RCX, Disp: 1 << 47}, nil, 1},
		{"signed-overflow", stack, x86asm.Mem{Base: x86asm.RCX, Disp: math.MaxInt64}, nil, 1},
		{"signed-underflow", stack, x86asm.Mem{Base: x86asm.RCX, Disp: math.MinInt64}, nil, 1},
		{"full-width-unmapped", stack, x86asm.Mem{Base: x86asm.RCX, Disp: 151}, nil, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := bound
			current.Registers[nativeproof.RCX].Pointer = test.pointer
			current.Thread.FS.Pointer = test.pointer
			got, valid := storageBoundaryLocation(t.Context(), current, test.memory, test.width)
			if valid != (test.want != nil) {
				t.Fatalf("extent=%+v valid=%t", got, valid)
			}
			if valid && got != storageTestExtent(t, bound.Geometry, test.want, test.width) {
				t.Fatal("wrong owned extent")
			}
		})
	}
}
