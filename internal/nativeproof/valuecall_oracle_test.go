package nativeproof

import (
	"math/bits"
	"math/rand/v2"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Concrete ISA execution is independent of known-bit propagation and predicate
// exclusion. It shares the decoder and the existing concrete scalar oracle only.
func checkValueCallOracle(t testing.TB, im *Image, b ValueCallBound, samples int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(193, 991))
	f := b.Request.Interface
	for sample := 0; sample < samples; sample++ {
		slot := Span{}
		o := concreteFrame{t: t, im: im, b: FrameBound{Accesses: b.Accesses, Interface: FrameInterface{Regions: f.Regions, Stack: f.Stack, Protected: f.Protected, Preserved: f.Preserved}}, memory: map[uint64]byte{}, permissions: map[uint64]uint8{}, pc: b.Request.Entry, returnSlot: &slot}
		for r := range o.regs {
			o.regs[r] = rng.Uint64()
		}
		if sample%2 == 0 {
			o.regs[R9] = 0
		}
		var vectors [16][16]byte
		for r := range vectors {
			for j := range vectors[r] {
				vectors[r][j] = byte(rng.Uint32())
			}
		}
		initialVectors := vectors
		for _, r := range f.Regions {
			for a := r.Bytes.Start; a < r.Bytes.End; a++ {
				if _, ok := o.memory[a]; !ok {
					o.memory[a] = byte(rng.Uint32())
				}
				if r.Readable {
					o.permissions[a] |= 1
				}
				if r.Writable {
					o.permissions[a] |= 2
				}
			}
		}
		for _, span := range f.Readonly {
			data, _, err := im.readonlyBytes(span.Start, span.End-span.Start, "oracle", "oracle")
			if err != nil {
				t.Fatal(err)
			}
			for j, v := range data {
				o.memory[span.Start+uint64(j)] = v
			}
		}
		pointer := func(p RegionPointer) uint64 { return f.Regions[p.Region].Bytes.Start + p.Min }
		for _, p := range f.Pointers {
			o.regs[p.Register] = pointer(p.Pointer)
		}
		for _, v := range f.Scalars {
			o.regs[v.Register] = o.regs[v.Register]&^v.Bits | v.Value
		}
		o.regs[RSP] = pointer(f.Stack)
		for _, p := range f.MemoryPointers {
			v := pointer(p.Pointer)
			for j := 0; j < 8; j++ {
				o.memory[p.Address+uint64(j)] = byte(v >> uint(j*8))
			}
		}
		for _, v := range f.StackValues {
			for j := 0; j < v.Width; j++ {
				o.memory[v.Address+uint64(j)] = byte(v.Value >> uint(j*8))
			}
		}
		before := o.regs
		called, returned := false, false
		for step := 0; step <= len(b.Instructions); step++ {
			raw, err := im.instructionBytes(o.pc)
			if err != nil {
				t.Fatal(err)
			}
			i := oracleInstruction(t, raw)
			next := o.pc + uint64(i.Len)
			vec := func(arg x86asm.Arg) int {
				r, ok := arg.(x86asm.Reg)
				if !ok || r < x86asm.X0 || r > x86asm.X15 {
					t.Fatal("bad concrete vector operand")
				}
				return int(r - x86asm.X0)
			}
			switch i.Op {
			case x86asm.CALL:
				if called {
					t.Fatal("concrete nested call")
				}
				called = true
				o.regs[RSP] -= 8
				o.write(o.regs[RSP], 8, next)
				slot = Span{o.regs[RSP], o.regs[RSP] + 8}
				next += uint64(i.Args[0].(x86asm.Rel))
			case x86asm.RET:
				if !called {
					t.Fatal("concrete omitted call")
				}
				next = o.read(o.regs[RSP], 8, FrameReturnRead)
				o.regs[RSP] += 8
				if next != b.Request.Continuation || o.regs[RSP] != b.ReturnedRSP {
					t.Fatal("concrete returned interface differs")
				}
				returned = true
			case x86asm.MOVQ:
				d := vec(i.Args[0])
				v := o.reg(i.Args[1].(x86asm.Reg))
				vectors[d] = [16]byte{}
				for j := 0; j < 8; j++ {
					vectors[d][j] = byte(v >> uint(j*8))
				}
			case x86asm.PUNPCKLBW:
				d, src := vec(i.Args[0]), vec(i.Args[1])
				a, c := vectors[d], vectors[src]
				for j := 0; j < 8; j++ {
					vectors[d][j*2], vectors[d][j*2+1] = a[j], c[j]
				}
			case x86asm.PSHUFD:
				d, src := vec(i.Args[0]), vec(i.Args[1])
				old := vectors[src]
				control := uint8(i.Args[2].(x86asm.Imm))
				for j := 0; j < 4; j++ {
					from := int(control >> uint(j*2) & 3)
					copy(vectors[d][j*4:j*4+4], old[from*4:from*4+4])
				}
			case x86asm.MOVDQU:
				d := vec(i.Args[0])
				address := o.addr(i.Args[1].(x86asm.Mem), next)
				o.access(address, 16, FrameRead)
				for j := 0; j < 16; j++ {
					vectors[d][j] = o.memory[address+uint64(j)]
				}
			case x86asm.PCMPEQB:
				d, src := vec(i.Args[0]), vec(i.Args[1])
				a, c := vectors[d], vectors[src]
				for j := 0; j < 16; j++ {
					vectors[d][j] = 0
					if a[j] == c[j] {
						vectors[d][j] = 255
					}
				}
			case x86asm.PMOVMSKB:
				var v uint64
				for j, c := range vectors[vec(i.Args[1])] {
					v |= uint64(c>>7) << uint(j)
				}
				o.set(i.Args[0].(x86asm.Reg), v)
			case x86asm.BSF:
				x := uint32(o.reg(i.Args[1].(x86asm.Reg)))
				o.zero = x == 0
				o.carry = rng.Uint32()&1 != 0
				o.overflow = rng.Uint32()&1 != 0
				o.sign = rng.Uint32()&1 != 0
				if x == 0 {
					register, _, _ := oracleReg(i.Args[0].(x86asm.Reg))
					o.regs[register] = rng.Uint64()
				} else {
					o.set(i.Args[0].(x86asm.Reg), uint64(bits.TrailingZeros32(x)))
				}
			case x86asm.TEST:
				r := i.Args[0].(x86asm.Reg)
				_, width, _ := oracleReg(r)
				var right uint64
				if reg, ok := i.Args[1].(x86asm.Reg); ok {
					right = o.reg(reg)
				} else {
					right = uint64(i.Args[1].(x86asm.Imm))
				}
				v := o.reg(r) & right & oracleMask(width)
				o.zero = v == 0
				o.sign = v>>(width-1) != 0
				o.carry = false
				o.overflow = false
			case x86asm.SHL, x86asm.SHR:
				r := i.Args[0].(x86asm.Reg)
				_, width, _ := oracleReg(r)
				old := o.reg(r)
				var count uint64
				if reg, ok := i.Args[1].(x86asm.Reg); ok {
					count = o.reg(reg)
				} else {
					count = uint64(i.Args[1].(x86asm.Imm))
				}
				count &= uint64(width - 1)
				v := old
				if count != 0 {
					if i.Op == x86asm.SHL {
						v = old << count & oracleMask(width)
						o.carry = old>>(width-uint(count))&1 != 0
						o.overflow = (v>>(width-1)&1 != 0) != o.carry
					} else {
						v = old >> count
						o.carry = old>>(count-1)&1 != 0
						o.overflow = old>>(width-1)&1 != 0
					}
					o.zero = v == 0
					o.sign = v>>(width-1)&1 != 0
				}
				o.set(r, v)
			default:
				if o.step() {
					t.Fatal("unexpected standalone concrete return")
				}
				next = o.pc
			}
			o.pc = next
			if returned {
				break
			}
		}
		if !returned {
			t.Fatal("concrete instruction budget exhausted")
		}
		for _, r := range b.Results {
			var actual uint64
			for j := uint64(0); j < r.Bytes.End-r.Bytes.Start; j++ {
				actual |= uint64(o.memory[r.Bytes.Start+j]) << (j * 8)
			}
			if actual != r.Value {
				t.Fatalf("concrete result %#x != proof %#x", actual, r.Value)
			}
		}
		for r, v := range o.regs {
			if (v^before[r])&^b.RegisterWrites[r] != 0 || (v^before[r])&f.Preserved[r] != 0 {
				t.Fatalf("unaccounted register change %d", r)
			}
		}
		for r, v := range vectors {
			if (b.XMMWrites&(1<<uint(r)) == 0 || f.PreservedXMM[r]) && v != initialVectors[r] {
				t.Fatal("unaccounted vector context change")
			}
		}
	}
}
