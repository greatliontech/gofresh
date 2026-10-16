package nativeproof

import (
	"math/rand/v2"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// This concrete interpreter shares only instruction decoding. It uses actual
// register values and byte-addressed memory, no frame pointer tokens, region
// lookup helpers, abstract transfer, joins or provenance. Samples check soundness
// of footprints, untouched state and optional pointer facts, not completeness.
func checkFrameOracle(t testing.TB, im *Image, b FrameBound, samples int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(0x127, 0x993))
	for sample := 0; sample < samples; sample++ {
		o := concreteFrame{t: t, im: im, b: b, memory: map[uint64]byte{}, permissions: map[uint64]uint8{}, pc: b.Entry}
		for r := range o.regs {
			o.regs[r] = rng.Uint64()
		}
		if sample%2 == 0 {
			o.regs[RBX] = 0
		}
		for _, region := range b.Interface.Regions {
			for address := region.Bytes.Start; address < region.Bytes.End; address++ {
				if _, exists := o.memory[address]; !exists {
					o.memory[address] = byte(rng.Uint32())
				}
				if region.Readable {
					o.permissions[address] |= 1
				}
				if region.Writable {
					o.permissions[address] |= 2
				}
				if region.Image {
					for _, load := range im.loads {
						if address >= load.va && address < load.end {
							if address-load.va < load.filesz {
								o.memory[address] = im.data[load.off+address-load.va]
							} else {
								o.memory[address] = 0
							}
							break
						}
					}
				}
			}
		}
		pointer := func(p RegionPointer) uint64 {
			return b.Interface.Regions[p.Region].Bytes.Start + p.Min + rng.Uint64N(p.Max-p.Min+1)
		}
		for _, p := range b.Interface.Pointers {
			o.regs[p.Register] = pointer(p.Pointer)
		}
		o.regs[RSP] = pointer(b.Interface.Stack)
		initialSP := o.regs[RSP]
		for _, p := range b.Interface.MemoryPointers {
			v := pointer(p.Pointer)
			for lane := 0; lane < 8; lane++ {
				o.memory[p.Address+uint64(lane)] = byte(v >> uint(lane*8))
			}
		}
		for lane := 0; lane < 8; lane++ {
			o.memory[initialSP+uint64(lane)] = byte(uint64(0x400123) >> uint(lane*8))
		}
		beforeRegs := o.regs
		before := map[uint64]byte{}
		for k, v := range o.memory {
			before[k] = v
		}
		for step := 0; step <= len(b.Instructions); step++ {
			if o.step() {
				break
			}
			if step == len(b.Instructions) {
				t.Fatal("concrete execution did not reach RET")
			}
		}
		if o.regs[RSP] != b.ReturnedRSP {
			t.Fatalf("returned RSP %#x, proof %#x", o.regs[RSP], b.ReturnedRSP)
		}
		for r, mask := range b.Interface.Preserved {
			if (o.regs[r]^beforeRegs[r])&mask != 0 {
				t.Fatalf("preserved register %d changed", r)
			}
		}
		for address, value := range before {
			if o.memory[address] == value {
				continue
			}
			allowed := false
			for _, a := range b.Accesses {
				allowed = allowed || a.Kind == FrameWrite && address >= a.Bytes.Start && address < a.Bytes.End
			}
			if !allowed {
				t.Fatalf("memory outside derived writes changed at %#x", address)
			}
		}
		for _, p := range b.ReturnedPointers {
			base := b.Interface.Regions[p.Pointer.Region].Bytes.Start
			if o.regs[p.Register] < base+p.Pointer.Min || o.regs[p.Register] > base+p.Pointer.Max {
				t.Fatalf("returned pointer %d contradicts proof", p.Register)
			}
		}
	}
}

type concreteFrame struct {
	t                           testing.TB
	im                          *Image
	b                           FrameBound
	regs                        [16]uint64
	memory                      map[uint64]byte
	permissions                 map[uint64]uint8
	pc                          uint64
	carry, zero, sign, overflow bool
	returnSlot                  *Span // nil selects the original entry slot; fragments supply theirs
}

func oracleReg(r x86asm.Reg) (int, uint, uint) {
	switch {
	case r >= x86asm.RAX && r <= x86asm.R15:
		return int(r - x86asm.RAX), 64, 0
	case r >= x86asm.EAX && r <= x86asm.R15L:
		return int(r - x86asm.EAX), 32, 0
	case r >= x86asm.AX && r <= x86asm.R15W:
		return int(r - x86asm.AX), 16, 0
	case r >= x86asm.AL && r <= x86asm.BL:
		return int(r - x86asm.AL), 8, 0
	case r >= x86asm.AH && r <= x86asm.BH:
		return int(r - x86asm.AH), 8, 8
	case r >= x86asm.SPB && r <= x86asm.R15B:
		return int(r-x86asm.SPB) + 4, 8, 0
	}
	panic("oracle register unsupported")
}

func oracleMask(width uint) uint64 {
	if width == 64 {
		return ^uint64(0)
	}
	return 1<<width - 1
}
func (o *concreteFrame) reg(r x86asm.Reg) uint64 {
	index, width, shift := oracleReg(r)
	return o.regs[index] >> shift & oracleMask(width)
}
func (o *concreteFrame) set(r x86asm.Reg, v uint64) {
	index, width, shift := oracleReg(r)
	if width == 32 {
		o.regs[index] = uint64(uint32(v))
		return
	}
	bits := oracleMask(width) << shift
	o.regs[index] = o.regs[index]&^bits | (v<<shift)&bits
}
func (o *concreteFrame) addr(m x86asm.Mem, next uint64) uint64 {
	var v uint64
	if m.Base == x86asm.RIP {
		v = next
	} else if m.Base != 0 {
		v = o.reg(m.Base)
	}
	if m.Index != 0 {
		v += o.reg(m.Index) * uint64(m.Scale)
	}
	return v + uint64(m.Disp)
}

func (o *concreteFrame) access(address uint64, width int, kind AccessKind) {
	o.t.Helper()
	end := address + uint64(width)
	if end < address {
		o.t.Fatal("concrete memory address overflow")
	}
	allowed := false
	for _, a := range o.b.Accesses {
		allowed = allowed || a.PC == o.pc && a.Kind == kind && a.Width == width && address >= a.Bytes.Start && end <= a.Bytes.End
	}
	if !allowed {
		o.t.Fatalf("concrete access absent from frame: pc=%#x address=%#x width=%d kind=%d", o.pc, address, width, kind)
	}
	permission := uint8(1)
	if kind == FrameWrite {
		permission = 2
	}
	for at := address; at < end; at++ {
		if o.permissions[at]&permission == 0 {
			o.t.Fatalf("concrete permission fault at %#x", at)
		}
	}
	if kind == FrameWrite {
		stack := o.b.Interface.Stack
		start := o.b.Interface.Regions[stack.Region].Bytes.Start + stack.Min
		slot := Span{start, start + 8}
		if o.returnSlot != nil {
			slot = *o.returnSlot
		}
		if address < slot.End && slot.Start < end {
			o.t.Fatal("concrete write corrupts return context")
		}
		for _, p := range o.b.Interface.Protected {
			if address < p.End && p.Start < end {
				o.t.Fatal("concrete write reaches protected memory")
			}
		}
	}
}

func (o *concreteFrame) read(address uint64, width int, kind AccessKind) uint64 {
	o.access(address, width, kind)
	var v uint64
	for j := 0; j < width; j++ {
		v |= uint64(o.memory[address+uint64(j)]) << uint(8*j)
	}
	return v
}
func (o *concreteFrame) write(address uint64, width int, v uint64) {
	o.access(address, width, FrameWrite)
	for j := 0; j < width; j++ {
		o.memory[address+uint64(j)] = byte(v >> uint(8*j))
	}
}

func (o *concreteFrame) step() bool {
	o.t.Helper()
	raw, err := o.im.instructionBytes(o.pc)
	if err != nil {
		o.t.Fatal(err)
	}
	i, err := x86asm.Decode(raw, 64)
	if err != nil {
		o.t.Fatal(err)
	}
	next := o.pc + uint64(i.Len)
	operand := func(a x86asm.Arg) uint64 {
		switch a := a.(type) {
		case x86asm.Reg:
			return o.reg(a)
		case x86asm.Imm:
			return uint64(a)
		case x86asm.Mem:
			return o.read(o.addr(a, next), i.MemBytes, FrameRead)
		}
		o.t.Fatalf("oracle operand %v", a)
		return 0
	}
	switch i.Op {
	case x86asm.RET:
		if o.read(o.regs[RSP], 8, FrameReturnRead) != 0x400123 {
			o.t.Fatal("concrete return context changed")
		}
		o.regs[RSP] += 8
		return true
	case x86asm.MOV, x86asm.MOVZX:
		v := operand(i.Args[1])
		if dest, ok := i.Args[0].(x86asm.Mem); ok {
			o.write(o.addr(dest, next), i.MemBytes, v)
		} else {
			o.set(i.Args[0].(x86asm.Reg), v)
		}
	case x86asm.LEA:
		o.set(i.Args[0].(x86asm.Reg), o.addr(i.Args[1].(x86asm.Mem), next))
	case x86asm.ADD, x86asm.SUB, x86asm.CMP, x86asm.XOR, x86asm.AND:
		dest := i.Args[0].(x86asm.Reg)
		_, width, _ := oracleReg(dest)
		left, right := o.reg(dest), operand(i.Args[1])&oracleMask(width)
		var result uint64
		switch i.Op {
		case x86asm.ADD:
			result = (left + right) & oracleMask(width)
			o.carry = result < left
			o.overflow = (^(left^right)&(left^result))>>(width-1)&1 != 0
		case x86asm.SUB, x86asm.CMP:
			result = (left - right) & oracleMask(width)
			o.carry = left < right
			o.overflow = ((left^right)&(left^result))>>(width-1)&1 != 0
		case x86asm.XOR:
			result = left ^ right
			o.carry = false
			o.overflow = false
		case x86asm.AND:
			result = left & right
			o.carry = false
			o.overflow = false
		}
		o.zero = result == 0
		o.sign = result>>(width-1)&1 != 0
		if i.Op != x86asm.CMP {
			o.set(dest, result)
		}
	case x86asm.JMP:
		next += uint64(i.Args[0].(x86asm.Rel))
	case x86asm.JE, x86asm.JNE, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JL, x86asm.JLE, x86asm.JG, x86asm.JGE:
		take := false
		switch i.Op {
		case x86asm.JE:
			take = o.zero
		case x86asm.JNE:
			take = !o.zero
		case x86asm.JA:
			take = !o.carry && !o.zero
		case x86asm.JAE:
			take = !o.carry
		case x86asm.JB:
			take = o.carry
		case x86asm.JBE:
			take = o.carry || o.zero
		case x86asm.JL:
			take = o.sign != o.overflow
		case x86asm.JLE:
			take = o.zero || o.sign != o.overflow
		case x86asm.JG:
			take = !o.zero && o.sign == o.overflow
		case x86asm.JGE:
			take = o.sign == o.overflow
		}
		if take {
			next += uint64(i.Args[0].(x86asm.Rel))
		}
	case x86asm.NOP:
	default:
		o.t.Fatalf("concrete oracle lacks %s", i.Op)
	}
	o.pc = next
	return false
}
