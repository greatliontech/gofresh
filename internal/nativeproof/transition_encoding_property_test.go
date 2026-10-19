package nativeproof

import (
	"math/rand"
	"slices"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

// This bridge compares the production decoder with the separately implemented
// executed-byte parser. It supplies no execution, provenance or cut semantics.
// Architectural register numbering is specified here rather than obtained from
// the production alias table whose interpretation this comparison exercises.
var oracleRegisters64 = [...]x86asm.Reg{x86asm.RAX, x86asm.RCX, x86asm.RDX, x86asm.RBX, x86asm.RSP, x86asm.RBP, x86asm.RSI, x86asm.RDI, x86asm.R8, x86asm.R9, x86asm.R10, x86asm.R11, x86asm.R12, x86asm.R13, x86asm.R14, x86asm.R15}
var oracleRegisters32 = [...]x86asm.Reg{x86asm.EAX, x86asm.ECX, x86asm.EDX, x86asm.EBX, x86asm.ESP, x86asm.EBP, x86asm.ESI, x86asm.EDI, x86asm.R8L, x86asm.R9L, x86asm.R10L, x86asm.R11L, x86asm.R12L, x86asm.R13L, x86asm.R14L, x86asm.R15L}

func compareExecutedEncoding(t testing.TB, code []byte) {
	t.Helper()
	want, expectedErr := to.Parse(code, testEntry)
	if len(code) == 0 {
		if expectedErr == nil {
			t.Fatal("empty encoding parsed")
		}
		return
	}
	im := image(t, code)
	got, err := decodeTransition(im, testEntry, 0)
	if (err == nil) != (expectedErr == nil) {
		t.Fatalf("executed admission for %x: production=%v independent=%v (%+v)", code, err, expectedErr, want)
	}
	if err != nil {
		return
	}
	count := uint8(1)
	if want.Intent.Operation == to.Return {
		count = 0
	}
	if want.Intent.Operation == to.Branch {
		count = 2
	}
	if int(got.size) != want.Length || got.count != count || got.boundary != boundaryNone {
		t.Fatalf("wrong instruction extent/successors for %x: %+v, expected %+v", code, got, want)
	}
	i := want.Intent
	args := got.inst.Args
	reg := func(arg x86asm.Arg, n uint8, narrow bool, high ...bool) {
		t.Helper()
		expected := oracleRegisters64[n]
		if narrow || i.Width == 32 {
			expected = oracleRegisters32[n]
		}
		if i.Width == 8 {
			regs := []x86asm.Reg{x86asm.AL, x86asm.CL, x86asm.DL, x86asm.BL, x86asm.SPB, x86asm.BPB, x86asm.SIB, x86asm.DIB, x86asm.R8B, x86asm.R9B, x86asm.R10B, x86asm.R11B, x86asm.R12B, x86asm.R13B, x86asm.R14B, x86asm.R15B}
			expected = regs[n]
			if len(high) != 0 && high[0] {
				expected = []x86asm.Reg{x86asm.AH, x86asm.CH, x86asm.DH, x86asm.BH}[n]
			}
		}
		if arg != expected {
			t.Fatalf("register for %x: %v, expected %v", code, arg, expected)
		}
	}
	mem := func(arg x86asm.Arg) {
		t.Helper()
		m, ok := arg.(x86asm.Mem)
		base := oracleRegisters64[i.Base]
		segment := x86asm.Reg(0)
		if i.FS {
			base = 0
			segment = x86asm.FS
		}
		if i.Operation == to.LEARIP || i.RIP {
			base = x86asm.RIP
		}
		if !ok || m.Base != base || m.Index != 0 || m.Segment != segment || m.Disp != i.SignedDisp {
			t.Fatalf("address for %x: %+v, expected base=%d displacement=%d", code, arg, i.Base, i.SignedDisp)
		}
		// A no-index SIB's scale bits have no address effect; their spelling is
		// retained and tested by the independent parser rather than this operand.
	}
	imm := func(arg x86asm.Arg, narrow bool) {
		t.Helper()
		v, ok := arg.(x86asm.Imm)
		value := uint64(v)
		if narrow || i.Width == 32 {
			value &= 0xffffffff
		}
		if i.Width == 8 {
			value &= 255
		}
		if !ok || value != i.Immediate {
			t.Fatalf("immediate for %x: %v, expected %#x", code, arg, i.Immediate)
		}
	}
	op := x86asm.MOV
	switch i.Operation {
	case to.NoOp:
		op = x86asm.NOP
	case to.LockedCompareExchange, to.LockedExchange, to.LockedExchangeAdd:
		op = map[to.Operation]x86asm.Op{to.LockedCompareExchange: x86asm.CMPXCHG, to.LockedExchange: x86asm.XCHG, to.LockedExchangeAdd: x86asm.XADD}[i.Operation]
		mem(args[0])
		reg(args[1], i.Src, false)
	case to.LockedAnd, to.LockedOr, to.LockedAndImmediate, to.LockedOrImmediate:
		op = x86asm.AND
		if i.Operation == to.LockedOr || i.Operation == to.LockedOrImmediate {
			op = x86asm.OR
		}
		mem(args[0])
		if i.Operation == to.LockedAndImmediate || i.Operation == to.LockedOrImmediate {
			imm(args[1], false)
		} else {
			reg(args[1], i.Src, false, i.HighSrc)
		}
	case to.AddRegister:
		op = x86asm.ADD
		reg(args[0], i.Dst, false)
		reg(args[1], i.Src, false)
	case to.SetRegister, to.SetMemory:
		op = map[uint8]x86asm.Op{2: x86asm.SETB, 3: x86asm.SETAE, 4: x86asm.SETE, 5: x86asm.SETNE, 6: x86asm.SETBE, 7: x86asm.SETA, 12: x86asm.SETL, 13: x86asm.SETGE, 14: x86asm.SETLE, 15: x86asm.SETG}[i.Condition]
		if i.Operation == to.SetMemory {
			mem(args[0])
		} else {
			reg(args[0], i.Dst, false, i.HighDst)
		}
		if args[1] != nil {
			t.Fatal("SETcc extra operand")
		}
	case to.CompareMemory, to.CompareFromMemory, to.CompareMemoryImmediate:
		op = x86asm.CMP
		if i.Operation == to.CompareFromMemory {
			reg(args[0], i.Dst, false, i.HighDst)
			mem(args[1])
		} else {
			mem(args[0])
			if i.Operation == to.CompareMemory {
				reg(args[1], i.Src, false, i.HighSrc)
			} else {
				imm(args[1], false)
			}
		}
	case to.Clear32:
		op = x86asm.XOR
		reg(args[0], i.Dst, true)
		reg(args[1], i.Dst, true)
	case to.Syscall:
		op = x86asm.SYSCALL
		if args != ([2]x86asm.Arg{}) {
			t.Fatal("SYSCALL explicit operands")
		}
	case to.Return:
		op = x86asm.RET
		if args != ([2]x86asm.Arg{}) {
			t.Fatal("RET explicit operands")
		}
	case to.Push, to.Pop:
		op = x86asm.PUSH
		if i.Operation == to.Pop {
			op = x86asm.POP
		}
		reg(args[0], i.Dst, false)
		if args[1] != nil {
			t.Fatal("stack extra operand")
		}
	case to.Call:
		op = x86asm.CALL
		if args[0] != x86asm.Rel(i.SignedDisp) || args[1] != nil || got.targets[0] != want.Target {
			t.Fatal("CALL target/extent differs")
		}
	case to.CPUID:
		op = x86asm.CPUID
		if args != ([2]x86asm.Arg{}) {
			t.Fatal("CPUID acquired explicit operands")
		}
	case to.MoveRegister:
		reg(args[0], i.Dst, false, i.HighDst)
		reg(args[1], i.Src, false, i.HighSrc)
	case to.Load:
		reg(args[0], i.Dst, false, i.HighDst)
		mem(args[1])
	case to.Store:
		mem(args[0])
		reg(args[1], i.Src, false, i.HighSrc)
	case to.MoveImmediate, to.MoveImmediate32:
		reg(args[0], i.Dst, i.Operation == to.MoveImmediate32, i.HighDst)
		imm(args[1], i.Operation == to.MoveImmediate32)
	case to.StoreImmediate:
		mem(args[0])
		imm(args[1], false)
	case to.LEA, to.LEARIP:
		op = x86asm.LEA
		reg(args[0], i.Dst, false)
		mem(args[1])
	case to.Subtract, to.And, to.Add:
		op = x86asm.SUB
		if i.Operation == to.And {
			op = x86asm.AND
		}
		if i.Operation == to.Add {
			op = x86asm.ADD
		}
		reg(args[0], i.Dst, false)
		imm(args[1], false)
	case to.Jump:
		op = x86asm.JMP
		if args[0] != x86asm.Rel(i.SignedDisp) || args[1] != nil || got.targets[0] != want.Target {
			t.Fatalf("relative transfer for %x: %+v, expected %+v", code, got, want)
		}
	case to.Compare, to.CompareImmediate, to.Test, to.TestImmediate:
		op = x86asm.CMP
		if i.Operation == to.Test || i.Operation == to.TestImmediate {
			op = x86asm.TEST
		}
		reg(args[0], i.Dst, false, i.HighDst)
		if i.Operation == to.Compare || i.Operation == to.Test {
			reg(args[1], i.Src, false, i.HighSrc)
		} else {
			imm(args[1], false)
		}
	case to.Branch:
		op = map[uint8]x86asm.Op{2: x86asm.JB, 3: x86asm.JAE, 4: x86asm.JE, 5: x86asm.JNE, 6: x86asm.JBE, 7: x86asm.JA, 10: x86asm.JP, 11: x86asm.JNP, 12: x86asm.JL, 13: x86asm.JGE, 14: x86asm.JLE, 15: x86asm.JG}[i.Condition]
		if args[0] != x86asm.Rel(i.SignedDisp) || args[1] != nil || got.targets[1] != want.Target {
			t.Fatal("conditional successor differs", code)
		}
	default:
		t.Fatal("unhandled independent operation", i.Operation)
	}
	if got.inst.Op != op || i.Operation != to.Jump && i.Operation != to.Call && i.Operation != to.Return && got.targets[0] != want.Next {
		t.Fatalf("opcode/fallthrough for %x: %+v, expected %+v", code, got, want)
	}
}

func descriptorPayload(d to.Descriptor, immediate uint64, displacement int32) to.Intent {
	i := d.Intent
	switch d.Encoding.Form {
	case to.MOVB8Imm64:
		i.Immediate = immediate
	case to.MOVB8Imm32:
		i.Immediate = uint64(uint32(immediate))
	case to.MOVC7, to.SUB81, to.SUB2D, to.ADD81, to.ADD05, to.AND81, to.AND25, to.CMP81, to.CMP3D, to.TESTF7, to.TESTA9:
		i.Immediate = uint64(int64(int32(immediate)))
	case to.SUB83, to.ADD83, to.AND83, to.CMP83:
		i.Immediate = uint64(int64(int8(immediate)))
	case to.MOVC6, to.MOVB0, to.TESTF6, to.TESTA8, to.CMP80, to.LOCKAND80, to.LOCKOR80:
		i.Immediate = uint64(uint8(immediate))
	}
	if i.Width == 32 {
		i.Immediate &= 0xffffffff
	}
	if d.Encoding.DispBytes == 1 || d.Encoding.Form == to.JMPEB || d.Encoding.Form == to.JccShort {
		i.SignedDisp = int64(int8(displacement))
	} else if d.Encoding.DispBytes == 4 || d.Encoding.Form == to.JMPE9 || d.Encoding.Form == to.JccNear || d.Encoding.Form == to.CALLE8 {
		i.SignedDisp = int64(displacement)
	}
	return i
}

func TestTransitionExecutedDescriptorPopulation(t *testing.T) {
	t.Parallel()
	count := 0
	for d := range to.Descriptors {
		count++
		for _, payload := range []struct {
			immediate uint64
			disp      int32
		}{{0, 0}, {0xfedcba9876543210, -8}, {0x8000000080000080, 0x7fffffff}} {
			i := descriptorPayload(d, payload.immediate, payload.disp)
			code, err := to.Encode(i, d.Encoding)
			if err != nil {
				t.Fatal(err)
			}
			compareExecutedEncoding(t, code)
		}
	}
	if count != 157118 {
		t.Fatalf("descriptor population changed: %d", count)
	}
	// The finite encoding dimension is enumerated in each property trial;
	// immediate and displacement payloads are independent full-width inputs.
	// This does not turn the sampled payload valuations into exhaustive values.
	if err := quick.Check(func(immediate uint64, displacement int32) bool {
		for d := range to.Descriptors {
			code, err := to.Encode(descriptorPayload(d, immediate, displacement), d.Encoding)
			if err != nil {
				t.Fatal(err)
			}
			compareExecutedEncoding(t, code)
		}
		return true
	}, &quick.Config{MaxCount: 8, Rand: rand.New(rand.NewSource(513))}); err != nil {
		t.Fatal(err)
	}
}

func FuzzTransitionExecutedEncoding(f *testing.F) {
	descriptors := slices.Collect(to.Descriptors)
	for _, seed := range []uint32{0, 1, 2, 17, 255, 4096, 14641, 0x80000000, 0xffffffff} {
		f.Add(seed, uint64(0x1234567887654321), int32(-8))
	}
	f.Fuzz(func(t *testing.T, selection uint32, immediate uint64, displacement int32) {
		d := descriptors[int(selection%uint32(len(descriptors)))]
		i := descriptorPayload(d, immediate, displacement)
		code, err := to.Encode(i, d.Encoding)
		if err != nil {
			t.Fatal(err)
		}
		compareExecutedEncoding(t, code)
	})
}

func FuzzTransitionExecutedRawAdmission(f *testing.F) {
	for _, code := range [][]byte{{0xf0, 0x0f, 0xb1, 0x11}, {0xf0, 0x44, 0x0f, 0xb1, 0x11}, {0xf0, 0x80, 0x09, 0x80}, {0xf0, 0x20, 0x21}, {0x80, 0x39, 0x80}, {0x38, 0x21}, {0x3a, 0x21}, {0x66, 0x0f, 0x1f, 0x44, 0, 0}} {
		f.Add(code)
	}
	f.Add([]byte{0x0f, 0xa2})
	f.Add([]byte{0x66, 0x0f, 0xa2})
	for _, code := range [][]byte{{0xf0, 0x48, 0x0f, 0xb1, 0x11}, {0xf0, 0x48, 0x0f, 0xb1, 0xc1}, {0xf0, 0x66, 0x48, 0x0f, 0xb1, 0x11}, {0x0f, 0x94, 0xc4}, {0x40, 0x0f, 0x94, 0xc4}, {0x0f, 0x94, 0xc8}, {0x48, 0x0f, 0x94, 0x01}, {0x84, 0xe1}, {0xf6, 0xc1, 0xff}, {0xa8, 0x80}, {0x48, 0x83, 0x39, 42}, {0x48, 0x3b, 0x11}, {0x90}, {0x66, 0x90}} {
		f.Add(code)
	}
	for _, code := range [][]byte{{0xe8, 0xf8, 0xff, 0xff, 0xff}, {0x54}, {0x5c}, {0x41, 0x5f}, {0xc3}, {0x0f, 0x05}, {0x64, 0x48, 0xc7, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, 0x23, 1, 0, 0}, {0x64, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0}, {0x48, 0x64, 0x8b, 0x04, 0x25, 0, 0, 0, 0}, {0x64, 0x67, 0x48, 0x8b, 0, 0, 0, 0}} {
		f.Add(code)
	}
	for _, code := range [][]byte{{0x48, 0x89, 0xe0}, {0x48, 0x8d, 0x80, 0xf8, 0xff, 0xff, 0xff}, {0x48, 0x8b, 0x04, 0xe0}, {0x48, 0x83, 0xec, 0x28}, {0x41, 0xbd, 0, 0, 0, 0}, {0xc5, 0xf8, 0x77}, {0x48, 0x48, 0x89, 0xe0}, {0x4f, 0x8d, 0x3d, 0x80, 0xff, 0xff, 0xff}} {
		f.Add(code)
	}
	f.Fuzz(func(t *testing.T, code []byte) {
		// Fifteen bytes is the architectural instruction window, not a grammar
		// restriction. Every bit pattern within that window remains expressible.
		compareExecutedEncoding(t, code[:min(len(code), 15)])
	})
}
