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
	if int(got.size) != want.Length || got.count != 1 || got.boundary != boundaryNone {
		t.Fatalf("wrong instruction extent/successors for %x: %+v, expected %+v", code, got, want)
	}
	i := want.Intent
	args := got.inst.Args
	reg := func(arg x86asm.Arg, n uint8, narrow bool) {
		t.Helper()
		expected := oracleRegisters64[n]
		if narrow {
			expected = oracleRegisters32[n]
		}
		if arg != expected {
			t.Fatalf("register for %x: %v, expected %v", code, arg, expected)
		}
	}
	mem := func(arg x86asm.Arg) {
		t.Helper()
		m, ok := arg.(x86asm.Mem)
		base := oracleRegisters64[i.Base]
		if i.Operation == to.LEARIP {
			base = x86asm.RIP
		}
		if !ok || m.Base != base || m.Index != 0 || m.Segment != 0 || m.Disp != i.SignedDisp {
			t.Fatalf("address for %x: %+v, expected base=%d displacement=%d", code, arg, i.Base, i.SignedDisp)
		}
		// A no-index SIB's scale bits have no address effect; their spelling is
		// retained and tested by the independent parser rather than this operand.
	}
	imm := func(arg x86asm.Arg, narrow bool) {
		t.Helper()
		v, ok := arg.(x86asm.Imm)
		value := uint64(v)
		if narrow {
			value &= 0xffffffff
		}
		if !ok || value != i.Immediate {
			t.Fatalf("immediate for %x: %v, expected %#x", code, arg, i.Immediate)
		}
	}
	op := x86asm.MOV
	switch i.Operation {
	case to.CPUID:
		op = x86asm.CPUID
		if args != ([2]x86asm.Arg{}) {
			t.Fatal("CPUID acquired explicit operands")
		}
	case to.MoveRegister:
		reg(args[0], i.Dst, false)
		reg(args[1], i.Src, false)
	case to.Load:
		reg(args[0], i.Dst, false)
		mem(args[1])
	case to.Store:
		mem(args[0])
		reg(args[1], i.Src, false)
	case to.MoveImmediate, to.MoveImmediate32:
		reg(args[0], i.Dst, i.Operation == to.MoveImmediate32)
		imm(args[1], i.Operation == to.MoveImmediate32)
	case to.StoreImmediate:
		mem(args[0])
		imm(args[1], false)
	case to.LEA, to.LEARIP:
		op = x86asm.LEA
		reg(args[0], i.Dst, false)
		mem(args[1])
	case to.Subtract, to.And:
		op = x86asm.SUB
		if i.Operation == to.And {
			op = x86asm.AND
		}
		reg(args[0], i.Dst, false)
		imm(args[1], false)
	case to.Jump:
		op = x86asm.JMP
		if args[0] != x86asm.Rel(i.SignedDisp) || args[1] != nil || got.targets[0] != want.Target {
			t.Fatalf("relative transfer for %x: %+v, expected %+v", code, got, want)
		}
	default:
		t.Fatal("unhandled independent operation", i.Operation)
	}
	if got.inst.Op != op || i.Operation != to.Jump && got.targets[0] != want.Next {
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
	case to.MOVC7, to.SUB81, to.SUB2D, to.AND81, to.AND25:
		i.Immediate = uint64(int64(int32(immediate)))
	case to.SUB83, to.AND83:
		i.Immediate = uint64(int64(int8(immediate)))
	}
	if d.Encoding.DispBytes == 1 || d.Encoding.Form == to.JMPEB {
		i.SignedDisp = int64(int8(displacement))
	} else if d.Encoding.DispBytes == 4 || d.Encoding.Form == to.JMPE9 {
		i.SignedDisp = int64(displacement)
	}
	return i
}

func TestTransitionExecutedDescriptorPopulation(t *testing.T) {
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
	if count != 14707 {
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
	f.Add([]byte{0x0f, 0xa2})
	f.Add([]byte{0x66, 0x0f, 0xa2})
	for _, code := range [][]byte{{0x48, 0x89, 0xe0}, {0x48, 0x8d, 0x80, 0xf8, 0xff, 0xff, 0xff}, {0x48, 0x8b, 0x04, 0xe0}, {0x48, 0x83, 0xec, 0x28}, {0x41, 0xbd, 0, 0, 0, 0}, {0xc5, 0xf8, 0x77}, {0x48, 0x48, 0x89, 0xe0}, {0x4f, 0x8d, 0x3d, 0x80, 0xff, 0xff, 0xff}} {
		f.Add(code)
	}
	f.Fuzz(func(t *testing.T, code []byte) {
		// Fifteen bytes is the architectural instruction window, not a grammar
		// restriction. Every bit pattern within that window remains expressible.
		compareExecutedEncoding(t, code[:min(len(code), 15)])
	})
}
