package nativeproof

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"
)

// emitVectorForm encodes register choices; it computes no instruction results.
// The optional suffix is an immediate byte, not a proposed shuffle summary.
func emitVectorForm(code []byte, prefix, opcode byte, dst, src int, suffix ...byte) []byte {
	code = append(code, prefix)
	rex := byte(0x40)
	if dst >= 8 {
		rex |= 4
	}
	if src >= 8 {
		rex |= 1
	}
	if rex != 0x40 {
		code = append(code, rex)
	}
	code = append(code, 0x0f, opcode, 0xc0|byte(dst%8)<<3|byte(src%8))
	return append(code, suffix...)
}

func emitVectorLoad(code []byte, dst int, address uint64) []byte {
	code = append(code, 0x48, 0xb8) // MOVABS RAX,address
	code = binary.LittleEndian.AppendUint64(code, address)
	code = append(code, 0xf3)
	if dst >= 8 {
		code = append(code, 0x44)
	}
	return append(code, 0x0f, 0x6f, byte(dst%8)<<3) // MOVDQU Xdst,[RAX]
}

// vectorInstructionFixture makes a connected CALL whose callee observes the
// vector result with PMOVMSKB. Golden cases first compare all sixteen bytes to
// a literal expected vector, so low-bit lane mistakes cannot hide behind equal
// sign bits. Fuzz cases use direct mask observation and the concrete ISA oracle.
// 'unknown' leaves one operand as arbitrary entry XMM state; 'half' supplies an
// arbitrary GP64 through MOVQ, whose upper two dword lanes are defined zeros.
func vectorInstructionFixture(t testing.TB, op byte, dst, src int, selector byte, left, right, expected []byte, unknown, half bool) ([]byte, ValueCallRequest) {
	t.Helper()
	if dst < 0 || dst >= 15 || src < 0 || src >= 15 || op != 0x60 && op != 0x70 {
		t.Fatal("invalid instruction fixture")
	}
	if len(expected) != 0 && (len(expected) != 16 || dst == 14 || src == 14) {
		t.Fatal("invalid golden vector fixture")
	}
	raw, request := valueCallFixture(t, "test.short", '=', false, false)
	addresses := []uint64{valueData + 0x300, valueData + 0x320, valueData + 0x340}
	for j, data := range [][]byte{left, right, expected} {
		if len(data) == 0 {
			continue
		}
		if len(data) != 16 {
			t.Fatal("vector fixture must contain sixteen bytes")
		}
		copy(raw[addresses[j]-testBase:], data)
		span := Span{addresses[j], addresses[j] + 16}
		request.Interface.Regions = append(request.Interface.Regions, ByteRegion{span, true, false, true})
		request.Interface.Readonly = append(request.Interface.Readonly, span)
	}
	var body []byte
	// For unpack, the unknown operand is the old destination. For shuffle, it
	// is the source. Neither omission is replaced by an implicit zero vector.
	if !(unknown && op == 0x60) {
		body = emitVectorLoad(body, dst, addresses[0])
	}
	if src != dst && !(unknown && op == 0x70) {
		body = emitVectorLoad(body, src, addresses[1])
	}
	if half {
		rex := byte(0x49) // MOVQ Xsrc,R9: R9 is unspecified, upper XMM half becomes zero
		if src >= 8 {
			rex |= 4
		}
		body = append(body, 0x66, rex, 0x0f, 0x6e, 0xc1|byte(src%8)<<3)
	}
	if op == 0x70 {
		body = emitVectorForm(body, 0x66, op, dst, src, selector)
	} else {
		body = emitVectorForm(body, 0x66, op, dst, src)
	}
	if len(expected) != 0 {
		body = emitVectorLoad(body, 14, addresses[2])
		body = emitVectorForm(body, 0x66, 0x74, dst, 14) // PCMPEQB result, literal golden
	}
	body = emitVectorForm(body, 0x66, 0xd7, 0, dst)         // PMOVMSKB EAX,Xdst
	body = append(body, 0x48, 0x89, 0x44, 0x24, 0x20, 0xc3) // real ABI0 result store and RET
	replaceValueCallee(t, raw, request, hex.EncodeToString(body))
	return raw, request
}

func checkedInstructionFixture(t testing.TB, raw []byte, r ValueCallRequest, samples int) ValueCallBound {
	t.Helper()
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckValueCall(t.Context(), im, r, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.Bound()
	if !ok {
		t.Fatal("missing instruction proof")
	}
	checkValueCallOracle(t, im, b, samples)
	return b
}

func TestValueCallVectorOperandsAndSelectors(t *testing.T) {
	left, right := []byte("0123456789:;<=>?"), []byte("abcdEFGHijklMNOP")
	// Literal lane arrangements are independent golden facts, not a second
	// implementation of the abstract shuffle/unpack transfer. The four rotations
	// alone place every source dword in every output position; reversal and four
	// broadcasts also distinguish aliasing/in-place and selector-bit errors.
	shuffles := []struct {
		name    string
		control byte
		golden  string
	}{
		{"identity", 0xe4, "abcdEFGHijklMNOP"},
		{"rotate1", 0x39, "EFGHijklMNOPabcd"},
		{"rotate2", 0x4e, "ijklMNOPabcdEFGH"},
		{"rotate3", 0x93, "MNOPabcdEFGHijkl"},
		{"reverse", 0x1b, "MNOPijklEFGHabcd"},
		{"broadcast0", 0x00, "abcdabcdabcdabcd"},
		{"broadcast1", 0x55, "EFGHEFGHEFGHEFGH"},
		{"broadcast2", 0xaa, "ijklijklijklijkl"},
		{"broadcast3", 0xff, "MNOPMNOPMNOPMNOP"},
	}
	for _, pair := range [][2]int{{0, 1}, {8, 12}, {12, 8}, {0, 0}, {8, 8}} {
		dst, src := pair[0], pair[1]
		t.Run(fmt.Sprintf("unpack/X%d_X%d", dst, src), func(t *testing.T) {
			golden := "0a1b2c3d4E5F6G7H"
			if dst == src {
				golden = "0011223344556677"
			}
			raw, r := vectorInstructionFixture(t, 0x60, dst, src, 0, left, right, []byte(golden), false, false)
			b := checkedInstructionFixture(t, raw, r, 4)
			if b.Results[0].Value != 0xffff {
				t.Fatalf("unpack changed bytes: comparison mask %#x", b.Results[0].Value)
			}
		})
		for _, shuffle := range shuffles {
			t.Run(fmt.Sprintf("shuffle/X%d_X%d/%s", dst, src, shuffle.name), func(t *testing.T) {
				destination := left
				if dst == src {
					destination = right
				}
				raw, r := vectorInstructionFixture(t, 0x70, dst, src, shuffle.control, destination, right, []byte(shuffle.golden), false, false)
				b := checkedInstructionFixture(t, raw, r, 4)
				if b.Results[0].Value != 0xffff {
					t.Fatalf("shuffle changed bytes: comparison mask %#x", b.Results[0].Value)
				}
			})
		}
	}
}

func TestValueCallVectorUnknownLanes(t *testing.T) {
	known := []byte("abcdEFGHijklMNOP")
	for _, pair := range [][2]int{{0, 1}, {8, 12}, {0, 0}, {8, 8}} {
		for _, op := range []byte{0x60, 0x70} {
			if op == 0x70 && pair[0] == pair[1] {
				continue
			} // alias half-known cases below
			raw, r := vectorInstructionFixture(t, op, pair[0], pair[1], 0x1b, known, known, nil, true, false)
			c, err := checkValueFixture(t, raw, r)
			valueCallRefusal(t, c, err)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Premise != "value-result" {
				t.Fatalf("unknown operand did not reach result judgment: %v", err)
			}
		}
		// MOVQ's arbitrary low half cannot acquire known sign bits through a
		// selector. All-zero and all-high-bit R9 values yield different masks.
		// Selectors confined to the architecturally zeroed upper half do qualify.
		for _, selector := range []byte{0x00, 0x55, 0xe4, 0xec, 0xaa, 0xff, 0xee} {
			raw, r := vectorInstructionFixture(t, 0x70, pair[0], pair[1], selector, known, known, nil, false, true)
			upperOnly := selector == 0xaa || selector == 0xff || selector == 0xee
			if upperOnly {
				b := checkedInstructionFixture(t, raw, r, 8)
				if b.Results[0].Value != 0 {
					t.Fatal("MOVQ upper-half zeros lost", b.Results)
				}
			} else {
				c, err := checkValueFixture(t, raw, r)
				valueCallRefusal(t, c, err)
				var refusal *Refusal
				if !errors.As(err, &refusal) || refusal.Premise != "value-result" {
					t.Fatalf("unknown selected lane did not reach result judgment: %v", err)
				}
			}
		}
	}
}

func FuzzValueCallVectorInstructionForms(f *testing.F) {
	data := make([]byte, 32)
	for j := range data {
		data[j] = byte(j*37 + 19)
	}
	for _, seed := range []struct{ op, dst, src, selector byte }{{0x60, 0, 1, 0}, {0x60, 8, 8, 0}, {0x70, 8, 12, 0xe4}, {0x70, 0, 0, 0x1b}, {0x70, 12, 8, 0x39}, {0x70, 0, 1, 0xff}} {
		f.Add(data, seed.op, seed.dst, seed.src, seed.selector)
	}
	f.Fuzz(func(t *testing.T, input []byte, op, dst, src, selector byte) {
		// Exactly one admitted vector operation, at most 32 data bytes, 15
		// choices per operand (including aliases), and all 256 shuffle controls.
		var data [32]byte
		copy(data[:], input)
		if op&0x10 == 0 {
			op = 0x60
		} else {
			op = 0x70
		}
		raw, r := vectorInstructionFixture(t, op, int(dst%15), int(src%15), selector, data[:16], data[16:], nil, false, false)
		checkedInstructionFixture(t, raw, r, 2)
	})
}

var arithmeticBranches = []struct {
	name   string
	opcode byte
	taken  func(bool, bool, bool, bool) bool
}{
	{"JB", 0x72, func(c, z, s, o bool) bool { return c }},
	{"JAE", 0x73, func(c, z, s, o bool) bool { return !c }},
	{"JE", 0x74, func(c, z, s, o bool) bool { return z }},
	{"JNE", 0x75, func(c, z, s, o bool) bool { return !z }},
	{"JBE", 0x76, func(c, z, s, o bool) bool { return c || z }},
	{"JA", 0x77, func(c, z, s, o bool) bool { return !c && !z }},
	{"JL", 0x7c, func(c, z, s, o bool) bool { return s != o }},
	{"JGE", 0x7d, func(c, z, s, o bool) bool { return s == o }},
	{"JLE", 0x7e, func(c, z, s, o bool) bool { return z || s != o }},
	{"JG", 0x7f, func(c, z, s, o bool) bool { return !z && s == o }},
}

func arithmeticInstructionFixture(t testing.TB, op string, width int, x, y uint64, branch byte) ([]byte, ValueCallRequest) {
	t.Helper()
	raw, r := valueCallFixture(t, "test.short", '=', false, false)
	body := []byte{0x48, 0xb8}
	body = binary.LittleEndian.AppendUint64(body, x) // MOVABS RAX,x
	body = append(body, 0x48, 0xba)
	body = binary.LittleEndian.AppendUint64(body, y) // MOVABS RDX,y
	if width == 64 {
		body = append(body, 0x48)
	}
	opcode := byte(0x39)
	if op == "add" {
		opcode = 0x01
	}
	body = append(body, opcode, 0xd0)                 // ADD/CMP (R|E)AX,(R|E)DX
	body = append(body, 0x48, 0x89, 0x44, 0x24, 0x28) // expose RAX: CMP preserves it; ADD32 zero-extends
	body = append(body, branch, 10)
	body = append(body, hexBytes(t, "48c744242000000000c348c744242001000000c3")...)
	replaceValueCallee(t, raw, r, hex.EncodeToString(body))
	r.Interface.Results = append(r.Interface.Results, Span{valueStack + 32, valueStack + 40})
	return raw, r
}

func checkArithmeticInstruction(t testing.TB, op string, width int, x, y uint64, condition int) {
	t.Helper()
	branch := arithmeticBranches[condition]
	raw, r := arithmeticInstructionFixture(t, op, width, x, y, branch.opcode)
	b := checkedInstructionFixture(t, raw, r, 2)
	// Reuse the independent arbitrary-precision oracle from the native relation
	// tests: overflow means the mathematical signed result is unrepresentable,
	// not a copy of setAddFlags/setSubFlags' bitwise overflow expressions.
	c, z, s, o := arithmeticFlags(op, x, y, width)
	want := uint64(0)
	if branch.taken(c, z, s, o) {
		want = 1
	}
	if len(b.Results) != 2 || b.Results[0].Value != want {
		t.Fatalf("%s%d %s x=%#x y=%#x: results %v, mathematical branch %d (CF=%v ZF=%v SF=%v OF=%v)", op, width, branch.name, x, y, b.Results, want, c, z, s, o)
	}
	register := x
	if op == "add" {
		if width == 32 {
			register = uint64(uint32(x) + uint32(y))
		} else {
			register = x + y
		}
	}
	if b.Results[1].Value != register {
		t.Fatalf("%s%d changed the wrong register bits: got %#x want %#x", op, width, b.Results[1].Value, register)
	}
}

func TestValueCallArithmeticFlagBoundaries(t *testing.T) {
	for _, width := range []int{32, 64} {
		high := uint64(1) << uint(width-1)
		maximum := uint64(math.MaxUint64)
		if width == 32 {
			maximum = math.MaxUint32
		}
		pairs := []struct {
			name string
			x, y uint64
		}{
			{"zero-zero", 0, 0}, {"zero-one", 0, 1}, {"one-zero", 1, 0}, {"one-one", 1, 1},
			{"max-zero", maximum, 0}, {"max-one", maximum, 1}, {"one-max", 1, maximum}, {"max-two", maximum, 2},
			{"positive-overflow", high - 1, 1}, {"double-positive-overflow", high - 1, high - 1},
			{"negative-overflow", high, high}, {"min-minus-one", high, maximum},
			{"mixed-sign", high, high - 1}, {"min-one", high, 1}, {"max-signed-minus-one", high - 1, maximum},
			{"one-min", 1, high}, {"max-max", maximum, maximum},
		}
		for _, op := range []string{"add", "cmp"} {
			for _, pair := range pairs {
				for condition, branch := range arithmeticBranches {
					t.Run(fmt.Sprintf("%s%d/%s/%s", op, width, pair.name, branch.name), func(t *testing.T) {
						x, y := pair.x, pair.y
						if width == 32 {
							x |= 0xa55aa55a00000000
							y |= 0x5aa55aa500000000
						}
						checkArithmeticInstruction(t, op, width, x, y, condition)
					})
				}
			}
		}
	}
}

func FuzzValueCallArithmeticFlags(f *testing.F) {
	for _, seed := range []struct {
		x, y      uint64
		wide, add bool
		branch    byte
	}{
		{0xffffffff, 1, false, true, 0}, {0x7fffffff, 1, false, true, 6}, {0x80000000, 1, false, false, 6},
		{math.MaxUint64, 1, true, true, 4}, {1 << 63, 1, true, false, 6}, {1 << 63, 1 << 63, true, true, 6},
	} {
		f.Add(seed.x, seed.y, seed.wide, seed.add, seed.branch)
	}
	f.Fuzz(func(t *testing.T, x, y uint64, wide, add bool, branch byte) {
		width := 32
		if wide {
			width = 64
		}
		op := "cmp"
		if add {
			op = "add"
		}
		checkArithmeticInstruction(t, op, width, x, y, int(branch)%len(arithmeticBranches))
	})
}
