package transitionoracle

import (
	"bytes"
	"math"
	"math/big"
	"math/rand/v2"
	"testing"
)

func allDescriptors() []Descriptor {
	var ds []Descriptor
	Descriptors(func(d Descriptor) bool { ds = append(ds, d); return true })
	return ds
}

// Domain selection happens before encoding. Each input word is independent of
// the descriptor and of the other payload; narrowing here selects the full
// representable domain, rather than an 8-bit correlated subset of an imm64.
func withPayload(d Descriptor, immediate uint64, displacement int64) Intent {
	i := d.Intent
	switch d.Encoding.Form {
	case MOVB8Imm64:
		i.Immediate = immediate
	case MOVB8Imm32:
		i.Immediate = uint64(uint32(immediate))
	case MOVC7, SUB81, SUB2D, ADD81, ADD05, AND81, AND25, CMP81, CMP3D, TESTF7, TESTA9:
		i.Immediate = uint64(int64(int32(immediate)))
	case SUB83, ADD83, AND83, CMP83:
		i.Immediate = uint64(int64(int8(immediate)))
	case MOVC6, MOVB0:
		i.Immediate = uint64(uint8(immediate))
	case JMPEB, JccShort:
		i.SignedDisp = int64(int8(displacement))
	case JMPE9, JccNear, CALLE8:
		i.SignedDisp = int64(int32(displacement))
	}
	if i.Width == 32 {
		i.Immediate &= 0xffffffff
	}
	if d.Encoding.DispBytes == 1 {
		i.SignedDisp = int64(int8(displacement))
	}
	if d.Encoding.DispBytes == 4 {
		i.SignedDisp = int64(int32(displacement))
	}
	return i
}

func roundTrip(t testing.TB, i Intent, e Encoding) []byte {
	t.Helper()
	b, err := Encode(i, e)
	if err != nil {
		t.Fatalf("encode %+v / %+v: %v", i, e, err)
	}
	d, err := Parse(b, 1<<32)
	if err != nil || d.Intent != i || d.Encoding != e || d.Length != len(b) {
		t.Fatalf("%x -> %+v, %v; want %+v / %+v", b, d, err, i, e)
	}
	if d.Next != 1<<32+uint64(len(b)) {
		t.Fatalf("next: %+v", d)
	}
	if i.Operation == Jump || i.Operation == Branch || i.Operation == Call {
		assertTarget(t, d, 1<<32)
	} else if d.Target != 0 {
		t.Fatal("nonbranch target")
	}
	assertIntegerPayloads(t, b, d)
	return b
}

// Check byte payloads independently using arbitrary-precision signed integers.
// Neither the encoder's binary package nor the parser's multiply/offset reader
// computes these expectations. The instruction's trailing fields are its disp
// followed by imm (or just rel for branches); opcode form fixes their widths.
func assertIntegerPayloads(t testing.TB, b []byte, d Decoded) {
	t.Helper()
	immWidth, signed := 0, true
	switch d.Encoding.Form {
	case MOVB8Imm64:
		immWidth, signed = 8, false
	case MOVB8Imm32:
		immWidth, signed = 4, false
	case MOVC7, SUB81, SUB2D, ADD81, ADD05, AND81, AND25, CMP81, CMP3D, TESTF7, TESTA9:
		immWidth = 4
	case SUB83, ADD83, AND83, CMP83:
		immWidth = 1
	case MOVC6, MOVB0:
		immWidth, signed = 1, false
	}
	if immWidth != 0 {
		n := literalInteger(b[d.Length-immWidth:d.Length], signed)
		width := uint(64)
		if d.Intent.Width == 32 {
			width = 32
		}
		if d.Intent.Width == 8 {
			width = 8
		}
		n.Mod(n, new(big.Int).Lsh(big.NewInt(1), width))
		if n.Uint64() != d.Intent.Immediate {
			t.Fatalf("immediate integer rule: %x -> %s, got %x", b, n, d.Intent.Immediate)
		}
	}
	dispWidth := int(d.Encoding.DispBytes)
	if d.Encoding.Form == JMPEB || d.Encoding.Form == JccShort {
		dispWidth = 1
	}
	if d.Encoding.Form == JMPE9 || d.Encoding.Form == JccNear || d.Encoding.Form == CALLE8 {
		dispWidth = 4
	}
	if dispWidth != 0 {
		end := d.Length - immWidth
		n := literalInteger(b[end-dispWidth:end], true)
		if n.Int64() != d.Intent.SignedDisp {
			t.Fatalf("displacement integer rule: %x -> %s, got %d", b, n, d.Intent.SignedDisp)
		}
	}
}

func literalInteger(little []byte, signed bool) *big.Int {
	bigEndian := make([]byte, len(little))
	for j, v := range little {
		bigEndian[len(little)-1-j] = v
	}
	n := new(big.Int).SetBytes(bigEndian)
	if signed && bigEndian[0] >= 128 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(little))))
	}
	return n
}

func TestDescriptorPopulation(t *testing.T) {
	want := map[Form]int{
		MOV89: 10856, MOV8B: 10856, MOVB8Imm64: 64, MOVB8Imm32: 16,
		MOVC7: 1357, LEA8D: 4288, SUB83: 64, SUB81: 64, SUB2D: 8,
		AND83: 64, AND81: 64, AND25: 8, JMPEB: 1, JMPE9: 1, CPUID0FA2: 1,
		MOV88: 10856, MOV8A: 10856, MOVC6: 1357, MOVB0: 136,
		ADD83: 64, ADD81: 64, ADD05: 8, CALLE8: 1, PUSH50: 16, POP58: 16, RETC3: 1, SYSCALL0F05: 1,
		CMP39: 1088, CMP3B: 1088, TEST85: 1088, CMP83: 136, CMP81: 136, TESTF7: 136, CMP3D: 17, TESTA9: 17, JccShort: 10, JccNear: 10,
	}
	// Per REX: non-SIB bases have 6+7+7 modes; no-index SIB
	// bases have 7+8+8 modes times four scales, with X=0 only.
	// Add one RIP spelling per prefix. All-width MOV has 17 prefixes
	// (none plus all REX bytes), nine with X=0: 17*21+9*23*4=1185
	// memory addresses; times eight selectors plus 17*64 register forms.
	// LEA uses only eight REX.W prefixes; its corresponding count is 4288.
	counts := map[Form]int{}
	seen := map[string]bool{}
	rng := rand.New(rand.NewPCG(0x123456789abcdef0, 0xfedcba9876543210))
	words := []uint64{0, 1, 127, 128, 255, 0x7fffffff, 0x80000000, 0xffffffff, 1 << 32, 1 << 63, math.MaxUint64, 0x0123456789abcdef, 0xfedcba9876543210}
	disps := []int64{0, 1, -1, 127, -128, 128, -129, math.MaxInt32, math.MinInt32, 0x12345678, -0x12345678}
	for d := range Descriptors {
		counts[d.Encoding.Form]++
		b := roundTrip(t, d.Intent, d.Encoding)
		if seen[string(b)] {
			t.Fatalf("duplicate descriptor bytes %x", b)
		}
		seen[string(b)] = true
		// Payload axes are exercised separately, not a huge Cartesian product.
		for _, word := range words {
			roundTrip(t, withPayload(d, word, 0), d.Encoding)
		}
		for _, disp := range disps {
			roundTrip(t, withPayload(d, 0, disp), d.Encoding)
		}
		roundTrip(t, withPayload(d, rng.Uint64(), int64(rng.Uint64())), d.Encoding)
		// Every proper prefix is incomplete, even for instructions with a
		// zero payload. Every continuation byte leaves consumption unchanged.
		for n := 0; n < len(b); n++ {
			if parsed, err := Parse(b[:n], 1<<32); err == nil || parsed != (Decoded{}) {
				t.Fatalf("truncated %x: %+v %v", b[:n], parsed, err)
			}
		}
		parsed, err := Parse(append(append([]byte{}, b...), 0x66, 0x48, 0xff), 1<<32)
		if err != nil || parsed.Length != len(b) || parsed.Intent != d.Intent || parsed.Encoding != d.Encoding {
			t.Fatalf("trailing bytes affected %x: %+v %v", b, parsed, err)
		}
	}
	if len(seen) != 54814 || len(counts) != len(want) {
		t.Fatalf("population: %d, counts %v", len(seen), counts)
	}
	for form, count := range want {
		if counts[form] != count {
			t.Fatalf("form %d: got %d want %d", form, counts[form], count)
		}
	}
	n := 0
	Descriptors(func(Descriptor) bool { n++; return false })
	if n != 1 {
		t.Fatalf("iterator ignored stop: %d", n)
	}
	t.Logf("%d unique descriptors; per-form counts: %v; full payload products are sampled, not exhausted", len(seen), counts)
}

func TestAllByteImmediateAndDisplacementValues(t *testing.T) {
	for value := 0; value < 256; value++ {
		signed := int64(value)
		if value >= 128 {
			signed -= 256
		}
		for _, form := range []Form{SUB83, AND83} {
			op := Subtract
			if form == AND83 {
				op = And
			}
			b := roundTrip(t, Intent{Operation: op, Dst: 9, Immediate: uint64(signed)}, Encoding{Form: form, REX: 0x4f})
			if b[len(b)-1] != byte(value) {
				t.Fatalf("imm8 %x: %x", value, b)
			}
		}
		for _, width := range []uint8{0, 32} {
			imm := uint64(signed)
			rex := byte(0x4f)
			if width == 32 {
				imm &= 0xffffffff
				rex = 0x47
			}
			roundTrip(t, Intent{Operation: CompareImmediate, Dst: 9, Width: width, Immediate: imm}, Encoding{Form: CMP83, REX: rex})
		}
		for _, form := range []Form{MOVC6, MOVB0} {
			roundTrip(t, Intent{Operation: MoveImmediate, Dst: 0, HighDst: true, Width: 8, Immediate: uint64(value)}, Encoding{Form: form})
			roundTrip(t, Intent{Operation: MoveImmediate, Dst: 15, Width: 8, Immediate: uint64(value)}, Encoding{Form: form, REX: 0x4f})
		}
		for _, cc := range []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15} {
			roundTrip(t, Intent{Operation: Branch, Condition: cc, SignedDisp: signed}, Encoding{Form: JccShort})
		}
		roundTrip(t, Intent{Operation: Jump, SignedDisp: signed}, Encoding{Form: JMPEB})
		roundTrip(t, Intent{Operation: Load, Base: 13, Dst: 12, SignedDisp: signed}, Encoding{Form: MOV8B, REX: 0x4d, SIB: true, Scale: 3, DispBytes: 1})
	}
}

// This enumeration starts from raw bytes, not from Descriptors or Encode. It
// covers ALL ModRM selector/mode bytes and ALL SIB bytes, including indexed,
// absent-base and arithmetic-memory refusals. The accepted set must equal the
// descriptor set's ModRM population, so two incomplete positive enumerators
// cannot silently agree merely by never presenting the missing form.
func TestRawModRMPopulation(t *testing.T) {
	accepted := map[string]bool{}
	trials := 0
	prefixes := []int{0}
	for rex := 0x40; rex <= 0x4f; rex++ {
		prefixes = append(prefixes, rex)
	}
	for _, rex := range prefixes {
		for _, op := range []byte{0x88, 0x89, 0x8a, 0x8b, 0x8d, 0xc6, 0xc7, 0x83, 0x81, 0x39, 0x3b, 0x85, 0xf7} {
			for m := 0; m < 256; m++ {
				mode, selector, rm := m/64, m/8%8, m%8
				hasSIB := mode < 3 && rm == 4
				sibCount := 1
				if hasSIB {
					sibCount = 256
				}
				for s := 0; s < sibCount; s++ {
					trials++
					valid := true
					if mode == 0 && hasSIB && s%8 == 5 {
						valid = false
					}
					if hasSIB && (rex/2%2 != 0 || s/8%8 != 4) {
						valid = false
					}
					if op == 0x8d && (mode == 3 || rex&8 == 0) {
						valid = false
					}
					if (op == 0xc7 || op == 0xc6 || op == 0xf7) && selector != 0 {
						valid = false
					}
					if (op == 0x83 || op == 0x81) && (mode != 3 || selector != 0 && selector != 4 && selector != 5 && selector != 7 || selector != 7 && rex&8 == 0) {
						valid = false
					}
					if (op == 0x39 || op == 0x3b || op == 0x85 || op == 0xf7) && mode != 3 {
						valid = false
					}
					b := []byte{}
					if rex != 0 {
						b = append(b, byte(rex))
					}
					b = append(b, op, byte(m))
					if hasSIB {
						b = append(b, byte(s))
					}
					b = append(b, make([]byte, 12)...)
					d, err := Parse(b, 1<<32)
					if (err == nil) != valid {
						t.Fatalf("raw %x: %+v, %v; valid=%v", b, d, err, valid)
					}
					if !valid {
						if d != (Decoded{}) {
							t.Fatal("partial refusal")
						}
						continue
					}
					length := 2
					if rex != 0 {
						length++
					}
					if hasSIB {
						length++
					}
					if mode == 1 {
						length++
					}
					if mode == 2 || mode == 0 && rm == 5 {
						length += 4
					}
					if op == 0x83 || op == 0xc6 {
						length++
					}
					if op == 0xc7 || op == 0x81 || op == 0xf7 {
						length += 4
					}
					if d.Length != length {
						t.Fatalf("raw %x length %d want %d", b, d.Length, length)
					}
					encoded, err := Encode(d.Intent, d.Encoding)
					if err != nil || !bytes.Equal(encoded, b[:length]) {
						t.Fatalf("raw spelling lost: %x -> %x, %v", b[:length], encoded, err)
					}
					accepted[string(b[:length])] = true
				}
			}
		}
	}
	if trials != 1409096 || len(accepted) != 53258 {
		t.Fatalf("raw trials %d positives %d", trials, len(accepted))
	}
	for d := range Descriptors {
		if d.Intent.FS {
			continue
		} // The independent FS-prefix population is below.
		switch d.Encoding.Form {
		case MOV89, MOV8B, MOVC7, LEA8D, SUB83, SUB81, ADD83, ADD81, AND83, AND81, MOV88, MOV8A, MOVC6, CMP39, CMP3B, TEST85, CMP83, CMP81, TESTF7:
			b, err := Encode(d.Intent, d.Encoding)
			if err != nil || !accepted[string(b)] {
				t.Fatalf("descriptor not in independent raw population: %+v, %x, %v", d, b, err)
			}
			delete(accepted, string(b))
		}
	}
	if len(accepted) != 0 {
		t.Fatalf("%d raw admitted encodings missing from descriptors", len(accepted))
	}
	t.Logf("%d raw ModRM/SIB trials; 53,258 accepted structural spellings", trials)
}

func TestRawFSPopulation(t *testing.T) {
	accepted := map[string]bool{}
	prefixes := []int{0}
	for rex := 0x40; rex <= 0x4f; rex++ {
		prefixes = append(prefixes, rex)
	}
	for _, rex := range prefixes {
		for _, op := range []byte{0x88, 0x89, 0x8a, 0x8b, 0xc6, 0xc7} {
			for modrm := 0; modrm < 256; modrm++ {
				mode, selector, rm := modrm/64, modrm/8%8, modrm%8
				count := 1
				if mode != 3 && rm == 4 {
					count = 256
				}
				for sib := 0; sib < count; sib++ {
					valid := mode == 0 && rm == 4 && sib%8 == 5 && sib/8%8 == 4 && rex&2 == 0
					if (op == 0xc6 || op == 0xc7) && selector != 0 {
						valid = false
					}
					b := []byte{0x64}
					if rex != 0 {
						b = append(b, byte(rex))
					}
					b = append(b, op, byte(modrm))
					if count == 256 {
						b = append(b, byte(sib))
					}
					b = append(b, make([]byte, 12)...)
					d, err := Parse(b, 1<<32)
					if (err == nil) != valid {
						t.Fatalf("FS raw %x accepted=%v want %v", b, err == nil, valid)
					}
					if !valid {
						if d != (Decoded{}) {
							t.Fatal("partial FS refusal")
						}
						continue
					}
					length := 8
					if rex != 0 {
						length++
					}
					if op == 0xc6 {
						length++
					}
					if op == 0xc7 {
						length += 4
					}
					if d.Length != length {
						t.Fatal("FS extent", d, length)
					}
					raw, err := Encode(d.Intent, d.Encoding)
					if err != nil || !bytes.Equal(raw, b[:length]) {
						t.Fatal("FS spelling lost", err)
					}
					accepted[string(raw)] = true
				}
			}
		}
	}
	if len(accepted) != 1224 {
		t.Fatal("FS structural population", len(accepted))
	}
	for d := range Descriptors {
		if !d.Intent.FS {
			continue
		}
		b, err := Encode(d.Intent, d.Encoding)
		if err != nil || !accepted[string(b)] {
			t.Fatal("missing FS descriptor", d, err)
		}
		delete(accepted, string(b))
	}
	if len(accepted) != 0 {
		t.Fatal("raw FS admission absent from descriptors")
	}
}
