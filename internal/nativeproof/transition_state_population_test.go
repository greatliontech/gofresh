package nativeproof

import (
	"encoding/binary"
	quickrand "math/rand"
	"slices"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func stateOp(i to.Intent, choice uint8) stateInstruction {
	return stateInstruction{intent: i, choice: choice}
}

// Each record factors operation, three register selectors, form, mask exponent,
// small pointer offset, write-only-region selector, full uint64 immediate,
// independent uint64 scalar operand, and full int32 displacement. The final four
// bytes are additional form entropy.
// Padding preserves a final partial command. Arrays have no semantic length
// cap. Materialization stops only after a prefix exceeds the *supplied checker*
// instruction limit; stateCheckLocated checks that exact overflow and the last
// admissible prefix, without claiming execution of the uninstantiated suffix.
func stateGenerated(data []byte) []stateInstruction {
	ops := []stateInstruction{stateOp(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4}, 0)}
	notAnchor := func(v uint8) uint8 {
		v %= 16
		if v == 12 {
			v = 13
		}
		return v
	}
	for len(data) != 0 {
		var record [32]byte
		n := copy(record[:], data)
		data = data[n:]
		dst, src, base := notAnchor(record[1]), record[2]%16, notAnchor(record[3])
		choice := record[4] ^ record[28] ^ record[29] ^ record[30] ^ record[31]
		imm := binary.LittleEndian.Uint64(record[8:16])
		operand := binary.LittleEndian.Uint64(record[16:24])
		disp := int64(int32(binary.LittleEndian.Uint32(record[24:28])))
		small := int64(int(record[6]%33) - 16)
		off := disp % 25 // all byte offsets, including unaligned overlap
		storeOff := off
		if record[7]&1 != 0 {
			storeOff = 56 // declared writable but not readable
		}
		add := func(i to.Intent) { ops = append(ops, stateOp(i, choice)) }
		switch record[0] % 12 {
		case 0:
			add(to.Intent{Operation: to.MoveRegister, Dst: dst, Src: src})
		case 1:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: imm})
		case 2:
			ops = append(ops, stateOp(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: uint64(int64(int32(imm)))}, choice|1))
		case 3:
			add(to.Intent{Operation: to.MoveImmediate32, Dst: dst, Immediate: uint64(uint32(imm))})
		case 4:
			add(to.Intent{Operation: to.Load, Dst: dst, Base: 12, SignedDisp: off})
		case 5:
			add(to.Intent{Operation: to.Store, Src: src, Base: 12, SignedDisp: storeOff})
		case 6:
			add(to.Intent{Operation: to.StoreImmediate, Base: 12, SignedDisp: storeOff, Immediate: uint64(int64(int32(imm)))})
		case 7:
			// Full signed displacement on a scalar, independent of the finite
			// memory permissions. LEA cannot promote it into a pointer.
			add(to.Intent{Operation: to.MoveImmediate, Dst: base, Immediate: operand})
			add(to.Intent{Operation: to.LEA, Dst: dst, Base: base, SignedDisp: disp})
		case 8:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: operand})
			add(to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(int64(int32(imm)))})
		case 9:
			add(to.Intent{Operation: to.LEA, Dst: dst, Base: 12, SignedDisp: small})
			add(to.Intent{Operation: to.And, Dst: dst, Immediate: -uint64(1 << (record[5] % 32))})
		case 10:
			add(to.Intent{Operation: to.LEA, Dst: dst, Base: 12, SignedDisp: small})
		case 11:
			add(to.Intent{Operation: to.MoveRegister, Dst: dst, Src: 12})
			add(to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(small)})
		}
		if 2*len(ops)+1 > statePopulationInstructions {
			return ops
		}
	}
	return ops
}

func FuzzTransitionStateComplete(f *testing.F) {
	// The seed population has every semantic class and chains beyond twenty
	// operations. Fuzz inputs independently vary the full payload fields.
	for seed, count := range []int{12, 24, 36, 65, 129, 4096} {
		data := make([]byte, 32*count)
		for j := 0; j < len(data)/32; j++ {
			r := data[j*32 : (j+1)*32]
			r[0], r[1], r[2], r[3] = byte(j%12), byte((j+int(seed))%16), byte((j*7+1)%16), byte((j*3+2)%16)
			r[4], r[5], r[6] = byte(j), byte(j+25), byte(j*11)
			binary.LittleEndian.PutUint64(r[8:], ^uint64(0)-uint64(j)*0x123456789abcdef)
			binary.LittleEndian.PutUint64(r[16:], uint64(j)*0xfedcba987654321+uint64(seed))
			binary.LittleEndian.PutUint32(r[24:], 0x80000000+uint32(j)*0x1234567)
		}
		f.Add(data, uint64(seed)*0x123456789abcdef, uint64(seed)*37, uint32(seed*7919), uint64(seed)*71)
	}
	f.Add([]byte{}, uint64(0), uint64(0), uint32(0), uint64(0))
	// Unrefreshed heap dependencies cross the actual depth frontier, despite
	// repeatedly writing the same scalar value. No command-count cap hides them.
	chain := make([]byte, 32*160)
	for j := 0; j < 160; j++ {
		chain[32*j] = byte(4 + j%2) // load RAX, then store RAX, at origin+0
	}
	f.Add(chain, uint64(731), uint64(971), uint32(0), uint64(119))
	f.Fuzz(func(t *testing.T, data []byte, valuation, layout uint64, residue uint32, cuts uint64) {
		face := stateFace(1<<31, uint64(residue)%(1<<31))
		stateCheckProgram(t, stateGenerated(data), face, stateInitial(face, valuation), layout, cuts, false)
	})
}

// Local segment properties release the whole-program anchor register. Every
// architectural register can be destination/source/base, including RSP and R12.
// All selected intermediate cuts are checked against a reference prefix.
func FuzzTransitionStateLocal(f *testing.F) {
	for op := uint8(0); op < 10; op++ {
		f.Add(op, uint8(op+7), uint8(op+3), uint8(op+5), ^uint64(0)-uint64(op), int32(-2147483648+int64(op)), uint8(op), uint64(op)*0x654321fedcba)
	}
	f.Add(uint8(8), uint8(0), uint8(15), uint8(4), uint64(0x8000000000000000), int32(2147483647), uint8(31), uint64(1))
	f.Add(uint8(4), uint8(0), uint8(1), uint8(4), uint64(0xffffffffffffffff), int32(-2147483648), uint8(2), uint64(731))
	// Uniform 64-bit values make signed-overflow boundaries rare. These seeds
	// supplement, rather than replace, the independent wide operand domain.
	for j, edge := range []struct {
		left  uint64
		right int32
	}{{1 << 63, 1}, {1<<63 - 1, -1}, {0, 1}, {1, 1}, {16, 1}, {0x80, 0}} {
		f.Add(uint8(4), uint8(0), uint8(15), uint8(4), edge.left, edge.right, uint8(j%3), uint64(j)*0x123456789abcdef)
	}
	f.Fuzz(func(t *testing.T, kind, dst, src, base uint8, immediate uint64, displacement int32, form uint8, valuation uint64) {
		dst, src, base = dst%16, src%16, base%16
		face := stateFace(1<<31, valuation%(1<<31))
		var ops []stateInstruction
		add := func(i to.Intent) { ops = append(ops, stateOp(i, form)) }
		switch kind % 10 {
		case 0:
			add(to.Intent{Operation: to.MoveRegister, Dst: dst, Src: src})
		case 1:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: immediate})
		case 2:
			add(to.Intent{Operation: to.MoveImmediate32, Dst: dst, Immediate: uint64(uint32(immediate))})
		case 3:
			add(to.Intent{Operation: to.MoveImmediate, Dst: base, Immediate: immediate})
			add(to.Intent{Operation: to.LEA, Dst: dst, Base: base, SignedDisp: int64(displacement)})
		case 4:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: immediate})
			add(to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(int64(displacement))})
		case 5:
			add(to.Intent{Operation: to.MoveRegister, Dst: base, Src: 4})
			add(to.Intent{Operation: to.Store, Base: base, Src: src, SignedDisp: int64(displacement % 25)})
			add(to.Intent{Operation: to.Load, Base: base, Dst: dst, SignedDisp: int64(displacement % 25)})
		case 6:
			add(to.Intent{Operation: to.MoveRegister, Dst: base, Src: 4})
			add(to.Intent{Operation: to.StoreImmediate, Base: base, Immediate: uint64(int64(displacement))})
			add(to.Intent{Operation: to.Load, Base: base, Dst: dst})
		case 7:
			add(to.Intent{Operation: to.MoveRegister, Dst: base, Src: 4})
			add(to.Intent{Operation: to.LEA, Dst: dst, Base: base, SignedDisp: int64(displacement)})
		case 8:
			add(to.Intent{Operation: to.MoveRegister, Dst: dst, Src: 4})
			add(to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(int64(displacement))})
			add(to.Intent{Operation: to.And, Dst: dst, Immediate: -uint64(1 << (form % 32))})
		case 9:
			// Arbitrary entry operand, independent of the immediate payload.
			// RSP is the pointer case; all other initial registers are scalars.
			add(to.Intent{Operation: to.Subtract, Dst: dst, Immediate: uint64(int64(int32(immediate)))})
		}
		stateCheckProgram(t, ops, face, stateInitial(face, valuation), immediate, valuation, true)
	})
}

func FuzzTransitionStateOverlap(f *testing.F) {
	for shift := uint8(0); shift < 16; shift++ {
		if shift == 8 { // negative zero duplicates the zero-shift population
			continue
		}
		for mode := uint8(0); mode < 3; mode++ {
			f.Add(shift, mode, uint64(shift)*0xfedcba987654321+uint64(mode), uint8(shift+mode))
		}
	}
	f.Fuzz(func(t *testing.T, distance, mode uint8, valuation uint64, form uint8) {
		shift := int64(distance % 8)
		if distance&8 != 0 {
			shift = -shift
		}
		face := stateFace(32, valuation%32)
		initial := stateInitial(face, valuation)
		// A raw input word numerically equal to a pointer remains scalar. This
		// assignment is made in the reference entry state, before certificate data.
		initial.words[0] = initial.origin + 8
		for j := int64(0); j < 8; j++ {
			initial.memory[stateLocation{off: j}] = stateByte{value: byte((initial.origin + 8) >> (8 * j))}
		}
		var ops []stateInstruction
		add := func(i to.Intent) { ops = append(ops, stateOp(i, form)) }
		add(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4})
		add(to.Intent{Operation: to.LEA, Dst: 3, Base: 12, SignedDisp: 8})
		add(to.Intent{Operation: to.Store, Base: 12, Src: 3, SignedDisp: -16})
		add(to.Intent{Operation: to.Load, Base: 12, Dst: 5, SignedDisp: -16})
		add(to.Intent{Operation: to.MoveRegister, Dst: 6, Src: 5})
		add(to.Intent{Operation: to.Store, Base: 12, Src: 6, SignedDisp: 16})
		source := uint8(3)
		switch mode % 3 {
		case 1:
			add(to.Intent{Operation: to.MoveImmediate, Dst: 7, Immediate: initial.origin + 8})
			source = 7
		case 2:
			add(to.Intent{Operation: to.Load, Base: 12, Dst: 7})
			source = 7
		}
		add(to.Intent{Operation: to.Store, Base: 12, Src: source, SignedDisp: -16 + shift})
		add(to.Intent{Operation: to.Load, Base: 12, Dst: 8, SignedDisp: -16})
		add(to.Intent{Operation: to.Load, Base: 12, Dst: 9, SignedDisp: -16 + shift})
		add(to.Intent{Operation: to.Store, Base: 12, Src: 8, SignedDisp: 16})
		add(to.Intent{Operation: to.Load, Base: 12, Dst: 10, SignedDisp: 16})
		// The same-value store is still an ordered write and part of the frame.
		add(to.Intent{Operation: to.Load, Base: 12, Dst: 11, SignedDisp: 24})
		add(to.Intent{Operation: to.Store, Base: 12, Src: 11, SignedDisp: 24})
		stateCheckProgram(t, ops, face, initial, valuation, uint64(distance), false)
		if shift != 0 || mode%3 != 0 {
			// Original word's mixed/overwritten lanes must not authorize an
			// access, including the zero-shift equal-numeric scalar overwrite.
			bad := append(slices.Clone(ops), stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 10}, form))
			x := stateArrange(t, stateExpanded(bad), valuation)
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(bad)*2), TransitionLimits{})
			transitionRefused(t, c, err)
		}
	})
}

func FuzzTransitionStateCongruence(f *testing.F) {
	for _, exponent := range []uint8{0, 1, 4, 7, 8, 16, 30, 31} {
		f.Add(exponent, uint32(0x76543210), int32(-2147483648), uint8(0), uint64(0xfedcba987654321))
		f.Add(exponent, uint32(0xffffffff), int32(2147483647), uint8(2), uint64(0x8123456789abcdef))
	}
	f.Fuzz(func(t *testing.T, exponent uint8, residue uint32, displacement int32, form uint8, valuation uint64) {
		k := uint64(1) << (exponent % 32)
		face := stateFace(k, uint64(residue)%k)
		ops := []stateInstruction{
			stateOp(to.Intent{Operation: to.LEA, Dst: 0, Base: 4, SignedDisp: int64(displacement)}, form),
			stateOp(to.Intent{Operation: to.And, Dst: 0, Immediate: -k}, form),
		}
		stateCheckProgram(t, ops, face, stateInitial(face, valuation), valuation, 0, true)
		if k > 1 {
			// The bounds contain many origins in both residue classes mod k;
			// k/2 congruence cannot establish one origin-relative aligned offset.
			face.Origin.Modulus = k / 2
			face.Origin.Residue %= k / 2
			x := stateArrange(t, stateExpanded(ops), valuation)
			c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(ops)*2), TransitionLimits{})
			transitionRefused(t, c, err)
		}
	})
}

func FuzzTransitionStateRawEqualAddress(f *testing.F) {
	for mode := uint8(0); mode < 6; mode++ {
		f.Add(mode, uint8(mode+8), uint64(mode)*0xfedcba987654321, uint8(mode))
	}
	f.Fuzz(func(t *testing.T, mode, destination uint8, valuation uint64, form uint8) {
		face := stateFace(16, valuation%16)
		// Positive signed-32 origins let C7 and B8/32 carry exactly the same
		// numerical pointer as B8/64, raw words and arbitrary entry registers.
		face.Origin.Min, face.Origin.Max = 1<<28, 1<<30
		face.Envelope = RelativeSpan{-64, 64}
		initial := stateInitial(face, valuation)
		dst := destination % 16
		if dst == 4 || dst == 12 {
			dst = 13
		}
		initial.regs[dst] = initial.origin
		initial.words[0] = initial.origin
		for j := int64(0); j < 8; j++ {
			initial.memory[stateLocation{off: j}] = stateByte{value: byte(initial.origin >> (8 * j))}
		}
		ops := []stateInstruction{stateOp(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4}, form)}
		add := func(i to.Intent, choice uint8) { ops = append(ops, stateOp(i, choice)) }
		if mode%6 != 0 {
			// The scalar-producing instruction must also erase old provenance.
			add(to.Intent{Operation: to.MoveRegister, Dst: dst, Src: 12}, form)
		}
		switch mode % 6 {
		case 0: // untouched arbitrary scalar, assigned equal bits by this valuation
		case 1:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: initial.origin}, 0)
		case 2:
			add(to.Intent{Operation: to.MoveImmediate, Dst: dst, Immediate: initial.origin}, 1)
		case 3:
			add(to.Intent{Operation: to.MoveImmediate32, Dst: dst, Immediate: initial.origin}, form)
		case 4:
			add(to.Intent{Operation: to.Load, Base: 12, Dst: dst}, form)
		case 5:
			add(to.Intent{Operation: to.Store, Base: 12, Src: 12}, form)
			add(to.Intent{Operation: to.StoreImmediate, Base: 12, Immediate: initial.origin}, form)
			add(to.Intent{Operation: to.Load, Base: 12, Dst: dst}, form)
		}
		// Copy/respill/reload cannot launder equal scalar bits into provenance.
		add(to.Intent{Operation: to.Store, Base: 12, Src: dst, SignedDisp: 16}, form)
		add(to.Intent{Operation: to.Load, Base: 12, Dst: dst, SignedDisp: 16}, form)
		stateCheckProgram(t, ops, face, initial, valuation, valuation, false)
		bad := append(slices.Clone(ops), stateOp(to.Intent{Operation: to.Load, Base: dst, Dst: 0}, form))
		x := stateArrange(t, stateExpanded(bad), valuation)
		c, err := CheckTransition(t.Context(), x.im, face, x.proposal(len(bad)*2), TransitionLimits{})
		transitionRefused(t, c, err)
		// The same access through the actual origin is an expected-accept
		// control, preventing an implementation that simply refuses all loads.
		good := append(slices.Clone(ops), stateOp(to.Intent{Operation: to.Load, Base: 12, Dst: 0}, form))
		stateCheckProgram(t, good, face, initial, valuation, valuation, false)
	})
}

func FuzzTransitionStateAlignmentZero(f *testing.F) {
	for _, singleton := range []bool{false, true} {
		f.Add(uint8(31), uint32(0x7fffffff), uint64(0), uint64(0xfedcba987654321), singleton)
		f.Add(uint8(4), uint32(3), uint64(1), uint64(0x8123456789abcdef), singleton)
		f.Add(uint8(0), uint32(0), uint64(0), uint64(731), singleton)
	}
	f.Fuzz(func(t *testing.T, exponent uint8, residue uint32, originIndex, valuation uint64, singleton bool) {
		k := uint64(1) << (exponent % 32)
		face := stateFace(k, uint64(residue)%k)
		face.Regions, face.Words = nil, nil
		face.Origin.Min, face.Origin.Max = 0, 1<<44
		if singleton {
			face.Origin.Max = face.Origin.Residue
		}
		face.Envelope = RelativeSpan{-int64(face.Origin.Residue), 64}
		initial := stateInitial(face, valuation)
		initial.origin = face.Origin.Residue + originIndex%((face.Origin.Max-face.Origin.Residue)/k+1)*k
		initial.regs[4] = initial.origin
		ops := []stateInstruction{stateOp(to.Intent{Operation: to.And, Dst: 4, Immediate: -k}, exponent)}
		// Singleton domains force a zero result, including any projected ZF.
		// Nonsingletons include both zero and nonzero aligned results; entry values
		// exercise the private predicate without promoting one sample to a bound.
		stateCheckProgram(t, ops, face, initial, valuation, 0, true)
	})
}

func FuzzTransitionStateJointValuations(f *testing.F) {
	for _, count := range []int{1, 17, 65, 129} {
		data := make([]byte, 32*count)
		for j := 0; j < count; j++ {
			r := data[32*j:]
			r[0], r[1], r[2], r[3], r[4] = byte(j%12), byte(j%16), byte((j+1)%16), byte((j+2)%16), byte(j)
			binary.LittleEndian.PutUint64(r[8:], uint64(j)*0xfedcba987654321)
			binary.LittleEndian.PutUint64(r[16:], ^uint64(j))
			binary.LittleEndian.PutUint32(r[24:], uint32(j)*0x1234567)
		}
		values := make([]byte, 8+128+1+80)
		for j := range values {
			values[j] = byte(j*count + 17)
		}
		f.Add(data, values, []byte{0x55, 0xaa}, uint64(count), uint32(count))
	}
	f.Fuzz(func(t *testing.T, data, valuation, cutBits []byte, layout uint64, residue uint32) {
		face := stateFace(1<<31, uint64(residue)%(1<<31))
		ops := stateGenerated(data)
		var cuts []int
		for j := 1; j < 2*len(ops); j++ {
			if (j-1)/8 < len(cutBits) && cutBits[(j-1)/8]&(1<<((j-1)%8)) != 0 {
				cuts = append(cuts, j)
			}
		}
		stateCheckProgram(t, ops, face, stateRawInitial(face, valuation), layout, 0, false, cuts)
	})
}

// Local memory transfer factors through eight ordered bytes at the independently
// computed base+displacement, not through a fixed small address. Base LEA, base
// SUB and access displacement are independent full signed-32 payloads. Their
// sums cover the reachable offsets of this three-operand construction, including
// cancellation to zero; no modulo-small-offset reduction occurs. Fragmentation,
// overlap, input-word placement, extra untouched regions and joint byte values
// vary separately. Exact keysets/frame checks observe all extra bytes as well.
// This tests locality/translation and provenance composition; the separate
// interface-size controls establish initialization at large inventory sizes.
// Neither alone claims enumeration of every larger program or region geometry.
func FuzzTransitionStateMemoryTranslation(f *testing.F) {
	for j, p := range [][3]int32{{12345, 0, -12345}, {-98765, -123, 98642}, {2147483647, -2147483648, -2147483648}, {-2147483648, 2147483647, 2147483647}, {17, 9, 11}, {-17, 9, -11}} {
		values := make([]byte, 512)
		for k := range values {
			values[k] = byte(k*37 + j)
		}
		f.Add(p[0], p[1], p[2], int32(j)*0x1234567, uint64(j)*0xfedcba987654321, values, uint64(j), uint8(j*3))
	}
	f.Fuzz(func(t *testing.T, baseDelta, subtract, displacement, remote int32, shape uint64, valuation []byte, layout uint64, registerRotation uint8) {
		stateTranslatedMemory(t, baseDelta, subtract, displacement, remote, shape, valuation, layout, registerRotation)
	})
}

func stateTranslatedMemory(t testing.TB, baseDelta, subtract, displacement, remote int32, shape uint64, valuation []byte, layout uint64, registerRotation uint8, chains ...[]stateInstruction) {
	t.Helper()
	base := int64(baseDelta) - int64(subtract)
	if len(chains) != 0 {
		base = 0
		for _, op := range chains[0] {
			switch op.intent.Operation {
			case to.LEA:
				base += op.intent.SignedDisp
			case to.Subtract:
				base -= int64(op.intent.Immediate)
			case to.And:
				k := -int64(op.intent.Immediate)
				remainder := (base + int64(shape%(1<<31))) % k
				if remainder < 0 {
					remainder += k
				}
				base -= remainder
			}
		}
	}
	a := base + int64(displacement)
	lo, hi := a-int64(shape&15), a+16+int64(shape>>4&15)
	face := stateFace(16, shape%16)
	face.Envelope = RelativeSpan{-1 << 35, 1 << 35}
	bias := int64(1 << 34)
	if len(chains) != 0 {
		// Even the first instruction-overflow prefix's summed int32 offsets
		// fit this envelope. The extra regions remain disjoint from all such
		// addressed regions; no enormous intervening byte range is allocated.
		face.Origin.Min, face.Origin.Max = 1<<45, 1<<46
		face.Origin.Modulus, face.Origin.Residue = 1<<31, shape%(1<<31)
		face.Envelope = RelativeSpan{-1 << 44, 1 << 44}
		bias = 1 << 43
	}
	left, right := int64(remote)-bias, int64(remote)+bias
	nLeft, nRight := 1+int64(shape>>16&31), 1+int64(shape>>24&31)
	face.Regions = []RelativeRegion{
		// Accesses/words have a containing permission declaration. The
		// subregions vary the byte-union inventory without assuming that the
		// admitted permission rule composes adjacent declarations into one.
		{RelativeSpan{lo, hi}, true, true},
		{RelativeSpan{lo, a + 3}, true, true}, {RelativeSpan{a + 3, a + 11}, true, true}, {RelativeSpan{a + 11, hi}, true, true},
		{RelativeSpan{-8, 8}, true, true},
		{RelativeSpan{left, left + nLeft}, shape&256 != 0, shape&512 != 0},
		{RelativeSpan{right, right + nRight}, true, shape&1024 != 0},
	}
	if shape&2048 != 0 {
		face.Regions = append(face.Regions, RelativeRegion{RelativeSpan{a + 1, a + 15}, true, true})
	}
	word := lo + int64((shape>>32)%uint64(hi-lo-7))
	face.Words = []int64{word}
	if word >= 8 || word+8 <= 0 {
		face.Words = append(face.Words, 0)
	}
	if nRight >= 8 && shape&4096 != 0 {
		face.Words = append(face.Words, right+int64((shape>>40)%uint64(nRight-7)))
	}
	if shape&8192 != 0 {
		slices.Reverse(face.Regions)
		slices.Reverse(face.Words)
	}
	form := uint8(shape)
	ops := []stateInstruction{
		stateOp(to.Intent{Operation: to.LEA, Dst: 12, Base: 4, SignedDisp: int64(baseDelta)}, form),
		stateOp(to.Intent{Operation: to.Subtract, Dst: 12, Immediate: uint64(int64(subtract))}, form),
		stateOp(to.Intent{Operation: to.Store, Base: 4, Src: 12}, form),
		stateOp(to.Intent{Operation: to.Load, Base: 4, Dst: 13}, form),
		stateOp(to.Intent{Operation: to.MoveRegister, Dst: 14, Src: 13}, form),
		stateOp(to.Intent{Operation: to.LEA, Dst: 15, Base: 14, SignedDisp: 8}, form),
		stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 14, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.Store, Src: 0, Base: 14, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.Store, Src: 14, Base: 14, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.Load, Dst: 1, Base: 14, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.MoveRegister, Dst: 2, Src: 1}, form),
		stateOp(to.Intent{Operation: to.Store, Src: 2, Base: 15, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.Load, Dst: 3, Base: 15, SignedDisp: int64(displacement)}, form),
		stateOp(to.Intent{Operation: to.Load, Dst: 5, Base: 3, SignedDisp: int64(displacement)}, form),
	}
	if len(chains) != 0 {
		tail := ops[2:]
		if shape&(1<<14) != 0 {
			// Direct access permits the deepest admitted base expression; the
			// separate round-trip arm also spends depth on pointer-byte transport.
			tail = []stateInstruction{
				stateOp(to.Intent{Operation: to.Load, Dst: 0, Base: 12, SignedDisp: int64(displacement)}, form),
				stateOp(to.Intent{Operation: to.Store, Src: 0, Base: 12, SignedDisp: int64(displacement)}, form),
			}
		}
		ops = append(slices.Clone(chains[0]), tail...)
	}
	// Rotate the independent logical roles through every physical GPR,
	// including RSP as a nonzero base. Save the entry origin first; this is
	// an actual copy, not an altered initial-register premise.
	reg := func(r uint8) uint8 { return (r + registerRotation) % 16 }
	located := []stateInstruction{stateOp(to.Intent{Operation: to.MoveRegister, Dst: reg(4), Src: 4}, form)}
	for _, op := range ops {
		i := &op.intent
		switch i.Operation {
		case to.MoveRegister:
			i.Dst, i.Src = reg(i.Dst), reg(i.Src)
		case to.LEA, to.Load:
			i.Dst, i.Base = reg(i.Dst), reg(i.Base)
		case to.Store:
			i.Base, i.Src = reg(i.Base), reg(i.Src)
		case to.Subtract, to.And:
			i.Dst = reg(i.Dst)
		}
		located = append(located, op)
	}
	// Check an independently selected arithmetic boundary and every suffix
	// boundary before/after memory transport. Dense arbitrary partitions have
	// their own input-bitset property; long chains need not always cut per step.
	check := func(f TransitionInterface, initial stateReference) {
		if len(chains) == 0 {
			stateCheckProgram(t, located, f, initial, layout, shape, true)
			return
		}
		start := 2 * (len(chains[0]) + 1)
		cuts := []int{1, 1 + int(layout%uint64(start))}
		for j := start; j < 2*len(located); j++ {
			cuts = append(cuts, j)
		}
		stateCheckProgram(t, located, f, initial, layout, shape, false, cuts)
	}
	initial := stateRawInitial(face, valuation)
	check(face, initial)
	// Explicit frame extension: recheck the same image and common input values
	// without the two untouched regions/word groups. Both independent roots are
	// checked against their full reference states; no alpha-map crosses differing
	// interfaces. Added byte inputs must neither disappear nor affect common
	// transfers. Together with the separately tested initialization/count rules,
	// this isolates the eight-byte transfer/ordered-lane rule from surrounding
	// memory inventory; it does not claim a stateful 1 MiB enumeration here.
	extra := func(off int64) bool {
		return off >= left && off < left+nLeft || off >= right && off < right+nRight
	}
	bare := face
	bare.Regions, bare.Words = nil, nil
	for _, region := range face.Regions {
		if !extra(region.Bytes.Start) {
			bare.Regions = append(bare.Regions, region)
		}
	}
	for _, word := range face.Words {
		if !extra(word) {
			bare.Words = append(bare.Words, word)
		}
	}
	small := initial.clone()
	for off := range small.memory {
		if !off.image && extra(off.off) {
			delete(small.memory, off)
		}
	}
	small.words = map[int64]uint64{}
	for _, word := range bare.Words {
		small.words[word] = initial.words[word]
	}
	check(bare, small)
}

func TestTransitionStateMemoryTranslationProperty(t *testing.T) {
	if err := quick.Check(func(baseDelta, subtract, displacement, remote int32, shape uint64, values [33]uint64, layout uint64, registerRotation uint8) bool {
		var raw []byte
		for _, value := range values {
			raw = binary.LittleEndian.AppendUint64(raw, value)
		}
		// 264 independent bytes suffice for the 137-byte header and every byte
		// of this family's maximum 126-byte union; this is not one PRNG seed.
		stateTranslatedMemory(t, baseDelta, subtract, displacement, remote, shape, raw, layout, registerRotation)
		return true
	}, &quick.Config{MaxCount: 32, Rand: quickrand.New(quickrand.NewSource(0x4d454d4f5259))}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionStateJointValuationProperty(t *testing.T) {
	if err := quick.Check(func(commands [8][4]uint64, values [28]uint64, layout, partition uint64, residue uint32) bool {
		var data, raw []byte
		for _, command := range commands {
			for _, field := range command {
				data = binary.LittleEndian.AppendUint64(data, field)
			}
		}
		for _, value := range values {
			raw = binary.LittleEndian.AppendUint64(raw, value)
		}
		face := stateFace(1<<31, uint64(residue)%(1<<31))
		ops := stateGenerated(data)
		var cuts []int
		for j := 1; j < 2*len(ops); j++ {
			if partition&(uint64(1)<<(j-1)) != 0 {
				cuts = append(cuts, j)
			}
		}
		stateCheckProgram(t, ops, face, stateRawInitial(face, raw), layout, 0, false, cuts)
		return true
	}, &quick.Config{MaxCount: 32, Rand: quickrand.New(quickrand.NewSource(0x4a4f494e5456414c))}); err != nil {
		t.Fatal(err)
	}
}

// This extends actual dereferences beyond one/two arithmetic payloads: full
// signed-32 LEA/SUB steps and congruence-justified ANDs participate in the address
// without narrowing its accumulated offset. Direct and spilled-pointer arms
// cover the deepest permitted bases and continuation transport. Instruction and
// expression-depth frontiers, not input-array length, bound instantiation.
func FuzzTransitionStateMemoryChains(f *testing.F) {
	for _, n := range []int{0, 1, 65, 255, 510, 511, 512, 2048} {
		chain := make([]byte, 5*n)
		for j := 0; j < n; j++ {
			binary.LittleEndian.PutUint32(chain[j*5+1:], 0x80000000)
			if n == 65 || n == 255 {
				chain[j*5] = byte(j % 3)
				if j%3 == 2 {
					binary.LittleEndian.PutUint32(chain[j*5+1:], 31)
				}
			}
		}
		values := make([]byte, 264)
		for j := range values {
			values[j] = byte(j*37 + n)
		}
		for _, direct := range []bool{false, true} {
			f.Add(chain, int32(-2147483648), int32(7919), uint64(n)*0x123456789abcdef, values, uint64(n), direct, uint8(n))
		}
	}
	// The opposite deep edge: 510 SUBs add 2^31 each, then LEA adds 2^31-1
	// without deepening ZF. The final displacement addresses offset 2^40-2.
	positive := make([]byte, 5*511)
	for j := 0; j < 511; j++ {
		positive[5*j] = 1
		binary.LittleEndian.PutUint32(positive[5*j+1:], 0x80000000)
	}
	positive[5*510] = 0
	binary.LittleEndian.PutUint32(positive[5*510+1:], 0x7fffffff)
	f.Add(positive, int32(2147483647), int32(-7919), uint64(731), make([]byte, 264), uint64(917), true, uint8(4))
	f.Fuzz(func(t *testing.T, chain []byte, displacement, remote int32, shape uint64, valuation []byte, layout uint64, direct bool, registerRotation uint8) {
		prefix := []stateInstruction{stateOp(to.Intent{Operation: to.MoveRegister, Dst: 12, Src: 4}, 0)}
		for len(chain) != 0 {
			var record [5]byte
			n := copy(record[:], chain)
			chain = chain[n:]
			payload := int64(int32(binary.LittleEndian.Uint32(record[1:])))
			i := to.Intent{Operation: to.LEA, Dst: 12, Base: 12, SignedDisp: payload}
			switch record[0] & 3 {
			case 1:
				i = to.Intent{Operation: to.Subtract, Dst: 12, Immediate: uint64(payload)}
			case 2:
				i = to.Intent{Operation: to.And, Dst: 12, Immediate: -uint64(1 << (uint32(payload) & 31))}
			}
			prefix = append(prefix, stateOp(i, record[0]>>2))
			if 2*(len(prefix)+1)+1 > statePopulationInstructions {
				break // includes the actual origin-saving instruction in the count
			}
		}
		shape &^= 1 << 14
		if direct {
			shape |= 1 << 14
		}
		stateTranslatedMemory(t, 0, 0, displacement, remote, shape, valuation, layout, registerRotation, prefix)
	})
}
