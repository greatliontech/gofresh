package nativeproof

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func scalarTailChecker(t testing.TB) *transitionChecker {
	m := sseTestChecker(t)
	m.state.path = m.truth
	for i := range m.state.regs {
		m.state.regs[i] = m.con(br.Bits(64), 0xfedcba9876543210+uint64(i))
		m.bound.Preserved[i] = ^uint64(0)
	}
	f := TransitionFlag{Preserved: true, Defined: true, Value: m.truth}
	m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
	m.setPredicates(TransitionPredicates{m.truth, m.truth, m.falsity})
	return m
}

// Unbounded subtraction and signed range checks independently determine borrow
// and overflow, including the max-word and max-low-nibble carry-in boundaries.
func scalarBorrowReference(a, b, carry uint64, width int) (uint64, [6]bool) {
	a, b = a&mask(width), b&mask(width)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(width))
	diff := new(big.Int).Sub(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	diff.Sub(diff, new(big.Int).SetUint64(carry))
	borrow := diff.Sign() < 0
	result := new(big.Int).Mod(diff, modulus).Uint64()
	signed := func(v uint64) *big.Int {
		n := new(big.Int).SetUint64(v)
		if v>>(width-1) != 0 {
			n.Sub(n, modulus)
		}
		return n
	}
	s := new(big.Int).Sub(signed(a), signed(b))
	s.Sub(s, new(big.Int).SetUint64(carry))
	limit := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	overflow := s.Cmp(limit) >= 0 || s.Cmp(new(big.Int).Neg(limit)) < 0
	return result, [6]bool{borrow, result == 0, overflow, result>>(width-1) != 0, int(a&15)-int(b&15)-int(carry) < 0, bits.OnesCount8(byte(result))%2 == 0}
}

func TestTransferKernelSubtractBorrowProperties(t *testing.T) {
	for _, width := range []int{8, 32, 64} {
		m := scalarTailChecker(t)
		a, b, c := m.scratch(br.Bits(width)), m.scratch(br.Bits(width)), m.scratch(br.Bool())
		k, _ := NewTransferKernel(t.Context(), RelationLimits{})
		r, err := k.SubtractBorrow(a, b, c)
		if err != nil {
			t.Fatal(err)
		}
		check := func(x, y uint64, borrow bool) bool {
			carry := uint64(0)
			if borrow {
				carry = 1
			}
			values := map[br.Term]uint64{a: x & mask(width), b: y & mask(width), c: carry}
			want, flags := scalarBorrowReference(x, y, carry, width)
			if stateEval(t, r.Value, values) != want {
				t.Fatal("SBB value", width, x, y, carry)
			}
			for j, f := range []TransitionFlag{r.Flags.CF, r.Flags.ZF, r.Flags.OF, r.Flags.SF, r.Flags.AF, r.Flags.PF} {
				if !f.Defined || f.Preserved || (stateEval(t, f.Value, values) != 0) != flags[j] {
					t.Fatal("SBB flags", width, x, y, carry, j)
				}
			}
			for j, p := range []br.Term{r.Predicates.CF, r.Predicates.ZF, r.Predicates.SFXorOF} {
				if (stateEval(t, p, values) != 0) != [3]bool{flags[0], flags[1], flags[3] != flags[2]}[j] {
					t.Fatal("SBB predicate", j)
				}
			}
			return true
		}
		edges := []uint64{0, 1, 15, 16, 127, 128, mask(width) >> 1, 1 << uint(width-1), mask(width)}
		for _, x := range edges {
			for _, y := range edges {
				check(x, y, false)
				check(x, y, true)
			}
		}
		if err := quick.Check(check, &quick.Config{MaxCount: 256}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransferKernelShiftLeft32Properties(t *testing.T) {
	m := scalarTailChecker(t)
	x, count := m.scratch(br.Bits(32)), m.scratch(br.Bits(8))
	k, _ := NewTransferKernel(t.Context(), RelationLimits{})
	r, err := k.ShiftLeft32(x, count)
	if err != nil {
		t.Fatal(err)
	}
	check := func(v uint32, n uint8) bool {
		values := map[br.Term]uint64{x: uint64(v), count: uint64(n)}
		s := n & 31
		want := v << s
		if stateEval(t, r.Value, values) != uint64(want) {
			t.Fatal("SHL value", v, n)
		}
		checks := []struct {
			term br.Term
			want bool
		}{{r.ZeroCount, s == 0}, {r.OneCount, s == 1}, {r.Sign, want>>31 != 0}, {r.Zero, want == 0}, {r.Parity, bits.OnesCount8(byte(want))%2 == 0}}
		if s != 0 {
			checks = append(checks, struct {
				term br.Term
				want bool
			}{r.Carry, v>>(32-s)&1 != 0})
		}
		if s == 1 {
			checks = append(checks, struct {
				term br.Term
				want bool
			}{r.Overflow, (v^want)>>31 != 0})
		}
		for _, c := range checks {
			if (stateEval(t, c.term, values) != 0) != c.want {
				t.Fatal("SHL flags", v, n)
			}
		}
		return true
	}
	for n := 0; n < 256; n++ {
		for _, v := range []uint32{0, 1, 0x80000000, 0x7fffffff, 0xffffffff, 0xa55af00f} {
			check(v, uint8(n))
		}
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionScalarTailForms(t *testing.T) {
	for _, form := range []string{"48ffc0", "49ffc7", "d3e0", "41d3e7", "19d0", "1bc2", "4521d1", "4523ca"} {
		code := hexBytes(t, form)
		im := image(t, append(code, 0xc3))
		i, b, err := transitionEncoding(im, testEntry)
		if err != nil {
			t.Fatal(form, err)
		}
		if err := validateTransitionForm(testEntry, i, b); err != nil {
			t.Fatal(form, err)
		}
		if !TransitionExpansionRequired(i) {
			t.Fatal("missing expansion choice", form)
		}
		for _, prefix := range []byte{0xf0, 0xf2, 0xf3, 0x66, 0x67, 0x64, 0x65} {
			bad := image(t, append(append([]byte{prefix}, code...), 0xc3))
			if _, err := decodeTransition(bad, testEntry, testEntry+uint64(len(code)+1)); err == nil {
				t.Fatalf("accepted prefix %x/%s", prefix, form)
			}
		}
		changed := i
		changed.Args[0] = x86asm.EBX
		if validateTransitionForm(testEntry, changed, b) == nil {
			t.Fatal("accepted mismatched normalized destination", form)
		}
	}
	for _, form := range []string{"ffc0", "66ffc0", "48ff00", "48ffc8", "d3e8", "48d3e0", "66d3e0", "d320", "c1e001", "4819d0", "1910", "1b02", "18d0", "2110", "23c2ff", "4821d0", "83e0ff"} {
		code := hexBytes(t, form)
		im := image(t, append(code, 0xc3))
		_, err := decodeTransition(im, testEntry, testEntry+uint64(len(code)))
		// The trailing FF case is valid AND followed by another instruction;
		// test the exact byte/normalized extent rather than rejecting that prefix.
		if form == "23c2ff" {
			i, _, e := transitionEncoding(im, testEntry)
			if e != nil || validateScalarTailForm(testEntry, i, code) == nil {
				t.Fatal("unbound trailing byte", e)
			}
		} else if err == nil {
			t.Fatal("accepted unsupported form", form)
		}
	}
	// Existing alignment AND remains automatic, as does the byte locked family.
	for _, form := range []string{"4883e4f0", "f02011"} {
		im := image(t, append(hexBytes(t, form), 0xc3))
		i, b, err := transitionEncoding(im, testEntry)
		if err != nil || validateTransitionForm(testEntry, i, b) != nil {
			t.Fatal(form, err)
		}
		if form == "4883e4f0" && TransitionExpansionRequired(i) {
			t.Fatal("alignment became optional")
		}
		if form == "f02011" && !TransitionExpansionRequired(i) {
			t.Fatal("locked byte AND lost its expansion choice")
		}
	}
}

func TestTransitionScalarTailRegistersAndCarry(t *testing.T) {
	for dst := 0; dst < 16; dst++ {
		for _, count := range []uint64{0, 1, 2, 31, 32, 33, 64, 255} {
			m := scalarTailChecker(t)
			m.state.regs[RCX] = m.con(br.Bits(64), 0xfeedface00000000|count)
			old := stateEval(t, m.state.regs[dst], nil)
			beforeFlags, beforePred := m.bound.Flags, m.state.flags
			if err := m.scalarTail(operation{Op: x86asm.SHL, Args: [2]x86asm.Arg{x86asm.EAX + x86asm.Reg(dst), x86asm.CL}}); err != nil {
				t.Fatal(dst, count, err)
			}
			want := uint64(uint32(old) << uint(count&31))
			if stateEval(t, m.state.regs[dst], nil) != want || m.bound.Preserved[dst] != 0 || m.pointers[dst] != nil {
				t.Fatal("SHL register", dst, count)
			}
			if count&31 == 0 && (m.bound.Flags != beforeFlags || m.state.flags != beforePred) {
				t.Fatal("zero count changed flags", dst, count)
			}
			if count&31 > 1 && (m.bound.Flags.OF.Defined || m.state.flags[flagLess].Valid()) {
				t.Fatal("undefined OF consumed")
			}
		}
		for _, cf := range []TransitionFlag{{}, {Defined: true}, {Preserved: true, Defined: true}} {
			for _, value := range []uint64{0, 1} {
				m := scalarTailChecker(t)
				cf.Value = m.con(br.Bool(), value)
				m.bound.Flags.CF = cf
				m.state.flags[flagCarry] = cf.Value
				m.state.regs[dst] = m.con(br.Bits(64), ^uint64(0))
				if err := m.scalarTail(operation{Op: x86asm.INC, Args: [2]x86asm.Arg{x86asm.RAX + x86asm.Reg(dst)}}); err != nil {
					t.Fatal(err)
				}
				if m.bound.Flags.CF != cf || m.state.flags[flagCarry] != cf.Value || stateEval(t, m.state.regs[dst], nil) != 0 || stateEval(t, m.bound.Flags.ZF.Value, nil) != 1 {
					t.Fatal("INC carry/result", dst)
				}
			}
		}
		for _, op := range []x86asm.Op{x86asm.AND, x86asm.SBB} {
			m := scalarTailChecker(t)
			m.bound.Flags.CF.Value = br.Term{} // defined private carry remains usable
			m.state.regs[dst] = m.con(br.Bits(64), 0xdeadbeef80000000)
			if err := m.scalarTail(operation{Op: op, Args: [2]x86asm.Arg{x86asm.EAX + x86asm.Reg(dst), x86asm.EAX + x86asm.Reg(dst)}}); err != nil {
				t.Fatal(err)
			}
			want := uint64(0x80000000)
			if op == x86asm.SBB {
				want = 0xffffffff
			}
			if stateEval(t, m.state.regs[dst], nil) != want {
				t.Fatal("aliased scalar operands", dst, op)
			}
		}
	}
	for _, mode := range []string{"undefined", "missing", "wrong-sort", "overwritten"} {
		m := scalarTailChecker(t)
		m.bound.InitialPredicates.CF = m.truth
		switch mode {
		case "undefined":
			m.bound.Flags.CF.Defined = false
		case "missing":
			m.state.flags[flagCarry] = br.Term{}
		case "wrong-sort":
			m.state.flags[flagCarry] = m.con(br.Bits(8), 1)
		case "overwritten":
			m.state.flags[flagCarry] = m.falsity
		}
		m.state.regs[RAX] = m.con(br.Bits(64), 7)
		err := m.scalarTail(operation{Op: x86asm.SBB, Args: [2]x86asm.Arg{x86asm.EAX, x86asm.EAX}})
		if mode == "overwritten" {
			if err != nil || stateEval(t, m.state.regs[RAX], nil) != 0 {
				t.Fatal("used initial carry", err)
			}
		} else if err == nil {
			t.Fatal("accepted unavailable carry", mode)
		}
	}
}

func TestTransitionScalarShiftGuardedFlags(t *testing.T) {
	for _, domain := range []string{"all", "nonzero", "zero-one", "zero-two", "zero"} {
		for _, metadata := range []string{"projected", "unprojected", "undefined", "missing-predicate"} {
			t.Run(domain+"/"+metadata, func(t *testing.T) {
				m := scalarTailChecker(t)
				n := m.scratch(br.Bits(8))
				r := m.shiftLeft32(m.con(br.Bits(32), 0x80000001), n)
				switch domain {
				case "nonzero":
					m.state.path = m.not(r.ZeroCount)
				case "zero-one":
					m.state.path = m.or(r.ZeroCount, r.OneCount)
				case "zero-two":
					m.state.path = m.or(r.ZeroCount, m.compare(br.Equal, m.extract(n, 0, 5), m.con(br.Bits(5), 2)))
				case "zero":
					m.state.path = r.ZeroCount
				}
				if metadata == "unprojected" {
					f := TransitionFlag{Defined: true}
					m.bound.Flags = TransitionFlags{f, f, f, f, f, f}
				}
				if metadata == "undefined" {
					m.bound.Flags = TransitionFlags{}
					m.state.flags = [flagCount]br.Term{}
				}
				if metadata == "missing-predicate" {
					m.state.flags = [flagCount]br.Term{}
				}
				old, pred := m.bound.Flags, m.state.flags
				f, p, err := m.shiftFlags(r)
				if err != nil {
					t.Fatal(err)
				}
				if domain == "zero" {
					if f != old || p != (TransitionPredicates{pred[0], pred[1], pred[2]}) {
						t.Fatal("zero scope changed flags")
					}
					return
				}
				defined := metadata != "undefined" || domain == "nonzero"
				if f.CF.Defined != defined || f.SF.Defined != defined || f.ZF.Defined != defined || f.PF.Defined != defined || f.AF.Defined || f.OF.Defined != (domain == "zero-one" && metadata != "undefined") {
					t.Fatal("incorrect guarantees", f)
				}
				wantProjection := defined && (metadata != "unprojected" || domain == "nonzero")
				if f.CF.Value.Valid() != wantProjection {
					t.Fatal("invented/lost projection")
				}
				wantPredicate := defined && (metadata != "missing-predicate" || domain == "nonzero")
				if p.CF.Valid() != wantPredicate || p.ZF.Valid() != wantPredicate || p.SFXorOF.Valid() != (domain == "zero-one" && metadata != "undefined" && metadata != "missing-predicate") {
					t.Fatal("predicate availability", p)
				}
				for _, count := range []uint64{0, 1, 2, 31, 32, 33, 64, 255} {
					values := map[br.Term]uint64{n: count}
					if stateEval(t, m.state.path, values) == 0 {
						continue
					}
					if p.CF.Valid() {
						want := uint64(0)
						if count&31 == 0 || count&31 == 1 {
							want = 1
						}
						if stateEval(t, p.CF, values) != want {
							t.Fatal("mixed carry", count)
						}
					}
					if p.SFXorOF.Valid() {
						want := uint64(0)
						if count&31 == 1 {
							want = 1
						}
						if stateEval(t, p.SFXorOF, values) != want {
							t.Fatal("mixed signed predicate", count)
						}
					}
				}
				if len(m.justifications) == 0 && domain != "all" && domain != "zero-two" {
					t.Fatal("missing retained side proof")
				}
			})
		}
	}
}

func TestTransitionScalarIncrementProvenance(t *testing.T) {
	for _, valid := range []bool{false, true} {
		m := scalarTailChecker(t)
		m.bound.Origin = m.scratch(br.Bits(64))
		m.lo, m.hi = 0x800000, 0x900000
		m.face.Envelope = RelativeSpan{0, 8}
		fixtureGeometry(t, m)
		offset := int64(8)
		if valid {
			offset = 7
		}
		m.pointers[RAX] = m.bound.Geometry.stackPointer(offset)
		m.state.regs[RAX] = m.binary(br.Add, m.bound.Origin, m.con(br.Bits(64), uint64(offset)))
		if err := m.scalarTail(operation{Op: x86asm.INC, Args: [2]x86asm.Arg{x86asm.RAX}}); err != nil {
			t.Fatal("scalar INC cannot fault", err)
		}
		if valid {
			if m.pointers[RAX] != m.bound.Geometry.stackPointer(8) {
				t.Fatal("lost affine pointer")
			}
		} else if m.pointers[RAX] != nil {
			t.Fatal("invented pointer")
		}
	}
}

func TestTransitionScalarTailContinuationAndLimits(t *testing.T) {
	for _, carry := range []uint64{0, 1} {
		t.Run(fmt.Sprint(carry), func(t *testing.T) { scalarTailCarryContinuation(t, carry) })
	}
}

func scalarTailCarryContinuation(t *testing.T, carry uint64) {
	// CMP supplies the opposite of INC's addition carry in both cases. SBB's
	// mask remains directly observable across the split, without a masking AND.
	initial := "ffffffffffffffff"
	if carry != 0 {
		initial = "0000000000000000"
	}
	code := hexBytes(t, "48b8"+initial+"b9010000004839c848ffc019d2d3e00f92c3")
	im := image(t, append(code, 0xc3))
	var expansions []TransitionExpansion
	for pc := testEntry; pc < testEntry+uint64(len(code)); {
		i, _, err := transitionEncoding(im, pc)
		if err != nil {
			t.Fatal(err)
		}
		if TransitionExpansionRequired(i) {
			expansions = append(expansions, TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
	}
	cut := testEntry + uint64(len(code))
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.BoundFor(im)
	values := make(map[br.Term]uint64)
	for _, input := range b.InitialRegisters {
		values[input] = 0
	}
	wantMask := uint64(0)
	if carry != 0 {
		wantMask = 0xffffffff
	}
	if stateEval(t, b.Registers[RAX].Value, values) != 2*carry || stateEval(t, b.Registers[RDX].Value, values) != wantMask {
		t.Fatal("tail result")
	}
	// Split immediately before SBB; continuation must keep INC's carry identity.
	split := testEntry + 21
	pre, err := ProposeTransition(t.Context(), im, split, TransitionLimits{}, TransitionOptions{Expansions: expansions[:1]})
	if err != nil {
		t.Fatal(err)
	}
	first, err := CheckTransition(t.Context(), im, stateFace(16, 0), pre, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := first.BoundFor(im)
	if stateEval(t, before.Flags.CF.Value, nil) != carry {
		t.Fatal("INC changed the incoming comparison carry")
	}
	nextProposal := continuationProposal(t, first, cut, TransitionOptions{Expansions: expansions[1:]})
	continued, err := CheckTransitionContinuation(t.Context(), first, nextProposal)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := first.BoundFor(im)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("continuation mutated predecessor")
	}
	cb, _ := continued.BoundFor(im)
	continuedValues := make(map[br.Term]uint64)
	for _, input := range cb.InitialRegisters {
		continuedValues[input] = 0
	}
	if stateEval(t, cb.Registers[RAX].Value, continuedValues) != stateEval(t, b.Registers[RAX].Value, values) {
		t.Fatal("continuation differs")
	}
	for _, seed := range []uint64{0, ^uint64(0), 0xabcdef0123456789} {
		for _, input := range cb.InitialRegisters {
			continuedValues[input] = seed
		}
		for _, input := range b.InitialRegisters {
			values[input] = seed
		}
		if stateEval(t, cb.Registers[RDX].Value, continuedValues) != wantMask || stateEval(t, b.Registers[RDX].Value, values) != wantMask {
			t.Fatal("whole/continued SBB mask differs or depends on an arbitrary input")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	refused, err := CheckTransition(ctx, im, stateFace(16, 0), p, TransitionLimits{})
	if !errors.Is(err, context.Canceled) || refused.checked != nil {
		t.Fatal("cancelled certificate", err)
	}
	refused, err = CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{RelationLimits: RelationLimits{Work: 3}})
	if err == nil || refused.checked != nil {
		t.Fatal("budget certificate")
	}
}

func scalarJoinProposal(t testing.TB, im *Image, cut uint64) TransitionProposal {
	t.Helper()
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, scalarJoinOptions(t, im, testEntry, cut))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func scalarJoinOptions(t testing.TB, im *Image, start, cut uint64) TransitionOptions {
	t.Helper()
	var expansions []TransitionExpansion
	for pc := start; pc < cut; {
		i, _, err := transitionEncoding(im, pc)
		if err != nil {
			t.Fatal(err)
		}
		if TransitionExpansionRequired(i) {
			expansions = append(expansions, TransitionExpansion{PC: pc})
		}
		pc += uint64(i.Len)
	}
	return TransitionOptions{Expansions: expansions}
}

func TestTransitionScalarUnavailablePredicateJoin(t *testing.T) {
	for _, shiftedTaken := range []bool{false, true} {
		for _, consumer := range []string{"overwrite", "carry", "signed-before-overwrite"} {
			t.Run(fmt.Sprintf("shifted-taken=%v/%s", shiftedTaken, consumer), func(t *testing.T) {
				// Both entry-ZF paths are feasible. One retains its signed predicate;
				// the other executes SHL with count two and loses that predicate.
				prefix := "b9020000007402d3e0"
				if shiftedTaken {
					prefix = "b9020000007402eb02d3e0"
				}
				suffix := map[string]string{"overwrite": "31d20f9cc3", "carry": "19d2", "signed-before-overwrite": "0f9cc331d2"}[consumer]
				code := hexBytes(t, prefix+suffix)
				im := image(t, append(code, 0xc3))
				join, cut := testEntry+uint64(len(prefix)/2), testEntry+uint64(len(code))
				p := scalarJoinProposal(t, im, cut)
				whole, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
				if consumer != "signed-before-overwrite" && err != nil {
					t.Fatalf("join rejected before its permitted consumer: %v", err)
				}
				pre := scalarJoinProposal(t, im, join)
				first, preErr := CheckTransition(t.Context(), im, stateFace(16, 0), pre, TransitionLimits{})
				if preErr != nil {
					t.Fatalf("unavailable predicate rejected at an unexecuted cut: %v", preErr)
				}
				if first.checked.flags[flagLess].Valid() || !first.checked.flags[flagCarry].Valid() || !first.checked.bound.Flags.CF.Defined || first.checked.bound.Flags.OF.Defined {
					t.Fatal("join lost carry or invented a signed predicate")
				}
				before, _ := first.BoundFor(im)
				nextProposal := continuationProposal(t, first, cut, scalarJoinOptions(t, im, join, cut))
				continued, nextErr := CheckTransitionContinuation(t.Context(), first, nextProposal)
				after, _ := first.BoundFor(im)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("join continuation mutated its predecessor")
				}
				if consumer == "signed-before-overwrite" {
					for _, failure := range []error{err, nextErr} {
						var r *Refusal
						if !errors.As(failure, &r) || r.PC != join || r.Premise != "relation-expression" {
							t.Fatalf("signed consumer did not refuse at the unavailable-predicate use: %v", failure)
						}
					}
					if whole.checked != nil || continued.checked != nil {
						t.Fatal("failed signed consumer published a certificate")
					}
					return
				}
				if nextErr != nil {
					t.Fatal(nextErr)
				}
				for _, result := range []TransitionCertificate{whole, continued} {
					b, _ := result.BoundFor(im)
					for zero := uint64(0); zero < 2; zero++ {
						for carry := uint64(0); carry < 2; carry++ {
							values := make(map[br.Term]uint64)
							for reg, input := range b.InitialRegisters {
								values[input] = 0xfedcba9800000000 + uint64(reg)
							}
							values[b.InitialRegisters[RAX]] = 0xabcdef0040000000
							values[b.InitialPredicates.ZF], values[b.InitialPredicates.CF], values[b.InitialPredicates.SFXorOF] = zero, carry, 1
							shifted := (zero != 0) == shiftedTaken
							want := uint64(0)
							if consumer == "carry" && (shifted || carry != 0) {
								want = 0xffffffff
							}
							if stateEval(t, b.Registers[RDX].Value, values) != want {
								t.Fatal("join consumer result", shiftedTaken, zero, carry)
							}
							if consumer == "overwrite" && stateEval(t, b.Registers[RBX].Value, values)&255 != 0 {
								t.Fatal("signed predicate not restored by overwrite")
							}
						}
					}
				}
			})
		}
	}
}

func TestTransitionScalarPredicateMergeAvailability(t *testing.T) {
	for _, missingSource := range []bool{false, true} {
		for _, guard := range []string{"symbolic", "false", "true"} {
			t.Run(fmt.Sprintf("missing-source=%v/%s", missingSource, guard), func(t *testing.T) {
				m := scalarTailChecker(t)
				src := m.state
				src.present = true
				src.path = m.scratch(br.Bool())
				if guard == "false" {
					src.path = m.falsity
				}
				if guard == "true" {
					src.path = m.truth
				}
				dst := src
				dst.path = m.not(src.path)
				valid := m.scratch(br.Bool())
				dst.flags[flagLess], src.flags[flagLess] = valid, valid
				if missingSource {
					src.flags[flagLess] = br.Term{}
				} else {
					dst.flags[flagLess] = br.Term{}
				}
				work := m.work
				m.merge(&dst, src)
				if m.err != nil {
					t.Fatal("merge prematurely refused", m.err)
				}
				wantValid := guard == "false" && missingSource || guard == "true" && !missingSource
				if dst.flags[flagLess].Valid() != wantValid || wantValid && dst.flags[flagLess] != valid {
					t.Fatal("predicate availability or literal selection")
				}
				if !dst.flags[flagCarry].Valid() || !dst.flags[flagZero].Valid() || m.work < work+16+flagCount {
					t.Fatal("unrelated predicates or cumulative work lost")
				}
			})
		}
	}
}

func TestTransferKernelScalarTailBounds(t *testing.T) {
	for _, name := range []string{"SBB", "SHL"} {
		m := scalarTailChecker(t)
		a, b, c := m.scratch(br.Bits(32)), m.scratch(br.Bits(32)), m.scratch(br.Bool())
		count := m.scratch(br.Bits(8))
		invoke := func(k *TransferKernel) error {
			if name == "SBB" {
				r, e := k.SubtractBorrow(a, b, c)
				if e != nil && r != (ArithmeticResult{}) {
					t.Fatal("partial SBB")
				}
				return e
			}
			r, e := k.ShiftLeft32(a, count)
			if e != nil && r != (ShiftLeft32Result{}) {
				t.Fatal("partial SHL")
			}
			return e
		}
		for _, kind := range []string{"cancel", "work", "nodes"} {
			ctx, cancel := context.WithCancel(t.Context())
			l := RelationLimits{}
			if kind == "work" {
				l.Work = 3
			}
			if kind == "nodes" {
				l.Nodes = 3
			}
			k, err := NewTransferKernel(ctx, l)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "cancel" {
				cancel()
			}
			err = invoke(k)
			cancel()
			if err == nil {
				t.Fatal(name, kind)
			}
		}
		k, _ := NewTransferKernel(t.Context(), RelationLimits{})
		if name == "SBB" {
			for _, operands := range [][3]br.Term{{a, b, count}, {a, count, c}, {a, {}, c}} {
				if _, e := k.SubtractBorrow(operands[0], operands[1], operands[2]); e == nil {
					t.Fatal("invalid SBB", fmt.Sprint(operands))
				}
			}
		} else {
			if _, e := k.ShiftLeft32(b, c); e == nil {
				t.Fatal("invalid SHL")
			}
		}
	}
}

func TestTransferKernelShiftCountStructure(t *testing.T) {
	for _, shape := range []string{"mask-one", "mask-two", "mask-any", "join", "offset"} {
		m := scalarTailChecker(t)
		x, input, choose := m.scratch(br.Bits(32)), m.scratch(br.Bits(32)), m.scratch(br.Bool())
		var count br.Term
		switch shape {
		case "mask-one", "mask-two", "mask-any":
			mask := map[string]uint64{"mask-one": 1, "mask-two": 2, "mask-any": 31}[shape]
			word := m.make(br.ZExt, br.Bits(64), 0, m.binary(br.BitAnd, input, m.con(br.Bits(32), mask)))
			count = m.extract(word, 0, 8)
		case "join":
			count = m.extract(m.ite(choose, m.con(br.Bits(32), 32), m.binary(br.BitAnd, input, m.con(br.Bits(32), 1))), 0, 8)
		case "offset":
			count = m.extract(m.make(br.Trunc, br.Bits(16), 0, input), 8, 8)
		}
		k, _ := NewTransferKernel(t.Context(), RelationLimits{})
		r, err := k.ShiftLeft32(x, count)
		if err != nil {
			t.Fatal(err)
		}
		for n := uint64(0); n < 256; n++ {
			for c := uint64(0); c < 2; c++ {
				values := map[br.Term]uint64{x: 0x87654321, input: 0x12340000 | n<<8 | n, choose: c}
				effective := stateEval(t, count, values) & 31
				if stateEval(t, r.Value, values) != uint64(uint32(0x87654321)<<uint(effective)) || (stateEval(t, r.ZeroCount, values) != 0) != (effective == 0) || (stateEval(t, r.OneCount, values) != 0) != (effective == 1) {
					t.Fatal("count normalization", shape, n, c)
				}
			}
		}
		if shape == "mask-one" || shape == "join" {
			f, p, err := m.shiftFlags(m.shiftLeft32(x, count))
			if err != nil || !f.OF.Defined || !p.SFXorOF.Valid() {
				t.Fatal("zero/one guarantee lost", shape, err)
			}
		}
	}
}

func TestTransitionScalarFlagConsumersAndSideProofLimits(t *testing.T) {
	for _, count := range []uint64{0, 1, 2} {
		for _, op := range []x86asm.Op{x86asm.SETB, x86asm.SETE, x86asm.SETL} {
			m := scalarTailChecker(t)
			m.state.regs[RCX] = m.con(br.Bits(64), count)
			if err := m.scalarTail(operation{Op: x86asm.SHL, Args: [2]x86asm.Arg{x86asm.EAX, x86asm.CL}}); err != nil {
				t.Fatal(err)
			}
			err := m.setConditionByte(operation{Op: op, Args: [2]x86asm.Arg{x86asm.DL}}, 3)
			if (err != nil) != (count == 2 && op == x86asm.SETL) {
				t.Fatal("flag consumer", count, op, err)
			}
		}
	}
	for _, kind := range []string{"cancel", "work", "storage"} {
		m := scalarTailChecker(t)
		r := m.shiftLeft32(m.con(br.Bits(32), 7), m.scratch(br.Bits(8)))
		switch kind {
		case "cancel":
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			m.ctx = ctx
		case "work":
			m.valueBuilder.limits.Work = m.work + 1
		case "storage":
			m.limits.LiveStateBytes = 1
		}
		_, _, err := m.shiftFlags(r)
		if err == nil {
			t.Fatal("side proof exhausted into successful abstraction", kind)
		}
		if kind == "cancel" && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	for _, carry := range []TransitionFlag{{}, {Defined: true}, {Defined: true, Preserved: true}} {
		m := scalarTailChecker(t)
		m.bound.Flags.CF = carry
		m.state.flags[flagCarry] = br.Term{}
		if carry.Defined {
			m.state.flags[flagCarry] = m.scratch(br.Bool())
		}
		before := m.state.flags[flagCarry]
		if err := m.scalarTail(operation{Op: x86asm.INC, Args: [2]x86asm.Arg{x86asm.RAX}}); err != nil {
			t.Fatal(err)
		}
		if m.bound.Flags.CF != carry || m.state.flags[flagCarry] != before {
			t.Fatal("INC invented carry projection or identity")
		}
	}
}
