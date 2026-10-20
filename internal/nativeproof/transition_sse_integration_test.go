package nativeproof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

func sseIntegrationFace() TransitionInterface {
	return TransitionInterface{
		Origin:     OriginDomain{Min: 4096, Max: 1<<47 - 4096, Modulus: 16},
		Envelope:   RelativeSpan{-32, 64},
		Regions:    []RelativeRegion{{Bytes: RelativeSpan{-32, 64}, Readable: true, Writable: true}},
		Conditions: interfaceConditions(),
	}
}

func sseIntegrationLoad(width, reg int, offset int8) []byte {
	prefix := byte(0xf3)
	if width == 64 {
		prefix = 0xf2
	}
	b := []byte{prefix}
	if reg >= 8 {
		b = append(b, 0x44)
	}
	return append(b, 0x0f, 0x10, 0x44|byte(reg&7)<<3, 0x24, byte(offset))
}

func sseIntegrationCompare(width, left, right int) []byte {
	var b []byte
	if width == 64 {
		b = append(b, 0x66)
	}
	rex := byte(0x40 | (left>>3)<<2 | right>>3)
	if rex != 0x40 {
		b = append(b, rex)
	}
	return append(b, 0x0f, 0x2e, 0xc0|byte(left&7)<<3|byte(right&7))
}

func sseIntegrationStore(bits uint64, offset int8) []byte {
	b := []byte{0x48, 0xb8}
	b = binary.LittleEndian.AppendUint64(b, bits)
	return append(b, 0x48, 0x89, 0x44, 0x24, byte(offset))
}

func sseIntegrationCheck(t testing.TB, code []byte, face TransitionInterface, expansions ...TransitionExpansion) (TransitionCertificate, error) {
	t.Helper()
	im := image(t, append(append([]byte{}, code...), 0xbb, 0, 0, 0, 0))
	expansions = append(expansions, sseIntegrationExpansions(code, testEntry)...)
	p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)), TransitionLimits{}, TransitionOptions{Expansions: expansions})
	if err != nil {
		return TransitionCertificate{}, err
	}
	return CheckTransition(t.Context(), im, face, p, TransitionLimits{})
}

// Fixtures contain contiguous instruction bytes, with no embedded data. These
// choices request SSE and byte TEST discovery; the checker still validates every form.
func sseIntegrationExpansions(code []byte, pc uint64) []TransitionExpansion {
	var choices []TransitionExpansion
	for len(code) != 0 {
		i, err := x86asm.Decode(code, 64)
		if err != nil {
			break
		}
		switch i.Op {
		case x86asm.MOVSS, x86asm.MOVSD_XMM, x86asm.UCOMISS, x86asm.UCOMISD, x86asm.XORPS, x86asm.TEST:
			choices = append(choices, TransitionExpansion{PC: pc, AllActivations: true})
		}
		pc += uint64(i.Len)
		code = code[i.Len:]
	}
	return choices
}

func sseIntegrationRequire(t testing.TB, code []byte, face TransitionInterface, expansions ...TransitionExpansion) TransitionBound {
	t.Helper()
	c, err := sseIntegrationCheck(t, code, face, expansions...)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.Bound()
	if !ok || b.Interface.Conditions.SSE != SSEModel || !b.SSE.MXCSRPreserved || !b.SSE.UpperVectorsPreserved {
		t.Fatal("missing selected model or preserved MXCSR/upper-vector context")
	}
	return b
}

// Every modeled entry lane receives a different nonzero value. Checking all 32
// lanes detects default-zero, stale-entry and wrong-register projections.
func sseIntegrationValues(t testing.TB, b TransitionBound) map[br.Term]uint64 {
	t.Helper()
	v := map[br.Term]uint64{}
	for reg, xmm := range b.InitialVectors {
		for lane, term := range []br.Term{xmm.Lo, xmm.Hi} {
			if term.Sort() != br.Bits(64) || term.View().Op != br.Variable || !term.View().Scratch {
				t.Fatal("initial vector lane is not an arbitrary BV64 input")
			}
			if _, exists := v[term]; exists {
				t.Fatal("entry vector identities alias")
			}
			v[term] = 0xaabbccdd00000001 + uint64(reg*2+lane)
		}
	}
	return v
}

func sseIntegrationVectors(t testing.TB, b TransitionBound, values map[br.Term]uint64, changed map[int]uint64) {
	t.Helper()
	for reg, xmm := range b.Vectors {
		lo, hi := values[b.InitialVectors[reg].Lo], values[b.InitialVectors[reg].Hi]
		if bits, ok := changed[reg]; ok {
			lo, hi = bits, 0
		}
		if xmm.Lo.Sort() != br.Bits(64) || xmm.Hi.Sort() != br.Bits(64) || evalRelationTerm(t, xmm.Lo, values, 0) != lo || evalRelationTerm(t, xmm.Hi, values, 0) != hi {
			t.Fatalf("XMM%d final lanes differ from actual load/preservation", reg)
		}
	}
}

func sseIntegrationFlags(t testing.TB, flags TransitionFlags, values map[br.Term]uint64, carry, zero, parity bool) {
	t.Helper()
	for _, check := range []struct {
		flag TransitionFlag
		want bool
	}{{flags.CF, carry}, {flags.ZF, zero}, {flags.PF, parity}, {flags.OF, false}, {flags.SF, false}, {flags.AF, false}} {
		if !check.flag.Defined || check.flag.Preserved || check.flag.Value.Sort() != br.Bool() || (evalRelationTerm(t, check.flag.Value, values, 0) == 1) != check.want {
			t.Fatalf("comparison flag differs: %+v, want %v", check.flag, check.want)
		}
	}
}

func TestTransitionSSEIntegrationArbitraryLoadsAndPermissions(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, reg := range []int{0, 7, 8, 15} {
			face := sseIntegrationFace()
			face.Conditions.SSE = SSEModel
			face.Regions = []RelativeRegion{{Bytes: RelativeSpan{1, 1 + int64(width/8)}, Readable: true}}
			code := sseIntegrationLoad(width, reg, 1)
			b := sseIntegrationRequire(t, code, face)
			if len(b.Accesses) != 1 || b.Accesses[0].Kind != FrameRead || b.Accesses[0].Bytes != face.Regions[0].Bytes || b.Accesses[0].Value.Sort() != br.Bits(width) || len(b.Instructions) != 1 {
				t.Fatal("scalar load did not read exactly its admitted bytes")
			}
			for _, flag := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.PF, b.Flags.OF, b.Flags.SF, b.Flags.AF} {
				if !flag.Preserved || !flag.Defined {
					t.Fatal("scalar load changed flag status")
				}
			}
			for j, cell := range b.Memory {
				if cell != b.InitialMemory[j] {
					t.Fatal("scalar load changed ordinary memory")
				}
			}
			for _, bits := range sseEdgeBits(width) {
				values := sseIntegrationValues(t, b)
				for _, cell := range b.InitialMemory {
					values[cell.Value] = bits >> (8 * uint(cell.Offset-1)) & 255
				}
				sseIntegrationVectors(t, b, values, map[int]uint64{reg: bits})
				if evalRelationTerm(t, b.Accesses[0].Value, values, 0) != bits {
					t.Fatal("load access value converted floating bits")
				}
			}
			// The same arbitrary bytes cannot authorize a following self-compare:
			// equality of operands does not remove sNaN/denormal exceptions.
			c, err := sseIntegrationCheck(t, append(code, sseIntegrationCompare(width, reg, reg)...), face)
			transitionRefused(t, c, err)
			for _, region := range []RelativeRegion{
				{Bytes: RelativeSpan{1, int64(width / 8)}, Readable: true},
				{Bytes: RelativeSpan{2, 1 + int64(width/8)}, Readable: true},
				{Bytes: face.Regions[0].Bytes, Writable: true},
			} {
				face.Regions = []RelativeRegion{region}
				c, err := sseIntegrationCheck(t, code, face)
				transitionRefused(t, c, err)
			}
		}
	}
}

func TestTransitionSSEIntegrationConcreteComparisons(t *testing.T) {
	// This is a finite Cartesian edge-class corpus plus deterministic bit-pattern
	// sampling, checked against Go floating comparisons. It does not establish
	// completeness of the verifier over arbitrary symbolic floating operands.
	for _, width := range []int{32, 64} {
		face := sseIntegrationFace()
		face.Conditions.SSE = SSEModel
		edges := sseEdgeBits(width)
		var pairs [][2]uint64
		for _, a := range edges {
			for _, b := range edges {
				pairs = append(pairs, [2]uint64{a, b})
			}
		}
		rng := rand.New(rand.NewSource(int64(width)))
		for range 32 {
			pairs = append(pairs, [2]uint64{rng.Uint64() & mask(width), rng.Uint64() & mask(width)})
		}
		for _, pair := range pairs {
			a, b := pair[0], pair[1]
			code := append(sseIntegrationStore(a, 8), sseIntegrationStore(b, 16)...)
			code = append(code, sseIntegrationLoad(width, 15, 8)...)
			code = append(code, sseIntegrationLoad(width, 9, 16)...)
			code = append(code, sseIntegrationCompare(width, 15, 9)...)
			c, err := sseIntegrationCheck(t, code, face)
			bad, carry, zero, parity := sseReference(width, a, b)
			if bad {
				transitionRefused(t, c, err)
				var r *Refusal
				if !errors.As(err, &r) || r.Premise != "transition-sse-operands" {
					t.Fatalf("binary%d (%x,%x) wrong refusal: %v", width, a, b, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("binary%d (%x,%x): %v", width, a, b, err)
			}
			bound, _ := c.Bound()
			sseIntegrationFlags(t, bound.Flags, nil, carry, zero, parity)
			sseIntegrationVectors(t, bound, sseIntegrationValues(t, bound), map[int]uint64{15: a, 9: b})
			if !bound.SSE.MXCSRPreserved || !bound.SSE.UpperVectorsPreserved || len(bound.Accesses) != 4 || len(bound.Instructions) != 7 {
				t.Fatal("comparison changed context or omitted load/store coverage")
			}
		}
	}
}

// A parity diamond leaves 11 in EBX on fallthrough and 22 on the taken edge.
func sseIntegrationParityDiamond(op byte, near bool) []byte {
	b := []byte{op, 7}
	if near {
		b = []byte{0x0f, op + 0x10, 7, 0, 0, 0}
	}
	return append(b, 0xbb, 11, 0, 0, 0, 0xeb, 5, 0xbb, 22, 0, 0, 0)
}

func TestTransitionSSEIntegrationParityAndOverwrites(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, unordered := range []bool{false, true} {
			bits := uint64(0)
			if unordered {
				bits = 0x7ff800007fc00000
			}
			prefix := sseIntegrationStore(bits, 8)
			prefix = append(prefix, sseIntegrationLoad(width, 0, 8)...)
			prefix = append(prefix, sseIntegrationCompare(width, 0, 0)...)
			for _, overwrite := range []string{"", "b001a801", "b000a801", "39c0"} {
				for _, op := range []byte{0x7a, 0x7b} {
					for _, near := range []bool{false, true} {
						face := sseIntegrationFace()
						face.Conditions.SSE = SSEModel
						code := append(append([]byte{}, prefix...), hexBytes(t, overwrite)...)
						branch := len(code)
						code = append(code, sseIntegrationParityDiamond(op, near)...)
						c, err := sseIntegrationCheck(t, code, face)
						if overwrite == "39c0" {
							transitionRefused(t, c, err)
							var r *Refusal
							if !errors.As(err, &r) || r.Premise != "transition-flag" {
								t.Fatal("coarse CMP invented parity or failed elsewhere", err)
							}
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
						b, _ := c.Bound()
						parity := unordered
						if overwrite != "" {
							parity = overwrite == "b000a801"
						}
						taken := parity == (op == 0x7a)
						want := uint64(11)
						if taken {
							want = 22
						}
						if evalRelationTerm(t, b.Registers[RBX].Value, nil, 0) != want {
							t.Fatalf("width%d JP/JNP %#x near%v overwrite%s used stale/wrong PF", width, op, near, overwrite)
						}
						// The actual taken and fallthrough instructions retain opposite
						// projected guards, not merely a correct final register value.
						branchSize := 2
						if near {
							branchSize = 6
						}
						for _, ins := range b.Instructions {
							if ins.Start == testEntry+uint64(branch+branchSize) || ins.Start == testEntry+uint64(branch+branchSize+7) {
								wantActive := ins.Start == testEntry+uint64(branch+branchSize+7) == taken
								if (evalRelationTerm(t, ins.Guard, nil, 0) == 1) != wantActive {
									t.Fatal("parity successors lost edge guard")
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestTransitionSSEIntegrationBranchContinuation(t *testing.T) {
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	qnan := uint64(0x7ff8000000000017)
	code := append(sseIntegrationStore(qnan, 8), sseIntegrationStore(0, 16)...)
	prefixCut := len(code)
	// JB consumes the arbitrary entry CF. Each arm defines a different vector
	// and PF. XMM8 is written only on fallthrough, exposing snapshot aliasing.
	fall := append(sseIntegrationLoad(64, 15, 8), sseIntegrationLoad(32, 8, 16)...)
	fall = append(fall, sseIntegrationCompare(64, 15, 15)...)
	taken := append(sseIntegrationLoad(64, 15, 16), sseIntegrationCompare(64, 15, 15)...)
	code = append(code, 0x72, byte(len(fall)+2))
	code = append(code, fall...)
	code = append(code, 0xeb, byte(len(taken)))
	code = append(code, taken...)
	joinCut := len(code)
	code = append(code, sseIntegrationParityDiamond(0x7a, false)...)
	finalCut := len(code)
	im := image(t, append(code, 0xbd, 0, 0, 0, 0))
	proposal := func(cut int) TransitionProposal {
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(cut), TransitionLimits{}, TransitionOptions{Expansions: sseIntegrationExpansions(code[:cut], testEntry)})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	direct, err := CheckTransition(t.Context(), im, face, proposal(finalCut), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	segmented, err := CheckTransition(t.Context(), im, face, proposal(prefixCut), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := segmented.Bound()
	predecessor := segmented
	for _, cut := range []int{joinCut, finalCut} {
		start := int(segmented.checked.bound.Boundary.PC - testEntry)
		q := continuationProposal(t, segmented, testEntry+uint64(cut), TransitionOptions{Expansions: sseIntegrationExpansions(code[start:cut], testEntry+uint64(start))})
		segmented, err = CheckTransitionContinuation(t.Context(), segmented, q)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := segmented.Bound()
		if b.InitialVectors != original.InitialVectors || b.InitialPredicates != original.InitialPredicates || b.SSE != original.SSE {
			t.Fatal("continuation restarted original vector/flag/context identities")
		}
	}
	for _, cert := range []TransitionCertificate{direct, segmented} {
		b, _ := cert.Bound()
		for _, carry := range []uint64{0, 1} {
			values := sseIntegrationValues(t, b)
			values[b.InitialPredicates.CF] = carry
			changed := map[int]uint64{15: 0}
			want := uint64(11)
			if carry == 0 {
				changed[15], changed[8], want = qnan, 0, 22
			}
			sseIntegrationVectors(t, b, values, changed)
			sseIntegrationFlags(t, b.Flags, values, carry == 0, true, carry == 0)
			if evalRelationTerm(t, b.Registers[RBX].Value, values, 0) != want {
				t.Fatal("joined PF lost vector/path correlation")
			}
		}
		// Public arrays are copies: edits cannot mutate certificate state.
		b.Vectors[15] = b.InitialVectors[15]
		again, _ := cert.Bound()
		if again.Vectors[15] == again.InitialVectors[15] {
			t.Fatal("public vector projection aliases certificate")
		}
	}
	after, _ := segmented.Bound()
	unchanged, _ := predecessor.Bound()
	if unchanged.Vectors != original.Vectors || original.Vectors != original.InitialVectors || after.Vectors == original.Vectors {
		t.Fatal("suffix changed predecessor or retained stale current vectors")
	}
}

func TestTransitionSSEIntegrationModelsAndUnsupportedForms(t *testing.T) {
	face := sseIntegrationFace()
	for _, model := range []string{"", "future-sse"} {
		face.Conditions.SSE = model
		c, err := sseIntegrationCheck(t, sseIntegrationLoad(64, 0, 8), face)
		transitionRefused(t, c, err)
	}
	face.Conditions.SSE = "future-sse"
	c, err := sseIntegrationCheck(t, []byte{0xb8, 0, 0, 0, 0}, face)
	transitionRefused(t, c, err)
	face.Conditions.SSE = ""
	code := append([]byte{0xb8, 0, 0, 0, 0}, sseIntegrationLoad(64, 0, 8)...)
	im := image(t, append(code, 0xbb, 0, 0, 0, 0))
	p, err := ProposeTransition(t.Context(), im, testEntry+5, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	projection, _ := parent.Bound()
	if projection.InitialVectors != (TransitionVectors{}) || projection.SSE != (TransitionSSEContext{}) {
		t.Fatal("unselected SSE model invented context")
	}
	projection.Interface.Conditions.SSE = SSEModel
	face.Conditions.SSE = SSEModel
	p, err = ProposeTransitionContinuation(t.Context(), parent, testEntry+uint64(len(code)), TransitionOptions{Expansions: sseIntegrationExpansions(code[5:], testEntry+5)})
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(t.Context(), parent, p)
	transitionRefused(t, c, err)
	for _, text := range []string{
		"a5", "f3a5", "f30f10c1", "f20f10c1", "f30f110424", "f20f110424",
		"0f2e0424", "660f2e0424", "0f2fc1", "660f2fc1", "c5fa100424", "c5f82ec1",
		"f3480f100424", "48f30f100424", "f3f30f100424", "66f30f100424",
		"f3640f100424", "f3670f100424", "f30f100444", "f30f10042500000000", "f00f2ec1",
	} {
		t.Run(text, func(t *testing.T) {
			c, err := sseIntegrationCheck(t, hexBytes(t, text), face)
			transitionRefused(t, c, err)
		})
	}
}

func TestTransitionSSEIntegrationGuardedExceptionalOperands(t *testing.T) {
	for _, width := range []int{32, 64} {
		for _, bad := range []uint64{1, 0x7ff000007f800001} {
			face := sseIntegrationFace()
			face.Conditions.SSE = SSEModel
			code := append(sseIntegrationStore(0, 8), sseIntegrationStore(bad, 16)...)
			goodLoad, badLoad := sseIntegrationLoad(width, 15, 8), sseIntegrationLoad(width, 15, 16)
			code = append(code, 0x72, byte(len(goodLoad)+2))
			code = append(code, goodLoad...)
			code = append(code, 0xeb, byte(len(badLoad)))
			code = append(code, badLoad...)
			compare := sseIntegrationCompare(width, 15, 15)
			branch := len(code)
			// Loads preserve entry CF. The second JB bypasses the comparison
			// precisely on the arm that loaded an exceptional operand.
			code = append(code, 0x72, byte(len(compare)))
			code = append(code, compare...)
			b := sseIntegrationRequire(t, code, face)
			for _, carry := range []uint64{0, 1} {
				values := sseIntegrationValues(t, b)
				values[b.InitialPredicates.CF] = carry
				want := uint64(0)
				if carry == 1 {
					want = bad & mask(width)
				}
				sseIntegrationVectors(t, b, values, map[int]uint64{15: want})
				for _, ins := range b.Instructions {
					if ins.Start == testEntry+uint64(branch+2) && evalRelationTerm(t, ins.Guard, values, 0) != 1-carry {
						t.Fatal("exceptional operand reached compare")
					}
				}
			}
			// JAE instead sends the exceptional arm into the very same UCOMI.
			code[branch] = 0x73
			c, err := sseIntegrationCheck(t, code, face)
			transitionRefused(t, c, err)
			var r *Refusal
			if !errors.As(err, &r) || r.Premise != "transition-sse-operands" {
				t.Fatal("feasible exceptional arm failed for unrelated reason", err)
			}
		}
	}
}

func TestTransitionSSEIntegrationCallAndCompletedReturn(t *testing.T) {
	face := sseIntegrationFace()
	face.Conditions.SSE = SSEModel
	// The caller loads XMM8, the callee loads XMM15, then its RET reaches the
	// selected cut. Return must preserve the callee's current vector state rather
	// than rolling back a caller snapshot. Both loads read the same actual bytes.
	bits := uint64(0xfff8000012345678)
	code := sseIntegrationStore(bits, 8)
	code = append(code, sseIntegrationLoad(64, 8, 8)...)
	call := len(code)
	code = append(code, 0xe8, 5, 0, 0, 0)
	cut := len(code)
	code = append(code, 0xbb, 0, 0, 0, 0)
	code = append(code, sseIntegrationLoad(64, 15, 16)...)
	code = append(code, 0xc3)
	im := image(t, code)
	expansions := append(sseIntegrationExpansions(code[:call], testEntry), TransitionExpansion{PC: testEntry + uint64(call)})
	expansions = append(expansions, sseIntegrationExpansions(code[cut+5:], testEntry+uint64(cut+5))...)
	p, err := ProposeTransition(t.Context(), im, testEntry+uint64(cut), TransitionLimits{}, TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	sseIntegrationVectors(t, b, sseIntegrationValues(t, b), map[int]uint64{8: bits, 15: bits})
	if !b.SSE.MXCSRPreserved || !b.SSE.UpperVectorsPreserved || len(b.Frames) != 0 || len(b.Accesses) != 5 || b.Accesses[2].Kind != FrameWrite || b.Accesses[4].Kind != FrameReturnRead {
		t.Fatal("CALL/RET omitted current vectors/context or implicit stack accesses")
	}
	// Complete a conditional incoming callee return after a load from owned
	// scratch memory; the original caller control word remains protected.
	callee := append(sseIntegrationStore(bits, -16), sseIntegrationLoad(64, 15, -16)...)
	retOffset := len(callee)
	callee = append(callee, 0xc3)
	ri, rf := returnFixture(t, fmt.Sprintf("%x", callee))
	rf.Conditions.SSE = SSEModel
	prefix := returnPrefix(t, ri, rf, testEntry+uint64(retOffset), sseIntegrationExpansions(callee[:retOffset], testEntry)...)
	returned := checkedReturn(t, prefix)
	r, ok := returned.Bound()
	if !ok || !r.State.CalleeTerminated || r.State.Vectors != r.Prefix.Vectors || r.State.SSE != r.Prefix.SSE || !r.State.SSE.MXCSRPreserved || !r.State.SSE.UpperVectorsPreserved {
		t.Fatal("completed return omitted vector/MXCSR projection")
	}
	sseIntegrationVectors(t, r.Prefix, sseIntegrationValues(t, r.Prefix), map[int]uint64{15: bits})
	r.State.Vectors[15] = r.Prefix.InitialVectors[15]
	again, _ := returned.Bound()
	if again.State.Vectors[15] == again.Prefix.InitialVectors[15] {
		t.Fatal("returned vector projection shares mutable state")
	}
}
