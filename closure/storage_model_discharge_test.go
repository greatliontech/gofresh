package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/token"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func requireScopedStorageModel(t testing.TB, p *globalFunctionCorrespondence) {
	t.Helper()
	d := p.storageModel
	if !d.boundFor(p, p.source, p.native, p.layout) || len(d.modelOccurrences) == 0 || len(d.dependent) < len(d.modelOccurrences) || d.model != conditionalRegionStorageModel() {
		t.Fatal("missing exact-scope model-dependent consequence discharge")
	}
	if p.open != (computationCorrespondenceObligations{true, true, true, true, true}) || p.source.region.packet.input.storageModel != conditionalRegionStorageModel() {
		t.Fatal("scoped consequences erased source antecedent or surrounding obligations")
	}
}

func storageModelEliminatedFixture(t testing.TB, floating bool) *globalFunctionCorrespondence {
	t.Helper()
	text := `var G uint32;func Check(){G=1};func F(){Check()}`
	if floating {
		text = `var G uint32;func Check(p *float64){if *p==0{G=1}else{G=2}};func F(){var x float64;Check(&x)}`
	}
	return storageModelEffectFixture(t, text)
}

func storageModelEffectFixture(t testing.TB, text string) *globalFunctionCorrespondence {
	t.Helper()
	source, completed := storageFunctionSource(t, text)
	base := nativeproof.ImageAddress(0x700008)
	f, native := storageFunctionNative(t, []storageFunctionOperation{{base, 4, true, 1}}, nativeproof.OriginDomain{})
	rho := storageRepresentation{source: source.prog, image: f.image, bindings: []storageBinding{{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: base}}}
	p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], f.image, f.entry, completed, native, rho, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScopedStorageModelExactScope(t *testing.T) {
	p := storageModelEliminatedFixture(t, true)
	requireScopedStorageModel(t, p)
	d := p.storageModel
	other := storageModelEliminatedFixture(t, true)
	copyAccount, copyDischarge, copySource, copyLayout := *p, *d, *p.source, *p.layout
	for _, tc := range []struct {
		name string
		d    *scopedStorageModelDischarge
		p    *globalFunctionCorrespondence
		s    *sourceReturnCompletion
		n    nativeproof.TransitionReturnCertificate
		l    *storageLayout
	}{
		{"copied-discharge", &copyDischarge, p, p.source, p.native, p.layout},
		{"copied-account", d, &copyAccount, p.source, p.native, p.layout},
		{"copied-source", d, p, &copySource, p.native, p.layout},
		{"foreign-source", d, p, other.source, p.native, p.layout},
		{"equal-byte-native-owner", d, p, p.source, other.native, p.layout},
		{"copied-layout", d, p, p.source, p.native, &copyLayout},
		{"foreign-layout", d, p, p.source, p.native, other.layout},
		{"missing-native", d, p, p.source, nativeproof.TransitionReturnCertificate{}, p.layout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.d.boundFor(tc.p, tc.s, tc.n, tc.l) {
				t.Fatal("discharge escaped its exact checked scope")
			}
		})
	}
	for _, change := range []func(){
		func() { p.source = other.source },
		func() { p.native = other.native },
		func() { p.layout = &copyLayout },
		func() { p.call = &globalCallComposition{} },
		func() { p.paired = other.paired },
		func() { p.rules += ";different" },
	} {
		saved := *p
		change()
		if d.boundFor(p, p.source, p.native, p.layout) {
			t.Fatal("moved scope retained an earlier discharge")
		}
		*p = saved
	}
	requireScopedStorageModel(t, p)
}

func TestScopedStorageModelRequiresCompleteEvidence(t *testing.T) {
	p := storageModelEliminatedFixture(t, true)
	for _, tc := range []struct {
		name string
		edit func(*globalFunctionCorrespondence)
	}{
		{"copied", func(*globalFunctionCorrespondence) {}},
		{"prefix", func(q *globalFunctionCorrespondence) {
			q.completion = nil
			q.native = nativeproof.TransitionReturnCertificate{}
		}},
		{"retry", func(q *globalFunctionCorrespondence) { q.completion = nil; q.source = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := *p
			tc.edit(&q)
			if d, err := checkScopedStorageModel(t.Context(), &q); d != nil || err == nil {
				t.Fatal("partial or copied account received a discharge")
			}
		})
	}
	for _, model := range []regionStorageModel{{}, {interpretation: regionIEEE754LittleEndian + 1}} {
		packet := p.source.region.packet
		saved := packet.input.storageModel
		packet.input.storageModel = model
		d, err := checkScopedStorageModel(t.Context(), p)
		packet.input.storageModel = saved
		if d != nil || err == nil {
			t.Fatal("missing or unsupported source model received a discharge")
		}
	}
	marker := storageModelEliminatedFixture(t, false)
	if marker.storageModel != nil {
		t.Fatal("model marker without an executed model-dependent use became evidence")
	}
	pointerOnly := storageModelEffectFixture(t, `var G uint32;func Check(p *float64){G=1};func F(){Check(nil)}`)
	if pointerOnly.storageModel != nil {
		t.Fatal("an unused float pointer type became a floating storage-model use")
	}
	requireScopedStorageModel(t, p)
}

func TestScopedStorageModelBoundedAndCanceled(t *testing.T) {
	p := storageModelEliminatedFixture(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if d, err := checkScopedStorageModel(ctx, p); d != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled derivation returned %v, %v", d, err)
	}
	for _, remaining := range []int{1, 3, 10} {
		meter := &correspondenceContext{Context: t.Context(), work: p.work, limit: p.work + remaining}
		if d, err := checkScopedStorageModel(meter, p); d != nil || err == nil {
			t.Fatal("exhausted shared account returned a partial discharge")
		}
	}
	if d, err := checkScopedStorageModel(&correspondenceContext{Context: t.Context(), limit: p.limit}, p); d != nil || err == nil {
		t.Fatal("a fresh meter replaced already consumed correspondence work")
	}
	saved := p.work
	p.work = p.limit
	d, err := checkScopedStorageModel(t.Context(), p)
	p.work = saved
	if d != nil || err == nil {
		t.Fatal("direct derivation restarted the complete account budget")
	}
	requireScopedStorageModel(t, p)
}

// Build actual machine instructions. The expected source outcome is never an
// input to the native checker. Both branches are proposed, and the native engine
// derives flags, parity and exclusions from the actual stored/loaded operand bits.
func storageModelSSECode(width int, bits uint64, variant string) ([]byte, uint64) {
	const base = uint64(0x401000)
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x40}
	store := func(offset byte, value uint64) {
		code = append(code, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, value)
		if width == 8 {
			code = append(code, 0x48)
		}
		code = append(code, 0x89, 0x44, 0x24, offset)
	}
	store(48, bits) // represented source object at original RSP-16
	store(56, 0)    // independently checked private zero operand
	load := byte(0xf3)
	if width == 8 {
		load = 0xf2
	}
	code = append(code, load, 0x0f, 0x10, 0x44, 0x24, 48)
	code = append(code, load, 0x0f, 0x10, 0x4c, 0x24, 56)
	if width == 8 {
		code = append(code, 0x66)
	}
	code = append(code, 0x0f, 0x2e, 0xc1) // UCOMIS[S/D] X0,X1
	writeGlobal := func(value uint32) {
		code = append(code, 0xb8)
		code = binary.LittleEndian.AppendUint32(code, value)
		pc := base + uint64(len(code))
		code = append(code, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(0x700008-(pc+6)))
	}
	for i := range 2 {
		if i == 1 && variant == "clobber-flags" {
			code = append(code, 0x31, 0xc0) // XOR EAX,EAX changes current PF
		}
		// Reuse the actual comparison flags across MOVs and JMP, never count
		// one native compare as a requirement for each source comparison.
		code = append(code, 0x7a, 15, 0x75, 13) // JP false; JNE false
		value := uint32(1 + i*2)
		if variant == "wrong-effect" {
			value++
		}
		writeGlobal(value)
		code = append(code, 0xeb, 11)
		writeGlobal(uint32(2 + i*2))
	}
	if variant == "mxcsr" {
		code = append(code, 0x0f, 0xae, 0x54, 0x24, 48) // LDMXCSR [RSP+48]
	}
	if variant == "upper-vectors" {
		code = append(code, 0xc5, 0xf8, 0x77) // VZEROUPPER
	}
	code = append(code, 0x48, 0x83, 0xc4, 0x40)
	cut := base + uint64(len(code))
	return append(code, 0xc3), cut
}

func storageModelCheckSSE(t testing.TB, code []byte, cut uint64, model string) (globalNativeFixture, nativeproof.TransitionReturnCertificate, error) {
	t.Helper()
	f, _ := storageFunctionNative(t, nil, nativeproof.OriginDomain{})
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.cut, f.face.Conditions.SSE = cut, model
	var expansions []nativeproof.TransitionExpansion
	for at := f.entry; at < cut; {
		instruction, decodeErr := x86asm.Decode(code[at-0x401000:], 64)
		if decodeErr != nil {
			// Discovery is not authority. Let the native checker refuse an
			// unsupported encoding rather than failing in fixture construction.
			break
		}
		if nativeproof.TransitionExpansionRequired(instruction) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(instruction.Len)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		return f, nativeproof.TransitionReturnCertificate{}, err
	}
	prefix, err := nativeproof.CheckRegionTransition(t.Context(), f.image, f.entry, f.face, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		return f, nativeproof.TransitionReturnCertificate{}, err
	}
	native, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
	return f, native, err
}

func TestScopedStorageModelActualSSEConsequences(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, tc := range []struct {
			name string
			bits uint64
		}{
			{"zero", 0},
			{"negative-zero", uint64(1) << (width*8 - 1)},
			{"quiet-nan", ^uint64(0) >> (64 - width*8)},
		} {
			t.Run(fmt.Sprintf("%d/%s", width, tc.name), func(t *testing.T) {
				source, completed := storageFunctionSource(t, fmt.Sprintf(`import "unsafe";var G uint32;func Check(p *float%d){if *p==0{G=1}else{G=2};if *p==0{G=3}else{G=4}};func F(){var x float%d;*(*uint%d)(unsafe.Pointer(&x))=%d;Check(&x)}`, width*8, width*8, width*8, tc.bits))
				for _, variant := range []string{"correct", "clobber-flags", "wrong-effect"} {
					code, cut := storageModelSSECode(width, tc.bits, variant)
					f, native, err := storageModelCheckSSE(t, code, cut, nativeproof.SSEModel)
					if err != nil {
						t.Fatal(err)
					}
					rho := storageRepresentation{source: source.prog, image: f.image, bindings: []storageBinding{
						{object: storageFunctionLocal(t, completed), base: nativeproof.StackOffset(-16)},
						{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members["G"].(*ssa.Global)}, base: nativeproof.ImageAddress(0x700008)},
					}}
					p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], f.image, f.entry, completed, native, rho, nil)
					positive := variant == "correct" || tc.name == "quiet-nan"
					if !positive {
						if err == nil || p != nil {
							t.Fatalf("%s acquired wrong floating consequences", variant)
						}
						continue
					}
					if err != nil {
						t.Fatalf("%s: %v", variant, err)
					}
					requireScopedStorageModel(t, p)
					sourceComparisons, nativeComparisons := 0, 0
					for _, occurrence := range p.storageModel.modelOccurrences {
						if op, ok := occurrence.instruction.(*ssa.BinOp); ok && op.Op == token.EQL {
							sourceComparisons++
						}
					}
					bound, _ := native.Bound()
					for _, occurrence := range bound.Instructions {
						instruction, err := native.InstructionAt(t.Context(), occurrence.ID)
						if err != nil {
							t.Fatal(err)
						}
						if instruction.Op == x86asm.UCOMISS || instruction.Op == x86asm.UCOMISD {
							nativeComparisons++
						}
					}
					if sourceComparisons != 2 || nativeComparisons != 1 || !bound.State.SSE.MXCSRPreserved || !bound.State.SSE.UpperVectorsPreserved {
						t.Fatal("lost executed comparison identities, checked reuse or preserved context")
					}
				}
			})
		}
	}
}

func TestScopedStorageModelNativeExceptionalRefusals(t *testing.T) {
	for _, width := range []int{4, 8} {
		quiet := uint64(1) << 22
		if width == 8 {
			quiet = uint64(1) << 51
		}
		for _, tc := range []struct {
			name, variant, model string
			bits                 uint64
		}{
			{"signaling-nan", "correct", nativeproof.SSEModel, (^uint64(0) >> (64 - width*8)) &^ quiet},
			{"subnormal", "correct", nativeproof.SSEModel, 1},
			{"missing-context", "correct", "", 0},
			{"foreign-context", "correct", "assumed-default-mxcsr", 0},
			{"changed-status", "mxcsr", nativeproof.SSEModel, 0},
			{"changed-upper-vectors", "upper-vectors", nativeproof.SSEModel, 0},
		} {
			t.Run(fmt.Sprintf("%d/%s", width, tc.name), func(t *testing.T) {
				code, cut := storageModelSSECode(width, tc.bits, tc.variant)
				_, native, err := storageModelCheckSSE(t, code, cut, tc.model)
				if err == nil || native != (nativeproof.TransitionReturnCertificate{}) {
					t.Fatal("exceptional operand or altered floating context acquired a native theorem")
				}
				if tc.name == "signaling-nan" || tc.name == "subnormal" {
					var refusal *nativeproof.Refusal
					if !errors.As(err, &refusal) || refusal.Premise != "transition-sse-operands" {
						t.Fatalf("wrong exceptional-operand refusal: %v", err)
					}
				}
			})
		}
	}
}
