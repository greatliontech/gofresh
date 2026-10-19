package nativeproof

import (
	"context"
	"errors"
	"math/big"
	"math/bits"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// The oracle uses unbounded unsigned and signed sums. In particular a negative
// delta is its full two's-complement bit pattern, not an unsigned magnitude.
func additionOracle(x, y uint64, width int) (uint64, [6]bool) {
	x, y = x&mask(width), y&mask(width)
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(width))
	sum := new(big.Int).Add(new(big.Int).SetUint64(x), new(big.Int).SetUint64(y))
	carry := sum.Cmp(modulus) >= 0
	z := new(big.Int).Mod(sum, modulus).Uint64()
	signed := func(v uint64) *big.Int {
		n := new(big.Int).SetUint64(v)
		if v>>(width-1) != 0 {
			n.Sub(n, modulus)
		}
		return n
	}
	s := new(big.Int).Add(signed(x), signed(y))
	limit := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	overflow := s.Cmp(limit) >= 0 || s.Cmp(new(big.Int).Neg(limit)) < 0
	return z, [6]bool{carry, z == 0, overflow, z>>(width-1) != 0, (x&15)+(y&15) >= 16, bits.OnesCount8(byte(z))%2 == 0}
}

func TestTransferKernelAdditionAndExchangeProperties(t *testing.T) {
	for _, width := range []int{8, 32, 64} {
		b, scope := br.NewBuilder(8), br.NewScope()
		x, y := inputTerm(t, b, scope, 0, width), inputTerm(t, b, scope, 1, width)
		k, err := NewTransferKernel(t.Context(), RelationLimits{})
		if err != nil {
			t.Fatal(err)
		}
		add, err := k.Add(x, y)
		if err != nil {
			t.Fatal(err)
		}
		var exchange ExchangeResult
		var xadd ExchangeAddResult
		if width == 64 {
			exchange, err = k.Exchange64(x, y)
			if err != nil {
				t.Fatal(err)
			}
			xadd, err = k.ExchangeAdd64(x, y)
			if err != nil {
				t.Fatal(err)
			}
		}
		check := func(left uint64, delta int64) bool {
			xv, yv := left&mask(width), uint64(delta)&mask(width)
			values := map[br.Term]uint64{x: xv, y: yv}
			z, flags := additionOracle(xv, yv, width)
			if stateEval(t, add.Value, values) != z {
				t.Fatal("modular sum differs", width, left, delta)
			}
			results := []ArithmeticResult{add}
			if width == 64 {
				if stateEval(t, exchange.Register, values) != xv || stateEval(t, exchange.Memory, values) != yv || stateEval(t, xadd.Register, values) != xv || stateEval(t, xadd.Memory, values) != z {
					t.Fatal("exchange outputs differ")
				}
				results = append(results, ArithmeticResult{Value: xadd.Memory, Flags: xadd.Flags, Predicates: xadd.Predicates})
			}
			for _, r := range results {
				for j, f := range []TransitionFlag{r.Flags.CF, r.Flags.ZF, r.Flags.OF, r.Flags.SF, r.Flags.AF, r.Flags.PF} {
					if !f.Defined || f.Preserved || (stateEval(t, f.Value, values) != 0) != flags[j] {
						t.Fatal("addition flag differs", width, j, left, delta)
					}
				}
				for j, p := range []br.Term{r.Predicates.CF, r.Predicates.ZF, r.Predicates.SFXorOF} {
					if (stateEval(t, p, values) != 0) != [3]bool{flags[0], flags[1], flags[3] != flags[2]}[j] {
						t.Fatal("condition predicate differs")
					}
				}
			}
			return true
		}
		for _, v := range []uint64{0, 1, 15, 16, 127, 128, 255, 1<<31 - 1, 1 << 31, 1<<63 - 1, 1 << 63, ^uint64(0)} {
			for _, d := range []int64{0, 1, -1, 15, 16, int64(v), -1 << 63} {
				check(v, d)
			}
		}
		if err := quick.Check(check, &quick.Config{MaxCount: 256}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransferKernelExchangeBounds(t *testing.T) {
	b, scope := br.NewBuilder(8), br.NewScope()
	x, y := inputTerm(t, b, scope, 0, 64), inputTerm(t, b, scope, 1, 64)
	narrow := inputTerm(t, b, scope, 2, 8)
	unsupported := inputTerm(t, b, scope, 3, 16)
	for _, kind := range []string{"add", "exchange", "xadd"} {
		invoke := func(k *TransferKernel, a, b br.Term) error {
			switch kind {
			case "add":
				r, err := k.Add(a, b)
				if err != nil && r != (ArithmeticResult{}) {
					t.Fatal("partial result")
				}
				return err
			case "exchange":
				r, err := k.Exchange64(a, b)
				if err != nil && r != (ExchangeResult{}) {
					t.Fatal("partial result")
				}
				return err
			default:
				r, err := k.ExchangeAdd64(a, b)
				if err != nil && r != (ExchangeAddResult{}) {
					t.Fatal("partial result")
				}
				return err
			}
		}
		for _, pair := range [][2]br.Term{{x, narrow}, {narrow, x}, {unsupported, unsupported}, {x, {}}, {{}, y}} {
			k, _ := NewTransferKernel(t.Context(), RelationLimits{})
			if invoke(k, pair[0], pair[1]) == nil {
				t.Fatal("invalid operands", kind)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		k, _ := NewTransferKernel(ctx, RelationLimits{})
		cancel()
		if err := invoke(k, x, y); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled result", kind, err)
		}
		k, _ = NewTransferKernel(t.Context(), RelationLimits{Work: 3})
		if invoke(k, x, y) == nil {
			t.Fatal("unmetered import", kind)
		}
	}
}

func TestTransitionExchangeRawForms(t *testing.T) {
	for _, form := range []string{"488711", "f0488711", "f0480fc111", "4801f2", "4803d6", "0f1f440000", "0f1f00", "0f1fc0", "0f1f84f088776655"} {
		code := hexBytes(t, form)
		compareExecutedEncoding(t, code)
		for _, p := range []byte{0xf0, 0xf2, 0xf3, 0x66, 0x67, 0x64, 0x48} {
			compareExecutedEncoding(t, append([]byte{p}, code...))
		}
		for n := 1; n < len(code); n++ {
			compareExecutedEncoding(t, code[:n])
		}
	}
	for _, form := range []string{"480fc111", "f00fc111", "f0480fc011", "488611", "8711", "f0480fc1d1", "4887d1", "6601f2", "01f2", "0f1f4c0000", "0f1f7c0000"} {
		code := hexBytes(t, form)
		compareExecutedEncoding(t, code)
		im := image(t, append(code, 0xc3))
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)), TransitionLimits{}, TransitionExpansion{PC: testEntry})
		if err == nil {
			c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
			transitionRefused(t, c, err)
		}
	}
}

func TestTransitionExchangePermissionsAndAliases(t *testing.T) {
	for _, form := range []string{"48871424", "f0480fc11424"} {
		code := hexBytes(t, form)
		im := image(t, append(code, 0xc3))
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)), TransitionLimits{}, TransitionExpansion{PC: testEntry})
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"good", "readonly", "writeonly", "short", "unaligned", "model", "alias-unknown"} {
			f := stateFace(16, 0)
			f.Words = nil
			f.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true, Writable: true}}
			f.Conditions.LockedMemory = LockedMemoryModel
			switch mode {
			case "readonly":
				f.Regions[0].Writable = false
			case "writeonly":
				f.Regions[0].Readable = false
			case "short":
				f.Regions[0].Bytes.End = 7
			case "unaligned":
				f.Origin.Residue = 1
			case "model":
				f.Conditions.LockedMemory = ""
			case "alias-unknown":
				// RDX as both base and source is arbitrary at entry. Its numeric
				// contents cannot create the pointer needed by the selected access.
				code = hexBytes(t, map[bool]string{true: "488712", false: "f0480fc112"}[form == "48871424"])
				im = image(t, append(code, 0xc3))
				p, err = ProposeTransition(t.Context(), im, testEntry+uint64(len(code)), TransitionLimits{}, TransitionExpansion{PC: testEntry})
				if err != nil {
					t.Fatal(err)
				}
			}
			c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
			if mode == "good" {
				if err != nil {
					t.Fatal(err)
				}
				if len(c.checked.bound.Accesses) != 2 {
					t.Fatal("missing write cycle")
				}
			} else {
				transitionRefused(t, c, err)
			}
		}
	}
	// Vary source/base aliasing, all GPR identities, incoming flags and bytes.
	check := func(seed uint64, source, base uint8, add bool) bool {
		source, base = source%16, base%16
		i := to.Intent{Operation: to.LockedExchange, Src: source, Base: base}
		e := to.Encoding{Form: to.XCHG87, REX: 0x48}
		if add {
			i.Operation, e.Form = to.LockedExchangeAdd, to.LOCKXADD0FC1
		}
		if source >= 8 {
			e.REX |= 4
		}
		if base >= 8 {
			e.REX |= 1
		}
		if base%8 == 4 {
			e.SIB = true
		}
		if base%8 == 5 {
			e.DispBytes = 1
		}
		atomicDescriptorState(t, to.Descriptor{Intent: i, Encoding: e}, i, []byte{byte(seed), byte(seed >> 8), byte(seed >> 16), byte(seed >> 32), byte(seed >> 56)})
		return true
	}
	for reg := uint8(0); reg < 16; reg++ {
		check(^uint64(0), reg, reg, false)
		check(1<<63, reg, reg, true)
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 64}); err != nil {
		t.Fatal(err)
	}
	if err := quick.Check(func(kind, source, base, permissions, extent uint8, displacement int8) bool {
		atomicPermissionProperty(t, kind, source, base, permissions, extent, displacement)
		return true
	}, &quick.Config{MaxCount: 128}); err != nil {
		t.Fatal(err)
	}
}

func atomicPermissionProperty(t testing.TB, kind, source, base, permissions, extent uint8, displacement int8) {
	t.Helper()
	kind, source, base = kind%3, source%16, base%16
	i := to.Intent{Operation: []to.Operation{to.LockedCompareExchange, to.LockedExchange, to.LockedExchangeAdd}[kind], Src: source, Base: base, SignedDisp: int64(displacement)}
	e := to.Encoding{Form: []to.Form{to.LOCKCMPXCHG0FB1, to.XCHG87, to.LOCKXADD0FC1}[kind], REX: 0x48, DispBytes: 1, SIB: base%8 == 4}
	if source >= 8 {
		e.REX |= 4
	}
	if base >= 8 {
		e.REX |= 1
	}
	var code []byte
	if base != 4 {
		p := to.Intent{Operation: to.MoveRegister, Dst: base, Src: 4}
		var err error
		code, err = to.Encode(p, stateEncoding(p, 0))
		if err != nil {
			t.Fatal(err)
		}
	}
	at := testEntry + uint64(len(code))
	raw, err := to.Encode(i, e)
	if err != nil {
		t.Fatal(err)
	}
	code = append(code, raw...)
	cut := testEntry + uint64(len(code))
	code = append(code, 0xc3)
	im := image(t, code)
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{}, TransitionExpansion{PC: at})
	if err != nil {
		t.Fatal(err)
	}
	f := stateFace(16, 0)
	f.Conditions.LockedMemory = LockedMemoryModel
	f.Words = nil
	n := int64(extent%16) + 1
	f.Regions = []RelativeRegion{{Bytes: RelativeSpan{int64(displacement), int64(displacement) + n}, Readable: permissions&1 != 0, Writable: permissions&2 != 0}}
	c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	valid := permissions&3 == 3 && n >= 8 && displacement%8 == 0
	if !valid {
		transitionRefused(t, c, err)
		return
	}
	if err != nil {
		t.Fatal("admissible RMW refused", kind, source, base, permissions, extent, displacement, err)
	}
	b := c.checked.bound
	if len(b.Accesses) != 2 || b.Accesses[0].Bytes != (RelativeSpan{int64(displacement), int64(displacement) + 8}) || b.Accesses[0].Bytes != b.Accesses[1].Bytes || b.Accesses[0].Kind != FrameRead || b.Accesses[1].Kind != FrameWrite {
		t.Fatal("RMW extent/permission oracle mismatch")
	}
}

func TestTransitionAddressShapedNOPNeverReads(t *testing.T) {
	code := hexBytes(t, "0f1f440000c3")
	im := image(t, code)
	p, err := ProposeTransition(t.Context(), im, testEntry+5, TransitionLimits{}, TransitionExpansion{PC: testEntry})
	if err != nil {
		t.Fatal(err)
	}
	f := stateFace(16, 0)
	f.Regions = nil
	f.Words = nil
	c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	b := c.checked.bound
	if len(b.Accesses) != 0 || len(b.PrimitiveEffects) != 0 || b.Registers[RAX].Value != b.InitialRegisters[RAX] {
		t.Fatal("NOP acquired data/address effects")
	}
	for _, v := range []uint64{0, 1 << 48, ^uint64(0)} {
		if stateEval(t, b.Registers[RAX].Value, map[br.Term]uint64{b.InitialRegisters[RAX]: v}) != v {
			t.Fatal("NOP constrained arbitrary address")
		}
	}
	for reg, value := range b.Registers {
		if value.Value != b.InitialRegisters[reg] || b.Preserved[reg] != ^uint64(0) {
			t.Fatal("NOP changed a register", reg)
		}
	}
}

func TestTransitionExchangePointerWordsAndUnchangedWrites(t *testing.T) {
	for _, kind := range []string{"exchange", "zero", "nonzero"} {
		// A complete eight-byte pointer word originates from actual LEA/store.
		prefix := "488d44240848890424"
		rmw := "f0480fc11424"
		switch kind {
		case "exchange":
			prefix += "4889e2"
			rmw = "48871424"
		case "zero":
			prefix += "48ba0000000000000000"
		case "nonzero":
			prefix += "ba01000000"
		}
		before := hexBytes(t, prefix)
		code := append(before, hexBytes(t, rmw+"488b0c24c3")...)
		im := image(t, code)
		f := stateFace(16, 0)
		f.Conditions.LockedMemory = LockedMemoryModel
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)-1), TransitionLimits{}, TransitionExpansion{PC: testEntry + uint64(len(before))})
		if err != nil {
			t.Fatal(err)
		}
		c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		b := c.checked.bound
		if b.Registers[RDX].Pointer != (OriginPointer{Origin: b.Origin, Offset: 8}) {
			t.Fatal("old memory pointer lost", kind, b.Registers[RDX].Pointer)
		}
		var want TransitionPointer
		if kind == "exchange" {
			want = OriginPointer{Origin: b.Origin, Offset: 0}
		}
		if kind == "zero" {
			want = OriginPointer{Origin: b.Origin, Offset: 8}
		}
		if b.Registers[RCX].Pointer != want {
			t.Fatal("new memory provenance unjustified", kind, b.Registers[RCX].Pointer)
		}
	}
	for _, raw := range []string{"488b142448871424c3", "ba00000000f0480fc11424c3"} {
		code := hexBytes(t, raw)
		im := image(t, code)
		at := testEntry + 4
		if raw[0] == 'b' {
			at = testEntry + 5
		}
		p, err := ProposeTransition(t.Context(), im, testEntry+uint64(len(code)-1), TransitionLimits{}, TransitionExpansion{PC: at})
		if err != nil {
			t.Fatal(err)
		}
		f := stateFace(16, 0)
		f.Conditions.LockedMemory = LockedMemoryModel
		f.Words = nil
		f.Regions = []RelativeRegion{{Bytes: RelativeSpan{0, 8}, Readable: true}}
		c, err := CheckTransition(t.Context(), im, f, p, TransitionLimits{})
		transitionRefused(t, c, err)
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.PC != at || refusal.Premise != "transition-permission" {
			t.Fatal("unchanged write lacked permission check", err)
		}
	}
	// Addition of an arbitrary register is not a justified offset, even when a
	// sampled assignment would happen to leave the numeric pointer unchanged.
	im := image(t, hexBytes(t, "4889e14801d1488b01c3"))
	p, err := ProposeTransition(t.Context(), im, testEntry+9, TransitionLimits{}, TransitionExpansion{PC: testEntry + 3})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CheckTransition(t.Context(), im, stateFace(16, 0), p, TransitionLimits{})
	transitionRefused(t, c, err)
}

func TestTransitionExchangeCancellationAndCumulativeAccounting(t *testing.T) {
	im := image(t, hexBytes(t, "48871424f0480fc114244801f20f1f440000c3"))
	f := stateFace(16, 0)
	f.Conditions.LockedMemory = LockedMemoryModel
	choices := []TransitionExpansion{{PC: testEntry}, {PC: testEntry + 4}, {PC: testEntry + 10}, {PC: testEntry + 13}}
	p, err := ProposeTransition(t.Context(), im, testEntry+18, TransitionLimits{}, choices...)
	if err != nil {
		t.Fatal(err)
	}
	count := &imageCallbackContext{Context: t.Context()}
	c, err := CheckTransition(count, im, f, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		ctx, cancel := context.WithCancel(t.Context())
		callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		failed, err := CheckTransition(callback, im, f, p, TransitionLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || failed.checked != nil {
			t.Fatal("cancellation acquired result", at, err)
		}
	}
	first, err := ProposeTransition(t.Context(), im, testEntry+4, TransitionLimits{}, choices[0])
	if err != nil {
		t.Fatal(err)
	}
	prior, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	limited, err := CheckTransition(t.Context(), im, f, first, TransitionLimits{RelationLimits: RelationLimits{Work: prior.checked.work + 10}})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := CheckTransitionContinuation(t.Context(), limited, p)
	transitionRefused(t, failed, err)
	next, err := CheckTransitionContinuation(t.Context(), prior, p)
	if err != nil {
		t.Fatal(err)
	}
	stateInheritedInputs(t, prior.checked.bound, next.checked.bound)
	assertTransitionAlpha(t, c, next)
	old, _ := c.Bound()
	projection, _ := c.Bound()
	projection.PrimitiveEffects[0] = LockedExchange64Effect{}
	projection.PrimitiveEffects[1] = LockedExchangeAdd64Effect{}
	after, _ := c.Bound()
	if !reflect.DeepEqual(old, after) {
		t.Fatal("projection changed owned exchange evidence")
	}
}
