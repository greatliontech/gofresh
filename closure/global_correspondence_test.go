package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

type globalNativeFixture struct {
	image      *nativeproof.Image
	raw        []byte
	entry, cut uint64
	cuts       []uint64
	face       nativeproof.TransitionInterface
}

// Generate from semantic intent, including independent data layout/payloads.
// This is a synthetic image, not a rewritten actual artifact. ELF entry is a RET
// before the conditional region, so a positive cannot come from entry substitution.
func globalNativeImage(t testing.TB, addresses [2]uint64, values [3]uint64, pointer uint64, dataBase uint64, payload []byte, extra string) globalNativeFixture {
	t.Helper()
	const base = uint64(0x401000)
	code := []byte{0xc3}
	var cuts []uint64
	mov := func(reg byte, value uint64) {
		code = append(code, 0x48, 0xb8+reg)
		code = binary.LittleEndian.AppendUint64(code, value)
		cuts = append(cuts, base+uint64(len(code)))
	}
	store := func(address uint64) {
		pc := base + uint64(len(code))
		code = append(code, 0x48, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(pc+7)))
		cuts = append(cuts, base+uint64(len(code)))
	}
	load := func(address uint64) {
		pc := base + uint64(len(code))
		code = append(code, 0x48, 0x8b, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(pc+7)))
	}
	if extra == "early-read" {
		load(addresses[0])
	}
	mov(0, values[0])
	store(addresses[0])
	mov(0, values[1])
	store(addresses[1])
	if extra == "extra-write" {
		store(addresses[1])
	}
	if extra == "matched-read" || extra == "extra-read" {
		load(addresses[1])
	}
	if extra == "extra-read" {
		// One load can implement the actual source operand read. A second is
		// surplus even though both return the same overwritten value.
		load(addresses[1])
	}
	mov(0, values[1])
	pc := base + uint64(len(code))
	code = append(code, 0x48, 0x8d, 0x0d)
	code = binary.LittleEndian.AppendUint32(code, uint32(int64(pointer)-int64(pc+7)))
	cuts = append(cuts, base+uint64(len(code)))
	mov(2, values[2])
	switch extra {
	case "rax-low":
		mov(0, values[1]^1)
	case "rax-high":
		mov(0, values[1]^(uint64(1)<<63))
	case "rdx-low":
		mov(2, values[2]^1)
	case "rdx-high":
		mov(2, values[2]^(uint64(1)<<63))
	case "clobber-rbx":
		mov(3, 17)
	case "clobber-r8":
		code = append(code, 0x49, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, 17)
		cuts = append(cuts, base+uint64(len(code)))
	}
	cut := base + uint64(len(code))
	code = append(code, 0xf0, 0x48, 0x0f, 0xb1, 0x11, 0xc3)
	raw := make([]byte, 8192+128)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], 2)
	binary.LittleEndian.PutUint16(raw[18:], 62)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint64(raw[24:], base)
	binary.LittleEndian.PutUint64(raw[32:], 64)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	binary.LittleEndian.PutUint16(raw[54:], 56)
	binary.LittleEndian.PutUint16(raw[56:], 2)
	for i, m := range []struct {
		off, addr, size uint64
		flags           uint32
	}{{4096, base, uint64(len(code)), 5}, {8192, dataBase, 128, 6}} {
		h := raw[64+i*56:]
		binary.LittleEndian.PutUint32(h, 1)
		binary.LittleEndian.PutUint32(h[4:], m.flags)
		binary.LittleEndian.PutUint64(h[8:], m.off)
		binary.LittleEndian.PutUint64(h[16:], m.addr)
		binary.LittleEndian.PutUint64(h[32:], m.size)
		binary.LittleEndian.PutUint64(h[40:], m.size)
		binary.LittleEndian.PutUint64(h[48:], 4096)
	}
	copy(raw[4096:], code)
	copy(raw[8192:], payload)
	im, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return globalNativeFixture{image: im, raw: raw, entry: base + 1, cut: cut, cuts: cuts, face: globalNativeFace([]nativeproof.Span{{Start: dataBase, End: dataBase + 128}})}
}

func globalNativeFace(spans []nativeproof.Span) nativeproof.TransitionInterface {
	return nativeproof.TransitionInterface{Origin: nativeproof.OriginDomain{Min: 0x100000000, Max: 0x1fffffff000, Modulus: 16}, Envelope: nativeproof.RelativeSpan{Start: -16, End: 16}, ImageRegions: spans,
		Conditions: nativeproof.TransitionConditions{Machine: nativeproof.MachineModel, InstructionMapping: true, EntryState: true, IsolatedExecution: true, MemoryMapping: true, NoHiddenAliases: true, UnalignedAccess: true}}
}

func globalSourceFixture(t testing.TB, names [2]string, values [3]uint64, extra, pointer string) (computationSource, *ssa.Call, [2]*ssa.Global) {
	t.Helper()
	if pointer == "" {
		pointer = names[0]
	}
	before, after := "", ""
	switch extra {
	case "early-read":
		before = fmt.Sprintf("_ = %s;", names[0])
	case "extra-write":
		after = "other=0;"
	case "extra-read":
		after = fmt.Sprintf("_ = %s;", names[0])
	case "hook":
		after = "hook();"
	}
	s := relationFixture(t, fmt.Sprintf("var %s,%s,other uint64;func hook(){other=1};func sink(p *uint64,x,y uint64);func F(){%s%s=%d;%s=%d;%ssink(&%s,%s,%d);other=77}", names[0], names[1], before, names[0], values[0], names[1], values[1], after, pointer, names[1], values[2]), 64)
	root := s.prog.Roots["F"]
	var call *ssa.Call
	for _, b := range root.Blocks {
		for _, ins := range b.Instrs {
			if c, ok := ins.(*ssa.Call); ok && c.Call.StaticCallee().Name() == "sink" {
				call = c
			}
		}
	}
	if call == nil {
		t.Fatal("missing fixture boundary")
	}
	p := root.Pkg
	return s, call, [2]*ssa.Global{p.Members[names[0]].(*ssa.Global), p.Members[names[1]].(*ssa.Global)}
}

func globalPrefix(t testing.TB, s computationSource, call *ssa.Call) *sourceOperandPrefix {
	t.Helper()
	p, err := checkSourceOperandPrefix(t.Context(), s, s.prog.Roots["F"], call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func globalNativeProof(t testing.TB, f globalNativeFixture, continued bool) nativeproof.TransitionCertificate {
	t.Helper()
	p, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, f.cut, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if !continued {
		c, err := nativeproof.CheckRegionTransition(t.Context(), f.image, f.entry, f.face, p, nativeproof.TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var c nativeproof.TransitionCertificate
	for i, cut := range f.cuts {
		var p nativeproof.TransitionProposal
		var err error
		if i == 0 {
			p, err = nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, cut, nativeproof.TransitionLimits{})
		} else {
			p, err = nativeproof.ProposeTransitionContinuation(t.Context(), c, cut)
		}
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			c, err = nativeproof.CheckRegionTransition(t.Context(), f.image, f.entry, f.face, p, nativeproof.TransitionLimits{})
		} else {
			c, err = nativeproof.CheckTransitionContinuation(t.Context(), c, p)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func globalRho(s computationSource, f globalNativeFixture, g [2]*ssa.Global, a [2]uint64) storageRepresentation {
	return storageRepresentation{source: s.prog, image: f.image, bindings: []storageBinding{
		{object: regionObject{kind: regionGlobal, site: g[0]}, base: nativeproof.TransitionLocation{Image: true, Offset: int64(a[0])}},
		{object: regionObject{kind: regionGlobal, site: g[1]}, base: nativeproof.TransitionLocation{Image: true, Offset: int64(a[1])}},
	}}
}

func checkGlobalFixture(ctx context.Context, s computationSource, call *ssa.Call, f globalNativeFixture, p *sourceOperandPrefix, n nativeproof.TransitionCertificate, rho storageRepresentation) (*globalOperandCorrespondence, error) {
	return checkGlobalOperandCorrespondence(ctx, s, s.prog.Roots["F"], call, f.image, f.entry, f.cut, p, n, rho)
}

func TestGlobalOperandCorrespondenceProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0x474c4f42414c))
	for sample := 0; sample < 32; sample++ {
		values := [3]uint64{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		base := uint64(0x700000 + 4096*sample)
		// Typed uint64 globals require selected-layout alignment even though
		// the native machine separately permits unaligned ordinary accesses.
		addresses := [2]uint64{base + 8*uint64(rng.Intn(4)), base + 64 + 8*uint64(rng.Intn(4))}
		payload := make([]byte, 128)
		for i := range payload {
			payload[i] = byte(rng.Uint32())
		}
		names := [2]string{fmt.Sprintf("left%d", sample), fmt.Sprintf("right%d", sample)}
		checkGlobalPopulation(t, names, values, addresses, base, payload, rng)
	}
}

func checkGlobalPopulation(t testing.TB, names [2]string, values [3]uint64, addresses [2]uint64, base uint64, payload []byte, rng *rand.Rand) {
	t.Helper()
	s, call, globals := globalSourceFixture(t, names, values, "", "")
	prefix := globalPrefix(t, s, call)
	for _, permuted := range []bool{false, true} {
		a := addresses
		if permuted {
			a[0], a[1] = a[1], a[0]
		}
		f := globalNativeImage(t, a, values, a[0], base, payload, "")
		for _, continued := range []bool{false, true} {
			n := globalNativeProof(t, f, continued)
			c, err := checkGlobalFixture(t.Context(), s, call, f, prefix, n, globalRho(s, f, globals, a))
			if err != nil {
				t.Fatalf("permutation=%t continuation=%t: %v", permuted, continued, err)
			}
			assertGlobalCertificate(t, c, values, a, rng)
		}
	}
}

func FuzzGlobalOperandCorrespondence(f *testing.F) {
	f.Add(uint64(42), uint64(0), uint64(1), uint64(17), []byte{0, 255})
	f.Add(^uint64(0), uint64(1)<<63, uint64(0xabcdefabcdefabcd), ^uint64(0), []byte{42, 0, 1})
	f.Fuzz(func(t *testing.T, z, x, next, layout uint64, payload []byte) {
		base := uint64(0x700000) + (layout%1024)*4096
		a := [2]uint64{base + 8*((layout>>10)%4), base + 64 + 8*((layout>>15)%4)}
		names := [2]string{fmt.Sprintf("left%d", layout), fmt.Sprintf("right%d", layout)}
		if len(payload) > 128 {
			payload = payload[:128]
		}
		checkGlobalPopulation(t, names, [3]uint64{z, x, next}, a, base, payload, rand.New(rand.NewSource(int64(layout))))
	})
}

// This independent intent oracle supplies sampled arbitrary prior bytes and
// scratch bits, then checks all retained memory and operand outputs. Acceptance
// itself uses universal checked equalities, not these concrete comparisons.
func assertGlobalCertificate(t testing.TB, c *globalOperandCorrespondence, values [3]uint64, addresses [2]uint64, rng *rand.Rand) {
	t.Helper()
	if c == nil || c.rules != globalOperandRules || c.open != (computationCorrespondenceObligations{true, true, true, true, true}) || c.account == nil || len(c.account.equalities) < 5 || len(c.account.inputs) != 2 {
		t.Fatal("incomplete proof")
	}
	for _, w := range c.account.equalities {
		if !w.Valid() {
			t.Fatal("unchecked equality")
		}
	}
	b, _ := c.native.Bound()
	for sample := 0; sample < 3; sample++ {
		assign := map[br.Term]uint64{}
		for _, term := range b.InitialRegisters {
			assign[term] = rng.Uint64()
		}
		assign[b.InitialPredicates.CF] = uint64(rng.Intn(2))
		assign[b.InitialPredicates.ZF] = uint64(rng.Intn(2))
		assign[b.InitialPredicates.SFXorOF] = uint64(rng.Intn(2))
		before := map[nativeproof.TransitionLocation]byte{}
		for _, cell := range b.InitialMemory {
			v := byte(rng.Uint32())
			assign[cell.Value] = uint64(v)
			before[cell.TransitionLocation] = v
		}
		assignments := make([]br.Assignment, 0, len(assign))
		for k, v := range assign {
			assignments = append(assignments, br.Assignment{Variable: k, Value: v})
		}
		eval := func(term br.Term) uint64 {
			v, err := br.Eval(t.Context(), term, assignments, br.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		for i, input := range c.account.inputs {
			var word [8]byte
			for j := range word {
				word[j] = before[nativeproof.TransitionLocation{Image: true, Offset: int64(addresses[i]) + int64(j)}]
			}
			if eval(input.native) != binary.LittleEndian.Uint64(word[:]) {
				t.Fatal("initial little-endian relation differs")
			}
		}
		for _, cell := range b.Memory {
			want := before[cell.TransitionLocation]
			for i, a := range addresses {
				if cell.Image && cell.Offset >= int64(a) && cell.Offset < int64(a+8) {
					want = byte(values[i] >> uint(8*(cell.Offset-int64(a))))
				}
			}
			if eval(cell.Value) != uint64(want) {
				t.Fatal("independent current-byte oracle disagrees")
			}
		}
		for reg, want := range map[nativeproof.Register]uint64{nativeproof.RAX: values[1], nativeproof.RCX: addresses[0], nativeproof.RDX: values[2]} {
			if eval(b.Registers[reg].Value) != want {
				t.Fatal("independent operand oracle disagrees")
			}
		}
	}
}

func TestGlobalOperandCorrespondenceRefusals(t *testing.T) {
	values := [3]uint64{42, 0, 1}
	addresses := [2]uint64{0x700008, 0x700048}
	names := [2]string{"a", "b"}
	s, call, globals := globalSourceFixture(t, names, values, "", "")
	f := globalNativeImage(t, addresses, values, addresses[0], 0x700000, nil, "")
	prefix := globalPrefix(t, s, call)
	native := globalNativeProof(t, f, false)
	if _, err := checkGlobalFixture(t.Context(), s, call, f, prefix, native, globalRho(s, f, globals, addresses)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"map-swap", "map-overlap", "source-alias", "native-target", "partial-overlap", "native-pointer", "source-value", "source-pointer", "source-pointer-width", "foreign-source", "foreign-image", "extra-write", "early-read", "extra-read", "wrong-cut", "wrong-boundary", "wrong-source-cut", "composition-budget", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			source, cut, packet, fragment, proof := s, call, prefix, f, native
			rho := globalRho(s, f, globals, addresses)
			ctx := t.Context()
			var limits []globalCorrespondenceLimits
			switch mode {
			case "map-swap":
				rho.bindings[0].base, rho.bindings[1].base = rho.bindings[1].base, rho.bindings[0].base
			case "map-overlap":
				rho.bindings[1].base.Offset = rho.bindings[0].base.Offset + 7
			case "source-alias":
				rho.bindings[1].object = rho.bindings[0].object
			case "native-target", "partial-overlap":
				a := addresses
				if mode == "partial-overlap" {
					a[1] = a[0] + 7
				} else {
					a[1] += 16
				}
				fragment = globalNativeImage(t, a, values, addresses[0], 0x700000, nil, "")
				proof = globalNativeProof(t, fragment, false)
				rho.image = fragment.image
			case "source-value", "source-pointer":
				v := values
				ptr := ""
				if mode == "source-value" {
					v[0]++
				} else {
					ptr = names[1]
				}
				var g [2]*ssa.Global
				source, cut, g = globalSourceFixture(t, names, v, "", ptr)
				packet = globalPrefix(t, source, cut)
				rho = globalRho(source, f, g, addresses)
			case "native-pointer":
				fragment = globalNativeImage(t, addresses, values, addresses[1], 0x700000, nil, "")
				proof = globalNativeProof(t, fragment, false)
				rho.image = fragment.image
			case "source-pointer-width":
				source = relationFixture(t, "var a,b uint64;func sink(*uint64,uint64,uint64);func F(){a=42;b=0;sink(&a,b,1)}", 32)
				for _, ins := range source.prog.Roots["F"].Blocks[0].Instrs {
					if c, ok := ins.(*ssa.Call); ok {
						cut = c
					}
				}
				packet = globalPrefix(t, source, cut)
				pkg := source.prog.Roots["F"].Pkg
				rho = globalRho(source, f, [2]*ssa.Global{pkg.Members["a"].(*ssa.Global), pkg.Members["b"].(*ssa.Global)}, addresses)
			case "foreign-source":
				other, c, _ := globalSourceFixture(t, names, values, "", "")
				packet = globalPrefix(t, other, c)
			case "foreign-image":
				other := f
				var err error
				other.image, err = nativeproof.NewImage(t.Context(), f.raw)
				if err != nil {
					t.Fatal(err)
				}
				proof = globalNativeProof(t, other, false)
			case "extra-write", "early-read", "extra-read":
				fragment = globalNativeImage(t, addresses, values, addresses[0], 0x700000, nil, mode)
				proof = globalNativeProof(t, fragment, false)
				rho.image = fragment.image
			case "wrong-cut":
				fragment.cut--
			case "wrong-boundary":
				fragment.raw = append([]byte(nil), f.raw...)
				fragment.raw[4096+int(f.cut-0x401000)] = 0x90
				var err error
				fragment.image, err = nativeproof.NewImage(t.Context(), fragment.raw)
				if err != nil {
					t.Fatal(err)
				}
				proof = globalNativeProof(t, fragment, false)
				rho.image = fragment.image
			case "composition-budget":
				limits = []globalCorrespondenceLimits{{work: 1}}
			case "wrong-source-cut":
				cut = nil
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := checkGlobalOperandCorrespondence(ctx, source, source.prog.Roots["F"], cut, fragment.image, fragment.entry, fragment.cut, packet, proof, rho, limits...)
			if got != nil || err == nil {
				t.Fatal("invalid relation accepted", mode)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if mode == "composition-budget" && !strings.Contains(err.Error(), "cumulative proof work exhausted") {
				t.Fatal("composition did not exhaust its cumulative work budget", err)
			}
			if mode == "source-value" && strings.Contains(err.Error(), "owner") {
				t.Fatal("value control failed for ownership instead of semantic mismatch", err)
			}
		})
	}
	for _, mode := range []string{"extra-write", "early-read", "hook"} {
		t.Run("source-"+mode, func(t *testing.T) {
			s, c, g := globalSourceFixture(t, names, values, mode, "")
			p, err := checkSourceOperandPrefix(t.Context(), s, s.prog.Roots["F"], c, defaultRegistrationLimits())
			if err == nil {
				_, err = checkGlobalFixture(t.Context(), s, c, f, p, native, globalRho(s, f, g, addresses))
			}
			if err == nil {
				t.Fatal("source effect escaped correspondence")
			}
		})
	}
}

func TestGlobalOperandCorrespondenceOrdinaryReadAccounting(t *testing.T) {
	values := [3]uint64{42, 7, 11}
	addresses := [2]uint64{0x700008, 0x700048}
	for _, mode := range []string{"source-extra-read", "matched-native-read"} {
		t.Run(mode, func(t *testing.T) {
			sourceExtra, nativeExtra := "", "matched-read"
			if mode == "source-extra-read" {
				sourceExtra, nativeExtra = "extra-read", ""
			}
			s, call, globals := globalSourceFixture(t, [2]string{"a", "b"}, values, sourceExtra, "")
			prefix := globalPrefix(t, s, call)
			fixture := globalNativeImage(t, addresses, values, addresses[0], 0x700000, nil, nativeExtra)
			native := globalNativeProof(t, fixture, false)
			proof, err := checkGlobalFixture(t.Context(), s, call, fixture, prefix, native, globalRho(s, fixture, globals, addresses))
			if err != nil {
				t.Fatal(err)
			}
			account := proof.account
			if mode == "source-extra-read" {
				if len(account.accesses) != 4 || len(account.matched) != 2 || len(account.eliminated) != 2 || account.eliminated[0] != 2 || account.eliminated[1] != 3 {
					t.Fatal("both known source reads must be retained and explicitly eliminated")
				}
			} else if len(account.accesses) != 3 || len(account.matched) != 3 || len(account.eliminated) != 0 {
				t.Fatal("actual native read must match the source operand read")
			}
		})
	}
}

func TestSourceOperandPrefixBoundariesAndResources(t *testing.T) {
	for _, mode := range []string{"cancel", "source-budget", "region-budget", "unknown-write", "branch", "later-call"} {
		t.Run(mode, func(t *testing.T) {
			s, c, _ := globalSourceFixture(t, [2]string{"a", "b"}, [3]uint64{9, 7, 11}, "", "")
			if mode == "unknown-write" || mode == "branch" || mode == "later-call" {
				body := "var p *uint64;*p=9;a=9;b=7;sink(&a,b,11)"
				if mode == "branch" {
					body = "if a!=0{a=9};b=7;sink(&a,b,11)"
				}
				if mode == "later-call" {
					body = "a=9;b=7;sink(&a,b,11);sink(&a,b,11)"
				}
				s = relationFixture(t, "var a,b uint64;func sink(*uint64,uint64,uint64);func F(){"+body+"}", 64)
				for _, b := range s.prog.Roots["F"].Blocks {
					for _, ins := range b.Instrs {
						if call, ok := ins.(*ssa.Call); ok {
							c = call
						}
					}
				}
			}
			limits := defaultRegistrationLimits()
			ctx := t.Context()
			switch mode {
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "source-budget":
				limits.source.work = 1
			case "region-budget":
				limits.region.nodes = 1
			}
			if p, err := checkSourceOperandPrefix(ctx, s, s.prog.Roots["F"], c, limits); p != nil || err == nil {
				t.Fatal("invalid prefix accepted")
			}
		})
	}
}

func TestGlobalOperandCorrespondenceOwnsInputs(t *testing.T) {
	values := [3]uint64{^uint64(0), 0xdeadbeef, 0x123456789abcdef0}
	addresses := [2]uint64{0x700008, 0x700048}
	s, call, g := globalSourceFixture(t, [2]string{"first", "second"}, values, "", "")
	f := globalNativeImage(t, addresses, values, addresses[0], 0x700000, nil, "")
	p, n := globalPrefix(t, s, call), globalNativeProof(t, f, false)
	rho := globalRho(s, f, g, addresses)
	ctx := &correspondenceCallbackContext{Context: t.Context(), mutate: func() {
		*f.image = nativeproof.Image{}
		rho.bindings[0] = storageBinding{}
	}}
	c, err := checkGlobalFixture(ctx, s, call, f, p, n, rho)
	if err != nil {
		t.Fatal(err)
	}
	if c.representation.bindings[0].object != (regionObject{kind: regionGlobal, site: g[0]}) || c.representation.bindings[0].base != (nativeproof.TransitionLocation{Image: true, Offset: int64(addresses[0])}) {
		t.Fatal("caller mutated fixed representation")
	}
	if _, ok := c.native.BoundFor(c.representation.image); !ok {
		t.Fatal("captured image ownership lost")
	}
	b, _ := c.native.Bound()
	b.ConditionalRegion = false
	b.Entry = 0
	b.Memory[0].Value = br.Term{}
	b.Accesses[0].Bytes = nativeproof.RelativeSpan{}
	still, _ := c.native.Bound()
	if !still.ConditionalRegion || still.Entry != f.entry || !still.Memory[0].Value.Valid() {
		t.Fatal("projection mutated opaque proof")
	}
	assertGlobalCertificate(t, c, values, addresses, rand.New(rand.NewSource(91)))
}

func TestGlobalOperandCorrespondenceCancellationCheckpoints(t *testing.T) {
	values := [3]uint64{11, 19, 27}
	addresses := [2]uint64{0x700008, 0x700048}
	s, call, g := globalSourceFixture(t, [2]string{"a", "b"}, values, "", "")
	f := globalNativeImage(t, addresses, values, addresses[0], 0x700000, nil, "")
	p, n := globalPrefix(t, s, call), globalNativeProof(t, f, false)
	for _, sourcePhase := range []bool{true, false} {
		run := func(ctx context.Context) error {
			if sourcePhase {
				proof, err := checkSourceOperandPrefix(ctx, s, s.prog.Roots["F"], call, defaultRegistrationLimits())
				if err != nil && proof != nil {
					t.Fatal("partial source evidence on cancellation")
				}
				return err
			}
			proof, err := checkGlobalFixture(ctx, s, call, f, p, n, globalRho(s, f, g, addresses))
			if err != nil && proof != nil {
				t.Fatal("partial correspondence on cancellation")
			}
			return err
		}
		baseline := &relationCallbackContext{Context: t.Context()}
		if err := run(baseline); err != nil {
			t.Fatal(err)
		}
		for _, at := range []int{1, baseline.checks / 4, baseline.checks / 2, baseline.checks - 1, baseline.checks} {
			ctx, cancel := context.WithCancel(t.Context())
			observed := &relationCallbackContext{Context: ctx, at: at, callback: cancel}
			err := run(observed)
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("phase source=%t checkpoint=%d/%d error=%v", sourcePhase, at, baseline.checks, err)
			}
		}
		if err := run(t.Context()); err != nil {
			t.Fatal("cancelled sibling damaged original evidence", err)
		}
	}
}

func TestGlobalOperandCorrespondenceIndependentScalarRefusals(t *testing.T) {
	values := [3]uint64{0xfedcba9876543210, 0xdeadbeef00112233, 0x123456789abcdef0}
	a := [2]uint64{0x700008, 0x700048}
	for _, mode := range []string{"unchanged", "source-third-low", "source-third-high", "rax-low", "rax-high", "rdx-low", "rdx-high"} {
		t.Run(mode, func(t *testing.T) {
			sourceValues := values
			extra := mode
			if strings.HasPrefix(mode, "source-third") {
				delta := uint64(1)
				if mode == "source-third-high" {
					delta <<= 63
				}
				sourceValues[2] ^= delta
				extra = ""
			}
			s, call, g := globalSourceFixture(t, [2]string{"a", "b"}, sourceValues, "", "")
			p := globalPrefix(t, s, call)
			f := globalNativeImage(t, a, values, a[0], 0x700000, nil, extra)
			n := globalNativeProof(t, f, false)
			// Both subordinate proofs are valid, and both actual stores still
			// have their correct values. Only the operand equality can reject.
			b, ok := n.Bound()
			if !ok {
				t.Fatal("native subordinate absent")
			}
			builder := br.NewBuilder(0)
			for i, address := range a {
				actual, err := storageNativeWord(t.Context(), builder, b.Memory, nativeproof.TransitionLocation{Image: true, Offset: int64(address)}, 8)
				if err != nil {
					t.Fatal(err)
				}
				want, _ := builder.Const(br.Bits(64), values[i])
				if _, err := br.Prove(t.Context(), actual, want, br.Limits{}); err != nil {
					t.Fatal("store changed in scalar-only control", err)
				}
			}
			c, err := checkGlobalFixture(t.Context(), s, call, f, p, n, globalRho(s, f, g, a))
			if mode == "unchanged" {
				if err != nil || c == nil {
					t.Fatal(err)
				}
				return
			}
			var equality *br.Refusal
			if c != nil || !errors.As(err, &equality) {
				t.Fatalf("expected correspondence equality refusal, got %v", err)
			}
		})
	}
}

func TestGlobalOperandCorrespondenceAdministrativeFrameRefusals(t *testing.T) {
	v := [3]uint64{42, 0, 1}
	a := [2]uint64{0x700008, 0x700048}
	s, call, g := globalSourceFixture(t, [2]string{"a", "b"}, v, "", "")
	p := globalPrefix(t, s, call)
	for _, mode := range []string{"unchanged", "clobber-rbx", "clobber-r8"} {
		t.Run(mode, func(t *testing.T) {
			f := globalNativeImage(t, a, v, a[0], 0x700000, nil, mode)
			n := globalNativeProof(t, f, false) // A valid native state theorem, not a native refusal.
			b, ok := n.Bound()
			if !ok {
				t.Fatal("native subordinate absent")
			}
			builder := br.NewBuilder(0)
			for reg, value := range map[nativeproof.Register]uint64{nativeproof.RAX: v[1], nativeproof.RCX: a[0], nativeproof.RDX: v[2]} {
				want, _ := builder.Const(br.Bits(64), value)
				if _, err := br.Prove(t.Context(), b.Registers[reg].Value, want, br.Limits{}); err != nil {
					t.Fatal("operand changed in frame-only control", err)
				}
			}
			if len(b.Accesses) != 2 {
				t.Fatal("frame-only control changed memory effects")
			}
			c, err := checkGlobalFixture(t.Context(), s, call, f, p, n, globalRho(s, f, g, a))
			if mode == "unchanged" {
				if err != nil || c == nil {
					t.Fatal(err)
				}
				return
			}
			if c != nil || err == nil || !strings.Contains(err.Error(), "administrative context is not preserved") {
				t.Fatalf("frame consumer did not refuse: %v", err)
			}
		})
	}
}
