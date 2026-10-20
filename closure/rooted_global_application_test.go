package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

type rootedGlobalFixture struct {
	p       *globalFunctionCorrespondence
	entered nativeproof.TransitionCertificate
	image   *nativeproof.Image
	face    nativeproof.TransitionInterface
	root    uint64
	options nativeproof.TransitionOptions
}

// The wrapper is real checked code: an ELF-root syscall, outer CALL, current
// global writes, context changes and a tail transfer to the original body.
// The body theorem is rebuilt under the final fresh image owner and translated
// interface before constructing the source correspondence or applying it.
func newRootedGlobalFixture(t testing.TB, boolean, local string) rootedGlobalFixture {
	t.Helper()
	const base, rootEntry, wrapper = uint64(0x401000), uint64(0x401200), uint64(0x401300)
	const global, boolB, boolC = int64(0x700008), int64(0x700020), int64(0x700021)
	text := `var G uint64;var B,C bool;func Stop(){};func F(){G=7;B=true;C=false;Stop()}`
	ops := []storageFunctionOperation{
		{nativeproof.ImageAddress(global), 8, true, 7},
		{nativeproof.ImageAddress(boolB), 1, true, 1},
		{nativeproof.ImageAddress(boolC), 1, true, 0},
	}
	if local == "materialized" {
		text = `var G uint64;var B,C bool;func Stop(p *uint64){if *p!=13{panic(1)}};func F(){G=7;B=true;C=false;var x uint64;x=13;Stop(&x)}`
		ops = append(ops, storageFunctionOperation{nativeproof.StackOffset(-16), 8, true, 13})
	} else if local == "eliminated" {
		text = `var G uint64;var B,C bool;func Stop(p *float64){if *p!=0{panic(1)}};func F(){G=7;B=true;C=false;var x float64;Stop(&x)}`
	} else if local == "argument" {
		text = `var G uint64;var B,C bool;func Stop(){};func F(p *uint64){G=7;B=true;C=false;Stop()}`
	}
	source, completed := storageFunctionSource(t, text)
	f, _ := storageFunctionNative(t, ops, nativeproof.OriginDomain{})
	code := append([]byte(nil), f.raw[4096:4096+int(f.cut-base)+1]...)
	pc := func() uint64 { return base + uint64(len(code)) }
	pad := func(target uint64) {
		for pc() < target {
			code = append(code, 0x90)
		}
	}
	imm := func(register byte, value uint64) {
		code = append(code, 0x48, 0xb8+register)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	store := func(address int64, width int) {
		at := pc()
		opcode, length := byte(0x88), int64(6)
		if width == 8 {
			code = append(code, 0x48)
			opcode, length = 0x89, 7
		}
		code = append(code, opcode, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(address-int64(at)-length))
	}
	pad(rootEntry)
	imm(0, 158)
	imm(7, 0x1002)
	imm(6, 0x700060)
	syscall := pc()
	code = append(code, 0x0f, 0x05)
	call := pc()
	code = append(code, 0xe8)
	code = binary.LittleEndian.AppendUint32(code, uint32(wrapper-call-5))
	continuation := pc()
	code = append(code, 0xc3)
	pad(wrapper)
	clear := pc()
	code = append(code, 0xfc) // Current DF differs from the original arbitrary DF.
	imm(5, 123)               // Current BP, not the original root BP, is preserved.
	imm(0, 99)
	store(global, 8)
	switch boolean {
	case "symbolic":
		code = append(code, 0x48, 0x83, 0xfb, 0, 0x0f, 0x95, 0xc0) // CMP RBX,0; SETNE AL (all entry flags defined)
	case "arbitrary":
		code = append(code, 0x88, 0xd8) // MOV AL,BL
	default:
		value := map[string]uint64{"zero": 0, "one": 1, "two": 2, "ff": 255}[boolean]
		imm(0, value)
	}
	store(boolB, 1)
	imm(0, 1)
	store(boolC, 1)
	jump := pc()
	code = append(code, 0xe9)
	code = binary.LittleEndian.AppendUint32(code, uint32(f.entry-jump-5))
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[24:], rootEntry)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[8192+8:], 44) // The rooted valuation must be 99, not ELF's 44.
	image, err := nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	rootFace := globalNativeFace(f.face.ImageRegions)
	rootFace.Envelope = nativeproof.RelativeSpan{Start: -80, End: 16}
	rootFace.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -80, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 16}, Readable: true}}
	rootFace.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -80, End: 0}, Until: &continuation}
	rootFace.Conditions.Syscall, rootFace.Conditions.UserAddressBits = nativeproof.LinuxAMD64SyscallModel, 48
	rootFace.Initialization, err = nativeproof.CheckImageInitialization(t.Context(), image, nativeproof.StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	childFace := f.face
	childFace.Origin.Min -= 8
	childFace.Origin.Max -= 8
	childFace.Origin.Residue = 8
	childFace.Conditions = rootFace.Conditions
	childFace.ReturnContext = &nativeproof.TransitionReturnContext{Target: continuation, Preserved: []nativeproof.Register{nativeproof.RBP}}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), image, f.entry, f.cut, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := nativeproof.CheckRegionTransition(t.Context(), image, f.entry, childFace, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	returned, err := nativeproof.CheckTransitionReturn(t.Context(), body)
	if err != nil {
		t.Fatal(err)
	}
	rho := storageRepresentation{source: source.prog, image: image}
	for i, name := range []string{"G", "B", "C"} {
		rho.bindings = append(rho.bindings, storageBinding{object: regionObject{kind: regionGlobal, site: source.prog.Roots["F"].Pkg.Members[name].(*ssa.Global)}, base: ops[i].location})
	}
	if local == "materialized" {
		rho.bindings = append(rho.bindings, storageBinding{object: storageFunctionLocal(t, completed), base: nativeproof.StackOffset(-16)})
	}
	var arguments []globalFunctionArgument
	if local == "argument" {
		arguments = []globalFunctionArgument{{parameter: source.prog.Roots["F"].Params[0], register: nativeproof.RBX}}
	}
	p, err := checkGlobalFunctionCorrespondence(t.Context(), source, source.prog.Roots["F"], image, f.entry, completed, returned, rho, arguments)
	if err != nil {
		t.Fatal(err)
	}
	options := nativeproof.TransitionOptions{Expansions: []nativeproof.TransitionExpansion{{PC: syscall, AllActivations: true}, {PC: call, AllActivations: true}, {PC: clear, AllActivations: true}}}
	decode := globalCandidateDecoder(t, f.raw)
	for at := wrapper + 1; at < pc(); {
		instruction := decode(at)
		if nativeproof.TransitionExpansionRequired(instruction) {
			options.Expansions = append(options.Expansions, nativeproof.TransitionExpansion{PC: at, AllActivations: true})
		}
		at += uint64(instruction.Len)
	}
	proposal, err = nativeproof.ProposeTransition(t.Context(), image, f.entry, nativeproof.TransitionLimits{}, options)
	if err != nil {
		t.Fatal(err)
	}
	entered, err := nativeproof.CheckTransition(t.Context(), image, rootFace, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return rootedGlobalFixture{p: p, entered: entered, image: image, face: rootFace, root: rootEntry, options: options}
}

func (f rootedGlobalFixture) application(t testing.TB) nativeproof.TransitionCallCertificate {
	t.Helper()
	a, err := nativeproof.CheckTransitionActiveReturn(t.Context(), f.entered, f.p.native)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRootedGlobalApplicationCurrentTypedInputs(t *testing.T) {
	for _, local := range []string{"none", "materialized", "eliminated"} {
		for _, boolean := range []string{"zero", "one", "symbolic", "two", "ff", "arbitrary"} {
			t.Run(local+"/"+boolean, func(t *testing.T) {
				f := newRootedGlobalFixture(t, boolean, local)
				a := f.application(t)
				p := f.p
				before := *p
				r, err := checkRootedGlobalApplication(t.Context(), p, a)
				if boolean == "two" || boolean == "ff" || boolean == "arbitrary" {
					if r != nil || err == nil || !strings.Contains(err.Error(), "Boolean encoding") {
						t.Fatalf("noncanonical entry admitted despite later overwrite: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if r.correspondence != p || r.application != a || !reflect.DeepEqual(before, *p) || len(r.inputs) != len(p.inputs) || len(r.equalities) != 2 || r.work == 0 {
					t.Fatal("adapter replaced or mutated original evidence")
				}
				bound, _ := a.BoundFor(f.image)
				entered, _ := f.entered.BoundFor(f.image)
				if bound.StackShift != -8 || bound.ChildEntry.ConditionalRegion || bound.Successor.InitialFS != entered.InitialFS || !bound.Successor.Thread.ContextChanged || bound.Successor.Thread != entered.Thread || bound.Successor.Direction != entered.Direction || bound.Successor.Registers[nativeproof.RBP] != entered.Registers[nativeproof.RBP] || len(bound.Successor.PrimitiveEffects) != 1 {
					t.Fatal("current context or original root history lost")
				}
				if len(bound.Successor.Accesses) < len(entered.Accesses) || !reflect.DeepEqual(bound.Successor.Accesses[:len(entered.Accesses)], entered.Accesses) {
					t.Fatal("earlier outer CALL and wrapper global effects disappeared")
				}
				if p.open != (computationCorrespondenceObligations{true, true, true, true, true}) || p.source.region.packet.input.storageModel != conditionalRegionStorageModel() {
					t.Fatal("rooted specialization cleared broader obligations or antecedent")
				}
				builder := br.NewBuilder(64)
				proof := globalFunctionCorrespondence{antecedent: bound.ChildEntry.EntryPredicate}
				for i, input := range r.inputs {
					if input.index != i || input.source.Sort() != p.inputs[i].source.Sort() || input.native.Sort() != p.inputs[i].native.Sort() {
						t.Fatal("input identity, type or width changed")
					}
					if p.inputs[i].source.Sort() == br.Bits(64) {
						expected, _ := builder.Const(br.Bits(64), 99)
						if err := proof.equal(t.Context(), input.source, expected); err != nil {
							t.Fatal("specialized integer is not the current wrapper value", err)
						}
					} else {
						global, ok := p.inputs[i].location.object.site.(*ssa.Global)
						if !ok || global.Name() != "B" && global.Name() != "C" {
							t.Fatal("Boolean oracle lost the fixture's original input identity")
						}
						for _, rbx := range []uint64{0, 1, 256, 1 << 63, ^uint64(0)} {
							// Expectations follow the encoded wrapper's original RBX
							// input and source global identities, not adapter byte maps.
							want := uint64(1)
							if global.Name() == "B" && (boolean == "zero" || boolean == "symbolic" && rbx == 0) {
								want = 0
							}
							got, err := br.Eval(t.Context(), input.source, []br.Assignment{{Variable: entered.InitialRegisters[nativeproof.RBX], Value: rbx}}, br.Limits{})
							if err != nil || got != want {
								t.Fatalf("Boolean %s at original RBX=%#x: got=%d want=%d: %v", global.Name(), rbx, got, want, err)
							}
						}
					}
				}
				if local == "eliminated" {
					requireScopedStorageModel(t, p)
					if len(p.representation.bindings) != 3 {
						t.Fatal("eliminated float local acquired an address")
					}
				}
				if local == "materialized" {
					footprint, ok := p.layout.objectFootprint(storageFunctionLocal(t, p.source))
					if !ok || footprint.Bytes != storageTestExtent(t, p.layout.geometry, nativeproof.StackOffset(-16), 8) {
						t.Fatal("body-local layout was replaced by root coordinates")
					}
					mapped, err := bound.Geometry.ResolveExtent(t.Context(), footprint.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					actual, err := storageNativeWord(t.Context(), builder, bound.Successor.Memory, mapped, 8)
					if err != nil {
						t.Fatal(err)
					}
					expected, _ := builder.Const(br.Bits(64), 13)
					if err := proof.equal(t.Context(), actual, expected); err != nil {
						t.Fatal("retained materialized local lost its translated residual bytes", err)
					}
				}
				original, _ := p.native.Bound()
				terminal := original.Instructions[len(original.Instructions)-1].ID
				var current nativeproof.TransitionOccurrenceID
				for _, occurrence := range bound.Occurrences {
					if occurrence.Input == terminal {
						current = occurrence.Current
					}
				}
				found := false
				for _, instruction := range bound.Successor.Instructions {
					if instruction.ID == current && instruction.Span == original.Instructions[len(original.Instructions)-1].Span {
						found = true
					}
				}
				if !found || current == 0 {
					t.Fatal("terminal RET lost its actual occurrence association")
				}
			})
		}
	}
}

func TestRootedGlobalApplicationOwnersAndBounds(t *testing.T) {
	plain := newRootedGlobalFixture(t, "one", "none")
	plainCopy := *plain.p
	if plain.p.storageModel != nil {
		t.Fatal("non-floating owner control unexpectedly has a model discharge")
	}
	if r, err := checkRootedGlobalApplication(t.Context(), &plainCopy, plain.application(t)); r != nil || err == nil {
		t.Fatal("copied non-floating account borrowed completion ownership")
	}
	f := newRootedGlobalFixture(t, "one", "eliminated")
	a := f.application(t)
	copyAccount := *f.p
	for _, p := range []*globalFunctionCorrespondence{nil, {}, &copyAccount, {rules: globalFunctionRules, source: f.p.source, native: f.p.native, layout: f.p.layout, representation: f.p.representation}} {
		if r, err := checkRootedGlobalApplication(t.Context(), p, a); r != nil || err == nil {
			t.Fatal("missing or copied completion acquired rooted authority")
		}
	}
	if r, err := checkRootedGlobalApplication(t.Context(), f.p, nativeproof.TransitionCallCertificate{}); r != nil || err == nil {
		t.Fatal("zero native application accepted")
	}
	other := newRootedGlobalFixture(t, "one", "eliminated")
	if r, err := checkRootedGlobalApplication(t.Context(), f.p, other.application(t)); r != nil || err == nil {
		t.Fatal("equal bytes and a different theorem owner accepted")
	}
	// Independent completion under the very same image and interface still is
	// another theorem, not the exact certificate retained by the correspondence.
	prefix, _ := f.p.native.Prefix()
	otherReturn, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	otherApplication, err := nativeproof.CheckTransitionActiveReturn(t.Context(), f.entered, otherReturn)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := checkRootedGlobalApplication(t.Context(), f.p, otherApplication); r != nil || err == nil {
		t.Fatal("same-image independently completed theorem borrowed identity")
	}
	argument := newRootedGlobalFixture(t, "one", "argument")
	if r, err := checkRootedGlobalApplication(t.Context(), argument.p, argument.application(t)); r != nil || err == nil || !strings.Contains(err.Error(), "zero-argument") {
		t.Fatalf("unsupported argument specialization admitted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r, err := checkRootedGlobalApplication(ctx, f.p, a); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled application: %v", err)
	}
	good, err := checkRootedGlobalApplication(t.Context(), f.p, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, budget := range []int{0, 1, good.work - 1, 20_000_001} {
		if r, err := checkRootedGlobalApplication(t.Context(), f.p, a, globalCorrespondenceLimits{work: budget}); r != nil || err == nil {
			t.Fatalf("budget %d accepted", budget)
		}
	}
	if r, err := checkRootedGlobalApplication(t.Context(), f.p, a, globalCorrespondenceLimits{work: good.work}); r == nil || err != nil {
		t.Fatalf("exact cumulative budget refused: %v", err)
	}
	for _, at := range []int{good.work / 2, good.work} {
		ctx := &rootedGlobalCancelContext{Context: t.Context(), at: at}
		if r, err := checkRootedGlobalApplication(ctx, f.p, a); r != nil || !errors.Is(err, context.Canceled) || ctx.calls != at {
			t.Fatalf("cancellation at work %d (including final publication): %v", at, err)
		}
	}
	if r, err := checkRootedGlobalApplication(t.Context(), f.p, a, globalCorrespondenceLimits{work: good.work}, globalCorrespondenceLimits{work: good.work}); r != nil || err == nil {
		t.Fatal("multiple outer budgets accepted")
	}
}

type rootedGlobalCancelContext struct {
	context.Context
	at, calls int
}

func (c *rootedGlobalCancelContext) Err() error {
	c.calls++
	if c.calls >= c.at {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestRootedGlobalApplicationNeedsRootAndCurrentLifetime(t *testing.T) {
	f := newRootedGlobalFixture(t, "one", "materialized")
	native, _ := f.p.native.Bound()
	proposal, err := nativeproof.ProposeTransition(t.Context(), f.image, native.Prefix.Entry, nativeproof.TransitionLimits{}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"conditional", "no-lifetime", "expired"} {
		t.Run(variant, func(t *testing.T) {
			face := f.face
			var entered nativeproof.TransitionCertificate
			if variant == "conditional" {
				face.Initialization = nativeproof.ImageInitialization{}
				face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: face.PrivateFrame.Bytes}
				face.ReturnContext = &nativeproof.TransitionReturnContext{Target: f.root}
				entered, err = nativeproof.CheckRegionTransition(t.Context(), f.image, f.root, face, proposal, nativeproof.TransitionLimits{})
			} else {
				face.PrivateFrame = nil
				if variant == "expired" {
					until := native.Prefix.Entry
					face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: f.face.PrivateFrame.Bytes, Until: &until}
				}
				entered, err = nativeproof.CheckTransition(t.Context(), f.image, face, proposal, nativeproof.TransitionLimits{})
			}
			if err != nil {
				t.Fatal("negative control lacks valid native prefix", err)
			}
			a, err := nativeproof.CheckTransitionActiveReturn(t.Context(), entered, f.p.native)
			if variant != "conditional" {
				var refusal *nativeproof.Refusal
				if _, ok := a.Bound(); ok || !errors.As(err, &refusal) || refusal.Premise != "transition-application-private" {
					t.Fatalf("current lifetime failure not refused by native application: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r, err := checkRootedGlobalApplication(t.Context(), f.p, a); r != nil || err == nil || !strings.Contains(err.Error(), "rooted application") {
				t.Fatalf("conditional application acquired rooted authority: %v", err)
			}
		})
	}
}

func TestRootedGlobalWordBoundedGrammar(t *testing.T) {
	b := br.NewBuilder(64)
	scope := br.NewScope()
	lo, _ := b.Input(br.Bits(8), scope, 0)
	hi, _ := b.Input(br.Bits(8), scope, 1)
	word, _ := b.Make(br.Concat, br.Bits(16), 0, lo, hi)
	lowCurrent, _ := b.Const(br.Bits(8), 0x12)
	highCurrent, _ := b.Const(br.Bits(8), 0x34)
	bytes := map[br.Term]br.Term{lo: lowCurrent, hi: highCurrent}
	actual, err := rootedGlobalWord(t.Context(), b, word, bytes)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := b.Const(br.Bits(16), 0x3412)
	if _, err := br.Prove(t.Context(), actual, expected, br.Limits{}); err != nil {
		t.Fatal("byte association order changed", err)
	}
	wide, _ := b.Input(br.Bits(16), scope, 2)
	constant, _ := b.Const(br.Bits(16), 3)
	computed, _ := b.Make(br.BitXor, br.Bits(16), 0, word, constant)
	for i, original := range []br.Term{{}, wide, constant, computed} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if term, err := rootedGlobalWord(t.Context(), b, original, bytes); term.Valid() || err == nil {
				t.Fatal("general expression evaluator admitted")
			}
		})
	}
	delete(bytes, hi)
	if term, err := rootedGlobalWord(t.Context(), b, word, bytes); term.Valid() || err == nil {
		t.Fatal("missing actual byte supplied by initialization or a fresh variable")
	}
}
