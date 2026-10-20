package closure

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

type globalCallFixture struct {
	source    computationSource
	completed *sourceReturnCompletion
	prefixes  []*sourceOperandPrefix
	native    globalNativeFixture
	call      nativeproof.TransitionCallCertificate
	tail      nativeproof.TransitionProposal
	rho       storageRepresentation
}

// Both computations are checked from their own transfers. The synthetic encoding
// describes data effects, an actual child control slot, residual private scratch,
// and a later use of the parent's local; no expected endpoint is proof input.
func globalCallCompositionFixture(t testing.TB, variant string) globalCallFixture {
	t.Helper()
	body, second, before := "A=11", "", ""
	if variant == "zero" {
		body = ""
	}
	if variant == "nested" {
		body = `if Read(&A)!=7 { panic("child read") }; A=11`
	}
	if variant == "two" {
		second = "Child();"
	}
	if variant == "retry" {
		before = `if Read(&x)!=0 { panic("first") }; x=0; if Read(&x)!=0 { panic("second") };`
	}
	source := relationFixture(t, fmt.Sprintf(`var A,B uint64
func Read(p *uint64) uint64 { return *p }
func Child() { %s }
func F() { var x uint64; A=7; B=9; %s Child(); %s B=Read(&x) }
`, body, before, second), 64)
	root := source.prog.Roots["F"]
	var calls []*ssa.Call
	var ret *ssa.Return
	var local *ssa.Alloc
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			switch x := instruction.(type) {
			case *ssa.Call:
				if x.Call.StaticCallee() == root.Pkg.Func("Child") {
					calls = append(calls, x)
				}
			case *ssa.Return:
				ret = x
			case *ssa.Alloc:
				local = x
			}
		}
	}
	var prefixes []*sourceOperandPrefix
	for _, call := range calls {
		var prefix *sourceOperandPrefix
		var err error
		if len(prefixes) == 0 {
			prefix, err = checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
		} else {
			prefix, err = checkSourceOperandContinuation(t.Context(), prefixes[len(prefixes)-1], call, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 || local == nil || ret == nil {
		t.Fatal("missing source fixture occurrences")
	}
	completed, err := checkSourceReturnContinuation(t.Context(), prefixes[len(prefixes)-1], ret, nil)
	if err != nil {
		t.Fatal(err)
	}
	const base, data, child = uint64(0x401000), uint64(0x700000), uint64(0x401200)
	addresses := [2]uint64{data + 8, data + 80}
	f := globalNativeImage(t, addresses, [3]uint64{}, addresses[0], data, nil, "")
	code := []byte{0xc3, 0x48, 0x83, 0xec, 0x20} // SUB RSP,32
	pc := func() uint64 { return base + uint64(len(code)) }
	mov := func(value uint64) {
		code = append(code, 0x48, 0xb8)
		code = binary.LittleEndian.AppendUint64(code, value)
	}
	store := func(address uint64) {
		at := pc()
		code = append(code, 0x48, 0x89, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(address)-int64(at+7)))
	}
	if variant == "early" {
		code = append(code, 0x48, 0x8b, 0x44, 0x24, 0x10)
	}
	if variant != "eliminated" && variant != "retry" {
		mov(0)
		code = append(code, 0x48, 0x89, 0x44, 0x24, 0x10) // local at origin-16
	}
	mov(7)
	store(addresses[0])
	mov(9)
	store(addresses[1])
	if variant == "retry" {
		mov(0)
		code = append(code, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0x8b, 0x44, 0x24, 0x10)
	}
	if variant == "swap" {
		mov(11)
		store(addresses[0])
	}
	var callPC uint64
	for range len(calls) {
		callPC = pc()
		code = append(code, 0xe8)
		code = binary.LittleEndian.AppendUint32(code, uint32(child-callPC-5))
	}
	code = append(code, 0x48, 0x8b, 0x4c, 0x24, 0xf0) // residual child scratch -> RCX
	if variant == "eliminated" {
		mov(0)
	} else {
		code = append(code, 0x48, 0x8b, 0x44, 0x24, 0x10) // actual later local use
	}
	store(addresses[1])
	code = append(code, 0x48, 0x83, 0xc4, 0x20) // ADD RSP,32
	parentRET := pc()
	code = append(code, 0xc3)
	for pc() < child {
		code = append(code, 0x90)
	}
	mov(42)
	code = append(code, 0x48, 0x89, 0x44, 0x24, 0xf8) // child private scratch
	if variant == "corrupt" {
		mov(0)
		code = append(code, 0x48, 0x89, 0x44, 0x24, 0x18) // same-value parent-local write
	}
	if variant == "nested" {
		at := pc()
		code = append(code, 0x48, 0x8b, 0x05)
		code = binary.LittleEndian.AppendUint32(code, uint32(int64(addresses[0])-int64(at+7)))
	}
	if variant != "zero" && variant != "swap" {
		mov(11)
		store(addresses[0])
	}
	if variant == "direction" {
		code = append(code, 0xfc) // The native child may clear DF; the source cannot.
	}
	childRET := pc()
	code = append(code, 0xc3)
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face.Envelope = nativeproof.RelativeSpan{Start: -64, End: 8}
	f.face.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true}}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -64, End: 0}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: base}
	childFace := f.face
	childFace.Origin.Min -= 40
	childFace.Origin.Max -= 40
	childFace.Origin.Residue = 8
	childFace.Envelope = nativeproof.RelativeSpan{Start: -16, End: 32}
	childFace.Regions = []nativeproof.RelativeRegion{{Bytes: nativeproof.RelativeSpan{Start: -16, End: 0}, Readable: true, Writable: true}, {Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true}, {Bytes: nativeproof.RelativeSpan{Start: 8, End: 32}, Readable: true, Writable: true}}
	childFace.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -16, End: 0}}
	childFace.ReturnContext = &nativeproof.TransitionReturnContext{Target: callPC + 5}
	decode := globalCandidateDecoder(t, f.raw)
	var expansions []nativeproof.TransitionExpansion
	for at := f.entry; at < childRET; {
		instruction := decode(at)
		if nativeproof.TransitionExpansionRequired(instruction) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(instruction.Len)
	}
	check := func(entry, cut uint64, face nativeproof.TransitionInterface) nativeproof.TransitionCertificate {
		var choices []nativeproof.TransitionExpansion
		for _, e := range expansions {
			if e.PC >= entry && e.PC < cut || entry == f.entry && e.PC >= child && variant == "two" {
				choices = append(choices, e)
			}
		}
		proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, entry, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: choices})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := nativeproof.CheckRegionTransition(t.Context(), f.image, entry, face, proposal, nativeproof.TransitionLimits{})
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	parent := check(f.entry, callPC, f.face)
	callee, err := nativeproof.CheckTransitionReturn(t.Context(), check(child, childRET, childFace))
	if err != nil {
		t.Fatal(err)
	}
	application, err := nativeproof.CheckTransitionCallReturn(t.Context(), parent, callee)
	if err != nil {
		t.Fatal(err)
	}
	successor, _ := application.Successor()
	var tailChoices []nativeproof.TransitionExpansion
	for _, e := range expansions {
		if e.PC > callPC && e.PC < parentRET {
			tailChoices = append(tailChoices, e)
		}
	}
	tail, err := nativeproof.ProposeTransitionContinuation(t.Context(), successor, parentRET, nativeproof.TransitionOptions{Expansions: tailChoices})
	if err != nil {
		t.Fatal(err)
	}
	globals := [2]*ssa.Global{root.Pkg.Members["A"].(*ssa.Global), root.Pkg.Members["B"].(*ssa.Global)}
	rho := globalRho(source, f, globals, addresses)
	for object := range prefixes[0].region.packet.observations[0].state.memory {
		if object.site == local {
			rho.bindings = append(rho.bindings, storageBinding{object: object, base: nativeproof.TransitionLocation{Offset: -16}})
		}
	}
	if len(rho.bindings) != 3 {
		t.Fatal("missing actual parent allocation")
	}
	return globalCallFixture{source, completed, prefixes, f, application, tail, rho}
}

func (f globalCallFixture) check(ctx context.Context, options ...globalCorrespondenceLimits) (*globalFunctionCorrespondence, error) {
	return checkGlobalFunctionCallComposition(ctx, f.source, f.source.prog.Roots["F"], f.native.image, f.completed, f.prefixes[len(f.prefixes)-1], f.call, f.tail, f.rho, options...)
}

func TestGlobalCallCompositionActualCurrentState(t *testing.T) {
	for _, variant := range []string{"ordinary", "zero", "nested", "two", "eliminated", "retry", "swap", "early", "corrupt", "direction"} {
		t.Run(variant, func(t *testing.T) {
			f := globalCallCompositionFixture(t, variant)
			p, err := f.check(t.Context())
			if variant == "swap" || variant == "early" || variant == "corrupt" || variant == "direction" {
				if err == nil || p != nil {
					t.Fatalf("unaccounted call effect accepted: %s", variant)
				}
				if variant == "direction" && !strings.Contains(err.Error(), "source correspondence direction was not preserved") {
					t.Fatalf("child direction change failed for another reason: %v", err)
				}
				if variant == "swap" {
					// The unconstrained full effect relation is valid: only actual-call
					// association distinguishes moving this effect before the child.
					successor, _ := f.call.Successor()
					prefix, e := nativeproof.CheckTransitionContinuation(t.Context(), successor, f.tail)
					if e != nil {
						t.Fatal(e)
					}
					completed, e := nativeproof.CheckTransitionReturn(t.Context(), prefix)
					if e != nil {
						t.Fatal(e)
					}
					if _, e := checkGlobalFunctionCorrespondence(t.Context(), f.source, f.source.prog.Roots["F"], f.native.image, f.native.entry, f.completed, completed, f.rho, nil); e != nil {
						t.Fatalf("cross-boundary control lacks otherwise valid full relation: %v", e)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, ok := p.native.BoundFor(f.native.image)
			if !ok || !b.State.CalleeTerminated || p.call == nil || p.call.prefix != f.prefixes[len(f.prefixes)-1] || p.call.application.proof.caller != p.call.prefix.cursor || p.call.application.proof.at != p.call.prefix.call || p.call.sourceUsage.work <= f.completed.region.packet.usage.work || p.work == 0 {
				t.Fatal("lost actual call, completed return or cumulative work")
			}
			builder := br.NewBuilder(128)
			residual, e := storageNativeWord(t.Context(), builder, b.State.Memory, nativeproof.TransitionLocation{Offset: -48}, 8)
			if e != nil {
				t.Fatal(e)
			}
			want, e := builder.Const(br.Bits(64), 42)
			if e != nil {
				t.Fatal(e)
			}
			for _, actual := range []br.Term{residual, b.State.Registers[nativeproof.RCX].Value} {
				if _, e := br.Prove(t.Context(), actual, want, br.Limits{}); e != nil {
					t.Fatalf("actual child scratch or later dependent read was lost: %v", e)
				}
			}
			if variant == "nested" && f.completed.region.packet.trace.calls[0].proof == p.call.application.proof {
				t.Fatal("fixture did not exercise postorder nested application selection")
			}
			if variant == "eliminated" && len(p.materialized) != 0 {
				t.Fatal("logical local initialization invented native materialization")
			}
			if variant == "two" {
				wrong := f
				wrong.prefixes = f.prefixes[:1]
				if bad, e := wrong.check(t.Context()); bad != nil || e == nil {
					t.Fatal("first source invocation borrowed second native application")
				}
			}
		})
	}
}

func TestGlobalCallCompositionOwnershipAndBounds(t *testing.T) {
	f := globalCallCompositionFixture(t, "ordinary")
	positive, err := f.check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, work := range []int{0, 1, positive.work - 1} {
		if p, err := f.check(t.Context(), globalCorrespondenceLimits{work: work}); p != nil || err == nil {
			t.Fatalf("budget %d accepted", work)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := f.check(ctx); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	foreignPrefix := globalPrefix(t, f.source, f.prefixes[0].call)
	foreignImage, err := nativeproof.NewImage(t.Context(), f.native.raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"prefix", "image", "rho-image", "application", "tail", "control-slot"} {
		t.Run(variant, func(t *testing.T) {
			bad := f
			bad.rho.bindings = slices.Clone(f.rho.bindings)
			switch variant {
			case "prefix":
				bad.prefixes = []*sourceOperandPrefix{foreignPrefix}
			case "image":
				bad.native.image = foreignImage
			case "rho-image":
				bad.rho.image = foreignImage
			case "application":
				bad.call = nativeproof.TransitionCallCertificate{}
			case "tail":
				bad.tail.Nodes = nil
			case "control-slot":
				bad.rho.bindings[2].base.Offset = -40
			}
			if p, err := bad.check(t.Context()); p != nil || err == nil {
				t.Fatalf("foreign/incomplete %s accepted", variant)
			}
		})
	}
	// Altering an internal retained application is an adversarial injection, not a
	// public capability. Restore each mutation so the same owned fixture stays usable.
	actual := positive.call.application.proof
	for _, variant := range []string{"target", "invocation", "model", "selection", "heap", "heap-local"} {
		t.Run(variant, func(t *testing.T) {
			old := *actual
			t.Cleanup(func() { *actual = old })
			switch variant {
			case "target":
				actual.target = f.source.prog.Roots["F"].Pkg.Func("Read")
			case "invocation":
				actual.invocation.path += "/foreign"
			case "model":
				actual.storageModel = regionStorageModel{}
			case "selection":
				actual.selection = nil
			case "heap":
				actual.initial = regionState{}
			case "heap-local":
				// Keep the globals that native checkpoint comparison observes,
				// but omit an untouched parent local from the child's input heap.
				// Complete source-state inclusion must reject this independently.
				actual.initial.memory = maps.Clone(actual.initial.memory)
				delete(actual.initial.memory, f.rho.bindings[2].object)
			}
			if p, err := f.check(t.Context()); p != nil || err == nil {
				t.Fatalf("changed actual source %s accepted", variant)
			} else if variant == "heap-local" && !strings.Contains(err.Error(), "initial heap differs from current caller") {
				t.Fatalf("missing local refused outside current-state inclusion: %v", err)
			}
		})
	}
	if _, err := f.check(t.Context()); err != nil {
		t.Fatalf("failed attempts damaged reusable input: %v", err)
	}
}

type globalCallCaptureContext struct {
	context.Context
	once func()
}

func (c *globalCallCaptureContext) Err() error {
	if c.once != nil {
		f := c.once
		c.once = nil
		f()
	}
	return c.Context.Err()
}

func TestGlobalCallCompositionCaptureBeforeCallbacks(t *testing.T) {
	f := globalCallCompositionFixture(t, "ordinary")
	// Deliberately mutate nested proposal storage at the first callback. Native
	// capture must already own it, and closure must already own the representation.
	ctx := &globalCallCaptureContext{Context: t.Context(), once: func() {
		f.tail.Nodes[0].PC++
		if len(f.tail.Nodes[0].Successors) != 0 {
			f.tail.Nodes[0].Successors[0]++
		}
		f.rho.bindings[0].base.Offset++
	}}
	p, err := f.check(ctx)
	if err != nil || p == nil {
		t.Fatalf("caller mutation crossed the capture boundary: %v", err)
	}
	if p.representation.bindings[0].base.Offset == f.rho.bindings[0].base.Offset {
		t.Fatal("representation retained caller-owned container")
	}
	if _, err := f.check(t.Context()); err == nil || !strings.Contains(err.Error(), "transition") {
		t.Fatalf("modified tail unexpectedly remained a valid proposal: %v", err)
	}
}

type globalCallCancellationContext struct {
	context.Context
	calls, stop int
}

func (c *globalCallCancellationContext) Err() error {
	c.calls++
	if c.stop != 0 && c.calls >= c.stop {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestGlobalCallCompositionFinalCancellation(t *testing.T) {
	f := globalCallCompositionFixture(t, "ordinary")
	count := &globalCallCancellationContext{Context: t.Context()}
	proof, err := f.check(count)
	if err != nil || proof == nil {
		t.Fatal(err)
	}
	if count.calls != proof.work {
		t.Fatal("native construction or correspondence escaped the single work account")
	}
	stop := &globalCallCancellationContext{Context: t.Context(), stop: count.calls}
	if proof, err := f.check(stop); proof != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation at completed-relation publication: %v", err)
	}
	if _, err := f.check(t.Context()); err != nil {
		t.Fatalf("final cancellation damaged retained source/native evidence: %v", err)
	}
}

func TestGlobalCallCompositionFailedSearchBudget(t *testing.T) {
	f := globalCallCompositionFixture(t, "retry")
	complete, err := f.check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := complete.native.Bound()
	view := bound.Prefix
	view.Accesses, view.Instructions, view.Memory = bound.Accesses, bound.Instructions, bound.State.Memory
	var observable []int
	for i := range view.Accesses {
		if !slices.Contains(complete.administrative, i) && !slices.Contains(complete.inactive, i) {
			observable = append(observable, i)
		}
	}
	account := func() *globalFunctionCorrespondence {
		return &globalFunctionCorrespondence{representation: complete.representation, layout: complete.layout, antecedent: complete.antecedent, inputs: complete.inputs, accesses: complete.accesses, traces: complete.traces, call: complete.call}
	}
	first := account()
	firstMeter := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
	plan := storageReadPlan{preferRetain: true, bound: len(first.accesses)}
	if err := first.matchStorageEffectAttempt(firstMeter, view.Accesses, view.InitialMemory, observable, nil, nil, &plan); !storageEffectRetryable(err) || len(plan.path) == 0 {
		t.Fatalf("actual-call fixture did not require alignment retry: %v", err)
	}
	p := account()
	full := &correspondenceContext{Context: t.Context(), limit: 2_000_000}
	if err := p.searchStorageEffects(full, view.Accesses, view.InitialMemory, observable, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if full.work <= firstMeter.work || len(p.materialized) != 0 || len(p.eliminated) == 0 {
		t.Fatal("failed initialization/read alignment was not discarded with its work retained")
	}
	limited := &correspondenceContext{Context: t.Context(), limit: full.work - 1}
	p = account()
	if err := p.searchStorageEffects(limited, view.Accesses, view.InitialMemory, observable, nil, nil, true); err == nil || storageEffectRetryable(err) || limited.work != limited.limit || len(p.matched) != 0 || len(p.equalities) != 0 {
		t.Fatalf("failed search reset budget or published tentative call account: %v", err)
	}
	stop := &storageSearchWorkContext{Context: t.Context(), cancelAt: full.work - 1}
	cancelled := &correspondenceContext{Context: stop, limit: 2_000_000}
	stop.account = cancelled
	if err := p.searchStorageEffects(cancelled, view.Accesses, view.InitialMemory, observable, nil, nil, true); !errors.Is(err, context.Canceled) || len(p.matched) != 0 || len(p.equalities) != 0 {
		t.Fatalf("cancelled search published tentative call account: %v", err)
	}
}
