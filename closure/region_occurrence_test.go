package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func occurrenceFixture(t testing.TB, text string, arguments ...int64) regionInput {
	t.Helper()
	source := relationFixture(t, text, 64)
	root := source.prog.Roots["F"]
	in := regionInput{owner: root.Prog, selection: source.prog, root: root, entry: regionPoint{root.Blocks[0], 0}, premises: []string{"exact input; isolated language execution; native applicability open"}, initial: regionState{values: map[ssa.Value]regionValue{}}}
	if len(arguments) != len(root.Params) {
		t.Fatal("fixture argument count")
	}
	for i, parameter := range root.Params {
		in.initial.values[parameter] = regionValue{typ: parameter.Type(), kind: regionConstant, scalar: constant.MakeInt64(arguments[i])}
	}
	return in
}

func occurrenceKernel(t testing.TB, ctx context.Context, in regionInput, owner *regionOccurrenceOwner, limits regionLimits) *regionKernel {
	t.Helper()
	k, err := newRegionContextKernel(in, newRegionCallSession(ctx, in, limits), regionInvocation{}, true)
	if err != nil {
		t.Fatal(err)
	}
	k.trace = &regionEffectTrace{owner: owner, seen: map[regionEffectOccurrence]bool{}}
	return k
}

func occurrenceProposal(t testing.TB, in regionInput) (*regionProposal, *regionOccurrenceOwner) {
	t.Helper()
	owner := &regionOccurrenceOwner{}
	p, err := proposeRegionKernel(occurrenceKernel(t, t.Context(), in, owner, defaultRegionLimits()))
	if err != nil {
		t.Fatal(err)
	}
	return p, owner
}

func occurrenceCheck(t testing.TB, in regionInput, p *regionProposal, owner *regionOccurrenceOwner) (*checkedRegion, *regionKernel, error) {
	t.Helper()
	in, p, err := regionCapture(in, p, defaultRegionLimits())
	if err != nil {
		return nil, nil, err
	}
	k := occurrenceKernel(t, t.Context(), in, owner, defaultRegionLimits())
	packet, err := checkRegionKernel(k, p)
	return packet, k, err
}

func TestRegionOccurrenceFiniteFamilies(t *testing.T) {
	for _, x := range []int64{-7, 0, 1, 2, 3, 7, 16, 33, 257, 2048} {
		t.Run(fmt.Sprint(x), func(t *testing.T) {
			in := occurrenceFixture(t, `func F(x int32)int32{s:=uint(0);for 1<<s<x{s++};return 1<<s}`, x)
			p, owner := occurrenceProposal(t, in)
			packet, k, err := occurrenceCheck(t, in, p, owner)
			if err != nil {
				t.Fatal(err)
			}
			// An ordinary Go loop is an independent oracle for this finite family.
			want, increments := int32(1), 0
			for want < int32(x) {
				want <<= 1
				increments++
			}
			got, exact := regionInt(packet.observations[0].value)
			if !exact || got != int64(want) {
				t.Fatalf("result %d/%v, want %d", got, exact, want)
			}
			conditions := 0
			seen := map[regionEffectOccurrence]bool{}
			for i, event := range packet.trace.instructions {
				if event.owner != owner || event.ordinal != uint64(i) || seen[event] || !packet.trace.seen[event] {
					t.Fatal("execution did not derive distinct ordered owned occurrences")
				}
				seen[event] = true
				if _, ok := event.instruction.(*ssa.If); ok {
					conditions++
				}
			}
			if conditions != increments+1 || len(packet.trace.excluded) != conditions {
				t.Fatalf("conditions/exclusions %d/%d, want %d", conditions, len(packet.trace.excluded), increments+1)
			}
			for _, exclusion := range packet.trace.excluded {
				if !seen[exclusion.regionEffectOccurrence] || exclusion.instruction != exclusion.branch {
					t.Fatal("exclusion lacks its exact checked branch occurrence")
				}
			}
			maxUnion := 0
			for _, entries := range k.boundaries {
				maxUnion = max(maxUnion, len(entries))
			}
			if maxUnion != increments+1 {
				t.Fatalf("boundary union lost occurrence entries: %d", maxUnion)
			}
			last := packet.trace.instructions[len(packet.trace.instructions)-1]
			if packet.observations[0].occurrence != last {
				t.Fatal("return observation does not identify its executed occurrence")
			}
		})
	}
}

func TestRegionOccurrenceSimultaneousPhiCorrelation(t *testing.T) {
	for _, n := range []int64{0, 1, 2, 5, 8} {
		in := occurrenceFixture(t, `func F(n uint32)(uint32,uint32){a,b:=uint32(3),uint32(9);for i:=uint32(0);i<n;i++{a,b=b,a};return a,b}`, n)
		p, owner := occurrenceProposal(t, in)
		packet, k, err := occurrenceCheck(t, in, p, owner)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint64{3, 9}
		if n%2 != 0 {
			want[0], want[1] = want[1], want[0]
		}
		for i, value := range packet.observations[0].value.elements {
			localEffectInteger(t, value, want[i])
		}
		if len(packet.observations[0].value.elements) != 2 {
			t.Fatal("tuple relation missing")
		}
		correlated := false
		for at, states := range k.boundaries {
			var pair []*ssa.Phi
			for _, instruction := range at.block.Instrs {
				if phi, ok := instruction.(*ssa.Phi); ok && (phi.Comment == "a" || phi.Comment == "b") {
					pair = append(pair, phi)
				}
			}
			if len(pair) == 2 {
				correlated = true
				for _, state := range states {
					a, _ := regionInt(state.values[pair[0]])
					b, _ := regionInt(state.values[pair[1]])
					if a+b != 12 || a == b {
						t.Fatal("static boundary union invented an uncorrelated phi pair")
					}
				}
			}
		}
		if !correlated {
			t.Fatal("fixture failed to retain the simultaneous phi boundary")
		}
	}
}

func TestRegionOccurrenceProofCorruption(t *testing.T) {
	in := occurrenceFixture(t, `func F(n uint32)uint32{a,b:=uint32(3),uint32(9);for i:=uint32(0);i<n;i++{a,b=b,a};return a}`, 3)
	p, owner := occurrenceProposal(t, in)
	branch := -1
	for i, node := range p.occurrences.nodes {
		if len(node.slots) == 2 {
			branch = i
			break
		}
	}
	if branch < 0 {
		t.Fatal("fixture has no branch")
	}
	for name, corrupt := range map[string]func(*regionProposal){
		"missing-slot": func(p *regionProposal) { p.occurrences.nodes[branch].slots = p.occurrences.nodes[branch].slots[:1] },
		"extra-slot": func(p *regionProposal) {
			p.occurrences.nodes[branch].slots = append(p.occurrences.nodes[branch].slots, regionOccurrenceFalse)
		},
		"wrong-slots": func(p *regionProposal) { slices.Reverse(p.occurrences.nodes[branch].slots) },
		"false-active-edge": func(p *regionProposal) {
			p.occurrences.nodes[branch].slots = []regionOccurrenceSlot{regionOccurrenceFalse, regionOccurrenceFalse}
		},
		"truncation": func(p *regionProposal) { p.occurrences.nodes = p.occurrences.nodes[:branch+1] },
		"extra-node": func(p *regionProposal) { p.occurrences.nodes = append(p.occurrences.nodes, p.occurrences.nodes[0]) },
		"residual": func(p *regionProposal) {
			p.occurrences.nodes[len(p.occurrences.nodes)-1].end = regionOccurrenceResidual
		},
		"wrong-successor": func(p *regionProposal) { p.occurrences.nodes[branch+1].at = p.occurrences.nodes[0].at },
		"widen-entry":     func(p *regionProposal) { p.occurrences.nodes[branch+1].entry = regionState{} },
		"phi-value": func(p *regionProposal) {
			for i := range p.occurrences.nodes {
				for value, current := range p.occurrences.nodes[i].entry.values {
					if _, ok := value.(*ssa.Phi); ok {
						current.scalar = constant.MakeInt64(77)
						p.occurrences.nodes[i].entry.values[value] = current
						return
					}
				}
			}
		},
		"mixed-arms":        func(p *regionProposal) { p.entries = map[*ssa.BasicBlock][]regionState{} },
		"missing-arm":       func(p *regionProposal) { p.occurrences = nil },
		"foreign-selection": func(p *regionProposal) { copy := *p.input.selection; p.input.selection = &copy },
	} {
		t.Run(name, func(t *testing.T) {
			_, copy, err := regionCapture(in, p, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			corrupt(copy)
			if packet, _, err := occurrenceCheck(t, in, copy, owner); err == nil || packet != nil {
				t.Fatal("corrupt occurrence proof accepted")
			}
		})
	}
	if packet, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil || packet != nil {
		t.Fatal("finite proof accepted by nonfinite arm")
	}
}

func TestRegionOccurrenceRefusalAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		args       []int64
		cause      string
	}{
		{"unbounded-roundlike", `func F(x int32)int32{s:=uint(0);for 1<<s<x{s++};return 1<<s}`, []int64{1<<30 + 1}, "budget"},
		{"negative-shift", `func F(n int32)int32{return 1<<n}`, []int64{-1}, "shift"},
		{"unknown-branch", `var b bool;func F()uint32{for b{};return 1}`, nil, "unresolved branch"},
		{"recurrent-call", `func g(){};func F()uint32{for i:=uint32(0);i<2;i++{g()};return 1}`, nil, "recurrent call"},
		{"recurrent-allocation", `var P *uint32;func F()uint32{for i:=uint32(0);i<2;i++{P=new(uint32)};return 1}`, nil, "fresh singleton"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := occurrenceFixture(t, tc.body, tc.args...)
			k := occurrenceKernel(t, t.Context(), in, &regionOccurrenceOwner{}, defaultRegionLimits())
			if p, err := proposeRegionKernel(k); err == nil || p != nil || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("wrong refusal: %v", err)
			}
		})
	}
	in := occurrenceFixture(t, `func F(n uint32)uint32{for i:=uint32(0);i<n;i++{};return n}`, 4)
	p, owner := occurrenceProposal(t, in)
	ctx, cancel := context.WithCancel(t.Context())
	k := occurrenceKernel(t, ctx, in, owner, defaultRegionLimits())
	cancel()
	if _, err := checkRegionKernel(k, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled check: %v", err)
	}
	for _, dimension := range []string{"nodes", "states", "work", "locations"} {
		t.Run(dimension, func(t *testing.T) {
			k := occurrenceKernel(t, t.Context(), in, owner, defaultRegionLimits())
			switch dimension {
			case "nodes":
				k.meter.nodes = k.meter.limits.nodes
			case "states":
				k.meter.states = k.meter.limits.states
			case "work":
				k.meter.work = k.meter.limits.work
			case "locations":
				k.meter.locations = k.meter.limits.locations
			}
			// The copy and discovery phases share the same cumulative allowance.
			if _, _, err := regionCaptureMeter(in, p, k.meter); err == nil {
				t.Fatal("exhausted cumulative budget accepted")
			}
		})
	}
}

func TestRegionOccurrenceNestedCallAndContinuation(t *testing.T) {
	source := relationFixture(t, `var G uint32;func Stop(uint32){};func round(n uint32)uint32{v:=uint32(1);for v<n{v=v+v};G=v;return v};func outer(n uint32)uint32{return round(n)};func F(){Stop(0);a:=outer(9);if a!=16{panic(1)};Stop(a)}`, 64)
	root := source.prog.Roots["F"]
	calls := localEffectCalls(t, root, "Stop")
	first, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	second, err := checkSourceOperandContinuation(t.Context(), first, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, second.operands[0], 16)
	if second.cursor.owner != first.cursor.owner || second.cursor.ordinal <= first.cursor.ordinal || !second.region.packet.trace.seen[first.cursor] {
		t.Fatal("continuation reset lineage, cursor, or execution history")
	}
	if len(second.region.packet.trace.calls) != 3 {
		t.Fatal("continuation omitted an actual ordinary child application")
	}
	for _, application := range second.region.packet.trace.calls {
		proof := application.proof
		if proof.occurrences == nil || proof.entries != nil || !second.region.packet.trace.seen[proof.caller] || proof.caller.instruction != proof.at || proof.caller.owner != first.cursor.owner {
			t.Fatal("ordinary call lacks complete occurrence proof at its actual invocation")
		}
	}
	foundGlobal := false
	for object, value := range second.region.packet.observations[0].state.memory {
		if object.kind == regionGlobal && object.site.Name() == "G" {
			foundGlobal = true
			localEffectInteger(t, value, 16)
		}
	}
	if !foundGlobal {
		t.Fatal("ordinary child return discarded its entire changed heap")
	}
	for _, mutate := range []func(*sourceOperandPrefix){
		func(p *sourceOperandPrefix) { p.cursor.ordinal++ },
		func(p *sourceOperandPrefix) { p.cursor.owner = &regionOccurrenceOwner{} },
		func(p *sourceOperandPrefix) { p.boundary = calls[0] },
	} {
		oldCursor, oldBoundary := second.cursor, second.boundary
		mutate(second)
		if second.checkedPacket() != nil {
			t.Fatal("forged continuation cursor or static anchor accepted")
		}
		second.cursor, second.boundary = oldCursor, oldBoundary
	}
	copy := *second.sourceEffectPrefix
	if checkedSourcePrefix(&copy) != nil {
		t.Fatal("copied prefix has continuation authority")
	}
	oldPrior := second.prior
	second.prior = nil
	if second.checkedPacket() != nil {
		t.Fatal("prefix detached from its checked inherited anchor")
	}
	second.prior = oldPrior
	oldSession := second.checker.session
	second.checker.session = nil
	if second.checkedPacket() != nil {
		t.Fatal("prefix without its checked execution session retained authority")
	}
	second.checker.session = oldSession
	oldOwner := second.region.packet.trace.owner
	second.region.packet.trace.owner = nil
	if second.checkedPacket() != nil {
		t.Fatal("prefix without its occurrence lineage retained authority")
	}
	second.region.packet.trace.owner = oldOwner
	var ret *ssa.Return
	for _, block := range root.Blocks {
		for _, ins := range block.Instrs {
			if r, ok := ins.(*ssa.Return); ok {
				ret = r
			}
		}
	}
	complete, err := checkSourceReturnContinuation(t.Context(), second, ret, nil)
	if err != nil || complete.checkedPacket() == nil || complete.occurrence.instruction != ret || complete.occurrence.owner != first.cursor.owner {
		t.Fatalf("return completion lost exact occurrence: %v", err)
	}
	complete.occurrence.ordinal++
	if complete.checkedPacket() != nil {
		t.Fatal("forged return occurrence accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := checkSourceReturnContinuation(ctx, second, ret, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled continuation: %v", err)
	}
	// A continuation inherits the already spent work account, even though this
	// suffix is shorter than an independently permitted execution.
	oldWork := second.region.packet.usage.work
	second.region.packet.usage.work = second.region.packet.usage.limits.work
	if _, err := checkSourceReturnContinuation(t.Context(), second, ret, nil); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("continuation restarted its work allowance: %v", err)
	}
	second.region.packet.usage.work = oldWork
}

func TestRegionOccurrenceRepeatedAccessIdentity(t *testing.T) {
	in := occurrenceFixture(t, `var G uint32;func F()uint32{for i:=uint32(0);i<3;i++{G=i};return G}`)
	p, owner := occurrenceProposal(t, in)
	packet, _, err := occurrenceCheck(t, in, p, owner)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[regionEffectOccurrence]bool{}
	writes := 0
	for _, access := range packet.trace.accesses {
		if seen[access.regionEffectOccurrence] || !packet.trace.seen[access.regionEffectOccurrence] {
			t.Fatal("repeated static access collapsed its occurrence identity")
		}
		seen[access.regionEffectOccurrence] = true
		if access.write {
			localEffectInteger(t, access.value, uint64(writes))
			writes++
		}
	}
	if writes != 3 {
		t.Fatalf("writes %d, want 3", writes)
	}
	localEffectInteger(t, packet.observations[0].value, 2)
}

func TestRegionOccurrenceCallProofBinding(t *testing.T) {
	in := occurrenceFixture(t, `func g(n uint32)uint32{for i:=uint32(0);i<n;i++{};return n};func F()uint32{return g(4)}`)
	p, owner := occurrenceProposal(t, in)
	if len(p.calls) != 1 || p.calls[0].occurrences == nil {
		t.Fatal("fixture has no finite child proof")
	}
	for name, change := range map[string]func(*regionCallProof){
		"owner":         func(p *regionCallProof) { p.caller.owner = &regionOccurrenceOwner{} },
		"ordinal":       func(p *regionCallProof) { p.caller.ordinal++ },
		"instruction":   func(p *regionCallProof) { p.caller.instruction = nil },
		"selection":     func(p *regionCallProof) { p.selection = nil },
		"mixed-arm":     func(p *regionCallProof) { p.entries = map[*ssa.BasicBlock][]regionState{} },
		"missing-arm":   func(p *regionCallProof) { p.occurrences = nil },
		"partial-child": func(p *regionCallProof) { p.occurrences.nodes = p.occurrences.nodes[:len(p.occurrences.nodes)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			_, copy, err := regionCapture(in, p, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			change(copy.calls[0])
			if packet, _, err := occurrenceCheck(t, in, copy, owner); err == nil || packet != nil {
				t.Fatal("foreign or incomplete child occurrence proof accepted")
			}
		})
	}
}

func TestRegionOccurrenceDiscoveryBoundIsNotPremise(t *testing.T) {
	in := occurrenceFixture(t, `func F(x int32)int32{s:=uint(0);for 1<<s<x{s++};return 1<<s}`, 2048)
	p, owner := occurrenceProposal(t, in)
	if _, _, err := occurrenceCheck(t, in, p, owner); err != nil {
		t.Fatal(err)
	}
	// Keep the graph admissible but leave too little path allowance. The same
	// actual argument must refuse, never acquire a shorter-execution premise.
	k := occurrenceKernel(t, t.Context(), in, owner, defaultRegionLimits())
	k.meter.nodes = k.meter.limits.nodes - 5
	if partial, err := proposeRegionKernel(k); err == nil || partial != nil {
		t.Fatal("discovery truncation supplied a completed execution")
	}
}

func TestRegionOccurrenceCaptureOwnsPath(t *testing.T) {
	in := occurrenceFixture(t, `func F(n uint32)uint32{for i:=uint32(0);i<n;i++{};return n}`, 3)
	p, owner := occurrenceProposal(t, in)
	capturedInput, captured, err := regionCapture(in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.occurrences.nodes {
		p.occurrences.nodes[i].end = regionOccurrenceResidual
		for j := range p.occurrences.nodes[i].slots {
			p.occurrences.nodes[i].slots[j] = regionOccurrenceFalse
		}
		clear(p.occurrences.nodes[i].entry.values)
	}
	if _, _, err := occurrenceCheck(t, capturedInput, captured, owner); err != nil {
		t.Fatalf("caller mutation changed captured occurrence proof: %v", err)
	}
}

func TestRegionOccurrenceExactWholeEntry(t *testing.T) {
	in := occurrenceFixture(t, `var G uint32;func F(n uint32)uint32{G=9;for i:=uint32(0);i<n;i++{};return 7}`, 3)
	p, owner := occurrenceProposal(t, in)
	packet, _, err := occurrenceCheck(t, in, p, owner)
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, packet.observations[0].value, 7)
	last := &p.occurrences.nodes[len(p.occurrences.nodes)-1]
	if len(last.entry.memory) == 0 || len(last.entry.values) == 0 || last.end != regionOccurrenceReturn {
		t.Fatal("fixture lacks a nontrivial terminal whole-state relation")
	}
	// The actual return is constant: no later operation can accidentally reject
	// this widened relation for an unknown operand. Exact whole-entry equivalence
	// itself must reject discarding the current heap and environment.
	last.entry = regionState{}
	if packet, _, err := occurrenceCheck(t, in, p, owner); err == nil || packet != nil || !strings.Contains(err.Error(), "complete incoming relation") {
		t.Fatalf("terminal entry widening did not fail its own obligation: %v", err)
	}
}

func TestRegionOccurrenceSelectedSizesOwnership(t *testing.T) {
	in := occurrenceFixture(t, `func F()uint32{return 1}`)
	for _, mutate := range []func(*regionInput){
		func(in *regionInput) { copy := *in.selection; copy.Prog = nil; in.selection = &copy },
		func(in *regionInput) {
			copy := *in.selection
			copy.Pkgs = append(slices.Clone(copy.Pkgs), copy.Pkgs[0])
			in.selection = &copy
		},
		func(in *regionInput) {
			copy := *in.selection
			pkg := *copy.Pkgs[0]
			pkg.TypesSizes = nil
			copy.Pkgs = slices.Clone(copy.Pkgs)
			copy.Pkgs[0] = &pkg
			in.selection = &copy
		},
	} {
		copy := in
		mutate(&copy)
		if _, err := newRegionContextKernel(copy, newRegionCallSession(t.Context(), copy, defaultRegionLimits()), regionInvocation{}, true); err == nil {
			t.Fatal("foreign, duplicate or missing selected sizes accepted")
		}
	}
	in.selection = nil
	k := occurrenceKernel(t, t.Context(), in, &regionOccurrenceOwner{}, defaultRegionLimits())
	if k.sizes != nil || !k.scalarConstant(types.Typ[types.Uint32], constant.MakeInt64(1)) {
		t.Fatal("unselected fixed-width language values require no storage model")
	}
}

type occurrenceCancelSizes struct {
	types.Sizes
	cancel context.CancelFunc
	panics bool
}

func (s occurrenceCancelSizes) Sizeof(typ types.Type) int64 {
	s.cancel()
	if s.panics {
		panic("invalid selected sizes")
	}
	return s.Sizes.Sizeof(typ)
}

func TestRegionOccurrenceSelectedSizesOperationalRefusal(t *testing.T) {
	for _, panics := range []bool{false, true} {
		in := occurrenceFixture(t, `func F()uint32{return 1}`)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		pkg := in.selection.Pkgs[0]
		pkg.TypesSizes = occurrenceCancelSizes{Sizes: pkg.TypesSizes, cancel: cancel, panics: panics}
		if _, err := newRegionContextKernel(in, newRegionCallSession(ctx, in, defaultRegionLimits()), regionInvocation{}, true); !errors.Is(err, context.Canceled) {
			t.Fatalf("selected sizes concealed cancellation (panic=%v): %v", panics, err)
		}
	}
	in := occurrenceFixture(t, `func F()uint32{return 1}`)
	in.selection.Pkgs[0].TypesSizes = &types.StdSizes{WordSize: 3, MaxAlign: 8}
	if _, err := newRegionContextKernel(in, newRegionCallSession(t.Context(), in, defaultRegionLimits()), regionInvocation{}, true); err == nil {
		t.Fatal("invalid selected word extent accepted")
	}
}
