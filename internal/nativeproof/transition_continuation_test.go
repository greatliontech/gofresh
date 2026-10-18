package nativeproof

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func continuationProposal(t testing.TB, im *Image, cut uint64) TransitionProposal {
	t.Helper()
	p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func continuationRoot(t testing.TB, im *Image, cut uint64, face TransitionInterface, limits TransitionLimits) TransitionCertificate {
	t.Helper()
	c, err := CheckTransition(t.Context(), im, face, continuationProposal(t, im, cut), limits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTransitionContinuationState(t *testing.T) {
	f := transitionFace()
	f.Regions[1] = RelativeRegion{RelativeSpan{-24, 0}, true, true}
	for _, tt := range []struct {
		tail    string
		pointer bool
	}{
		{"488b4c2420", true},
		{"4889442421488b4c2420", false},
		{"48895c2421488b4c2420", false},
		{"4889442420488b4c2420", false},
	} {
		t.Run(tt.tail, func(t *testing.T) {
			im, cut := transitionFixture(t, entryPrefix+tt.tail)
			oldCut := testEntry + uint64(len(hexBytes(t, entryPrefix)))
			root := continuationRoot(t, im, oldCut, f, TransitionLimits{})
			before, _ := root.Bound()
			c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			if b.Origin != before.Origin || b.InitialRegisters != before.InitialRegisters || !reflect.DeepEqual(b.InitialMemory, before.InitialMemory) || !reflect.DeepEqual(b.Words, before.Words) || !reflect.DeepEqual(b.Interface, before.Interface) {
				t.Fatal("continuation changed root scope or premises")
			}
			if (b.Registers[RCX].Pointer != nil) != tt.pointer || b.Preserved[RAX] != 0 || len(b.Accesses) != len(before.Accesses)+len(hexBytes(t, tt.tail))/5 {
				t.Fatal("state/provenance/footprint was reset")
			}
			if tt.pointer {
				requireStackPointer(t, b.Registers[RCX].Pointer)
			}
			assertTransitionOracle(t, im, b, 12)
			after, _ := root.Bound()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("predecessor mutated")
			}
		})
	}
}

func TestTransitionContinuationMOV32AndFlags(t *testing.T) {
	for _, prefix := range []string{"", "4883e801", "4883e4f0"} {
		for reg := 0; reg < 16; reg++ {
			for _, imm := range []uint32{0, 1, 0x80000000, 0xffffffff} {
				code := fmt.Sprintf("%02x%02x%02x%02x%02x", 0xb8+reg%8, byte(imm), byte(imm>>8), byte(imm>>16), byte(imm>>24))
				if reg >= 8 {
					code = "41" + code
				}
				im, cut := transitionFixture(t, prefix+code)
				oldCut := testEntry + uint64(len(hexBytes(t, prefix)))
				root := continuationRoot(t, im, oldCut, transitionFace(), TransitionLimits{})
				p, err := ProposeTransition(t.Context(), im, cut, TransitionLimits{})
				if err != nil {
					t.Fatalf("proposal %s %s: %v", prefix, code, err)
				}
				c, err := CheckTransitionContinuation(t.Context(), root, p)
				if err != nil {
					t.Fatalf("%s %s: %v", prefix, code, err)
				}
				b, _ := c.Bound()
				if got := evalRelationTerm(t, b.Registers[reg].Value, nil, ^uint64(0)); got != uint64(imm) || b.Registers[reg].Pointer != nil || b.Preserved[reg] != 0 {
					t.Fatalf("MOV32 reg%d imm%x: got %x", reg, imm, got)
				}
				if b.Flags != root.checked.bound.Flags || c.checked.flags != root.checked.flags || len(b.Accesses) != 0 {
					t.Fatal("MOV changed flags or accessed memory")
				}
				for _, x := range []uint64{0, 1, 1 << 63, ^uint64(0)} {
					values := map[br.Term]uint64{b.InitialRegisters[RAX]: x, b.Origin: 0x100000000}
					for j, predicate := range c.checked.flags {
						if prefix == "" {
							if predicate.View().Op != br.Variable || !predicate.View().Scratch {
								t.Fatal("initial flags not arbitrary")
							}
							continue
						}
						want := []bool{false, false, false}
						if prefix == "4883e801" {
							want = []bool{x < 1, x-1 == 0, int64(x) < 1}
						}
						got := evalRelationTerm(t, predicate, values, 0) != 0
						if got != want[j] {
							t.Fatalf("stale flag %d after %s x%x", j, prefix, x)
						}
					}
				}
			}
		}
	}
	for _, code := range []string{"40bd00000000", "42bd00000000", "44bd00000000", "66bd0000", "41bd000000"} {
		im, cut := transitionFixture(t, code)
		c, err := proveTransition(t, im, cut, transitionFace())
		transitionRefused(t, c, err)
	}
}

func TestTransitionContinuationRefusals(t *testing.T) {
	im, cut := transitionFixture(t, "eb0248894889e04889c34889d9")
	root := continuationRoot(t, im, testEntry+7, transitionFace(), TransitionLimits{})
	p := continuationProposal(t, im, cut)
	for _, target := range []uint64{testEntry, testEntry + 1, testEntry + 2, testEntry + 4, testEntry + 5, testEntry + 7, cut + 1, cut + 5} {
		q := p
		q.Cut = target
		c, err := CheckTransitionContinuation(t.Context(), root, q)
		transitionRefused(t, c, err)
	}
	for _, change := range []func(*TransitionProposal){
		func(p *TransitionProposal) { p.Entry++ },
		func(p *TransitionProposal) { p.ImageDigest[0]++ },
		func(p *TransitionProposal) { p.Nodes = p.Nodes[1:] },
		func(p *TransitionProposal) { p.Nodes[0].PC++ },
		func(p *TransitionProposal) { p.Nodes[0].Size++ },
		func(p *TransitionProposal) { p.Nodes[0].Successors = []uint64{cut} },
		func(p *TransitionProposal) { p.Nodes[0].Successors = []uint64{cut, cut} },
	} {
		q := p
		q.Nodes = append([]Node(nil), p.Nodes...)
		change(&q)
		c, err := CheckTransitionContinuation(t.Context(), root, q)
		transitionRefused(t, c, err)
	}
	c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{}, p)
	transitionRefused(t, c, err)
	for _, rules := range []string{"", "gofresh/native-transition@1", strings.Split(TransitionRules, ";")[0], TransitionRules + ";unknown"} {
		fake := *root.checked
		fake.bound.Rules = rules
		c, err := CheckTransitionContinuation(t.Context(), TransitionCertificate{&fake}, p)
		transitionRefused(t, c, err)
	}
	// A locally acyclic suffix that re-enters or overlaps the prefix is not a
	// continuation. Full-graph occupancy and cycle checks must see both segments.
	for _, code := range []string{"4889e0ebfb", "4889e0ebfc", "4889e0ebfd", "4889e00f05", "4889e0488d0440"} {
		im, cut := transitionFixture(t, code)
		root := continuationRoot(t, im, testEntry+3, transitionFace(), TransitionLimits{})
		p := TransitionProposal{ImageDigest: im.digest, Entry: im.entry, Cut: cut}
		c, err := CheckTransitionContinuation(t.Context(), root, p)
		transitionRefused(t, c, err)
		var r *Refusal
		if !errors.As(err, &r) || r.Premise == "transition-proposal" {
			t.Fatalf("inventory masked coverage/transfer refusal: %v", err)
		}
	}
	// Unexecuted old boundary bytes are an obligation, not an instruction summary.
	corrupt := *root.checked
	corrupt.bound = cloneTransitionBound(corrupt.bound)
	corrupt.bound.Boundary.Bytes[0] ^= 1
	c, err = CheckTransitionContinuation(t.Context(), TransitionCertificate{&corrupt}, p)
	transitionRefused(t, c, err)
}

func TestTransitionContinuationPremisesCannotStrengthen(t *testing.T) {
	for _, tt := range []struct {
		code    string
		face    TransitionInterface
		premise string
	}{
		{"4889e0488b00", func() TransitionInterface { f := transitionFace(); f.Regions = nil; f.Words = nil; return f }(), "transition-permission"},
		{"4889e04883e0f0", func() TransitionInterface {
			f := transitionFace()
			f.Origin.Modulus = 8
			f.Origin.Max = 1<<47 - 16
			return f
		}(), "transition-alignment"},
	} {
		im, cut := transitionFixture(t, tt.code)
		root := continuationRoot(t, im, testEntry+3, tt.face, TransitionLimits{})
		projection, _ := root.Bound()
		projection.Interface.Origin.Modulus = 16
		projection.Interface.Regions = []RelativeRegion{{RelativeSpan{-48, 8}, true, true}}
		c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
		transitionRefused(t, c, err)
		var r *Refusal
		if !errors.As(err, &r) || r.Premise != tt.premise {
			t.Fatal(err)
		}
	}
}

func TestTransitionContinuationOwnershipCancellationAndSiblings(t *testing.T) {
	im, cut := transitionFixture(t, entryPrefix+"bd00000000")
	root := continuationRoot(t, im, cut-5, transitionFace(), TransitionLimits{})
	p := continuationProposal(t, im, cut)
	count := &imageCallbackContext{Context: t.Context()}
	first, err := CheckTransitionContinuation(count, root, p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := root.Bound()
	for at := 1; at <= count.calls; at++ {
		q := p
		q.Nodes = append([]Node(nil), p.Nodes...)
		for j := range q.Nodes {
			q.Nodes[j].Successors = append([]uint64(nil), q.Nodes[j].Successors...)
		}
		local := root
		projection, _ := local.Bound()
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n != at {
				return
			}
			local = TransitionCertificate{}
			q.Entry = 0
			q.ImageDigest = [32]byte{}
			q.Cut = 0
			q.Nodes[0].PC = 0
			q.Nodes[0].Successors[0] = 0
			projection.Interface.Regions[0] = RelativeRegion{}
			projection.Memory[0].Value = br.Term{}
			projection.InitialRegisters = [16]br.Term{}
			projection.Boundary.Bytes[0] = 0
		}}
		got, err := CheckTransitionContinuation(ctx, local, q)
		if err != nil {
			t.Fatalf("capture callback %d: %v", at, err)
		}
		x, _ := got.Bound()
		if x.Origin != before.Origin || x.Registers[RBP].Pointer != nil || got.checked.work != first.checked.work {
			t.Fatal("sibling changed inherited state or budget")
		}
		stop, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: stop, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckTransitionContinuation(ctx, root, p)
		cancel()
		if !errors.Is(err, context.Canceled) || got.checked != nil {
			t.Fatalf("cancel callback %d: %v", at, err)
		}
	}
	after, _ := root.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("sibling or cancellation changed predecessor")
	}
	c, err := CheckTransitionContinuation(nil, root, p)
	transitionRefused(t, c, err)
	// Audit retained ownership shape: only terms can lead to expression nodes;
	// no certificate, checker, symbolicState snapshot, builder, or context remains.
	typ := reflect.TypeFor[checkedTransition]()
	want := map[string]reflect.Type{"image": reflect.TypeFor[*Image](), "bound": reflect.TypeFor[TransitionBound](), "limits": reflect.TypeFor[TransitionLimits](), "work": reflect.TypeFor[int](), "flags": reflect.TypeFor[[flagCount]br.Term]()}
	want["exclusions"], want["coverageGuard"] = reflect.TypeFor[[]br.Witness](), reflect.TypeFor[br.Term]()
	want["justifications"] = reflect.TypeFor[[]br.Witness]()
	for j := 0; j < typ.NumField(); j++ {
		f := typ.Field(j)
		if want[f.Name] != f.Type {
			t.Fatal("unexpected retained owner", f)
		}
	}
}

func TestTransitionContinuationCumulativeBudgets(t *testing.T) {
	face := transitionFace()
	face.Regions = nil
	face.Words = nil
	im, cut := transitionFixture(t, strings.Repeat("4883e801", 6))
	oldCut := testEntry + 4
	for _, limits := range []TransitionLimits{
		{RelationLimits: RelationLimits{Instructions: 4}},
	} {
		root := continuationRoot(t, im, oldCut, face, limits)
		c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
		transitionRefused(t, c, err)
	}
	// Three prior SUBs fit depth five (including ZF); one more exceeds it.
	// Resetting imported nodes to depth one would incorrectly accept this suffix.
	deep := continuationRoot(t, im, testEntry+12, face, TransitionLimits{RelationLimits: RelationLimits{Depth: 5}})
	c, err := CheckTransitionContinuation(t.Context(), deep, continuationProposal(t, im, testEntry+16))
	transitionRefused(t, c, err)
	// Find the actual retained union, then leave enough capacity for either the
	// imported DAG or the new arena alone, but not for their union.
	root := continuationRoot(t, im, oldCut, face, TransitionLimits{})
	m, err := newTransitionChecker(t.Context(), root.checked.image, root.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*root.checked); err != nil {
		t.Fatal(err)
	}
	cap := len(m.depth) + 3 // root construction also allocated three now-dead initial predicates
	root = continuationRoot(t, im, oldCut, face, TransitionLimits{RelationLimits: RelationLimits{Nodes: cap}})
	c, err = CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, oldCut+4))
	transitionRefused(t, c, err)
	// Root and each one-instruction suffix are small; all construction and full
	// graph checks still accumulate, including prior continuation construction.
	root = continuationRoot(t, im, oldCut, face, TransitionLimits{})
	second, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, oldCut+4))
	if err != nil {
		t.Fatal(err)
	}
	limit := second.checked.work + 1
	bounded := continuationRoot(t, im, oldCut, face, TransitionLimits{RelationLimits: RelationLimits{Work: limit}})
	second, err = CheckTransitionContinuation(t.Context(), bounded, continuationProposal(t, im, oldCut+4))
	if err != nil {
		t.Fatal(err)
	}
	c, err = CheckTransitionContinuation(t.Context(), second, continuationProposal(t, im, oldCut+8))
	transitionRefused(t, c, err)
	if root.checked.work >= limit || second.checked.work >= limit {
		t.Fatal("control did not isolate cumulative exhaustion")
	}
	// A large existing memory relation must be charged again for proof copies,
	// imports, materialization and sorting, even if the suffix touches no memory.
	face.Regions = []RelativeRegion{{RelativeSpan{0, 2048}, true, true}}
	face.Envelope = RelativeSpan{-48, 2048}
	face.Origin.Max = 1<<47 - 4096
	root = continuationRoot(t, im, oldCut, face, TransitionLimits{})
	large, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, oldCut+4))
	if err != nil {
		t.Fatal(err)
	}
	if large.checked.work-root.checked.work < 8*2048 {
		t.Fatal("memory construction escaped work accounting")
	}
	bounded = continuationRoot(t, im, oldCut, face, TransitionLimits{RelationLimits: RelationLimits{Work: root.checked.work + 2048}})
	c, err = CheckTransitionContinuation(t.Context(), bounded, continuationProposal(t, im, oldCut+4))
	transitionRefused(t, c, err)
}

func TestTransitionContinuationSignedDisplacement(t *testing.T) {
	// The actual disp32 is -8, not +0xfffffff8. Only the latter has permission;
	// treating decoder metadata as ISA arithmetic would produce a false theorem.
	im, cut := transitionFixture(t, "4889e0488b8c24f8ffffff")
	f := transitionFace()
	f.Origin = OriginDomain{Min: 16, Max: 1 << 40, Modulus: 16}
	f.Envelope = RelativeSpan{-8, 1 << 32}
	f.Regions = []RelativeRegion{{RelativeSpan{1<<32 - 8, 1 << 32}, true, false}}
	f.Words = nil
	root := continuationRoot(t, im, testEntry+3, f, TransitionLimits{})
	c, err := CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
	transitionRefused(t, c, err)
	var r *Refusal
	if !errors.As(err, &r) || r.Premise != "transition-permission" {
		t.Fatal(err)
	}
	// With the actual negative extent admitted, the same selected bytes succeed.
	f.Regions[0].Bytes = RelativeSpan{-8, 0}
	root = continuationRoot(t, im, testEntry+3, f, TransitionLimits{})
	c, err = CheckTransitionContinuation(t.Context(), root, continuationProposal(t, im, cut))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.checked.bound.Accesses; len(got) != 1 || got[0].Bytes != (RelativeSpan{-8, 0}) {
		t.Fatal(got)
	}
}

func TestTransitionContinuationRetainedExpressionUnion(t *testing.T) {
	// Most initial register and byte variables are no longer reachable from the
	// cut state. They still belong to the root relation and its imported DAG cap.
	f := transitionFace()
	f.Regions = []RelativeRegion{{RelativeSpan{0, 8}, true, true}}
	code := "48c7042400000000"
	for r := 0; r < 16; r++ {
		prefix := ""
		if r >= 8 {
			prefix = "41"
		}
		code += fmt.Sprintf("%s%02x%08x", prefix, 0xb8+r%8, 0)
	}
	im, cut := transitionFixture(t, code+"bd01000000")
	root := continuationRoot(t, im, cut-5, f, TransitionLimits{})
	assertTransitionRetainedExpressionUnion(t, root, continuationProposal(t, im, cut))
}

// Both stack-only and mixed image/stack populations use this complete union
// check, including dead original byte inputs and each live constructor depth.
func assertTransitionRetainedExpressionUnion(t testing.TB, root TransitionCertificate, proposal TransitionProposal) {
	t.Helper()
	b := root.checked.bound
	depths := map[br.Term]int{}
	var visit func(br.Term) int
	visit = func(term br.Term) int {
		if !term.Valid() {
			return 0
		}
		if d := depths[term]; d != 0 {
			return d
		}
		d := 1
		for _, a := range term.View().Args {
			d = max(d, visit(a)+1)
		}
		depths[term] = d
		return d
	}
	visit(b.Origin)
	visit(b.CutGuard)
	visit(root.checked.coverageGuard)
	for j, e := range root.checked.exclusions {
		left, right := e.Roots()
		visit(left)
		visit(right)
		visit(b.ExcludedBoundaries[j].Guard)
	}
	visit(b.InitialPredicates.CF)
	visit(b.InitialPredicates.ZF)
	visit(b.InitialPredicates.SFXorOF)
	for _, occurrence := range b.Instructions {
		visit(occurrence.Guard)
	}
	for _, v := range b.InitialRegisters {
		visit(v)
	}
	for _, v := range b.Registers {
		visit(v.Value)
		if p, ok := v.Pointer.(OriginPointer); ok {
			visit(p.Origin)
		}
	}
	for _, memory := range [][]TransitionByte{b.InitialMemory, b.Memory} {
		for _, v := range memory {
			visit(v.Value)
			if p, ok := v.Pointer.(OriginPointer); ok {
				visit(p.Origin)
			}
		}
	}
	for _, w := range b.Words {
		visit(w.Value)
	}
	for _, effect := range b.PrimitiveEffects {
		e := effect.(CPUIDEffect)
		for _, term := range []br.Term{e.Leaf, e.Subleaf, e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
			visit(term)
		}
	}
	for _, v := range root.checked.flags {
		visit(v)
	}
	for _, v := range []TransitionFlag{b.Flags.CF, b.Flags.OF, b.Flags.SF, b.Flags.ZF, b.Flags.AF, b.Flags.PF} {
		visit(v.Value)
	}
	m, err := newTransitionChecker(t.Context(), root.checked.image, root.checked.limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.inherit(*root.checked); err != nil {
		t.Fatal(err)
	}
	for term, want := range depths {
		if got := m.depth[term]; got != want {
			t.Fatalf("retained node depth %d != %d", got, want)
		}
	}
	visit(m.truth)
	visit(m.falsity)
	if len(m.depth) != len(depths) {
		t.Fatal("import did not contain exactly the retained union plus Boolean constants")
	}
	c, err := CheckTransitionContinuation(t.Context(), root, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if c.checked.bound.InitialRegisters != b.InitialRegisters || !slices.Equal(c.checked.bound.InitialMemory, b.InitialMemory) {
		t.Fatal("dead root inputs dropped or reconstructed")
	}
}
