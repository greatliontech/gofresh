package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

const entryRelationCode = "493b6610760cb801000000bb02000000eb020f0bc3"

func entryRelationFixture(t testing.TB, code string) (*Image, TransitionInterface) {
	t.Helper()
	im, err := NewImage(t.Context(), transitionImageELF(t, hexBytes(t, code), imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	face := TransitionInterface{
		Origin:   OriginDomain{Min: 4096, Max: 1<<47 - 4096, Modulus: 16},
		Envelope: RelativeSpan{-128, 128}, Conditions: interfaceConditions(),
		ImageRegions:         []Span{{imageStateAddress, imageStateAddress + 32}},
		EntryImagePointers:   []TransitionEntryImagePointer{{R14, imageStateAddress}},
		EntryWordUpperBounds: []TransitionEntryWordUpperBound{{imageStateAddress + 16, 0}},
	}
	return im, face
}

func entryRelationProposal(t testing.TB, im *Image, cut uint64, expansions ...TransitionExpansion) TransitionProposal {
	t.Helper()
	p, err := ProposeRegionTransition(t.Context(), im, testEntry, cut, TransitionLimits{}, TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func entryRelationCheck(t testing.TB, im *Image, face TransitionInterface, p TransitionProposal) TransitionCertificate {
	t.Helper()
	c, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func entryRelationValues(b TransitionBound, origin, guard uint64) map[br.Term]uint64 {
	values := map[br.Term]uint64{}
	for r, v := range b.InitialRegisters {
		values[v] = uint64(r)*0xfedcba987654321 + 17
	}
	values[b.Origin] = origin
	for _, p := range b.Interface.EntryImagePointers {
		values[b.InitialRegisters[p.Register]] = p.Address
	}
	for _, v := range b.InitialMemory {
		values[v.Value] = 0
		if v.Image && v.Offset >= int64(imageStateAddress+16) && v.Offset < int64(imageStateAddress+24) {
			values[v.Value] = guard >> (8 * uint(v.Offset-int64(imageStateAddress+16))) & 255
		}
	}
	return values
}

func TestTransitionEntryRelationCompareSemantics(t *testing.T) {
	im, face := entryRelationFixture(t, entryRelationCode)
	p := entryRelationProposal(t, im, testEntry+4, TransitionExpansion{PC: testEntry})
	c := entryRelationCheck(t, im, face, p)
	b, _ := c.Bound()
	if len(b.Accesses) != 1 || b.Accesses[0].Kind != FrameRead || b.CutGuard != b.EntryPredicate {
		t.Fatal("CMP did not retain its conditional full-width read")
	}
	for _, s := range []uint64{4096, 1 << 32, 1<<47 - 4096} {
		for _, g := range []uint64{0, s - 1, s, s + 1, math.MaxUint64} {
			values := entryRelationValues(b, s, g)
			truth := func(v bool) uint64 {
				if v {
					return 1
				}
				return 0
			}
			if stateEval(t, b.Accesses[0].Value, values) != g || stateEval(t, b.EntryPredicate, values) != truth(g < s) || stateEval(t, b.Flags.CF.Value, values) != truth(s < g) || stateEval(t, b.Flags.ZF.Value, values) != truth(s == g) {
				t.Fatal("raw CMP operand order, width, equality or unsigned carry differs", s, g)
			}
		}
	}
}

func TestTransitionEntryRelationRealPrologue(t *testing.T) {
	im, face := entryRelationFixture(t, entryRelationCode)
	p := entryRelationProposal(t, im, testEntry+11, TransitionExpansion{PC: testEntry})
	c := entryRelationCheck(t, im, face, p)
	b, _ := c.Bound()
	if !b.ConditionalRegion || b.EntryPredicate.Sort() != br.Bool() || literalBool(b.EntryPredicate, 1) || len(b.ExcludedBoundaries) != 1 || b.ExcludedBoundaries[0].PC != testEntry+18 {
		t.Fatal("missing actual entry antecedent or slow-path exclusion")
	}
	if len(b.Accesses) != 1 || b.Accesses[0].Bytes != (RelativeSpan{int64(imageStateAddress + 16), int64(imageStateAddress + 24)}) || !b.Accesses[0].Image || b.Accesses[0].Kind != FrameRead {
		t.Fatal("entry declaration fabricated access or CMP lost its full read", b.Accesses)
	}
	if b.Instructions[0].Guard != b.EntryPredicate || b.Registers[R14].Value != b.InitialRegisters[R14] || b.Preserved[R14] != math.MaxUint64 || b.Preserved[RSP] != math.MaxUint64 {
		t.Fatal("entry binding lost original variable, preservation or guard")
	}
	ptr, ok := b.Registers[R14].Pointer.(ImagePointer)
	if !ok || ptr.Address != imageStateAddress || ptr.owner != &im.data[0] || b.Registers[RSP].Pointer != (OriginPointer{Origin: b.Origin}) {
		t.Fatal("missing owned entry provenance")
	}
	for _, v := range b.InitialMemory {
		if v.Value.View().Op != br.Variable {
			t.Fatal("witness zero or ELF data leaked into symbolic current bytes")
		}
	}
	// Universal constraints, rather than an assumed guard value, exclude both
	// equality and strictly greater unsigned words at the actual CMP/JBE.
	builder := br.NewBuilder(0)
	zero, _ := builder.Const(br.Bool(), 0)
	greater, _ := builder.Make(br.ULT, br.Bool(), 0, b.Origin, b.Accesses[0].Value)
	equal, _ := builder.Make(br.Equal, br.Bool(), 0, b.Origin, b.Accesses[0].Value)
	bad, _ := builder.Make(br.Or, br.Bool(), 0, greater, equal)
	under, _ := builder.Make(br.And, br.Bool(), 0, b.EntryPredicate, bad)
	if _, err := br.Prove(t.Context(), under, zero, br.Limits{}); err != nil {
		t.Fatal("entry relation did not exclude equal/greater guard", err)
	}
	for _, s := range []uint64{4096, 8192, 1<<40 + 16, 1<<47 - 4096} {
		for _, g := range []uint64{0, 1, s - 1, s, s + 1, math.MaxUint64} {
			v := entryRelationValues(b, s, g)
			want := uint64(0)
			if g < s {
				want = 1
			}
			if stateEval(t, b.EntryPredicate, v) != want || stateEval(t, b.CutGuard, v) != want || stateEval(t, b.ExcludedBoundaries[0].Guard, v) != 0 {
				t.Fatal("unsigned entry/branch semantics differ", s, g)
			}
			v[b.InitialRegisters[R14]]++
			if stateEval(t, b.EntryPredicate, v) != 0 {
				t.Fatal("pointer provenance was not tied to entry register bits")
			}
		}
	}
	// S+1 permits G==S; a 32-bit CMP or a different displacement no longer
	// establishes the actual slow-path exclusion. All are semantic refusals.
	for _, mode := range []string{"no-bound", "weaker-bound", "no-pointer", "different-word", "width32", "signed-disp"} {
		t.Run(mode, func(t *testing.T) {
			f, image := cloneTransitionInterface(face), im
			switch mode {
			case "no-bound":
				f.EntryWordUpperBounds = nil
			case "weaker-bound":
				f.EntryWordUpperBounds[0].OriginOffset = 1
			case "no-pointer":
				f.EntryImagePointers = nil
			case "different-word":
				f.EntryWordUpperBounds[0].Address++
			case "width32":
				image, _ = entryRelationFixture(t, "413b6610"+entryRelationCode[8:])
			case "signed-disp":
				image, _ = entryRelationFixture(t, "493b66f0"+entryRelationCode[8:])
			}
			q := entryRelationProposal(t, image, testEntry+11, TransitionExpansion{PC: testEntry})
			got, err := CheckRegionTransition(t.Context(), image, testEntry, f, q, TransitionLimits{})
			transitionRefused(t, got, err)
		})
	}
}

func TestTransitionEntryRelationValidation(t *testing.T) {
	im, face := entryRelationFixture(t, "c3")
	p := entryRelationProposal(t, im, testEntry)
	entryRelationCheck(t, im, face, p)
	for _, tc := range []struct {
		name string
		edit func(*TransitionInterface)
	}{
		{"RSP", func(f *TransitionInterface) { f.EntryImagePointers[0].Register = RSP }},
		{"register-range", func(f *TransitionInterface) { f.EntryImagePointers[0].Register = Register(255) }},
		{"duplicate", func(f *TransitionInterface) {
			f.EntryImagePointers = append(f.EntryImagePointers, f.EntryImagePointers[0])
		}},
		{"unmapped-pointer", func(f *TransitionInterface) { f.EntryImagePointers[0].Address = 1 }},
		{"undeclared-pointer", func(f *TransitionInterface) { f.EntryImagePointers[0].Address += 32 }},
		{"noncanonical-pointer", func(f *TransitionInterface) { f.EntryImagePointers[0].Address = 1 << 47 }},
		{"wrapped-pointer", func(f *TransitionInterface) { f.EntryImagePointers[0].Address = math.MaxUint64 }},
		{"short-word", func(f *TransitionInterface) { f.ImageRegions[0].End = imageStateAddress + 23 }},
		{"unmapped-word", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].Address = 1 }},
		{"wrapped-word", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].Address = math.MaxUint64 - 3 }},
		{"low-origin-wrap", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].OriginOffset = -4097 }},
		{"high-origin-wrap", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].OriginOffset = 4096 }},
		{"min-signed", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].OriginOffset = math.MinInt64 }},
		{"max-signed", func(f *TransitionInterface) { f.EntryWordUpperBounds[0].OriginOffset = math.MaxInt64 }},
		{"all-zero-upper", func(f *TransitionInterface) { f.Origin.Max = 4096; f.EntryWordUpperBounds[0].OriginOffset = -4096 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := cloneTransitionInterface(face)
			tc.edit(&f)
			c, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
			transitionRefused(t, c, err)
		})
	}
	for _, offset := range []int64{-4096, 0, 4095} {
		f := cloneTransitionInterface(face)
		f.EntryWordUpperBounds[0].OriginOffset = offset
		entryRelationCheck(t, im, f, p)
	}
	// Rounded congruent endpoints, rather than raw bounds, govern arithmetic.
	f := cloneTransitionInterface(face)
	f.Origin = OriginDomain{Min: 4095, Max: 8193, Modulus: 16}
	f.EntryWordUpperBounds[0].OriginOffset = -4096
	entryRelationCheck(t, im, f, p)
	// An entry pointer does not enlarge its declared memory permission.
	read, f := entryRelationFixture(t, "498b4610c3")
	f.EntryWordUpperBounds = nil
	f.ImageRegions[0].End = imageStateAddress + 1
	q := entryRelationProposal(t, read, testEntry+4)
	c, err := CheckRegionTransition(t.Context(), read, testEntry, f, q, TransitionLimits{})
	transitionRefused(t, c, err)
	loads := imageStateLoads()
	loads[0].read = false
	unreadable, err := NewImage(t.Context(), transitionImageELF(t, []byte{0xc3}, loads))
	if err != nil {
		t.Fatal(err)
	}
	for _, onlyPointer := range []bool{false, true} {
		f := cloneTransitionInterface(face)
		if onlyPointer {
			f.EntryWordUpperBounds = nil
		} else {
			f.EntryImagePointers = nil
		}
		q := entryRelationProposal(t, unreadable, testEntry)
		c, err := CheckRegionTransition(t.Context(), unreadable, testEntry, f, q, TransitionLimits{})
		transitionRefused(t, c, err)
	}
	// Neither typed declarations nor matching numeric entry PCs grant ELF-root
	// or loader/source-zero initialization authority.
	c, err = CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
	init, err := CheckImageInitialization(t.Context(), im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	f = cloneTransitionInterface(face)
	f.Initialization = init
	c, err = CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
	transitionRefused(t, c, err)
}

func TestTransitionEntryRelationNonvacuity(t *testing.T) {
	for _, executable := range []bool{false, true} {
		for _, word := range []uint64{0, 4095, 4096, 8191, 8192, 0x9090909090909090} {
			loads := []interfaceMapping{{start: imageStateAddress, end: imageStateAddress + 16, file: 0x10000, filesz: 16, read: true, execute: executable}}
			raw := transitionImageELF(t, []byte{0xc3}, loads)
			clear(raw[0x10000:0x10010])
			binary.LittleEndian.PutUint64(raw[0x10000:], word)
			im, err := NewImage(t.Context(), raw)
			if err != nil {
				t.Fatal(err)
			}
			face := TransitionInterface{Origin: OriginDomain{Min: 4096, Max: 8192, Modulus: 16}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions(), ImageRegions: []Span{{imageStateAddress, imageStateAddress + 16}}, EntryWordUpperBounds: []TransitionEntryWordUpperBound{{imageStateAddress, 0}, {imageStateAddress + 1, 0}}}
			p := entryRelationProposal(t, im, testEntry)
			c, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
			want := !executable || word < 8192 && binary.LittleEndian.Uint64(raw[0x10001:]) < 8192
			if (err == nil) != want || (c.checked != nil) != want {
				t.Fatalf("fixed=%v word=%x nonvacuity want %v: %v", executable, word, want, err)
			}
		}
	}
	// The last congruent origin is page-excluded. A fixed bound between the
	// last admissible origin and that excluded endpoint must refuse.
	raw := transitionImageELF(t, []byte{0xc3}, []interfaceMapping{{start: imageStateAddress, end: imageStateAddress + 8, file: 0x10000, filesz: 8, read: true, execute: true}})
	binary.LittleEndian.PutUint64(raw[0x10000:], testEntry-16)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	face := TransitionInterface{Origin: OriginDomain{Min: testEntry - 32, Max: testEntry + 32, Modulus: 16}, Envelope: RelativeSpan{0, 1}, Conditions: interfaceConditions(), Regions: []RelativeRegion{{Bytes: RelativeSpan{0, 1}, Readable: true}}, ImageRegions: []Span{{imageStateAddress, imageStateAddress + 8}}, EntryWordUpperBounds: []TransitionEntryWordUpperBound{{imageStateAddress, 0}}}
	p := entryRelationProposal(t, im, testEntry)
	c, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, TransitionLimits{})
	transitionRefused(t, c, err)
	face.EntryWordUpperBounds[0].OriginOffset = 1
	entryRelationCheck(t, im, face, p)
	// Executable bytes beyond filesz are unknown even if raw file bytes happen
	// to exist at the corresponding offset. No zero-fill or convenient file read.
	unknown := transitionImageELF(t, []byte{0xc3}, []interfaceMapping{{start: imageStateAddress, end: imageStateAddress + 16, file: 0x10000, filesz: 8, read: true, execute: true}})
	unknown = append(unknown, make([]byte, 8)...)
	im, err = NewImage(t.Context(), unknown)
	if err != nil {
		t.Fatal(err)
	}
	face.Regions = nil
	face.ImageRegions[0].End += 8
	face.EntryWordUpperBounds[0].Address += 8
	c, err = CheckRegionTransition(t.Context(), im, testEntry, face, entryRelationProposal(t, im, testEntry), TransitionLimits{})
	transitionRefused(t, c, err)
}

func TestTransitionEntryRelationOwnershipContinuationAndBudgets(t *testing.T) {
	im, face := entryRelationFixture(t, "493b6610b801000000bb02000000c3")
	p := entryRelationProposal(t, im, testEntry+4, TransitionExpansion{PC: testEntry})
	c := entryRelationCheck(t, im, face, p)
	original, _ := c.Bound()
	q := entryRelationProposal(t, im, testEntry+14, TransitionExpansion{PC: testEntry})
	next, err := CheckTransitionContinuation(t.Context(), c, q)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := next.Bound()
	if b.EntryPredicate != original.EntryPredicate || b.Origin != original.Origin || b.InitialRegisters != original.InitialRegisters || !reflect.DeepEqual(b.Interface, original.Interface) || !reflect.DeepEqual(b.InitialMemory, original.InitialMemory) {
		t.Fatal("continuation changed entry relation or identities")
	}
	direct := entryRelationCheck(t, im, face, q)
	assertTransitionAlpha(t, direct, next)
	assertTransitionRetainedExpressionUnion(t, c, q)
	b.Interface.EntryWordUpperBounds[0].OriginOffset++
	b.Interface.EntryImagePointers[0].Register = RAX
	b.EntryPredicate = br.Term{}
	retained, _ := next.Bound()
	if retained.EntryPredicate != original.EntryPredicate || !reflect.DeepEqual(retained.Interface, original.Interface) {
		t.Fatal("mutable projection changed opaque entry premises")
	}
	fresh := entryRelationCheck(t, im, face, p)
	if fresh.checked.bound.Origin == original.Origin || fresh.checked.bound.EntryPredicate == original.EntryPredicate {
		t.Fatal("fresh root reused entry variables")
	}
	foreign, err := NewImage(t.Context(), im.data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.BoundFor(foreign); ok {
		t.Fatal("independent owner borrowed pointer relation")
	}
	foreignC := entryRelationCheck(t, foreign, face, p)
	if foreignC.checked.bound.Registers[R14].Pointer == original.Registers[R14].Pointer {
		t.Fatal("equal bytes shared pointer owner")
	}
	count := &imageCallbackContext{Context: t.Context()}
	if _, err := CheckRegionTransition(count, im, testEntry, face, p, TransitionLimits{}); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		f, supplied := cloneTransitionInterface(face), *im
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				f.EntryWordUpperBounds[0] = TransitionEntryWordUpperBound{}
				f.EntryImagePointers[0] = TransitionEntryImagePointer{}
				supplied = Image{}
			}
		}}
		got, err := CheckRegionTransition(ctx, &supplied, testEntry, f, p, TransitionLimits{})
		if err != nil || !reflect.DeepEqual(got.checked.bound.Interface, original.Interface) {
			t.Fatal("callback crossed owned entry declaration snapshot", at, err)
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		stop := &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckRegionTransition(stop, im, testEntry, face, p, TransitionLimits{})
		cancel()
		if !errors.Is(err, context.Canceled) || got.checked != nil {
			t.Fatal("cancelled entry relation published", at, err)
		}
	}
	for _, limit := range []TransitionLimits{{RelationLimits: RelationLimits{Nodes: 40}}, {RelationLimits: RelationLimits{Depth: 2}}, {RelationLimits: RelationLimits{Work: 2}}, {LiveStateBytes: 64}, {Bytes: 7}} {
		got, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, limit)
		transitionRefused(t, got, err)
	}
	limit := TransitionLimits{RelationLimits: RelationLimits{Work: c.checked.work + 1}}
	limited, err := CheckRegionTransition(t.Context(), im, testEntry, face, p, limit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CheckTransitionContinuation(t.Context(), limited, q)
	transitionRefused(t, got, err)
	for _, pointers := range []bool{false, true} {
		f := cloneTransitionInterface(face)
		if pointers {
			f.EntryImagePointers = make([]TransitionEntryImagePointer, 16)
		} else {
			f.EntryWordUpperBounds = make([]TransitionEntryWordUpperBound, 65536/8+1)
		}
		got, err := CheckRegionTransition(t.Context(), im, testEntry, f, p, TransitionLimits{})
		transitionRefused(t, got, err)
	}
}
