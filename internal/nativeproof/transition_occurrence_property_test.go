package nativeproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
	"golang.org/x/arch/x86/x86asm"
)

// The adapter consumes the reference's already executed intent trace. Witness
// edges locate opaque identities only: they never choose a reference successor,
// instruction, branch outcome, value, or termination condition.
type occurrencePropertyFixture struct {
	program    occurrenceOracleProgram
	image      *Image
	digest     [32]byte
	limits     TransitionLimits
	options    TransitionOptions
	reference  testing.TB
	provenance map[occurrenceOracleCut]occurrencePropertyProvenance
}

func occurrencePropertyFixtureFor(t testing.TB, p occurrenceOracleProgram) occurrencePropertyFixture {
	t.Helper()
	raw := elfBytes(p.code)
	binary.LittleEndian.PutUint64(raw[24:], p.pcs[p.entry])
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	f := occurrencePropertyFixture{program: p, image: im, digest: sha256.Sum256(raw), reference: t, provenance: map[occurrenceOracleCut]occurrencePropertyProvenance{}}
	f.limits = TransitionLimits{RelationLimits: RelationLimits{Instructions: 16384, Nodes: 262144, Work: 16_000_000, Depth: 512}, LiveStateBytes: 128 << 20}
	// The finite grammar's selector classes and outcome-independent maximum
	// path determine a discovery allowance. It is not passed as an entry fact.
	// A checked false frontier is still required at every truncated transfer.
	for selector := 0; selector <= p.maximum; selector++ {
		input := occurrenceOracleInitial(p, uint64(selector), 0)
		r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
		if err != nil {
			t.Fatal(err)
		}
		f.options.MaxOccurrences = max(f.options.MaxOccurrences, len(r.visits)+1)
	}
	return f
}

// Select optional forms from the intent's syntactic scope, independently of
// decoding or a proposed inventory. The call stack supplies actual RET edges;
// a visited static point closes search only, never an execution theorem.
func occurrencePropertyOptions(p occurrenceOracleProgram, start, cut int, maximum int, returns []int) TransitionOptions {
	o := TransitionOptions{MaxOccurrences: maximum}
	seen, selected := map[string]bool{}, map[int]bool{}
	var walk func(int, []int)
	walk = func(j int, stack []int) {
		if j == cut {
			return
		}
		key := fmt.Sprintf("%d/%v", j, stack)
		if seen[key] {
			return
		}
		seen[key] = true
		op := p.ops[j]
		if to.RequiresExpansion(op.intent) && !selected[j] {
			o.Expansions = append(o.Expansions, TransitionExpansion{PC: p.pcs[j], AllActivations: true})
			selected[j] = true
		}
		switch op.intent.Operation {
		case to.Call:
			walk(op.taken, append(slices.Clone(stack), op.next))
		case to.Return:
			if len(stack) != 0 {
				walk(stack[len(stack)-1], stack[:len(stack)-1])
			}
		case to.Branch:
			walk(op.next, stack)
			walk(op.taken, stack)
		default:
			walk(op.next, stack)
		}
	}
	walk(start, returns)
	return o
}

func (f occurrencePropertyFixture) root(t testing.TB, cut int) (TransitionCertificate, TransitionProposal) {
	t.Helper()
	p := f.program
	o := occurrencePropertyOptions(p, p.entry, cut, f.options.MaxOccurrences, nil)
	q, err := ProposeRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.pcs[cut], f.limits, o)
	if err != nil {
		t.Fatal("finite reference proposal", err)
	}
	c, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, q, f.limits)
	if err != nil {
		t.Fatal("finite reference-positive root", err)
	}
	return c, q
}

// Evaluate exactly the provided variable valuation. An unbound variable is an
// error even in an inactive branch; totalizations must have an owned origin.
func occurrencePropertyEval(ctx context.Context, term br.Term, values map[br.Term]uint64) (uint64, error) {
	seen := map[br.Term]bool{}
	stack := []br.Term{term}
	var assignments []br.Assignment
	edges := 0
	for len(stack) != 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !x.Valid() {
			return 0, errors.New("missing relation term")
		}
		if seen[x] {
			continue
		}
		seen[x] = true
		v := x.View()
		if v.Op == br.Variable {
			value, ok := values[x]
			if !ok {
				return 0, fmt.Errorf("unbound occurrence variable: %+v", v)
			}
			assignments = append(assignments, br.Assignment{Variable: x, Value: value})
		}
		edges += len(v.Args)
		stack = append(stack, v.Args...)
	}
	limits, ok := stateEvaluationLimits(len(seen), edges, len(assignments))
	if !ok {
		return 0, errors.New("reference evaluation allowance overflow")
	}
	return br.Eval(ctx, term, assignments, limits)
}

func occurrencePropertyInputs(ctx context.Context, p occurrenceOracleProgram, b TransitionBound, input occurrenceOracleInput) (map[br.Term]uint64, error) {
	if b.Geometry.root == nil || b.Geometry.root.origin != b.Origin || !reflect.DeepEqual(b.Geometry.root.face, p.face) || !reflect.DeepEqual(b.Interface, p.face) || b.Origin != b.InitialRegisters[RSP] || len(b.InitialMemory) != len(input.state.memory) || len(b.Words) != 0 || b.InitialFS.Valid() {
		return nil, errors.New("joint initial interface/domain differs")
	}
	values := map[br.Term]uint64{}
	seen := map[uint64]bool{}
	scope := b.Origin.View().Scope
	variable := func(term br.Term, sort br.Sort, value uint64) error {
		v := term.View()
		if !term.Valid() || v.Op != br.Variable || v.Sort != sort || !v.Scratch || v.Scope != scope || scope == (br.Scope{}) || seen[v.Immediate] || len(v.Args) != 0 {
			return errors.New("joint initial variable identity/sort differs")
		}
		seen[v.Immediate], values[term] = true, value
		return nil
	}
	for reg, term := range b.InitialRegisters {
		if err := variable(term, br.Bits(64), input.state.regs[reg]); err != nil {
			return nil, err
		}
	}
	direction := uint64(0)
	if input.state.direction {
		direction = 1
	}
	if err := variable(b.InitialDirection, br.Bool(), direction); err != nil {
		return nil, err
	}
	for reg, vector := range b.InitialVectors {
		for lane, term := range []br.Term{vector.Lo, vector.Hi} {
			if err := variable(term, br.Bits(64), input.vectors[reg][lane]); err != nil {
				return nil, err
			}
		}
	}
	for j, term := range []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF} {
		value := uint64(0)
		if []bool{input.state.flags[0], input.state.flags[1], input.state.flags[3] != input.state.flags[2]}[j] {
			value = 1
		}
		if err := variable(term, br.Bool(), value); err != nil {
			return nil, err
		}
	}
	bytes := map[stateLocation]bool{}
	for _, cell := range b.InitialMemory {
		key := stateByteLocation(cell)
		value, exists := input.state.memory[key]
		if !exists || bytes[key] || cell.Value.Sort() != br.Bits(8) || cell.Pointer != nil || cell.PointerLane != 0 {
			return nil, errors.New("joint initial byte keyset differs")
		}
		bytes[key] = true
		if !cell.isImage() && cell.offset >= 0 && cell.offset < 8 {
			actual, err := occurrencePropertyEval(ctx, cell.Value, nil)
			if err != nil || actual != uint64(value.value) {
				return nil, errors.New("protected input control byte differs")
			}
		} else if err := variable(cell.Value, br.Bits(8), uint64(value.value)); err != nil {
			return nil, err
		}
	}
	return values, nil
}

type occurrencePropertyProvenanceValue struct {
	address statePointer
	lineage occurrenceOracleLineage
	lane    uint8
}

type occurrencePropertyProvenance struct {
	registers [16]occurrencePropertyProvenanceValue
	memory    map[stateLocation]occurrencePropertyProvenanceValue
}

func occurrencePropertyReferenceProvenance(r occurrenceOracleResult) occurrencePropertyProvenance {
	p := occurrencePropertyProvenance{memory: map[stateLocation]occurrencePropertyProvenanceValue{}}
	for reg := range p.registers {
		p.registers[reg] = occurrencePropertyProvenanceValue{address: r.state.ptrs[reg], lineage: r.lineage[reg]}
	}
	for key, cell := range r.state.memory {
		v := occurrencePropertyProvenanceValue{address: cell.ptr, lineage: r.lineageBytes[key]}
		if cell.ptr.valid {
			v.lane = cell.lane
		} else if v.lineage.valid {
			v.lane = v.lineage.lane
		}
		p.memory[key] = v
	}
	return p
}

// Provenance depends on this grammar's actual selector classes and, for its
// early-exit variant, the first zero EAX response. Numeric data never creates a
// pointer: CAS and CPUID results are scalars regardless of their values. Run all
// these control classes and intersect their metadata, rather than requiring a
// conditional save's lineage merely because one concrete execution saved it.
// This cache contains reference metadata only, never a projected checker fact.
func (f occurrencePropertyFixture) commonProvenance(ctx context.Context, want occurrenceOracleResult) (occurrencePropertyProvenance, error) {
	cut := occurrenceOracleCut{instruction: -1}
	if !want.returned {
		cut = occurrenceOracleCut{instruction: want.boundary.instruction, encounter: 1}
		for _, visit := range want.visits {
			if visit.instruction == cut.instruction {
				cut.encounter++
			}
		}
	}
	if cached, ok := f.provenance[cut]; ok {
		return cached, nil
	}
	var common occurrencePropertyProvenance
	exits := 0
	if f.program.variant == occurrenceOracleEarlyQuery {
		exits = f.program.maximum
	}
	for selector := 0; selector <= f.program.maximum; selector++ {
		for exit := 0; exit <= exits; exit++ {
			input := occurrenceOracleInitial(f.program, uint64(selector), 0)
			if exit != 0 {
				input.state.outcomes[exit-1][0] = 0
			}
			var r occurrenceOracleResult
			var err error
			if want.returned {
				r, err = occurrenceOracleRun(f.reference, ctx, f.program, input, 2048)
			} else {
				r, err = occurrenceOracleRunTo(f.reference, ctx, f.program, input, 2048, &cut)
			}
			if err != nil {
				return common, fmt.Errorf("reference common-cut provenance: %w", err)
			}
			current := occurrencePropertyReferenceProvenance(r)
			if common.memory == nil {
				common = current
				continue
			}
			for reg, value := range current.registers {
				if value != common.registers[reg] {
					common.registers[reg] = occurrencePropertyProvenanceValue{}
				}
			}
			for key, value := range current.memory {
				if value != common.memory[key] {
					common.memory[key] = occurrencePropertyProvenanceValue{}
				}
			}
		}
	}
	f.provenance[cut] = common
	return common, nil
}

func occurrencePropertyPointer(owner TransitionCertificate, image *Image, origin br.Term, got TransitionPointer, lane uint8, want occurrencePropertyProvenanceValue, required bool) error {
	// Loop joins may conservatively forget an optional capability even when
	// the concrete control classes agree. Absence carries no ordered lanes.
	// Required coordinates (derived registers and the unconditional root save)
	// must retain their independently established metadata.
	if got == nil && !required {
		if lane != 0 {
			return errors.New("absent pointer retains an invented lane")
		}
		return nil
	}
	if lane != want.lane {
		return errors.New("ordered pointer lane differs")
	}
	if want.address.valid {
		if want.lineage.valid {
			return errors.New("reference confuses address capability with caller lineage")
		}
		pointer, ok := got.(AddressPointer)
		g := owner.checked.bound.Geometry
		if !ok || !g.ownsPointer(pointer) || pointer.isImage() != want.address.image || pointer.offset != want.address.off || g.Origin() != origin {
			return errors.New("owned address provenance differs")
		}
		if pointer.isImage() && (!sameImage(pointer.view.backing.geometry.image, image) || pointer.view.load != want.address.load) {
			return errors.New("owned image provenance differs")
		}
		return nil
	}
	if want.lineage.valid {
		register, ok := owner.EntryValueRegister(got)
		if !ok || register != want.lineage.register {
			return errors.New("owned caller-register lineage differs or is absent")
		}
		return nil
	}
	if got != nil {
		return errors.New("scalar or uncorrelated bytes acquired pointer provenance")
	}
	return nil
}

type occurrencePropertyPath struct {
	active      map[TransitionOccurrenceID]occurrenceOracleVisit
	ids         []TransitionOccurrenceID
	referenceID map[uint64]TransitionOccurrenceID
	boundary    TransitionOccurrenceID
}

type occurrencePropertyFrontierError struct {
	id   TransitionOccurrenceID
	pc   uint64
	step int
}

func (e *occurrencePropertyFrontierError) Error() string {
	return fmt.Sprintf("concrete step %d reaches supported frontier ID %d at %#x", e.step, e.id, e.pc)
}

func occurrencePropertyMap(p occurrenceOracleProgram, q TransitionProposal, want occurrenceOracleResult) (occurrencePropertyPath, error) {
	path := occurrencePropertyPath{active: map[TransitionOccurrenceID]occurrenceOracleVisit{}, referenceID: map[uint64]TransitionOccurrenceID{}}
	nodes := map[TransitionOccurrenceID]TransitionNode{}
	for _, n := range q.Nodes {
		if n.ID == 0 || nodes[n.ID].ID != 0 {
			return path, errors.New("witness ID absent or aliased")
		}
		nodes[n.ID] = n
	}
	id := q.Root
	for step, visit := range want.visits {
		n, exists := nodes[id]
		if exists && n.Frontier && n.PC == p.pcs[visit.instruction] && int(n.Size) == len(p.encoded[visit.instruction]) {
			return path, &occurrencePropertyFrontierError{id: id, pc: n.PC, step: step}
		}
		if !exists || n.Frontier || path.active[id].id != 0 || n.PC != p.pcs[visit.instruction] || int(n.Size) != len(p.encoded[visit.instruction]) {
			return path, fmt.Errorf("witness differs from concrete transfer at step %d: ID %d PC %#x frontier %t, expected intent PC %#x", step, id, n.PC, n.Frontier, p.pcs[visit.instruction])
		}
		path.active[id], path.referenceID[visit.id] = visit, id
		path.ids = append(path.ids, id)
		if want.returned && step == len(want.visits)-1 {
			if p.ops[visit.instruction].intent.Operation != to.Return || len(n.Successors) != 0 || n.PC != q.Cut {
				return path, errors.New("completed return did not consume exact retained cut")
			}
			return path, nil
		}
		slot := 0
		if visit.branchSlot >= 0 {
			slot = visit.branchSlot
			if len(n.Successors) != 2 {
				return path, errors.New("conditional successor slot missing")
			}
		} else if len(n.Successors) != 1 {
			return path, errors.New("concrete transfer successor missing")
		}
		id = n.Successors[slot]
	}
	boundary, exists := nodes[id]
	if !exists || path.active[id].id != 0 || boundary.PC != p.pcs[want.boundary.instruction] || len(boundary.Successors) != 0 {
		return path, errors.New("concrete cut mapping differs")
	}
	path.boundary, path.referenceID[want.boundary.id] = id, id
	return path, nil
}

// One joint assertion checks original access indices before filtering, exact
// occurrence guards before assigning outcomes, complete active slice order, and
// the whole state. Returning errors lets malformed detached projections exercise
// this same oracle rather than a weaker duplicate predicate.
func occurrencePropertyJoint(ctx context.Context, f occurrencePropertyFixture, owner TransitionCertificate, q TransitionProposal, b TransitionBound, input occurrenceOracleInput, want occurrenceOracleResult, complete bool, inactive uint32, overrides ...map[TransitionOccurrenceID][4]uint32) error {
	return occurrencePropertyJointObserved(ctx, f, owner, q, b, input, want, complete, inactive, nil, overrides...)
}

func occurrencePropertyJointObserved(ctx context.Context, f occurrencePropertyFixture, owner TransitionCertificate, q TransitionProposal, b TransitionBound, input occurrenceOracleInput, want occurrenceOracleResult, complete bool, inactive uint32, observed *occurrencePropertyObservation, overrides ...map[TransitionOccurrenceID][4]uint32) error {
	p := f.program
	if b.ImageDigest != f.digest || b.Rules != TransitionRules || !b.ConditionalRegion || b.Entry != p.pcs[p.entry] || len(b.Abstractions) != 0 {
		return errors.New("joint theorem scope differs")
	}
	mode := TransitionNumericFirstHit
	if q.After != 0 {
		mode = TransitionFirstAfter
	}
	if b.Endpoint.Mode != mode || b.Endpoint.Anchor != q.After || b.Endpoint.Cut != b.Boundary.ID {
		return errors.New("joint endpoint mode/anchor/exact cut differs")
	}
	path, err := occurrencePropertyMap(p, q, want)
	if err != nil {
		return err
	}
	values, err := occurrencePropertyInputs(ctx, p, b, input)
	if err != nil {
		return err
	}
	equal := func(term br.Term, sort br.Sort, expected uint64) error {
		if term.Sort() != sort {
			return errors.New("joint relation sort differs")
		}
		actual, err := occurrencePropertyEval(ctx, term, values)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("joint relation = %#x, expected %#x", actual, expected)
		}
		if observed != nil {
			observed.expected[term] = expected
		}
		return nil
	}
	if err := equal(b.EntryPredicate, br.Bool(), 1); err != nil {
		return fmt.Errorf("entry nonvacuity: %w", err)
	}
	nodes := map[TransitionOccurrenceID]TransitionNode{}
	static := map[uint64]int{}
	for j, pc := range p.pcs {
		static[pc] = j
	}
	for _, n := range q.Nodes {
		j, ok := static[n.PC]
		if !ok || int(n.Size) != len(p.encoded[j]) {
			return errors.New("witness bytes differ from intent encoding")
		}
		nodes[n.ID] = n
	}
	guards := map[TransitionOccurrenceID]GuardedInstruction{}
	members := map[TransitionOccurrenceID]bool{}
	for _, ins := range b.Instructions {
		n, exists := nodes[ins.ID]
		if !exists || members[ins.ID] || n.Frontier || ins.Start != n.PC || ins.End != n.PC+uint64(n.Size) {
			return errors.New("instruction exact-ID membership differs")
		}
		guards[ins.ID], members[ins.ID] = ins, true
	}
	for _, excluded := range b.ExcludedBoundaries {
		n, exists := nodes[excluded.ID]
		if !exists || members[excluded.ID] || n.PC != excluded.PC || n.Frontier != excluded.Frontier || len(n.Successors) != 0 || !slices.Equal(excluded.Bytes, p.encoded[static[n.PC]]) {
			return errors.New("excluded occurrence membership/frontier differs")
		}
		members[excluded.ID] = true
	}
	if !complete {
		if members[b.Boundary.ID] || b.Boundary.ID != path.boundary || b.Boundary.PC != p.pcs[want.boundary.instruction] || !slices.Equal(b.Boundary.Bytes, p.encoded[want.boundary.instruction]) {
			return errors.New("unexecuted exact boundary differs")
		}
		members[b.Boundary.ID] = true
	} else {
		last := want.visits[len(want.visits)-1]
		if b.Boundary.ID != path.ids[len(path.ids)-1] || b.Boundary.PC != p.pcs[last.instruction] || !slices.Equal(b.Boundary.Bytes, p.encoded[last.instruction]) {
			return errors.New("return consumed a different retained boundary occurrence")
		}
	}
	if len(members) != len(nodes) {
		return errors.New("joint occurrence inventory is not exact")
	}
	accesses := map[TransitionOccurrenceID][]int{}
	for j, a := range b.Accesses {
		ins, exists := guards[a.ID]
		if !exists || a.PC != ins.Start || a.Context != ins.Context {
			return errors.New("access lacks exact occurrence guard")
		}
		accesses[a.ID] = append(accesses[a.ID], j)
	}
	primitiveAt := map[TransitionOccurrenceID]int{}
	for j, effect := range b.PrimitiveEffects {
		var id TransitionOccurrenceID
		var pc uint64
		var activation TransitionActivationID
		read, write := -1, -1
		grouped := false
		var before, after br.Term
		switch e := effect.(type) {
		case CPUIDEffect:
			id, pc, activation = e.ID, e.PC, e.Context
		case LockedCompareExchangeEffect:
			id, pc, activation, read, write, before, after = e.ID, e.PC, e.Context, e.ReadAccess, e.WriteAccess, e.Before, e.After
			grouped = true
		case LockedLogicalEffect:
			id, pc, activation, read, write, before, after = e.ID, e.PC, e.Context, e.ReadAccess, e.WriteAccess, e.Before, e.After
			grouped = true
		default:
			return fmt.Errorf("unexpected joint primitive %T", effect)
		}
		ins, exists := guards[id]
		_, duplicate := primitiveAt[id]
		if !exists || duplicate || ins.Start != pc || ins.Context != activation {
			return errors.New("primitive lacks unique exact occurrence guard")
		}
		primitiveAt[id] = j
		if grouped {
			if read < 0 || write != read+1 || write >= len(b.Accesses) || len(accesses[id]) != 2 || accesses[id][0] != read || accesses[id][1] != write {
				return errors.New("original indivisible access indices differ")
			}
			r, w := b.Accesses[read], b.Accesses[write]
			if r.ID != id || w.ID != id || r.Kind != FrameRead || w.Kind != FrameWrite || r.Bytes != w.Bytes || r.Value != before || w.Value != after {
				return errors.New("indivisible access group lost exact identity/value")
			}
		}
	}
	scopes := map[br.Scope]bool{b.Origin.View().Scope: true}
	var activeIDs []TransitionOccurrenceID
	var activeAccesses, activePrimitives []int
	var events []occurrenceOracleEvent
	for _, ins := range b.Instructions {
		guard, err := occurrencePropertyEval(ctx, ins.Guard, values)
		if err != nil {
			return fmt.Errorf("guard before own/future outcomes: %w", err)
		}
		visit, active := path.active[ins.ID]
		if (guard == 1) != active || guard > 1 {
			return errors.New("occurrence guard differs from independent execution")
		}
		if observed != nil {
			observed.expected[ins.Guard] = guard
		}
		if active {
			contextID := TransitionActivationID(0)
			if visit.activation != 0 {
				contextID = TransitionActivationID(path.referenceID[visit.activation])
				if contextID == 0 {
					return errors.New("activation has no invoking occurrence")
				}
			}
			if ins.Context != contextID {
				return errors.New("instruction borrowed another CALL activation")
			}
			activeIDs = append(activeIDs, ins.ID)
			events = append(events, occurrenceOracleEvent{visit.id, "fetch", len(activeIDs) - 1})
		}
		for _, index := range accesses[ins.ID] {
			a := b.Accesses[index]
			if !active {
				continue
			}
			if len(activeAccesses) >= len(want.state.accesses) {
				return errors.New("extra active access")
			}
			w := want.state.accesses[len(activeAccesses)]
			kind, event := FrameRead, "read"
			if w.write {
				kind, event = FrameWrite, "write"
			} else if w.returnRead {
				kind, event = FrameReturnRead, "return-read"
			}
			if w.instruction != visit.instruction || a.Kind != kind || !b.Geometry.owns(a.Bytes.start) || a.Bytes.start.isImage() != w.off.image || extentCoordinates(a.Bytes) != (RelativeSpan{w.off.off, w.off.off + int64(w.width)}) {
				return errors.New("ordered active access differs")
			}
			if err := equal(a.Value, br.Bits(w.width*8), w.value); err != nil {
				return fmt.Errorf("access value: %w", err)
			}
			events = append(events, occurrenceOracleEvent{visit.id, event, len(activeAccesses)})
			activeAccesses = append(activeAccesses, index)
		}
		index, exists := primitiveAt[ins.ID]
		if !exists {
			continue
		}
		var reference statePrimitive
		if active {
			if len(activePrimitives) >= len(want.state.primitives) {
				return errors.New("extra active primitive")
			}
			reference = want.state.primitives[len(activePrimitives)]
		}
		switch e := b.PrimitiveEffects[index].(type) {
		case CPUIDEffect:
			leaf, err := occurrencePropertyEval(ctx, e.Leaf, values)
			if err != nil {
				return err
			}
			subleaf, err := occurrencePropertyEval(ctx, e.Subleaf, values)
			if err != nil || e.Leaf.Sort() != br.Bits(32) || e.Subleaf.Sort() != br.Bits(32) {
				return errors.New("query selectors missing or wrong width")
			}
			tuple := occurrencePropertyInactiveTuple(e.ID, inactive)
			if len(overrides) != 0 {
				if override, exists := overrides[0][e.ID]; exists {
					tuple = override
				}
			}
			if active {
				q, ok := reference.(stateQuery)
				if !ok || q.instruction != visit.instruction || leaf != uint64(q.leaf) || subleaf != uint64(q.subleaf) {
					return errors.New("query order/old selectors differ")
				}
				tuple = q.results
				if observed != nil {
					observed.expected[e.Leaf], observed.expected[e.Subleaf] = uint64(q.leaf), uint64(q.subleaf)
				}
			}
			scope := e.ResultsEAX.View().Scope
			if scopes[scope] || scope == (br.Scope{}) {
				return errors.New("query outcome occurrence scope reused")
			}
			scopes[scope] = true
			for lane, term := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
				v := term.View()
				if v.Op != br.Variable || v.Sort != br.Bits(32) || v.Scratch || v.Scope != scope || v.Immediate != uint64(lane) || len(v.Args) != 0 {
					return errors.New("query outcome shape/origin differs")
				}
				values[term] = uint64(tuple[lane])
			}
			if !active && observed != nil {
				observed.inactive = append(observed.inactive, occurrencePropertyInactiveQuery{e.ID, [4]br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX}})
			}
		case LockedCompareExchangeEffect:
			if active {
				w, ok := reference.(stateRMW)
				if !ok || w.kind != to.LockedCompareExchange || w.instruction != visit.instruction || e.Width != 4 {
					return errors.New("CAS32 occurrence/kind differs")
				}
				success := uint64(0)
				if w.success {
					success = 1
				}
				for j, term := range []br.Term{e.Before, e.Compare, e.Replacement, e.After, e.Accumulator, e.Success} {
					sort := br.Bits(32)
					if j == 4 {
						sort = br.Bits(64)
					} else if j == 5 {
						sort = br.Bool()
					}
					if err := equal(term, sort, []uint64{w.before, w.compare, w.replacement, w.after, w.accumulator, success}[j]); err != nil {
						return fmt.Errorf("CAS relation: %w", err)
					}
				}
			}
		case LockedLogicalEffect:
			if active {
				w, ok := reference.(stateRMW)
				kind := x86asm.AND
				if w.kind == to.LockedOr || w.kind == to.LockedOrImmediate {
					kind = x86asm.OR
				}
				if !ok || !stateLogical(w.kind) || w.instruction != visit.instruction || e.Width != 1 || e.Kind != kind {
					return errors.New("byte RMW occurrence/kind differs")
				}
				for j, term := range []br.Term{e.Before, e.Operand, e.After} {
					if err := equal(term, br.Bits(8), []uint64{w.before, w.replacement, w.after}[j]); err != nil {
						return err
					}
				}
			}
		}
		if active {
			events = append(events, occurrenceOracleEvent{visit.id, "primitive", len(activePrimitives)})
			activePrimitives = append(activePrimitives, index)
		}
	}
	if !slices.Equal(activeIDs, path.ids) || !slices.Equal(events, want.events) || len(activeAccesses) != len(want.state.accesses) || len(activePrimitives) != len(want.state.primitives) {
		return errors.New("complete interleaved active trace differs")
	}
	// Above grouping cannot repair a permuted original cumulative slice.
	if !slices.IsSorted(activeAccesses) || !slices.IsSorted(activePrimitives) {
		return errors.New("original active effect slice was reordered")
	}
	for _, excluded := range b.ExcludedBoundaries {
		if err := equal(excluded.Guard, br.Bool(), 0); err != nil {
			return fmt.Errorf("false residual/exclusion: %w", err)
		}
	}
	if err := equal(b.CutGuard, br.Bool(), 1); err != nil {
		return fmt.Errorf("complete cut: %w", err)
	}
	provenance, err := f.commonProvenance(ctx, want)
	if err != nil {
		return err
	}
	for reg, value := range b.Registers {
		if err := equal(value.Value, br.Bits(64), want.state.regs[reg]); err != nil {
			return fmt.Errorf("GPR%d: %w", reg, err)
		}
		if (input.state.regs[reg]^want.state.regs[reg])&b.Preserved[reg] != 0 {
			return errors.New("false GPR preservation")
		}
		written := want.state.writtenBits[reg]
		if want.state.written[reg] && written == 0 {
			written = ^uint64(0)
		}
		if written&b.Preserved[reg] != 0 {
			return fmt.Errorf("GPR%d claims independently written bits were never written", reg)
		}
		if err := occurrencePropertyPointer(owner, f.image, b.Origin, value.Pointer, 0, provenance.registers[reg], true); err != nil {
			return fmt.Errorf("GPR%d provenance: %w", reg, err)
		}
	}
	if b.Registers[RSP].Pointer != b.Geometry.stackPointer(int64(want.state.regs[RSP]-input.state.origin)) {
		return errors.New("current SP provenance differs")
	}
	for reg, vector := range b.Vectors {
		for lane, term := range []br.Term{vector.Lo, vector.Hi} {
			if err := equal(term, br.Bits(64), want.vectors[reg][lane]); err != nil {
				return fmt.Errorf("vector%d lane%d: %w", reg, lane, err)
			}
		}
	}
	if !b.SSE.MXCSRPreserved || !b.SSE.UpperVectorsPreserved {
		return errors.New("unchanged vector context lost")
	}
	if len(b.Memory) != len(want.state.memory) {
		return errors.New("residual memory extent differs")
	}
	seenBytes := map[stateLocation]bool{}
	for _, cell := range b.Memory {
		key := stateByteLocation(cell)
		w, exists := want.state.memory[key]
		if !exists || seenBytes[key] {
			return errors.New("residual memory keyset differs")
		}
		seenBytes[key] = true
		if err := equal(cell.Value, br.Bits(8), uint64(w.value)); err != nil {
			return fmt.Errorf("memory %+v: %w", key, err)
		}
		required := !cell.isImage() && cell.offset >= -8 && cell.offset < 0
		if err := occurrencePropertyPointer(owner, f.image, b.Origin, cell.Pointer, cell.PointerLane, provenance.memory[key], required); err != nil {
			return fmt.Errorf("byte %+v provenance: %w", key, err)
		}
	}
	defined, _ := want.state.flagStatus()
	for j, flag := range []TransitionFlag{b.Flags.CF, b.Flags.ZF, b.Flags.OF, b.Flags.SF, b.Flags.AF, b.Flags.PF} {
		// Definedness is a universal guarantee; one concrete execution cannot
		// require the joined theorem to expose a value it deliberately omits.
		// The projection contract permits defined flags without value terms.
		if flag.Defined && !defined[j] || !flag.Defined && flag.Value.Valid() || flag.Preserved && want.state.writer != 0 {
			return fmt.Errorf("flag%d definedness/preservation differs: %+v", j, flag)
		}
		if flag.Value.Valid() {
			value := uint64(0)
			if want.state.flags[j] {
				value = 1
			}
			if err := equal(flag.Value, br.Bool(), value); err != nil {
				return fmt.Errorf("flag%d: %w", j, err)
			}
		}
	}
	if len(b.Frames) != len(want.frames) {
		return errors.New("active frame count differs")
	}
	for j, frame := range b.Frames {
		w := want.frames[j]
		id := path.referenceID[w.activation]
		if frame.ID != id || frame.Context != TransitionActivationID(id) || frame.Call != p.pcs[w.call] || frame.Return != p.pcs[w.after] || frame.Slot != b.Geometry.stackPointer(int64(w.slot-input.state.origin)) {
			return errors.New("active frame occurrence/control slot differs")
		}
	}
	if !complete {
		activation := TransitionActivationID(path.referenceID[want.boundary.activation])
		if b.Boundary.Context != activation {
			return errors.New("cut activation differs")
		}
	}
	if observed != nil {
		observed.values = values
	}
	return nil
}

func occurrencePropertyReturned(b TransitionReturnBound) TransitionBound {
	x := b.Prefix
	x.Instructions, x.Accesses = b.Instructions, b.Accesses
	x.Registers, x.Memory, x.Preserved, x.Flags = b.State.Registers, b.State.Memory, b.State.Preserved, b.State.Flags
	x.Vectors, x.SSE, x.Thread = b.State.Vectors, b.State.SSE, b.State.Thread
	return x
}

func occurrencePropertyRequire(t testing.TB, f occurrencePropertyFixture, owner TransitionCertificate, q TransitionProposal, b TransitionBound, input occurrenceOracleInput, want occurrenceOracleResult, complete bool) {
	t.Helper()
	if err := occurrencePropertyCheck(t.Context(), f, owner, q, b, input, want, complete); err != nil {
		t.Fatal(err)
	}
}

func occurrencePropertyCheck(ctx context.Context, f occurrencePropertyFixture, owner TransitionCertificate, q TransitionProposal, b TransitionBound, input occurrenceOracleInput, want occurrenceOracleResult, complete bool) error {
	if err := occurrencePropertyJoint(ctx, f, owner, q, b, input, want, complete, 0); err != nil {
		return err
	}
	observed := occurrencePropertyObservation{expected: map[br.Term]uint64{}}
	if err := occurrencePropertyJointObserved(ctx, f, owner, q, b, input, want, complete, 0xa59137ef, &observed); err != nil {
		return err
	}
	return observed.perturb(ctx)
}

type occurrencePropertyInactiveQuery struct {
	id    TransitionOccurrenceID
	lanes [4]br.Term
}

type occurrencePropertyObservation struct {
	values   map[br.Term]uint64
	expected map[br.Term]uint64
	inactive []occurrencePropertyInactiveQuery
}

func (o occurrencePropertyObservation) perturb(ctx context.Context) error {
	// Independently perturb each inactive occurrence and each response lane,
	// holding every other lane at its occurrence-specific baseline. Coupled
	// totalizations alone can hide cross-occurrence cancellation dependencies.
	// The baseline already checked inventory, causal binding, and every observed
	// value against the independent reference. Only dependent expression roots
	// need re-evaluation: guards, active selectors/accesses/effects, cut reach and
	// complete final state. Inactive selectors may legitimately vary.
	parents := map[br.Term][]br.Term{}
	seen := map[br.Term]bool{}
	var stack []br.Term
	for term := range o.expected {
		stack = append(stack, term)
	}
	for len(stack) != 0 {
		term := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[term] {
			continue
		}
		seen[term] = true
		for _, arg := range term.View().Args {
			parents[arg] = append(parents[arg], term)
			stack = append(stack, arg)
		}
	}
	for _, query := range o.inactive {
		for lane, variable := range query.lanes {
			if err := ctx.Err(); err != nil {
				return err
			}
			old, bound := o.values[variable]
			if !bound {
				return errors.New("inactive perturbation lacks its owned variable assignment")
			}
			o.values[variable] = old ^ 0xffffffff
			queue, visited := []br.Term{variable}, map[br.Term]bool{}
			for len(queue) != 0 {
				term := queue[0]
				queue = queue[1:]
				if visited[term] {
					continue
				}
				visited[term] = true
				if expected, observed := o.expected[term]; observed {
					value, err := occurrencePropertyEval(ctx, term, o.values)
					if err != nil || value != expected {
						o.values[variable] = old
						return fmt.Errorf("inactive occurrence %d lane %d changes an observed relation: got %#x want %#x (%v)", query.id, lane, value, expected, err)
					}
				}
				queue = append(queue, parents[term]...)
			}
			o.values[variable] = old
		}
	}
	return nil
}

// Zero is the all-zero control. The second baseline is deterministic but varies
// independently with the full occurrence ID and lane; it is not a theorem about
// arbitrary outcomes. One-at-a-time lane perturbations provide separate controls.
func occurrencePropertyInactiveTuple(id TransitionOccurrenceID, seed uint32) (tuple [4]uint32) {
	if seed == 0 {
		return tuple
	}
	x := uint64(id) ^ uint64(seed)<<32
	for lane := range tuple {
		x += 0x9e3779b97f4a7c15
		z := (x ^ x>>30) * 0xbf58476d1ce4e5b9
		z = (z ^ z>>27) * 0x94d049bb133111eb
		tuple[lane] = uint32(z ^ z>>31)
	}
	return tuple
}

func TestTransitionOccurrenceJointWholeStateSensitivity(t *testing.T) {
	p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleQuery, 0, 3)
	f := occurrencePropertyFixtureFor(t, p)
	c, q := f.root(t, p.rootReturn)
	input := occurrenceOracleInitial(p, 0, 1)
	input.state.regs[R15] = input.state.origin + 16 // numeric coincidence grants no address capability
	cut := occurrenceOracleCut{p.rootReturn, 1}
	want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	occurrencePropertyRequire(t, f, c, q, b, input, want, false)
	if len(want.state.primitives) != 0 || !want.state.written[RBP] || want.state.regs[RBP] != input.state.regs[RBP] {
		t.Fatal("whole-state controls lack inactive queries and a restored written BP")
	}
	var queries []CPUIDEffect
	for _, effect := range b.PrimitiveEffects {
		if query, ok := effect.(CPUIDEffect); ok {
			queries = append(queries, query)
		}
	}
	if len(queries) < 2 {
		t.Fatal("cross-occurrence control needs two inactive outcomes")
	}
	for _, mode := range []string{"inactive-cross-XOR", "inactive-cross-masked", "register-image-pointer", "register-provenance-absent", "arbitrary-register-alias", "scratch-pointer-lane", "scratch-orphan-lane", "saved-lineage-absent", "saved-lineage-lane", "restored-register-mask"} {
		t.Run(mode, func(t *testing.T) {
			bad, _ := c.Bound()
			switch mode {
			case "inactive-cross-XOR", "inactive-cross-masked":
				builder := br.NewBuilder(5)
				difference, err := builder.Make(br.BitXor, br.Bits(32), 0, queries[0].ResultsEAX, queries[1].ResultsEAX)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "inactive-cross-masked" {
					// Hide the dependency from BOTH full baseline valuations. Only
					// an independent lane perturbation can decide this control.
					a := occurrencePropertyInactiveTuple(queries[0].ID, 0xa59137ef)
					b := occurrencePropertyInactiveTuple(queries[1].ID, 0xa59137ef)
					mask := ^(a[0] ^ b[0])
					if mask == 0 {
						t.Fatal("masked dependency control needs a nonempty hidden bit set")
					}
					constant, err := builder.Const(br.Bits(32), uint64(mask))
					if err != nil {
						t.Fatal(err)
					}
					difference, err = builder.Make(br.BitAnd, br.Bits(32), 0, difference, constant)
					if err != nil {
						t.Fatal(err)
					}
				}
				wide, err := builder.Make(br.ZExt, br.Bits(64), 0, difference)
				if err != nil {
					t.Fatal(err)
				}
				bad.Registers[RAX].Value, err = builder.Make(br.BitXor, br.Bits(64), 0, bad.Registers[RAX].Value, wide)
				if err != nil {
					t.Fatal(err)
				}
				if err := occurrencePropertyJoint(t.Context(), f, c, q, bad, input, want, false, 0); err != nil {
					t.Fatal("cross-occurrence cancellation control needs its coupled zero baseline", err)
				}
				if mode == "inactive-cross-masked" {
					if err := occurrencePropertyJoint(t.Context(), f, c, q, bad, input, want, false, 0xa59137ef); err != nil {
						t.Fatal("masked control must also survive the occurrence-specific baseline", err)
					}
				}
				for _, query := range queries[:2] {
					tuple := [4]uint32{0xffffffff, 0, 0, 0}
					if err := occurrencePropertyJoint(t.Context(), f, c, q, bad, input, want, false, 0, map[TransitionOccurrenceID][4]uint32{query.ID: tuple}); err == nil {
						t.Fatal("one-at-a-time inactive outcome failed to expose cross-occurrence dependency")
					}
				}
			case "register-image-pointer":
				bad.Registers[R14].Pointer = b.Geometry.imagePointer(0, input.state.origin)
			case "register-provenance-absent":
				bad.Registers[R14].Pointer = nil
			case "arbitrary-register-alias":
				bad.Registers[R15].Pointer = b.Geometry.stackPointer(16)
			case "scratch-pointer-lane", "scratch-orphan-lane", "saved-lineage-absent", "saved-lineage-lane":
				offset := int64(-24)
				if mode == "saved-lineage-absent" {
					offset = -8
				} else if mode == "saved-lineage-lane" {
					offset = -7
				}
				found := false
				for j := range bad.Memory {
					if !bad.Memory[j].isImage() && bad.Memory[j].offset == offset {
						switch mode {
						case "scratch-pointer-lane":
							bad.Memory[j].Pointer = b.Geometry.stackPointer(-24)
						case "scratch-orphan-lane":
							bad.Memory[j].PointerLane = 5
						case "saved-lineage-absent":
							bad.Memory[j].Pointer = nil
						case "saved-lineage-lane":
							bad.Memory[j].PointerLane = 0
						}
						found = true
					}
				}
				if !found {
					t.Fatal("scratch control location absent")
				}
			case "restored-register-mask":
				bad.Preserved[RBP] = ^uint64(0)
			}
			if err := occurrencePropertyCheck(t.Context(), f, c, q, bad, input, want, false); err == nil {
				t.Fatal("joint oracle accepted whole-state projection corruption")
			}
		})
	}
}

func TestTransitionOccurrenceJointPopulation(t *testing.T) {
	for placement := occurrenceOracleLocal; placement <= occurrenceOracleParentLoop; placement++ {
		for payload := occurrenceOracleCAS; payload <= occurrenceOracleQuery; payload++ {
			for layout := 0; layout < 2; layout++ {
				t.Run(fmt.Sprintf("placement%d/payload%d/layout%d", placement, payload, layout), func(t *testing.T) {
					p := occurrenceOracleBuild(t, placement, payload, layout, 3)
					f := occurrencePropertyFixtureFor(t, p)
					prefix, q := f.root(t, p.rootReturn)
					b, _ := prefix.Bound()
					returned, err := CheckTransitionReturn(t.Context(), prefix)
					if err != nil {
						t.Fatal(err)
					}
					rb, _ := returned.BoundFor(f.image)
					if !rb.State.CalleeTerminated || rb.State.PC != p.pcs[p.boundary] {
						t.Fatal("actual root RET incomplete")
					}
					for count := 0; count <= 3; count++ {
						for variant := 0; variant < 2; variant++ {
							input := occurrenceOracleInitial(p, uint64(count), variant)
							cut := occurrenceOracleCut{p.rootReturn, 1}
							before, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
							if err != nil {
								t.Fatal(err)
							}
							occurrencePropertyRequire(t, f, prefix, q, b, input, before, false)
							want, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
							if err != nil {
								t.Fatal(err)
							}
							occurrencePropertyRequire(t, f, prefix, q, occurrencePropertyReturned(rb), input, want, true)
						}
					}
				})
			}
		}
	}
}

func occurrencePropertyPrefixRetained(before, after TransitionCertificate) error {
	a, _ := before.Bound()
	b, _ := after.Bound()
	if a.InitialDirection != b.InitialDirection || a.Origin != b.Origin || a.InitialRegisters != b.InitialRegisters || a.InitialVectors != b.InitialVectors || a.InitialPredicates != b.InitialPredicates || a.EntryPredicate != b.EntryPredicate || !reflect.DeepEqual(a.InitialMemory, b.InitialMemory) || !reflect.DeepEqual(a.Interface, b.Interface) {
		return errors.New("continuation replaced original state identities/premises")
	}
	old := before.checked.witness
	nodes := map[TransitionOccurrenceID]TransitionNode{}
	for _, node := range after.checked.witness.Nodes {
		nodes[node.ID] = node
	}
	for _, node := range old.Nodes {
		if node.ID != a.Boundary.ID && !reflect.DeepEqual(nodes[node.ID], node) {
			return errors.New("continuation changed an executed prefix edge or exclusion")
		}
	}
	if len(b.PrimitiveEffects) < len(a.PrimitiveEffects) || !slices.Equal(a.PrimitiveEffects, b.PrimitiveEffects[:len(a.PrimitiveEffects)]) {
		return errors.New("continuation replaced primitive origins")
	}
	return nil
}

func occurrencePropertyContinue(t testing.TB, f occurrencePropertyFixture, prior TransitionCertificate, start, cut int, returns []int) (TransitionCertificate, TransitionProposal) {
	t.Helper()
	o := occurrencePropertyOptions(f.program, start, cut, f.options.MaxOccurrences, returns)
	q, err := ProposeTransitionContinuation(t.Context(), prior, f.program.pcs[cut], o)
	if err != nil {
		t.Fatal("finite continuation proposal", err)
	}
	next, err := CheckTransitionContinuation(t.Context(), prior, q)
	if err != nil {
		for selector := 0; selector <= 3; selector++ {
			input := occurrenceOracleInitial(f.program, uint64(selector), 1)
			stop := occurrenceOracleCut{cut, 1}
			want, referenceError := occurrenceOracleRunTo(t, t.Context(), f.program, input, 2048, &stop)
			if referenceError != nil {
				t.Logf("selector %d reference: %v", selector, referenceError)
			} else {
				_, mapError := occurrencePropertyMap(f.program, q, want)
				t.Logf("selector %d independent path mapping: %v", selector, mapError)
			}
		}
		t.Fatal("finite continuation", err)
	}
	if err := occurrencePropertyPrefixRetained(prior, next); err != nil {
		t.Fatal(err)
	}
	return next, q
}

func occurrencePropertyCheckReturn(t testing.TB, f occurrencePropertyFixture, prefix TransitionCertificate, inputs []occurrenceOracleInput) {
	t.Helper()
	c, err := CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.BoundFor(f.image)
	if !ok || !b.State.CalleeTerminated || b.State.PC != f.program.pcs[f.program.boundary] {
		t.Fatal("conditional return scope differs")
	}
	for _, input := range inputs {
		want, err := occurrenceOracleRun(t, t.Context(), f.program, input, 2048)
		if err != nil {
			t.Fatal(err)
		}
		occurrencePropertyRequire(t, f, prefix, prefix.checked.witness, occurrencePropertyReturned(b), input, want, true)
	}
	if _, err := c.InstructionAt(t.Context(), b.Prefix.Boundary.ID); err != nil {
		t.Fatal("exact retained return occurrence unavailable", err)
	}
}

func TestTransitionOccurrenceJointContinuations(t *testing.T) {
	for placement := occurrenceOracleLocal; placement <= occurrenceOracleParentLoop; placement++ {
		t.Run(fmt.Sprintf("placement%d", placement), func(t *testing.T) {
			p := occurrenceOracleBuild(t, placement, occurrenceOracleMixed, 1, 3)
			f := occurrencePropertyFixtureFor(t, p)
			start, returns := p.outerHeader, []int(nil)
			if placement == occurrenceOracleChildLoop {
				start, returns = p.childHeader, []int{p.ops[p.call].next}
			}
			prior, q := f.root(t, start)
			b, _ := prior.Bound()
			var inputs []occurrenceOracleInput
			for count := 0; count <= 3; count++ {
				input := occurrenceOracleInitial(p, uint64(count), 1)
				inputs = append(inputs, input)
				cut := occurrenceOracleCut{start, 1}
				want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
				if err != nil {
					t.Fatal(err)
				}
				occurrencePropertyRequire(t, f, prior, q, b, input, want, false)
			}
			next, _ := occurrencePropertyContinue(t, f, prior, start, p.rootReturn, returns)
			occurrencePropertyCheckReturn(t, f, next, inputs)
			beforeSibling, _ := next.Bound()
			sibling, _ := occurrencePropertyContinue(t, f, prior, start, p.rootReturn, returns)
			siblingBound, _ := sibling.Bound()
			scopes := map[br.Scope]bool{}
			for _, effect := range beforeSibling.PrimitiveEffects {
				if query, ok := effect.(CPUIDEffect); ok {
					scopes[query.ResultsEAX.View().Scope] = true
				}
			}
			for _, effect := range siblingBound.PrimitiveEffects {
				if query, ok := effect.(CPUIDEffect); ok && scopes[query.ResultsEAX.View().Scope] {
					t.Fatal("sibling continuations shared new query outcome ownership")
				}
			}
			afterSibling, _ := next.Bound()
			if !reflect.DeepEqual(beforeSibling, afterSibling) {
				t.Fatal("sibling construction mutated retained occurrence evidence")
			}
			_, err := ProposeTransitionContinuation(t.Context(), next, p.pcs[start])
			occurrencePropertyRefused(t, TransitionCertificate{}, err, "transition-continuation")
		})
	}
}

func TestTransitionOccurrenceJointCallApplication(t *testing.T) {
	occurrencePropertyApplication(t, occurrenceOracleChildLoop)
}

func TestTransitionOccurrenceJointSameSiteApplication(t *testing.T) {
	occurrencePropertyApplication(t, occurrenceOracleNested)
}

func occurrencePropertyApplication(t *testing.T, placement occurrenceOraclePlacement) {
	t.Helper()
	p := occurrenceOracleBuild(t, placement, occurrenceOracleMixed, 0, 3)
	f := occurrencePropertyFixtureFor(t, p)
	caller, _ := f.root(t, p.call)
	childEntry, childRET := p.ops[p.call].taken, -1
	for j, op := range p.ops {
		if op.intent.Operation == to.Return && j != p.rootReturn {
			childRET = j
		}
	}
	face := p.face
	face.Origin.Min -= 32
	face.Origin.Max -= 32
	face.Envelope.Start += 32
	face.Envelope.End += 32
	face.Regions = slices.Clone(p.face.Regions)
	for j := range face.Regions {
		face.Regions[j].Bytes.Start += 32
		face.Regions[j].Bytes.End += 32
	}
	face.ReturnContext = &TransitionReturnContext{Target: p.pcs[p.ops[p.call].next], Preserved: []Register{RBP}}
	o := occurrencePropertyOptions(p, childEntry, childRET, f.options.MaxOccurrences, nil)
	q, err := ProposeRegionTransition(t.Context(), f.image, p.pcs[childEntry], p.pcs[childRET], f.limits, o)
	if err != nil {
		t.Fatal(err)
	}
	child, err := CheckRegionTransition(t.Context(), f.image, p.pcs[childEntry], face, q, f.limits)
	if err != nil {
		t.Fatal("independent looping child", err)
	}
	returned, err := CheckTransitionReturn(t.Context(), child)
	if err != nil {
		t.Fatal(err)
	}
	application, err := CheckTransitionCallReturn(t.Context(), caller, returned)
	if err != nil {
		t.Fatal("actual-call loop theorem application", err)
	}
	bound, _ := application.Bound()
	if !application.AppliesTo(returned) || bound.ID != caller.checked.bound.Boundary.ID || bound.Activation != TransitionActivationID(bound.ID) || bound.StackShift != -32 {
		t.Fatal("application borrowed a different invoking occurrence")
	}
	successor, _ := application.Successor()
	var inputs []occurrenceOracleInput
	for count := 0; count <= 3; count++ {
		input := occurrenceOracleInitial(p, uint64(count), 1)
		if placement == occurrenceOracleNested {
			// Both invocations change current narrow memory. Reusing the first
			// invocation's input bytes or returned scratch cannot match the second.
			input.state.outcomes = [][4]uint32{{7, 17, 0x101, 11}, {99, 19, 0x202, 13}, {11, 23, 0x303, 17}, {17, 29, 0x404, 23}}
			if count&1 != 0 {
				input.state.outcomes = [][4]uint32{{0x80000000, 17, 0x101, 11}, {7, 19, 0x202, 0x80000000}, {0xffffffff, 23, 0x303, 13}, {0x80000000, 29, 0x404, 0x12345678}}
			}
		}
		inputs = append(inputs, input)
		for _, checkpoint := range []struct {
			cut int
			c   TransitionCertificate
		}{{childEntry, application.checked.entry}, {p.ops[p.call].next, successor}} {
			cut := occurrenceOracleCut{checkpoint.cut, 1}
			want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := checkpoint.c.Bound()
			occurrencePropertyRequire(t, f, checkpoint.c, checkpoint.c.checked.witness, b, input, want, false)
		}
	}
	// A valid standalone return theorem for another continuation cannot
	// borrow this invocation's actual CALL/control word.
	wrongFace := face
	wrongFace.ReturnContext = &TransitionReturnContext{Target: p.pcs[p.boundary], Preserved: []Register{RBP}}
	wrongChild, err := CheckRegionTransition(t.Context(), f.image, p.pcs[childEntry], wrongFace, q, f.limits)
	if err != nil {
		t.Fatal("alternate conditional-return positive control", err)
	}
	wrongReturn, err := CheckTransitionReturn(t.Context(), wrongChild)
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := CheckTransitionCallReturn(t.Context(), caller, wrongReturn)
	var refusal *Refusal
	if borrowed.checked != nil || !errors.As(err, &refusal) || refusal.Premise != "transition-application" || refusal.PC != p.pcs[p.call] || application.AppliesTo(wrongReturn) {
		t.Fatal("actual-call consumer borrowed another return continuation", err)
	}
	if placement == occurrenceOracleNested {
		direct, _ := f.root(t, p.rootReturn)
		occurrencePropertyCheckReturn(t, f, direct, inputs)
		_, err := ProposeTransitionContinuation(t.Context(), successor, p.pcs[p.call])
		occurrencePropertyRefused(t, TransitionCertificate{}, err, "transition-continuation")
		anchor, _ := successor.Bound()
		o := occurrencePropertyOptions(p, p.ops[p.call].next, p.call, f.options.MaxOccurrences, nil)
		nextCallProposal, err := ProposeNextTransitionContinuation(t.Context(), successor, p.pcs[p.call], o)
		if err != nil {
			t.Fatal("anchored repeated CALL proposal", err)
		}
		if nextCallProposal.After != anchor.Boundary.ID {
			t.Fatal("future CALL proposal did not bind its opaque predecessor boundary")
		}
		nextCaller, err := CheckTransitionContinuation(t.Context(), successor, nextCallProposal)
		if err != nil {
			t.Fatal("anchored repeated CALL", err)
		}
		if err := occurrencePropertyPrefixRetained(successor, nextCaller); err != nil {
			t.Fatal(err)
		}
		nextCall, _ := nextCaller.Bound()
		if nextCall.Endpoint.Mode != TransitionFirstAfter || nextCall.Endpoint.Anchor != anchor.Boundary.ID || nextCall.Boundary.PC != p.pcs[p.call] || nextCall.Boundary.ID == bound.ID {
			t.Fatal("repeated same-address CALL lost its new owned occurrence")
		}
		second, err := CheckTransitionCallReturn(t.Context(), nextCaller, returned)
		if err != nil {
			t.Fatal("second same-site theorem application", err)
		}
		secondBound, _ := second.Bound()
		if !second.AppliesTo(returned) || secondBound.ID != nextCall.Boundary.ID || secondBound.ID == bound.ID || secondBound.Activation == bound.Activation {
			t.Fatal("second application borrowed the first invocation identity")
		}
		secondSuccessor, _ := second.Successor()
		if err := occurrencePropertyPrefixRetained(successor, secondSuccessor); err != nil {
			t.Fatal(err)
		}
		for _, input := range inputs {
			for _, checkpoint := range []struct {
				cut int
				c   TransitionCertificate
			}{{p.call, nextCaller}, {childEntry, second.checked.entry}, {p.ops[p.call].next, secondSuccessor}} {
				stop := occurrenceOracleCut{checkpoint.cut, 2}
				want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &stop)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := checkpoint.c.Bound()
				occurrencePropertyRequire(t, f, checkpoint.c, checkpoint.c.checked.witness, b, input, want, false)
			}
		}
		badAnchor := occurrencePropertyCloneProposal(nextCallProposal)
		badAnchor.After = bound.ID // an earlier executed CALL is not the actual boundary
		bad, err := CheckTransitionContinuation(t.Context(), successor, badAnchor)
		occurrencePropertyRefused(t, bad, err, "transition-anchor")
		backIntoPrefix := occurrencePropertyCloneProposal(nextCallProposal)
		redirected := 0
		for j := range backIntoPrefix.Nodes {
			for slot, id := range backIntoPrefix.Nodes[j].Successors {
				if id == nextCall.Boundary.ID {
					// Same decoded target address, but an already executed CALL.
					backIntoPrefix.Nodes[j].Successors[slot] = bound.ID
					redirected++
				}
			}
		}
		if redirected == 0 {
			t.Fatal("future CALL lacks an incoming successor slot")
		}
		occurrencePropertyKeepReachable(&backIntoPrefix)
		bad, err = CheckTransitionContinuation(t.Context(), successor, backIntoPrefix)
		occurrencePropertyRefused(t, bad, err, "acyclic-control", "transition-cut")
		bad, err = CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, nextCallProposal, f.limits)
		occurrencePropertyRefused(t, bad, err, "transition-anchor")
		successor = secondSuccessor
	}
	next, _ := occurrencePropertyContinue(t, f, successor, p.ops[p.call].next, p.rootReturn, nil)
	occurrencePropertyCheckReturn(t, f, next, inputs)
}

func TestTransitionOccurrenceJointSupplements(t *testing.T) {
	for layout := 0; layout < 2; layout++ {
		for _, variant := range []occurrenceOracleVariant{occurrenceOracleEarlyQuery, occurrenceOracleResetQuery, occurrenceOracleCore} {
			t.Run(fmt.Sprintf("layout%d/variant%d", layout, variant), func(t *testing.T) {
				payload := occurrenceOracleQuery
				if variant == occurrenceOracleCore {
					payload = occurrenceOracleMixed
				}
				p := occurrenceOracleBuildVariant(t, occurrenceOracleLocal, payload, layout, 3, variant)
				f := occurrencePropertyFixtureFor(t, p)
				prefix, _ := f.root(t, p.rootReturn)
				var inputs []occurrenceOracleInput
				if variant == occurrenceOracleEarlyQuery {
					for exit := 0; exit <= 3; exit++ {
						input := occurrenceOracleInitial(p, 3, 0)
						if exit != 0 {
							input.state.outcomes[exit-1][0] = 0
						}
						inputs = append(inputs, input)
					}
				} else {
					for pattern := 0; pattern < 2; pattern++ {
						input := occurrenceOracleInitial(p, 3, pattern)
						if payload == occurrenceOracleMixed {
							input, _, _, _, _ = occurrenceOracleMixedInput(p, pattern)
						}
						inputs = append(inputs, input)
					}
				}
				occurrencePropertyCheckReturn(t, f, prefix, inputs)
				if len(prefix.checked.bound.ExcludedBoundaries) == 0 {
					t.Fatal("bounded supplemental proof omitted residual obligations")
				}
			})
		}
	}
}

// This is a bounded shape grammar, not arbitrary program verification: three
// placements, three payloads, two layouts, and the same actual selector code.
// Raw bytes jointly vary all unconstrained GPRs/memory and all vector lanes;
// outcomes vary independently. Only actual interface premises fix RSP/control.
func FuzzTransitionOccurrenceJoint(f *testing.F) {
	for _, seed := range []struct {
		shape    uint8
		selector uint64
	}{{0, 0}, {5, 3}, {11, ^uint64(0)}, {17, 2}} {
		f.Add(seed.shape, seed.selector, []byte{17, 31, 63, 127, 255}, []byte{1, 0x80, 37, 255}, []byte{7, 11, 13, 17, 19})
	}
	f.Fuzz(func(t *testing.T, shape uint8, selector uint64, raw, vectorBytes, outcomes []byte) {
		p := occurrenceOracleBuild(t, occurrenceOraclePlacement(shape%3), occurrenceOraclePayload(shape/3%3), int(shape/9%2), 3)
		fixture := occurrencePropertyFixtureFor(t, p)
		input := occurrenceOracleInitial(p, selector, 0)
		if len(raw) > 8+128+1+192 {
			raw = raw[:8+128+1+192]
		}
		input.state = stateRawInitial(p.face, raw)
		input.state.regs[RSI] = selector
		for lane := int64(0); lane < 8; lane++ {
			input.state.memory[stateLocation{off: lane}] = stateByte{value: byte(p.face.ReturnContext.Target >> (8 * lane))}
		}
		word := func(data []byte, offset, width int) uint64 {
			var bytes [8]byte
			if offset < len(data) {
				copy(bytes[:width], data[offset:])
			}
			return binary.LittleEndian.Uint64(bytes[:])
		}
		for reg := range input.vectors {
			for lane := range input.vectors[reg] {
				input.vectors[reg][lane] = word(vectorBytes, 16*reg+8*lane, 8)
			}
		}
		input.state.outcomes = make([][4]uint32, occurrenceOracleMaximum)
		for query := range input.state.outcomes {
			for lane := range input.state.outcomes[query] {
				input.state.outcomes[query][lane] = uint32(word(outcomes, 16*query+4*lane, 4))
			}
		}
		prefix, _ := fixture.root(t, p.rootReturn)
		occurrencePropertyCheckReturn(t, fixture, prefix, []occurrenceOracleInput{input})
	})
}

func occurrencePropertyCloneProposal(q TransitionProposal) TransitionProposal {
	q.Nodes = slices.Clone(q.Nodes)
	for j := range q.Nodes {
		q.Nodes[j].Successors = slices.Clone(q.Nodes[j].Successors)
	}
	return q
}

// A retargeting control may disconnect descendants. Remove those records so
// its intended progress/endpoint fault is not masked by an unrelated membership
// refusal. This changes untrusted negative input, never a reference execution.
func occurrencePropertyKeepReachable(q *TransitionProposal) {
	byID := map[TransitionOccurrenceID]TransitionNode{}
	for _, node := range q.Nodes {
		byID[node.ID] = node
	}
	queue, live := []TransitionOccurrenceID{q.Root}, map[TransitionOccurrenceID]bool{}
	for len(queue) != 0 {
		id := queue[0]
		queue = queue[1:]
		if live[id] {
			continue
		}
		live[id] = true
		queue = append(queue, byID[id].Successors...)
	}
	q.Nodes = slices.DeleteFunc(q.Nodes, func(node TransitionNode) bool { return !live[node.ID] })
}

func occurrencePropertyRefused(t testing.TB, c TransitionCertificate, err error, premises ...string) {
	t.Helper()
	var refusal *Refusal
	if c.checked != nil || !errors.As(err, &refusal) || !slices.Contains(premises, refusal.Premise) {
		t.Fatalf("wanted no certificate and %v, got %v", premises, err)
	}
}

func TestTransitionOccurrenceJointWitnessControls(t *testing.T) {
	p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleQuery, 0, 3)
	f := occurrencePropertyFixtureFor(t, p)
	good, q := f.root(t, p.rootReturn)
	b, _ := good.Bound()
	input := occurrenceOracleInitial(p, 3, 1)
	cut := occurrenceOracleCut{p.rootReturn, 1}
	want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
	if err != nil {
		t.Fatal(err)
	}
	occurrencePropertyRequire(t, f, good, q, b, input, want, false)
	frontiers := 0
	for _, excluded := range b.ExcludedBoundaries {
		if excluded.Frontier {
			frontiers++
		}
	}
	if frontiers == 0 {
		t.Fatal("positive loop has no checked false residual frontier")
	}
	for _, control := range []struct {
		name     string
		premises []string
		mutate   func(*TransitionProposal)
	}{
		{"missing-slot", []string{"transition-proposal", "graph-membership"}, func(q *TransitionProposal) {
			for j := range q.Nodes {
				if len(q.Nodes[j].Successors) == 2 {
					q.Nodes[j].Successors = q.Nodes[j].Successors[:1]
					return
				}
			}
		}},
		{"cycle", []string{"acyclic-control"}, func(q *TransitionProposal) {
			// Redirect an actual loop JMP to an ancestor at its actual decoded
			// target. A jump to entry would test target checking, not progress.
			byID := map[TransitionOccurrenceID]TransitionNode{}
			parents := map[TransitionOccurrenceID][]TransitionOccurrenceID{}
			for _, node := range q.Nodes {
				byID[node.ID] = node
				for _, next := range node.Successors {
					parents[next] = append(parents[next], node.ID)
				}
			}
			changed := false
			for j, node := range q.Nodes {
				if changed {
					break
				}
				for index, op := range p.ops {
					if op.name != "backedge" || p.pcs[index] != node.PC || len(node.Successors) != 1 {
						continue
					}
					queue, seen := slices.Clone(parents[node.ID]), map[TransitionOccurrenceID]bool{}
					for len(queue) != 0 {
						id := queue[0]
						queue = queue[1:]
						if seen[id] {
							continue
						}
						seen[id] = true
						if byID[id].PC == p.pcs[op.next] {
							q.Nodes[j].Successors[0] = id
							changed = true
							break
						}
						queue = append(queue, parents[id]...)
					}
				}
			}
			if !changed {
				t.Fatal("cycle control has no actual backedge ancestor")
			}
			// Remove only nodes the retargeting disconnected, isolating the
			// otherwise byte/edge-correct cycle from membership failures.
			occurrencePropertyKeepReachable(q)
		}},
		{"alias-ID", []string{"transition-proposal"}, func(q *TransitionProposal) { q.Nodes[1].ID = q.Root }},
		{"overlap", []string{"instruction-overlap"}, func(q *TransitionProposal) { q.Nodes[1].PC = q.Nodes[0].PC + 1 }},
		{"disconnected", []string{"graph-membership"}, func(q *TransitionProposal) {
			q.Nodes = append(q.Nodes, TransitionNode{ID: ^TransitionOccurrenceID(0), PC: p.pcs[p.rootReturn], Size: 1})
		}},
		{"swap-slots", []string{"transition-proposal"}, func(q *TransitionProposal) {
			for j := range q.Nodes {
				if len(q.Nodes[j].Successors) == 2 {
					slices.Reverse(q.Nodes[j].Successors)
					return
				}
			}
		}},
	} {
		t.Run(control.name, func(t *testing.T) {
			bad := occurrencePropertyCloneProposal(q)
			control.mutate(&bad)
			c, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, bad, f.limits)
			occurrencePropertyRefused(t, c, err, control.premises...)
		})
	}
	sparse := occurrencePropertyCloneProposal(q)
	remap := func(id TransitionOccurrenceID) TransitionOccurrenceID { return ^TransitionOccurrenceID(0) - id*97 }
	sparse.Root = remap(sparse.Root)
	for j := range sparse.Nodes {
		sparse.Nodes[j].ID = remap(sparse.Nodes[j].ID)
		for k, id := range sparse.Nodes[j].Successors {
			sparse.Nodes[j].Successors[k] = remap(id)
		}
	}
	slices.Reverse(sparse.Nodes)
	sc, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, sparse, f.limits)
	if err != nil {
		t.Fatal("sparse shuffled IDs are not ranks or array extents", err)
	}
	sb, _ := sc.Bound()
	occurrencePropertyRequire(t, f, sc, sparse, sb, input, want, false)
	o := occurrencePropertyOptions(p, p.entry, p.rootReturn, f.options.MaxOccurrences/2, nil)
	short, err := ProposeRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.pcs[p.rootReturn], f.limits, o)
	if err != nil {
		t.Fatal("feasible-frontier control must construct its witness", err)
	}
	_, mapError := occurrencePropertyMap(p, short, want)
	var reached *occurrencePropertyFrontierError
	if !errors.As(mapError, &reached) {
		t.Fatal("short witness lacks an independently reached residual frontier", mapError)
	}
	refused, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, short, f.limits)
	occurrencePropertyRefused(t, refused, err, "transition-frontier")
}

func TestTransitionOccurrenceJointCoincidentSlots(t *testing.T) {
	branch, err := to.Encode(to.Intent{Operation: to.Branch, Condition: 4}, to.Encoding{Form: to.JccNear})
	if err != nil {
		t.Fatal(err)
	}
	nop, err := to.Encode(to.Intent{Operation: to.NoOp}, to.Encoding{Form: to.NOP90})
	if err != nil {
		t.Fatal(err)
	}
	raw := elfBytes(append(branch, nop...))
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	cut := testEntry + uint64(len(branch))
	q := TransitionProposal{ImageDigest: sha256.Sum256(raw), Entry: testEntry, Cut: cut, Root: 41, Nodes: []TransitionNode{
		{ID: 41, PC: testEntry, Size: uint8(len(branch)), Successors: []TransitionOccurrenceID{7, 7}},
		{ID: 7, PC: cut, Size: uint8(len(nop))},
	}}
	face := TransitionInterface{Origin: OriginDomain{Min: 1 << 40, Max: (1 << 40) + 16, Modulus: 16}, Envelope: RelativeSpan{-8, 8}, Conditions: interfaceConditions()}
	c, err := CheckRegionTransition(t.Context(), im, testEntry, face, q, TransitionLimits{})
	if err != nil {
		t.Fatal("coincident-edge positive control", err)
	}
	b, _ := c.Bound()
	for _, zf := range []uint64{0, 1} {
		values := map[br.Term]uint64{b.InitialPredicates.CF: 0, b.InitialPredicates.ZF: zf, b.InitialPredicates.SFXorOF: 0}
		for reg, term := range b.InitialRegisters {
			values[term] = uint64(reg+1)*0x123456789abcdef ^ zf
		}
		values[b.Origin] = face.Origin.Min + 16*zf
		for reg, value := range b.Registers {
			actual, err := occurrencePropertyEval(t.Context(), value.Value, values)
			if err != nil || actual != values[b.InitialRegisters[reg]] {
				t.Fatal("coincident conditional changed register state", reg, err)
			}
		}
		if value, err := occurrencePropertyEval(t.Context(), b.CutGuard, values); err != nil || value != 1 {
			t.Fatal("coincident successor lost one incoming arm", err)
		}
	}
	q.Nodes[0].Successors = q.Nodes[0].Successors[:1]
	bad, err := CheckRegionTransition(t.Context(), im, testEntry, face, q, TransitionLimits{})
	occurrencePropertyRefused(t, bad, err, "transition-proposal")
}

func TestTransitionOccurrenceJointProjectionSensitivity(t *testing.T) {
	for _, payload := range []occurrenceOraclePayload{occurrenceOracleQuery, occurrenceOracleCAS, occurrenceOracleByte} {
		p := occurrenceOracleBuild(t, occurrenceOracleLocal, payload, 0, 3)
		f := occurrencePropertyFixtureFor(t, p)
		c, q := f.root(t, p.rootReturn)
		input := occurrenceOracleInitial(p, 3, 0)
		cut := occurrenceOracleCut{p.rootReturn, 1}
		want, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
		if err != nil {
			t.Fatal(err)
		}
		baseline, _ := c.Bound()
		occurrencePropertyRequire(t, f, c, q, baseline, input, want, false)
		path, err := occurrencePropertyMap(p, q, want)
		if err != nil {
			t.Fatal(err)
		}
		activePrimitive := []int{}
		for index, effect := range baseline.PrimitiveEffects {
			var id TransitionOccurrenceID
			switch e := effect.(type) {
			case CPUIDEffect:
				id = e.ID
			case LockedCompareExchangeEffect:
				id = e.ID
			case LockedLogicalEffect:
				id = e.ID
			}
			if path.active[id].id != 0 {
				activePrimitive = append(activePrimitive, index)
			}
		}
		modes := []string{"primitive-order", "access-owner", "guard", "effect-ID", "outcome-or-write"}
		if payload == occurrenceOracleQuery {
			modes = append(modes, "own-outcome-guard", "future-selector")
		} else {
			modes = append(modes, "missing-group")
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("payload%d/%s", payload, mode), func(t *testing.T) {
				bad, _ := c.Bound()
				switch mode {
				case "primitive-order":
					a, b := activePrimitive[0], activePrimitive[1]
					bad.PrimitiveEffects[a], bad.PrimitiveEffects[b] = bad.PrimitiveEffects[b], bad.PrimitiveEffects[a]
				case "access-owner":
					// Keep PC/context/value untouched: only exact ownership moves.
					bad.Accesses[0].ID = bad.Boundary.ID
				case "guard":
					for j := range bad.Instructions {
						if path.active[bad.Instructions[j].ID].id != 0 {
							bad.Instructions[j].Guard, _ = br.NewBuilder(1).Const(br.Bool(), 0)
							break
						}
					}
				case "effect-ID":
					index := activePrimitive[1]
					switch e := bad.PrimitiveEffects[index].(type) {
					case CPUIDEffect:
						e.ID = bad.PrimitiveEffects[activePrimitive[0]].(CPUIDEffect).ID
						bad.PrimitiveEffects[index] = e
					case LockedCompareExchangeEffect:
						e.ID = bad.PrimitiveEffects[activePrimitive[0]].(LockedCompareExchangeEffect).ID
						bad.PrimitiveEffects[index] = e
					case LockedLogicalEffect:
						e.ID = bad.PrimitiveEffects[activePrimitive[0]].(LockedLogicalEffect).ID
						bad.PrimitiveEffects[index] = e
					}
				case "outcome-or-write":
					index := activePrimitive[1]
					if payload == occurrenceOracleByte {
						index = activePrimitive[2] // OR 0's unchanged write is still an effect.
					}
					switch e := bad.PrimitiveEffects[index].(type) {
					case CPUIDEffect:
						first := bad.PrimitiveEffects[activePrimitive[0]].(CPUIDEffect)
						e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX = first.ResultsEAX, first.ResultsEBX, first.ResultsECX, first.ResultsEDX
						bad.PrimitiveEffects[index] = e
					case LockedCompareExchangeEffect:
						bad.Accesses = append(bad.Accesses[:e.WriteAccess], bad.Accesses[e.WriteAccess+1:]...)
					case LockedLogicalEffect:
						bad.Accesses = append(bad.Accesses[:e.WriteAccess], bad.Accesses[e.WriteAccess+1:]...)
					}
				case "own-outcome-guard":
					effect := bad.PrimitiveEffects[activePrimitive[0]].(CPUIDEffect)
					guard, err := br.NewBuilder(1).Make(br.Nonzero, br.Bool(), 0, effect.ResultsEAX)
					if err != nil {
						t.Fatal(err)
					}
					for j := range bad.Instructions {
						if bad.Instructions[j].ID == effect.ID {
							bad.Instructions[j].Guard = guard
						}
					}
				case "future-selector":
					first := bad.PrimitiveEffects[activePrimitive[0]].(CPUIDEffect)
					second := bad.PrimitiveEffects[activePrimitive[1]].(CPUIDEffect)
					first.Leaf = second.ResultsEAX
					bad.PrimitiveEffects[activePrimitive[0]] = first
				case "missing-group":
					index := activePrimitive[0]
					switch e := bad.PrimitiveEffects[index].(type) {
					case LockedCompareExchangeEffect:
						e.ReadAccess, e.WriteAccess = -1, -1
						bad.PrimitiveEffects[index] = e
					case LockedLogicalEffect:
						e.ReadAccess, e.WriteAccess = -1, -1
						bad.PrimitiveEffects[index] = e
					}
				}
				if !reflect.DeepEqual(bad.Registers, baseline.Registers) || !reflect.DeepEqual(bad.Memory, baseline.Memory) {
					t.Fatal("trace control accidentally changed final state")
				}
				if err := occurrencePropertyJoint(t.Context(), f, c, q, bad, input, want, false, 0); err == nil {
					t.Fatal("joint oracle accepted malformed detached projection")
				}
			})
		}
		unchanged, _ := c.Bound()
		if !reflect.DeepEqual(unchanged, baseline) {
			t.Fatal("projection control mutated retained certificate")
		}
		unknown, err := br.NewBuilder(1).Input(br.Bits(64), br.NewScope(), 0)
		if err != nil {
			t.Fatal(err)
		}
		bad, _ := c.Bound()
		bad.Registers[R15].Value = unknown
		if err := occurrencePropertyJoint(t.Context(), f, c, q, bad, input, want, false, 0); err == nil {
			t.Fatal("joint oracle supplied a value for an unowned symbolic input")
		}
		if payload == occurrenceOracleQuery {
			returned, err := CheckTransitionReturn(t.Context(), c)
			if err != nil {
				t.Fatal(err)
			}
			projection, _ := returned.Bound()
			complete, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
			if err != nil {
				t.Fatal(err)
			}
			b := occurrencePropertyReturned(projection)
			occurrencePropertyRequire(t, f, c, q, b, input, complete, true)
			b.Boundary.ID = b.Instructions[0].ID
			if err := occurrencePropertyJoint(t.Context(), f, c, q, b, input, complete, true, 0); err == nil {
				t.Fatal("joint return oracle accepted a borrowed retained return identity")
			}
		}
	}
}

func TestTransitionOccurrenceJointOwnershipAndResources(t *testing.T) {
	p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleQuery, 0, 3)
	f := occurrencePropertyFixtureFor(t, p)
	c, q := f.root(t, p.rootReturn)
	before, _ := c.Bound()
	other, err := NewImage(t.Context(), slices.Clone(f.image.data))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.BoundFor(other); ok {
		t.Fatal("equal-byte owner borrowed occurrence evidence")
	}
	for _, ins := range before.Instructions {
		if _, err := c.InstructionAt(t.Context(), ins.ID); err != nil {
			t.Fatal("owned exact occurrence unavailable", err)
		}
	}
	if _, err := c.InstructionAt(t.Context(), before.Boundary.ID); err == nil {
		t.Fatal("unexecuted boundary acquired execution authority")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	stopped, err := CheckRegionTransition(ctx, f.image, p.pcs[p.entry], p.face, q, f.limits)
	if stopped.checked != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled construction supplied evidence or wrong refusal", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	callback := &imageCallbackContext{Context: ctx, onErr: func(n int) {
		if n == 16 {
			cancel()
		}
	}}
	stopped, err = CheckRegionTransition(callback, f.image, p.pcs[p.entry], p.face, q, f.limits)
	cancel()
	if callback.calls < 16 || stopped.checked != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("mid-construction cancellation lost its cause or published evidence", err)
	}
	limits := f.limits
	limits.Work = 1
	limited, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, q, limits)
	occurrencePropertyRefused(t, limited, err, "relation-budget")
	parent, prefix := f.root(t, p.outerHeader)
	limits.Work = parent.checked.work + 16
	bounded, err := CheckRegionTransition(t.Context(), f.image, p.pcs[p.entry], p.face, prefix, limits)
	if err != nil {
		t.Fatal("cumulative control did not admit its prefix", err)
	}
	old, _ := bounded.Bound()
	o := occurrencePropertyOptions(p, p.outerHeader, p.rootReturn, f.options.MaxOccurrences, nil)
	proposal, err := ProposeTransitionContinuation(t.Context(), bounded, p.pcs[p.rootReturn], o)
	var result TransitionCertificate
	if err == nil {
		result, err = CheckTransitionContinuation(t.Context(), bounded, proposal)
	}
	occurrencePropertyRefused(t, result, err, "relation-budget", "transition-budget")
	after, _ := bounded.Bound()
	if !reflect.DeepEqual(after, old) {
		t.Fatal("exhaustion mutated predecessor")
	}
	q.Nodes[0].ID = 0
	projection, _ := c.Bound()
	projection.Instructions[0].ID = 0
	after, _ = c.Bound()
	if !reflect.DeepEqual(after, before) {
		t.Fatal("proposal/projection mutation changed owned occurrence evidence")
	}
}
