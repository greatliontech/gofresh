package nativeproof

import (
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

// This finite grammar crosses 4 stack deltas, 2 frame sizes, 2 incoming-memory
// histories and 3 BP provenance classes: 48 independently checked applications.
// Each runs 8 concrete valuations (both branch arms at four admissible origins),
// for 384 joint cases. It covers no loops, primitives, vector state or source
// correspondence. Reference execution below uses byte memory and uint64 values;
// it never decodes checker operations or evaluates a checker term for an answer.
type applicationPopulation struct {
	delta, frame int
	seeded       bool
	bp           int // arbitrary lineage, derived stack pointer, owned image pointer
}

type applicationPopulationProgram struct {
	im                      *Image
	parent, child           TransitionInterface
	call, childRet, rootRet uint64
	pc                      map[string]uint64
}

func applicationPopulationBuild(t testing.TB, p applicationPopulation) applicationPopulationProgram {
	t.Helper()
	const child = testEntry + 128
	const returned = testEntry + 256
	code := []byte{}
	pcs := map[string]uint64{}
	emit := func(name string, bytes ...byte) {
		pcs[name] = testEntry + uint64(len(code))
		code = append(code, bytes...)
	}
	if p.bp == 1 {
		emit("pointer", 0x48, 0x8d, 0x6c, 0x24, 24) // LEA BP,[original SP+24]
	}
	if p.seeded {
		emit("seed", 0x48, 0x89, 0x7c, 0x24, byte(-p.delta-24)) // child Words[-16]
	}
	emit("adjust", 0x48, 0x8d, 0x64, 0x24, byte(-p.delta))
	emit("call", 0xe8, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], uint32(child-pcs["call"]-5))
	emit("released-word", 0x4c, 0x8b, 0x4c, 0x24, byte(-p.frame-16)) // R9
	emit("released-byte", 0x44, 0x8a, 0x54, 0x24, byte(-p.frame-8))  // R10B
	emit("restore", 0x48, 0x8d, 0x64, 0x24, byte(p.delta))
	emit("parent-ret", 0xc3)
	for len(code) < 128 {
		code = append(code, 0x90)
	}
	emit("save", 0x55)
	emit("frame", 0x48, 0x89, 0xe5)
	emit("allocate", 0x48, 0x83, 0xec, byte(p.frame))
	emit("input", 0x48, 0x8b, 0x54, 0x24, byte(p.frame-8)) // RDX = child [-16:-8]
	emit("compare", 0x83, 0xf8, 0)                         // CMP EAX,0: both arms feasible
	emit("branch", 0x74, 0)
	branch := len(code) - 1
	emit("nonzero-word", 0x48, 0x89, 0x14, 0x24) // [SP] = RDX
	emit("nonzero-byte", 0xc6, 0x44, 0x24, 8, 0xa5)
	emit("join-jump", 0xeb, 0)
	jump := len(code) - 1
	code[branch] = byte(len(code) - branch - 1)
	emit("zero-word", 0x48, 0x89, 0x1c, 0x24) // [SP] = RBX
	emit("zero-byte", 0xc6, 0x44, 0x24, 8, 0x5a)
	code[jump] = byte(len(code) - jump - 1)
	emit("result", 0x4c, 0x8b, 0x04, 0x24) // R8 = selected residual word
	emit("deallocate", 0x48, 0x83, 0xc4, byte(p.frame))
	emit("pop", 0x5d)
	emit("child-ret", 0xc3)
	for len(code) < 256 {
		code = append(code, 0x90)
	}
	code = append(code, 0xbb, 7, 0, 0, 0) // actual parent continuation, unexecuted
	im, err := NewImage(t.Context(), transitionImageELF(t, code, imageStateLoads()))
	if err != nil {
		t.Fatal(err)
	}
	modulus := uint64(16 << (p.delta / 16))
	residue := uint64(0)
	if p.frame == 32 {
		residue = 8
	}
	minimum := uint64(65536) + residue
	shift := int64(-p.delta - 8)
	privateStart := shift - int64(p.frame) - 8
	parent := TransitionInterface{
		Origin:     OriginDomain{Min: minimum - 3, Max: minimum + 3*modulus + 5, Modulus: modulus, Residue: residue},
		Envelope:   RelativeSpan{-128, 32},
		Regions:    []RelativeRegion{{Bytes: RelativeSpan{-128, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 32}, Readable: true}},
		Conditions: interfaceConditions(), ReturnContext: &TransitionReturnContext{Target: returned, Preserved: []Register{RSI, RDI, RBX}},
		PrivateFrame: &TransitionPrivateFrame{Bytes: RelativeSpan{privateStart, shift}},
	}
	if p.bp == 2 {
		parent.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 8}}
		parent.EntryImagePointers = []TransitionEntryImagePointer{{Register: RBP, Address: imageStateAddress}}
	}
	childFace := TransitionInterface{
		Origin:     OriginDomain{Min: uint64(int64(parent.Origin.Min) + shift), Max: uint64(int64(parent.Origin.Max) + shift), Modulus: modulus, Residue: (residue + uint64(shift)) & (modulus - 1)},
		Envelope:   RelativeSpan{-int64(p.frame) - 8, 8},
		Regions:    []RelativeRegion{{Bytes: RelativeSpan{-int64(p.frame) - 8, 0}, Readable: true, Writable: true}, {Bytes: RelativeSpan{0, 8}, Readable: true}},
		Conditions: interfaceConditions(), ReturnContext: &TransitionReturnContext{Target: pcs["call"] + 5, Preserved: []Register{RBP, RSI, RDI, RBX}},
		PrivateFrame: &TransitionPrivateFrame{Bytes: RelativeSpan{-int64(p.frame) - 8, 0}}, Words: []int64{-16},
	}
	return applicationPopulationProgram{im: im, parent: parent, child: childFace, call: pcs["call"], childRet: pcs["child-ret"], rootRet: pcs["parent-ret"], pc: pcs}
}

type applicationConcreteAccess struct {
	pc      uint64
	context TransitionActivationID
	kind    AccessKind
	span    RelativeSpan
	value   uint64
}

type applicationConcreteState struct {
	regs   [16]uint64
	bytes  map[stateLocation]byte
	access []applicationConcreteAccess
}

func (s applicationConcreteState) clone() applicationConcreteState {
	s.bytes = maps.Clone(s.bytes)
	s.access = slices.Clone(s.access)
	return s
}

func (s *applicationConcreteState) load(pc uint64, context TransitionActivationID, offset int64, width int, kind AccessKind) uint64 {
	var value uint64
	for lane := 0; lane < width; lane++ {
		value |= uint64(s.bytes[stateLocation{off: offset + int64(lane)}]) << (8 * lane)
	}
	s.access = append(s.access, applicationConcreteAccess{pc, context, kind, RelativeSpan{offset, offset + int64(width)}, value})
	return value
}

func (s *applicationConcreteState) store(pc uint64, context TransitionActivationID, offset int64, width int, value uint64) {
	for lane := 0; lane < width; lane++ {
		s.bytes[stateLocation{off: offset + int64(lane)}] = byte(value >> (8 * lane))
	}
	s.access = append(s.access, applicationConcreteAccess{pc, context, FrameWrite, RelativeSpan{offset, offset + int64(width)}, value})
}

// The oracle is the grammar's imperative contract, independent of symbolic
// transfer, provenance, guarded-join machinery and native instruction decoding.
func applicationConcreteRun(p applicationPopulation, code applicationPopulationProgram, initial applicationConcreteState, activation TransitionActivationID) (entry, returned, completed applicationConcreteState) {
	s := initial.clone()
	base := s.regs[RSP]
	if p.bp == 1 {
		s.regs[RBP] = base + 24
	}
	if p.seeded {
		s.store(code.pc["seed"], 0, int64(-p.delta-24), 8, s.regs[RDI])
	}
	s.regs[RSP] -= uint64(p.delta)
	childSP := int64(-p.delta - 8)
	s.regs[RSP] -= 8
	s.store(code.call, 0, childSP, 8, code.call+5)
	entry = s.clone()
	s.regs[RSP] -= 8
	s.store(code.pc["save"], activation, childSP-8, 8, s.regs[RBP])
	s.regs[RBP] = s.regs[RSP]
	s.regs[RSP] -= uint64(p.frame)
	s.regs[RDX] = s.load(code.pc["input"], activation, childSP-16, 8, FrameRead)
	local := childSP - 8 - int64(p.frame)
	word, octet, arm := s.regs[RDX], uint64(0xa5), "nonzero"
	if uint32(s.regs[RAX]) == 0 {
		word, octet, arm = s.regs[RBX], 0x5a, "zero"
	}
	s.store(code.pc[arm+"-word"], activation, local, 8, word)
	s.store(code.pc[arm+"-byte"], activation, local+8, 1, octet)
	s.regs[R8] = s.load(code.pc["result"], activation, local, 8, FrameRead)
	s.regs[RSP] += uint64(p.frame)
	s.regs[RBP] = s.load(code.pc["pop"], activation, childSP-8, 8, FrameRead)
	s.regs[RSP] += 8
	s.load(code.childRet, activation, childSP, 8, FrameReturnRead)
	s.regs[RSP] += 8
	returned = s.clone()
	s.regs[R9] = s.load(code.pc["released-word"], 0, local, 8, FrameRead)
	low := s.load(code.pc["released-byte"], 0, local+8, 1, FrameRead)
	s.regs[R10] = s.regs[R10]&^255 | low
	s.regs[RSP] += uint64(p.delta)
	s.load(code.rootRet, 0, 0, 8, FrameReturnRead)
	s.regs[RSP] += 8
	return entry, returned, s
}

func applicationPopulationInputs(t testing.TB, b TransitionBound, p applicationPopulation, ordinal, arm int) (map[br.Term]uint64, applicationConcreteState) {
	t.Helper()
	base := uint64(65536) + b.Interface.Origin.Residue + uint64(ordinal)*b.Interface.Origin.Modulus
	state := applicationConcreteState{bytes: make(map[stateLocation]byte)}
	values := make(map[br.Term]uint64)
	for r := range state.regs {
		state.regs[r] = uint64(r+1)*0x9e3779b97f4a7c15 ^ uint64(ordinal+1)*0x13579bdf2468ace0
	}
	// Numeric aliases are deliberately ordinary scalars. They cannot manufacture
	// provenance, including values equal to incoming/saved control addresses.
	aliases := []uint64{base, base - uint64(p.delta) - 8, imageStateAddress, ^uint64(0)}
	state.regs[RSP], state.regs[RBP], state.regs[RDI], state.regs[RBX] = base, aliases[ordinal], aliases[(ordinal+1)%4], aliases[(ordinal+2)%4]
	state.regs[RAX] = uint64(ordinal)<<32 | uint64(arm)
	if p.bp == 2 {
		state.regs[RBP] = imageStateAddress
	}
	for r, input := range b.InitialRegisters {
		values[input] = state.regs[r]
	}
	for j, input := range []br.Term{b.InitialPredicates.CF, b.InitialPredicates.ZF, b.InitialPredicates.SFXorOF} {
		values[input] = uint64((ordinal + j) & 1)
	}
	for _, input := range b.InitialMemory {
		value := byte(uint64(input.offset)*73 + uint64(ordinal*41+arm*19+17))
		if !input.isImage() && input.offset >= 0 && input.offset < 8 {
			value = byte((testEntry + 256) >> (8 * uint(input.offset)))
		} else if input.Value.View().Op == br.Variable {
			values[input.Value] = uint64(value)
		} else {
			t.Fatal("grammar's arbitrary incoming byte was unexpectedly constrained")
		}
		state.bytes[stateByteLocation(input)] = value
	}
	if stateEval(t, b.EntryPredicate, values) != 1 {
		t.Fatal("generated valuation violates parent entry relation")
	}
	return values, state
}

func applicationPopulationAssert(t testing.TB, registers [16]TransitionValue, memory []TransitionByte, instructions []GuardedInstruction, accesses []TransitionAccess, values map[br.Term]uint64, want applicationConcreteState) {
	t.Helper()
	for r, v := range registers {
		if got := stateEval(t, v.Value, values); got != want.regs[r] {
			t.Fatalf("register %d = %#x, want %#x", r, got, want.regs[r])
		}
	}
	if len(memory) != len(want.bytes) {
		t.Fatalf("retained memory has %d bytes, want %d", len(memory), len(want.bytes))
	}
	for _, v := range memory {
		if got := stateEval(t, v.Value, values); got != uint64(want.bytes[stateByteLocation(v)]) {
			t.Fatalf("byte %+v = %#x, want %#x", v.TransitionLocation, got, want.bytes[stateByteLocation(v)])
		}
	}
	guards := make(map[TransitionOccurrenceID]bool)
	for _, ins := range instructions {
		guards[ins.ID] = stateEval(t, ins.Guard, values) == 1
	}
	var actual []applicationConcreteAccess
	for _, access := range accesses {
		active, exists := guards[access.ID]
		if !exists {
			t.Fatal("access lost its occurrence guard")
		}
		if active {
			if access.Bytes.start.isImage() {
				t.Fatal("grammar unexpectedly accessed image memory")
			}
			actual = append(actual, applicationConcreteAccess{access.PC, access.Context, access.Kind, extentCoordinates(access.Bytes), stateEval(t, access.Value, values)})
		}
	}
	if !slices.Equal(actual, want.access) {
		t.Fatalf("ordered accesses differ\ngot  %+v\nwant %+v", actual, want.access)
	}
}

func TestTransitionApplicationJointPopulation(t *testing.T) {
	for _, delta := range []int{0, 16, 32, 48} {
		for _, frame := range []int{16, 32} {
			for _, seeded := range []bool{false, true} {
				for bp := 0; bp < 3; bp++ {
					p := applicationPopulation{delta, frame, seeded, bp}
					t.Run(fmt.Sprintf("delta%d/frame%d/seeded%t/bp%d", delta, frame, seeded, bp), func(t *testing.T) {
						code := applicationPopulationBuild(t, p)
						parent := applicationRoot(t, code.im, testEntry, code.call, code.parent, nil)
						child := checkedReturn(t, applicationRoot(t, code.im, testEntry+128, code.childRet, code.child, nil))
						application, err := CheckTransitionCallReturn(t.Context(), parent, child)
						if err != nil {
							t.Fatal(err)
						}
						b, _ := application.Bound()
						if !application.AppliesTo(child) || b.Activation != TransitionActivationID(parent.checked.bound.Boundary.ID) || b.StackShift != int64(-delta-8) || len(b.ChildEntry.Frames) != 1 || len(b.Successor.Frames) != 0 || b.Successor.Boundary.PC != code.call+5 || b.Successor.Boundary.Context != 0 {
							t.Fatal("application lost exact child or restored activation")
						}
						if b.Successor.Registers[RBP].Pointer != parent.checked.bound.Registers[RBP].Pointer {
							t.Fatal("child did not preserve actual incoming BP provenance")
						}
						frame := b.ChildEntry.Frames[0]
						if frame.Call != code.call || frame.Return != code.call+5 || frame.Context != b.Activation || frame.Slot != b.Successor.Geometry.stackPointer(b.StackShift) {
							t.Fatal("actual CALL frame does not bind its parent-root control word")
						}
						if len(b.Words) != 1 || b.Words[0].Input.Bytes.start.offset != -16 {
							t.Fatal("callee word association lost its grouping")
						}
						var wordPointer TransitionPointer
						if seeded {
							wordPointer = parent.checked.bound.Registers[RDI].Pointer
						}
						if b.Words[0].Current.Pointer != wordPointer {
							t.Fatal("current word invented or dropped incoming provenance")
						}
						for _, saved := range b.Successor.Memory {
							start := b.StackShift - 8
							if !saved.isImage() && saved.offset >= start && saved.offset < start+8 {
								want := parent.checked.bound.Registers[RBP].Pointer
								if saved.Pointer != want || want != nil && saved.PointerLane != uint8(saved.offset-start) {
									t.Fatal("saved BP residual lanes lost actual pointer provenance")
								}
							}
						}
						successor, _ := application.Successor()
						proposal, err := ProposeTransitionContinuation(t.Context(), successor, code.rootRet)
						if err != nil {
							t.Fatal(err)
						}
						beforeRET, err := CheckTransitionContinuation(t.Context(), successor, proposal)
						if err != nil {
							t.Fatal(err)
						}
						completed, _ := checkedReturn(t, beforeRET).Bound()
						if completed.State.PC != testEntry+256 || !completed.State.CalleeTerminated {
							t.Fatal("actual parent RET did not complete its incoming context")
						}
						// Direct expansion is a secondary cross-check, never the oracle.
						direct := checkedReturn(t, applicationRoot(t, code.im, testEntry, code.rootRet, code.parent, []TransitionExpansion{{PC: code.call}}))
						db, _ := direct.Bound()
						for origin := 0; origin < 4; origin++ {
							for arm := 0; arm < 2; arm++ {
								values, initial := applicationPopulationInputs(t, b.Successor, p, origin, arm)
								entry, returned, complete := applicationConcreteRun(p, code, initial, TransitionActivationID(parent.checked.bound.Boundary.ID))
								var incomingWord uint64
								for lane := 0; lane < 8; lane++ {
									incomingWord |= uint64(entry.bytes[stateLocation{off: b.StackShift - 16 + int64(lane)}]) << (8 * lane)
								}
								if stateEval(t, b.Words[0].Current.Value, values) != incomingWord {
									t.Fatal("callee arbitrary input word was not specialized to current bytes")
								}
								applicationPopulationAssert(t, b.ChildEntry.Registers, b.ChildEntry.Memory, b.ChildEntry.Instructions, b.ChildEntry.Accesses, values, entry)
								applicationPopulationAssert(t, b.Successor.Registers, b.Successor.Memory, b.Successor.Instructions, b.Successor.Accesses, values, returned)
								applicationPopulationAssert(t, completed.State.Registers, completed.State.Memory, completed.Instructions, completed.Accesses, values, complete)
								otherValues, _ := applicationPopulationInputs(t, db.Prefix, p, origin, arm)
								applicationPopulationAssert(t, db.State.Registers, db.State.Memory, db.Instructions, db.Accesses, otherValues, complete)
							}
						}
					})
				}
			}
		}
	}
}
