package closure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// The joint grammar is the reference grammar, not a compiler-output whitelist.
// This encoder owns only byte construction and candidate coordinates. Expected
// source execution and native byte effects are computed before checking from
// actual SSA and independent semantic intent respectively.
type storageJointNative struct {
	globalNativeFixture
	program    []storageByteStep
	prefixCut  uint64
	accessPCs  []uint64
	maskedByte bool
}

func storageJointEncode(t testing.TB, program []storageByteStep, prefixSteps int, maskedByte ...bool) storageJointNative {
	t.Helper()
	const codeBase, dataBase = uint64(0x401000), uint64(0x700000)
	if len(program) > 64 || prefixSteps < 0 || prefixSteps > len(program) {
		t.Fatal("joint encoder exceeded its finite intent grammar")
	}
	f := storageJointNative{globalNativeFixture: globalNativeImage(t, [2]uint64{dataBase + 8, dataBase + 80}, [3]uint64{}, dataBase+8, dataBase, nil, ""), program: slices.Clone(program)}
	if len(maskedByte) > 1 {
		t.Fatal("more than one byte-load encoding selection")
	}
	if len(maskedByte) == 1 {
		f.maskedByte = maskedByte[0]
	}
	code := []byte{0xc3, 0x48, 0x81, 0xec, 0x80, 0, 0, 0} // SUB RSP,128; ELF entry remains a separate RET.
	pc := func() uint64 { return codeBase + uint64(len(code)) }
	var branches []int
	lastWidth := 0
	for index, step := range program {
		if index == prefixSteps {
			f.prefixCut = pc()
		}
		switch step.Kind {
		case "address":
			if step.Register != 0 {
				t.Fatal("joint encoder only allocates logical address register zero")
			}
			at := pc()
			if step.At.Image {
				code = append(code, 0x48, 0x8d, 0x0d) // LEA RCX,[RIP+disp32]
				code = binary.LittleEndian.AppendUint32(code, uint32(step.At.Offset-int64(at+7)))
			} else {
				code = append(code, 0x48, 0x8d, 0x8c, 0x24) // LEA RCX,[RSP+disp32]
				code = binary.LittleEndian.AppendUint32(code, uint32(step.At.Offset+128))
			}
		case "load", "store":
			if step.FromLoaded || step.Register != 0 || step.Width != 1 && step.Width != 4 && step.Width != 8 {
				t.Fatal("joint encoder operand outside bounded grammar")
			}
			write := step.Kind == "store"
			if write {
				code = append(code, 0x48, 0xba) // MOV RDX,imm64; independent of loaded RAX.
				code = binary.LittleEndian.AppendUint64(code, step.Value)
			}
			if !write && step.Width == 1 && !f.maskedByte {
				code = append(code, 0xb8, 0, 0, 0, 0)
			} // MOV EAX,0 before the partial byte write.
			at := pc()
			if index == prefixSteps {
				f.prefixCut = at
			}
			f.accessPCs = append(f.accessPCs, at)
			if step.Width == 8 {
				code = append(code, 0x48)
			}
			op := byte(0x8b)
			reg := byte(0)
			if write {
				op, reg = 0x89, 2
			}
			if step.Width == 1 {
				op--
			}
			code = append(code, op)
			if step.Indirect {
				code = append(code, reg<<3|1) // [RCX]
			} else if step.At.Image {
				code = append(code, reg<<3|5)
				length := uint64(6)
				if step.Width == 8 {
					length++
				}
				code = binary.LittleEndian.AppendUint32(code, uint32(step.At.Offset-int64(at+length)))
			} else {
				code = append(code, 0x84|reg<<3, 0x24)
				code = binary.LittleEndian.AppendUint32(code, uint32(step.At.Offset+128))
			}
			if !write {
				lastWidth = step.Width
			}
		case "guard":
			if lastWidth == 0 || step.Register != 0 {
				t.Fatal("guard lacks actual loaded operand")
			}
			if lastWidth == 1 && f.maskedByte {
				// Canonicalize the loaded byte with admitted AND32 semantics;
				// a register/register CMP8 is outside the selected ISA kernel.
				code = append(code, 0xba, 0xff, 0, 0, 0, 0x21, 0xd0) // MOV EDX,255; AND EAX,EDX
			}
			code = append(code, 0x48, 0xba)
			code = binary.LittleEndian.AppendUint64(code, step.Value)
			if lastWidth == 8 {
				code = append(code, 0x48)
			}
			op := byte(0x39) // CMP RAX/EAX/AL,RDX/EDX/DL.
			code = append(code, op, 0xd0, 0x0f, 0x85)
			branches = append(branches, len(code))
			code = append(code, 0, 0, 0, 0)
		default:
			t.Fatalf("unsupported joint intent %s", step.Kind)
		}
	}
	if prefixSteps == len(program) {
		f.prefixCut = pc()
	}
	// The private local address is an internal operand, not a returned pointer.
	code = append(code, 0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0) // MOV RCX,0
	code = append(code, 0x48, 0x81, 0xc4, 0x80, 0, 0, 0)    // ADD RSP,128.
	f.cut = pc()
	code = append(code, 0xc3)
	for _, branch := range branches {
		binary.LittleEndian.PutUint32(code[branch:], uint32(int64(pc())-int64(codeBase+uint64(branch)+4)))
		code = append(code, 0xe8, 0, 0, 0, 0, 0xc3) // An actual unexecuted throwing-call boundary.
	}
	if len(code) >= 4096 {
		t.Fatal("joint code overlaps data mapping")
	}
	f.raw = append(slices.Clone(f.raw), make([]byte, 128)...)
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+56+32:], 256)
	binary.LittleEndian.PutUint64(f.raw[64+56+40:], 256)
	var err error
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	f.face = globalNativeFace([]nativeproof.Span{{Start: dataBase, End: dataBase + 256}})
	f.face.Origin = nativeproof.OriginDomain{Min: 1 << 40, Max: (1 << 40) + 0x10000, Modulus: 16}
	f.face.Envelope = nativeproof.RelativeSpan{Start: -128, End: 16}
	f.face.Regions = []nativeproof.RelativeRegion{
		{Bytes: nativeproof.RelativeSpan{Start: -128, End: 0}, Readable: true, Writable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 0, End: 8}, Readable: true},
		{Bytes: nativeproof.RelativeSpan{Start: 8, End: 16}, Readable: true, Writable: true},
	}
	f.face.PrivateFrame = &nativeproof.TransitionPrivateFrame{Bytes: nativeproof.RelativeSpan{Start: -128, End: 0}}
	f.face.ReturnContext = &nativeproof.TransitionReturnContext{Target: codeBase, Preserved: []nativeproof.Register{nativeproof.RBX, nativeproof.RBP, nativeproof.RSI, nativeproof.RDI, nativeproof.R8, nativeproof.R9, nativeproof.R10, nativeproof.R11, nativeproof.R12, nativeproof.R13, nativeproof.R14, nativeproof.R15}}
	return f
}

func storageJointTransition(t testing.TB, f storageJointNative, cut uint64) (nativeproof.TransitionCertificate, error) {
	t.Helper()
	decode := globalCandidateDecoder(t, f.raw)
	var expansions []nativeproof.TransitionExpansion
	for at := f.entry; at < f.cut; {
		instruction := decode(at)
		if nativeproof.TransitionExpansionRequired(instruction) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(instruction.Len)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		return nativeproof.TransitionCertificate{}, err
	}
	return nativeproof.CheckRegionTransition(t.Context(), f.image, f.entry, f.face, proposal, nativeproof.TransitionLimits{})
}

type storageJointSource struct {
	source                      computationSource
	input                       regionInput
	call                        *ssa.Call
	prefix                      *sourceOperandPrefix
	complete                    *sourceReturnCompletion
	objects                     map[int]regionObject
	initialReference, reference storageSourceResult
}

func storageJointSourceCase(t testing.TB, c storageOracleTemplate, selectedWord ...int) storageJointSource {
	t.Helper()
	word := 64
	if len(selectedWord) > 1 {
		t.Fatal("multiple source size selections")
	}
	if len(selectedWord) == 1 {
		word = selectedWord[0]
	}
	source, in, call := storageSourceFixture(t, c, word)
	sizes := source.prog.Pkgs[0].TypesSizes
	initial, err := executeStorageSource(t, in, storageSourceRun{Globals: storageGlobals(c, in.root, 2), Sizes: sizes})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := executeStorageSource(t, in, storageSourceRun{Globals: storageGlobals(c, in.root, 2), Sizes: sizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	objects := map[int]regionObject{}
	seen := map[ssa.Value]bool{}
	for _, object := range reference.Objects {
		if seen[object.Site] {
			t.Fatal("joint acyclic grammar repeated an allocation site; instance binding must be extended explicitly")
		}
		seen[object.Site] = true
		switch site := object.Site.(type) {
		case *ssa.Global:
			objects[object.ID] = regionObject{kind: regionGlobal, site: site}
		case *ssa.Alloc:
			if object.Invocation != 1 || site.Parent() != in.root {
				t.Fatal("joint binding expects actual root allocation, not site-only helper summaries")
			}
			objects[object.ID] = regionObject{kind: regionAllocation, site: site, context: in.root}
		default:
			t.Fatal("reference object has no owned SSA allocation/global")
		}
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, in.root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatalf("positive selected source prefix: %v", err)
	}
	returns := storageOracleInstructions[*ssa.Return](in.root)
	if len(returns) != 1 {
		t.Fatal("joint source needs exactly one actual root return")
	}
	completed, err := checkSourceReturnContinuation(t.Context(), prefix, returns[0], nil)
	if err != nil {
		t.Fatalf("positive selected source completion: %v", err)
	}
	return storageJointSource{source, in, call, prefix, completed, objects, initial, reference}
}

func (s storageJointSource) representation(t testing.TB, c storageOracleTemplate, layout storageOracleLayout, image *nativeproof.Image) storageRepresentation {
	rho := storageRepresentation{source: s.source.prog, image: image}
	for i, at := range layout.Globals {
		global := s.input.root.Pkg.Members[fmt.Sprintf("g%d", i)].(*ssa.Global)
		rho.bindings = append(rho.bindings, storageBinding{object: regionObject{kind: regionGlobal, site: global}, base: nativeproof.TransitionLocation{Image: at.Image, Offset: at.Offset}})
	}
	if c.Kind != "zero-arg" && c.Kind != "eliminated" {
		id := storageOracleLocalID(t, c, s.initialReference)
		rho.bindings = append(rho.bindings, storageBinding{object: s.objects[id], base: nativeproof.TransitionLocation{Offset: layout.Local.Offset}})
	}
	return rho
}

// Input identity includes the complete scoped variable vocabulary, not labels,
// equal sample values, or pointer equality of hash-consed expression handles.
type storageJointVariable struct {
	scope   br.Scope
	slot    uint64
	scratch bool
	sort    br.Sort
}

func storageJointVariableOf(term br.Term) (storageJointVariable, bool) {
	v := term.View()
	return storageJointVariable{v.Scope, v.Immediate, v.Scratch, v.Sort}, v.Op == br.Variable
}

func storageJointVariables(term br.Term) map[storageJointVariable]bool {
	out := map[storageJointVariable]bool{}
	seen := map[br.Term]bool{}
	var visit func(br.Term)
	visit = func(term br.Term) {
		if seen[term] {
			return
		}
		seen[term] = true
		if id, variable := storageJointVariableOf(term); variable {
			out[id] = true
		}
		for _, arg := range term.View().Args {
			visit(arg)
		}
	}
	visit(term)
	return out
}

func storageJointCheckInputs(t testing.TB, c storageOracleTemplate, layout storageOracleLayout, p *globalFunctionCorrespondence, b nativeproof.TransitionBound) {
	t.Helper()
	if len(p.inputs) != c.Globals {
		t.Fatalf("global input population=%d want %d", len(p.inputs), c.Globals)
	}
	initial := map[nativeproof.TransitionLocation]br.Term{}
	for _, cell := range b.InitialMemory {
		if _, duplicate := initial[cell.TransitionLocation]; duplicate {
			t.Fatal("duplicate initial native byte")
		}
		initial[cell.TransitionLocation] = cell.Value
	}
	seen := map[storageJointVariable]bool{}
	antecedent := storageJointVariables(p.antecedent)
	var paired []br.Term
	var conjunction func(br.Term)
	conjunction = func(term br.Term) {
		if term == p.antecedent || term.View().Op == br.Constant && term.View().Immediate == 1 {
			return
		}
		if term.View().Op == br.And {
			for _, arg := range term.View().Args {
				conjunction(arg)
			}
			return
		}
		if term.View().Op != br.Equal {
			t.Fatal("paired initial domain contains an additional unsupported constraint")
		}
		paired = append(paired, term)
	}
	conjunction(p.paired)
	if len(paired) != len(p.inputs) {
		t.Fatal("paired domain omitted or introduced typed initial constraints")
	}
	for i, input := range p.inputs {
		global := p.representation.source.Roots["F"].Pkg.Members[fmt.Sprintf("g%d", i)].(*ssa.Global)
		if input.location.object.site != global || input.location.object.kind != regionGlobal || len(input.location.path) != 0 || input.source.Sort() != br.Bits(c.Width*8) || input.native.Sort() != br.Bits(c.Width*8) {
			t.Fatal("typed initial pair has another object, extent or sort")
		}
		id, arbitrary := storageJointVariableOf(input.source)
		if !arbitrary || seen[id] || antecedent[id] {
			t.Fatal("source prior value is fixed, correlated or administratively constrained")
		}
		seen[id] = true
		want := map[storageJointVariable]bool{}
		var ordered []storageJointVariable
		for lane := range c.Width {
			at := storageAt(layout.Globals[i], int64(lane))
			term := initial[nativeproof.TransitionLocation{Image: true, Offset: at.Offset}]
			id, variable := storageJointVariableOf(term)
			if !variable || term.Sort() != br.Bits(8) || seen[id] || antecedent[id] {
				t.Fatal("native initial global bytes lack original independent variable identities")
			}
			seen[id], want[id] = true, true
			ordered = append(ordered, id)
		}
		if !reflect.DeepEqual(storageJointVariables(input.native), want) {
			t.Fatal("paired native word borrows another object's variables or expected outputs")
		}
		// Interpret the variable/concatenation domain as ordered bytes. This checks
		// every bit's original variable, rather than only three sampled words.
		var actual []storageJointVariable
		var bytes func(br.Term)
		bytes = func(term br.Term) {
			if id, variable := storageJointVariableOf(term); variable && term.Sort() == br.Bits(8) {
				actual = append(actual, id)
				return
			}
			v := term.View()
			if v.Op != br.Concat {
				t.Fatal("initial word has non-byte-composition semantics")
			}
			for _, arg := range v.Args {
				bytes(arg)
			}
		}
		bytes(input.native)
		if !slices.Equal(actual, ordered) {
			t.Fatal("initial global byte significance differs from selected little-endian representation")
		}
		found := 0
		for _, pair := range paired {
			args := pair.View().Args
			if len(args) == 2 && (args[0] == input.source && args[1] == input.native || args[1] == input.source && args[0] == input.native) {
				found++
			}
		}
		if found != 1 {
			t.Fatal("typed source variable is not paired with exactly its original native word")
		}
	}
}

func storageJointAssignments(t testing.TB, b nativeproof.TransitionBound, initial map[storageByteLocation]byte, origin uint64, seed uint64) ([]br.Assignment, [16]uint64) {
	t.Helper()
	assigned := map[br.Term]uint64{}
	put := func(term br.Term, value uint64) {
		if _, variable := storageJointVariableOf(term); !variable {
			return
		}
		if old, exists := assigned[term]; exists && old != value {
			t.Fatal("initial native variables unexpectedly alias incompatible fixture values")
		}
		assigned[term] = value
	}
	put(b.Origin, origin)
	var registers [16]uint64
	for i, term := range b.InitialRegisters {
		registers[i] = 0xa5968778695a4b3c ^ uint64(i)*0x102030405060708 ^ seed
		if nativeproof.Register(i) == nativeproof.RSP {
			registers[i] = origin
		}
		put(term, registers[i])
	}
	put(b.InitialPredicates.CF, seed&1)
	put(b.InitialPredicates.ZF, (seed>>1)&1)
	put(b.InitialPredicates.SFXorOF, (seed>>2)&1)
	for i, vector := range b.InitialVectors {
		put(vector.Lo, seed^uint64(i+1))
		put(vector.Hi, ^seed^uint64(i+1))
	}
	put(b.InitialFS, seed^0x123456789)
	if len(b.InitialMemory) != len(initial) {
		t.Fatalf("initial native byte domain=%d want %d", len(b.InitialMemory), len(initial))
	}
	for _, cell := range b.InitialMemory {
		value, present := initial[storageByteLocation{cell.Image, cell.Offset}]
		if !present {
			t.Fatal("certificate introduced storage outside fixture domain")
		}
		put(cell.Value, uint64(value))
	}
	assignments := make([]br.Assignment, 0, len(assigned))
	for variable, value := range assigned {
		assignments = append(assignments, br.Assignment{Variable: variable, Value: value})
	}
	for _, cell := range b.InitialMemory {
		if storageJointEval(t, cell.Value, assignments) != uint64(initial[storageByteLocation{cell.Image, cell.Offset}]) {
			t.Fatal("native entry relation silently initialized fixture scratch")
		}
	}
	return assignments, registers
}

func storageJointEval(t testing.TB, term br.Term, assignments []br.Assignment) uint64 {
	t.Helper()
	value, err := br.Eval(t.Context(), term, assignments, br.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func storageJointCheckNative(t testing.TB, c storageOracleTemplate, placement storageOracleLayout, f storageJointNative, s storageJointSource, p *globalFunctionCorrespondence, valuation int, seed uint64) {
	t.Helper()
	b, ok := p.native.BoundFor(f.image)
	if !ok || !b.State.CalleeTerminated || b.State.PC != 0x401000 || b.Continuation.PC != 0x401000 || b.Prefix.Entry != f.entry || !b.Prefix.ConditionalRegion {
		t.Fatal("complete theorem lost actual image, conditional entry or returned context")
	}
	initial := storageInitialBytes(c, placement, valuation, seed)
	// The incoming continuation is a declared protected control word, not Go
	// initialization. Every other stack byte remains its independent sentinel.
	for lane := range 8 {
		initial[storageByteLocation{Offset: int64(lane)}] = byte(uint64(0x401000) >> (8 * lane))
	}
	want, err := executeStorageBytes(initial, f.program)
	if err != nil {
		t.Fatalf("positive independent native intent: %v", err)
	}
	origin := uint64(1<<40) + uint64(valuation+1)*0x100
	assignments, registers := storageJointAssignments(t, b.Prefix, initial, origin, seed+uint64(valuation))
	for _, input := range p.inputs {
		assignments = append(assignments, br.Assignment{Variable: input.source, Value: storageJointEval(t, input.native, assignments)})
	}
	if storageJointEval(t, p.antecedent, assignments) != 1 || storageJointEval(t, p.paired, assignments) != 1 {
		t.Fatal("independent arbitrary global valuation excluded from paired relation")
	}
	for i, input := range p.inputs {
		if storageJointEval(t, input.native, assignments) != storagePriorValue(c.Width, i, valuation) {
			t.Fatal("initial typed pairing has wrong byte order or belongs to another global")
		}
	}
	if len(b.State.Memory) != len(want.Memory) {
		t.Fatal("returned native state dropped or introduced bytes")
	}
	seen := map[storageByteLocation]bool{}
	for _, cell := range b.State.Memory {
		at := storageByteLocation{cell.Image, cell.Offset}
		expected, present := want.Memory[at]
		if !present || seen[at] || storageJointEval(t, cell.Value, assignments) != uint64(expected) {
			t.Fatalf("native current byte %+v differs from independent intent/sentinel", at)
		}
		seen[at] = true
	}
	guards := map[nativeproof.TransitionOccurrenceID]uint64{}
	for _, instruction := range b.Instructions {
		if _, duplicate := guards[instruction.ID]; duplicate {
			t.Fatal("native instruction occurrence ID reused")
		}
		guards[instruction.ID] = storageJointEval(t, instruction.Guard, assignments)
	}
	if len(b.Accesses) != len(want.Events)+1 {
		t.Fatal("native read/write/return population differs from independent intent")
	}
	for i, access := range b.Accesses {
		if guard, exists := guards[access.ID]; !exists || guard != 1 || access.Context != 0 {
			t.Fatal("access lacks its actual executing occurrence/activation guard")
		}
		if i == len(want.Events) {
			if access.Kind != nativeproof.FrameReturnRead || access.Image || access.Bytes.Start != 0 || access.Bytes.End != 8 || access.PC != f.cut || storageJointEval(t, access.Value, assignments) != 0x401000 {
				t.Fatal("actual return read is missing or changed")
			}
			continue
		}
		wantAccess := want.Events[i]
		kind := nativeproof.FrameRead
		if wantAccess.Write {
			kind = nativeproof.FrameWrite
		}
		if access.Kind != kind || access.Image != wantAccess.At.Image || access.Bytes.Start != wantAccess.At.Offset || access.Bytes.End-access.Bytes.Start != int64(wantAccess.Width) || access.PC != f.accessPCs[i] || storageJointEval(t, access.Value, assignments) != wantAccess.Value {
			t.Fatalf("ordered native access %d differs from intent %+v", i, wantAccess)
		}
	}
	// Track this encoder's explicit GPR writes independently of symbolic outputs.
	eventIndex := 0
	lastWidth := 0
	for _, step := range f.program {
		switch step.Kind {
		case "address":
			registers[nativeproof.RCX] = uint64(step.At.Offset)
			if !step.At.Image {
				registers[nativeproof.RCX] = uint64(int64(origin) + step.At.Offset)
			}
		case "store":
			registers[nativeproof.RDX] = step.Value
			eventIndex++
		case "load":
			value := want.Events[eventIndex].Value
			eventIndex++
			lastWidth = step.Width
			if step.Width == 1 && f.maskedByte {
				registers[nativeproof.RAX] = registers[nativeproof.RAX]&^255 | value
			} else {
				registers[nativeproof.RAX] = value
			}
		case "guard":
			if lastWidth == 1 && f.maskedByte {
				registers[nativeproof.RAX] &= 255
			}
			registers[nativeproof.RDX] = step.Value
		}
	}
	registers[nativeproof.RSP] = origin + 8
	registers[nativeproof.RCX] = 0
	for i, expected := range registers {
		if storageJointEval(t, b.State.Registers[i].Value, assignments) != expected {
			t.Fatalf("native returned register %d differs from explicit transfer intent", i)
		}
	}
	if len(b.State.Restored) != len(f.face.ReturnContext.Preserved) || !reflect.DeepEqual(b.State.Vectors, b.Prefix.InitialVectors) || len(b.Prefix.PrimitiveEffects) != 0 || len(b.Prefix.Abstractions) != 0 || b.State.Thread.ContextChanged {
		t.Fatal("ordinary grammar lost preserved context or acquired unexplained primitive effects")
	}
	for i, flag := range []nativeproof.TransitionFlag{b.State.Flags.CF, b.State.Flags.OF, b.State.Flags.SF, b.State.Flags.ZF, b.State.Flags.AF, b.State.Flags.PF} {
		want := uint64(0)
		if i == 5 {
			want = 1
		} // ADD restores a positive, nonzero, low-byte-zero aligned origin.
		if !flag.Defined || storageJointEval(t, flag.Value, assignments) != want {
			t.Fatal("native final arithmetic flags differ from explicit stack restoration")
		}
	}
	storageJointCheckAccounts(t, c, p, b.Accesses, assignments, s, placement, false)
}

func storageJointCheckAccounts(t testing.TB, c storageOracleTemplate, p *globalFunctionCorrespondence, accesses []nativeproof.TransitionAccess, assignments []br.Assignment, s storageJointSource, placement storageOracleLayout, prefix bool) {
	t.Helper()
	reference := s.reference
	if prefix {
		reference = s.initialReference
	}
	var sourceEvents []storageSourceEvent
	for _, event := range reference.Events {
		if event.Kind == "read" || event.Kind == "write" {
			sourceEvents = append(sourceEvents, event)
		}
	}
	if len(sourceEvents) != len(p.accesses) {
		t.Fatal("source effect account is not indexed by independent executed events")
	}
	bases := map[int]storageByteLocation{}
	for _, object := range reference.Objects {
		if global, ok := object.Site.(*ssa.Global); ok {
			for i := range c.Globals {
				if global == s.input.root.Pkg.Members[fmt.Sprintf("g%d", i)] {
					bases[object.ID] = placement.Globals[i]
				}
			}
		}
	}
	if c.Kind != "zero-arg" && c.Kind != "eliminated" {
		bases[storageOracleLocalID(t, c, s.initialReference)] = placement.Local
	}
	wantLanes := make([]map[storageByteLocation]byte, len(sourceEvents))
	for i, event := range sourceEvents {
		if base, represented := bases[event.Location.Object]; represented {
			wantLanes[i] = map[storageByteLocation]byte{}
			for offset, value := range storageSourceBytes(s.source.prog.Pkgs[0].TypesSizes, event.Type, event.Value) {
				wantLanes[i][storageAt(base, event.Location.Offset+offset)] = value
			}
		}
	}
	sourceLanes := make([]map[storageByteLocation]bool, len(sourceEvents))
	nativeLanes := make([]map[storageByteLocation]bool, len(accesses))
	for i := range sourceLanes {
		sourceLanes[i] = map[storageByteLocation]bool{}
	}
	for i := range nativeLanes {
		nativeLanes[i] = map[storageByteLocation]bool{}
	}
	classes := make([]string, len(accesses))
	set := func(index int, class string) {
		if index < 0 || index >= len(classes) || classes[index] != "" && classes[index] != class {
			t.Fatal("native effect has conflicting projection accounts")
		}
		classes[index] = class
	}
	sourceCovered := make([]bool, len(p.accesses))
	for _, match := range p.matched {
		set(match.native, "matched")
		if match.source < 0 || match.source >= len(sourceCovered) {
			t.Fatal("matched account lost source occurrence")
		}
		sourceCovered[match.source] = true
		event, access := sourceEvents[match.source], accesses[match.native]
		if (event.Kind == "write") != (access.Kind == nativeproof.FrameWrite) {
			t.Fatal("matched source/native account changes access direction")
		}
		actual := storageJointEval(t, access.Value, assignments)
		count := 0
		for at, want := range wantLanes[match.source] {
			if at.Image != access.Image || at.Offset < access.Bytes.Start || at.Offset >= access.Bytes.End {
				continue
			}
			if sourceLanes[match.source][at] || nativeLanes[match.native][at] || byte(actual>>uint(8*(at.Offset-access.Bytes.Start))) != want {
				t.Fatal("matched account duplicates or misattributes an observable source/native byte")
			}
			sourceLanes[match.source][at], nativeLanes[match.native][at] = true, true
			count++
		}
		if count == 0 {
			t.Fatal("matched account has no independently corresponding byte")
		}
	}
	for _, i := range p.materialized {
		set(i, "materialized")
	}
	for _, i := range p.administrative {
		set(i, "administrative")
		if accesses[i].Kind != nativeproof.FrameReturnRead {
			t.Fatal("represented/ordinary byte intent was hidden as administrative traffic")
		}
	}
	for _, i := range p.inactive {
		set(i, "inactive")
		t.Fatal("unconditional intent was incorrectly classified inactive")
	}
	for _, i := range p.eliminated {
		if i < 0 || i >= len(sourceCovered) || sourceCovered[i] {
			t.Fatal("source effect has conflicting matched/eliminated account")
		}
		sourceCovered[i] = true
		if sourceEvents[i].Kind == "write" && len(wantLanes[i]) != 0 {
			t.Fatal("represented source write was classified as eliminated")
		}
	}
	for _, covered := range sourceCovered {
		if !covered {
			t.Fatal("source effect has no checked relation disposition")
		}
	}
	for _, class := range classes {
		if class == "" {
			t.Fatal("native access has no projection account")
		}
	}
	for i, covered := range sourceLanes {
		if len(covered) != 0 && len(covered) != len(wantLanes[i]) {
			t.Fatal("matched source access has uncovered observable bytes")
		}
	}
	paddingSeen := map[struct {
		native int
		at     storageByteLocation
	}]bool{}
	for _, pad := range p.padding {
		at := storageByteLocation{pad.location.Image, pad.location.Offset}
		key := struct {
			native int
			at     storageByteLocation
		}{pad.native, at}
		if c.Kind != "padding" || at.Image || at.Offset < placement.Local.Offset+1 || at.Offset > placement.Local.Offset+3 || pad.native < 0 || pad.native >= len(accesses) || paddingSeen[key] || nativeLanes[pad.native][at] {
			t.Fatal("padding account hides an observable byte or crosses its independently selected extent")
		}
		paddingSeen[key] = true
		nativeLanes[pad.native][at] = true
		access := accesses[pad.native]
		if at.Offset < access.Bytes.Start || at.Offset >= access.Bytes.End || byte(storageJointEval(t, access.Value, assignments)>>uint(8*(at.Offset-access.Bytes.Start))) != byte(storageJointEval(t, pad.value, assignments)) {
			t.Fatal("padding account is detached from its actual native access")
		}
	}
	for i, class := range classes {
		if class == "matched" && int64(len(nativeLanes[i])) != accesses[i].Bytes.End-accesses[i].Bytes.Start {
			t.Fatal("matched native access has bytes absent from typed/padding accounts")
		}
	}
	if c.Kind == "zero" && len(p.materialized) != 1 {
		t.Fatal("zero-read local lacks actual native initialization account")
	}
	if c.Kind == "write-only" && len(p.materialized) != 0 {
		t.Fatal("write-only helper required premature native zero initialization")
	}
	if (c.Kind == "array" || c.Kind == "padding") && len(p.materialized) != 0 {
		t.Fatal("explicit ordinary aggregate stores were consumed as allocation initialization")
	}
	if c.Kind == "read-choice" {
		var matched []globalFunctionAccess
		var eliminated, materialized []int
		if !prefix {
			matched = []globalFunctionAccess{{0, 0}, {2, 1}, {3, 2}}
			eliminated = []int{1}
			if c.ReadChoice == storageRetainBothReads {
				matched = []globalFunctionAccess{{0, 0}, {1, 2}, {2, 3}, {3, 4}}
				eliminated = nil
				materialized = []int{1}
			} else if c.ReadChoice == storageDeferLastRead {
				matched = []globalFunctionAccess{{0, 0}, {1, 2}, {2, 3}}
				eliminated = []int{3}
				materialized = []int{1}
			}
		}
		if !slices.Equal(p.matched, matched) || !slices.Equal(p.eliminated, eliminated) || !slices.Equal(p.materialized, materialized) {
			t.Fatalf("read-choice account differs from independent occurrence mapping: matched=%v eliminated=%v materialized=%v", p.matched, p.eliminated, p.materialized)
		}
		if len(materialized) != 0 {
			actual := accesses[1]
			if actual.Kind != nativeproof.FrameWrite || actual.Image || actual.Bytes.Start != placement.Local.Offset || actual.Bytes.End != placement.Local.Offset+4 || storageJointEval(t, actual.Value, assignments) != 0 {
				t.Fatal("retained-read initializer is not the actual zero write to X")
			}
		}
	}
	if c.Kind == "source-zero" {
		var matched []globalFunctionAccess
		var eliminated, materialized []int
		if !prefix {
			matched = []globalFunctionAccess{{1, 0}}
			eliminated = []int{0}
			if c.RetainZeroRead {
				matched = []globalFunctionAccess{{0, 1}, {1, 2}}
				eliminated = nil
				materialized = []int{0}
			}
		}
		if !slices.Equal(p.matched, matched) || !slices.Equal(p.eliminated, eliminated) || !slices.Equal(p.materialized, materialized) {
			t.Fatalf("source-zero account differs from independent source-only elimination/materialized-read intent: matched=%v eliminated=%v materialized=%v", p.matched, p.eliminated, p.materialized)
		}
		if len(materialized) != 0 {
			actual := accesses[0]
			if actual.Kind != nativeproof.FrameWrite || actual.Image || actual.Bytes.Start != placement.Local.Offset || actual.Bytes.End != placement.Local.Offset+4 || storageJointEval(t, actual.Value, assignments) != 0 {
				t.Fatal("retained source-zero read lacks its actual zero initializer")
			}
		}
	}
	if c.Kind == "eliminated" && (len(p.representation.bindings) != 0 || len(p.eliminated) == 0) {
		t.Fatal("eliminated source local acquired storage or lacks elimination evidence")
	}
	if c.Kind == "padding" && c.Combined {
		if len(p.padding) != 3 {
			t.Fatal("combined ordinary write lost accessed padding account")
		}
		for i, pad := range p.padding {
			if storageJointEval(t, pad.value, assignments) != uint64([]byte{0xaa, 0xbb, 0xcc}[i]) {
				t.Fatal("padding account substituted source zero for actual native bytes")
			}
		}
	}
}

func storageJointCheckSource(t testing.TB, s storageJointSource, p *globalFunctionCorrespondence, prefix bool) {
	t.Helper()
	reference := s.reference
	var state regionState
	if prefix {
		reference = s.initialReference
		state = s.prefix.region.packet.observations[0].state
	} else {
		state = s.complete.region.packet.observations[0].state
	}
	invocations := map[regionInvocation]uint64{{}: 1}
	var applications []regionCallApplication
	for _, trace := range p.traces {
		applications = append(applications, trace.calls...)
	}
	for _, invocation := range reference.Invocations[1:] {
		found := 0
		for _, app := range applications {
			if app.proof.at == invocation.Call && app.proof.target == invocation.Target {
				if _, duplicate := invocations[app.proof.invocation]; duplicate {
					t.Fatal("source call contexts collapsed")
				}
				invocations[app.proof.invocation] = invocation.ID
				found++
			}
		}
		if found != 1 {
			t.Fatal("actual concrete invocation has no unique checked source application")
		}
	}
	loc := func(location regionLocation) storageSourceLocation {
		id := 0
		var typ types.Type
		for _, object := range s.reference.Objects {
			if s.objects[object.ID] == location.object {
				id, typ = object.ID, object.Type
			}
		}
		if id == 0 {
			t.Fatal("source location borrows another object or allocation invocation")
		}
		out := storageSourceLocation{Object: id}
		for _, step := range location.path {
			if step.summary {
				t.Fatal("exact source oracle location widened to summary")
			}
			out.Path = append(out.Path, int(step.index))
			switch u := typ.Underlying().(type) {
			case *types.Array:
				if step.field {
					t.Fatal("array index became a field")
				}
				out.Offset += step.index * s.source.prog.Pkgs[0].TypesSizes.Sizeof(u.Elem())
				typ = u.Elem()
			case *types.Struct:
				if !step.field {
					t.Fatal("field became array index")
				}
				fields := make([]*types.Var, u.NumFields())
				for i := range fields {
					fields[i] = u.Field(i)
				}
				out.Offset += s.source.prog.Pkgs[0].TypesSizes.Offsetsof(fields)[step.index]
				typ = fields[step.index].Type()
			default:
				t.Fatal("source subobject path crosses scalar")
			}
		}
		return out
	}
	var value func(regionValue) any
	value = func(v regionValue) any {
		switch v.kind {
		case regionConstant:
			switch v.scalar.Kind() {
			case constant.Bool:
				return constant.BoolVal(v.scalar)
			case constant.Int:
				if v.typ.Underlying().(*types.Basic).Info()&types.IsUnsigned != 0 {
					x, ok := constant.Uint64Val(v.scalar)
					if !ok {
						t.Fatal("inexact unsigned source value")
					}
					return x
				}
				x, ok := constant.Int64Val(v.scalar)
				if !ok {
					t.Fatal("inexact signed source value")
				}
				return x
			}
		case regionAggregate:
			out := make([]any, len(v.elements))
			for i, element := range v.elements {
				out[i] = value(element)
			}
			return out
		case regionPointer:
			return loc(v.location)
		case regionNil:
			return nil
		}
		t.Fatalf("positive source value lost exact concrete semantics: kind=%v", v.kind)
		return nil
	}
	var events []storageSourceEvent
	for _, trace := range p.traces {
		for _, occurrence := range trace.instructions {
			invocation, known := invocations[occurrence.invocation]
			if !known {
				t.Fatal("source event has unbound invocation")
			}
			e := storageSourceEvent{Instruction: occurrence.instruction, Invocation: invocation}
			switch instruction := occurrence.instruction.(type) {
			case *ssa.Alloc:
				for _, allocation := range trace.allocations {
					if allocation.regionEffectOccurrence == occurrence {
						e.Kind = "allocate"
						e.Location = loc(allocation.location)
						e.Type = allocation.initializer.typ
						e.Width = s.source.prog.Pkgs[0].TypesSizes.Sizeof(e.Type)
						e.Value = value(allocation.initializer)
					}
				}
			case *ssa.Store, *ssa.UnOp:
				if u, ok := instruction.(*ssa.UnOp); ok && u.Op != token.MUL {
					continue
				}
				for _, access := range trace.accesses {
					if access.regionEffectOccurrence == occurrence {
						if access.locked {
							t.Fatal("ordinary source unexpectedly atomic")
						}
						e.Kind = "read"
						if access.write {
							e.Kind = "write"
						}
						e.Location = loc(access.location)
						e.Type = access.value.typ
						e.Width = s.source.prog.Pkgs[0].TypesSizes.Sizeof(e.Type)
						e.Value = value(access.value)
					}
				}
			case *ssa.Call:
				for _, app := range applications {
					if app.proof.caller == occurrence {
						e.Kind = "call"
						e.Child = invocations[app.proof.invocation]
						e.Operands = make([]any, len(app.proof.arguments))
						for i, arg := range app.proof.arguments {
							e.Operands[i] = value(arg)
						}
					}
				}
			case *ssa.Return:
				e.Kind = "return"
				e.Operands = []any{}
				if invocation != 1 {
					for _, app := range applications {
						if app.proof.invocation == occurrence.invocation && len(instruction.Results) > 0 {
							e.Operands = []any{value(app.outcome.value)}
						}
					}
				}
			default:
				continue
			}
			if e.Kind == "" {
				t.Fatal("checked source occurrence lacks its actual typed event")
			}
			events = append(events, e)
		}
	}
	if len(events) != len(reference.Events) {
		t.Fatalf("source ordered event population=%d, want %d", len(events), len(reference.Events))
	}
	for i, got := range events {
		want := reference.Events[i]
		if (got.Type == nil) != (want.Type == nil) || got.Type != nil && !types.Identical(got.Type, want.Type) {
			t.Fatalf("source event %d has another Go type: got %v want %v", i, got.Type, want.Type)
		}
		// byte and uint8 denote the same Go type; structural *types.Basic
		// comparison would mistake the alias spelling for a semantic difference.
		got.Type, want.Type = nil, nil
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("source event %d differs from independent concrete SSA execution:\ngot %+v\nwant %+v", i, got, want)
		}
	}
	for _, object := range reference.Objects {
		v, present := state.memory[s.objects[object.ID]]
		if prefix && (!present || v.kind == regionUnknown) {
			if _, global := object.Site.(*ssa.Global); global {
				paired := false
				for _, input := range p.inputs {
					paired = paired || input.location.object == s.objects[object.ID]
				}
				if !paired {
					t.Fatal("arbitrary prefix global lacks a checked initial-variable relation")
				}
				continue
			}
		}
		if !present || !reflect.DeepEqual(value(v), object.Value) {
			t.Fatal("source completion lost current whole object or allocation lifetime")
		}
	}
}

func checkStorageJointCase(t testing.TB, c storageOracleTemplate, s storageJointSource, permutation int, seed uint64) {
	t.Helper()
	placement := storageOraclePlacement(c.Globals, permutation)
	program, prefixSteps := c.nativeIntent(placement)
	f := storageJointEncode(t, program, prefixSteps)
	prefix, err := storageJointTransition(t, f, f.cut)
	if err != nil {
		t.Fatalf("positive native complete-prefix %s: %v", c.Name, err)
	}
	returned, err := nativeproof.CheckTransitionReturn(t.Context(), prefix)
	if err != nil {
		t.Fatalf("positive native return: %v", err)
	}
	rho := s.representation(t, c, placement, f.image)
	p, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, returned, rho, nil)
	if err != nil {
		t.Fatalf("positive complete-function joint relation %s layout=%d: %v", c.Name, permutation, err)
	}
	b, _ := returned.BoundFor(f.image)
	storageJointCheckInputs(t, c, placement, p, b.Prefix)
	for valuation := range 3 {
		concrete, err := executeStorageSource(t, s.input, storageSourceRun{Globals: storageGlobals(c, s.input.root, valuation), Sizes: s.source.prog.Pkgs[0].TypesSizes, Whole: true})
		if err != nil {
			t.Fatal(err)
		}
		valued := s
		valued.reference = concrete
		storageJointCheckSource(t, valued, p, false)
		storageJointCheckNative(t, c, placement, f, valued, p, valuation, seed)
	}
}

func TestStorageJointCorrespondencePopulation(t *testing.T) {
	templates := storageOracleTemplates(0)
	if len(templates) != 24 {
		t.Fatal("joint template population differs from its bounded 24-case contract")
	}
	for _, c := range templates {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			for permutation := range 2 {
				t.Run(fmt.Sprint(permutation), func(t *testing.T) { checkStorageJointCase(t, c, s, permutation, 0) })
			}
		})
	}
	t.Log("48 complete-function relations; 144 joint source/native valuations, with universal initial-variable binding inspected separately")
}

func checkStorageJointPrefix(t testing.TB, c storageOracleTemplate, s storageJointSource, permutation int, seed uint64) {
	t.Helper()
	placement := storageOraclePlacement(c.Globals, permutation)
	program, steps := c.nativeIntent(placement)
	f := storageJointEncode(t, program, steps)
	native, err := storageJointTransition(t, f, f.prefixCut)
	if err != nil {
		t.Fatalf("positive actual native operand prefix: %v", err)
	}
	rho := s.representation(t, c, placement, f.image)
	p, err := checkGlobalOperandCorrespondence(t.Context(), s.source, s.input.root, s.call, f.image, f.entry, f.prefixCut, s.prefix, native, rho)
	if c.Kind == "eliminated" {
		if p != nil || err == nil {
			t.Fatal("optimized-away source pointer acquired an invented native operand")
		}
		if !strings.Contains(err.Error(), "unrepresented") && !strings.Contains(err.Error(), "no represented native storage") {
			t.Fatalf("eliminated operand refused for another premise: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("positive operand-prefix relation %s layout=%d: %v", c.Name, permutation, err)
	}
	bound, _ := native.BoundFor(f.image)
	if bound.Boundary.PC != f.prefixCut || bound.Entry != f.entry || !bound.ConditionalRegion {
		t.Fatal("operand certificate lost its actual unexecuted boundary")
	}
	storageJointCheckInputs(t, c, placement, p.account, bound)
	for valuation := range 3 {
		concrete, err := executeStorageSource(t, s.input, storageSourceRun{Globals: storageGlobals(c, s.input.root, valuation), Sizes: s.source.prog.Pkgs[0].TypesSizes})
		if err != nil {
			t.Fatal(err)
		}
		valued := s
		valued.initialReference = concrete
		storageJointCheckSource(t, valued, p.account, true)
		initial := storageInitialBytes(c, placement, valuation, seed)
		for lane := range 8 {
			initial[storageByteLocation{Offset: int64(lane)}] = byte(uint64(0x401000) >> (8 * lane))
		}
		want, err := executeStorageBytes(initial, program[:steps])
		if err != nil {
			t.Fatal(err)
		}
		origin := uint64(1<<40) + uint64(valuation+1)*0x100
		assignments, registers := storageJointAssignments(t, bound, initial, origin, seed+uint64(valuation))
		for _, input := range p.account.inputs {
			assignments = append(assignments, br.Assignment{Variable: input.source, Value: storageJointEval(t, input.native, assignments)})
		}
		if storageJointEval(t, p.account.paired, assignments) != 1 || storageJointEval(t, bound.CutGuard, assignments) != 1 {
			t.Fatal("prefix narrowed an admitted initial valuation")
		}
		if len(bound.Memory) != len(want.Memory) || len(bound.Accesses) != len(want.Events) {
			t.Fatal("prefix byte/effect domain differs from unexecuted-boundary intent")
		}
		seen := map[storageByteLocation]bool{}
		for _, cell := range bound.Memory {
			at := storageByteLocation{cell.Image, cell.Offset}
			v, exists := want.Memory[at]
			if !exists || seen[at] || storageJointEval(t, cell.Value, assignments) != uint64(v) {
				t.Fatal("prefix current bytes differ from independent scratch/materialization intent")
			}
			seen[at] = true
		}
		guards := map[nativeproof.TransitionOccurrenceID]uint64{}
		for _, instruction := range bound.Instructions {
			if instruction.ID == bound.Boundary.ID || instruction.Start == bound.Boundary.PC {
				t.Fatal("native operand boundary already executed")
			}
			if _, duplicate := guards[instruction.ID]; duplicate {
				t.Fatal("prefix occurrence ID reused")
			}
			guards[instruction.ID] = storageJointEval(t, instruction.Guard, assignments)
		}
		for i, access := range bound.Accesses {
			w := want.Events[i]
			kind := nativeproof.FrameRead
			if w.Write {
				kind = nativeproof.FrameWrite
			}
			if guards[access.ID] != 1 || access.Context != 0 || access.PC != f.accessPCs[i] || access.Kind != kind || access.Image != w.At.Image || access.Bytes.Start != w.At.Offset || access.Bytes.End-access.Bytes.Start != int64(w.Width) || storageJointEval(t, access.Value, assignments) != w.Value {
				t.Fatal("prefix ordered native effect differs from independent intent")
			}
		}
		// These prefixes perform stores/address formation only; the first actual
		// source operation and its corresponding native memory instruction wait.
		for _, step := range program[:steps] {
			switch step.Kind {
			case "store":
				registers[nativeproof.RDX] = step.Value
			case "address":
				registers[nativeproof.RCX] = uint64(step.At.Offset)
				if !step.At.Image {
					registers[nativeproof.RCX] = uint64(int64(origin) + step.At.Offset)
				}
			default:
				t.Fatal("prefix grammar unexpectedly executes a read/guard")
			}
		}
		if steps < len(program) {
			next := program[steps]
			if next.Kind == "store" {
				registers[nativeproof.RDX] = next.Value
			}
			if next.Kind == "load" && next.Width == 1 {
				registers[nativeproof.RAX] = 0
			}
		}
		registers[nativeproof.RSP] = origin - 128
		for i, want := range registers {
			if storageJointEval(t, bound.Registers[i].Value, assignments) != want {
				t.Fatalf("actual prefix register %d differs from operand preparation intent", i)
			}
		}
		storageJointCheckAccounts(t, c, p.account, bound.Accesses, assignments, valued, placement, true)
	}
}

func TestStorageJointOperandPopulation(t *testing.T) {
	for _, c := range storageOracleTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			for permutation := range 2 {
				t.Run(fmt.Sprint(permutation), func(t *testing.T) { checkStorageJointPrefix(t, c, s, permutation, 0) })
			}
		})
	}
}

func TestStorageJointStoreOperandCounterexamples(t *testing.T) {
	for index, width := range []int{1, 4, 8} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			c := storageOracleTemplates(0)[12+index]
			source := relationFixture(t, fmt.Sprintf(`func Write(p *uint%d,v uint%d){*p=v};func F(){var x [2]uint%d;Write(&x[0],%d)}`, width*8, width*8, width*8, c.Value), 64)
			root := source.prog.Roots["F"]
			calls, allocations := storageOracleInstructions[*ssa.Call](root), storageOracleInstructions[*ssa.Alloc](root)
			if len(calls) != 1 || len(allocations) != 1 {
				t.Fatal("store operand fixture lost its actual call/allocation")
			}
			call := calls[0]
			in := regionInput{root: root, owner: root.Prog, entry: regionPoint{block: root.Blocks[0]}, use: regionUse{at: regionPoint{call.Block(), slices.Index(call.Block().Instrs, ssa.Instruction(call))}, operand: call.Call.Value}}
			reference, err := executeStorageSource(t, in, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes})
			if err != nil {
				t.Fatal(err)
			}
			if reference.Returned || reference.Cut != call || len(reference.Objects) != 1 || len(reference.Events) != 1 || reference.Events[0].Kind != "allocate" || len(reference.Operands) != 2 || reference.Objects[0].Site != allocations[0] || reference.Objects[0].Size != int64(2*width) || !reflect.DeepEqual(reference.Objects[0].Value, []any{uint64(0), uint64(0)}) {
				t.Fatal("independent source prefix executed the callee or lost its typed zero allocation")
			}
			pointer := reference.Operands[0].(storageSourceLocation)
			if pointer.Object != 1 || pointer.Offset != 0 || !slices.Equal(pointer.Path, []int{0}) {
				t.Fatal("source call no longer points at the first actual array subobject")
			}
			prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
			if err != nil {
				t.Fatalf("independent source operand prefix: %v", err)
			}
			s := storageJointSource{source: source, input: in, call: call, prefix: prefix, objects: map[int]regionObject{1: {kind: regionAllocation, site: allocations[0], context: root}}, initialReference: reference, reference: reference}
			placement := storageOraclePlacement(0, 0)
			// Neither the selected source call nor this actual store executes. No
			// complete-function/native-return theorem is requested by these controls.
			program := []storageByteStep{{Kind: "address", At: placement.Local}, {Kind: "store", At: placement.Local, Width: width, Value: c.Value}}
			const steps = 1
			good := storageJointEncode(t, program, steps)
			native, err := storageJointTransition(t, good, good.prefixCut)
			if err != nil {
				t.Fatalf("independent native prefix: %v", err)
			}
			baseline, err := checkGlobalOperandCorrespondence(t.Context(), source, root, call, good.image, good.entry, good.prefixCut, prefix, native, s.representation(t, c, placement, good.image))
			if err != nil || baseline == nil {
				t.Fatalf("write-only operand control lacks an accepted baseline: %v", err)
			}
			storageJointCheckSource(t, s, baseline.account, true)
			for _, mutation := range []string{"wrong-new-value", "other-subobject"} {
				t.Run(mutation, func(t *testing.T) {
					badProgram := slices.Clone(program)
					if mutation == "wrong-new-value" {
						badProgram[steps].Value ^= 1
					} else {
						badProgram[steps].At = storageAt(placement.Local, int64(width))
					}
					initial := storageJointInitial(c, placement)
					before, err := executeStorageBytes(initial, program[:steps])
					if err != nil {
						t.Fatal(err)
					}
					after, err := executeStorageBytes(initial, badProgram[:steps])
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before.Memory, initial) || !reflect.DeepEqual(after.Memory, initial) || len(before.Events) != 0 || len(after.Events) != 0 {
						t.Fatal("operand control changed prior concrete memory/effects")
					}
					for lane := range 2 * width {
						if initial[storageAt(placement.Local, int64(lane))] == 0 {
							t.Fatal("write-only control accidentally supplied native zero initialization")
						}
					}
					// The counterexample is in evaluated operands, not in a hypothetical
					// execution of the future store or its following guard/return.
					wantValue := reference.Operands[1].(uint64)
					wantAddress := uint64(int64(1<<40) + placement.Local.Offset + pointer.Offset)
					changed := storageJointEncode(t, badProgram, steps)
					changedNative, err := storageJointTransition(t, changed, changed.prefixCut)
					if err != nil {
						t.Fatalf("changed operands must retain a valid independent entry-to-store prefix: %v", err)
					}
					bound, _ := changedNative.BoundFor(changed.image)
					if len(bound.Accesses) != 0 || len(bound.Memory) != len(initial) || bound.Boundary.PC != changed.prefixCut {
						t.Fatal("actual native store was executed or prior byte domain changed")
					}
					for _, instruction := range bound.Instructions {
						if instruction.ID == bound.Boundary.ID || instruction.Start == bound.Boundary.PC {
							t.Fatal("unexecuted store entered the prefix inventory")
						}
					}
					assignments, _ := storageJointAssignments(t, bound, initial, 1<<40, 0x1234)
					for _, cell := range bound.Memory {
						if storageJointEval(t, cell.Value, assignments) != uint64(initial[storageByteLocation{cell.Image, cell.Offset}]) {
							t.Fatal("mutated operand preparation changed a prior native byte")
						}
					}
					memory, isMemory := bound.Boundary.Instruction.Args[0].(x86asm.Mem)
					register, isRegister := bound.Boundary.Instruction.Args[1].(x86asm.Reg)
					if bound.Boundary.Instruction.Op != x86asm.MOV || bound.Boundary.Instruction.MemBytes != width || !isMemory || !isRegister || memory.Base != x86asm.RSP || memory.Index != 0 || memory.Segment != 0 {
						t.Fatal("counterexample did not retain the actual bounded store form")
					}
					operand, err := changedNative.RegisterValue(t.Context(), register)
					if err != nil {
						t.Fatal(err)
					}
					actualValue := storageJointEval(t, operand, assignments)
					actualAddress := uint64(int64(storageJointEval(t, bound.Registers[nativeproof.RSP].Value, assignments)) + memory.Disp)
					if operand.Sort() != br.Bits(width*8) {
						t.Fatal("store source-register projection has another width")
					}
					if mutation == "wrong-new-value" {
						if actualValue != wantValue^1 || actualAddress != wantAddress {
							t.Fatal("low-bit value counterexample is absent or pointer also changed")
						}
					} else {
						if actualValue != wantValue || actualAddress != wantAddress+uint64(width) {
							t.Fatal("sibling-subobject counterexample is absent or new value also changed")
						}
					}
					accepted, err := checkGlobalOperandCorrespondence(t.Context(), source, root, call, changed.image, changed.entry, changed.prefixCut, prefix, changedNative, s.representation(t, c, placement, changed.image))
					if accepted != nil || err == nil {
						t.Fatal("different unexecuted store operand acquired correspondence")
					}
					if mutation == "wrong-new-value" {
						var refusal *br.Refusal
						if !errors.As(err, &refusal) {
							t.Fatalf("wrong new value refused outside actual scalar equality: %v", err)
						}
					} else if !strings.Contains(err.Error(), "another storage origin or subobject") {
						t.Fatalf("wrong store pointer refused outside actual operand provenance: %v", err)
					}
				})
			}
		})
	}
}

func TestStorageJointByteMaskGuard(t *testing.T) {
	c := storageOracleTemplates(0)[0]
	s := storageJointSourceCase(t, c)
	placement := storageOraclePlacement(0, 0)
	program, steps := c.nativeIntent(placement)
	f := storageJointEncode(t, program, steps, true)
	returned, err := storageJointReturn(t, f)
	if err != nil {
		t.Fatalf("admitted byte load followed by AND32 mask must establish its actual equality guard: %v", err)
	}
	p, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, returned, s.representation(t, c, placement, f.image), nil)
	if err != nil {
		t.Fatal(err)
	}
	for valuation := range 3 {
		storageJointCheckNative(t, c, placement, f, s, p, valuation, 0)
	}
}

func FuzzStorageJointCorrespondencePopulation(f *testing.F) {
	for i := range 22 {
		f.Add(uint8(i), uint8(i%2), uint64(i)*0x102030405060708)
	}
	for _, tc := range storageOracleValueCases() {
		f.Add(uint8(tc.template), uint8(0), tc.seed)
	}
	for i := range storageOracleReadChoiceTemplates(0) {
		f.Add(uint8(22+i), uint8(0), uint64(0))
	}
	for i := range storageOracleSourceZeroTemplates(0) {
		f.Add(uint8(25+i), uint8(0), uint64(0))
	}
	for i := range 2 {
		f.Add(uint8(27+i), uint8(i%2), uint64(i)*0x102030405060708)
	}
	f.Fuzz(func(t *testing.T, index, permutation uint8, seed uint64) {
		templates := storageOracleFuzzTemplates(seed)
		c := templates[int(index)%len(templates)]
		s := storageJointSourceCase(t, c)
		checkStorageJointCase(t, c, s, int(permutation%2), seed)
		checkStorageJointPrefix(t, c, s, int(permutation%2), seed)
	})
}

func TestStorageJointSourceZeroSupplements(t *testing.T) {
	for _, c := range storageOracleSourceZeroTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			for permutation := range 2 {
				t.Run(fmt.Sprint(permutation), func(t *testing.T) {
					checkStorageJointCase(t, c, s, permutation, 0)
					checkStorageJointPrefix(t, c, s, permutation, 0)
				})
			}
		})
	}
	t.Log("four source-zero complete-function relations and actual Keep prefixes, each with three valuations; prior populations remain separate")
}

func TestStorageJointSourceZeroCounterexamples(t *testing.T) {
	for _, c := range storageOracleSourceZeroTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			placement := storageOraclePlacement(0, 0)
			program, steps := c.nativeIntent(placement)
			f := storageJointEncode(t, program, steps)
			native, err := storageJointReturn(t, f)
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, native, s.representation(t, c, placement, f.image), nil)
			if err != nil || baseline == nil {
				t.Fatalf("source-zero controls need their accepted complete-function baseline: %v", err)
			}
			storageJointCheckSource(t, s, baseline, false)
			storageJointCheckNative(t, c, placement, f, s, baseline, 2, 0)
			initial := storageJointInitial(c, placement)
			before, err := executeStorageBytes(initial, program)
			if err != nil {
				t.Fatal(err)
			}
			storageOracleCheckSourceZero(t, c, s.reference, before, placement, initial)
			controls := []string{"wrong-final-write", "missing-final-write", "actual-read-before-overwrite"}
			for _, mutation := range controls {
				t.Run(mutation, func(t *testing.T) {
					changed := slices.Clone(program)
					last := len(changed) - 1
					if changed[last].Kind != "store" || changed[last].At != placement.Local || changed[last].Value != c.Value || c.Value == 0 {
						t.Fatal("source-zero final nonzero store is absent")
					}
					switch mutation {
					case "wrong-final-write":
						changed[last].Value ^= 1
					case "missing-final-write":
						changed = changed[:last]
					case "actual-read-before-overwrite":
						changed = append([]storageByteStep{{Kind: "load", At: placement.Local, Width: 4}}, changed...)
					}
					after, err := executeStorageBytes(initial, changed)
					if err != nil {
						t.Fatalf("counterexample must remain a valid concrete native intent: %v", err)
					}
					if mutation == "actual-read-before-overwrite" {
						if !reflect.DeepEqual(before.Memory, after.Memory) || len(after.Events) != len(before.Events)+1 || after.Events[0].Write || after.Events[0].Value == 0 {
							t.Fatal("actual cold read lacks its nonzero input-value/equal-endpoint counterexample")
						}
					} else {
						if reflect.DeepEqual(before.Memory, after.Memory) {
							t.Fatal("nonzero source store has no concrete final-byte counterexample")
						}
						if c.RetainZeroRead && mutation == "missing-final-write" {
							for lane := range 4 {
								if after.Memory[storageAt(placement.Local, int64(lane))] != 0 {
									t.Fatal("retained zero initializer did not remain distinct from the missing nonzero ordinary write")
								}
							}
						}
					}
					if storageJointSameByteEffects(before.Events, after.Events) {
						t.Fatal("source-zero control lacks an independent effect discrepancy")
					}
					bad := storageJointEncode(t, changed, steps)
					returned, err := storageJointReturn(t, bad)
					if err != nil {
						t.Fatalf("source-zero counterexample must reach correspondence with an actual native return: %v", err)
					}
					accepted, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, bad.image, bad.entry, s.complete, returned, s.representation(t, c, placement, bad.image), nil)
					if accepted != nil || err == nil {
						t.Fatal("source-only zero fact hid an actual cold read or wrong/missing ordinary write")
					}
					if strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), "budget") {
						t.Fatalf("source-zero control refused for an unrelated premise: %v", err)
					}
				})
			}
		})
	}
}

func TestStorageJointSourceZeroReadOperandNeedsMaterialization(t *testing.T) {
	c := storageOracleSourceZeroTemplates(0)[0]
	s := storageJointSourceCase(t, c)
	var read *ssa.Call
	for _, call := range storageOracleInstructions[*ssa.Call](s.input.root) {
		if call.Call.StaticCallee() == s.input.root.Pkg.Func("Read") {
			if read != nil {
				t.Fatal("source-zero fixture has more than one Read")
			}
			read = call
		}
	}
	if read == nil {
		t.Fatal("source-zero actual Read call is absent")
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), s.source, s.input.root, read, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	placement := storageOraclePlacement(0, 0)
	for _, materialized := range []bool{false, true} {
		t.Run(fmt.Sprint(materialized), func(t *testing.T) {
			var program []storageByteStep
			if materialized {
				program = append(program, storageByteStep{Kind: "store", At: placement.Local, Width: 4, Value: 0})
			}
			program = append(program, storageByteStep{Kind: "address", At: placement.Local})
			cut := len(program)
			program = append(program, storageByteStep{Kind: "load", Width: 4, Indirect: true}, storageByteStep{Kind: "store", At: placement.Local, Width: 4, Value: c.Value})
			f := storageJointEncode(t, program, cut)
			native, err := storageJointTransition(t, f, f.prefixCut)
			if err != nil {
				t.Fatal(err)
			}
			bound, _ := native.BoundFor(f.image)
			initial := storageJointInitial(c, placement)
			want, err := executeStorageBytes(initial, program[:cut])
			if err != nil {
				t.Fatal(err)
			}
			assignments, _ := storageJointAssignments(t, bound, initial, 1<<40, 0)
			for _, cell := range bound.Memory {
				if storageJointEval(t, cell.Value, assignments) != uint64(want.Memory[storageByteLocation{cell.Image, cell.Offset}]) {
					t.Fatal("actual read boundary borrowed source zero for native storage")
				}
			}
			for lane := range 4 {
				at := storageAt(placement.Local, int64(lane))
				if materialized && want.Memory[at] != 0 || !materialized && (want.Memory[at] == 0 || want.Memory[at] != initial[at]) {
					t.Fatal("actual zero-store/cold-byte prefix counterexample disappeared")
				}
			}
			accepted, err := checkGlobalOperandCorrespondence(t.Context(), s.source, s.input.root, read, f.image, f.entry, f.prefixCut, prefix, native, s.representation(t, c, placement, f.image))
			if materialized {
				if err != nil || accepted == nil {
					t.Fatalf("actual read with materialized X refused: %v", err)
				}
				if !slices.Equal(accepted.account.materialized, []int{0}) {
					t.Fatal("actual zero write lacks prefix initialization account")
				}
			} else {
				var refusal *br.Refusal
				if accepted != nil || !errors.As(err, &refusal) {
					t.Fatalf("actual cold read operand did not refuse its missing current-byte equality: %v", err)
				}
			}
		})
	}
}

func TestStorageJointReadChoiceSupplements(t *testing.T) {
	for _, c := range storageOracleReadChoiceTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			for permutation := range 2 {
				t.Run(fmt.Sprint(permutation), func(t *testing.T) {
					checkStorageJointCase(t, c, s, permutation, 0)
					checkStorageJointPrefix(t, c, s, permutation, 0)
				})
			}
		})
	}
	t.Log("six read-choice complete-function relations and actual Keep prefixes, each with three valuations; base 144 and zero/mixed 18 remain separate")
}

func TestStorageJointReadChoiceCounterexamples(t *testing.T) {
	for _, c := range storageOracleReadChoiceTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			s := storageJointSourceCase(t, c)
			placement := storageOraclePlacement(0, 0)
			program, steps := c.nativeIntent(placement)
			f := storageJointEncode(t, program, steps)
			native, err := storageJointReturn(t, f)
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, native, s.representation(t, c, placement, f.image), nil)
			if err != nil || baseline == nil {
				t.Fatalf("read-choice controls require their actual accepted mapping first: %v", err)
			}
			storageJointCheckSource(t, s, baseline, false)
			storageJointCheckNative(t, c, placement, f, s, baseline, 2, 0)
			initial := storageJointInitial(c, placement)
			before, err := executeStorageBytes(initial, program)
			if err != nil {
				t.Fatal(err)
			}
			storageOracleCheckReadChoice(t, c, s.reference, before, placement)
			for _, mutation := range []string{"missing-all-X-writes", "surplus-unchanged-zero-writes"} {
				t.Run(mutation, func(t *testing.T) {
					changed := slices.Clone(program)
					isXWrite := func(step storageByteStep) bool {
						return step.Kind == "store" && step.At == placement.Local && step.Width == 4 && step.Value == 0
					}
					count := 0
					for _, step := range program {
						if isXWrite(step) {
							count++
						}
					}
					wantCount := 2
					if c.ReadChoice == storageDeferFirstRead {
						wantCount = 1
					}
					if count != wantCount {
						t.Fatal("read-choice intent lost its independently specified X-write allowance")
					}
					if mutation == "missing-all-X-writes" {
						// Deleting only the tail of the third positive variant would
						// recover the first positive variant. Remove every actual X
						// write so no alternate correspondence can supply the source store.
						changed = slices.DeleteFunc(changed, isXWrite)
					} else {
						// One initializer plus one ordinary source write can account
						// for two X writes. A third is genuinely surplus: append TWO
						// to the deferred-first variant, ONE to either other variant.
						for extra := 0; extra < 3-count; extra++ {
							changed = append(changed, storageByteStep{Kind: "store", At: placement.Local, Width: 4, Value: 0})
						}
					}
					after, err := executeStorageBytes(initial, changed)
					if err != nil {
						t.Fatalf("read-choice mutation must retain valid Y reads/guards: %v", err)
					}
					if storageJointSameByteEffects(before.Events, after.Events) {
						t.Fatal("read-choice control has no concrete ordered-effect discrepancy")
					}
					if mutation == "surplus-unchanged-zero-writes" {
						if !reflect.DeepEqual(before.Memory, after.Memory) {
							t.Fatal("endpoint-equal read-choice control changed final bytes")
						}
					} else {
						for lane := range 4 {
							at := storageAt(placement.Local, int64(lane))
							if after.Memory[at] != initial[at] || after.Memory[at] == 0 || before.Memory[at] != 0 {
								t.Fatal("missing X write lacks its nonzero prior-byte counterexample")
							}
						}
					}
					bad := storageJointEncode(t, changed, steps)
					returned, err := storageJointReturn(t, bad)
					if err != nil {
						t.Fatalf("read-choice counterexample must have a complete checked native return: %v", err)
					}
					accepted, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, bad.image, bad.entry, s.complete, returned, s.representation(t, c, placement, bad.image), nil)
					if accepted != nil || err == nil {
						t.Fatal("missing/surplus ordinary effect acquired a complete read-choice relation")
					}
					if strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), "budget") {
						t.Fatalf("read-choice control failed for an unrelated premise: %v", err)
					}
				})
			}
		})
	}
}

func TestStorageJointZeroValueSupplements(t *testing.T) {
	for _, tc := range storageOracleValueCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := storageOracleTemplates(tc.seed)[tc.template]
			s := storageJointSourceCase(t, c)
			for permutation := range 2 {
				t.Run(fmt.Sprint(permutation), func(t *testing.T) {
					checkStorageJointCase(t, c, s, permutation, tc.seed)
					checkStorageJointPrefix(t, c, s, permutation, tc.seed)
				})
			}
		})
	}
	t.Log("six supplemental complete-function and operand relations, each with three concrete valuations; separate from the base 48/144 population")
}

func storageJointReturn(t testing.TB, f storageJointNative) (nativeproof.TransitionReturnCertificate, error) {
	t.Helper()
	prefix, err := storageJointTransition(t, f, f.cut)
	if err != nil {
		return nativeproof.TransitionReturnCertificate{}, err
	}
	return nativeproof.CheckTransitionReturn(t.Context(), prefix)
}

func storageJointInitial(c storageOracleTemplate, placement storageOracleLayout) map[storageByteLocation]byte {
	initial := storageInitialBytes(c, placement, 2, 0)
	for lane := range 8 {
		initial[storageByteLocation{Offset: int64(lane)}] = byte(uint64(0x401000) >> (8 * lane))
	}
	return initial
}

func storageJointSameByteEffects(a, b []storageByteEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		x.Step, y.Step = 0, 0
		if x != y {
			return false
		}
	}
	return true
}

// Every semantic control begins with an accepted joint relation. The independent
// byte interpreter establishes the discrepancy BEFORE any mutated proof is asked
// for. Endpoint-equal extra accesses are compared as events, not erased as noise.
func TestStorageJointEffectCounterexamples(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template int
	}{
		{"wider-access", 0}, {"partial-combine", 17}, {"wrong-byte-order", 17},
		{"early-read", 2}, {"extra-unchanged-local-write", 2}, {"uninitialized-zero-read", 9},
		{"dependent-reordered-write", 21}, {"padding-zero-assumption", 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := storageOracleTemplates(0)[tc.template]
			s := storageJointSourceCase(t, c)
			placement := storageOraclePlacement(c.Globals, 0)
			program, cut := c.nativeIntent(placement)
			good := storageJointEncode(t, program, cut)
			returned, err := storageJointReturn(t, good)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, good.image, good.entry, s.complete, returned, s.representation(t, c, placement, good.image), nil)
			if err != nil || proof == nil {
				t.Fatalf("negative control has no accepted baseline: %v", err)
			}
			initial := storageJointInitial(c, placement)
			before, err := executeStorageBytes(initial, program)
			if err != nil {
				t.Fatal(err)
			}
			bad := slices.DeleteFunc(slices.Clone(program), func(step storageByteStep) bool { return step.Kind == "guard" })
			switch tc.name {
			case "wider-access":
				for i := range bad {
					if bad[i].Kind == "load" {
						bad[i].Width = 4
						break
					}
				}
			case "partial-combine":
				bad[0].Width = 1
			case "wrong-byte-order":
				bad[0].Value = 0x11223344
			case "early-read":
				bad = append([]storageByteStep{{Kind: "load", At: placement.Local, Width: c.Width}}, bad...)
			case "extra-unchanged-local-write":
				bad = append(bad, storageByteStep{Kind: "store", At: placement.Local, Width: c.Width, Value: c.Value})
			case "uninitialized-zero-read":
				bad = bad[1:]
			case "dependent-reordered-write":
				var writes []int
				for i, step := range bad {
					if step.Kind == "store" {
						writes = append(writes, i)
					}
				}
				if len(writes) != 4 {
					t.Fatal("alias source intent no longer has four stores")
				}
				bad[writes[1]], bad[writes[2]] = bad[writes[2]], bad[writes[1]]
			case "padding-zero-assumption":
				// The incorrect implementation treats the first eight bytes as if the
				// padding were absent/zero and substitutes them for the uint32 read.
				for i := range bad {
					if bad[i].Kind == "load" {
						bad[i].Indirect = false
						bad[i].At = placement.Local
						bad[i].Width = 8
						break
					}
				}
			}
			after, err := executeStorageBytes(initial, bad)
			if err != nil {
				t.Fatalf("semantic control should remain a concrete permitted byte execution: %v", err)
			}
			// Removed pure guards may renumber intent steps; numbering alone is
			// not a counterexample to observable byte/effect correspondence.
			if reflect.DeepEqual(before.Memory, after.Memory) && storageJointSameByteEffects(before.Events, after.Events) {
				t.Fatal("mutation has no independent concrete byte/effect counterexample")
			}
			if tc.name == "early-read" || tc.name == "extra-unchanged-local-write" || tc.name == "dependent-reordered-write" {
				if !reflect.DeepEqual(before.Memory, after.Memory) {
					t.Fatal("equal-endpoint effect-order control changed final bytes")
				}
			}
			changed := storageJointEncode(t, bad, 0)
			changedReturn, err := storageJointReturn(t, changed)
			if err != nil {
				t.Fatalf("counterexample must reach correspondence with a valid native return: %v", err)
			}
			accepted, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, changed.image, changed.entry, s.complete, changedReturn, s.representation(t, c, placement, changed.image), nil)
			if err == nil || accepted != nil {
				t.Fatal("independently demonstrated effect/value discrepancy acquired correspondence")
			}
			if strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), "budget") {
				t.Fatalf("semantic control refused for an unrelated premise: %v", err)
			}
		})
	}
}

func TestStorageJointRepresentationCounterexamples(t *testing.T) {
	c := storageOracleTemplates(0)[8] // Three independently arbitrary uint64 globals plus one local.
	s := storageJointSourceCase(t, c)
	placement := storageOraclePlacement(c.Globals, 0)
	program, cut := c.nativeIntent(placement)
	f := storageJointEncode(t, program, cut)
	returned, err := storageJointReturn(t, f)
	if err != nil {
		t.Fatal(err)
	}
	rho := s.representation(t, c, placement, f.image)
	baseline, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, returned, rho, nil)
	if err != nil || baseline == nil {
		t.Fatalf("representation controls lack accepted baseline: %v", err)
	}
	for _, name := range []string{"correlated-globals", "foreign-source-object", "foreign-allocation", "unexplained-local-invocation", "wrong-local-context", "root-control-slot", "foreign-image", "constrained-global", "read-only-local"} {
		t.Run(name, func(t *testing.T) {
			changed := f
			candidate := rho
			candidate.bindings = slices.Clone(rho.bindings)
			native := returned
			switch name {
			case "correlated-globals":
				if storagePriorValue(8, 0, 2) == storagePriorValue(8, 1, 2) {
					t.Fatal("arbitrary prior global counterexample accidentally correlated")
				}
				candidate.bindings[1].base = candidate.bindings[0].base
			case "foreign-source-object":
				other := storageJointSourceCase(t, c)
				candidate.bindings[0].object.site = other.input.root.Pkg.Members["g0"].(*ssa.Global)
			case "foreign-allocation":
				other := storageJointSourceCase(t, c)
				id := other.initialReference.Operands[0].(storageSourceLocation).Object
				candidate.bindings[len(candidate.bindings)-1].object = other.objects[id]
			case "unexplained-local-invocation":
				candidate.bindings[len(candidate.bindings)-1].object.invocation = regionInvocation{root: s.input.root, path: "unexecuted invocation"}
			case "wrong-local-context":
				candidate.bindings[len(candidate.bindings)-1].object.context = s.input.root.Pkg.Func("Read")
			case "root-control-slot":
				candidate.bindings[len(candidate.bindings)-1].base.Offset = 0
			case "foreign-image":
				other, err := nativeproof.NewImage(t.Context(), f.raw)
				if err != nil {
					t.Fatal(err)
				}
				candidate.image = other
			case "constrained-global":
				changed.face.EntryWordUpperBounds = []nativeproof.TransitionEntryWordUpperBound{{Address: uint64(placement.Globals[0].Offset)}}
				var err error
				native, err = storageJointReturn(t, changed)
				if err != nil {
					t.Fatalf("constrained global control needs a nonempty checked native domain: %v", err)
				}
			case "read-only-local":
				changed.face.Regions = slices.Clone(f.face.Regions)
				changed.face.Regions[0].Writable = false
				// Private-frame admission itself requires writable storage. Remove
				// that independent premise so this control reaches the actual store.
				changed.face.PrivateFrame = nil
				deniedPC := f.accessPCs[c.Globals] // Three image stores precede the first local store.
				before, err := storageJointTransition(t, changed, deniedPC)
				if err != nil {
					t.Fatalf("readonly mapping must admit the prefix before its first local store: %v", err)
				}
				beforeBound, ok := before.BoundFor(changed.image)
				if !ok || beforeBound.Boundary.PC != deniedPC || beforeBound.Boundary.Instruction.Op != x86asm.MOV || len(beforeBound.Accesses) != c.Globals {
					t.Fatal("readonly control did not reach the actual unexecuted local store")
				}
				_, err = storageJointTransition(t, changed, changed.cut)
				var refusal *nativeproof.Refusal
				if !errors.As(err, &refusal) || refusal.Premise != "transition-permission" || refusal.PC != deniedPC || refusal.Detail != "full access lacks declared permission" {
					t.Fatalf("readonly local did not refuse at its actual store's missing write permission: %v", err)
				}
				return
			}
			accepted, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, changed.image, changed.entry, s.complete, native, candidate, nil)
			if err == nil || accepted != nil {
				t.Fatal("invalid storage/initial-domain authority acquired joint correspondence")
			}
			if name == "constrained-global" && !strings.Contains(err.Error(), "constrains represented source storage") {
				t.Fatalf("arbitrary-domain control refused for another reason: %v", err)
			}
		})
	}
}

func TestStorageJointAlignedPartialGlobalOverlap(t *testing.T) {
	// Alignment-one objects make the overlap itself the only changed layout
	// condition. Their final A[7] and B[0] also give a concrete incompatible byte.
	var text strings.Builder
	text.WriteString("var a,b [8]byte;func Stop(){};func F(){")
	for index, name := range []string{"a", "b"} {
		fmt.Fprintf(&text, "%s=[8]byte{", name)
		for lane := range 8 {
			fmt.Fprintf(&text, "%d,", 0x10+index*0x70+lane)
		}
		text.WriteString("};")
	}
	text.WriteString("Stop()}")
	source := relationFixture(t, text.String(), 64)
	root := source.prog.Roots["F"]
	globals := [2]*ssa.Global{root.Pkg.Members["a"].(*ssa.Global), root.Pkg.Members["b"].(*ssa.Global)}
	calls := storageOracleInstructions[*ssa.Call](root)
	if len(calls) != 1 {
		t.Fatal("array-global source lost its actual zero-argument cut")
	}
	call := calls[0]
	in := regionInput{owner: root.Prog, root: root, entry: regionPoint{block: root.Blocks[0]}, use: regionUse{at: regionPoint{call.Block(), slices.Index(call.Block().Instrs, ssa.Instruction(call))}, operand: call.Call.Value}}
	at := [2]storageByteLocation{{Image: true, Offset: 0x700010}, {Image: true, Offset: 0x700030}}
	initial := storageJointInitial(storageOracleTemplate{}, storageOraclePlacement(0, 0))
	initialGlobals := map[*ssa.Global]any{}
	for i, global := range globals {
		typ := global.Type().Underlying().(*types.Pointer).Elem()
		if source.prog.Pkgs[0].TypesSizes.Alignof(typ) != 1 || source.prog.Pkgs[0].TypesSizes.Sizeof(typ) != 8 {
			t.Fatal("overlap control no longer has actual eight-byte alignment-one objects")
		}
		values := make([]any, 8)
		for lane := range values {
			values[lane] = uint64(initial[storageAt(at[i], int64(lane))])
		}
		initialGlobals[global] = values
	}
	reference, err := executeStorageSource(t, in, storageSourceRun{Globals: initialGlobals, Sizes: source.prog.Pkgs[0].TypesSizes})
	if err != nil {
		t.Fatal(err)
	}
	if reference.Returned || reference.Cut != call || len(reference.Objects) != 4 || len(reference.Events) != 22 {
		t.Fatal("independent array-global reference lost its prefix scope/effects")
	}
	program := []storageByteStep{{Kind: "store", At: at[0], Width: 8, Value: 0x1716151413121110}, {Kind: "store", At: at[1], Width: 8, Value: 0x8786858483828180}}
	want, err := executeStorageBytes(initial, program)
	if err != nil {
		t.Fatal(err)
	}
	for i, object := range reference.Objects[:2] {
		if object.Site != globals[i] {
			t.Fatal("concrete global ordering differs from actual source objects")
		}
		for lane, value := range object.Value.([]any) {
			if want.Memory[storageAt(at[i], int64(lane))] != byte(value.(uint64)) {
				t.Fatal("independent source/native array baseline differs")
			}
		}
	}
	if reference.Objects[0].Value.([]any)[7] == reference.Objects[1].Value.([]any)[0] {
		t.Fatal("partial overlap lacks an incompatible concrete shared-byte valuation")
	}
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	f := storageJointEncode(t, program, len(program))
	native, err := storageJointTransition(t, f, f.prefixCut)
	if err != nil {
		t.Fatal(err)
	}
	rho := storageRepresentation{source: source.prog, image: f.image}
	for i, global := range globals {
		rho.bindings = append(rho.bindings, storageBinding{object: regionObject{kind: regionGlobal, site: global}, base: nativeproof.TransitionLocation{Image: true, Offset: at[i].Offset}})
	}
	baseline, err := checkGlobalOperandCorrespondence(t.Context(), source, root, call, f.image, f.entry, f.prefixCut, prefix, native, rho)
	if err != nil || baseline == nil {
		t.Fatalf("aligned array overlap control lacks an actual accepted source/native baseline: %v", err)
	}
	bound, ok := native.BoundFor(f.image)
	if !ok {
		t.Fatal("array baseline lost its owned native image")
	}
	assignments, _ := storageJointAssignments(t, bound, initial, 1<<40, 0)
	for _, cell := range bound.Memory {
		if storageJointEval(t, cell.Value, assignments) != uint64(want.Memory[storageByteLocation{cell.Image, cell.Offset}]) {
			t.Fatal("array baseline native bytes differ from independent intent")
		}
	}
	if layout, err := checkStorageAuthority(t.Context(), prefix, bound, rho, storageProtectedFootprints(bound)); err != nil || layout == nil {
		t.Fatalf("original relation lacks actual checked authority: %v", err)
	}
	overlap := rho
	overlap.bindings = slices.Clone(rho.bindings)
	overlap.bindings[1].base.Offset = overlap.bindings[0].base.Offset + 7
	layout, err := checkStorageAuthority(t.Context(), prefix, bound, overlap, storageProtectedFootprints(bound))
	if layout != nil || err == nil || err.Error() != "storage layout: overlapping live objects" {
		t.Fatalf("aligned partial overlap did not refuse on disjoint live-object extents: %v", err)
	}
}

func TestStorageJointConditionalMatchedWrite(t *testing.T) {
	c := storageOracleTemplates(0)[2]
	s := storageJointSourceCase(t, c)
	placement := storageOraclePlacement(0, 0)
	program, steps := c.nativeIntent(placement)
	// The source's equality guard is already established; this valid native
	// optimization retains the ordinary read without a redundant native branch.
	program = slices.DeleteFunc(slices.Clone(program), func(step storageByteStep) bool { return step.Kind == "guard" })
	f := storageJointEncode(t, program, steps)
	returned, err := storageJointReturn(t, f)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, returned, s.representation(t, c, placement, f.image), nil)
	if err != nil || baseline == nil {
		t.Fatalf("conditional-write control lacks accepted baseline: %v", err)
	}
	initial := storageJointInitial(c, placement)
	good, err := executeStorageBytes(initial, program)
	if err != nil {
		t.Fatal(err)
	}
	skipped := slices.Clone(program)
	if skipped[0].Kind != "store" || skipped[0].Width != 8 {
		t.Fatal("conditional control requires its first exact 8-byte stack store")
	}
	skipped = skipped[1:]
	want, err := executeStorageBytes(initial, skipped)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(good.Memory, want.Memory) || good.Events[len(good.Events)-1].Value == want.Events[len(want.Events)-1].Value {
		t.Fatal("skipping actual write did not produce the concrete read counterexample")
	}
	// TEST R8,R8; JE over the eight-byte MOV [RSP+disp32],RDX. Only this
	// bounded conditional control is encoded; no generic reference ISA is added.
	const base = uint64(0x401000)
	at := int(f.accessPCs[0] - base)
	length := int(binary.LittleEndian.Uint64(f.raw[64+32:]))
	code := slices.Clone(f.raw[4096 : 4096+length])
	if !slices.Equal(code[at:at+4], []byte{0x48, 0x89, 0x94, 0x24}) {
		t.Fatal("conditional control no longer addresses the intended exact store")
	}
	code = slices.Insert(code, at, 0x4d, 0x85, 0xc0, 0x74, 0x08)
	f.raw = slices.Clone(f.raw)
	copy(f.raw[4096:], code)
	binary.LittleEndian.PutUint64(f.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(f.raw[64+40:], uint64(len(code)))
	f.cut += 5
	f.image, err = nativeproof.NewImage(t.Context(), f.raw)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := storageJointReturn(t, f)
	if err != nil {
		t.Fatalf("both conditional native paths must return under arbitrary R8: %v", err)
	}
	b, _ := conditional.BoundFor(f.image)
	assignments, _ := storageJointAssignments(t, b.Prefix, initial, 1<<40, 0)
	for i := range assignments {
		if assignments[i].Variable == b.Prefix.InitialRegisters[nativeproof.R8] {
			assignments[i].Value = 0
		}
	}
	for _, cell := range b.State.Memory {
		if storageJointEval(t, cell.Value, assignments) != uint64(want.Memory[storageByteLocation{cell.Image, cell.Offset}]) {
			t.Fatal("native chosen false-write path differs from independent concrete counterexample")
		}
	}
	p, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, conditional, s.representation(t, c, placement, f.image), nil)
	if p != nil || err == nil || !strings.Contains(err.Error(), "not proved to execute") {
		t.Fatalf("conditional matched write did not refuse at its actual occurrence guard: %v", err)
	}
}

func TestStorageJointUnsupportedSelectionAndScalar(t *testing.T) {
	t.Run("selected-32-bit-pointer", func(t *testing.T) {
		c := storageOracleTemplates(0)[1]
		s := storageJointSourceCase(t, c, 32)
		if s.source.prog.Pkgs[0].TypesSizes.Sizeof(types.NewPointer(types.Typ[types.Uint32])) != 4 {
			t.Fatal("source selection did not actually use 32-bit pointer layout")
		}
		placement := storageOraclePlacement(0, 0)
		program, steps := c.nativeIntent(placement)
		f := storageJointEncode(t, program, steps)
		native, err := storageJointReturn(t, f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := checkGlobalFunctionCorrespondence(t.Context(), s.source, s.input.root, f.image, f.entry, s.complete, native, s.representation(t, c, placement, f.image), nil)
		if p != nil || err == nil || !strings.Contains(err.Error(), "pointer width") {
			t.Fatalf("unsupported selected pointer representation acquired native64 correspondence: %v", err)
		}
	})
	t.Run("float-consumption", func(t *testing.T) {
		// A prior unknown float remains outside the exact finite source grammar.
		// Independent local initialization supplies no value for this global.
		source := relationFixture(t, `var Unknown float64;type S struct{B uint32;F float64};func Stop(p *uint32){};func F(){var x S;x.B=7;Stop(&x.B);if Unknown!=0{panic(1)}}`, 64)
		root := source.prog.Roots["F"]
		calls := storageOracleInstructions[*ssa.Call](root)
		returns := storageOracleInstructions[*ssa.Return](root)
		if len(calls) != 1 || len(returns) != 1 {
			t.Fatal("scalar refusal fixture lost its actual boundaries")
		}
		prefix, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits())
		if err != nil {
			t.Fatalf("unused float sibling invalidated independent integer prefix: %v", err)
		}
		complete, err := checkSourceReturnContinuation(t.Context(), prefix, returns[0], nil)
		var refusal *regionOperationFailure
		if complete != nil || !errors.As(err, &refusal) || refusal.instruction == nil || refusal.instruction.Parent() != root {
			t.Fatalf("unsupported float consumption did not retain its actual operation refusal: %v", err)
		}
		floatOperand := false
		for _, operand := range refusal.instruction.Operands(nil) {
			if operand != nil && *operand != nil {
				typ := (*operand).Type()
				if pointer, ok := typ.Underlying().(*types.Pointer); ok {
					typ = pointer.Elem()
				}
				if basic, ok := typ.Underlying().(*types.Basic); ok && basic.Info()&types.IsFloat != 0 {
					floatOperand = true
				}
			}
		}
		if !floatOperand {
			t.Fatalf("float control refused at an unrelated operation: %v", refusal.instruction)
		}
	})
}
