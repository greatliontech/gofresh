package closure

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// These populations execute the existing independent interpreter. They are
// bounded samples of source grammar, not evidence of universal termination.
type regionOccurrenceOracleCase struct {
	kind  string
	word  int
	input int64
}

func (c regionOccurrenceOracleCase) sourceText() string {
	switch c.kind {
	case "round":
		return fmt.Sprintf(`var input,output int32
func Advance(x int32)int32 {s:=uint(0);for 1<<s<x{s++};return 1<<s}
func Mark(){};func F(){input=%d;output=Advance(input);Mark()}`, c.input)
	case "bounded":
		return fmt.Sprintf(`var input uint;var output uint32
func Advance(n uint)uint32 {a:=uint32(4294967294);for i:=uint(0);i<n;i++{a+=3};return a}
func Mark(){};func F(){input=%d;output=Advance(input);Mark()}`, c.input)
	case "swap":
		return fmt.Sprintf(`var input uint;var output,left,right uint32
func Advance(n uint)uint32 {a,b:=uint32(7),uint32(11);left=a;right=b
for i:=uint(0);i<n;i++ {a,b=b,a;left=a;right=b;if a==b{panic(1)}}
return a+(b<<4)}
func Mark(){};func F(){input=%d;output=Advance(input);Mark()}`, c.input)
	default:
		panic("unknown occurrence oracle family")
	}
}

func (c regionOccurrenceOracleCase) expected() any {
	if c.kind == "round" {
		x := int32(c.input)
		// The generated positive population stops at 1<<30. Larger positive
		// inputs have no normal return and are exercised with a finite budget.
		if x > 1<<30 {
			panic("nonterminating round input has no expected result")
		}
		v := int32(1)
		for v < x {
			v <<= 1
		}
		return int64(v)
	}
	if c.kind == "bounded" {
		v := uint32(4294967294)
		for i := int64(0); i < c.input; i++ {
			v += 3
		}
		return uint64(v)
	}
	a, b := uint32(7), uint32(11)
	for i := int64(0); i < c.input; i++ {
		a, b = b, a
	}
	return uint64(a + (b << 4))
}

func regionOccurrenceOracleFixture(t testing.TB, c regionOccurrenceOracleCase) (computationSource, regionInput, storageSourceRun) {
	t.Helper()
	source := relationFixture(t, c.sourceText(), c.word)
	root := source.prog.Roots["F"]
	mark := root.Pkg.Func("Mark")
	var cut *ssa.Call
	for _, call := range storageOracleInstructions[*ssa.Call](root) {
		if call.Call.StaticCallee() == mark {
			cut = call
		}
	}
	if cut == nil {
		t.Fatal("loop family lacks its actual post-loop call boundary")
	}
	in := regionInput{owner: root.Prog, selection: source.prog, root: root, entry: regionPoint{block: root.Blocks[0]},
		use: regionUse{at: regionPoint{cut.Block(), slices.Index(cut.Block().Instrs, ssa.Instruction(cut))}, operand: cut.Call.Value}}
	config := storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Globals: map[*ssa.Global]any{}}
	for _, member := range root.Pkg.Members {
		global, ok := member.(*ssa.Global)
		if !ok || global.Name() == "init$guard" {
			continue
		}
		if global.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Basic).Info()&types.IsUnsigned != 0 {
			config.Globals[global] = uint64(23)
		} else {
			config.Globals[global] = int64(-23)
		}
	}
	return source, in, config
}

func checkRegionOccurrenceOracle(t testing.TB, c regionOccurrenceOracleCase) {
	t.Helper()
	source, in, config := regionOccurrenceOracleFixture(t, c)
	prefix, err := executeStorageSource(t, in, config)
	if err != nil {
		t.Fatal(err)
	}
	config.Whole = true
	whole, err := executeStorageSource(t, in, config)
	if err != nil {
		t.Fatal(err)
	}
	if !whole.Returned || prefix.Returned || prefix.Cut != regionInstruction(in.use.at) || len(whole.Invocations) != 3 || len(prefix.Invocations) != 2 {
		t.Fatal("loop source lost exact prefix and ordinary-call completion")
	}
	var got any
	for _, object := range whole.Objects {
		if object.Site == in.root.Pkg.Members["output"].(*ssa.Global) {
			got = object.Value
		}
	}
	if got != c.expected() {
		t.Fatalf("%s/%d/%d output=%v want=%v", c.kind, c.word, c.input, got, c.expected())
	}
	if !reflect.DeepEqual(prefix.Instructions, whole.Instructions[:len(prefix.Instructions)]) {
		t.Fatal("separate prefix and whole runs disagree on actual instruction history")
	}
	checkRegionOracleInstructionOrder(t, whole)
	checkRegionOracleLoopVisits(t, c, in.root.Pkg.Func("Advance"), whole)
	checkRegionOccurrenceProof(t, source, in, prefix, whole)
	// A separately executed path has separately owned instruction containers.
	for i := range prefix.Instructions {
		if len(prefix.Instructions[i].Operands) != 0 {
			old := whole.Instructions[i].Operands[0]
			prefix.Instructions[i].Operands[0] = "changed snapshot"
			if whole.Instructions[i].Operands[0] != old {
				t.Fatal("instruction operands alias another run")
			}
			break
		}
	}
}

// Production facts are only the actual side of this comparison. All expected
// instructions, slots, values and contexts came from the independent execution.
func checkRegionOccurrenceProof(t testing.TB, source computationSource, in regionInput, oraclePrefix, oracleWhole storageSourceResult) {
	t.Helper()
	prefix, err := checkSourceOperandPrefix(t.Context(), source, in.root, oraclePrefix.Cut, defaultRegistrationLimits())
	if err != nil {
		t.Fatalf("closed loop prefix: %v", err)
	}
	returns := storageOracleInstructions[*ssa.Return](in.root)
	if len(returns) != 1 {
		t.Fatal("closed root lacks its one actual return")
	}
	complete, err := checkSourceReturnContinuation(t.Context(), prefix, returns[0], nil)
	if err != nil {
		t.Fatalf("closed loop continuation: %v", err)
	}
	packet := complete.checkedPacket()
	if packet == nil || prefix.checkedPacket() == nil || packet.input.selection != source.prog || prefix.region.packet.input.selection != source.prog {
		t.Fatal("loop proof lost authenticated completion or selected sizes")
	}
	var instructions []regionEffectOccurrence
	var calls []regionCallApplication
	var excluded []regionExcludedEdge
	for _, trace := range []*regionEffectTrace{prefix.region.packet.trace, packet.trace} {
		instructions = append(instructions, trace.instructions...)
		calls = append(calls, trace.calls...)
		excluded = append(excluded, trace.excluded...)
	}
	if len(prefix.region.packet.trace.instructions) != len(oraclePrefix.Instructions) || len(instructions) != len(oracleWhole.Instructions) {
		t.Fatalf("proof instruction coverage prefix=%d/%d whole=%d/%d", len(prefix.region.packet.trace.instructions), len(oraclePrefix.Instructions), len(instructions), len(oracleWhole.Instructions))
	}
	contexts := map[uint64]regionInvocation{1: {}}
	proofs := map[uint64]*regionCallProof{}
	for _, invocation := range oracleWhole.Invocations[1:] {
		var selected *regionCallProof
		for _, application := range calls {
			p := application.proof
			if p.at == invocation.Call && p.target == invocation.Target && p.caller.invocation == contexts[invocation.Parent] {
				if selected != nil {
					t.Fatal("one actual invocation acquired multiple checked applications")
				}
				selected = p
			}
		}
		if selected == nil || selected.occurrences == nil || selected.entries != nil || selected.selection != source.prog {
			t.Fatal("ordinary invocation lacks its selected finite occurrence proof")
		}
		contexts[invocation.ID], proofs[invocation.ID] = selected.invocation, selected
	}
	if len(calls) != len(oracleWhole.Invocations)-1 {
		t.Fatal("call proof population differs from actual invocations")
	}
	owner := prefix.cursor.owner
	seen := map[regionEffectOccurrence]bool{}
	branch := 0
	for i, want := range oracleWhole.Instructions {
		got := instructions[i]
		if got.instruction != want.Instruction || got.invocation != contexts[want.Invocation] || got.ordinal+1 != want.Ordinal || got.owner != owner || seen[got] {
			t.Fatalf("complete occurrence projection differs at %d: %s invocation=%d ordinal=%d", i, want.Instruction, want.Invocation, want.Ordinal)
		}
		seen[got] = true
		if call, ok := want.Instruction.(*ssa.Call); ok {
			found := false
			for _, application := range calls {
				if application.proof.caller == got && application.proof.at == call {
					found = true
				}
			}
			if !found {
				t.Fatal("checked call application lost the exact invoking occurrence")
			}
		}
		if conditional, ok := want.Instruction.(*ssa.If); ok {
			if branch >= len(excluded) {
				t.Fatal("actual branch lost its complete false successor slot")
			}
			edge := excluded[branch]
			if edge.regionEffectOccurrence != got || edge.branch != conditional || edge.condition != want.Value || edge.successor != conditional.Block().Succs[1-want.Successor] {
				t.Fatal("excluded edge differs from independent control occurrence")
			}
			branch++
		}
	}
	if branch != len(excluded) || instructions[len(oraclePrefix.Instructions)] != prefix.cursor || instructions[len(instructions)-1] != complete.occurrence {
		t.Fatal("control inventory, preserved boundary cursor or executed return differs")
	}
	// Each phi is checked against its whole occurrence entry rather than a
	// componentwise union that could invent impossible cross-paired values.
	for id, proof := range proofs {
		var nodes []regionOccurrenceNode
		nodes = append(nodes, proof.occurrences.nodes...)
		at := 0
		for _, observation := range oracleWhole.Instructions {
			if observation.Invocation != id {
				continue
			}
			if observation.Instruction == observation.Instruction.Block().Instrs[0] {
				if at >= len(nodes) || nodes[at].at != (regionPoint{block: observation.Instruction.Block()}) {
					t.Fatal("finite call path lost an actual block occurrence")
				}
				at++
			}
			if phi, ok := observation.Instruction.(*ssa.Phi); ok {
				state := nodes[at-1].entry
				value := state.values[phi]
				if value.kind != regionConstant || !regionMatchesConcrete(value, state, observation.Value, 0) {
					t.Fatal("whole occurrence entry disagrees with independent simultaneous phi")
				}
			}
			if observation.Successor >= 0 {
				node := nodes[at-1]
				if len(node.slots) != len(observation.Instruction.Block().Succs) || node.end != regionOccurrenceContinue {
					t.Fatal("finite path lacks complete ordered successor slots")
				}
				for slot, disposition := range node.slots {
					want := regionOccurrenceFalse
					if slot == observation.Successor {
						want = regionOccurrenceAdvance
					}
					if disposition != want {
						t.Fatal("finite path successor disposition differs from independent execution")
					}
				}
			} else if _, returned := observation.Instruction.(*ssa.Return); returned {
				if nodes[at-1].end != regionOccurrenceReturn || len(nodes[at-1].slots) != 0 {
					t.Fatal("actual return has residual finite path slots")
				}
			}
		}
		if at != len(nodes) {
			t.Fatal("finite call path has unconsumed block occurrences")
		}
	}
	for _, event := range oracleWhole.Events {
		if event.Kind != "return" || len(event.Operands) != 1 {
			continue
		}
		found := false
		for _, application := range calls {
			if application.proof.invocation == contexts[event.Invocation] {
				value := application.outcome.value
				if value.kind != regionConstant || !regionMatchesConcrete(value, application.outcome.state, event.Operands[0], 0) {
					t.Fatal("actual ordinary callee result differs from independent return")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("concrete callee return has no checked application")
		}
	}
	state := packet.observations[0].state
	for _, object := range oracleWhole.Objects {
		global, ok := object.Site.(*ssa.Global)
		if !ok {
			t.Fatal("loop family unexpectedly allocated a local object")
		}
		value := state.memory[regionObject{kind: regionGlobal, site: global}]
		if value.kind != regionConstant || !regionMatchesConcrete(value, state, object.Value, 0) {
			t.Fatalf("exact final global %s differs from independent execution", global.Name())
		}
	}
}

func checkRegionOracleLoopVisits(t testing.TB, c regionOccurrenceOracleCase, function *ssa.Function, result storageSourceResult) {
	t.Helper()
	var header *ssa.BasicBlock
	for _, instruction := range storageOracleInstructions[*ssa.BinOp](function) {
		if instruction.Op == token.LSS {
			header = instruction.Block()
		}
	}
	if header == nil || len(header.Succs) != 2 {
		t.Fatal("loop family has no actual less-than header")
	}
	iterations := int(c.input)
	if c.kind == "round" {
		iterations = 0
		for value := int32(1); value < int32(c.input); value <<= 1 {
			iterations++
		}
	}
	visits := 0
	for _, observation := range result.Instructions {
		if observation.Invocation != 2 {
			continue
		}
		if phi, ok := observation.Instruction.(*ssa.Phi); ok && phi.Block() == header {
			if phi.Type().Underlying().(*types.Basic).Kind() == types.Uint {
				if observation.Value != uint64(visits) {
					t.Fatalf("counter phi visit %d=%v", visits, observation.Value)
				}
			} else if c.kind == "swap" {
				// Each carried value keeps its own initial constant and swaps
				// simultaneously on the backedge. Sequential assignment would
				// collapse both values even though their static phis differ.
				initial, ok := phi.Edges[0].(*ssa.Const)
				if !ok || observation.Predecessor == nil {
					t.Fatal("swap phi lost initial constant or predecessor")
				}
				value, exact := constant.Uint64Val(initial.Value)
				if !exact || value != 7 && value != 11 {
					t.Fatal("swap phi is not one of the two correlated inputs")
				}
				if visits%2 != 0 {
					value = 18 - value
				}
				if observation.Value != value {
					t.Fatalf("correlated phi %s visit %d=%v want=%d", phi, visits, observation.Value, value)
				}
			}
		}
		if _, ok := observation.Instruction.(*ssa.If); ok && observation.Instruction.Block() == header {
			if observation.Value != (visits < iterations) || observation.Successor != map[bool]int{true: 0, false: 1}[visits < iterations] {
				t.Fatal("header branch occurrence differs from independently bounded family")
			}
			visits++
		}
	}
	if visits != iterations+1 {
		t.Fatalf("header visits=%d want=%d", visits, iterations+1)
	}
	if c.kind == "round" {
		// Entire dynamic child instruction order is fixed independently from
		// the concrete trace: entry, repeated header/body, final header, exit.
		want := slices.Clone(function.Blocks[0].Instrs)
		for i := 0; i < iterations; i++ {
			want = append(want, header.Instrs...)
			want = append(want, header.Succs[0].Instrs...)
		}
		want = append(want, header.Instrs...)
		want = append(want, header.Succs[1].Instrs...)
		var got []ssa.Instruction
		for _, observation := range result.Instructions {
			if observation.Invocation == 2 {
				got = append(got, observation.Instruction)
			}
		}
		if !slices.Equal(got, want) {
			t.Fatal("round loop complete instruction projection differs from header/body/exit order")
		}
	}
}

// Validate the inventory against static SSA successors and actual call/return
// nesting. This neither reconstructs answers from production traces nor permits
// a repeated instruction to collapse onto its first visit.
func checkRegionOracleInstructionOrder(t testing.TB, result storageSourceResult) {
	t.Helper()
	next := map[uint64]ssa.Instruction{}
	pred := map[uint64]*ssa.BasicBlock{}
	ordinals := map[uint64]uint64{}
	stack := []uint64{1}
	for _, invocation := range result.Invocations {
		next[invocation.ID] = invocation.Target.Blocks[0].Instrs[0]
	}
	child := uint64(2)
	for _, observation := range result.Instructions {
		id, ins := observation.Invocation, observation.Instruction
		ordinals[id]++
		if len(stack) == 0 || stack[len(stack)-1] != id || observation.Ordinal != ordinals[id] || next[id] != ins || pred[id] != observation.Predecessor {
			t.Fatalf("instruction order/phi predecessor differs at invocation=%d ordinal=%d: %s", id, observation.Ordinal, ins)
		}
		block := ins.Block()
		index := slices.Index(block.Instrs, ins)
		if observation.Successor >= 0 {
			if index != len(block.Instrs)-1 || observation.Successor >= len(block.Succs) {
				t.Fatal("control occurrence has no actual ordered successor slot")
			}
			if _, ok := ins.(*ssa.If); ok {
				if observation.Value != (observation.Successor == 0) {
					t.Fatal("branch value disagrees with actual taken slot")
				}
			} else if _, ok := ins.(*ssa.Jump); !ok || observation.Successor != 0 {
				t.Fatal("non-control instruction supplied successor evidence")
			}
			next[id], pred[id] = block.Succs[observation.Successor].Instrs[0], block
		} else if _, returned := ins.(*ssa.Return); returned {
			delete(next, id)
			stack = stack[:len(stack)-1]
		} else {
			if index+1 == len(block.Instrs) {
				t.Fatal("unterminated actual block occurrence")
			}
			next[id] = block.Instrs[index+1]
		}
		if call, ok := ins.(*ssa.Call); ok {
			if child > uint64(len(result.Invocations)) {
				t.Fatal("call instruction has no actual child invocation")
			}
			invocation := result.Invocations[child-1]
			if invocation.Call != call || invocation.Parent != id || invocation.Target != call.Call.StaticCallee() {
				t.Fatal("instruction call child has wrong context")
			}
			stack = append(stack, child)
			child++
		}
	}
	if len(stack) != 0 || len(next) != 0 || child != uint64(len(result.Invocations)+1) {
		t.Fatal("complete instruction inventory has residual frames or edges")
	}
}

func TestRegionOccurrenceOraclePopulation(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, kind := range []string{"round", "bounded", "swap"} {
			inputs := []int64{0, 1, 2, 3, 7}
			if kind == "round" {
				inputs = []int64{-1, 0, 1, 2, 3, 7, 16, 2048, 1 << 30}
			}
			for _, input := range inputs {
				c := regionOccurrenceOracleCase{kind, word, input}
				t.Run(fmt.Sprintf("%s/word%d/input%d", kind, word, input), func(t *testing.T) { checkRegionOccurrenceOracle(t, c) })
			}
		}
	}
	t.Log("38 sampled closed-source loop configurations across selected 32/64-bit uint, including modular overflow and simultaneous correlated phi swaps")
}

func FuzzRegionOccurrenceOracle(f *testing.F) {
	for kind := uint8(0); kind < 3; kind++ {
		for _, word := range []bool{false, true} {
			for _, seed := range []uint16{0, 1, 7, 2048} {
				f.Add(kind, word, seed)
			}
		}
	}
	f.Fuzz(func(t *testing.T, kind uint8, wide bool, seed uint16) {
		word := 32
		if wide {
			word = 64
		}
		c := regionOccurrenceOracleCase{[]string{"round", "bounded", "swap"}[kind%3], word, int64(seed % 8)}
		if c.kind == "round" {
			c.input = int64(seed)
		}
		checkRegionOccurrenceOracle(t, c)
	})
}

func TestRegionOccurrenceOracleRefusal(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, input := range []int64{1<<30 + 1, 1<<31 - 1} {
			_, in, config := regionOccurrenceOracleFixture(t, regionOccurrenceOracleCase{"round", word, input})
			config.Whole, config.MaxSteps = true, 300
			result, err := executeStorageSource(t, in, config)
			if err == nil || !strings.Contains(err.Error(), "instruction budget exhausted") || !reflect.DeepEqual(result, storageSourceResult{}) {
				t.Fatalf("nonterminating int32 round input returned partial/positive answer: %+v %v", result, err)
			}
		}
	}
	_, in, config := regionOccurrenceOracleFixture(t, regionOccurrenceOracleCase{"round", 64, 2048})
	config.Whole = true
	complete, err := executeStorageSource(t, in, config)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxSteps = len(complete.Instructions)
	if _, err := executeStorageSource(t, in, config); err != nil {
		t.Fatalf("exact instruction budget refused: %v", err)
	}
	config.MaxSteps--
	if result, err := executeStorageSource(t, in, config); err == nil || !reflect.DeepEqual(result, storageSourceResult{}) {
		t.Fatal("one missing instruction certified completion")
	}
}

func TestRegionOccurrenceOracleSourceRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		word       int
	}{
		{"unknown-bound", strings.Replace((regionOccurrenceOracleCase{"round", 64, 7}).sourceText(), "input=7;", "", 1), 64},
		{"unclosed-int32-word32", (regionOccurrenceOracleCase{"round", 32, 1<<30 + 1}).sourceText(), 32},
		{"unclosed-int32-word64", (regionOccurrenceOracleCase{"round", 64, 1<<30 + 1}).sourceText(), 64},
		{"negative-shift", `var count int64;var output int32;func Mark(){};func F(){count=-1;output=1<<count;Mark()}`, 64},
		{"recurrent-call", `var output uint;func Step(x uint)uint{return x+1};func Mark(){};func F(){for i:=uint(0);i<3;i++{output=Step(i)};Mark()}`, 64},
		{"recurrent-allocation", `var output *uint;func Mark(){};func F(){for i:=uint(0);i<3;i++{x:=i;output=&x};Mark()}`, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, tc.word)
			root := source.prog.Roots["F"]
			var cut *ssa.Call
			for _, call := range storageOracleInstructions[*ssa.Call](root) {
				if call.Call.StaticCallee() == root.Pkg.Func("Mark") {
					cut = call
				}
			}
			if cut == nil {
				t.Fatal("refusal control lost actual boundary")
			}
			limits := defaultRegistrationLimits()
			limits.region.work = 30000
			limits.region.nodes = 512
			if prefix, err := checkSourceOperandPrefix(t.Context(), source, root, cut, limits); err == nil || prefix != nil {
				t.Fatal("unsupported/unclosed source execution produced a finite certificate")
			}
		})
	}
}

func TestRegionOccurrenceOracleUnsignedShiftCount(t *testing.T) {
	for _, word := range []int{32, 64} {
		source := relationFixture(t, `var input int32;var count uint64;func F()int32{return input<<count}`, word)
		root := source.prog.Roots["F"]
		input, count := root.Pkg.Members["input"].(*ssa.Global), root.Pkg.Members["count"].(*ssa.Global)
		for _, tc := range []struct {
			input int64
			count uint64
			want  int64
		}{
			{-1, 0, -1}, {-1, 1, -2}, {-1, 31, -1 << 31}, {-1, 32, 0}, {1, 64, 0}, {1, 1 << 63, 0}, {1, ^uint64(0), 0},
		} {
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{input: tc.input, count: tc.count}})
			if err != nil || !reflect.DeepEqual(result.Results, []any{tc.want}) {
				t.Fatalf("signed left=%d unsigned count=%d: result=%v err=%v", tc.input, tc.count, result.Results, err)
			}
		}
	}
}

func TestRegionOccurrenceOracleRepeatedInvocationObjects(t *testing.T) {
	source := relationFixture(t, `var first,last *uint
func Make(v uint)*uint{x:=v;return &x}
func F(){for i:=uint(0);i<3;i++ {p:=Make(i);if i==0{first=p};last=p};*last=9}`, 64)
	root := source.prog.Roots["F"]
	first, last := root.Pkg.Members["first"].(*ssa.Global), root.Pkg.Members["last"].(*ssa.Global)
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{first: nil, last: nil}})
	if err != nil {
		t.Fatal(err)
	}
	checkRegionOracleInstructionOrder(t, result)
	var objects []storageSourceObject
	var invocations []storageSourceInvocation
	for _, object := range result.Objects {
		if _, allocation := object.Site.(*ssa.Alloc); allocation {
			objects = append(objects, object)
		}
	}
	for _, invocation := range result.Invocations[1:] {
		invocations = append(invocations, invocation)
	}
	if len(objects) != 3 || len(invocations) != 3 {
		t.Fatal("repeated call lost its three actual dynamic objects")
	}
	for i, want := range []uint64{0, 1, 9} {
		if objects[i].Value != want || objects[i].Site != objects[0].Site || objects[i].Invocation != invocations[i].ID || !invocations[i].Returned || invocations[i].Call != invocations[0].Call {
			t.Fatal("repeated static invocation/allocation pooled distinct live objects")
		}
		for j := 0; j < i; j++ {
			if objects[i].ID == objects[j].ID || objects[i].Invocation == objects[j].Invocation {
				t.Fatal("dynamic object/invocation identities collapsed")
			}
		}
	}
	for _, object := range result.Objects {
		if object.Site == first && object.Value.(storageSourceLocation).Object != objects[0].ID || object.Site == last && object.Value.(storageSourceLocation).Object != objects[2].ID {
			t.Fatal("escaped pointers lost their exact earlier or last allocation")
		}
	}
}

func TestRegionOccurrenceOracleIntegerBoundaries(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, typ := range []string{"int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "int", "uint", "uintptr"} {
			t.Run(fmt.Sprintf("word%d/%s", word, typ), func(t *testing.T) {
				source := relationFixture(t, fmt.Sprintf(`type N %s;var a,b N;var count int64;func Add(x,y N)N{return x+y};func Shift(x N,n int64)N{return x<<n};func F()(N,N){return Add(a,b),Shift(a,count)}`, typ), word)
				root := source.prog.Roots["F"]
				global := func(name string) *ssa.Global { return root.Pkg.Members[name].(*ssa.Global) }
				sizes := source.prog.Pkgs[0].TypesSizes
				named := global("a").Type().Underlying().(*types.Pointer).Elem()
				width := uint(sizes.Sizeof(named) * 8)
				unsigned := named.Underlying().(*types.Basic).Info()&types.IsUnsigned != 0
				mask := ^uint64(0) >> (64 - width)
				var a, b, add any
				if unsigned {
					a, b, add = mask, uint64(1), uint64(0)
				} else {
					a, b, add = int64(mask>>1), int64(1), -int64(mask>>1)-1
				}
				for _, count := range []int64{0, int64(width - 1), int64(width), int64(width + 1), 127, 1 << 62, -1} {
					config := storageSourceRun{Sizes: sizes, Whole: true, Globals: map[*ssa.Global]any{global("a"): a, global("b"): b, global("count"): count}}
					result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, config)
					if count < 0 {
						if err == nil || !strings.Contains(err.Error(), "negative shift count") || !reflect.DeepEqual(result, storageSourceResult{}) {
							t.Fatal("negative shift count produced a result")
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					var shifted any
					if count == 0 {
						shifted = a
					} else if count == int64(width-1) {
						if unsigned {
							shifted = uint64(1) << (width - 1)
						} else {
							shifted = -int64(mask>>1) - 1
						}
					} else if unsigned {
						shifted = uint64(0)
					} else {
						shifted = int64(0)
					}
					if !reflect.DeepEqual(result.Results, []any{add, shifted}) {
						t.Fatalf("width=%d count=%d got=%v want=%v", width, count, result.Results, []any{add, shifted})
					}
					for _, name := range []string{"Add", "Shift"} {
						ops := storageOracleInstructions[*ssa.BinOp](root.Pkg.Func(name))
						want := token.ADD
						if name == "Shift" {
							want = token.SHL
						}
						if len(ops) != 1 || ops[0].Op != want || !types.Identical(ops[0].Type(), named) {
							t.Fatal("typed source decoded a different operator/result boundary")
						}
					}
				}
			})
		}
	}
}

func TestRegionOccurrenceOracleCompoundObservations(t *testing.T) {
	for _, tc := range []struct {
		name, kind, text string
		phi              bool
	}{
		{"interface", "interface", `func F()bool{var x any=7;return x==nil}`, false},
		{"typed-nil-interface", "typed-nil-interface", `func F()bool{var p *int;var x any=p;return x==nil}`, false},
		{"function", "function", `func Plain(){};func F()bool{x:=Plain;return x==nil}`, false},
		{"closure", "closure", `func F()bool{v:=7;x:=func()int{return v};return x==nil}`, false},
		{"slice", "slice", `func F()bool{a:=[2]int{7,9};x:=a[:1];return x==nil}`, false},
		{"empty-slice", "empty-slice", `func F()bool{var a [0]int;x:=a[:];return x==nil}`, false},
		{"empty-view", "empty-view", `func F()bool{var a [2]int;x:=a[1:1];return x==nil}`, false},
		{"zero-sized-elements", "zero-sized-elements", `func F()bool{var a [2]struct{};x:=a[:];return x==nil}`, false},
		{"interface-phi", "interface", `var choose bool;func F()bool{var x any=7;if choose{x=int64(9)};return x==nil}`, true},
		{"function-phi", "function", `var choose bool;func Plain(){};func Other(){};func F()bool{x:=Plain;if choose{x=Other};return x==nil}`, true},
		{"slice-phi", "slice", `var choose bool;func F()bool{a:=[2]int{7,9};x:=a[:1];if choose{x=a[1:]};return x==nil}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, 64)
			root := source.prog.Roots["F"]
			choices := []bool{false}
			if tc.phi {
				choices = append(choices, true)
			}
			for _, choose := range choices {
				config := storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{}}
				if tc.phi {
					config.Globals[root.Pkg.Members["choose"].(*ssa.Global)] = choose
				}
				result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, config)
				if err != nil || !result.Returned || !reflect.DeepEqual(result.Results, []any{false}) {
					t.Fatalf("previously executable nonnil %s comparison failed: result=%v err=%v", tc.kind, result.Results, err)
				}
				var operand, phi any
				comparisons, phis := 0, 0
				for _, observation := range result.Instructions {
					switch instruction := observation.Instruction.(type) {
					case *ssa.BinOp:
						if instruction.Op != token.EQL || len(observation.Operands) != 2 || observation.Operands[1] != nil || observation.Value != false {
							t.Fatal("nil comparison lost exact operand/result observations")
						}
						operand = observation.Operands[0]
						comparisons++
					case *ssa.Phi:
						if observation.Predecessor == nil {
							t.Fatal("compound phi lost its actual predecessor")
						}
						phi = observation.Value
						phis++
					}
				}
				if comparisons != 1 || tc.phi && (phis != 1 || !reflect.DeepEqual(phi, operand)) || !tc.phi && phis != 0 {
					t.Fatal("compound instruction observations omitted the actual comparison or phi")
				}
				switch tc.kind {
				case "typed-nil-interface":
					got, ok := operand.(storageSourceInterface)
					if !ok || !types.Identical(got.Type, types.NewPointer(types.Typ[types.Int])) || got.Value != nil {
						t.Fatal("typed nil interface collapsed into a nil interface")
					}
				case "interface":
					got, ok := operand.(storageSourceInterface)
					kind, value := types.Int, int64(7)
					if choose {
						kind, value = types.Int64, 9
					}
					if !ok || !types.Identical(got.Type, types.Typ[kind]) || got.Value != value {
						t.Fatalf("interface observation lost dynamic type/value: %+v", operand)
					}
				case "function":
					got, ok := operand.(storageSourceFunction)
					name := "Plain"
					if choose {
						name = "Other"
					}
					if !ok || got.Target != root.Pkg.Func(name) || len(got.Environment) != 0 {
						t.Fatal("function observation lost actual selected target")
					}
				case "closure":
					got, ok := operand.(storageSourceFunction)
					closures := storageOracleInstructions[*ssa.MakeClosure](root)
					if !ok || len(closures) != 1 || got.Target != closures[0].Fn || len(got.Environment) != 1 || len(result.Objects) != 1 {
						t.Fatal("closure observation lost target or captured cell")
					}
					if location, ok := got.Environment[0].(storageSourceLocation); !ok || location.Object != result.Objects[0].ID || len(location.Path) != 0 || result.Objects[0].Value != int64(7) {
						t.Fatal("closure snapshot copied contents instead of retaining cell identity")
					}
				case "slice", "empty-slice", "empty-view", "zero-sized-elements":
					got, ok := operand.(storageSourceSlice)
					start, length, capacity, cells := 0, 1, 2, 2
					if choose {
						start, capacity = 1, 1
					}
					if tc.kind == "empty-slice" {
						length, capacity, cells = 0, 0, 0
					}
					if tc.kind == "empty-view" {
						start, length, capacity = 1, 0, 1
					}
					if tc.kind == "zero-sized-elements" {
						length = 2
					}
					if !ok || got.Start != start || got.Length != length || got.Capacity != capacity || len(got.Cells) != cells {
						t.Fatalf("slice observation lost its nonnil descriptor: %+v", operand)
					}
					var object storageSourceObject
					views := storageOracleInstructions[*ssa.Slice](root)
					if len(views) == 0 {
						t.Fatal("slice fixture has no actual slice operation")
					}
					for _, candidate := range result.Objects {
						if candidate.Site == views[0].X {
							object = candidate
						}
					}
					if object.ID == 0 {
						t.Fatal("slice fixture lost backing array")
					}
					for i, location := range got.Cells {
						offset := int64(i) * config.Sizes.Sizeof(types.Typ[types.Int])
						if tc.kind == "zero-sized-elements" {
							offset = 0
						}
						if location.Object != object.ID || !slices.Equal(location.Path, []int{i}) || location.Offset != offset {
							t.Fatalf("slice snapshot invented an address or lost backing-cell identity: cell=%+v expected object=%+v offset=%d all objects=%+v", location, object, offset, result.Objects)
						}
					}
					if tc.phi {
						phi.(storageSourceSlice).Cells[0].Path[0] = 99
						if got.Cells[0].Path[0] != 0 {
							t.Fatal("phi and comparison slice snapshots share mutable paths")
						}
					}
				}
			}
		})
	}
}

func TestRegionOccurrenceOracleCompoundSnapshotOwnership(t *testing.T) {
	source := relationFixture(t, `func Target(){};func F(){var a [2]int32;_ = &a}`, 64)
	target := source.prog.Roots["F"].Pkg.Func("Target")
	run := &regionConcreteExecution{sizes: source.prog.Pkgs[0].TypesSizes, cells: map[*any]storageSourceLocation{}}
	var cell any = []any{int64(7), int64(9)}
	arrayType := types.NewArray(types.Typ[types.Int32], 2)
	location := run.object(nil, 1, arrayType, &cell)
	backing := cell.([]any)
	pointer := regionConcretePointer{cell: &backing[1]}
	view := regionConcreteSlice{cells: backing, start: 1, length: 1, capacity: 1}
	aggregate := []any{[]any{int64(11)}, pointer, view}
	box := regionConcreteInterface{typ: arrayType, value: []any{int64(3), int64(5)}}
	function := regionConcreteFunction{target: target, environment: []any{aggregate, box}}
	first := run.snapshot(function).(storageSourceFunction)
	second := run.snapshot(function).(storageSourceFunction)
	firstAggregate := first.Environment[0].([]any)
	secondAggregate := second.Environment[0].([]any)
	firstSlice := firstAggregate[2].(storageSourceSlice)
	secondSlice := secondAggregate[2].(storageSourceSlice)
	alias := firstAggregate[1].(storageSourceLocation)
	if first.Target != target || second.Target != target || !reflect.DeepEqual(alias, firstSlice.Cells[firstSlice.Start]) || alias.Object != location.Object {
		t.Fatal("nested snapshot lost function identity or pointer/slice alias")
	}
	// Editing one observation cannot change a neighbor, the live closure
	// environment, the boxed by-value aggregate, or the location registry.
	firstAggregate[0].([]any)[0] = int64(99)
	first.Environment[1].(storageSourceInterface).Value.([]any)[0] = int64(99)
	firstSlice.Cells[1].Path[0] = 99
	firstSlice.Cells[0].Object = 99
	alias.Path[0] = 88
	if secondAggregate[0].([]any)[0] != int64(11) || aggregate[0].([]any)[0] != int64(11) || second.Environment[1].(storageSourceInterface).Value.([]any)[0] != int64(3) || box.value.([]any)[0] != int64(3) || secondSlice.Cells[1].Path[0] != 1 || secondSlice.Cells[0].Object != location.Object || run.location(pointer).Path[0] != 1 {
		t.Fatal("compound snapshot borrowed mutable containers")
	}
	// Pointer-like snapshots describe cells, never frozen copies of pointees.
	// A live store updates both aliases while the retained location stays valid.
	regionConcreteStore(pointer.cell, int64(17))
	if view.cells[1] != int64(17) || !reflect.DeepEqual(secondSlice, run.snapshot(view)) || secondAggregate[1].(storageSourceLocation).Object != location.Object {
		t.Fatal("slice observation copied backing contents or lost live alias identity")
	}
	// Zero backing extent has no invented cell/address; a nonnil descriptor is
	// still observably distinct from the nil slice/interface value.
	empty := run.snapshot(regionConcreteSlice{})
	if empty == nil || run.snapshot(nil) != nil || len(empty.(storageSourceSlice).Cells) != 0 {
		t.Fatal("empty nonnil slice collapsed into nil or acquired a cell")
	}
}

func TestRegionOccurrenceOracleSliceRegressions(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		refused    bool
	}{
		{"nil-slice", `func F()bool{var x []int;return x[:0]==nil}`, false},
		{"negative-high", `var high int;func F()bool{a:=[1]int{7};return a[:high]==nil}`, true},
		{"index-at-length", `func F()bool{a:=[2]int{7,9};s:=a[:0];return s[0]==7}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, 64)
			root := source.prog.Roots["F"]
			config := storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{}}
			if member, ok := root.Pkg.Members["high"]; ok {
				config.Globals[member.(*ssa.Global)] = int64(-1)
			}
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, config)
			if tc.refused {
				if err == nil || !reflect.DeepEqual(result, storageSourceResult{}) {
					t.Fatalf("exceptional slice/index returned an answer: %+v %v", result, err)
				}
			} else if err != nil || !reflect.DeepEqual(result.Results, []any{true}) {
				t.Fatalf("valid nil slicing changed nilness: %+v %v", result, err)
			}
		})
	}
}

func TestRegionOccurrenceOracleNilArrayPointerContract(t *testing.T) {
	// The language's pointer-to-array slicing shorthand dereferences the pointer,
	// including a zero-length array. This direct Go control guards that nuance;
	// it is not the distinct nil-slice case, whose valid slices remain nil.
	for name, operation := range map[string]func(){
		"zero-simple":    func() { var p *[0]int; _ = p[:0] },
		"zero-full":      func() { var p *[0]int; _ = p[:0:0] },
		"nonzero-simple": func() { var p *[1]int; _ = p[:0] },
		"nonzero-full":   func() { var p *[1]int; _ = p[:0:0] },
	} {
		t.Run(name, func(t *testing.T) {
			panicked := false
			func() { defer func() { panicked = recover() != nil }(); operation() }()
			if !panicked {
				t.Fatal("Go did not panic on nil array-pointer slicing")
			}
		})
	}
	var nilSlice []int
	if nilSlice[:0] != nil || nilSlice[:0:0] != nil {
		t.Fatal("Go changed nil-slice slicing nilness")
	}
}

func TestRegionOccurrenceOracleSliceBounds(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, unsigned := range []bool{false, true} {
			boundType := "int64"
			if unsigned {
				boundType = "uint64"
			}
			for _, shape := range []struct {
				name, body, result string
				capacity           int
				full, nilSlice     bool
			}{
				{"array", `var a [3]int;return a[low:high]`, "[]int", 3, false, false},
				{"array-pointer", `var a [3]int;p:=&a;return p[low:high]`, "[]int", 3, false, false},
				{"slice", `var a [3]int;s:=a[:1];return s[low:high]`, "[]int", 3, false, false},
				{"full", `var a [3]int;s:=a[:1];return s[low:high:max]`, "[]int", 3, true, false},
				{"short-capacity", `var a [3]int;s:=a[:2:2];return s[low:high]`, "[]int", 2, false, false},
				{"nil", `var s []int;return s[low:high]`, "[]int", 0, false, true},
				{"nil-full", `var s []int;return s[low:high:max]`, "[]int", 0, true, true},
				{"string", `return "abc"[low:high]`, "string", 3, false, false},
			} {
				t.Run(fmt.Sprintf("word%d/%s/%s", word, boundType, shape.name), func(t *testing.T) {
					source := relationFixture(t, fmt.Sprintf("var low,high,max %s;func F()%s{%s}", boundType, shape.result, shape.body), word)
					root := source.prog.Roots["F"]
					for _, bounds := range [][3]int64{{0, 0, 0}, {0, 1, 1}, {0, 3, 3}, {1, 2, 3}, {2, 1, 3}, {-1, 1, 3}, {0, -1, 3}, {0, 1, -1}, {0, 2, 1}, {0, 1, 4}, {0, 1 << 32, 3}, {1 << 32, 1 << 32, 1 << 32}, {0, 1<<63 - 1, 3}} {
						config := storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{}}
						for i, name := range []string{"low", "high", "max"} {
							var value any = bounds[i]
							if unsigned {
								value = uint64(bounds[i])
							}
							config.Globals[root.Pkg.Members[name].(*ssa.Global)] = value
						}
						low, high, max := bounds[0], bounds[1], int64(shape.capacity)
						if shape.full {
							max = bounds[2]
						}
						valid := 0 <= low && low <= high && high <= max && max <= int64(shape.capacity)
						result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, config)
						if !valid {
							if _, failure := err.(regionConcreteFailure); !failure || !reflect.DeepEqual(result, storageSourceResult{}) {
								t.Fatalf("out-of-range %v returned a partial/positive result: %+v %v", bounds, result, err)
							}
							continue
						}
						if err != nil || !result.Returned || len(result.Results) != 1 {
							t.Fatalf("valid bounds %v refused: %+v %v", bounds, result.Results, err)
						}
						if shape.result == "string" {
							if result.Results[0] != "abc"[low:high] {
								t.Fatal("string bounds changed bytes")
							}
						} else if shape.nilSlice {
							if result.Results[0] != nil {
								t.Fatal("nil slicing fabricated a nonnil descriptor")
							}
						} else {
							view, ok := result.Results[0].(storageSourceSlice)
							if !ok || view.Start != int(low) || view.Length != int(high-low) || view.Capacity != int(max-low) || len(view.Cells) != 3 {
								t.Fatalf("slice bounds %v lost descriptor: %+v", bounds, result.Results[0])
							}
							for i, location := range view.Cells {
								if location.Object != view.Cells[0].Object || !slices.Equal(location.Path, []int{i}) || location.Offset != int64(i)*config.Sizes.Sizeof(types.Typ[types.Int]) {
									t.Fatal("bounded slice lost common backing-cell aliases")
								}
							}
						}
					}
				})
			}
		}
	}
}

func TestRegionOccurrenceOracleIndexBounds(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, unsigned := range []bool{false, true} {
			boundType := "int64"
			if unsigned {
				boundType = "uint64"
			}
			for _, shape := range []struct {
				name, body, result string
				length             int
			}{
				{"slice", `var a [3]int;s:=a[1:2];return s[index]`, "int", 1},
				{"empty-slice", `var a [3]int;s:=a[:0];return s[index]`, "int", 0},
				{"array", `var a [3]int;return a[index]`, "int", 3},
				{"array-pointer", `var a [3]int;p:=&a;return p[index]`, "int", 3},
				{"array-value", `return Value()[index]`, "int", 3},
				{"nil-slice", `var s []int;return s[index]`, "int", 0},
				{"nil-array-pointer", `var p *[3]int;return p[index]`, "int", 0},
				{"string", `return "abc"[index]`, "byte", 3},
			} {
				t.Run(fmt.Sprintf("word%d/%s/%s", word, boundType, shape.name), func(t *testing.T) {
					source := relationFixture(t, fmt.Sprintf("var index %s;func Value()[3]int{return [3]int{}};func F()%s{%s}", boundType, shape.result, shape.body), word)
					root := source.prog.Roots["F"]
					for _, index := range []int64{0, 1, 2, 3, -1, 1 << 32, 1<<63 - 1} {
						var value any = index
						if unsigned {
							value = uint64(index)
						}
						result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true, Globals: map[*ssa.Global]any{root.Pkg.Members["index"].(*ssa.Global): value}})
						if index < 0 || index >= int64(shape.length) {
							if _, failure := err.(regionConcreteFailure); !failure || !reflect.DeepEqual(result, storageSourceResult{}) {
								t.Fatalf("exceptional index %d returned an answer: %+v %v", index, result, err)
							}
							continue
						}
						var want any = int64(0)
						if shape.result == "byte" {
							want = uint64("abc"[index])
						}
						if err != nil || !reflect.DeepEqual(result.Results, []any{want}) {
							t.Fatalf("valid index %d differs: %v %v", index, result.Results, err)
						}
					}
				})
			}
		}
	}
}

func TestRegionOccurrenceOracleSliceNilnessAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       []any
		refused    bool
	}{
		{"nil-defaults", `func F()(bool,int,int){var s []int;v:=s[:];return v==nil,len(v),cap(v)}`, []any{true, int64(0), int64(0)}, false},
		{"nil-full", `func F()(bool,int,int){var s []int;v:=s[:0:0];return v==nil,len(v),cap(v)}`, []any{true, int64(0), int64(0)}, false},
		{"empty-array", `func F()(bool,int,int){var a [0]int;v:=(&a)[:0:0];return v==nil,len(v),cap(v)}`, []any{false, int64(0), int64(0)}, false},
		{"alias-and-default-high", `func F()(int,int,int,int,int,int,int,bool){var a [3]int;s:=a[1:2:3];t:=s[:2];u:=s[:];t[1]=17;return a[2],len(s),cap(s),len(t),cap(t),len(u),cap(u),t==nil}`, []any{int64(17), int64(1), int64(2), int64(2), int64(2), int64(1), int64(2), false}, false},
		{"nil-zero-array", `func F()bool{var p *[0]int;return p[:0]==nil}`, nil, true},
		{"nil-zero-array-full", `func F()bool{var p *[0]int;return p[:0:0]==nil}`, nil, true},
		{"nil-array", `func F()bool{var p *[1]int;return p[:0]==nil}`, nil, true},
		{"nil-array-full", `func F()bool{var p *[1]int;return p[:0:0]==nil}`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, 64)
			root := source.prog.Roots["F"]
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
			if tc.refused {
				if _, failure := err.(regionConcreteFailure); !failure || !reflect.DeepEqual(result, storageSourceResult{}) {
					t.Fatalf("nil array-pointer slicing returned an answer: %+v %v", result, err)
				}
			} else if err != nil || !reflect.DeepEqual(result.Results, tc.want) {
				t.Fatalf("slice nilness/alias/extent differs: %v want %v err %v", result.Results, tc.want, err)
			}
		})
	}
}
