package nativeproof

import (
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Leaf values and the merge result are computed from intent, before any bytes
// or certificate exist. A merge overwrites the upper four bytes of the left
// word with the lower four bytes of the right word. Seven distinct temporaries
// preserve left subtrees while recursively constructing right subtrees. There
// are no inserted jumps and no cuts inside the construction.
func evaluationTree(levels, leafDepth int, literal uint64) ([]stateInstruction, uint64) {
	temporaries := [...]uint8{1, 2, 3, 5, 6, 7, 8}
	var program []stateInstruction
	ordinal := uint64(0)
	var emit func(int) uint64
	emit = func(level int) uint64 {
		if level == 0 {
			value := literal + ordinal*0x9e3779b97f4a7c15
			ordinal++
			program = append(program, stateOp(to.Intent{Operation: to.MoveImmediate, Dst: 0, Immediate: value}, 0))
			for j := 0; j < leafDepth; j++ {
				program = append(program, stateOp(to.Intent{Operation: to.LEA, Dst: 0, Base: 0, SignedDisp: 1}, 1))
			}
			return value + uint64(leafDepth)
		}
		left := emit(level - 1)
		temp := temporaries[level-1]
		program = append(program, stateOp(to.Intent{Operation: to.MoveRegister, Dst: temp, Src: 0}, 0))
		right := emit(level - 1)
		program = append(program,
			stateOp(to.Intent{Operation: to.Store, Base: 4, Src: temp, SignedDisp: -8}, 1),
			stateOp(to.Intent{Operation: to.Store, Base: 4, Src: 0, SignedDisp: -4}, 1),
			stateOp(to.Intent{Operation: to.Load, Base: 4, Dst: 0, SignedDisp: -8}, 1),
		)
		return left&0xffffffff | (right&0xffffffff)<<32
	}
	want := emit(levels)
	return program, want
}

func checkEvaluationTree(t testing.TB, levels, leafDepth int, literal uint64, raw []byte, reproduce bool) {
	t.Helper()
	if levels < 0 || levels > 7 || leafDepth < 0 || leafDepth+1+8*levels+2 > 512 {
		t.Fatal("evaluation-tree generator escaped its admitted depth domain")
	}
	program, scalar := evaluationTree(levels, leafDepth, literal)
	cut := len(program)
	leaves := 1 << levels
	if cut != leaves*(leafDepth+1)+4*(leaves-1) {
		t.Fatal("balanced construction instruction count changed")
	}
	program = append(program,
		stateOp(to.Intent{Operation: to.LEA, Dst: 0, Base: 0, SignedDisp: 17}, 1),
		stateOp(to.Intent{Operation: to.Store, Base: 4, Src: 0, SignedDisp: 16}, 1),
	)
	// Depth is established from the intent's constructor shape, not observed
	// from a certificate to excuse a production refusal. Each balanced merge
	// adds eight levels; the suffix adds an Add and a byte Extract.
	if len(program)+1 > 65536 {
		t.Fatal("evaluation-tree generator escaped its admitted depth/instruction domain")
	}
	face := sequenceFace(0)
	initial := stateRawInitial(face, raw)
	want := initial.clone()
	for j, op := range program[:cut] {
		want.referenceExec(t, op.intent, j)
	}
	if want.regs[0] != scalar {
		t.Fatal("numeric machine and independent balanced merge formula disagree")
	}
	final := want.clone()
	for j := cut; j < len(program); j++ {
		final.referenceExec(t, program[j].intent, j)
	}
	if final.regs[0] != scalar+17 {
		t.Fatal("independent suffix formula disagrees")
	}
	// Reference execution is complete before encoding. The production limits
	// depend on intent counts and input memory, never on the observed term graph.
	x := sequenceLayout(t, program, 0)
	limits, representable := sequenceLimits(face, len(program), len(initial.memory), 1, 65536)
	if !representable {
		t.Fatal("bounded evaluation regression has unrepresentable production limits")
	}
	c, err := CheckTransition(t.Context(), x.im, face, x.proposal(cut), limits)
	if err != nil {
		t.Fatal("admitted balanced construction refused by checker", err)
	}
	if reproduce {
		// These observations establish that the regression really reaches the
		// evaluator's former limit. They supply neither the scalar answer nor
		// a production acceptance/refusal decision.
		seen := map[br.Term]bool{}
		stack := []br.Term{c.checked.bound.Registers[0].Value}
		adds := 0
		for len(stack) != 0 {
			term := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[term] {
				continue
			}
			seen[term] = true
			v := term.View()
			if v.Op == br.Add {
				adds++
			}
			stack = append(stack, v.Args...)
		}
		height := stateTermHeight(c.checked.bound.Registers[0].Value, nil)
		t.Logf("checker accepted: instructions=%d unique_nodes=%d Add_nodes=%d depth=%d", cut, len(seen), adds, height)
		if cut != 33404 || adds != 32768 || len(seen) <= 32768 || height != 313 {
			t.Fatal("wide/shallow regression no longer reaches the intended evaluator boundary")
		}
	}
	values := stateBindings(t, c, face, initial)
	stateAssert(t, c, x, cut, initial, want, values)
	original, _ := c.Bound()
	next, err := CheckTransitionContinuation(t.Context(), c, x.proposal(len(program)))
	if err != nil {
		t.Fatal("wide DAG continuation refused", err)
	}
	stateInheritedInputs(t, original, next.checked.bound)
	stateAssert(t, next, x, len(program), initial, final, values)
	stateAssert(t, c, x, cut, initial, want, values)
}

func TestTransitionStateWideDAGEvaluation(t *testing.T) {
	checkEvaluationTree(t, 7, 256, 0x73bd, []byte{1, 2, 3, 4, 5, 6, 7, 8}, true)
}

func TestTransitionStateEvaluationLimitArithmetic(t *testing.T) {
	maximum := int(^uint(0) >> 1)
	for _, counts := range [][3]int{{1, 0, 0}, {1, 0, 1}, {34802, 70000, 16}} {
		limits, ok := stateEvaluationLimits(counts[0], counts[1], counts[2])
		if !ok || limits.Nodes < counts[0] || limits.Nodes < counts[2] || limits.Work <= 0 {
			t.Fatal("representable evaluator inventory lost its allowance", counts, limits)
		}
	}
	for _, counts := range [][3]int{{1, maximum, 0}, {maximum, 0, maximum}, {0, 0, 0}, {1, -1, 0}} {
		if limits, ok := stateEvaluationLimits(counts[0], counts[1], counts[2]); ok {
			t.Fatal("invalid/unrepresentable evaluator inventory wrapped into an allowance", counts, limits)
		}
	}
}

// This positive family varies balanced width (1..128 leaves) and every leaf
// chain depth fitting the actual 512-level constructor limit, including the
// continuation's Add/Extract. Its maximum instruction count is below the actual
// supplied 65536 limit. All cases require checker acceptance and exact state;
// an evaluator failure can never be reclassified as a production resource fault.
func FuzzTransitionStateBalancedEvaluation(f *testing.F) {
	for _, shape := range [][2]uint16{{0, 0}, {3, 17}, {6, 95}, {7, 256}} {
		f.Add(uint8(shape[0]), shape[1], uint64(0xfedcba9876543210), []byte{17, 31, 63, 127, 255})
	}
	f.Fuzz(func(t *testing.T, width uint8, chain uint16, literal uint64, raw []byte) {
		levels := int(width % 8)
		maximumChain := 512 - 1 - 8*levels - 2
		depth := int(chain) % (maximumChain + 1)
		checkEvaluationTree(t, levels, depth, literal, raw, false)
	})
}
