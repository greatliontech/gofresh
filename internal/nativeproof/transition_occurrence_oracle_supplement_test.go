package nativeproof

import (
	"fmt"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Eight supplemental executions: two layouts crossed with exit after query
// one, two, three, or no outcome exit. The structural loop ceiling remains three.
// These tests qualify the reference, not production guards/frontier proofs.
func TestOccurrenceOracleOutcomeExit(t *testing.T) {
	for layout := 0; layout < 2; layout++ {
		p := occurrenceOracleBuildVariant(t, occurrenceOracleLocal, occurrenceOracleQuery, layout, 3, occurrenceOracleEarlyQuery)
		for exit := 0; exit <= 3; exit++ {
			t.Run(fmt.Sprintf("layout%d/exit%d", layout, exit), func(t *testing.T) {
				input := occurrenceOracleInitial(p, 3, 0)
				if exit != 0 {
					input.state.outcomes[exit-1][0] = 0
				}
				count := exit
				if count == 0 {
					count = 3
				}
				r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
				if err != nil {
					t.Fatal(err)
				}
				occurrenceOracleAssertReference(t, p, input, r, count)
				occurrenceOracleCheckPayload(t, p, input, r, count)
				increments := 0
				for _, visit := range r.visits {
					if p.ops[visit.instruction].intent.Operation == to.Increment64 {
						increments++
					}
				}
				wantIncrements := count
				if exit != 0 {
					wantIncrements--
				}
				if increments != wantIncrements || r.state.regs[R12] != uint64(wantIncrements) {
					t.Fatal("outcome exit occurred after an invented increment")
				}
				cut := occurrenceOracleCut{instruction: p.earlyExit, encounter: count}
				prefix, err := occurrenceOracleRunTo(t, t.Context(), p, input, 2048, &cut)
				if err != nil {
					t.Fatal(err)
				}
				// Incoming CMP EAX,0 flags live in state. An unexecuted branch's
				// post-execution snapshot is deliberately unset.
				if prefix.state.flags[0] || prefix.state.flags[1] != (exit != 0) || prefix.state.regs[RAX] != uint64(input.state.outcomes[count-1][0]) || prefix.boundary.after != ([16]uint64{}) || prefix.boundary.flags != ([6]bool{}) || prefix.boundary.defined != ([6]bool{}) {
					t.Fatal("outcome-branch cut lost incoming flags or executed its boundary")
				}
			})
		}
	}
}

// Four supplemental executions with identical selectors and distinct response
// tuples. Actual MOVs reset EAX/ECX before every query; final MOVs erase results.
func TestOccurrenceOracleRepeatedSelectors(t *testing.T) {
	for layout := 0; layout < 2; layout++ {
		p := occurrenceOracleBuildVariant(t, occurrenceOracleLocal, occurrenceOracleQuery, layout, 3, occurrenceOracleResetQuery)
		for variant := 0; variant < 2; variant++ {
			t.Run(fmt.Sprintf("layout%d/value%d", layout, variant), func(t *testing.T) {
				input := occurrenceOracleInitial(p, 3, variant)
				r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
				if err != nil {
					t.Fatal(err)
				}
				occurrenceOracleAssertReference(t, p, input, r, 3)
				occurrenceOracleCheckPayload(t, p, input, r, 3)
				seen := map[[4]uint32]bool{}
				instruction := -1
				for _, primitive := range r.state.primitives {
					query, ok := primitive.(stateQuery)
					if !ok || query.leaf != occurrenceOracleFixedLeaf || query.subleaf != occurrenceOracleFixedSubleaf || seen[query.results] || instruction >= 0 && query.instruction != instruction {
						t.Fatal("same selectors/PC collapsed distinct query history")
					}
					seen[query.results], instruction = true, query.instruction
				}
				if len(seen) != 3 || occurrenceOracleCount(p, r, instruction) != 3 {
					t.Fatal("erased query history is incomplete")
				}
			})
		}
	}
}

// Four supplemental mixed executions: S/F/S and F/S/F over two layouts. Failed
// CAS writeback, rather than the preceding query's EAX, selects the next query.
func occurrenceOracleMixedInput(p occurrenceOracleProgram, pattern int) (occurrenceOracleInput, [3]uint32, [3]uint64, [3]bool, uint32) {
	input := occurrenceOracleInitial(p, 3, 0)
	input.state.outcomes = [][4]uint32{{7, 17, 0x101, 11}, {99, 19, 0x202, 13}, {11, 23, 0x303, 0x80000001}}
	leaves := [3]uint32{7, 7, 11}
	accumulators := [3]uint64{7, 11, 11}
	success := [3]bool{true, false, true}
	word := uint32(0x80000001)
	if pattern != 0 {
		input.state.outcomes = [][4]uint32{{99, 17, 0x101, 11}, {7, 19, 0x202, 0x80000000}, {0xffffffff, 23, 0x303, 13}}
		leaves, accumulators, success, word = [3]uint32{7, 7, 7}, [3]uint64{7, 7, 0x80000000}, [3]bool{false, true, false}, 0x80000000
	}
	return input, leaves, accumulators, success, word
}

func TestOccurrenceOracleMixedSelectors(t *testing.T) {
	for layout := 0; layout < 2; layout++ {
		p := occurrenceOracleBuild(t, occurrenceOracleLocal, occurrenceOracleMixed, layout, 3)
		for pattern := 0; pattern < 2; pattern++ {
			t.Run(fmt.Sprintf("layout%d/pattern%d", layout, pattern), func(t *testing.T) {
				input, leaves, accumulators, success, word := occurrenceOracleMixedInput(p, pattern)
				r, err := occurrenceOracleRun(t, t.Context(), p, input, 2048)
				if err != nil {
					t.Fatal(err)
				}
				occurrenceOracleAssertReference(t, p, input, r, 3)
				occurrenceOracleCheckPayload(t, p, input, r, 3)
				for iteration := 0; iteration < 3; iteration++ {
					q := r.state.primitives[2*iteration].(stateQuery)
					cas := r.state.primitives[2*iteration+1].(stateRMW)
					if q.leaf != leaves[iteration] || cas.success != success[iteration] || cas.accumulator != accumulators[iteration] {
						t.Fatal("mixed selectors/CAS outcomes differ from explicit sequence")
					}
				}
				for lane := int64(0); lane < 4; lane++ {
					if r.state.memory[stateLocation{off: 16 + lane}].value != byte(word>>(8*lane)) {
						t.Fatal("mixed current narrow-memory result differs")
					}
				}
			})
		}
	}
}
