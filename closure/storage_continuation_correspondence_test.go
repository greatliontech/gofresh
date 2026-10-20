package closure

import (
	"fmt"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// Continue the actual opaque native endpoint; rebuilding a root at a later cut
// would not exercise retention of its arbitrary inputs and occurrence identities.
func storageContinuationNative(t testing.TB, fixture storageJointNative, prior nativeproof.TransitionCertificate, cut uint64) nativeproof.TransitionCertificate {
	t.Helper()
	bound, owned := prior.BoundFor(fixture.image)
	if !owned {
		t.Fatal("native predecessor belongs to another image")
	}
	decode := globalCandidateDecoder(t, fixture.raw)
	var expansions []nativeproof.TransitionExpansion
	for at := bound.Boundary.PC; at < cut; {
		instruction := decode(at)
		if nativeproof.TransitionExpansionRequired(instruction) {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: at})
		}
		at += uint64(instruction.Len)
	}
	proposal, err := nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	continued, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, proposal)
	if err != nil {
		t.Fatal(err)
	}
	next, owned := continued.BoundFor(fixture.image)
	if !owned || next.Boundary.PC != cut || next.Origin != bound.Origin || !reflect.DeepEqual(next.InitialMemory, bound.InitialMemory) {
		t.Fatal("continuation replaced the original owner, origin or arbitrary memory")
	}
	if len(next.Instructions) <= len(bound.Instructions) || !reflect.DeepEqual(next.Instructions[:len(bound.Instructions)], bound.Instructions) || len(next.Accesses) < len(bound.Accesses) || !reflect.DeepEqual(next.Accesses[:len(bound.Accesses)], bound.Accesses) {
		t.Fatal("continuation discarded or reidentified an inherited native occurrence")
	}
	return continued
}

// This is a non-authorizing account of real opaque endpoints. It calls the same
// cumulative prefix checker as production continuation without manufacturing an
// operand certificate or extending the CAS-specific continuation protocol.
func storageContinuationAccount(t testing.TB, source *sourceOperandPrefix, native nativeproof.TransitionCertificate, rho storageRepresentation) (*globalFunctionCorrespondence, error) {
	t.Helper()
	bound, owned := native.BoundFor(rho.image)
	if !owned {
		t.Fatal("prefix account lacks its owned native endpoint")
	}
	layout, err := checkStorageAuthority(t.Context(), source, bound, rho, storageProtectedFootprints(t.Context(), bound))
	if err != nil {
		return nil, err
	}
	var chain []*sourceEffectPrefix
	for at := source.sourceEffectPrefix; at != nil; at = at.prior {
		chain = append(chain, at)
	}
	slices.Reverse(chain)
	account := &globalFunctionCorrespondence{representation: layout.representation, layout: layout, antecedent: bound.EntryPredicate, limit: 2_000_000}
	for _, phase := range chain {
		packet := phase.checkedPacket()
		if packet == nil {
			t.Fatal("prefix account lacks its opaque source endpoint")
		}
		if err := checkStoragePrefixBounds(bound, packet.trace); err != nil {
			return nil, err
		}
		account.traces = append(account.traces, packet.trace)
		account.accesses = append(account.accesses, packet.trace.accesses...)
	}
	if err := checkStoragePrefixAccount(t.Context(), account, source, native, bound); err != nil {
		return nil, err
	}
	return account, nil
}

func storageContinuationCurrent(t testing.TB, endpoint storageSourceEndpoint, object regionObject, want uint64) {
	t.Helper()
	allocation, live, err := endpoint.liveAllocation(object, t.Context().Err)
	if err != nil || !live || allocation.location.object != object || allocation.instruction != object.site.(*ssa.Alloc) || allocation.invocation != object.invocation {
		t.Fatalf("missing retained allocation instance: live=%v error=%v", live, err)
	}
	localEffectInteger(t, allocation.initializer, 0)
	packet := endpoint.storagePacket()
	if packet == nil || len(packet.observations) != 1 {
		t.Fatal("current contents lack an opaque source endpoint")
	}
	localEffectInteger(t, readRegionLocation(packet.observations[0].state, regionLocation{object: object}, types.Typ[types.Uint32]), want)
}

func TestStorageContinuationFactoryInstances(t *testing.T) {
	for _, values := range []struct {
		name             string
		second, retained uint64
	}{{"distinct-values", 5, 7}, {"equal-at-second-cut", 3, 3}} {
		t.Run(values.name, func(t *testing.T) {
			source := relationFixture(t, fmt.Sprintf(`
				func Make(v uint32) *uint32 { p:=new(uint32); *p=v; return p }
				func Read(p *uint32) uint32 { return *p }
				func Write(p *uint32,v uint32) { *p=v }
				func F() {
					p:=Make(3); Read(p)
					q:=Make(%d); Write(p,%d); Read(p)
					Write(p,7); Write(q,9); Read(q); Read(p)
				}`, values.second, values.retained), 64)
			root := source.prog.Roots["F"]
			reads := localEffectCalls(t, root, "Read")
			if len(reads) != 4 {
				t.Fatal("fixture lost its actual read boundaries")
			}
			first, err := checkSourceOperandPrefix(t.Context(), source, root, reads[0], defaultRegistrationLimits())
			if err != nil {
				t.Fatal(err)
			}
			second, err := checkSourceOperandContinuation(t.Context(), first, reads[1], nil)
			if err != nil {
				t.Fatal(err)
			}
			var returned *ssa.Return
			for _, block := range root.Blocks {
				for _, instruction := range block.Instrs {
					if ret, ok := instruction.(*ssa.Return); ok {
						if returned != nil {
							t.Fatal("fixture has more than one return")
						}
						returned = ret
					}
				}
			}
			completed, err := checkSourceReturnContinuation(t.Context(), second, returned, nil)
			if err != nil {
				t.Fatal(err)
			}
			if second.prior != first.sourceEffectPrefix || completed.prior != second.sourceEffectPrefix || len(first.checkedPacket().trace.allocations) != 1 || len(second.checkedPacket().trace.allocations) != 1 || len(completed.checkedPacket().trace.allocations) != 0 {
				t.Fatal("source did not retain two separate allocation-bearing phases")
			}
			p := first.checkedPacket().trace.allocations[0].location.object
			q := second.checkedPacket().trace.allocations[0].location.object
			if p == q || p.site != q.site || p.context != q.context || p.invocation == q.invocation || p.context.Name() != "Make" || first.operands[0].location.object != p || second.operands[0].location.object != p {
				t.Fatal("factory instances collapsed or the old pointer changed objects")
			}
			storageContinuationCurrent(t, first, p, 3)
			storageContinuationCurrent(t, second, p, values.retained)
			storageContinuationCurrent(t, second, q, values.second)
			storageContinuationCurrent(t, completed, p, 7)
			storageContinuationCurrent(t, completed, q, 9)
			// Later continuations must not mutate the older receipt's current heap.
			storageContinuationCurrent(t, first, p, 3)
			storageContinuationCurrent(t, second, p, values.retained)

			pBase := nativeproof.StackOffset(-32)
			qBase := nativeproof.StackOffset(-16)
			pAt, qAt := storageByteLocation{Offset: int64(pBase)}, storageByteLocation{Offset: int64(qBase)}
			program := []storageByteStep{
				{Kind: "store", At: pAt, Width: 4, Value: 3},
				{Kind: "load", At: pAt, Width: 4},
				{Kind: "store", At: qAt, Width: 4, Value: values.second},
				{Kind: "store", At: pAt, Width: 4, Value: values.retained},
				{Kind: "load", At: pAt, Width: 4},
				{Kind: "store", At: pAt, Width: 4, Value: 7},
				{Kind: "store", At: qAt, Width: 4, Value: 9},
				{Kind: "load", At: qAt, Width: 4},
				{Kind: "load", At: pAt, Width: 4},
			}
			fixture := storageJointEncode(t, program, 1)
			nativeFirst, err := storageJointTransition(t, fixture, fixture.prefixCut)
			if err != nil {
				t.Fatal(err)
			}
			nativeSecond := storageContinuationNative(t, fixture, nativeFirst, fixture.accessPCs[4])
			nativeLast := storageContinuationNative(t, fixture, nativeSecond, fixture.cut)
			nativeReturn, err := nativeproof.CheckTransitionReturn(t.Context(), nativeLast)
			if err != nil {
				t.Fatal(err)
			}
			firstBound, _ := nativeFirst.BoundFor(fixture.image)
			secondBound, _ := nativeSecond.BoundFor(fixture.image)
			returnBound, owned := nativeReturn.BoundFor(fixture.image)
			if !owned || !returnBound.State.CalleeTerminated || len(firstBound.Accesses) != 1 || len(secondBound.Accesses) != 4 {
				t.Fatal("native endpoints do not cover the intended complete history")
			}
			for _, cell := range firstBound.InitialMemory {
				cell := storageTestByte(t, firstBound.Geometry, cell)
				if !cell.Image && (cell.Offset >= int64(pBase) && cell.Offset < int64(pBase)+4 || cell.Offset >= int64(qBase) && cell.Offset < int64(qBase)+4) && cell.Value.View().Op != br.Variable {
					t.Fatal("source allocation supplied native initial bytes")
				}
			}
			for _, current := range []struct {
				memory []nativeproof.TransitionByte
				base   nativeproof.StorageSelector
				want   uint64
			}{{firstBound.Memory, pBase, 3}, {secondBound.Memory, pBase, values.retained}, {secondBound.Memory, qBase, values.second}, {returnBound.State.Memory, pBase, 7}, {returnBound.State.Memory, qBase, 9}} {
				term, err := storageNativeWord(t.Context(), br.NewBuilder(64), current.memory, storageTestExtent(t, firstBound.Geometry, current.base, 4), 4)
				if err != nil {
					t.Fatal(err)
				}
				bits, err := br.Eval(t.Context(), term, nil, br.Limits{})
				if err != nil || bits != current.want {
					t.Fatalf("retained native contents = %d, want %d: %v", bits, current.want, err)
				}
			}
			rho := storageRepresentation{source: source.prog, image: fixture.image, bindings: []storageBinding{{object: p, base: pBase}, {object: q, base: qBase}}}
			firstRho := rho
			firstRho.bindings = slices.Clone(rho.bindings[:1])
			firstAccount, err := storageContinuationAccount(t, first, nativeFirst, firstRho)
			if err != nil {
				t.Fatalf("initial real prefix account: %v", err)
			}
			secondAccount, err := storageContinuationAccount(t, second, nativeSecond, rho)
			if err != nil {
				t.Fatalf("continued real prefix account: %v", err)
			}
			proof, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, nativeReturn, rho, nil)
			if err != nil {
				t.Fatalf("complete correspondence from second source/native cut: %v", err)
			}
			if proof.source != completed || len(proof.inputs) != 0 || len(firstAccount.accesses) != 1 || len(secondAccount.accesses) != 4 || len(proof.accesses) != 9 || len(proof.matched) != 9 || len(proof.eliminated) != 0 || len(proof.traces) != 3 {
				t.Fatal("ordinary storage history was omitted, duplicated, or replaced by local input premises")
			}
			seen := map[struct {
				instruction ssa.Instruction
				invocation  regionInvocation
			}]bool{}
			for i, trace := range []*regionEffectTrace{first.checkedPacket().trace, second.checkedPacket().trace, completed.checkedPacket().trace} {
				if proof.traces[i] != trace || len(trace.accesses) != []int{1, 3, 5}[i] {
					t.Fatal("complete driver lost the exact once-only phase order")
				}
				for _, access := range trace.accesses {
					key := struct {
						instruction ssa.Instruction
						invocation  regionInvocation
					}{access.instruction, access.invocation}
					if seen[key] {
						t.Fatal("source effect occurrence was replayed across opaque cuts")
					}
					seen[key] = true
				}
			}

			t.Run("future-instance-at-earlier-cut", func(t *testing.T) {
				future := rho
				// In the equal-value case these bytes already contain exactly the
				// later object's value. Neither bytes nor the same SSA site grant
				// that future invocation allocation authority at the earlier cut.
				future.bindings = []storageBinding{{object: q, base: pBase}}
				if got, err := checkStorageAuthority(t.Context(), first, firstBound, future, storageProtectedFootprints(t.Context(), firstBound)); got != nil || err == nil || !strings.Contains(err.Error(), "allocation lacks actual live singleton evidence") {
					t.Fatalf("future object not refused for missing allocation authority: %v", err)
				}
			})
			t.Run("overlapping-live-instances", func(t *testing.T) {
				overlap := rho
				overlap.bindings = slices.Clone(rho.bindings)
				overlap.bindings[1].base = pBase
				if got, err := checkStorageAuthority(t.Context(), second, secondBound, overlap, storageProtectedFootprints(t.Context(), secondBound)); got != nil || err == nil || !strings.Contains(err.Error(), "overlapping live objects") {
					t.Fatalf("live overlap not refused at authority: %v", err)
				}
			})
			t.Run("hidden-current-pointer", func(t *testing.T) {
				hidden := rho
				hidden.bindings = slices.Clone(rho.bindings[1:])
				// The shared account refuses first: this still-live operand's
				// source storage cannot be eliminated as isolated local traffic.
				if got, err := storageContinuationAccount(t, second, nativeSecond, hidden); got != nil || err == nil || !strings.Contains(err.Error(), "unrepresented source storage is not isolated") {
					t.Fatalf("hidden old storage not refused by its isolation obligation: %v", err)
				}
				layout, err := checkStorageAuthority(t.Context(), second, secondBound, hidden, storageProtectedFootprints(t.Context(), secondBound))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := checkStorageOperandBoundary(t.Context(), second, nativeSecond, layout); err == nil || !strings.Contains(err.Error(), "source pointer has no represented native storage") {
					t.Fatalf("hidden old pointer not refused at actual use: %v", err)
				}
			})
			t.Run("swapped-association", func(t *testing.T) {
				swapped := rho
				swapped.bindings = slices.Clone(rho.bindings)
				swapped.bindings[0].base, swapped.bindings[1].base = qBase, pBase
				layout, err := checkStorageAuthority(t.Context(), second, secondBound, swapped, storageProtectedFootprints(t.Context(), secondBound))
				if err != nil {
					t.Fatal(err)
				}
				// Equal values at the second cut still cannot substitute for the
				// actual operand's retained origin and allocation association.
				if _, err := checkStorageOperandBoundary(t.Context(), second, nativeSecond, layout); err == nil || !strings.Contains(err.Error(), "native operand has another storage origin or subobject") {
					t.Fatalf("swapped pointer association not refused: %v", err)
				}
				if got, err := checkGlobalFunctionCorrespondence(t.Context(), source, root, fixture.image, fixture.entry, completed, nativeReturn, swapped, nil); got != nil || err == nil || !strings.Contains(err.Error(), "complete effects:") {
					t.Fatalf("complete driver did not reject swapped effects before final values: %v", err)
				}
			})
		})
	}
}
