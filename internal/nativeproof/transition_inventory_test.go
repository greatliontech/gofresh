package nativeproof

import "testing"

type transitionTestPoint struct {
	pc      uint64
	context TransitionActivationID
}

// Locate a fixture occurrence for mutation/inspection, without treating a PC as
// an authorization coordinate. Ordinal selects repeated fixture occurrences.
func transitionTestID(t testing.TB, p TransitionProposal, pc uint64, ordinal int) TransitionOccurrenceID {
	t.Helper()
	for _, n := range p.Nodes {
		if n.PC == pc {
			if ordinal == 0 {
				return n.ID
			}
			ordinal--
		}
	}
	t.Fatalf("fixture occurrence %#x/%d absent", pc, ordinal)
	return 0
}

// These static forms are explicit fixture discovery choices. Inventory comparison
// independently checks every exact occurrence choice afterward.
func transitionTestOptions(p TransitionProposal) TransitionOptions {
	var o TransitionOptions
	seen := map[uint64]bool{}
	for _, n := range p.Nodes {
		if n.Expanded && !seen[n.PC] {
			seen[n.PC] = true
			o.Expansions = append(o.Expansions, TransitionExpansion{PC: n.PC, AllActivations: true})
		}
	}
	return o
}

// IDs are proof-local names. Compare rooted graphs by an injective edge
// correspondence, not by assuming independent proposers assign equal IDs.
func transitionInventoryMap(t testing.TB, a, b TransitionProposal) map[TransitionOccurrenceID]TransitionOccurrenceID {
	t.Helper()
	if a.Entry != b.Entry || a.Cut != b.Cut || a.ImageDigest != b.ImageDigest || len(a.Nodes) != len(b.Nodes) {
		t.Fatal("occurrence proposal scope differs")
	}
	left, right := map[TransitionOccurrenceID]TransitionNode{}, map[TransitionOccurrenceID]TransitionNode{}
	for _, n := range a.Nodes {
		if n.ID == 0 || left[n.ID].ID != 0 {
			t.Fatal("duplicate/zero left ID")
		}
		left[n.ID] = n
	}
	for _, n := range b.Nodes {
		if n.ID == 0 || right[n.ID].ID != 0 {
			t.Fatal("duplicate/zero right ID")
		}
		right[n.ID] = n
	}
	mapping := map[TransitionOccurrenceID]TransitionOccurrenceID{a.Root: b.Root}
	reverse := map[TransitionOccurrenceID]TransitionOccurrenceID{b.Root: a.Root}
	queue := []TransitionOccurrenceID{a.Root}
	for at := 0; at < len(queue); at++ {
		x, y := left[queue[at]], right[mapping[queue[at]]]
		if x.ID == 0 || y.ID == 0 || x.PC != y.PC || x.Size != y.Size || x.Expanded != y.Expanded || x.Frontier != y.Frontier || len(x.Successors) != len(y.Successors) {
			t.Fatal("occurrence transfer differs", x, y)
		}
		for j, next := range x.Successors {
			other := y.Successors[j]
			if mapped, ok := mapping[next]; ok {
				if mapped != other {
					t.Fatal("edge association differs")
				}
				continue
			}
			if _, ok := reverse[other]; ok {
				t.Fatal("noninjective occurrence mapping")
			}
			mapping[next], reverse[other] = other, next
			queue = append(queue, next)
		}
	}
	if len(mapping) != len(a.Nodes) {
		t.Fatal("disconnected fixture inventory")
	}
	return mapping
}
