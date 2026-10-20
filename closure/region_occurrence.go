package closure

import (
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// A path supplies complete ordered successor slots, never destinations or ranks.
// An advancing slot targets exactly the following node. Every other actual slot
// must be false under the canonical typed transfer. An active residual refuses.
type regionOccurrencePath struct{ nodes []regionOccurrenceNode }

type regionOccurrenceNode struct {
	at    regionPoint
	entry regionState
	slots []regionOccurrenceSlot
	end   regionOccurrenceEnd
}

type regionOccurrenceSlot uint8

const (
	regionOccurrenceFalse regionOccurrenceSlot = iota
	regionOccurrenceAdvance
)

type regionOccurrenceEnd uint8

const (
	regionOccurrenceContinue regionOccurrenceEnd = iota
	regionOccurrenceUse
	regionOccurrenceReturn
	regionOccurrenceResidual
)

// Nonzero size ensures separate evidence roots have distinct pointer identities.
type regionOccurrenceOwner struct{ identity byte }

func (k *regionKernel) boundaryOccurrence(instruction ssa.Instruction) regionEffectOccurrence {
	if k.trace == nil {
		return regionEffectOccurrence{}
	}
	return regionEffectOccurrence{instruction: instruction, invocation: k.invocation, owner: k.trace.owner, ordinal: k.next}
}

func (m *regionMeter) copyOccurrences(path *regionOccurrencePath) (*regionOccurrencePath, error) {
	if path == nil {
		return nil, nil
	}
	if len(path.nodes) == 0 || len(path.nodes) > m.limits.nodes-m.nodes {
		return nil, regionError("occurrence node budget exhausted or empty path")
	}
	m.nodes += len(path.nodes)
	copy := &regionOccurrencePath{nodes: make([]regionOccurrenceNode, len(path.nodes))}
	for i, node := range path.nodes {
		if err := m.tick(); err != nil {
			return nil, err
		}
		if len(node.slots) > 2 {
			return nil, regionError("occurrence successor slot budget exhausted")
		}
		var err error
		node.entry, err = m.copyState(node.entry)
		if err != nil {
			return nil, err
		}
		node.slots = slices.Clone(node.slots)
		copy.nodes[i] = node
	}
	return copy, nil
}

func (k *regionKernel) proposeFlow() (map[*ssa.BasicBlock][]regionState, *regionOccurrencePath, error) {
	if k.trace != nil {
		path, err := k.proposeOccurrences()
		return nil, path, err
	}
	entries, err := k.proposeEntries()
	return entries, nil, err
}

func (k *regionKernel) checkFlow(entries map[*ssa.BasicBlock][]regionState, path *regionOccurrencePath) ([]regionObservation, error) {
	if k.input.normalReturns && k.trace != nil {
		return nil, regionError("normal-return postcondition has no complete effect authority")
	}
	if k.trace != nil {
		if entries != nil || path == nil {
			return nil, regionError("finite flow requires only an occurrence proof")
		}
		return k.checkOccurrences(path)
	}
	if path != nil || entries == nil {
		return nil, regionError("invariant flow requires only block invariants")
	}
	return k.checkEntries(entries)
}

func (k *regionKernel) occurrenceNode(at regionPoint, state regionState) (regionOccurrenceNode, []regionEdge, []regionObservation, error) {
	node := regionOccurrenceNode{at: at, entry: state}
	edges, observations, err := k.blockFrom(at, state)
	if err != nil {
		return node, nil, nil, err
	}
	if len(observations) == 1 && len(edges) == 0 {
		node.end = regionOccurrenceUse
		if k.fullReturns {
			node.end = regionOccurrenceReturn
		}
		return node, edges, observations, nil
	}
	if len(edges) != 1 || len(observations) != 0 {
		return node, nil, nil, regionError("finite occurrence lacks one actual successor or terminal")
	}
	node.slots = make([]regionOccurrenceSlot, len(at.block.Succs))
	if edges[0].slot < 0 || edges[0].slot >= len(node.slots) || edges[0].block != at.block.Succs[edges[0].slot] {
		return node, nil, nil, regionError("occurrence successor is not the actual ordered slot")
	}
	node.slots[edges[0].slot] = regionOccurrenceAdvance
	return node, edges, nil, nil
}

func (k *regionKernel) proposeOccurrences() (*regionOccurrencePath, error) {
	path := &regionOccurrencePath{}
	at, state := k.input.entry, k.input.initial
	for {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		k.meter.nodes++
		if k.meter.nodes > k.meter.limits.nodes {
			return nil, regionError("occurrence discovery exhausted with a feasible frontier")
		}
		node, edges, _, err := k.occurrenceNode(at, state)
		if err != nil {
			return nil, err
		}
		path.nodes = append(path.nodes, node)
		if node.end != regionOccurrenceContinue {
			return path, nil
		}
		at, state = regionPoint{edges[0].block, 0}, edges[0].state
	}
}

// The checker reconstructs every transfer independently. Mutual inclusion makes
// each proposed whole entry relation exact for this grammar, including arbitrary
// unknown globals. The union at a static point retains whole correlated states;
// it never uses the widening join or projects independent value/heap components.
// Closure plus the rank len(nodes)-i proves progress: each feasible CFG edge goes
// to i+1, including backedges; every other actual slot is checked false. A final
// feasible edge cannot be justified by the discovery allowance.
func (k *regionKernel) checkOccurrences(path *regionOccurrencePath) ([]regionObservation, error) {
	if path == nil || len(path.nodes) == 0 || len(path.nodes) > k.meter.limits.nodes || k.trace.owner == nil {
		return nil, regionError("missing bounded owned occurrence path")
	}
	k.boundaries = map[regionPoint][]regionState{}
	at, state := k.input.entry, k.input.initial
	for i, node := range path.nodes {
		if err := k.meter.tick(); err != nil {
			return nil, err
		}
		if node.at != at || len(node.slots) > 2 {
			return nil, regionError("occurrence root or actual successor boundary differs")
		}
		if err := k.validateState(node.entry); err != nil {
			return nil, err
		}
		for _, pair := range [][2]regionState{{state, node.entry}, {node.entry, state}} {
			same, err := k.included(pair[0], pair[1])
			if err != nil {
				return nil, err
			}
			if !same {
				return nil, regionError("occurrence entry changes the complete incoming relation")
			}
		}
		actual, edges, observations, err := k.occurrenceNode(at, node.entry)
		if err != nil {
			return nil, err
		}
		if node.end != actual.end || !slices.Equal(node.slots, actual.slots) {
			return nil, regionError("occurrence terminal or complete successor slots differ")
		}
		k.boundaries[at] = append(k.boundaries[at], node.entry)
		if actual.end != regionOccurrenceContinue {
			if i != len(path.nodes)-1 {
				return nil, regionError("unused occurrence nodes after terminal")
			}
			return observations, nil
		}
		if i+1 == len(path.nodes) {
			return nil, regionError("feasible residual occurrence frontier")
		}
		at, state = regionPoint{edges[0].block, 0}, edges[0].state
	}
	return nil, regionError("occurrence path has no checked terminal")
}

// Layout is selected once from the exact root package, independently of the
// optional IEEE interpretation. No host architecture or package-name match is
// numeric authority. Validate the small primitive layout surface before use.
func (k *regionKernel) selectSizes() (err error) {
	in := k.input
	if in.selection == nil {
		return nil
	}
	if in.selection.Prog != in.owner || in.root.Pkg == nil || in.owner.Package(in.root.Pkg.Pkg) != in.root.Pkg || len(in.selection.Pkgs) > k.meter.limits.nodes {
		return regionError("selected numeric layout has another owner or exceeds its bound")
	}
	defer func() {
		if recover() != nil {
			// A malformed Sizes implementation may also have cancelled the
			// operation. Keep the operational refusal rather than hiding it behind
			// the semantic layout diagnostic.
			err = k.meter.tick()
			if err == nil {
				err = regionError("invalid selected numeric sizes")
			}
		}
	}()
	found := false
	for _, pkg := range in.selection.Pkgs {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if pkg == nil || pkg.Types != in.root.Pkg.Pkg {
			continue
		}
		if found || pkg.TypesSizes == nil {
			return regionError("missing or duplicate selected numeric sizes")
		}
		found, k.sizes = true, pkg.TypesSizes
	}
	if !found {
		return regionError("root has no exact selected numeric sizes")
	}
	for _, kind := range []types.BasicKind{types.Int, types.Uint, types.Uintptr, types.Int8, types.Uint8, types.Int16, types.Uint16, types.Int32, types.Uint32, types.Int64, types.Uint64} {
		if err := k.meter.tick(); err != nil {
			return err
		}
		typ := types.Typ[kind]
		size, align := k.sizes.Sizeof(typ), k.sizes.Alignof(typ)
		if err := k.meter.tick(); err != nil {
			return err
		}
		want := int64(0)
		switch kind {
		case types.Int8, types.Uint8:
			want = 1
		case types.Int16, types.Uint16:
			want = 2
		case types.Int32, types.Uint32:
			want = 4
		case types.Int64, types.Uint64:
			want = 8
		}
		if want != 0 && size != want || want == 0 && size != 4 && size != 8 || align <= 0 || align > size || align&(align-1) != 0 {
			return regionError("invalid selected numeric width or alignment")
		}
	}
	return nil
}
