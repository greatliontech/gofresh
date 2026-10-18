package nativeproof

import (
	"encoding/binary"
	"errors"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

func inputWord(raw []byte, at int) uint32 {
	var b [4]byte
	if at < len(raw) {
		copy(b[:], raw[at:])
	}
	return binary.LittleEndian.Uint32(b[:])
}

// Semantic records, successor words and layout words are independent products.
// Each successor can name ANY later logical node, so both arms evolve separately
// rather than sharing an obligatory fallthrough spine. No semantic-record cap
// drops a tail: the configured 4096 native-instruction limit is checked against
// actual reachable encoded occurrences, including every delivery and trampoline.
func guardedRecords(records, edges []byte) []dagOp {
	n := (len(records) + 31) / 32
	if n == 0 {
		n = 1
	}
	blocks := make([][]dagOp, n)
	starts := make([]int, n+1)
	for j := range blocks {
		var r [32]byte
		if j*32 < len(records) {
			copy(r[:], records[j*32:])
		}
		dst := r[1] % 15
		if dst >= 4 {
			dst++
		}
		src := r[2] % 16
		w := uint8(0)
		if r[3]&1 != 0 {
			w = 32
		}
		i := to.Intent{Operation: to.Compare, Dst: dst, Src: src, Width: w}
		address := uint64(0)
		payload := binary.LittleEndian.Uint64(r[8:16])
		switch r[0] % 14 {
		case 0:
		case 1:
			i.Operation = to.Test
		case 2, 3:
			i.Src = 0
			i.Immediate = uint64(int64(int32(payload)))
			if r[3]&2 != 0 {
				i.Immediate = uint64(int64(int8(payload)))
			}
			if w == 32 {
				i.Immediate &= 0xffffffff
			}
			i.Operation = to.CompareImmediate
			if r[0]%14 == 3 {
				i.Operation = to.TestImmediate
			}
		case 4:
			i.Operation = to.MoveRegister
			if r[3]&2 != 0 {
				i.Width = 8
			}
		case 5:
			i = to.Intent{Operation: to.CPUID}
		case 6:
			conditions := []uint8{2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
			i = to.Intent{Operation: to.Branch, Condition: conditions[int(r[1])%10]}
		case 7, 8, 9, 10, 12:
			if r[3]&2 != 0 {
				w = 8
			}
			i = to.Intent{Operation: to.Store, Base: r[5] % 16, Src: src, Width: w, SignedDisp: int64(r[16]%25) - 8}
			if r[0]%14 == 8 || r[0]%14 == 10 {
				i.Operation, i.Src, i.Dst = to.Load, 0, dst
			}
			if r[0]%14 == 12 {
				i.Operation, i.Src = to.StoreImmediate, 0
				i.Immediate = uint64(int64(int32(payload)))
				if w == 32 {
					i.Immediate &= 0xffffffff
				}
				if w == 8 {
					i.Immediate &= 255
				}
			}
			if r[0]%14 == 9 || r[0]%14 == 10 {
				i.Base, i.SignedDisp, i.RIP = 0, 0, true
				address = imageStateAddress + uint64(r[16]%25)
			} else if i.Base != 4 {
				p := to.Intent{Operation: to.MoveRegister, Dst: i.Base, Src: 4}
				blocks[j] = append(blocks[j], dagScalar(p, stateEncoding(p, r[4]), 0))
			}
		case 11:
			i = to.Intent{Operation: to.LEARIP, Dst: dst}
			address = imageStateAddress + uint64(r[16]%25)
		case 13:
			i = to.Intent{Operation: to.MoveImmediate, Dst: dst, Width: w, Immediate: payload}
			if r[3]&2 != 0 {
				i.Width = 8
				i.Immediate &= 255
			} else if w == 32 {
				i.Immediate &= 0xffffffff
			}
		}
		e := stateEncoding(i, r[4])
		if i.Operation == to.Branch {
			e.Form = to.JccNear
		}
		blocks[j] = append(blocks[j], dagOp{i: i, e: e, address: address})
		starts[j+1] = starts[j] + len(blocks[j])
	}
	var ops []dagOp
	for j, block := range blocks {
		next := j + 1 + int(inputWord(edges, j*8))%(n-j)
		taken := j + 1 + int(inputWord(edges, j*8+4))%(n-j)
		for k, op := range block {
			op.next = starts[next]
			op.taken = starts[taken]
			if k+1 < len(block) {
				op.next = starts[j] + k + 1
			}
			ops = append(ops, op)
		}
	}
	return ops
}

// Every permutation is expressible by the successive full-word choices. No
// PRNG seed restricts the n! placement product; missing words explicitly mean 0.
func guardedPermutation(n int, raw []byte) []int {
	p := make([]int, n)
	for j := range p {
		p[j] = j
	}
	for j := range p {
		k := j + int(inputWord(raw, j*4))%(n-j)
		p[j], p[k] = p[k], p[j]
	}
	return p
}

func guardedCommonCuts(ops []dagOp) []int {
	// Dominators of the final node in the independently specified forward DAG.
	// A node dominates the cut iff removing it makes the cut unreachable.
	var cuts []int
	for cut := 1; cut < len(ops); cut++ {
		reachable := make([]bool, len(ops)+1)
		reachable[0] = true
		for j, op := range ops {
			if j == cut || !reachable[j] {
				continue
			}
			reachable[op.next] = true
			if op.i.Operation == to.Branch {
				reachable[op.taken] = true
			}
		}
		if !reachable[len(ops)] {
			cuts = append(cuts, cut)
		}
	}
	return cuts
}

func checkGuardedRecords(t testing.TB, records, edges, placement, cuts, raw, inactive []byte) {
	t.Helper()
	ops := guardedRecords(records, edges)
	face := stateFace(16, 0)
	face.Regions = []RelativeRegion{{RelativeSpan{-8, 24}, true, true}}
	face.Words = nil
	face.ImageRegions = []Span{{imageStateAddress, imageStateAddress + 32}}
	face.Conditions.CPUID = CPUIDModel
	initial := stateRawInitial(face, raw)
	x := dagArrangePermutation(t, ops, guardedPermutation(len(ops)+1, placement))
	end := 2 * len(ops)
	p := x.proposal(end)
	count := len(p.Nodes)
	common := guardedCommonCuts(ops)
	// Scale construction/import allowances with the actual finite inventory.
	// Depth is independently counted below, not hidden by a periodic state reset.
	limits := TransitionLimits{RelationLimits: RelationLimits{Instructions: 4096, Nodes: 32768 + count*1024, Work: 1_000_000 + count*16384*(2+len(common)), Depth: 512}}
	var shape *dagShapes
	var final *dagDepthState
	if count <= limits.Instructions {
		shape, final = dagDepth(t, x, end, initial)
	}
	direct, err := CheckTransition(t.Context(), x.im, face, p, limits)
	frontier := end
	if count > limits.Instructions || shape.fault != 0 {
		if count > limits.Instructions {
			stateInventoryOverflow(t, direct, err, count, limits.Instructions)
		} else {
			stateExpressionDepthRefused(t, direct, err, shape.fault)
		}
		// Establish the greatest supported common scope preceding this exact
		// counted refusal. Never reinterpret that prefix as the full input.
		frontier = 0
		lo, hi := 0, len(common)
		for lo < hi {
			mid := (lo + hi) / 2
			k := 2 * common[mid]
			ok := len(x.proposal(k).Nodes) <= limits.Instructions
			if ok {
				s, _ := dagDepth(t, x, k, initial)
				ok = s.fault == 0
			}
			if ok {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			frontier = 2 * common[lo-1]
		}
		shape, final = dagDepth(t, x, frontier, initial)
		direct, err = CheckTransition(t.Context(), x.im, face, x.proposal(frontier), limits)
	}
	if err != nil {
		t.Fatal("independently admitted DAG refused", err)
	}
	assertDAGDepth(t, shape, final, direct)
	dagAssert(t, direct, x, frontier, face, initial, inactive)
	root, err := CheckTransition(t.Context(), x.im, face, x.proposal(0), limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range common {
		if 2*k >= frontier {
			break
		}
		if len(cuts) > k/8 && cuts[k/8]&(1<<uint(k%8)) != 0 {
			prior := root.checked.bound
			root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(2*k))
			if err != nil {
				t.Fatal(err)
			}
			stateInheritedInputs(t, prior, root.checked.bound)
			dagAssert(t, root, x, 2*k, face, initial, inactive)
		}
	}
	if frontier != 0 {
		prior := root.checked.bound
		root, err = CheckTransitionContinuation(t.Context(), root, x.proposal(frontier))
		if err != nil {
			t.Fatal(err)
		}
		stateInheritedInputs(t, prior, root.checked.bound)
		dagAssert(t, root, x, frontier, face, initial, inactive)
	}
	if frontier != end {
		c, e := CheckTransitionContinuation(t.Context(), root, p)
		if count > limits.Instructions {
			stateInventoryOverflow(t, c, e, count, limits.Instructions)
		} else {
			s, _ := dagDepth(t, x, end, initial)
			stateExpressionDepthRefused(t, c, e, s.fault)
		}
	}
}

func TestTransitionGuardedEvolvingSequence(t *testing.T) {
	t.Parallel()
	for seed := 0; seed < 24; seed++ {
		records, edges, layout := make([]byte, 40*32), make([]byte, 40*8), make([]byte, 81*4)
		for j := range records {
			records[j] = byte(j*37 + seed*13)
		}
		for j := range edges {
			edges[j] = byte(j*11 + seed)
		}
		for j := range layout {
			layout[j] = byte(j*53 + seed)
		}
		raw := make([]byte, 1024)
		inactive := make([]byte, 640)
		for j := range raw {
			raw[j] = byte(j*31 + seed*17)
		}
		for j := range inactive {
			inactive[j] = byte(j*47 + seed*7)
		}
		checkGuardedRecords(t, records, edges, layout, []byte{255, 255, 255, 255, 255}, raw, inactive)
	}
}

func TestTransitionGuardedActualResourceFrontiers(t *testing.T) {
	t.Parallel()
	// Full reachable graphs on both sides of the actual native-inventory bound.
	// These inputs also exercise depth refusal before that bound with no refresh.
	for _, n := range []int{1, 33, 128, 256, 2047, 2048, 2049} {
		records := make([]byte, 32*n)
		for j := 0; j < n; j++ {
			records[j*32] = 6
			records[j*32+1] = 4
		}
		checkGuardedRecords(t, records, nil, nil, nil, []byte{1, 2, 3}, nil)
	}
	// Balanced independent arms with balanced joins reach the instruction
	// frontier without first exhausting expression depth. Padding is executable
	// identity MOVs after the common join, not a heap/predicate refresh.
	for _, n := range []int{2047, 2048} {
		var graph []dagOp
		var tree func(int) (int, int)
		tree = func(depth int) (int, int) {
			start := len(graph)
			if depth == 0 {
				graph = append(graph, dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 15}, to.Encoding{}, 0))
				return start, start
			}
			graph = append(graph, dagBranch(4, 0, 0))
			left, lastLeft := tree(depth - 1)
			right, lastRight := tree(depth - 1)
			join := len(graph)
			graph = append(graph, dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 15}, to.Encoding{}, 0))
			graph[start].next, graph[start].taken = left, right
			graph[lastLeft].next, graph[lastRight].next = join, join
			return start, join
		}
		_, tail := tree(8)
		for len(graph) < n {
			next := len(graph)
			graph[tail].next = next
			graph = append(graph, dagScalar(to.Intent{Operation: to.MoveRegister, Dst: 15, Src: 15}, to.Encoding{}, 0))
			tail = next
		}
		graph[tail].next = n
		records, edges := make([]byte, n*32), make([]byte, n*8)
		for j, op := range graph {
			records[32*j], records[32*j+1], records[32*j+2] = 4, 14, 15
			if op.i.Operation == to.Branch {
				records[32*j], records[32*j+1] = 6, 4
				binary.LittleEndian.PutUint32(edges[j*8+4:], uint32(op.taken-j-1))
			}
			binary.LittleEndian.PutUint32(edges[j*8:], uint32(op.next-j-1))
		}
		checkGuardedRecords(t, records, edges, nil, nil, []byte{31}, nil)
	}
}

func TestTransitionGuardedIndependentArmsAndPlacement(t *testing.T) {
	records := make([]byte, 32*7)
	for j, op := range []byte{6, 13, 7, 13, 8, 5, 1} {
		records[32*j] = op
		records[32*j+1] = 9
		records[32*j+5] = 11
		records[32*j+8] = byte(j * 17)
	}
	// 0 -> {1,3}; 1 -> 2 -> 5; 3 -> 4 -> 5 -> 6 -> cut.
	edges := make([]byte, 7*8)
	binary.LittleEndian.PutUint32(edges[4:], 2)
	binary.LittleEndian.PutUint32(edges[2*8:], 2)
	for _, layout := range [][]byte{nil, {7, 0, 0, 0, 6, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1}} {
		for _, raw := range [][]byte{nil, bytesOf(1024, 255)} {
			checkGuardedRecords(t, records, edges, layout, []byte{255}, raw, bytesOf(128, 37))
		}
	}
	// Explicit malformed successor relations remain negative graph controls.
	ops := guardedRecords(records, edges)
	ops[0].next = 0
	x := dagArrangePermutation(t, ops, guardedPermutation(len(ops)+1, nil))
	c, err := CheckTransition(t.Context(), x.im, cpuidFace(), x.proposal(2*len(ops)), TransitionLimits{})
	transitionRefused(t, c, err)
	var r *Refusal
	if !errors.As(err, &r) || r.Premise != "acyclic-control" {
		t.Fatal(err)
	}
}
func bytesOf(n int, b byte) []byte {
	v := make([]byte, n)
	for j := range v {
		v[j] = b
	}
	return v
}

func FuzzTransitionGuardedDAG(f *testing.F) {
	spine := make([]byte, 128*32)
	for j := 0; j < 128; j++ {
		spine[j*32] = byte(j % 14)
		spine[j*32+1] = byte(j % 15)
		spine[j*32+2] = byte(j % 16)
		spine[j*32+3] = byte(j % 4)
		spine[j*32+5] = byte((j + 7) % 16)
		binary.LittleEndian.PutUint64(spine[j*32+8:], uint64(j)*0x123456789abcdef)
		spine[j*32+16] = byte(j)
	}
	f.Add(spine, []byte{}, []byte{}, bytesOf(32, 255), bytesOf(1024, 0xa5), bytesOf(2048, 0x3c))
	for _, seed := range []byte{0, 4, 6, 31, 127, 255} {
		records := make([]byte, 40*32)
		edges := make([]byte, 40*8)
		layout := make([]byte, 81*4)
		raw := make([]byte, 1024)
		inactive := make([]byte, 640)
		for j := range records {
			records[j] = byte(j*37) + seed
		}
		for j := range edges {
			edges[j] = byte(j*19) + seed
		}
		for j := range layout {
			layout[j] = byte(j*11) + seed
		}
		for j := range raw {
			raw[j] = byte(j*31) + seed
		}
		for j := range inactive {
			inactive[j] = byte(j*47) + seed
		}
		f.Add(records, edges, layout, []byte{255}, raw, inactive)
	}
	f.Fuzz(func(t *testing.T, records, edges, layout, cuts, raw, inactive []byte) {
		checkGuardedRecords(t, records, edges, layout, cuts, raw, inactive)
	})
}
