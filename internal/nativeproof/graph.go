package nativeproof

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/arch/x86/x86asm"
)

type instruction struct {
	boundary boundaryKind
	pc       uint64
	inst     operation
	next     [2]int
	count    uint8
	size     uint8
	parent   int
	indegree int
}

// operation retains only what scalar transfer reads. The complete decoder
// result is checked for mode, prefixes, encoding shape and extra operands before
// this projection is made; discarding those fields does not bypass their checks.
type operation struct {
	Op   x86asm.Op
	Args [2]x86asm.Arg
	// MemBytes is retained only by domains admitting checked data-memory forms.
	MemBytes int
}

// Decoding produces target addresses; discovery resolves them to node indices.
// The supported grammar has at most two successors. Targets are not retained
// beside the resolved edges: their PCs come from the graph's destination nodes.
type decodedInstruction struct {
	boundary boundaryKind
	inst     operation
	targets  [2]uint64
	count    uint8
	size     uint8
}

type graph struct {
	nodes []instruction
	byPC  map[uint64]int
	order []int
}

// A cut is decoded but unexecuted. It is never a return instruction or evidence
// for a return interface; domains select their own permitted terminal kind.
type boundaryKind uint8

const (
	boundaryNone boundaryKind = iota
	boundaryReturn
	boundaryCut
)

func (g *graph) failure(pc uint64, err error) error {
	r, ok := err.(*Refusal)
	if !ok {
		return err
	}
	path := []uint64{pc}
	if index, ok := g.byPC[pc]; ok {
		for parent := g.nodes[index].parent; parent >= 0; parent = g.nodes[parent].parent {
			path = append(path, g.nodes[parent].pc)
		}
	}
	slices.Reverse(path)
	r.Path = path
	return r
}

// Propose discovers an untrusted graph. Check performs a fresh traversal of the
// bound image; neither this graph nor the proposer's interface is authoritative.
// The image container is captured before any context callback.
func Propose(ctx context.Context, im *Image, entry uint64, face Interface) (Proposal, error) {
	im = im.snapshot()
	g, err := decodeGraph(ctx, im, entry)
	if err != nil {
		return Proposal{}, err
	}
	p := Proposal{Entry: entry, Interface: face, Nodes: make([]Node, len(g.order))}
	edgeCount := 0
	for _, index := range g.order {
		edgeCount += int(g.nodes[index].count)
	}
	edges := make([]uint64, edgeCount)
	at := 0
	for j, index := range g.order {
		ins := &g.nodes[index]
		n := Node{PC: ins.pc, Size: ins.size}
		if ins.count != 0 {
			end := at + int(ins.count)
			n.Successors = edges[at:end:end]
			for k, next := range ins.next[:ins.count] {
				n.Successors[k] = g.nodes[next].pc
			}
			at = end
		}
		p.Nodes[j] = n
	}
	return p, nil
}

func decodeGraph(ctx context.Context, im *Image, entry uint64) (*graph, error) {
	return decodeGraphLimited(ctx, im, entry, 0)
}

// A nonzero limit is a refusal boundary, never a successful coverage boundary.
func decodeGraphLimited(ctx context.Context, im *Image, entry uint64, limit int) (*graph, error) {
	return decodeGraphUsing(ctx, entry, limit, func(pc uint64) (decodedInstruction, error) { return decode(im, pc) })
}

// All native domains share instruction occupancy, successor closure and acyclic
// scheduling. A domain's decoder supplies forms, never an asserted edge list.
func decodeGraphUsing(ctx context.Context, entry uint64, limit int, decodeOne func(uint64) (decodedInstruction, error)) (*graph, error) {
	// Decode the root before allocating graph storage: an unsupported entry has
	// no discovered graph, and its refusal already carries the entry-only path.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	first, err := decodeOne(entry)
	if err != nil {
		return nil, err
	}
	g := &graph{
		nodes: make([]instruction, 1, 1+int(first.count)),
		byPC:  map[uint64]int{entry: 0},
	}
	g.nodes[0] = instruction{pc: entry, parent: -1}
	// Discovery order is the queue; membership and parent ownership are recorded
	// once when a target first receives its index. Occupancy is a different fact:
	// it records decoded byte extents, including instruction interiors.
	occupied := make(map[uint64]uint64)
	for at := 0; at < len(g.nodes); at++ {
		pc := g.nodes[at].pc
		var ins decodedInstruction
		if at != 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if owner, ok := occupied[pc]; ok && owner != pc {
			return nil, g.failure(pc, refuse(pc, "instruction-overlap", fmt.Sprintf("target enters instruction at %#x", owner)))
		}
		if at == 0 {
			ins = first
		} else {
			ins, err = decodeOne(pc)
			if err != nil {
				return nil, g.failure(pc, err)
			}
		}
		for off := uint64(0); off < uint64(ins.size); off++ {
			if owner, ok := occupied[pc+off]; ok && owner != pc {
				return nil, g.failure(pc, refuse(pc, "instruction-overlap", fmt.Sprintf("instruction intersects start %#x", owner)))
			}
			occupied[pc+off] = pc
		}
		g.nodes[at].inst = ins.inst
		g.nodes[at].boundary = ins.boundary
		g.nodes[at].count = ins.count
		g.nodes[at].size = ins.size
		for edge, target := range ins.targets[:ins.count] {
			next, exists := g.byPC[target]
			if !exists {
				if limit > 0 && len(g.nodes) >= limit {
					return nil, g.failure(pc, refuse(pc, "relation-budget", "instruction graph budget"))
				}
				next = len(g.nodes)
				g.byPC[target] = next
				g.nodes = append(g.nodes, instruction{pc: target, parent: at})
			}
			// Appending can move the node slice. Resolve through its current base
			// rather than keeping a node pointer across discovery of a successor.
			g.nodes[at].next[edge] = next
			g.nodes[next].indegree++
		}
	}
	// A topological traversal both rejects cycles and ensures all incoming states
	// are joined before an instruction transfer. No arbitrary depth cutoff is used.
	g.order = make([]int, 0, len(g.nodes))
	for index := range g.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if g.nodes[index].indegree == 0 {
			g.order = append(g.order, index)
		}
	}
	// The ready queue becomes the final order in place.
	for at := 0; at < len(g.order); at++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ins := &g.nodes[g.order[at]]
		for _, next := range ins.next[:ins.count] {
			g.nodes[next].indegree--
			if g.nodes[next].indegree == 0 {
				g.order = append(g.order, next)
			}
		}
	}
	if len(g.order) != len(g.nodes) {
		for _, ins := range g.nodes {
			if ins.indegree != 0 {
				pc := ins.pc
				return nil, g.failure(pc, refuse(pc, "acyclic-control", "reachable cycle is unsupported"))
			}
		}
	}
	return g, nil
}

func decode(im *Image, pc uint64) (decodedInstruction, error) {
	i, b, err := decodeEncoding(im, pc)
	if err != nil {
		return decodedInstruction{}, err
	}
	return decodeLeaf(pc, i, b)
}

// decodeEncoding validates shared encoding constraints before either the scalar
// grammar or the call-fragment grammar interprets operands. A decoded boundary
// alone does not assert that the instruction's effects have been checked.
func decodeEncoding(im *Image, pc uint64) (x86asm.Inst, []byte, error) {
	i, b, err := decodeBytes(im, pc)
	if err != nil {
		return x86asm.Inst{}, nil, err
	}
	if err := legalPrefixes(pc, b, i); err != nil {
		return x86asm.Inst{}, nil, err
	}
	for _, arg := range i.Args[2:] {
		if arg != nil {
			return x86asm.Inst{}, nil, refuse(pc, "instruction-shape", "extra operands")
		}
	}
	return i, b, nil
}

// decodeBytes does structural decoding only. Every consumer must apply its own
// explicit encoding/form validation before interpreting the returned instruction.
func decodeBytes(im *Image, pc uint64) (x86asm.Inst, []byte, error) {
	b, err := im.instructionBytes(pc)
	if err != nil {
		return x86asm.Inst{}, nil, err
	}
	i, err := decodeStructure(b)
	if err != nil || i.Op == 0 || i.Len <= 0 || i.Len > len(b) {
		return x86asm.Inst{}, nil, refuse(pc, "instruction-decode", "invalid or truncated instruction")
	}
	for _, p := range i.Prefix {
		if p&x86asm.PrefixInvalid != 0 {
			return x86asm.Inst{}, nil, refuse(pc, "instruction-decode", "invalid instruction prefix")
		}
	}
	b = b[:i.Len]
	normalizeDisplacements(&i, b)
	return i, b, nil
}

// decodeStructure repairs structural byte accounting and context in the pinned
// AVX decoder.
// Intel's operand-free VEX.128/256.0F.WIG 77 ZO forms have no ModRM or immediate;
// vvvv must be 1111b, pp is 00, and L selects the operation. R/X/B have no
// operand to extend and W is ignored. The complete instruction is just the
// two- or three-byte VEX prefix and opcode, even at the end of a mapping.
//
// x86asm v0.32's AVX decoder instead treats any following byte as ModRM (and
// can consume SIB/displacement bytes), and omits mode/address/opcode metadata.
// Construct all fields from this encoding rather than adjusting that result's
// length. Every other entry in its avxMap0F/0F38/0F3A tables (VEX and EVEX)
// has a ModRM-dependent operand and a register/memory form constraint. The
// decoder skips both that constraint and the ModRM read when the byte is
// absent, so require it before delegating. Its SIB, displacement, immediate
// and is4-selector reads already check availability. This table-specific rule
// does not assert a layout for future vector encodings. Legacy-prefixed forms
// keep the decoder's handling. Domain validators still refuse VEX/EVEX execution.
func decodeStructure(b []byte) (x86asm.Inst, error) {
	prefix := 0
	switch {
	case len(b) == 0:
		return x86asm.Inst{}, x86asm.ErrTruncated
	case b[0] == 0xc5:
		prefix = 2
	case b[0] == 0xc4:
		prefix = 3
	case b[0] == 0x62:
		prefix = 4
	default:
		return x86asm.Decode(b, 64)
	}
	if len(b) <= prefix {
		return x86asm.Inst{}, x86asm.ErrTruncated
	}
	zero := b[prefix] == 0x77 && (b[0] == 0xc5 || b[0] == 0xc4 && b[1]&0x1f == 1)
	if !zero {
		if len(b) <= prefix+1 {
			return x86asm.Inst{}, x86asm.ErrTruncated
		}
		i, err := x86asm.Decode(b, 64)
		if err != nil || i.Op == 0 {
			return i, err
		}
		// The AVX early return bypasses the legacy decoder's context and
		// opcode bookkeeping. These bare prefixes have no address override.
		// DataSize already follows the decoder's 32/W=64 attribute, not the
		// vector width. Opcode includes opcode, ModRM and (if present) SIB,
		// left aligned, excluding displacements and immediates.
		i.Mode, i.AddrSize = 64, 64
		modrm := b[prefix+1]
		i.Opcode = uint32(b[prefix])<<24 | uint32(modrm)<<16
		if modrm&0xc0 != 0xc0 && modrm&7 == 4 {
			i.Opcode |= uint32(b[prefix+2]) << 8
		}
		// In 64-bit addressing only non-SIB mod=00,r/m=101 is RIP-relative,
		// regardless of the B extension. SIB base=101 instead means no base.
		if modrm&0xc7 == 5 {
			for j, arg := range i.Args {
				if mem, ok := arg.(x86asm.Mem); ok {
					mem.Base = x86asm.RIP
					mem.Disp = int64(int32(binary.LittleEndian.Uint32(b[prefix+2:])))
					i.Args[j] = mem
					i.PCRel, i.PCRelOff = 4, prefix+2
				}
			}
		}
		return i, nil
	}
	control := b[prefix-1]
	if control&0x7b != 0x78 { // vvvv=1111, pp=00; L and R/W are independent.
		return x86asm.Inst{}, x86asm.ErrUnrecognized
	}
	i := x86asm.Inst{Op: x86asm.VZEROUPPER, Opcode: 0x77000000, Mode: 64, AddrSize: 64, DataSize: 32, Len: prefix + 1}
	if control&4 != 0 {
		i.Op = x86asm.VZEROALL
	}
	for j, p := range b[:prefix] {
		i.Prefix[j] = x86asm.Prefix(p)
	}
	return i, nil
}

// x86asm v0.32 represents ModRM/SIB disp32 as an unsigned value, but 64-bit
// effective addresses sign-extend it. disp8 is already signed and absent
// displacements are zero. A0..A3 instead encode full-width absolute addresses;
// locate those opcodes in the actual bytes so their moffs operands are never
// truncated. This structural prefix scan confers no encoding/form admission:
// every consumer still applies its own prefix and operand validators.
func normalizeDisplacements(i *x86asm.Inst, b []byte) {
	if i.Mode != 64 || i.AddrSize != 64 {
		return
	}
	at := 0
prefixes:
	for at < len(b) {
		switch b[at] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f:
			at++
		default:
			break prefixes
		}
	}
	if at < len(b) && b[at] >= 0xa0 && b[at] <= 0xa3 {
		return
	}
	for j, arg := range i.Args {
		if mem, ok := arg.(x86asm.Mem); ok {
			mem.Disp = int64(int32(mem.Disp))
			i.Args[j] = mem
		}
	}
}

func decodeLeaf(pc uint64, i x86asm.Inst, b []byte) (decodedInstruction, error) {
	for _, arg := range i.Args {
		if _, memory := arg.(x86asm.Mem); memory && i.Op != x86asm.LEA && i.Op != x86asm.NOP {
			return decodedInstruction{}, refuse(pc, "data-memory", "decoded data-memory operand is outside the leaf bound")
		}
	}
	return decodeControl(pc, i, b)
}

// decodeControl checks the shared scalar/control inventory after each domain
// has admitted its memory forms. Transfer still validates every operand shape.
func decodeControl(pc uint64, i x86asm.Inst, b []byte) (decodedInstruction, error) {
	next, ok := plus(pc, uint64(i.Len))
	if !ok {
		return decodedInstruction{}, refuse(pc, "control-target", "instruction end overflow")
	}
	n := decodedInstruction{inst: operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}, size: uint8(i.Len)}
	switch i.Op {
	case x86asm.RET:
		if len(b) != 1 || b[0] != 0xc3 || i.Args[0] != nil {
			return decodedInstruction{}, refuse(pc, "return-interface", "only unprefixed ordinary near RET is modeled")
		}
		n.boundary = boundaryReturn
	case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JE, x86asm.JNE, x86asm.JL, x86asm.JLE, x86asm.JG, x86asm.JGE:
		rel, ok := i.Args[0].(x86asm.Rel)
		if !ok || i.Args[1] != nil {
			return decodedInstruction{}, refuse(pc, "control-target", "only direct relative branches are modeled")
		}
		target, ok := relative(next, int64(rel))
		if !ok {
			return decodedInstruction{}, refuse(pc, "control-target", "relative target overflow")
		}
		if i.Op != x86asm.JMP {
			n.targets[n.count] = next
			n.count++
		}
		n.targets[n.count] = target
		n.count++
	case x86asm.MOV, x86asm.ADD, x86asm.XOR, x86asm.AND, x86asm.LEA, x86asm.SHR, x86asm.CMP,
		x86asm.SETA, x86asm.SETAE, x86asm.SETB, x86asm.SETBE, x86asm.SETE, x86asm.SETNE, x86asm.SETL, x86asm.SETLE, x86asm.SETG, x86asm.SETGE:
		n.targets[0], n.count = next, 1
	case x86asm.NOP:
		if !(len(b) == 1 && b[0] == 0x90 || len(b) == 2 && b[0] == 0x66 && b[1] == 0x90) {
			return decodedInstruction{}, refuse(pc, "instruction-shape", "unsupported NOP encoding")
		}
		n.targets[0], n.count = next, 1
	default:
		return decodedInstruction{}, refuse(pc, "instruction-semantics", i.Op.String()+" is unsupported")
	}
	return n, nil
}

// A decoded mnemonic is not evidence that the encoding is legal. This subset
// admits at most one operand-size override (only MOV16 or the exact 6690 NOP),
// followed by at most one REX. All ignored/invalid prefix metadata refuses, as
// do LOCK, REP, segments, address overrides, VEX/EVEX and redundant prefixes.
func legalPrefixes(pc uint64, b []byte, i x86asm.Inst) error {
	allow16 := i.Op == x86asm.MOV && i.DataSize == 16 || len(b) == 2 && b[0] == 0x66 && b[1] == 0x90
	return legalScalarPrefixes(pc, b, i, allow16)
}

func legalScalarPrefixes(pc uint64, b []byte, i x86asm.Inst, allow16 bool) error {
	if i.Mode != 64 || i.AddrSize != 64 {
		return refuse(pc, "instruction-prefix", "unsupported addressing mode")
	}
	count, size, rex := 0, false, false
	for _, p := range i.Prefix {
		if p == 0 {
			break
		}
		if p&(x86asm.PrefixInvalid|x86asm.PrefixIgnored) != 0 {
			return refuse(pc, "instruction-prefix", "invalid or ignored prefix")
		}
		v := byte(p)
		if v == 0x66 && !size && !rex {
			size = true
		} else if v >= 0x40 && v <= 0x4f && !rex {
			rex = true
		} else {
			return refuse(pc, "instruction-prefix", "unsupported or duplicate prefix")
		}
		count++
	}
	if count >= len(b) {
		return refuse(pc, "instruction-prefix", "missing opcode")
	}
	if size && !allow16 {
		return refuse(pc, "instruction-prefix", "unsupported operand-size override")
	}
	return nil
}
