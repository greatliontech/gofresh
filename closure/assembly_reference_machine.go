package closure

import (
	"context"
	"go/types"
	"slices"
	"strconv"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

type assemblyReferenceSlot struct{ offset, width int }
type assemblyReferencePermission struct {
	space, start, end int
	read, write       bool
}

// The two spaces are separated allocations of the reference semantics. Q and P
// range over canonical, nonwrapping, eight-aligned origins whose full extents
// are disjoint ordinary coherent RAM, mapped for their declared lifetimes and
// permissions. These are reference-model conditions, not sampled addresses or
// assertions about an inline machine frame. Alignment excludes split/bus locks;
// ordinary execution excludes transactional/debug/lock-fault interposition and
// asynchronous modification. The initial return word designates the valid
// executable reference continuation under ordinary near-return semantics; its
// exact bits are arbitrary control context, never a scalar argument. RET must
// prove equality to that original word, rather than assume normal completion.
// RBP retains the caller's frame chain. Other admitted general registers are
// ABI0 scratch (including R14); no operation here changes MXCSR or direction.
type assemblyReferenceFrame struct {
	frameSpace, targetSpace int
	arguments               [3]assemblyReferenceSlot
	result                  assemblyReferenceSlot
	size                    int
	permissions             []assemblyReferencePermission
}

func assemblyReferenceABI(sig *types.Signature, sizes types.Sizes) (assemblyReferenceFrame, error) {
	var f assemblyReferenceFrame
	if sig == nil || sizes == nil || sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 || sig.RecvTypeParams().Len() != 0 || sig.Params().Len() != 3 || sig.Results().Len() != 1 || !types.Identical(sig.Params().At(0).Type(), types.NewPointer(types.Typ[types.Uint64])) || !types.Identical(sig.Params().At(1).Type(), types.Typ[types.Uint64]) || !types.Identical(sig.Params().At(2).Type(), types.Typ[types.Uint64]) || !types.Identical(sig.Results().At(0).Type(), types.Typ[types.Bool]) {
		return f, assemblyReferenceError("unsupported exact typed reference interface")
	}
	word := sizes.Sizeof(types.Typ[types.Uintptr])
	if word != 8 || sizes.Alignof(types.Typ[types.Uint64]) != 8 || sizes.Sizeof(types.Typ[types.Uint64]) != 8 || sizes.Sizeof(types.Typ[types.Bool]) != 1 {
		return f, assemblyReferenceError("selected widths/alignment do not describe amd64 ABI0")
	}
	f.frameSpace, f.targetSpace = 1, 2
	// ABI0 places its argument base one return word above entry SP. Parameters
	// follow their selected typed alignments; results begin at pointer alignment.
	next := int(word)
	align := func(n, a int) int { return (n + a - 1) / a * a }
	for i := range f.arguments {
		t := sig.Params().At(i).Type()
		width, alignment := int(sizes.Sizeof(t)), int(sizes.Alignof(t))
		if width != 8 || alignment != 8 {
			return f, assemblyReferenceError("selected parameter layout is not a full ABI0 word")
		}
		next = align(next, alignment)
		f.arguments[i] = assemblyReferenceSlot{next, width}
		next += width
	}
	next = align(next, int(word))
	f.result = assemblyReferenceSlot{next, int(sizes.Sizeof(sig.Results().At(0).Type()))}
	f.size = next + f.result.width
	f.permissions = []assemblyReferencePermission{
		{f.frameSpace, 0, int(word), true, false},
		{f.frameSpace, int(word), next, true, false},
		{f.frameSpace, next, f.size, true, true},
		{f.targetSpace, 0, 8, true, true},
	}
	return f, nil
}

type assemblyReferencePointer struct{ space, offset int }
type assemblyReferenceCell struct {
	value   br.Term
	pointer assemblyReferencePointer
	lane    int
}
type assemblyReferenceRegister struct {
	value   br.Term
	pointer assemblyReferencePointer
}
type assemblyReferenceSymbolicAccess struct {
	statement                int
	space, offset, width     int
	write, locked, returning bool
	value                    br.Term
}

// The retained relation includes every private access and complete current byte
// state. Only the source projection hides the proven disjoint administrative
// frame. In particular an RMW always contributes both external accesses.
type assemblyReferenceRelation struct {
	inputs                    [3]br.Term // current memory, comparison, replacement -- independent
	value, result             br.Term
	accesses                  []assemblyReferenceSymbolicAccess
	definition                assemblyReferenceDefinition
	frame                     assemblyReferenceFrame
	private, external         []assemblyReferenceCell
	registers                 [16]assemblyReferenceRegister
	flags                     nativeproof.TransitionFlags
	returnedSP, returnWord    br.Term
	returnProof, booleanProof br.Witness
}

type assemblyReferenceMachine struct {
	m                    *assemblyReferenceMeter
	b                    *br.Builder
	isa                  *nativeproof.TransferKernel
	err                  error
	r                    assemblyReferenceRelation
	flags                nativeproof.TransitionPredicates
	entryReturn, entrySP br.Term
	index                int
}

func (x *assemblyReferenceMachine) make(op br.Op, sort br.Sort, imm uint64, args ...br.Term) br.Term {
	if x.err != nil {
		return br.Term{}
	}
	if x.err = x.m.Err(); x.err != nil {
		return br.Term{}
	}
	t, err := x.b.Make(op, sort, imm, args...)
	x.err = err
	return t
}

func (x *assemblyReferenceMachine) extract(t br.Term, offset, width int) br.Term {
	// Register writes concatenate the preserved and replaced bit intervals.
	// Select an interval wholly contained in one component directly; reading a
	// byte must not reintroduce scratch bits preserved outside that byte. Crossing
	// an interval boundary retains an explicit Extract of the whole expression.
	for depth := 0; ; depth++ {
		if x.err != nil {
			return br.Term{}
		}
		if x.err = x.m.Err(); x.err != nil {
			return br.Term{}
		}
		if depth >= x.m.limits.depth || offset < 0 || width < 1 || offset > t.Sort().Width()-width {
			x.err = assemblyReferenceError("invalid or over-depth bit interval")
			return br.Term{}
		}
		if offset == 0 && t.Sort() == br.Bits(width) {
			return t
		}
		v := t.View()
		if v.Op != br.Concat {
			break
		}
		low := v.Args[0].Sort().Width()
		if offset+width <= low {
			t = v.Args[0]
			continue
		}
		if offset >= low {
			t, offset = v.Args[1], offset-low
			continue
		}
		break
	}
	return x.make(br.Extract, br.Bits(width), uint64(offset), t)
}

func (x *assemblyReferenceMachine) seed(cells []assemblyReferenceCell, at, width int, value br.Term, pointer assemblyReferencePointer) {
	for i := 0; i < width; i++ {
		cells[at+i] = assemblyReferenceCell{x.extract(value, i*8, 8), pointer, i}
	}
}

// A whole-word load can recover its original term only when every actual byte
// is precisely the corresponding Extract of that one immutable word. Otherwise
// it reconstructs the word from the current bytes. This is a byte identity, not
// an unchecked value cache. Pointer provenance has the same complete-lane rule.
func (x *assemblyReferenceMachine) word(cells []assemblyReferenceCell, at, width int) assemblyReferenceRegister {
	v := cells[at].value
	if width > 1 {
		first := v.View()
		whole := first.Op == br.Extract && first.Immediate == 0 && len(first.Args) == 1 && first.Args[0].Sort() == br.Bits(width*8)
		for i := 1; i < width && whole; i++ {
			part := cells[at+i].value.View()
			whole = part.Op == br.Extract && part.Immediate == uint64(i*8) && len(part.Args) == 1 && part.Args[0] == first.Args[0]
		}
		if whole {
			v = first.Args[0]
		} else {
			for i := 1; i < width; i++ {
				v = x.make(br.Concat, br.Bits((i+1)*8), 0, v, cells[at+i].value)
			}
		}
	}
	p := cells[at].pointer
	if width != 8 || p.space == 0 {
		p = assemblyReferencePointer{}
	} else {
		for i := 0; i < width; i++ {
			if cells[at+i].pointer != p || cells[at+i].lane != i {
				p = assemblyReferencePointer{}
				break
			}
		}
	}
	return assemblyReferenceRegister{v, p}
}

func assemblyReferenceInterpret(m *assemblyReferenceMeter, definition assemblyReferenceDefinition, frame assemblyReferenceFrame) (*assemblyReferenceRelation, error) {
	if definition.symbol.abi != "ABI0" || definition.locals != 0 || definition.flags&4 == 0 || definition.flags & ^uint64(4|512) != 0 || definition.arguments != int64(frame.size-8) || frame.frameSpace == 0 || frame.targetSpace == 0 || frame.frameSpace == frame.targetSpace {
		return nil, assemblyReferenceError("ABI0 frame, separated storage or zero-leaf prologue conditions disagree")
	}
	// The interpreter's scalar operands are full words and its one projected
	// result is a byte. Consume the typed layout, without a second table of
	// parameter names or precomputed ABI offsets.
	next := 8
	for _, slot := range frame.arguments {
		if slot.offset != next || slot.width != 8 {
			return nil, assemblyReferenceError("argument layout disagrees with the scalar interface")
		}
		next += slot.width
	}
	if frame.result.offset != next || frame.result.width != 1 || frame.size != next+frame.result.width {
		return nil, assemblyReferenceError("result layout disagrees with the scalar interface")
	}
	for i, permission := range frame.permissions {
		if err := m.Err(); err != nil {
			return nil, err
		}
		bound := frame.size
		if permission.space == frame.targetSpace {
			bound = 8
		} else if permission.space != frame.frameSpace {
			return nil, assemblyReferenceError("permission has an unknown allocation origin")
		}
		if permission.start < 0 || permission.end <= permission.start || permission.end > bound {
			return nil, assemblyReferenceError("permission escapes its allocation extent")
		}
		for _, previous := range frame.permissions[:i] {
			if err := m.Err(); err != nil {
				return nil, err
			}
			if permission.space == previous.space && permission.start < previous.end && previous.start < permission.end {
				return nil, assemblyReferenceError("overlapping permission regions are unsupported")
			}
		}
	}
	if len(definition.body) == 0 || len(definition.body) > m.limits.instructions {
		return nil, assemblyReferenceError("missing or oversized complete assembly body")
	}
	kernel, err := nativeproof.NewTransferKernel(m, nativeproof.RelationLimits{Instructions: m.limits.instructions, Nodes: m.limits.nodes, Work: m.limits.work, Depth: m.limits.depth})
	if err != nil {
		return nil, err
	}
	x := &assemblyReferenceMachine{m: m, b: br.NewBuilder(m.limits.nodes), isa: kernel, r: assemblyReferenceRelation{definition: definition, frame: frame, private: make([]assemblyReferenceCell, frame.size), external: make([]assemblyReferenceCell, 8)}}
	scope := br.NewScope()
	for i := range x.r.inputs {
		x.r.inputs[i], err = x.b.Input(br.Bits(64), scope, uint64(i))
		if err != nil {
			return nil, err
		}
	}
	pointer, err := x.b.Input(br.Bits(64), scope, 3)
	if err != nil {
		return nil, err
	}
	x.entrySP, err = x.b.Input(br.Bits(64), scope, 4)
	if err != nil {
		return nil, err
	}
	x.entryReturn, err = x.b.Scratch(br.Bits(64), scope, 0)
	if err != nil {
		return nil, err
	}
	for i := range x.r.registers {
		t, err := x.b.Scratch(br.Bits(64), scope, uint64(i+1))
		if err != nil {
			return nil, err
		}
		x.r.registers[i].value = t
	}
	x.r.registers[nativeproof.RSP] = assemblyReferenceRegister{x.entrySP, assemblyReferencePointer{frame.frameSpace, 0}}
	for i := range x.r.private {
		t, err := x.b.Scratch(br.Bits(8), scope, uint64(i+32))
		if err != nil {
			return nil, err
		}
		x.r.private[i].value = t
	}
	// All six incoming arithmetic flags are arbitrary, with their actual
	// architectural identities retained. SETcc before an overwrite stays unknown.
	flagFields := []*nativeproof.TransitionFlag{&x.r.flags.CF, &x.r.flags.OF, &x.r.flags.SF, &x.r.flags.ZF, &x.r.flags.AF, &x.r.flags.PF}
	for i, field := range flagFields {
		t, err := x.b.Scratch(br.Bool(), scope, uint64(i+128))
		if err != nil {
			return nil, err
		}
		*field = nativeproof.TransitionFlag{Preserved: true, Defined: true, Value: t}
	}
	x.flags = x.predicates(x.r.flags)
	x.seed(x.r.private, 0, 8, x.entryReturn, assemblyReferencePointer{})
	x.seed(x.r.private, frame.arguments[0].offset, 8, pointer, assemblyReferencePointer{frame.targetSpace, 0})
	x.seed(x.r.private, frame.arguments[1].offset, 8, x.r.inputs[1], assemblyReferencePointer{})
	x.seed(x.r.private, frame.arguments[2].offset, 8, x.r.inputs[2], assemblyReferencePointer{})
	x.seed(x.r.external, 0, 8, x.r.inputs[0], assemblyReferencePointer{})
	locked, returned := false, false
	for index, statement := range definition.body {
		x.index = index
		if err := m.Err(); err != nil {
			return nil, err
		}
		if x.err != nil {
			return nil, x.err
		}
		if returned {
			return nil, assemblyReferenceError("unaccounted operations after the reference return")
		}
		if statement.op == "LOCK" {
			if locked || len(statement.args) != 0 {
				return nil, assemblyReferenceError("invalid or repeated LOCK prefix")
			}
			locked = true
			continue
		}
		if locked && statement.op != "CMPXCHGQ" {
			return nil, assemblyReferenceError("LOCK does not prefix its supported RMW instruction")
		}
		if statement.op == "RET" {
			if len(statement.args) != 0 {
				return nil, assemblyReferenceError("redirecting or adjusted return is unsupported")
			}
			ret, err := x.readMemory(x.r.registers[nativeproof.RSP].pointer, 8, false, true)
			if err != nil {
				return nil, err
			}
			if x.r.registers[nativeproof.RSP].pointer != (assemblyReferencePointer{frame.frameSpace, 0}) {
				return nil, assemblyReferenceError("return does not use its protected continuation word")
			}
			w, err := br.Prove(m, ret.value, x.entryReturn, br.Limits{Nodes: m.limits.nodes, Work: m.limits.work})
			if err != nil {
				return nil, err
			}
			x.r.returnWord, x.r.returnProof = ret.value, w
			x.r.returnedSP = x.make(br.Add, br.Bits(64), 0, x.entrySP, x.make(br.Constant, br.Bits(64), 8))
			returned = true
			continue
		}
		if err := x.step(statement, locked); err != nil {
			return nil, err
		}
		locked = false
	}
	if x.err != nil {
		return nil, x.err
	}
	if !returned || locked {
		return nil, assemblyReferenceError("complete body lacks its ordinary return")
	}
	byteResult := x.word(x.r.private, frame.result.offset, frame.result.width).value
	x.r.result = x.make(br.Nonzero, br.Bool(), 0, byteResult)
	canonical := x.make(br.BoolToBits, br.Bits(8), 0, x.r.result)
	if x.err != nil {
		return nil, x.err
	}
	x.r.booleanProof, err = br.Prove(m, byteResult, canonical, br.Limits{Nodes: m.limits.nodes, Work: m.limits.work})
	if err != nil {
		return nil, err
	}
	x.r.value = x.word(x.r.external, 0, 8).value
	// Frame/address values and incoming scratch may not escape to the source
	// projection, including through a partial scalar write that erased provenance.
	roots := []br.Term{x.r.value, x.r.result}
	for _, access := range x.r.accesses {
		if access.space == frame.targetSpace {
			roots = append(roots, access.value)
		}
	}
	if err := assemblyReferenceScalarClosure(m, roots, x.r.inputs); err != nil {
		return nil, err
	}
	if err := m.Err(); err != nil {
		return nil, err
	}
	return &x.r, nil
}

func (x *assemblyReferenceMachine) predicates(f nativeproof.TransitionFlags) nativeproof.TransitionPredicates {
	p := nativeproof.TransitionPredicates{CF: f.CF.Value, ZF: f.ZF.Value}
	if f.SF.Defined && f.OF.Defined && f.SF.Value.Valid() && f.OF.Value.Valid() {
		p.SFXorOF = x.make(br.Not, br.Bool(), 0, x.make(br.Equal, br.Bool(), 0, f.SF.Value, f.OF.Value))
	}
	return p
}

func (x *assemblyReferenceMachine) memory(p assemblyReferencePointer, width int, write bool) ([]assemblyReferenceCell, error) {
	if err := x.m.Err(); err != nil {
		return nil, err
	}
	var cells []assemblyReferenceCell
	switch p.space {
	case x.r.frame.frameSpace:
		cells = x.r.private
	case x.r.frame.targetSpace:
		cells = x.r.external
	default:
		return nil, assemblyReferenceError("address has no checked pointer provenance")
	}
	if p.offset < 0 || width <= 0 || p.offset > len(cells)-width {
		return nil, assemblyReferenceError("full memory access escapes its owned extent")
	}
	if p.space == x.r.frame.targetSpace && (p.offset != 0 || width != 8) {
		return nil, assemblyReferenceError("source projection requires a full typed uint64 access")
	}
	for _, permission := range x.r.frame.permissions {
		if err := x.m.Err(); err != nil {
			return nil, err
		}
		if permission.space == p.space && p.offset >= permission.start && p.offset+width <= permission.end {
			if write && !permission.write || !write && !permission.read {
				return nil, assemblyReferenceError("access lacks its required memory permission")
			}
			if write && p.space == x.r.frame.frameSpace && p.offset < 8 {
				return nil, assemblyReferenceError("write overlaps protected return context")
			}
			return cells, nil
		}
	}
	return nil, assemblyReferenceError("access crosses an unavailable permission boundary")
}

func (x *assemblyReferenceMachine) readMemory(p assemblyReferencePointer, width int, locked, returning bool) (assemblyReferenceRegister, error) {
	cells, err := x.memory(p, width, false)
	if err != nil {
		return assemblyReferenceRegister{}, err
	}
	v := x.word(cells, p.offset, width)
	x.r.accesses = append(x.r.accesses, assemblyReferenceSymbolicAccess{x.index, p.space, p.offset, width, false, locked, returning, v.value})
	return v, x.err
}

func (x *assemblyReferenceMachine) writeMemory(p assemblyReferencePointer, width int, v assemblyReferenceRegister, locked bool) error {
	cells, err := x.memory(p, width, true)
	if err != nil {
		return err
	}
	if v.pointer.space != 0 {
		return assemblyReferenceError("pointer escapes through a reference store")
	}
	x.seed(cells, p.offset, width, v.value, assemblyReferencePointer{})
	x.r.accesses = append(x.r.accesses, assemblyReferenceSymbolicAccess{x.index, p.space, p.offset, width, true, locked, false, v.value})
	return x.err
}

// Plan 9's AX/BX/... select their width from the actual opcode; byte high
// aliases are explicit. The normalized x86 register is then checked by the
// shared alias kernel, including partial-write preservation and 32-bit extension.
func assemblyReferenceRegisterName(name string, width int) (x86asm.Reg, bool) {
	names := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	idx := slices.Index(names, name)
	if idx >= 0 {
		switch width {
		case 64:
			return x86asm.RAX + x86asm.Reg(idx), true
		case 32:
			return x86asm.EAX + x86asm.Reg(idx), true
		case 8:
			if idx < 4 {
				return x86asm.AL + x86asm.Reg(idx), true
			}
			return x86asm.SPB + x86asm.Reg(idx-4), true
		}
	}
	if width == 8 {
		if idx := slices.Index([]string{"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"}, name); idx >= 0 {
			return x86asm.AL + x86asm.Reg(idx), true
		}
	}
	return 0, false
}

func (x *assemblyReferenceMachine) address(tokens []string) (assemblyReferencePointer, error) {
	if len(tokens) < 3 || tokens[len(tokens)-3] != "(" || tokens[len(tokens)-1] != ")" {
		return assemblyReferencePointer{}, assemblyReferenceError("unsupported source memory operand")
	}
	base := tokens[len(tokens)-2]
	prefix := tokens[:len(tokens)-3]
	displacement := int64(0)
	var pointer assemblyReferencePointer
	if base == "FP" {
		if len(prefix) < 1 || !assemblyReferenceIdentifier(prefix[0]) {
			return pointer, assemblyReferenceError("FP requires a named argument reference")
		}
		prefix = prefix[1:]
		pointer = assemblyReferencePointer{x.r.frame.frameSpace, 8}
	} else {
		reg, ok := assemblyReferenceRegisterName(base, 64)
		if !ok {
			return pointer, assemblyReferenceError("unsupported address base")
		}
		full, _, _, _ := nativeproof.RegisterAlias(reg)
		pointer = x.r.registers[full].pointer
	}
	if len(prefix) > 0 {
		sign := int64(1)
		if prefix[0] == "+" || prefix[0] == "-" {
			if prefix[0] == "-" {
				sign = -1
			}
			prefix = prefix[1:]
		}
		if len(prefix) != 1 {
			return pointer, assemblyReferenceError("unsupported address displacement")
		}
		n, err := strconv.ParseInt(prefix[0], 0, 32)
		if err != nil || n < 0 {
			return pointer, assemblyReferenceError("invalid address displacement")
		}
		displacement = sign * n
	}
	if pointer.space == 0 || displacement < -int64(pointer.offset) || displacement > int64(x.r.frame.size+8-pointer.offset) {
		return pointer, assemblyReferenceError("address lacks bounded pointer provenance")
	}
	pointer.offset += int(displacement)
	return pointer, nil
}

func (x *assemblyReferenceMachine) operand(tokens []string, width int) (assemblyReferenceRegister, error) {
	if len(tokens) == 1 {
		reg, ok := assemblyReferenceRegisterName(tokens[0], width)
		if ok {
			full, offset, bits, ok := nativeproof.RegisterAlias(reg)
			if !ok || bits != width {
				return assemblyReferenceRegister{}, assemblyReferenceError("normalized register width differs")
			}
			v := x.r.registers[full]
			v.value = x.extract(v.value, offset, width)
			if width != 64 {
				v.pointer = assemblyReferencePointer{}
			}
			return v, x.err
		}
	}
	if len(tokens) >= 2 && tokens[0] == "$" {
		value := uint64(0)
		var err error
		negative := false
		if len(tokens) == 2 {
			value, err = strconv.ParseUint(tokens[1], 0, 64)
		} else if len(tokens) == 3 && tokens[1] == "-" {
			var n int64
			n, err = strconv.ParseInt("-"+tokens[2], 0, 64)
			value = uint64(n)
			negative = true
		} else {
			return assemblyReferenceRegister{}, assemblyReferenceError("unsupported immediate expression")
		}
		if err != nil {
			return assemblyReferenceRegister{}, assemblyReferenceError("invalid immediate")
		}
		if width < 64 && (!negative && value > ^uint64(0)>>(64-width) || negative && int64(value) < -(int64(1)<<(width-1))) {
			return assemblyReferenceRegister{}, assemblyReferenceError("immediate exceeds its instruction width")
		}
		value &= ^uint64(0) >> (64 - width)
		return assemblyReferenceRegister{value: x.make(br.Constant, br.Bits(width), value)}, x.err
	}
	p, err := x.address(tokens)
	if err != nil {
		return assemblyReferenceRegister{}, err
	}
	return x.readMemory(p, width/8, false, false)
}

func (x *assemblyReferenceMachine) destination(tokens []string, width int, v assemblyReferenceRegister) error {
	if len(tokens) == 1 {
		reg, ok := assemblyReferenceRegisterName(tokens[0], width)
		if ok {
			full, offset, bits, ok := nativeproof.RegisterAlias(reg)
			if !ok || bits != width || full == nativeproof.RSP || full == nativeproof.RBP {
				return assemblyReferenceError("register destination intersects protected stack/frame context")
			}
			if width == 64 {
				x.r.registers[full] = v
				return x.err
			}
			if width == 32 {
				x.r.registers[full] = assemblyReferenceRegister{value: x.make(br.ZExt, br.Bits(64), 0, v.value)}
				return x.err
			}
			old := x.r.registers[full].value
			value := v.value
			if offset > 0 {
				value = x.make(br.Concat, br.Bits(offset+width), 0, x.extract(old, 0, offset), value)
			}
			if offset+width < 64 {
				value = x.make(br.Concat, br.Bits(64), 0, value, x.extract(old, offset+width, 64-offset-width))
			}
			x.r.registers[full] = assemblyReferenceRegister{value: value}
			return x.err
		}
	}
	p, err := x.address(tokens)
	if err != nil {
		return err
	}
	return x.writeMemory(p, width/8, v, false)
}

func assemblyReferenceCondition(op string) (x86asm.Op, bool) {
	switch op {
	case "SETEQ":
		return x86asm.SETE, true
	case "SETNE":
		return x86asm.SETNE, true
	case "SETCS":
		return x86asm.SETB, true
	case "SETCC":
		return x86asm.SETAE, true
	case "SETHI":
		return x86asm.SETA, true
	case "SETLS":
		return x86asm.SETBE, true
	case "SETLT":
		return x86asm.SETL, true
	case "SETLE":
		return x86asm.SETLE, true
	case "SETGT":
		return x86asm.SETG, true
	case "SETGE":
		return x86asm.SETGE, true
	}
	return 0, false
}

func (x *assemblyReferenceMachine) step(statement assemblyReferenceStatement, locked bool) error {
	args := statement.args
	if op, ok := assemblyReferenceCondition(statement.op); ok {
		if len(args) != 1 {
			return assemblyReferenceError("SETcc requires one exact byte destination")
		}
		value, err := x.isa.SetCondition(op, x.flags)
		if err != nil {
			return err
		}
		return x.destination(args[0], 8, assemblyReferenceRegister{value: value})
	}
	if len(args) != 2 {
		return assemblyReferenceError("unsupported body transfer or operand count: " + statement.op)
	}
	if statement.op == "CMPXCHGQ" {
		if !locked || len(args[0]) != 1 {
			return assemblyReferenceError("compare/exchange requires locked memory and a full register source")
		}
		reg, ok := assemblyReferenceRegisterName(args[0][0], 64)
		if !ok {
			return assemblyReferenceError("compare/exchange replacement is not a full register")
		}
		full, _, _, _ := nativeproof.RegisterAlias(reg)
		source := x.r.registers[full]
		p, err := x.address(args[1])
		if err != nil {
			return err
		}
		// Write permission is required before either arm, including failure's
		// unchanged-value write cycle. Only an external uint64 is projected.
		if p.space != x.r.frame.targetSpace {
			return assemblyReferenceError("RMW destination is not represented source storage")
		}
		if _, err := x.memory(p, 8, true); err != nil {
			return err
		}
		current, err := x.readMemory(p, 8, true, false)
		if err != nil {
			return err
		}
		if source.pointer.space != 0 || x.r.registers[nativeproof.RAX].pointer.space != 0 {
			return assemblyReferenceError("RMW operands carry escaping pointer representations")
		}
		result, err := x.isa.CompareExchange64(x.r.registers[nativeproof.RAX].value, current.value, source.value)
		if err != nil {
			return err
		}
		x.r.flags, x.flags = result.Flags, result.Predicates
		x.r.registers[nativeproof.RAX] = assemblyReferenceRegister{value: result.Accumulator}
		return x.writeMemory(p, 8, assemblyReferenceRegister{value: result.Memory}, true)
	}
	width := 0
	switch statement.op {
	case "MOVQ", "CMPQ", "TESTQ":
		width = 64
	case "MOVL", "CMPL", "TESTL":
		width = 32
	case "MOVB", "CMPB", "TESTB":
		width = 8
	default:
		return assemblyReferenceError("unsupported selected-body instruction: " + statement.op)
	}
	left, err := x.operand(args[0], width)
	if err != nil {
		return err
	}
	if statement.op[:3] == "MOV" {
		// amd64 MOV has no memory-to-memory form. Reject before interpreting a
		// fictitious write, even when the byte domains could model such a copy.
		if len(args[0]) > 1 && args[0][0] != "$" && len(args[1]) > 1 {
			return assemblyReferenceError("MOV has two memory operands")
		}
		if width == 64 && args[0][0] == "$" && len(args[1]) > 1 && !assemblyReferenceSignedImmediate32(left.value) {
			return assemblyReferenceError("MOVQ memory immediate lacks its sign-extended 32-bit encoding")
		}
		return x.destination(args[1], width, left)
	}
	right, err := x.operand(args[1], width)
	if err != nil {
		return err
	}
	if len(args[0]) > 1 && len(args[1]) > 1 {
		return assemblyReferenceError("comparison has unsupported memory/immediate operands")
	}
	if width == 64 && (args[0][0] == "$" && !assemblyReferenceSignedImmediate32(left.value) || args[1][0] == "$" && !assemblyReferenceSignedImmediate32(right.value)) {
		return assemblyReferenceError("64-bit comparison/test immediate lacks its sign-extended 32-bit encoding")
	}
	var flags nativeproof.TransitionFlags
	// Go's CMP order is left minus right; TEST is commutative. Instruction
	// normalization establishes that order before sharing the scalar ISA rule.
	if statement.op[:3] == "CMP" {
		flags, err = x.isa.Compare(left.value, right.value)
	} else {
		flags, err = x.isa.Test(left.value, right.value)
	}
	if err != nil {
		return err
	}
	x.r.flags, x.flags = flags, x.predicates(flags)
	return x.err
}

func assemblyReferenceSignedImmediate32(t br.Term) bool {
	v := t.View()
	return v.Op == br.Constant && t.Sort() == br.Bits(64) && uint64(int64(int32(v.Immediate))) == v.Immediate
}

func assemblyReferenceScalarClosure(m *assemblyReferenceMeter, roots []br.Term, inputs [3]br.Term) error {
	type item struct {
		term  br.Term
		depth int
	}
	stack := make([]item, 0, len(roots))
	for _, root := range roots {
		stack = append(stack, item{root, 1})
	}
	seen := map[br.Term]int{}
	for len(stack) > 0 {
		if err := m.Err(); err != nil {
			return err
		}
		at := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !at.term.Valid() || at.depth > m.limits.depth {
			return assemblyReferenceError("invalid scalar relation or expression depth")
		}
		if seen[at.term] >= at.depth {
			continue
		}
		seen[at.term] = at.depth
		if len(seen) > m.limits.nodes {
			return assemblyReferenceError("scalar graph node budget exhausted")
		}
		v := at.term.View()
		if v.Op == br.Variable && !slices.Contains(inputs[:], at.term) {
			return assemblyReferenceError("pointer, private bytes or arbitrary scratch escape the scalar projection")
		}
		for _, child := range v.Args {
			stack = append(stack, item{child, at.depth + 1})
		}
	}
	return nil
}

// evaluate applies only the three retained input variables. It preserves every
// other variable and obtains constants from independently checked normalization,
// never from assigning arbitrary scratch bits or evaluating samples.
func (r *assemblyReference) evaluate(ctx context.Context, current, old, replacement uint64) (assemblyReferenceResult, error) {
	if r == nil || r.checked == nil || r.checked.rules != assemblyReferenceRules || r.checked.relation == nil {
		return assemblyReferenceResult{}, assemblyReferenceError("missing checked reference")
	}
	p := r.checked
	m := &assemblyReferenceMeter{Context: ctx, limits: p.limits}
	return assemblyReferenceApply(m, p.relation, [3]uint64{current, old, replacement})
}

func assemblyReferenceApply(m *assemblyReferenceMeter, r *assemblyReferenceRelation, values [3]uint64) (assemblyReferenceResult, error) {
	b := br.NewBuilder(m.limits.nodes)
	substitution := map[br.Term]br.Term{}
	for i, input := range r.inputs {
		if err := m.Err(); err != nil {
			return assemblyReferenceResult{}, err
		}
		if !input.Valid() || input.View().Op != br.Variable || input.View().Scratch || input.Sort() != br.Bits(64) {
			return assemblyReferenceResult{}, assemblyReferenceError("invalid retained formal input")
		}
		t, err := b.Const(input.Sort(), values[i])
		if err != nil {
			return assemblyReferenceResult{}, err
		}
		substitution[input] = t
	}
	cache := map[br.Term]br.Term{}
	var substitute func(br.Term, int) (br.Term, error)
	substitute = func(t br.Term, depth int) (br.Term, error) {
		if err := m.Err(); err != nil {
			return br.Term{}, err
		}
		if depth > m.limits.depth || !t.Valid() {
			return br.Term{}, assemblyReferenceError("substitution expression depth exhausted")
		}
		if value, ok := substitution[t]; ok {
			return value, nil
		}
		if value, ok := cache[t]; ok {
			return value, nil
		}
		if len(cache) >= m.limits.nodes {
			return br.Term{}, assemblyReferenceError("substitution node budget exhausted")
		}
		v := t.View()
		if v.Op == br.Variable {
			return t, nil
		}
		args := make([]br.Term, len(v.Args))
		for i, child := range v.Args {
			var err error
			args[i], err = substitute(child, depth+1)
			if err != nil {
				return br.Term{}, err
			}
		}
		result, err := b.Make(v.Op, v.Sort, v.Immediate, args...)
		if err != nil {
			return br.Term{}, err
		}
		cache[t] = result
		return result, nil
	}
	constant := func(t br.Term) (uint64, error) {
		instantiated, err := substitute(t, 0)
		if err != nil {
			return 0, err
		}
		return assemblyReferenceConstant(m, instantiated)
	}
	var result assemblyReferenceResult
	var err error
	result.Value, err = constant(r.value)
	if err != nil {
		return assemblyReferenceResult{}, err
	}
	boolean, err := constant(r.result)
	if err != nil {
		return assemblyReferenceResult{}, err
	}
	if !r.result.Sort().IsBool() || boolean > 1 {
		return assemblyReferenceResult{}, assemblyReferenceError("reference result is not Boolean")
	}
	result.Result = boolean == 1
	for _, access := range r.accesses {
		if err := m.Err(); err != nil {
			return assemblyReferenceResult{}, err
		}
		if access.space != r.frame.targetSpace {
			continue
		}
		value, err := constant(access.value)
		if err != nil {
			return assemblyReferenceResult{}, err
		}
		result.Accesses = append(result.Accesses, assemblyReferenceAccess{access.write, access.locked, value})
	}
	if err := m.Err(); err != nil {
		return assemblyReferenceResult{}, err
	}
	return result, nil
}

func assemblyReferenceConstant(m *assemblyReferenceMeter, term br.Term) (uint64, error) {
	// Search may propose a normal form, but only Check's equality at these exact
	// endpoints establishes a result for all remaining admitted variables.
	limits := br.Limits{Nodes: m.limits.nodes, Work: m.limits.work}
	proposal, err := br.Propose(m, term, term, limits)
	if err != nil {
		return 0, err
	}
	for i, step := range proposal.Steps {
		if err := m.Err(); err != nil {
			return 0, err
		}
		v := step.Right.View()
		if step.Left != term || v.Op != br.Constant || step.Right.Sort() != term.Sort() {
			continue
		}
		w, err := br.Check(m, term, step.Right, br.Proof{Steps: proposal.Steps[:i+1]}, limits)
		if err != nil {
			return 0, err
		}
		left, right := w.Roots()
		if !w.Valid() || left != term || right != step.Right {
			return 0, assemblyReferenceError("scalar specialization proof endpoints differ")
		}
		return v.Immediate, nil
	}
	return 0, assemblyReferenceError("scalar specialization retains unproved arbitrary state")
}
