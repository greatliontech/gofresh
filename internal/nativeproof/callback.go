package nativeproof

import (
	"context"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// CallbackRules identifies the readonly-data and single-call composition rules.
const CallbackRules = "gofresh/native-callback@1;" + RuleModel

// DescriptorConditions declares the actual loading premise, not an observation
// of a running process. ReadonlyMapping requires the image's PT_LOAD mapping at
// its declared addresses, 4KiB pages, stable file-backed bytes and permissions,
// no additional aliases or relocation, and no writes through external agents.
type DescriptorConditions struct {
	Machine         string
	ReadonlyMapping bool
}

// DescriptorBound describes one checked little-endian 64-bit entry word. Target
// is a complete conditional entry certificate, not a claim that it was invoked.
type DescriptorBound struct {
	ImageDigest  [32]byte
	Rules        string
	Word, Region Span
	Target       Bound
	Conditions   DescriptorConditions
}

// Descriptor owns checked immutable data and a checked same-image target. Its
// zero value and its descriptive projection grant no evidence.
type Descriptor struct{ checked *checkedDescriptor }
type checkedDescriptor struct {
	image  *Image
	target Certificate
	bound  DescriptorBound
}

// Bound returns a copied, non-authorizing description.
func (d Descriptor) Bound() (DescriptorBound, bool) {
	if d.checked == nil {
		return DescriptorBound{}, false
	}
	b := d.checked.bound
	b.Target, _ = d.checked.target.Bound()
	return b, true
}

// CheckDescriptor binds actual readonly loaded bytes to a separately checked
// target. The address proposes coordinates only; it supplies no incoming-value
// provenance or registration-to-use linkage. Inputs are captured before context
// callbacks. An independent image reconstruction, even byte-identical, refuses.
func CheckDescriptor(ctx context.Context, im *Image, address uint64, target Certificate, conditions DescriptorConditions) (Descriptor, error) {
	im = im.snapshot()
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	if conditions.Machine != MachineModel || !conditions.ReadonlyMapping {
		return Descriptor{}, refuse(address, "descriptor-premises", "explicit machine and immutable loaded-data conditions are required")
	}
	if target.checked == nil || !sameImage(im, target.checked.image) || target.checked.bound.Rules != RuleModel {
		return Descriptor{}, refuse(address, "descriptor-target", "requires a checked target owned by this image and rule model")
	}
	entry, region, err := im.readonlyWord(address)
	if err != nil {
		return Descriptor{}, err
	}
	if entry != target.checked.bound.Entry {
		return Descriptor{}, refuse(address, "descriptor-target", "descriptor word does not designate the checked target entry")
	}
	if _, err := im.instructionBytes(entry); err != nil {
		return Descriptor{}, err
	}
	b := DescriptorBound{ImageDigest: im.digest, Rules: CallbackRules, Word: Span{address, address + 8}, Region: region, Target: target.checked.bound, Conditions: conditions}
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	return Descriptor{&checkedDescriptor{im, target, b}}, nil
}

// LocationKind distinguishes exact entry-state locations; neither is an address
// of an observed runtime value. A stack word is relative to entry RSP.
type LocationKind uint8

const (
	EntryRegister LocationKind = iota + 1
	EntryStackWord
)

// Location identifies a full word. Register locations require Offset==0; stack
// locations require Register==0 and a nonnegative byte offset from entry RSP.
type Location struct {
	Kind     LocationKind
	Register Register
	Offset   int64
}

// ArgumentTransfer requires the selected bits at To to equal those at From on
// fragment entry. The union must exactly cover the callee's declared input bits.
// Interpretation is bit identity; this does not assert a Go ABI or source type.
type ArgumentTransfer struct {
	From Location
	To   Register
	Bits uint64
}

// CallStack is an explicit conditional memory premise: the half-open Region is
// readable/writable, protected for the invocation and has no aliases outside
// itself (including code/data and frame aliases). Pointer is entry RSP. The
// checker verifies the eight-byte CALL write fits, excludes image overlap, and
// retains that write as an effect. The caller's own return slot is not assumed.
type CallStack struct {
	Pointer              uint64
	Region               Span
	Readable, Writable   bool
	Protected, NoAliases bool
}

// CallConditions are premises for the whole fragment and callee invocation.
// EntryState supplies the specified descriptor provenance and argument locations.
// These remain conditions, never derived facts about an ordinary Go invocation.
type CallConditions struct {
	Machine            string
	InstructionMapping bool
	IsolatedInvocation bool
	EntryState         bool
	Stack              CallStack
}

// CallInterface describes a finite fragment ending immediately after one actual
// CALL returns. On entry DescriptorRegister designates the bound descriptor with
// its immutable-region provenance; at the call ContextRegister must designate the
// same descriptor. Arguments describe exact transport, Results select callee
// result bits, and Preserved bits must survive both fragment and callee. Flags
// are clobberable. Every other register bit may be clobbered. Memory is unchanged
// except the retained eight-byte CALL write. No continuation instruction executes
// within this scope; its independently decoded bytes establish the cut boundary.
type CallInterface struct {
	DescriptorRegister, ContextRegister Register
	Arguments                           []ArgumentTransfer
	Results, Preserved                  Masks
	Conditions                          CallConditions
}

// InstructionBytes retains an independently checked instruction and owned bytes.
type InstructionBytes struct {
	Span  Span
	Bytes []byte
}

// CallBound is a non-authorizing projection. The descriptor-register antecedent
// in Interface is not discharged by this certificate. CalleeStackPointer and
// CallWrite describe CALL's RSP-8/store; on return RSP is RestoredStackPointer and
// RIP is Continuation.Span.Start. Target retains every callee premise. Actual use,
// language lowering, suspension, registration, and harness coverage remain open.
type CallBound struct {
	ImageDigest                              [32]byte
	Rules                                    string
	Entry, Call                              uint64
	Descriptor                               DescriptorBound
	Interface                                CallInterface
	Instructions                             []InstructionBytes
	Continuation                             InstructionBytes
	CallWrite                                Span
	CalleeStackPointer, RestoredStackPointer uint64
}

// CallCertificate is an opaque conditional transfer proof with retained target,
// image and descriptor ownership. It has no conversion to public reuse evidence.
type CallCertificate struct{ checked *checkedCall }
type checkedCall struct {
	image      *Image
	descriptor Descriptor
	bound      CallBound
}

func cloneInstruction(i InstructionBytes) InstructionBytes {
	i.Bytes = append([]byte(nil), i.Bytes...)
	return i
}

// Bound returns a fully copied description, never accepted as proof input.
func (c CallCertificate) Bound() (CallBound, bool) {
	if c.checked == nil {
		return CallBound{}, false
	}
	b := c.checked.bound
	b.Descriptor, _ = c.checked.descriptor.Bound()
	b.Interface.Arguments = append([]ArgumentTransfer(nil), b.Interface.Arguments...)
	b.Instructions = append([]InstructionBytes(nil), b.Instructions...)
	for j := range b.Instructions {
		b.Instructions[j] = cloneInstruction(b.Instructions[j])
	}
	b.Continuation = cloneInstruction(b.Continuation)
	return b, true
}

// CheckCall independently checks a linear MOV64/NOP/near-CALL fragment from entry
// to the specified return continuation. A register-indirect call must use a word
// actually loaded from the bound descriptor. A relative direct call must resolve
// to that same checked entry. MOV64 admits register copies, descriptor-word loads
// and loads from declared stack arguments. Other forms, branches and nested calls
// refuse. limit==0 selects 64 instructions; larger limits are capped at 4096.
// A limit or an arbitrary symbol extent can never supply a successful cut.
// The callee is already fully checked; its return and all machine/input/frame
// premises are composed here, including the CALL write before ReturnSlot applies.
func CheckCall(ctx context.Context, im *Image, entry, continuation uint64, descriptor Descriptor, face CallInterface, limit int) (CallCertificate, error) {
	im = im.snapshot()
	if len(face.Arguments) > 16*64 {
		return CallCertificate{}, refuse(entry, "call-interface", "too many argument intervals")
	}
	face.Arguments = append([]ArgumentTransfer(nil), face.Arguments...)
	if err := ctx.Err(); err != nil {
		return CallCertificate{}, err
	}
	if descriptor.checked == nil || !sameImage(im, descriptor.checked.image) {
		return CallCertificate{}, refuse(entry, "call-binding", "missing descriptor or different image owner")
	}
	if limit == 0 {
		limit = 64
	}
	if limit < 1 || limit > 4096 {
		return CallCertificate{}, refuse(entry, "call-budget", "invalid instruction limit")
	}
	target := descriptor.checked.target.checked.bound
	if err := validCallInterface(im, entry, face, target.Interface); err != nil {
		return CallCertificate{}, err
	}
	// Provenance tokens track exact whole-word copies, not dependence alone.
	// Descriptor and target tokens cannot be manufactured by a raw immediate.
	var tokens [16]callToken
	for r := range tokens {
		tokens[r] = callToken{location: Location{Kind: EntryRegister, Register: Register(r)}}
	}
	tokens[face.DescriptorRegister] = callToken{descriptor: true}
	var s state
	protect := Interface{Preserved: face.Preserved}
	stack := face.Conditions.Stack
	b := CallBound{ImageDigest: im.digest, Rules: CallbackRules, Entry: entry, Interface: face,
		CallWrite: Span{stack.Pointer - 8, stack.Pointer}, CalleeStackPointer: stack.Pointer - 8, RestoredStackPointer: stack.Pointer}
	b.Descriptor, _ = descriptor.Bound()
	pc := entry
	for step := 0; step < limit; step++ {
		if err := ctx.Err(); err != nil {
			return CallCertificate{}, err
		}
		i, encoded, err := decodeEncoding(im, pc)
		if err != nil {
			return CallCertificate{}, callFailure(entry, b.Instructions, pc, err)
		}
		next := pc + uint64(i.Len) // executable image is within the low canonical subset
		ins := InstructionBytes{Span{pc, next}, append([]byte(nil), encoded...)}
		if err := disjointTarget(ins.Span, target); err != nil {
			return CallCertificate{}, callFailure(entry, b.Instructions, pc, err)
		}
		if i.Op == x86asm.CALL {
			if next != continuation {
				return CallCertificate{}, callFailure(entry, b.Instructions, pc, refuse(pc, "call-continuation", "CALL does not return to the selected continuation"))
			}
			if err := callOperand(pc, next, i, encoded, tokens, target.Entry); err != nil {
				return CallCertificate{}, callFailure(entry, b.Instructions, pc, err)
			}
			if !tokens[face.ContextRegister].descriptor {
				return CallCertificate{}, callFailure(entry, b.Instructions, pc, refuse(pc, "call-context", "context is not the incoming descriptor"))
			}
			for _, arg := range face.Arguments {
				want := callToken{location: arg.From}
				if arg.From.Kind == EntryRegister && arg.From.Register == face.DescriptorRegister {
					want = callToken{descriptor: true}
				}
				if tokens[arg.To] != want {
					return CallCertificate{}, callFailure(entry, b.Instructions, pc, refuse(pc, "call-argument", fmt.Sprintf("register %d does not carry its declared incoming argument", arg.To)))
				}
			}
			// CALL's protected writable slot is established by validCallInterface;
			// its stored next PC is an actual decoded boundary, not a borrowed
			// callee ReturnSlot assumption or a symbol-size stopping rule.
			cont, raw, err := decodeEncoding(im, continuation)
			if err != nil {
				return CallCertificate{}, callFailure(entry, append(b.Instructions, ins), continuation, err)
			}
			b.Continuation = InstructionBytes{Span{continuation, continuation + uint64(cont.Len)}, append([]byte(nil), raw...)}
			if err := disjointTarget(b.Continuation.Span, target); err != nil {
				return CallCertificate{}, callFailure(entry, append(b.Instructions, ins), continuation, err)
			}
			b.Call = pc
			b.Instructions = append(b.Instructions, ins)
			if err := ctx.Err(); err != nil {
				return CallCertificate{}, err
			}
			return CallCertificate{&checkedCall{im, descriptor, b}}, nil
		}
		if pc == continuation {
			return CallCertificate{}, callFailure(entry, b.Instructions, pc, refuse(pc, "call-continuation", "continuation reached without an actual call"))
		}
		if err := callMove(pc, i, encoded, &s, &tokens, face, protect); err != nil {
			return CallCertificate{}, callFailure(entry, b.Instructions, pc, err)
		}
		b.Instructions = append(b.Instructions, ins)
		pc = next
	}
	return CallCertificate{}, callFailure(entry, b.Instructions, pc, refuse(pc, "call-budget", "fragment instruction budget exhausted"))
}

type callToken struct {
	location           Location
	descriptor, target bool
}

func callFailure(entry uint64, path []InstructionBytes, pc uint64, err error) error {
	if r, ok := err.(*Refusal); ok {
		r.Path = make([]uint64, 0, len(path)+1)
		for _, ins := range path {
			r.Path = append(r.Path, ins.Span.Start)
		}
		r.Path = append(r.Path, pc)
		if len(path) == 0 && entry != pc {
			r.Path = append([]uint64{entry}, r.Path...)
		}
	}
	return err
}

func disjointTarget(span Span, target Bound) error {
	for _, callee := range target.Instructions {
		if span.Start < callee.End && callee.Start < span.End {
			return refuse(span.Start, "call-overlap", "fragment or continuation overlaps the checked callee")
		}
	}
	return nil
}

func validCallInterface(im *Image, pc uint64, face CallInterface, target Interface) error {
	c := face.Conditions
	// Each non-return callee premise is supplied at this scope. EntryInputs is
	// discharged by exact argument transport below; ReturnSlot by the CALL write.
	if c.Machine != MachineModel || !c.InstructionMapping || !c.IsolatedInvocation || !c.EntryState ||
		c.Machine != target.Conditions.Machine || !target.Conditions.InstructionMapping || !target.Conditions.IsolatedInvocation || !target.Conditions.EntryInputs || !target.Conditions.ReturnSlot {
		return refuse(pc, "call-premises", "machine, immutable instructions, isolation and entry-state premises must compose with the callee")
	}
	if face.DescriptorRegister > R15 || face.DescriptorRegister == RSP || face.ContextRegister > R15 || face.ContextRegister == RSP || face.Preserved[RSP]|face.Results[RSP] != 0 {
		return refuse(pc, "call-interface", "invalid descriptor/context or stack-pointer projection")
	}
	s := c.Stack
	if !s.Readable || !s.Writable || !s.Protected || !s.NoAliases || s.Pointer < 8 || s.Region.Start >= s.Region.End || s.Region.End > 1<<47 || s.Pointer > s.Region.End || s.Pointer-8 < s.Region.Start {
		return refuse(pc, "call-stack", "CALL requires a canonical, protected, readable/writable, unaliased eight-byte push slot")
	}
	for _, m := range im.loads {
		if s.Region.Start&^uint64(4095) < (m.end+4095)&^uint64(4095) && m.va&^uint64(4095) < (s.Region.End+4095)&^uint64(4095) {
			return refuse(pc, "call-stack", "stack region overlaps an image mapping page")
		}
	}
	var covered Masks
	for _, a := range face.Arguments {
		if a.To > R15 || a.To == RSP || a.Bits == 0 || covered[a.To]&a.Bits != 0 {
			return refuse(pc, "call-interface", "invalid or overlapping argument projection")
		}
		if err := validLocation(pc, s, a.From); err != nil {
			return err
		}
		covered[a.To] |= a.Bits
	}
	if covered != target.Inputs {
		return refuse(pc, "call-interface", "argument transfers must exactly cover the callee input bits")
	}
	for r := range face.Results {
		if face.Results[r]&^target.Results[r] != 0 || face.Preserved[r]&^target.Preserved[r] != 0 {
			return refuse(pc, "call-frame", "returned results or preserved context exceed the checked callee interface")
		}
	}
	return nil
}

func validLocation(pc uint64, s CallStack, l Location) error {
	switch l.Kind {
	case EntryRegister:
		if l.Register <= R15 && l.Register != RSP && l.Offset == 0 {
			return nil
		}
	case EntryStackWord:
		address, ok := relative(s.Pointer, l.Offset)
		end, endOK := plus(address, 8)
		if l.Register == 0 && l.Offset >= 0 && ok && endOK && address >= s.Region.Start && end <= s.Region.End {
			return nil
		}
	}
	return refuse(pc, "call-interface", "argument is not a valid entry register or protected stack word above the CALL slot")
}

func callOperand(pc, next uint64, i x86asm.Inst, b []byte, tokens [16]callToken, target uint64) error {
	if i.Args[1] != nil {
		return refuse(pc, "call-target", "CALL has extra operands")
	}
	switch operand := i.Args[0].(type) {
	case x86asm.Rel:
		address, ok := relative(next, int64(operand))
		if len(b) == 5 && b[0] == 0xe8 && ok && address == target {
			return nil
		}
	case x86asm.Reg:
		a, ok := register(operand)
		if ok && a.width == 64 && a.reg != int(RSP) && tokens[a.reg].target {
			return nil
		}
	}
	return refuse(pc, "call-target", "CALL does not use the loaded descriptor target or its exact direct entry")
}

func callMove(pc uint64, i x86asm.Inst, b []byte, s *state, tokens *[16]callToken, face CallInterface, protect Interface) error {
	if i.Op == x86asm.NOP {
		_, err := decodeLeaf(pc, i, b)
		return err
	}
	if i.Op != x86asm.MOV {
		return refuse(pc, "call-instruction", "fragment supports MOV64, NOP and one near CALL only")
	}
	r, ok := i.Args[0].(x86asm.Reg)
	a, valid := register(r)
	if !ok || !valid || a.width != 64 || a.reg == int(RSP) {
		return refuse(pc, "call-instruction", "MOV requires a full non-stack integer register destination")
	}
	var token callToken
	op := operation{Op: i.Op, Args: [2]x86asm.Arg{i.Args[0], i.Args[1]}}
	switch src := i.Args[1].(type) {
	case x86asm.Reg:
		from, ok := register(src)
		if !ok || from.width != 64 || from.reg == int(RSP) {
			return refuse(pc, "call-instruction", "MOV source must be a full non-stack integer register")
		}
		token = tokens[from.reg]
		if err := transfer(pc, op, s, protect); err != nil {
			return err
		}
	case x86asm.Mem:
		if i.MemBytes != 8 || src.Segment != 0 || src.Index != 0 {
			return refuse(pc, "call-memory", "only unsegmented unindexed word loads are modeled")
		}
		base, ok := register(src.Base)
		if !ok || base.width != 64 {
			return refuse(pc, "call-memory", "load requires a full integer base register")
		}
		if tokens[base.reg].descriptor && src.Disp == 0 {
			token.target = true
		} else if base.reg == int(RSP) {
			location := Location{Kind: EntryStackWord, Offset: src.Disp}
			found := false
			for _, arg := range face.Arguments {
				found = found || arg.From == location
			}
			if !found {
				return refuse(pc, "call-memory", "stack load lacks a declared protected argument location")
			}
			token.location = location
		} else {
			return refuse(pc, "call-memory", "load lacks descriptor or protected stack provenance")
		}
		// The memory rule supplies the loaded word; shared alias/write validation
		// enforces the same frame rule as the scalar checker.
		if err := s.write(pc, a, value{}, protect); err != nil {
			return err
		}
	default:
		return refuse(pc, "call-instruction", "raw immediates cannot manufacture descriptor or argument provenance")
	}
	tokens[a.reg] = token
	return nil
}
