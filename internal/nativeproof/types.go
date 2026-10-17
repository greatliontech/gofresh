package nativeproof

import "fmt"

// Register identifies a full integer register; aliases are decoded internally.
type Register uint8

const (
	RAX Register = iota
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// Masks identifies individual bits in the sixteen integer registers.
type Masks [16]uint64

// MachineModel identifies the supported foundational ISA and return semantics.
// It requires ordinary user-mode x86-64 long mode, baseline integer ISA, no CET
// shadow stack/IBT, and no instruction instrumentation, debug/single-step traps,
// hardware failures, or other synchronous exceptions beyond those excluded by
// the mapping/return conditions. Arithmetic flags at entry remain arbitrary.
const MachineModel = "x86-64/baseline-long-mode/ordinary-near-return@1"

// RuleModel identifies the decoder and abstract proof rules together. A semantic
// change requires a new identity; this is not an implementation approval list.
const RuleModel = "gofresh/native-leaf@5;x86asm@v0.32.0"

// Conditions are explicit caller-supplied premises, not facts this checker proves.
type Conditions struct {
	Machine string
	// InstructionMapping means the checked executable bytes are mapped at their
	// ELF virtual addresses without a load bias, using the 4KiB page mapping
	// model, readable/executable and immutable throughout invocation. ET_EXEC
	// alone does not establish this actual loading condition.
	InstructionMapping bool
	// ReturnSlot means entry RSP addresses eight readable stable bytes containing
	// a valid canonical continuation, RSP+8 is valid without wrap, and ordinary
	// near RET is permitted. The continuation's behavior is outside the scope.
	ReturnSlot bool
	// EntryInputs means the declared input bits are supplied at the entry PC.
	EntryInputs bool
	// IsolatedInvocation excludes asynchronous signals, runtime/preemption work,
	// concurrent modification and surrounding startup/caller/continuation effects.
	IsolatedInvocation bool
}

// Interface declares the exact conditional invocation boundary. Inputs and
// Results are bit projections, not scalar-value or source-language predicates.
// Preserved bits must be untouched; restoring a written register is unsupported.
// RSP belongs exclusively to the return interface and cannot occur in these masks.
// All other unlisted register bits may be clobbered. Arithmetic flags are scratch.
type Interface struct {
	Inputs, Results, Preserved Masks
	Conditions                 Conditions
}

// Node is an untrusted instruction-start inventory entry. Successors are ordered:
// fallthrough first, then the branch target; JMP has only its target, RET none.
type Node struct {
	PC         uint64
	Size       uint8
	Successors []uint64
}

// Proposal carries no authority. Its interface must exactly match the separately
// supplied checking interface, and every node and successor is reconstructed.
type Proposal struct {
	Entry     uint64
	Interface Interface
	Nodes     []Node
}

// Refusal identifies the failed premise at a PC and an entry-to-PC dependency
// path. An unavailable proof is not a counterexample to the proposed property.
type Refusal struct {
	PC      uint64
	Path    []uint64
	Premise string
	Detail  string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("native proof at %#x: %s: %s", r.PC, r.Premise, r.Detail)
}

func refuse(pc uint64, premise, detail string) *Refusal {
	return &Refusal{PC: pc, Path: []uint64{pc}, Premise: premise, Detail: detail}
}

// Span is a half-open virtual-address extent. Its owner distinguishes a proposed
// memory region from a checked instruction or data-access footprint.
type Span struct{ Start, End uint64 }

// Bound is a non-authorizing projection of an opaque checked certificate. The
// proposition is exactly the package's conditional effect/input bound; this
// projection is not accepted as evidence by any constructor or checker.
type Bound struct {
	ImageDigest  [32]byte
	Rules        string
	Entry        uint64
	Interface    Interface
	Instructions []Span
}

// Certificate can only acquire authority through Check. Its zero value has none.
// There is deliberately no serialization or unchecked positive constructor.
type Certificate struct{ checked *checked }

type checked struct {
	image *Image
	bound Bound
}

// Bound returns a copied description and whether this certificate was checked.
func (c Certificate) Bound() (Bound, bool) {
	if c.checked == nil {
		return Bound{}, false
	}
	b := c.checked.bound
	b.Instructions = append([]Span(nil), b.Instructions...)
	return b, true
}
