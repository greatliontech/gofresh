// Package transitionoracle supplies test evidence for the executed instruction
// vocabulary of an amd64 entry-to-cut transition. It is not a machine interpreter:
// it knows no register values, flags, memory contents, provenance or permissions.
// In particular, every immediate bit pattern is admitted regardless of whether a
// transition consumer can establish its pointer or mask side conditions.
//
// This is an executed-only grammar, NOT the grammar of an unexecuted cut. NOP,
// CALL, RET, conditional branches and vector instructions can be legitimate cut
// evidence even though Parse refuses them. Never use this package to narrow cut
// admission. Its tests alone establish none of the transition theorem's coverage,
// state-transfer, provenance or composition obligations.
//
// The machine conventions are Intel 64 long mode: little-endian payloads, GPR
// numbers RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8 through R15; one REX.W for
// 64-bit data, and default 64-bit addressing with one base and no index. The only
// 32-bit operation is B8+rd imm32 (no prefix for low registers, 41 for high ones),
// whose write zero-extends to 64 bits. Prefixes, indexed/absent/RIP-relative bases,
// other widths and other opcode forms are outside this executed grammar.
//
// Intent exists before encoding. Encode and Parse deliberately use different
// integer and byte-field algorithms, with no shared conversion, extraction or
// admission helper. Literal fixtures and mathematical integer checks are needed
// alongside round trips: agreement of two implementations is not its own oracle.
package transitionoracle

// Operation describes semantic operands, independently of their opcode spelling.
type Operation uint8

const (
	MoveRegister    Operation = iota + 1 // Dst <- Src, 64 bits.
	Load                                 // Dst <- memory[Base + SignedDisp], 64 bits.
	Store                                // memory[Base + SignedDisp] <- Src, 64 bits.
	MoveImmediate                        // Dst <- Immediate, 64 bits (B8 or C7).
	MoveImmediate32                      // Dst <- Immediate, zero-extending a 32-bit write.
	StoreImmediate                       // memory[Base + SignedDisp] <- Immediate, 64 bits.
	LEA                                  // Dst <- Base + SignedDisp, 64 bits, no memory access.
	Subtract                             // Dst <- Dst - Immediate, modulo 2^64.
	And                                  // Dst <- Dst & Immediate, 64 bits.
	Jump                                 // next IP + SignedDisp.
)

// Intent is a semantic instruction description. Registers are architectural
// numbers 0..15, including for MoveImmediate32 (the destination's full-register
// identity). Immediate is the effective 64-bit bit pattern, AFTER sign extension
// for C7/81/83/25/2d or zero extension for MoveImmediate32. SignedDisp is a signed
// byte offset: a memory/LEA displacement or a branch displacement from the END of
// the instruction, never an absolute address. Fields unused by Operation must be
// zero; Encode rejects them rather than silently normalizing them.
type Intent struct {
	Operation  Operation
	Dst        uint8
	Src        uint8
	Base       uint8
	SignedDisp int64
	Immediate  uint64
}

// Form selects an opcode spelling. Memory/register direction is determined by
// Intent, not by an extra operand-mode field that could disagree with it.
type Form uint8

const (
	MOV89 Form = iota + 1
	MOV8B
	MOVB8Imm64
	MOVB8Imm32
	MOVC7
	LEA8D
	SUB83
	SUB81
	SUB2D
	AND83
	AND81
	AND25
	JMPEB
	JMPE9
)

// Encoding preserves choices that semantic intent deliberately forgets. REX is
// the exact prefix byte (zero means absent), including ignored R/X/B bits.
// DispBytes is 0, 1 or 4 for memory/LEA and zero otherwise; branch widths are in
// Form. SIB selects an optional no-index SIB, even for bases not requiring it.
// Scale is the literal two-bit SIB scale field 0..3, NOT a multiplier; all four
// values are retained although no index is present. Scale must be zero without
// SIB. Redundant zero/small displacements remain distinct encodings.
type Encoding struct {
	Form      Form
	REX       byte
	DispBytes uint8
	SIB       bool
	Scale     uint8
}

// Decoded retains the semantic instruction and its exact encoding choices.
// Length excludes following bytes. Next is the nonwrapping end address. Target
// is meaningful only for Jump, and is Next + SignedDisp without uint64 wrap.
type Decoded struct {
	Intent   Intent
	Encoding Encoding
	Length   int
	Next     uint64
	Target   uint64
}
