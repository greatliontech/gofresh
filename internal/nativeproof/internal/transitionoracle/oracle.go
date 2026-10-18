// Package transitionoracle supplies test evidence for the executed instruction
// vocabulary of an amd64 entry-to-cut transition. It is not a machine interpreter:
// it knows no register values, flags, memory contents, provenance or permissions.
// In particular, every immediate bit pattern is admitted regardless of whether a
// transition consumer can establish its pointer or mask side conditions.
//
// This is an executed-only grammar, NOT the grammar of an unexecuted cut.
// Unsupported conditional branches and vector instructions can be legitimate cut
// evidence even though Parse refuses them. Never use this package to narrow cut
// admission. Its tests alone establish none of the transition theorem's coverage,
// state-transfer, provenance or composition obligations.
//
// The machine conventions are Intel 64 long mode: little-endian payloads, GPR
// numbers RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8 through R15; one REX.W for
// 64-bit data, and default 64-bit addressing with one base and no index. MOV
// admits byte, 32 and 64 bits; narrow register writes preserve other byte lanes
// or zero-extend 32 bits. CMP admits register/immediate/memory 32/64-bit forms;
// TEST admits register/immediate 8/32/64-bit forms. Locked CMPXCHG admits memory64
// under exactly LOCK then REX.W; SETcc admits one byte register or memory operand,
// with the canonical /0 field. Both use ordinary base/displacement or RIP forms.
// Exact 90 and 6690 NOP preserve state. These are structural grammars; permission,
// alignment and primitive applicability remain the machine consumer's obligations.
// conditional edges use the ten conditions over CF/ZF/SF!=OF. CPUID is exact
// operand-free 0f a2, without prefixes. Register self-XOR admits 32-bit operands,
// clearing the full register; other XOR shapes are outside this grammar.
// RIP-relative LEA and data accesses use
// next IP. Direct CALL uses signed rel32, near RET reads the actual return word,
// PUSH/POP admit the canonical 64-bit register forms, and SYSCALL is exact 0f05.
// FS-prefixed MOV admits displacement-only signed disp32 with no index. Other
// legacy prefixes, indexed/absent bases and other widths remain outside
// this executed grammar. REX.W has no width effect on explicitly byte opcodes.
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
	LEARIP                               // Dst <- next IP + SignedDisp, no memory access.
	CPUID                                // Operand-free architectural CPU query.
	Compare
	CompareImmediate
	Test
	TestImmediate
	Branch
	Add
	Call
	Push
	Pop
	Return
	Syscall
	Clear32               // Self-XOR of a 32-bit register, zero-extending into its full GPR.
	LockedCompareExchange // Locked memory <- Src on RAX equality, failed writeback otherwise.
	SetRegister
	SetMemory
	CompareMemory     // memory - Src; no write.
	CompareFromMemory // Dst - memory; no write.
	CompareMemoryImmediate
	NoOp
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
	// Width zero retains the full-width vocabulary; 8/32 select narrow operands.
	Width            uint8
	RIP              bool
	HighDst, HighSrc bool  // AH/CH/DH/BH, with Dst/Src in 0..3.
	Condition        uint8 // Intel condition field, only 2..7 and 12..15.
	FS               bool  // Displacement-only FS memory; Base, RIP and index are absent.
}

// RequiresExpansion is the intent-side search grammar for transition test
// proposals. It is independent of native decoding and never admits execution.
// Byte TEST and memory CMP remain distinct from their older register families.
func RequiresExpansion(i Intent) bool {
	switch i.Operation {
	case Call, Syscall, Clear32, LockedCompareExchange, SetRegister, SetMemory,
		CompareMemory, CompareFromMemory, CompareMemoryImmediate, NoOp:
		return true
	case Test, TestImmediate:
		return i.Width == 8
	}
	return false
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
	CPUID0FA2
	CMP39
	CMP3B
	CMP83
	CMP81
	CMP3D
	TEST85
	TESTF7
	TESTA9
	JccShort
	JccNear
	MOV88
	MOV8A
	MOVC6
	MOVB0
	ADD83
	ADD81
	ADD05
	CALLE8
	PUSH50
	POP58
	RETC3
	SYSCALL0F05
	XOR31
	XOR33
	LOCKCMPXCHG0FB1
	SETcc0F90
	TEST84
	TESTF6
	TESTA8
	NOP90
	NOP6690
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
