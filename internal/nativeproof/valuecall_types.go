package nativeproof

// ValueCallMachine adds enabled ordinary SSE2 execution to MachineModel: SSE2 is
// available, CR0.EM/TS and CR4.OSFXSR permit the admitted integer-vector forms,
// and SIMD/debug/alignment exceptions are excluded by the declared machine and
// mapping conditions. It admits no AVX, floating-point arithmetic, TLS or syscall
// semantics. This is a foundational model, not a compiler/CPU approval label.
const ValueCallMachine = MachineModel + ";enabled-integer-sse2@1"

// ValueCallRules identifies checked constant/known-bit value, byte-memory, branch
// exclusion and direct-CALL composition semantics. Older leaf/frame certificates
// cannot represent this scope's value premises or memory result interface.
const ValueCallRules = "gofresh/native-value-call@1;" + FrameRules

// RegisterConstant is an explicit entry-bit premise, separate from permissions.
// Value has no bits outside Bits. Other bits remain arbitrary.
type RegisterConstant struct {
	Register    Register
	Bits, Value uint64
}

// MemoryConstant describes an explicit initial scalar in external stack memory.
// Width is 1, 2, 4 or 8 bytes, little-endian. It cannot overlap another initial
// word/pointer premise or a requested result: output values are derived, not inputs.
type MemoryConstant struct {
	Address uint64
	Width   int
	Value   uint64
}

// ValueCallConditions applies for the entire fragment and callee. ImageBytesMapped
// additionally requires Readonly's actual loaded bytes to equal the immutable
// image bytes throughout the scope. EntryState supplies the declared register,
// pointer and stack-value premises. These conditions do not establish actual Go
// execution, isolation, suspension lifting or source-call association.
type ValueCallConditions struct {
	Machine                                                          string
	InstructionMapping, MemoryMapping, ImageBytesMapped              bool
	NoHiddenAliases, UnalignedAccess, IsolatedInvocation, EntryState bool
}

// ValueCallInterface starts within an already allocated caller frame. Stack is
// exact caller RSP, not a pre-existing return slot. Regions/Protected/Preserved
// have the byte-frame meanings; the actual CALL separately establishes its own
// protected return slot within Stack's region. Initial pointer origins must be
// exact in this domain.
// Readonly selects immutable image byte spans whose contents the checker reads;
// other memory is arbitrary unless covered by a declared MemoryConstant/pointer.
// Results selects disjoint 1/2/4/8-byte writable stack slots. Every callee terminal
// path must actually write all their bytes and derive the same complete values.
// No scalar register result or post-continuation behavior is claimed.
type ValueCallInterface struct {
	Regions           []ByteRegion
	Pointers          []RegisterPointer
	MemoryPointers    []MemoryPointer
	Stack             RegionPointer
	Protected         []Span
	Preserved         Masks
	PreservedXMM      [16]bool
	Scalars           []RegisterConstant
	StackValues       []MemoryConstant
	Readonly, Results []Span
	Conditions        ValueCallConditions
}

// ValueCallRequest proposes the fragment entry, direct target, and immediate
// post-CALL continuation. None is a trusted boundary or callee summary.
type ValueCallRequest struct {
	Entry, Target, Continuation uint64
	Interface                   ValueCallInterface
}

// MemoryResult is a derived complete little-endian result, not an expected value.
type MemoryResult struct {
	Bytes Span
	Value uint64
}

// BranchEvidence retains an actual decoded branch's feasible successor inventory.
// Known predicates retain only their justified successor; unknown but defined
// predicates retain both. Repeated PCs can have distinct path-local evidence.
type BranchEvidence struct {
	PC         uint64
	Successors []uint64
}

// ValueCallBound describes a conditional, connected value/frame proof. Accesses
// includes caller marshaling, CALL's eight-byte write, all callee data accesses
// and RET's read. CalleeEntryRSP and ReturnedRSP retain the actual push/return
// relation. Instructions includes all checked caller/callee instructions, and
// Continuation is decoded solely to establish the cut boundary. Register/XMM
// writes are conservative unions, not claims that scratch has a particular value.
type ValueCallBound struct {
	ImageDigest                       [32]byte
	Rules                             string
	Request                           ValueCallRequest
	Call, CalleeEntryRSP, ReturnedRSP uint64
	Instructions                      []InstructionBytes
	Continuation                      InstructionBytes
	Branches                          []BranchEvidence
	Accesses                          []FrameAccess
	Results                           []MemoryResult
	RegisterWrites                    Masks
	XMMWrites                         uint16
}

// ValueCall is opaque owned evidence. It is deliberately not a leaf Certificate
// or FrameCertificate: their interfaces lack this theorem's conditional values.
// There is no unchecked constructor, serialization or public runtime grant.
type ValueCall struct{ checked *checkedValueCall }
type checkedValueCall struct {
	image *Image
	bound ValueCallBound
}

func cloneValueCallInterface(f ValueCallInterface) ValueCallInterface {
	f.Regions = append([]ByteRegion(nil), f.Regions...)
	f.Pointers = append([]RegisterPointer(nil), f.Pointers...)
	f.MemoryPointers = append([]MemoryPointer(nil), f.MemoryPointers...)
	f.Protected = append([]Span(nil), f.Protected...)
	f.Scalars = append([]RegisterConstant(nil), f.Scalars...)
	f.StackValues = append([]MemoryConstant(nil), f.StackValues...)
	f.Readonly = append([]Span(nil), f.Readonly...)
	f.Results = append([]Span(nil), f.Results...)
	return f
}

// Bound returns a fully copied, non-authorizing projection.
func (c ValueCall) Bound() (ValueCallBound, bool) {
	if c.checked == nil {
		return ValueCallBound{}, false
	}
	b := c.checked.bound
	b.Request.Interface = cloneValueCallInterface(b.Request.Interface)
	b.Instructions = append([]InstructionBytes(nil), b.Instructions...)
	for j := range b.Instructions {
		b.Instructions[j] = cloneInstruction(b.Instructions[j])
	}
	b.Continuation = cloneInstruction(b.Continuation)
	b.Branches = append([]BranchEvidence(nil), b.Branches...)
	for j := range b.Branches {
		b.Branches[j].Successors = append([]uint64(nil), b.Branches[j].Successors...)
	}
	b.Accesses = append([]FrameAccess(nil), b.Accesses...)
	b.Results = append([]MemoryResult(nil), b.Results...)
	return b, true
}
