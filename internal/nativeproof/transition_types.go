package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionRules identifies the conditional symbolic-origin transition rules,
// including their decoder, expression and ordered pointer-lane dependencies.
const TransitionRules = "gofresh/native-transition@1;" + ValueRules + ";" + FrameRules

// RelativeSpan is a half-open byte extent relative to the single stack origin.
// An envelope permits its End as a pointer, but grants no memory permission.
type RelativeSpan struct{ Start, End int64 }

// OriginDomain quantifies S over inclusive low-canonical bounds and S % Modulus
// == Residue. Modulus must be a positive power of two. Declared external memory
// must additionally be page-disjoint from every image mapping. These conditions
// are conjunctive and must admit at least one S; no concrete runtime S is input.
type OriginDomain struct{ Min, Max, Modulus, Residue uint64 }

// RelativeRegion declares stable ordinary RAM and bounds the accesses this proof
// may use, independently of the address envelope. Mapping premises require every
// granted permission; false grants none without asserting that the underlying
// page lacks it. Overlapping regions must agree on their declared permissions.
type RelativeRegion struct {
	Bytes              RelativeSpan
	Readable, Writable bool
}

// TransitionConditions retains machine, loading, fault and interference premises
// for a prefix only. Machine uses MachineModel's baseline execution restrictions;
// no return slot or normal-completion premise is imported. EntryState asserts
// applicability of the declared symbolic state at the ELF entry. InstructionMapping
// has Conditions' static ELF/4KiB meaning. IsolatedExecution excludes asynchronous
// interference, external termination and context changes before the cut.
// MemoryMapping, NoHiddenAliases and UnalignedAccess have FrameConditions' ordinary
// RAM, stable permissions, distinct-byte and alignment-exception meanings.
type TransitionConditions struct {
	Machine                                           string
	InstructionMapping, EntryState, IsolatedExecution bool
	MemoryMapping, NoHiddenAliases, UnalignedAccess   bool
}

// TransitionInterface declares only entry premises. RSP is the fresh origin S;
// all other registers and flags are arbitrary. Each Words offset introduces a
// fresh arbitrary 64-bit scalar in eight readable bytes, with no pointer or
// process-argument meaning. Other declared bytes are fresh arbitrary bytes;
// undeclared memory remains arbitrary and inaccessible. Expected outputs and
// caller-supplied symbolic values are deliberately absent.
type TransitionInterface struct {
	Origin     OriginDomain
	Envelope   RelativeSpan
	Regions    []RelativeRegion
	Words      []int64
	Conditions TransitionConditions
}

// TransitionLimits bounds graph/expression work and finite declared memory.
// Zero selects defaults; exhaustion never establishes an endpoint.
type TransitionLimits struct {
	RelationLimits
	Regions, Bytes int
}

// TransitionProposal is an untrusted complete entry-to-cut instruction inventory.
// The checker obtains Entry independently from the owned ELF header. The cut node
// has no executed successors; its actual instruction is retained separately.
type TransitionProposal struct {
	ImageDigest [32]byte
	Entry, Cut  uint64
	Nodes       []Node
}

// OriginPointer associates an exact signed offset with the fresh scalar origin.
// A zero Origin means no provenance. Equality of scalar values never creates it.
type OriginPointer struct {
	Origin br.Term
	Offset int64
}

// TransitionValue is a scalar relation with separately justified provenance.
type TransitionValue struct {
	Value   br.Term
	Pointer OriginPointer
}

// TransitionByte is a byte relation at an origin-relative address. PointerLane
// is meaningful only with a nonzero Pointer and reconstructs provenance only
// when all eight ordered lanes of the same pointer are loaded together.
type TransitionByte struct {
	Offset      int64
	Value       br.Term
	Pointer     OriginPointer
	PointerLane uint8
}

// TransitionWord records a fresh arbitrary input word, not an expected output.
type TransitionWord struct {
	Offset int64
	Value  br.Term
}

// TransitionAccess retains an actual full-width access in execution order.
type TransitionAccess struct {
	PC    uint64
	Kind  AccessKind
	Bytes RelativeSpan
}

// TransitionFlag describes an architectural status independently of projection.
// Preserved flags retain their arbitrary entry value; Defined flags may have no
// projected value. Undefined flags have no invented symbolic value.
type TransitionFlag struct {
	Preserved, Defined bool
	Value              br.Term
}

// TransitionFlags covers the arithmetic flags. Every other flag/context component
// is untouched by the admitted instructions under the machine premises.
type TransitionFlags struct{ CF, OF, SF, ZF, AF, PF TransitionFlag }

// CutBoundary records a decoded, reachable but unexecuted instruction. Its bytes
// establish the boundary, not that its effects have been modeled.
type CutBoundary struct {
	PC          uint64
	Instruction x86asm.Inst
	Bytes       []byte
}

// TransitionBound is a cloned, non-authorizing projection. Origin exclusions are
// half-open scalar-S intervals induced by external/image-page disjointness, not
// chosen runtime bases. Registers and Memory are derived cut relations; memory
// outside FrameWrite footprints, preserved GPRs and remaining context are unchanged.
// Instructions contains executed fetches only. Boundary is unexecuted.
type TransitionBound struct {
	ImageDigest      [32]byte
	Rules            string
	Entry            uint64
	Interface        TransitionInterface
	Origin           br.Term
	ExcludedOrigins  []Span
	InitialRegisters [16]br.Term
	InitialMemory    []TransitionByte
	Words            []TransitionWord
	Registers        [16]TransitionValue
	Memory           []TransitionByte
	Preserved        Masks
	Flags            TransitionFlags
	Instructions     []Span
	Accesses         []TransitionAccess
	Boundary         CutBoundary
}

// TransitionCertificate owns a conditional entry-to-cut theorem. It cannot be
// converted to return, frame, value-call, source-startup or runtime reuse evidence.
// Its zero value carries no authority; projections cannot reconstruct it.
type TransitionCertificate struct{ checked *checkedTransition }
type checkedTransition struct {
	image *Image
	bound TransitionBound
}

func cloneTransitionInterface(f TransitionInterface) TransitionInterface {
	f.Regions = append([]RelativeRegion(nil), f.Regions...)
	f.Words = append([]int64(nil), f.Words...)
	return f
}

// Bound returns owned mutable projections and immutable expression handles.
func (c TransitionCertificate) Bound() (TransitionBound, bool) {
	if c.checked == nil {
		return TransitionBound{}, false
	}
	b := c.checked.bound
	b.Interface = cloneTransitionInterface(b.Interface)
	b.ExcludedOrigins = append([]Span(nil), b.ExcludedOrigins...)
	b.InitialMemory = append([]TransitionByte(nil), b.InitialMemory...)
	b.Words = append([]TransitionWord(nil), b.Words...)
	b.Memory = append([]TransitionByte(nil), b.Memory...)
	b.Instructions = append([]Span(nil), b.Instructions...)
	b.Accesses = append([]TransitionAccess(nil), b.Accesses...)
	b.Boundary.Bytes = append([]byte(nil), b.Boundary.Bytes...)
	return b, true
}
