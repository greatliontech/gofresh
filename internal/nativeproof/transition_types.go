package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionRules identifies the conditional symbolic-origin transition rules,
// including guarded DAG transport, decoder, expression, pointer-lane and CPUID dependencies.
const TransitionRules = "gofresh/native-transition@5;" + ValueRules + ";" + FrameRules + ";" + cpuidRules

const cpuidRules = "gofresh/native-cpuid@1"

// CPUIDModel identifies the ordinary x86-64 architectural CPUID step: available
// and enabled at the executing privilege level, with applicable faulting controls
// disabled, outside transactional/enclave abort or exception contexts and without
// a guest-visible exception or unproved handler path. ISA-conforming virtual CPUs,
// microcode and transparent host VM exits below this layer are admitted. This is
// a configuration predicate, not an assumption of normal completion or an observed
// response. Fetch, isolation, debug and other machine premises remain required.
const CPUIDModel = "x86-64/cpuid-enabled-architectural-step@1"

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
// for an entry-to-cut scope. A continuation retains these as premises over the
// entire longer scope, not as observed stability facts from its predecessor.
// Machine uses MachineModel's baseline execution restrictions;
// no return slot or normal-completion premise is imported. EntryState asserts
// applicability of the declared symbolic state at the ELF entry. InstructionMapping
// has Conditions' static ELF/4KiB meaning. IsolatedExecution excludes asynchronous
// interference, external termination and context changes before the cut.
// MemoryMapping, NoHiddenAliases and UnalignedAccess have FrameConditions' ordinary
// RAM, stable permissions, distinct-byte and alignment-exception meanings.
type TransitionConditions struct {
	Machine string
	// CPUID is optional for scopes that do not execute a query. Executing CPUID
	// requires CPUIDModel; an unknown nonempty model is unsupported in any scope.
	CPUID                                             string
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
	Origin   OriginDomain
	Envelope RelativeSpan
	Regions  []RelativeRegion
	// ImageRegions grants access only within these absolute extents. Permissions
	// come from the owned PT_LOAD mappings; every initial data byte is arbitrary,
	// including readonly and zero-fill bytes. Instruction fetch is separate.
	ImageRegions []Span
	Words        []int64
	Conditions   TransitionConditions
}

// TransitionLimits bounds graph/expression work and finite declared memory.
// Zero selects defaults; exhaustion never establishes an endpoint. Continuations
// inherit the root's normalized limits, cumulative construction work and complete
// instruction inventory (including the new unexecuted cut).
type TransitionLimits struct {
	RelationLimits
	Regions, Bytes int
	// LiveStateBytes bounds aggregate live node states, including byte maps.
	LiveStateBytes int
}

// TransitionProposal is an untrusted complete entry-to-cut instruction inventory.
// The checker obtains Entry independently from the owned ELF header. The cut node
// has no executed successors; its actual instruction is retained separately.
// A continuation still supplies this complete inventory from the original entry.
type TransitionProposal struct {
	ImageDigest [32]byte
	Entry, Cut  uint64
	Nodes       []Node
}

// TransitionPointer is a closed provenance sum. Nil means no provenance. Its
// arms identify a symbolic stack origin or an owned image mapping; equality of
// scalar values never creates either. Distinct arms do not prove numerical
// inequality outside the declared, disjoint memory footprints.
type TransitionPointer interface{ transitionPointer() }

// OriginPointer associates an exact signed offset with the fresh scalar origin.
type OriginPointer struct {
	Origin br.Term
	Offset int64
}

func (OriginPointer) transitionPointer() {}

// ImagePointer identifies an address within one owned logical load (including
// its canonical one-past address). The private backing owner survives Image's
// container snapshots, but not independent construction from equal bytes.
type ImagePointer struct {
	Address uint64
	owner   *byte
	load    int
}

func (ImagePointer) transitionPointer() {}

// TransitionLocation is a byte coordinate in the single current memory map.
// Image selects an absolute low-canonical address; otherwise Offset is relative
// to S. The namespaces are disjoint only for declared accessible memory.
type TransitionLocation struct {
	Image  bool
	Offset int64
}

// TransitionValue is a scalar relation with separately justified provenance.
type TransitionValue struct {
	Value   br.Term
	Pointer TransitionPointer
}

// TransitionByte is a byte relation at a tagged stack/image location. PointerLane
// is meaningful only with a non-nil Pointer and reconstructs provenance only
// when all eight ordered lanes of the same pointer are loaded together.
type TransitionByte struct {
	TransitionLocation
	Value       br.Term
	Pointer     TransitionPointer
	PointerLane uint8
}

// TransitionWord records a fresh arbitrary input word, not an expected output.
type TransitionWord struct {
	Offset int64
	Value  br.Term
}

// TransitionAccess retains a conditional full-operand access. Its PC identifies
// the owning instruction guard; filtering those guards yields execution order.
type TransitionAccess struct {
	PC    uint64
	Kind  AccessKind
	Bytes RelativeSpan
	// Image selects absolute low-canonical coordinates in Bytes.
	Image bool
}

// PrimitiveEffect is a closed sum of checked architectural primitive occurrences.
// Each PC inherits its instruction's guard. Filtering those guards supplies the
// occurrence order and interleaving with other transfers. These are dependencies,
// not observations or claims that every listed occurrence executes.
type PrimitiveEffect interface{ primitiveEffect() }

// CPUIDEffect retains a serializing architectural query even when all results
// are overwritten. Leaf/Subleaf are the old low RAX/RCX bits; each result is an
// independent arbitrary BV32 in this occurrence's private scope. It claims no
// repeatability, feature consistency, latency, cache, TLB or host-state behavior.
type CPUIDEffect struct {
	PC                                             uint64
	Leaf, Subleaf                                  br.Term
	ResultsEAX, ResultsEBX, ResultsECX, ResultsEDX br.Term
}

func (CPUIDEffect) primitiveEffect() {}

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

// TransitionPredicates binds the three independent architectural entry predicates.
// SFXorOF means SF != OF, not either architectural flag separately.
type TransitionPredicates struct{ CF, ZF, SFXorOF br.Term }

// GuardedInstruction is the sole occurrence guard. Accesses and primitive effects
// inherit it by PC. Filtering this topological inventory gives the executed order.
type GuardedInstruction struct {
	Span
	Guard br.Term
}

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
// Instructions contains guarded fetch occurrences. Filtering their guards gives
// the executed trace. Boundary is unexecuted.
type TransitionBound struct {
	ImageDigest       [32]byte
	Rules             string
	Entry             uint64
	Interface         TransitionInterface
	Origin            br.Term
	ExcludedOrigins   []Span
	InitialRegisters  [16]br.Term
	InitialPredicates TransitionPredicates
	InitialMemory     []TransitionByte
	Words             []TransitionWord
	Registers         [16]TransitionValue
	Memory            []TransitionByte
	Preserved         Masks
	Flags             TransitionFlags
	Instructions      []GuardedInstruction
	// CutGuard is the derived reach expression, never inferred from graph closure.
	CutGuard         br.Term
	Accesses         []TransitionAccess
	PrimitiveEffects []PrimitiveEffect
	Boundary         CutBoundary
}

// TransitionCertificate owns a conditional entry-to-cut theorem. It cannot be
// converted to return, frame, value-call, source-startup or runtime reuse evidence.
// Its zero value carries no authority; projections cannot reconstruct it.
type TransitionCertificate struct{ checked *checkedTransition }
type checkedTransition struct {
	image  *Image
	bound  TransitionBound
	limits TransitionLimits
	work   int
	// Only private condition predicates supplement the bound's sole register
	// and byte-state snapshot. No builder or predecessor certificate is retained.
	flags [flagCount]br.Term
}

func cloneTransitionInterface(f TransitionInterface) TransitionInterface {
	f.Regions = append([]RelativeRegion(nil), f.Regions...)
	f.ImageRegions = append([]Span(nil), f.ImageRegions...)
	f.Words = append([]int64(nil), f.Words...)
	return f
}

// Bound returns owned mutable projections and immutable expression handles.
func (c TransitionCertificate) Bound() (TransitionBound, bool) {
	if c.checked == nil {
		return TransitionBound{}, false
	}
	return cloneTransitionBound(c.checked.bound), true
}

func cloneTransitionBound(b TransitionBound) TransitionBound {
	b.Interface = cloneTransitionInterface(b.Interface)
	b.ExcludedOrigins = append([]Span(nil), b.ExcludedOrigins...)
	b.InitialMemory = append([]TransitionByte(nil), b.InitialMemory...)
	b.Words = append([]TransitionWord(nil), b.Words...)
	b.Memory = append([]TransitionByte(nil), b.Memory...)
	b.Instructions = append([]GuardedInstruction(nil), b.Instructions...)
	b.Accesses = append([]TransitionAccess(nil), b.Accesses...)
	b.PrimitiveEffects = append([]PrimitiveEffect(nil), b.PrimitiveEffects...)
	b.Boundary.Bytes = append([]byte(nil), b.Boundary.Bytes...)
	return b
}
