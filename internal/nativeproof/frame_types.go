package nativeproof

// FrameRules identifies the conditional byte-region frame domain and its shared
// decoding/scalar dependencies. It supplies no source-value correspondence.
const FrameRules = "gofresh/native-frame@1;" + RuleModel

// ByteRegion is a half-open virtual-address extent of ordinary memory. Permissions
// bound accesses, not values. Overlapping regions name the same bytes and must
// agree on permissions and backing; distinct addresses have no hidden aliases
// under FrameConditions. Image regions must agree with actual PT_LOAD mappings;
// external regions must not overlap any image mapping page. No initial contents
// are implied, even for image-backed bytes or a nonwritable region.
type ByteRegion struct {
	Bytes              Span
	Readable, Writable bool
	Image              bool
}

// RegionPointer identifies an inclusive range of byte offsets from a region's
// start. One-past-end pointers are representable, but cannot authorize an access.
// Every offset in the range is possible. Region indices address Interface.Regions.
type RegionPointer struct {
	Region   int
	Min, Max uint64
}

// RegisterPointer supplies a conditional full-register entry pointer origin.
// RSP is supplied exclusively by FrameInterface.Stack.
type RegisterPointer struct {
	Register Register
	Pointer  RegionPointer
}

// MemoryPointer supplies the conditional initial little-endian pointer word at
// Address. Its eight bytes must be readable external memory, disjoint from other
// initial pointer words and the protected return slot. Other bytes are arbitrary.
type MemoryPointer struct {
	Address uint64
	Pointer RegionPointer
}

// FrameConditions retains Conditions' instruction, entry-state, return and
// isolation premises. MemoryMapping requires declared ordinary RAM extents and
// permissions to remain mapped and stable for the invocation, with image data
// loaded at its static ELF addresses. NoHiddenAliases means distinct virtual
// addresses denote distinct bytes, with no extra mappings, devices or external
// writers. UnalignedAccess excludes alignment-check exceptions for ordinary
// scalar accesses (the admitted x86 model permits unaligned accesses). These are
// conditional premises, never observed Go isolation or suspension guarantees.
type FrameConditions struct {
	Conditions
	MemoryMapping, NoHiddenAliases, UnalignedAccess bool
}

// FrameInterface is a conditional entry and return boundary. Stack must be an
// exact pointer into an external readable region; its initial eight-byte return
// slot is protected against all writes. RET must use that original slot, and
// returns with RSP advanced by eight. Protected adds byte extents that must never
// be written, regardless of region write permissions. Preserved register bits
// must never be written, as in Interface; restoration of a written context
// register is conservatively unsupported. Unspecified registers and memory are
// arbitrary. There is no requested output value or "writes nowhere" summary.
type FrameInterface struct {
	Regions        []ByteRegion
	Pointers       []RegisterPointer
	MemoryPointers []MemoryPointer
	Stack          RegionPointer
	Protected      []Span
	Preserved      Masks
	Conditions     FrameConditions
}

// FrameLimits bounds work before growth. RegionBytes counts declared bytes
// (overlaps count twice). StateBytes bounds the dense abstract states, including
// pointer provenance per represented byte. States bounds graph states, not paths.
// Work charges graph checkpoints, scans, state copies/joins and byte transfers.
// Zero fields select defaults; every field also has a fixed supported ceiling.
type FrameLimits struct {
	Instructions, States, Regions, RegionBytes, StateBytes, Work int
}

// DefaultFrameLimits is a finite analysis budget, not a semantic premise.
func DefaultFrameLimits() FrameLimits {
	return FrameLimits{Instructions: 1024, States: 1024, Regions: 64, RegionBytes: 65536, StateBytes: 32 << 20, Work: 2_000_000}
}

// FrameProposal is only an untrusted image/entry and complete instruction/edge
// inventory. CheckFrame reconstructs it independently. No proposed state, effect
// classification, pointer origin or expected output is accepted as a conclusion.
type FrameProposal struct {
	ImageDigest [32]byte
	Entry       uint64
	Nodes       []Node
}

// AccessKind distinguishes ordinary loads/stores from RET's implicit slot read.
type AccessKind uint8

const (
	FrameRead AccessKind = iota + 1
	FrameWrite
	FrameReturnRead
)

// FrameAccess bounds all addresses touched by one decoded access, including its
// full Width. A ranged pointer may touch only part of Bytes in one execution;
// the whole interval is a conservative footprint over all admitted states/paths.
type FrameAccess struct {
	PC    uint64
	Kind  AccessKind
	Bytes Span
	Width int
}

// FrameBound is a copied, non-authorizing projection of checked evidence.
// Instructions cover instruction fetch; Accesses covers every ordinary/implicit
// data access. Memory outside FrameWrite footprints and all Preserved/Protected
// state is untouched. Writable contents and scalar return values are not claimed
// deterministic. ReturnedPointers are optional derived all-return facts; absence
// means unknown, never a harmless pointer. Return continuation behavior is outside
// the scope. Input provenance, memory/isolation and actual-use premises remain.
type FrameBound struct {
	ImageDigest      [32]byte
	Rules            string
	Entry            uint64
	Interface        FrameInterface
	Instructions     []Span
	Accesses         []FrameAccess
	ReturnedPointers []RegisterPointer
	ReturnedRSP      uint64
}

// FrameCertificate owns a conditional frame proof. Its zero value has no
// authority. No serialization, unchecked constructor or public discharge exists.
type FrameCertificate struct{ checked *checkedFrame }
type checkedFrame struct {
	image *Image
	bound FrameBound
}

func cloneFrameInterface(f FrameInterface) FrameInterface {
	f.Regions = append([]ByteRegion(nil), f.Regions...)
	f.Pointers = append([]RegisterPointer(nil), f.Pointers...)
	f.MemoryPointers = append([]MemoryPointer(nil), f.MemoryPointers...)
	f.Protected = append([]Span(nil), f.Protected...)
	return f
}

// Bound returns owned copies of every mutable projection.
func (c FrameCertificate) Bound() (FrameBound, bool) {
	if c.checked == nil {
		return FrameBound{}, false
	}
	b := c.checked.bound
	b.Interface = cloneFrameInterface(b.Interface)
	b.Instructions = append([]Span(nil), b.Instructions...)
	b.Accesses = append([]FrameAccess(nil), b.Accesses...)
	b.ReturnedPointers = append([]RegisterPointer(nil), b.ReturnedPointers...)
	return b, true
}
