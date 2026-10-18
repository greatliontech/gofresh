// Package nativeproof checks conditional value, effect, input and callback-transfer
// bounds in an immutable ELF image. It is an internal proof prerequisite, not a
// source-equivalence, whole-program, execution, termination, or freshness API.
//
// The caller supplies the invocation interface and machine conditions explicitly;
// no Go ABI table, symbol name, symbol size, compiler label, or hash establishes
// them. Under those conditions, Check's acyclic leaf graph has no data memory
// operations or calls except the specified near-return slot read. Branch
// decisions and declared result bits depend only on declared input bits and
// instruction constants; selected preserved bits are never written. Undeclared
// scratch bits and incoming arithmetic flags are arbitrary. Instruction fetch,
// RET's stack read and RSP increment, and the excluded surrounding execution are
// expressly part of the conditional model.
//
// The trusted mechanism comprises debug/elf's structural reader, the pinned
// x/arch/x86asm decoder, and this package's operand interpretation, mapping, graph
// and abstract transfer rules. Shared operand interpretation sign-extends disp32
// for 64-bit addressing while retaining full-width absolute moffs addresses;
// domain-specific encoding and form checks still govern admission.
// Structural decoding recognizes operand-free VEX.128/256.0F.WIG 77 directly
// from its prefix and opcode, retaining exactly the VZEROUPPER/VZEROALL bytes
// without borrowing a following instruction as ModRM. This includes both VEX
// prefix lengths, requires reserved vvvv=1111 and pp=00, and grants no VEX
// execution semantics. Other VEX/EVEX entries in the pinned decoder's three
// opcode-map tables require ModRM; structural decoding checks its presence
// before the decoder selects an operand form. The decoder checks subsequent
// SIB, displacement, immediate and is4-selector availability itself.
// Successful bare VEX/EVEX decoding retains 64-bit mode/address context and
// left-aligned opcode/ModRM/SIB bits under x86asm's convention; DataSize remains
// its scalar size attribute, not vector width. Non-SIB mod=00,r/m=101 memory
// operands retain RIP and signed disp32 with PC-relative length/offset metadata;
// SIB's no-base form remains distinct. Structural admission rejects explicit
// invalid-prefix markers, not ignored prefixes or valid unsupported operations
// (including UD2). These repairs confer no vector execution authority.
// The proposer supplies only an untrusted instruction/edge inventory. The
// checker independently decodes reachable image bytes and computes transfers;
// it never uses a proposed semantic summary. Known-bit/definedness propagation
// is conservative, with no path-value exclusion or functional source relation.
// All conditional successors are checked, cycles and unsupported operations
// refuse, and no size or exploration budget can terminate a successful proof.
// DeriveRelation additionally interprets the checked graph as immutable scalar
// expressions, retaining exact register projections and path-conditioned merges.
// A separate equality checker must relate those expressions to selected source;
// neither input dependence nor symbolic evaluation alone establishes that relation.
// A zero-result interface retains the complete effect and return obligations.
//
// CheckDescriptor binds a readonly loaded entry word to a checked same-image
// target. CheckCall verifies a local decoded transfer through that target,
// including descriptor and declared stack-argument reads, the protected eight-byte
// CALL write, argument/context identity and the return transition. Its incoming
// descriptor provenance, loaded-memory integrity and invocation/frame conditions
// remain explicit premises. It does not establish which registration row selected
// the descriptor, or lift isolated invocation to ordinary Go suspension/resumption.
// CallbackRules identifies this composition separately from the leaf RuleModel.
//
// CheckFrame derives byte-region read/write footprints and context preservation
// through a bounded acyclic graph. Its memory permissions, entry pointer ranges,
// lifetimes, return slot and absence of hidden aliases are explicit conditions;
// image overlap and load permissions are independently checked. Stores invalidate
// overlapping pointer-byte facts, and only checked full-word spills/reloads
// preserve pointer provenance. Unknown loaded values cannot authorize addressing.
// The frame does not establish memory-value or scalar-output determinism, source
// correspondence, or whole-harness noninterference. Calls and external primitives
// remain unsupported in this domain. FrameRules identifies these distinct rules;
// ordinary Go isolation and suspension/resumption lifting remain open obligations.
//
// CheckValueCall adds a distinct conditional value/frame scope: explicit entry
// constants and checked immutable image bytes, a bounded state-sensitive graph,
// and one actual direct CALL through every callee return. The enabled-SSE2 model
// interprets exact scalar/vector forms; decoded predicates alone exclude paths.
// Its output is the derived memory result and complete access/frame bound at the
// immediate decoded continuation, not a scalar-register or enclosing-caller
// result. Unknown bits/bytes remain arbitrary, undefined flags remain unsupported
// when consumed, and CPU selectors or loops are never removed by ABI/CPU labels.
// ValueCallRules and ValueCallMachine retain this scope separately: neither the
// old leaf Certificate nor FrameCertificate can express its initial-value facts.
//
// CheckTransition establishes a distinct ELF-entry-to-unexecuted-cut relation.
// One fresh stack origin is universally quantified over explicit bounds,
// congruence and external/image-page disjointness; joint nonemptiness is checked
// before deriving state. Relative address envelopes, memory permissions and
// arbitrary initial byte/word contents are separate. Exact scalar expressions
// share the value calculus, while origin arithmetic and alignment justify their
// pointer provenance under the retained conditions. Full ordered pointer lanes
// survive spills and reloads; numeric coincidence cannot create an origin.
// The transition grammar admits full-width MOV, canonical MOV r32,imm32,
// base/displacement and RIP-relative LEA, constant SUB, justified alignment AND
// and relative JMP/fallthrough. Narrow register writes clear pointer provenance. Graph
// occupancy and acyclic closure establish that every path reaches the decoded
// cut. Its instruction is not executed or relabeled RET. Arithmetic flag values
// may be unprojected, never invented or mistaken for preservation. No normal
// return, source storage, process-argument meaning, completed bootstrap or public
// runtime authority follows from this conditional state relation.
//
// Root image footprints select absolute bytes in the owned PT_LOAD mappings;
// permissions and backing-alias checks share the frame domain's mapping policy.
// Their initial values are fresh arbitrary scalars, including readonly and BSS
// bytes. No loader-zeroing or file-content premise is introduced. Stack and image
// provenance have separate coordinates in one current byte state. Checked RIP
// address formation can introduce image provenance; matching scalar bits cannot.
// Ordered lanes preserve either pointer kind across mixed-memory spills and
// reloads. Representable pointers alone grant no access, and pointer-kind tags do
// not prove numerical inequality outside the declared disjoint footprints.
//
// CheckTransitionContinuation consumes only an immutable predecessor and a full
// root-to-new-cut proposal. It rechecks the complete graph and predecessor prefix,
// inherits the same symbolic inputs and derived state, and executes only the
// suffix. Normalized root limits and cumulative work also govern inherited terms,
// copies and the combined graph; a new segment cannot reset those bounds. Mapping
// and interference conditions remain premises over the longer scope, rather than
// actual stability facts inferred from the predecessor. No replacement image,
// interface, heap, expected result or per-segment limits can be supplied.
//
// NewImage binds a copied byte image, not a filesystem or execution observation.
// Its consumer must supply the existing inspected-artifact ownership and span
// binding before composing this claim. Even that composition supplies neither
// source-instance/startup coverage nor runtime-reuse authority.
package nativeproof
