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
// x/arch/x86asm decoder, and this package's mapping, graph and abstract transfer
// rules. The proposer supplies only an untrusted instruction/edge inventory. The
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
// NewImage binds a copied byte image, not a filesystem or execution observation.
// Its consumer must supply the existing inspected-artifact ownership and span
// binding before composing this claim. Even that composition supplies neither
// source-instance/startup coverage nor runtime-reuse authority.
package nativeproof
