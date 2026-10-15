# grpc/protobuf runtime memos and the channelz registry

## Problem

The grpctransport benchmark enumeration (2026-08-17, 209 residual
culprits after the then-shipped discharges, classification on record in
the consumer's waiver rationale) left two classes the reported channels did not
cover: 19 content-invariant lazy memos (protobuf impl's
aberrant/legacy caches, needsInitCheckMap, lazyUnmarshalOptions, the
descopts lazy fills, hpack's lazyRootHuffmanNode, transport's
ioBufferPoolMap — get-or-compute fills from immutable inputs, the
structMap shape at scale) and one genuinely subject-dependent
registry (grpc internal channelz.db, written unconditionally per
registration by bench-executed code — the subject-own-registry class,
the mapping set's shape without its source-audited variable list).
The consumer capped the class with an enumeration-backed per-arm
purity waiver that retires when this lands.

## Shape

The structural get-or-compute proof is a candidate for the memo
class (the audited memoization set's entries retire only when the proof
actually covers them); channelz needs a separately justified audited entry
under the single-subject attestation (subject-own registry — the
attestation-gated discipline the mapping set carried before its
attestation-free deepening; channelz is genuinely subject-dependent,
so it needs the attestation-gated shape, never the mapping set's
current attestation-free one). The 188 init-only-in-fact
identities from the same enumeration are vouch-shaped and need no
engine change.

The nineteen reported memos hold carriers — message types, options and
Huffman nodes — so the carrier-free data memo does not establish their
immutability. Coordinate with `immutable-after-construction-objects.md`,
including external aliases and writers. Keep channelz's subject-dependent
authority separate; neither the old enumeration nor a successful benchmark
licenses a general registry discharge. Re-census the exact dependency versions
before retiring the consumer's waiver.

Lands: docs/plans/tooling-redesign.md 7.8.
