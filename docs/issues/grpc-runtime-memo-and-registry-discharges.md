# grpc/protobuf runtime memos and the channelz registry

## Problem

The grpctransport benchmark enumeration (2026-08-17, 209 residual
culprits after every shipped discharge, classification on record in
the consumer's waiver rationale) left two classes no current channel
covers: 19 content-invariant lazy memos (protobuf impl's
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

The chartered structural get-or-compute discharge subsumes the memo
class (the audited memoization set's entries retire to it per the
spec's own retirement sentence); channelz wants a named audited entry
under the single-subject attestation (subject-own registry, the
mapping set's derivation verbatim). The 188 init-only-in-fact
identities from the same enumeration are vouch-shaped and need no
engine change.

Lands: with the structural get-or-compute discharge charter.
