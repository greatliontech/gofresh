# Consolidate the audit mechanisms' parallel spellings

Four related duplications, surfaced by the go1.27 audited-set review:

1. Three version-keyed audit mechanisms coexist: the toolchain-release
   map (closure/toolchainaudit.go), the module-variable rows
   (auditedSourceSet in dynamicstate.go), and the property-harness
   version gate. Their version domains differ (toolchain releases,
   module pins, harness releases) — recorded as the reason they did
   not merge — but the lookup-and-refuse shape is one mechanism
   written three times.
2. The audited sync/pool/reflect sets are spelled at two tiers:
   closure/maximal.go's symbol predicates and purity.go's
   auditedSynchronization/auditedPooling/auditedImmutableType. Both
   now key to the one release list; the set contents remain dual.
3. isStandardFallbackExempt hand-folds "testing" beside the
   source-only set — a third spelling of the harness admission and the
   remaining guard-free path in that family (deliberate: exemption of
   the fallback is not an admission; note when consolidating).
4. auditedLinknamesOnly's whole-field directive match and
   generatedProtoHeader's token-bound match are one "directive name as
   a whole token" mechanism written twice.

Lands: with the next audited-set change set that adds a row or
predicate to any of these surfaces.
