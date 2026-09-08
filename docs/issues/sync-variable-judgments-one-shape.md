# The sync variable judgments are two shapes and the audited-set admissions five one-liners

Two judgments decide whether a package-level `sync` variable's calls
mark nothing: the proven pool (`provenSharedPools`) and the data memo
(`dataMemoVars`). Both walk an unexported package-level variable's
uses and admit a receiver call set typed by the declaration, but with
different completeness strategies — the pool's affirmative "any other
appearance evicts the proof", the memo's "an unadmitted call opens it,
every non-call use is the uses walk's own mark" — and two receiver
ladders (`poolCarrierIdent` unparenthesizes and reaches array and
slice elements; the memo arm takes a bare identifier). The memo's
soundness is therefore non-local: it rests on the uses walk marking
every non-call use, pinned only end to end.

Beside them, the effect tiers' audited-set admissions are five
one-line predicates (`auditedSyncSymbol`, `auditedPoolSymbol`,
`auditedMemoSymbol`, `auditedRuntimeTypeSymbol`, and the
`classBPureStandard` chain in `closure/effects.go`) with a
hand-maintained mirror in the reference scan that grows a term per
set.

The collapse: one sync-variable use judgment parameterized by the
admitted call set and the declaration type, with one receiver ladder;
one audited-set admission table (package, receiver, method) the effect
tiers and the reference scan both read. Invariants preserved: the
pool's attestation-gated leg, the memo's unconditional leg, the
fail-closed default on every unlisted use.

Lands: with the next audited sync set, or with
docs/issues/flag-surface-one-table.md's collapse (the same one-table
shape).
