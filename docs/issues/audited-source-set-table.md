# Collapse auditedMappingOut/auditedMemoOut onto one audited-source-set table

After the mapping set's attestation retirement, `auditedMappingOut`
and `auditedMemoOut` (dynamicstate.go) are the same shape modulo the
audited-version switch: pinned package, exact variable key, audited
versions. One table-driven `auditedSourceSet` keyed by
`(pkgPath, key, audited versions)` collapses the duplication and makes
the next audited entry a row instead of a function. Surfaced by the
mapping-set change set's reviewer; deferred so the reviewed delta is
not churned by a refactor its successor touches anyway.

Lands: with the next audited VARIABLE-set change set — one adding or
editing a (pkgPath, variable key, audited versions) entry. (The
2026-08-22 audited atomic transparency was an audited-discharge
change set but a TYPE audit in the carrier walk, touching neither
function; the frameAccounting discharge landed that way, so the
original parenthetical's premise dissolved. The audited
TOOLCHAIN-surface checks — the atomic path+name test, the linkname
targets — are candidate rows for the same table when it lands.)
