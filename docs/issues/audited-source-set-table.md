# Collapse auditedMappingOut/auditedMemoOut onto one audited-source-set table

After the mapping set's attestation retirement, `auditedMappingOut`
and `auditedMemoOut` (dynamicstate.go) are the same shape modulo the
audited-version switch: pinned package, exact variable key, audited
versions. One table-driven `auditedSourceSet` keyed by
`(pkgPath, key, audited versions)` collapses the duplication and makes
the next audited entry a row instead of a function. Surfaced by the
mapping-set change set's reviewer; deferred so the reviewed delta is
not churned by a refactor its successor touches anyway.

Lands: with the next audited-discharge change set (the
frameAccounting/framePools layers touch exactly these functions).
