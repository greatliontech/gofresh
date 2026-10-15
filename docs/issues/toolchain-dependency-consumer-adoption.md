# Adopt native dependency evidence

Lands: docs/plans/tooling-redesign.md 5.2d.

Secondary constituent: 5.4 owns Gomutant's producing/checking adoption.
Stipulator's completed 5.2b source-certificate work is a retained control,
not an unimplemented part of this producer migration.

Native fingerprints carry optional `toolchainContent` and `admissionPolicy`
keys after `buildConfig`. Their omission preserves historical encoding, not
applicability: an old result without selected-content evidence cannot become
valid by inserting today's identity. Observation proof compatibility is
`gofresh/observation-rta@44`, and proof integrity and prepared outcome-subject
identities bind the producing content and policy. Consumers retain the native
form; mirrors and conversion code cannot omit these constituents.

Runtime-input manifests now use generation 3, retaining truthful observed PWD
values as environment dependencies. Generation 2 could omit those reads and
cannot establish that the omitted dependency was irrelevant. At the explicit
consumer bump, retain old native records as history but regenerate their runtime
evidence; do not rewrite the manifest version or insert a current directory.
Exercise same-build/different-runtime-directory checks and restart, including
identity-only profiles and any adopted or merged observations. A record without
a runtime-input manifest retains its independently governed evidence rules.
The outer native-record keys are unchanged by this manifest correction; decide
consumer format changes from the actual admission contract, not a blanket bump.

At each adoption:

- Preserve old bytes as history. Missing execution evidence requires
  re-execution where the claim requires it; missing static-certificate
  dependencies require re-derivation or an unavailable answer, not a new
  execution obligation. Do not rewrite an older proof or outcome binding to
  look current.
- Update the consumer's own format/version boundary where an older reader
  would otherwise encounter unknown native keys. Gomutant's embedded native
  member and key-set guard require its document-version decision at the bump;
  Stipulator's native aliases still need record-name and store-admission
  checks.
- Stipulator's source-derived resolution certificates now retain their complete
  selected-view and derivation dependencies. Preserve that separate static
  claim through `resolutioncache.SourceTiers`, admission and current-source
  comparison; a witness alias is not its certificate. Same-version selected
  content and missing historical dependencies remain independently judged,
  without inventing a witness execution obligation.
- Account for the public `closure.Closure` fields and `SetAnalysisScope`'s
  returned enriched scope where used. No current call site in these remaining
  consumers uses either API. An ordinary call may discard the new return;
  a caller separately consuming the scope needs the constructed hasher's
  dependencies, because an incomplete caller scope does not arm a memo.
- Exercise ordinary and observed reuse, explicit purity, applicability
  extension, producer closing and restart. A same-version GOROOT edit must not
  reuse an old result, and missing historical evidence must remain missing.
- Preserve the shared contained-query boundary when adopting its Linux
  collected execution. It holds the exited leader waitable through pipe
  draining and cleanup, before reaping. Prepared commands run directly by a
  consumer still require that consumer's own cleanup; the library's collected
  form does not silently change those lifetimes or other platforms' limits.

A linked library version alone does not establish end-to-end producing
adoption. Account for the complete descriptions, actual retained artifact,
finalization, native checking and publication path together at each consumer;
do not mark the vertical complete while a degraded legacy adapter remains.
