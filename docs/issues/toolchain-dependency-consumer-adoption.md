# Adopt native dependency evidence

Lands: docs/plans/tooling-redesign.md 5.1u for Pew's runtime-input generation,
5.2 for Stipulator and 5.4 for Gomutant.

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
- Stipulator's source-derived resolution certificates have a separate
  projection and comparison: `resolutioncache.SourceTiers`, `Admits`, and
  `backends/golang.closureMoved`. Adopt the dependencies of that static claim
  at all three sites; updating the witness alias alone leaves this path
  unchanged. Test same-version selected-content changes and historical
  certificates with missing dependencies independently of witness execution.
- Account for the public `closure.Closure` fields and `SetAnalysisScope`'s
  returned enriched scope where used. No current call site in these remaining
  consumers uses either API. An ordinary call may discard the new return;
  a caller separately consuming the scope needs the constructed hasher's
  dependencies, because an incomplete caller scope does not arm a memo.
- Exercise ordinary and observed reuse, explicit purity, applicability
  extension, producer closing and restart. A same-version GOROOT edit must not
  reuse an old result, and missing historical evidence must remain missing.

The remaining consumer pins stay unchanged until these scoped adoptions. Their
current binaries do not acquire new native-field support merely because the
library has a newer release.
