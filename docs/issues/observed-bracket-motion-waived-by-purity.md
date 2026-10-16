# Observed producing-span movement is waived by purity

Lands: docs/plans/tooling-redesign.md 5.1w.4.

## Reachable false-valid path

A retained reader process consumes `before`. Before native finalization ingests
its observation, the caller changes the input to `after`. The bracket detects
movement, but `runtimeinput` records it only among diagnostic unverifiable
reasons while retaining the post-write digest. Native checking then allows
explicit purity to waive that inferred-unverifiable marker. Closing succeeds
and publishes Valid; JSON round-trip and historical checking also return Valid.

The reproduction against v0.118.0 ran twice. The consumer regression is
Stipulator's `TestGoDeriveRuntimeDriftAndUnverifiableSkipRecords`: both reader
records incorrectly remain cacheable. Independent stable-unhashable purity and
supported-environment controls passed. Reproduction artifacts are retained at
`/tmp/opencode/gofresh-native-motion-repro`, with the actual historical record
at `/tmp/opencode/native-motion-v3-fingerprint.json`; these machine-local files
supplement, not replace, the regression that must land in the repository.

## Diagnosis and correction

Bracket revalidation conflates unknown comparability with known movement;
runtime-input state represents both as inferred unverifiability. The violated
invariant is producing-value binding: a post-run digest cannot stand for the
different value the process consumed. Purity may discharge an inferred blind
spot, never a demonstrated guard mismatch.

Retain typed known movement independently of diagnostics and unknown siblings,
preserve it through all evidence transformations and later restoration, and
refuse producing close after retaining the non-authorizing process account.
Respect cancellation/abort precedence and expose no finalized subject evidence.

The user selected v4-only runtime-manifest reuse: v1-v3 observations cannot
establish the new distinction and require remeasurement. Historical enclosing
fingerprints remain readable and byte-preserving. The canonical obligations
live in [runtime inputs](../specs/runtime-inputs.md),
[purity](../specs/purity.md) and [evidence](../specs/evidence.md).
