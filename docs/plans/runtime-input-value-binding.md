# Runtime-input value binding

Spec: docs/specs/runtime-inputs.md

- [x] 1. Bracket primitive: `CaptureBracket`/context variant with per-kind hashing, root exclusions, absent/retyped-root semantics, and capture/revalidate self-agreement plus move-detection property tests.
- [ ] 2. Bind observation construction: `WithBracket` required alongside `WithCompletedProcess` (clean break), resolution-based coverage per identity (reusing the existing per-identity EvalSymlinks), sealing dispositions for moved-bracket, uncovered-identity, and symlink-escape, with the run-to-ingest window and symlink-target-mutation regression tests.
- [ ] 3. Propagate binding reasons through Absolute/Merge/Dirty tests; extend FuzzMergeAlgebra with bracket-carrying observations and merge refusal of completed states lacking bracket provenance; add INV enforcement pointers; package doc rationale.

(Consumer adoption lands in stipulator's legacy-verify rewire, not here. Prerequisite there: package-directory resolution moves pre-spawn. Migration note: reads resolving outside declared roots become permanently per-identity unverifiable — the consumer's root policy owns the recommended default. Blast radius: only stipulator's observe.go/freshness.go/stream fuzzer construct completed observations; pew uses IncompleteEnv and is unaffected.)
