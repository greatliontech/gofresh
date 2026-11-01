# Phase C & D Blueprint: Correctness Audit, Exhaustive Case/Edge Coverage, and Optimization

## 1. Execution Ordering Principle

1. **Finish Phase A (Tracing) and Phase B (Surface Eviction & Legacy Layer Collapse) first** so no audit or optimization effort is spent on evicted subpackages or legacy `session.go` shims.
2. **Fold the Deep Correctness Audit directly into Phase C (Per-Subsystem Correctness Audit + Exhaustive Case/Edge/Fuzz Suite)**:
   - As we visit each core subsystem, we perform an adversarial line-by-line correctness audit of its invariants and boundary conditions, fix any discovered soundness/completeness/fail-open defects, and immediately lock the subsystem down with direct unit, property, fuzz, and trace-witness tests.
3. **Run Phase D (Performance & Optimization Audit & Implementation) last**:
   - Once Phase A, B, and C are complete and green, every optimization is guided by `internal/trace` hit/miss counters and `mlock quiet` benchmarks, and guarded against semantic regression by the full Phase C exhaustive test and trace-witness suite.

## 2. Phase C Pillars (Correctness Audit + Exhaustive Case & Edge Coverage)

### 2.1 Trace-Backed Causal-Witness & Non-Interference Harness
- **Zero-Unintended-Degradation Gate**:
  - Attach `trace.WithSink` (`*trace.Recorder`) in `internal/testenv` and `Session` test helpers to assert that no unexpected `toolchain` degradation (`package_verdict_error`, `package_io_error`, or non-empty `degradation` notice) or `view` pass-divergence (`two_pass_diff`) occurs unless explicitly expected by the test.
- **Exact Causal-Witness Pinning**:
  - On refusal, impurity, and staleness tests across `toolchain`, `closure`, `view`, and `session`, assert on the structured trace event's exact causal witness (call-graph edge, `dynstate` carrier symbol, rejected stdlib delegate/file, diverging `subjectFacts` field, or moved runtime input) so tests cannot pass for the wrong reason.
- **Universal Trace Non-Interference Property Test**:
  - Property/fuzz test executing `Session`, `Snapshot`, `Unit`, and `Check` twice on identical inputs—once with tracing disabled (`activeCount == 0` fast path) and once with `GOFRESH_TRACE=all` and `GOFRESH_TRACE` / `GOFRESH_TRACE_FILE` present in the input environment—verifying byte-for-byte identical `Fingerprint`, `Closure`, `Guards`, `RuntimeInputs`, and `Verdict` outputs.

### 2.2 Direct Exhaustive Unit, Property & Fuzz Coverage of Deep Internal Engines
1. **`internal/dynstate` (`internal/dynstate/dynstate_test.go`)**:
   - Correctness audit of `func_summary.go`, `facts.go`, `fixpoint.go`, `typecarrier.go`, and `directives.go`.
   - Direct in-package property and fuzz tests over `solveLeastFixedPoint`, `solveReachFixedPoint`, `DeferralResolution`, and `EnvAuditResolution` across arbitrary directed graphs with cycles, mutual recursion, and multi-hop field deferral/poisoning (`FieldDeferAt`, `FieldPoisonAt`, `RetDeferAt`, `RetPoisonAt`).
   - Direct unit and fuzz tests over `directives.go` (`//gofresh:vouch` parser edge cases) and `typecarrier.go` (recursive structs, interfaces, generic type parameters, composite carriers).
2. **`internal/testvariant` (`internal/testvariant/testvariant_test.go` + Closure Soundness Bridge)**:
   - Correctness audit of `testvariant.go` (`DiffTestVariantLedgers`, `InertForSubject`, declaration hashing, and reference extraction).
   - Exhaustive AST edge matrix: generic value/pointer receiver normalization (`(*T[A, B])` vs `T[A, B]`), grouped `var`/`const`/`type` ordinal shifts, `iota` with implicit expression repetition across blank `_` governors, package-clause renames, embedded files, and `//go:` directives.
   - Soundness bridge property/fuzz test: for any AST mutation between `before` and `after` where `InertForSubject(before, after, subj) == true`, verify that the compiled `Closure` digest and `MaximalFacts` of `subj` remain 100% unchanged.
3. **`internal/closure` C Preprocessor & Cgo Scanner (`internal/closure/cpreprocessor_test.go`)**:
   - Correctness audit of `toolchain_cpreprocessor.go` and `cgo_includes.go`.
   - Dedicated `FuzzCPreprocessor` and deterministic edge matrix covering `\` line continuations, multiline `/* ... */` comment splicing, `#if`/`#elif` integer constant expression evaluation (including `/ 0`, `% 0`, unsigned/signed shifts, ternary `?:`, short-circuit `&&`/`||`, `defined`), function-like macro expansion with `#` stringification, `##` token pasting, variadic `__VA_ARGS__`, self-referential macro termination, `#include` cycle/depth/path-traversal refusal, and `runtime.` / `runtime·` symbol extraction.

### 2.3 Multi-Feature Composition, Two-Pass / Bracket TOCTOU Seams & Workspace/Symlink Edges
1. **Multi-Feature Call-Graph & Compartment Composition Matrix**:
   - Combinatorial cases composing generics + RTA interface dispatch + bound method values/closures + stdlib higher-order delegates (`sync.OnceFunc`, `slices.SortFunc`, `maps`, `cmp`) + `//gofresh:vouch` + `//go:linkname` across 3-way compartments (`p` base, `p` in-package test, `p_test` external test), pinned with `internal/trace` causal witnesses.
2. **Deterministic Two-Pass (`newViewFor`) & Bracket TOCTOU Fault-Injection Matrix**:
   - Perturb every individual field of `subjectFacts` / `observationFacts` between pass 1 and pass 2 of `newViewFor`, asserting `two_pass_diff` trace events name the exact diverging field and `newViewFor` refuses with `ErrViewChanged`.
   - Verify metadata-only (`st_ctime`/`st_mtime` bump with identical bytes) vs. 1-byte content mutation mid-pass in `verifyReadPackageDigest` and `newViewFor`.
   - Test bracket and `ScratchNamespace` boundary escapes (symlink inside scratch namespace targeting a tracked file, prefix-collision directory names `scratch` vs `scratch2`, hardlinks, and filenames containing attribution framing bytes `\r`, `\n`, `"`, `; `).
3. **Workspace (`go.work`), Symlinked Coordinate (`PWD`/`TMPDIR`/`GOROOT`) & Cache Resilience Suite**:
   - Multi-module `go.work` cross-module closures and runtime file reads across sibling workspace modules.
   - Repository checked out inside `$TMPDIR` with symlinked `$PWD`, verifying `moduleInterior` precedence over `ephemeralRoot`.
   - Corrupted, truncated, bit-flipped, and concurrent writes to persisted cache files in `XDG_CACHE_HOME`.

## 3. Phase D: Performance & Optimization Audit & Implementation

- Audit hot paths across `internal/closure` (toolchain surface verification, AST/SSA/RTA traversal, `freshpath` / `observability`), `internal/dynstate` (summary extraction and fixed-point iteration), `internal/runtimeinput` (bracket walking and manifest hashing), and root `Session`/`Snapshot` two-pass orchestration.
- Measure baseline and post-change performance under `mlock quiet` benchmarks (`benchmarks/`), ensuring every optimization preserves all Phase C correctness, trace-witness, and non-interference invariants.
