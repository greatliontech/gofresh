# Working Notes: Non-AST Leaf Environment, Guard & File-Input Queries (`v0.127.2`)

## Context & Root-Cause Diagnosis

Adversarial review of downstream `stipulator` Chunk 1 and fleet-wide cross-audit against `pew ab` surfaced a concrete domain-boundary coupling introduced when `cf3cb7c` (`v0.127.1`) folded three non-AST leaf queries onto `gofresh.Session`:

1. **`CheckFileInputEligibility` (`REQ-inputs-file-eligibility`)**:
   - Raw-byte file-input preflight inspects filesystem paths (`Lstat`, `EvalSymlinks`, regular file mode) and toolchain/cache roots (`GOROOT`, `GOMODCACHE`, `GOCACHE`, scratch, exclusions) via `internal/runtimeinput`. It never parses Go ASTs or types and produces no `Fingerprint`, `Observation`, or `Verdict`.
   - Requiring a `*Session` forced `stipulator` (`REQ-go-invocation-input-files`) to construct `NewSession`, gating non-witness executions and degraded runs on frontend `ToolchainSkew` (`ToolchainProvenanceError`) under `devel`/`local` or newer Go toolchains and spawning extra `go env -json` processes.
2. **`ResolveToolchainSelection` & `Session.ToolchainSelection`**:
   - Policy normalization (`stipulator` `REQ-check-policy-notices`, `REQ-go-owned-processes-runner`) takes one `go env -json` snapshot, pins `n.Env`, and resolves advisory `SelectionNotice` with zero additional `go env` spawns (`got.env == 1`) and without aborting `CapturePolicy` (`StoreGC`, `ExecutePolicy`) on frontend `ToolchainSkew`.
   - Pass-scoped `goEnv` sharing belongs on standalone `ResolveToolchainSelection(ctx, build, goEnv, prepare...)`, while `(*Session).ToolchainSelection` intentionally uses `s.newPassReader()` so live `GOENV` or `go.mod`/`go.work` edits after `NewSession` are never masked across passes (`REQ-guard-explicit-build`). Both validate `buildFlags` (`gotool.ValidateBuildFlags`) and enforce mid-call `ctx.Err()` cancellation attribution (`REQ-fresh-context`).
3. **`CaptureGuards` (`REQ-guard-explicit-build`, `REQ-guard-selective-capture`)**:
   - `pew ab` compares build and runtime `Guards` across two git worktrees/refs where source intentionally differs and no AST/closure `Session` applies, sharing a pass-scoped `go env -json` map (`goEnv`).

## Structural Design

- Keep `Session -> Snapshot -> RuntimeBinding/BuildBinding -> Unit / CheckingUnit` as the exclusive producer and checking protocol for `Fingerprint`, `Observation`, `TestVariantLedger`, and `Verdict` (zero Generation-1 producer types restored, and `BuildDescription` stays free of `GoEnv`).
- Export three clean leaf helpers in root `gofresh`:
  1. `FileInputRoots` (opaque wrapper around `runtimeinput.Roots`), `FileInputOptions`, and `CheckFileInputEligibility(ctx, treeRoot, pkgDir, file, opts)`, with `(*Session).CheckFileInputEligibility` delegating to the same `checkFileInputEligibility` kernel (uniform `refreshTraceFromEnv` and root/exclusion semantics).
  2. `ResolveToolchainSelection(ctx, build, goEnv, prepare...)` alongside `(*Session).ToolchainSelection(ctx)` sharing `resolveToolchainSelection` (`ValidateBuildFlags` + `ctx.Err()` cancellation attribution).
  3. `CaptureGuards(ctx, build, goEnv, runtimeEnv, kind, prepare...)` computing the exact `REQ-guard-explicit-build` (`gofresh/build-description@2`) + `REQ-guard-selective-capture` `Guards` matching `Session` + `BindRuntime`.

## Review Dispositions (Round 1)

1. **[Medium] [Introduced] `resolveToolchainSelection` omitted `gotool.ValidateBuildFlags`** — Fixed in `provenance.go`: `resolveToolchainSelection` now calls `gotool.ValidateBuildFlags(ctx, reader, buildFlags)` before `toolchain.ResolveToolchainSelection`, covered by `-overlay=overlay.json` test in `surface_test.go`.
2. **[Medium] [Introduced] `(*Session).ToolchainSelection` lacked mid-call `ctx.Err()` attribution + `initSnapshot` note drift** — Fixed in `provenance.go` (`defer` moved into `resolveToolchainSelection`, tested via mid-call cancellation on `cancelSess.ToolchainSelection`) and updated `docs/notes/leaf-non-ast-helpers.md` to record why `(*Session).ToolchainSelection` takes a fresh pass snapshot per `REQ-guard-explicit-build`.
3. **[Low] [Introduced] `CaptureGuards(nil runtimeEnv)` test used `CodeResult` instead of `Measurement`** — Fixed in `surface_test.go`: sets `GOGC=123` in `buildEnv`, asserts `CaptureGuards(..., nil, Measurement) == mFP.Guards` and `!= CaptureGuards(..., []string{}, Measurement)`, plus symlinked `build.Directory` parity and empty `map[string]string{}` `goEnv` refusals.
4. **[Low] [Introduced] `refreshTraceFromEnv` and doc comment on `CheckFileInputEligibility`** — Fixed in `runtimeinputs.go`: moved `refreshTraceFromEnv()` into `checkFileInputEligibility` and documented absolute `treeRoot`/`pkgDir`/clean-absolute `file` contract.
