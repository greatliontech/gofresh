# Working Notes: Fleet Evaluation, Incrementality & Architecture

## 1. Current Fleet Baseline (2026-11-09)

All 5 owned repositories are clean on `main`, green on GitHub Actions (`Next` + `CI` + `Release`), and installed locally against `gofresh v0.122.2`:

| Repository | Tag / Revision | Local Binary |
| :--- | :--- | :--- |
| `go-x-tools` | `5215c18e3` (`main`) | — |
| `gofresh` | `v0.122.2` (`2e2ee4ef659f4ff4b620ec9e792c278d398e7503`) | — |
| `pew` | `v0.10.3` (`3f543e8f85990e7f52c00707347c5d17f3dfd706`) | `/home/nikolas/.local/bin/pew` |
| `stipulator` | `v0.76.1` (`e4d5c3688dc3c1d5a0af44556744868ab6eab9be`) | `/home/nikolas/.local/bin/stipulator` |
| `gomutant` | `v0.67.2` (`1d2b1375d8ea80fb47b4b3bd15596d86ef17e636`) | `/home/nikolas/.local/bin/gomutant` & `/home/nikolas/go/bin/gomutant` |

### Recent Root-Cause Fixes Landed
1. **`go-x-tools` (`5215c18e3`)**: Eagerly unpack `*types.Named` (`t.Underlying()`) and `*types.Alias` (`types.Unalias(a)`) in `go/packages` immediately after `gcimporter.IImportShallow` finishes for a package, before closing `lp.done` and releasing dependent package typecheckers. Eliminates concurrent lazy `resolve()` races across shared imported types.
2. **`gofresh v0.122.2` (`2e2ee4e`)**:
   - Added nil-safe `underlyingType(t types.Type)` across `internal/dynstate` (`refconfine.go`, `discharges_audited.go`, `discharges_proto.go`, `func_summary.go`) and `internal/closure` (`propertyharness.go`) so `info.TypeOf(...)` returning `nil` (such as on constant-folded `unsafe.{Sizeof,Alignof,Offsetof}` calls where `go/types` omits `call.Fun` from `info.Types`) never panics.
   - Added `lookupBuiltin(info, fun)` in `internal/dynstate/refconfine.go` so package-qualified `unsafe.{Sizeof,Alignof,Offsetof}` calls are recognized alongside `len` and `cap` in `VerifyReadOnlyRefConfinement` and `callCallErasesSeedStruct`, while pointer-aliasing `unsafe` builtins (`unsafe.SliceData`, `unsafe.StringData`, `unsafe.Slice`, `unsafe.String`, `unsafe.Add`) remain rejected on protected references.
3. **`gomutant v0.67.2` (`1d2b137`)**:
   - Fixed cross-OS `GOOS=windows go vet -tags integration ./...` in `internal/engine/run.go`.
   - Fixed map-iteration order sensitivity in `TestMergeWholeFindingsPrunesAbsentSymbols` (`edits_test.go`).
   - Updated `TestOracleObservationBindsTheDeliveredMemoryEnvironment` (`internal/engine/outcome_test.go`) to verify the delivered `TMPDIR` on `deliveredEnv` while testing `GOMEMLIMIT` observation binding without conflicting with ambient `TMPDIR` ingest preservation.

---

## 2. Protocol: End-to-End Speed, Efficiency, Accuracy & Incremental Findings Evaluation

Target repositories (ordered smallest-to-largest): **`pew` → `stipulator` → `gomutant` → `gofresh`**.

### Stage 1: `stipulator` Speed, Cache Efficiency & Zero-Edit Incrementality
1. **Pass 1 (Cold / Stale Cache Refresh)**:
   - Run `stipulator check` and `stipulator verify --no-test` (under `unset ANTIGRAVITY_SOURCE_METADATA && ~/.local/bin/mlock run`).
   - Record per-phase wall-clock time (`compile`, `discovery`, `execution`, `verification`, `coverage`), resident/peak RSS, resolution-cache hit rate (`served from records` vs `resolved typed`), and witness-cache behavior (`served fresh`, `executed`, `uncacheable`, and any `WITNESS_CACHE_REFUSAL_*`).
2. **Pass 2 (Warm Zero-Edit Re-Run — Must-Have Incremental Contract)**:
   - Immediately re-run `stipulator check` with zero source edits.
   - **Contract**:
     - `0` typed resolutions recomputed (`100%` served from resolution cache).
     - `0` deterministic witnesses re-executed (only random-seeded property witnesses execute; `0` witness-cache refusals).
     - Sub-second / low-second discovery + verification latency.

### Stage 2: `gomutant` Full Campaign, Incremental Findings & Surgical Delta Verification
1. **Pass 1 (Populate Incremental Findings & Measure Campaign Throughput)**:
   - Run `gomutant run` (starting with scoped inventories in `.gomutant/*-targets.json` and expanding to package/repository campaigns).
   - Measure:
     - **Speed & Efficiency**: wall-clock time, mutants/sec, per-package mutant schema compilation vs overlay fallback rate, RTA oracle ordering short-circuits, baseline bank reuse, and peak RSS.
     - **Accuracy**: audit every `survived`, `killed`, `equivalent`, and `unverifiable` finding. Verify that pure/hermetic packages (such as `pew/internal/git`) finalize with verifiable runtime-input evidence and zero false refusals.
2. **Pass 2 (Warm Zero-Edit Re-Run — Must-Have Incremental Serve)**:
   - Run `gomutant status` and `gomutant run` immediately with zero edits.
   - **Contract**:
     - `100%` of findings served directly from `.gomutant/findings.json` (schema v17) with `0` oracle test spawns, `0` schema compilations, and `0` dropped/demoted/stale records.
3. **Pass 3 (Surgical Edit & Revert — Must-Have Incremental Delta)**:
   - Apply controlled single-function edits (reverted after verification):
     - **Inert edit** (comment/formatting): verify `gofresh` canonical/compartment digests keep the symbol's findings **100% fresh** (`0` re-executions).
     - **Semantic edit** to one function: verify `gomutant` invalidates and re-measures **only** the touched symbol/closure while serving all other symbols in `.gomutant/findings.json` untouched, and accurately flips the affected mutant verdict.

### Stage 3: `pew` Benchmark Freshness & Incrementality
1. Run `pew status` across `gofresh`, `pew`, `stipulator`, and `gomutant` to inspect which committed `benchmarks/` baselines moved after the `gofresh v0.122.2` upgrade.
2. Re-measure stale benchmarks under `mlock quiet`, then immediately run `pew status` and `pew verify` to confirm `100%` fresh serving (`0` stale) on warm re-check.

### Stage 4: Bottleneck & Survivor Fix Loop
1. **Speed / Efficiency**: Profile and fix any phase exhibiting redundant `go` tool spawns, unexpected cache invalidation, schema-compile blowup, or excessive RSS.
2. **Accuracy / Coverage**: For any genuine surviving mutant, strengthen tests to kill it or record a verified semantic equivalence; for any false `unverifiable` refusal on a pure/hermetic target, diagnose and fix the underlying analyzer from first principles.
