# Unmemoized `withMovedInputs` Manifest Hashing & `CheckingUnit.Close` Stale-Slot Re-Evaluation

- **Status:** Open
- **Governing contract:** [`docs/specs/evidence.md`](../specs/evidence.md) (`REQ-fresh-result-model`), [`docs/specs/runtime-inputs.md`](../specs/runtime-inputs.md), [`docs/specs/purity.md`](../specs/purity.md) (`REQ-purity-override`)
- **Lands:** Chunk 6 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

When checking or revalidating batch-produced witness records that share a common `Fingerprint.RuntimeInputs` manifest, two `O(subjects * manifest_paths)` redundancies dominate verification latency:

1. **`withMovedInputs` Re-Decodes and Re-Hashes Identical `RuntimeInputs` Manifests Once per Subject Record (`validate.go:475-485`)**
   - In `withMovedInputs` ([`validate.go`](../../validate.go) lines 475–485), `movedInputsForView(ctx, v, recorded.RuntimeInputs)` (`line 479` -> `MovedInputs` in `internal/runtimeinput/manifest.go:401` -> `fileHash` in `internal/runtimeinput/hash.go:289`) has no per-manifest memoization.
   - In a batch of `N` tests sharing one `RuntimeInputs` manifest (e.g., `361` subjects in `gofresh` sharing a `345`-path manifest, or `70` subjects in `stipulator/internal/cmd` sharing a `6,766`-path / `3.15 MiB` manifest), `CheckBatch` and `CheckingUnit` decode the base64url JSON manifest and `stat`/`sha256`-hash every path `N` times per round (`124,545` path evaluations per call in `gofresh`, and `~140 GiB` of `sha256` hashing per round in `stipulator`).

2. **`CheckingUnit.close` Re-Evaluates Already-`Stale` Historical Slots Only to Discard the Result (`checking.go:523-542`)**
   - During opening candidate selection (`CheckingUnit.Check` / `CheckBatch`), `u.slots` accumulates every historical candidate variant checked across rounds, most of which were already judged `Stale` (`1,431` stale historical slots alongside `20` valid served slots in `gofresh`).
   - In `CheckingUnit.close` ([`checking.go`](../../checking.go) lines 523–542), line 525 only short-circuits `!slot.result.evaluated`:
     ```go
     if !slot.result.evaluated {
         records[i].refusal = slot.result.verdict
     }
     ```
     Every evaluated slot whose opening `slot.result.verdict.Status` was already `Stale` is passed into `current.checkRecords` (`line 529`), running `observeRecordInputs` + `withMovedInputs` a second time across all `1,431` stale records, only for lines 537–538 (`if slot.result.verdict.Status == Stale { result.verdict = slot.result.verdict }`) to overwrite and discard the recomputed verdict.

## Soundness Constraint & Resolution Scope

1. **Point-in-Time Memo Scope Invariant**: `CheckingUnit` evaluates runtime inputs at two distinct points in time — before execution (`Check` / `CheckBatch`) and after execution (`CheckingUnit.Close`) to detect mid-run drift (`REQ-purity-override` `producing-motion` / `guard-drift`). Memoization of `movedInputsForView` (and `observeRecordInputs` where not already deduplicated) MUST be scoped strictly to a single point-in-time check pass (`CheckBatch` invocation or a single `CheckingUnit.close` invocation), keyed by `(recorded.RuntimeInputs, baseDir, envFingerprint)`, and MUST NEVER share cached filesystem hashes across the pre-execution to post-execution boundary.
2. **Stale-Slot Short-Circuit**: In `CheckingUnit.close` ([`checking.go`](../../checking.go) lines 523–542), pre-populate `records[i].refusal = slot.result.verdict` whenever `!slot.result.evaluated || slot.result.verdict.Status == Stale` so `current.checkRecords` only re-checks slots that were non-`Stale` at opening time.
