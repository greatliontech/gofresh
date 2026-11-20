# Open Issues

Tracked defect, precision, consolidation, and performance issues for `gofresh`. Each open issue names its governing spec requirements and concrete `Lands:` chunk in [`docs/plans/plan.md`](../plans/plan.md) and is retired at chunk close-out.

| Issue | Summary | Lands |
| :--- | :--- | :--- |
| [moved-inputs-memoization-and-checking-close-short-circuit](moved-inputs-memoization-and-checking-close-short-circuit.md) | Fold mover computation into `populateManifestDigests` (`MovedInputs` / `Adopt` / `withMovedInputs` deduplication), skip proof selection, mover formatting, and `runtimeMotion` on terminal `Stale` slots in `CheckingUnit.close` while preserving endpoint-interval closing, and deduplicate root engine helpers. | Chunk 14 in [`docs/plans/plan.md`](../plans/plan.md) |
