# Open Issues

Tracked defect, precision, consolidation, and performance issues for `gofresh`. Each open issue names its governing spec requirements and concrete `Lands:` chunk in [`docs/plans/plan.md`](../plans/plan.md) and is retired at chunk close-out.

| Issue | Summary | Lands |
| :--- | :--- | :--- |
| [testlog-streaming-chdir-elision-and-overlay-cleanup](testlog-streaming-chdir-elision-and-overlay-cleanup.md) | Unify `producer.go` and `testlog.go` onto one streaming `testlog` reader and shared `open`/`stat`/`chdir` path spine, gate tracked `t.Chdir` unsealing/restoration on toolchain + binary-graph + balanced LIFO stack premises, and clean up `testenv` / closure fixture overlays. | Chunks 7, 13 in [`docs/plans/plan.md`](../plans/plan.md) |
| [moved-inputs-memoization-and-checking-close-short-circuit](moved-inputs-memoization-and-checking-close-short-circuit.md) | Fold mover computation into `populateManifestDigests` (`MovedInputs` / `Adopt` / `withMovedInputs` deduplication), skip proof selection, mover formatting, and `runtimeMotion` on terminal `Stale` slots in `CheckingUnit.close` while preserving endpoint-interval closing, and deduplicate root engine helpers. | Chunk 14 in [`docs/plans/plan.md`](../plans/plan.md) |
