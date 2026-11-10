# Open Issues

Tracked architectural decomposition, simplification, optimization, defect, and test-hardening issues for `gofresh` (and `go-x-tools`). Each open issue names its concrete `Lands:` chunk in [`docs/plans/plan.md`](../plans/plan.md) and is retired at chunk close-out.

| Issue | Summary | Lands |
| :--- | :--- | :--- |
| [go-x-tools-startup-purity-and-determinism](go-x-tools-startup-purity-and-determinism.md) | Eliminate startup `os.Getenv("GOPACKAGESDEBUG")` in `go/packages`, `reflect.TypeFor` on concrete types in `go/ast/edge` and `go/ssa`, startup `tRune` global in `go/ssa`, and startup `maphash.MakeSeed()` in `go/types/typeutil`. | Chunk 8 |
