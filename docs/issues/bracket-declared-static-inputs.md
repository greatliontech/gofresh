# Repo-anchored static inputs defeat observation brackets wholesale

Measured on the cerebro corpus (2026-08-04, `stipulator check --json`
uncacheableReasons): 2,407 of the project's witnesses are uncacheable, and the
dominant classes are bracket misses on inputs that are static repo content, not
runtime dynamism — 709 witnesses tripping on `go.mod` (the repo-root discovery
walk every source-reading test performs), 533 on `cmd` and 18 on
`docs/specs/law-corpus.md` (tree-scanning oracle tests over committed content),
and 182 on `.claude` (a session harness directory a foreign tool mutates inside
the repo, dragged in by the same tree walks). Every one of these is content the
snapshot already digests or deliberately ignores; treating a read of it as an
unbracketed runtime input makes the witness permanently uncacheable and forces
whole-suite re-execution on every check.

The collapse: the bracket vocabulary admits declared static inputs — repo files
and directories whose digests ride the generation snapshot (`go.mod`, committed
trees like `cmd/` and `docs/`), so a read inside them brackets as covered — and
non-corpus dot-directories (`.claude`-class session dirs) are excluded from the
observed set outright, matching the snapshot's own ignore discipline. Estimated
recovery on cerebro: ~1,440 witnesses (60% of the uncacheable mass) become
cacheable, which with the memoized serving engine moves the warm check from the
~22-minute class toward the measured ~2-minute floor family.

Lands: with the check-view-cardinality fix family (stipulator
docs/issues/check-view-cardinality.md) — one observation-cost program, both
axes: pass count and cache admission.
