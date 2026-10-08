# Mutation target inventories

`outcome-targets.json` selects the outcome-support boundaries and their explicit
oracles. Run this inventory on Linux: it includes a `/proc/self/fd` ownership
witness and exercises the audited Linux outcome method. It is a scoped inventory,
not a claim of whole-repository mutation coverage.

```sh
mlock run gomutant run --targets .gomutant/outcome-targets.json --budget 0
```

Execution outcomes, source-equivalence judgments, and record freshness are
separate evidence. A non-reusable finding still reports its measured outcomes;
unverifiable freshness never establishes equivalence for a surviving mutation.

An oracle that reads its per-process scratch-directory environment can produce
different input values on each execution. The producer records those values
truthfully; filesystem-root admission does not erase them. Such evidence may
prevent reuse even when all measured candidates have been killed or dispositioned.
