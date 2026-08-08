# The maximal tier's preferred diagnostic implements its own precedence, not the shared cause-preference order

Every effect-adding arm of the maximal per-file scan now feeds a named
reason, and the package fold keeps effect-backed reasons over effectless
import fallbacks — but the tier's precedence is still a fixed stratum
switch plus a lexicographic fold, not the rank derivation the
observation tiers share (`effectCauseRank`). Deterministic and
display-only (verdicts are unchanged; only which honest reason is
named), with demonstrated inversions in both directions:

- a file with `import _ "os"` and a `t.Short()` helper names
  `testing.Short` (rank 0) over the blank-import unaudited effect
  (rank 4 under the code's own table);
- `fmt.Printf` (rank 1) is named over `t.TempDir` (rank 4);
- the package fold orders within a class lexicographically, not by rank.

Also carried here:

- `effectCauseRank` ranks any `packagePath == ""` effect top as a
  structural finding before examining kind, so opaque unaudited-import
  effects rank above the strata sentence's down-ranked "unaudited"
  classification — an internal inconsistency in the one shared order.
- No property-level pin exists for "a non-empty effect set always
  carries a non-empty preferred"; the instance tests and the
  equivalence oracle share production's logic (a shared
  misunderstanding passes both). A generator-driven property check is
  the opportunistic extension.

Settled (spec amended): the maximal tier's package diagnostic is an
instance of the legacy single-reason projection and owes the shared
cause-preference order — rank strata with the legacy lexicographic
tie-break. The work: rank plumbing in the per-file preferred derivation
(replacing the fixed stratum switch; the always-external import reason
participates as a top-stratum candidate so its precedence over
same-package symbol reasons survives via the lexicographic tie), a
rank-aware package fold in place of the effect-backed/lexicographic
two-class fold, the `packagePath == ""` branch fix in the shared rank
table, and the interaction with the unrefinable-reason class (opaque
native reasons must keep winning where refinability gates downstream
behavior, not merely display) — plus the property pin above.

Lands: cross-tool train chunk 29.
