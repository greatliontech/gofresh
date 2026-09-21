# The moved-bracket attribution has no published split

REQ-inputs-refusal-attribution publishes `RefusalClause` as the one
split a consumer keys on, scoped to the classification refusals and the
resolved-target refusals (the ` — ` suffix). The observation-bracket
refusal attributes too — `observation bracket moved: <root>` followed by
a bracketed member list (`bracketMoveAttribution`, runtimeinput/
bracket.go) — and that suffix has no published split: gomutant's
exemption record keeps its own strip for it (exemptions.go's
bracket-form clause, composed after `RefusalClause`), the second
attribution grammar the fleet reads.

Collapse: `RefusalClause` splits both forms (the bracket suffix is
well-formed as `[recently touched: …]`/`[added: …]`/`[removed: …]`
running to the reason's end), the clause names the moved-bracket
refusal among the governed ones, and gomutant's copy deletes at its
next bump. Invariants preserved: a path's own bracketed segment is never
stripped (only the moved-bracket clause carries the form). gomutant's
strip cuts at the last `" ["`, so a moved member whose own name carries
`" ["` garbles the clause on both sides alike (the entry still matches
its garbled twin); the published split parses the attribution from its
prefix instead.

Lands: a gofresh change set amending REQ-inputs-refusal-attribution's
governed set (the split grows the moved-bracket form); gomutant's copy
deletes at the bump behind it.
