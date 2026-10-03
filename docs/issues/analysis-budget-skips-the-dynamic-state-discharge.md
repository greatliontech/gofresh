# The analysis budget never reaches the dynamic-state discharge's reachability analysis

Field report from the protodb session (2026-10-02, the standing channel,
relayed through gomutant's 304 triage): two campaigns over protodb with
`--analysis-budget 5s` sat in gomutant's "proving oracle closure
freshness (gofresh hash proof) github.com/greatliontech/protodb/internal/db
(1/1)" for 23 and 10+ minutes before measuring. That event is gofresh's
`prove` unit emitted at closure/rooted.go (ComputeRootedFunctions — the
dynamic-state discharge's attributed reachability analysis, "No memo
layer: the inventory is recomputed per pass"), called from purity.go's
scanViewSubjects on the view-construction Hasher (view.go, the
`closure.NewAt` after the pass snapshot), which never receives
`BoundAnalysis`: the budget is installed only on the observability-proof
Hasher (view.go's `closure.NewBracketAt` path). WithAnalysisBudget's doc
("bounds each precise-analysis phase") and REQ-fresh-context's "the
optional precise-analysis tier" over-claim against this tier. The scan
facts memo serves an unchanged package, so the cost is paid per MISSED
package — every edit inside a view package's cone during a campaign
re-pays the reachability analysis in full, minutes-class on a package
the size of protodb's internal/db, with the operator's one lever
(the budget) inert.

The derivation: the discharge is a precise analysis in the clause's own
sense (attributed RTA over the loaded program) and must obey the one
budget — a cut leaves the culprit STANDING (undischarged: the subject
keeps its dynamic-state refusal, fail-closed, never validity), the pass
reports the exhaustion once with the count of subjects left
undischarged, and the clause and the doc name the tier. The memo for the
rooted inventories (the "no memo layer" half) is the dynamic-state
tier's design, chunk 202's.

Lands: cross-tool train chunk 305 (gofresh, a release directly after 304;
gomutant reads it at its next bump — its plumbing is in place).
