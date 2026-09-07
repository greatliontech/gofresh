# The harness admission families are four predicate-and-constructor pairs

The closure walk admits four families of testing-harness facts —
logging (`auditedHarnessLogging`/`harnessLoggingEffect`), the subtest
driver, the fuzz driver, and benchmark pacing
(`auditedHarnessPacing`/`harnessPacingEffect`) — each as a predicate
over the bare symbol name, an observable effect constructor, a
`…Function(audited, fn)` twin in `closure/analyzer.go`, a term in
`stdBodyCut`, an arm in the enumerated dynamic-target loop, and a
declaration inventory test. Every family repeats the same six sites;
the pacing family's first version missed two of them before its
review found the gaps.

The collapse: one table keyed by symbol name → effect kind, reason,
and receiver-type restriction, consumed by one predicate, one
constructor, one body-cut term, one dynamic-target arm, and one
inventory walk — a fifth family becomes a table row, and a missing
site becomes unrepresentable.

Lands: with the next harness admission family.
