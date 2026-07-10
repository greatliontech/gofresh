# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[closure-analysis-cost-amortization](closure-analysis-cost-amortization.md)** — per-subject RTA
  makes a 127-test tree cost ~57 CPU-minutes and ~12 GB per engine pass, dwarfing the test time
  the freshness verdicts save. *Lands: 6.*
- **[stipulator-coverage-witness-classes](stipulator-coverage-witness-classes.md)** — eight
  requirements have fresh bindings and passing tests but lack the property, analyzer, or
  executed witness class their requirement kind needs. *Lands: when binding evidence
  classifications are next revised, or before the next release.*
