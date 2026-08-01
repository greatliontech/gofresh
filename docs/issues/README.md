# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[testing-log-output-defeats-observability](testing-log-output-defeats-observability.md)** — the
  observability proof classifies `t.Fatal`'s formatted output as unobservable, so file-reading
  oracles that can fail through it are permanently uncacheable under the observed policy.
  *Lands: when a consumer needs observed-policy caching for `t.Fatal`-failing oracles that read
  runtime inputs, or the next observability-analysis precision pass.*
- **[observability-batch-retains-every-program](observability-batch-retains-every-program.md)** — a
  capture batch over a many-package view grows peak RSS with the package count (10.4 GB vs
  614 MB measured on a 33-package set) because the observability batch never releases loaded
  whole-program SSA. *Lands: 5 (of the active analysis-simplification plan).*
