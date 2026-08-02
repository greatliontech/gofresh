# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[testing-log-output-defeats-observability](testing-log-output-defeats-observability.md)** — the
  observability proof classifies `t.Fatal`'s formatted output as unobservable, so file-reading
  oracles that can fail through it are permanently uncacheable under the observed policy.
  *Lands: the observability precision pass — the next gofresh plan, opening immediately after
  this plan's close-out.*
- **[dotless-module-paths-classified-standard](dotless-module-paths-classified-standard.md)** — isStdImportPath
  treats any dotless first path element as standard-library, so a module named without a
  dot has its whole startup walk silently filtered out and every startup refusal
  (effects and the test-main dispatch widen alike) disabled.
  *Lands: the next gofresh plan.*
