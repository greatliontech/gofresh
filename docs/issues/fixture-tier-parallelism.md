# The fixture tier runs serially; `t.Parallel()` is the unmeasured lever

The full tier (`task test`) is child-process-bound: 24→4 cores cost
~4% (measured 2026-08-27, `.github/workflows/ci.yaml`), so per-test
parallelism — absent everywhere in the suite — is the lever that
would cut its wall (closure 544s, whole run 555s) without touching
coverage. A mechanical pass is unsafe: `t.Setenv` appears in 12 test
files (85 sites) and forbids `t.Parallel()`; `SetMemoRoot` is a package
global; `ExplainDynamicState` holds a process-global mutex. Landing it
means a per-test audit of shared state, then measuring the wall under
the CI core count.

Lands: when the full tier's measured wall crosses half its CI budget
(15m of the 30m `-timeout`), or with the next change to the closure
test fixtures' shared state.
