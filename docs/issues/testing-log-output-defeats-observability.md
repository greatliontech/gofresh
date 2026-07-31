# testing log output defeats the observability proof for file-reading oracles

`gofresh/observation-rta@4` classifies the formatted-output effect reached
through `testing.T`'s failure/logging methods (`t.Fatal`, `t.Fatalf`,
`t.Log`, …) as unobservable (`ObservationReason: reaches fmt.Printf
(formatted output)`), so a test function that both reads a runtime input and
can fail through `t.Fatal` never earns an observation-completeness proof —
its recorded evidence can never rescue the file-I/O unverifiability, and its
results are permanently uncacheable under the observed policy.

Observed (gomutant fixture, go1.26.5): a test reading `baseline.txt` and
failing via `t.Fatal` records `ObservationObservable:false` with the reason
above; the identical test failing via `t.Fail()` (no logging) records
`ObservationObservable:true` and serves. Real oracles and witnesses fail via
`t.Fatal` almost universally, so the practical effect is that observed-policy
caching silently excludes most file-reading test subjects — the exact
population the runtime-input machinery exists for.

The formatted output in question lands in the testing harness's in-memory
buffer and the run's captured output — plausibly harness-internal rather
than an unobservable external effect, adjacent to the existing typed
testing-runtime effect handling (closure's maximalTesting classification).
Whether it can be classified observable (or testing-runtime-internal) needs
its own diagnosis against REQ-closure-observability-analysis's contract.

Lands: when a consumer needs observed-policy caching for `t.Fatal`-failing
oracles that read runtime inputs, or the next observability-analysis
precision pass, whichever comes first.
