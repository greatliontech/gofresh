# Observation-pass floor is per-pass toolchain subprocesses

Lands: when a view lifecycle spends fewer observation passes (an observed
capture sharing the construction pair as its opening bracket is the known
candidate), or a pass batches its toolchain probes, or the ~0.3-0.4s/pass
floor is accepted.

## Measured (gomutant fixture, 3 records, gofresh post-dynamic-state-memo)

Findings inspection costs 2.6s for 3 records, of which 2.37s is subprocess
execution: 56 go invocations - per observation pass one metadata listing
(`go list -json -deps -test`, ~50ms), one typed roots load (~50ms driver +
context probes), one guard capture (`go version` + `go env -json`), plus
`go env GOFLAGS`/`GOMODCACHE` validations. Six passes per record lifecycle
(construction pair, precise-analysis bracket pair, validation pair) - the
pass count is the drift-refusal contract, so the floor scales with it.
In-process analysis no longer measures: the dynamic-state fact memo and the
roots-only pass load removed it.

## Resolution shapes

Fewer passes: an observed capture immediately following construction could
open its bracket on the construction pair's second observation (5 passes,
-17%) - a REQ-fresh-coherent-view amendment, since the bracket's
independence is currently unconditional. Cheaper passes: guard capture and
env validation re-exec per pass; batching the probes into one `go env -json`
read per pass (or deriving GOFLAGS validation from it) trims ~100ms/pass
without touching pass count. Both are contract-adjacent; neither is plumbing.
