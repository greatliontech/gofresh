# Witnessed gate runs red in the witness layer while direct tests pass

Lands: when a witnessed gate run over this corpus captures per-witness
failure output and the failures are diagnosed, or when this corpus moves
to a policy-derived witnessed execution.

## Observed

A full witnessed `stipulator gate` over this corpus reported a broad red
set — requirements bound to packages across the tree, including packages
an in-flight change never touched — while every named package passed
`go test -race` directly and `verify --no-test` reported clean records.
The reds therefore sit in the witness execution layer (fresh-checked
`-race` witness runs), not in the tests themselves. Per-witness failure
output was not captured (lost to a truncating pipe); the diagnosis needs
a re-run with the gate's stderr retained in full.

CI is unaffected: this repository's workflow runs the plain test suite,
never the witnessed gate.

## Diagnostic

Run the witnessed gate with stderr retained whole (no pipe truncation),
bounded and niced; read each failing witness's retained output. A
degrade names an environmental cause; an assertion failure gets a fresh
diagnosis. The witness layer here is the legacy whole-suite runner, so
load-pattern degradation (the class stipulator's own corpus exhibited
under whole-suite -race load) is the standing first hypothesis.
