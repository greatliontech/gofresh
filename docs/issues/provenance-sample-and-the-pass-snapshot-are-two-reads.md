# The provenance sample and the pass snapshot read one fact twice

A consumer's judged run samples the ambient toolchain twice: the
provenance composite's `go env GOVERSION` through its memoized sampler
before judging, and the engine pass's `go env -json` snapshot, whose
GOVERSION the toolchain guard reads (gofresh chunk 281.C). Both are
runtime.Version() of the toolchain answering in the module directory,
so within one judged run they agree unless the toolchain is replaced
between them — a window in which the pass's snapshot carries the new
version and the composite's memo the old, and which nothing compares
(across passes the guard compares against the recorded value, not
against the composite).

The fold: serve the composite's sample from the pass snapshot (the
consumer primes its provenance from the reader it hands the engine, or
the composite reads the reader), or the reverse, so one operation
takes one sample and the two readers cannot disagree. The consumers'
provenance runs at preparation, before an engine exists, so the shape
is the consumer's to choose at its bump and gofresh's to offer: a
ToolchainSampler over an EnvReader.

Lands: cross-tool train chunk 290 (the first consumer bump behind
gofresh 281 that holds both the composite and an engine pass in one
operation).
