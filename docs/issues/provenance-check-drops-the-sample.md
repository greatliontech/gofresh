# ToolchainProvenance.Check answers the verdict without the sample

`gofresh.ToolchainProvenance.Check` samples the ambient toolchain and
judges the skew, returning only the refusal. A consumer whose ladder
reads the sample beside the verdict — gomutant's build-events floor
(`go1.24` test2json events) judges the same sampled version — asks the
sampler again after the check; the memoized `gotool.Sampler` answers
the second ask without a second process, so the cost is one memo
lookup and one more call site, but the composite's contract ("one
sample per ladder") is held by the consumer's discipline rather than
by the composite's return.

## Collapse sketch

`Check` returns the sampled version beside the error (`(string,
error)`), or a sibling `Judge` does; a consumer's floor reads the
returned sample and the memo carries no second ask. Invariants
preserved: one sample per coordinate and environment per composite
lifetime; the refusals unchanged.

Lands: gofresh chunk 279 (a rider on its release: the consumer bumps
behind it read the returned sample).
