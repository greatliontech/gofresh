# The toolchain sampler and the roots memo are two memos of one shape

gotool.Sampler (the memoized toolchain sample) and runtimeinput.Roots
(the memoized classification-root snapshots, chunk 281.D) are the
same mechanism twice: a mutex-guarded map keyed by the directory
coordinate and the environment, held by the consumer for one judged
run, keeping a failed answer and never a cancelled one. They spell
their keys differently — the sampler's memoEnv degrades a malformed
environment while rootsKey refuses it and strips PWD — so the one
rule ("a coordinate and a normalized environment") has two
implementations that can drift.

The fold: one generic memo in gotool, parameterised by the value it
holds, with one key spelling both read; Sampler and Roots become the
two instances. Invariants preserved: the per-judged-run bound both
docs state, the failed-answer memo, the never-memoized cancellation,
the key's coordinate-and-normalized-environment rule.

Lands: cross-tool train chunk 327 (the gotool surface release: one generic judged-run memo, the Sampler and runtimeinput.Roots its instances with one key spelling; audit 316).