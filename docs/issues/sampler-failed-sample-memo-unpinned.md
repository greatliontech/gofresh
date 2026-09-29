# The sampler's memoized failure has no witness

`gotool.Sampler` memoizes a failed sample like an answered one ("the
toolchain does not change between two asks in one lifetime"), so a
second ask of a refused (coordinate, environment) spawns nothing and
answers the same refusal. `TestSamplerMemoizesByCoordinateAndNeverACancellation`
pins the coordinate and environment keying and the cancellation arm;
no pin asks twice after a failure and counts one spawn. stipulator's
own memoized sampler carried that pin (TestMemoizedSamplerSamplesOncePerKey)
and retired it at its gotool fold (chunk 272) on the premise that
gofresh's covers it — it does not.

Lands: cross-tool train chunk 281 (audit 285, 2026-09-29: a fleet coverage loss,
not a test-surface item — gotool/gotool.go:171–178 unpinned since stipulator
retired its pin at 272).
