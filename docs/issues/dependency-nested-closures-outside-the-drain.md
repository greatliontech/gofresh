# Dependency nested-function values need a precise reachability account

The earlier diagnosis that `addObject` filters dependency functions before
scanning them is false for the current implementation. In
`closure/analyzer.go`, it scans a function's SSA value before the standard/
test-main filter; the cached-dependency arm also scans declaration references
and function bodies. Dependencies are not wholesale outside this scan.

The remaining precision question is a nested function value reached only by
reference through a dependency: identify the exact SSA value, parent/body
scan and conservative refusal before changing the drain or adding summaries.
Compare it with the already-covered first-party form and a direct dependency
call. No current wrong-valid result is established by this filing, and no
general dependency-body scan should be built on the refuted diagnosis.

Lands: docs/plans/tooling-redesign.md 7.8.
