# Verification-harness cost needs current attribution

The August 2026 fixture measurement (24 to four cores cost about 4%;
closure 544s, whole run 555s) does not identify today's critical path.
Measure the current plain and race workloads, distinguishing recurring warm
verification from cold compiler-cache population. Attribute compiler/linker
spawns, repeated fixtures and analysis setup, cache isolation, and the longest
individual tests before selecting a mechanism.

Parallelism alone is not a diagnosis: `t.Setenv`, package-level memo controls,
analysis hooks, and the explanation mutex constrain safe sharing. Audit the
actual shared state before changing fixture ownership or scheduling. Preserve
every deciding assertion, test population, race obligation and isolation
boundary. Compare equal completed workloads, retaining targeted development
checks and the full settled-tree gate after independent review convergence.

Lands: docs/plans/tooling-redesign.md 3.5 for current measurement and harness
repair; 7.7 and 9.3 retain broader performance and final assurance obligations.
