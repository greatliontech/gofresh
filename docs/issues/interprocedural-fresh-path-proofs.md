# Fresh-path observability proofs stop at function boundaries

## Observed

28 corpus witnesses carry proof refusals "reaches os.WriteFile
(filesystem mutation)" (23) or "reaches os.ReadFile (file I/O)" (5)
because the fresh-path admission grammar (freshPathValue and the
observableFreshPath* walks) is intraprocedural: a path rooted at
testing.TempDir loses its freshness proof the moment it crosses a
function boundary — a test that builds scratch paths in a helper, or
passes t.TempDir() into one, refuses even though the same statements
inlined would admit. The observablefresh fixture's helper-escape rows
pin the current refusal deliberately.

## Shape of the fix

Interprocedural fresh-path propagation in the SSA tier: a parameter is
fresh when every attributed call site passes a fresh value, with the
same consumer discipline (mutation admissions demand created-before
facts) applied across the boundary; escape via globals, channels, or
goroutines refuses as today. Bounded by the attributed reachability the
proof already computes. This is a sizeable, soundness-critical analyzer
extension — the admission must not outrun the attribution the
batch-equivalence invariants pin.

Lands: when the observability audit next extends beyond admission
classes, or when a consuming corpus's serving is demonstrably gated on
helper-mediated scratch patterns.
