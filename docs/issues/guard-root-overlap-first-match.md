# Overlapping guard roots: the first admitting root's failure is final

Lands: when overlapping guard-covered roots occur in a real
configuration, or when the coverage walk is next touched.

`guardCoveredUncached` returns false as soon as the first lexically
admitting root fails resolution (unresolvable chain, missing object,
escape), without consulting a later overlapping root that would admit
the same path. Conservative direction only — the read stays observed,
so no unsoundness — but reuse is forfeited in overlap topologies
(a build cache configured inside a module cache's covered region, an
ancestor-declared root shadowing a child). One-loop fix: continue to
the next root instead of returning.
