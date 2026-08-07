# Init-only-reachable registration state stays downgraded

A registry mutated solely through helpers that no non-init root
reaches (a `Declare`-style helper called only from package-level var
initializers) is startup-deterministic state in fact, but the mutation
walk is syntactic and fail-closed: the helper body is program code, so
the write marks and the declaring package opens. Field measurement:
this is the dominant first-party residual after the use-shape
precision landed - a `declarations.Declare(name, ...)` helper opens
its package and downgrades every importer.

Mechanism options for triage (spec-first): prove init-only
reachability over the whole-program call graph (no non-init root
reaches the mutating body) and treat such writes as init flow; or
keep fail-closed and route the pattern to the workload (registries
populated in initializer expressions or init bodies directly). The
property-test library's runtime caches are NOT this class - they are
genuinely runtime-mutated - and stay correctly open either way.

Lands: cross-tool train chunk 22.
