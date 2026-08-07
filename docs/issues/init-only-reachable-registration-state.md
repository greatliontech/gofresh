# Init-only-reachable registration state stays downgraded

A registry mutated solely through helpers that no non-init root
reaches (a `Declare`-style helper called only from package-level var
initializers) is startup-deterministic state in fact, but the mutation
walk is syntactic and fail-closed: the helper body is program code, so
the write marks and the declaring package opens. Field measurement:
this is the dominant first-party residual after the use-shape
precision landed - a `declarations.Declare(name, ...)` helper opens
its package and downgrades every importer.

Mechanism (user decision: full tool-side precision): a mutation
inside an unexported function whose every in-package reference is a
call from an initializer expression, an init body, or another such
init-only function - transitively, with any value reference,
export, or method-value bind refusing the class - is init flow.
Package-local and fact-compatible; fail-closed on every other shape.
Discharging the read side of pointer-typed registries (method calls
like Get marking as address captures) is the separate
receiver-effect-facts item - both are needed before the registration
pattern fully discharges. The property-test library's runtime caches
are NOT this class - they are genuinely runtime-mutated - and stay
correctly open either way.

Lands: cross-tool train chunk 22.
