# Purity scan runs a second full typed load per view construction

Lands: when the purity scan consumes the view's own loaded packages (or
view construction shares one typed load end to end), or the per-record
serving floor is accepted.

## Observed (gomutant warm-path re-measure, gofresh v0.32.0)

`observeView` calls `scanSubjectsInWithBuildFlagsEnv` (purity.go), which
runs its own `packages.Load` with
NeedSyntax|NeedTypes|NeedTypesInfo|NeedImports|NeedDeps over the same
subject packages the view has already loaded - a complete second parse
and type-check per view, per invocation, on unchanged trees.

Measured downstream (gomutant fixture, 3 records): freshness
classification costs ~3.3s per record per invocation and is unchanged by
the persistent observability memo, because the memo covers only the
proving leg; view construction - including this duplicate load - is the
floor. Consumer-side numbers:
gomutant/docs/issues/warm-floor-view-construction.md.

## Resolution shape

The scan needs syntax and types for directive and open-world
classification; both are present in the view's own load. Passing the
loaded packages in (or hoisting one shared load above both consumers)
removes the duplicate without changing any classification.
