# Broader per-test scheduling needs shared-state ownership

`t.Setenv`, package-level memo controls, analysis hooks, and the explanation
mutex constrain safe sharing between concurrently executing fixture tests.
An audit of those owners is required before introducing per-test parallelism;
sharing one fixture's loaded representation inside a sequential table does
not establish that unrelated tests can run together safely.

At the broader performance pass, use the then-current per-test and per-phase
cost inventory to decide whether scheduling changes are warranted. Preserve
every deciding assertion, test population, race obligation and isolation
boundary; compare equal completed workloads and distinguish cold builds from
recurring warm verification. Historical core-count measurements do not prove
that increasing concurrency will reduce the current critical path. There is
no obligation to add parallelism in the absence of a measured benefit and an
established ownership model.

Lands: docs/plans/tooling-redesign.md 7.7 and 9.3 for broader performance and
final assurance, before any concurrent-fixture scheduling change.
