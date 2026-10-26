# Issues

Parked deferrals. Each source issue has one primary open slot in
`docs/plans/plan.md`; secondary constituents are stated in its doc.
Historical reports remain attributed and do not assert current runtime
verification. The doc is deleted when its obligation resolves (git holds history).

| issue | summary | Lands |
|---|---|---|
| [fleet-sweep-provenance-install-path](fleet-sweep-provenance-install-path.md) | The sweep's provenance loop stats `~/go/bin/<tool>` while the installed gomutant/pew/stipulator live in `~/.local/bin`, so all three read `NO BINARY installed` (fleet sweep 2026-10-26) as a red fact instead of NOT MEASURED and their revision-vs-build-input fact is unmeasured; resolve the binary as the preflight does. | 2.1 (the first consumer rebuild; an earlier gatherer fix closes it sooner — closes on the provenance section naming a revision for all three tools) |
