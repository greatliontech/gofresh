# Outcome-capability mutation oracle evidence

The installed gomutant uses a gofresh version predating the nodwarf5 source audit
and the execution-bound outcome protocol. Campaign measurement executes the
mutants, but the resulting records cannot establish reusable freshness evidence.
Negative capture fixtures also intentionally exercise an unrepresentable path;
their observed input union makes passing candidates `unstable-oracle`, so those
rows do not establish equivalent mutations or a complete assertion audit.

The direct tests and named ephemeral kill probes remain execution evidence.
They do not turn the campaign's unjudged rows into equivalence dispositions.
During the consumer migration, remeasure with the migrated tool and distinguish
remaining deliberate negative-fixture limitations from actual missing assertions.
Any supported treatment of those fixtures must preserve their negative behavior,
not suppress observation or add an unsupported purity assertion.

Lands: pew performance-evidence plan chunk 6 (gomutant's producer and dependency migration).
