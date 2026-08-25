# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

| issue | summary | Lands |
|---|---|---|
| [dst-tagged-selection-outside-audit-key](dst-tagged-selection-outside-audit-key.md) | dst-tagged build selections get default-selection audit admissions; the key cannot see tags | with the first judged run over a dst-tagged build selection |
| [unlisted-toolchain-refusals-lack-naming-diagnostic](unlisted-toolchain-refusals-lack-naming-diagnostic.md) | consumers on an unlisted toolchain see generic refusals, not the release that needs walking | user decision |
| [audit-key-mechanism-consolidation](audit-key-mechanism-consolidation.md) | four parallel spellings of the audit lookup/refuse mechanism | with the next audited-set change set touching any of them |
| [binary-roots-single-mask-union](binary-roots-single-mask-union.md) | one all-roots RTA walk instead of per-root batches for the binary inventory | with the next reachability-scoping change |
| [unify-discharge-walks](unify-discharge-walks.md) | one culprit walk parameterized by proof and destination; the reason-channel clause and verb literals now spelled at two composition points fold in, and a channel enum carried by the discharge machinery would make message-names-a-channel-the-engine-won't-honor unrepresentable | with the next reachability-scoping change |
| [sibling-reason-families-name-their-channels](sibling-reason-families-name-their-channels.md) | external-syscall and caller-supplied-dynamism reasons still dead-end; same fix shape as the shared-dynamic-state family | with the next change to either reason's composition site, or a field report showing the dead end again |
| [unify-carrier-walks](unify-carrier-walks.md) | one carrier-type walk parameterized by TypeParam policy and leaf table | with the next reachability-scoping change |
| [attestation-keyed-record](attestation-keyed-record.md) | collapse the per-mode discharge plumbing into one attestation-keyed record | user decision |
