# Plan: hot-loop reuse — guard-covered toolchain reads, attributable refusals, per-input digests

Spec: `docs/specs/runtime-inputs.md`, `docs/specs/guards.md`, `docs/specs/closure.md`,
`docs/specs/overview.md`. Widens the read-classification trust model (reads already pinned by
existing guards stop sealing observations unverifiable), gives the manifest per-input digests so
refusals can name the moved input, and clears the parked engine issues.

- [x] 1. Triage gate
- [x] 2. GOROOT reads classify as toolchain-guard-covered (spec + observation classification + tests)
- [x] 3. GOMODCACHE reads classify as immutable-pinned (spec + observation classification + tests)
- [x] 4. Manifest gains per-input digests: the one canonical encoding redefined in place — exactly one schema ever readable, prior encodings rejected, consumers regenerate; Describe/Current gain per-input recorded-vs-current attribution
- [x] 5. Moving-identity refusals: view-change and unverifiable errors name the subject, observation class, and — via per-input digests — the moved input
- [x] 6. Refined tier: missing-root degradation becomes subject-local instead of failing the batch
- [x] 7. Refined tier: precision/cost evaluation on the dependency-heavy sample; disposition surfaced with numbers
- [x] 8. Sealed-observation manifest union gap
- [ ] 9. Close-out gate
