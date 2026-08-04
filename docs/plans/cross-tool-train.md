# Cross-tool train: overlay cost, run-ephemera classification, gomutant throughput

The active roadmap across gofresh, gomutant, stipulator, and pew. Each
chunk is one commit in its named repo, run through the full adversarial
loop there; gofresh chunks release before consumer chunks bump. WIP = 1.
Ordering for the gomutant tail follows the `Lands:` lines in that repo's
issue docs; the two lead chunks are the field-blocking overlay defect and
its root-cause class.

- [x] 1. gomutant: overlay commit cost + quarantine
      (gomutant docs/issues/store-update-reparses-whole-overlay.md) —
      stat-keyed overlay parse cache (O(changed) per commit; the
      whole-set merge and prune semantics preserved) plus a size-ceiling
      quarantine treating oversized entries as evictable cache content.
- [x] 2. gofresh: run-scratch runtime-input handling
      (charter: pew
      docs/issues/bench-scratch-dirs-recorded-as-runtime-inputs.md;
      that doc's automatic-classification direction proved unsound —
      the identity-only testlog cannot split own-scratch from
      absence-probes) — enforced scratch-namespace admission
      (caller-declared MkdirTemp-shaped namespace, gofresh proves
      absence at both bracket endpoints before dropping a record) plus
      directory objects contributing membership+mode, never own
      size/mtime, to bracket and path digests; runtimeinput spec
      amendment + observation-strategy revision; corpus pin re-consent
      as the LAST spec operation of the change set.
- [ ] 3. pew, gomutant, stipulator: ride the chunk-2 gofresh release;
      pew grows the per-package scratch-namespace declaration (its
      wiring does change, contra the issue doc's claim) and its
      scratch-dirs issue closes; confirm the field repo's
      manifests shrink — field measurements run against a pinned copy
      of the workload repo, never a live checkout.
- [ ] 4. gomutant: run survives any single oracle outcome + incremental
      persistence (gomutant
      docs/issues/oracle-deadline-aborts-run-nothing-persisted.md) —
      inserted ahead of the throughput tail: a campaign losing every
      verdict to one slow mutant gates the tail's field measurements.
- [ ] 5. gomutant: preflight plan phase + execution progress
      (gomutant docs/issues/preflight-plan-phase.md and
      docs/issues/silent-execution-no-progress.md — one run-loop pass
      wires both).
- [ ] 6. gomutant: confirmation uses stability evidence
      (gomutant docs/issues/confirmation-ignores-stability-evidence.md).
- [ ] 7. gomutant: kill-cache keying by killing-oracle content
      (gomutant docs/issues/kill-cache-keying-asymmetry.md — builds on
      the compartment ledger the preflight surfaces).
- [ ] 8. gomutant: pipeline preparation with execution
      (gomutant docs/issues/pipeline-preparation-with-execution.md —
      includes the measured pre-baseline stall; before/after measured
      on a pinned copy of an available workload repo, its own baseline
      pair).
- [ ] 9. pew: one go-invocation environment
      (pew docs/issues/one-go-invocation-environment.md).
- [ ] 10. gofresh: open the startup-effect-precision plan
      (charter gofresh docs/issues/startup-effect-precision.md;
      dotless-module-paths, one-dispatch-site-classifier, and
      runtimeinput-producer-facade ride it per their Lands lines).
