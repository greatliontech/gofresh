# Cross-tool train: overlay cost, run-ephemera classification, gomutant throughput

The active roadmap across gofresh, gomutant, stipulator, and pew. Each
chunk is one commit in its named repo, run through the full adversarial
loop there; gofresh chunks release before consumer chunks bump. WIP = 1.
Ordering for the gomutant tail follows the `Lands:` lines in that repo's
issue docs; the two lead chunks are the field-blocking overlay defect and
its root-cause class.

- [ ] 1. gomutant: overlay commit cost + quarantine
      (gomutant docs/issues/store-update-reparses-whole-overlay.md) —
      stat-keyed overlay parse cache (O(changed) per commit; the
      whole-set merge and prune semantics preserved) plus a size-ceiling
      quarantine treating oversized entries as evictable cache content.
- [ ] 2. gofresh: run-ephemera runtime-input classification
      (direction in pew
      docs/issues/bench-scratch-dirs-recorded-as-runtime-inputs.md) —
      paths under the observation bracket root absent from the pre-run
      fingerprint and absent again at close classify as the process's
      own ephemera under the completed-process assumption; runtimeinput
      spec amendment + strategy/format revision; corpus pin re-consent
      as the LAST spec operation of the change set.
- [ ] 3. pew, gomutant, stipulator: ride the chunk-2 gofresh release;
      pew's scratch-dirs issue closes; confirm the field repo's
      manifests shrink.
- [ ] 4. gomutant: preflight plan phase + execution progress
      (gomutant docs/issues/preflight-plan-phase.md and
      docs/issues/silent-execution-no-progress.md — one run-loop pass
      wires both).
- [ ] 5. gomutant: confirmation uses stability evidence
      (gomutant docs/issues/confirmation-ignores-stability-evidence.md).
- [ ] 6. gomutant: kill-cache keying by killing-oracle content
      (gomutant docs/issues/kill-cache-keying-asymmetry.md — builds on
      the compartment ledger the preflight surfaces).
- [ ] 7. gomutant: pipeline preparation with execution
      (gomutant docs/issues/pipeline-preparation-with-execution.md —
      includes the measured pre-baseline stall).
- [ ] 8. pew: one go-invocation environment
      (pew docs/issues/one-go-invocation-environment.md).
- [ ] 9. gofresh: open the startup-effect-precision plan
      (charter gofresh docs/issues/startup-effect-precision.md;
      dotless-module-paths, one-dispatch-site-classifier, and
      runtimeinput-producer-facade ride it per their Lands lines).
