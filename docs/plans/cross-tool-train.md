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
- [x] 3. pew, gomutant, stipulator: ride the chunk-2 gofresh release;
      pew grows the per-package scratch-namespace declaration (its
      wiring does change, contra the issue doc's claim) and its
      scratch-dirs issue closes; confirm the field repo's
      manifests shrink — field measurements run against a pinned copy
      of the workload repo, never a live checkout.
- [x] 4. gomutant: run survives any single oracle outcome + incremental
      persistence (gomutant
      docs/issues/oracle-deadline-aborts-run-nothing-persisted.md) —
      inserted ahead of the throughput tail: a campaign losing every
      verdict to one slow mutant gates the tail's field measurements.
- [x] 5. gofresh: bracket-declared static inputs
      (gofresh docs/issues/bracket-declared-static-inputs.md) — the
      bracket vocabulary admits declared static inputs (repo files and
      committed trees whose digests ride the generation snapshot) and
      excludes non-corpus session dot-dirs; ~60% of cerebro's
      uncacheable witness mass.
- [x] 6. stipulator + gomutant: retire the targets seam (user decision:
      the binding-surfaces export predates the tool split, no consumer
      drives it, and findings never return — the adequacy loop it was
      designed for was declined rather than closed) — stipulator loses
      the targets verb, binding-surfaces spec, wire module, and the two
      issue docs premised on surfaces; gomutant loses the adapter and
      format-sniff, its own config document becoming the one producer
      schema.
- [ ] 7. gofresh: fmt taint keys on the sink
      (gofresh docs/issues/purity-bars-dynamic-and-fmt.md, the fmt
      half — ~308 witnesses) — the writer-first print family is
      Sprint-equivalent when the writer provably pins an audited
      in-memory sink; unproven writers keep the refusal.
- [ ] 8. gofresh: caller-supplied dynamic narrows to escaping dynamism
      (the same doc's dynamic half — ~647 witnesses) — a dynamic
      argument every in-view call site pins to view-analyzed values is
      not dynamism; enumeration-refused, escaping, or
      outside-view-supplied dynamism keeps the refusal.
- [ ] 9. stipulator: ride the purity/statics gofresh release; re-measure the
      cerebro check against the warm floor; closes stipulator
      docs/issues/cerebro-uncacheable-mass-measured.md (the chunk-5, 7,
      and 8 fixes) and the two gofresh docs at their close-outs.
- [ ] 10. gomutant: preflight plan phase + execution progress
      (gomutant docs/issues/preflight-plan-phase.md and
      docs/issues/silent-execution-no-progress.md — one run-loop pass
      wires both).
- [ ] 11. gomutant: confirmation uses stability evidence
      (gomutant docs/issues/confirmation-ignores-stability-evidence.md).
- [ ] 12. gomutant: kill-cache keying by killing-oracle content
      (gomutant docs/issues/kill-cache-keying-asymmetry.md — builds on
      the compartment ledger the preflight surfaces).
- [ ] 13. gomutant: pipeline preparation with execution
      (gomutant docs/issues/pipeline-preparation-with-execution.md —
      includes the measured pre-baseline stall; before/after measured
      on a pinned copy of an available workload repo, its own baseline
      pair).
- [ ] 14. pew: one go-invocation environment
      (pew docs/issues/one-go-invocation-environment.md).
- [ ] 15. gofresh: open the startup-effect-precision plan
      (charter gofresh docs/issues/startup-effect-precision.md;
      dotless-module-paths, one-dispatch-site-classifier, and
      runtimeinput-producer-facade ride it per their Lands lines).
