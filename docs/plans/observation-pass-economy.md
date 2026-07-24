# Plan: observation-pass economy — comparison reads once, brackets share

Spec: `docs/specs/overview.md` (REQ-fresh-coherent-view,
REQ-fresh-producer-view), `docs/specs/guards.md`, `docs/specs/closure.md`
(quiescence sentences). Closes
`docs/issues/observation-pass-subprocess-floor.md`.

- [x] 1. Single-read comparison: a validation observation that is only
  compared against captured facts — never recorded — reads once (an unequal
  torn read refuses, the safe direction; an equal torn read is the excluded
  restore interval). The maximal-only Validate arm and both rich arms'
  base-compare prelude collapse their construction pairs; spec sentence
  states the record/compare asymmetry.
- [x] 2. Seeded validation views and shared brackets: a validation view
  seeds from the captured facts plus the one fresh agreeing observation
  (no second pair), and every precise-analysis bracket may open on the
  view's last agreed observation (wider window, refusal-conservative) —
  ensurePrecise on producer and validation views, and validateRefined's
  third view collapses onto the shared after-observation.
- [x] 3. Batched toolchain probes: one `go env -json` snapshot per
  observation pass serves guard capture, GOFLAGS validation, and
  GOMODCACHE resolution.
- [ ] 4. Close-only runtime-input windows: CheckObserved's window pair
  opens on the view's agreed facts and reads only at close — the serve
  path's remaining pair class, same asymmetry, spec sentence generalized
  from the analysis bracket to comparison windows.
- [ ] 5. Re-measure (fixture protocol + corpus), spec enforcement pointers,
  close-out.
