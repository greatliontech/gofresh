# Plan: scan derivation cost — one load per pass, memoized dependency facts

Spec: `docs/specs/overview.md` (REQ-fresh-coherent-view, REQ-fresh-producer-view),
`docs/specs/closure.md` (REQ-closure-shared-dynamic-state,
REQ-closure-observability-memo, REQ-closure-pinned-dep, REQ-closure-mutable-local),
`docs/specs/purity.md` (directive discovery).

- [x] 1. Shared per-pass typed load: one `packages.Load` per view observation
  feeds both the subject/purity/dynamic-state scan and the closure tier's
  testing-type effect scan; environment validation and package-env derivation
  run once per pass. Behavior-identical; equivalence and single-load pinned by
  test.
- [x] 2. Persistent dynamic-state facts: per-package mutation/declaration facts
  for guard-pinned packages (stdlib keyed under the toolchain, module-cache
  packages under module version + import-cone version signature) served from
  the user-cache memo; local packages always derived fresh. The shared load
  shrinks to metadata graph + syntax of root and local packages. Spec clause
  beside the observability memo; equivalence and key-motion enforced by test.
- [ ] 3. Re-measure (fixture protocol + corpus check), close
  `purity-scan-duplicate-typed-load`, update the downstream issue docs with
  the new numbers, release.
