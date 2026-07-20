# Plan: issue elimination — the serving substrate

Spec: `docs/specs/runtime-inputs.md` (canonical for observation classes),
`docs/specs/guards.md`, `docs/specs/closure.md`, `docs/specs/purity.md`.
Eliminates the standing issue inventory, guard classes first: three
observation classes block ~97% of witness serving on this corpus, and every
downstream serving surface (stipulator check, gomutant measurement reuse)
is gated on them. Success metric: the serving check over this corpus
collapses from 464 uncacheable toward the ~14-refusal residue.

- [ ] 1. GOCACHE guard-covered root: spec clause extending
  REQ-inputs-guard-covered with the build cache (admission: entries are
  content-addressed derivations of already-pinned inputs — toolchain,
  sources, build config — so re-observing adds no protection), runtimeinput
  coverage, engine/recorder option, fail-closed resolution discipline as the
  toolchain root
- [ ] 2. Ephemeral temp-tree class: run-created per-process temp trees are
  fresh by construction; spec clause + classification clearing the ambient
  temp-root reads
- [ ] 3. Machine-guard-covered proc reads: /proc/cpuinfo, /proc/meminfo pin
  under the machine guard's identity; spec clause + classification
- [ ] 4. Residue review (~14 genuine refusals: /dev/null, stat metadata,
  file-I/O proofs) + measurement: gofresh self-suite uncacheable count and
  the stipulator serving check over this corpus, before/after
- [ ] 5. Observability audit: toolchain accessors (runtime.GOROOT class) in
  the observability analyzer's proof leg
- [ ] 6. Refined-batch load-failure coupling
- [ ] 7. dependency-heavy-refinement-precision: disposition (implement or
  redefer with a sharpened trigger)
- [ ] 8. Close-out gate: full suite, release, downstream re-measure
  (stipulator serving check over gofresh; gomutant bump unblocked)
