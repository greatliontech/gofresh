# Plan: issue elimination — the serving substrate

Spec: `docs/specs/runtime-inputs.md` (canonical for observation classes),
`docs/specs/guards.md`, `docs/specs/closure.md`, `docs/specs/purity.md`.
Eliminates the standing issue inventory, guard classes first: three
observation classes block ~97% of witness serving on this corpus, and every
downstream serving surface (stipulator check, gomutant measurement reuse)
is gated on them. Success metric: the serving check over this corpus
collapses from 464 uncacheable toward the ~14-refusal residue.

- [x] 1. GOCACHE guard-covered root: spec clause extending
  REQ-inputs-guard-covered with the build cache (admission: entries are
  content-addressed derivations of already-pinned inputs — toolchain,
  sources, build config — so re-observing adds no protection), runtimeinput
  coverage, engine/recorder option, fail-closed resolution discipline as the
  toolchain root
- [x] 2. Ephemeral temp-tree class: run-created per-process temp trees are
  fresh by construction; spec clause + classification clearing the ambient
  temp-root reads
- [x] 3. Machine-identity proc digests: /proc/cpuinfo, /proc/meminfo pin
  under the machine guard's identity; spec clause + classification
- [x] 4. Residue review (~14 genuine refusals: /dev/null, stat metadata,
  file-I/O proofs) + measurement: gofresh self-suite uncacheable count and
  the stipulator serving check over this corpus, before/after
- [x] 4.2 Machine-fact allowlist completion: /proc/sys/kernel/osrelease
  (the guard's own KernelVersion read) joins the projection identities;
  /proc/stat gets a class decision
- [x] 4.3 /dev/null identity admission: contentless kernel sink read/written
  across the corpus; identity-only, nothing to digest
- [x] 4.4 Self-created temp scratch: paths the test process itself creates
  under the ephemeral root (t.TempDir randomized names) observed as moved
  inputs every run; classify creation-observed scratch as non-input
- [x] 4.5 Residue disposition: PWD process-local env reads and /home
  external-directory inputs — eliminate, admit, or accept as genuine
- [ ] 5. Observability audit: toolchain accessors (runtime.GOROOT class) in
  the observability analyzer's proof leg; the dynamic-behavior and
  os.ReadFile proof refusals, the purity-suppression-vs-proof-leg
  interaction, and the /home external-directory MkdirAll-ancestor class
  fold in here
- [ ] 6. Refined-batch load-failure coupling
- [ ] 7. dependency-heavy-refinement-precision: disposition (implement or
  redefer with a sharpened trigger)
- [ ] 8. Close-out gate: full suite, release, downstream re-measure
  (stipulator serving check over gofresh; gomutant bump unblocked)
