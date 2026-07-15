# Completeness lift: assertion-vouched unverifiability needs subject-tier observability

Lands: 4 of `docs/plans/observation-completeness-proof.md`.

The idea: a caller-owned completeness assertion — "the producing
harness observed every file and environment read of the subject's
process" — recorded beside the purity assertion, lifting closure
unverifiability when the engine proves every dependence the subject
can reach is one the harness logs, with the runtime-input guard as
the working protection. REQ-inputs-evidence-not-proof leaves the door
open ("absent an explicit completeness proof").

Consumer pressure is currently relieved without engine change:
per-subject `//gofresh:pure` directives (REQ-purity-directive) give a
caller-responsible opt-in whose hashable guards all stay active. The
lift's remaining value is replacing that author trust with engine
proof.

## Status: two designs down, obligations sharpened

A full implementation was built and withdrawn (design 1, adversarial
review). A maximal-tier redesign was then attacked on paper and
refuted before implementation (design 2). What follows is the
surviving structure and the obligations those reviews exposed; the
canonical specs now carry the settled contract. The reviews' verdict
converged: **observability is a call-graph-tier property.** No
syntactic maximal-tier scan can carry the proof alone; the maximal
tier can at most fail closed.

### Survives (use in any future design)

- **Observability as a separate, complete, fail-closed conjunction** —
  never derived from the selected unverifiability reason (design 1's
  existence-scan shadowing is what killed it). Every selected file of
  every non-standard closure package walked to the end; any
  unclassified selector on an external-capable package, dot-import,
  non-audited std import, cgo/`.s`/`.syso`, `//go:linkname`,
  `//go:wasmimport`, or process spawn ⇒ not observable.
- **Recompute-never-inherit across closure drift**: unchanged maximal
  hash keeps a recorded disposition (the hash covers selected file
  contents, `.s`/`.syso`/embed presence, pinned-dep versions, and
  REQ-guard-buildconfig pins env-driven selection); on drift the
  granting tier recomputes in the current view; unrecognized evidence
  conservatively clears.
- **Typed classification keyed (package, symbol), pinned against real
  producer strings** — never substring matching over prose reasons.
- **Laundering exclusion**: `os.Rename`/`Link`/`Symlink` and syscall
  equivalents transport unobserved bytes onto observed identities;
  never admissible at any tier.

### Refuted false-valid channels (each is a named obligation)

1. **Init-time reads.** `StartTestLog` begins in `testing.M.before`,
   after every package `init` and any pre-`m.Run` TestMain code. A
   `var mode = os.Getenv(...)` or init-time `os.ReadFile` passes any
   symbol table yet records no identity: env/testdata are not source,
   so every guard holds across a change. No maximal-tier discharge
   exists; reads reachable only from init need call-graph evidence.
   Like direct syscalls and foreign code, this is an engine-proved
   exclusion rather than a caller-asserted exception.
2. **Mutation return values are unlogged existence probes.** No
   mutation op calls testlog. `os.Mkdir` → EEXIST, `os.Remove` →
   ENOENT are unobserved reads of filesystem state a test can branch
   on; the probed path may lie outside both source and manifest.
   "Cannot transport unobserved bytes" is true and insufficient.
3. **Remove/RemoveAll destructively consume logged inputs.** Read
   pre-existing F (logged), remove it; finalization digests
   "missing", check sees "missing" → valid, while F's consumed bytes
   shaped the verdict. Fresh-by-construction holds only for
   run-created paths — a path-value property, call-graph-tier again.
4. **OpenFile is flag-blind at symbol granularity.** Read-only vs
   O_RDWR|O_TRUNC is a value, not a symbol; admitting it opens the
   read-modify-write masking channel. Symbol-keyed tables must reject
   it; only dataflow on the flags argument can admit it.
5. **`os.Environ` is not testlog-hooked** (it calls
   `syscall.Environ` directly). Any admitted-set claim must be
   re-verified against the actual hook set — open, stat, chdir,
   getenv — per toolchain version, as contract.
6. **Lexical identity resolution across symlinks.** Manifest path
   identities are cleaned lexically; the kernel resolves symlinks
   before `..`, so `link/../x` digests the wrong file. Harmless
   today (such subjects stay unverifiable); validity-bearing under a
   lift. Any lift must resolve identities physically or refuse `..`
   traversals it cannot prove symlink-free.
7. **Identity records do not capture operation outcomes.** Testlog
   records a path, not the bytes returned, byte count, or error. A
   transient short read or `EIO` can shape a cached result while
   finalization later hashes unchanged bytes. Identity-only evidence
   therefore cannot establish completeness: every behavior-affecting
   outcome must agree with the guarded value, or the process
   observation is incomplete.

Consequence for the subject-tier admitted set: it contains only logged
value-bounded read operations — open (read-only provably, so not
OpenFile), ReadFile, sorted ReadDir, Getenv, and LookupEnv — with
complete outcome evidence and **no metadata or mutation class at
all**. The maximal tier only rejects; `testing.TempDir`-idiom suites
are served only by the refined-tier extension below.

### Specification obligations (beyond the channels)

- **Enumerate suppressible manifest-unverifiability reasons.** The
  settled set is empty: malformed or unrecognized records,
  incomplete processes, metadata-only observations, ambiguous or
  unhashable identities, external directories, and symlink targets
  all remain blocking.
- **Version the observability disposition** (as
  `gofresh/declaration-rta@1` versions refinement): an engine fix to
  the class analysis must invalidate recorded dispositions computed
  under the buggy analysis even when the maximal hash is unchanged;
  "conservatively clear unrecognized evidence" is unenforceable
  without a recorded identity to fail to recognize.
- **Child-observation merge needs termination and outcome gates**: a
  child log truncated at a line boundary is indistinguishable from
  complete, and identity records do not vouch for operation results;
  the caller must attach exactly one completed or incomplete
  observation for every contributing process.
- **Method-set audit rule**: every method of every type reachable
  from an admitted symbol's results must itself be observable or
  effect-free; metadata, mutation, descriptor escape, and unknown
  methods block even when the originating handle is read-only.
- **Exec blocks unconditionally** at every tier. Child observations
  can complete the child's runtime manifest but cannot guard the
  parent-visible spawn, status, signal, or communication outcome.
- Amend REQ-inputs-evidence-not-proof to license the recorded
  assertion+proof pair and say which word governs; the class table
  and the actual testlog hook set become contract.

### The realistic shape of attempt three

Declaration-RTA (whole-program SSA, init roots already required by
REQ-closure-analysis) computing: reachability of any I/O from init
paths (obligation 1), path-value freshness for the mutation and
OpenFile classes (obligations 2–4), with the maximal tier
contributing only the fail-closed negative scan. That is per-subject
analysis cost — the Lands condition — and it should be designed
against this obligation list from the start, not arrived at by
shrinking another optimistic table.
