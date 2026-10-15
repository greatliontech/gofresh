# Cross-tool train: correctness, speed, caching, UX

The retained obligation inventory across gofresh, gomutant, stipulator,
and pew. The active roadmap is [tooling-redesign.md](tooling-redesign.md);
its accepted architecture and execution sequence govern this inventory.
Each landing runs through independent review; shared releases precede
consumer adoption. WIP = 1 across the tooling work. Numbers here remain
stable identities for existing obligations, not a second execution order.
Chunk numbers are stable identifiers, never
order; chunks 1–102 are landed or listed below — landed chunks live in
git history (`git log --all -- docs/plans/cross-tool-train.md` recovers
every close-out), and numbering continues from where they left off.

Replanned 2026-08-26 (user-confirmed): the train subsumes the
startup-effect-precision plan (its open chunks fold in below; that file
is deleted, history in git) and absorbs the standing-guard program.
The focus axes are **correctness, speed, caching, UX** — every chunk
names its axis. Capability charters (work activated by a future need,
not schedulable now) live OUTSIDE the train in
docs/plans/capability-charters.md; everything else slots into a
numbered chunk — no condition-parked `Lands:` survives outside the
register.

## Standing doctrine

- **Evidence tools have scoped authority.** Select verification per change
  and the instrument's actual execution path, version and known limitations.
  A green answer from a known-defective path is not diligence; an unaffected
  path of the same tool may still provide useful evidence. This takes
  precedence over the retained command recipes below: preserve the proof
  obligation, choose a suitable independent or direct check, and record the
  limitation rather than treating a tool invocation as the obligation itself.
  The early negative-coverage cutoff and existing authorization limits still
  apply; this is no permission to weaken assertions, omit deciding oracles,
  or launch unapproved broad witness runs or campaigns.

- **Field-response protocol.** A field defect gets a numbered chunk in
  the session that diagnoses it, band stated (blocking-a-user /
  current-arc / tail); visit-shaped work outside the train is retired.
  The weekly health sweep (chunk 109) is the standing producer of
  field reports; sessions should stop discovering breakage by
  tripping on it.
- **MCP UX doctrine** (user ruling 2026-08-26, sharpening the chunk-41
  principle): the MCP surface serves an LLM in a harness, and its
  verbosity budget is spent on usefulness — the minimum strings/tokens
  that keep the model ON POINT, not merely cheap. Every refusal or
  verdict carries its actionable next step (a suggestion) when one is
  derivable. CLI output serves a human and may differ; the MCP surface
  outranks it. Every chunk touching a surface is audited against this.
- **Tool-resident guidance** (user ruling 2026-08-26): an LLM must not
  need to read a tool's source to learn what a verb does, what a knob
  controls, or when to use which — the tool itself answers those,
  over both surfaces, derived from the specs the repos already carry
  (single source, never hand-duplicated prose). Chunk 111 designs the
  mechanism; every later surface chunk conforms.
- **No wasted work** (user ruling 2026-09-02, binding on every open
  chunk and on the loop that lands them): every operation is staged
  as fail-early preparation, then an incremental measure loop.
  Preparation is the cheap pass that derives every refusal decidable
  from its inputs — a surface that cannot be pinned, an oracle that
  cannot compile, a declaration that cannot resolve, a record that
  cannot be written — and exits before any measurement runs; a
  refusal that could have been derived at preparation and surfaces
  after measurement is a defect, filed like any other. The loop then
  runs per unit: check freshness (serve what is proven), measure only
  what is not, persist before the next unit starts, repeat — so an
  interruption loses one unit, never a run. The unit is a coherent
  VERTICAL — one slice carried from freshness through measurement to
  persisted evidence before the next slice is touched — and the whole
  of an operation (every symbol resolved, every subject captured,
  every proof proven) is never computed up front when the slice can
  carry its own share; "committed evidence first" is the test of
  conformance. Gomutant's unit is the target within its confirmation
  window, Stipulator's the package under its covering invocation, and
  Pew's the measured arm. Retried executions and bounded post-process
  evidence finalization obey the same durability rule. Gofresh supplies
  the consumer-selected view and its analysis budget; a static sharing
  unit is not automatically a persistence barrier for unrelated results.
  These are obligations, not declarations that every path conforms.
  The pending publication and interruption corrections are numbered in
  the active sequence below. The same rule governs
  this train's own gates: a long measurement runs once, over the
  settled tree, after the loop converges; a measurement started
  before its inputs settle is wasted work, not diligence. A
  verification whose cost is itself the defect under repair — the
  stipulator check's serial per-witness spawn, 1h47m over gofresh at
  chunk 154, chunk 155's target — runs once per chunk over the
  released tree, its verdict recorded in the closing commit; the
  change sets inside the chunk gate on the fast tier, the ephemeral
  probes, and the full tier. Band P is the application; chunk 136's
  scan walks what it leaves.
- **Two surfaces, derived defaults** (user ruling 2026-09-02, sharpening
  the MCP UX doctrine): the CLI serves a human at a terminal and the
  MCP surface serves an LLM in a harness — different inputs, different
  outputs, different token economics — and each is designed for its
  reader, never one rendered through the other. Output is minimal and
  useful: on MCP, the fewest tokens that keep the model on point (the
  verdict, the counts that change what it does next, the actionable
  rows, the suggestion) and nothing decorative; on the CLI, what a
  human needs to act, no more. Per tool, per verb, the DEFAULT
  behaviour, output, and every default value is DERIVED and recorded —
  from the verb's purpose and the surface's reader, never inherited
  from the other surface or from the first implementation — and
  everything else is opt-in with a stated purpose (a knob or view that
  cannot state its purpose is deleted). Each Band P chunk lands that
  derivation as a table in the tool's spec (verb × surface: default
  behaviour, default output, defaults, opt-ins with purpose) and
  conforms the surfaces to it.
- **The MCP surface is self-starting** (same ruling): an LLM connecting
  to a tool must know from the surface alone what to call first, what
  the ordinary loop is, and which verb answers which question — the
  server instructions name the entry call and the loop concretely
  ("start with X over the tree; then Y; Z answers why"), every tool
  description says when to use it and what it returns, and `guidance`
  serves the rest from the embedded document (chunk 111's mechanism)
  — so the model never improvises a call sequence and is never sent to
  read the repo. A surface that needs its source read to be used is a
  defect; Band P's per-tool chunks land the entry guidance and a test
  that pins it derives from the spec.

- **One tooling owner.** Gofresh, gomutant, stipulator and pew follow
  the single sequence below. Pew's docs/plans/performance-evidence.md
  remains the completion checklist for its performance workflow, not a
  second execution lane. Fetch all four tool repositories and the active
  shared-workflow/toolchain prerequisite repositories at every chunk open,
  before pushing, and at every chunk close. During long work, fetch again
  at review returns and long-run/CI completion checkpoints. Inspect incoming
  issue changes and disposition them against the active roadmap; fetching
  alone is not triage. At these checkpoints, review and commit completed
  same-machine field-agent issue documents and their index entries too, with
  their `Lands:` routed into the roadmap, then push them. An entry in the
  obligation map does not publish an uncommitted report. Preserve the report's
  evidence limitations and conditional scope; committing a filing is not
  verification of its hypothesis or authorization to implement its request.
  Re-derive contracts across incoming code changes before
  continuing in the affected repository. A fetch updates remote references,
  not an observing run's worktree: integrate only at a safe stopped boundary,
  never by auto-stashing or overwriting another actor's dirty work. Where
  integration cannot yet occur, inspect the remote documents directly and
  retain their obligations in the map rather than silently losing the report.
  Preserve migration checkpoints, WIP branches and dirty worktrees until
  their contents have been individually reconciled and verified. Git-go
  is outside this roadmap; godst and go-x-tools changes are prerequisites
  only where a demonstrated tooling fault requires them.
- **The shared evidence boundary is canonical.** Gofresh's overview and
  runtime-input specs and Pew's native-envelope contract govern process
  completion, outcome support, fingerprint serialization, applicability,
  attachment and validation. Published implementations, checkpointed work
  and proposals are distinct. No merge upgrades historical evidence,
  grants outcome support from healthy execution, or replaces producer
  validation with a later reconstruction. A producer change releases
  before consumer adoption; each consumer retains its own execution-model
  obligations.

- **Cross-session filings are triage inputs.** An issue filed into
  the train by another session carries `Lands: awaiting triage`; the
  next chunk-open gate slots it (a chunk of this plan or a checkable
  condition) or records a genuine fork as `Lands: user decision` with
  its arms stated. A `Lands: user decision` the train's own session
  writes must name the judgment the user owns; a derivable design is
  slotted, never parked (ruling 2026-09-09).

- **Standing rule — the re-audit band (ruling 2026-09-09).** The
  per-chunk consolidation scan sees only what a chunk touched, so
  cross-subsystem drift accumulates unseen while chunks fix and bolt
  on. A re-audit band therefore runs at every band close or after
  every twelve landed chunks, whichever comes first, and is never
  deferred to the train's end: one audit chunk per repo (gofresh,
  gomutant, stipulator, pew), read-only, fresh reviewers reading
  whole subsystems against the specs — duplicated mechanisms,
  parallel abstractions at the wrong altitude, vestigial scaffolding,
  two code concepts where the spec has one, spec clauses that no
  longer describe the emergent shape — with every candidate
  dispositioned as a chartered consolidation chunk or a recorded
  dispute, and the queued chunks re-sequenced under the emergent
  shape (some merge, some dissolve). The audit's output is a replan,
  never a fix. The chunk-open gate counts landed chunks since the
  last audit; reaching twelve opens the band ahead of whatever is
  queued. The first band (194–197) closed 2026-09-09; the count of
  landed chunks since the last audit restarts at zero from there.

## Execution order

The active sequence is [tooling-redesign.md](tooling-redesign.md). The
numbered charters below retain the prior audit's obligations and must be
mapped to that sequence before implementation, not executed as a parallel
train. The approved controls and architecture replace mechanisms proposed
here where they differ; historical evidence and unfinished work stay tracked.

- [x] 339. Reconcile the four current implementations, migration
      checkpoints, contracts, history and field reports; independently
      audit reuse soundness, package/arm/target durability, analysis cost
      and both reader surfaces; derive one execution sequence without
      treating a field timing as a reproduced fault or a checkpoint as
      completed work. Preserve every remaining numbered obligation below.
      Each numbered implementation entry has its own regression, review
      and landing boundary and counts once toward the standing twelve-chunk
      re-audit rule; an intervening re-audit takes precedence over the
      displayed sequence.
- [x] 340. gofresh: make content-audit admission a complete input to
      cached and recorded evidence. Pin the same-version changed-GOROOT
      case across fresh and memo-served analysis and historical observed
      checks; couple dependent scopes and compatibility to the admitted
      surface without allowing an old proof to suppress a current audit
      refusal. Settle the contract and invalidation rules first,
      then review and release before consumer adoption; this owns the
      correctness opening of 203, not its unrelated memo cleanup.
- [x] 341. gofresh: preserve budget-cut provenance through sibling
      projection and validation. Pin cut-first/complete-second parent
      construction followed by sibling validation over the unchanged
      tree, and retain real-drift precedence. Release the correction.
- [x] 342. stipulator: resolve under the complete declared selection,
      including module mode and an explicit toolchain without tags.
      Align selection construction, keys, loading and precedence with
      the contract, adopting 340/341 first; fold this portion of 226.
- [x] 343. stipulator: use the longest declared import path for dotted
      package identities in discovery, resolution, capture and publication;
      retain the external symbol grammar and fold this portion of 249.
- [x] 344. stipulator: make cached resolution certificates cover the
      selection-local and policy-wide facts their answers depend on.
      Preserve cross-selection seeding, first-declaring-view precedence
      and classifier identity across cache hits and upgrades. Pin edits
      confined to another selected view and introduction of an earlier
      declaring view; refuse old records lacking the required evidence.
- [ ] 345. stipulator: keep ambiguous binary arguments identity-bearing.
      Active destination: tooling-redesign **5.3**; constituent 7.4.
      Pin timeout-looking custom values, positionals after `--`, unknown
      forms and ordinary timeout controls. Discharge only proven active
      budget tokens; reconcile typed/raw repetition and its record identity.
- [ ] 346. stipulator: preserve clause scope through supersede or refuse
      an unresolvable carry. Active destination: tooling-redesign **5.3**.
      Include resolved clause identity in duplicate detection; pin labels,
      ordinals, missing/colliding clauses, multiple successors and whole
      contrasts. Ordinary retarget's repair does not fix supersede.
- [ ] 347. gofresh: reconcile the locality portion of
      checkpoint 5bf9023. Active destination: tooling-redesign **6.1**;
      constituent 6.2. Re-derive mixed validation, independent siblings,
      discharge rejection and missing-attachment ordering against live
      identities, not reserved strategy literals. Reconcile bindings and
      generated controls; locality alone grants no candidate non-influence.
      Preserve the checkpoint until independently verified integration.
- [ ] 348. gofresh: separately reconcile checkpoint 5bf9023's record-only
      support validation. Active destination: tooling-redesign **8.1**.
      Preserve original producing identity and trust class; perform no
      current observation or authenticity inference. Distinguish recognized
      compatibility from current-strategy equality, reject malformed or
      unsupported records, and complete bindings and independent controls.
- [ ] 349. gomutant: require sound negative-coverage authority before
      any omission. Active destination: tooling-redesign **6.2**;
      constituents 6.1 and 9.1. Preserve landed full-oracle admission and
      historical cutoffs; independently establish complete harness/locality
      and candidate-influence premises, including child execution, runtime
      environment and compile-time influence. Unknown negatives run the
      full oracle; retain the arithmetic positive and sampling limit.
      Recover affected historical populations for authorized remeasurement;
      neither old banks nor the removed scheduler confer authority.
- [x] 350. pew: derive requested profile obligations from the benchmark
      inventory, including benchmarks absent on both recording sides.
      Pin one fulfilled diagnostic beside an unrecorded requested benchmark
      on both renderers and the command's exit classification.
- [x] 351. pew: carry a successfully completed timed process into its
      bounded finalization gate before observation ingestion. Pin
      cancellation after successful execution, genuine incomplete execution
      and finalization drift; preserve earlier arms.
- [x] 352. pew: judge A/B stream names against the requested declarations,
      not names supplied by the stream. Pin an unselected well-formed row
      beside the selected result without dropping valid sub-benchmarks.
- [x] 353. pew: reconcile checkpoint 1f8df13, retain its native positive
      controls and stated non-OS-exit limit, bind the generated premise
      witness as the required evidence class and converge independent
      review. Do not close the property gap on file presence alone.
- [ ] 354. gomutant: remove best-effort instability attribution from the
      path blocking other measured targets' commits. Active destination:
      tooling-redesign **6.3**; constituent 7.2. Expose test/repeat/completed
      progress, preserve partial work and distinguish unknown/failed from
      stable. Callback presence and explicit/derived oracle provenance
      cannot silently commission or suppress advisory execution.
- [ ] 355. gomutant: close a measured window after its own validation and
      confirmation. Active destination: tooling-redesign **6.4**.
      Pin a completed window beside blocked successor preparation; preserve
      drift refusal and deterministic tree/order/worker membership. Exercise
      real run wiring at both candidate and execution-bound cliffs.
- [ ] 356. gomutant: give passing baselines independently validated durable
      deposits. Active destination: tooling-redesign **6.5**. Establish each
      deposit's complete producing evidence and closing validation, then
      serialize shared-tree bank merges across different findings documents.
      Pin restart before any finding and concurrent deposits; pre-baseline
      proof rows alone are insufficient and old coverage banks stay retired.
- [ ] 357. stipulator: use the package completion path for drift retries
      as well as first executions. Active destination: tooling-redesign
      **5.3**. Preserve completed packages across a later retry's cancellation
      through the existing package publication boundary, not a second protocol.
- [ ] 358. stipulator: keep race/plain attribution on each served group
      record. Active destination: tooling-redesign **5.3**. Pin one subject
      serving from both admitted tiers and preserve each grant in correlation.
- [ ] 359. stipulator: preserve resolution and witness publication
      accounts on errors. Active destination: tooling-redesign **5.3**;
      constituents 7.5 and 8.3. Quiesce already publishes and releases the
      resolver; retain its notices through later RunTests errors and
      cancellation, distinguishing durable records from incomplete work.
- [ ] 360. Measure the remaining preparation barriers on the
      current trees. Active destination: tooling-redesign **7.7**;
      constituent 7.8. Attribute cold/warm loading, SSA, digests, validation,
      first durable result, interruption loss and served fraction over equal
      completed populations. Separate retained RSS from peaks, parent from
      children and pre-exec inheritance from driver/build/test needs. Existing
      program release, resolver quiescence and shared admission are controls,
      not missing mechanisms. Collection targets are not physical room;
      exit 137 alone is no OOM diagnosis. Change ownership only from evidence.
- [ ] 361. gofresh: settle cancellation ownership for observation
      composition and revalidation. Active destination: tooling-redesign
      **5.5**. Cover FromState, adoption, conversion and merge without hidden
      background continuation; preserve guard semantics, bounded checks and
      independent opening/closing observations. Existing owned finalization
      stays intact; loader containment is a separate constituent of 241/238.
- [ ] 362. gomutant: keep cumulative counters through audit events,
      final merge and rendering. Active destination: tooling-redesign **6.7**.
      Non-candidate events cannot reset counters; expiry and post-write errors
      preserve committed typed rows, run/root identity, layer counts and an
      incomplete-render account. Coordinate with bounded recovery in 233.
- [ ] 363. stipulator: share one live evaluation across requested
      projections. Active destination: tooling-redesign **7.5**. Make
      evaluation explicit and inspections non-measuring; keep acceptance,
      execution and report scopes distinct. Missing/NoOutcome/partial facts
      neither grant a pass nor permit evidence-based deletion; retain
      invocation identity and prohibit persisted verdicts as evidence inputs.
- [ ] 364. pew: reconcile entry guidance, exit classifications and the
      enforcing workflow. Active destination: tooling-redesign **7.6**;
      constituent 8.3. Implement complete/require/compatible enforcing
      defaults, preserving informational comparison, explicit partial scope,
      requested metrics and exit precedence. Derive confidence from alpha
      unless a concrete independent workflow justifies its separate control;
      new machine-reader forms require actual unmet reader needs.
- [ ] 365. Settle the historical-floor policy without presenting an
      empirical envelope as harmless noise. Active destination:
      tooling-redesign **8.2**; constituents 8.1 and 7.6. Report admitted
      variation with population, lineage, conditions, candidate overlap and
      missing history/support visible. Use record-only native support checks
      and explicit tolerances; never automatically raise a threshold from
      historical spread or turn an insufficient history into a safe floor.
- [ ] 366. Finish Pew performance-evidence 11.3 and 12 on the settled
      tree. Active destination: tooling-redesign **9.1**; constituents
      9.2, 9.3 and 9.4, after 6.6/6.7. Recover every target/candidate
      population, missing run ID and excluded delta in Pew's
      docs/issues/mutation-oracle-observation.md: a41d8ee, 1e11674dc9cefba4,
      e8423761e551fb96, the twelve distinct hand probes, the
      newStatCmd/validateOptions/Compare run, 82f26be60d13cf04, the JSON
      run, a6d4f75aaf58cae4 and 9eeabef27df54358. Renames and removals
      need explicit obligation mappings; today's changed scope is no
      substitute. The native producer-premise property already landed;
      extend its evidence rather than repeat it. Final measurement requires
      explicit authorization and complete deciding oracles; partial history
      grants no completion. Settle formats, guidance and descriptive history,
      reconcile all retained obligations, then retire resolving artifacts
      and install clean tools. No reserved version or automatic floor applies.

Standing rule from the ruling (restated 2026-09-07, binding on every
chunk): the tools' self-checks — `stipulator check` over a repo and
gomutant campaigns — are NOT part of a chunk's fix workflow and do
not run at a chunk's close. They run only at these named points: (1)
none before a release — a release's gate is CI's plain, race and
records tiers on the pushed commit, the tag waiting for them (amended
2026-10-02; the local self-check is no longer a release's
precondition), the tiers one reusable workflow in
greatliontech/actions every repository calls with its own inputs —
its toolchain pinned to a listed release, never `stable` — so a
change to the gate's contract lands in every repository at once
(2026-10-06, chunk 325); (2) at a band's close, over the settled tree; (3) where
a chunk's charter names its own self-host verdict (141, 155 — and
175's close, where the closure identity becomes subject-scoped and a
gofresh check turns warm); (4) on the fleet sweep's schedule, in idle
windows. A chunk's close-out evidence is the full `go test` tier
(never the -short tier alone) plus the ephemeral probes of its review
rounds. Between named points the check is not run even when cheap;
running it "because the tree settled" was the waste the ruling ends.
Ratified 2026-09-29 (promoted from the two deleted campaign docs,
gomutant own-face-gate-suite-decomposition and stipulator
train-114-campaign-idle-window): a full-face campaign over a
suite-class oracle — gomutant's own face, stipulator's `--changed`
sweeps — is not run as a measurement and suite decomposition is not
chartered; the gate is the probes, the measured pace (148 of 11,867
candidates in 7h26m, ~537 h projected; ~217 h on gomutant's face)
makes the campaign worthless as an instrument, and a decomposition
has no correctness driver.
Ratified at Band R4 (audit 285 A17, 2026-09-29), amended 2026-10-02
(operator: the gate must not carry the shared machine's hour): a
release is gated in CI, not by a pre-push self-check — the release
workflow cuts a tag only after the CI workflow succeeded on the pushed
commit: the plain tier, a race tier over the whole tree (the policy's
own race selection — run as shards whose `-run` regexes partition the
tree's tests, each Test, Example and Fuzz function in exactly one,
the partition pinned in the tree; the shards together are the tier),
and a RECORDS tier (the corpus compiles; every
binding resolves to a current symbol at a consented pin — 289's
dangling binding and deleted proof are exactly what it names; the gap
and attestation pins stay consented locally by `stipulator pin` and
judged by the full self-check at its named points), so no release
stands on a red or unrun tier and the gate cannot be skipped on the
automated path (a manual tag is outside it); the release lands on the
judged commit itself, serialized, a superseded commit releasing
nothing; the next-rc leg is an early warning in its own workflow,
never a release blocker. The committer still runs the same records
checks locally before a push — the same view through a released
stipulator in CI and the development binary locally, a format move
between them a red job, the safe direction; stipulator's own gate
builds it from the tree, since a pinned release could not read a
format move the tree makes — and the change sets' own test tiers
stand as always. The full self-check
(witness freshness, serving evidence, the race tier under the owned
environment) runs at band closes and on the fleet sweep's schedule, in
idle windows, never as a release's precondition. gofresh carries the
CI gate from 281's close; gomutant, stipulator and pew adopt the same
release/CI shape at their next chunk. Between named points a commit
that deletes or renames a symbol runs the records-only bindings view,
and a commit that amends a clause runs a scoped pass over the amended
requirements — seconds, never the self-check.

Previous order (user-confirmed 2026-08-26, kept for the field band's
relative sequence): 103, 107, 83, 108, 82, 94, 109, 110, 105,
126, 93, 106, then the UX pair 111, 112, then 128, 113, 114, 141, 138, 140, 115, then
— amended 2026-08-27 under the field-response doctrine (bldc campaign
reports): 132 inserted after 83 (coverage integrity; lands before
108 so the canary corpus includes the shapes it fixes), 133 inserted
after 110 (same artifact, the findings document), 134 inserted after
133 (chartered 2026-08-27: enforcement pointers become bindings), 135
inserted after 109 (field-response: the sweep's first report — gofresh
own-estate red), and — amended 2026-09-03 under the same doctrine
(consumer-observed reports) — 138 inserted after 114 (workspace
path-resolution defect with findings-integrity fallout) and 139
inserted after 130 (delta-line survivor view; beside the carry gate's
records work); and — amended 2026-09-03, same doctrine, the bldc
fourteen-report batch — 141 inserted after 114 (verdict/serving
integrity outranks diagnostics), 140 after 138 (ephemeral probe
integrity, our own loop's tooling), and the stipulator band 142–145
after 131, with gap-covered-unknown-id folding into 114's gap fold —
and — amended 2026-09-02, same doctrine, a field report on
staged campaigns — 146 inserted after 138 (the staged snapshot's
external-input refusal, beside 138's bracket declarations) — then
91, 92, 96, then 129, 130, 139, 131, then the bldc stipulator band 142, 143, 144, 145 in that order, then the precision/discharge band
116–125 and 98–101 (with their recorded rides) in field-mass order at
triage, then the 125 histogram's charters 179–181 in that order (their
recorded field mass), then 182 (chartered from the 180 re-measurement), then Band F 158–178 in its listed order with 183 directly after 170 (triage 2026-09-09), the re-audit band 194–197 directly after 183 (its replan re-sequences everything below), and 184–193 after 178 (175 is a design chunk opening with the user); gofresh's order after audit 332 (2026-10-07): 315 (the machine walk with 297's corpus; the std digests memoized; a release) → 338 (godst: the test-log writer propagates write errors; a build; the dst rows re-listed — a gofresh release) → 330 (godst's caller frame; a godst release, then gofresh's; after the evidence-model plan's 5.2) → 240 → 241 → 260 → 203 → 204 → 206 → 255 → [held by the evidence-model owner: 314, 202] → 191 (a release, after their 5.3) → 295 (after their outcome capability) → 192 → 193 → 242 and 243 together → 175 → 102; 297 merged into 315; 303 closed by verdict; 199 dissolved; gomutant's order after audit 333 (2026-10-07): 336 (the gate red: fixture git maintenance, the guard's walk scope) → 324 (the v0.111.x bump with everything it absorbs) → 302 → 187 (reported first) → 313 → 269 (reported at open) → 209 → 268 → 267 → 258 → 245 → 212 → 216 → 218 → 217 → 220 → 214 (after gofresh 240) → 219 → 254 → 296 → 256 → 188 → 233 → 294 → 95 last when its SDK prerequisite lands; 284 dissolved (its campaign half 302's close); 210 dissolved (done at 246/278); stipulator's order after audit 334 (2026-10-07): 337 (conformance: the owned roots probe, every reason classed, the served instructions) → 331 (the admission: origin attribution, every slot-spawned process registered, the cold build measured; 322 merged) → 290r (the v0.111.x bump with the restored riders and the snapshot fold; 184 merged) → 270 (before the evidence-model plan's 6.1, its owner told) → 226 → 249 → 185 → 225 and 248 together → 228 → 176 → 238 (behind gofresh 241); 97 un-chartered; pew's current route is its performance-evidence plan chunks 5–12 (1–4 landed on the other machine: the compare fix, the gofresh adoption, the recovery store, the shared evidence contract); after that plan closes, 320 (narrowed) → 252r → 232r → 276r; 173 dissolved (landed at 275.C); THE CROSS-REPO LANE after the sixth re-audit band (332–335, closed 2026-10-07; the audit count restarts at zero): soundness and conformance first, a producer's release before the consumer bump that reads it, pew's slots via the other machine's performance-evidence plan, the evidence-model boundary held there (gofresh 202 and 314 held; 191, 295, 330, 102, 175, 260, 240's projection item, stipulator 337's roots probe, gomutant 187 and 269 reported to its owner before implementing), design chunks autonomous, 95 last — gomutant 336 (the gate red) → stipulator 337 (conformance) → stipulator 331 (the admission; 322 merged) → gomutant 324 (the v0.111.x bump) → stipulator 290r (the v0.111.x bump; 184 merged) → stipulator 270 (before the plan's 6.1 opens; its owner told) → gofresh 315 (release) → godst 338 (the fork's writer fix, a build, the dst rows re-listed; a gofresh release) → gomutant 302 → stipulator 226 → gofresh 330 (after the plan's 5.2; godst first) → gomutant 187 → stipulator 249 → gofresh 240 → gomutant 313 → stipulator 185 → gofresh 241 → gomutant 269 → stipulator 225+248 → gofresh 260 → gomutant 209 → stipulator 228 → gofresh 203 → gomutant 268 → stipulator 176 → gofresh 204 → gomutant 267 → stipulator 238 (behind gofresh 241) → gofresh 206 → gomutant 258 → gofresh 255 → gomutant 245 → [pew: via performance-evidence chunks 5–6 (gofresh's shared outcome-support release by the other machine, then the gomutant/stipulator/pew adapters — train sessions hold off those adapter files while 6 runs)] → gomutant 212 → 216 → 218 → 217 → 220 → 214 (after gofresh 240) → 219 → [pew: via performance-evidence chunks 7–8] → gofresh 191 (release, after the plan's 5.3) → 295 (after its outcome capability) → 192 → 193 (after 202) → 242+243 → 175 → 102 (after the plan's 5.3) → gomutant 254, 296, 256, 188, 233, 294 → [pew: via performance-evidence chunks 9–12]; gofresh 202 and 314 when the evidence-model owner releases them; after performance-evidence closes, pew 320 → 252r → 232r → 276r; 95 last
(ecosystem-blocked, re-audited at open), with the
design chunks 15 (102 inside it), 97, and 127 opening with the user
and scheduled at the user's convenience.

**CI doctrine** (chunk 107's review, binding on 108+): a
workspace repo's "full suite" is the module-path pattern
(`github.com/greatliontech/<repo>/...`), never `./...` — `./...`
silently drops workspace members. A CI budget states its
measurement host, date, AND toolchain — the dev fleet's default go
is the godst fork, and a fork-hosted timing is not evidence about
upstream stable (measured 2026-08-27 at n=1 per arm: stock go1.27.0
-2.1..-4.4% on the three long suites, +19% on pew's 83-second arm —
noise-class at that length; the budgets carry the stock numbers);
runner-class factors are measured, not assumed
(core count probed 2026-08-27: ~1.04x on the dominant child-process
workloads, godst-hosted; cold cache lands on the job ceiling).

## Band T — self-test partition (the tools' code testable without the tools)

Audit evidence: docs/plans/pipeline-audit/*.md §6. Every repo's plain
suite is one package of fixture-driven executions (gofresh `closure`
544s of 555s; gomutant root 966s of 971s; stipulator
`internal/backends/golang` 1327s of 1333s; pew `cmd/pew` 83s of 84s),
and the `-short` partition that would give a seconds-class tier is
latent (stipulator 96 gates, gomutant 179 gates — nothing passes
`-short`) or absent (gofresh 0, pew 1). Each chunk below lands the
partition, the task-runner target, and the CI seat; no production
code moves.

- [x] 150. gofresh: self-test partition — `testing.Short()` gates on
      every temp-module / `closure/fixtures/` / SSA-building test
      (~500 of ~640), the pure tier (verdict ladder, guard
      comparison, provenance core, guidance, internal/*) as the
      default `go test -short ./...` in seconds; the memo cache
      isolated from the user's real cache per package run (verified
      already so — `TestMain` in root and closure; the audit's
      contrary claim corrected) and per test wherever a test asserts
      memo state; `t.Parallel()` on the child-process-bound
      fixture tier; a Taskfile with `test:short`, `test`, `vet`
      (gofresh is the one repo without one — folds the Taskfile half of
      `git log --all -- docs/issues/reusable-ci-workflow.md`); CI runs
      the full tier at its measured budget. Measurement: none.
- [x] 151. gomutant: self-test partition — `task test:short`
      (`go test -short ./...`, the 179 existing gates: ~436 of 615
      tests, no subprocess), `task test` unchanged as the merge gate,
      `task test:selfhost-plan` (`gomutant run --plan --targets
      testdata/self-host-targets.json` — the only cheap way to keep
      the self-host path from bit-rotting; made genuinely cheap and
      complete by 156); the stale `findings.json.campaign` /
      `.lock` residue removed. Measurement: none.
- [x] 152. stipulator: self-test partition — finish the `Short()`
      gating in `internal/backends/golang` (245 tests, ~64 gates) so
      `go test -short ./...` is the seconds-class tier; `task
      test:short`; CI keeps the full tier; the dangling CI-seat
      pointer (`.github/workflows/ci.yaml:39` cites a
      nonexistent CI-seat issue; current home: this plan's Standing doctrine)
      resolved — the check verdict's seat is the weekly sweep and the
      chunk close-out, stated where the pointer was. Measurement:
      none.
- [x] 153. pew: self-test partition — the pure helpers of `cmd/pew`
      and `internal/*` as the `-short` tier (under 2 s); the ~20
      unstubbed `runRun`/`runPackage` sites, the `gc`/`stat` fixture
      modules, and the git fixtures `-short`-gated (extending the
      existing `execute`/`build` seams where the case needs only
      process ordering); the analysis canaries unconditional in CI,
      gated locally. Measurement: none.

## Band P — the operation pipeline contract (no wasted work)

Audit evidence: docs/plans/pipeline-audit/*.md §§2–5, 8. Four
structures recur in every repo: refusals live where their data is
convenient, not where it is first available; the progress reporter is
built for one surface or one verb and the rest inherit nothing;
freshness is decided after the expensive setup it could have
replaced; persistence granularity was solved once and not propagated.
One root sits under all of them: the engine's observation pass has no
freshness of its own, so every consumer pays a full observation before
it can serve. Each chunk restages one tool's operations as **prepare →
(per unit: check freshness → measure only what is not proven → persist
before the next unit) → report**, the spec stating the contract as
invariants — prepare refuses everything preparation can decide, before
any measurement; progress on both surfaces (phase, unit k/N, why this
unit executes rather than serves, measured pace; interruption names
what was kept); unit-level persistence (an interruption loses at most
one unit); cancellation is a context cancel on every surface — and
lands the audit's knob dispositions in the same seam. Each closes by
running the restaged tool over its own tree ONCE, warm, as the
verdict, and records the measured wall against the audit's baseline.

- [x] 154. gofresh: the observation pass gains a preparation pass,
      a contribution memo, and a unit tick (pipeline-audit
      gofresh.md §8's seam: `observeView` and `observationFacts`).
      Preparation: listing, package classification, subject
      existence, and recorded-record shape resolved before any typed
      load (the seven late refusals of §2 move to it; the
      toolchain-selection verdict is announced at `New`; producer
      declarations are validated pre-spawn in `CaptureProducerFrame`).
      Freshness: a persistent per-file contribution memo keyed as the
      effect-scan memo is, so "did any recorded identity move?" is
      answered from persisted digests before the load; the served-
      versus-measured decision per package inside the pass. Progress:
      a per-package tick through `Hasher.OnProgress` on the load and
      hash phases, a served event on the memo-hit path, and the
      kept-on-cancel report (which slices, which scans are on disk).
      Batches return partial verdict maps beside the first error
      instead of nil. Knobs: the four classification roots derived
      from the engine's own `EnvSnapshot`; `DisableMemos` deleted;
      `WithAnalysisBudget` derived from observed per-package cost;
      `maxAttributedSubjects` measured. Spec: closure.md and
      overview.md gain the preparation, progress, and partial-batch
      invariants. Release; 155–157 bump. Measurement: the pipeline-
      audit baseline (two observations per view; 3m42s proof) re-
      measured at close.
- [x] 155. stipulator: the prepared policy capture, the CLI reporter,
      and unit persistence (pipeline-audit stipulator.md §8's seam).
      One `capturePolicy` at the top of every witness-consuming
      operation carrying the validated policy (the four static checks
      move from `NormalizeInvocation` into `validateConfig`), the
      normalized invocations and obligation universe (built once —
      today four `NormalizeInvocation` and four `discoverUniverse`
      sites, ~fifteen `go env` and twelve `go list` spawns before a
      test runs), the coverage policy (its cell-duplication refusal
      fires before execution in all five consumers), the resolved
      scope and the caller's view/bucket/filter vocabulary (validated
      pre-run on every verb, the `toolCheck` shape), and the record-
      hygiene half of verification before the run; `gate`/`verify`
      share one resolver child. Freshness before the typed loads
      (consumes 154). Reporter: the `progress` sink installed in
      `cmd/root.go` as it is in the MCP server, per-unit lines
      naming why a subject executes rather than serves, a measured
      pace line, `signal.NotifyContext` in `main.go` with the kept
      report; `--full` installs per invocation. Knobs: policy
      `timeout` default derived from the store's recorded walls,
      `witness_concurrency` deleted as a policy field, `no_test`
      merged into the freshness path. Spec: change.md and mcp.md gain
      the preparation, both-surface progress, cancellation, and
      unit-persistence invariants. Surfaces: the verb × surface
      defaults table derived and recorded in mcp.md and the CLI
      section of the spec (check's summary/full views re-derived for
      the LLM reader, the CLI render for the human), the server
      instructions naming the entry call and the loop, every tool
      description saying when and what it returns, opt-ins each with
      a purpose or deleted. Close: the deferred chunk-141 self-host
      verdict runs here, once, warm. Measurement: the cold 30m43s /
      warm baselines re-measured.
      At the bump: the fast-tier gate pin collapses to gofresh's
      shortgates.Pin (landed in every consumer; the shared package is
      github.com/greatliontech/gofresh/shortgates).
- [x] 156. gomutant: the per-verb prepare stage and the reporter for
      every verb (pipeline-audit gomutant.md §8's seam: `--plan`
      made whole). Prepare: the campaign lock at flag parse, `budget`
      and `runs` and the attestation reason and the retarget pair and
      the scratch/vouch parse and the exemptions/findings documents
      all refused before `LoadContextSelection`, the bracket preflight
      at `Tree.Run`'s entry over every module root, the ephemeral
      zero-match refusal from the loaded set, `--targets`/`--changed`
      refused together on `run` as on `discover`; `--plan` reaches
      every refusal and pays no producer union. FOLDS chunk 146 (the
      staged snapshot's unpinnable external input refuses at
      preparation, headlined as the external input with its remedy;
      the staged dirty judgment realigns with the results spec —
      gomutant's deleted
      docs/issues/staged-external-input-refuses-late-and-misnamed.md
      (git log --all --
      docs/issues/staged-external-input-refuses-late-and-misnamed.md,
      in gomutant) deletes at close). Freshness: one batched view set
      threaded to `findings --judge`, `explain`, and the closure
      signpost (the inspection path gets the union `run` already
      has); the signpost bounded and reported; `Store.Update`'s
      per-commit whole-document rewrite replaced by a per-record
      overlay so a campaign's persistence is O(unit). Reporter: the
      CLI `ephemeral` and `findings --judge` and the tree load get
      the phases, ticks, and interruption summary `run` has;
      `run`'s coverage-probe phase ticks and projects (FOLDS gomutant
      recovery: `git log --all -- docs/issues/probe-phase-cost-invisible.md`; deletes at close).
      Knobs: `--progress-interval`, the two baseline leashes,
      `windowBudget`, and the schedule minimums derived from the
      bank's measured durations; `--json` and `--jsonl` one name; the
      heartbeat literals and the six envelope caps one policy each.
      Spec: execution.md and mcp.md gain the invariants. Surfaces:
      the verb × surface defaults table derived and recorded; the
      server instructions name the entry call and the loop (run over
      the tree, findings to inspect, ephemeral inside the adversarial
      loop, explain for why); the `{"edits":[…]}` wrapper and every
      input shape stated where the LLM reads them; opt-ins each with a
      purpose or deleted. Measurement: `--plan` over
      `testdata/self-host-targets.json` timed before and after; the
      ephemeral probe path's silent stretches re-measured.
      At the bump: the fast-tier gate pin collapses to gofresh's
      shortgates.Pin (landed in every consumer; the shared package is
      github.com/greatliontech/gofresh/shortgates).
- [x] 157. pew: the package preparation record, the reporter, and
      per-arm persistence (pipeline-audit pew.md §8's seam). Prepare:
      one record per package after `go list` carrying the benchmark
      declarations, the validated store destinations (label, path,
      name, duplicates, store-covered and overlapping sources), the
      GOFLAGS/PGO digest and sampled GOVERSION for every module, and
      the single typed view — the thirteen late refusals of §2 fire
      there; `ab` builds every side, captures every guard, and
      refuses a guard mismatch (as spec §12 already says) before its
      first iteration. Freshness: serve-what-is-proven is the default
      (`--stale` inverted to an explicit `--all`), the freshness view
      reused for capture instead of discarded. Persistence: per arm,
      with the drift and HEAD gates re-derived per arm; `ab`'s
      `--out` and `gc`'s report written incrementally. Reporter: a
      pew-owned progress seam (phase, package k/N, arm k/N, pace),
      engine keep-alives no longer dropped, `signal.NotifyContext`
      with the kept report. Knobs: `ab --benchmem` deleted (always
      on, as `run`), `--assume-pure`/`--impure` merged into the source
      directives, the three `--vouch` flags merged into the repo-level
      vouch file (rides with 115's rider), `--pin`'s CPU list derived
      from sysfs with the switch kept; `--count`/`--benchtime`/
      `--threshold` derivation is spec-level and files against
      REQ-pew-sample-completeness for the user's call. Spec: spec.md
      gains the preparation, progress, cancellation, and unit-
      persistence contract (it carries none today). Surfaces: pew has
      no MCP surface — the chunk derives and records the CLI verb
      defaults table and the machine (`--json`) contract as the
      LLM-facing output, and decides whether an MCP surface is owed
      (a genuine fork: file for the user if so). Measurement:
      whole-store `pew status` wall before and after; no bench arms
      move.
      At the bump: the fast-tier gate pin collapses to gofresh's
      shortgates.Pin (landed in every consumer; the shared package is
      github.com/greatliontech/gofresh/shortgates).
## Band A — verdict integrity (correctness)


## Band B — standing guards (the neglect-proofing layer)

## Band U — UX (MCP-first)

- [x] 112. cross-tool: MCP surface audit against the sharpened
      doctrine — every MCP verb re-audited: minimum strings/tokens
      that keep the LLM on point, suggestions attached to every
      refusal/verdict where derivable. FOLDS gomutant
      recovery: `git log --all -- docs/issues/actionable-unverifiable-refusals.md` (each unverifiable
      reason names its discharge channel — vouch/directive/
      restructure) and stipulator
      recovery: `git log --all -- docs/issues/pin-forms-shape-guidance.md` (shape-moved guidance and
      the ids-form answer mislead exactly when shapes mismatch); both
      docs delete at close.

## Band C — ergonomics, robustness, consolidation

- [x] 128. gomutant: serve carve-out consolidation (gomutant
      recovery: `git log --all -- docs/issues/fold-growth-into-generalized-drift.md`
      and `git log --all -- docs/issues/consolidate-reidentification-and-bucket-policy.md`) — growth is a
      strict special case of generalized drift; one re-identification
      helper, one advisory-bucket policy; same subsystem as the
      landed 103 (gomutant 2ba8841), whose windowScores bundle and
      newSurvivor/carrySurvivor constructors are the shapes the
      consolidation builds on; both docs delete at close.
- [x] 113. gomutant: ergonomics and robustness batch — landed
      (gomutant c4093cb..4400573; gofresh 40317df; dispositions in
      the commit records; the campaign-scale residue was ruled and
      resolved in chunk 137 (successor residue: gomutant
      recovery: `git log --all -- docs/issues/own-face-gate-suite-decomposition.md`), and
      suite-shared-fixture-bracket-flake redeferred on its sharpened
      instrumentation trigger).
- [x] 137. gomutant: survivor-oracle narrowing + campaign economics
      — landed (gomutant 33d7863..49795ea: narrowed survivor with
      savings-derived full-oracle audit; window cost model with
      priced projections, completion ticks, live pace; value-ordered
      windows; SIGTERM joins the deadline-bounded graceful drain;
      content-pinned baseline bank with immediate-persist deposits).
      Landing check measured and REFUSED on its own verdict: window-1
      projection ~33h43m (79/92 narrowed — covering ≈ suite on the
      e2e-heavy own face), pace ~217h for 129 targets/10,235
      candidates, audit share ~10.8% ≤ 1/8, first window
      value-ordered; stopped at 3h33m priced-upfront. Own-face gates
      stay on ephemeral probes; the fork's unchartered (a) half files
      as Gomutant recovery: `git log --all -- docs/issues/own-face-gate-suite-decomposition.md`
      (user decision); probe-phase visibility files for 136. Six
      converged loops; dispositions in the commit records.
- [x] 114. stipulator: runner-environment inspectability — landed
      (stipulator e31795d..25b7dcd + 62fc1a7, five folds: timeout
      kills attribute the reviewed -test.timeout budget with the
      runtime's victim roster; load failures name the
      dependency-resolution state from the go.work/go.mod pin table;
      verdict-flipping failures carry the runner-vs-ambient env
      divergence, render-bounded and UTF-8-safe; claim-writing verbs
      batch or refuse repeated flags through one alignment/refusal
      vocabulary; gap records gain content-pin consent with
      declare-time landing-target grammar validation and one
      machine-owned gap writer). Five converged loops (4+5+6+4+3
      rounds); five issue docs deleted (witness-runner-environment-
      divergence, timeout-kill-attribution,
      cli-repeated-flag-claims-silently-dropped,
      gapped-requirement-spec-edits-invisible-to-pin,
      gap-covered-unknown-id-at-declare); the bldc batch's nine
      surviving docs retargeted onto 141-145 (stipulator 62fc1a7);
      dispositions in the commit records.
- [x] 141. (converged 2026-09-02 — three review rounds, fourteen
      probes killed, package suites green; committed with its
      self-host verdict DEFERRED to chunk 155's close under the
      replan's standing rule; the checkbox closes there)
      stipulator: verdict and serving integrity (field-response,
      bldc reports 2026-09-03; stipulator
      recovery: `git log --all -- docs/issues/check-green-over-witness-failure.md` +
      `git log --all -- docs/issues/property-suite-witness-serving.md`). 141.1 reproduces
      the green-over-named-failure shape against the current verdict
      fold — the witness path judges no suite health by design, so the
      question is what a witnessFailureHeadings entry must do to the
      canonical verdict — then fixes or regression-pins it. The
      serving leg is spec-tier: a classifier-derived property-witness
      class lowers or disables freshness serving so a random-seeded
      witness re-executes every check (the flake-pinned-until-inputs-
      move stance stays for example witnesses). Both docs delete at
      close. Measurement surface: verdict/diagnostics only — no pew
      arms, no DST legs.
- [x] 138. gomutant: workspace-relative path resolution
      (field-response, consumer reports 2026-09-03; gomutant
      recovery: `git log --all -- docs/issues/bracket-path-module-relative-in-workspace.md`) — a
      relative --bracket-path resolves against the invocation's --dir
      (or workspace root), one declared surface for every module's
      oracles, so an in-tree file spelled relatively never joins onto
      the target module's directory, never plans unverifiable, and
      never forces the absolute-path workaround whose machine-local
      records keep attestations out of the committed findings
      document; and (rider, field report 2026-09-02) an absolute
      directory is an admissible bracket path — a replace module
      outside the repository is one declared surface, never an
      enumeration of its files. RIDES gomutant
      recovery: `git log --all -- docs/issues/ephemeral-test-pkg-shorthand.md` — ephemeral
      --test-pkg accepts a relative package directory resolved
      against the loaded set, matching the --dir default. Both docs
      delete at close. Measurement surface: diagnostics/CLI
      resolution only — no pew arms, no DST legs.
- [x] 140. gomutant: ephemeral probe integrity (field-response, bldc
      reports 2026-09-03; Gomutant recovery:
      `git log --all -- docs/issues/ephemeral-deletion-probes-strand-imports.md` — an imports fix runs
      over the mutant before compiling (a probe declares no import
      intent), the result saying which happened;
      `git log --all -- docs/issues/ephemeral-blind-spots-stated-and-refused.md` — a target file no
      measured test compiled is a REFUSAL, never a survivor, and the
      three blind spots enter the ephemeral guidance with the
      mutate-the-guard's-input workaround beside them;
      `git log --all -- docs/issues/ephemeral-compiler-crash-retry.md` — a compiler signal death retries
      once or marks "compiler crashed — re-run to confirm";
      `git log --all -- docs/issues/ephemeral-batch-wrapper-undiscoverable.md` — the {"edits": [...]}
      wrapper named in guidance and refusal, or the bare array
      accepted). Four docs delete at close. Measurement surface:
      probe-path diagnostics only — no pew arms, no DST legs.
- [x] 146. FOLDED into chunk 156 (Band P, 2026-09-02): the staged
      snapshot's external-input refusal is one instance of the
      prepare-stage invariant 156 lands; the field report's doc rides
      156's close.
- [x] 115. pew: verdict-surface batch (Pew recovery:
      `git log --all -- docs/issues/gitblob-linked-worktree-object-lookup.md` — pew run fails in linked
      worktrees; `git log --all -- docs/issues/ab-worktree-placement-escape.md` — operator escape +
      startup sweep; `git log --all -- docs/issues/verdict-ladder-shared-admissibility.md` — the
      status/stat admissibility ladder collapses to one shared
      function with the per-side working-tree input) — three docs
      delete at close. RIDES: pew
      recovery: `git log --all -- docs/issues/repo-level-vouch-source.md` — a reviewed vouch file
      beside the store replaces hand-mirrored flag lists; doc deletes
      at close. Deviations: the gitblob doc (user decision) folded —
      one option on the open call, no judgment; `--vouch` flags
      extend the file and never remove (no `--no-vouch`); the
      residue sweep is ownership-scoped (this repository's, or an
      empty mint) after review; the vouch-globals and row-decode
      collapse is governed by `../pew/docs/specs/spec.md` §7's
      invocation-owned admission and package-batch judgment.
- [x] 142. stipulator: clause-granular binding claims (bldc report
      2026-09-03; stipulator
      recovery: `git log --all -- docs/issues/clause-granular-binding-claims.md`) — a binding
      names the clause it witnesses (ordinal or spec-admitted label),
      and coverage reports the unclaimed clauses of an otherwise-bound
      requirement as a distinct "bound, clauses unclaimed" bucket —
      the consumer's own H-graded false-green channel retired
      upstream; doc deletes at close. Spec-format + coverage + both
      surfaces. Measurement surface: none. Deviations: the bucket is
      named `partial` and is the `uncovered` excuse class in part (no
      new gap excuse, no record migration); clauses are the payload's
      list items only — no clause inference from prose; whole claims
      on clause-structured requirements stay admitted (stipulator
      docs/issues/clause-structured-whole-claims.md, user decision);
      the witness-selection guard fold
      (witness-selection-guard-masked-by-ineligible-red) landed as
      its own change set.
- [x] 143. stipulator: consent provenance (bldc report 2026-09-03;
      Stipulator recovery: `git log --all -- docs/issues/content-hash-function-versioning.md`) — a
      hash-function move is its own recorded state ("rehash",
      bulk-re-pinnable without editorial consent) or the pin records
      the declaring document's blob hash beside the content hash, so
      a re-consent over unchanged text is self-evidently that. RIDES
      Stipulator recovery: `git log --all -- docs/issues/pin-req-unchanged-text-wording.md` ("text unchanged;
      nothing to re-consent" over "pins current"). Both docs delete
      at close. Measurement surface: none. Deviations: the second
      option landed, but VCS-free — a consent-source digest over the
      consent surface's raw blocks plus the document's link reference
      labels (the one document-scoped parse input), not a blob hash;
      rehash is derived from the two pins, never stored; the blanket
      pin now also judges attestations and refreshes a current
      record's source pin; the named form's no-op names its reason
      (text unchanged / no records / attestation stale).
- [x] 144. stipulator: CLI query parity (bldc report 2026-09-03;
      Stipulator recovery: `git log --all -- docs/issues/cli-verify-view-path-and-explain.md`) —
      CLI verify gains --view/--path and the explain verb lands on
      the CLI, so "what claims this symbol" is a query, never a grep
      over the record format. RIDES
      Stipulator recovery: `git log --all -- docs/issues/normative-keyword-lint-timing-and-remedy.md` (a lint
      entry point compiling the corpus at the amendment; the remedy
      in the message). Both docs delete at close. Measurement
      surface: none.
      RIDER (bldc report 2026-09-02, slotted at 114 close): the
      attestation-cell refusal and explain-on-uncovered name the
      reclassification remedy (stipulator
      recovery: `git log --all -- docs/issues/attestation-refusal-names-no-reclassification.md`;
      doc deletes at close). Deviations: the rider landed as a kind
      hint stating the IR's kind definitions, never a reclassification
      instruction (the tool computes remediations, never prescribes
      fixes); the keyword lint's entry point is `compile`, named in
      the diagnostic and guidance — no new timing hook; a scope now
      narrows the verification summary on both surfaces.

- [x] 145. stipulator: spec-graph authoring (bldc reports 2026-09-03;
      Stipulator recovery: `git log --all -- docs/issues/refines-multiple-targets.md` — refines
      admits a target list, canonical form ordering it, impact and
      coverage reading every edge — +
      Stipulator recovery: `git log --all -- docs/issues/supersede-removed-source-one-step.md` — the
      removed-source supersede is one step: a dispose mode or compile
      admitting a supersedes edge into the tombstones-or-pending
      set). Both docs delete at close. Measurement surface: none.
      Deviations: both asks already held in the code (the list form
      compiled; the one-step supersede ran on the mid-disposition
      corpus) — the gap was discoverability, and under review the
      disposition's unit proved wrong for chains: it now follows the
      declared edges (BREAKING precondition relaxation, retarget per
      declaring successor), and the compile refusal names the one
      step once per component as a `remedy` diagnostic class rendered
      by every refusing surface except the counterfactual ones (the
      tombstone overlay, the historical HEAD corpus); coverage reads
      no edges and no spec clause asks it to (plan-only wording);
      "tombstones-or-pending set" names no mechanism — the overlay is
      it. Filed: Stipulator recovery: `git log --all -- docs/issues/remedy-spellings-one-source.md`
      (user decision).
- [x] 136. cross-tool: retroactive automation-and-consolidation audit
      (user directive 2026-08-29; the automation-over-configuration
      standing directive, tugboat fb4a45b, applied to the existing
      estate). Per tool, walk every knob, flag, env override, and
      config surface against the derivability test — a knob whose
      right value is derivable, detectable, or measurable at runtime
      is dispositioned: derive it (fold small, file larger with
      Lands), keep it with the recorded value judgment that earns it,
      or delete it; and walk parallel mechanisms within and across
      the tools as one consolidation scan (candidates feed the
      existing consolidation chunks — 98-101's walk unifications —
      or file fresh). RESCOPED 2026-09-02: the knob inventory and the
      refusal-site walk were done by the pipeline audit
      (docs/plans/pipeline-audit/*.md §§2, 5) and their dispositions
      land in Band P (154–157); this chunk keeps the consolidation
      scan — the parallel mechanisms the audit and the ledgers name
      (stipulator consolidation-ledger-train-114, gomutant
      rescore-mechanism-unification and
      run-scoped-services-through-options, pew's three bench-dir
      resolvers and its verdict ladder, gofresh's four walk
      unifications) — and re-walks every knob Band P kept, "none"
      only by looking. Runs after Band P and before the D-band
      consolidation chunks. Measurement: a knob this audit deletes or
      re-derives on a bench-armed shape names its pew arms in the
      disposition and re-records in the same change set.
- [x] 91. gomutant: deferred-check-close adoption — the run-end and
      per-window producer validations run full in-process gofresh
      analysis (~25% of in-process CPU under repeated packages.Load);
      gofresh's deferred-close contract is the closing-cost lever; a
      design pass, then the adoption; history: `git log --all --
      docs/issues/post-completion-cpu-tail.md` (gomutant).
- [x] 92. gomutant: fold the decision batch (maximal captures) and the
      observed proof union — two back-to-back full observation passes
      over the identical symbol set with the same engines; one
      observed union view set serving both roles halves the warm
      campaign's observation floor; also dispositions the
      strict/union view-build-loop duplication in freshness.go.
      Rider (91's design verdict, 2026-09-07): once one view set is
      both checked and validated per window before that window's
      commit, gofresh's deferred check close is sound for it
      (REQ-fresh-coherent-view's deferred-close clause: verdicts
      consumed only under a later successful validation of the same
      view) — adopt WithDeferredCheckClose in the same change set and
      re-measure the closing observation (60 ms per view warm at 91).
- [x] 96. gomutant: concurrent ephemeral probe overrides — two
      concurrent probes' width/ceiling snapshot-restores can
      interleave (bounded, self-healing); either the probe claim goes
      exclusive or the interleaving is recorded as accepted.
- [x] 129. gofresh: comment/format-insensitive closure identity — a
      closure identity insensitive to comments and formatting
      (caching axis: comment-only edits stop invalidating consumer
      evidence); chartered as the prerequisite gomutant's carry gate
      names (semantic-closure-in-the-carry-gate); release, then 130
      rides.
- [x] 130. gomutant: semantic closure in the carry gate (gomutant
      docs/issues/semantic-closure-in-the-carry-gate.md) — adopt
      129's identity at both poles of the carry gate; doc deletes at
      close.
- [x] 139. gomutant: delta-line survivor view (field-response,
      consumer report 2026-09-03; gomutant
      recovery: `git log --all -- docs/issues/delta-line-survivor-view.md`) — a --changed
      campaign's summary and result rows gain a changed-lines filter
      (survivors on the delta's added lines counted and listed
      distinctly from the symbol's pre-existing remainder), and
      findings rows gain a run identity so an inspection scopes to
      one campaign's records without re-deriving the measured set;
      doc deletes at close. The run-identity half is records-shape
      work on the v11 document — splitting it from the cheaper filter
      is a triage-gate call at 139.1. Measurement surface: no new pew
      arms; whole-store pew status at close re-judges the findings
      reader arms if the records shape moves. FOLDS:
      Gomutant recovery: `git log --all -- docs/issues/legacy-overlay-read-deletes-attestations.md`
      — preserve unsupported older overlays and their authored
      equivalence reasoning while refusing to serve them; doc deletes
      at close.
- [x] 131. stipulator: one identity walk, two windows (stipulator
      recovery: `git log --all -- docs/issues/identity-walk-two-trackers.md`) — attachment and
      extent answer "whose block is this" via two independent reset
      tables in two packages; collapse to one walk producing both
      windows so the subset relationship is structural; doc deletes
      at close.

## Band D — precision and discharge (speed + caching for consumers)

The startup-effect-precision plan's open ladder (folded 2026-08-26;
charter histogram and methodology: `git log --all --grep
"startup-effect-precision plan charters"`), then the discharge family
re-based on current field mass (tugboat 2026-08-26 measure:
coldBufPool 647, net/http 305, errInboundClosed 54, frameAccounting
42). Audited-set changes each carry their own source audit and
strategy bump.

- [x] 116. gofresh: custom-FlagSet-scoped sink precision (was SEP
      0b2) — scope 0b's registration poison to registrations whose
      FlagSet (or the default set) can carry os.Args, via
      Parse-argument provenance; narrows 0b's fail-closed widening.
- [x] 117. gofresh: call-shaped unaudited-std scan classes narrow per
      audit (was SEP 0f) — crypto/rand first; the general retirement
      of the unaudited-std scan arm is the band's endgame, not one
      chunk.
- [x] 118. gofresh: benchmark-loop package-scan audit (was SEP 0d) —
      testing.Loop blocks every subject in a benchmark-bearing
      package; decide the class (admit as harness pacing like m.Run,
      or keep with the refusal naming the benchmark) — own audit.
      Until it lands, pew's serve-proven default serves only
      empty-bodied benchmarks (every b.N/b.Loop reader is
      unverifiable): pew's deleted
      docs/issues/serve-proven-blocked-by-benchmark-loop.md (git log
      --all -- docs/issues/serve-proven-blocked-by-benchmark-loop.md,
      in pew) lands here.
- [x] 119. gofresh: writer-sensitive fmt.Fprint startup
      classification (was SEP 1; ~1,096 in the charter histogram) —
      an init formatting into a provably-local pure sink is value
      computation. FOLDS at this chunk: gofresh
      recovery: `git log --all -- docs/issues/audit-key-mechanism-consolidation.md` (four parallel
      spellings of the audit lookup/refuse mechanism — this is the
      band's first audited-set change) and
      Gofresh recovery: `git log --all -- docs/issues/nodwarf5-toolchain-audit-key-mismatch.md` (release,
      selection, and baked-experiment matching must use the actual
      audited toolchain identity); docs delete at close.
- [x] 120. gofresh: math/big joins the audited-pure set (was SEP 2;
      ~505) — own audit.
- [x] 121. gofresh: fixed-argument time construction audited (was SEP
      3; ~186) — Date/AddDate/Format read no clock; own audit.
- [x] 122. gofresh: std init-closure exemption (was SEP 4; ~58) —
      synthetic init$N closures ride the toolchain guard as named
      init does.
- [x] 123. gofresh: maximal-tier pure-shape selector audits (was SEP
      5; ~23) — net/url.Parse, time.Time, path/filepath.Ext.
- [x] 124. gofresh: enumeration targets tightened (was SEP 10;
      Gofresh recovery: `git log --all -- docs/issues/enumeration-targets-over-approximated.md`,
      already deleted — history in git). RIDES: gofresh
      recovery: `git log --all -- docs/issues/range-over-func-yield-closure.md` — admit the
      range-desugared yield callback as a closing caller and flip the
      corpus pin deliberately in the same change set; doc deletes at
      close.
- [x] 125. gofresh: precision-band acceptance — re-run the charter
      sweep on the pinned field repro and record the
      observable-subject fraction against the 0.5% baseline (was SEP
      11).
- [x] 179. gofresh: startup and test-main dynamic sites narrowed by
      the closed-value judgment — both walks take a dynamic site's
      whole-mask signature-class projection as its targets, so an
      initializer's func-value call or interface invoke reaches every
      standard closure or method of a matching signature in the
      program (the 125 sweep: 961 of 2,119 cerebro subjects refuse at
      the startup walk on encoding/json/v2.init$2,
      internal/godebugs.init$1, crypto/internal/fips140/aes.init#2$1 —
      closures no user code can name — 169 on archive/zip.Read and 36
      on the property harness reached through
      (*encoding/json.MarshalerError).Error, the invoke form); resolve
      the site's operand through the closed-value walk under the local
      projection, as the subject walk's resolved sites do, before the
      RTA fallback. RIDES Gofresh recovery: `git log --all -- docs/issues/dynamic-target-init-exemption.md`
      (its field report arrived at 125; the recorded exemption shape is
      refused — a standard closure's body is never walked, so the
      fallback's refusal is the sound answer for a target the operand
      genuinely carries).
- [x] 180. gofresh: reflect's Elem by symbol — 464 of the 125 sweep's
      subjects refuse at the startup walk on reflect.Elem; audit
      (Type).Elem (an invoke-nothing type-level accessor) and
      (Value).Elem (a dereference of memory the operand pins) for the
      audited set, admitting by symbol or recording the channel that
      refuses each.
- [x] 181. gofresh: time's shared-name exclusion made
      receiver-sensitive — 121 admitted time's fixed-argument surface
      by bare name and so excluded whole every name a pure method
      shares with an ambient declaration; the 125 sweep prices that
      cost at 175 subjects (time.UTC 113, (Time).AddDate 62) beside
      time.Parse's 115 (zone abbreviations through Local, refused
      deliberately); admit the pure method form where the receiver
      distinguishes it — (Time).UTC, (Time).AddDate — at every tier,
      the package-level variable and function keeping their class.
- [x] 182. gofresh: reflect's descriptor-view surface by symbol — the
      180 re-measurement moved the same 1,365 subjects one view method
      deeper, to reflect.Kind, and each admission on its own uncovers
      the next; audit the whole invoke-nothing read surface of
      reflect.Type on the pinned toolchain source (Kind, Name, String,
      PkgPath, Size, Align, NumField, Field, FieldByName, NumMethod,
      Key, Len, NumIn, NumOut, In, Out, Implements, AssignableTo,
      ConvertibleTo, Comparable, and the Value forms sharing those
      names) in one pass, admitting by symbol or recording the channel
      that refuses each, so the sweep's next line is not a reflect
      view method.
- [x] 98. gofresh: stateless-value escape discharge — zero-field
      struct values cannot be observably mutated through escaped
      aliases; justification re-bases at triage on the then-current
      measure (the original 285-witness class was discharged in-tree
      meanwhile); zero measured mass closes the chunk unbuilt. The
      three rides (unify-carrier-walks, unify-discharge-walks — its
      walk half landed at 179 as dischargeCulprits, the rest filed as
      discharge-reason-channel-one-source — and
      binary-roots-single-mask-union) move to 179, the band's first
      reachability-scoping change.
- [x] 99. gofresh: guarded deterministic memoization discharge — the
      get-or-compute idiom (check-then-fill under mutex/Once/sync.Map,
      key-derived fill through proven-env-free functions, no
      cross-key observable escape) is warm/cold-equivalent and
      discharges structurally; the field class is third-party
      (rapid's memo maps, vouched as the interim); close-out trims
      the then-redundant rapid vouches from consumer policies and
      re-measures. RIDES: gofresh
      docs/issues/attestation-keyed-record.md (the per-mode discharge
      plumbing collapses to one attestation-keyed record) and
      grpc-runtime-memo-and-registry-discharges.md (triage folds or
      re-charters on read); docs delete at close. Release, then
      consumer bumps ride.
- [x] 100. gofresh: in-module scratch discharge — reads of a
      module-interior directory the test itself mints, writes, and
      removes classify as runtime inputs no bracket can cover and
      seal the observation; tugboat's .realseam-tmp WAL smoke tier
      was 129 witnesses (excluded as the interim); design reasoning:
      `git log --all --
      docs/issues/fresh-mutation-in-module-scratch.md`; triage
      re-derives against the then-current measure. Release, then
      consumer bumps ride.
- [x] 101. gofresh: audited-construction discharge reaches carrier
      stores, and errors.New joins the audited set — storing an
      audited-construction carrier into a struct field marks the
      SOURCE variable mutated though the store copies the interface
      value (reproduced); same family: var Err = errors.New(...)
      sentinels refuse as escapes-writable/mutated — tugboat's
      errInboundClosed/frameAccounting classes, 96 witnesses at the
      2026-08-26 measure. Coordinates with the audited-pooling-set
      owner before touching the discharge. RIDES: gofresh
      recovery: `git log --all -- docs/issues/sibling-reason-families-name-their-channels.md`
      (external-syscall and caller-supplied-dynamism reasons dead-end;
      the shared-dynamic-state naming pattern applies at these
      composition sites); doc deletes at close. Release, then
      consumer bumps ride.

## Band F — dispositioned decisions (2026-09-07 walk of the user-decision register)

Every issue whose shape derives from first principles — a demonstrated
soundness gap, a correctness fault, or a collapse with one defensible
form — is chartered here in execution order: soundness first, then
correctness, then consolidations. The genuine forks stay `user decision`
in their repos.

- [x] 158. gomutant: the never-executed bucket joins the audit sample
      (gomutant docs/issues/never-executed-exemption-unaudited.md) — a
      mutant whose extent the coverage attributes to no test is exempt
      from every batch AND outside the narrowed audit, so a wrong
      attribution is never re-scored (a probe-killed line recorded open);
      sample the bucket into the audit exactly as the narrowed class, a
      disagreement there the loudest signal; doc deletes at close.
- [x] 159. stipulator: random-seeded serving follows a transitive seeding
      class (stipulator's deleted
      docs/issues/seeded-witness-serving-follows-direct-call-classifier.md
      (git log --all --
      docs/issues/seeded-witness-serving-follows-direct-call-classifier.md,
      in stipulator)) — a helper-indirected rapid driver serves as
      deterministic; serving consults a transitive seeding class resolved
      from the recognized-driver table while the evidence classification
      stays direct-call; doc deletes at close.
- [x] 160. gomutant: ephemeral hardening — the probe never writes under
      the caller's tree (gomutant's deleted
      docs/issues/ephemeral-rapid-failfile-in-tree.md (git log --all
      -- docs/issues/ephemeral-rapid-failfile-in-tree.md, in
      gomutant): rapid's failfile directory and the test working
      directory
      isolated into the probe's temp dir), an attested survivor's verdict
      line and MCP row say so (Gomutant recovery: `git log --all -- docs/issues/ephemeral-attested-survivor-invisible.md`),
      and the attestation is keyed on the mutated file's post-edit content
      hash rather than the edit text (Gomutant recovery: `git log --all -- docs/issues/ephemeral-attestation-keyed-on-edit-text.md`); three docs delete at close.
- [x] 161. stipulator: a gap can say "contradicted by design until a
      condition fires" (Stipulator recovery: `git log --all -- docs/issues/gap-cannot-say-contradicted.md`)
      — a `contradicted` gap state reported distinctly from unwitnessed,
      resolving only on an explicit fire, never on a passing witness while
      unfired; doc deletes at close.
- [x] 162. gofresh: the repo-level vouch convention (Gomutant recovery:
      `git log --all -- docs/issues/repo-level-vouch-source.md`) — the engine sources a repository's
      reviewed dynamic-state vouch file (pew's grammar and precedence:
      flags extend, never remove) for every consumer; gofresh spec change;
      release, then consumer bumps ride and pew's store-owned file
      delegates; doc deletes at close.
- [x] 163. gomutant: an unreachable build leg is a stated coverage bound
      (the interim of gomutant
      docs/issues/external-oracle-for-tagged-and-subprocess-targets.md)
      — a tag selection's discovered targets that no
      oracle reaches are recorded and rendered as a coverage bound, never a
      silent zero; the external-oracle mode itself stays the user's fork
      (the doc stays, retargeted to that half).
- [x] 164. gomutant: the window commit horizon derives from candidate
      count (gomutant's deleted
      docs/issues/window-commit-horizon-for-suite-class-oracles.md
      (git log --all --
      docs/issues/window-commit-horizon-for-suite-class-oracles.md, in
      gomutant)) — a content-stable window budget sized by the oracle
      group's candidate count so suite-class oracles commit on a horizon
      without moving the partition between runs of an unchanged tree; doc
      deletes at close.
- [x] 165. gomutant: the MCP server's exit is diagnosable — the server
      logs why and where it stopped serving; the idle-session liveness
      witness rides mcp-liveness-cancellation-witness's condition.
- [x] 166. stipulator: every Go child runs with the toolchain's telemetry
      owned — the config home every child inherits points at an owned
      telemetry-off home, so the descendant tree is exactly what the
      runner owns.
- [x] 167. stipulator: spec enforcement pointers follow retarget and are
      judged — every "Enforced by" name resolves to a tests/proves binding
      of its requirement, and retarget rewrites the pointers a moved member
      names in the document.
- [x] 168. gofresh: the compartment-ledger entailment is an invariant —
      under one listing configuration and identity strategy, equal
      compartment hashes carry equal ledgers, stated in
      REQ-closure-test-variant-hash with a seeded property witness
      over generated compartments and a per-axis anchor.
- [x] 169. stipulator: one spelling source for remedies and knob prose
      — remedies composed from the registered verb
      and flag names and parsed against the command tree; schema tags and
      usage strings rendered from the guidance document's knob text; two
      docs delete at close.
- [x] 170. stipulator: one record store, one backend — the witness and resolution caches
      one store parameterized by record kind, the served backend the
      degenerate path of the owned one; doc deletes at close.
- [x] 183. gomutant: measured, committable, and reusable findings distinct
      at the run surface — the run summary and the attestation verdict state
      the record's posture beside its counts (measured outcome,
      committability, reuse refusal with its reason channel and the
      linked package), so a consumer never mistakes a committed record for
      current reusable evidence; the stored-observation and later-judgment
      reasons name their channels; both faces; doc deletes at close.
- [x] 172. stipulator: per-stream color (stipulator docs/issues/
      per-stream-color.md) — style decided once from NO_COLOR/TERM and
      both streams' isatty becomes a per-stream styler; doc deletes at
      close (its test-binary half moved to 228 by audit 196).
      (263: MERGED into 225 — one rendering layer, one commit shape.)
- [x] 173. pew: the flag usage strings rendered from the guidance
      document (Pew recovery: `git log --all -- docs/issues/guidance-knobs-and-verb-table.md`) — pew's
      REQ-pew-guidance already names the document the authoritative
      superset and gofresh's REQ-guidance-render its projection, so every
      flag usage literal (the --vouch text triplicated, --bench-dir in two
      wordings) renders through guidance.Knob as stipulator's do, the
      §12 table staying pinned to the DefValues; no fleet-format change;
      after 229; doc deletes at close.
      (237: premise met — guidance.Knob exists at v0.101.3 — and a
      conformance justification: nine usage strings cite spec sections
      the document does not (REQ-pew-guidance names that a defect);
      REORDERS after 205's terse-clause export and pew's bump 253 — pew
      carries no third spelling of the clause grammar.)
      (264: reorders behind gofresh 266 — pew reads that projection rather
      than minting a fourth; premise verified (Knob.Clause unconsumed, --vouch
      usage triplicated verbatim, nine usage strings citing spec sections the
      document does not); riders from gomutant 246: no default parentheticals
      in the served clause (cobra prints non-zero defaults per flag type), no
      back-quoted span in a usage string (pflag reads it as the value name).)
      DISSOLVED at audit 288 (2026-09-29): its payload landed at 275.C
      (c37a204 — every leaf verb's flag usage is
      GuidanceKnob(…).Usage(), every Short/Long GuidanceRegistration;
      the doc it cited was deleted at 275); the residue (§12's purpose
      column; the root command's hand-written Short outside
      visitLeafVerbs) is 232's.
- [x] 174. pew: invocation-wide `ab --out` and one verdict path
      (`../pew/docs/specs/spec.md` §10.2 and §7)
      — one benchmark-format artifact preserving every package and
      completed pair, with separately owned diagnostic companions;
      stat's working-tree arm adopts the batched per-package check
      (today verdictForRecs builds a whole-program view per benchmark and
      a second on the inert-growth rider; checkOne has no production
      caller); pew's vouch grammar and file reader deleted for gofresh's
      ReadVouchFile and ParseVouchEntry with the four process-wide vouch
      globals a threaded value; one recording-row decode feeds admission,
      the fingerprint, the closed set, and --explain; after 229; the
      remaining A/B issue doc deletes at its close.
      (237: NARROWED — the vouch grammar and reader clause LANDED at
      229; what remains: one verdict path (checkPackage vs verdictForRecs
      + inertGrownRecheck — a whole-program view per benchmark on stat's
      arm, the first unmeasured cost surface once tugboat re-records;
      checkOne has no production caller) and the vouch resolution as one
      value through one engine constructor (four globals, four
      constructors); FIRST among pew's queue after 231.)
      (264: grows — checkOne is test-only with a false doc (status and run
      judge through checkPackage, stat through verdictForRecs): deleted, its
      nine pins MOVED onto the live paths in the same change set; stat's
      inline engine-construction ladder (EffectiveGoflags → PGOInput →
      resolveVouches → buildEngine) is the fault "one value through one
      constructor" prevents — the vouch safety is positional today; the ab
      artifact's four pew- keys through the registry's namespace. The vouch
      GRAMMAR half is 275's; 174 owns the threading.)
      The current contract is `../pew/docs/specs/spec.md` §5
      (dynamic-state strategy is a freshness key), §7 (one
      invocation-owned current-tree judgment), §7.8 (explicit observed
      policy), and §7.9 (applicability extension preserves producing
      evidence).
      Delegated: the verdict path, row decode, vouch threading and explain row per validity key → performance-evidence chunk 8, after the canonical record at 7; `ab --out` per package and the artifact's keys → chunk 11 (the handoff doc).
- [ ] 176. stipulator: whole-requirement test claims on clause-structured
      requirements need an explicit default policy. Active destination:
      tooling-redesign **5.3**. Amend today's legal whole tests/proves grant
      to default refusal with a manifest opt-out; implements remains whole.
      Cover authoring and existing-record hygiene. Preserve representable
      clause scope through supersede or refuse, include scope in duplicate
      detection, and name a malformed empty-label record without unbinding
      valid siblings. Derive bind/supersede placement once, retaining explicit
      file intent and collision refusal. The four current issue bodies are
      the deciding cases; ordinary retarget's fixed clause key stays intact.
- [x] 177. pew: `--json` on run, ab, and gc (pew docs/issues/
      mcp-surface.md; user ruling 2026-09-07) — the progress channel half
      landed with REQ-pew-progress (every verb's 30 s cadence line); the
      MCP surface itself waits for a driving agent to appear; doc
      retargets at close.
      Audit 288 (2026-09-29): stands — --json on status and stat only;
      §12's 'where one exists' reads as intent; the MCP half's trigger
      is checkable.
      Delegated: `--json` and parity → performance-evidence 12.1/9.2; the MCP half keeps mcp-surface's checkable trigger.

- [x] 178. stipulator: policy-declared scratch namespaces (the consumer
      half of the in-module scratch discharge, chunk 100's verdict) — a
      capture group's policy carries `scratch_namespaces` DIR:PATTERN rows
      with REQ-inputs-scratch-namespace's grammar, passed to the engine
      exactly as gomutant's --scratch-namespaces are; the excluded-path
      interim retires where a namespace covers it; tugboat's .realseam-tmp
      is the first declaration (its session's work).
      (236: RIDES 250 — it adds a capture-group key segment, a
      whole-store re-execution; batched with the bump's own restale.)

- [x] 184. stipulator: one terse clause per face (Stipulator recovery:
      `git log --all -- docs/issues/knob-terse-clause-per-face.md`) — a knob's document line carries a
      clause per surface where the faces' spellings differ, the render
      picks its face's, the cross-face prose leaves the parenthesis; the
      two-surfaces ruling applied to knob prose; doc deletes at close.
      (263: re-aimed — the document half is gofresh's guidance format, 266
      owns it; stipulator keeps the render's face pick. After 266.)
      Audit 287 (2026-09-29): stands — nothing in the render diverged;
      the document half is gofresh 300's.
      Audit 6 (2026-10-07): MERGED into 290r (audit 334): gofresh 300
      landed the document half and parked knob-terse-clause-per-face for
      the consumer bumps — the face pick is the bump's.
- [ ] 185. stipulator: the ledger store as a record kind (stipulator
      docs/issues/ledger-store-as-a-record-kind.md). Active destination:
      tooling-redesign **5.6**; constituents 5.2e and 9.2. Fold remaining
      scan/name/content/collection and entry/record projections only where
      their rules agree. Preserve full provenance and binding coordinates,
      lazy ledger reads, referenced refused records and concurrent-install
      protection under shared exclusion. Digest/WriteAtomic/encoder-error and
      strict envelope repairs already exist. Account for rejected runtime
      variants and the historical-strategy load discrepancy at 5.2e; neither
      decoding nor mechanical sharing upgrades historical support.
- [x] 186. gomutant: the execution window's cost models in one home
      (Gomutant recovery: `git log --all -- docs/issues/window-cost-models-one-home.md`) — a windowcost
      home stating the three questions (membership, order, execution),
      their permitted inputs, and the constants beside the invariants that
      tie them; the partition stays a function of tree + order + worker
      count; doc deletes at close.
- [ ] 187. gomutant: mutant runs outside the caller's tree (gomutant
      docs/issues/ephemeral-probe-writes-under-the-callers-tree.md).
      Active destination: tooling-redesign **5.4**; constituent 5.5.
      Contain arbitrary transient and persistent oracle writes through an
      owned execution boundary, preserving actual cwd, relative inputs,
      transformed-artifact identity and complete oracles. Cover cancellation
      and descendants; state measured cost without weakening the no-write
      contract or restoring coverage omissions. Rapid failfile suppression
      is already resolved; deleting residue afterward is not containment.
- [ ] 188. gomutant: explicit fixture package selection loads a testdata
      package (gomutant docs/issues/explicit-testdata-package-selection.md)
      — Active destination: tooling-redesign **5.4**. Distinguish explicit
      directory/import loading from wildcard package filters, covering test
      selection, mutation and persisted attribution without source copies or
      artificial modules. Preserve tree-escape, selection and no-test refusals;
      use tool-owned fixtures, not an unauthorized VMM campaign.
- [x] 190. gofresh: the analyzing frontend named once — the canonical member
      form is a go/scanner token stream and the ledger's parse a
      go/parser one, so the analyzing toolchain is an input to the fold;
      IdentityStrategy composes it (today the memo scopes key on
      runtime.Version() while the strategy claims equality across it —
      the triage first reproduces a scanner move yielding equal
      ClosureStrategy with unequal hashes) and every memo scope reads
      the one spelling; the spec's two toolchain axes — the analyzing
      frontend and the analyzed selection — distinguished in every memo
      clause; the ledger's non-Go compiled member arm settled by
      construction (deleted with its prose if no test-only non-Go
      compiled input is constructible, else pinned) in the same strategy
      bump, so consumers re-measure once; both docs delete at close.
- [ ] 191. gofresh: account for behavior-affecting GODEBUG (gofresh
      docs/issues/net-url-parse-godebug-channel.md) through a sound
      runtime-relevance judgment. Active destination: tooling-redesign
      **7.8**. Account for process-level settings and in-process Setenv in
      shared processes; start-environment equality alone is insufficient.
      Derive guards or observations from the canonical contract, retain
      net/url parsing refusal until proven, and release any evidence-format
      change before consumer adoption.
- [ ] 192. gofresh: dependency closures reached by reference (gofresh
      docs/issues/dependency-nested-closures-outside-the-drain.md).
      Active destination: tooling-redesign **7.8**. addObject already scans
      dependency values before filtering. Reduce the exact nested-value
      path against direct-call and first-party controls before choosing a
      summary or traversal refinement; preserve standard audit boundaries.
- [ ] 193. gofresh: immutability after construction as a proven property
      (gofresh docs/issues/immutable-after-construction-objects.md).
      Active destination: tooling-redesign **7.8**; constituent 9.2.
      Prove reachable storage, construction inputs, external writable aliases,
      method/parameter effects, conversions, returns and later writes without
      a circular immutable-type premise. Re-census carrier memos and the
      separately subject-dependent channelz registry; retire rapid/runtime
      vouches only when the exact versions and graphs are covered. Preserve
      VMM reduced refusal controls. Split independently editable closure
      bundles, including base benchmark pacing, with their own consent,
      bindings and wrap-aware citations; no admission follows from a split.

## Band R — re-audit (the standing rule; recurs at every band close or twelve chunks)

- [x] 194. gofresh: coherence re-audit — read-only, whole subsystems
      against the specs (closure tiers, guards, auditset, the fold, the
      test-variant ledger, guidance); output a chartered consolidation set,
      recorded disputes, and a re-sequencing of the queued gofresh chunks.
- [x] 195. gomutant: coherence re-audit — the engine's window/schedule/
      estimate models, the findings document and its posture model (183's
      landing read here), the two faces, the scratch channel; same output.
- [x] 196. stipulator: coherence re-audit — the backends/golang witness
      pipeline (derive, witnessrun, served, freshness), the record stores,
      compile/coverage/views, the two faces and remedy; same output.
- [x] 197. pew: coherence re-audit — the verdict path, the store and vouch
      files, ab/run/status verbs, the guidance; same output; the replan
      across all four repos closes the band.

## Band G — gofresh under the emergent shape (chartered by audit 194)

- [x] 198. gofresh: the spec chunk — contract the code holds and the spec
      does not: ToolchainSkew's directional cross-major fail-closed
      refusal and the consumers' GOVERSION sampling obligation
      (provenance.go) specified; the shared-substrate sentence names
      guidance, shortgates, and shapecorpus; an index in the overview
      whose pointer graph reaches every spec document; the seam's typed
      control flow (ErrViewChanged, UnknownSubjectsError) and
      Progress.Detail's diagnostics channel pinned; the repository vouch
      union and its precedence over a caller's set stated beside
      REQ-vouch-input; REQ-explain-passive re-observes the view's inputs
      and may straddle a later edit. Spec only; re-consented.
- [x] 199. gofresh: a typed downgrade class on closure.Closure (gofresh
      docs/issues/discharge-reason-channel-one-source.md) — the verdict
      decision discriminates the shared-dynamic-state downgrade on a
      reason-string prefix composed at three sites; the class carries
      it, the reason text follows; doc deletes at close.
      (234: FOLDS INTO 202 — the class belongs on closure.Closure while
      the composers live in the root package, the split 202 closes;
      doing it first is the work done twice.)
      DISSOLVED at audit 285 (2026-09-29): folded into 202 at audit
      234 and again in 261's record; the typed downgrade class the
      engine verdict reads is 202's (A4 there).
- [x] 200. gofresh: the mega-requirements decomposed — REQ-closure-
      shared-dynamic-state (one 8,300-word paragraph, 224 cites),
      REQ-closure-observability-analysis, and REQ-closure-test-variant-
      compartment (four separable contracts) split into per-sub-contract
      IDs so a sub-rule's edit re-consents itself alone and a cite names
      a rule; every cite and binding retargeted through the tool; before
      193 so the fixpoint's clauses have addressable IDs.
- [x] 201. gofresh: the API-surface sweep — pre-v1 clean break: the
      implicit-environment overload families collapse to their explicit-
      environment form (guard.Capture/CaptureContext/CaptureForContext
      and siblings, runtimeinput.Adopt/Incomplete/Absolute/Relative/Dirty,
      ScanPureDirectivesWithBuildFlags, closure.NewAtContext); the
      exported functions whose signatures require internal/gotool's
      EnvSnapshot unexported or the type promoted; six dead functions
      deleted; the two fixture packages under internal/ rehomed under
      closure/fixtures; the three-hop testvariant alias chain cut to one;
      one release; pew's one call moves at its bump.
- [ ] 203. gofresh: reconcile memo ownership and versioning (gofresh
      docs/issues/memo-scope-axes.md and per-file-memos-one-shape.md).
      Active destination: tooling-redesign **7.8**; cost changes require
      7.7 first. Preserve completed selected-content/admission/source-position
      dependencies while sharing per-file containers and per-pass reads;
      separate cone composition from whole-pass state. Reconcile listing
      scopes/stamps, injective keys, payload versions versus recorded-proof
      compatibility, served summaries and phase vocabulary. Use independent
      literal/property controls, retaining existing scan/listing bindings.
      Replace stale version narratives with the actual bump rules. Closed
      315's unfulfilled standard-source digest memo is conditional cost work:
      measure repeated reads, then reuse only within a proven immutable
      generation, never by version/path/operation name alone. Do not reopen
      its completed audit, release or traversal tests.
- [ ] 204. gofresh: auditset's receiver side as one table — the five
      parallel method tables retain distinct receiver/authority rules.
      Active destination: tooling-redesign **7.1**; constituent 7.8.
      Preserve the existing ReceiverMethod ladder while folding inventories
      and rehoming BoundedToken. Include flag, class-B and harness-family
      table obligations: every fold/static/dynamic/body-cut/outcome reader
      follows one inventory, but storage proofs, observable effects and
      outcome methods remain distinct. Entropy refinements require separate
      compatibility proof, not an incidental admission expansion.
- [x] 205. gofresh + consumers: one guidance plumbing — an exported
      embed-accessor shape and a Progress diagnostic sink in gofresh; at
      each consumer's next bump the three identical accessors read it,
      gomutant's and pew's knob prose renders from the document as
      stipulator's does (REQ-guidance-single-source), and the vouch
      grammar's three copies read ParseVouchEntry (rides
      vouch-file-consumer-homes).
      (234: plumbing only — the embed accessor and the terse-clause
      projection shared by the three consumers; the terse-clause RULE
      stays with 184, the user's call.)
      (234/237: the terse-clause projection is a property of the
      format — guidance.Knob.Clause() exported here; stipulator's
      KnobClause folds at 250, pew's 173 consumes at 253; 184's RULE
      stays with the user.)
- [ ] 206. gofresh: consolidate equivalent verification setup while
      preserving independent oracles. Active destination:
      tooling-redesign **9.3**; constituents 5.6 and 7.7. Re-census writers,
      cache-home/memo-root/hook ownership, shared helpers, ambiguity controls,
      reference-scan budget and obsolete tier names. Preserve independent
      assertions and complete API-root coverage including resident's explicit
      environment exception. Extend generated chain/content controls where
      still missing; reconcile actual cgo/non-amd64/race premises and current
      CI timings/records-pin policy. Broader scheduling requires measured
      equal-population benefit and safe ownership; no historical count or
      completed fixture-sharing change proves that premise.

## Band H — gomutant under the emergent shape (chartered by audit 195)
- [x] 208. gomutant: three correctness faults the audit found — the
      baseline path classifies a build failure by matching the harness
      output for "[build failed]" (a passing baseline whose test prints
      the string refuses) where results.md names the harness's own event
      and buildRejected beside it already reads that event; the
      load-time toolchain floor (go1.24, build events) refuses every load
      but the attest path's provenance check omits it, so attest admits
      a toolchain the load refuses; the MCP ephemeral derives oracle
      bounds twice so `oracle_memory_mib:-1` yields the default ceiling
      on MCP and unlimited on the CLI — one derivation, one meaning.
- [x] 207. gomutant: face parity through one rendering seam — the MCP
      attest_survivor writes the document, echoes, then loads a tree and
      demotes the load ladder's refusal — a toolchain skew, the go1.24
      build-events floor, or a GODEBUG that silences those events — to a
      posture warning where REQ-exec-provenance runs the check before
      the write (the CLI does), and the ladder's environment arm —
      input-decidable — sits at the load's head, after the lock
      REQ-exec-preparation places last (the one stage order decides
      its stage)
      and REQ-exec-preparation wants one stage order on both faces; the
      banked summary (REQ-exec-banked-summary, face-neutral) renders on
      the CLI alone while cancellation is an MCP campaign's ordinary end;
      the audit's disagreement rate rides the CLI report, not
      RunSummary; four grammars hand-mirrored (decisions, analysis
      events, execution events with the audit-flip payload folded flat,
      the banked epilogue) become Text() methods beside
      PreparationEvent's, RunSummary carrying the audit and banked
      payloads, the faces keeping prefix and column policy alone; one
      findings-path resolver, one guidance accessor, one target-source
      preamble, one delta-cut acquisition.
- [x] 211. gomutant: the vestigial and façade sweep — ~30 names with no
      caller (the non-Context wrapper pairs production never takes,
      readInput, gitref.output, gitOutput, subjectView.inspect, five
      engine helpers), the exported-but-test-only tree methods
      (FilterTargets, DescribeTargets, Load, Fresh*, InspectFinding*, the
      five merge wrappers onto their Against forms, UpdateDocument*,
      ApplyEdits, Committability, Export — which drops a version-12
      coverage bound: carried or deleted), the tracked baselines.json
      residue, the orphan panicky fixture, two false comments (a
      vanished identifier; gitref "never execs git"), the sideline
      name's ordinal arm no store has ever taken and the per-version
      narrative recording bumps with no code arm.
- [ ] 209. gomutant: reconcile reader contracts and the candidate
      contributor account against actual producer admission.
      Active destination: tooling-redesign **8.3**; constituent 9.2.
      Reconcile live cancellation boundaries, served candidate counts,
      catalog inventory, tree-root vouch reach, sideline encodings, server
      executable/document-range identity and envelope constants with their
      enforcement. Replace historical speed prose with an honest contract.
      Completed CLI version and INV-to-REQ work stays closed; remaining
      evidence-class obligations are not discharged by bindings alone.
      Readable-history floor/fixtures belong with 302 and decomposition with
      268, under the current version 16 and full-oracle policy.
- [ ] 212. gomutant: consolidate admitted candidate-result composition;
      historical drift helpers are not an approved composition model.
      Active destination: tooling-redesign **5.4**; constituents 5.6 and 6.6.
      Re-census admitted fresh/candidate-local/extension paths and consolidate
      their conservation, operator/count checks, kill attribution, survivor
      buckets and disposition carries/sheds. Retire unconsumed drift helpers
      and mechanism-only claims while preserving changed-oracle, withdrawn-
      killer, history and contradiction regressions. Changed oracle evidence
      requires whole remeasurement; no old splice producer is restored.
- [x] 210. gomutant: the vouch file at the tree root and gofresh's
      grammar (Gofresh recovery: `git log --all -- docs/issues/vouch-file-consumer-homes.md`, gomutant
      arm) — every engine opens WithDir(module dir), so in a go.work tree
      the tree-root vouches file governs nothing (fail-closed today);
      the root file read once through gofresh's ReadVouchFile and its
      entries through ParseVouchEntry, gomutant's line-for-line
      re-implementation deleted.
      (235: DISSOLVES INTO 246 — the bump chunk carries the vouch-file
      arm beside the rest of the gofresh consumer seams.)
      DISSOLVED at audit 286 (2026-09-29): done — gomutant.go:335
      reads the tree-root file through gofresh.ReadVouchFile,
      ParseDynamicStateVouches forwards to gofresh.ParseVouchEntries,
      engines carry WithoutRepositoryVouches() (landed at 246/278).
- [x] 213. gomutant: one seam struct — fifteen mutable package-level
      test seams across run.go, schedule.go, ephemeral.go, and
      freshness.go, two of them duplicates of one engine function each
      (coveredPositions ≡ campaignCoveredPositions, groupBaselineProbe ≡
      phaseBaselineProbe), and the seam fields on Options, in one struct
      in one file.
      (235: grown and pulled forward — C5: two production sites call
      engine.TestProbeObservedEnv past both probe seams, one of them the
      killer-scoped baseline (a verdict-bearing path): a stubbed seam
      leaves the confirmation unmeasured; sixteen root seams + six face
      seams + SwapGoVersionSamplerForTest with no non-test caller.)
- [ ] 214. gomutant: the engine's catalog and spawn fan (gomutant
      docs/issues/engine-run-scoped-oracle-value.md)
      — Active destination: tooling-redesign **7.4**; constituents 5.4,
      7.1 and 7.8. Bind run-owned bounds/environment once, preserve concurrent
      operation isolation and explicit memory/width/command/oracle/analysis
      policy, and refuse overflowing MiB conversions. Distinguish collection
      targets from physical admission instead of selecting either old formula
      by precedent. Consolidate live catalog ranks/emitters, init ordinals,
      merge attribution and shared Go flag grammar; preserve quoted values
      and explicit-empty selection. Remove verified dead engine entries.
      Measure current candidate materialization before lazy construction,
      preserving exact sources, identities, extents and discard/dedup behavior.
- [ ] 216. gomutant: one classified evidence check — evidencePrecheck
      and inspection projections agree where they ask the same question.
      Active destination: tooling-redesign **7.8**. Reconcile body/shaped
      policy, resource/regime and runtime-state checks under complete keys;
      share only endpoint-coherent work and retain verify-on-reuse and whole
      compared reasons. Preserve shaped-path injection and independent
      refusal controls; a common memo key grants no absent evidence.
- [ ] 217. gomutant: record-parse discipline — LoadExemptions and
      LoadEphemeralAttestations need their own contract's complete refusal
      ladder. Active destination: tooling-redesign **9.2**. Reconcile unique
      keys, nulls, unknown fields and trailing data in inline, nested and
      interned historical/current records, with field-inventory controls.
      Current writer version is 16; preserve malformed input until judgment,
      valid siblings and readable history without upgrading policy/support.
      Keep the bank's deliberately lenient contract distinct.
- [ ] 218. gomutant: the store's report path (gomutant docs/issues/
      store-report-path-walk.md). Active destination: tooling-redesign
      **7.8**. Measure residual report work beyond existing caches; share
      entry facts only under complete content, layer/document, policy and
      external-evidence identities. Read write routing for placement, retain
      requested current judgment and full inventory; stat alone is insufficient.
- [ ] 219. gomutant: reconcile verification setup and witness gaps
      against current source. Active destination:
      tooling-redesign **9.3**; constituents 5.6, 6.4 and 6.7. Re-census
      fixture/copy/git/cache/seam helpers and share setup with independent
      face expectations and unexported root reach intact. Preserve existing
      writer isolation and hermetic git maintenance controls. Reconcile all
      eighteen issue-listed unbound MCP witnesses and actual export/model,
      envelope/phase/grammar/memory gaps against current clauses. Pin real
      window cliffs, nonempty residue sheds, whole-state external relinks,
      failed ping writes and post-write recovery. Observe heartbeat events,
      not wall-clock counts. Windows-native execution requires an actual
      runner/caller; keep its trigger through 9.4, never count cross-builds
      as execution. Clean binary files do not identify a live MCP process.
- [ ] 220. gomutant: the named smalls — the ephemeral option tuple onto
      EphemeralRequest and other surviving duplicated mechanics.
      Active destination: tooling-redesign **5.6**; constituents 5.5a,
      8.3 and 9.2. Re-census bank-key composition, skip-radius/DarkPackages,
      lock-ignore, receiver mutation, context-aware I/O, preambles/path
      vocabulary, install/report helpers and native wire copies. Retain
      distinct wire edit forms and lexical/resolved absent-path containment.
      Remove verified dead/test-only exports and obsolete drift/coverage
      helpers with bindings retargeted. Common list bounds retain exact
      omissions and their actual populations; run/findings row projections
      remain 267's. No removed schedule or estimate producer returns.
- [ ] 233. gomutant: MCP campaign observability (from
      docs/issues/mcp-run-observability.md). Active destination:
      tooling-redesign **6.7**; constituent 5.5a. Provide bounded tokenless
      recovery in the resolved tree's machine-local state home, not the repo:
      run/root identity, active work, both-layer counts and terminal account
      survive lost replies/restarts. Make non-measuring preflight reachable
      or explicitly direct to it; distinguish its counters from execution.
      Preserve committed structured output on render expiry/post-write error;
      a heartbeat proves neither progress nor completion. Tasks capability
      is conditional, not a prerequisite for this recovery.

## Band R, second run — re-audit at twelve landed chunks (190, 208, 221, 207, 223, 201, 229, 211, 222, 198, 186, 224; chartered at 224's tick, 2026-09-10)

- [x] 234. gofresh: coherence re-audit — read-only, whole subsystems
      against the specs since 194 (the one-environment forms of 201, the
      canonical member form and identity strategy of 190, the vouch
      channels, the audited symbol tables); output a chartered
      consolidation set, recorded disputes, and a re-sequencing of the
      queued gofresh chunks.
- [x] 235. gomutant: coherence re-audit — the harness-classified baseline
      and load ladder (208), the two faces' parity and the banked
      summary (207), the collapsed public surface (211), the window cost home (186), the findings
      document's version paragraph; same output.
- [x] 236. stipulator: coherence re-audit — the one witness pipeline
      (223: tracker, judgment, residue), the verb cores and the one
      projection (224), the provenance and module-root coordinates (221),
      the record stores (170), the spec's declared gaps (222); same output.
- [x] 237. pew: coherence re-audit — the bump's vouch and closure-strategy
      handling (229), the verdict path, the store; same output; closes
      with the cross-repo replan (the lane below it re-sequenced).
- [ ] 238. stipulator: the parent-hosted engine loads' owned boundary
      remains distinct from contained runner children. Active destination:
      tooling-redesign **5.5**; constituents 7.1 and 7.8. Establish actual
      loader descendant cancellation under a capability the loader supplies;
      no existing runner hook reaches those children. Reconcile the declared
      gap only with that boundary. Attribute dynamic-state explain's whole-
      discovery cost and share or host its load only while preserving the
      same policy-scoped views, generation-qualified hooks and caller context.
- [x] 239. gofresh: the environment, toolchain, and go-command policy
      exported (234 C1/A1/A5) — gofresh owns the whole policy and
      publishes none of it: internal/processenv (Normalize, ForCommand,
      ForGoPackages, Lookup), canonicalDir, and the `go env GOVERSION`
      sampler REQ-fresh-toolchain-skew specifies but does not implement.
      One public home beside gofresh/gotool; the sampler exported; the
      substrate paragraph names gotool. Consumer arms at their bumps:
      pew's internal/gotool (a divergent dir policy), stipulator's
      normalizeEnv copy, and the three provenance samplers delete.
      Release before the bumps.
      (236: gofresh's gotool.Run isolates no process group; the export
      carries a spawn hook (or the boundary's own form) so stipulator's
      REQ-go-owned-processes survives adoption.)
      (237: also exports the verdict reason vocabulary as constants —
      pew's §7.9 rule keys on the bare literal "test variants" across
      the repo boundary.)
- [ ] 240. gofresh: reconcile memo/recomputation, provenance, resource
      and native-record contracts.
      Active destination: tooling-redesign **9.2**; constituents 7.4 and
      8.3. Reconcile against current canonical semantics, not obsolete commit-
      only keys, source-audit vocabulary or completed spawn/API work. Preserve
      typed capture refusals, caller-pin responsibility, model-discharge and
      native projection constituents, progress vocabulary and resident links.
      Distinguish GC targets/child limits from physical admission. Split
      toolchain-skew/go-command-policy bundles before adding facts; retain
      memo/snapshot rules and distinct enforcement. Re-census base/sub-ID
      bindings, independent guard/unsafe/writer witnesses, wrap-aware citations
      and clause-specific gap triggers; no old row count proves completeness.
- [ ] 241. gofresh: typed loading needs one policy and explicit ownership,
      not an assumed common lifetime across every loading path.
      Active destination: tooling-redesign **7.1**; constituents 5.5, 7.8
      and 8.3. Preserve non-nil policy environment, directory, build-flag
      validation, test variants, driver refusal and cancellation at every
      load. State the loader's actual containment limitation. Qualify explain
      hooks by tree/generation so identical package/variable names cannot
      borrow another checkout's facts. Reproduce the dependency-culprit report
      without the disproved blanket omission premise. Carry structured
      culprit/cause facts and deliberately open consumer chain vocabulary;
      preserve passive later-tree semantics and independent endpoints.
- [ ] 242. gofresh: internalize the public construction surface only
      after an actual consumer capability census.
      Active destination: tooling-redesign **7.1**; constituent 5.6.
      Internalize analysis-scope/load/memo mechanics only after preserving
      used source-audit, outcome and test-variant vocabulary through a
      coherent public boundary. Reconcile content-audit names and diagnostics;
      retarget every binding/cite and coordinate 243's verified removals.
      Neither zero importers nor a specific alias shape is assumed.
- [ ] 243. gofresh: retire verified vestiges and duplicate primitives
      after current four-repository caller tracing.
      Active destination: tooling-redesign **5.6**; constituents 5.5 and
      9.2. Retire unused Dirty/CommitInspector and static-input-root APIs
      with their clauses, references and bindings; do not invent adopters.
      Re-census guard/purity/shortgate/guidance forwarders and duplicate
      surface inventories, preserving live consumer capabilities and already
      removed gotool forms. Share JSON/quoted-string primitives only while
      preserving raw versus compacted canonicality, distinct tails, legacy
      bare roots and idempotent re-keying. Observation composition context
      work remains 361's, not an excuse to delete its semantic boundary.
- [x] 244. gomutant: the face-parity residue (235 C2/C3/C4/C12 +
      A3/A4/A5) — 207 landed one rendering seam and left the run
      epilogue written twice (the attest snapshot, the shed-dedup key at
      four sites, the incremental Commit closure, the final merge, the
      promoted and machine-local counts), the target-source dispatch
      three times (wholeTree by two expressions; CLI discover on its own
      git path), the inspection walk and the delta-cut assembly twice,
      the carry and shed sentences twice as prose where the clause says
      rows; and three fact divergences: a tokenless MCP run discards the
      analysis events the clause forbids discarding (an analysis field
      on runOut), the preparation stages fire in different orders on the
      two faces (targets_path after the load on MCP run/discover; CLI
      findings' --vouch after the load; findings' state check vs record
      read swapped), and the envelope's numbers are unpinned (the
      surfaces pin reads one section; the unreached roster cut at 20 on
      the CLI and 50 on MCP — decide whether 20 is contract). One
      epilogue, one dispatch, one walk in the root package; both faces
      renderers.
- [ ] 245. gomutant: decompose the live run loop and Tree roles by their
      actual ownership boundaries. Active destination:
      tooling-redesign **5.4**; constituents 7.1 and 7.2. Give immutable
      options/bounds/root, resolution, views, target preparation, driver and
      epilogue explicit owners; reconcile Tree roles and file homes. Preserve
      deterministic preparation/decision and window membership while adopting
      independent closing. Give run and inspection observers stable owned
      lifetimes, including synchronization of snapshot entry; do not delete
      live seams or let subscriptions trigger execution.
- [x] 246. gomutant: the gofresh bump — five releases behind at v0.99.0
      (235 C8; 210 dissolves in; 205 rides) — the consumer arms
      reachable now: ParseDynamicStateVouches deleted for
      gofresh.ParseVouchEntry, the tree-root vouch file read through the
      engine (or WithoutRepositoryVouches — the module-root reach
      decided), treecache's digest through gotool.EnvSnapshot.Identity,
      the GOVERSION sampler through gotool.Run, the six env composers
      with four key rules onto one (env-key-composition-one-rule folds
      in), the nine ad-hoc canonicalization sites; the arms that wait on
      gofresh 239's release (the env-composition rule, languageSeries,
      canonicalDir) in the same chunk if 239 has shipped, else a rider.
      Every consumer store re-measures once at the bump.
- [x] 247. stipulator: the correctness chunk 236 found — A1 one
      outside-policy accounting (the selective form counts expected
      witness subjects outside the eligible selection as the clause
      says; the full form counts executed rows that were never expected
      — one wire field, two meanings, the witness-selection problem
      keyed on it); A2 the MCP record applier writes-and-renames per
      path where REQ-record-cas stages every file before the first
      rename (a multi-write batch lands half) and A3 the admissibility
      pre-pass exists on the MCP seam alone → one record applier for
      both faces (internal/recordapply: duplicate-path refusal, the
      precondition pre-pass, admitWrite, stage-all-then-rename-all, the
      per-path notes); A11 the declaration-reading verbs open the
      whole-tree form on the CLI and the served form on MCP (a malformed
      policy refuses at construction on one face, at first answer on
      the other; one publishes resolution records, the other none) —
      one form per verb, stated.
- [ ] 248. stipulator: reconcile live reader and record contracts,
      including the remaining decomposition residue. Active destination:
      tooling-redesign **8.3**; constituent 9.2. State/pin per-reader caps
      and omitted counts, one root-discovery account and typed publication
      projections that never become verdict inputs. Replace version history
      with actual format/compatibility rules. Work through every remaining
      item in docs/issues/decomposition-editorial-pass.md: antecedents,
      exceptions, loader gap, normative bundles, duplicate/misplaced sentences,
      bindings and evidence-tier consequences. Preserve completed selection
      and certificate contracts; distinguish editorial corrections from
      semantic amendments, including snapshot provenance and historical proof
      readability. Coordinate shared vocabulary/cap mechanics with 225.
- [ ] 249. stipulator: witness, check, coverage and compilation
      orchestration need explicit evaluation ownership.
      Active destination: tooling-redesign **7.5**; constituents 5.2c,
      5.2e, 5.3, 7.8 and 8.3. Resolve the check/verifyrun dependency cycle
      around one explicit evaluator and non-measuring readers, preserving
      suite health, scoped policy and unknown/deletion limits. Fold live
      backend/ID/corpus/refusal/report assembly, not distinct producing
      transactions. Keep retry package durability, per-group tiers,
      NoOutcome and unequal per-invocation accounts; retain publication at
      quiescence through later errors. Mint executed/resolution cause classes
      at composition and preserve Gofresh-owned causes. Add bounded diagnostic
      timelines and roster/residue allocation while retaining existing UTF-8
      scrubbing. Package-producing support belongs to 5.2c/d, not automatic
      isolate-each-once proofs. Bounded export refresh and scoped discovery
      measurements remain separate from valid-current evidence grants.
- [x] 250. stipulator: the gofresh bump — v0.101.0 → current (three
      releases behind, two breaking; v0.101.1's canonical strategy @2
      restales every witness record) — riding gofresh 239's release so
      C16 lands in the same bump: normalizeEnv/setEnv/dropEnv/lookupEnv
      and effectiveGoEnv onto gofresh's exported env policy, the
      GOVERSION sampler onto gotool (with 239's boundary hook), and 178
      (the scratch namespaces' group-key segment) in the same chunk, so
      the store re-executes ONCE for the three moves; KnobClause
      offered to gofresh's guidance as the terse-clause export pew 173
      will need.
- [x] 251. pew: one recording-key registry with per-key marks (237 P1;
      audit-note-keys-mirror-the-spec folds in) — the record's key set
      is six lists (RecordingConfigKeys, the toolchain key twice,
      recordingConfigKeys and its admission twin, IsRecordingShape's
      mandatory literal, compare's audit names) plus the spec table plus
      six test builders: 229 added one key and touched all of them. One
      row per key {spelling, mandatory, omittable, audit, display name}
      read by the writer, the shape check, the foreign-key check,
      admission, the ignore set, the audit notes, and one test builder.
- [ ] 252. pew: retain one semantic rule per surviving
      path/module/store/progress concern.
      Active destination: tooling-redesign **5.6**; constituents 7.1 and
      8.3. Re-census containment and longest-existing-prefix resolution,
      module metadata, duplicate GC walks, cancellation between destructive
      units, progress composition, completion-marker/raw-line grammars and
      actual wrappers/vestiges. Preserve active A/B selection and intentionally
      wider inactive-tag GC inventory, both using benchmarksInFiles; do not
      misclassify that difference as a parser defect. Git containment, metric
      registry, native envelope and producer adoption are already complete.
      Fold only demonstrated duplicates, preserving distinct refresh/profile/
      overwrite and guard-missing semantics and independent expectations.
- [x] 253. pew: the gofresh bump after 239's and 205's releases — the
      go-tool consumer arm (pew/internal/gotool's six importers and its
      divergent dir policy onto gofresh's exported policy with 239's
      boundary hook; the GOVERSION sampler onto gotool), the verdict
      reason vocabulary consumed as constants, guidance.Knob.Clause
      consumed (173 follows). The store re-measures once at the bump.
- [ ] 254. gomutant: the gitfs run-surface asks (field reports
      on purity and attribution) retain distinct authority questions.
      Active destination: tooling-redesign **6.3**; constituents 6.2 and
      7.3. Name actual execution flips independently of reuse/volatile-input
      refusals and placement; partial, failed or unknown advisory work is not
      stability. Derive root/subject-scoped recorded purity permission and
      revocation separately. Future negatives need complete locality and
      influence authority; removed scheduler estimates, batch audits and
      reach-only exemptions are rejected, not unfinished implementation.
- [ ] 256. gomutant: the document face's attest gains `--reattest`
      and explicit withdrawal with retained reasons. Active destination:
      tooling-redesign **6.6**; constituent 9.2. Preserve selected record and
      both-layer ownership, previews and history on both faces. Extend file/
      oracle/selection lifecycle to ephemeral attestations without silently
      re-anchoring dirty/new-file producing provenance or upgrading execution
      policy. Existing ephemeral replacement does not satisfy findings lifecycle.
- [x] 257. gomutant: a delta campaign's freshness proofs bounded by
      the delta (field report freshness-proofs-stall-on-large-record-
      sets, 2026-09-19: a `run --changed` over a 292-record document
      spends its whole budget in per-target freshness and a "proofs
      (union over N subjects)" pass that scales with the document —
      1608 subjects, 8 GiB resident, nothing measured) — the union
      priced by the delta's targets and their oracle closures, proofs
      persisted per subject and served across runs, memory bounded;
      the report's shape the measure at open and close. Directly after
      the bumps 246/250/253.
      (262: the trigger corrected — 253 is pew's bump with no bearing on
      gomutant's proofs; the precondition, 246, has landed: 257 runs FIRST
      in gomutant's order. Its open triages gofresh's
      analysis-budget-and-static-roots-unadopted (now static-input-root-unadopted, the budget half adopted here): gofresh.WithAnalysisBudget
      is the ready mechanism nothing calls, and subjectViewSet.observed is
      the unbounded union the report names.)
- [ ] 258. gomutant: the evidence walk's faults stamp their own clause
      rather than dirty git provenance. Active destination: tooling-redesign
      **5.4**; constituents 5.5 and 8.3. Keep record-wide unavailable evidence
      separate from each subject's observation and preserve the intentional
      completed-process union. RuntimeAttribution clearing is already repaired
      and changed-oracle splicing retired; analysis-unavailable stamping remains
      the live case. Carry actionable missing-view/manifest and cancellation/
      stderr causes through current contained readers. Add CLI explain as a
      projection of the semantic reader with recorded/judged distinctions.
- [ ] 255. gofresh: a downgrade reason names its invoke site — a
      semantic diagnostic, not a claim of observed execution.
      Active destination: tooling-redesign **8.3**. Carry call expression, operand
      type and reached sink so consumers distinguish conservative invoke
      enumeration from an established path; do not parse prose for authority.
- [x] 259. gofresh: the runtime-input classification's origin and the
      root input (field report root-directory-input-with-empty-manifest,
      2026-09-20: a pb campaign's records carry `external directory
      input: /` on every evidence subject with an empty manifest — the
      classifier handed the literal filesystem root by an origin the
      record does not name; expected: a runtime input names the
      observation that produced it — the bracket root, the environment
      form, the default — and an empty manifest classifies as no input,
      never as the root; the scoped reproduction at 250's close over
      pb's validatePath under its scratch namespace did not reach the
      shape (unverifiable earlier on rapid's shared state) — the measure
      at open is pb's ExtractZip campaign under its standing vouches).
      Directly after 200, before 240.
      (261: the path classification extends runtimeinput's existing origin —
      process observations carry one, classifyPath's `/` reason names none —
      never a second origin concept.)
- [ ] 260. gofresh: the iterator's yield bound at the range statement
      and standard interface targets need exact reductions.
      Active destination: tooling-redesign **7.8**. Reproduce pb's SplitSeq return
      flow and local SHA-256/Hash.Sum shapes against current SSA/RTA; existing
      iterator positives preclude the old blanket conformance diagnosis.
      Preserve operand closedness, target/method-set completeness, promoted
      body and audit limits. Fold dispatch predicates and value/cell traversal
      only with their distinct fail-closed policies; uncertain targets keep
      the full conservative projection.

## Band I — stipulator under the emergent shape (chartered by audit 196)
- [x] 261. gofresh: coherence re-audit (the third re-audit band, fired
      by the twelfth landed chunk since 234–237: 239, 244, 247, 231,
      200, 213, 227, 205, 246, 250, 253, 251) — read-only, whole
      subsystems against the specs since 234: the gotool policy and its
      three consumer arms (239, 246, 250, 253), the guidance and
      diagnostics plumbing (205), the closure decomposition (200), the
      field-report chunks chartered since (254–260); output a chartered
      consolidation set, recorded disputes, and a re-sequencing of the
      queued gofresh chunks.
- [x] 262. gomutant: coherence re-audit — the face-parity residue and
      the seams (244, 213), the bump's registry and knob-clause folds
      (246), the exit log and the ledger since 235; same output.
- [x] 263. stipulator: coherence re-audit — the correctness chunk (247),
      the vestigial sweep (227), the bump with the scratch namespaces
      and the environment policy (250); same output.
- [x] 264. pew: coherence re-audit — the conformance half (231), the
      bump (253), the recording-key registry and the one test builder
      (251); same output; closes with the cross-repo replan (the lane
      re-sequenced from it).
- [x] 265. gofresh: gotool's second half — what the three bumps left every
      consumer building for itself (261 C1/C2/C3/C4/C6/C7 + A1): a
      containable, streamed go spawn under the policy (a prepared command
      with the derived PWD, one process-group containment and wait-delay
      rule; gomutant's process_*.go, stipulator's command*.go, pew's
      runCommand delete — the evidence-producing spawns that today set
      cmd.Env raw), the toolchain-provenance composite (memoized sampler
      keyed by the resolved dir and env + the typed refusal; three copies
      with byte-identical prose), an environment setter (gomutant appends,
      stipulator inserts in sort order — one rule, gofresh's), the vouch
      SET rule (parse-many, dedup, sort; ParseVouchEntries, relayed at
      246), a multi-key go-env read with a lazily self-taking snapshot
      (three snapshot-or-probe ladders and three line grammars delete;
      the snapshot stays pass-scoped), and the degrading canonical
      directory (CanonicalDir → Abs → spelling: pew's CommandDir and
      gomutant's rootCoordinate are one function, stipulator keys its
      store on a third rule); gotool's doc stops claiming the hook
      reaches gofresh's own spawns until an Option installs a runner.
      A release; before stipulator 238, whose loader arm it unblocks;
      the consumers' arms at their next bumps (gomutant's provenance.go
      carries a preparation-stage driver refusal REQ-exec-preparation
      requires before the first load — the bump keeps that arm).
      (257: also exports the progress event's per-unit classification —
      Progress.IsUnit() or an exported phase set — so a consumer's
      stretch vocabulary reads one home; gomutant's
      analysis-unit-phases-one-home lands at its bump behind this
      release.)
- [x] 266. gofresh: the guidance face projections (261 C5) — a pflag-
      flavoured and a JSON-schema-flavoured projection on Document/Knob
      and one cobra/MCP registration shape, replacing the three consumer
      triples (same panic wording), the two knobSchema copies that have
      already diverged (stipulator recurses into nested objects and
      Items, gomutant does not), and the two knob→usage grammars;
      184's rule stays the user's. Rides 265's release.
- [ ] 267. gomutant: the run's reader-facing vocabularies one source on
      both faces. Active destination: tooling-redesign **8.3**;
      constituents 6.3 and 6.7. Re-census phases/actions, resource refusals,
      loading/preparation and lifecycle empty-match accounts; use semantic
      facts with reader-specific rendering. Preserve cumulative cadence
      through final merge/render and establish historical deadline-overrun
      cause independently. Project run/findings/explain rows once with routed
      layer, reason, absent/empty delta and correct physical/merged/commit
      populations. Publish structured sheds/carries and derivation facts,
      declaring wire changes; carry them through partial recovery. Retain
      bounded panic/frame output, exact list omissions and face-neutral terse
      knob clauses at every depth. A removed scheduler has no vocabulary to
      rebuild; callback presence grants no execution authority.
- [ ] 268. gomutant: decompose the live bundled requirements into
      addressable current subcontracts. Active destination: tooling-redesign
      **9.4**. Re-census mutation operators/basis, stale-result admission,
      run status, ephemeral execution, layers, oracle execution, attribution,
      attestations, lifecycle, export, MCP surfaces, preflight and analysis
      budget/proof-unit lifecycle. Preserve normative strength and every
      constituent's bindings/consent/citations through the split, with
      wrap-aware and normalized-text checks. Historical counts and removed
      drift carve-outs are not current scope; retain completed INV-to-REQ work
      and reconcile any remaining evidence-class deficiency explicitly.
- [ ] 269. gomutant: one test-stream judgment — internal/engine/run.go's
      live readers need consistent authority. Active destination:
      tooling-redesign **5.4**. Re-census decoders and consolidate corrupt,
      truncated, build-rejected, package-crash and test-attributed outcomes,
      preserving baseline disposition and compiler-crash retry precedence.
      A malformed stream cannot become a passing verdict or fabricated
      completion receipt. Add independent generated outcome-stream evidence
      for attributed kills and bounded crash diagnostics. The removed
      coverage-schedule producer and its batch-build breaker stay retired.
- [x] 270. stipulator: the corpus's mega-requirements decomposed into
      per-sub-contract ids on gofresh 200's mechanics (263 A1) —
      REQ-evidence-witness-freshness (one 306-line paragraph, ~20
      contracts, 99 of 1,051 bindings), REQ-check-verdict,
      REQ-go-owned-processes, REQ-mcp-progress, REQ-go-policy-complete,
      REQ-policy-attribution, REQ-check-preparation, REQ-mcp-tools,
      REQ-evidence-witness-cache-format; the corpus that specifies the
      clause mechanism declares no payload list and carries no clause
      binding — one coverage cell answers for twenty contracts and one
      re-consent restales 99 pins. 226's clause-split opening lands here;
      176 measurable after it.
      Audit 287 (2026-09-29): grows and MOVES UP (directly after the
      bump 290; it gates 176's measurability and 238's gap and bounds
      293's amendment) — the measured census:
      REQ-evidence-witness-freshness is one unbroken 306-line
      paragraph (evidence.md:193–498) carrying ~20 contracts and 99 of
      1,076 bindings; REQ-go-owned-processes 79 lines / 34 bindings /
      eight contracts behind one gap;
      REQ-evidence-witness-cache-format 116/19; REQ-check-verdict
      49/32; REQ-mcp-progress 43/30; add REQ-policy-cancellation (23),
      REQ-evidence-resolution-freshness (22), REQ-mcp-views (21),
      REQ-policy-explicit (19).
      Grown (2026-10-06, audit 318): REQ-policy-cancellation's ending names the resolution records Quiesce publishes before execution (aborted-pass's clause half); the three memory-return pins 190eeb2 landed 'unbound by design' get their clause (the release of each leg and of the group's view); REQ-evidence-resolution-freshness's 'answered from what it kept' squared with the respawn for an unheard symbol (5b03427); the census re-measured (REQ-evidence-witness-freshness 111 bindings/344 lines, REQ-mcp-progress 43/63 — its CLI exit-status and signal rules move out of mcp.md); RULE until 270 lands: no new sentence is appended to a 270 target — a new fact gets its own clause.
      Audit 6 (2026-10-07): re-census at open: REQ-evidence-witness-
      freshness is 357 lines and 114 bindings (344/111 at 318; 306/99 at
      263) — 298 bent 318's rule by splicing the breadth-first
      precedence, named values and dot-imported drivers into the
      paragraph in place; the rule restated: no new fact enters a 270
      target paragraph, appended or spliced (a new fact is its own
      clause, as 299 did). Before the evidence-model plan's 6.1 opens,
      its owner told at open (D2: PE 6 then amends sub-ids, not a
      357-line paragraph).
- [x] 271. stipulator: the two faces' refusal ladders and projections one
      source (263 A2–A5, C3) — verify's record-only hygiene refusal on the
      MCP (today a witnessless summary reads as a clean pass); pin's ids
      form all-or-nothing on both faces (the CLI writes ids 1–2 before
      id 3 refuses); an id list reducing to nothing refused on the CLI
      (`check --ids ","` runs the global pass today); the explicit-empty
      backend one rule; the CLI gap list a projection of GapReport;
      every MCP remedy through the composers (three hardcoded); the
      red-row ladder ×3, SuiteHealthy re-implemented, the heading twins,
      Tally recomputed from wire rows. Correctness first.
- [x] 272. stipulator: the bump behind gofresh 265/266 — the gotool
      copies (command*.go, the hand-built sampler, setEnv/envEntryLess,
      the nine-key go env read, resolveOrSelf and the raw store keying)
      and the guidance projections (knobbedTool/knobSchema,
      renderKnobUsage) delete; go-version-sampler-outside-gotool and
      effective-go-env-sample-outside-gotool close; the policy record's
      stale budget rationale (gofresh v0.85.1, 2026-08-26) re-measured;
      238 unblocks. When 265 and 266 have released.
- [x] 280. stipulator: the self-host warm path — CLOSED BY VERDICT at
      open: the charter's premise (an engine-building witness never
      serves) came from warm runs made with --full, which executes the
      whole accepted policy by definition; a plain warm check over the
      same store measured 52.1s, 676 served fresh, 94 executed (readers
      of docs/, changed between the runs), 20 uncacheable. The memo-file
      entries in a manifest are per-identity uncovered reasons that seal
      an observation proof, never a plain serve. The resolution cache's
      empty race selection stands filed (Lands 226).
- [x] 281. gofresh: gotool's containment over a consumer's own command
      (chartered at pew 275's close) — Containment is applied by Runner
      alone, which prepares `go` only; gomutant's oracle, stipulator's
      resolver child, and pew's runCommand each carry a hand copy of the
      process-group boundary for their non-go spawns. An exported form
      over an arbitrary command (Containment.Command(ctx, dir, env, name,
      args...), or the boundary over a prepared *exec.Cmd) under the same
      policy Runner.Command applies, pinned once; the three copies delete
      at the consumers' next bumps. A release before those bumps; after
      277 in the lane.
      Audit 285 (2026-09-29): grows — the largest release of the
      cluster: (a) a listing-shaped reader with one salvage decision
      (gomutant salvages a go list with a hand-spelled predicate,
      stipulator refuses one — one clause, three answers); (b) two
      toolchain samples, one policy-bearing
      (gotool.Runner.SampleGoVersion, memoized, salvage-aware) and one
      not (guard/guard.go:169 unmemoized per Capture, returning on any
      error) — one sample; (c) a zero ToolchainProvenance silently
      drops the policy (provenance.go:145 mints a Sampler with the
      zero Runner when the field is unset — Structural-check: the
      default is representable and wrong); (d)
      sampler-failed-sample-memo-unpinned (resolved at 281.C; `git log
      --all -- docs/issues/sampler-failed-sample-memo-unpinned.md`, gofresh)
      moves here
      (gotool/gotool.go:171–178 unpinned; stipulator retired its pin
      at 272 on the premise gofresh covers it); (e) the roots probe is
      a second go env keyed on the raw dir and raw env order
      (runtimeinput/roots.go:69–79) against Sampler's
      Coordinate+normalized key, a process-global sync.Map never
      evicting; (f) gomutant's 286 asks: a containment for a non-go
      program (three consumers hand-roll it; gomutant's git spawns
      have none) — Runner.Command hardcodes go — and the GOVERSION
      series parse exported (gomutant's parseGoVersion and releaseTags
      re-parse it).
- [x] 274. gofresh: the fingerprint record's published wire form (263 C1)
      — stipulator's witnesscache.Fingerprint (17 fields + ToGofresh +
      reverse + a shape-guarding UnmarshalJSON), gomutant's two mirrors,
      pew's field reads each mirror gofresh.Fingerprint, and
      stipulator's REQ-evidence-witness-cache-format carries gofresh's
      key list as its own contract because none is published: gofresh
      publishes the record form and its validity semantics (an absent
      strategy reads empty and fails closed; a code fingerprint carrying
      a machine or runtime guard is refused; unknown fields refuse); the
      mirrors delete at their bumps, the spec block shrinks to a
      reference. After 266, before the consumer bumps.
- [x] 275. pew: the bump behind gofresh 265, 266, and 274 (264 C1, A1,
      A2, C3) — internal/gotool's composition, runCommand's containable
      spawn, provenance.go's memoized sampler and refusal class, the vouch
      grammar and filename, the four single-key go-env/module probes, the
      guidance projection triple, and the fingerprint field reads delete
      for gofresh's published forms; the engine diagnostic line rendered
      through Progress.Diagnostic/DiagnosticsTo (pew's hand rendering has
      diverged: a double space on an empty Package, no multi-line fold,
      an unsynchronized sink); format-rung-two-readers closes here.
      Invariants kept: the nil-env-inherits contract, the typed
      environment refusal distinct from the skew refusal, the cancelled
      sample never memoized. The store re-measures once.
- [ ] 276. pew: complete independent generated assurance over the
      current producer and record surfaces. Active destination:
      tooling-redesign **9.3**; constituents 7.8 and 9.1. Extend existing
      native-envelope, corruption, comparison, profile and A/B generators
      with independent stream/conditions/topology/policy and pin-ladder
      expectations; retain actual process terminal and asymmetric diagnostic
      controls. Native producer-premise evidence already landed. Re-census
      binding gaps, self-oracles and production-engine construction rather
      than reuse old counts. Exercise completed cold/warm/discarded facts
      separately from budget availability. Exact campaign scopes remain 366's
      ledger and require explicit authorization, not a dependency bump.
- [x] 277. gomutant: a delta run's preparation scales with the delta
      (pb's second field report at 257's close: over a 308-record document a one-target and
      a 73-target `--changed` run spend the same first quarter hour — the
      closure signpost over every prior record four minutes, one
      target's freshness proof five more, 9.5 GiB peak) — the
      inspection of prior findings scoped to the run's targets, the
      records outside the delta read and never judged until a run over
      them asks (REQ-result-run-posture's pass over the run's records,
      REQ-exec-preparation's order kept); the signpost's cost priced
      like the proof passes. Riders (277.1, 2026-09-22): the bump's
      readers — toolchainProvenance adapts ToolchainProvenance.Check's
      (sample, error); the unverifiable read attributed to the subject
      whose observation carried it or named the union's, through
      Observation.Attribution (pb's guidance field report); the gap on REQ-exec-go-command-runner closed (gofresh 279
      landed the two readers' salvage). After 282 and Band R4.
- [x] 282. gomutant: record verbs over both layers (chartered at 277's
      open from pb's field reports, correctness first) — prune reports a
      machine-local record removed and leaves it in the overlay, re-emitting
      the repo document whole; a package retarget writes one record short
      and reports the whole count, and the identical rerun refuses the
      batch naming the dropped record as a collision (the check meeting
      the re-judged view of the record it rewrites); a prefix retarget
      re-emits the whole document (unordered tables in visit order) and
      re-digests 144 records' evidence under a rename of 21. The verbs act
      on the overlay as on the repo document; a verb writes exactly what
      it reports or refuses whole; the collision check over stored
      identities; tables emitted in a stable order so a document with no
      semantic change diffs as its rows; the banked and per-target
      decision lines name the layer each record landed in; the rename's
      re-digest cost measured with a campaign over the retargeted
      document at the open (whether the 144 re-measure). Directly before
      277 in the lane; the twelfth landed chunk since Band R3.
- [x] 283. gomutant: Store.Update returns the layer it routed each
      record to (gomutant
      recovery: `git log --all -- docs/issues/store-update-returns-its-routing.md`, filed at 282's
      banked-line review) — the write's
      routing the one source the ledger, the tallies and Finish read,
      the post-write re-classification through the store's predicate
      retired; the seams of both faces and their tests carry the
      report. After 282.
      Riders (2026-09-29 replan, derived from first principles — no longer user forks): (1) retarget rewrites the reviewed exemption record's subjects under the prefix pair beside the document — a subject is identity, the acceptance (reason, rationale) is the reviewed content and does not move, attestations already follow their mutants, `check` previews the diff and git holds it; the carried-subject refusal 282.B landed retires. (2) a run that demotes a standing repo row states the demoted count as it states the promoted one (gomutant findings-doc-demotion-unstated: the same kind of document change, read from the write's routing this chunk returns).
      Audit 286 (2026-09-29): grows — (a) REQ-result-lifecycle's
      per-layer counts are unimplemented on both faces
      (PruneResult.Kept one int over both layers, lifecycle.go:62/66
      with Revise already passing the layer; RetargetResult.Touched
      likewise; retargetOut.Touched's served schema at server.go:2033
      promises a per-layer number that is an aggregate) — the same
      edit as the routing; (b) the exemption rider names its amendment
      set: REQ-result-lifecycle's refusal sentence and its rationale
      (results.md:1144–1152, lifecycle.go:434 detachedExemption),
      REQ-result-exemptions' 'a stamp names the old subject until the
      next measurement re-derives it', and mcp.md:143's retarget row.
      TRIAGE FOLDS at 283.1: REQ-exec-go-command-runner's closing
      sentence ('which discards it today', execution.md:1402) is false
      since gofresh 279's salvage and the v0.107.0 bump — amend it,
      retract .stipulator/gaps/exec-go-command-runner.textproto (its
      condition fired at 277's bump), and buildset.go:85 calls
      gotool.Salvaged instead of re-spelling it; results.md:148's
      INV-RESULT-CANDIDATE-CONSERVATION pointer names
      TestGrowFindingCountsReplacesSurvivorOutcomes, removed at
      4690ca2 with no successor — repair the pointer (the binding half
      stays at 209); the register chore (A10) landed in this tick.
- [x] 284. gomutant: self-campaign oracles gomutant can afford, then
      chunk 277's close-out campaign (gomutant issue
      self-campaign-oracles-cost-a-day): the root package's 22-minute,
      539-test integration binary is every root-package target's derived
      oracle and its tests read /usr/bin/git outside the bracket, so
      277's campaign over `--changed 9753a5e` costs a day and commits
      machine-local records; the chunk decides the layout under which a
      target's oracle is the tests that exercise it (integration
      campaigns in their own package or build configuration, or an
      explicit-oracle targets document), preserving every test and its
      bindings, then runs the campaign with the derived oracle timeout
      and `--bracket-path /usr/bin/git`. In the lane directly after 283.
      Rider (2026-09-29 replan): the observed union's proof pass bound (gomutant observed-union-memory-slicing) is decided here by measurement, not by a product choice — the affordable self-campaign is the case that pays it: slice the union to the resident bound the host guard enforces and measure the repeated-load cost against the unsliced pass; the shape with the lower wall over this repo's own campaign lands.
      Dissolved (2026-10-06, audit 317): the layout half landed at 284.A (6c90a16); the campaign half is 302's close measure (its parked 42/89 prefix void: bank v1 empty since 304, records predating the selection and audit keys — resuming it is wasted work); self-campaign-oracles-cost-a-day → 302's close.
- [x] 285. gofresh: the fourth re-audit band's gofresh audit — one
      read-only Opus auditor over the repo with the eight lenses (the
      designR shape), output a disposition tick and issue docs, no
      code; chartered at the 2026-09-29 replan (thirteen whole chunks
      landed since Band R3). The band 285–288 closes with the cross-repo
      replan at 288; the audit count restarts at zero.
      Rider (2026-09-29): the auditor's brief excludes the dynamic-state
      tier's internals (purity.go, dynamicstate.go) — 202 is chartered and
      slotted directly after the bumps; a finding on the shape 202
      replaces is wasted work (the no-wasted-work ruling).
      Dispositioned 2026-09-29 (the tick's record: seventeen coherence
      findings, eight consolidation candidates, the queue walked): 199
      dissolved (folded into 202 twice over), 300 chartered (the
      guidance lint's gofresh half), 242 and 243 land together, 295
      unpinned from 243, 297 ahead of 202 (a fired field trigger
      outranks the design chunk's place), the release gate's doctrine
      sentence written.
- [x] 286. gomutant: the fourth re-audit band's gomutant audit (as 285).
      Dispositioned 2026-09-29: twelve coherence findings, twelve
      consolidation candidates, the queue walked — 210 dissolved (done
      at 246/278), 301 chartered (writer-side fixture isolation,
      directly after 283), 283 absorbs three triage folds, 268 grows
      to ten requirements, 269's count corrected to seven.
- [x] 287. stipulator: the fourth re-audit band's stipulator audit (as 285).
      Dispositioned 2026-09-29: twelve coherence findings, thirteen
      consolidation candidates, the queue walked — 270 moved up (it
      gates 176 and 238 and bounds 293), 293's amendment target
      widened to REQ-coverage-buckets, 176's false note struck, 238
      behind 270, the register chore (one resolved doc deleted, three
      retargets).
- [x] 288. pew: the fourth re-audit band's pew audit (as 285); closes the
      band with the cross-repo lane re-sequenced.
      Dispositioned 2026-09-29 — BAND R4 CLOSED: seven coherence
      findings, seven consolidation candidates, the queue walked — 173
      dissolved (landed at 275.C), 174's rider reframed (the flip is
      the store's, not a wrong verdict; the explain row per validity
      key is the work), 291 ahead of 252 with the Quit rider, 232 and
      252 and 276 grown, 127's scope sharpened. The cross-repo lane is
      in the order sentence (recorded at 285's tick); the audit count
      restarts at zero.
- [x] 289. gofresh: the weekly fleet sweep's first measured `stipulator
      check` over this repo is RED on three requirements —
      REQ-fresh-fingerprint-data, REQ-fresh-observation-data,
      REQ-guard-buildconfig — with no gap excusing any (measured at
      b34f15c; recover with `git log --all -- docs/issues/check-red-fleet-sweep.md`): the
      diagnosis first (a cold check over the current tree, the rows
      file read per binding), then the re-bind per requirement with the
      bound bodies read — never a blanket — and any row still red after
      it treated as the regression it is. Soundness first: directly
      after 277 in the lane, before the band.
- [x] 290. stipulator: the bump behind gofresh 279, 281 (and whatever
      the remote's latest tag carries at open; v0.107.0 today) —
      stipulator gofresh-corpus-pin-lag (closed at 290.2a; `git log --all
      -- docs/issues/gofresh-corpus-pin-lag.md`, stipulator); the containment
      copy 281 lets the resolver child delete rides it; the store
      re-executes once (279's declaration). After 281's release.
      Split (2026-10-04): 290.2a — the compile-breaking surface alone
      (the pin to v0.108.3, one constructor call) landed cbc9908 ahead of
      307: the lagging pin left go1.27.1-dst.13 unlisted for the
      installed binary, so every check on such a host re-executed its
      whole corpus (measured 58m53s of a 59m29s check over gofresh);
      the rest of 290 stays behind gofresh 292/297/300's releases.
      Rider (2026-09-29 replan): the two spec-amend candidates from 272.C (the fingerprint member's form stated once in the layout clause; the seventeen-key enumeration replaced by a pointer to gofresh's REQ-fresh-fingerprint-record) — editorial correctness under the standing authority; and the exemption-clause re-key gofresh 292 declares.
      Audit 287 (2026-09-29): grows — the resolver child's containment
      carries a dead quit arm (command_unix.go:20–40 fires SIGQUIT
      only on errEnvelopeExpired, produced on the execution path 272.B
      moved onto ownedRunner; commandContext's one caller is
      resolverclient.go:129; its rationale describes a go test binary)
      with no WaitDelay and an ambient SystemRoot read on Windows —
      deleted when gofresh 281's containment lands (whichever of
      225/290 lands first takes the dead arm); the spec-mirror rider
      confirmed (evidence.md:573–584 enumerates sixteen keys the code
      no longer has; the reflection-filled key-set golden is the right
      mirror); vouchIdentity (normalize.go:388) reimplements
      gofresh.ParseVouchEntry clause for clause — join the pair and
      call it; gotool.Salvaged inlined at discovery.go:255;
      Progress.IsUnit/UnitPhases unused while derive.go:980
      keep-alives on every event; recordstore.fingerprintDigest takes
      any.
      Rider (2026-09-30, gofresh 281 landed — v0.108.1 and the
      releases after it): the bump adopts 281's forms — the resolver
      child's and the driver's boundary copies delete against
      gotool.Runner.Program (SysProcAttr fields set after construction
      merge into Program's); discovery's `go list` reads
      gotool.Runner.List, whose refusal carries
      gotool.ErrListingRefused, never exec.ErrWaitDelay, so
      discovery.go:258's own wait-delay arm is re-derived there; the
      provenance composite is constructed through
      gofresh.NewToolchainProvenance; the MCP server holds one
      gotool.Sampler and one runtimeinput.Roots per served operation
      (never per process —
      recovery: `git log --all -- docs/issues/mcp-server-holds-one-toolchain-sampler-per-process.md`
      lands here) and passes the memo on every ProducerIngest; any
      series parse of its own folds onto
      gotool.LanguageSeries/ParseGoVersion.
      Rider (2026-10-06, gofresh 51cac16 — released after v0.109.0):
      gofresh/resident's ceiling rule now lets an explicit operator
      GOMEMLIMIT replace the derivation, `off` included — an
      environment carrying GOMEMLIMIT suppresses the derivation for
      the whole process, an oracle's test binary included (the
      clause's consumer obligation); stipulator's two ceiling pins
      (internal/mcpserver/contract_test.go's installed-ceiling arm,
      internal/cmd/execute_test.go's ceiling assertion) lift the limit
      alone today and go red under an ambient or oracle GOMEMLIMIT
      once the bump reads the fleet rule — they clear GOMEMLIMIT in
      their TestMain before the process's first derivation;
      internal/resident folds onto gofresh/resident (the resident-
      package-folds-onto-gofresh issue) at the same bump.
      Split (2026-10-06, audit 318): 290.2b lands NOW — the bump to gofresh v0.109.x (014efbd deleted closure.ToolchainSelectionNotice and AuditedToolchainSelection: the notice through the pass reader, ToolchainSelectionNoticeResolved); one toolchain read (the snapshot's GOVERSION feeds provenance, the per-member check and the selection notice; provenance.go's discarded Check sample and its per-member re-sample delete — gofresh's provenance-sample-and-the-pass-snapshot-are-two-reads); internal/resident folded onto gofresh/resident (the explicit-GOMEMLIMIT word, Words/Suffix/ByteWord, one walk per transition; the six duplicated tests delete; gofresh refuses a malformed memory line where stipulator skipped it — declared); the spec's ceiling sentence amended to the fleet rule and REQ-policy-explicit's 'only sources of execution bounds' universal qualified by the admission's memory term (307.C); the MCP sampler per operation; the server derives the ceiling only at the zero-in-flight transition (gomutant 308's shape) until the own-set derivation lands in gofresh 314; the two ceiling pins clear GOMEMLIMIT (their TestMains); resolver-child-kill-orphans retargeted to the first Runner.Program spawn. The remainder (292's clause re-key, 297's walk, 300's lint) stays behind gofresh 292/297/300.
  - [x] 290.2b the bump to gofresh v0.109.6 — the selection notice content-keyed at normalization, the resident fold with the admission's own observations, one toolchain sampler per operation, the gate vetting four other platforms; 290r (the clause re-key, the walk, the lint) stays behind gofresh 292/297/300.
      Audit 6 (2026-10-07): 290r grows (audit 334): the bump to v0.111.x
      (@41 re-derives every dynamic-state fact once; 292's clause re-key
      re-measures the stored records; 300's lint half and the four
      parked gofresh docs as riders; only a comment names the deleted
      gotool.TakeEnvSnapshot — no compile break); the dropped adoption
      riders restored — discovery.go's hand-built listing with its own
      ErrWaitDelay arm → gotool.Runner.List/ErrListingRefused, the
      resolver child's spawn through commandContext → Runner.Program
      (resolver-child-kill-orphans' parenthetical '290.2b replaces
      commandContext' was false); the normalization's snapshot spelled
      four ways (the *EnvSnapshot, effectiveGoEnv's 10-tuple,
      captureGroup.toolchain, a transient PrimedEnvReader for the
      notice) and groupSample re-implementing gotool.SnapshotSampler →
      NormalizedInvocation holds the primed reader, the notice, the pin
      judgment and provenance read it through SnapshotSampler, the tuple
      and groupSample deleted (the one-read invariant and the per-
      operation sampler kept); 184 MERGED in (the render's face pick is
      the bump's work); command.go's 'no go command, so outside gotool's
      runner' comment stale since 281.A. Directly after 331; no longer
      behind 292/297/300 (landed or merged) nor 314/315/202.
- [x] 291. pew: the bump behind gofresh 279, 281 (v0.107.0 today) — recover
      in Pew with `git log --all -- docs/issues/gofresh-corpus-pin-lag.md`;
      runCommand's containment
      copy deletes at it (281); the store re-measures once. After 290.
      Rider (2026-09-29 replan): gofresh 292's clause re-key, as at 290.
      Delegated (2026-10-06): lands as pew's performance-evidence plan
      chunk 2 on the other machine; ticked here when that chunk lands.
      Audit 288 (2026-09-29): moves AHEAD of 252 (252's
      environment-normalized-once builds over gofresh 265's setter,
      absent from the v0.105.1 pin; 291 deletes the containment copy
      252 would re-touch). Riders: (a) gofresh's Containment sends
      SIGQUIT to the group before SIGKILL, and SIGQUIT to a go test
      benchmark dumps goroutine stacks into the measured stream that
      §9 reads as splice evidence — the measurement spawn carries NO
      Quit arm, as a pinned fact; (b) provenance.go:79 discards the
      sampled go version that is the recording's toolchain guard
      value, captured a second time through guard.Capture — record the
      checked sample; (c) the row projection validates through
      gofresh's Fingerprint.Validate (285 A14 / 240's projection
      obligation).
      Rider (2026-09-30, gofresh 281 landed): the bump adopts 281's
      forms — runCommand's boundary copy deletes against
      gotool.Runner.Program (its post-construction SysProcAttr fields
      merged, never replaced); every `go list` of its own reads
      gotool.Runner.List; the provenance composite is constructed
      through gofresh.NewToolchainProvenance; one runtimeinput.Roots
      per verb invocation on every ProducerIngest beside its sampler;
      any GOVERSION parse folds onto
      gotool.LanguageSeries/ParseGoVersion.
      Dissolved (2026-10-06, audit 319): lands as pew's performance-evidence plan chunk 2 on the other machine; its riders in pew docs/issues/train-riders-for-the-performance-evidence-plan.md.
- [x] 292. gofresh: an in-module refused path's clause spelled
      module-relative (gofresh `git log --all --
      docs/issues/refused-in-module-path-spelled-absolute.md` — derived
      at the 2026-09-29 replan: checkout
      independence is the property 279 set out to give the attribution
      limb, and the refused path's own absolute spelling is the one
      residual that defeats it; the cost is a one-time re-key of every
      hand-authored exemption clause naming an in-module absolute path,
      a migration the consumers perform at their bumps — 290, 291, and
      gomutant's next — with the tool rewriting the clause it can
      derive and refusing the one it cannot). A release; before 290.
      Not chartered: the Windows job object (gofresh
      containment-windows-job-object) — no consumer runs on Windows;
      the Windows oracle keeps gomutant's own job object until a
      Windows consumer's report exists (the doc's trigger).
      Audit 285 (2026-09-29): grows — (a) the attribution has one
      reader fleet-wide and gofresh's own verdict path drops it
      (view.go:676–679 builds the fingerprint through CompletedState,
      which returns a State without it; stipulator and pew read
      neither Observation.Attribution nor either split): decide here
      whether the engine's verdict path carries it — checkout
      independence is this chunk's property; (b)
      bracket-move-attribution-unsplit (gofresh `git log --all --
      docs/issues/bracket-move-attribution-unsplit.md`) folds here — its Lands names
      this change set verbatim (bracket.go:216–230's bracket grammar
      unrecognised by attributionWellFormed, runtimeinput.go:1853);
      gomutant's second strip deletes at the same bump as the re-key.
- [x] 293. stipulator: a gap's excuse is judged over every red class a
      row carries (stipulator, resolved at 293 — `git log --all --
      docs/issues/gap-excuse-judges-the-winning-bucket-only.md` —
      derived 2026-09-29: a gap excuses exactly the
      classes it declares; a red the gap does not name stands, so a
      stale-class red behind an excused broken bucket is an undeclared
      red passing silently — the never-silent rule; per-row class set
      judged against the declared set, REQ-gate-no-undeclared amended
      to say so). Soundness first: directly before 290; doc deletes at
      close.
      Audit 287 (2026-09-29): grows — the amendment is
      REQ-coverage-buckets (evidence.md:899: 'exactly one bucket …
      broken forces broken, else stale forces stale'), which is what
      hides the constituent red; REQ-gate-no-undeclared already states
      'a gap excuses only the violation classes it declares' and
      coverage.go:760 conforms to it under the one-bucket rule;
      rowFacts already carries f.stale apart from the bucket and
      coverage.go:727 looks behind it — a per-row class set beside the
      reported bucket, no new concept.
- [ ] 294. gomutant: the external-oracle mode (gomutant docs/issues/
      external-oracle-for-tagged-and-subprocess-targets.md).
      Active destination: tooling-redesign **5.4**. Settle the actual external
      capability model before implementation: mutated artifact identity,
      complete contributors, baseline symmetry, terminal/support authority
      and attributable outcomes. Browser and nested-compiler shapes must
      demonstrably read the mutant; whole host oracles and parent-profile
      absence do not establish that. Preserve the existing unreached bound.
- [ ] 295. gofresh: a declared surface for the ephemeral
      process-identity input class. Active destination: tooling-redesign
      **7.3**. Derive exact assertion scope, authority home, provenance and
      revocation under native evidence support before adding a form. A lock
      holder's start time can change behavior; keep volatile-input refusal
      outside the explicit permission, and never substitute static purity,
      process-wide trust or an automatic liveness carve-out. Release shared
      changes before consumers; reuse refusal is separately not flip evidence.
- [ ] 296. gomutant: an unstable test quarantined per test (gomutant
      docs/issues/unstable-test-quarantine.md) cannot silently weaken the
      claimed oracle. Active destination: tooling-redesign **6.3**. Name
      actual flipping tests and affected scope, preserving confirmation,
      complete-oracle fallback and partial/unknown advisory distinctions.
      Any explicit quarantine changes oracle identity and requires separate
      whole remeasurement; a stated cap or test-name match grants no carry.
- [x] 297. gofresh: the dst-selection walk for the toolchain-audit key
      (Gofresh recovery: `git log --all -- docs/issues/walk-dst-selection-for-audit-key.md`, whose
      trigger fired 2026-09-29 — the field report
      dst-selection-walk-trigger-fired-tugboat, with the admission
      rationale maintained in closure/toolchainaudit.go (recover with
      `git log --all -- docs/issues/dst-selection-walk-trigger-fired-tugboat.md`):
      tugboat's first judged run over `dst` and
      `dst,race` under go1.27.0-dst.14 re-executes ~1,070 subjects per
      leg with no proof to serve, the loud refusal chunk 126's two-axis
      key promised) — walk the dst selection's live hook bodies against
      the admission bar: time/dst_tz.go against the class-B time claims,
      testing/dst_hostio.go against the harness channel claims, sync's
      dst-and-race hook seam, and the os fault-injection surface
      (dst_fd.go, dst_root.go, dst_disk_fault.go and siblings, ~19k
      lines) against the observation producer model
      (REQ-inputs-observable-read-set's admitted-wrapper audit and the
      completed-observation conjunction); the walk lists "dst" and
      "dst,race" for the installed flavor in closure/toolchainaudit.go's
      selections axis, flipping dst-tagged analyses from loud refusal to
      audited admissions; both docs delete at close. Directly after 191;
      a release (every dst-tagged consumer store re-measures once).
      Audit 285 (2026-09-29): moves AHEAD of 202 — its trigger fired
      and the cost is paid by a consumer on every check; a
      self-contained walk plus a selections-axis entry, a release
      stipulator's bump 290 reads for tugboat's dst legs; 191 keeps
      its place behind 202.
      Merged into 315 (2026-10-06, audit 316): the dst walk's ~19k-line os fault-injection delta is the largest moved-key corpus the fleet has — walking it by hand and then measuring 315 over the same bytes walks it twice; 315's measurement at open takes it as its first corpus, the human walk the fallback for the classes the scans cannot judge (the harness channels, the linkname floor); 315's open also measures which toolchains the fleet runs and lists the walked godst builds (dst.10–15, go1.27.1-dst.12 — present on this host; 310's tick claimed otherwise) as delta rows over their chains or records the drop. Its charter's 'selections axis' and 'two-axis key' vocabulary is 310's content-key form: a dst row is a listedSelections entry, ' dst' and ' dst race' delta rows over the host chain.
- [x] 298. stipulator: the seeding walk's declaration lookup under the
      invocation's own selection (the stipulator field report
      seeding-declaration-not-in-default-view — resolved at 298 by
      verdict, stipulator `git log --all --
      docs/issues/seeding-declaration-not-in-default-view.md` — tugboat,
      2026-09-29: ~560 of 1,073 witnesses per check refused as
      "declaration … is not in the \"default\" view of in-module
      package …" for interface-method and unexported-type-method
      declarations living in UNTAGGED files, under a `-tags dst -race`
      invocation — the receiver-declaration lookup keyed to a view the
      witness did not run under, adjacent to 159's per-selection walk
      key and 272.F's staticCallees; reproduce over tugboat first, fix
      the lookup, and give the seeding family an explain derivation —
      every uncacheable reason class explainable or naming the verb
      that explains it). Directly after 293; doc deletes at close.
      Audit 287 (2026-09-29): grows — golang.go:922's one message
      conflates three causes (a view excluding the file; an object
      with no *ast.FuncDecl to index, :863; a package loaded under a
      different walkKey, :831) — split the refusal by cause BEFORE
      fixing the lookup; explain derives one reason class (the
      dynamic-state culprit) and the seeding/declaration family none —
      make 'every uncacheable reason class explains or names its verb'
      structural (the class carries its explain kind);
      seeding-walk-unreached-routes folds here (its trigger fired at
      272.F's staticCallees).
      Rider (2026-10-04): testing/quick.Check recognized as a direct
      property driver (Stipulator recovery:
      `git log --all -- docs/issues/testing-quick-property-driver.md` — Weaver's field report; the
      derivation at open: Check and CheckEqual, the callback's
      quantification, Config.Rand against the time seed — the
      runtime-seeded freshness class every other driver carries; an
      unsupported driver named in the diagnostic).
      Grown (2026-10-06, audit 318): property-completion-adapter-guidance (derived: the direct-driver rule is soundness; the remedy a diagnostic naming the reached-through helper and the direct-call form).
- [x] 299. stipulator: a policy toolchain pin the environment does not
      satisfy refuses at load (the stipulator field report, resolved at
      299 — stipulator `git log --all --
      docs/issues/toolchain-pin-unhonored-runs-silently.md` — tugboat,
      2026-09-29: the
      policy pins go1.26.5-dst.6, the exported GOTOOLCHAIN is overridden
      by the machine's go wrapper, and every witness executed and was
      judged under go1.27.0-dst.14 with no diagnostic — a pin with no
      enforcement; the sampled toolchain (gofresh's runner sample) is
      compared against the pin at load and a mismatch refuses naming
      both and the remedy; the comparison is stipulator's, the pin's
      consumer — gofresh has no pin concept). Soundness first: heads
      stipulator's order, before 293; doc deletes at close.
      Audit 287 (2026-09-29): grows — no clause states a pin
      comparison (REQ-evidence-toolchain-provenance judges skew, never
      pin-vs-sample) and policy.proto:116's 'Pin-at-load' over-claims
      enforcement: name the clause written or amended and correct the
      proto comment in the same chunk.
      Rider (2026-10-06, audit 318): follows 290.2b and compares the policy pin against the one toolchain read (the snapshot's GOVERSION) — never a fourth sample.
- [x] 300. gofresh: the guidance lint's gofresh half (audit 285 A9 —
      four gofresh guidance issues parked on stipulator 184, whose own
      parenthetical says 266 owns the document half, and 266 landed
      without them): the default-spelling rules — a knob's derived
      default spelled in prose, the zero-default lint over the
      document (Gofresh recovery:
      `git log --all -- docs/issues/guidance-lint-zero-default-spelling.md`;
      `git log --all -- docs/issues/coverage-lint-default-on-zero-default-flag.md`), the prints-default
      rule as a NAME-KEYED table gofresh can host (the pflag-typed
      switch refused on the dependency boundary: gofresh carries no
      pflag; Knob.Usage already implements pflag's grammar as a string
      transform — prints-default-one-home lands as the table) — and
      the long-help join one home (cli-long-help-rendering-two-homes);
      plus the coverage JUDGMENT the two consumers re-derive with
      divergent local grammars (stipulator's cliUsage cuts the last
      '(default ' only where stripDefault removes every one by paren
      depth; pew's firstClause decrements depth unguarded where Clause
      floors at 0 — guidance.md:164–168 forbids a consumer grammar):
      the judgment needs no SDK type and lives here; the
      SchemaNode→jsonschema adapter stays in the consumers (it needs
      the SDK type — refused for gofresh). A release before 290/291,
      where the four docs close and the consumers' guards read it.
- [x] 301. gomutant: writer-side fixture isolation (audit 286 A12 —
      internal/engine/run_test.go:552 and :584 create
      .unstable-input-fixture / .stable-input-fixture inside the
      tracked internal/engine/testdata/fixturemod/lib that 170
      root-package tests load in place; every mitigation is at the
      consumers — root_test skips dot entries, run_test copies — never
      at the writer, and 257 paid a wasted probe round to this class):
      every fixture writer writes into a copy; the tracked tree is
      read-only by construction (a pin that refuses a dirty fixture
      tree after the suite). Directly after 283, before any chunk
      whose probes read the shared tree.
- [ ] 302. gomutant: a findings record keyed by (symbol, selection)
      (gomutant docs/issues/findings-records-keyed-by-symbol-alone.md).
      Active destination: tooling-redesign **6.6**; constituents 6.5, 9.2
      and 9.3. Derive complete resolved selection identity, preserving
      omitted/explicit-empty differences. Keep measurements and dispositions
      across both layers, filters, reconciliation, serve/extension, prune and
      retarget; a cross-selection killer reference replaces neither record.
      Current document version is 16, not a reserved 14-to-15 transition.
      Decide actual historical readability, duplicate-key controls and native
      compatibility from live formats; policies 1/2 and changed oracle evidence
      cannot grant spliced reuse. Baseline durability remains 356's and the
      original self-campaign population requires explicit authorization after
      selection coexistence and recovery, never cheaper substitute oracles.
- [x] 303. gofresh: a build selection whose tags constrain no
      standard-library file is admitted with the base selection's
      audit (gofresh selection-with-no-standard-library-delta-unwalked,
      filed at 284's review, closed at 310; `git log --all --
      docs/issues/selection-with-no-standard-library-delta-unwalked.md`): a tag absent from every build constraint
      under GOROOT/src has an empty delta by construction, yet the
      toolchain audit refuses it as unwalked — gomutant's
      `integration` tag, measured 2026-09-30: zero files under
      go1.27.0-dst.15's GOROOT/src carry the constraint, and its
      integration campaign cannot serve; the selections axis gains the
      derived arm (a scan of //go:build lines and the platform name
      suffixes under GOROOT/src, memoized per toolchain), a tag any
      standard-library file names keeps the listed-or-refused rule,
      the clause stating the listed rule amended. A release, directly
      after 300; gomutant's next bump (302) reads it.
      Rider (2026-10-04): after 310 the audit keys on the selected
      files' content, so a tag constraining no standard-library file
      selects the same files and the same key — 303 re-derives its
      charter at open against that key (the derived arm may be the
      key itself).
- [x] 304. gomutant: the derived oracle narrowed by measured
      reachability before measurement (gomutant
      derived-oracle-is-the-whole-closure-and-prices-out, folded at 304;
      `git log --all --
      docs/issues/derived-oracle-is-the-whole-closure-and-prices-out.md`,
      gomutant — protodb's field report 2026-10-02, the standing
      channel): over
      a tree whose root links everything the derived oracle is the
      whole suite for every target (protodb: 2,269 tests across 10
      packages, 0 of 112 targets committed in 75 minutes; the train's
      own pb campaign stalled the same way at 257), and the workaround
      is a hand-built targets document with oracleExplicit per symbol
      that can drop an oracle silently. The sound narrowing is the one
      the narrowed survivor already rests on — a test whose execution
      never reaches the mutated function cannot observe the mutation —
      applied before measurement from the baseline's per-test coverage
      the campaign already pays: a target's oracle is its reaching
      tests, the non-reaching remainder exempt on that measured
      coverage; a target whose narrowed oracle still prices past the
      window is refused with its pricing (114/137's rule), never a
      prefix survivor; own-package-first ordering and a test-count
      prefix commit refused as unsound for survivors (recorded in the
      issue). The report's condition is the measure at close: a
      `--changed` run over protodb's tree commits its first target
      within an hour with no targets document. Correctness first:
      directly after 284 in gomutant's order, before 302.
- [x] 305. gofresh: the analysis budget bounds the dynamic-state
      discharge's reachability analysis (gofresh
      analysis-budget-skips-the-dynamic-state-discharge, resolved at 305;
      `git log --all --
      docs/issues/analysis-budget-skips-the-dynamic-state-discharge.md`
      — protodb's field report 2026-10-02, triaged at gomutant 304's
      open): the `prove (1/1)` unit is closure/rooted.go's
      ComputeRootedFunctions, the discharge's attributed RTA, run from
      purity.go's scanViewSubjects on the view-construction Hasher,
      which never receives BoundAnalysis — the budget is installed
      only on the observability-proof Hasher — so `--analysis-budget
      5s` left protodb's internal/db in that phase for 23 minutes; the
      view-construction Hasher is bounded by the same budget, a cut
      leaves the culprit standing (undischarged, fail-closed, never
      validity) with the exhaustion reported once and counted,
      REQ-fresh-context's "optional precise-analysis tier" and
      WithAnalysisBudget's doc name the tier; the rooted inventories'
      memo is 202's. A release, directly after 304; gomutant reads it
      at its next bump.
- [x] 306. gomutant: an explicit oracle superset re-measures only the
      open survivors against the added tests (gomutant
      explicit-oracle-growth-serves-the-prior-record, resolved at 306;
      `git log --all --
      docs/issues/explicit-oracle-growth-serves-the-prior-record.md`,
      gomutant — protodb's field report 2026-10-02; the serve claim
      refuted at
      HEAD by the match gate and two pins: an explicit superset
      re-measures WHOLE today): with every pin holding and the
      request's explicit set a superset of the record's, kills stand
      (each unmoved oracle's recorded pass stands exactly as a
      standing kill does — REQ-result-stale's own keystone, with no
      compartment delta to attribute), the open survivors run against
      the added tests alone, a kill by an added test commits, a
      survival keeps the record with its oracle list grown;
      REQ-result-stale's "a grown set serves only when … both
      non-explicit" sentence amended (its reason is scoping, not
      soundness). Directly after 304 and 305 in the lane.
- [x] 307. stipulator: the pass's resident set bounded and stated
      (stipulator docs/issues/resolver-child-resident-set.md — two
      cerebro field reports, 2026-09-22 and 2026-10-04: the resolver
      child at 3.2–4.7 GB RSS before any test executed and alive through
      execution; the parent `check` at 6.9 GB during execution beside
      111 `go test -json` children; the host at zero available memory,
      runs killed by its guard with no verdict written). Mapped
      2026-10-04: the child loads `./...` per workspace member per
      build selection (Tests: true; NeedSyntax, NeedTypes,
      NeedTypesInfo) into Backend.pkgs/byPath/typesPkg and the seeding
      walk's declIndex (on-demand loads kept by their ASTs), released
      never; first spawned at discovery (NeverServe + typed per witness)
      and closed at check.Run's and verifyrun's return — after
      execution — because verify.Run resolves every bound symbol after
      execution and Served.Close publishes then (classify, NeverServe,
      the closing capture of the straddle check); the parent holds per
      capture group witnessGroup{engine, view, observed, fps} and the
      execMerge's rows, diagnostics and ProcessObservation.Runtime
      manifests for the run, the per-package output capped at 64 KiB
      per in-flight test; the only memory controls are two
      debug.FreeOSMemory calls; the spawn bound is GOMAXPROCS/2 with no
      memory term. Change sets: (A) the measure — a per-phase
      resident-set line on the progress channel (the parent's and the
      child's VmRSS/VmHWM at every phase transition and in the summary;
      the never-silent rule) and a reproduction over gofresh's own
      corpus; (B) the child's life ends before execution — every
      question the pass asks (verify.Run's per-binding resolve, class
      and package) asked at discovery, the publish with its straddle
      capture run before PHASE_EXECUTION, the child closed there; its
      load scoped to the unserved symbols' packages per selection
      (childPatterns' `./...` arm and the NotFound widening
      re-derived), each selection's load released once its answers are
      memoized, the seeding walk's on-demand ASTs released after the
      walk (answers memoized by declKey); (C) the tool's own processes
      under a ceiling derived from the host (MemTotal's share, the
      oracle ceiling's derivation) through debug.SetMemoryLimit on the
      parent and the child — never GOMEMLIMIT on a witness child: it is
      a runtime-config guard key (gofresh guard.go's
      runtimeConfigEnvKeys) and would re-key every recording — the spawn
      bound gaining a memory term (a per-package estimate from the
      invocation's own completed packages, the first package alone
      until one completes) and a pass the host cannot hold refusing
      stated instead of dying under its guard; (D) the parent's
      run-long accumulations bounded or streamed (the execMerge's rows
      and diagnostics, a manifest held only until its ingest). Heads
      stipulator's order and the lane (the user's ask 2026-10-04); the
      issue deletes at close.
      Sequencing (the user's ruling 2026-10-04): B is the unit loop's
      vertical for discovery and lands directly after A, ahead of C and
      D, which follow gomutant 311.
- [x] 308. gomutant: the server's and the pass's resident set released
      (gomutant `git log --all --
      docs/issues/mcp-server-retains-the-pass-resident-set.md`
      — cerebro, 2026-09-22: an idle `gomutant mcp` at 2.29 GB RSS,
      23.7 h up, nothing in flight; the 233 rider promoted to its own
      chunk at the 2026-10-04 replan, the host baseline that leaves
      stipulator's spike no room): the pass's programs and memo
      released at the end of every request (the persistent memo layer
      serves shared folds across passes), the heap returned to the host
      at request end (debug.FreeOSMemory), the server's own process
      under the oracle ceiling's derivation (debug.SetMemoryLimit),
      and the run's per-phase resident-set line on both faces in 307's
      words; acceptance a measured before/after — VmRSS at idle after a
      run-class request. Directly after stipulator 307 in the lane.
      Rider (2026-10-06, at 308.A's review): the process memory limit
      is NOT gomutant's own derivation — it is gofresh/resident's
      fleet rule (InstallCeiling: the host's available memory halved,
      1 GiB floor; an explicit operator GOMEMLIMIT replacing it, `off`
      included — gofresh 51cac16), installed in the CLI's shared
      preamble (every verb) and at serve start, with the bump that
      reads gofresh/resident (change set B; the gap on REQ-mcp-
      resident-set names it); B's acceptance measures the idle
      resident set and the cold single-target run's wall time under
      the ceiling (gctrace) beside the per-phase resident line;
      gomutant's own pins clear GOMEMLIMIT before the first
      derivation, as the clause's consumer obligation requires (the
      oracle sets it on every test binary).
- [x] 309. stipulator: the witness engine attests its execution model
      (stipulator `git log --all -- docs/issues/engine-call-attests-no-execution-model.md`
      — tugboat, 2026-09-29: every engine call attests neither
      WithSingleSubjectExecution nor WithPackageProcessExecution, so
      gofresh's two-leg own-code discharges never apply to a stipulator
      witness — tugboat's two `//gofresh:single-subject` pools stay
      listed at 45 and 450 witnesses while pew's runs discharge them):
      the package-process model attested on every engine (derive.go's
      newEngine — each invocation runs a package's subjects in the
      package's own test binary, the isolation re-run's solo processes
      that binary too; stated against REQ-check-witness-selection), and
      a `//gofresh:single-subject` directive met under a model that does
      not back it named on the uncacheable face as unbacked (gofresh's
      reason reproduced whole), never silently ignored; measured over
      tugboat's corpus at close. Directly after 307 in stipulator's
      order (chartered at 307.1); the issue deletes at close.
- [x] 310. gofresh: the toolchain-source audit keyed by content, not by
      name (the user's question 2026-10-04; a release). Today
      closure/toolchainaudit.go admits a release by its FULL version
      string — experiment and vendor flavors included — as the proxy for
      "which standard-library source", so every build of identical
      source needs its own row (the file itself says the nodwarf5 builds
      are "those same sources"), each dst tag, distro build and stock
      patch release costs a listing commit, a release and a bump in
      every consumer, and an unlisted-but-identical toolchain fails
      closed on every host that moved (the dst.13 lag re-executed
      gofresh's whole closure package for 59 minutes per check until
      290.2a). The key becomes the content the audit is about: a digest
      of each audited package's audited files — the non-test sources the
      whole-dir walk reads, the delegate implementation packages
      included, taken over the files the build SELECTS for the package
      under the selection (so a GOEXPERIMENT that selects no different
      file in the audited set is the same key) — as found in the GOROOT
      in use; the table maps digest to verdict, the version string a
      label on the row; the canary test asks whether the running
      toolchain's audited digests are listed; the same-source rows
      (nodwarf5, the dst tags whose patches touch no audited package)
      retire; an unknown digest keeps the fail-closed refusal naming the
      packages whose digest moved, so a human walk covers exactly the
      delta. Second half, decided at open by measurement: the walk the
      machine can do — the audited classes gofresh's own effect and
      purity scans already judge over any package run over an audited
      std package at its first unknown digest, the verdict persisted
      under the digest, the human-judged classes (harness channels,
      atomic transparency) staying a digest-keyed table. The recording
      skew identity (REQ-fresh-toolchain-skew) stays by version: a
      measurement's cache key, not an admission. The clause stating the
      listed-or-refused rule amended; 303's selection axis re-derives on
      the content key (its rider). Heads gofresh's order; directly after
      stipulator 309 in the lane — gomutant 308 reads the resident
      sampler's fleet home this release carries (its rider, from
      stipulator's internal/resident), so the consumer follows the
      release (re-sequenced 2026-10-05 at 308's open); consumers read it
      at their bumps.
- [x] 312. gomutant: the server writes nothing in the repo (the user's
      ask 2026-10-05, not high priority, slotted after the memory and
      the unit-loop verticals). The MCP server is registered globally
      and starts in whatever project is open; at start it opens
      `.gomutant/mcp.log` under its working directory and mints
      `.gomutant/.gitignore` beside it, so every opened repo — Go or
      not, gomutant or not — shows an untracked `.gomutant/`. The exit
      log moves to the machine-local home under the XDG state directory,
      keyed by the tree as the findings overlay and the baseline bank
      are keyed under the cache directory (one key, two homes); the
      server mints nothing at start — `.gomutant/` appears only when a
      committing verb writes the findings document; the exit line and
      the served instructions name the log's path. An opt-in switch is
      refused: a diagnosability log is useful only always-on; the defect
      is the home. REQ-mcp-exit-log amended; StoreOwnPaths and the
      minted ignore lose the log; the three repos' `.gomutant/.gitignore`
      drop the two mcp.log lines (chores). Pins: a server session over a
      temp directory leaves it untouched; the log under the state home
      carries the exit line; the instructions name the path.
- [ ] 313. gomutant: the repo declares its own facts — `.gomutant/policy.json`
      is a rejected omnibus proposal, not a required file. Active destination:
      tooling-redesign **7.3**. Classify each standing declaration by owner,
      root/subject scope, precedence, default and consequence. Selection
      overrides are not union; external bracket coordinates and operator
      budgets are not repository facts. Retain one justified trust home,
      explicit revocation, preparation-time refusal and truthful inventory
      on both faces without silently spreading server defaults across roots.
- [ ] 314. gofresh: the analysis pass's program retention bounded
      only after causal ownership attribution. Active destination:
      tooling-redesign **7.7**. Compare current cold/warm phase-local peaks
      and retained RSS over the same completed subjects/verdicts; completed
      observability groups, empty roots and discharge programs already release.
      Do not rebuild that mechanism from historical HWM figures. Attribute
      vfork/persistent shared-page sums against actual kernel ownership before
      changing resident arithmetic; equal counters or a minimum sample are
      not proof. Resource-control contracts remain distinct at 7.4/9.2.
- [x] 315. gofresh: the toolchain-source audit's second half — the walk
      the machine can do (310's charter, deferred at 310's open to its
      own measurement; a release). The content key names the keys that
      moved; a human walk still judges every moved key against the
      admission bar. Measured at open: whether gofresh's own effect and
      purity scans, run over a moved audited package as program code at
      its first unknown digest, decide the audited classes the walks
      decide by reading (the pure set's single-file value computation
      and never-mutated exported variables, the class-B operations'
      effect classes, the delegates' purity), the verdict persisted
      under the digest; the human-judged classes (the harness channels,
      the atomic transparency, the linkname-target floor) stay a
      digest-keyed table. A measurement showing the scans cannot judge a
      class soundly closes that class by verdict and records why. After
      314 in gofresh's order and the lane.
      Grown (2026-10-06, audit 316): 297 merged in as the first measured corpus (its human walk the fallback); the fleet's toolchain census at open, the walked godst builds listed or their drop recorded; the long-term relief of the release gate's floating toolchain (325 pins the gate meanwhile). Before 314 in gofresh's order.

      Audit 6 (2026-10-07): the two dst-walk docs merged into dst-
      selection-walk-trigger-fired-tugboat (retargeted here; walk-dst-
      selection-for-audit-key described the deleted version-axis
      mechanism) — rewritten in content-key terms at open: which std
      files the dst tag selects, the refusal naming the keys off the
      closest chain; the std source digests (~220 packages, ~210 of 331
      MB in one root test) read on every Hasher construction memoized
      per judged run under MemoKey + the stamps (never across runs; a
      stale stamp refuses); the suite-runtime note's unfiled deferral
      filed as source-traversal-cancellation-gaps (resolved at 315.B;
      `git log --all -- docs/issues/source-traversal-cancellation-gaps.md`); the
      charter's own 'After 314' struck — Before 314, as 316 grew it.
- [x] 338. godst (greatliontech/godst, main): the testing harness's
      test-log writer propagates a write error — testing/dst_hostio.go's
      `dstHostStreamWrite` returns the errno its `writeFull` swallows
      (EINTR/EAGAIN retried as today) and `dstTestlogWriter.Write`
      returns it, so the harness's buffered writer sticks and
      `StopTestLog` fails the binary as the stock harness does; a build
      cut from the fix and installed as the fleet's running build; then
      gofresh's canary re-lists the dst selections over that build (the
      digests and admission rationale in closure/toolchainaudit.go;
      every other moved key re-walked), a
      gofresh release. Opens by cloning the fork beside the other repos
      and measuring how its builds are cut (~/.local/godst holds builds,
      no source) — the procedure recorded for 330, which cuts the next
      godst build. Directly after 315 in gofresh's order and the lane.
- [x] 316. gofresh: the fifth re-audit band's gofresh audit — one
      read-only Opus auditor over the repo with the eight lenses (the
      designR shape), output a disposition tick and issue docs, no
      code; chartered at 312's tick (twelve whole chunks landed since
      Band R4: 283, 301, 281, 304, 305, 306, 311, 307, 309, 310, 308,
      312; 284 pending its parked campaign). The band 316–319 closes
      with the cross-repo replan at 319; the audit count restarts at
      zero.
      Dispositioned 2026-10-06: ten coherence findings, six consolidation candidates, the queue walked — 325 chartered (the reusable CI/release workflow; the trigger fired at 48bbe3a; the gate's toolchain pinned with a next-stable leg), 326 (the resident release: the own-set derivation + the children's budget), 327 (the gotool surface release: UnsetEnv, one judged-run memo, the ToolchainSampler over an EnvReader, the dead set); 297 merged into 315; 314 narrowed; 202/240/241/203/206/242 grown; the register: five retargets, a phrase corrected, two binding chores (the retired version-listing witness rebound off the toolchain-key clause; TestUnauditedSelectionDisablesAdmissions bound). Disputes D1–D5 accepted as argued.
- [x] 325. cross-repo: the reusable CI/release workflow (audit 316;
      reusable-ci-workflow's trigger fired at gofresh 48bbe3a — the
      race/records/workflow_run gate is the CI-contract change every
      copy must carry, and 321/323 were about to hand-copy it): one
      org-level workflow (greatliontech/.github) the four repos call
      with their inputs (race on or off and its budget, the records
      tier, the package pattern); the gate's toolchain PINNED to a
      listed one (the canary row's version) — on `stable` a commit's
      releasability changes with Go's release calendar, and the first
      point release reds every gofresh release until a listing lands
      — with a next-stable early-warning leg beside next-rc; 321 and
      323 shrink to the call. Opens with the user's confirmation of
      the org repo's creation (an outward-facing action). Heads the
      lane.

- [x] 326. gofresh: the resident release (audit 316): resident.Ceiling
      derives from available plus the process's own set (the halved
      rule installs a ceiling below a live heap and pins the collector
      at its CPU cap — ceiling-derivation-excludes-the-callers-own-set),
      and the package exports the children's complementary budget
      composed from the same reading (gomutant's oracle bounds and
      stipulator's admission term derive it locally today); absent
      never zero, the operator's word wins, the floor. Before
      stipulator 290.2b/322 and gomutant 214. A release.

- [x] 327. gofresh: the gotool surface release (audit 316): UnsetEnv
      beside SetEnv; one generic judged-run memo with the Sampler and
      runtimeinput.Roots its instances (one key spelling: the
      coordinate plus the normalized environment; a failed answer
      memoized, a cancellation never); the ToolchainSampler over an
      EnvReader offered (the gofresh half of
      provenance-sample-and-the-pass-snapshot-are-two-reads); the dead
      set deleted (the package-level
      Run/SampleGoVersion/TakeEnvSnapshot forwarders, EnvReader.Taken,
      ParseEnvDocument, Containment.Quit/Grace). Before stipulator
      290.2b and gomutant 324. A release.
- [x] 329. cross-repo: the race tier sharded (the user's ruling
      2026-10-06 — a release waited an hour on one job: gofresh's race
      tier is the closure package's observability proofs under the
      detector, about four times their plain cost on a 4-vCPU runner,
      45–61 min against the plain tier's 19): go-gate.yml gains a
      `race-shard-runs` input — a JSON list of `-run` regexes — and
      runs one race job per shard over the caller's pattern (one entry
      keeps today's shape; the budget inputs bound each shard); gofresh
      passes a partition of the closure package's tests by name that
      balances the measured durations (measured once at open under
      `go test -json ./closure`), and PINS the partition: every Test
      function of every package in the module matches exactly one
      shard's regex (the logic over synthetic names, the real-tree walk
      the hand-edit oracle), so a test is never run twice or skipped;
      the first sharded run is the measurement (recorded at the tick;
      the wall should land at the plain tier's). gomutant's gate has no
      race tier (plain_witness); stipulator's turns back on behind the
      go/types fix. Directly after 327.

- [ ] 330. cross-repo (godst + gofresh): the test log carries the
      operation's caller frame as diagnostic provenance. Active destination:
      tooling-redesign **8.3**; constituent 5.5. Specify an optional log
      extension with package/function/file/line and its attribution grammar,
      preserving unextended harnesses and owning cancellation/completion
      boundaries. Release godst, then Gofresh's parser/audit, then consumers.
      Caller frames never authorize ignoring an observed directory input;
      open-for-sync and open-for-listing remain indistinguishable by operation
      alone. Separate native input attribution from record-wide copied reasons;
      never infer caller order from sorted manifest neighbours. This work does
      not wait for 314 and authorizes no Protodb campaign.
- [x] 331. stipulator: the memory term's estimate attributed and
      bounded to a package's run (the bldc field report
      cold-package-estimate-invocation-timeout — `git log --all --
      docs/issues/cold-package-estimate-invocation-timeout.md` in
      stipulator, 2026-10-07: a 7.3 GiB
      per-package estimate held three packages past a 25-minute
      execution budget after a 43-minute cold discovery whose own peak
      was 7.3 GiB; the warm retry passed in 12 minutes). Derived at
      298's close: the estimate reads this invocation's execution
      phase alone — a completed package's largest process from its wait
      status and a registered tree's largest reading — so discovery's
      peak cannot enter it and the 7.3 GiB was one package's real
      process tree, retained as every later package's need (the term
      never shrinks within an invocation); the executor's child is `go
      test`, whose reaped rusage folds the compiler and linker in, so a
      cold compile of one large package prices every run after it. The
      chunk: the deadline account and the held-package diagnostic name
      the estimate's ORIGIN (the package, its pid, the term — completed
      peak or live tree) so a genuine need and a build transient read
      apart; the build's peak never prices a run — measured at open
      whether execution rebuilds what discovery's listing built (flags
      differing from the listing build) and, where it does, the listing
      build reused or the build priced under its own serial admission;
      the discovery-peak half is gofresh 314's (the cold analysis
      working set). Directly after Band R6, ahead of 290r; the doc
      deletes at close.
      Audit 6 (2026-10-07): RESTATED at audit 334 (my 298-close charter
      half-wrong): the derivable half stands — the estimate's origin
      (package, pid, term) in the admission's state, shown everywhere
      the term's words appear (the refusal, the held words, the deadline
      account); the 'a build's peak never prices a run' half REFUTED —
      discovery runs `go list` plus type-checking, not `go test -list`
      (discovery.go:237, execute.go:843), so execution's `go test`
      builds every package and a cold compile is a real need of its own
      tree (execute.go:443's floor says so); the fault the charter
      missed: runSelectedPackages (execute.go:282–289) runs the
      selective form's isolation re-runs inSlot WITHOUT registering the
      re-run pids and releases with the first process's peak alone, so
      during re-runs the running package's real tree is unattributed
      (the whole estimate reserved, 'conservative') and the re-runs' own
      peaks never reach the estimate — wrong both ways, and bldc's
      interrupted one-test ingest package fits a re-run; every process a
      slot spawns registered and released with its peak; the cost of a
      cold build measured at open (pricing build and run apart needs its
      own build admission — an execution-model change, never dropping
      the build's peak); 322 MERGED in: its premises landed at 290.2b.B
      (the growth term reads the pass's own readings; the share term
      deleted) and its residue is the same admission — concurrent MCP
      operations each build their own admission over whole-process
      readings and reserve only their own trees, so two can admit into
      one available memory.
- [x] 332. gofresh: the sixth re-audit band's gofresh audit — one
      read-only Opus auditor over the repo with the eight lenses (the
      designR shape), output a disposition tick and issue docs, no
      code; chartered at 298's tick (twelve whole chunks landed since
      Band R5: 325, 326, 323, 321, 327, 329, 290.2b, 292, 300, 299,
      293, 298). The band 332–335 closes with the cross-repo replan at
      335; the audit count restarts at zero.
      Audit 6 (2026-10-07): Dispositioned 2026-10-07: thirteen coherence
      findings, six consolidation candidates, the queue walked — 203
      grown (the @N conflation: a memo record version apart from the
      recorded strategy; the three memo-key spellings; the narratives),
      240 grown (children-budget's spec strike, the two mega-clauses
      split with a no-append rule, 3361645's vocabulary, item (d)
      reported), 241 (the chain vocabulary open + a structured culprit),
      202 (the verdict class widened), 206 (CI comments from CI's
      figures; the records-pin rule), 315 (the dst docs merged +
      rewritten in content-key terms, the std digests memoized per
      judged run, the note's deferral filed, its 314 lines fixed), 204
      (the harness-family table), 243 (the quoting rules; the 3361645
      exports); 330 and stipulator 322 unpinned from 314, 290r no longer
      behind 315; six charters carry 'reported to the evidence-model
      owner before implementing' (191, 295 — holds behind their chunk 5,
      102, 175, 260, 330, 240's item (d)); the register: children-budget
      → 240, gotool-carries-no-env-drop deleted (landed at 327),
      the merged default-spelling filing is recoverable in Gofresh via
      `git log --all -- docs/issues/guidance-lint-zero-default-spelling.md`;
      the five 300 docs were kept at that audit (a filed
      deferral lives until its Lands fires — the consumer bumps carry
      them as riders; D6 refused in part), harness-admission-families →
      204, prints-default-one-home's pflag-rendering rider; D1–D5
      accepted as argued. Inputs relayed to the evidence-model owner:
      the @41 conflation, the stale inputs-outcome-method gap reason,
      the four gaps citing their plan's chunks.
- [x] 333. gomutant: the sixth re-audit band's gomutant audit (as 332).
      Audit 6 (2026-10-07): Dispositioned 2026-10-07: thirteen coherence
      findings, ten consolidation candidates, the queue walked — 336
      CHARTERED (the gate red at HEAD: fixture git maintenance + the
      guard's walk scope; heads gomutant and the lane), 324 grown to the
      full release set it absorbs (v0.111.x, the vet pre step, the re-
      key, the gotool version grammar, REQ-mcp-resident-set's pointer,
      the CI/policy premises, the INV bindings, the records-pin rider)
      and moved ahead of 302 (D1 accepted: a campaign before the bump is
      the waste the no-wasted-work ruling ends; 324 is correctness too),
      302 (the bank's contradiction; the version bump absorbs the legacy
      floor), 269 (eight decoders, four fail-open; owner told at open),
      209 narrowed, 268 (the INV bindings), 267 (campaign-silent slotted
      here — D6 accepted; the fourth bound site; the explain row), 216
      (sequenceKey → MemoKey), 217 restated (three decoders), 214 (the
      oracle bound decided at open after gofresh 240 — D2 accepted;
      plan-cost slotted), 219 (the clocked pin; git maintenance), 245
      (the seams sentence), 187 (reported before implementing — D5
      accepted; the doc's fork retired), 313 (loses campaign-silent);
      the register: three Lands moved, one doc's framing rewritten; the
      coordination bullet (2026-10-07) added to the doctrine at 335's
      tick.
- [x] 334. stipulator: the sixth re-audit band's stipulator audit (as
      332); 331's charter is a triage input to its replan.
      Audit 6 (2026-10-07): Dispositioned 2026-10-07: eleven coherence
      findings, seven consolidation candidates, the queue walked — 337
      CHARTERED (the roots probe outside the owned runner — reported
      first; the unclassed store-refusal reason with the reason type
      collapse; the served instructions' two stale contracts with a pin;
      the register's re-derivations), 331 RESTATED (D3 accepted: the
      floor's own rationale refutes 'a build never prices a run'; the
      unregistered isolation re-run window is the fault the charter
      missed; origin attribution stands) with 322 MERGED in (D2
      accepted), 290r grown (v0.111.x, the restored adoption riders, the
      snapshot-as-reader fold, 184 MERGED in) and moved directly after
      331 — no longer behind 314/315/202, 270 (the re-census; the no-
      splice rule — D4 accepted), 226/249 timed against the evidence-
      model plan's 6.1, 228 (a generated witness-body grammar), 238
      (explaindynamic in the child), 248 (the pin clause's read); the
      chain vocabulary → gofresh 241 (332 carries it); the register: the
      orphan Lands line struck, cross-platform-resolution-views' trigger
      aligned, resolver-child-kill-orphans' false parenthetical
      corrected, witness-verdict's deleted symbol named for 226's re-
      derivation; D1/D5 accepted.
- [x] 335. pew: the sixth re-audit band's pew audit (as 332) — the
      other machine's performance-evidence plan read, never replanned
      here; closes the band with the cross-repo replan.
      Audit 6 (2026-10-07): Dispositioned 2026-10-07: eleven coherence
      findings, six consolidation candidates, the queue walked —
      320/252r/232r/276r narrowed against the performance-evidence
      plan's 5–12 (the writer census, checkOne, the pew-format-invalid
      key, the ledger round trip dissolve into its 7.2/8.3/7/7.3; the
      REQ home rule's two new pairs and §5's three stale format
      sentences grow 232r; a resident ceiling and 300's lint half ride
      320), 242 gains 3361645's SelectionAudited reader, the harness-
      family table at 204 (332's C3); the register: per-arm-noise-
      floors' second Lands struck, guidance-purpose-column-second-
      enumeration → the plan's 12.2, mutation-oracle-observation cross-
      referenced with gomutant's campaign-silent (267), spec-wide-
      requirement-forming's Lands → 232r's home rule, the handoff doc's
      vestige list corrected; D1–D6 accepted as argued (320 shrinks, 270
      before the plan's 6.1 with its owner told, 226/249 never
      concurrent with the migration, 324/290r now with the second re-
      measure recorded, A1 not a train fix, 269 reported at open).
      INPUTS RELAYED to the evidence-model owner (the handoff doc, 'Band
      R6 inputs'): both consumers' specs still claim a completed
      observation the facade builds the old way (WithCompletedProcess;
      REQ-inputs-producer-premises/-outcome-method) — the train restates
      no premise (270/269); the outcome derivation is per subject while
      stipulator and gomutant run several subjects per process under
      parent-composed environments (their 5.2); @41 versions a field no
      record stores (332's A1); the four gofresh gaps citing their
      plan's chunks; §5/§7.8's contradictions (their 7.1/6.2). The lane
      re-sequenced below; the audit count is ZERO.
- [x] 336. gomutant: the gate is red at HEAD —
      TestDiffNamesEveryMovedMember's walk met the runner's git auto-
      maintenance (.git/objects/maintenance.lock vanishing mid-walk: CI
      run 37582009896 and Next 37582009834 on 065dc4d, the release
      skipped; green on 761b50c — timing-dependent, deterministic in
      class: git 2.55 maintains in the background after a commit and the
      guard's Take walks .git). Fixture repositories carry no background
      git maintenance (the setting at every runGit closure and in
      gitfixture), the guard's walk scope stated (.git in or out, with
      its reason), the pin gaining a concurrent-writer arm. Heads
      gomutant and the lane: a release-blocking red (the 2026-10-02
      doctrine's gate). Audit 333.
- [x] 337. stipulator: conformance — three contract violations audit 334
      found: (1) the gofresh roots probe spawns outside the owned runner
      — observe.go's ProducerIngest carries no Runner and no Roots, so
      `go env -json` runs under a zero gotool.Runner (no boundary, no
      observer, unmemoized, once per package observation) while REQ-go-
      owned-processes says every go child but the loader's runs through
      the runner; a 290 rider dropped silently at 6ec5cfd — the roots
      probe through the owned runner with one runtimeinput.Roots per
      judged operation (both fields exist at v0.109.6; boundary
      plumbing: reported to the evidence-model owner before
      implementing); (2) one minted uncacheable reason has no class —
      packageleg.go's 'the store refused the record: …' is outside
      reasons.go's table, so explain refuses what REQ-mcp-explain says
      it answers; the structural collapse: a reason type constructible
      only through its class (the literal walk's belt retired); (3) the
      served MCP instructions describe two replaced contracts —
      guidance.md's server-instructions block still says a tagged
      invocation fail-closes until its std delta is walked (content-
      keyed since gofresh 310/303; REQ-check-policy-notices amended at
      290.2b) and that explain answers dynamic-state reasons alone —
      restated with a pin tying the instructions' contract sentences to
      their clauses, the stale 'unwalked' wording in the proto and test
      comments swept; (4) the register's re-derivations (witness-
      verdict-one-body-classifier's bodyDrivesRunner premise →
      bodyFactsOf, go-backend-load-path-pairs' double-resolve). Heads
      stipulator, directly after gomutant 336.
- [x] 317. gomutant: the fifth re-audit band's gomutant audit (as 316).
      Dispositioned 2026-10-06: twelve coherence findings, seven consolidation candidates, the queue walked — 323 chartered (the CI/release gate: plain + records, no race — the policy's own selection), 324 chartered (the 281 adoption with the rc-toolchain divergence pinned), 284 dissolved, 187 derived and moved up, 233 re-aimed, 302/313/256/209/268/267/258/220/214/219/269 grown, 254 narrowed; the register: evidence-attach-resident-spike deleted, two docs filed (the campaign silent past its deadline; 304's measure), eight retargets, two test files renamed off their codename.
- [x] 323. gomutant: the CI/release gate — gofresh 48bbe3a's shape (audit
      317): release.yaml on `workflow_run` of a successful CI for a
      same-repository push, serialized, SEMREL_BRANCH=head_sha, a
      superseded commit releasing nothing; a records job (stipulator
      compile + the bindings view failing on any non-current row);
      next-rc its own workflow; the tier plain + records — the policy's
      own selection carries no race (plain_witness, the standing
      no-race rule); policy.textproto's and ci.yaml's stale "unwalked
      selection" premise corrected (303 closed by verdict at 310).
      Heads gomutant's order.

- [x] 324. gomutant: the 281 adoption (audit 317; moved out of 302):
      Runner.List for buildset's linked-set listing; Runner.Program-
      contained git (one runner below the root, 258's fold); one
      runtimeinput.Roots and one Sampler per judged run on every
      ProducerIngest; gotool.ParseGoVersion/ReleaseTags replacing
      engine.go's parseGoVersion and enumerationcheck.go's releaseTags
      — which answers nil for go1.28rc1 (a spurious fail-closed
      enumeration refusal under any rc toolchain on a //go:build go1.N
      test file; the next-rc leg is that environment) and bounds no
      overflow — the divergence pinned. Directly after 187.


      Audit 6 (2026-10-07): grows to the full release set it absorbs
      (gofresh v0.109.1 → v0.111.x: 326's family-room ceiling, 327's
      MemoKey/RunMemo/SnapshotSampler with the forwarders deleted — no
      production compile break, the dead forbidden-name arms in
      runnerwalk_test retired — 292's exemption-clause re-key
      (bracketClause deleted), 300's lint consumer half (the four parked
      gofresh docs as riders), 3361645's @41 — every record re-measures
      once, a second re-measure expected at the evidence-model plan's
      5.4, recorded not deferred); ci.yaml's darwin/BSD vet pre step
      (gofresh-pin-breaks-darwin-and-bsd-builds closes with it; the
      build half closed at gofresh bdb0a37); parseGoVersion/releaseTags
      fold onto gotool's (a devel spelling read as a version; nil for
      go1.28rc1); REQ-mcp-resident-set points at REQ-fresh-resident-
      readings instead of restating the halved-available rule 326
      retired — the 0→1 gating stated with its cost or dropped;
      ci.yaml's full-timeout premise (test 29m–30m against 60m) and
      policy.textproto's 'before v0.109.0' arm restated from the runner;
      the INV-MUT-COMPREHENSIVE and INV-RESULT-CANDIDATE-CONSERVATION
      bindings (records-only; mutation.md:30's status narrative struck)
      — deferred four audits, judged by CI's records tier now; a rider
      pinning the records tier's stipulator to the version that writes
      the bindings. Directly after 336 and ahead of 302.
- [x] 318. stipulator: the fifth re-audit band's stipulator audit (as 316).
      Dispositioned 2026-10-06: twelve coherence findings, eight consolidation candidates, the queue walked — 321 chartered (the CI/release gate, heading stipulator), 290 split (290.2b now: the v0.109.x bump, one toolchain read, the resident fold, the spec amendments, the per-operation sampler), 322 chartered (per-operation readings in a long-lived server, after gofresh 314), 299/298/270/226/249/185/225/248/228/176 grown, 238's dependency corrected; the register: four retargets (property-completion derived to 298, dotted-package to 226, kill-orphans to the first Runner.Program spawn, aborted-pass re-derived at 249); A10's gap-record claim REFUTED (a gap record is a tracking artifact — it may cite the plan); C8 (the 1 GiB floor spelled twice across repos) relayed to 316.
- [x] 321. stipulator: the CI/release gate — gofresh 48bbe3a's shape
      (audit 318): release.yaml on `workflow_run` of a successful CI
      for a same-repository push, serialized, SEMREL_BRANCH=head_sha, a
      superseded commit releasing nothing; a race job with its budget
      measured at open (ci.yaml's 2026-08-27 budget comment is stale:
      backends/golang 2045–2099 s against a 75 m timeout); a records
      job (compile + the bindings view) — the twelve `implements` rows
      on stipulator.v1.* messages no backend resolves decided at open;
      next-rc its own workflow; ci.yaml's "self-check at each chunk's
      close-out" text corrected to the 2026-09-07 ruling. Every
      stipulator tag feeds gofresh's own records gate. Heads
      stipulator's order.

- [x] 322. stipulator: per-operation readings in a long-lived server
      (audit 318, 307.D's remainder): the admission's growth headroom
      is VmHWM − VmRSS, a lifetime peak — after one large call every
      later pass reserves room to grow back to it (a spurious hold or a
      "cannot hold one process" refusal on a small host); the gate is
      per invocation but DescendantsBytes/running divides the whole
      process's descendants, so concurrent MCP operations inflate each
      other's estimates; 5407c3d rebased the reporter's peak, never the
      admission. After gofresh 314 (the own-set derivation).


      Audit 6 (2026-10-07): MERGED into 331 (audit 334): its two
      premises landed at 290.2b.B; the concurrent-operation residue is
      331's admission code.
- [x] 319. pew: the fifth re-audit band's pew audit (as 316); closes the
      band with the cross-repo lane re-sequenced.
      Dispositioned 2026-10-06 — BAND R5 CLOSED: twelve coherence findings, seven consolidation candidates, the queue walked — 291, 174, 127, 15 and 177 dissolved into pew's performance-evidence plan (the handoff doc carries their riders), 252, 232 and 276 narrowed to residues after that plan closes, 320 chartered (the residual bump), A3's circular remedy (the train's 230 anchor) handed to that plan's chunk 3, A5's gomutant half filed. The cross-repo lane is in the order sentence; the audit count restarts at zero.
- [ ] 320. pew: adopt only shared capabilities and projections
      actually unconsumed by the live caller. Active destination:
      tooling-redesign **5.6**; constituents 7.4 and 8.3. Current Pew already
      pins v0.117.2 and has Session/native-binary, retained-artifact, query,
      profile and A/B adoption plus shared Coverage lint. Remove remaining
      zeroDefault/cliUsage/firstClause copies with independent pflag/literal
      controls; adopt LongHelp's missing pointer. Reconcile remaining parent
      resident/resource controls without changing the measured environment.
      Future released capabilities require explicit adoption and compatibility
      judgment, not a blanket repetition of completed migrations.
- [x] 311. gomutant: the observation-proof pass per group — the vertical
      (the user's ruling 2026-10-04: the unit loop's deviations are the
      source of most of the fleet's problems and take priority; gomutant
      recovery: `git log --all -- docs/issues/observed-union-memory-slicing.md`, its measured trigger
      retired for the principle). Today the derived oracle's proof pass
      (`subjectViewSet.observed` → gofresh's CaptureObservedBatch, the
      "prove" phase) runs over the WHOLE union under one Hasher per
      module view before the first target commits: protodb watched it
      for an hour, pb's 1,608-subject union reached 8 GiB, and a run
      interrupted in it banks nothing. The pass becomes part of each
      group's vertical: the group's union proven (its own Hasher,
      released after), its targets measured and committed, the next
      group — committed evidence after the first group, the resident set
      the group's, the persistent memo serving shared folds across
      groups; the preparation's pricing line prices the proof per group;
      REQ-exec-analysis-budget / the prove phase's clauses amended to the
      per-group pass. Measured at close over gomutant's own `--changed`
      campaign: time to the first committed target, peak resident set.
      Directly after stipulator 307.B in the lane; heads gomutant's
      remainder; the issue deletes at close.



- [x] 278. gomutant: the bump behind gofresh 265, 266, and 274 (the lane's
      "bumps gomutant" step, chartered at 274's close) — the gotool
      copies (the hand-built runner/containment, the sampler and its
      memo, the env snapshot and setter, the vouch entries parser)
      delete for gofresh.gotool's; runtimeinput.RefusalClause replaces
      reasonClause/carriesAttribution (259's exemption records key on
      the reason text — the bump is BREAKING until they do); the
      analysis phases read gofresh.UnitPhases()/Progress.IsUnit
      (analysis-unit-phases-one-home closes); the guidance projections
      (knobbedFlags/flagUsage/knobProsePointer/knobSchema/KnobClause)
      delete for Knob.Usage/Clause, Document.DescribeSchema (the nested
      edit fields earn prose; the coverage enumeration reads the
      visited names), Embedded.Registration and the Must refusals,
      Coverage's Registered map (knob-terse-clause-per-face closes);
      SubjectEvidence embeds gofresh.Fingerprint's published record
      form beside its own fields (ModuleBase, RuntimeUnverifiable,
      RuntimeReason), the flattened proof and the hand inventory
      delete, a DocumentVersion bump with the version chain's rule; the
      provenance composite reads gofresh.ToolchainProvenance. Every
      record re-validates once. When 265, 266, and 274 have released.
- [x] 279. gofresh: the runtime-input digest folds the refusal clause
      (attribution-in-runtime-input-digest, found at gomutant 278's
      reason-clause change set) — the manifest's unverifiable entries
      and the digest carry RefusalClause(reason), the recorded reason
      its attribution whole; REQ-inputs-refusal-attribution states
      which readers see which; a release (every consumer's
      machine-local records re-measure once at its bump — declared).
      Correctness first: directly before 240 in gofresh's order. Rides
      (from gomutant 278's runner fold): ToolchainProvenance.Check
      returns its sample (provenance-check-drops-the-sample); the
      snapshot and the roots probe serve the answer Run salvages beside
      ErrWaitDelay (runner-run-salvage-unread-at-snapshot-and-roots).
- [x] 221. stipulator: soundness conformance between the policy record
      and the engine — the repository vouch file is neither declined
      (gofresh's WithoutRepositoryVouches, the "one set, one home" the
      producer's clause requires of a consumer owning its set) nor
      partitioned into the capture-group key; the witness command's
      -mod and -pgo flags never reach the engine's build flags and the
      PGO profile's content is digested by nothing (spurious reuse on a
      profile edit at a stable path); module_root is in neither key
      table though the identity table claims completeness (two
      invocations differing only by it share one capture group); the
      provenance probe spawns outside the owned boundary
      (REQ-policy-cancellation's "every child process"). Code, with the
      identity table's claim made true or the omission stated.
- [x] 223. stipulator: one witness pipeline (Stipulator recovery:
      `git log --all -- docs/issues/two-completion-mechanisms.md`,
      `git log --all -- docs/issues/publish-refusal-ladders.md`,
      `git log --all -- docs/issues/executor-diagnostics-trio.md`) — the selective runner's 592-line
      runWitnesses and the health-judged recorder (Derive, covered,
      invocationCompleted, publishRemaining, publishGroup) are two
      implementations of one spec object, which REQ-evidence-freshness-
      degrade already frames as one path with an empty served set; one
      group tracker, one refusal ladder with one reason vocabulary, one
      publish path; invariants: REQ-policy-cancellation's unit of
      persistence, REQ-evidence-freshness-no-health's serving integrity;
      the last of the parallel pairs 170 collapsed; docs delete at close.
- [x] 222. stipulator: the spec chunk — the policy's blanket purity
      assertion (assume_pure, invocation-wide, set on this corpus's own
      three invocations) stated beside REQ-evidence-witness-freshness's
      in-source opt-in; REQ-core-proto-io carves out the intra-
      invocation resolver protocol as the store-layout clause carves out
      record files; the derived policy constants (the two timeouts)
      stated or their omission stated; REQ-go-owned-processes'
      toolchain-query half enumerates the provenance probe. Spec only;
      re-consented.
- [x] 224. stipulator: one verb core per verb across both faces — prune
      written twice end to end with two serving-class predicates
      (ServingClassRequired on the CLI, ServingEvidence on MCP); MCP's
      verifyPipeline seam generalized so each verb's core takes a
      face-supplied renderer and the faces keep their defaults; wire's
      one-projection claim made true (protojson.Marshal at verify.go,
      gate.go, check.go and the four StructuredContent bypasses read the
      canonical projection); the 2,329-line MCP server split per verb to
      mirror internal/cmd.
- [ ] 225. stipulator: the small folds — one reason tally behind two
      reader-specific caps and one semantic vocabulary. Active destination:
      tooling-redesign **5.6**; constituent 8.3. Re-census reference-key case
      rules, keyword/enum/bucket renderings, Unicode truncation and prose
      composers before folding; preserve each reader's cap and omitted count.
      Retire verified write-only/test-only exports, unused seams and stale
      comments with binding checks, not the old inventory wholesale. Per-stream
      styling judges each destination's TTY/NO_COLOR/TERM independently and
      never colors structured output. Existing executor UTF-8 repair stays
      closed; roster allocation and operation accounts remain distinct.
- [ ] 226. stipulator: golang.go split by its three subsystems
      (resolution/shape, classification/seeding and generated detection).
      Active destination: tooling-redesign **7.8**; constituents 5.2d and
      5.2e. Complete selections, module mode, physical declaration positions,
      dotted package ownership and cross-view certificates are already closed
      controls. Consolidate remaining workspace membership/error/path facts,
      including portable syntax, escaping links and legitimate `..foo` paths;
      retain distinct go-command requirement parsing and test-variant identity.
      Share the two per-view body scans while keeping resolved class and
      cross-view seeding union distinct. Dependency/interface and generic-
      constraint precision needs separate seeded/deterministic/unresolved
      proof. Reconcile subject-key and per-operation sampler/roots/runner
      lifetimes. Reviewed-row lifecycle folds ride package adoption, retaining
      distinct exclusion/vouch/namespace authority and endpoint observations.
- [x] 227. stipulator: the vestigial sweep — three build-tagged
      atomicReplace declarations with no call site (the Windows arm
      dragging kernel32), the legacy .stipulator/cache removal on every
      load with no writer, Backend.members write-only, testEvent's two
      unread fields, the Toolchain/ToolchainContext dead pair, two
      injection seams with no injection site, a test-only option
      mechanism, resolutioncache.Record.Key, the six test-only wrappers
      over production entries, and ResolverChildMain's second argv
      routing.
      (236: grown — 225 folds in; two corrections: the two injection
      seams claim is REFUTED (every seam has a test injection) and
      ResolverChildMain's live cobra route stands — the item is
      resolver.go's self-routing argv beside cmd/internalresolve, reached
      by four TestMains; adds: the dead atomicReplace trio (drops
      golang.org/x/sys as a direct dependency), five atomic writes onto
      recordstore.WriteAtomic, two Digest copies, the legacy cache
      RemoveAll, Backend.members, Toolchain/ToolchainContext, testEvent's
      unread fields, progress.WithInterval, Record.UnmarshalJSON,
      resolutioncache.StoreDir, impact.SpecTouched, facts.OverlapCap,
      the two test-only exported wrappers, six over-exports; the MCP
      shared machinery out of verb files (writes.go/export.go/schema.go);
      internal/dossier into facts; author.go and verify.go split by job.)
- [ ] 228. stipulator: the test surface (stipulator docs/issues/
      cli-test-binary-builds.md). Active destination: tooling-redesign
      **5.6**; constituent 9.3. Share the eight same-identity CLI builds
      and reconcile four ambient helpers, preserving isolated fixtures,
      real process/version tests and mutation-sensitive in-process pins.
      Re-census workspace fixtures, helper copies, process-global settings,
      enumeration/self-oracles and coverage/progress/format arms. Separate
      witness-cache tamper cases by sub-contract and preserve strict history
      controls. Add exact-field/value-pointer-method structural evidence and
      a generated driver × spelling × reach body grammar, with independent
      expected classes/never-serve facts across selected views. Completed
      guidance grammar removal and source certificates are not repeated work.

## Band J — pew under the emergent shape (chartered by audit 197)
- [x] 229. pew: the gofresh bump v0.95.0 → v0.101.0 (recover in Pew with
      `git log --all -- docs/issues/gofresh-corpus-pin-lag.md` and
      `git log --all -- docs/issues/serve-proven-blocked-by-benchmark-loop.md`)
      — six releases consumed at once: the harness-pacing audit that
      lifts serve-proven's inertness (today run's default serves only
      empty-bodied benchmarks), the canonical closure member (every
      recording re-measures once) with Fingerprint.ClosureStrategy's
      key-set decision for pew's writer and reader, the evidence-root
      anchoring, the repository vouch file — pew's reviewed set lives at
      the store root by REQ-pew-vouch-source, so the engine declines the
      module's file (WithoutRepositoryVouches) and the home stays one —
      and guidance.Knob for 173; both docs delete at close.
- [x] 230. pew: the artifact-format bound — G5 and REQ-pew-artifact-format
      promise every stored .txt parseable by benchfmt and plain benchstat,
      and pew's own writer breaks it: the runtime-inputs and test-variant-
      ledger lines grow past benchfmt's 64 KiB scanner bound, which pew's
      reader survives only by lifting them out before parsing; the two
      blob encodings are bounded (chunked, or digests with a sidecar the
      spec sanctions) so the promise holds as stated — the spec is never
      narrowed to the escape hatch.
      (264: leads pew's queue — the one MUST violation there: liftOversizedConfig
      lifts header lines past a 48 KiB bound pew's reader compensates for and
      plain benchstat cannot (REQ-pew-artifact-format).)
- [x] 231. pew: the hygiene sweep — the vestigial exports (store.List and
      its predicate, recordingFromPath, gitblob.State, run.ExecuteBinary,
      run.Execute's test-only seam); one containment predicate for three
      named and seven inline ones and one longest-existing-prefix
      resolver; one go-command constructor for the five identical
      bridges, closing the provenance probe's unresolved dir and unpinned
      PWD structurally (§9's one environment policy); the shared source-
      scan seam out of gc.go and the scratch helpers out of it; four
      engine constructors one; gc's two full store walks one; ab's
      duplicated count check; a fused doc block; the six recording
      builders and two duplicated helpers in the tests one.
      (237: NARROWED to the conformance half — the one go-command
      constructor gotool.Command(ctx, dir, env, args...) replacing the
      five hand-wired bridges (§9's one policy structurally; the
      provenance probe is the one invocation outside it today) and the
      context threading REQ-pew-interruption requires at the eleven
      Background/exec.Command sites (229 threaded ctx into gofresh's
      forms with a locally minted Background); the sweep is 252.)
- [ ] 232. pew: reconcile current requirement homes, reader contracts
      and their documentation. Active destination:
      tooling-redesign **8.3**; constituent 9.2. Reconcile live README/spec
      format and native-executor descriptions, subprocess requirements,
      --explain stream, effective comparison policies and source inventory.
      Preserve active A/B versus inactive-tag GC semantics. Census genuinely
      unformed or duplicate requirement homes, including recovery/status
      pairs, rather than re-forming every paragraph; IDs and a derived-state
      gap already exist. Reconcile §12's purpose column under the spec's
      authority and shared help/default projections, preserving distinct
      validity/diagnostic/format dispositions and normative strength.

## Band E — design chunks (open with the user)
- [x] 215. gomutant: Tree.Run decomposed (design, with the user) — a
      2,713-line function holding the campaign's state in 52 locals and
      19 closures, three of 380–480 lines; a campaign struct with methods
      makes the state nameable and testable and is the precondition for
      the splice collapse's siblings and any future window work; the
      root package's 80 methods on a four-field Tree span seven roles
      worth naming; after 207, 211, 186, and 212 have shrunk its
      surroundings.
      (262: MERGED into 245 — dissolved as its own chunk.)

- [ ] 202. gofresh: the dynamic-state tier's home and walk context
      need one semantic owner. Active destination: tooling-redesign **7.1**;
      constituents 5.2c, 7.8 and 8.3. Carry source-audit, subject/model,
      package-graph, cut/unavailability and explanation facts coherently,
      retaining fail-closed defaults and independent transaction state.
      Typed semantic causes are still absent from gofresh.Verdict: release
      the minimal authority/cause/culprit boundary at package adoption rather
      than grow consumer-local prose parsers or claim completed 4.1 supplied
      every structured ground. Consolidate discharge channels, attestation
      records and carrier/call/use walks only where their policies agree.
      TLS entropy irrelevance is unproven; generated own/dependency descriptors
      already have a single-subject channel. Package-process refinement,
      carrier memos and immutable objects require separate alias/runtime
      proofs before widening, never blanket TLS or local-vouch admission.
- [x] 15. pew: profile capture and attribution as recording
      companions (`../pew/docs/specs/spec.md` §§6.2/10.2; noise floors:
      pew docs/issues/per-arm-noise-floors.md) — explicit CPU/allocation
      diagnostics own their execution evidence independently of timed
      samples. Full immutable profiles retain unresolved attribution;
      status separates integrity, freshness and relation, and historical
      comparison reads companions from each selected ref. Per-arm noise
      floors remain delegated to performance-evidence 12.1, sound on
      package closures; gofresh 102 only refines lineage precision.
- [ ] 102. gofresh: per-subject sliced closures — Fingerprint gains
      no field merely because the checkpoint proposed one. Active destination:
      tooling-redesign **7.8**; constituent 8.2. Reconcile chunk-102-wip
      08be384's attributed declaration identity with current canonical source,
      compartments, complete dependencies and maximal fallback. Prove relevant
      constants/initializers/imports/embeds move the identity and unreached
      edits do not where bounded; unchanged-tree examples prove no universal.
      Coordinate with 175 before any native format/application change. No
      slice implies layout-only harmlessness or authorizes a noise floor;
      preserve the checkpoint until its obligations are decided.
- [x] 127. pew: observed-fingerprint recording path — governed by
      `../pew/docs/specs/spec.md` §7.8: each measurement invocation
      owns its observation, and current-tree judgments explicitly
      select observed policy. Normal process completion alone does
      not establish outcome support; unsupported inventories retain
      identity-only guards, never an observation-based freshness lift.
      The native fingerprint contract (§5) preserves historical
      evidence as recorded, and inert growth (§7.9) advances only the
      checked applicability endpoint and paired ledger while retaining
      the original producing fields and support.
      Delegated: → performance-evidence chunk 8, after the shared completion capability/adapters at 5/6 and the canonical fingerprint boundary at 7. Process health alone supplies no outcome support, and old observation assertions are not upgraded by the format cutover.

- [ ] 175. gofresh: derive subject-scoped closure identity under the
      canonical evidence contract. Active destination:
      tooling-redesign **7.8**. Establish complete reachable-member identity
      and maximal fallback, including source/configuration/derivation inputs,
      before licensing finer applicability. Package-maximal canonical hashes
      do not certify subject semantics. Keep Gomutant's current unshaped
      domain and shaped pin distinctions until the new license exists;
      neither dropping incomparable hashes nor carrying a strategy move may
      hide a simultaneous real edit. Coordinate 102's checkpoint and native
      format/binding consequences without automatic historical upgrade.
- [x] 328. gofresh: admit the source-audited go1.27.1 nodwarf5 selection and its standard selection variants without weakening content-key admission.
  - [x] 328.1 Reproduce the unlisted internal/goexperiment key, compare the dwarf5 selection against the existing audited chain, and inspect the selected constants and their consumers.
  - [x] 328.2 Record the audited source deltas and retain rejection of unlisted content, including selection-specific chains.
  - [x] 328.3 Run the applicable Go tests and mutation evidence, converge independent review, commit and push the completed source audit, and make its released version available to the consumer bump.

## Ecosystem-blocked

- [ ] 95. gomutant: MCP Tasks adoption — protocol-level operation
      identity, polling, result retrieval and explicit cancellation remain
      conditional. Active destination: tooling-redesign **6.7**; trigger
      census 9.4. Provide bounded recovery independently of Tasks. Adopt the
      protocol only when the SDK and a consuming agent client actually
      support it; preserve that observable trigger at final census, not an
      implementation grant. History in Gomutant: `git log --all --
      docs/issues/mcp-long-running-runs.md`.
