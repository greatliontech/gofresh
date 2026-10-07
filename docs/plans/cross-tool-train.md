# Cross-tool train: correctness, speed, caching, UX

The active roadmap across gofresh, gomutant, stipulator, and pew. Each
chunk is one commit in its named repo, run through the full adversarial
loop there; gofresh chunks release before consumer chunks bump. WIP = 1
across the whole train. Chunk numbers are stable identifiers, never
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
  conformance. Per tool (restated by the user 2026-10-04, recorded so
  it is never re-derived): gomutant's vertical is the target within
  its window — preparation fail-early, freshness per record, the
  window committed and banked per batch (207.2b, 304) — with ONE known
  deviation: the derived oracle's observation-proof pass runs over the
  whole union before the first target commits (the prove phase;
  observed-union-memory-slicing's trigger, 277), to become per group
  (prove the group's union, commit its targets, the next group).
  stipulator's vertical is the PACKAGE under its covering invocation — a
  witness group is the invocation's build coordinate and spans every
  package the invocation runs, so the group was the deviation (a check
  cancelled at 1h51m "kept nothing"); 307.B2a lands the package unit on
  the selective form (its executed records publish at its completion,
  its isolation re-runs inside its unit, its served records revalidated
  after every execution), 307.B2b on the health-judged form — with the
  resolver child's whole-corpus discovery the remaining deviation (307.B's
  last step). pew's vertical is the arm (157.2a's preparation, 157.3's
  per-arm persistence and gates) — conforms. gofresh is the library:
  the view a consumer builds is the vertical, every pass is per view
  and bounded by the analysis budget (305); its conformance is its
  consumers' slicing. The principle holds across the board; what is per
  tool is only the vertical's unit. The same rule governs
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

- **A second machine works pew under pew's own plan** (pew
  docs/plans/performance-evidence.md, 2026-10-06; its chunk 2 is the
  train's 291, its chunks 4–8 reach into 174, 252, 232, 276, 177, 15
  and 127). No train session opens a pew chunk while that plan is
  open; pew's train tail is re-chartered at the pew re-audit (319)
  against that plan's residue; every chunk open AND every push here
  fetches all four repos first and rebases onto origin (the other
  machine does the same); a pew-side chore the train owes — the
  minted ignore's two exit-log lines (gomutant 312) — lands after that
  machine's gomutant reinstall, never before.
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

Replanned 2026-09-02 (user ruling: no wasted work; audit the four
repos, consolidate the behaviour, and only then run the tools against
the work). The audit is docs/plans/pipeline-audit/ (delete-on-close).
The order from here: **Band T first** — 150, 151, 152, 153 (the
self-test partition per repo: the code of every tool testable in
seconds without running the tool over a tree) — then **Band P** —
154 (gofresh: the observation pass gains a preparation pass, a
persistent contribution memo, and a per-package tick; release),
155 (stipulator), 156 (gomutant), 157 (pew) — each the tool's
operations restaged as fail-early preparation, then the incremental
check-freshness / measure / persist loop per unit, the operator told
throughout, on both surfaces, with every preparation-decidable refusal
moved forward and the audit's knob dispositions landed in the same
seam — then the deferred self-host verdicts (141's, re-run once over
the settled tree under 155's warm, reporting check), then the field
band as previously ordered: 138, 140, 115, then 142, 143, 144, 145,
then 136 (rescoped: the consolidation scan and the refusal-site walk
that Band P leaves), then the rest as recorded below.

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
recorded field mass), then 182 (chartered from the 180 re-measurement), then Band F 158–178 in its listed order with 183 directly after 170 (triage 2026-09-09), the re-audit band 194–197 directly after 183 (its replan re-sequences everything below), and 184–193 after 178 (175 is a design chunk opening with the user); gofresh's order after audit 316 (2026-10-06): 325 (the reusable CI workflow, cross-repo) → 326 (the resident release) → 327 (the gotool surface release) → 329 (the race tier sharded, cross-repo) → 292 (a release) → 300 (a release) → 315 (the machine walk with 297's corpus; a release) → 314 (a release) → 330 (godst's caller frame in the test log, cross-repo; a release) → 202 (design, autonomous) → 191 (a release) → 295 (a release) → 240 → 241 → 260 → 203 → 204 → 206 → 192 → 193 → 255 → 242 and 243 together → 175 → 102; 297 merged into 315; 303 closed by verdict; 199 dissolved; gomutant's order after audit 317 (2026-10-06): 323 (the CI gate) → 302 → 187 → 324 → 313 → 269 → 209 → 268 → 267 → 258 → 245 → 212 → 216 → 218 → 217 → 220 → 214 → 219 → 254 → 296 → 256 → 188 → 233 → 294 → 95 last when its SDK prerequisite lands; 284 dissolved (its campaign half 302's close); 210 dissolved (done at 246/278); stipulator's order after audit 318 (2026-10-06): 321 (the CI gate) → 290.2b (the v0.109.x bump, one toolchain read, the resident fold) → 299 → 293 → 298 → 322 (after gofresh 314) → 290r (behind gofresh 292/297/300) → 270 → 226 → 249 → 185 → 225 and 248 together → 228 → 184 (behind gofresh 300) → 176 → 238 (behind gofresh 241); 97 un-chartered; pew's order after audit 319 (2026-10-06): via pew's performance-evidence plan chunks 2–8 on the other machine (291, 174, 127, 15, 177 dissolved into them; the handoff doc names every rider); after that plan closes, 320 → 252r → 232r → 276r; 173 dissolved (landed at 275.C); THE CROSS-REPO LANE after the fifth re-audit band (316–319, closed 2026-10-06; the audit count restarts at zero): soundness and conformance first, a producer's release before the consumer bump that reads it, pew's slots deferred to the other machine's plan, design chunks autonomous, 95 last — cross-repo 325 (the reusable CI/release workflow; opens with the user's confirmation of the org repo) → gomutant 323 (the CI gate, the call) → stipulator 321 (the CI gate, the call) → gofresh 326 (the resident release) → 327 (the gotool surface release) → cross-repo 329 (the race tier sharded) → stipulator 290.2b (the v0.109.x bump: one toolchain read, the resident fold) → gofresh 292 (release) → 300 (release) → stipulator 299 → 293 → 298 → [pew: via performance-evidence chunk 2 (the train's 291 with its handoff riders) and chunk 3 (the loader's legacy lines) on the other machine] → gomutant 302 → 187 → 324 (the 281 adoption) → 313 → gofresh 315 (the machine walk with 297's corpus; release) → 314 (release) → cross-repo 330 (godst's caller frame in the test log; a godst release, then gofresh's) → stipulator 322 (after 314) → 290r (behind 292/297/300) → gofresh 202 (design, autonomous) → 191 (release) → 295 (release) → stipulator 270 → gofresh 240 → stipulator 226 → [pew: via performance-evidence chunk 4 (174's verdict path, 127, the two covered gaps' anchors)] → gofresh 241 → gomutant 269 → stipulator 249 → [pew: via performance-evidence chunks 5–8 (177, 15, the metric registry, ab's git stages)] → then the tails round-robin in each repo's recorded order: gofresh 260 → gomutant 209 → stipulator 185 → gofresh 203 → gomutant 268 → stipulator 225+248 → gofresh 204 → gomutant 267 → stipulator 228 → gofresh 206 → gomutant 258 → stipulator 184 → gofresh 192 → gomutant 245 → stipulator 176 → gofresh 193 → gomutant 212 → stipulator 238 → gofresh 255 → gomutant 216 → gofresh 242+243 → gomutant 218 → gofresh 175 → gomutant 217 → gofresh 102 → gomutant 220, 214, 219, 254, 296, 256, 188, 233, 294; after performance-evidence closes, pew 320 → 252r → 232r → 276r; 95 last
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
      docs/issues/ci-seat-for-the-check-verdict that does not exist)
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
      docs/issues/probe-phase-cost-invisible.md; deletes at close).
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
      docs/issues/actionable-unverifiable-refusals (each unverifiable
      reason names its discharge channel — vouch/directive/
      restructure) and stipulator
      docs/issues/pin-forms-shape-guidance (shape-moved guidance and
      the ids-form answer mislead exactly when shapes mismatch); both
      docs delete at close.

## Band C — ergonomics, robustness, consolidation

- [x] 128. gomutant: serve carve-out consolidation (gomutant
      docs/issues: fold-growth-into-generalized-drift,
      consolidate-reidentification-and-bucket-policy) — growth is a
      strict special case of generalized drift; one re-identification
      helper, one advisory-bucket policy; same subsystem as the
      landed 103 (gomutant 2ba8841), whose windowScores bundle and
      newSurvivor/carrySurvivor constructors are the shapes the
      consolidation builds on; both docs delete at close.
- [x] 113. gomutant: ergonomics and robustness batch — landed
      (gomutant c4093cb..4400573; gofresh 40317df; dispositions in
      the commit records; the campaign-scale residue was ruled and
      resolved in chunk 137 (successor residue: gomutant
      docs/issues/own-face-gate-suite-decomposition.md), and
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
      as gomutant docs/issues/own-face-gate-suite-decomposition.md
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
      docs/issues/check-green-over-witness-failure.md +
      docs/issues/property-suite-witness-serving.md). 141.1 reproduces
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
      docs/issues/bracket-path-module-relative-in-workspace.md) — a
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
      docs/issues/ephemeral-test-pkg-shorthand.md — ephemeral
      --test-pkg accepts a relative package directory resolved
      against the loaded set, matching the --dir default. Both docs
      delete at close. Measurement surface: diagnostics/CLI
      resolution only — no pew arms, no DST legs.
- [x] 140. gomutant: ephemeral probe integrity (field-response, bldc
      reports 2026-09-03; gomutant docs/issues:
      ephemeral-deletion-probes-strand-imports — an imports fix runs
      over the mutant before compiling (a probe declares no import
      intent), the result saying which happened;
      ephemeral-blind-spots-stated-and-refused — a target file no
      measured test compiled is a REFUSAL, never a survivor, and the
      three blind spots enter the ephemeral guidance with the
      mutate-the-guard's-input workaround beside them;
      ephemeral-compiler-crash-retry — a compiler signal death retries
      once or marks "compiler crashed — re-run to confirm";
      ephemeral-batch-wrapper-undiscoverable — the {"edits": [...]}
      wrapper named in guidance and refusal, or the bare array
      accepted). Four docs delete at close. Measurement surface:
      probe-path diagnostics only — no pew arms, no DST legs.
- [x] 146. FOLDED into chunk 156 (Band P, 2026-09-02): the staged
      snapshot's external-input refusal is one instance of the
      prepare-stage invariant 156 lands; the field report's doc rides
      156's close.
- [x] 115. pew: verdict-surface batch (pew docs/issues:
      gitblob-linked-worktree-object-lookup — pew run fails in linked
      worktrees; ab-worktree-placement-escape — operator escape +
      startup sweep; verdict-ladder-shared-admissibility — the
      status/stat admissibility ladder collapses to one shared
      function with the per-side working-tree input) — three docs
      delete at close. RIDES: pew
      docs/issues/repo-level-vouch-source.md — a reviewed vouch file
      beside the store replaces hand-mirrored flag lists; doc deletes
      at close. Deviations: the gitblob doc (user decision) folded —
      one option on the open call, no judgment; `--vouch` flags
      extend the file and never remove (no `--no-vouch`); the
      residue sweep is ownership-scoped (this repository's, or an
      empty mint) after review; the vouch-globals and row-decode
      collapse filed as pew docs/issues/verdict-path-consolidation.md.
- [x] 142. stipulator: clause-granular binding claims (bldc report
      2026-09-03; stipulator
      docs/issues/clause-granular-binding-claims.md) — a binding
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
      stipulator docs/issues/content-hash-function-versioning.md) — a
      hash-function move is its own recorded state ("rehash",
      bulk-re-pinnable without editorial consent) or the pin records
      the declaring document's blob hash beside the content hash, so
      a re-consent over unchanged text is self-evidently that. RIDES
      docs/issues/pin-req-unchanged-text-wording.md ("text unchanged;
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
      stipulator docs/issues/cli-verify-view-path-and-explain.md) —
      CLI verify gains --view/--path and the explain verb lands on
      the CLI, so "what claims this symbol" is a query, never a grep
      over the record format. RIDES
      docs/issues/normative-keyword-lint-timing-and-remedy.md (a lint
      entry point compiling the corpus at the amendment; the remedy
      in the message). Both docs delete at close. Measurement
      surface: none.
      RIDER (bldc report 2026-09-02, slotted at 114 close): the
      attestation-cell refusal and explain-on-uncovered name the
      reclassification remedy (stipulator
      docs/issues/attestation-refusal-names-no-reclassification.md;
      doc deletes at close). Deviations: the rider landed as a kind
      hint stating the IR's kind definitions, never a reclassification
      instruction (the tool computes remediations, never prescribes
      fixes); the keyword lint's entry point is `compile`, named in
      the diagnostic and guidance — no new timing hook; a scope now
      narrows the verification summary on both surfaces.

- [x] 145. stipulator: spec-graph authoring (bldc reports 2026-09-03;
      stipulator docs/issues/refines-multiple-targets.md — refines
      admits a target list, canonical form ordering it, impact and
      coverage reading every edge — +
      docs/issues/supersede-removed-source-one-step.md — the
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
      it. Filed: stipulator docs/issues/remedy-spellings-one-source.md
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
      docs/issues/delta-line-survivor-view.md) — a --changed
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
      gomutant docs/issues/legacy-overlay-read-deletes-attestations.md
      — preserve unsupported older overlays and their authored
      equivalence reasoning while refusing to serve them; doc deletes
      at close.
- [x] 131. stipulator: one identity walk, two windows (stipulator
      docs/issues/identity-walk-two-trackers.md) — attachment and
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
      docs/issues/audit-key-mechanism-consolidation.md (four parallel
      spellings of the audit lookup/refuse mechanism — this is the
      band's first audited-set change) and
      docs/issues/nodwarf5-toolchain-audit-key-mismatch.md (release,
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
      gofresh docs/issues/enumeration-targets-over-approximated.md,
      already deleted — history in git). RIDES: gofresh
      docs/issues/range-over-func-yield-closure.md — admit the
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
      RTA fallback. RIDES docs/issues/dynamic-target-init-exemption.md
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
      docs/issues/sibling-reason-families-name-their-channels.md
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
      line and MCP row say so (ephemeral-attested-survivor-invisible.md),
      and the attestation is keyed on the mutated file's post-edit content
      hash rather than the edit text (ephemeral-attestation-keyed-on-edit-
      text.md); three docs delete at close.
- [x] 161. stipulator: a gap can say "contradicted by design until a
      condition fires" (stipulator docs/issues/gap-cannot-say-contradicted.md)
      — a `contradicted` gap state reported distinctly from unwitnessed,
      resolving only on an explicit fire, never on a passing witness while
      unfired; doc deletes at close.
- [x] 162. gofresh: the repo-level vouch convention (gomutant docs/issues/
      repo-level-vouch-source.md) — the engine sources a repository's
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
      document (pew docs/issues/guidance-knobs-and-verb-table.md) — pew's
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
- [x] 174. pew: `ab --out` per package and one verdict path (pew
      docs/issues/ab-out-multi-package.md, verdict-path-consolidation.md)
      — one artifact per package under a derived path, its encoding
      (pew-ab: 1, dirty, pkg, pew-ab-ref, pew-ab-side) stated in §12;
      stat's working-tree arm adopts the batched per-package check
      (today verdictForRecs builds a whole-program view per benchmark and
      a second on the inert-growth rider; checkOne has no production
      caller); pew's vouch grammar and file reader deleted for gofresh's
      ReadVouchFile and ParseVouchEntry with the four process-wide vouch
      globals a threaded value; one recording-row decode feeds admission,
      the fingerprint, the closed set, and --explain; after 229; two docs
      delete at close.
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
      Rider (tugboat field report 2026-09-29, pew docs/issues/strategy-stale-arms-flipped-valid-without-rerecord.md): 46 arms flipped `stale (dynamic-state strategy)` → `valid` between the v0.101.3 and v0.102.0 pew builds with the store untouched — the ladder's strategy handling stated once (audit or validity, per 229's ruling) and the flip explained under both builds; the wrong verdict is a defect fixed here, the false-valid direction voiding stat verdicts.
      Audit 288 (2026-09-29): the strategy-flip rider REFRAMED — no
      verdict was wrong: the rung (admission.go:61) and its operands
      are byte-identical at both builds, gofresh.DynamicStateStrategy
      is @38 at v0.101.3 and v0.102.0 alike, and the format rung
      (RecordingFormat 2→3 at 230) sits strictly above it, so a
      rebuild can only move recordings DOWN into stale (format); a
      `valid` arm on 09-21 carries pew-format: 3, which only a
      post-230 pew writes — the store moved (the whole-store
      re-record) or the sweep misreported; checkable by grep over
      tugboat's store. The work: the recorded-vs-current operands on
      the stale line and an explain row for EVERY validity key
      (explainRecordAgainstCurrent lays out the closure strategy and
      never the dynamic-state one — a stale (dynamic-state strategy)
      verdict is unexplainable by pew's own --explain), the rung
      stated once; admission reads the registry's validity? column
      (232 adds it). Heads pew's tail after the bump.
      Dissolved (2026-10-06, audit 319): the verdict path, the row decode, the vouch threading and the explain row per validity key → performance-evidence chunk 4; `ab --out` per package and the artifact's keys → chunk 7 (the handoff doc).
- [ ] 176. stipulator: whole-requirement test claims on clause-structured
      requirements are refused by default (stipulator docs/issues/
      clause-structured-whole-claims.md; user ruling 2026-09-07) — a
      `tests`/`proves` claim naming no clause on a requirement that
      declares clauses refuses at write time and reads as a hygiene
      violation for existing records, `implements` claims stay whole, a
      corpus manifest opt-out keeps a corpus that accepts whole claims
      honest about it; doc deletes at close.
      (263: merges with supersede-carry-drops-clause-scope and
      dangling-empty-label-remedy-names-no-clause — one clause-scope
      semantics decision; measurable only after 270 (zero clause-structured
      requirements today).)
      Audit 287 (2026-09-29): the note 'measurable only after 270
      (zero clause-structured requirements today)' is FALSE —
      REQ-evidence-ladder (evidence.md:148) carries a five-item
      payload list, i.e. five clauses, and coverage.textproto:145
      holds a whole-requirement tests claim on it
      (internal/coverage.TestPolicyDefaults) — the exact false-green
      channel 176 closes; it follows 270 for scale only.
      Rider (2026-10-06, audit 318): bindings-per-requirement-file-derivation lands here (its Lands said so; the entry did not) — cerebro's hand-move on every supersede.
- [x] 177. pew: `--json` on run, ab, and gc (pew docs/issues/
      mcp-surface.md; user ruling 2026-09-07) — the progress channel half
      landed with REQ-pew-progress (every verb's 30 s cadence line); the
      MCP surface itself waits for a driving agent to appear; doc
      retargets at close.
      Audit 288 (2026-09-29): stands — --json on status and stat only;
      §12's 'where one exists' reads as intent; the MCP half's trigger
      is checkable.
      Dissolved (2026-10-06, audit 319): `--json` and parity → performance-evidence 8.1/5.2; the MCP half keeps mcp-surface's checkable trigger.

- [x] 178. stipulator: policy-declared scratch namespaces (the consumer
      half of the in-module scratch discharge, chunk 100's verdict) — a
      capture group's policy carries `scratch_namespaces` DIR:PATTERN rows
      with REQ-inputs-scratch-namespace's grammar, passed to the engine
      exactly as gomutant's --scratch-namespaces are; the excluded-path
      interim retires where a namespace covers it; tugboat's .realseam-tmp
      is the first declaration (its session's work).
      (236: RIDES 250 — it adds a capture-group key segment, a
      whole-store re-execution; batched with the bump's own restale.)

- [ ] 184. stipulator: one terse clause per face (stipulator docs/issues/
      knob-terse-clause-per-face.md) — a knob's document line carries a
      clause per surface where the faces' spellings differ, the render
      picks its face's, the cross-face prose leaves the parenthesis; the
      two-surfaces ruling applied to knob prose; doc deletes at close.
      (263: re-aimed — the document half is gofresh's guidance format, 266
      owns it; stipulator keeps the render's face pick. After 266.)
      Audit 287 (2026-09-29): stands — nothing in the render diverged;
      the document half is gofresh 300's.
- [ ] 185. stipulator: the ledger store as a record kind (stipulator
      docs/issues/ledger-store-as-a-record-kind.md) — recordstore.Name gains
      the one-segment form, the compartment ledger sub-store becomes a
      nested store (its temporary, scan, atomic write, and sweep the
      core's; the concurrent-install sparing rule stays its own); the
      two hand-rolled copies of recordstore.Digest (derive.go's group
      digest, telemetry.go's home digest beside its own Root call) read
      the core's; doc deletes at close.
      (236: verified — six duplicated primitives, the two Digest copies
      (227 takes those), the naming blocker exact; adds C15: the
      mirrored entry/Record field lists in both stores, where a field
      added to Record and forgotten in entry stops persisting silently.)
      (263: grows — the composition above recordstore is rewritten per kind
      (open→Names→Read→decode→append; open→Sweep) in resolutioncache and
      witnesscache, each record spelled three times — 236's C15, exact.)
      Audit 287 (2026-09-29): grows — the compartment-ledger sub-store
      hand-rolls recordstore (witnesscache.go:358/:393/:425/:457); the
      record decode ladder differs per kind and the fail-closed rule
      is the one that differs (witnesscache.go:337 refuses trailing
      bytes; resolutioncache.go:120 omits it and derives the
      content-name check from the decoded record, so appended bytes
      survive into a served resolution); two hand validFingerprint
      ladders over one gofresh type; recordstore.fingerprintDigest
      takes any; undecodable-manifest-records-dropped-silently
      re-slotted here (a decode-ladder behaviour, not 249's
      decomposition).
      Rider (2026-10-06, audit 318): 79f2638 touched resolutioncache (SourceTiers/Admits) — re-verify the trailing-bytes premise at open.
- [x] 186. gomutant: the execution window's cost models in one home
      (gomutant docs/issues/window-cost-models-one-home.md) — a windowcost
      home stating the three questions (membership, order, execution),
      their permitted inputs, and the constants beside the invariants that
      tie them; the partition stays a function of tree + order + worker
      count; doc deletes at close.
- [ ] 187. gomutant: mutant runs outside the caller's tree (gomutant
      docs/issues/ephemeral-probe-writes-under-the-callers-tree.md) — the
      tree-write mechanism is one on both paths (go test runs each binary
      in the real package directory: run.go's probe and campaign
      executors alike), so REQ-mut-overlay's "a mutant run must not write
      into the tree" is breached by every relatively writing test; the
      probe takes the scratch channel shaped candidates already run
      through, its cost stated per probe; the campaign path opens with
      the fork settled explicitly rather than implemented narrowly — two
      whole-tree copies per candidate is not a campaign cost, so either
      a cheaper containment (a run directory the binary is spawned in)
      lands or the spec's promise is qualified to name the campaign
      residual, the latter the user's call (an issue doc at the open);
      the promise is never narrowed silently; doc deletes at close.
      Derived (2026-10-06, audit 317): the user's-call text struck — REQ-mut-overlay's MUST (no write into the tree) stands breached by every relatively writing probed test, and the spec wins by default: containment (a run directory or a scratch copy) with the cost stated; moved up directly after 302 as correctness.
- [ ] 188. gomutant: explicit fixture package selection loads a testdata
      package (gomutant docs/issues/explicit-testdata-package-selection.md)
      — an explicit oracle selector or campaign target under testdata is
      loaded on demand through loading, test selection, mutation
      application, and attribution, tree-escape and build-selection
      refusals preserved; both spellings pinned; the persisted
      campaign/freshness boundary stated; doc deletes at close.
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
- [ ] 191. gofresh: GODEBUG joins the code-result guard (gofresh
      docs/issues/net-url-parse-godebug-channel.md) — the process-level
      channel captured for every result kind, the in-process Setenv
      channel poisoned as shared dynamic state (a subject mutating GODEBUG
      marks every GODEBUG-reading admission in the binary), net/url's
      parsing half then admitted by symbol; doc deletes at close.
      (234: carries a spec amendment — GODEBUG leaves the measurement
      guard for the code guard, REQ-guard-runtimeconfig and
      REQ-fresh-guard-set amended — and a release: every consumer store
      re-measures once.)
- [ ] 192. gofresh: dependency closures reached by reference (gofresh
      docs/issues/dependency-nested-closures-outside-the-drain.md) — the
      dependency facts carry a per-function effect summary the drain
      consults for a referenced dependency function, so a dependency's
      nested closure reached only by reference has its effects seen
      without walking standard bodies; doc deletes at close.
- [ ] 193. gofresh: immutability after construction as a proven property
      (gofresh docs/issues/immutable-after-construction-objects.md) — the
      per-package fixpoint over types (all fields unexported, every
      method read-only, no outside assignment or address-taking, no
      conversion, results hand out no mutable reach), a value handed
      into such a construction not leaked, immutable type keys a new
      persisted fact; the consumers' rapid vouch trimmed at their bumps;
      gomutant docs/issues/vmm-finding-admission-refusals.md rides it;
      doc deletes at close.
      Rider (derived 2026-09-29): the channelz registry as a named
      audited entry under the single-subject attestation — the
      attestation-gated subject-own-registry discipline the spec
      already carries, one table row plus the audit of grpc's channelz
      db (gofresh
      docs/issues/grpc-runtime-memo-and-registry-discharges.md's
      second half; the consumer's enumeration-backed
      waiver retires when both halves land).
      Audit 285 (2026-09-29): grows — the decomposition's FOURTH
      bundle: the surviving base REQ-closure-observability-analysis
      (closure.md:1257–1297) still contains a distinct
      benchmark-pacing clause with no sub-ID, cited as prose at eight
      sites (closure-sub-contract-granularity-residue.md names three
      bundles; the fourth joins it).

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
- [ ] 203. gofresh: one memo scope, one versioning rule (gofresh
      docs/issues/memo-scope-axes.md, per-file-memos-one-shape.md) — eight
      persistent memo classes render their scope four ways and only the
      listing memo carries a record version; AnalysisScope the one
      source, every memo versioned by the one rule; docs delete at close.
      (234: grown — nine memo classes, two record versions
      (listingmemo, scanEntryVersion), three per-file memo shapes; the
      canonical-digest memo serves silently while its eight siblings
      report — its Served summary is the regression anchor.)
      (261: grows — REQ-closure-scan-memo and REQ-closure-listing-memo are
      unbound and ungapped, the only such ids beside REQ-fresh-caller-pins;
      their witnesses land here.)
      Audit 285 (2026-09-29): grows — (a) the set↔scope coupling:
      ObservationRTA moved @30→@40 and effectScanStrategy @19→@21
      across 116–123 and 180–182 with nothing coupling an audited-set
      edit to the memo scope; a NARROWING of a fold-consulted table
      without an effect-scan bump serves a warm memo's admissions the
      narrower set no longer grants — a wrong pass
      (docs/issues/audited-set-versions-decoupled.md folds here); (b)
      the per-file memos' three parallel triples
      (closure/filememo.go:88–98; per-file-memos-one-shape); (c) the
      memo classes' Served names as literals with no set, and the
      progress phase names spelled at eight emitters beside unitPhases
      — one exported phase set (unit + fact/diagnostic; gomutant's 286
      A6 reads it); (d) the digest field-join rule's two spellings
      (length-prefixed %d:%s vs \x00 joins) — one injectivity rule;
      (e) the memo-scope pins read their own constants as the oracle
      (viewscope_test.go:20–33, closure/scope_test.go:12–41 — a
      swapped strategy constant moves got and want together): the
      rule's enforcement gets a literal anchor here. NARROWS:
      REQ-closure-listing-memo is bound
      (bindings/closure.textproto:1565); only REQ-closure-scan-memo
      remains unbound/ungapped. Repair memo-scope-axes.md's Lands line
      at open (a dangling half-sentence).
      Grown (2026-10-06, audit 316): two persistent memos of one go list question — closure/listingmemo.go (content digests, listingRecordVersion + shape, serves off unix) and toolchainsource.go's listing memo (stat stamps, sourceDigestsVersion, never off unix) — one served-listing rule with one record-versioning rule, or the reason GOROOT warrants stamps stated (the digests never memoized; a stale record never decides selection); the scanmemo pins reading scanEntryVersion; REQ-closure-scan-memo is bound (that item done).
- [ ] 204. gofresh: auditset's receiver side as one table — the five
      parallel method tables and their predicates one package-keyed
      map behind the one ladder, as symbolTables already is; BoundedToken
      rehomed out of the audited-set package.
      Audit 285 (2026-09-29): narrowed — the one ladder landed at 181
      (auditset.ReceiverMethod); five tables (syncMethods,
      memoMethods, poolMethods, reflectMethods, timeMethods) and five
      predicates remain, BoundedToken in auditset with two callers.
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
- [ ] 206. gofresh: the test surface — one file-map fixture writer for
      the seven copies, the per-test cache-home settings collapsed onto
      the package TestMains, the shared helpers out of view_test.go, the
      ambiguity arm pinned once, the reference effect scan's budget
      stated; the four package-global hook surfaces and the process-
      global memo root under one seam (fixture-tier-parallelism's
      precondition); the TestTier2 names renamed for the tiers the spec
      names.
      (234: grown — eight fixture writers; SetMemoRoot's three
      forwarding homes fold in; the 65 production tier2* identifiers
      renamed for the tiers the spec names, beside the test names.)
      Audit 285 (2026-09-29): grows — the fixture surface is twelve
      sites (eight map→tree writers + four inline copies), 70
      XDG_CACHE_HOME settings over two identical TestMains, tier2 at
      73 production occurrences; apisurface_test.go:25's hand-listed
      roots omit guidance/, shapecorpus/, shortgates/;
      fixture-tier-parallelism retargeted here (its trigger reads as
      met at the recorded closes — closure 798–812s beside root
      390–398s — state the per-package reading or fire it). LOSES
      sampler-failed-sample-memo-unpinned (resolved at 281.C; `git log
      --all -- docs/issues/sampler-failed-sample-memo-unpinned.md`, gofresh)
      to 281.
      Grown (2026-10-06, audit 316): the toolchain-key gap fires — the row-chain admission is a for-all a generated-rows property witnesses (sixteen content-key pins exist); cgoEnabled(t) duplicated across the root and closure test packages; gotool/contain_test.go's TestContain* names refer to the deleted Contain/Apply; apisurface_test.go's hand-listed roots omit resident/ (reads GOMEMLIMIT by design — state the exemption); the canary's row table is the hand mirror 315 retires.

## Band H — gomutant under the emergent shape (chartered by audit 195)
      (261: measured — tier2* now 69 production occurrences; four global hook
      surfaces; 23 files use t.Setenv; SetMemoRoot's two-hop chain confirmed.)

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
- [ ] 209. gomutant: the spec chunk — execution.md's "a launched
      candidate contributes its observation even when compilation
      rejection discards it" contradicts results.md and the code
      (amended to results.md's rule); the load-time toolchain floor
      stated beside the skew refusal; the tree-root vouches file and
      the sideline name grammar stated as contract; REQ-exec-run-status's
      decision grammar admits `candidates` on a served decision (results
      already requires the count); REQ-exec-oracle-run's six contracts
      and REQ-result-stale's three carve-outs split into sibling ids so
      an edit re-consents its own rule; re-consented through the tool.
      (235: grown — A1 the INV-RESULT-CANDIDATE-CONSERVATION pointer names
      a deleted test (the two INV ids are the only spec ids with no
      stipulator binding: bind their witnesses, so a rename can never
      dangle again); A6 the cancellation boundary stated (which reads
      poll ctx); A7 the sidelined legacy-entry name `<stem>.legacy-v<n>.json`
      and the tree-root `vouches` file's module-root reach stated as
      encodings; the versions 4–9 inline arms judged against the fleet's
      oldest live document (version 10) — grandfathering for documents
      none can find is a pre-v1 clean-break verdict.)
      (262: grows — INV-MUT-COMPREHENSIVE and INV-RESULT-CANDIDATE-CONSERVATION
      bound, the catalogue inventory derived through spectable instead of a
      74-entry hand map; REQ-result-version-surface's server side (the
      Implementation literal names no binary identity or document range);
      the envelope numbers stated once (REQ-mcp-explain's four unpinned);
      the served decision's candidates count; the sideline name grammar.
      The seven-clause decomposition leaves for 268.)
      Audit 286 (2026-09-29): grows — the INV binding half (neither
      project invariant has a binding; grep INV- over .stipulator
      returns nothing); OldestReadableDocumentVersion = 4 with one arm
      for 4–10 and no fixture at 5–10; the v13 success path exercised
      by nothing (the only v13 test asserts a refusal); gomutant's own
      tracked document is version 11 with zero findings (the measured
      datum); type document (findings.go:763) has one test caller and
      a comment contradicting findings.go:769.
      Grown (2026-10-06, audit 317): the served guidance's history prose ('seconds-class where it was minutes-class') restated as contract; word numerals in REQ-mcp-surfaces' CLI column keyed to digits and the table refusing word numerals (rewrittenExemptionRoster, idleTreeRelease keyed); the fired gap mcp-resident-set pruned at 317's chore.
- [ ] 212. gomutant: one splice — driftFindingCounts, extendFindingCounts,
      and spliceFindingCounts share their opening, their scores walk, and
      their tally tail (47 lines identical between two) and differ only
      in which candidate subset re-measured; one splice over a
      re-measured index set with a carry policy, the four splice*Finding
      wrappers following; invariants: candidate conservation, carried
      survivors keeping their buckets, kill attribution completeness;
      after 209's sibling split names the carve-outs.
      Audit 286 (2026-09-29): grows — the three FindingCounts writers
      differ in six ways, the one to settle as the invariant:
      kill-attribution policy (extend/splice degrade via
      killsComplete; drift ABORTS the run at run.go:5641 — two
      policies over an input class REQ-result-export says is
      tolerated); the negative-count reconcile absent in extend; the
      byOperator value type; missing-operator handling
      (error/error/append); unstableForBuckets hoisted vs in-loop;
      attestation shedding (returned/dropped/carried).
- [x] 210. gomutant: the vouch file at the tree root and gofresh's
      grammar (gofresh docs/issues/vouch-file-consumer-homes.md's gomutant
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
      docs/issues/engine-run-scoped-oracle-value.md, probe-seam-tuple.md)
      — five variant emitters of one token shape and ~35 family-rank
      literals across seven files become one table the emitters and the
      inventory test read; eight spawn entries into runMutantBase and
      three into the probe become one request struct; docs delete at
      close.
      (235: C6's dead engine entries fold in — LoadContext,
      DeclaredSymbols, TestsOf, PackageOf, PackagePath with zero
      references; Load, PackageContext, ValidateOracle, SplitRapidPkgs,
      RunMutant/RunMutantEnv/RunMutantObserved, TestProbe test-only.)
      (262: grows — the eight `go test -json` decoders' non-correctness
      residue after 269 lands the one stream walk; the observation-merge
      degradation rule twice (root and engine); the per-file init ordinal
      rule three times; the dead forwarders and test-only exports in
      internal/engine incl. the whole Mutants/MutantsContext pair.)
      Audit 286 (2026-09-29): grows — mergeFindingObservationsContext
      (run.go:5083) and mergeRuntimeEvidenceContext
      (internal/engine/run.go:930) are one function in two packages;
      only the root one attributes the divergence, so a merge failure
      reached through the engine loses 'diverging inputs'; four engine
      exports with no caller (engine.LoadContext,
      Tree.DeclaredSymbols, Tree.TestsOf, Tree.PackagePath).
      Grown (2026-10-06, audit 317): the oracle memory derivation reads resident.HostMemory's total with the fleet's one floor and REQ-exec-oracle-memory states the composition of the two halvings (the parent's Available/2, the oracles' Total/(2·jobs)) — MemTotal kept: the recorded ceiling serves directionally; one GOFLAGS -tags parse (selection.go, enumerationcheck.go).
- [ ] 216. gomutant: one classified evidence check — evidencePrecheck
      with evidencePairsValid (boolean) and inspectContext (classified)
      run the same five checks in different order and strictness; the
      boolean derives from the classified one.
      (235: refined — evidencePrecheck rides the run's runtimeMemo while
      inspectContext calls runtimeinput.CurrentEnvContext directly: the
      inspection path pays outside the memo; the empty-manifest order
      divergence is unreachable, both fields being required.)
      (262: grows — the evidence serve-check ladder twice
      (evidenceSetMatchesContextWithCurrent / shapedEvidenceMatchesContext,
      the operator-set/timeout/memory/regime list two copies).)
      Audit 286 (2026-09-29): grows —
      evidenceSetMatchesContextWithCurrent and
      shapedEvidenceMatchesContext (freshness.go:2023/2056) 80%
      identical, the shaped one minting newCurrentRuntimeMemo() so no
      test's current stub drives it (a seam-injectability gap);
      evidencePrecheck (:758) and inspectContext (:849) walk one
      ladder with precheck alone comparing state.Reason and refusing
      an empty manifest.
- [ ] 217. gomutant: record-parse discipline — LoadExemptions and
      LoadEphemeralAttestations read with plain Unmarshal where the
      findings document refuses duplicate keys, trailing data, and nulls
      under the same "a malformed record refuses" clauses; one decoder;
      inlineFindingFields gains the inventory test its sibling has and
      the five tags it omits.
      (235: narrowed — exemptions.go and ephemeralattest.go fold onto
      decodeKnownObject; the baseline bank stays lenient by contract.)
- [ ] 218. gomutant: the store's report path (gomutant docs/issues/
      store-report-path-walk.md) — Store.Layer walks the full manifest
      per record at six sites and keeps the first reason; the two memos
      of one entry (cache, judged) one entry-state record the report path
      consults; doc deletes at close.
      (235: anchored — Store.Layer/LayerReasons recompute
      CommittableReasons past the write path's judged memo; two
      per-symbol memos beside it.)
- [ ] 219. gomutant: the test surface — one fixture home (the 37 CopyFS
      sites, three fixtureDir declarations, twelve git-fixture builders,
      53 inline example modules), the byte-identical face cache-isolation
      tests and the eight per-face scenario rewrites one face-scenario
      table that pins the faces decide alike (the net that would have
      caught 207's four divergences), with the stated limit that the
      root package's in-package tests keep their unexported reach.
      (235: grown — 38 CopyFS sites, 145 inline module declarations,
      34 git inits, ~12 fixture builders, three test-only packages, one
      seam name on both faces; runs AFTER 244 so the face-scenario table
      pins the collapsed shape — it is the net that would have caught
      244's fact divergences.)
      (262: grows — 328 of 879 tests unbound; 165 inline go.mod bodies, 21
      hand-rolled runGit closures beside internal/gitfixture, 48 seam
      save/restore pairs, cacheisolation_test.go ×3, the two faces' identical
      stretch helpers; the vacuous memory-floor pin, the unpinned
      envelope.streamed, the seam-default and grammar tables with no
      completeness guard; the face-seam parity; REQ-mcp-explain's numbers
      join the envelope pin. After 267.)
      Audit 286 (2026-09-29): the writer-side fixture isolation SPLITS
      OUT as 301 (directly after 283); the remainder grows with
      envelope.streamed = 100 and the four Analysis* prose strings,
      wire-visible with no anchor.
      Grown (2026-10-06, audit 317): the two covered adoption-sweep gaps (REQ-result-export, REQ-target-model) witnessed; mcp-liveness-cancellation-witness (the transport-seam injection); split 219a fixture home + face-scenario table / 219b witness and binding gaps.
- [ ] 220. gomutant: the named smalls — the ephemeral option tuple onto
      EphemeralRequest; longestBaselineFor reading the bank key through
      its composer; PackageSkip.Dark carrying the whole skip-radius
      predicate; documentlock_other's missing ensureLockIgnore;
      Coverage.Merge's receiver mutation behind a value signature; the
      three edit value types stay (two are wire-pinned).
      (235: grown — Store.Load reads past ctx (contextio the one
      cancellation-aware reader, its package doc stating the boundary;
      21 raw ReadFile/WriteFile sites); C6's dead root and gitref entries
      (UpdateDocument, Tree.Fresh/FreshFor, Tree.DynamicStateVouches,
      Load/LoadContext, Export; gitref ChangedSurface/ChangedPaths/Show);
      C7 the `Context` suffix dropped once no non-Context sibling
      survives (stipulator retarget for the bindings); C10 the
      estimate's absent-never-zero rule spelled three times.)
      (262: narrows — the two row-projection issues leave for 267; the
      absent-never-zero item dissolved (EstimateProjected is a string, one
      reader); keeps the root's dead exports, the face preamble ×6 and the
      loading event ×7, the tool-owned path vocabulary ×7, DarkPackages
      computed twice.)
      Audit 286 (2026-09-29): grows — rootCoordinate
      (gomutant.go:416–423) is gotool.Coordinate line for line
      (root-coordinate-one-spelling gets its owner; two more
      open-coded degrading ladders at ephemeral.go:375 and
      ephemeralattest.go:182; pew's CommandDir is the same copy — a
      252 note); closureRow (bank.go:283–292) a second wire form of
      five fingerprint-record keys in gofresh's spellings; ten
      test-only exports, the go.sum stipulate/structural v0.2.0
      residue, the 'machine-local runtime input' prefix composed at
      store.go:271 and matched at :1084.
      Grown (2026-10-06, audit 317): the CLI's five roster bounds one policy the faces read and the surfaces pin keys (merged with list-bounders-one-helper: one bounder, one remainder grammar; every rendered list names its omitted count); the install-and-report helper one root helper; the Taskfile installs to both homes; sheds the two row-projection docs to 267.
- [ ] 233. gomutant: MCP campaign observability (from
      mcp-run-observability, 2026-09-09) — a long campaign's caller must
      distinguish progress, a slow phase, completion, and cancellation
      without a progress token or retained notifications: a run-state
      record beside the findings document (the run's identity, the
      current stretch, the target in flight, elapsed, committed count)
      the caller can read while the run lives and after it ends, and a
      preflight form of run on the MCP face (the CLI's --plan); the
      surface question the visibility ruling decides — never a silent
      wait.
      Re-aimed (2026-10-06, audit 317): the run-state record lives in the tree's machine-local state home as the exit log does since 312 (`$XDG_STATE_HOME/gomutant/repos/<tree key>/`), never beside the findings document; its path named on the run's boundary lines; mcp-render-bound-discards-the-response rides unchanged.

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
      (the contradicted gap on REQ-go-owned-processes, declared at 222)
      — the analysis engines the served backend hosts spawn the package
      loader's go list in the parent's process group, so a cancelled
      load ends its go list and not the loader's descendants: the
      mechanism decision (the engines in the resolver child, or a
      group-isolated loader spawn gofresh offers) and the gap's close.
      (236: after 226's clause split — its gap over-excuses four met
      mechanisms until REQ-go-owned-processes is split.)
      (263: behind 272 — gofresh 265 supplies the group-isolated loader
      spawn.)
      Audit 287 (2026-09-29): behind 270, not 226 — the clause split
      moved to 270 at the third band; this note replaces 236's.
      Corrected (2026-10-06, audit 318): its gap waits on gofresh 241 (x/tools has no spawn hook — loader-spawns-outside-the-runner), not on gofresh 265 or stipulator 270; neither contradicted gap has fired.
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
- [ ] 240. gofresh: the spec corrections 234 found (A2 the memo key
      names "the commit" no memo keys on — REQ-guard-cache and
      REQ-guard-recompute; A4 ErrViewSealed the fourth typed refusal on
      the capture seam, pinned by identity beside its siblings; the
      go-command policy the substrate paragraph names since 239 stated
      as a requirement with the gotool pins as its enforcement
      pointers — today no REQ id, so no binding tracks it). Spec only;
      re-consented.
      (261: grows — REQ-fresh-caller-pins, a caller-side MAY, gets its
      declared gap; the base ids' redundant gap records and the one
      base-bound test (TestSharedDynamicStateEscapesAndRebindsDowngradeWithCulprit)
      slot onto their sub-ids; 200's cite rule applied in closure/*.go and
      purity.md:126 — the purity.go/dynamicstate.go half rides 202.)
      Audit 285 (2026-09-29): grows — (a)
      REQ-fresh-go-command-policy's reader enumeration is closed at
      three where gofresh spawns five (the listing at
      closure/closure.go:1240, guard.Capture's go version at
      guard/guard.go:169) and the fleet answers the fourth three ways;
      the spec half here, the listing reader's salvage decision at
      281; (b) the cite rule's scope is every file but
      purity.go/dynamicstate.go — four bare-base cites in the root
      (gofresh.go:480, :593, :855, :883) and the closure/ list in the
      record; (c) three 200 sub-IDs (-guard-pinned, -unsafe,
      -writer-sink) bind one witness
      (closure.TestReadOnlyObservabilityProof) — addressable ids need
      their own; 26 clauses fleet-wide are single-witness; (d)
      REQ-fresh-fingerprint-data's 'never a second encoding' vs pew's
      row projection (275's accepted deviation): state the projection
      obligation — a projecting consumer validates through the
      published ladder (pew's Validate call rides 291) — and complete
      the constituents
      (singleSubjectDischarges/packageProcessDischarges are unnamed);
      (e) REQ-fresh-progress states the fact/diagnostic phase set; (f)
      one pass over the 43 gap records: 40 carry one boilerplate
      condition — each clause's own witness shape stated.
      Grown (2026-10-06, audit 316): the overview's substrate paragraph and Documents list name the resident package; REQ-fresh-resident-readings gains its Enforced-by pointers (eight bindings exist); REQ-closure-observability-toolchain-key's opening set↔scope sentence split into its own sub-id (203 enforces it); the pre-310 vocabulary's doc half (toolchainkey_test.go, effectmemo.go, VersionListing's and dynamicstate.go's 'toolchain release' docs); REQ-fresh-caller-pins the one unbound, ungapped id; the thirty-seven boilerplate gap conditions (f). Loses UnsetEnv to 327 and (a) as done at 281 (2dbbc6f deleted the guard's go version spawn, 53b9e1d named List) — spec and records only.
- [ ] 241. gofresh: one typed-load seam (234 C2/A6/A7) — four
      packages.Load sites with four hand-built configs (viewload.go the
      designated seam; explain.go, maximal.go, internal/program) merge
      into loadView's config builder parameterized by mode, so explain
      re-derives under the load REQ-fresh-coherent-view describes and
      the GOPACKAGESDRIVER refusal holds at every site; the explain
      hookset's tree-blind match key (pkgPath.varName across two
      checkouts of one module in one process) keyed by the view's tree
      or its guarantee restated to what the guard holds.
      (261: grows — explain's load gains NeedForTest (REQ-explain-passive's
      test variants) and internal/program's config builds from the policy's
      environment, not a raw one.)
      Audit 285 (2026-09-29): stands —
      loader-spawns-outside-the-runner is the one undischarged half of
      REQ-fresh-go-command-policy's exception (cfg.Env != nil pinned
      nowhere); explain.go:122 skips buildflags.Validate where
      closure/viewload.go:75 treats it as part of the pass.
      Grown (2026-10-06, audit 316): explain-no-chain-for-a-dependency-culprit named here (its Lands said so); loses one-memo-shape to 327.
- [ ] 242. gofresh: closure/ an internal package (234 C7) — a public
      package with zero external importers publishing Hasher and forty
      methods, AnalysisScope, the memo loaders, the attribution entries
      as API with no installed base; closure/ → internal/closure with
      the public vocabulary (closure/testvariant) kept reachable through
      the root aliases (verify at open that every consumer touch goes
      through them). BREAKING API; pre-v1 clean break.
      Audit 285 (2026-09-29): its 'zero external importers' premise is
      FALSE — stipulator/internal/backends/golang/normalize.go:610
      reads closure.ToolchainSelectionNotice (legitimately, from its
      own capture): the internalization keeps that entry reachable
      through a root alias. 242 and 243 LAND TOGETHER (one symbol set
      after 202; two passes double the binding retargets).
      Grown (2026-10-06, audit 316): the pre-310 vocabulary renamed once on the public surface — Hasher's selectionResolved/selection ('two-axis'), selectionDegradation, the 'toolchain-selection audit:' notice and its source-path suffix (view.go appends ' (closure/toolchainaudit.go)' to every notice), SelectionAudited/SelectionNotice/SelectionAttribution/AttributeSelection — the spec's one concept is the toolchain-source audit.
- [ ] 243. gofresh: the vestigial sweep 234 found (C10) — guard's
      invalidKind (zero references in four repos); ScanPureDirectives
      exported with no production caller in any repo (the exported face
      of REQ-purity-directive: adopt or delete, the clause following);
      Engine.analysisBudget's one unreachable read (the filed
      analysis-budget issue rides). One commit through the loop.
      (261: grows — the surface set spelled twice in guidance (surfaces +
      knownSurface); the dead public surface beyond the three: runtimeinput
      Dirty/CommitInspector, shortgates' Walk/Check/WalkReport/Report/Failer
      (four consumers call Pin alone — the sweep decides), WithStaticInputRoot,
      ErrViewSealed/ErrAnalysisUnavailable undiscriminated, shapecorpus
      Entry.BenchFiles. After 202: the tier's move under closure/ redraws the
      boundary 242 and 243 sweep.)
      Rider (derived 2026-09-29): REQ-inputs-dirty's CommitInspector and
      the testlog ingest's static-input-root acceptance RETIRE with their
      clauses (gofresh docs/issues/runtime-inputs-dirty-unadopted.md,
      static-input-root-unadopted.md) — pre-v1, no installed base, no
      consumer selects either, gomutant's baseline provenance reads git
      itself and works: dead public surface, not a fork.
      Audit 285 (2026-09-29): grows — the manifest decoder has no
      duplicate-key and no null rule (runtimeinput.go:2583–2602; a
      duplicated or null key is caught incidentally as 'non-canonical
      manifest encoding' where the record names the key) —
      json-record-readers-one-home sharpened; the dead set grew by
      four (gotool.EnvReader.Taken, gotool.ParseEnvDocument —
      unexport, guidance.KnobUsage/Registration.Knobs,
      Document.DescribeSchema reached only through MustDescribeSchema,
      runtimeinput.ModuleRelPaths whose only reader is the dead
      Dirty), zero-reader forwarders
      gotool.Run/SampleGoVersion/TakeEnvSnapshot,
      Containment.Quit/Grace with no gofresh reader,
      guidance.go:63/:65 spelling one two-element set twice,
      Fingerprint.Validate a one-line forwarder three internal sites
      bypass; shapecorpus.Entry.BenchFiles comes OFF the list
      (pew/cmd/pew/canary_test.go:26 reads it);
      runtime-input-entries-implicit-context and the two retire riders
      stand. Lands together with 242; 295 no longer waits on it.
      Narrowed (2026-10-06, audit 316): the gotool dead set (package-level Run/SampleGoVersion/TakeEnvSnapshot forwarders, EnvReader.Taken, ParseEnvDocument, Containment.Quit/Grace with no reader) moves to 327.
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
- [ ] 245. gomutant: runCounted's decomposition (235 C1; design —
      derived 2026-09-29: a decomposition along the named seams under
      the three invariants is engineering with no external tradeoff;
      slotted directly before 212 so the chunks that reason about the
      whole function do so once) — 2,723 lines and thirty nested closures with two named
      phases and a 200-line epilogue; a campaign value carrying the run's
      constants with the closures as methods along the natural seams
      (options/bounds/repository, resolution, views/modes, per-target
      preparation, the driver, the epilogue); invariants: the
      deterministic preparation-and-decision order, the window
      partition's input set, the commit horizon. 212, 213, and 233 each
      reason about the whole function until it lands.
      (262: grows — 215 merges in: Tree.Run is a 14-line wrapper and the
      2,713-line function 215 named IS runCounted; 215's distinct half — 77
      methods on a five-field Tree across seven roles — and the file homes
      (run.go 6,591 lines across seven concepts; four concepts spread over
      four to eight files each, incl. the input-validation refusals against
      REQ-exec-preparation's one stage) come with it; run-seams-snapshotted-
      per-run lands here.)
      Audit 286 (2026-09-29): grows — 213's charter item did not land:
      seven unexported observer seams stay on the exported Options
      (afterExecution, aggregate, producer, proofAttempt, dispatched,
      executedScope, confirmScoped) and seams.go:13–15 states the
      false universal; the run value is their home. runCounted is now
      2,795 lines with 47 closures.
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
- [ ] 248. stipulator: the spec corrections 236 found + one message —
      A6 the seven cap values across four packages are contract the
      spec never states (the same reason map cut at 5 on the wire and 8
      on the terminal with different remainder semantics): one cap
      policy stated and pinned as the sibling tool's envelope is; A7
      the root-discovery message spelled four times (only the MCP's
      names the upward search) → one; A8 evidence.md's version bump
      chain is process record → the version is 8, prior versions fail
      closed; A9 the resolution-cache format names no version value.
      (263: grows — the reason-tally cap policy merged from 225 (two
      reductions with caps 5 and 8 and different remainders: one rule, a
      per-reader bound) and the "not a stipulator repository" message ×4
      re-deriving manifest absence; 225 and 248 land together.)
      Audit 287 (2026-09-29): grows — evidence.md:549–565 narrates the
      version chain (process record in the spec); the cap census is
      ten across six packages (execute.go:40, envreport.go:48/:55,
      facts.go:332, mcpserver/compile.go:47, gap.go:148,
      response.go:69, views/check.go:16/:221/:226) with
      REQ-mcp-response-contract stating forms and no values; the four
      'stipulator repository' spellings (corpus/root.go:25,
      cmd/root.go:170/:207, mcpserver/server.go:133).
      Grown (2026-10-06, audit 318): the publish account typed in the backend and prose on both faces (served.go flattens it to strings; the MCP face re-parses by prefix; the CLI renders every per-symbol typed line unbounded — about a thousand after a strategy bump) → one typed account message each face projects under the one cap policy, 'advisory, never a verdict input' preserved.
- [ ] 249. stipulator: the monoliths (236 C1/C12) — runWitnesses
      (570 lines, ~40 locals, five closures, seven nested loop stages)
      split by the stages its comments name, preserving
      REQ-policy-cancellation's unit of persistence and
      REQ-evidence-freshness-degrade; coverage.Evaluate (349 lines) and
      compile.resolve (331 lines) decomposed likewise. After 226 has
      thinned the package.
      (263: grows — check.Run repeats verifyrun's capture → symbols →
      served-backend ladder and hand-builds the backend map (the one site
      247.C's BackendSet did not reach) — check-pass-shares-the-verification-
      ladder lands here (a derivable design, un-parked); five compile-refusal
      ladders and five id-list validation ladders, corpus membership spelled
      two ways; process-output-utf8-marshal's executor-diagnostics trigger
      fired at 223.B3 — lands here. Premise corrected: runWitnesses lives in
      witnessrun.go, which 226 does not thin.)
      Rider (2026-09-29 replan): the no-outcome count beside the outside count, and a result-level line when an execution reached no expected witness (247's relayed candidate) — derived from the never-silent rule (a counted remainder, never a dropped one); lands with check.Run's ladder.
      Rider (derived 2026-09-29): the selective form isolates unasserted impure siblings to earn their observation proofs (stipulator docs/issues/impure-siblings-never-earn-a-proof.md) — one solo process per impure subject once, against two re-executions on every later run; the isolation pass already spawns solo processes with owned observations for denied tests, so the mechanism exists and the cost is repaid on the first served run.
      Rider (tugboat field report 2026-09-29, stipulator docs/issues/check-summary-tally-names-one-invocation.md): the summary face's witnessed tally per invocation — one line per invocation stating its eligibility and its served/executed/uncacheable split (the never-silent rule: a leg executed and never accounted for reads as absent); lands with check.Run's ladder.
      Audit 287 (2026-09-29): grows — premises re-measured:
      runWitnesses 573 lines, coverage.Evaluate 400 (up from 349 —
      271.B added to it), compile.resolve 332, check.Run 254, a new
      sibling prepareWitnessGroups 153; check.go:169 hand-builds the
      backend map where golang.BackendSet is the one spelling (the
      site 247.C missed) and the policy backend set is spelled three
      times (cmd/policy.go:32 a registry in the CLI package,
      check.go:227, derive.go:475); the per-invocation tally rider
      gets its clause home (check.go:207–222 sets one scalar over
      every invocation; neither REQ-check-witness-selection nor
      REQ-check-verdict states a per-invocation account).
      Grown (2026-10-06, audit 318): opens by inverting the verifyrun→check dependency (check.Run cannot join the shared ladder today: an import cycle; check-pass-shares-the-verification-ladder is otherwise unbuildable); the three folds of a package's runs (assembleInvocation, SelectionResult.absorb, execMerge.addUnit) one — finalizeRun's double run on the hook path and its idempotence guard are redundant state; aborted-pass re-derived at open; measured: runWitnesses 580 lines, check.Run 267, prepareWitnessGroups 185; invocation-folds-two-shapes and aborted-pass named here (their Lands said so; the entry did not).
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
- [ ] 252. pew: the hygiene sweep (231's other half; 237 P4/P7/P8) — one
      containment predicate and one longest-existing-prefix resolver
      (pathWithin ≡ withinRoot, five inline Rel+IsLocal containments,
      resolveExistingPrefix ≡ moduleBenchDir's walk ≡ CommandDir's
      weaker variant); the vestigial
      six (store List/recordingFromPath, gitblob.State, ExecuteBinary
      with no caller, Execute's one seam, checkOne once 174 lands); two
      full store walks in gc; ab's count check twice. After 174 and 251.
      (264: grows — two rules for a package's declared benchmarks
      (selectedBenchmarks constraint-aware, sourceBenchmarks constraint-blind;
      ab enumerates side A with one and side B with the other); ab's
      guard-agreement treats two empty values as agreement where compare
      refuses them as missing — one guard-set judgment both surfaces;
      Destinations' "one derivation" false for Write (refreshRecording a live
      caller); stat's fallback pkgMeta partial (ImportPath/Name/TestGoFiles
      unset); the stretch vocabulary twenty bare literals across five verbs
      (213's collapse); the metric set spelled three times (knownUnits,
      higherIsWorse, unitOrder — one registry on 251's pattern); twelve
      one-caller config writers over the registry; two module resolvers;
      the vestige set verified present: ExecuteBinary, recordingFromPath,
      RepositoryState.Root, isPewRecording dead; gitblob.State, Store.List,
      run.Execute, checkOne test-only; equalExcept's excluded and Demux's
      extra dead generality; RunIn and ReproducibleAtWithin vestigial exports.
      environment-normalized-once stays here but is built over gofresh 265's
      setter (after 275); format-rung-two-readers leaves for 275.)
      Audit 288 (2026-09-29): grows, after 291 — FIRST the conformance
      half: ab's seven git stages are bare exec.Command
      (ab.go:543–701), so REQ-pew-interruption's 'any stage on the
      verb's path' does not hold there (a Ctrl-C during git worktree
      add neither ends the verb nor kills the child) — raised from
      hygiene; then C1 the metric set spelled three (four) times
      (stat.go:101 knownUnits, compare.go:168/:572/:74) → one registry
      on 251's pattern (unit, worse direction, rank, gateable; §10.1's
      sec/op default preserved); C2 one containment predicate, seven
      spellings plus two longest-existing-prefix resolvers; C3 two
      module resolvers (gc.go:212 GOMOD vs stat.go:681 go list -m
      -json — a third subprocess form §11 does not list); C5 the
      writer census corrected (seven named single-key writers + two
      inline, all from run.go's two composers; Destinations' 'one
      derivation' false for its second caller); C6 the vestige list
      corrected (dead: recordingFromPath, ExecuteBinary,
      isPewRecording; test-only: store.List, gitblob.State,
      run.Execute, checkOne with a false doc; dead capability:
      equalExcept's excluded, RunIn's dir; LIVE contrary to 264:
      RepositoryState.Root, run.Demux, ReproducibleAtWithin); C7 the
      audit-note renderers; the CommandDir = gotool.Coordinate copy
      (286 C1); A6 sourceBenchmarks vs selectedBenchmarks one rule.
      Narrowed (2026-10-06, audit 319): the git stages → performance-evidence 7, environment-normalized-once → 2, the metric set and audit notes → 5; the residue — seven containment spellings, two module resolvers, the vestige set (ExecuteBinary, recordingFromPath, run.Execute, gotool.RunIn, gitblob.State, checkOne, equalExcept's unused parameter), the stretch literals, the writer census, the declared-benchmarks rule, stat's partial pkgMeta — stands after that plan closes.
- [x] 253. pew: the gofresh bump after 239's and 205's releases — the
      go-tool consumer arm (pew/internal/gotool's six importers and its
      divergent dir policy onto gofresh's exported policy with 239's
      boundary hook; the GOVERSION sampler onto gotool), the verdict
      reason vocabulary consumed as constants, guidance.Knob.Clause
      consumed (173 follows). The store re-measures once at the bump.
- [ ] 254. gomutant: the gitfs run-surface asks (field reports
      6d98001, triaged at 244's open) — the caller's whole-run purity
      assertion (gofresh WithAssumePure, REQ-purity-directive's
      "global assertion") on both faces, recorded on the evidence as
      vouches are; and the estimate event's narrowing ground: when the
      covering/exempt decision does not engage, the event names why
      (fewer than two probed batches, the batch whose coverage verdict
      is absent and on what ground, an all- or none-reaching
      partition, the schedule minimums) on both faces, with the spec
      stating that freshness facts never withhold the exemption (reach
      keys it; instability relabels after scoring). After 246.
      Rider (derived 2026-09-29 from gomutant fe44f4d): a reuse fact
      never scores as instability — instability is a verdict flipping
      between runs of one tree, an unverifiable observed input (a
      volatile /proc read) is a reuse blocker on the record's layer;
      conflating them withholds a survivor verdict for a reason that
      has nothing to do with whether the test flips. REQ-result-
      exemptions' rule narrows to the flip evidence; the observed input
      keeps the record machine-local and says so on both faces
      (gomutant
      docs/issues/process-identity-reads-have-no-discharge-channel.md's
      scoring half; its declaration half is gofresh 295).
      Narrowed (2026-10-06, audit 317): 304's EstimateNoSignal names the group-level no-signal reasons; the residue is the per-candidate partition ground (all- or none-reaching), the whole-run purity assertion, the reuse-vs-instability rider.
- [ ] 256. gomutant: the document face's attest gains `--reattest`
      (the guard the ephemeral face applies since 160: a standing
      disposition replaced only with the flag, the prior reason kept
      on the record) and a withdraw form returning the survivor to
      open with the withdrawal reason recorded — the attestation
      history reads forward like the document; both faces. After 254.
      Grown (2026-10-06, audit 317): the ephemeral attestation record's lifecycle — its rows (Files, TestPkg, Run) followed by prune and retarget as 283.C follows the exemption record's (ephemeral-attestation-lifecycle, fired at 282/283).
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
      (field report evidence-fault-rendered-as-dirty-provenance,
      2026-09-20: a fault in the evidence walk — an evidence subject with
      no view, an unreadable runtime-input manifest — stamps the finding
      dirty on a non-staged run and returns no reason, so the portable
      line reads the flag as git drift and `findings` stops at that
      clause; expected: the fault names the subject and the manifest as
      the staged run already reports it, and "dirty worktree provenance"
      means git-visible drift alone) and explain's CLI face (field
      report explain-has-no-cli-face: a read verb with structured input
      the CLI can take, the same class as findings — both faces, per
      the two-surfaces doctrine). After 209.
      (259: grows — the post-splice divergence arm stamps ONE target-side
      runtime reason onto every evidence subject beside their untouched
      manifests (gomutant
      docs/issues/divergence-reason-stamped-on-every-evidence-subject.md):
      pb's 243 identical subjects with empty manifests
      were that stamp; the attributed reason now names the target-side
      process the stamp copies.)
      (257: reproduced over pb's archive-only oracle — a non-staged run's
      scratch residue moved the bracket and the record stamped dirty with
      no reason, the report's exact shape; stampUnverifiable is now the
      one evidence-wide stamp the divergence arm and the budget-cut
      validation share, the per-subject attribution this chunk's.)
      Audit 286 (2026-09-29): grows — gomutant.gitOutputContext
      (provenance.go:391) is a bare cmd.Output(): stderr discarded, no
      ctx.Err() precedence, so a cancelled provenance read surfaces as
      'commit provenance unavailable … exit status 1' — the
      dirty/commit layer of
      evidence-fault-rendered-as-dirty-provenance; the correctness
      half here (cancellation named, stderr carried); the one-home
      half rides gofresh 281's non-go containment.
      Grown (2026-10-06, audit 317): one contained, stderr-carrying git runner below the root over gofresh's Runner.Program (provenance.go's gitOutputContext and gitref's outputContext fold; gitref.Show deleted).
- [ ] 255. gofresh: a downgrade reason names its invoke site — a
      "reaches <sink>" reason composed through an interface invoke
      names the call expression and its operand type in the subject
      beside the reached sink (REQ-closure-refusal-channels' principle:
      a reason names its channel), so a consumer tells an
      over-approximated interface invoke from a real reach. After 206.
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
      (field report iterator-calls-and-std-invokes-open-the-closure's
      first half: a range over `strings.SplitSeq` reaches the analyzer's
      computed-call widening, where closure.md already names the range
      statement's binding of the yielded function — a conformance fault
      of the analyzer against its own clause; the report's invoke half
      — a std-constructed `hash.Hash` behind an interface operand
      reported outside RTA — rides invoke-targets-narrowed-by-operand's
      landing). After 240.
      Audit 285 (2026-09-29): grows to BOTH halves of its own field
      report — the invoke half (writeMember dispatches hash.Hash.Sum
      refused outside RTA) fired the arm
      dispatch-admissions-one-predicate and
      invoke-targets-narrowed-by-operand named; both docs retarget
      here (their triggers were circular);
      closed-value-ladders-one-source and
      registration-audit-walk-helper-unification re-slot onto
      unify-carrier-walks alone.

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
      both faces and the tail cadence (262 A2/A3/A4/A7/A8 + C8): the phase
      and decision-action vocabularies REQ-exec-run-status states become
      named constants read by every emitter, the renderer, the tally, and
      both faces (213's stretch treatment applied to the two older
      vocabularies), pinned against the clause; the CLI's cadence lives
      through the final merge and the render (rep.stop() precedes
      ledger.Finish today — a run silent for minutes after its last
      decision), or the clause states the line's end; the faces read
      RunTallies (a Measured field) instead of recounting; the bound
      refusal one implementation (validateRunBounds) both faces; the
      preparation stretch on every MCP tool that holds the lock; the two
      row-projection issues (run-faces-assemble-rows-twice,
      findings-row-projections-one-shape) land here. Before 219.
      Rider (2026-09-29 replan): the structured face's sheds and carries as structured rows, not prose (gomutant mcp-sheds-and-carries-as-prose) — the MCP face is the agent's, structured by the two-surfaces doctrine; BREAKING wire, declared at the tick.
      Audit 286 (2026-09-29): grows — analysisVocabulary
      (grammar.go:200–213) misses gofresh's live diagnostic phases
      toolchain-unaudited and listing-unmodelled, which reach the
      operator raw on both faces (gofresh 203 exports the whole phase
      set; the map's completeness pinned against it); the bound
      refusal three implementations with divergent wording
      (validateRunBounds vs the CLI's two copies; the CLI's timeout in
      no library rule; MCP none); rep.stop() before ledger.Finish
      (internal/cmd/run.go:375/398 — minutes of silence); only run
      primes a preparation stretch on MCP; the lifecycle verbs two
      drivers and two renderers with the CLI lacking the 'prefix
      matched nothing' answer the MCP schema states; the loading
      preamble at seven CLI sites + report.go:101 vs MCP's one
      constant; the liveness ticker twice.
      Grown (2026-10-06, audit 317): one row projection carrying layer, reason and delta on both faces — run-faces-assemble-rows-twice, findings-row-projections-one-shape and per-layer-counts-one-type land here (their Lands moved from 220); a symbol in both layers counts once per layer.
- [ ] 268. gomutant: the seven mega-requirements decomposed into
      per-sub-contract ids under 200's recorded mechanics (262 A10):
      REQ-result-stale (2,917 words, 12 bindings), REQ-exec-run-status
      (2,219/56), REQ-exec-ephemeral (1,772/30), REQ-result-layers
      (1,559/31), REQ-exec-oracle-run (1,252/31), REQ-exec-attribution
      (1,242/13), REQ-attest-survivor (1,113/17) — one uppercase keyword
      per paragraph, bindings retargeted to the sub-rule they witness,
      every cite (wrap-aware) retargeted, byte-preservation by word-diff.
      After 209.
      Audit 286 (2026-09-29): grows to TEN requirements —
      REQ-mut-operators FIRST (1,975 words / 2 bindings; it contains
      INV-MUT-COMPREHENSIVE and the 35-row catalogue whose ten named
      tests are unbound), REQ-result-lifecycle (921/14 after 282),
      REQ-result-export (906/9 after version 14), REQ-mcp-surfaces
      (714/3), REQ-exec-plan-only (404/3); the charter's figures
      moved: REQ-result-layers 31→40 bindings, REQ-exec-run-status
      56→68.
      Grown (2026-10-06, audit 317): REQ-exec-analysis-budget's proof-unit lifecycle (membership, derivation, release, the serial pass, the lookahead holdings) split out of the budget clause as a run-loop contract; measured: REQ-result-stale 3,056 words/15 bindings, REQ-exec-run-status 2,581/76, REQ-result-lifecycle 1,027, REQ-mcp-surfaces 816/3.
- [ ] 269. gomutant: one test-stream walk (262 C1) — internal/engine/run.go's
      eight `go test -json` decoders, each with its own truncated-stream
      policy (break, ignore, empty, an io.EOF sentinel, false, error) and
      a kill path walking one buffer four to five times, collapse onto
      parseTestStream's "read once; a stream that cannot be read has no
      verdict"; invariants: the crash-truncated attribution
      (REQ-core-attributed-kills), the build-fail event's precedence
      (208), the compiler-crash retry. A correctness chunk: after 257.
      Audit 286 (2026-09-29): count corrected — SEVEN go test -json
      decoders in internal/engine/run.go (:291, 1204, 1226, 1271,
      1288, 1303, 1359) with FIVE truncated-stream policies;
      firstFailingTest and buildRejected read one mutant stream under
      opposite policies.
      Grown (2026-10-06, audit 317): REQ-core-attributed-kills' property witness (a generator over outcome streams) — its keystone invariant has two example bindings and no property.
- [ ] 270. stipulator: the corpus's mega-requirements decomposed into
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
- [ ] 276. pew: the generator surface (264 A11/A12) — 276 tests, zero
      Fuzz, zero rapid, on the fleet's most generator-shaped surfaces:
      §9's stream-corruption grammar (REQ-pew-sample-completeness's
      "detection boundary" is a for-all claim with three example
      anchors), the ledger encode/decode round trip, the run-conditions
      grammar, liftOversizedConfig, the --pin derivation ladder;
      REQ-pew-progress (one binding for seven stretches) and
      REQ-pew-sha-independence (one) thickened; the eight pins built over
      a bare gofresh.New() rebuilt through buildEngine (production never
      builds an engine without WithoutRepositoryVouches). Bound by
      adjacency, its own commits. After 232.
      Audit 288 (2026-09-29): grows — premise re-verified after 230
      (zero Fuzz, zero rapid tree-wide; 230's fixed-seed
      inverse-property loop on the chunk grammar, chunk_test.go:17, is
      the pattern the other surfaces follow); the id-citation sweep
      (eight of 22 requirement ids named by no test —
      REQ-pew-closure-soundness, -validity-verdict, -derived-state,
      -sha-independence, -closure-noncall, -mutable-local,
      -regression-gate, -sample-completeness — several witnessed
      without the cite); the self-oracle pins
      (guidance_test.go:62–68/:99–101 against the same memoized
      document; knobs_test.go:70 derivePin against run.DerivePin); the
      eight bare-engine pins bypassing buildEngine; the generator
      VEHICLE stated at open (rapid is not in pew's go.mod — extend
      the seeded-loop pattern, or a dependency ask).
      Narrowed (2026-10-06, audit 319): liftOversizedConfig no longer exists (deleted at 230); performance-evidence 1 added the one Fuzz (native fuzzing, no dependency) and 3.2 the long-line regressions; the residue — §9's corruption grammar, the ledger round trip, the conditions grammar, the pin ladder, the eleven uncited ids, the self-oracle pins (guidance_test.go, knobs_test.go), the six bare gofresh.New() engines in tests — stands after that plan closes.
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
      docs/issues/store-update-returns-its-routing.md, filed at 282's
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
      REQ-guard-buildconfig — with no gap excusing any (gofresh
      docs/issues/check-red-fleet-sweep.md, measured at b34f15c): the
      diagnosis first (a cold check over the current tree, the rows
      file read per binding), then the re-bind per requirement with the
      bound bodies read — never a blanket — and any row still red after
      it treated as the regression it is. Soundness first: directly
      after 277 in the lane, before the band.
- [ ] 290. stipulator: the bump behind gofresh 279, 281 (and whatever
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
      docs/issues/mcp-server-holds-one-toolchain-sampler-per-process.md
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
- [x] 291. pew: the bump behind gofresh 279, 281 (v0.107.0 today) — pew
      docs/issues/gofresh-corpus-pin-lag.md; runCommand's containment
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
- [ ] 293. stipulator: a gap's excuse is judged over every red class a
      row carries (stipulator
      docs/issues/gap-excuse-judges-the-winning-bucket-only.md —
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
      external-oracle-for-tagged-and-subprocess-targets.md — derived
      2026-09-29: the trigger the 2026-09-07 deferral named, a
      consumer's request to measure the bounded leg, is wisp's own
      report of 2026-09-05; the interim bound 163 landed states the
      cap, the measurement is `--oracle-cmd` per tag set or package
      with the mutated tree materialized and a pass/fail read; the
      materialized-mutation half for subprocess oracles rides it).
      Last of gomutant's tail; doc deletes at close.
- [ ] 295. gofresh: a declared surface for the ephemeral
      process-identity input class (gomutant
      docs/issues/process-identity-reads-have-no-discharge-channel.md's
      declaration half —
      derived 2026-09-29: a liveness read of `/proc/<pid>/stat` is
      verdict-bearing, so no classification carve-out is sound; the
      sound shape is the caller's assertion carried for exactly that
      path class, REQ-inputs-volatile-os-roots gaining the declaration
      as bracket-path carries tree paths, gomutant passing it at its
      next bump — the alternative, a whole-symbol purity directive,
      over-asserts, which the refusal-channel doctrine forbids). After
      243; a release.
      Audit 285 (2026-09-29): UNPINNED from 243 — an additive
      declaration on REQ-inputs-volatile-os-roots depends on no
      dead-surface sweep; slotted after 191 in the release cluster
      (gomutant's process-identity reads stay unverifiable until it
      lands).
- [ ] 296. gomutant: an unstable test quarantined per test (gomutant
      docs/issues/unstable-test-quarantine.md — derived 2026-09-29: a
      per-test exclusion with a stated cap on the run surface and in
      the document is the narrowing class the 2026-08-31 ruling
      accepted for the survivor oracle (option b, chunk 137), and the
      alternative degrades every verdict in the group for one test's
      defect; the test is named with its flip evidence on every face,
      the exclusion is a counted coverage cap, the consumer's
      obligation to fix the test stays). After 254; doc deletes at
      close.
- [x] 297. gofresh: the dst-selection walk for the toolchain-audit key
      (gofresh docs/issues/walk-dst-selection-for-audit-key.md, whose
      trigger fired 2026-09-29 — the field report
      dst-selection-walk-trigger-fired-tugboat in gofresh's index:
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
- [ ] 298. stipulator: the seeding walk's declaration lookup under the
      invocation's own selection (the stipulator field report
      seeding-declaration-not-in-default-view — tugboat,
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
      property driver (stipulator docs/issues/
      testing-quick-property-driver.md — Weaver's field report; the
      derivation at open: Check and CheckEqual, the callback's
      quantification, Config.Rand against the time seed — the
      runtime-seeded freshness class every other driver carries; an
      unsupported driver named in the diagnostic).
      Grown (2026-10-06, audit 318): property-completion-adapter-guidance (derived: the direct-driver rule is soundness; the remedy a diagnostic naming the reached-through helper and the direct-call form).
- [ ] 299. stipulator: a policy toolchain pin the environment does not
      satisfy refuses at load (the stipulator field report
      toolchain-pin-unhonored-runs-silently — tugboat, 2026-09-29: the
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
      document (guidance-lint-zero-default-spelling,
      coverage-lint-default-on-zero-default-flag), the prints-default
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
      (gomutant docs/issues/findings-records-keyed-by-symbol-alone.md,
      filed at 284's review): a record keyed by its symbol alone lets
      two build selections over one document re-measure each other,
      and a drift re-measure under the default selection turns the
      integration selection's kill into a survivor — measured at 284:
      89.4% of the root's statements covered under the integration
      selection, 59.9% under the default, 1,601 of 4,958 covered
      blocks and 97 of 514 covered functions reach zero under the
      affordable selection; the document holds one record per
      selection it was measured under, the faces read the selection's
      records, serving and drift judged within a selection, a survivor
      under one selection carrying the other's verdict where one
      exists; REQ-result-record's key sentence and the tables amended,
      the document version bumped; the bump behind gofresh 303 rides
      it (the integration campaign then serves), and that bump adopts
      281's forms: gotool.Runner.List for the linked-set `go list`
      (buildset.go's served salvage retires),
      gofresh.NewToolchainProvenance for the composite, one
      runtimeinput.Roots and one gotool.Sampler per judged run on
      every ProducerIngest, parseGoVersion/releaseTags folded onto
      gotool.ParseGoVersion/ReleaseTags (the development-build
      divergence declared), the oracle's boundary through
      Runner.Program. Correctness first: heads gomutant's tail,
      directly before 269.
      Grown (2026-10-06, audit 317): heads gomutant's tail after the CI gate; the stale 'behind gofresh 303' clause struck (303 closed by verdict at 310 — the integration selection admits by content; policy.textproto and ci.yaml's premise text corrected at 323); the 281 adoption moved out to 324; serve-path-posture-keying judged at its open gate; its close measure the self-campaign (284's half).
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
      beside the findings document, tracked, carrying the knobs that are
      repo facts and re-passed identically on every run today: bracket
      paths, scratch namespaces, build tags and toolchain. Flags extend
      the file and never narrow it (the vouch file's rule); vouches stay
      in the tree root's `vouches` file (gofresh's contract); host and
      operator facts (jobs, budgets, timeouts, memory) stay knobs with
      derived defaults. Both faces read the file at preparation (its
      shape joins REQ-exec-preparation's declaration stage; a malformed
      file refuses before the load); the served inventory names the
      declared set; the guidance states each knob's class. A design
      chunk: the knob classification is its design, finished at its
      open (scratchpad design-gomutant-ux.md). Directly after 312.
      Grown (2026-10-06, audit 317): the design settles two gaps — bracket paths outside the tree are host facts, not repo facts; 'flags extend, never narrow' is undefined for a selection (tags, toolchain). Slotted after 324 (soundness first: 302 turns integration kills into survivors, 187 is a live MUST breach; the user's 2026-10-05 slot named priority, not a binding position).
- [ ] 314. gofresh: the analysis pass's program retention bounded
      (docs/issues/cold-analysis-pass-program-retention.md — measured at
      gomutant 308's open: one target of gomutant's derived campaign,
      796 subjects over 5 oracle packages, 0.54 GB warm and 3.47 GB cold
      at the parent's high-water mark, the cold pass holding every
      program it loaded for its life inside the proof pass; the 311
      campaign's 8.4 GB is the same shape at scale). The pass's live set
      bounded by its current subject's need — programs released per
      package group as 305's discharge does, or the pass partitioned per
      package — the cost model stated in the clause with the measured
      anchor; a release, after 313 in the lane; consumers read it at
      their bumps.
      Narrowed (2026-10-06, audit 316): program retention alone — the ceiling's own-set derivation and the children's budget are 326's (a release before stipulator 290.2b/322 and gomutant 214).
- [ ] 315. gofresh: the toolchain-source audit's second half — the walk
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
      operation's caller frame — protodb's campaign classifies `external
      directory input: /` in every package with an empty input list
      (gofresh docs/issues/root-directory-input-with-empty-manifest.md):
      an open of a directory is an observed input under the log's
      vocabulary (open, stat, chdir — no read), so a directory opened
      for a sync and one listed are indistinguishable and the
      classification stands fail-closed; the one fact that separates
      them is the CALL, which only the toolchain can log. godst's test
      log gains the operation's caller frame (the first frame outside
      the runtime and the os/syscall packages: package path, function,
      file:line) on every open/stat/chdir line as a stated extension of
      the log's grammar; gofresh's parser reads it, the refusal's
      attribution names it (`open "/" from <pkg>.<func> at <file:line>`
      — the attribution limb, never the clause; the attribution
      checker's grammar gains the frame form with its split pins), and a
      godst build without the frame parses as today. The grammar is a
      godst release consumed by a gofresh release (the listing + the
      walk), measured over protodb's campaign at close. After 314.


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

- [ ] 324. gomutant: the 281 adoption (audit 317; moved out of 302):
      Runner.List for buildset's linked-set listing; Runner.Program-
      contained git (one runner below the root, 258's fold); one
      runtimeinput.Roots and one Sampler per judged run on every
      ProducerIngest; gotool.ParseGoVersion/ReleaseTags replacing
      engine.go's parseGoVersion and enumerationcheck.go's releaseTags
      — which answers nil for go1.28rc1 (a spurious fail-closed
      enumeration refusal under any rc toolchain on a //go:build go1.N
      test file; the next-rc leg is that environment) and bounds no
      overflow — the divergence pinned. Directly after 187.


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

- [ ] 322. stipulator: per-operation readings in a long-lived server
      (audit 318, 307.D's remainder): the admission's growth headroom
      is VmHWM − VmRSS, a lifetime peak — after one large call every
      later pass reserves room to grow back to it (a spurious hold or a
      "cannot hold one process" refusal on a small host); the gate is
      per invocation but DescendantsBytes/running divides the whole
      process's descendants, so concurrent MCP operations inflate each
      other's estimates; 5407c3d rebased the reporter's peak, never the
      admission. After gofresh 314 (the own-set derivation).


- [x] 319. pew: the fifth re-audit band's pew audit (as 316); closes the
      band with the cross-repo lane re-sequenced.
      Dispositioned 2026-10-06 — BAND R5 CLOSED: twelve coherence findings, seven consolidation candidates, the queue walked — 291, 174, 127, 15 and 177 dissolved into pew's performance-evidence plan (the handoff doc carries their riders), 252, 232 and 276 narrowed to residues after that plan closes, 320 chartered (the residual bump), A3's circular remedy (the train's 230 anchor) handed to that plan's chunk 3, A5's gomutant half filed. The cross-repo lane is in the order sentence; the audit count restarts at zero.
- [ ] 320. pew: the residual bump (audit 319): the gofresh release
      pew's performance-evidence chunk 2 predates — 292's clause re-key,
      297's dst walk, 300's guidance lint with its pew half (the five
      derived defaults 275 spelled in prose, which the lint must see)
      — taken after that plan closes, before 252r/232r/276r.


- [x] 311. gomutant: the observation-proof pass per group — the vertical
      (the user's ruling 2026-10-04: the unit loop's deviations are the
      source of most of the fleet's problems and take priority; gomutant
      docs/issues/observed-union-memory-slicing.md, its measured trigger
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
- [x] 223. stipulator: one witness pipeline (stipulator docs/issues/
      two-completion-mechanisms.md, publish-refusal-ladders.md,
      executor-diagnostics-trio.md) — the selective runner's 592-line
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
      caps (ReasonHistogram, blockerRows) and one diagnostic heading;
      refKey once (compile, bundle).
      (236: DISSOLVES INTO 227 — the folds and the sweep touch the same
      files; refKey is THREE (a local closure in compile.resolve shadows
      the package one with a different case rule); the cap-and-count
      block duplicated across views.)
      (263: does NOT dissolve — its refKey trio and reason tallies never
      landed; grows to "one vocabulary, one composer": bucket words in five
      tables over two types, the keyword's three spellings (MUST_NOT / MUST
      NOT / must not — two on wire surfaces), enumWord + eleven hand-rolls,
      four truncate helpers, per-face prose pairs as surface-parameterized
      composers; 227's six deferred test-only production entries and two
      true vestiges (resolverClient.stdin write-only, gitfs.absPath an
      injection seam with no site); 172 merges in.)
      Audit 287 (2026-09-29): grows — refKey three ways with
      compile.go:487 a local closure shadowing the package function
      and dropping the case folding (two term references differing
      only in case are one identity at :540 and two at :487 — under
      the comment citing REQ-model-layout-independence);
      truncate-with-ellipsis four ways, three wrong (completions.go:36
      cuts by bytes — invalid UTF-8; server.go:231; progress.go:45 off
      by one; envreport.go:70 correct); bucket words two tables
      (coverage.go:55 vs :805, one contradicting views.go:35's
      comment; views.go:38 hand-lists what proto.go:126 derives);
      vestiges verified: progress.WithInterval + progress.Option zero
      production callers (227's 'seam' verdict re-derived),
      resolutioncache.StoreDir, gitfs.absPath (a seam nothing
      substitutes), resolverClient.stdin written never read,
      profile.Dump ×4 zero references, over-exports
      (verify.Registration.TopLevel, coverage.Policy.Active,
      views.Scope.Empty, prune.ResolutionCounts,
      proptest.Corpus.Partition, profile.LineIndex/NewLineIndex);
      per-stream-color re-slotted here (172 merged into 225).
      Grown (2026-10-06, audit 318): the post-307 vestiges — test-only exported production entries (ExecuteSelection, ExecuteInvocation, ExecutePolicy, RunWitnesses' dir form, ConservationReport, ServedCount, newResolverClient, telemetryOffEnvFor); packageleg.go's comment naming a field that no longer exists.
- [ ] 226. stipulator: golang.go split by its three subsystems
      (resolution and shape hashing, witness classification and the
      seeding walk, generated detection) with the classifier's three
      body inspections one per-view pass (stipulator docs/issues/
      witness-verdict-one-body-classifier.md); doc deletes at close.
      (236: grown — opens with the clause split A4 (REQ-go-owned-processes
      carries five mechanisms and REQ-go-build-selections two behind one
      gap each; split so a gap excuses only its own); the module-mode
      view triple lands here (A5: derive keys module mode, the resolution
      view does not); C8 the classifier's one pass; C9 the split.)
      (263: loses its clause-split opening to 270; grows — workspaceMembers /
      policyMembers one go.work rule (identical refusal text) with
      depattribution's third ParseWork reader; path containment hand-rolled
      six times; the subject key joined inline at 45 sites beside
      witnesscache.Record.Key; the twin semver comparators; folds
      go-backend-load-path-pairs and reviewed-row-sets-one-pattern.)
      Audit 287 (2026-09-29): LEADS with the go.work divergence —
      policyMembers (policy.go:447) refuses a non-host-portable member
      before the escape test while workspaceMembers (workspace.go:22,
      the load/witness reader) has no such check, so one go.work is
      refused at derivation and admitted at verification, and
      depattribution.go:111 re-parses go.work swallowing both errors
      (REQ-go-workspace: 'never silently bent'); the third band's
      'identical refusal text' note was wrong. Grows: path containment
      EIGHT ways, two wrong (the two strings.Contains(clean, '..')
      forms at mcpserver/export.go:53 and author/author.go:125 refuse
      a legitimate ..foo component; golang.go:542's separator-less
      HasPrefix judges a file under a ..cache directory out of tree;
      recordapply.go:380's within resolves no symlink); test-variant
      folding two rules (slice.go:156 by build identity vs seven sites
      by spelling). Preserve the lexical-then-resolved two-step
      workspace.go:41+:81 states.
      Grown (2026-10-06, audit 318): the symbol-to-package derivation one rule — Backend.splitSymbol's longest-loaded-package answer (dotted-package-element-unresolvable moves here from 249); packageOf, check.scopeSubjects and records.SymbolMember fold onto it; served.go's childPatterns stops widening the load on an unparsable symbol (307.B's unfinished scope item).
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
      cli-test-binary-builds.md) — one built CLI binary per package run
      behind sync.Once; the byte-identical firstClause helpers one; the
      temp-module builders across the Go backend's tests one; the
      comment-stripped freshfixture copies of fixturemod folded onto it;
      the policyderive workspace fixture made real (its go.work names two
      members that do not exist, so the derive path never meets a real
      workspace); doc deletes at close.
      (236: re-aimed — firstClause folds onto a test-support package,
      never onto KnobClause (169's review removed that vacuous oracle);
      the temp-module builders item has dissolved (one survivor);
      FIRST: neutralAmbient has four copies and one diverges (GOWORK=off,
      GOCACHE="" in golang's, whose rationale applies to check's
      fixtures) — a fault, not tidiness; seven go-build sites behind
      one sync.Once; repoWith, untouchable, compileFiles duplicated.)
      Audit 287 (2026-09-29): grows — eight go build …/cmd/stipulator
      sites in seven test files, none referencing newRootCmd
      (bind/pin/prune/gap/check/interrupt exercised only out of
      process — the recorded lesson, unlanded); neutralAmbient four
      copies, two diverging (GOWORK=off, GOCACHE='');
      firstClause/repoWith/untouchable/compileFiles duplicated;
      freshfixture duplicates six fixturemod packages; the
      policyderive/workspace fixture's go.work names members that do
      not exist and its golden pins them; vacuous oracles
      (hygiene_test.go:49's len floor over the surface 271 made the
      MCP's correctness gate; vocabulary_test.go ranging the
      production tables; the guidance tests taking want from the
      rendered document; keysoundness_test.go:205/:255); untested arms
      (progress.Word zero test references;
      coverage.satisfied/requiredEvidence never see ANALYZER_PROOF or
      PROPERTY; gapRowCap, ledgerVersion).
      Grown (2026-10-06, audit 318): freshness_test.go's process-global runtime.GOMAXPROCS(4) where siblings set SpawnBound explicitly; the 287 census unchanged (eight go build sites with no sync.Once, four neutralAmbient copies, firstClause/repoWith/untouchable/compileFiles duplicated).

## Band J — pew under the emergent shape (chartered by audit 197)
      (263: grows — enumeration pins blind to a new member: progress.Word's
      fallthrough (three of six phases untested), coverage.satisfied /
      requiredEvidence's fallthrough sampled one cell per kind, the
      witness-cache key list and the MCP tool names mirrored by hand;
      premises re-verified: eight go build sites, neutralAmbient four copies
      diverging on GOWORK=off.)

- [x] 229. pew: the gofresh bump v0.95.0 → v0.101.0 (pew docs/issues/
      gofresh-corpus-pin-lag.md, serve-proven-blocked-by-benchmark-loop.md)
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
- [ ] 232. pew: the spec chunk — §11's "never by shelling to a git
      binary" and "the only subprocesses are the Go toolchain" against
      ab's seven git invocations (go-git cannot create linked worktrees:
      ab requires a git binary, stated, with the install story); the
      contradicting format-1 sentence deleted; --explain's stream stated
      (stderr) and unified; the reader-injected pew-format-invalid key
      stated or renamed out of the pew- namespace; REQ-pew-derived-state
      given a two-item payload list so its shortfall is a clause gap
      (pew docs/issues/derived-state-recompute-invariance-witness.md's
      rationale predates stipulator's clause claims) — the first case for
      spec-wide-requirement-forming; re-consented.
      (237: grown — A6 §5's mandatory field set is a twelve-key literal
      the table states only by prose: a mandatory/omittable column
      (251 derives the code from one registry); A9 the strategy-class
      admission is co-owned with gofresh's verdict ladder — name the
      engine as the class's origin, pew's rung the pre-comparison
      projection.)
      Audit 288 (2026-09-29): grows — three format sentences under one
      rule (spec.md:630 'Format-2 recordings are checked through the
      ordinary fingerprint path' false since 230; :183 format-1's
      canonical incomplete disposition describes a shape no reader
      interprets; :110 correct); a validity? column in §5's table (the
      one registry projection not derived — 'validity key' is prose at
      :98/:102 and the rung a hand-written compare) that 174's
      admission reads; a format bump announces its re-class (§10.1
      already separates 'everything stale (format)' from 'nothing
      recorded'; the same duty across a version bump); §11's
      subprocess list gains go list -m -json; the declared-benchmarks
      rule stated once (gc's two enumerations); 264's A4 as one
      sentence naming ab's disagreement-only rule beside §10.1's
      non-empty-equal rule (not one predicate); the recorded items
      stand (§11's git-binary sentence, --explain's stream, the
      reader-injected pew-format-invalid key, REQ-pew-derived-state's
      payload list, §§1–12 ids, the purpose column).
      Narrowed (2026-10-06, audit 319): the format sentences → performance-evidence 3, the validity column and the strategy class's origin → 4, §11's git sentence and subprocess list → 7, the purpose-column doc → 8.2; the residue — `--explain`'s stream, the `pew-format-invalid` key, REQ-pew-derived-state's payload list, the REQ home rule — stands after that plan closes.

## Band E — design chunks (open with the user)
      (264: grows — states which files a package's benchmarks are (§4's B,
      §12's gc "gone from the source") so 252's collapse has its rule; pew's
      requirements warrant no decomposition chunk — the largest is 393 words,
      every id bound or gapped; what is missing is ids for §§1–12, filed here.)

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
      (design — released to the autonomous order by the user
      2026-09-29; the design derives under the standing authority and
      is recorded in the change set's commit) — purity.go and dynamicstate.go implement
      REQ-closure-shared-dynamic-state in the root package while the
      spec home and every peer tier live under closure/; four functions
      of 675–1,760 lines with `audited` hand-threaded through 34
      signatures and `singleSubject` beside it; the collapse is a walk
      context carrying the selection's audit, the subject scope, the
      package, and the explain hooks, and the tier moved under closure/;
      invariants: the per-package-graph judgment and the fail-closed
      zero value; unblocks 193's fixpoint, 191's poisoning rule, and the
      four filed walk unifications.
      Audit 285 (2026-09-29): grows — the engine verdict discriminates
      the shared-dynamic-state downgrade by a reason-string prefix
      (gofresh.go:1279 over purity.go:47's sharedDynamicStatePrefix)
      while 279 published runtimeinput.RefusalClause as the channel
      mechanism for the other reason family; the walk context's design
      names the typed class the ENGINE VERDICT reads, not only the
      composers 199 folded in.
      Grown (2026-10-06, audit 316): the analysis-unavailable class is discriminated by a reason-string prefix spelled in two packages (view.go's analysisUnavailablePrefix, closure/observability.go) — 305 widened its use — the typed verdict class covers it with the shared-dynamic-state family, one spelling on closure's side; generated-proto-discharge-single-subject-only (named here: the descriptor's content-invariance binds no execution model); 305's cut fact (observationFacts.cut, the held unavailability) and 5a7f309's per-attestation channel are tier-boundary inputs to the design.

      Triage 281.1 (2026-09-30): two tugboat field reports ride here
      as design inputs —
      entropy-reach-through-tls-handshakes-marks-networked-witnesses-uncacheable
      (828 of 1,098 subjects refused for a handshake nonce no witness
      observes: an admission for entropy consumed but never observed,
      judged by what the subject can observe of the reach) and
      in-module-generated-descriptor-writes-have-no-discharge
      (protoc-gen-go's init-once descriptor writes in an in-module
      generated package: the vouch is dependency-only and a directive
      cannot live in generated code — a generated-package admission
      keyed on the generator's marker, or the vouch extended in-module
      under an attestation).
- [x] 15. pew: profile capture and attribution as recording
      companions (pew docs/issues/profile-capture-attribution.md and
      per-arm-noise-floors.md) — --profile captures per-arm cpu (and
      mem where B/op is claimed) evidence under the recording's
      provenance conjunction; status gains the attribution verdict,
      stat the profile-diff view; the noise-floor lineage keys on
      chunk 102's sliced closures. Design derived 2026-09-29 from the
      two issue docs' directions (top-N attribution stored beside the
      recording under its provenance; the arm floor derived from the
      lineage's same-closure recordings, the bar named per row); 102
      lands inside this chunk's arc, after gofresh 175.
      Audit 288 (2026-09-29): stands (after gofresh 175/102).
      Dissolved (2026-10-06, audit 319): profiles → performance-evidence chunks 6/7, per-arm noise floors → 8.1 (sound on the package closure today; gofresh 102 only refines them).
- [ ] 102. gofresh: per-subject sliced closures — Fingerprint gains
      SlicedClosure (declaration-level hash over the subject's
      attributed-reachable set; widens to the maximal hash where
      attribution cannot bound, so slice-equal is never claimable
      without proven reachability; closure-equal implies
      slice-equal). Consumer: pew records pew-slice per arm; the
      noise-floor lineage classifies unreached-declaration commits as
      layout-only neighbors. Sequenced inside 15.
      (234: after 175 — both derive a subject-scoped hash over the
      attributed-reachable set; 175 decides whether that identity is
      semantic and how it composes into IdentityStrategy.)
- [x] 127. pew: observed-fingerprint recording path (pew
      docs/issues/observed-fingerprint-recording-path.md) —
      plain-Capture recordings leave every true-external-effect
      benchmark permanently unverifiable; adopt CaptureObserved per
      arm and retire §7.8's no-proof sentence; a spec-level
      verdict-model change derived 2026-09-29: the observed-evidence
      substitution is gofresh's own gate, already the reuse verdict of
      the other two consumers, and pew's single-subject execution gives
      every arm its own completed observation — adopting a proven gate
      is not a fork; doc deletes at close.
      Audit 288 (2026-09-29): scope sharpened — the exemption at
      cmd/pew/fingerprint_roundtrip_test.go:43
      (ObservationAssertion/ObservationProof, the two record fields §5
      has no rows for, exempted 'recomputed at judge time, never
      served' — §7.8's retiring sentence): two omittable rows + the
      format bump + that exemption flipped.
      Dissolved (2026-10-06, audit 319): → performance-evidence chunk 4, with the format bump DERIVED there, never assumed (§5's omittable class reads an absent row as today's behaviour).

- [ ] 175. gofresh: subject-scoped closure identity (design — derived
      2026-09-29: the identity is the canonical member form over the
      subject's attributed-reachable set, widening to the package's
      maximal closure wherever attribution cannot bound it, so equality
      entails that no member the subject can reach changed semantically
      — the maximal closure's own soundness argument over a proven
      subset; it composes into IdentityStrategy as one more derivation
      version; gomutant docs/issues/semantic-closure-in-the-carry-gate.md;
      chartered by the user's ruling 2026-09-07) — a closure identity that is both semantic
      (the canonical member form) and scoped to the subject's own
      reachable closure, so gomutant's carry gate can shed on a semantic
      move of the subject's closure and carry across sibling edits; the
      carry gate stays body hash + operator set until it lands; doc
      deletes at close.
      Audit 285 (2026-09-29): stands (autonomous since ede9ab0).

- [x] 328. gofresh: admit the source-audited go1.27.1 nodwarf5 selection and its standard selection variants without weakening content-key admission.
  - [x] 328.1 Reproduce the unlisted internal/goexperiment key, compare the dwarf5 selection against the existing audited chain, and inspect the selected constants and their consumers.
  - [x] 328.2 Record the audited source deltas and retain rejection of unlisted content, including selection-specific chains.
  - [x] 328.3 Run the applicable Go tests and mutation evidence, converge independent review, commit and push the completed source audit, and make its released version available to the consumer bump.

## Ecosystem-blocked

- [ ] 95. gomutant: MCP Tasks adoption — protocol-level operation
      identity, polling, result retrieval after a client deadline,
      explicit cancellation. Opens by re-auditing the prerequisites
      that blocked it at chunk-41 time (SEP-2663 stable in go-sdk AND
      a consuming agent client that speaks it); history: `git log
      --all -- docs/issues/mcp-long-running-runs.md` (gomutant).
