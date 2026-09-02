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
  interruption loses one unit, never a run. The same rule governs
  this train's own gates: a long measurement runs once, over the
  settled tree, after the loop converges; a measurement started
  before its inputs settle is wasted work, not diligence. Band P is
  the application; chunk 136's scan walks what it leaves.
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

Standing rule from the ruling, binding on the loop: a long
measurement (self-host check, campaign, full fixture suite) runs
ONCE, over the settled tree, after the adversarial loop converges;
the loop's own gates ride Band T's fast tier plus ephemeral probes.
While Band P is open, no chunk's close waits on a tool-on-itself run
of a tool Band P has not yet restaged — the verdict is deferred to
that chunk's close and named in the commit record.

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
triage, then 95 (ecosystem-blocked, re-audited at open), with the
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

- [ ] 150. gofresh: self-test partition — `testing.Short()` gates on
      every temp-module / `closure/fixtures/` / SSA-building test
      (~500 of ~640), the pure tier (verdict ladder, guard
      comparison, provenance core, guidance, internal/*) as the
      default `go test -short ./...` in seconds; every fixture test
      redirects `SetMemoRoot` to a per-test temp dir (the suite writes
      the user's real effect-scan cache today — pipeline-audit
      gofresh.md §6); `t.Parallel()` on the child-process-bound
      fixture tier; a Taskfile with `test:short`, `test`, `vet`
      (gofresh is the one repo without one — folds gofresh
      docs/issues/reusable-ci-workflow.md's Taskfile half); CI runs
      the full tier at its measured budget. Measurement: none.
- [ ] 151. gomutant: self-test partition — `task test:short`
      (`go test -short ./...`, the 179 existing gates: ~436 of 615
      tests, no subprocess), `task test` unchanged as the merge gate,
      `task test:selfhost-plan` (`gomutant run --plan --targets
      testdata/self-host-targets.json` — the only cheap way to keep
      the self-host path from bit-rotting; made genuinely cheap and
      complete by 156); the stale `findings.json.campaign` /
      `.lock` residue removed. Measurement: none.
- [ ] 152. stipulator: self-test partition — finish the `Short()`
      gating in `internal/backends/golang` (245 tests, ~64 gates) so
      `go test -short ./...` is the seconds-class tier; `task
      test:short`; CI keeps the full tier; the dangling CI-seat
      pointer (`.github/workflows/ci.yaml:39` cites a
      docs/issues/ci-seat-for-the-check-verdict that does not exist)
      resolved — the check verdict's seat is the weekly sweep and the
      chunk close-out, stated where the pointer was. Measurement:
      none.
- [ ] 153. pew: self-test partition — the pure helpers of `cmd/pew`
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

- [ ] 154. gofresh: the observation pass gains a preparation pass,
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
- [ ] 155. stipulator: the prepared policy capture, the CLI reporter,
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
- [ ] 156. gomutant: the per-verb prepare stage and the reporter for
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
      gomutant docs/issues/staged-external-input-refuses-late-and-
      misnamed.md deletes at close). Freshness: one batched view set
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
- [ ] 157. pew: the package preparation record, the reporter, and
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
- [ ] 141. (converged 2026-09-02 — three review rounds, fourteen
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
- [ ] 138. gomutant: workspace-relative path resolution
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
- [ ] 146. FOLDED into chunk 156 (Band P, 2026-09-02): the staged
      snapshot's external-input refusal is one instance of the
      prepare-stage invariant 156 lands; the field report's doc rides
      156's close.
- [ ] 115. pew: verdict-surface batch (pew docs/issues:
      gitblob-linked-worktree-object-lookup — pew run fails in linked
      worktrees; ab-worktree-placement-escape — operator escape +
      startup sweep; verdict-ladder-shared-admissibility — the
      status/stat admissibility ladder collapses to one shared
      function with the per-side working-tree input) — three docs
      delete at close. RIDES: pew
      docs/issues/repo-level-vouch-source.md — a reviewed vouch file
      beside the store replaces hand-mirrored flag lists; doc deletes
      at close.
- [ ] 142. stipulator: clause-granular binding claims (bldc report
      2026-09-03; stipulator
      docs/issues/clause-granular-binding-claims.md) — a binding
      names the clause it witnesses (ordinal or spec-admitted label),
      and coverage reports the unclaimed clauses of an otherwise-bound
      requirement as a distinct "bound, clauses unclaimed" bucket —
      the consumer's own H-graded false-green channel retired
      upstream; doc deletes at close. Spec-format + coverage + both
      surfaces. Measurement surface: none.
- [ ] 143. stipulator: consent provenance (bldc report 2026-09-03;
      stipulator docs/issues/content-hash-function-versioning.md) — a
      hash-function move is its own recorded state ("rehash",
      bulk-re-pinnable without editorial consent) or the pin records
      the declaring document's blob hash beside the content hash, so
      a re-consent over unchanged text is self-evidently that. RIDES
      docs/issues/pin-req-unchanged-text-wording.md ("text unchanged;
      nothing to re-consent" over "pins current"). Both docs delete
      at close. Measurement surface: none.
- [ ] 144. stipulator: CLI query parity (bldc report 2026-09-03;
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
      doc deletes at close).

- [ ] 145. stipulator: spec-graph authoring (bldc reports 2026-09-03;
      stipulator docs/issues/refines-multiple-targets.md — refines
      admits a target list, canonical form ordering it, impact and
      coverage reading every edge — +
      docs/issues/supersede-removed-source-one-step.md — the
      removed-source supersede is one step: a dispose mode or compile
      admitting a supersedes edge into the tombstones-or-pending
      set). Both docs delete at close. Measurement surface: none.
- [ ] 136. cross-tool: retroactive automation-and-consolidation audit
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
- [ ] 91. gomutant: deferred-check-close adoption — the run-end and
      per-window producer validations run full in-process gofresh
      analysis (~25% of in-process CPU under repeated packages.Load);
      gofresh's deferred-close contract is the closing-cost lever; a
      design pass, then the adoption; history: `git log --all --
      docs/issues/post-completion-cpu-tail.md` (gomutant).
- [ ] 92. gomutant: fold the decision batch (maximal captures) and the
      observed proof union — two back-to-back full observation passes
      over the identical symbol set with the same engines; one
      observed union view set serving both roles halves the warm
      campaign's observation floor; also dispositions the
      strict/union view-build-loop duplication in freshness.go.
- [ ] 96. gomutant: concurrent ephemeral probe overrides — two
      concurrent probes' width/ceiling snapshot-restores can
      interleave (bounded, self-healing); either the probe claim goes
      exclusive or the interleaving is recorded as accepted.
- [ ] 129. gofresh: comment/format-insensitive closure identity — a
      closure identity insensitive to comments and formatting
      (caching axis: comment-only edits stop invalidating consumer
      evidence); chartered as the prerequisite gomutant's carry gate
      names (semantic-closure-in-the-carry-gate); release, then 130
      rides.
- [ ] 130. gomutant: semantic closure in the carry gate (gomutant
      docs/issues/semantic-closure-in-the-carry-gate.md) — adopt
      129's identity at both poles of the carry gate; doc deletes at
      close.
- [ ] 139. gomutant: delta-line survivor view (field-response,
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
      reader arms if the records shape moves.
- [ ] 131. stipulator: one identity walk, two windows (stipulator
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

- [ ] 116. gofresh: custom-FlagSet-scoped sink precision (was SEP
      0b2) — scope 0b's registration poison to registrations whose
      FlagSet (or the default set) can carry os.Args, via
      Parse-argument provenance; narrows 0b's fail-closed widening.
- [ ] 117. gofresh: call-shaped unaudited-std scan classes narrow per
      audit (was SEP 0f) — crypto/rand first; the general retirement
      of the unaudited-std scan arm is the band's endgame, not one
      chunk.
- [ ] 118. gofresh: benchmark-loop package-scan audit (was SEP 0d) —
      testing.Loop blocks every subject in a benchmark-bearing
      package; decide the class (admit as harness pacing like m.Run,
      or keep with the refusal naming the benchmark) — own audit.
- [ ] 119. gofresh: writer-sensitive fmt.Fprint startup
      classification (was SEP 1; ~1,096 in the charter histogram) —
      an init formatting into a provably-local pure sink is value
      computation. FOLDS at this chunk: gofresh
      docs/issues/audit-key-mechanism-consolidation.md (four parallel
      spellings of the audit lookup/refuse mechanism — this is the
      band's first audited-set change); doc deletes at close.
- [ ] 120. gofresh: math/big joins the audited-pure set (was SEP 2;
      ~505) — own audit.
- [ ] 121. gofresh: fixed-argument time construction audited (was SEP
      3; ~186) — Date/AddDate/Format read no clock; own audit.
- [ ] 122. gofresh: std init-closure exemption (was SEP 4; ~58) —
      synthetic init$N closures ride the toolchain guard as named
      init does.
- [ ] 123. gofresh: maximal-tier pure-shape selector audits (was SEP
      5; ~23) — net/url.Parse, time.Time, path/filepath.Ext.
- [ ] 124. gofresh: enumeration targets tightened (was SEP 10;
      gofresh docs/issues/enumeration-targets-over-approximated.md,
      already deleted — history in git). RIDES: gofresh
      docs/issues/range-over-func-yield-closure.md — admit the
      range-desugared yield callback as a closing caller and flip the
      corpus pin deliberately in the same change set; doc deletes at
      close.
- [ ] 125. gofresh: precision-band acceptance — re-run the charter
      sweep on the pinned field repro and record the
      observable-subject fraction against the 0.5% baseline (was SEP
      11).
- [ ] 98. gofresh: stateless-value escape discharge — zero-field
      struct values cannot be observably mutated through escaped
      aliases; justification re-bases at triage on the then-current
      measure (the original 285-witness class was discharged in-tree
      meanwhile); zero measured mass closes the chunk unbuilt. RIDES
      at this chunk (first reachability-scoping change of the band):
      gofresh docs/issues/unify-carrier-walks.md,
      unify-discharge-walks.md, binary-roots-single-mask-union.md —
      three docs delete at close. Release, then consumer bumps ride.
- [ ] 99. gofresh: guarded deterministic memoization discharge — the
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
- [ ] 100. gofresh: in-module scratch discharge — reads of a
      module-interior directory the test itself mints, writes, and
      removes classify as runtime inputs no bracket can cover and
      seal the observation; tugboat's .realseam-tmp WAL smoke tier
      was 129 witnesses (excluded as the interim); design reasoning:
      `git log --all --
      docs/issues/fresh-mutation-in-module-scratch.md`; triage
      re-derives against the then-current measure. Release, then
      consumer bumps ride.
- [ ] 101. gofresh: audited-construction discharge reaches carrier
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

## Band E — design chunks (open with the user)

- [ ] 15. pew: profile capture and attribution as recording
      companions (pew docs/issues/profile-capture-attribution.md and
      per-arm-noise-floors.md) — --profile captures per-arm cpu (and
      mem where B/op is claimed) evidence under the recording's
      provenance conjunction; status gains the attribution verdict,
      stat the profile-diff view; the noise-floor lineage keys on
      chunk 102's sliced closures. Opens with a user design
      discussion; 102 lands inside this chunk's arc.
- [ ] 102. gofresh: per-subject sliced closures — Fingerprint gains
      SlicedClosure (declaration-level hash over the subject's
      attributed-reachable set; widens to the maximal hash where
      attribution cannot bound, so slice-equal is never claimable
      without proven reachability; closure-equal implies
      slice-equal). Consumer: pew records pew-slice per arm; the
      noise-floor lineage classifies unreached-declaration commits as
      layout-only neighbors. Sequenced inside 15.
- [ ] 97. stipulator: cross-platform resolution views — a selection
      declaring GOOS/GOARCH off the host refuses by name today; the
      charter question is an on-host resolution-only view for
      cross-platform selections whose witnesses no on-host run can
      grant.
- [ ] 127. pew: observed-fingerprint recording path (pew
      docs/issues/observed-fingerprint-recording-path.md) —
      plain-Capture recordings leave every true-external-effect
      benchmark permanently unverifiable; adopt CaptureObserved per
      arm and retire §7.8's no-proof sentence; spec-level
      verdict-model change, opens with a design discussion; doc
      deletes at close.

## Ecosystem-blocked

- [ ] 95. gomutant: MCP Tasks adoption — protocol-level operation
      identity, polling, result retrieval after a client deadline,
      explicit cancellation. Opens by re-auditing the prerequisites
      that blocked it at chunk-41 time (SEP-2663 stable in go-sdk AND
      a consuming agent client that speaks it); history: `git log
      --all -- docs/issues/mcp-long-running-runs.md` (gomutant).
