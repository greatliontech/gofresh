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

## Execution order

User-confirmed 2026-08-26: 103, 107, 83, 108, 82, 94, 109, 110, 105,
126, 93, 106, then the UX pair 111, 112, then 128, 113, 114, 115, then
— amended 2026-08-27 under the field-response doctrine (bldc campaign
reports): 132 inserted after 83 (coverage integrity; lands before
108 so the canary corpus includes the shapes it fixes), 133 inserted
after 110 (same artifact, the findings document), 134 inserted after
133 (chartered 2026-08-27: enforcement pointers become bindings) —
then
91, 92, 96, then 129, 130, 131, then the precision/discharge band
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

## Band A — verdict integrity (correctness)

- [ ] 94. gomutant: line-directive position hazards — pre-existing
      sites read //line-adjusted positions where on-disk identity is
      meant: the _test.go suffix gates (enumerate, surface), the
      candidate catalog's source read (catalog.go fileOf +
      os.ReadFile — measuring ANY target in a //line file fails
      ENOENT on HEAD) and the survivor position anchors minted from
      adjusted names (candidate_edit.go). Audit and convert the
      remaining sites, with directive fixtures (the immune sites
      landed in chunk 40).
- [ ] 105. gomutant: structural-shaped probe provenance (gomutant
      docs/issues/structural-shaped-probe-provenance-gap.md) —
      structural shapes' probe content escapes dirty judgment and
      serve re-observation; close the stale-serve path; doc deletes
      at close.
- [ ] 126. gofresh: dst-tagged selections join the audit key (gofresh
      docs/issues/dst-tagged-selection-outside-audit-key.md) —
      dst-tagged build selections get default-selection audit
      admissions because the key cannot see tags; judged runs over
      dst-tagged selections are imminent (stipulator's build-tagged
      binding landed; tugboat's dst legs are the consumer); doc
      deletes at close.
- [ ] 93. cross-tool: parenthesized-receiver naming grammar — the
      shared receiver-naming convention (gofresh recvTypeName,
      gomutant's twin, stipulator's Go backend) cannot reduce the
      legal parenthesized receiver form, so such methods are
      unnameable everywhere; gofresh's purity scan additionally minted
      them as plain-function subjects. Extend the grammar with the
      ParenExpr unwrap in all three tools in lockstep, or record the
      unnameable form as contract.
- [ ] 106. gofresh: scalar-global cross-test mutation coverage
      (startup-effect-precision 0e, folded 2026-08-26) — the carrier
      net prices alias-handing carriers, and unsafe-mediated mutation
      of a NON-carrier scalar global evades it; verify how the class
      is covered (or price it) — the chunk-86 review's recorded
      adjacent residual.

## Band B — standing guards (the neglect-proofing layer)

- [ ] 109. cross-tool: weekly fleet health sweep — scheduled (cron)
      sweep over the machine's tool estate: store freshness (pew
      status), check summaries (stipulator), findings-document size
      and layer health (gomutant), binary provenance (installed
      binaries vs repo HEADs — the skew guards refuse loudly at use;
      the sweep catches drift before use), and shape-corpus version
      lag (each consumer's pinned gofresh vs the corpus's latest —
      content drift is unrepresentable, version lag is the one drift
      channel left); its report files field-response chunks per the
      standing doctrine.
- [ ] 110. gomutant: findings-document bounds (gomutant docs/issues:
      findings-doc-unbounded-growth — 70 MB after one campaign;
      findings-inspection-cost — inspection without re-judging,
      summary O(targets)) — bound, compact, and make inspection
      cheap; both docs delete at close.
- [ ] 133. gomutant: evidence pins travel (gomutant docs/issues:
      machine-local-evidence-pins — bldc 2026-08-27: absolute
      runtime-input paths and host-RAM-derived oracleMemoryBytes in
      evidence identity confine a committed findings document to the
      producing checkout, defeating the portable repo layer) —
      module-relative runtime-input path pins; split measurement
      identity from machine circumstance (the toolchain pin STAYS
      identity — provenance-refusal is deliberate; the RAM-derived
      ceiling moves to a machine-profile facet unless the ceiling
      demonstrably decided a verdict). Stated residual: the doc's
      "or a CI runner" case stays open BY DESIGN — the toolchain pin
      keeps cross-toolchain documents re-measuring (this fleet's godst
      vs CI's stock), and 133 delivers same-toolchain travel only;
      close-out promotes that refusal into the spec's provenance
      section, then the doc deletes.

## Band U — UX (MCP-first)

- [ ] 134. cross-tool: enforcement pointers become bindings —
      complete gomutant's stipulator adoption (manifest compiled,
      zero bindings authored): author tests-role bindings for every
      requirement's "enforced by" prose pointer (29 across
      execution/results/mcp/mutation), stipulator check joins the
      change-set gate, and the prose lists delete — spec prose states
      contracts, the binding store owns enforcement (stale pins
      refuse at check; prose lists drift silently — the two-places
      redundancy the structural gate collapses). The same sweep
      deletes gofresh's six residual prose pointers (purity.md,
      closure.md — adoption already full). pew ADOPTS (user ruling
      2026-08-27, timing and method delegated): manifest, corpus
      compile over pew's specs, and tests-role bindings land as this
      chunk's pew leg, check green before its change set ships.
- [ ] 111. cross-tool: tool-resident guidance — design chunk, opens
      with a short design pass (mechanism only; the ruling itself is
      settled): each tool answers "what does this verb do, what does
      this knob control, when do I use which" FROM the tool, over
      both surfaces, MCP-first — derived from the repo's own
      specs/docs at build or serve time (single source; a binding
      keeps served guidance and spec text from drifting), with
      per-verb examples and decision guidance ("use X when …, prefer
      Y when …"); the design names the shared shape all four tools
      implement, then per-tool adoption rides as its own commits
      inside this chunk's arc.
- [ ] 112. cross-tool: MCP surface audit against the sharpened
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

- [ ] 128. gomutant: serve carve-out consolidation (gomutant
      docs/issues: fold-growth-into-generalized-drift,
      consolidate-reidentification-and-bucket-policy) — growth is a
      strict special case of generalized drift; one re-identification
      helper, one advisory-bucket policy; same subsystem as the
      landed 103 (gomutant 2ba8841), whose windowScores bundle and
      newSurvivor/carrySurvivor constructors are the shapes the
      consolidation builds on; both docs delete at close.
- [ ] 113. gomutant: ergonomics and robustness batch (gomutant
      docs/issues: graceful-interrupt-persistence,
      refusal-exit-collapse, coverage-guided-oracle-ordering,
      campaign-refuses-tree-change-from-rapid-failfiles,
      staged-campaign-reports-clean-index-as-drift,
      symbol-cutter-duality, planonly-gatherwindow-suite-hang — the
      hang needs a mechanism-showing dump or closes unreproducible at
      triage) — seven docs delete at close.
- [ ] 114. stipulator: runner-environment inspectability (stipulator
      docs/issues/witness-runner-environment-divergence.md) — a
      witness red only inside the runner dumps the divergence (env
      delta, cwd, limits) so the correlated variable is identified,
      not guessed; doc deletes at close. FOLDS stipulator
      docs/issues/timeout-kill-attribution.md — a
      harness-timeout kill's red names the exhausted budget, not the
      unlucky test; same diagnostics class, doc deletes at close.
- [ ] 115. pew: verdict-surface batch (pew docs/issues:
      gitblob-linked-worktree-object-lookup — pew run fails in linked
      worktrees; ab-worktree-placement-escape — operator escape +
      startup sweep; verdict-ladder-shared-admissibility — the
      status/stat admissibility ladder collapses to one shared
      function with the per-side working-tree input) — three docs
      delete at close.
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
