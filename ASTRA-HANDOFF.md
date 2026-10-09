# Consolidated tooling migration — consume, discuss, then delete

Written 2026-10-09 for the next **Astra** session on the destination machine.
This is a temporary transfer artifact, not a new Spec or Plan. It supersedes the
ordering of the older `handoff.md`, while retaining that file's technical inputs.

## First instruction: orient and return to the user

You are to become the **single tooling owner** for gofresh, Pew, Gomutant,
Stipulator, and the relevant godst toolchain work. Consolidate the two previous
sessions into one trajectory. Subagents are authorized for exploration,
implementation and independent review; reviewers remain read-only. Do not run a
second independent tooling train beside your own.

**This session's performance-evidence trajectory takes priority over the other
agent's cross-tool train.** The user explicitly requested that you first consume
both handoffs, inspect destination/remote state, and tell them the merged,
consolidated trajectory. Then **stop for discussion**: they want to decide
whether to replan or simply start. Do not begin implementation, tests, mutation
campaigns, releases, toolchain installation, or broad verification before that
conversation. Lightweight Git inspection and reading are sufficient for arrival.

The migration was requested because this machine was continuously CPU-saturated.
Do not immediately recreate that load on the destination. Propose how one owner
will sequence heavy work, respecting the destination's other sessions and locks.

## Transfer map

Repositories are siblings under `github.com/greatliontech/`; derive their actual
destination paths rather than assuming the source machine's home directory.

| Repository | Branch to fetch/use | Transfer contents |
|---|---|---|
| gofresh | `migration/astra-tooling-consolidation` | This handoff and WIP locality/record-only-support APIs, including the latest review fixes and provisional bindings |
| pew | `migration/astra-tooling-consolidation` | WIP `cmd/pew/observation_property_test.go` |
| gomutant | `main` | Published observation adapter, child-coverage defect issue, and incoming moved-bracket re-key rider |
| stipulator | `main` | Published adapter and the other agent's requirement decomposition/memory report |
| godst | `main` and release tags | Other agent's harness repair/release work; recheck live state |

Both migration branches are **checkpoint branches, not release-ready changes**.
Do not merge them blindly to main or install binaries from them. Keep their WIP
commit messages and verification caveats until the normal review/gates converge.
Fetch before checkout. Inspect any destination dirty work or unpublished commits
before switching/rebasing; never overwrite the other session's local residue.
If a local branch already exists, inspect it rather than resetting it.

Checkpoint identifiers at writing:

- gofresh `5bf9023`: locality/record-support checkpoint atop upstream `18b828b`.
  The branch also adds this file in a subsequent documentation commit.
- Pew `1f8df13`: property-test checkpoint atop upstream `34d9cc8`.
- Gomutant `78fbb1b`: latest fetched main, clean locally.
- Stipulator `80d41a4`: latest fetched main, clean locally.

All completed implementation work from this session is already on public main
branches. No extra checkpoint branches were needed for Gomutant or Stipulator.
The source gofresh stash `ffa5e1569226213f5503399c8528986abd5afdea` is a local
pre-integration recovery copy only; the migration branch carries the restored
work and does not require that stash on the destination. The earlier checkpoint
hashes `ca5ff06` and `75403ab` were superseded by local rebases before publication.

## Primary trajectory: finish Pew's whole performance-evidence plan

Authority: `pew/docs/specs/spec.md`, shared gofresh specs, and
`pew/docs/plans/performance-evidence.md`. The user repeatedly rejected stopping
at intermediate milestones: after the arrival discussion authorizes resumption,
complete the agreed roadmap rather than requesting another go-ahead per chunk.
Do not silently drop difficult obligations or shrink contracts to match code.

Chunks 1–10 are closed in the roadmap. Chunk 11 implementation is published and
its review converged; its root/11.3 checkboxes still need close-out reconciliation.
CI **37930913545** succeeded for `a41d8ee`; release **v0.8.0** exists. Do not
redo the implementation merely because those two boxes remain unchecked.

Important completed boundaries:

| Repository / commit | Delivered |
|---|---|
| gofresh `e7df801`, v0.112.1 | Separate normal completion and independently prepared outcome support; honest identity-only finalization and its reason |
| Pew `50646e7`, v0.5.1 | Native gofresh fingerprint payload; no parallel field-by-field persisted owner |
| gofresh `067717f`, v0.112.2 | Binding-aware inert-growth classification: predeclared-name shadowing and import rebinding cannot masquerade as inert; base-file evidence included |
| gofresh `022f06b`, v0.113.0 | Durable applicability endpoint separate from immutable producing fingerprint; original support preserved through repeated extension/restart |
| Pew `35ad290`, v0.6.0 | Invocation-owned vouches/environment/preparation; unified current-tree observed judgments; exact attached arm fingerprint publication |
| Pew `a8570ae`, v0.7.0 | Typed coverage/dispositions, optional complete/freshness/conditions policies, historical side identity, recording-level audits, numeric admission |
| Pew `9c39708`, v0.7.1 | Separate CPU/allocation diagnostics, native evidence, immutable objects, serialized exact-byte attachment, independent integrity/freshness/relation/attribution |
| Pew `a41d8ee`, v0.8.0 | Ref-pinned historical profiles; both-side A/B diagnostics; invocation-wide benchmark-format artifact; contained Git lifecycle; both-side selected-input output protection |

Current recording format is **5**; A/B artifact format is **`pew-ab: 2`**.
Final numbering/reset belongs to chunk 12 after schema stability, not a premature
mechanical reset. Clean regeneration-only cutovers were authorized. The approved
third-party profile dependency is already pinned; do not ask for it again.

Source-machine installed Pew binaries were verified at release v0.7.0, not v0.8.0.
Destination installations must be inspected independently. Source builds used
`go1.27.1-X:nodwarf5 linux/amd64`; never assume the destination shares its audited
toolchain, source digests, caches, or installed tool binaries.

## In-flight gofresh change: locality and record-only support

Read the branch diff against main and the canonical requirements before changing
it. Primary files: `coverage_locality.go`, `recorded_support.go`, their tests,
`closure/observability.go`, `closure/outcomes_test.go`, `runtimeinput/outcome.go`,
`view.go`, `view_test.go`, three specs and three binding files.

1. `View.CaptureCoverageLocality(ctx)` returns a typed, identity-bound static
   disposition for each selected subject. It admits only audited **empty external
   effect** inventories plus admitted harness operations; all environment reads
   are refused. Caller vouches/single-subject/package-process discharges do not
   establish locality. Initialization/TestMain/callbacks participate. Validation
   and sibling inheritance retain the obligation.
2. `ValidateRecordedObservationSupport(fp, subject)` and
   `runtimeinput.ValidateRecordedSupport` validate compatible native proof,
   original producing-subject membership, recognized method, canonical manifest,
   refusal absence, and aggregate digest **from recorded entries**. They perform
   no current-file/environment observation and make no authenticity/freshness
   claim. Purity is not native verified support.
3. `CoverageLocalityStrategy` is `gofresh/coverage-locality@1`.
   `ObservationRTA` changes **@41 → @42**, because the projection shares the
   current memo. This also invalidates older persisted observation proofs; the
   pending memo/proof version split was not assumed already implemented.

Review status is **not converged after the latest fixes**:

- First review found mixed locality+observed validation performed analysis before
  an already-known missing-attachment refusal; fixed by shared preparation and
  one current validation view/proof pass, preserving observed runtime checks.
- Direct caller-discharge rejection lacked a discriminating witness; added each
  nonempty-discharge control and a real package-process/sibling anchor.
- New tests assert zero observation before missing-attachment refusal, exactly
  one analysis/two runtime reads for mixed completed selection, and closing drift.
- These fixes passed focused/race/short checks and three specific mutation probes
  according to their author. Earlier task check, two fuzz drivers and five probes
  passed. The pre-fix full suite hit 30 minutes in root/closure; both passed a
  later 90-minute allowance, other packages passed the first run.
- **The post-fix full root rerun was user-aborted. It is not a pass.** Do not
  restart it during arrival. No post-merge executable verification exists.
- Bindings predate the final validation collapse. In particular inspect/repair
  the claim naming removed `View.validateCoverageLocality`, and bind the new mixed
  validation/discharge witnesses. The last attempted records-agent follow-up did
  not launch. Do not report the earlier 23-current scoped check as current proof.

Integration already performed on the source machine: upstream 315 work was
fast-forwarded through `96252a5`, local changes reapplied, and additive conflicts
in `.stipulator/bindings/{closure,inputs}.textproto` resolved retaining both claim
sets. Specs auto-merged. Then the checkpoint rebased onto `a5b44b3` (handoff-only
update). Diff whitespace passes; content pins and new harness-premise interactions
still need fresh inspection/verification on the destination. A further rebase
onto `18b828b` incorporated the stale-base release update, again handoff-only.

## In-flight Pew witness

`cmd/pew/observation_property_test.go` directly invokes `testing/quick.Check`:
20 deterministic generated draws × 18 premise modes, with randomized environment
and log ordering/multiplicity. Native engine-issued support supplies a mandatory
positive control. Missing/mismatched frame/process/environment/completion/support,
wrong subject, duplicate keys, absent logs, abnormal completion, cancellation,
identity-only lanes and process-identity merge conflicts are exercised.

The logs and terminal judgments are generated; this is not an OS process-exit
test. Preserve that limit. Author reports named test, short suite, and three
mutation kills. **Independent review, requirement binding/classification and
integration with the new gofresh version remain pending.** Do not delete
`pew/docs/issues/observation-premise-property-evidence.md` on presence alone.

## Remaining chunk 12 work, in dependency order

### A. Make Gomutant negative-coverage admission sound

Owning issue: `gomutant/docs/issues/child-coverage-cannot-authorize-negative-exemptions.md`.
The current parent `-coverprofile` misses a self-reexecuting child's counters.
With another in-process reaching batch, the child-owning killer is wrongly
exempted. A real full-oracle audit flipped a narrowed survivor to killed.
This differs from a subprocess rebuilding unmutated disk sources: Pew executes
the actual mutated test binary through `os.Executable()`.

Do not simply set `GOCOVERDIR`: Go 1.27 testing teardown without
`-test.gocoverdir` uses and removes a private directory. Child polling cannot
prove absence. Do not remove integration tests, add purity vouches, or attest
inequivalent mutants to make campaigns green.

The planned conjunction uses the new static locality API, actual selected roots
and normally finalized coverage under an admitted harness, sound coordinates,
and **candidate-specific execution influence**. Unknown negatives restore the
whole oracle group; positive spans remain useful. Pure arithmetic must still
have an admitted narrowing control. Two additional counterexamples from design
review must be implemented as real regressions, not merely documented:

- `TestKills` skips when `os.Getenv("GOCOVERDIR") != ""`; a separate reaching
  test calls the target without checking its answer. Coverage and scored
  environments differ. This is why the locality subset rejects **all env reads**.
- `func Value(jump bool) int { if jump { goto done }; const n = 1; done: return n }`.
  A killer calling `Value(true)` skips the mutated const declaration's coverage
  block but observes its compile-time effect. Force whole-group execution for
  candidates in compile-time contexts without an influence guarantee; do not
  drop those mutants. Locality alone cannot fix this.

Bank v2 and findings v14 were the inspected versions; inspect actual versions
before modifying. Old negative evidence and old findings must not serve through
exact reuse, budget extension, carry/splice, or machine-local overlays. A document
version bump alone is insufficient when decoding upgrades old records. Admit the
actual coverage harness/instrumentation separately from the static locality
component. Preserve the existing explicitly accepted runtime-dependent sampling
risk; do not silently strengthen its stated guarantee.

### B. Complete and review the observation-premise property witness

Use the checkpoint above. A prior agent accidentally ran `stipulator check --full`
despite the scoped-only instruction; the overall result was red because the
existing invariant had only example-class evidence. Passing examples and
records-only hygiene do not establish the property evidence class. Do not weaken
the invariant, its tests, or its binding role to obtain green.

### C. Implement per-arm historical floors

Authority/deferral: `pew/docs/issues/per-arm-noise-floors.md`. A read-only design
was developed but **no code or approved canonical contract amendment exists**.
Present the design in the arrival discussion before treating it as settled:

- Proposed opt-in `--noise-floor=history|off`, default off, preserving existing
  regression defaults. Applied bar `max(global threshold, historical floor)`.
- Descriptive admitted-history envelope, **not** proof of harmless noise or a
  confidence bound: `100*(max(center)/min(center)-1)`. Minimum two distinct sample
  contents and two measured commits; no arbitrary top-N/window/sample cap.
- Pin baseline ref once; traverse all reachable parents and exact recording-path
  history. No candidate-only descendants/worktree training. Incomplete/shallow
  history cannot yield a prefix-derived floor. Existing gitblob lacks the needed
  full history reader.
- Exact row/config/unit and producing-fingerprint lineage; applicability refresh
  does not create a new timing observation or merge producing variants. Dedup
  reordered/copied samples, refresh-only changes and profile attachments. Missing
  capture UUID/budget remains unknown, never independent-run evidence.
- Candidate overlap with training history causes explicit fallback. Native support
  admission uses record-only API; explicit purity is a separate asserted lane;
  unsupported evidence without that premise cannot train suppression.
- All-zero history yields zero; mixed zero/positive or overflow yields global
  fallback. Preserve zero-baseline regression rules. Conditions/coverage policies
  remain orthogonal. Report applied bar, history counts/dispositions/completeness,
  trust lane and whether a global-threshold regression was suppressed.
- A true regression within a historical envelope can be suppressed; show this
  tradeoff, never call it proved noise. Maximal source closure limits how many
  layout-only neighbors actually share a lineage.

### D. Finish workflow surfaces, guidance and format settlement

Read `pew/docs/issues/{mcp-surface,guidance-purpose-column-second-enumeration}.md`
and the remaining handoff riders. Comparison text/JSON parity is delivered.
`run`/`ab`/`gc` machine-readable/progress scope and a whole MCP surface are not
implicitly authorized by that fact; discuss genuine product choices rather than
silently filing or implementing them. Spec purpose/default requirements remain
authoritative when consolidating duplicate guidance prose.

Final format numbering/reset, clean-baseline workflow, all remaining issue/gap
triage, evidence campaign and final installs must close before deleting the Pew
plan. Never replace unfinished work with a checkmark or an aspirational trigger.

### E. Remeasure honestly, then return to git-go

`pew/docs/issues/mutation-oracle-observation.md` inventories incomplete campaigns
and bounded scope. Last substantive subset: run `e8423761e551fb96`, 16 generated,
15 killed, one false-false `gc.go:41:5` survivor attributable to unsound child
coverage; named hand probe kills it. Two duplicate early admission-loop mutations
were genuinely equivalent and attested. These machine-local records, prior kills
and temporary probe JSON are **not transferred as reusable evidence**.

After the shared fix, remeasure the required current selections with sound full
oracles and disposition survivors. Do not repeat repeated 30-minute baseline-only
attempts and call the final gate done. Reconcile stale/deleted targets and actual
scope explicitly. Heavy work must be scheduled rather than launched as concurrent
unbounded full suites.

Only after the complete agreed tooling roadmap closes, resume git-go:
`git-go/docs/plans/object-snapshot.md` (12 chunks), architecture note and specs.
Source git-go is at `086d3b7`, **has no remote**, and has preexisting untracked
`.gomutant/`. No git-go implementation changed in this session and no transfer
branch was invented for it. Destination availability/transport must be resolved
with the user before resuming. Public capabilities must not require Git strings
or ASTs, no stubs, SHA-1DC dependency choice remains pending. Reference Git on the
source machine was v2.56.0, not guaranteed present on destination.

## Merge in the other agent's lane without changing priority

Read `handoff.md`, `handoff/design338.md`, and the helpers as **inputs**, not
commands to execute blindly. Their outstanding narrow prerequisite is godst 338:
port the repaired test-log writer to the required upstream Go patch, complete its
release, and audit/re-list its dst selections in gofresh. This is now a separate
fork-port change set, not just a release retry. Discuss its ordering with the user;
it may be a prerequisite if the destination changes its running toolchain, but
does not authorize resuming the entire secondary train first.

Updated live snapshot at writing (recheck on arrival; the other agent was active):

- godst fix `6a6db7c`: matrix **37949379157** and CI **37949347772** succeeded.
- Release commit **`a91cc85`** and annotated tag `go1.27.1-dst.14` were pushed,
  but release workflow **37952542400 failed the stale-base gate**: upstream is
  Go 1.27.2 while the fork's base is Go 1.27.1. The tag consumes counter 14 but
  has no release assets. Main **`b1db1f1e6140bf1c893696bfaade180eff8d32aa`**
  reverts only the VERSION release commit to dst.13; the harness fix remains.
  The release-commit CI was cancelled, and revert CI **37952853139** was running.
- **dst.15 is planned, not released at this check.** Per the updated handoff,
  first port main to Go 1.27.2 using the fork's port/verify/audit/check procedure,
  review the upstream intercepted-surface diff and pass the matrix, then cut
  **`go1.27.2-dst.15`**, subject to a fresh scan of all consumed tag counters.
  Do not retag dead dst.14 or just retry it over the stale base. GitHub still lists
  dst.13 latest. Recheck remotes/workflows before doing anything: the other agent
  was updating this state during migration.
- gofresh main includes 315's audited testdeps/harness premise, cancellable source
  digest traversal, and exported `CanonicalMovedBracketClause`; **v0.115.0** exists.
  Latest incoming handoff update is **`18b828b`**, explaining the failed release,
  VERSION revert, and not-yet-started Go 1.27.2 port.
- dst selections remain unlisted until the valid repaired build is installed and
  its exact selection digests audited. Never invent row digests or infer safe
  completion from an exit-zero log whose writes might have been dropped.
- The older design/helper files and even some row examples in `handoff.md` still
  contain hardcoded dst.14/Go 1.27.1 assumptions. The latest release-state section
  overrides them: the real repaired release needs Go 1.27.2 root rows (stock too),
  its actual dst counter and selection deltas, and measured digests throughout.
- Helpers contain old data paths and mutation
  snippets. `insertrows.py` reads `handoff/m315/rows-*.txt`, which are not supplied
  by this transfer. Use it as a shape reference, not a runnable complete recipe.
  Translate required edits through the normal editing/review workflow.

Preserve the secondary train after the primary roadmap, with prerequisite riders
folded only where justified: Gomutant 302 (includes moved-bracket root clause
re-key through gofresh's exported function), Stipulator 226, gofresh 330,
Gomutant 187, Stipulator 249, gofresh 240, then the current train order. Do not
lose `stipulator/docs/issues/discovery-exit137-memory-target.md` (incoming field
report, `Lands: user decision` needing a genuine-fork audit). Stipulator 270's
requirement decomposition is published; bind against current IDs rather than old
mega-requirement spellings. All four tooling remotes were fetched before this
checkpoint; fetch again before new work and pushes.

## Execution and evidence rules to preserve

- Heavy tests/builds/vet/generation/probes/verification use `mlock run`; only real
  statistical measurements use `mlock quiet`. Do not diagnose elapsed shared-lock
  test timings as performance evidence. Honor destination machine-sharing rules.
- Use normal Go suites/task gates plus **scoped records-only Stipulator checks**.
  **No broad Stipulator witness runs** were authorized in this trajectory. The
  accidental broad run is not precedent. When resolving evidence classification,
  inspect the exact needed claim and agree any additional execution scope.
- Main owns integration, specs, findings and campaigns. Each change set gets
  independent read-only adversarial review to zero new findings. Latest locality
  fixes and the merged upstream changes still need that review.
- Normally completed failing tests may supply completion receipts; panic/fatal/
  timeout may not. Completion, outcomes, health, source proof, identity guards,
  explicit purity and reusable evidence are distinct. Profiling instrumentation
  presently has no admitted outcome model and uses identity-only capture.
- Original producing evidence is immutable; applicability requires its explicit
  native transformation and all remaining guard checks. Do not reconstruct past
  support from current analysis, health, rehashing or decoding.
- No installed binary should come from unfinished migration branches. Check
  module version/checksum or VCS revision and clean-tree status as applicable.
- User authorized migration branch checkpoint commits/pushes despite unfinished
  review. That is not permission to claim release-quality verification.

## Arrival report and disposal

After reading and lightweight reconciliation, tell the user:

1. Which branches/commits and destination-only changes you found.
2. What is already released versus checkpointed or only designed.
3. A proposed single dependency-ordered trajectory, with Pew chunk 12 first and
   secondary train obligations retained; name any toolchain prerequisite.
4. The real decisions (noise-floor policy, remaining machine-reader scope,
   schedule/resource limits, git-go transport), not a request to reapprove
   already approved dependencies or completed cutovers.
5. Verification still owed, especially the aborted post-fix test and post-merge
   bindings/review. Then **wait for discussion and explicit resumption**.

Once the user has discussed/accepted the consolidated trajectory and all useful
details are represented in canonical specs, existing plan checkboxes or properly
slotted issue docs, delete **this file**, the older `handoff.md`, and the obsolete
`handoff/` helpers. Do not delete them before destination capture, and do not keep
them as permanent history: their commits are the recovery record. Preserve any
genuinely needed helper until its data/design is transferred or its step completes.
