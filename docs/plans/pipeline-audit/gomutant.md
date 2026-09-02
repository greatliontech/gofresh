# gomutant — pipeline, reporting, knob, and self-test audit (2026-09-02)

Cost classes: **C** cheap · **L** typed package load (plus gofresh view construction) · **P** process execution.

## 1. Operations inventory

| operation | entry point | stages in order | persisted / when | interruption loses |
|---|---|---|---|---|
| `run` (CLI) | `internal/cmd/run.go:76` | 1 flag validation, timeout/oracle-timeout only (C) · 2 `LoadContextSelection` (L) `run.go:108` · 3 parse scratch-namespaces + vouches (C) `:112,:117` · 4 discovery: `DiscoverContext` / `DiscoverChangedContext` + `gitref` (L+P) `:141-155` · 5 `FilterTargets` (C) · 6 campaign lock (C) `:170` · 7 exemptions + store open + prior findings (C) `:175-183` · 8 `OracleClosureSignpost` — whole-document freshness pass (L, per prior record) `:187` · 9 `Tree.Run` resolve loop (L) `run.go:1671-1900` · 10 decision-view union (L) `run.go:1904` · 11 per-target prepare: producer observed union (P) `run.go:2629`, candidate gen (C), bracket preflight (C) `:2861`, group baselines (P) `:2883` · 12 window: coverage probes (P) `run.go:3143`, estimate, mutant pool (P), serial confirmation (P), narrowed-survivor audit (P) · 13 aggregate + splice + provenance stamp · 14 final merge `run.go:454` | **per finished target**: `Commit` → `Store.Update` whole-document rewrite (`internal/cmd/run.go:398`, `store.go:382`). Baseline bank deposits persist immediately (`bank.go:186,214`). | one window's in-flight candidates (SIGINT drains the dispatched prefix and commits it candidate-capped, `run.go:3283-3311`); with a hard cancel, the current window's uncommitted targets |
| `run` (MCP) | `internal/mcpserver/server.go:742` | same, plus width claim first (C) `:753`; lock at `:838`; signpost at `:806` | identical (`server.go:930`) | identical |
| `ephemeral` (CLI) | `internal/cmd/ephemeral.go:48` | 1 flag/form checks (C) · 2 batch parse (C) · 3 `LoadContextSelection` (L) `:97` · 4 edit resolution + identity/no-op checks (C) `ephemeral.go:161-176` · 5 gates: `HasPackage`, `BuildCompilesFile`, `LinkedTestPackages` (C+L) `ephemeral.go:365-393` · 6 rapid detection (P) · 7 **baseline probe** (P, ≤10 m leash `ephemeral.go:239`) · 8 N mutant runs (P) · 9 **coverage probe** (P, ≤10 m leash; ~2 h measured on this repo's face) `:494` · 10 optional attest (C) | nothing until step 10 | everything — no probe result is persisted |
| `ephemeral` (MCP) | `server.go:1828` | same, plus probe-override claim (C) `:1848` | same | same |
| `discover` | `internal/cmd/discover.go:76` / `server.go:1196` | `LoadContextSelection` (L) · flag-combination refusal (C) `discover.go:85` · discovery (L+P) · filter · `DescribeTargets` (L) | nothing | everything |
| `findings --judge` | `internal/cmd/findings.go:71` / `server.go:1321` | state-filter check (C) `:72` · store load (C) · `LoadContextSelection` (L) · **per record** `InspectFindingContext` (L, builds its own view set) `freshness.go:820,:923` | nothing | everything |
| `explain` (MCP only) | `server.go:1501` | store load · load tree (L) · one `InspectFindingContext` (L), or the document arm (C) | nothing | everything |
| `attest` / `attest_survivor` | `internal/cmd/attest.go:35` / `server.go:1657` | toolchain provenance (C) `attest.go:42` · store update (C) `:50` · **then** load tree (L) + inspect (L) for the advisory echo | the disposition at `:50`, before the slow echo | only the echo |
| `prune` | `internal/cmd/lifecycle.go:33` / `server.go:1729` | store open · load tree (L) · `PackagesHealthy` + `DeclaredSymbols` (L) · one document update | whole document, once `lifecycle.go:81` | everything |
| `retarget` | `internal/cmd/lifecycle.go:89` / `server.go:1774` | store open · load tree (L) `:94` · six prefix-shape refusals (C) `lifecycle.go:332-373` · `DeclaredSymbols` (L) · one document update | whole document, once | everything |

## 2. Late refusals (defects against the ruling)

| refusal | derived at | fires in | earliest inputs exist | cost wasted | remedy sketch |
|---|---|---|---|---|---|
| "a campaign already holds `<doc>`" | `campaignlock_unix.go:31` | run stage 6 (`cmd/run.go:170`; MCP `server.go:838`) | flag parse (`run.go:53,66`) | full typed load + discovery + filter (+ MCP: prior load + signpost) — minutes; the spec says "refuses immediately" (`docs/specs/execution.md:920`) | acquire the lock right after flag parse |
| "budget must be non-negative" | `run.go:1570` | `Tree.Run` entry, after stages 2-8 | flag parse | typed load, discovery, filter, lock, exemptions, store, prior load, signpost | validate beside the negative-duration checks at `cmd/run.go:77-82` and in `toolRun` |
| "bracket path `<p>` does not exist at run start" / "preflight failed" | `run.go:1542,1559` | per-module group formation `run.go:2861` (shaped lane `:2405`) — after the observed producer union (`run.go:2629`) and, for a second workspace module, after earlier windows executed | declared paths at `cmd/run.go:59`; module roots at load (`gomutant.go:398`) | an observed-union pass; potentially a module's measurement. `--plan` never reaches it (`run.go:2825` precedes it) | hoist into `Tree.Run`'s entry beside `validateBracketPaths` (`run.go:1586`) |
| "`<pat>` matched no tests in `<pkg>`" | `ephemeral.go:418` | after the baseline probe (≤10 m) | the loaded package set — sibling gates at `ephemeral.go:365-393` use the same data | one full oracle process | enumerate test functions and match the regex in the gate block |
| "an equivalence attestation needs its reasoning on the record" | `ephemeralattest.go:102` | after baseline + N mutant runs + coverage probe | flag parse | the entire probe — hours on this repo's face | trim-check the reason beside the form checks |
| "give --targets or --changed, not both" | `internal/cmd/discover.go:85` | after `LoadContextSelection` | flag parse | full typed load. `run` never refuses the pair at all — `cmd/run.go:125-155` silently prefers `--targets` | move above the load; add the refusal to `run` |
| scratch-namespace / vouch parse errors | `gomutant.go:313,334` | `cmd/run.go:112,117`, after the load | flag parse; the help text promises "malformed declarations refuse before any measurement" | full typed load | parse before `LoadContextSelection` |
| malformed exemptions document | `exemptions.go:56,59` | `cmd/run.go:175` / `server.go:886`, after load+discovery+lock | file at startup | typed load + discovery | load exemptions and open the store first |
| unreadable/version-ahead findings document | `store.go:92` | `cmd/run.go:179-183` | file at startup | typed load + discovery | same hoist |
| six retarget prefix-shape refusals | `lifecycle.go:332-373` | after `LoadContextSelection` | flag parse — pure predicates on two strings | full typed load (tree first needed at `:376`) | `ValidateRetargetPair(from,to)` before the load on both faces |
| "runs must be between 1 and 10" | `ephemeral.go:358` | after `LoadContextSelection` (`cmd/ephemeral.go:97`) | flag parse; MCP already checks pre-load (`server.go:1885`) | full typed load | mirror into `cmd/ephemeral.go` |
| "unstaged drift … (measured input outside the repository: …)" | `provenance.go:125` via `stampProvenance`'s staged arm | per target, after measurement | the observation exists before the first mutant | field-measured **50 minutes**, every target refused | filed: `docs/issues/staged-external-input-refuses-late-and-misnamed.md` |

Correctly early, the pattern to generalise: `findings`' state-filter check (`findings.go:72`) and `attest`'s toolchain-provenance guard before the write (`attest.go:42`).

## 3. Progress and reporting

**`run`, CLI — the strongest surface in the repo.** `prepare loading` once (`cmd/run.go:106`), per-target `resolving`/`freshness`/`mutants`/`baseline`/`oracle-budget` events (`renderPreparation`, `:628`), one decision line per target naming *why* (`renderRunDecision`, `:731`): `measure … (stale: …)`, `cached … (served: …)`, `skipped … (oracle baseline does not pass)`. Execution adds `executing`/`confirming`/`estimate`/`audit`/`confirmation-flip` (`:648`); per-candidate ticks feed a cadenced line every 30 s with targets committed, candidates done/total, kills, open, elapsed and a measured-pace `est ~Xh remaining` (`report.go:265,283`). A 10 s analysis heartbeat names the gofresh phase (`cmd/run.go:346`, `report.go:361`).

Silent stretches in CLI `run`: load + discovery + filter (`cmd/run.go:108-157`) — the cadence has not started (`:164`); MCP covers this with `withHeartbeat(…, "loading tree", …)` (`server.go:790`), the CLI has no equivalent. `OracleClosureSignpostContext` (`cmd/run.go:187` → `gomutant.go:508`) — one `InspectFindingContext` per prior record not in the target set, each building its own view set; the cadence reports `0/N … candidates 0/0` with no phase name. The window's coverage-probe phase (`run.go:3143` → `schedule.go:250`) — serial, before the `estimate` event and any tick; **~2 h** measured for window 1 here (`docs/issues/probe-phase-cost-invisible.md`). `validateProducers` (`run.go:4038`) runs unannounced.

**Interruption — best-in-class.** First SIGINT: `interrupt - draining in-flight mutants and committing measured prefixes; interrupt again to cancel hard` (`cmd/run.go:282`); the drained window commits candidate-capped prefixes (`run.go:3283`); the exit line names the cause and exactly what the document holds (`report.go:200,325`). SIGTERM arms a 5 s drain deadline (`internal/cmd/interrupt.go:24`).

**`run`, MCP.** Same events as notifications with a token, plus a 20 s `still working: <phase> (<elapsed>)` heartbeat (`server.go:1002`). Without a token, nothing streams.

**`ephemeral`, CLI.** Zero output until the verdict (`cmd/ephemeral.go:143`). Baseline probe (≤10 m), N mutant runs, coverage probe (~2 h measured) all silent. No interruption summary. MCP gets `prepare loading`, `running <pkg>`, the 20 s heartbeat (`server.go:1919-1934`); "the ephemeral library path exposes no per-step callbacks". The largest face asymmetry in the repo.

**`findings --judge`, CLI.** No output during a stretch its own help calls "minutes-class" (`findings.go:63`); no callback seam at `findings.go:243`. MCP: one `inspecting N record(s)` line and the heartbeat, no per-record tick. `explain` on a symbol has the same shape.

**`prune` / `retarget` / `discover`.** Silent through the typed load on the CLI; MCP wraps the load in `withHeartbeat`.

## 4. Incrementality and freshness

| operation | unit of freshness | vs expensive setup | unit of persistence | resumes prefix? |
|---|---|---|---|---|
| `run` | per target: body hash + operator set + oracle test closures + observed runtime inputs + toolchain/build config + timeout/memory pins + property regime (`evidenceSetMatchesContext`, `run.go:2612`); three carve-outs (`run.go:2645-2698`) | **after** the whole-tree typed load and the decision-view set (`run.go:1904`); **before** the observed producer union (`run.go:2629`) — a fully-cached warm run pays no observation pass: the deliberate lazy seam | one finding per `Store.Update` (`cmd/run.go:398`); bank entries at deposit (`bank.go:186,214`) | yes |
| oracle group baseline | `baselineKey` scoped by bracket paths and scratch namespaces (`bank.go:354`); pins re-verified (`bankPinsHold`) | before the probe (`run.go:2135`) | machine-local `baselines.json`, per deposit | yes |
| coverage/schedule probe | group oracle closure rows + covered package row (`schedule.go:281`) | before the probe batches | banked per group (`schedule.go:311`) | yes |
| `ephemeral` | none — every probe re-measures from scratch | n/a | nothing | no |
| `findings --judge` / `explain` | per record, same predicate as `run` | after the typed load; **each record builds its own view set** (`freshness.go:920-926`, `prebuilt == nil`) | n/a | n/a |
| `prune` / `retarget` | `DeclaredSymbols` membership | after the load | whole document, once | n/a |

Whole-run results written only at the end: the final merge (`cmd/run.go:454`) and plan-mode (persists nothing by contract) — both deliberate.

Three real gaps: (1) **`InspectFindingContext` has no batching** — `run` solved this with one observed union ("replaces the per-target proof builds … ~270 observation passes per warm campaign", `run.go:2016`) and the inspection path never got it; the seam exists (`inspectFindingStateContext` takes a `*subjectViewSet`, `freshness.go:859`). (2) **The signpost is an unbounded whole-document pass inside `run`'s preparation** (`gomutant.go:508`), under the campaign lock, with no progress, re-paid on every changed-scope run, producing one suffix on a residue line. (3) **`Store.Update` rewrites the whole document per committed target** (`store.go:382-437`): O(document) per unit, O(N²) over a campaign. A fourth: `--plan` reaches `buildProducerUnion` (`run.go:2629`, test processes) before its return at `run.go:2825` but never reaches the bracket preflight — the plan is neither cheap nor complete as a refusal derivation.

## 5. Knob inventory

Shared CLI flags (`--dir`, `--findings`, `--tag`, `--toolchain`, `--check`, `--json`): keep; `--json` merge-with `--jsonl` (one machine-face name).

`run` flags (`internal/cmd/run.go:53-72`): `--budget` 0=exhaustive (sentinel is the derivation, keep); `--timeout` keep; `--oracle-timeout` 0 derives 4× measured baseline floor 60 s (keep); `--oracle-memory-mib` 0 derives RAM/(2×jobs) floor 1 GiB (keep); `--jobs` 0 derives `max(1, NumCPU/2)` (keep); `--bracket-path`, `--scratch-namespace`, `--vouch`, `--staged`, `--force`, `--changed`, `--targets`, `--package`, `--symbol`, `--jsonl`, `--plan` keep; **`--progress-interval` 30 s — derive** (the cadence should follow measured per-candidate pace, `report.go:250`).

Other verbs: `findings` (`--label`, `--state` ⇒ `--judge`, `--judge`, `--symbol`, `--detail`, `--vouch`) keep; `attest` operands keep; `ephemeral` (`--file`, `--replacement`, `--batch`, `--test-pkg`, `--run`, `--timeout`, `--oracle-timeout`, `--oracle-memory-mib`, `--runs`, `--attest`) keep, `--test-pkg .` filed; `retarget --from/--to` keep; `mcp --dir/--vouch` keep.

Env vars read in production: `GOMUTANT_PPROF` (`internal/cmd/pprof.go:15`, keep), `XDG_CACHE_HOME` via `os.UserCacheDir()` (keep). Written, never read: `GOMEMLIMIT`, `GOMAXPROCS`, `GOFLAGS -tags`/`GOTOOLCHAIN`, `TMPDIR` — derived. ~30 `GOMUTANT_*` are test-only fixture channels.

MCP-only: `timeout_sec` (absent=300, 0=unlimited; keep), `oracle_memory_mib` tri-state (keep), `judge`/`detail` (keep).

Hardcoded tunables behaving like knobs: **`ephemeralBaselineLeash` 10 m and `campaignBaselineLeash` 1 h (`ephemeral.go:239,248`) — derive from the banked baseline**; `ephemeralBudgetFloor`/×4 keep; `MaxEphemeralRuns` keep; `auditShareDivisor`/`auditNarrowedCap` keep (cap already derived, `estimate.go:216`); `confirmStreak`/`confirmStride` keep; **`windowBudget` `jobs*8` floor 64 (`run.go:3034`) — partly derivable from measured pace**; **`scheduleMinCandidates`/`scheduleMinTests` 2/8 (`schedule.go:58,59`) — derive against the banked probe cost**; heartbeat 20 s twice (`server.go:174,1002`) merge; `clientKeepAliveInterval`, `defaultCommandTimeoutSec` keep; envelope caps (six literals `server.go:591,363,282,327,1130,1502`) merge into one cap policy; corruption ceilings, flock cadences, niceness, output caps, memory floor, chunk size keep.

**Counts: 106 rows** — 24 distinct CLI flags (78 registrations), 2 production env vars, 21 MCP fields, 22 exported `Options` fields, 37 hardcoded tunables. **9 already derive**; **5 should be derived and are not** (`--progress-interval`, both leashes, `windowBudget`, the schedule minimum pair); **3 merge-with**; **0 delete**; **89 keep**.

## 6. Self-test story

`Taskfile.yml`: `test` = `go test -timeout 2700s ./...`, `install`. No lint, short, or self-mutation target. CI: build, vet, `go test ./... -count=1 -timeout=60m` under a 90 m ceiling, repeated on the newest Go RC. Budget comment (`ci.yaml:40-51`): **slowest package the root at 966 s, whole run 971 s** on 24 cores; 24→4 cores ~4%; "a budget overrun is a real finding".

Shape: 615 tests over 7 packages — root 370, `internal/engine` 116, `internal/cmd` 68, `internal/mcpserver` 54. Zero fuzz targets, zero benchmarks, **zero `t.Parallel()`**. The root's 370 serial tests are the 966 s — `go test` subprocesses per mutant candidate against `internal/engine/testdata/fixturemod/` (30 packages), `workspacemod/`, `escapemod/`, ~200 ad-hoc temp modules, ~20 real `git init` fixtures. Heaviest: `TestRunEndToEnd` (`run_test.go:33`), `run_test.go:2434,3716`, pacing fixtures with 900 ms–3 s sleeps per oracle (`run_test.go:4324`, `pipeline_test.go:26-246`), `vouch_test.go:42` (`go mod tidy` + protobuf views), git-provenance triples, `staged_test.go`, `shaped_test.go`, `memlimit_test.go:53` (runaway allocation), `documentlock_unix_test.go:38` (waits out the retry budget). Three per-package `TestMain`s repoint `XDG_CACHE_HOME` — no cache amortised across packages.

**Self-hosting: gomutant does not gate on gomutant, by recorded decision.** `testdata/self-host-targets.json` (six targets) is a manual dogfood path; `TestSelfHostTargetsResolve` (`targeting_test.go:210`) resolves, never measures. `.gomutant/findings.json` is tracked and empty; two stale markers (`findings.json.campaign`, `findings.json.lock`) are residue of killed self-face campaigns. `docs/issues/own-face-gate-suite-decomposition.md`: window 1 priced ~33 h 43 m, pace extrapolated ~217 h, stopped at 3 h 33 m. The standing gate: scoped `ephemeral` probes with named deciding tests, plus the stipulator corpus (`.stipulator/policy.textproto`: 2 h timeout, `-test.timeout=40m`, race off, plain witness).

**Proposal.** The partition exists and is never used: **179 `testing.Short()` guards** with cost-classified skip strings (98 × "runs go test per mutant", 20 × "runs go test", 10 × "runs the oracle per mutant", …); root 144, `internal/engine` 19, `internal/cmd` 10, `internal/mcpserver` 6. `grep -rn '\-short'` across `*.go`, `*.md`, `*.yaml` returns **zero**.
1. `task test:short` = `go test -short ./...`: ~436 of 615 tests with no subprocess (catalog/operator enumeration, freshness/merge/splice arithmetic, the whole reporter, lifecycle string algebra, MCP envelope logic) — low tens of seconds; the fast PR gate.
2. The current `go test ./...` unchanged as the merge gate (971 s / 60 m budget). No build tag needed.
3. Nothing needs the self-host run today, and that is correct: (a) freshness machinery over a real document is covered by the stipulator corpus and `TestSelfHostTargetsResolve`; (b) own-face mutation adequacy is the filed user decision.
4. Add `task test:selfhost-plan` = `gomutant run --plan --targets testdata/self-host-targets.json` — exercises resolution, oracle derivation, view construction, candidate generation, decision rendering with no probe and no mutant; the only cheap way to keep the self-host path from bit-rotting (currently it will not catch a bad `--bracket-path` and pays the producer union — §2).

## 7. Known-failure register relevant to our own loop

- **staged-external-input-refuses-late-and-misnamed** — 50 minutes measured, every target refused under a drift headline. *Lands: chunk 146.*
- **probe-phase-cost-invisible** — ~2 h coverage-probe phase with no tick and no projection. *Lands: with 136, or the next window cost-model change.*
- **own-face-gate-suite-decomposition** — ~217 h extrapolated; own-face gates stay on probes. *Lands: user decision.*
- **bracket-path-module-relative-in-workspace** (+ absolute-directory rider). *Lands: chunk 138.*
- **ephemeral-blind-spots-stated-and-refused**, **ephemeral-deletion-probes-strand-imports**, **ephemeral-compiler-crash-retry**, **ephemeral-batch-wrapper-undiscoverable**. *Lands: chunk 140.*
- **ephemeral-test-pkg-shorthand**. *Lands: chunk 138.*
- **delta-line-survivor-view**. *Lands: chunk 139.*
- **suite-shared-fixture-bracket-flake**, **rescore-mechanism-unification** (136), **run-scoped-services-through-options** (136), **ephemeral-attestation-lifecycle**, **windows-process-fact-arms-unexecuted**, **symbol-grammar-package-set-resolution**, **mcp-liveness-cancellation-witness**, **semantic-closure-in-the-carry-gate** — as filed.

## 8. Cross-cutting shape

**Refusals live where their data is convenient, not where it is first available.** Exemplary in two places (`attest.go:42`, `findings.go:72`) and nowhere else; the habit is validate-at-use: `--budget -1` inside `Tree.Run`, six retarget predicates after a full load, the campaign lock (spec: "refuses immediately") after discovery, the bracket preflight at per-module group formation. Every one reads only flags or files that exist at `main`. What is missing is a *place* — a per-verb preparation function owning every input-decidable refusal, before the first `LoadContextSelection`.

**Progress lives on the run verb, and the other verbs inherit nothing.** `run` has the phase enum, per-target decisions with reasons, per-candidate ticks, the measured-pace cadence, the window cost model, the banked-state exit summary — the ruling's stage (3), built phase by phase under field reports. But the reporter is `internal/cmd/report.go`, private to the CLI's `run`, and the library callbacks exist only on `Tree.Run`. `Ephemeral`, `InspectFindingContext`, `PruneDetached`, `Retarget` expose no callback.

**Freshness got its batching fix on the measurement path and not on the inspection path.** One observed union replaced ~270 per-target passes in `run`; `findings --judge`, `explain`, and the signpost still build a view set per record.

**Knobs are in good shape; measurement-derivable *thresholds* stayed literal.** Every operator-facing resource knob derives from a runtime measurement with the flag as override; the internal thresholds gating *whether a measurement is worth taking* — the two baseline leashes, `windowBudget`, the schedule minimums, the progress cadence — are literals sized from a field report, though the baseline bank now holds the durations they should be functions of.

**The shared seam: a per-verb `prepare` stage object** — what `--plan` half-is. It owns (a) every input-decidable refusal ahead of any load; (b) the phase/unit reporter so every verb streams `phase · unit · why · pace`; (c) one batched view set threaded to every freshness consumer; (d) the derived thresholds, read from the bank. `run.go`'s `runPreparation` (`run.go:529`) and `internal/cmd/report.go`'s `runReporter` are the two existing halves; `docs/issues/run-scoped-services-through-options.md` is chartered against the same seam.
