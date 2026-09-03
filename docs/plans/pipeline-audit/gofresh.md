# gofresh — pipeline, reporting, knob and self-test audit (2026-09-02)

**Scope note:** gofresh has no CLI and no MCP server; its "operations" are library entry points the consumers drive, plus the shell gatherer in `scripts/`. The ruling's "operator" is the consuming tool's operator, reached only through the `Progress` callback (`gofresh.go:506-523`).

## 1. Operations inventory

| operation | entry point | stages in order (cost class) | persisted | interruption loses |
|---|---|---|---|---|
| `New` | `gofresh.go:743` | normalize env → producer-env build-identity compare `:768` → `canonicalDir` stat → `buildflags.ValidateEnv` = `go env GOFLAGS` (**process**, `internal/buildflags/buildflags.go:51`) | nothing | nothing (`context.Background()` at `:789`, deliberate) |
| `NewView`/`NewViewFor` | `view.go:68/74` → `newView:78` | arg validation → `coherentDir` stat → `scopeSubjects` → **`observeView` pass #1** (`view.go:104`) → **pass #2** (`view.go:108`) → agreement compare (`view.go:112-167`) | nothing of the view; memo side-effects only | the whole view; both passes |
| ↳ `observeView` (the unit of nearly all cost) | `view.go:225` | `go env -json` (**process**, `gotool.go:88`) → `closure.NewAtContextEnvSnapshot` → guard capture incl. live `go version` (**process**, `guard/guard.go:105`) + `/proc` reads → `GraphMetadata` = N× `go list -json -deps -test` (**process per package**, `closure/closure.go:1054-1057`) → `LoadViewPackagesEnvSnapshot` (**typed load**, `closure/viewload.go:81-96`) → `deriveViewDynamicState`: optional whole-graph `LoadViewGraphEnv` (**typed load**, `dynamicstate.go:1015`) + optional pinned-miss load (`dynamicstate.go:1104`) → `ComputeMaximalBatchWithSources` = read+hash every contributing file (`view.go:287`, `closure/maximal.go:60-64`) → per-file digests (`view.go:198-206`) → per-package test-variant ledgers (`view.go:305-312`) | effect scans per pinned package (`closure/maximal.go:1066`); testing scans per package (`:319`); dynamic-state facts per bucket, **once after the whole miss loop** (`dynamicstate.go:1134-1137`) | the pass; closure hashes and `go list` results (per-Hasher only: `closure/closure.go:99-104, 1050-1053`) |
| `View.Capture` / `CaptureBatch` | `view.go:399/457` | map reads | nothing | nothing |
| `View.CaptureObserved(Batch)` | `view.go:476/497` | `ensureObservable` → live `GOFLAGS` revalidation (**process**, `closure/closure.go:200`) → per package: memo probe → whole-program SSA load (**typed**, `closure/observability.go:40`) → attributed RTA in slices of 64 (`:180-186`) | observability proofs **per 64-subject slice** (`closure/observability.go:163,178,219`) | the in-flight slice only |
| `View.Check` / `CheckBatch` | `view.go:570/585` → `checkBatch:683` | record-shape validation inside the loop (`view.go:697-704`) → evidence ladder (`gofresh.go:928`) → runtime-input open observation (**filesystem**, `view.go:762`) → verdict → close observation → **`closeCheckWindow` → full `observeView`** (`view.go:1292-1311`) unless deferred | nothing | **the whole verdict map** (nil on any error, `view.go:723-733`) |
| `View.CheckObserved(Batch)` | `view.go:596/615` | as above plus drift-forced `ensureObservable` | as `CaptureObserved` | whole verdict map |
| `Engine.Capture`/`CaptureFor`/`Check`/`CheckObserved` | `gofresh.go:839-874` | one-shot: `validateRecordedKind` first (**good preparation**, `gofresh.go:862`) → `NewViewFor` → the View call | as above | whole operation |
| `View.Validate` (maximal) | `view.go:840` | seal → one full `observeView` (`view.go:930`) → compare | nothing | the validation; the producer's whole batch |
| `View.Validate` (observed) | `view.go:1064` | seal → `newSeededValidationView` = full `observeView` (`view.go:1035`) → `compareAttachedObservations` (`view.go:1094`) → `ensureObservable` (**typed + RTA**, `view.go:1096`) → proof compare → `compareAttachedObservations` again (`:1105`) | proofs per slice | the validation; all captured evidence |
| `View.ExplainDynamicState` | `explain.go:104` | global mutex (`explain.go:21,148`) → own `packages.Load(LoadAllSyntax\|NeedModule, Tests:true)` (**typed**, `explain.go:117-123`) → `ToolchainSelectionNoticeResolvedContext` (**process**) → re-derive every package's fact | nothing | everything |
| `ScanPureDirectives*` | `purity.go:28-56` | `context.Background()` (`purity.go:52`) → `GraphMetadata` (N× `go list`) → typed load | effect/testing scans | everything; **not cancellable** |
| `runtimeinput.CaptureBracket` / `CaptureProducerFrame` | `runtimeinput/bracket.go:103`, `producer.go:69` | symlink resolution → recursive walk + digest of every declared root (**filesystem**, `bracket.go:351,381`) | nothing | everything |
| `runtimeinput.FromTestLogEnv` / `Observe` / `CurrentEnvContext` / `MovedInputsContext` | `runtimeinput.go:687`, `producer.go`, `runtimeinput.go:1233,2257` | testlog parse / manifest decode → per-path stat/digest (**filesystem**) | nothing | everything |
| `scripts/fleet-sweep.sh` | `scripts/fleet-sweep.sh:1` | preflight tool check (`:65-70`) → quiet gate (`:74-79`) → 5 sections each `mlock run timeout <budget>` (`:87-91`): provenance, corpus lag, gomutant findings 30s, `stipulator check` 3600s, `pew status` 3600s, parked, trailer | report file; row dirs under `SWEEP_ROWS_DIR` (`:212,244`) | one section marked `NOT MEASURED`; the report survives — **the one operation in the repo with genuine per-unit staging** |

## 2. Late refusals

| refusal | derived at | fires in | inputs first available | cost wasted | remedy sketch |
|---|---|---|---|---|---|
| `subject %s.%s not found in selected source` | `view.go:333` | fingerprint-assembly loop of pass #1 | `scan.known` at `view.go:286` | `ComputeMaximalBatchWithSources` (`view.go:287`): read + hash every contributing file of every view package | check `known[subject]` right after `scanViewSubjects`, before the maximal batch |
| `dynamic-state scan: view package %s resolves into the module cache` | `dynamicstate.go:1046` | dynamic-state composition inside pass #1 | node classes from `GraphMetadata` at `purity.go:85` | `LoadViewPackagesEnvSnapshot` (`purity.go:111`) and, when reached, the whole-graph load (`dynamicstate.go:1015`) | classify requested view packages against `meta` right after `GraphMetadata` |
| `recorded result kind %d … does not match view kind %d` | `view.go:699`, `view.go:633` | inside the `checkBatch` / `CheckObservedBatch` record loop | the caller's `recorded` map at entry (`view.go:570,585,596,615`) | for a View-API consumer: both construction passes; for a batch: every verdict already decided is discarded | a preparation pass over `recorded` (shape + kind + membership) before the runtime-input window opens; `Engine.Check` already does this at `gofresh.go:862` |
| `invalid recorded result kind %d` / `code-result fingerprint carries measurement guards` | `gofresh.go:889,892`, from `view.go:697` | same | same | same | same |
| `subject %s.%s is not in this analysis view` | `view.go:703`, `637` | same loop | `v.facts.maximal` at construction; `recorded` at call entry | same; aborts the batch | same preparation pass |
| `subject %s.%s has no attached completed observation` | `view.go:1260` | `compareAttachedObservations`, from `validateObserved` at `view.go:1094` | `v.attachedObservations` at `Validate` entry | one **full `observeView`** in `newSeededValidationView` (`view.go:1035`) — minutes on a real tree | check attachment completeness before `newSeededValidationView` |
| `no captured observation proof` | `view.go:1091` | `validateObserved` after the seeded view | `v.capturedObserved` at `view.go:842` | the same full `observeView` | hoist above `newSeededValidationView` |
| unaudited-toolchain-selection degradation (`Progress{Phase:"toolchain-unaudited"}` and the per-symbol admission refusals it explains) | emitted `view.go:1436`; predicate `closure/toolchainaudit.go:249,313` | first `ensureObservable` — after the view is built, only on the precise-analysis path | `buildFlags` at `New` (`gofresh.go:487`), `GOFLAGS`/`GOEXPERIMENT` from the first `go env -json`; `ToolchainSelectionNoticeResolvedContext` (`closure/toolchainaudit.go:299`) already computes it standalone | both construction passes; then every proof silently degraded | resolve and announce the selection verdict in `New` |
| `guard: %w` / `guard: runtime env: %w` | `guard/guard.go:110,114` | every observation pass, after `go env -json` | `New` already normalized both envs (`gofresh.go:754,766`) | one `go env -json` per pass; repeated | pass the normalized envs through |
| `runtimeinputs: guard-covered root must be a clean absolute path` etc. | `runtimeinput/runtimeinput.go:497,477,489,524` | option application inside `FromTestLogEnv` | the caller's declarations, before the producing process spawns | the whole producing run: the testlog only exists post-execution | validate the declaration vocabulary in `CaptureProducerFrame` (`producer.go:69`), which already runs pre-spawn |

Legitimately post-measurement: `ErrViewChanged` (`view.go:117-166`), `ErrAnalysisUnavailable` on budget exhaustion (`view.go:1121`), proof drift (`view.go:1124`), the post-load internal invariant at `dynamicstate.go:1048`, `closure: load %s: %s` (`closure/maximal.go:291`). Counterexamples worth naming: `Engine.coherentDir` (`gofresh.go:1032`) and `New`'s producer-env divergence check (`gofresh.go:768`) are derived before any measurement — the earlier position exists and is used, just not consistently.

## 3. Progress and reporting

The whole reporter surface is one struct and one option: `Progress{Phase, Package, Detail}` (`gofresh.go:506-516`) via `WithProgress` (`:522`). No stderr writer, no phase enum, no counter, no ETA; the doc forecloses more: events "are emitted before the step runs, carry no completion signal, and are diagnostic keep-alive data, not contract" (`gofresh.go:511-513`). The one contract channel is `Hasher.OnDiagnostic` (`closure/closure.go:136-139`).

Emission sites, exhaustively: `view.go:230` (`"observe"`, once per pass), `view.go:775` (`"runtime"`, once per check window with a manifest), `view.go:1430/1433` (forwarding the hasher's `"load"`/`"prove"`/`"analysis-unavailable"`), `view.go:1436` (`"toolchain-unaudited"`), `closure/observability.go:40,135`, `closure/rooted.go:93`, `:205`.

What the operator sees: view construction — two `"observe"` lines. Capture/CheckBatch on a built view — nothing unless a manifest is present or drift forces precise analysis. Observability capture — one `"load"` and one `"prove"` per package, the only per-unit tick, naming the package but not count/total/position. Nothing anywhere says *why* a unit executes rather than serves: the memo hit at `closure/observability.go:120-133` skips with no event, so a served package and an absent package look identical.

Silent stretches over ~1 minute: (1) one `observeView` body (`view.go:229-392`) — N `go list -json -deps -test` spawns, one or two `packages.Load` calls with `NeedSyntax|NeedTypes`, a full read-and-hash of every contributing file; the loader and hasher have no progress plumbing; (2) the second construction pass, identical; (3) `closeCheckWindow` → `reobserveBase` (`view.go:1292-1311`): a third full `observeView` per check call when any record carries a manifest and `WithDeferredCheckClose` is off; (4) `newSeededValidationView` (`view.go:1035`): a fourth; (5) within one package's `attributedReachableSets` (`closure/observability.go:186`) — `TestReadOnlyObservabilityProof` is 3m42s plain, 15m02s race; (6) `runtimeinput.CaptureBracket` — recursive walk and digest with no callback; (7) `ScanPureDirectives*` — no progress, no caller context; (8) `ExplainDynamicState` — its own `LoadAllSyntax` load behind a process-global mutex.

Interruption: cancellation is honored densely (`view.go:81,113,120,166,300`, `closure/observability.go:112,181,192`, `closure/maximal.go:1044`; REQ-fresh-context forbids a private uncancellable context). But **nothing reports what was kept**: the memo store is silent by design (`closure/memo.go:52-54`, `cachefile.go:118-120`); an operator who cancels a proof batch is not told the completed 64-subject slices are on disk and a rerun will serve them (`closure/memo_test.go:298` pins exactly that).

## 4. Incrementality and freshness

**Unit of freshness.** The maximal closure hash, then the test-variant compartment, then the guard values — `recordedEvidenceVerdict` (`gofresh.go:928-950`), `decideAfterClosureObserved` (`:967-1005`). Pure functions over facts already computed.

**Where the comparison sits.** After everything. The freshness answer for *any* subject requires the maximal hash for its package, which requires the listing, the typed load, the dynamic-state scan, and the file hashing — a complete `observeView`, run twice before a view exists. There is no cheap prefilter. The engine already holds the data one would need — `View.SourceFilesFor` (`view.go:425`) exposes the contributing file identities and `observationFacts.fileDigests` (`view.go:198-206`) a content digest per identity — but only as a by-product of the expensive pass, never persisted, so a next run cannot ask "did any recorded identity move?" before loading.

**Unit of persistence.** gofresh persists no verdict and no fingerprint (REQ-fresh-fingerprint-data assigns storage to the caller). Engine-owned persistence is the memo store (`closure/internal/cachefile/cachefile.go`, "a cache, never a record"): observability proofs per package group and per 64-subject slice — genuinely incremental ("an analysis deadline expiring mid-group forfeits only the interrupted slice", `closure/observability.go:173-176`); effect scans per version-pinned package and testing scans per package — incremental; dynamic-state facts written per bucket only after the whole miss loop (`dynamicstate.go:1114-1137`); **the maximal closure hash and per-file contributions — no persistent memo at all** (`h.contribs`, `h.lists` per-Hasher, rearmed per call; each observation pass builds a fresh Hasher, `view.go:242`). The dominant cost is repaid in full every pass: ×2 at construction, ×1 per check close, ×1–2 per validation.

**Re-run after interruption:** proofs yes (slice-granular); effect/testing scans yes; dynamic-state facts only if the whole miss loop completed; closure hashes, guards, listings, typed loads — **no**.

**Whole-run in memory, written at the end:** `observationFacts` (`view.go:184-210`) — never written; the verdict maps in `checkBatch`/`CheckObservedBatch` — nil on the first error (`view.go:699-704, 723-733`), one malformed record loses the batch; the proof map in `ComputeObservabilityBatch` (`closure/observability.go:94`) — nil on any error though the memo absorbed completed slices; `store` in the dynamic-state loop; `WithDeferredCheckClose` (`gofresh.go:646`) makes all-or-nothing a *contract* ("any validation outcome short of success … discards every served verdict", `gofresh.go:637-641`).

## 5. Knob inventory

| knob | surface | default | derivable? | disposition |
|---|---|---|---|---|
| `WithBuildFlags` `gofresh.go:487`, `WithBuildInputs` `:495` | api | none | no | keep |
| `WithProgress` `:522` | api | nil | sink | keep |
| `WithAnalysisBudget` `:535` | api | 0 = unbounded | **measurable** — the engine times per-package `"prove"` phases | derive (or a multiple of observed per-package cost) |
| `WithAssumePure` `:543`, `WithDynamicStateVouches` `:561` | api | — | no — caller responsibility | keep |
| `WithSingleSubjectExecution` `:595`, `WithPackageProcessExecution` `:627` | api | off | no — facts about the caller's scheduler | keep; merge the two (`docs/issues/attestation-keyed-record.md`) |
| `WithDeferredCheckClose` `:646` | api | off | **partly** — the engine knows whether a manifest is pending (`view.go:672-676`) and seals on `Validate`; it controls a full `observeView` per check | merge into the producer protocol |
| `WithDir` `:653`, `WithEnv` `:663`, `SetMemoRoot` `:73` | api | `os.Getwd()`, `os.Environ()`, `os.UserCacheDir()` | derived defaults already applied | keep |
| `WithProducerEnv` `:694` | api | = `WithEnv` | no | keep |
| `DisableMemos` `:77` / `closure/memo.go:32` | api | enabled | **yes** — every store failure is already silent and harmless (`cachefile.go:118-156`) | delete (or keep purely as a hermeticity assertion) |
| `Hasher.SetAnalysisScope`, `Hasher.UseViewLoad`, `Hasher.BoundAnalysis` | api (internal) | — | derived at their one call site | merge |
| `Hasher.OnProgress`/`OnDiagnostic` | api | nil | sinks | keep |
| `maxAttributedSubjects = 64` `closure/observability.go:78` | const | 64 | **measurable** — fixes RTA batch width and memo persistence granularity; a memory/latency tradeoff observable at runtime | derive |
| `show = 3` `view.go:1170`, `limit = 3` `view.go:1218`, `cappedList` limit `bracket.go:309` | const | 3 | display caps | merge |
| `WithCompletedProcess` `runtimeinput.go:397`, `WithBracket` `:426` | api | none | no | keep |
| `WithToolchainRoot` `:443`, `WithModuleCacheRoot` `:453`, `WithBuildCacheRoot` `:472`, `WithEphemeralTempRoot` `:485`, `ClassificationRoots{…}` `producer.go:97-103` | api | none | **yes — GOROOT, GOMODCACHE, GOCACHE, TMPDIR**, all in the engine's `EnvSnapshot` (`gotool.go:65-99`, `view.go:186-190`) | derive |
| `WithStaticInputRoot` `:520`, `WithScratchNamespace` `:554`, `WithExcludedPaths` `:603` | api | — | no — caller assertions | keep |
| `WithBracketExcludedPaths` `bracket.go:69`, `FrameOptions.BracketPaths/ExcludedPaths` `producer.go:55-57` | api | `.git` hard-coded at `producer.go:83` | pass-through | merge-with `WithExcludedPaths` |
| `ProducerIngest.{…}` `producer.go:117-127` | api | — | no | keep |
| env vars read by the code | — | — | **none exist** | exemplary |
| `SWEEP_ROWS_DIR`, estate lists, `pew_args` vouch set, section budgets `scripts/fleet-sweep.sh` | script | — | opt-in / documented value judgment / detectable once a repo-level vouch source exists / measured | keep; derive the vouch set when that lands |
| `-timeout=30m`, `timeout-minutes: 60` `.github/workflows/ci.yaml:50,28`; `-test.timeout=60m`, `timeout {seconds: 7200}`, `bracket_paths`, `assume_pure` `.stipulator/policy.textproto` | ci / policy | measured, evidence in-comment / soundness declarations | keep |

**Counts: 41 knobs — 8 derivable, 24 keep, 1 delete (`DisableMemos`), 8 merge-with.** Zero environment variables. Every `Engine` default that could be derived already is.

## 6. Self-test story

**Task runner: none** (`docs/issues/reusable-ci-workflow.md`: "gofresh is the one repo with no Taskfile"). CI: build, vet, `go test ./... -count=1 -timeout=30m` (`:47-50`), repeated on a next-Go-rc leg. Measurement comment (`:37-45`): **slowest package `closure` 544s, whole run 555s, headroom ~3.3×**; 24→4 cores ~4% ("child-process-serialized").

Census: root 234, `closure` 208, `runtimeinput` 155, `closure/internal/testvariant` 18, `guard` 23, `guidance` 5 (0.002s). 5 fuzz targets, 4 benchmarks.

Heavy: effectively all of root and `closure`. Almost every test synthesizes a temp module and runs the real engine (`t.TempDir()` 46× in `dynamicstate_test.go`, 43× in `closure/closure_test.go`, 25× in `view_test.go`; `New(` 127× in `view_test.go`) or runs over the 145 in-repo fixture packages under `closure/fixtures/`; each spawns `go list -json -deps -test` plus a `packages.Load` with `NeedSyntax|NeedTypes`; the observability tests build whole-program SSA. The most expensive run `go mod tidy` with `GOFLAGS=-mod=mod` (`dynamicstate_test.go:44,556,722,851,1147`) and clean module caches. Worst case: `TestReadOnlyObservabilityProof` (`closure/closure_test.go:1503`): **3m42s plain, 15m02s race**.

**No partition exists.** `testing.Short()` appears nowhere as a gate; `t.Parallel()` once, inside a fixture; the only test build tag is `//go:build linux`. The 544s `closure` package is fully serialized and runs on every `go test`.

**Self-hosting.** gofresh does not judge gofresh. One hop out, stipulator runs `./...` under `-race`, width 2, per-binary 60m, 7200s: recorded baseline **502 witnesses re-executed in 35m58s** (2026-08-28), the race detector at **4.06×** on the observability proofs; deliberately machine-side, weekly with a 3600s budget (`scripts/fleet-sweep.sh:200`). The gomutant side is inert: `.gomutant/findings.json` is version 11 with zero findings, two stale coordination files beside it.

**Cache hygiene (corrected at chunk 150).** The audit's claim that plain `go test ./...` writes the user's real cache was wrong: `cacheisolation_test.go` and `closure/cacheisolation_test.go` set `XDG_CACHE_HOME` to a fresh temp dir in `TestMain`, and `cachefile.storeRoot()` resolves `os.UserCacheDir()` lazily per call, so every memo write in a test run lands under that dir. Isolation is per package run, not per test; the tests that assert memo state (`closure/memo_test.go`, `effectmemo_test.go`, `testingmemo_test.go`) additionally redirect per test with `t.Setenv`. Suite timing is still cache-state dependent within a run.

**Proposed partition.**
1. *Pure tier — keep on the default path:* the verdict ladder and guard comparison (`gofresh.go:928-1005`, `FuzzDecideSound`, `structural_test.go`), `toolchainSkew`'s pure core, receiver-name derivation, explain ordering, `guidance/`, `internal/buildflags`, `internal/processenv`, `internal/gotool`, `internal/puredirective`, `closure/effectscan_reference_test.go`, the `cacheisolation_test.go` files, `guard`'s pure parse tier. ~40–60 of ~640 tests; single-digit seconds.
2. *Fixture-driven executions — `-short`-gate:* everything reaching `t.TempDir()`+module synthesis or `closure/fixtures/` (~500 tests, essentially all of the 544s). Two sub-tiers: (a) synthetic temp modules that pay `go mod tidy` and module-cache population — the most expensive; (b) in-repo fixtures. Both should redirect `SetMemoRoot` to a per-test temp dir.
3. *Self-host run: nothing here.* The one tool-over-tree gate is stipulator's race witness run, in the weekly sweep, not CI.

Expected: default `go test ./...` from 555s to the seconds class; the fixture tier rides CI inside the 3.3× headroom; the measured 4% cost of 24→4 cores says the fixture tier is child-process-bound, so `t.Parallel()` there — absent everywhere — is the second lever.

## 7. Known-failure register relevant to our own loop

- **range-over-func-yield-closure** — a subject ranging a function iterator refuses observability; the corpus pins the refusal. *Lands: chunk 124.*
- **walk-dst-selection-for-audit-key** — a `-tags dst` analysis refuses **every** stdlib admission loudly; the walk that would lift it is undone. *Lands: with the first judged run over a dst-tagged selection.*
- **sibling-reason-families-name-their-channels** — two refusal reasons dead-end the operator with no remedy channel; per-refusal reasons carry no toolchain-selection attribution. *Lands: with the next change to either reason's composition site, or a field report.*
- **grpc-runtime-memo-and-registry-discharges** — 209 residual culprits keep a real consumer workload unverifiable. *Lands: with the get-or-compute discharge charter.*
- **binary-roots-single-mask-union** — ⌈N/64⌉ attributed RTA analyses plus N provenance walks for a union needing none. *Lands: with the next reachability-scoping change.*
- **attestation-keyed-record** — a `Sibling` fact-copy omission "reached a consumer e2e before any gofresh test". *Lands: user decision.*
- **reusable-ci-workflow** — the rc-resolution contract exists in four copies; names gofresh's missing Taskfile. *Lands: user decision.*
- Consolidation only: `audit-key-mechanism-consolidation`, `unify-carrier-walks`, `unify-discharge-walks`, `registration-audit-walk-helper-unification`.

## 8. Cross-cutting shape

**One observation pass is the atom, and the pass has no freshness of its own.** Every question the engine answers — is this fresh, is it observable, has it drifted — rebuilds the same maximal observation from zero. `h.contribs` and `h.lists` are per-Hasher, rearmed per call; each pass builds a fresh Hasher. The tool whose purpose is avoiding recomputation recomputes its own dominant input in full: twice at construction, again at every check close, again at validation. The persistent memos (`effectscan`, `testingscan`, `dynamicstate`, `observability`) sit *below* this layer, memoizing the cheap syntactic parts while the expensive listing-plus-load-plus-hash is uncached.

**Refusals live where their data is convenient, not where it is first available.** Subject existence in the fingerprint-assembly loop rather than beside the scan; the module-cache refusal in dynamic-state composition rather than beside `GraphMetadata`; record-shape validation inside the batch loop; attachment completeness after a full re-observation. `Engine.Check` proves the earlier position exists (`gofresh.go:862`); the discipline is not applied at the View surface.

**Progress is a phase name with no unit.** The single longest stretch, one `observeView`, is exactly one event; the memo-hit path that would justify "served, not measured" emits nothing.

**Batches are all-or-nothing.** Every check surface returns nil on the first error; `WithDeferredCheckClose` promotes that to a pipeline-wide contract. One malformed record, or one cancelled window, discards work already decided.

**The knobs are mostly assertions — correctly — and the derivable ones cluster:** the four classification roots the caller must declare while the engine already resolves them in its own `EnvSnapshot`.

**The shared seam: `observeView` (`view.go:225`) and the `observationFacts` it produces (`view.go:184`).** One consolidation attaches there: a preparation pass resolving listing, package classification, subject existence and recorded-record shape *before* any typed load; a per-package progress tick threaded from the seam the precise-analysis path already has (`Hasher.OnProgress`); a persistent per-file contribution memo keyed exactly as the effect-scan memo is (`closure/effectmemo.go:112`); and a served-versus-measured decision made per package inside the pass rather than per view after it.
