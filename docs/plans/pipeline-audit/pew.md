# pew — pipeline, reporting, knob, and self-test audit (2026-09-02)

## 1. Operations inventory

No MCP surface exists in this repo. Six CLI verbs: `run`, `ab`, `status`, `stat`, `gc`, `guidance` (`cmd/pew/main.go:39-46`). `guidance` is pure embedded-document projection and is excluded below as sub-second.

| operation | entry point | stages in order (cost class) | persisted, and when | interruption loses |
|---|---|---|---|---|
| `pew run [packages]` | `cmd/pew/run.go:52` → `runRun` `run.go:103` | 1. flag conflict check (cheap, `run.go:61-69`) 2. `go list -json ./...` (process exec, `status.go:576`) 3. sysfs quiesce observation (cheap, `run.go:111`) 4. bench-dir resolution per module (cheap, `run.go:126`) 5. scratch sweep at command entry (cheap FS, `run.go:142-153`) 6. git state snapshot per module (process/FS, `run.go:158`) — then **per package**: 7. `go env GOFLAGS` + PGO digest + `go env GOVERSION` + engine (process exec, `run.go:168`→`status.go:93-203`) 8. parse test files for benchmark decls (cheap, `run.go:286`) 9. `//pew:scratch` scan (cheap, `run.go:293`) 10. *(`--stale` only)* store read + typed SSA view + `CheckBatch` (**typed package load**, `run.go:318`→`status.go:343-392`) 11. re-snapshot + equality (cheap, `run.go:333`) 12. **second** typed view `NewViewFor` + per-subject `Capture` + ledger (**typed package load**, `run.go:346-364`) 13. warm-up `go test -c` (**process execution**, `run.go:382`) 14. `go env` roots + target platform (process exec, `run.go:388,392`) 15. **per benchmark arm**: scratch re-sweep, state snapshot, observation frame, `go test -bench` (**process execution, the dominant cost**), throttle bracket, state snapshot, testlog ingest, stream parse/audit (`run.go:410-421`, `measureBench` `run.go:583-724`) 16. post-loop gates: `view.Validate`, dirty recompute, path building, store-covered/destination rejects, second `Validate`, PGO re-digest, HEAD re-check (`run.go:425-519`) 17. `WriteBatch` (`run.go:520`, `store.go:151`) | one `WriteBatch` **per package**, after every arm of that package has measured (`run.go:520`); temp-file + rename, all-or-nothing across the package (`store.go:246-278`). `--stale` additionally rewrites inert-growth recordings during stage 10 (`run.go:924`, `store.Write` `store.go:111`) | **every measured arm of the package in flight** — up to N benchmarks × `--count`10 × `--benchtime`1s plus builds. Earlier packages are safe. No signal handler exists anywhere (`grep signal\|NotifyContext` → none; every context is `context.Background()`, `run.go:345`), so SIGINT kills mid-batch with no message. |
| `pew ab [packages]` | `cmd/pew/ab.go:111` → `runAB` `ab.go:134` | 1. `count>=1` (cheap, `ab.go:135`) 2. `go list` (process exec, `ab.go:138`) 3. quiesce observation (cheap, `ab.go:148`) 4. `git rev-parse --show-toplevel` (process exec, `ab.go:161`) 5. `git worktree add --detach` + device check (**process execution / FS copy**, `ab.go:168`, `addWorktree` `ab.go:353`) — then **per package**: 6. module-containment check (cheap, `ab.go:178`) 7. side-B dir stat (cheap, `ab.go:196`) 8. two `go test -c` builds (**process execution**, `ab.go:218,221`) 9. `go list -f {{.Name}}` at ref (process exec, `ab.go:232`) 10. two guard captures (**typed/env work**, `ab.go:236,240`) 11. interleaved A/B measurement loop, `2 × --count` binary executions (**process execution, dominant**, `ab.go:257-268`) 12. throttle delta (`ab.go:269`) 13. parse both streams (`ab.go:276,280`) 14. stamp guards, `compare.Compare`, `WriteText` (`ab.go:299-307`) 15. optional `--out` artifact write (`ab.go:310`) | nothing to the recording store by design (spec §12, `docs/specs/spec.md:961-975`). Only the optional `--out` file, written once at the very end of a package (`writeABArtifact` `ab.go:322`) | the whole comparison for the package in flight, and the `--out` artifact entirely. Both raw streams are accumulated in memory (`outA`, `outB`, `ab.go:255,262,267`). Crash also leaves a `.pew-ab-worktree-*` sibling and a stale `.git/worktrees` entry (filed: `docs/issues/ab-worktree-placement-escape.md`). |
| `pew status [packages]` | `cmd/pew/status.go:36` → `runStatus` `status.go:205` | 1. `go list` (process exec, `status.go:206`) — per package: 2. `go env GOFLAGS` + PGO + `go env GOVERSION` + engine (process exec, `status.go:224`) 3. benchmark decl parse (cheap, `status.go:250`) 4. store reads for every bench (cheap FS, `status.go:353`) 5. one `NewViewFor` + `CheckBatch` for the package (**typed package load, dominant**, `status.go:385-392`) 6. optional inert-growth re-check with a second ledger/capture/check (`status.go:401`, `484-515`) 7. row printing (`status.go:274-297`) 8. optional `--explain` `CaptureFor` per non-valid row (**typed load again**, `explain.go:66`) | nothing (read-only surface) | nothing durable; all analysis work for the current package. |
| `pew stat [ref [refB]]` | `cmd/pew/stat.go:34` → `runStat` `stat.go:236` | 1. flag/gate validation (cheap, `stat.go:47-57`, `80-107`) 2. `go list` with module fallback (process exec, `stat.go:461`, `645`) 3. `gitblob.Open` (`stat.go:245`) 4. per-module bench-dir + repo + benchmark decl parse (`stat.go:487-525`) 5. historical module discovery: `ListAt`/`ReadAt` per ref per root, `modfile.Parse` (**git object reads**, `stat.go:565-610`) 6. inventory per module: `ListAt` at each ref + parse every candidate recording (`stat.go:666-717`) 7. per key: two side reads (cached, `stat.go:798`), format/strategy/dirty gates (`stat.go:306-359`) 8. **lazy** engine build + `verdictForRecs` per working-tree key (**typed package load**, `stat.go:392-403`) 9. accumulate all rows into `baseAll`/`newAll` (`stat.go:429-430`) 10. one `compare.Compare` over the whole corpus (`stat.go:434`) 11. render + gate exit (`stat.go:435-457`) | nothing (read-only) | everything; output is produced only at step 10-11. |
| `pew gc` | `cmd/pew/gc.go:21` → `runGC` `gc.go:36` | 1. `go list ./...` (process exec, `gc.go:37`) 2. per package AST scan of `*_test.go` (cheap, `gc.go:62`, `benchmarksInFiles` `gc.go:335`) 3. `ListCandidates` + parse every candidate, twice (`gc.go:90` then `gc.go:95`→`gc.go:119-124`) 4. `st.Remove` per orphan (`gc.go:147`) 5. sorted report (`gc.go:102-113`) | each `Remove` is an immediate FS unlink (`store.go:495`) — per recording | at most the un-reported removals; removals already done persist, but the summary is printed only at the end so an interrupted `gc` reports **nothing it did**. |

## 2. Late refusals (defects against the ruling)

| refusal | derived at | stage it fires in | earliest its inputs exist | cost wasted between | remedy sketch |
|---|---|---|---|---|---|
| `store: invalid label %q (want [A-Za-z0-9_-]+)` | `store.go:98` via `st.Path` `run.go:476` | `run` write-gate, after every arm of the package measured | `--label` is a flag value, bound at `run.go:84`; validatable at `RunE` entry `run.go:60` | the package's entire measurement (N × `--count` × `--benchtime`). `--stale` masks it (`st.Read` errors first at `status.go:353`), so the defect is exactly the plain-`run` path | validate `--label` against `store.labelRe` in `newRunCmd`'s `RunE` alongside the pure/impure conflict check |
| `store: invalid package path %q` / `store: invalid benchmark name %q` | `store.go:90,93` via `run.go:476` | same write-gate | `pkgRel` at `run.go:309`, bench names at `run.go:297` | same | build every destination path immediately after `matchingBenchmarks` (`run.go:297`) and fail there |
| `store: duplicate recording destination: %s` / `recording destination is not a regular file` | `store.go:182,188` | inside `WriteBatch`, post-measurement | destinations derivable from `(pkgRel, benches, label)` at `run.go:297-309`; the `Lstat` is a cheap FS probe | same | pre-flight the destination set in the preparation pass |
| `run: measured source %s lies under the recording store %s` | `rejectStoreCoveredSources` `run.go:256`, called `run.go:482` | post-measurement | `view.SourceFiles()` is available the moment the view exists (`run.go:346`); `gc.exclude` at `run.go:135` | the package's entire measurement | move the call to immediately after `run.go:364` (before the warm-up build) |
| `run: recording destination %s overlaps source input %s` | `runtime_destinations.go:18`, called `run.go:485` | post-measurement | same as above — both operands known at `run.go:346` | same | same |
| `run: GOFLAGS names an empty -pgo= profile path` / `run: reading PGO profile %s` | `run.go:384,401` | via `newEngineForPkg` `run.go:168` — before *this* package's measurement, but after **all earlier packages** measured | `go env GOFLAGS` + profile bytes are readable for every package right after `go list` at `run.go:104` | every prior package's full measurement | resolve GOFLAGS/PGO for all packages in one preparation sweep before the first measurement |
| `toolchain provenance: binary built with %s, ambient toolchain unidentifiable` / `gofresh.ToolchainSkew` | `provenance.go:92,95`; classified `run.go:170-172`, `status.go:227-229` (invocation-level abort) | first engine build of the *offending module* — in a multi-module (`go.work`) tree, after earlier modules measured | `go env GOVERSION` per module dir; every module dir is known at `run.go:104` | earlier modules' complete measurements | sample GOVERSION for every distinct module dir in the preparation pass (the memo at `provenance.go:29` already makes this ~free) |
| `ab: package %s lives in a module outside this repository (%s)` | `ab.go:180` | per-package loop, after earlier packages fully measured | `p.Module.Dir` + `repoRoot` known at `ab.go:157-164` | prior packages' `2 × --count` measurement iterations | hoist the containment check above the per-package loop |
| `ab: package %s does not exist at %s: %w` | `ab.go:197` | same | worktree path exists at `ab.go:168`; package dirs at `ab.go:138` | same | stat all side-B package dirs right after `addWorktree` |
| `ab: building side A/B ...` | `ab.go:219,222` | same | both trees exist at `ab.go:168` | prior packages' measurements | build **all** packages' A and B binaries in one preparation stage, then measure |
| `ab: capturing side A/B guards` | `ab.go:238,242` | same | both module dirs known at `ab.go:168-196` | prior packages' measurements | capture all guards in the same preparation stage |
| **`<bench>: toolchain mismatch (base=… new=…); not compared`** (and `buildconfig`, `machine`, `runtimeconfig`) | `compare.go:411-425`, reached from `ab.go:306` | **after the entire interleaved measurement loop** | `guardsA`/`guardsB` are both in hand at `ab.go:243`, before the loop at `ab.go:257` | the whole `2 × --count` measurement for that package. The largest single instance in the repo, and it contradicts the spec's own wording — §12 says `ab` "refuses a ref pinning a different toolchain or PGO bytes with the mismatch named" (`docs/specs/spec.md:966-971`), yet the code neither refuses nor exits non-zero: it prints a note and returns nil. The test only pins the message text, not its timing (`ab_test.go:232-259`) | compare `guardsA` vs `guardsB` on the four `compareGuards` keys at `ab.go:244` and return an error there; keep `compare`'s note as the fallback for stat |
| `ab: %s: pattern %q produced no results on side A/B` | `ab.go:291` | post-measurement | benchmark declarations on both sides are parseable from source before any run — `run` already does exactly this (`selectedBenchmarks` `gc.go:225`, `matchingBenchmarks` `run.go:297`); side B's tree exists at `ab.go:168` | the whole measurement loop | scan both trees' benchmark declarations against `--bench` right after the worktree materializes |
| `ab: refusing to run under noisy conditions (--strict)` | `ab.go:154` | correctly early | — | none | — (the correct shape) |
| `stat: --alpha/--confidence/--threshold`, `unknown --gate unit`, `--explain and -json are mutually exclusive` | `stat.go:81-89`, `99`, `56` | flag-parse time | — | none | — (correct) |
| `run: %s is both --assume-pure and --impure` | `run.go:64` | command entry | — | none | — (correct) |

Refusals correctly derived *only* from measurement results, and therefore not defects: `view.Validate` source drift (`run.go:425,488`), `effective PGO input changed during the benchmark run` (`run.go:503`), `repository HEAD moved during the benchmark run` (`run.go:518`), per-arm `repository state moved during %s measurement` (`run.go:643`), sample-floor/corruption refusals (`run.go:690,704,722`), `VerifyToolchainConfig` (`run.go:676`), throttle-under-`--strict` (`run.go:654`, `ab.go:273`), `benchmark %s produced no result` (`run.go:730`), `store: refusing to write empty recording` (`store.go:173`).

## 3. Progress and reporting

**`pew run` — CLI.** No phase names, no unit counter, no pace, no ETA, no "package k of N". Every write in the verb is either a warning or a terminal result line (`run.go:114,174,180,324,525,652,680,683,981`). The operator sees: quiesce warnings up front (`run.go:114`), scratch-sweep lines if any leftovers exist (`gc.go:263`), then — for the entire measurement of a package — **nothing on stdout**. `recorded <pkg>.<bench>` lines print only after `WriteBatch` succeeds (`run.go:524-526`), i.e. after every arm of the package finished. Under `--stale` a fully fresh package prints one line (`run.go:324`), which is the only "why this unit serves" signal anywhere; a unit that *executes* is never announced, and the reason it executes is never stated. Stderr carries only exceptional events.

*Silent stretches > 1 minute in `run`:* (a) the typed SSA view + per-subject `Capture` + ledger, `run.go:346-364`; (b) under `--stale`, a *second* typed load precedes it (`run.go:318`→`status.go:385-392`), doubling the silence; (c) the warm-up `go test -c` (`run.go:382`); (d) the per-arm measurement loop (`run.go:410-421`) — the dominant stretch, `N × count × benchtime` with zero per-arm output.

The one progress seam that exists is `gofresh.WithProgress(emitEngineDiagnostic)` (`status.go:195`), and `emitEngineDiagnostic` **deliberately drops every detail-free event** — `if p.Detail != ""` (`status.go:178-182`). There is no pew-owned progress package, phase enum, or reporter type anywhere in the tree.

*Interruption:* nothing. No `signal.NotifyContext`; every context is `context.Background()` (`run.go:345`, `status.go:377,427,474,492`, `explain.go:65`, `ab.go:61`). SIGINT kills pew before `WriteBatch` — nothing of the current package was kept and the operator is told nothing.

**`pew ab` — CLI.** One header line per package, printed *after* that package's whole measurement (`ab.go:305`), then the comparison table. Nothing during the `2 × --count` loop. Interruption reports nothing and loses the whole comparison; the `--out` artifact is written last (`ab.go:310`); the worktree cleanup is a `defer` (`ab.go:172`) that a `SIGKILL` skips.

**`pew status` — CLI/JSON.** Rows print per benchmark as each package completes (`status.go:290`, `status.go:275`). Silent stretch: the per-package `NewViewFor`+`CheckBatch` (`status.go:385-392`); `--stale` over a clean tree prints **nothing at all** (`status.go:271`) then exits 0. No package counter, no pace.

**`pew stat` — CLI/JSON.** Skip warnings stream to stderr as keys are walked, so there is incidental progress, but all *results* are held and emitted at the end (`stat.go:434-443`). The empty-comparison diagnostic is good: `statTally.emptyReason` (`stat.go:139-162`) names per-cause counts, and `--fail-on-regression` exits 2 rather than vacuously green (`stat.go:454-456`). Silent stretch: the lazy per-module engine build (`stat.go:392-403`).

**`pew gc`.** Removals happen during the scan (`gc.go:147`) but every line is printed after all groups are processed (`gc.go:102-113`); an interrupted `gc` has deleted files and reported none of them.

## 4. Incrementality and freshness

**`run`.** *Unit of freshness:* the recorded `gofresh.Fingerprint` (`fingerprintFromConfig` `status.go:520`) versus the current tree, via `CheckBatch` (`status.go:389`) — per benchmark. *Where:* only under `--stale` (`run.go:317`); the store read comes first so unrecorded benchmarks skip analysis (`status.go:352-376`) — the right shape — but the engine (`go env` ×2 + PGO digest, `run.go:168`) is built before the package's benchmark declarations are parsed, and the freshness view at `status.go:385` is **discarded** while `runPackage` immediately builds a *second* view over the same subjects at `run.go:346`. Without `--stale` there is **no freshness check at all**: "serve what is proven" is opt-in — the ruling's loop inverted.

*Unit of persistence:* the **package**. `measured` accumulates every arm's rows in memory (`run.go:407,419`) and one `WriteBatch` installs them after the last arm (`run.go:520`). A re-run after interruption does **not** serve the measured prefix. Nothing in the spec requires the write to happen once, at the end; the pre-write gates (`view.Validate` `run.go:488`, HEAD re-check `run.go:517`) force the batch shape and would have to be re-derived per arm.

*Whole-run state held in memory:* `measured`, `fingerprints` (`run.go:350,407`); `written`/`writes` (`run.go:423,435`); `armFailed`/`armRefused` (`run.go:529-558`); one arm's entire `go test` stream buffered in `run.Execute` (`internal/run/run.go:58-64`).

**`ab`.** No freshness concept by design. Persistence is the whole `--out` file at `ab.go:310`; `outA`/`outB` accumulate in memory (`ab.go:262,267`). The builds correctly precede all measurement (`ab.go:218-221`, pinned by `ab_test.go:211-213`) — the one place preparation-before-measurement is explicitly designed and tested.

**`status`.** Reads the store first and builds a view only for decoded recordings (`status.go:352-392`) — correct ordering; one view per package (`status.go:336-342`). The single-benchmark inert-growth path builds a *fresh* view (`status.go:472-478`) — a second typed load per rider on stat's route.

**`stat`.** Cheap gates precede the typed load — correct. Engine cache keyed `(moduleDir, pgo)` (`stat.go:273,386-397`); side reads memoized (`stat.go:798-811`). `baseAll`/`newAll` grow across every key and compare in one shot (`stat.go:434`); `m.sides` retains every parsed historical recording for the process lifetime (`stat.go:802`).

**`gc`.** Parses every candidate twice (`gc.go:158,168` and `gc.go:119,124`).

## 5. Knob inventory

| knob | surface | default | derivable at runtime? | disposition |
|---|---|---|---|---|
| `run --bench-dir` | cli | `<module>/benchmarks` (`run.go:214`) | no — store location | keep |
| `run --count` | cli | `10` (`run.go:79`) | **measurable** — the sample count for a non-degenerate benchmath CI is a function of observed per-arm variance (`docs/issues/per-arm-noise-floors.md`); collides with REQ-pew-sample-completeness ("exactly the demanded `--count`", `spec.md:1052`) — a spec-level derivation | derive |
| `run --benchtime` | cli | `1s` (`run.go:80`) | measurable — same class; `b.Loop()` auto-scales already (`spec.md:706-708`) | derive |
| `run --bench` | cli | `.` | no — selection intent | keep |
| `run --pin` | cli | `""` | value **detectable** (CPU topology from sysfs, already read at `quiesce_linux.go:44`); *whether* to pin is risk appetite (`spec.md:735-739`) | derive the CPU list, keep the switch |
| `run --strict` | cli | `false` | no — risk appetite | keep |
| `run --label` | cli | `""` | no | keep |
| `run --assume-pure` / `--impure` | cli | none | no — author assertions; the in-code `//gofresh:pure` / `//gofresh:external` forms are strictly better | merge-with the directives |
| `run --stale` | cli | `false` (`run.go:87`) | **derivable** — "serve what is proven, measure what is not" is the recorded verdict, already computed by `checkPackage`; re-measuring a `valid` recording is wasted work by construction | derive (make it the default; `--all`/`--force` as the escape) |
| `run --vouch` | cli | none | no — reviewed human acceptance | merge-with a repo-level vouch file (`docs/issues/repo-level-vouch-source.md`) |
| `ab --bench` | cli | `.` | no | keep |
| `ab --count` | cli | `6` | measurable — iterate until the interleaved delta's CI separates, or a budget is hit | derive |
| `ab --benchtime` | cli | `""` | measurable | derive |
| `ab --benchmem` | cli | `false` | **settled** — `run` has `-benchmem` unconditionally on (`internal/run/run.go:42`, `spec.md:711-714`); `ab` making it optional is an unjustified divergence | delete (always on) |
| `ab --ref` | cli | `HEAD` | no | keep |
| `ab --pin` | cli | `""` | as `run --pin` | derive value, keep switch |
| `ab --strict` | cli | `false` | no | keep |
| `ab --out` | cli | `""` | no | keep |
| `status --bench-dir`, `--label`, `--stale`, `--explain`, `--json` | cli | — | no (display/filter/contract) | keep |
| `status --vouch` | cli | none | no | merge-with repo-level vouch file |
| `stat --bench-dir`, `--label` | cli | — | no | keep |
| `stat --alpha` | cli | `0.05` (`compare.go:66`) | no — statistical value judgment | keep |
| `stat --threshold` | cli | `3` (`compare.go:67`) | **derivable from stored data** — per-arm empirical floor from the lineage (`docs/issues/per-arm-noise-floors.md`), global value as the fallback | derive |
| `stat --confidence` | cli | `0.95` | no | keep |
| `stat --fail-on-regression`, `--explain`, `--json`, `--gate` | cli | — | no | keep |
| `stat --vouch` | cli | none | no | merge-with repo-level vouch file |
| `gc --bench-dir` | cli | — | no | keep |
| `//gofresh:pure`, `//gofresh:external`, `//pew:scratch` | in-source | absent | no — author assertions | keep |

**Env vars:** none read (`grep os.Getenv\|os.LookupEnv` → zero in non-test code); toolchain environment is read only through `go env`. **Config fields:** `run.Options` and `compare.Options` mirror the flags; no config file.

**Counts — flags: 36.** derive 6 (`run --stale`, `run --count`, `run --benchtime`, `ab --count`, `ab --benchtime`, `stat --threshold`) + 2 half (`--pin` ×2); delete 1 (`ab --benchmem`); merge-with 5; keep 24. Directives: 3 keep. Env vars: 0.

## 6. Self-test story

`Taskfile.yml`: `build`, `test` (`go test ./...`), `test:race`, `vet`, `tidy`, `check` (= vet + test), `install`. No self-hosting gate.

**Cost.** CI comment: "slowest package cmd/pew 83s, whole run 84s … headroom ~11x", core count a non-factor (`.github/workflows/ci.yaml:38-47`); CI runs `go test ./... -count=1 -timeout=15m` (`ci.yaml:48,101`), job cap 30m; stipulator policy 3600 s with `-test.timeout=30m`.

**Heavy tests.** `cmd/pew` is the entire cost: 123 tests, ~6 200 test lines. ~23 call sites drive `runRun`/`runPackage` with real `go test -c` + `go test -bench` per arm over throwaway modules (`run_test.go:182,…,1985`); only 3 stub the `execute` seam (`run_test.go:489,1745,1908`). `TestLanguageShapeCanaries` (`canary_test.go:18`) builds an engine per shape-corpus entry; `TestNewEngineHonorsDirectives` and `status_test.go:174,244,286,331` load the pew module itself. `TestVouchedEngineDischargesPinnedCulprit` (the only `-short`-gated test) runs `go mod tidy` and builds three views over the protobuf graph (`vouch_test.go:57-168`). `gc_test.go`, `stat_test.go` drive real `go list` per case; `ab_test.go` shells to real `git` but stubs `build`/`execute`. `internal/*` packages are sub-10 ms.

**Gates depending on the tool.** None: no benchmark store of its own, no `pew status` self-gate, no CI step invoking the binary. Stipulator: 30 bindings over `REQ-pew-*`, two open gaps, one `plain` invocation with `plain_witness: true` — `stipulator check` costs ≈84 s plus analysis and proves binding freshness/coverage only.

**Proposed partition.**
1. *Pure/unit, seconds:* all `internal/*` plus the pure helpers in `cmd/pew` (`TestBaselineFor`, `TestParseGateUnits`, `TestValidateOptions`, `TestApplyPurity`, `TestMatchingBenchmarks…`, `TestRestrictBenchmarkPattern…`, `TestSourceBenchmarks…`, `TestScratchPatternsDiscoversDirectives`, `TestSweepScratchLeftovers`, `TestWarnNewVariantLineage`, `TestLineage…`, `TestFingerprintConfigRoundTrip`, `TestGuidance*`, `TestMemoizedSamplerSamplesOncePerKey`, `TestGoVersionCmdWiresDirAndEnv`, `TestToolchainProvenanceErrorClassifies`). Under 2 s; needs only to stop sharing a package with the heavy tests.
2. *Fixture-driven executions, `-short`-gated:* the ~20 unstubbed `run` sites, `gc_test`/`stat_test` fixtures, `ab_test` git fixtures — the 83 s. Extending the existing `execute`/`build` seams is cheaper than a build tag for most of this tier.
3. *Analysis canaries — unconditional in CI, `-short`-gated locally:* `TestLanguageShapeCanaries`, `TestNewEngineHonorsDirectives`, the four `newEngineAt` cases, `TestVouchedEngineDischargesPinnedCulprit`.

Nothing needs a self-host run. Irreducible executions (single-subject process isolation `run_test.go:1724`, per-arm attribution `run_test.go:1901`, PGO drift `run_test.go:809`, symlinked-module observation `run_test.go:1213`) belong in tier 2.

## 7. Known-failure register relevant to our own loop

- **`gitblob-linked-worktree-object-lookup`** — `pew run` fails the whole package inside a `git worktree add --detach` checkout (`gitblob: worktree status: object not found`); observed 2026-08-22 against tugboat. *Lands: user decision.*
- **`ab-worktree-placement-escape`** — `pew ab` hard-refuses on an unwritable or cross-device parent with no escape; crashed runs leave `.pew-ab-worktree-*` residue. *Lands: first consumer hit, or the next ab-surface chunk.*
- **`per-arm-noise-floors`** — one global `--threshold` misreports layout-only ±10% cross-commit drift on ns-class arms (run-to-run CV 0.2–1.4%). *Lands: chunk 15.*
- **`observed-fingerprint-recording-path`** — the recording path uses plain `Capture`, so every benchmark with a true external effect is permanently `unverifiable` and re-measures every `--stale` campaign (44 of 55 tugboat arms) — the single largest source of wasted measurement. *Lands: its own train chunk (spec-level).*
- **`verdict-ladder-shared-admissibility`** — `status` and `stat` hand-order the same admissibility ladder twice; both read only `recs[0]`. *Lands: the next chunk extending the ladder.*
- **`repo-level-vouch-source`** — vouch set exists only as flags, hand-mirrored; the unsafe drift direction is silent. *Lands: chunk 115.*
- **`gofresh-corpus-pin-lag`** — pew pins gofresh v0.91.0 against v0.92.0. *Lands: chunk 115.*
- **`profile-capture-attribution`**, **`derived-state-recompute-invariance-witness`**, **`spec-wide-requirement-forming`**, **`remote-bench-execution`** — as filed.

## 8. Cross-cutting shape

**Refusals live at the write gate, because the write gate is where the data was already gathered for another purpose.** `run`'s destination checks (`run.go:476,482,485`) sit beside the genuinely post-measurement gates and inherit their position by adjacency. `ab` is the same shape: `guardsA`/`guardsB` are captured before measurement precisely to claim build identity (`ab.go:224-243`), then their *comparison* is delegated to `compare.Compare` after the loop (`ab.go:306`) because that is where the comparison already lived.

**There is no reporter.** No progress package, no phase enum, no unit counter — 9 `Fprint` sites in `run`, all warnings or terminal results. The one channel that exists (`gofresh.WithProgress(emitEngineDiagnostic)`) drops detail-free keep-alives on purpose (`status.go:178`). The spec is complicit: `grep -i progress docs/specs/spec.md` returns nothing.

**Persistence is package-scoped because atomicity was designed against source drift, not against interruption.** Measurement is per arm and every piece of evidence is arm-local, but `WriteBatch` installs all arms at once behind gates whose premise is a whole-package span (`run.go:488,517`): the soundness model is fully incremental and the durability model is not.

**Freshness is opt-in, and computed twice.** `--stale` gates the only serve path (`run.go:317`); when on, the typed view built to answer it (`status.go:385`) is thrown away so `runPackage` can build another (`run.go:346`). Every package — including those with no benchmarks — pays `go env GOFLAGS` + PGO probe + engine construction before its declarations are parsed (`run.go:168` before `run.go:286`; `status.go:224` before `status.go:250`).

**The shared seam.** A *package preparation record* — computed once per package after `go list`, before any engine, build, or measurement — carrying the benchmark declarations, the resolved and validated store destinations, the effective GOFLAGS/PGO digest, the sampled GOVERSION, and the single typed view. Every late refusal in §2 becomes a preparation-time refusal over that record; the view stops being built twice; the record is the natural place to hang a per-unit reporter and the per-arm persistence decision; it absorbs the three divergent bench-dir resolvers (`moduleBenchDir` `run.go:211`, the inline forms at `status.go:257` and `gc.go:52`, `statBenchDir` `stat.go:534`). The filed `verdict-ladder-shared-admissibility` collapse is the read-side half of the same seam.
