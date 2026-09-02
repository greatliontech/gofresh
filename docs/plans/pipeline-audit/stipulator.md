# stipulator — pipeline, reporting, knob, and self-test audit (2026-09-02)

Audited with the staged chunk-141 change set in the tree (observed-red verdict term; the owned resolver child hoisted above the witness run, `internal/check/check.go:134`).

## 1. Operations inventory

| Operation | Entry point | Stages in order (cost class) | Persisted, and when | Interruption loses |
|---|---|---|---|---|
| CLI `check` (default) | `internal/cmd/check.go:24` → `internal/check/check.go:62` | compile corpus (cheap) → `records.Load` (cheap) → `policy.Load` (cheap) → `SelectionNotices` = N× `NormalizeInvocation` (process: `go env` each, `normalize.go:291`) → `NewOwned` resolver child spawn (process, `check.go:134`) → `capturePolicy` = N× normalize + N× `DiscoverInvocation` (`go list`, `go list -deps`; `derive.go:582,586`) → `classifySeeded` = typed load of every witness package in the child (`golang.go:524`) → `discoverUniverse` (process, `partition.go:144`) → `witnesscache.Load` (cheap) → `prepareWitnessGroups`: per group `NewView` = **two** full typed package loads (gofresh `view.go:104,107`) then `checkFingerprints` (cheap) → `executeSelections` (process execution, `witnessrun.go:423`) → per-group `finishGroup` + install → `verify.Run` (typed, via child) → manifest/coverage (cheap) | Witness cache records under the user cache dir, one JSON file per record variant, installed at the moment a group's last covering invocation completes (`witnessrun.go:405-422, 380-384`) and after the retry pass (`:484`). | Records for groups whose last covering invocation had not completed; the whole verdict. Installed groups survive. |
| CLI `check --full` | `check.go:147` → `derive.go:1117` | `NewWitnessRecorder` (`capturePolicy` again) → `ExecutePolicy` (`execute.go:988`): `discoverUniverse` + `discoverInvocations` (process) → serial invocations, packages fanned out (process execution) → `Derive` (`derive.go:860`): publish validation → install loop `derive.go:929` → second `discoverUniverse` (`derive.go:1168`) | **All records installed at the end**, one loop after the whole policy executed (`derive.go:929`). | Everything. A `--full` run killed at minute 29 of the measured 30m43s wall publishes zero records. |
| CLI `check --ids` | `check.go:153` | as default, plus `ScopeSubjects` (cheap) after the resolver child spawn | as default | as default |
| CLI `gate` | `internal/cmd/gate.go:23` | compile → `records.Load` → `witnessRun` (`cmd/witness.go:24`: its own resolver child, full selective run) → `makeBackends` (**second** resolver child) → `verify.Run` → manifest → coverage → render | witness records only | the verdict |
| CLI `verify` | `internal/cmd/verify.go:20` | compile → `records.Load` → `witnessRun` → `makeBackends` (second child) → `verify.Run` | witness records only | the verdict |
| CLI `prune` | `internal/cmd/prune.go:28` | `--store` fast path → compile → `records.Load` → `--dangling` fast path → no-gap fast path (`:107`) → `GapScope` → `witnessRunScoped` → `makeBackends` → `verify.Run` → coverage → CAS-batched record writes (`root.go:130`) | gap-record deletions, all-or-nothing after preconditions (`root.go:140-195`) | the deletions; the verdict |
| CLI `impact` | `internal/cmd/impact.go:20` → `internal/impact/impact.go:72` | `gitfs.Changed` (process) → two compiles → `records.Load` → short-circuit if nothing changed (`impact.go:121`) → `NewOwned` + symbol resolution + import reach (typed) | nothing | the report |
| CLI `diff` | `internal/cmd/diff.go:20` | git object read + two compiles (cheap) | nothing | the report |
| MCP `check` | `internal/mcpserver/server.go:542` | view/ids validated first (`:544-550`) → `startProgress` → `check.Run` | as CLI | as CLI |
| MCP `gate` / `verify` / `context` / `partitions` | `server.go:505,478,1710,1801` | `verifyPipeline` (`:445`): compile → id refusal → `records.Load` → `backends` → `runTests` (full witness run) → `verify.Run`; then policy, coverage, render; `context` adds the slice leg (`:1747`) | witness records; `export_path` writes at the end | the verdict/report |
| MCP `prune` | `server.go:1537` | as CLI prune | as CLI prune | as CLI prune |
| `compile`, `read_spec`, `explain`, `guidance`, `bind`/`gap`/`pin`/`dispose`/`retarget`/`attest` | `internal/cmd/*.go`, `server.go:405,1343,1363,2159` | cheap or single typed load; writes are CAS batches | record files, all-or-nothing | nothing durable |

## 2. Late refusals (defects against the ruling)

| Refusal | Where derived | Fires in stage | Earliest stage its inputs exist | Cost wasted | Remedy sketch |
|---|---|---|---|---|---|
| `"manifest policy names the cell (%s, %s) twice"` | `internal/coverage/coverage.go:177` | after the whole witness run: `check.go:210`, `cmd/gate.go:56`, `cmd/prune.go:158`, `server.go:365` (via `toolGate:515`, `toolContext:1723`) | manifest readable at `check.go:73` / `cmd/gate.go:30` | the entire execution phase — up to the measured 30m43s cold wall | load the manifest and build the coverage policy in the preparation pass, beside `policy.Load` |
| `"unknown bucket %q …"`, `"bad filter %q"` | `internal/views/views.go:49,54` | `cmd/gate.go:63/74`, `server.go:519` (gate), `server.go:484` (verify) — after the run | parse time | whole witness run | call `Scope.Validate()` before the run, as `toolCheck` already does (`server.go:548`) |
| `"unknown view %q …"` | `internal/views/views.go:224,401` | `cmd/gate.go:63`, `server.go:523/490` — after the run | parse time | whole witness run | probe the view against an empty report pre-run — the `toolCheck` pattern |
| `"fix verification problems first"` | `internal/cmd/prune.go:150` | after `witnessRunScoped` | 12 of 14 problem classes are pure record/corpus hygiene (`verify.go:406-429, 562-614`), derivable from `spec`+`store` at `prune.go:70-75` | the scoped witness run | run the record-hygiene half of `verify.Run` before the run |
| gate's `os.Exit(1)` on `rep.Problems` | `internal/cmd/gate.go:44-47` | after `witnessRun` | same | whole witness run | same |
| `"invocation %q: witness_concurrency must be positive when present"` | `normalize.go:223` | `capturePolicy` (`derive.go:582`) — after 3 `go env` spawns and the resolver child | the record, at `policy.Load` (`check.go:112`); purely static | child spawn + N `go env` | move into `validateConfig` (`golang/policy.go:43`), which already refuses `count<=0` (`:106`) |
| `"bracket path %q is empty / carries a parent traversal / is not clean"` | `normalize.go:467-483`, called at `:357` | after `effectiveGoEnv` (`go env`, `:291`) | the record; static | one `go env` per invocation, ×2 call sites | move to `validateConfig` |
| `"dynamic_state_vouches package … / variable … is not one Go identifier"` | `normalize.go:396-409` | after `effectiveGoEnv` | the record; static. `docs/specs/evidence.md` states this "refuses at policy acceptance" | same | move to `validateConfig`; also a spec-conformance gap |
| `"excluded path %q is empty / … not clean"` | `normalize.go:420-447` | after `effectiveGoEnv` | the record; only the "inside the verification tree" arm (`:442`) needs the resolved root | same | split: static arms to `validateConfig` |
| `"invocation %q: GOPACKAGESDRIVER=%q is unsupported"` | `normalize.go:187` | normalize | process environment, at startup | small, but repeated N×2 | one-shot environment precheck |
| `"unknown requirement identifier %q in ids scope"` | `internal/check/check.go:286` | `check.go:154` — after `SelectionNotices` (N `go env`) and the resolver-child spawn | `spec` at `:79`, `store` at `:101`, ids from the caller | N `go env` + child spawn | move `ScopeSubjects` above `SelectionNotices` |
| `"give either --json or --quiet"`, `"prune --store composes with no other prune mode"`, `"ids scoping composes with the default class only"`, policy record problems (`ErrRecord`) | `cmd/check.go:26`, `cmd/prune.go:40`, `check.go:70`, `policy.go:42-82` | preparation — correct | — | — | — |

## 3. Progress and reporting

**The CLI installs no progress sink at all.** `progress.FromContext` returns nil on every CLI path — the reporter is created only in `internal/mcpserver/server.go:758`. Every `rep.Phase`/`rep.Step`/`rep.Keepalive` call in `check.go:78,195,214`, `witnessrun.go:121,368,438`, `execute.go:192-201,988`, `derive.go:732,1118` is a documented no-op there (`check.go:75-77`). `REQ-mcp-progress` (`docs/specs/mcp.md:147`) is scoped to MCP; the CLI has no counterpart clause.

What the CLI operator sees for `check`: one `dim` line at start (`cmd/check.go:30-33`), then **nothing** until `renderCheck` (`cmd/check.go:51`) — on a cold tree the full 30m43s wall as one silent stretch. `gate`/`verify`/`prune`: `"witnessing: …"` (`cmd/witness.go:25,46`) then silence until `printWitnessSummary` (`cmd/witness.go:73`). The only mid-run output is `emitEngineDiagnostic` (`derive.go:748`) — gofresh payload-bearing events, incidental.

Silent stretches over a minute: (a) `SelectionNotices` + `capturePolicy` + `classifySeeded` + `discoverUniverse` — three `go env` and three `go list` passes twice over, plus a typed load of every witness package in the child; (b) `prepareWitnessGroups` — the **double** `NewView` per capture group, the single largest pre-execution cost; (c) `executeSelections`; (d) `finishGroup`'s post-run revalidation. Only (c) has a per-unit tick, and only on MCP.

MCP: with a progress token, `startProgress` (`server.go:712-758`) emits phase transitions and per-invocation `completed/total` package counts (`execute.go:201`, `progress.go:128`), rate-limited to one per second, with a reserved terminal slot. Without a token but with a log level, one info log per phase. With neither, only the completed call's `Stamps()` line (`progress.go:272`).

Missing on both surfaces: **pace or ETA** (no code computes one), and **the reason a unit executes rather than serves is never emitted during the run** — `ExecutedReasons`/`UncacheableReasons` are rendered only at the end as a top-8 histogram (`cmd/check.go:199-232`).

Interruption: the CLI has **no signal handling and no cancellable context** — `cmd/stipulator/main.go:11` calls `cmd.Execute()` on `context.Background()`; there is no `signal.NotifyContext` in the repo. SIGINT kills the process: `ctx.Err()` never fires, `REQ-policy-cancellation`'s discard logic never runs, nothing is printed about what was kept (the default form's per-group installs survive on disk, unreported). On MCP, `terminalToolError` (`server.go:769-777`) names the terminal cause and phase but not which records were kept.

## 4. Incrementality and freshness

| Operation | Freshness unit | Where the comparison sits | Persistence unit | Serves the prefix after interruption? |
|---|---|---|---|---|
| `check` (default), `gate`, `verify`, `prune` witness legs | one test subject per capture group, a gofresh `Fingerprint` vs the tree, up to 4 stored variants tried in rounds (`witnessrun.go:736-748`, `witnesscache.go:42`) | **after** two full typed loads per group (`witnessrun.go:712` → gofresh `view.go:104,107`) and after a typed load of every witness package for seeded classification (`golang.go:524`). The freshness answer is computed after the load it could have replaced. | one JSON file per record variant, at group completion (`witnessrun.go:405-422`) | Yes for completed groups. Invocations run serially (`witnessrun.go:189-208`), so interruption inside the 7200s `race` invocation loses every record it would have produced. |
| `check --full` | none — the whole policy executes unconditionally (`execute.go:988-1010`); freshness only decides publication | n/a | **whole run**: `Derive` installs everything in one end-of-run loop (`derive.go:929`) | No. |
| `impact`, `diff`, `compile` | n/a | preparation short-circuits are correct (`impact.go:121`) | n/a | n/a |
| `prune --store` | binding-record liveness vs store identities (`cmd/prune.go:46-66`) | before compilation — deliberately | per-file deletions | n/a |

Whole-run results held in memory: `ExecutePolicy`'s slices (`execute.go:992-1010`) and `Derive`'s `published` (`derive.go:929`) on `--full`; `check.Run`'s `CheckResult`; `verifyPipeline`'s report on MCP.

Duplicated preparation: `NormalizeInvocation` (one `go env` each) from four call sites — `SelectionNotices` (`normalize.go:682`), `capturePolicy` (`derive.go:582`), `discoverInvocations` (`partition.go:125`), `baselineInvocation` (`partition.go:182`). `discoverUniverse` from `witnessrun.go:142`, `execute.go:990`, `derive.go:1168`, `partition.go:95`. On this repo's three invocations and three workspace members, a `--full` check pays roughly fifteen `go env` spawns and twelve `go list` passes before executing a test; the default form about nine and six. `gate` and `verify` spawn two resolver children in sequence (`cmd/witness.go:26`, `cmd/root.go:117`) where `check` shares one (`check.go:134`).

## 5. Knob inventory

| Knob | Surface | Default | Derivable at runtime? | Disposition |
|---|---|---|---|---|
| `--chdir/-C` | cli | `.` | detectable — `corpus.FindRoot` walks up (`root.go:69`) | keep (escape hatch) |
| `check --full` | cli, mcp | false | no — evidence class | keep |
| `check --ids`, `gate --req`, `verify/context/partitions/pin ids` | cli, mcp | empty | no — operands | keep |
| `check/gate --json`, `--quiet` | cli | false | no | keep |
| `check/gate/verify view` | cli(gate), mcp | `summary` | no | keep |
| `gate --bucket`, `--filter`, `--path` | cli, mcp | empty | no | keep |
| `verify --no-test`, `prune --no-test`, `context/partitions no_test` | cli, mcp | false | **yes** — "skip the expensive leg"; with a fresh store the leg is nearly free; the right value is measurable | merge-with the freshness path; keep only as an explicit records-only claim that says no witnesses were gathered |
| `prune --check`, `retarget --check` | cli, mcp | false | no | keep |
| `prune --dangling`, `--store` | cli, mcp | false | no (`REQ-evidence-store-gc`) | keep |
| `dispose retire --force` | cli, mcp | false | no | keep |
| `diff --against`, `compile --ir` | cli | — | no | keep |
| authoring operands (`--req`, `--symbol`, `--role`, `--backend`, `--file`, `--reason`, `--covered`, `--exists`, `--manual`, `--excuses`, `--fired`, `--retract`, `--list`, `--id`, `--from`, `--into`, `--to`, `claims[]`) | cli, mcp | — | no | keep |
| `context slice`, `export_path` | mcp | — | partly / no | keep |
| `NO_COLOR`, `TERM`, `SystemRoot` | env | — | detectable, already are | keep |
| policy `name` | config | — | no | keep |
| policy `timeout` | config | required | **measurable** — set by measurement today (`policy.textproto:6-10`, "~3x the measured cold wall"); a bound is not identity-bearing | derive a default from the store's recorded wall times; keep as reviewed override |
| `go.module_root`, `packages` | config | — | no | keep |
| `go.race`, `plain_witness` | config | false | no — evidence-tier judgment | keep |
| `go.toolchain`, `goos`, `goarch`, `cgo_enabled`, `goflags`, `workspace_mode` | config | pin-at-load | **already derived** (`policy.proto:88-98`) | keep |
| `go.environment`, `env_deny` | config | none | no | keep |
| `go.tags`, `module_mode`, `pgo`, `count`, `cache_mode`, `args` | config | toolchain defaults | no | keep |
| `go.witness_concurrency` | config | `max(1, GOMAXPROCS/2)` | **already derived** (`policy.proto:191-198`, `execute.go:361-382`) | delete as a policy field; a wrong value is a host-freezing fan-out, not a semantic choice |
| `go.assume_pure`, `bracket_paths`, `excluded_paths`, `dynamic_state_vouches` | config | — | no — caller soundness assertions | keep |
| manifest `include`, `policy[]`, `term_lint.*` | config | — | detectable / no | keep |
| internal constants (`variantBound=4`, `defaultInterval=1s`, `sinkBuffer=16`, render caps, `derivedTimeout=2h`, `derivedBinaryTimeout=30m`) | compiled | — | `variantBound` measurable from hit rates; caps are presentation | keep unconfigurable |

**Counts.** 78 distinct knobs (105 surface entries). Derivable/detectable: 9, of which 8 already derive. Recommended: derive 1 (policy `timeout` default), delete 1 (`witness_concurrency`), merge-with 1 (`no_test`), keep 75. 11 internal constants stay constants.

## 6. Self-test story

`task test` is the diagnostic (`go test -race -timeout=40m github.com/greatliontech/stipulator/...`); `task check` is the canonical verdict (vet → fmt-check → tidy-check → `go run ./cmd/stipulator check`).

CI: `go test … -count=1 -timeout=75m` (`.github/workflows/ci.yaml:56,113`); measurement comment `:44-55`: **slowest package `internal/backends/golang` 1327s, whole run 1333s** on 24 cores — the plain suite is ~22 minutes, 99.5% one package holding 245 of ~380 tests. Self-host `stipulator check --full` cold: **30m43s for 446 executed / 0 served** (`.stipulator/policy.textproto:6-10`); race invocation 7200s envelope, `-test.timeout=100m`; the two `stipulate` members 2700s each.

Heavy tests: CLI-building tests (`owned_test.go:23`, `internal/cmd/check_test.go:182`, `pin_cli_test.go:28,114`, `prune_scoped_test.go:30`, `bind_cli_test.go:137`, `gap_lifecycle_test.go:26`); race-instrumented witness suites over temp modules (`freshness_purity_test.go`, `freshness_env_test.go`, `witnessrun_test.go` — 29 short-gates in that file); policy discovery / `go list` (`provenance_test.go`, `discovery_test.go`); `vouch_test.go:74` runs `go mod tidy`. Four `TestMain`s route resolver-child re-execs into the test binary.

`testing.Short()` gating exists at **96 sites across 21 files** (64 in `internal/backends/golang`, 23 in `internal/check`, 6 in `internal/cmd`, 3 in `internal/mcpserver`). **Nothing runs `-short`** — neither Taskfile nor CI — so the gates are latent.

What the self-host gate proves beyond the plain tests: the binding graph against the real corpus — every `REQ-*` resolves to a symbol with a matching shape hash and a passing bound test in this run; no resolved gap lingers; the coverage policy leaves no red unexcused; the serving path is sound over a real multi-invocation policy with 446 subjects. The plain suite proves the code over synthetic fixtures.

**Proposed partition.**
- *Tier 1 — pure/unit, seconds:* `internal/{canon, wire, diff, bundle, corpus, compile, coverage, views, records, policy, author, dossier, progress, profile, proptest, facts, verify}`, `stipulate`, `stipulate/structural` — ~135 tests; the CI measurement puts everything outside `golang` at ~6s.
- *Tier 2 — fixture-driven executions, the 22 minutes:* `internal/backends/golang` spawns, the CLI-building tests, the in-process server runs. The 96 gates mark most of it; `internal/backends/golang` has 245 tests and ~64 gates — finish the gating so `go test -short ./...` lands in seconds; run Tier 2 unchanged in CI.
- *Tier 3 — the self-host `stipulator check`.* Only this proves corpus↔code binding; it should stay *warm*. CI does **not** run it: `.github/workflows/ci.yaml:39` cites `docs/issues/ci-seat-for-the-check-verdict`, **which does not exist** — a dangling pointer; the seat is unfilled.

## 7. Known-failure register relevant to our own loop

- **witness-selection-guard-masked-by-ineligible-red** — the empty-witness-selection diagnostic keys on any outcome; an ineligible leg's failed row masks the cause. *Lands: chunk 142.*
- **process-output-utf8-marshal** — one invalid UTF-8 byte makes the whole `CheckResult` unmarshallable after the run. *Lands: first field marshal failure, or the next executor-diagnostics change set.*
- **seeded-witness-serving-follows-direct-call-classifier** — a helper-indirected `rapid.Check` serves forever. *Lands: user decision.*
- **clause-granular-binding-claims** — a multi-clause requirement reads green with a clause unenforced. *Lands: chunk 142.*
- **content-hash-function-versioning** — a rebuild reds a tree that did not change. *Lands: chunk 143.*
- **pin-req-unchanged-text-wording** — misreporting. *Lands: chunk 143.*
- **normative-keyword-lint-timing-and-remedy** — a late refusal in the authoring loop. *Lands: chunk 144.*
- **attestation-refusal-names-no-reclassification** — no remedy named. *Lands: chunk 144.*
- **cli-verify-view-path-and-explain** — a CLI operator cannot narrow after a long run. *Lands: chunk 144.*
- **consolidation-ledger-train-114** — includes the N-requirement `gap` declaration compiling N times, and the two publish refusal ladders. *Lands: chunk 136.*
- **identity-walk-two-trackers**, **train-114-campaign-idle-window** — as filed.
- **Unfiled, found by this audit:** the dangling CI-seat pointer (`.github/workflows/ci.yaml:39`).

## 8. Cross-cutting shape

**Refusals live where their data is convenient, not where it is first available.** The Go backend's two-tier design is clean on paper — `validateConfig` is "static, record-only" (`golang/policy.go:27-33`) — but four purely static checks drifted into `NormalizeInvocation` next to the field they populate. At the orchestration level the coverage policy's only refusal sits after execution in all five consumers, and the scope/view vocabulary after the run in `gate` and `verify` — while `toolCheck` (`server.go:544-550`) shows the corrected shape, applied once and not generalized.

**Progress is a reporter only one of two surfaces constructs.** The `progress` package is well-built and has one instantiation site, in the MCP server; every phase mark on the CLI path is knowingly inert. `REQ-mcp-progress` demands liveness only of the agent surface, so the CLI's 30-minute silence is an unstated requirement, not a violation.

**The freshness answer is computed after the load it could have replaced.** `prepareWitnessGroups` builds two full typed observations per group, then asks whether each fingerprint is valid; chunk 141 adds a whole-tree typed load ahead of it for seeded classification. A warm check with a fully valid store pays the entire package-loading cost of a cold one; only execution is saved. Four call sites re-derive the same normalized invocations and obligation universe.

**Persistence granularity was solved once and not propagated.** The selective runner installs at each invocation's completion; the `--full` path batches every record into an end-of-run loop. With no CLI signal handling, an interrupted `--full` check loses everything and says nothing.

**The shared seam:** a *prepared policy capture* — one value at the top of every witness-consuming operation carrying the validated policy, normalized invocations, obligation universe, coverage policy, resolved scope, and the caller's view/scope vocabulary, every refusal decidable from those inputs raised before the first child process. `capturePolicy` (`derive.go:575`) is three-quarters of it, built too late and more than once. Attaching the same seam to a CLI reporter (a sink installed in `cmd/root.go`, mirroring `server.go:712`) and to `signal.NotifyContext` in `main.go` closes sections 2, 3 and the duplication half of 4 in one structural move.
