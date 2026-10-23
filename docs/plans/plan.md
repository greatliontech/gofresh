# Gofresh & Ecosystem Master Plan

This is the single canonical plan for `gofresh` and its consumer ecosystem (`stipulator`, `gomutant`, `pew`). It consolidates and replaces all historical plan documents (`tooling-redesign.md`, `cross-tool-train.md`, `capability-charters.md`, `unified-ecosystem-plan.md`, and `pipeline-audit/*`).

---

## Operating Principles

1. **First-Principles `gofresh` Focus First**: Audit, measure, refactor, and collapse duplicated/legacy seams inside `gofresh` using fast standard Go tooling (`go test`, `go vet`, `task check`, benchmarks, `go tool pprof`) before cutting a new release or running cross-repo pin/verify trains.
2. **Zero Open `gofresh` Issue Debt**: Retire all 50 issues in `docs/issues/` (`docs/issues/README.md` + `tooling-redesign-obligation-map.md`) by resolving their code, specification, and structural obligations from first principles and deleting each retired issue file.
3. **Rigorous Measurement & Adversarial Verification**: Measure CPU, heap allocations, and wall-clock latency before and after structural changes; run adversarial review subagents (`adversarial-reviewer`) on every pillar; commit atomically once tests and reviews pass with zero defects.

---

## Completed Foundation (Phases 1–4)

- [x] **Phase 1: Structural Toolchain Boundary Verifier (`gofresh/toolchain-verifier@5`)** (`12e22dd`)
  - [x] Replace brittle per-version stdlib SHA-256 hash tables with structural AST/directive verification (`closure/toolchainaudit.go`) enforcing `REQ-closure-toolchain-variation` across OS/arch/Go patch releases.
  - [x] Prune the abandoned `5.1w` native-proof spike (`-115,483 LOC`).
- [x] **Phase 2: Consumer Alignment with Structural Toolchain Verifier**
  - [x] Update `stipulator` (`02d4991`), `gomutant` (`c7eb401`), and `pew` (`a791928`) to consume the structural toolchain verifier and install clean binaries via `task install`.
- [x] **Phase 3: Plan Consolidation & Full 50-Issue First-Principles Audit**
  - [x] Audit every file in `docs/issues/` (52 files) and `docs/plans/` and classify all obligations into 6 execution pillars.
  - [x] Retire `docs/plans/tooling-redesign.md`, `docs/plans/cross-tool-train.md`, `docs/plans/capability-charters.md`, `docs/plans/unified-ecosystem-plan.md`, and `docs/plans/pipeline-audit/*` into this single canonical `docs/plans/plan.md`.
- [x] **Phase 4: Cold-Pass SSA / RTA / Allocation Optimization** (`c7667be`, `733ebe2`)
  - [x] Lazy `batchPreparer` (`(*Program).Prepare`, `(*Prepared).HasRoots`, per-group `(*Prepared).Release`) and completed/rootless group `delete(h.progs, group.path)` in `closure/observability.go` and `closure/rooted.go`.
  - [x] Pre-filter `(*freshParamAnalysis).resolve` by `paramCrossingEligible` / `paramEligible` and hoist `fn.String()` outside `sort.Slice` in `closure/freshparam.go` (**-150.2 MB/op**).
  - [x] Guard comment directive scanning with `strings.Contains` in `(*tier2Analyzer).buildIndex` and `linknamesFromDoc` in `closure/analyzer.go` (**-67.3 MB/op**).
  - [x] Share a single filtered `ssautil.AllFunctions` slice between `flagRegistrationFacts` and `flagSetProvenance` in `closure/observability.go` (**-59.4 MB/op**).
  - [x] Move zero-delta mask check before `ContainsTypeParam` in `(*attributedRTA).addRuntimeType` and reuse `r.typeParamSeen` in `closure/internal/rta/rta.go` (**-33.2 MB/op**).
  - [x] Add `verifiedPackageMemoKeyWithPolicy` in `closure/toolchainaudit.go` to avoid per-package `admissionPolicy()` recomputation.

### Benchmark & Gate Telemetry Summary

| Benchmark / Gate | Baseline | Post-Phase 4 (`c7667be`) | Delta |
| :--- | ---: | ---: | ---: |
| `BenchmarkComputeObservabilityBatch-24` (time/op) | `6.04 s/op` | `3.89 s/op` | **-35.7%** |
| `BenchmarkComputeObservabilityBatch-24` (bytes/op) | `2.70 GB/op` | `1.46 GB/op` | **-45.8%** |
| `BenchmarkComputeObservabilityBatch-24` (allocs/op) | `34.86M allocs/op` | `21.09M allocs/op` | **-39.5%** |
| `gofresh` warm `stipulator verify --no-test` | `11.1s` (verify `1.4s`) | `11.1s` (verify `1.4s`) | Verified |
| `stipulator` warm `stipulator verify --no-test` | `1m06.4s` (verify `3.9s`) | `1m06.4s` (verify `3.9s`) | Verified |
| `pew` warm `stipulator verify --no-test` | `3.6s` (verify `0s`) | `3.6s` (verify `0s`) | Verified |
| `gomutant` warm `stipulator verify --no-test` | `4.3s` (verify `0s`) | `4.3s` (verify `0s`) | Verified |

---

## Active `gofresh` First-Principles Refactoring & Issue Retirement (Pillars 1–6)

### Pillar 1: Retire Resolved Issues & Remove Unadopted `runtimeinput` Surface
- [x] **`runtime-type-parameter-rescan.md`**: Verify focused regression test coverage for self-referential named types + staggered masks in `closure/internal/rta/rta_test.go` (implemented in `c7667be`) and delete issue doc.
- [x] **`toolchain-variation-admission-registry.md`**: Retired by structural AST/directive verification (`gofresh/toolchain-verifier@5` in `12e22dd`); delete issue doc.
- [x] **`cold-analysis-pass-program-retention.md`**: Retired by lazy `batchPreparer.release` and `delete(h.progs, group.path)` in `c7667be`; delete issue doc.
- [x] **`runtime-inputs-dirty-unadopted.md`**: Remove unadopted `runtimeinput/dirty.go` (`CommitInspector`, `Dirty`) and its tests, remove `REQ-inputs-dirty` from `docs/specs/runtime-inputs.md`, reconcile `.stipulator/bindings/runtime-inputs.textproto`, and delete issue doc.
- [x] **`static-input-root-unadopted.md`**: Remove unadopted `runtimeinput.WithStaticInputRoot` and its tests, remove the static-input-root clause from `docs/specs/runtime-inputs.md`, reconcile `.stipulator/bindings/runtime-inputs.textproto`, and delete issue doc.
- [x] Run `go test ./...`, `task check`, adversarial review, and commit Pillar 1.

### Pillar 2: Collapse `closure` Classification Tables & Predicates
- [x] **`flag-surface-one-table.md`**: Collapse `flagSymbols` (`internal/auditset`), `flagRegistrationSymbol` / `flagValueRegistration` / `flagPointerRegistration` (`closure/observability.go`), `flagProvenSetMethod` / `flagProvenSetUse`, and the refused-rows test table (`closure/audited_test.go`) into one `auditset.FlagSurface(name)` table, and share the unaudited-standard symbol ladder between `closure/maximal.go` and `closure/analyzer.go` while keeping refusal tier observable and storage provenance independent.
- [x] **`classb-arms-one-table.md`**: Collapse `closure/effects.go`'s 9 per-package `if pkgPath == ...` arms in `classBEffect` and the `classBPackages` gate into one declarative table keyed by `(pkgPath, symbol) -> (effectKind, reason)` where `classBPackages` derives from the table's keys, preserving current refusal precedence.
- [x] **`harness-admission-families-one-table.md`**: Collapse the 4 testing-harness admission families (logging, subtest driver, fuzz driver, benchmark pacing) across predicate, effect constructor, `...Function(audited, fn)`, `stdBodyCut`, enumerated dynamic-target loop, and `immutableEnvironmentMethod` into one table keyed by symbol name, preserving observable-effect vs. outcome-method distinction.
- [x] **`dispatch-admissions-one-predicate.md`**: Collapse the 3 computed-call/invoke dispatch admission routes (`resolved`, `subjectDeterminedInvokes`, `heldKnown`/`narrowedTargets`) in `closure/analyzer.go` (`scanCall`) into one shared predicate over `(site, operand, targets)` with explicit operand-closure and indexed non-test-main target checks.
- [x] **`fold-import-name-declared.md`**: In `closure/maximal.go`, bind unnamed imports using the declared package name from the package listing (`h.listings`) when available before falling back to path derivation, preserving fail-closed collision behavior.
- [x] Delete the 5 Pillar 2 issue docs, run `go test ./...`, benchmarks, adversarial review, and commit Pillar 2.

### Pillar 3: Collapse Duplicate AST / SSA / Type Walkers in `closure` & Root `gofresh`
- [x] **`unify-carrier-walks.md`**: Collapse `typeMayCarryUnknownDynamic` (`purity.go`), `typeMayCarryDynamic` (`closure/attribution.go`), and `typeHandsOutDynamicAlias` (`purity.go`), plus `openWorldTerm` (`purity.go`) and `rootMayReceiveUnknownDynamic` (`closure/attribution.go`), into one exported structural walk in `closure/` parameterized by `TypeParam` cycle policy and leaf semantics.
- [x] **`closed-value-ladders-one-source.md`**: In `closure/freshpath.go`, unify `closedDynamicValueUncached` and `collectDynamicTargets` (and `cellReferrersClosed` / `collectCellStores`) into one shared ladder returning `(closed bool, targets []*ssa.Function)`.
- [x] **`direct-call-site-index-one-source.md`**: In `purity.go`, fold `initOnlyReachableHelpers` and the `memberTypes` / `carrierFree` judges onto the shared `callSiteIndex` (`directCallSites`, `resolveParam`), preserving `initOnlyReachableHelpers`'s direct `ast.Ident` callee restriction and per-variant scoping.
- [x] **`sync-variable-judgments-one-shape.md`**: Unify `provenSharedPools` and `dataMemoVars` in `purity.go` over one sync-variable use walker parameterized by admitted call set, receiver ladder, and completeness policy, and unify `auditedSyncSymbol` / `auditedPoolSymbol` / `auditedMemoSymbol` in `closure/effects.go`.
- [x] **`registration-audit-walk-helper-unification.md`**: In `purity.go`'s environment-free registration audit, collapse the 3 break-walks (`breakTargets`, `breakReachIn`, deep-write arm) into one `breakIdents(expr, gate)` helper and the 3 composite-literal element walks into one iterator.
- [x] Delete the 5 Pillar 3 issue docs, run `go test ./...`, benchmarks, adversarial review, and commit Pillar 3.

### Pillar 4: Algorithmic, Memo, & Resource Improvements
- [x] **`binary-roots-single-mask-union.md`**: In `closure/rooted.go` (`binaryRootedPackage`), compute the binary-wide harness-root reachability union in one all-roots attributed RTA walk (single mask) instead of calling `ComputeRootedFunctions` in 64-subject slices and unioning per-root maps, preserving `prog.Ambiguous`, fail-closed completeness, cancellation, and `defer delete(h.progs, path)`.
- [x] **`per-file-memos-one-shape.md` & `memo-scope-axes.md`**: Share the per-directory load-serve-pend-merge memo mechanics across `fileScan`, `variantParseMemo`, and `canonicalFileDigest` (preserving each payload's complete key including compartment member filename), consolidate redundant file-read paths within a pass, and split the dynamic-state pass result type from the per-cone composition result type in `dynamicstate.go`.
- [x] **`persistent-memo-disk-retention.md`**: Add bounded disk retention / pruning for the disposable memo store (`~/.cache/gofresh`) in `closure/internal/cachefile/cachefile.go` (`DefaultMaxBytes = 2 << 30`, `SetMaxBytes`, `Prune`) and re-export `DefaultMemoMaxBytes`, `MemoPruneReport`, `SetMemoMaxBytes`, and `PruneMemos` in `closure` and `gofresh`.
- [x] **`children-budget-bounded-by-available.md` & `resident-walk-counts-a-vfork-child-twice.md`**: Reconcile `REQ-fresh-resident-readings` (`docs/specs/overview.md` and `resident/host.go`) so soft GC targets, child limits, and physical spawn admission are explicitly separated and `/proc` shared-mapping / `CLONE_VM` semantics are accurately specified.
- [x] **`attribution-mask-width.md` & `fixture-tier-parallelism.md`**: Record post-Phase-4 benchmark evidence (`3.89s` for `BenchmarkComputeObservabilityBatch`, `4.6s` for `closure` short tier) showing `uint64` mask width and current fixture isolation boundaries meet targets without coarsening cancellation or risking shared-state races; delete both issue docs.
- [x] Delete all 8 Pillar 4 issue docs, run `go test ./...`, benchmarks, adversarial review, and commit Pillar 4.

### Pillar 5: Root `gofresh`, `runtimeinput`, `gotool`, & Codec/Plumbing Collapses
- [x] **`discharge-reason-channel-one-source.md`**: In `dynamicstate.go` (`composeDynamicState`), carry the deciding discharge channel enum on the culprit fact and compose the verb + channel reason string in one place, preserving typed deciding causes.
- [x] **`attestation-keyed-record.md`**: Consolidate duplicate `SingleSubject` / `PackageProcess` attestation plumbing across `Engine`, `factScope`, `observationFacts`, and `View.Sibling` into an attestation-keyed internal map while preserving published JSON/evidence fields (`SingleSubjectDischarges`, `PackageProcessDischarges`) and `GeneralExecution` semantics.
- [x] **`json-record-readers-one-home.md`**: Extract shared strict JSON decoding primitives (`uniqueObjectFields`, `isJSONNull`, `requireJSONEnd`, canonical re-encode check parameterized by whitespace policy) into `internal/jsonrecord`, used by both `Fingerprint.UnmarshalJSON` and `runtimeinput.parseManifest`.
- [x] **`attribution-splits-one-quoted-string-helper.md`**: In `runtimeinput`, share one `strconv.QuotedPrefix`-based helper between `splitBracketAttribution` and `splitAttribution`, preserving legacy bare-root handling and canonical re-key idempotence.
- [x] **`runtime-input-entries-implicit-context.md`**: Thread the owning unit's `context.Context` through `runtimeinput` `FromState`, adoption, `Absolute` / `Relative`, and `Merge` paths so cancelled operations never continue under a private `context.Background()`.
- [x] **`loader-spawns-outside-the-runner.md`**: Consolidate `packages.Load` configuration construction across `explain.go`, `closure/viewload.go`, `closure/maximal.go`, and `closure/internal/program/program.go` behind one shared helper enforcing explicit `Env`, `Dir`, and `Context`.
- [x] **`closure-sub-contract-granularity-residue.md`**: Decompose the 3 bundled paragraphs in `docs/specs/closure.md` (`REQ-closure-shared-dynamic-state-escape-narrowings`, `REQ-closure-shared-dynamic-state-audited-discharges`, `REQ-closure-observability-audited-set`, plus benchmark pacing in `REQ-closure-observability-analysis`) into atomic sub-requirements at sentence boundaries and retarget bindings/citations.
- [x] Delete all 7 Pillar 5 issue docs, run `go test ./...`, adversarial review, and commit Pillar 5.

### Pillar 6: Precision Refinements, Field-Report Dispositions, & Consumer Alignment
- [x] **Dynamic Call & Closure Precision (`invoke-targets-narrowed-by-operand.md`, `iterator-calls-and-std-invokes-open-the-closure.md`, `dependency-nested-closures-outside-the-drain.md`, `enumeration-targets-over-approximated.md`)**:
  - Narrow interface invoke targets in `closure/freshpath.go` (`closedInvokeTargets`) and `closure/observability.go` / `closure/analyzer.go` (`narrowedTargets`, `dispatchAdmitted`) when the receiver operand resolves to a closed set of concrete types whose selected methods have analyzed or audited bodies; traverse static call returns (`staticCallResultDynamicValue`) when the callee is analyzed/audited and its arguments carry no dynamic dispatch; scan cached dependency anonymous closures and closed dynamic targets in `addFunction` / `dispatchAdmitted`; retire the 4 issue docs.
- [x] **Standard Library & Protobuf / gRPC Boundary Refinements (`net-url-parse-godebug-channel.md`, `generated-proto-discharge-single-subject-only.md`, `in-module-generated-descriptor-writes-have-no-discharge.md`, `grpc-runtime-memo-and-registry-discharges.md`, `immutable-after-construction-objects.md`, `entropy-reach-through-tls-handshakes-marks-networked-witnesses-uncacheable.md`)**:
  - Fix `linkKeys` in `purity.go` (`initAliasedLocals`) to read `linkAliased` (excluding call-result bindings) so `out := protoimpl.TypeBuilder{..., MessageInfos: file_..._msgTypes}.Build(); File_..._proto = out.File` never creates a false `CarrierLinks` edge between `File_..._proto` and `file_..._msgTypes`; preserve the fail-closed boundaries for `net/url` `GODEBUG` parsing, single-subject lazy proto table discharges, whole-object immutability fixpoints, and `crypto/rand.Read` TLS handshake entropy; retire the 6 issue docs.
- [x] **Diagnostics, Edge Cases, & Platform Boundaries (`explain-no-chain-for-a-dependency-culprit.md`, `root-directory-input-with-empty-manifest.md`, `coverage-testmain-export-load-failure.md`, `go-types-named-unpack-races-iscomplete.md`, `assembly-fixtures-amd64-only.md`, `containment-windows-job-object.md`)**:
  - Follow `CarrierLinks` (`linkAdj`) connected components in `explain.go` (`explainCulprit` and `envAuditTrail`) so culprits whose refusal arrived via a shared-backing carrier link derive their full chain instead of returning an empty chain; preserve fail-closed loader/testlog boundaries and record platform/toolchain triggers in Conditional Capability Triggers below; retire the 6 issue docs.
- [x] **Consumer & Fleet-Sweep Alignment (`prints-default-one-home.md`, `served-knob-strings-judged-by-consumer-grammars.md`, `cli-long-help-rendering-two-homes.md`, `fleet-sweep-tugboat-vouch-list-retires.md`, `toolchain-dependency-consumer-adoption.md`, `audit-boundary-residue.md`, `tooling-redesign-obligation-map.md`, `docs/issues/README.md`)**:
  - Remove the duplicate `tugboat` `--vouch` list in `scripts/fleet-sweep.sh` (and `docs/fleet-sweep.md`) now that `tugboat` carries `benchmarks/vouches`; route consumer-side obligations (`pew`, `gomutant`, `stipulator`) to the Post-`gofresh` Ecosystem Verification & Release Train below; retire all remaining `docs/issues/*.md` files and `tooling-redesign-obligation-map.md`, leaving `docs/issues/README.md` with zero open issues.

---

## Post-`gofresh` Ecosystem Verification & Release Train

- [x] Re-pin and run `stipulator verify --no-test` and `task check` on `gofresh`.
- [x] Update `stipulator`, `gomutant`, and `pew` to the finalized `gofresh` commit, align `pew` guidance helpers (`guidance.PrintsDefault`, `Document.Served`, `Registration.LongHelp`), run `stipulator pin` and `stipulator verify --no-test` across all 4 repositories, and install updated binaries via `task install`.
- [ ] Execute tagged release train (`gofresh` -> `pew`, `stipulator`, `gomutant`) when ready for downstream distribution.

---

## Conditional Capability Triggers (Archived from `capability-charters.md` & Field Issues)

These capabilities are intentionally not active work items; they trigger **only** when their concrete admission condition is met:

1. **Cross-Process Shared-Memory / External Service Witness Isolation**: Triggers only if a first-party repository requires cacheable witness attestation across external daemon processes not spawned as children of the test process.
2. **TLS Entropy / Loopback Handshake Discharge**: `crypto/tls` handshakes inherently read `crypto/rand.Reader` (`REQ-closure-entropy`). Discharging loopback TLS handshakes triggers only if a deterministic test-only entropy injection seam or explicit loopback TLS attestation model is introduced in the specification.
3. **Runtime-Mutated Global Registry & Carrier Memo Discharges (`google.golang.org/grpc/balancer.Register`, `channelz`, `pgregory.net/rapid:anyRuneGen`)**: Discharging runtime-mutated registries or pointer-to-struct globals requires a whole-object immutability-after-construction fixpoint proof (`immutable-after-construction-objects`) or single-subject registry attestation.
4. **In-Process `GODEBUG` Runtime-Relevance Channel (`net/url` Parsing)**: `url.Parse` / `ParseQuery` read `GODEBUG` settings (`urlstrictcolons`, `urlmaxqueryparams`) mutable in-process via `os.Setenv("GODEBUG", ...)`; admission triggers only when `CodeResult` guards and in-process `Setenv("GODEBUG")` package poisoning are jointly specified.
5. **Selected-Toolchain Covered Test-Main Export & `go/types` Concurrency (`GOFLAGS=-cover`, `Named.unpack`)**: Triggers when the upstream/forked Go toolchain (`cmd/go/internal/work/exec.go` covered test-main path handling and `go/types` `Named.fromRHS` synchronization) lands in the pinned toolchain release; loader errors continue to fail closed until then.
6. **Non-`amd64` Assembly Fixture Bodies & Windows Job Object Containment (`CREATE_BREAKAWAY_FROM_JOB`)**: Triggers when non-`amd64` fixture execution or Windows native runner execution is selected on CI hosts.
7. **Testlog Caller-Frame Provenance for `/` Opens**: Triggers only if the Go toolchain `runtime/internal/testlog` interface is extended to pass caller PCs alongside open/stat operations.
8. **Remote Benchmark Execution & MCP Transport in `pew`**: Triggers only when a provisioned remote benchmark host or concrete driving-agent MCP workflow exists.
