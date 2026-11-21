# Chunk 6 Working Notes: Unified Consumer-Boundary Capabilities

## Scope & Goals

Deliver the unified consumer-boundary capabilities on `gofresh` so `stipulator`, `gomutant`, and `pew` can operate directly on `Session -> Snapshot -> RuntimeBinding/BuildBinding -> Unit / CheckingUnit` with zero parallel source-certificate engines, zero duplicate `Session.Snapshot` loads across execution models, zero filesystem/SSA/`go env` overhead on pure units, runner-owned ephemeral environment exclusions, and endpoint-coherent stale runtime-input mover diagnostics.

## Derived Design & Invariants

### 1. Static-Declaration Subjects & `SourceResult` Certificate Kind
- **Go Declaration Universe (`internal/dynstate/directives.go`, `scan.go`)**:
  - **Callable subjects (`Callable: true`)**: top-level `func` declarations (excluding blank `_`), positional `init#<file>#<ordinal>` declarations, and concrete methods `<TypeName>.<Method>` on non-interface types where `!syntaxutil.InterfaceReceiver(method)` (plus concrete struct methods promoted from embedded interfaces, preserving open-world carrier soundness on concrete method wrappers).
  - **Non-callable static declarations (`Callable: false` / `StaticDecl: true`)**:
    - Top-level `type` (`*types.TypeName`, defined types and type aliases, excluding `_`), `const` (`*types.Const`), and `var` (package-level `*types.Var`).
    - Interface method specifications `<IfaceName>.<Method>` (`_, isIface := typeName.Type().Underlying().(*types.Interface); isIface`).
    - Struct fields `<StructName>.<Field>` (`_, isStruct := typeName.Type().Underlying().(*types.Struct); isStruct`), including promoted fields resolved unambiguously via `types.LookupFieldOrMethod(typeName.Type(), true, p.Types, candName)` (`v, ok := fieldObj.(*types.Var); ok && v.IsField()`, keyed by `v.Origin()`), guarded by a `visited map[types.Type]bool` set for pointer-embedded recursive structs (`type Node struct { *Node }`).
  - **Directives & Ambiguity Soundness**:
    - `//gofresh:pure` and `//gofresh:external` are scanned on `GenDecl`/`TypeSpec`/`ValueSpec` and struct/interface `ast.Field.Doc` (including promoted fields/interface methods across package cones via `Fact.PureFields`/`ExternalFields` and `PureMethods`/`ExternalMethods`); conflicting `//gofresh:pure` + `//gofresh:external` refuses the scan.
    - Enclosing-type ambiguity propagation: when `scan.ambiguous[Subject{pkg, recv}] != ""` (for example, `type Box = dep.Box` declared in two variants), `<recv>.<Member>` inherits that ambiguity refusal even if `v.Origin()` resolves to the same upstream declaration.
    - Non-callable static declarations never receive `openWorld`, `downgradeReason`, `downgradeCulprit`, `vouchDischarges`, or `discharges` in `scan.go`, so they never enter Stage-B reachability or inflate budget-cut counts.
- **Result Kinds (`SourceResult`, `CodeResult`, `Measurement`)**:
  - **`SourceResult` (`guard.SourceResult = 3`)**: certifies a static source/declaration fact (symbol resolution, shape pin, static witness classification) for **any** Go declaration (callable or non-callable). Captures code guards only (`Toolchain`, `BuildConfig`); skips `deriveViewDynamicState` and Stage-B SSA reachability during `Snapshot` observation (`cones = nil`, `computeOpenWorld = false`); validates `MaximalClosure`, `EffectiveTestVariantClosure` (including `ExtendInertBatch` / `CheckBatchWithLedgers`), `ToolchainContent`, `AdmissionPolicy`, `ClosureStrategy`, code `Guards`, and `AmbiguousSubjectCause` while rejecting measurement guards and runtime execution/observation fields in `Fingerprint.Validate()`. Refused by `Unit.Begin*`, `NeedsObservation`, and `captureObserved`.
  - **`CodeResult` (`guard.CodeResult = 1`)**: admits both callable subjects (full execution freshness) and non-callable static declarations (`StaticDecl: true` clears runtime `Unverifiable` while preserving `AmbiguousSubjectCause` and `ExternalDirectiveCause`). `Unit.Begin*`, `NeedsObservation`, and `ensureObservable` refuse non-callable declarations (`StaticDecl: true`).
  - **`Measurement` (`guard.Measurement = 2`)**: refuses non-callable declarations (`StaticDecl: true`) at `Session.Snapshot` preparation before `ComputeMaximalFactsBatch`.
- **`testvariant.InertForSubject` (`internal/testvariant/testvariant.go`)**:
  - Extend `hasDot` (`<recv>.<name>`) handling so `decl.Kind == "type" && decl.Name == recv` in `before.Declarations` is marked reachable (defeating inertness if `type <recv>` or its embedded types in `*_test.go` are edited or removed), and `rooted` holds when a matching `method` exists, when `type <recv>` transitively reaches `name` (or an imported embedded package in `oldFiles[decl.File].Imports`), or when `base.Bindings.References` contains `recv` alongside `name` (or an imported embedded package in `base.Bindings.Imports`), while rejecting nonexistent members on self-contained types (`pair.nonexistent`).

### 2. Execution-Model Snapshot Projection (`(*Snapshot).WithExecution(ExecutionModel)`)
- **Snapshot-Scoped Execution Model**:
  - Store `executionModel ExecutionModel` and `hasExecutionModel bool` on `Snapshot` (`effectiveExecutionModel()` returns `v.executionModel` when `hasExecutionModel` is true, falling back to `v.session.executionModel` only on raw struct-literal test views).
  - Replace all direct `v.session.executionModel` reads in `view.go`, `binding.go`, `checking.go`, `judgment.go`, `unit.go`, and `explain.go` with `v.effectiveExecutionModel()`.
- **Single-Pass Multi-Model Precomputation (`scan.go`, `scan_dynstate.go`, `execution_projection.go`, `internal/observability/rooted.go`)**:
  - When `SessionPolicy.Execution` is `GeneralExecution`, `scanViewSubjects` preserves its zero-SSA fast path and populates `GeneralExecution` only; `WithExecution(m)` succeeds for `GeneralExecution` and refuses `m != GeneralExecution`.
  - When `SessionPolicy.Execution` is `PackageExecution` or `SingleSubjectExecution` (test-binary sessions), `deriveViewDynamicState` evaluates `dynstate.Compose` in memory for all 3 models (`GeneralExecution`, `PackageExecution`, `SingleSubjectExecution`), and `observability.Prover.ComputeRootedAndBinaryFunctions` computes both per-subject `RootedFunctions` and per-package binary `RootedFunctions` over a **single** loaded `*Program` per downgraded package (`<= 1` `"load"` and `<= 1` `"prove"` event per cold package; `0` extra `go` spawns or SSA builds), persisting all 3 per-model projections in `packageScanEntry` (`scanEntryVersion = 9`, `DynamicStateStrategy = "gofresh/dynamic-state@100"`).
  - `(*Snapshot).WithExecution(model ExecutionModel) (*Snapshot, error)` projects `v.facts` onto `model` in pure memory in $O(|\text{subjects}|)$ with fresh transactional state (`sealed = false`, empty attachments/obligations) and `v.observe(ctx)` re-observes at `v.effectiveExecutionModel()` so closing comparisons match 100%.

### 3. Zero-Overhead Pure `Unit` & `(*RuntimeBinding).NeedsObservation`
- Reorder `Unit.Register` (`unit.go`) so `ValidateBracketOptions` (`BracketPaths`, `ExcludedPaths`, `ExcludedEnv`, `ScratchNamespaces`), `u.view.CaptureBatch(preparing)`, and `observed` selection execute **before** frame capture.
- When `len(observed) == 0 && !u.identityOnly && process.Capture == ""`:
  - Use `runtimeinput.ResolveProducerFrame` (symlink-resolved coordinates + `outcome.Span` with **zero** `CaptureBracket` directory tree walk).
  - Skip `prepareOutcomeSupport` (zero Tier-2 SSA) and `prepareTrackedChdirSupport` (zero Tier-2 SSA and zero `go env`).
  - On `NormalCompletion`, `Unit.Close` skips `frame.Observe*` (zero `go env`, zero `testlog` I/O); on `AbnormalCompletion`, `frame.Completion` + `frame.ObserveInputs` still synthesizes the canonical incomplete observation from `ResolveProducerFrame`'s coordinates.
- Add `(*RuntimeBinding).NeedsObservation(subjects []Subject) (bool, error)` in `binding.go`: validates non-empty callable `subjects` under the binding's snapshot and execution model (refusing `SourceResult`, `StaticDecl` subjects, unknown subjects, cross-package sets, and `len > 1` under `SingleSubjectExecution`) and returns `true` iff any subject requires runtime observation to be `Valid`.

### 4. Runner-Owned Environment Exclusions (`ProcessDescription.ExcludedEnv`)
- Add `ExcludedEnv []string` to `ProcessDescription` (`unit.go`), `ProducerIngest` (`internal/runtimeinput/producer.go`), and `WithExcludedEnv(names ...string)` (`internal/runtimeinput/testlog.go`, re-exported in `runtimeinputs.go` for Chunk 6 tests before Gen-1 cleanup in Chunk 7).
- Validate each excluded name via `ValidateExcludedEnv`: non-empty valid UTF-8, no `'='`, `'\x00'`, `'\r'`, or `'\n'`, and **`PWD` strictly non-excludable** (`gotool.EqualEnvKey(name, "PWD")` refused fail-closed at `Unit.Register` and `TestLogOption` evaluation).
- During `"getenv"` ingestion, matching excluded names (`gotool.EqualEnvKey`) record neither an `env` manifest entry nor a per-env disposition, while `OutcomeBinding` and classification-root resolution continue using the full `Env`.

### 5. Endpoint-Coherent Stale Runtime-Input Diagnostics (`MovedInputs`)
- Add `MovedInputs []string` to `CheckedCandidate` (`checking.go`) and `RuntimeInputSpanError` (`unit.go`):
  - `Verdict` remains `==` value-comparable (`judgment.go`).
  - `recordResult` retains `movedInputs []string` captured directly from the deciding `runtimeEndpoint` (`before` or `after`) during `checkRecordsWithEndpoints` and `CheckingUnit.closeSlots` (preserving movers across ABA revert intervals without post-window TOCTOU filesystem re-reads, uncapped and cloned for caller ownership).
  - `RuntimeInputSpanError` populates `MovedInputs` from the bracket revalidation attribution on `BracketMoved`.
