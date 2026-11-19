# Chunk 11 Working Notes: Delete `internal/dynstate/protoaudit` & De-Specialize/Consolidate `internal/propharness`

## 1. Scope & Governing Contracts (`docs/plans/plan.md:53-56`)

1. **Part A — Delete `internal/dynstate/protoaudit/` Completely & Generalize Capsule/Builder/Cluster Analysis**:
   - Update `REQ-closure-shared-dynamic-state` and `REQ-closure-shared-dynamic-state-proto` in `docs/specs/closure.md` and `REQ-vouch-recorded` in `docs/specs/purity.md` (re-pinning `.stipulator/bindings/closure.textproto` and `.stipulator/bindings/vouch.textproto`).
   - Delete `internal/dynstate/protoaudit/` completely (`0` `proto*` package/type/role names, `0` hardcoded protobuf field/method/role strings).
   - Replace `ProtoClusters` and `ProtoRuntimeTypes` with general Go dataflow-classified `LazyOnceCapsuleType`, `InitBuilderFact`, and `InitSettledClusterFact` (`RequireImmutableCapsuleGuard` in `freshstruct`).
   - Preserve all 7 capsule/cluster soundness invariants:
     1. `NonBuilderReferencedFn`
     2. CFG dominance of once-init before sub-struct pointer handouts
     3. `!bytes.Equal` snapshot guard
     4. Concrete capsule verification on interface containers
     5. Stateless / local-`sync.Once` closure capture checks
     6. `RequireImmutableCapsuleGuard`
     7. `NoPostInitCarrierWrites` + `CarrierImportCalls` sink isolation
2. **Part B — Total De-Specialization & Consolidation of `internal/propharness`**:
   - Update `REQ-closure-observability-property-harness` in `docs/specs/closure.md` (re-pinning `.stipulator/bindings/closure.textproto`).
   - Remove 100% of `"pgregory.net/rapid"` / `"RAPID_"` / `"rapid."` / `"T"` / `"Check"` / `"MakeCheck"` / `"Example"` hardcoding across `internal/propharness`, `internal/closure/propertyharness.go`, and `internal/dynstate`.
   - Consolidate duplicated AST indexing, settled-var, mutex-cache, and stdlib-purity helpers onto `refconfine.PkgIndex`, `internal/auditset`, `refconfine.WalkDynamicCarrier`, and one shared `propharness.VerifyPackageCached` memo across `closure` and `dynstate`.
   - Retire `docs/issues/dynstate-flowir-consolidation-and-despecialization.md` (and remove from `docs/issues/README.md`).
   - Bump `DynamicStateStrategy` and `ObservationRTA` / `propertyHarnessSummaryKeyPrefix`.

## 2. Architectural Design & Soundness Invariants (From Parallel Audits)

### 2A. Acyclic Import DAG & Cohesive File Layout (`<= ~900` LOC per non-test file)
- `internal/dynstate/syntaxutil/capsule_facts.go` (`~230` LOC): pure serializable fact structs (`LazyOnceCapsuleType`, `InitBuilderFact`, `BuilderSliceSpec`, `InitSettledClusterFact`, `ClusterCapsuleSliceBinding`) so `dynstate`, `closure` tests, and root tests share fact types with zero `internal/` visibility conflicts.
- `internal/dynstate/internal/capsule/` (replaces deleted `internal/dynstate/protoaudit/`, 13 cohesive files `<= ~880` LOC each):
  - `derive.go`, `methods_and_sinks.go`, `capsule_types.go`, `capsule_dominance.go`, `once_cone.go`, `atomic_cas_ptr.go`, `capsule_reflect.go`, `capsule_reflect_steps.go`, `builder_sample.go`, `builder_raw.go`, `builder_raw_init.go`, `snapshot_cone.go`, `clusters.go`.
  - Zero `proto*` package/type/role names; zero hardcoded protobuf field/method/type strings; adds `ExportedWriteGuardFields` (`if recv.<GuardField> == nil` dominance on `onceCone` exported-field writes, mechanically inferring `["ExtensionType"]` on `impl.ExtensionInfo` and requiring `NonNilExportedNames` membership on `StaticLiteral` slices).
- `internal/dynstate/cone_discharges_capsules.go` (`~250` LOC): extracts capsule/builder/cluster variant-intersection & `RequireImmutableCapsuleGuard` helpers from `cone_discharges.go` (`968` -> `~800` LOC) and `cone_resolve.go` (`1,024` -> `~940` LOC).
- `internal/propharness/` (6 cohesive files `<= ~800` LOC each, replacing `index.go` and `protocol.go`):
  - `verify.go`, `surface.go`, `protocol_stdlib.go`, `protocol_context.go`, `vars.go`, `vars_cache.go`.
  - Zero `"pgregory.net/rapid"` / `"rapid"` / `"RAPID_"` / `"rapid."` / `"T"` / `"TB"` / `"Generator"` / `"Check"` / `"MakeCheck"` / `"Custom"` / `"Example"` / `"Make"` / `"MakeCustom"` strings.
  - Two-stage O(imports) `MayBeHarnessImports` + O(scope) `ScreenPackage` filter (`!pkg.Standard && (pkg.Module != nil || strings.Contains(firstSeg, "."))`), deriving `<UPPER_PKG>_`, `<pkg>.`, and `testdata/<pkg>` from `pkg.Types.Name()`, discovering `HandleStructs`, `HandleIfaces`, `DriverFuncs`, `WrapperFactoryFuncs`, `GeneratorTypes`, `SeededSampleMethods`, and `ReflectSynthFuncs` structurally, reusing `refconfine.PkgIndex`, `auditset`, `refconfine.WalkDynamicCarrier`, and `VerifyPackagePinnedCached` / `VerifyPackageWithIndex`.
  - Enforces 3 tightened soundness invariants:
    1. Upward caller-confinement of all ambient operations (`maphash`, `time.*`, post-init `os.*` / `filepath.Glob` / `template.Execute`, `testing.Short` / `Verbose`, and post-init reads of env/flag-derived `categoryA` globals).
    2. `sigRequiresSealedHarnessHandle` (`*H` or stdlib `*testing.T` / `testing.TB`, excluding unsealed `pkg.TB` interfaces) on `TypeParam`-returning exported functions/methods.
    3. Closed dynamic args + `harnessHandleValue` check on handle-typed param 0 when invoking anonymous harness closures (`target.Parent() != nil`) in `closure/analyzer.go` (blocking `f := MakeCheck(...); f(nil)` in non-test functions).
  - Generalizes `rta.Seeds.HarnessPkg string` -> `HarnessPkgs map[string]bool`.

