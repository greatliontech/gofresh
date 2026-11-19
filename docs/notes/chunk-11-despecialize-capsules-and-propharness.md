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
