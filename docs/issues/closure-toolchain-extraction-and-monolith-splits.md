# Extract `internal/closure/internal/toolchain`, Consolidate Directive/Type Helpers, and Split Oversized Toolchain Verifiers

**Lands:** Chunk 3 in [`docs/plans/plan.md`](../plans/plan.md) (`Extract gofresh/internal/closure/internal/toolchain`).

## Context & Concrete Findings

### 1. `toolchain_*.go` Concentrates ~23,200 Lines Inside Flat `internal/closure`

- `toolchain_audit_io.go` (`8,319` lines), `toolchain_audit_core.go` (`6,091` lines), `toolchain_loader.go` (`2,814` lines), `toolchain_contracts.go` (`1,995` lines), `toolchain_scope.go` (`977` lines), `toolchain_index.go` (`856` lines), `dependencies.go` (`125` lines), and `toolchainsource_*.go` (`57` lines) total `~21.2k–23.2k` lines inside `internal/closure` despite interacting with the rest of `closure` through a narrow selection/digest surface (`ResolveSelection`, `ResolveToolchainSelection`, `AttributeSelection`, `SourceDigests`, `SelectionDegradation`).

### 2. Duplicated Directive Scanners, Receiver-Type Extractors, and Audited Linkname Tables

1. **5 Compiler Directive (`//go:linkname`, `//go:linknamestd`, `//go:wasmimport`, `//go:cgo_*`) Scanners**:
   - `auditedLinknamesWithLocals` (`maximal.go:1637-1678`), `buildIndex` + `linknamesFromDoc` (`analyzer.go:625-645, 2414-2439`), `scanGoDirectiveComments` + `scanVerifiedLinknameDirectives` (`toolchain_index.go:231-451`), `discoverRuntimeInactiveGates` (`toolchain_contracts.go:1192-1236`), and `hasHarnessForbiddenDirective` (`propertyharness.go:997-1012`).
2. **3 AST Receiver Base Type Name Extractors**:
   - `receiverBaseTypeName` (`analyzer.go:2536-2553`), `recvBaseTypeName` (`toolchain_contracts.go:481-498`, byte-for-byte identical), and `recvTypeName` (`toolchain_index.go:509-522`, missing `*ast.IndexExpr` / `*ast.IndexListExpr`).
3. **Audited Linkname Tables Split Across `maximal.go` and `toolchain_index.go`**:
   - `auditedLinknameTargets` (`maximal.go:1540`) and `auditedReadOnlyVarLinknameTargets` (`maximal.go:1609`) are defined in `maximal.go` and referenced by `toolchain_index.go` and `asmverify.go` instead of living in `internal/auditset` alongside all other audited symbol tables.

### 3. Oversized Monolithic Toolchain AST Verifier Functions

Five single functions in `toolchain_audit_io.go` and `toolchain_audit_core.go` span 840–1,622 lines each:
1. `verifyOSPackageAST` (`toolchain_audit_io.go:13-1635` — **1,622 lines**).
2. `verifyTestingPackageAST` (`toolchain_audit_core.go:1032-2380` — **1,348 lines**).
3. `verifyTimePackageAST` (`toolchain_audit_core.go:3222-4278` — **1,056 lines**).
4. `verifyReflectPackageAST` (`toolchain_audit_core.go:4280-5230` — **950 lines**).
5. `verifySyncPackageAST` (`toolchain_audit_core.go:2382-3220` — **838 lines**).

## Resolution

During Chunk 3 (`Extract gofresh/internal/closure/internal/toolchain`):
1. Move `auditedLinknameTargets`, `auditedReadOnlyVarLinknameTargets`, and `ClassBPackages` into `internal/auditset` so `closure`, `asmverify`, and `toolchain` share a single authoritative source.
2. Extract `internal/closure/internal/toolchain`, unifying `receiverBaseTypeName` (including generic `*ast.IndexExpr` / `*ast.IndexListExpr` receivers) and directive comment scanning.
3. Decompose `verifyOSPackageAST`, `verifyTestingPackageAST`, `verifyTimePackageAST`, `verifyReflectPackageAST`, and `verifySyncPackageAST` into cohesive helper functions by subsystem/requirement while moving them into `internal/closure/internal/toolchain`.
