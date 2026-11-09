# Extract `internal/closure/internal/toolchain`, Unify Structural AST Primitives, Decompose Toolchain Verifiers & Add Direct Unit Tests

**Lands:** Chunk 4 in [`docs/plans/plan.md`](../plans/plan.md) (`Extract, Consolidate, Optimize & Harden gofresh/internal/closure/internal/toolchain`).

## Context & Concrete Findings

### 1. `toolchain_*.go` Concentrates ~20,036 Lines Across 6 Flat Files in `internal/closure`

- `toolchain_audit_io.go` (`8,320` lines: `verifyOSPackageAST` + helpers `7,508` lines; `verifyBufioWriterAST` `797` lines), `toolchain_audit_core.go` (`6,091` lines), `toolchain_loader.go` (`2,814` lines), `toolchain_contracts.go` (`1,995` lines), `toolchain_scope.go` (`977` lines), and `toolchain_index.go` (`840` lines) live inside flat `internal/closure` despite the AST/assembly/binary verifiers depending only on `go/ast`, `go/parser`, `go/token`, `debug/elf`, `debug/macho`, `internal/auditset`, and `internal/closure/internal/cprep` (zero `go/ssa` or `go/packages` dependency).

### 2. Extensive Duplication Across the 19 `verify*PackageAST` Verifiers

1. **`indexPackageAST` (`toolchain_index.go:53-239`) Is Only Used in 4 of 19 Verifiers**:
   - Only `verifyIOCopyPackageAST`, `verifyBytesBufferAST`, `verifyStringsBuilderAST`, and `verifyBufioWriterAST` call `indexPackageAST`.
   - The other **15 package verifiers** (`verifyOSPackageAST`, `discoverOSInactiveState`, `verifyInternalTestlogAST`, `verifyTestingPackageAST`, `verifyRuntimeExitHooksAST`, `verifySyscallExitAST`, `verifySyncOnceAST`, `verifyMapsPackageAST`, `verifySlicesPackageAST`, `verifyContextPackageAST`, `verifyReflectPackageAST`, `verifyFmtPackageAST`, `verifyFilepathPackageAST`, `verifyInternalCPUInitializeAST`, `verifyInternalPollAST`) hand-roll their own 60–170 line file/import/declaration indexing loops.
   - Notably, `verifyOSPackageAST` (`toolchain_audit_io.go:155-322`) and `discoverOSInactiveState` (`toolchain_audit_io.go:5881-5983`) both walk `os` `files` in the same call to build duplicate `pkgDeclCounts`, `funcFile`, `topFuncs`, struct spec maps, and per-file import maps.
2. **Duplicate Scope / Shadowing & Non-Selector Identifier Walkers (`toolchain_scope.go` vs `toolchain_contracts.go` & `toolchain_audit_io.go`)**:
   - `verifyInternalPollAST` defines local closures `collectNonSel` (`toolchain_contracts.go:1356-1371`) and `shadows` (`1380-1453`) that are 100% duplicates of `walkNonSelectorPropIdents` / `allNonSelPropIdentsIn` and `funcShadowsAnyIdent` in `toolchain_scope.go`.
   - `rawFileMethodShadowsReserved` (`toolchain_audit_io.go:31-53`) and `paramsOrResultsShadow` (`toolchain_audit_io.go:7216-7233`) duplicate `funcDeclaresParamOrResult` + `bodyDeclaresAnyIdent` (`toolchain_scope.go:25-77`).
3. **Three Duplicate `ignoringEINTR` / `ignoringEINTR2` Verifiers**:
   - `verifyOSIgnoringEINTR` (`toolchain_audit_io.go:2868-2924`), `ignoringEINTR2` in `verifyOSGetwd` (`toolchain_audit_io.go:4400-4463`), and `verifyIgnoringEINTR` in `verifyInternalPollAST` (`toolchain_contracts.go:1474-1522`) all verify the same retry loop (`for { [v,] err := fn(); if err != syscall.EINTR { return [v,] err } }` or `return fn()`).
4. **Near-Identical `verifyMapsPackageAST` (`toolchain_audit_core.go:2927-3028`) and `verifySlicesPackageAST` (`3030-3137`)**, plus **Parallel `verifyBytesBufferAST` (`5010-5321`) and `verifyStringsBuilderAST` (`5323-5635`)**:
   - `verifyMapsPackageAST` and `verifySlicesPackageAST` duplicate 95 lines of import, bodyless-decl, `go`-stmt, and `unsafe`/`runtime`/`syscall`/`reflect` identifier rules, differing only in package name and required function list.
   - `verifyBytesBufferAST` and `verifyStringsBuilderAST` duplicate ~250 lines verifying in-memory byte-slice sinks (`buf []byte`, `Len()`, `Cap()`, `Reset()`, `Grow(n)`, `Write(p)`, `WriteByte(c)`, `WriteRune(r)`, `WriteString(s)`).
5. **Duplicated Directive Scanners, Receiver-Type Extractors, and Audited Linkname Tables**:
   - 5 compiler directive scanners (`auditedLinknamesWithLocals` in `maximal.go:1637`, `buildIndex` + `linknamesFromDoc` in `analyzer.go:625, 2414`, `scanGoDirectiveComments` + `scanVerifiedLinknameDirectives` in `toolchain_index.go:231`, `discoverRuntimeInactiveGates` in `toolchain_contracts.go:1192`, `hasHarnessForbiddenDirective` in `propertyharness.go:997`).
   - 3 AST receiver base type name extractors (`receiverBaseTypeName` in `analyzer.go:2536`, `recvBaseTypeName` in `toolchain_contracts.go:481`, `recvTypeName` in `toolchain_index.go:509`).
   - `auditedLinknameTargets` (`maximal.go:1540`) and `auditedReadOnlyVarLinknameTargets` (`maximal.go:1609`) live in `maximal.go` instead of `internal/auditset`.

## Resolution

During Chunk 4:
1. Move `auditedLinknameTargets`, `auditedReadOnlyVarLinknameTargets`, and `ClassBPackages` into `internal/auditset`.
2. Extract `internal/closure/internal/toolchain` organized into 17 focused files (~400–750 lines each: `index.go`, `scope.go`, `audit_os_core.go`, `audit_os_open_read.go`, `audit_os_getwd.go`, `audit_os_stat.go`, `audit_os_inactive.go`, `audit_bufio.go`, `audit_io_buffers.go`, `audit_fmt.go`, `audit_testing.go`, `audit_testlog_poll_cpu.go`, `audit_runtime_syscall.go`, `audit_sync_context_collections.go`, `audit_reflect.go`, `audit_filepath_offsurface.go`, `audit_asm_machcode.go`), while splitting `toolchain_loader.go` in `internal/closure` into `toolchain_contracts_orchestrator.go` and `toolchain_source_loader.go`.
3. Extend `PackageASTIndex` in `toolchain/index.go` and use it across all 19 `Verify*PackageAST` verifiers; extract shared structural primitives (`VerifyStructFields`, `VerifyFuncPreamble`, `VerifyIgnoringEINTRHelper`, `VerifyPureGenericCollectionPackageAST`, shared buffer-sink helpers, and canonical statement matchers); and delete the duplicate scope/shadow/ident closures in `verifyInternalPollAST` and `verifyOSPackageAST`.
4. Add direct, fast AST unit tests in `internal/closure/internal/toolchain/` (`index_scope_test.go`, `audit_os_test.go`, `audit_sinks_test.go`, `audit_runtime_testing_test.go`).
