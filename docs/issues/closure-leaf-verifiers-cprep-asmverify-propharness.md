# Extract `cprep`, `asmverify`, and `propharness` Leaf Packages and Deduplicate Preprocessor/Harness Passes

**Lands:** Chunk 2 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose gofresh/internal/closure Leaf Verifiers`).

## Context & Concrete Findings

### 1. Duplicated Preprocessor, Cgo Preamble, and Assembly Token Scanners (`toolchain_cpreprocessor.go`, `cgo_includes.go`, `asmverify.go`)

1. **Two Near-Identical 200-Line Assembly Preprocessor Passes**:
   - `verifyAssemblyFileSinglePass` (`toolchain_cpreprocessor.go:1892-2107`) and `verifyNonStdAsmPreprocessorPass` (`asmverify.go:589-785`) both run a two-pass loop over `stripAssemblyComments(src, false, joinSpace)` (`joinSpace` in `{false, true}`), scan `#include` / `#define` / `#undef` / `#if*`, validate `#include "..."` against `allowedPureAsmStandardHeaders`, split middle-dot (`·` / `\u00b7` / `\xe2\x8b\x85`) tokens, and check `#define` bodies against forbidden assembly tokens.
2. **Three Duplicate Cgo Preamble & `"C"` Import Extractors**:
   - `sourceMayImportC` / `extractCgoPreamble` / `extractFileCgoPreambles` (`toolchain_cpreprocessor.go:139-200`).
   - `goCgoPreamble` / `appendCgoCommentGroup` / `isCgoImportLit` (`cgo_includes.go:225-274`).
   - `cgoPreamble` (`canonical.go:228-256`).
3. **14+ Open-Coded Quoted-Literal Skip Loops and Duplicate `[]byte` vs `string` Symbol Scanners**:
   - Quoted string/char literal skip loops (`if ch == '"' || ch == '\'' || ch == '`'` with `\\` escape handling) are open-coded 6 times in `toolchain_cpreprocessor.go` (`659, 716, 818, 893, 1152, 1514`) and 8 times in `asmverify.go` (`1423, 1833, 1888, 1954, 1985, 2021, 2082, 2583`).
   - `collectRawBytesRuntimeSymbolRefs` (`toolchain_cpreprocessor.go:91-113`) vs `collectTextRuntimeSymbolRefs` (`115-137`) and `collectRuntimeIdentsAndMachO` (`1275-1296`) vs `collectRuntimeIdentsAndMachOString` (`1298-1319`) duplicate the same ASCII identifier scanner for `[]byte` and `string`.

### 2. Redundant Whole-Package `ast.Inspect` Scans in `propertyharness.go`

- `verifyPropertyHarnessPackageWithReason` (`propertyharness.go:689-995`) walks `pkg.Syntax` 8+ times during cold verification:
  1. `hasHarnessForbiddenDirective` (`997-1012`).
  2. Top-level declaration / `init` / global classification (`729-950`).
  3. `collectMutatedHarnessNamedStructs(pkg)` (`4610-4690`).
  4. `verifyGeneratorImmutability(pkg)` (`2501-2576`).
  5. `verifyReadOnlyRefConfinement` (`2606-2915`).
  6. `verifyHarnessSyncMapGlobal` (`2040-2499`).
  7. `verifyHarnessCategoryB` (`2917-3228`, building `allDecls`, `funcValueTaken`, `callSites`).
  8. `verifyHarnessExportedSurface` (`3233-3312`, rebuilding `allDecls` a second time at `3255-3264`).

### 3. Duplicate Variadic Slice-Over-Local-Alloc SSA Extractors

- Four functions (`fixedVariadicArgs` in `freshpath.go:319-389`, `closedParseArgument` in `observability.go:1521-1564`, `harnessVariadicClosed` in `propertyharness.go:456-494`, and `harnessExampleHasExplicitSeed` in `propertyharness.go:530-608`) re-implement the same SSA check for a variadic slice backed by a local `[N]T` `*ssa.Alloc` populated solely by in-bounds constant `*ssa.IndexAddr` + `*ssa.Store` pairs.

## Resolution

During Chunk 2 (`Decompose gofresh/internal/closure Leaf Verifiers`):
1. Extract `internal/closure/internal/cprep` with unified `SkipQuotedLiteral`, `VerifyAssemblyPreprocessorPass`, `ExtractFileCgoPreambles`, and unified string/byte symbol scanners.
2. Extract `internal/closure/internal/asmverify` (`VerifyNonStdPackageAssembly`, Plan 9 `.s` parser, `RODATA`/`(SB)` discipline checker, and ISA instruction verifiers), calling `cprep.VerifyAssemblyPreprocessorPass` instead of duplicating the 200-line preprocessor pass.
3. Extract `internal/closure/internal/propharness` (`VerifyPackageWithReason` and property-harness type/call-site predicates), indexing `pkg.Syntax` once (`harnessPkgIndex`) per `VerifyPackageWithReason` call.
4. Consolidate `extractLocalVariadicSliceElems(v ssa.Value) ([]ssa.Value, bool)` and replace `unwrapParens` / `unwrapASTParen` with `ast.Unparen`.
