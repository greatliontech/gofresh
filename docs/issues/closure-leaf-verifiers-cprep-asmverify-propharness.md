# Decompose, Simplify, Optimize & Harden `cprep`, `asmverify`, and `propharness` Leaf Packages

**Lands:** Chunk 2 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose, Simplify, Optimize & Harden gofresh/internal/closure Leaf Verifiers`).

## Context & Concrete Findings

### 1. `internal/closure/internal/cprep` (`toolchain_cpreprocessor.go`, `cgo_includes.go`, `canonical.go`)

1. **Four Duplicate `#define` & Preprocessor Directive Parsers and 9 Open-Coded Identifier Loops**:
   - `#define` headers (macro name, immediate-`(` function-like vs object-like parameter list, variadic `...` / `args...`, and body) are parsed in 4 separate places: `CollectCPPMacrosFromText` (`cprep/macros.go:21-73`), `buildLogicalNonGoScanLines` (`cprep/symbols.go:204-224`), `VerifyAssemblyPreprocessorPass` Pass 1 and Pass 2 (`cprep/asm.go:351-383, 416-443`), and `asmLineContinuesOperandOrHeader` (`asmverify/asmverify.go:275-292`).
   - Open-coded leading ASCII identifier loops (`for mEnd < len(s) && IsASCIIIdentByte(s[mEnd])`) appear 9 times across `cprep` and `asmverify`, alongside a redundant `leadingASCIIIdent` wrapper (`tokens.go:268-270`).
2. **Zero-Copy-Defeating `[]rune` Conversions & Redundant Whole-File Passes in Assembly Preprocessing**:
   - `IsAsmWordRune` (`cprep/tokens.go:130-133`) only accepts ASCII `[A-Za-z0-9_./<>]` plus two UTF-8 runes: `'·'` (`\u00b7`, 2 bytes `"\xc2\xb7"`) and `'∕'` (`\u2215`, 3 bytes `"\xe2\x88\x95"`). Yet `extractExpandedLineSymbols` (`cprep/symbols.go:149`) and `VerifyAssemblyPreprocessorPass` (`cprep/asm.go:465`) convert every line (and even the entire concatenated `nonDirText` file!) to `[]rune(norm)` and allocate `string(runes[start:i])` for every token before checking `strings.ContainsRune(tok, '·')`.
   - `VerifyAssemblyPreprocessorPass` (`cprep/asm.go:303-561`) runs `StripAssemblyComments(src, true, joinContinuationWithSpace)` at line 305, splits into lines and parses `#define` directives, and then at line 406 runs `StripAssemblyComments(src, false, joinContinuationWithSpace)` over the entire file a second time and re-parses every `#define` directive.
   - `VerifyAssemblyFile` (`cprep/asm.go:288-298`) and `verifyNonStdAsmPreprocessor` (`asmverify/asmverify.go:301-310`) unconditionally run `VerifyAssemblyPreprocessorPass` twice (`joinContinuationWithSpace = true`, then `false`) even when `!strings.Contains(src, "\\")` (where both passes are identical).
3. **Redundant Macro Body Tokenization & String Allocations in `cprep/macros.go`**:
   - `bodyMacroRefsMode` (`macros.go:320`) always loops over `[]string{def.Body, CollapseTokenPasteOps(def.Body)}`, tokenizing `def.Body` twice even when `def.Body` contains no `##` operator.
   - `CollapseTokenPasteOps` (`macros.go:100-116`) repeatedly concatenates `s = s[:left] + s[right:]` in a loop instead of fast-pathing `!strings.Contains(s, "##")` and building once.
   - `mergeBlockedMacros` (`macros.go:246-260`) calls `strings.Split(b, "|")` allocating a slice on every step instead of scanning `|` with `strings.IndexByte`.
4. **Duplicate Symlink/Path Resolution in `cgo_includes.go` & Redundant `toolchain_cpreprocessor.go` Pass-Throughs**:
   - In `internal/closure/cgo_includes.go:175-186`, `symlinkDirInPath(include, filepath.Dir(path))` is called at line 175 and immediately called again on iteration 0 of `for _, dir := range searchDirs` (where `searchDirs[0] == filepath.Dir(path)`) at line 184, performing duplicate `EvalSymlinks`/`Lstat`/`Stat` syscalls on every `#include`.
   - In `cgoIncludeRootOutsideDir` (`cgo_includes.go:48`), `resolveReal(modCache)` is called inside the loop on every `-I` flag dir instead of once before the loop.
   - Moving Cgo `-I` flag parsing (`CgoIncludeFlagDirs`), outside-dir detection (`CgoIncludeRootOutsideDir`), and escaping header resolution (`CgoEscapingInclude`) into `cprep/cgo.go` reduces `internal/closure/cgo_includes.go` to a 30-line `listPkg` adapter, and updating callers to invoke `cprep.*` directly retires `internal/closure/toolchain_cpreprocessor.go` completely.

### 2. `internal/closure/internal/asmverify` (`asmverify.go`, `parse.go`, `isa.go`, `r14.go`, `cpuid.go`)

1. **Seven Separate Token/Quote Scans per Assembly Instruction (`isa.go`, `r14.go`)**:
   - `HasUnquotedColon` (`isa.go:280`), `hasAsmPCToken` (`isa.go:301`), `stmtContainsARM64SysReg` (`isa.go:329`), `hasForbiddenAsmToken` (`isa.go:375`), and `stmtMentionsAMD64R14` (`r14.go:26`) all run separate character-by-character loops over the same statement string `s`, calling `cprep.SkipQuotedLiteralChecked(s, i)` and `cprep.ScanIdentToken(s, i, true)` and allocating `strings.ToLower(tok)` on every identifier just to check `isFrameSlotIdentBeforePlusFP(s, start, end)`.
   - On every instruction in `verifyAsmTextInstruction` (`isa.go:487-613`), `rest` is scanned 7 separate times.
2. **Duplicate Mnemonic, Prefix, and Register Tables (`isa.go`)**:
   - `isReservedNonStdAsmMacroName` (`isa.go:60-100`) and `isImpureOrSystemAsmMnemonic` (`isa.go:432-485`) duplicate the same 10-way `strings.HasPrefix` chain (`RDRAND`, `RDSEED`, `RDFSBASE`, `RDGSBASE`, `WRFSBASE`, `WRGSBASE`, `FXRSTOR`, `XRSTOR`, `POPF`, `PUSHF`), the ~75 system/impure mnemonics, the call/indirect-jump mnemonics from `verifyAsmTextInstruction` (`isa.go:516-522`), and the forbidden register names from `hasForbiddenAsmToken` (`isa.go:416-418`).
   - Four manual digit-checking loops in `isForbiddenX86ControlOrDebugReg` (`isa.go:14-19`), `isArchRegisterIdent` (`isa.go:695-744`), and `isCleanARM64SysRegDestGPR` (`isa.go:365-368`, which allocates `strconv.Itoa(n)`) all parse a 1-or-2 digit non-leading-zero decimal register index.
3. **Redundant Statement Re-Splitting in `verifyParsedNonStdAsmFile` (`isa.go:115-137`)**:
   - `verifyParsedNonStdAsmFile` re-walks all `parsed.lines`, re-splitting statements and labels just to find top-level `DATA` directives that Pass 1 (`parseSingleNonStdAsmFile`, `parse.go:276`) already parsed.

### 3. `internal/closure/internal/propharness` (`propertyharness.go`)

1. **12+ Redundant Whole-Package / Function-Body `ast.Inspect` Scans**:
   - `verifyPropertyHarnessPackageWithReason` (`propertyharness.go:844-995`) walks `pkg.Syntax` 12+ separate times:
     - Rebuilds `allDecls` 3 times (`lines 1785, 2916, 3255`).
     - Rebuilds the intra-package call graph and `valueTaken` set twice (`computeHarnessFunctionUsage` at `line 1049` and `verifyHarnessMaphashCallerConfinement` at `line 1774`).
     - Scans all statements 4 separate times for mutations (`collectMutatedHarnessNamedStructs` at `line 4610`, `verifyGeneratorFieldsWriteOnce` at `line 2710`, `mutatedOrAddrLocals` at `line 2924`, and `reassignedParams` at `line 4180`).
     - Runs a second `ast.Inspect(root)` pass in both `checkTree` (`lines 1693-1733`) and `checkVarUses` (`lines 2332-2353`) even though parent `*ast.CallExpr` nodes are visited in pre-order before their child `*ast.Ident` nodes.
     - Runs 2 `ast.Inspect(body)` passes per variable in `isDeclaredInBodyBefore` (`verifyFreshUnaliasedLocalAtStore`, `lines 4832-4876`).
2. **Duplicated AST Helpers Across `propertyharness.go`**:
   - Five duplicate mutating-builtin checks (`lines 1603, 2238, 2797, 2947, 4680`).
   - Three duplicate place-spine walkers (`rootImportedVar` at `line 2646`, `rootPkgVar` at `line 2674`, `markLocalChain` at `line 2886`).
   - Duplicate `lookupLocalVar` (`line 4165`) and `lookupLocal` (`line 4443`), plus linear `findFuncParamIndex` (`line 1937`).
   - Duplicate `osStdoutIdent` (`line 1960`) and `osEnvLookupIdent` (`line 1976`).
   - Four variadic slice-over-local-alloc SSA extractors (`fixedVariadicArgs` in `freshpath.go`, `closedParseArgument` in `observability.go`, `harnessVariadicClosed` and `harnessExampleHasExplicitSeed` in `propertyharness.go`).

## Resolution

During Chunk 2:
1. **`internal/closure/internal/cprep`**:
   - Unify `#define` and directive parsing via `CutDirectiveKeyword` and `ParseDefineDirective` (`macros.go`, `tokens.go`).
   - Replace `[]rune` conversions with byte-level `NextAsmWordRune` / `ScanAsmWordToken` (`tokens.go`), replace the second whole-file `StripAssemblyComments` pass in `VerifyAssemblyPreprocessorPass` with per-line `BlankQuotedLiterals`, and skip the second `VerifyAssemblyPreprocessorPass` pass when `!strings.Contains(src, "\\")`.
   - Optimize `CollapseTokenPasteOps`, `bodyMacroRefsMode`, and `mergeBlockedMacros` in `macros.go`.
   - Consolidate Cgo `-I` / symlink / escaping-include verification into `cprep/cgo.go` (fixing duplicate `symlinkDirInPath` and `resolveReal(modCache)` calls), shrink `cgo_includes.go` to a thin `listPkg` adapter, and delete `toolchain_cpreprocessor.go`.
   - Move and expand direct unit + fuzz tests in `internal/closure/internal/cprep/cprep_test.go`.
2. **`internal/closure/internal/asmverify`**:
   - Replace the 7 per-instruction token/quote scans with a single-pass `scanAsmTokens(s string) asmTokenFlags` and zero-allocation `isFrameSlotIdentBeforePlusFP` (`isa.go`, `r14.go`).
   - Unify `isReservedNonStdAsmMacroName`, `isImpureOrSystemAsmMnemonic`, `isForbiddenCallOrJumpMnemonic`, `isForbiddenAsmRegisterName`, and `parseRegIndex` (`isa.go`).
   - Record `dataDirectives` during Pass 1 (`parse.go`) so `verifyParsedNonStdAsmFile` does not re-split all lines of the file.
   - Add a comprehensive direct unit test suite in `internal/closure/internal/asmverify/asmverify_test.go` covering expression evaluation, token flags, ARM64 word opcodes, AMD64 R14 kill CFGs, and SSA/ASM CPUID leaf bounds.
3. **`internal/closure/internal/propharness` & `propertyharness.go`**:
   - Extract `internal/closure/internal/propharness` into 4 focused files (`index.go`, `vars.go`, `protocol.go`, `surface.go`) built around a single-pass `harnessPkgIndex` (eliminating 9 redundant package/body AST traversals and making `findFuncParamIndex` $O(1)$).
   - Fold post-walk `approvedIdents` checks into the pre-order walks in `checkTree` and `checkVarUses`, pre-index `fd.Body` once in `verifyFreshUnaliasedLocalAtStore`, and unify `mutatingBuiltinFirstArg`, `rootPlaceVar`, `lookupLocalVar`, and `usedIdentAndObject`.
   - Consolidate `forEachLocalSliceAllocStore` across `freshpath.go`, `observability.go`, and `propertyharness.go` (`harnessVariadicClosed`, `harnessExampleHasExplicitSeed`).
   - Add a comprehensive direct unit test suite in `internal/closure/internal/propharness/propharness_test.go`.
