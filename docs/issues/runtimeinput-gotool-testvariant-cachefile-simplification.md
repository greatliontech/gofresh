# Simplify, Optimize, Fix Defects & Harden `internal/runtimeinput`, `gotool`, `testvariant`, `cachefile`, `guard`, and `testenv`

**Lands:** Chunk 7 in [`docs/plans/plan.md`](../plans/plan.md) (`Redesign Root package gofresh & Simplify/Optimize/Fix internal/runtimeinput, gotool, testvariant, cachefile, guard, and testenv`).

## Context & Concrete Findings

### 1. `internal/runtimeinput` (`~5,174` Non-Test Lines)

1. **Inconsistent UTF-8 / Control-Byte Validation Between `WithBracketExcludedPaths` (`bracket.go:68-89`) and `WithExcludedPaths` (`testlog.go:180-207`)**:
   - `WithBracketExcludedPaths` validates `!utf8.ValidString(q) || strings.ContainsAny(q, "\x00\r\n")` before calling `exclusionPatterns(patterns)`, whereas `WithExcludedPaths` calls `exclusionPatterns(patterns)` without that check, silently accepting invalid UTF-8 or `\x00`/`\r`/`\n` when `FromTestLog` is called without a `Bracket`.
2. **Repeated `filepath.EvalSymlinks(moduleDir)` and Redundant `EvalSymlinks(p)` Calls (`hash.go:148-253`, `eligibility.go:37`, `scratch.go:232, 319`, `bracket.go:369`)**:
   - During `populateManifestDigests`, `hashPath` calls `resolvedTarget(p, moduleDir)` (`hash.go:240-253`), which executes `filepath.EvalSymlinks(moduleDir)` on **every single relative file** ($N + R + 3$ symlink evaluations of the same `moduleDir` per `fromTestLog` call).
   - When `observed != nil` (`CaptureBracket` and `Bracket.revalidate`), `hashPath` (`hash.go:149`) resolves `p` component-by-component via `chainResolveObserved(ctx, p, observed)` and then calls `filepath.EvalSymlinks(p)` **again** at lines 168 and 189 on the exact same path `p`.
3. **Unmemoized Ancestor Symlink Walks in `bracketCoverage.covers` (`bracket.go:365-445`)**:
   - `Bracket.coverage()` (`bracket.go:365-381`) re-resolves every bracket root from scratch via `chainResolve(start)`, and `coverage.covers(id)` (`bracket.go:414`) runs `chainResolve(start)` from `/` down to the file directory on every manifest path without memoizing resolved ancestor directory prefixes.
4. **Double `finalizeManifestState` in `fromTestLog` (`testlog.go:558-587`) and Redundant Manifest Encode/Decode Round-Trips (`observation.go:125-151, 503-587`, `producer.go:268-273`)**:
   - `fromTestLog` runs pure in-memory `finalizeManifestState(m)` at line 558 before `cfg.bracket.revalidate(ctx, moduleDir)` (line 562), and then runs `finalizeManifestState(m)` a second time at line 584 when `!unchanged`. Running `revalidate` immediately after `populateManifestDigests` (the last input read) requires only one `finalizeManifestState(m)` call.
   - `Incomplete` (`observation.go:142-149`) and `Merge` (`observation.go:563-567`) base64/JSON-encode a `manifest` struct only to immediately base64/JSON-decode it back into `manifest` inside `currentWithNormalizedEnvContext`.
   - `HasOutcomeSupport` (`producer.go:268-273`) is called inside a per-subject loop in `Unit.account()` (`unit.go:608-615`), decoding and re-encoding the entire manifest $N$ times instead of decoding once per manifest.
5. **Four Duplicate Path Containment Helpers and Two Ancestor-Symlink Resolvers**:
   - Lexical/resolved containment is implemented 4 times (`relUnder` in `testlog.go:924`, `pathWithin` in `roots.go:153`, `pathOffset` in `bracket.go:607`, and inline `filepath.Rel` in `producer.go:101`).
   - Nearest-existing-ancestor symlink resolution is implemented twice (`nearestExistingAncestor` in `scratch.go:424` and `resolveOrSelf` in `roots.go:230`).

### 2. `internal/gotool` (`collect_linux.go`, `env.go`, `gotool.go`)

1. **Immediate Zero-Duration Timer Race in `drainCollected` When `cmd.WaitDelay == 0` (`collect_linux.go:139-146`)**:
   - A command is treated as contained whenever `cmd.Cancel != nil || cmd.WaitDelay > 0` (`isContained`, line 17). When a caller sets `cmd.Cancel != nil` with `cmd.WaitDelay == 0`, `drainCollected` arms `time.NewTimer(0)` at line 141, which fires immediately and can race `<-done` in `select`, closing `stdoutRead`/`stderrRead` prematurely and returning `exec.ErrWaitDelay` (`collect_linux.go:108-110`).
2. **Double `NormalizeEnv` in `EnvForCommand` (`env.go:56-76`) and `EnvForPackages` (`env.go:121-139`)**:
   - Both functions call `NormalizeEnv(env)`, strip a key, append `key=value`, and call `NormalizeEnv(out)` a second time instead of calling `SetEnv(normalized, key, value)` (`env.go:27-38`), which updates a normalized slice in sorted order in $O(N)$.

### 3. `internal/testvariant` (`testvariant.go`)

1. **Duplicate `BaseFiles` & `ledgerFileBindings` Work and $O(D^2 \cdot \text{ParseExpr})$ Fixpoint Loop in `InertForSubject` (`testvariant.go:301, 318-328, 471-494, 548, 753-766`)**:
   - `InertForSubject` calls `DiffTestVariantLedgers(before, after)` (which checks `reflect.DeepEqual(before.BaseFiles, after.BaseFiles)` and builds `ledgerFileBindings(before)` / `ledgerFileBindings(after)`) and then immediately repeats all three calls at lines 318–328 when `!d.Inert()`.
   - The reachability fixpoint loop at lines 471–494 rescans all `before.Declarations` on every iteration and calls `receiverTypeName(decl.Receiver)` -> `go/parser.ParseExpr(recv)` (`line 650`) on every unreached method declaration on every pass instead of pre-indexing declarations and precomputing `receiverTypeName` once.
   - `DiffTestVariantLedgers` (`line 548`) redefines `type identity` identical to `declarationIdentity` (`line 239`), and `bindingsPreserved` (`lines 753-766`) runs a nested $O(\text{files} \times \text{refs} \times \text{added})$ loop instead of indexing `added`.

### 4. `internal/cachefile` (`cachefile.go`), `internal/guard` (`guard.go`), and `internal/testenv` (`frontend.go`, `goroot.go`)

1. **`knownBytes` Upward Drift on Cache Overwrites & Unbounded `writeSeq` Map in `internal/cachefile` (`cachefile.go:58, 199-213, 360`)**:
   - Overwriting an existing cache file (`Store` / `Merge`) adds `knownBytes += size` without subtracting the file's previous size, causing repeated `Merge` updates to artificially inflate `knownBytes` and trigger unnecessary `filepath.WalkDir` pruning passes (`pruneDirLocked`), and `writeSeq` is never reconciled against on-disk files during `pruneDirLocked`.
2. **Test-Only `buildConfigDigest` and Unused `runtimeGuard` Parameter in `internal/guard` (`guard.go:167-189, 298-307`)**:
   - `buildConfigDigest` has zero production callers and belongs in `guard_test.go`; `runtimeGuard` takes an unused `[]string` parameter.
3. **Duplicated `types.Info` Allocation, Importer Closure, and Overlay Env Tail in `internal/testenv` (`frontend.go:541-609, 884-893, 1047-1076`, `goroot.go:229-262`)**.

## Resolution

During Chunk 7:
1. **`internal/runtimeinput`**:
   - Move UTF-8 and `\x00\r\n` validation into `exclusionPatterns` so `WithExcludedPaths` and `WithBracketExcludedPaths` enforce identical framing invariants (with regression test).
   - Consolidate path containment (`pathWithin` / `pathOffset`) and nearest-existing-ancestor symlink resolution; resolve `moduleDir` once per operation; reuse `chainResolveObserved` target in `hashPath`; memoize ancestor directory resolutions in `bracketCoverage.covers`; run `finalizeManifestState` once after `revalidate` in `fromTestLog`; and eliminate redundant manifest encode/decode round-trips in `Incomplete`, `Merge`, and `HasOutcomeSupport`.
2. **`internal/gotool`, `internal/testvariant`, `internal/cachefile`, `internal/guard`, `internal/testenv`**:
   - Only arm `time.NewTimer(wait)` when `wait > 0` in `drainCollected` (`collect_linux.go:140`, with regression test in `collect_linux_test.go`), and use `SetEnv` in `EnvForCommand` / `EnvForPackages`.
   - Pre-index declarations/methods and `receiverTypeName` in `testvariant.InertForSubject`, share `ledgerFileBindings`, reuse `declarationIdentity`, and index `added` in `bindingsPreserved`.
   - Track per-file size in `cachefile.go` so overwrites adjust `knownBytes += size - prevSize` and reconcile `writeSeq` during `pruneDirLocked` (with regression test in `cachefile_test.go`).
   - Clean up `guard.go` and deduplicate `testenv` helpers.
