# `gomutant` / `gofresh` zero-reuse from test-startup RTA (`fmt.Println` / stdlib assembly), interface-parameter dynamic-carrier rejection, and stale deleted symbols in `findings.json`

Lands: Chunk C.4 and Chunk B.3 in docs/plans/plan.md

## Context & Reproduction

- **Consumer workspace:** `/home/nikolas/repos/github.com/greatliontech/git-go`
- **Findings file:** `/home/nikolas/repos/github.com/greatliontech/git-go/.gomutant/findings.json` (`version: 17`, `toolchain: go1.27.2-dst.15 linux/amd64`)
- **Command:**
  ```bash
  unset ANTIGRAVITY_SOURCE_METADATA && ~/.local/bin/mlock run gomutant run --staged --bracket-path object/testdata --package "github.com/greatliontech/git-go/object" --package "github.com/greatliontech/git-go/object/policy"
  ```

---

## Finding 1: `0 reusable as they stand, 453 not` — Startup/Init RTA Pollutes Every Target Symbol with `startup effect: reaches fmt.Println` and `reaches non-standard assembly`

### Demonstrated Fault
Across all `453` target symbols and all `1,208` entries in `evidenceTable` in `.gomutant/findings.json`, **0 targets are reusable across runs** (`453 measured, 0 cached, 0 skipped; reuse: 0 reusable as they stand, 453 not`), even when source and tests are unchanged.

Every single symbol—including trivial leaf functions with zero calls, zero globals, and zero package `init()` functions—is marked `observable: false` by `gofresh/observation-rta@57` with:
- `stored observation: startup effect: reaches fmt.Println (formatted output)` (on **1,208 / 1,208** `evidenceTable` entries), and
- `freshness: target: reaches non-standard assembly` (on **196+** pure functions that make no calls at all).

### Concrete Evidence (`object.asciiLowerByte` and `object.Kind.Valid`)
In `object/checks.go`:
```go
func asciiLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
```
And in `object/values.go`:
```go
func (k Kind) Valid() bool {
	switch k {
	case KindCommit, KindTree, KindBlob, KindTag:
		return true
	default:
		return false
	}
}
```
Neither `github.com/greatliontech/git-go/object` nor `github.com/greatliontech/git-go/object/policy` has any `init()` function or any call to `fmt.Println` anywhere in the repository (`grep -rn "Println" object/` returns 0 matches).

Yet `.gomutant/findings.json` records:
```json
{
  "symbol": "github.com/greatliontech/git-go/object.asciiLowerByte",
  "fingerprint": {
    "maximalClosure": "872f653c0a59d1602762fd8f8c021f42",
    "testVariantClosure": "3ba20e8964ac3a3728c5ed6e220662ec",
    "toolchain": "go1.27.2-dst.15 linux/amd64",
    "buildConfig": "24bfdceda7a76822cc05832b8653834a",
    "toolchainContent": "030e51bda0e457a2264044b7a5088f3e4e002c0f504188adb474fc5bcbf00ca0",
    "admissionPolicy": "8c1ceeefb4013089055d25598cf9dd3645f2ad1a95ba1d9a38d2228060b482eb",
    "observationAssertion": "caller assertion",
    "observationProof": {
      "strategy": "gofresh/observation-rta@57",
      "package": "github.com/greatliontech/git-go/object",
      "symbol": "asciiLowerByte",
      "observable": false,
      "reason": "startup effect: reaches fmt.Println (formatted output)",
      "evidence": "a3b02bcb61403b0e317faea5399d832d"
    },
    "dynamicStateStrategy": "gofresh/dynamic-state@48",
    "closureStrategy": "gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@2",
    "runtimeDigest": "3a2390a043d30f3d1965977395d044e0",
    "resultKind": 1
  }
}
```
And during `gomutant run`, both `asciiLowerByte` and `Kind.Valid` log:
```text
reuse: unverifiable; freshness: target: reaches non-standard assembly (dischargeable by restructuring the subject away from the reach, or by the //gofresh:pure directive on the subject's declaration or the caller's purity assertion); stored observation: startup effect: reaches fmt.Println (formatted output); analysis: no re-judgment lifts it — a source change, a vouch, or a discharge does
```

### Proximate Cause
When `gofresh/observation-rta@57` and the target freshness analyzer construct the RTA / reachability graph for a symbol or test variant, they include the synthesized test binary / stdlib `init` startup root (`testing.MainStart` / `flag` / `fmt.Println` / stdlib runtime assembly) in the startup effect and target reachability of every symbol in the package. Because `testing`'s own startup/harness reaches `fmt.Println` and stdlib assembly, every target and every test oracle in every package is marked `observable: false` (`startup effect: reaches fmt.Println (formatted output)`) and `reaches non-standard assembly`, completely disabling incremental caching/reuse (`0 cached` out of `453 targets`).

---

## Finding 2: `context.Context` and `error` Parameters Treated as Unverifiable Dynamic Carriers Even Without Dynamic Dispatch

### Demonstrated Fault
Every function that accepts `ctx context.Context` (even when `ctx` is only used for cancellation checks `ctx.Err()` / `ctx.Done()`) or `err error` (including standard `Error.Is(target error) bool` methods on concrete error structs) is rejected as unverifiable:
```text
reuse: unverifiable; freshness: target: subject accepts caller-supplied dynamic behavior through its parameter ctx context.Context (dischargeable by bounding that type away from dynamic carriers, or by the //gofresh:pure directive on the subject's declaration or the caller's purity assertion)
```
and for `func (e *CancelledError) Is(target error) bool { return target == ErrCancelled }`:
```text
reuse: unverifiable; freshness: target: subject accepts caller-supplied dynamic behavior through its parameter target error (dischargeable by bounding that type away from dynamic carriers, or by the //gofresh:pure directive on the subject's declaration or the caller's purity assertion)
```
Even when `Is(target error) bool` performs only an interface-value equality comparison (`target == ErrCancelled`) and never invokes any method on `target`, the parameter's static interface type `error` triggers dynamic-carrier rejection. Across idiomatic Go packages where API entrypoints accept `context.Context` and custom error types implement `Is(target error) bool`, this disqualifies ~100+ functions per package from reuse unless manually annotated with `//gofresh:pure`.

---

## Finding 3: Stale Deleted Symbols Retained in `.gomutant/findings.json` Across `gomutant run --staged` Runs

### Demonstrated Fault
When helper functions are refactored away or deleted between `gomutant run --staged` runs, `gomutant` updates existing and newly added symbols in `.gomutant/findings.json` (`run: "560e65ac549bc397"`, `stagedTree: "5d5a1dc03b420769fccdf70e71094ca1153936ec"`), but **retains findings for deleted functions** from prior runs (`run: "f48f67d8fcc78d41"`):
- `github.com/greatliontech/git-go/object.readReaderWithCancel` (41 survivors)
- `github.com/greatliontech/git-go/object.stripUnquotedComment` (39 survivors)
- `github.com/greatliontech/git-go/object.stepDirectoryEntry` (26 survivors)
- `github.com/greatliontech/git-go/object.percentDecodeLenient` (25 survivors)
- `github.com/greatliontech/git-go/object.percentDecodeString` (25 survivors)
- `github.com/greatliontech/git-go/object.checkStrictTreeComponent` (45 survivors)
- `github.com/greatliontech/git-go/object.readContentWithCancel` (21 survivors)

None of these 7 symbols exist in the current codebase or staged tree anymore, yet they remain in `.gomutant/findings.json` (`460` findings in JSON vs `453` actual targets in the package). When `gomutant run` measures a full `--package`, any persisted finding for that package whose symbol no longer exists in the resolved package target set should be pruned from `.gomutant/findings.json` (and unreferenced `evidenceTable` / `runtimeInputsTable` / `ledgerTable` entries garbage-collected).
