# Nested Workspace Submodule `go.mod` Recorded in `rec.Absent` by `listingInputs`

- **Status:** Open
- **Governing contract:** [`docs/specs/guards.md`](../specs/guards.md), [`docs/specs/closure.md`](../specs/closure.md) (`REQ-fresh-dependency-identities`)
- **Lands:** Chunk 5 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

In Go workspaces (`go.work`) containing nested submodule directories (such as a root module at `<root>/go.mod` alongside `<root>/stipulate/go.mod` and `<root>/stipulate/structural/go.mod`), `listingInputs` ([`internal/closure/listingmemo.go`](../../internal/closure/listingmemo.go) lines 304–312, 360–370) poisons its own persistent listing memo whenever a session rooted at a nested submodule lists a package belonging to an ancestor workspace module:

1. When `h.dir` is `<root>/stipulate/structural` and `go list` resolves `<root>/internal/...`, the listed package's transitive dependency set `pkgs` contains packages from `<root>` (`Module.Main == true`) and external modules, but no package from `<root>/stipulate/structural`.
2. Consequently, `mainDirs` (`lines 304–312`) contains `<root>`, not `<root>/stipulate/structural` or `<root>/stipulate`.
3. At `lines 360–370`, `strings.HasPrefix(dir, candidate+"/")` matches `mainDir = <root>`, and the directory walk
   ```go
   for d := dir; d != mainDir; d = filepath.Dir(d) {
       absent[filepath.Join(d, "go.mod")] = true
   }
   ```
   unconditionally inserts `<root>/stipulate/structural/go.mod` and `<root>/stipulate/go.mod` into `rec.Absent` — **even though both `go.mod` files exist on disk at capture time**.
4. `storeListing` writes this `rec.Absent` set to `~/.cache/gofresh/listing/...`. On every subsequent lookup, `loadListing` (`lines 163–166`) stats each path in `rec.Absent`, sees `!os.IsNotExist(err)` because the nested `go.mod` exists, and treats the memo entry as stale (`100%` cache miss rate, spawning `go list` `322` extra times = `32.6s` in `stipulator` discovery).

## Resolution Scope

In `listingInputs` ([`internal/closure/listingmemo.go`](../../internal/closure/listingmemo.go)), deduplicate `go.mod` and `go.work` local `replace` target recording (`lines 290–301` vs. `415–426`) and ancestor `go.mod` sentinel recording into shared helpers: inspect each intermediate `filepath.Join(d, "go.mod")` between `dir` and `mainDir` (and workspace member `go.mod` files under active `go.work`), record existing `go.mod` files by content hash in `rec.Files`, record a path in `rec.Absent` only when `os.Lstat` reports `os.IsNotExist` at capture time, and bump `listingRecordVersion` (`listingmemo.go` lines 39–43) because the input-recording semantics change without changing `listingRecord`'s struct layout.
