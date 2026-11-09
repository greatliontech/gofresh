# Eliminate Startup Environment, RNG, and Unaudited Reflection Side Effects in `go-x-tools`

**Lands:** Chunk 6 in [`docs/plans/plan.md`](../plans/plan.md) (`Redesign Snapshot / Sibling Observability Sharing, Downstream Efficiency & go-x-tools Fixes`).

## Context & Concrete Findings in `go-x-tools`

1. **`go/packages`: Eager `os.Getenv("GOPACKAGESDEBUG")` at Package `init` Time (`go/packages/golist.go:29`, `go/packages/packages.go:737`)**:
   - `go/packages/golist.go:29` declares `var debug, _ = strconv.ParseBool(os.Getenv("GOPACKAGESDEBUG"))` at package level.
   - Every binary or test package that transitively imports `go/packages` executes `os.Getenv` during `packages.init` (triggering `startup effect: calls os.Getenv` in `gofresh` even for subjects that never call `packages.Load`), and freezing `debug` at startup prevents `t.Setenv("GOPACKAGESDEBUG", "true")` from taking effect inside tests.
   - **Fix**: Remove package-level `var debug` from `go/packages/golist.go:29` and evaluate `if debug, _ := strconv.ParseBool(os.Getenv("GOPACKAGESDEBUG")); debug` at its single use site in `newLoader` (`go/packages/packages.go:737`).
2. **`go/ast/edge` & `go/ssa`: `reflect.TypeFor` on Concrete Types (`go/ast/edge/edge.go:185`, `go/ssa/ssa.go:1629, 1633`)**:
   - `go/ast/edge/edge.go:185` (`func info[N ast.Node](fieldName string) fieldInfo`) calls `nodePtrType := reflect.TypeFor[N]()`, invoked 103 times in the package-level `var fieldInfos = [...]fieldInfo{...}` initializer (`edge.go:193-299`), where every `N` is a concrete pointer-to-struct type (`*ast.ArrayType`, `*ast.AssignStmt`, etc.).
   - `go/ssa/ssa.go:1629, 1633` (`concatTypeParamLists`) calls `reflect.TypeFor[types.TypeParamList]()` and `reflect.TypeFor[[]*types.TypeParam]()`.
   - **Fix**: Replace with `var zero N; nodePtrType := reflect.TypeOf(zero)` in `go/ast/edge/edge.go:185` and `reflect.TypeOf(types.TypeParamList{})` / `reflect.TypeOf(([]*types.TypeParam)(nil))` in `go/ssa/ssa.go:1629, 1633`.
3. **`go/ssa`: Startup `types.Universe.Lookup("rune").Type()` in `ssa.init` (`go/ssa/builder.go:95, 2213`, `go/ssa/sanity.go:193`)**:
   - `go/ssa/builder.go:95` initializes package-level `tRune = types.Universe.Lookup("rune").Type().(*types.Basic)` during `ssa.init` (whereas `varOk()` and `varIndex()` at lines 103–104 were already converted to functions).
   - **Fix**: Convert `tRune` into `func tRune() *types.Basic { return types.Universe.Lookup("rune").Type().(*types.Basic) }` and update the two call sites (`go/ssa/builder.go:2213` and `go/ssa/sanity.go:193`).
4. **`go/types/typeutil`: Startup `maphash.MakeSeed()` Entropy (`go/types/typeutil/map.go:13, 375-383`)**:
   - `go/types/typeutil/map.go:375` declares `var theSeed = maphash.MakeSeed()`, used only in `hashTypeName(tname *types.TypeName) uint32`.
   - This pulls process RNG entropy during `typeutil.init` in every binary importing `go/types/typeutil`, `go/ssa`, or `go/callgraph/...`, and makes `typeutil.Hasher.Hash` non-deterministic across processes for `*types.Named` and free `*types.TypeParam` even though `typeutil.Map` already resolves collisions via `types.Identical` and hashes every other type category deterministically via `hashString`.
   - **Fix**: Replace `theSeed` in `hashTypeName` with deterministic `hashString(tname.Name())`, `uint32(tname.Pos())`, and (when `tname.Pkg() != nil`) `hashString(tname.Pkg().Path())`.

## Resolution

Land in `go-x-tools` and bump `go-x-tools` across `gofresh`, `pew`, `stipulator`, and `gomutant` in Chunk 6.
