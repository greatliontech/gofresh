# Phase A Blueprint: First-Class Tracing (`internal/trace`)

## 1. Activation & Destination Contract

- **Ambient Environment Variables**:
  - `GOFRESH_TRACE=<spec>`: comma-separated domain tokens with optional `:substring` target filters (e.g., `GOFRESH_TRACE=all`, `GOFRESH_TRACE=1`, `GOFRESH_TRACE=toolchain,view`, `GOFRESH_TRACE=closure:BenchmarkPWD,toolchain:encoding/json`).
  - `GOFRESH_TRACE_FILE=<path>`: optional output file path opened with `O_CREATE|O_WRONLY|O_APPEND` (`0o644`). When unset, events write to `os.Stderr`.
- **Programmatic Test Hook**:
  - `trace.WithSink(ctx, sink)` and `trace.WithFilteredSink(ctx, spec, sink)` in `internal/trace`, paired with `trace.NewRecorder()` (`*trace.Recorder`) for in-memory causal-witness assertions in unit, property, and integration tests.
- **Package Boundary & Spec Requirements (`docs/specs/overview.md`)**:
  - All Go types and functions reside in `github.com/greatliontech/gofresh/internal/trace` (zero new exported Go symbols on root `gofresh`).
  - `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` are specified in [`docs/specs/overview.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md) under **`REQ-fresh-trace`** (operational diagnostic tracing across `toolchain`, `closure`, `view`, and `session`, filter grammar, destination, and text/JSONL wire formats) and **`REQ-fresh-trace-non-interference`** (invariant: enabling tracing never alters any normalized subprocess environment, build/runtime guard, closure digest, memo scope key, or recorded runtime-input dependency), bound in [`.stipulator/bindings/fresh.textproto`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/.stipulator/bindings/fresh.textproto), and documented in the [`gofresh` package doc comment](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session.go#L1-L11).

## 2. Non-Interference Invariant

- Enabling `GOFRESH_TRACE` or `GOFRESH_TRACE_FILE` MUST NEVER alter any `gofresh` output, digest, scope key, or recorded dependency:
  1. **Normalized Go Subprocess & Build Environments**: `NormalizeEnv` validates every environment entry (rejecting NUL bytes, malformed entries, and duplicate keys) and strips `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` from the normalized environment slice so child `go` invocations, `memoKey`s, `completeBuildEnvironment` digests, and `OutcomeBinding` environment digests are byte-for-byte identical whether tracing is on or off.
  2. **Runtime-Input Environment Recording**: Testlog ingestion (`case "getenv":`) ignores `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` so a traced process reading those variables never records them as persisted runtime-input dependencies.

## 3. Zero-Cost Disabled Fast Path

- `trace.Enabled(ctx, domain, target)` and `trace.Emit(ctx, domain, name, target, fields...)` check a single process-wide `atomic.Int32` active-sink counter (`activeCount.Load() <= 0`) on the fast path.
- When tracing is off (no ambient `GOFRESH_TRACE` and no active `WithSink` context), `trace.Enabled` is a single atomic load returning `false` with zero allocations and zero `ctx.Value` walks.
- `trace.RefreshFromEnv()` is invoked at package `init()` and at top-level `gofresh` entry points (`NewSession`, `beginOperation`, `ResolveToolchainSelection`, `CaptureGuards`, `ExplainDynamicState`) so `t.Setenv("GOFRESH_TRACE", ...)` in tests takes effect immediately (including when set after `NewSession` before `Snapshot` / `Check` / `Validate`) without polling `os.Getenv` on hot paths.
- Context sinks registered via `WithFilteredSink` decrement `activeCount` via `sync.OnceFunc` wired to both `context.AfterFunc` (when `ctx.Done() != nil`) and `runtime.AddCleanup` so `activeCount` returns to `0` as soon as the context finishes or becomes unreachable.

## 4. Structured Domains & High-Signal Events

1. **`toolchain` (`trace.DomainToolchain`)**:
   - `scope_resolved`: resolved `GOROOT`, `GOVERSION`, `build_flags`, `scope`, and whether the surface listing cache hit (`warm_listing=true|false`).
   - `listing_stamp_mismatch`: when `stampsCurrent` fails on a cached listing, records the **exact first directory or entry stamp mismatch** (`path`, `entry`, `reason`, and recorded vs. current `size`, `mtime`, `ctime`, `mode`).
   - `stamp_fallback`: when `verifyReadPackageDigest` observes a post-read `Lstat` stamp change and falls back to `os.ReadFile` + `bytes.Equal` (`target=<importPath>`, `file`, `content_equal=true|false`).
   - `package_verdict_error` / `package_io_error`: any stdlib package failing structural contract verification (`verdictErr`) or source reading (`ioErr`), naming the package and error.
   - `selection_resolved`: final `audited` boolean, `content_digest`, `policy_digest`, `pure_delegates` count, `failed_packages`, and `degradation` notice.
2. **`closure` (`trace.DomainClosure`)**:
   - `subject_closure`: per-subject `Closure` digest, `test_variant` compartment digest, `effects`, `unverifiable`, `refusal`, `culprit`, and the **causal witness** (`diagnostic` / call-graph edge / `dynstate` token) when non-pure or degraded.
   - `observability`: per-subject observability proof result (`observable`, `reason`, `target`).
3. **`view` (`trace.DomainView`)**:
   - `pass_summary`: summary of each `observeView` pass (`dir`, `subjects`, `source_files`, `cut_subjects`, `guards_toolchain`, `guards_buildconfig`).
   - `two_pass_diff`: emitted whenever `compareObservations` detects divergence between pass 1 (`base`) and pass 2 (`current`), naming the **exact first diverging field** (`diff_field`, `subject`, `first_value`, `second_value`).
4. **`session` (`trace.DomainSession`)**:
   - `session_init`: `dir`, `module_dir`, `goversion`, `toolchain_skew`, `complete_build`.
   - `check_verdict`: per-candidate check decision (`target=<pkg.Symbol>`, `status`, `cause`, `subkind`, `reason`, and when runtime inputs moved, `moved_inputs`).

## 5. Wire Formats

- **Line-Oriented Key-Value Format (Default)**:
  - `gofresh/trace pid=<pid> domain=<d> event=<e> [target=<t>] <k>=<v> ...\n`
  - Values containing whitespace, quotes, `=`, `\`, or control bytes are quoted with `strconv.Quote`.
- **JSONL Format (When `GOFRESH_TRACE_FILE` ends in `.jsonl` or `.json`)**:
  - `{"ts":"<RFC3339Nano>","pid":<pid>,"domain":"<d>","event":"<e>","target":"<t>","fields":{...}}\n`
- **Atomicity**:
  - Every event is formatted into a single `\n`-terminated buffer and written in one mutex-serialized `Write` call so concurrent goroutines never interleave mid-line.
