# Repository Directives & Compaction Defense

## Compaction Defense & Working Notes (`docs/notes/`)

Context compaction is the primary operational hazard on multi-chunk work. Treat ephemeral conversation memory as volatile and `docs/notes/` in Git as the durable session memory:

1. **Read First After Startup or Compaction:** Always read `docs/plans/plan.md` and `docs/notes/working-notes.md` before designing or editing code so active chunk boundaries, prior audit findings, rejected dead ends, and user decisions are loaded intact.
2. **Continuous Updates:** Record every architectural alignment with the user, root-cause diagnosis, soundness or performance audit result, hypothesis, and review disposition in `docs/notes/working-notes.md` as it happens — never defer note-taking until chunk close-out.
3. **Commit Notes Frequently:** Commit updates to `docs/notes/` and `docs/plans/` in small standalone `docs(notes): ...` / `docs(plan): ...` commits (staging only the intended doc files without sweeping in uncommitted code) whenever an audit, user alignment, or milestone completes.
4. **Never Pile Cross-Chunk Edits onto an Uncommitted Tree:** Keep each active chunk isolated, adversarially reviewed, verified, and committed before starting the next chunk.

## Scope, Authority & First-Principles Architecture

1. **5-Repo Ownership:** Full ownership of specs and code spans `go-x-tools`, `gofresh`, `gomutant`, `stipulator`, and `pew`. Keep `godst` outside repository modification scope unless explicitly requested.
2. **Toolchain Flavor Invariance:** Every analysis, guard, build, and test across the 5 repos must work identically under both `godst` (custom Go builds) and vanilla / system-installed Go toolchains, with zero flavor-specific or Go-version-list hardcoding.
3. **Zero Third-Party Module/Version Allowlists:** `gofresh` analyzes arbitrary user subject repositories and their transitive dependencies, not just our own tools. Never add third-party module or semver allowlists (`VersionListing`) to `internal/auditset` or `internal/closure` to paper over an analysis gap:
   - Valid Go constructs (such as startup dead-branch pruning on unmutated zero globals, memoizer patterns, interface/parameter closure, and sentinel globals) must be analyzed mechanically from first principles.
   - Non-toolchain `.s` assembly must be verified mechanically on disk per `TEXT` symbol (checking `RODATA` globals, `(SB)` symbol discipline, absence of syscalls/traps/clocks/RNGs, decoded ISA feature-query instructions, and carrier-free Go signatures) without naming specific third-party module paths or versions.
   - Only genuine non-derivable external blindspots require explicit caller authority (`//gofresh:pure` or dependency-boundary vouches).
