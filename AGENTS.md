# Repository Directives & Compaction Defense

## Compaction Defense & Working Notes (`docs/notes/`)

Context compaction is the primary operational hazard on multi-chunk work. Treat ephemeral conversation memory as volatile and `docs/notes/` in Git as the durable session memory:

1. **Read First After Startup or Compaction:** Always read `docs/plans/plan.md` and `docs/notes/working-notes.md` (when present) before designing or editing code so active chunk boundaries, prior audit findings, rejected dead ends, and user decisions are loaded intact.
2. **Continuous Updates:** Record every architectural alignment with the user, root-cause diagnosis, soundness or performance audit result, hypothesis, and review disposition in `docs/notes/working-notes.md` as it happens — never defer note-taking until chunk close-out.
3. **Commit Notes Frequently:** Commit updates to `docs/notes/` and `docs/plans/` in small standalone `docs(notes): ...` / `docs(plan): ...` commits (staging only the intended doc files without sweeping in uncommitted code) whenever an audit, user alignment, or milestone completes.
4. **Never Pile Cross-Chunk Edits onto an Uncommitted Tree:** Keep each active chunk isolated, adversarially reviewed, verified, and committed before starting the next chunk.

## Scope, Authority & First-Principles Architecture

1. **5-Repo Ownership (Including Autonomous Commit & Push):** Full ownership of specs, code, commits, and pushes (`git push`) spans `go-x-tools`, `gofresh`, `gomutant`, `stipulator`, and `pew` — push converged, verified work directly without asking for confirmation. Keep `godst` outside repository modification scope unless explicitly requested.
2. **Toolchain Flavor Invariance:** Every analysis, guard, build, and test across the 5 repos must work identically under both `godst` (custom Go builds) and vanilla / system-installed Go toolchains, with zero flavor-specific or Go-version-list hardcoding.
3. **Zero Third-Party Module/Version Allowlists:** `gofresh` analyzes arbitrary user subject repositories and their transitive dependencies, not just our own tools. Never add third-party module or semver allowlists (`VersionListing`) to `internal/auditset` or `internal/closure` to paper over an analysis gap:
   - Valid Go constructs (such as startup dead-branch pruning on unmutated zero globals, memoizer patterns, interface/parameter closure, and sentinel globals) must be analyzed mechanically from first principles.
   - Non-toolchain `.s` assembly must be verified mechanically on disk per `TEXT` symbol (checking `RODATA` globals, `(SB)` symbol discipline, absence of syscalls/traps/clocks/RNGs, decoded ISA feature-query instructions, and carrier-free Go signatures) without naming specific third-party module paths or versions.
   - Only genuine non-derivable external blindspots require explicit caller authority (`//gofresh:pure` or dependency-boundary vouches).

## Exhaustive Testing, Oracles & Harness Discipline

Treat tests and test harnesses as first-class architectural artifacts designed alongside every mechanism — never as post-implementation or review-driven afterthoughts:

1. **Exhaustive Case-Space Design (Cases, Not LOC):** Before or alongside implementing any executable change, enumerate the orthogonal dimensions and boundary conditions of its input space (type/AST/SSA/CFG combinators, execution modes, cache/memo warm-vs-cold states, cross-mode replay, malformed/adversarial inputs, and negative/positive controls) and cover them via compact, parameterized table-driven matrices that maximize distinct semantic cases rather than line count.
2. **Compositional `pgregory.net/rapid` Properties & Independent Oracles:** Accompany static analyses, type/layout predicates, and semantic verifiers with compositional `rapid` generators checked against independent semantic or executable reference oracles (e.g., byte-level memory/header layout maps via `go/types.Sizes`, runtime state-drift execution oracles, and metamorphic AST/CFG/SSA transformations such as dead-branch insertion, local rebinding, and helper extraction).
3. **`testing.F` Fuzzing on Parsers, Scanners, Lowerings & Codecs:** Pair syntax/assembly/testlog parsers, CFG/IR lowerings, and wire/manifest codecs with `testing.F` fuzz targets seeded from the boundary table cases, asserting crash-freedom, determinism, and round-trip/oracle invariants.
4. **Invest in Reusable Test Harnesses:** Build or extend clean shared in-memory/hermetic test harnesses (`internal/testenv` or focused subsystem harnesses) whenever existing test setup makes exhaustive case generation verbose or duplicative, and verify every new or changed testable invariant kills targeted `gomutant ephemeral` probes (`0` non-equivalent survivors — strengthen tests or demonstrate semantic equivalence) and cannot pass for the wrong reason.
