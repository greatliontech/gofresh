# Unclosed mutation and operation boundaries

Lands: the component destinations in docs/plans/tooling-redesign.md below;
delete after every component has landed or been refuted by its deciding case.

These are distinct obligations, not permission to broaden a repair into a
second implementation trajectory. Except where explicitly measured below,
the mechanisms are source-traced and their deciding regressions remain to be
run. Existing execution-model, assertion and sampling limits remain governing.

## Shaped mutation materialization and dependencies — 5.4, before shaped assurance

Gomutant `shaped.go` copies symlinks unchanged, then writes replacements through
the copied path. A manual recipe targeting an absolute symlink to the original
tree follows it during the scratch write; the clean twin follows it too.
The same path can reach an external file. The tool's own write, not merely its
oracle, needs physical isolation. Test original bytes across success, failure
and cancellation with both original-tree and outside-tree targets. This path
is not used by fresh body-overlay probes.

The same file's `localReplaceActive` scans text after `=>` for unquoted path
prefixes. A legal quoted local replacement is missed. An import-boundary
candidate can introduce an external dependency absent from the clean oracle;
changing its initializer leaves the current shape digest without that source.
Use module grammar or resolved metadata, with quoted/unquoted, workspace and
mutable introduced-dependency controls. Current-policy shaped records also
need that dependency judgment; their policy label alone grants nothing.

## Remaining build-description adoption — 5.1 / 5.2 / 5.4

Adopt the explicit build/runtime boundary and its complete-build guard together
at the remaining producers and their checking surfaces. The shared contract is
REQ-guard-explicit-build in `docs/specs/guards.md`; unit ownership is
REQ-fresh-built-unit in `docs/specs/evidence.md`. A compiling producer cannot
simply rename its old split-environment option to a runtime description.
The legacy distinct-environment form refuses with the migration remedy.

The deciding regression retains the actual selected implementations: analysis
under `GOAMD64=v1` and a compiling producer under `v2` previously admitted results
1 and 2, followed by result 3 after editing the producer-only implementation
while the analysis closure and guard stayed equal. Execute the admitted artifact,
preserve legitimate runtime differences, and pin later native checking under
the same guard domain. Diagnostic producers retain identity-only evidence;
their instrumentation cannot silently acquire ordinary outcome support.

## Declaration snapshot ownership — 5.4 / 5.5a

Gomutant's `internal/mcpserver/treecache.go` walks lexical tree paths without
descending directory symlinks. Its local-replacement containment is lexical,
and a workspace member can likewise resolve through an unchanged symlink.
A loaded physical member's changed declarations can therefore leave the key
unchanged. Warm a tree in which a retained finding's declaration is absent,
add that declaration in the symlinked member, then preview prune: a cached
absence can propose deleting the now-live record. Test warm/cold discovery
and prune before accepting a snapshot dependency certificate. This is separate
from shaped mutation's scratch-write isolation above.

The same loader holds the server mutex through loading and the closing key
read. A second caller cancelled while waiting cannot leave until the first
load ends; the hit path then returns without checking its cancellation. Pin
a held first loader and a cancelled waiter, without timer-based ordering.

`Tree` also stores `Selection.Tags` from the caller and returns the same slice
through `Selection()`, although execution has already materialized its frozen
environment. Mutating either slice can report selection B over artifacts
loaded under A. Constructor inputs and returned projections need owned values.
These cases constrain 4.1's shared design and are enforced at Gomutant adoption.

## Selection grammar fidelity — 5.3 / 5.4 / 7.4

Gomutant's `replaceTagsFlag` splits and rejoins GOFLAGS using whitespace.
Adding tags to `'-modfile=/tmp/two  spaces/alternate.mod'` changes the quoted
path's significant bytes. Preserve Go's argument grammar and audit the matcher
that independently splits the same input. Include repeated tags and quoted
paths; this is not the already-recorded omitted-versus-empty selection case.

Stipulator's `validateGoflags` refuses `-skip` but not Go's accepted
`-test.skip` alias. A passing bound test beside an unbound failing test, with
GOFLAGS selecting the latter out, can produce healthy package execution while
discovery still inventories the whole package. Canonicalize recognized aliases
before the selection-ownership judgment. Keep binary-argument arity/identity
parsing distinct from this go-command flag policy.

## Declaration and envelope fidelity — 5.2 / 7.8 / 9.2

Stipulator's syntax-only test discovery requires a bare `*T` to come from a
dot import, although Go also accepts `type T = testing.T` followed by
`func TestAlias(t *T)`. The alias-shaped test can run under Go but disappear
from the selective obligation inventory. Match Go's syntactic inventory and
let compilation decide type compatibility; preserve broken-package discovery.

Its runnable-witness and `SymbolFile` paths use line-adjusted positions for
physical test-file membership and ownership. A `//line generated.go:1` in a
physical `_test.go` can demote a quick-driven witness or name another file.
Separate physical positions from intentionally adjusted diagnostic positions.

The witness envelope rejects `registrations: null`, but not null optional
`observationExclusions` or `observationNamespaces`. Those decode to nil slices
and can retain a valid record name. Pin per-file refusal under the declared
optional-field grammar while preserving the native and ledger codecs' distinct
rules. This is not authentication of a private store.

## MCP resource publication — 5.5a, including the existing single-root server

Stipulator's `Server.syncIndex` reads/writes/iterates `indexed` without a lock,
while the SDK permits concurrent handlers. A settled corpus containing newly
added requirements can trigger concurrent map access from overlapping reads.
Separately, `toolCompile` returns successful new corpus counts without updating
the advertised resource index. Test overlapping same-root calls and successful
compile followed by `resources/list`, including removals. One successful
compilation publication boundary can own reconciliation without changing
compile's diagnostic-return behavior. Repair is not conditional on adding cwd.

## Remaining A/B selection admission — 5.1

Extend requested-workload admission to the already-mapped A/B selection case:
a valid but unselected row cannot authorize its own selection. Requested work
is distinct from native freshness and from capture health. Retain the known
bounds on dynamic children never observed; missing-on-both-sides profile
obligations remain requested obligations rather than disappearing from the
intersection of emitted rows.

## Destructive cancellation — 5.6 / 7.1

Pew's `gcStore` takes no context and keeps removing records after a cancellation
inside one store; each `Store.Remove` obtains a background publication context.
Test cancellation after the first reported removal and while waiting for the
next lock. Completing a paid measured arm does not authorize beginning another
destructive unit. Shared closing-policy ownership preserves distinct measurement
overwrite, applicability refresh and profile attachment semantics.

## Verification and consolidation residues

- **5.3 / 7.4:** typed repetition count is absent from Stipulator record identity.
  This is not the reproduced raw-count override. Test count 1 followed by count 2
  with stateful repeated execution; decide any reuse license from the witness
  model, not merely the unchanged build. No false serve is asserted here.
- **5.6:** Gomutant's historical coverage wire data remains needed, but production
  `Coverage.Persist` / `PersistedCoverage.Restore` have only test callers after
  the cutoff. Separate fixture conversion from live execution capability.
- **7.7:** `gotool.Runner.Run` retains all output in buffers before bounding a
  refusal, and Pew A/B retains streams plus cloned blocks while rewriting each
  accumulated prefix. Source establishes the allocation/cumulative work shape,
  not a measured resource failure. Measure equal completed workloads before
  choosing bounded retention; never truncate authoritative successful listings.
