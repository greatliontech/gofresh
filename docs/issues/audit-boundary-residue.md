# Unclosed mutation and operation boundaries

Lands: docs/plans/tooling-redesign.md 5.2d.

These are distinct obligations, not permission to broaden a repair into a
second implementation trajectory. Except where explicitly measured below,
the mechanisms are source-traced and their deciding regressions remain to be
run. Existing execution-model, assertion and sampling limits remain governing.

The shared `Session`/built-artifact singleton and package-process forms exist,
with typed deciding causes, scope and accepted authority. Stipulator's
engine constructor uses `gofresh.NewContext`; its physical declaration
positions, full selection and dotted package identities, and source-resolution
certificate dependencies have also landed. Those are controls for the remaining
work, not repairs to repeat. The primary residual is adopting the shared
package-producing form and complete build/runtime descriptions; secondary
constituents below retain their own destinations. Each native unit closes one
execution over its complete subject set; consumer publication groups and retry
selection remain distinct and cannot union separate attempts' evidence.

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

Generated import probes also always choose `zz_gomutant_structural_probe.go`
without establishing that the path is absent. An existing file with an
initializer can be overwritten in the scratch tree, so a test fails because
the initializer vanished rather than because of the declared forbidden import.
Pin a collision carrying independent behavior, not merely a pre-existing copy
of the same blank import. Preserve exact candidate attribution and the original
tree; this is part of safe shaped materialization before shaped assurance.

## Remaining build-description adoption — 5.2d / 5.4

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

Preserve the now-context-owned Stipulator constructor while migrating its
producer to the package form. Its existing use of `NewContext` does not itself
establish complete build/runtime descriptions, retained artifacts or independent
unit closing. The loader's separate containment limitation remains distinct.

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
These cases constrain Gomutant's adoption of the existing shared design.

## Selection grammar fidelity — 5.3 / 5.4 / 7.4

Gomutant's `replaceTagsFlag` splits and rejoins GOFLAGS using whitespace.
Adding tags to `'-modfile=/tmp/two  spaces/alternate.mod'` changes the quoted
path's significant bytes. Preserve Go's argument grammar and audit the matcher
that independently splits the same input. Include repeated tags and quoted
paths; this is not the already-recorded omitted-versus-empty selection case.

Stipulator's `validateGoflags` still reads `selectionGoflags`, which lists
`skip` but not Go's accepted `test.skip` alias. The separate
`selectionBinaryArgs` table includes `test.skip` but does not govern this
GOFLAGS path. A passing bound test beside an unbound failing test, with
GOFLAGS selecting the latter out, can leave discovery's full inventory beside
partial execution. Preserve this alias-policy residual separately from the
landed build-selection and declaration-certificate work. Canonicalize accepted
aliases before judging selection ownership; keep binary-argument arity and
identity distinct. Typed repetition identity is another question below.

## Landed declaration controls retained at adoption

The alias-shaped runnable test (`type T = testing.T; func TestAlias(t *T)`),
physical `_test.go` ownership under `//line`, dotted import identities and
complete selected-view certificates are now covered by the completed 5.2a/5.2b
work. Preserve those properties when migrating producers; source certificates
do not become execution evidence and missing historical dependencies do not
become current by decoding.

## MCP resource publication — 5.5a, including the existing single-root server

Stipulator's `Server.syncIndex` reads/writes/iterates `indexed` without a lock,
while the SDK permits concurrent handlers. A settled corpus containing newly
added requirements can trigger concurrent map access from overlapping reads.
Separately, `toolCompile` returns successful new corpus counts without updating
the advertised resource index. Test overlapping same-root calls and successful
compile followed by `resources/list`, including removals. One successful
compilation publication boundary can own reconciliation without changing
compile's diagnostic-return behavior. Repair is not conditional on adding cwd.

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
- **5.6:** Pew's profile parser and ordinary runner separately recognize the
  same PASS/optional-CR completion marker. Use one recognizer when consolidating
  the producer readers; keep executor success, sample admission and profile
  validity separate. No current disagreement between those grammars is claimed.
- **5.2d / 5.4 / 7.1:** Adopt the shared typed authority/cause account rather than
  growing another consumer-local reason parser. Separately,
  `EnvSnapshot.JSON` is mutable beside its parsed values; make the common
  representation immutable before extending its consumer exposure.
- **9.2:** Pew's older producer prose still describes a compiling go-test driver
  and one package transaction beside the retained-binary/per-arm clauses. Its
  toolchain prose conflates reported version with selected content. Reconcile
  these with the current built-arm and selected-content contracts, without
  changing the installed evidence model to match obsolete prose.
- **5.2 / 5.3:** Stipulator's cancellation and publication prose must distinguish
  interrupted work from the already-completed package prefix; the publisher's
  old group-completion comment must describe its actual package callback.
- **5.4:** Gomutant's shaped-observation prose must describe the transformed
  executable's identity-only evidence and distinct assertion authority. A clean
  baseline's supported observation is not the mutant's support.
- **7.7:** `gotool.Runner.Run` retains all output in buffers before bounding a
  refusal, and Pew A/B retains streams plus cloned blocks while rewriting each
  accumulated prefix. Source establishes the allocation/cumulative work shape,
  not a measured resource failure. Measure equal completed workloads before
  choosing bounded retention; never truncate authoritative successful listings.
