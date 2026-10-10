# Unclosed listing, oracle and operation boundaries

Lands: the component destinations in docs/plans/tooling-redesign.md below;
delete after every component has landed or been refuted by its deciding case.

These are distinct obligations, not permission to broaden a repair into a
second implementation trajectory. Except where explicitly measured below,
the mechanisms are source-traced and their deciding regressions remain to be
run. Existing execution-model, assertion and sampling limits remain governing.

## Listing dependency admission — 3.1b / 3.2

`closure/listingmemo.go` records directory names but only the bytes of entries
already recognized as regular source files. Replacing an empty directory
`extra.go` with a source file of the same name leaves the recorded names equal
and adds no compared file. The old listing can omit the new initializer and
feed an unchanged scan key. Test warm/cold/discarded-cache answers after the
retype, including a changed value read by the original subject.

`closure/toolchainsource.go` accepts a version-matching cached surface with
no packages or stamps. Its empty digest map reaches `movedKeys`, which checks
only supplied keys, and produces no moved key. Incomplete cache shape is not
positive admission evidence. Test empty and structurally incomplete inventories
under a selection the real listing refuses, with an ordinary valid hit as
control. Preserve legitimate empty selected-file sets for individual packages;
do not confuse those with an absent surface inventory or demand authentication
of coherently forged private cache data.

## Oracle growth and shared state — 3.0 safety prerequisite

Gomutant's `freshness.go` killer-drift gate follows forward declaration
references and refreshes the target compartment. An added test can write a
carrier-free scalar that an unchanged test reads without entering that forward
walk. The assertion that growth cannot un-kill is then false.

Measured against Gomutant `a921be9`, with the original implementation and a
temporary added-test overlay:

- `Value(x) = x+1`, `var disabled bool`, and `TestZ` checking `Value(1)==2`
  only when `!disabled`: the original complete oracle kills three candidates.
- Add `aa_test.go` with earlier-running `TestA` setting `disabled=true`, and
  include both tests in the explicit oracle.
- Reuse reports all three kills standing and re-measures zero candidates.
  A forced complete-oracle run reports zero kills and three survivors.

The inverse, a new test enabling an assertion, is a required survivor-side
case. Historical full-oracle execution does not prove independence under a
changed oracle. Disable unlicensed composition conservatively and prevent
records produced through it from gaining exact-reuse authority after the fix.
Retain useful history and independently justified unchanged-input reuse.
Until that cutoff is installed, use direct tests or fresh explicit-full-oracle
ephemeral probes for assurance, never killer-drift composition or its scores.

## Shaped mutation materialization and dependencies — 5.4, before shaped assurance

Gomutant `shaped.go` copies symlinks unchanged, then writes replacements through
the copied path. A manual recipe targeting an absolute symlink to the original
tree follows it during the scratch write; the clean twin follows it too.
The same path can reach an external file. The tool's own write, not merely its
oracle, needs physical isolation. Test original bytes across success, failure
and cancellation with both original-tree and outside-tree targets. This path
is not used by the fresh body-overlay probes allowed above.

The same file's `localReplaceActive` scans text after `=>` for unquoted path
prefixes. A legal quoted local replacement is missed. An import-boundary
candidate can introduce an external dependency absent from the clean oracle;
changing its initializer leaves the current shape digest without that source.
Use module grammar or resolved metadata, with quoted/unquoted, workspace and
mutable introduced-dependency controls. Current-policy shaped records also
need that dependency judgment; their policy label alone grants nothing.

## Immutable configuration after cancellation — 4.1

`gotool.Sampler.Sample` installs a holder retaining the supplied environment
slice before its cancelled take returns. Reusing that backing slice for B and
then asking with a fresh A can run B under A's memo key. Test a pre-cancelled
first ask, sequential caller slice reuse and the eventual spawned environment.
No current fleet caller's exploitation is asserted; the public API ownership
case belongs in the session boundary.

## MCP resource publication — 5.5a, including the existing single-root server

Stipulator's `Server.syncIndex` reads/writes/iterates `indexed` without a lock,
while the SDK permits concurrent handlers. A settled corpus containing newly
added requirements can trigger concurrent map access from overlapping reads.
Separately, `toolCompile` returns successful new corpus counts without updating
the advertised resource index. Test overlapping same-root calls and successful
compile followed by `resources/list`, including removals. One successful
compilation publication boundary can own reconciliation without changing
compile's diagnostic-return behavior. Repair is not conditional on adding cwd.

## Requested work and destination ownership — 4.1–4.5 / 5.1

Pew's per-package `Destinations` check cannot see two workspace modules with
root-level `BenchmarkWork` writing to the same explicit store path. Under
`run --all`, both can report recorded while the second replaces the first.
Admit destination injectivity over the whole requested invocation before any
measurement, not independently per package.

A valid recording of `BenchmarkWork/small` can satisfy ordinary `run`'s
top-level freshness filter for a subsequent request of `BenchmarkWork/large`.
Requested workload fulfillment is separate from native freshness. Carry one
admitted workload through selection, serving and stream admission; retain the
known bounds on dynamic children never observed, and extend the same rule to
the already-mapped A/B selection case.

`run --benchtime=bogus` reaches ordinary package preparation and warm-up before
the measurement command rejects it; run count also lacks the corresponding
entry admission. Test the supported duration/iteration and count domains before
listing/building, keeping diagnostic effort separate from ordinary effort.

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
- **4.3 / 4.5 before acceptance:** every conversion/adoption/merge used by the
  first Pew arm needs unit-owned cancellation there. Item 5.5 completes other
  paths; it cannot defer a prerequisite of the first accepted vertical.
