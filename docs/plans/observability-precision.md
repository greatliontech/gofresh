# Observability precision

Spec: docs/specs/closure.md (REQ-closure-observability-analysis, REQ-closure-observability-batch-equivalence, REQ-closure-observability-memo); docs/specs/runtime-inputs.md governs chunk 4.

- [x] 1. Testing-harness failure/logging channel: amend the audited-pure set with a
  method-scoped, output-only carve-out for `testing.(*common)`'s failure/logging
  family (`Fatal`, `Fatalf`, `Error`, `Errorf`, `Log`, `Logf`, `Skip`, `Skipf`,
  `Fail`, `FailNow`, `SkipNow`, and the exact audited remainder the diagnosis
  settles), so the walk classifies them as harness-internal instead of descending
  into `fmt`; argument method sets stay reachability-visible; `Setenv`/`Chdir`/
  `TempDir` keep their existing classifications. ObservationRTA bumps; fixture
  corpus grows failure-path legs (t.Fatal/t.Log observable, Setenv still blocked)
  and moved rows re-pin.
- [x] 2. Harness dispatch through `testing.TB`: helpers taking `testing.TB` —
  the dominant real-world carrier of `tb.Fatal` — are refused at two tiers
  today, and both need their own diagnosis: the maximal typed testing scan
  flags the escape (`testing runtime value escapes analyzable receiver`),
  refusing the whole package, and the subject tier widens the RTA-resolved
  invoke (`interface invoke outside RTA`, the `locallyClosedDynamicValue`
  guard). Admit exactly the dispatch whose resolved target set is entirely
  audited harness methods, with a spec statement per tier; fixture leg
  `harnesstb/TestHelperTBFatal` re-pins from refused to observable. (The
  bound-method form `f := t.Fatal; f(x)` already classifies — the SSA wrapper
  carries the method object — and is pinned by `harnesslog/TestBoundMethodFatal`.)
- [x] 3. Refusal-diagnostic preference order: the proof's refusal names the first
  blocking effect under a causal-attributions-first preference order (fresh-path
  and attributed escapes before generic classifications), deterministic across
  recomputations; spec's diagnostic clause gains the order; corpus rows whose
  named reason moves re-pin; strategy-version disposition recorded (shares
  chunk 1's bump iff unreleased, else its own). In scope: folding the legacy
  reason rank onto `externalEffect.kind` (the rank currently re-derives the
  classification by substring), so one preference mechanism serves both
  projections.
- [x] 4. Observe-path stall: diagnose the ~100s warm-run stall in the observe phase
  (anchor: the d2cf048 measurement record — stall 100.5s on the cerebro repro at
  9d0fe5a2) via the tailprobe instrument; fix per the diagnosis at the narrowest
  level, or decompose into sub-chunks if the mechanism demands it.
- [ ] 5. Startup-flow dispatch closure: `directExternalEffects` records
  classified static and attributed dynamic-target effects but cannot widen an
  invoke with no attributed targets, so a `TestMain` dispatching on a
  test-planted global after `m.Run()` reaches effects the startup walk never
  sees (pre-existing, surfaced by chunk 2's review). Chunk 2 scoped its
  receiver-escape exemption to packages without a user TestMain exactly
  because of this gap — landing the startup widen lifts that scoping (the
  spec sentence records the lift condition). The naive fix — widen
  every unattributed startup invoke — would refuse every initializer doing
  interface I/O; needs its own diagnosis plus corpus measurement of the
  refusal blast radius.
- [ ] 6. Cerebro-scale validation and close-out: re-measure the uncacheable
  population (baseline ~2,113 subjects) and the warm/cold campaign profile on the
  cerebro repro; promote the issue doc's load-bearing rationale into the spec,
  delete it; consolidation scan; plan close-out.
