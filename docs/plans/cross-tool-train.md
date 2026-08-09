# Cross-tool train: overlay cost, run-ephemera classification, gomutant throughput

The active roadmap across gofresh, gomutant, stipulator, and pew. Each
chunk is one commit in its named repo, run through the full adversarial
loop there; gofresh chunks release before consumer chunks bump. WIP = 1.
Ordering for the gomutant tail follows the `Lands:` lines in that repo's
issue docs; the two lead chunks are the field-blocking overlay defect and
its root-cause class. Remaining chunks execute bottoms-up by layer:
gofresh first (21, 22, 23, 24, 20, 17), one gofresh release, then
stipulator (18, 19) and its bump, then 25, then the re-measure (16), then pew
(15), then plan close-out.

- [x] 1. gomutant: overlay commit cost + quarantine
      (gomutant docs/issues/store-update-reparses-whole-overlay.md) —
      stat-keyed overlay parse cache (O(changed) per commit; the
      whole-set merge and prune semantics preserved) plus a size-ceiling
      quarantine treating oversized entries as evictable cache content.
- [x] 2. gofresh: run-scratch runtime-input handling
      (charter: pew
      docs/issues/bench-scratch-dirs-recorded-as-runtime-inputs.md;
      that doc's automatic-classification direction proved unsound —
      the identity-only testlog cannot split own-scratch from
      absence-probes) — enforced scratch-namespace admission
      (caller-declared MkdirTemp-shaped namespace, gofresh proves
      absence at both bracket endpoints before dropping a record) plus
      directory objects contributing membership+mode, never own
      size/mtime, to bracket and path digests; runtimeinput spec
      amendment + observation-strategy revision; corpus pin re-consent
      as the LAST spec operation of the change set.
- [x] 3. pew, gomutant, stipulator: ride the chunk-2 gofresh release;
      pew grows the per-package scratch-namespace declaration (its
      wiring does change, contra the issue doc's claim) and its
      scratch-dirs issue closes; confirm the field repo's
      manifests shrink — field measurements run against a pinned copy
      of the workload repo, never a live checkout.
- [x] 4. gomutant: run survives any single oracle outcome + incremental
      persistence (gomutant
      docs/issues/oracle-deadline-aborts-run-nothing-persisted.md) —
      inserted ahead of the throughput tail: a campaign losing every
      verdict to one slow mutant gates the tail's field measurements.
- [x] 5. gofresh: bracket-declared static inputs
      (gofresh docs/issues/bracket-declared-static-inputs.md) — the
      bracket vocabulary admits declared static inputs (repo files and
      committed trees whose digests ride the generation snapshot) and
      excludes non-corpus session dot-dirs; ~60% of cerebro's
      uncacheable witness mass.
- [x] 6. stipulator + gomutant: retire the targets seam (user decision:
      the binding-surfaces export predates the tool split, no consumer
      drives it, and findings never return — the adequacy loop it was
      designed for was declined rather than closed) — stipulator loses
      the targets verb, binding-surfaces spec, wire module, and the two
      issue docs premised on surfaces; gomutant loses the adapter and
      format-sniff, its own config document becoming the one producer
      schema.
- [x] 7. gofresh: fmt taint keys on the sink
      (gofresh docs/issues/purity-bars-dynamic-and-fmt.md, the fmt
      half — ~308 witnesses) — the writer-first print family is
      Sprint-equivalent when the writer provably pins an audited
      in-memory sink; unproven writers keep the refusal.
- [x] 8. gofresh: caller-supplied dynamic narrows to escaping dynamism
      (the same doc's dynamic half — ~647 witnesses) — a dynamic
      argument every in-view call site pins to view-analyzed values is
      not dynamism; enumeration-refused, escaping, or
      outside-view-supplied dynamism keeps the refusal.
- [x] 9. stipulator: ride the purity/statics gofresh release — dep bump
      to v0.47.1 plus reviewed observation exclusions (excluded_paths
      with withdrawal-bound evidence); repo-anchored oracle reads route
      through cerebro-side bracket_paths config, deliberately not
      tool-side static roots.
- [x] 10. gomutant: preflight plan phase + execution progress
      (gomutant docs/issues/preflight-plan-phase.md and
      docs/issues/silent-execution-no-progress.md — one run-loop pass
      wires both).
- [x] 11. gomutant: confirmation uses stability evidence
      (gomutant docs/issues/confirmation-ignores-stability-evidence.md).
- [x] 12. gomutant: kill-cache keying by killing-oracle content
      (gomutant docs/issues/kill-cache-keying-asymmetry.md — builds on
      the compartment ledger the preflight surfaces).
- [x] 13. gomutant: pipeline preparation with execution
      (gomutant docs/issues/pipeline-preparation-with-execution.md —
      includes the measured pre-baseline stall; before/after measured
      on a pinned copy of an available workload repo, its own baseline
      pair).
- [x] 14. pew: one go-invocation environment
      (pew docs/issues/one-go-invocation-environment.md).
- [ ] 15. pew: profile capture and attribution as recording
      companions (pew docs/issues/profile-capture-attribution.md) —
      --profile captures per-arm cpu (and mem, where B/op is claimed)
      evidence stored under the recording's provenance conjunction;
      status gains the attribution verdict, stat the profile-diff view;
      the consumer hand protocol stays as the derivation loop. A
      further pew issue folds in here (user-flagged, content briefed at
      chunk open); the chunk opens with a design discussion covering it
      and any surface redesign it implies, before implementation.
- [x] 25. gofresh: cross-package init-only registration (gofresh
      docs/issues/cross-package-init-only-registration.md) - the
      chunk-22 fixed point lifted to composition: function-attributed
      mutation facts plus per-fact foreign-reference regions prove an
      exported constructor init-only across the graph; the field
      probe's last first-party blocker.
- [x] 26. gomutant: serve-path provenance re-stamp (gomutant
      docs/issues/served-record-provenance-frozen.md) - a pure serve
      recomputes commit/dirty provenance like the growth and drift
      serves already do, so a record born dirty promotes to the repo
      findings document (attestations riding along) once its content
      lands at a clean commit; without it, attest-before-commit
      dispositions never reach teammates or CI.
- [x] 27. gofresh: external-dependence refusals name their sink (gofresh
      docs/issues/unnamed-external-dependence-verdict.md) - effects
      added by the unaudited-standard-operation arm feed the
      preferred-reason selection, so a subject refused for reaching fmt
      names the package and symbol; the field re-measure's 413 fmt
      verdicts are unjudgeable without it.
- [x] 28. gofresh: init-flow escape discharge for registry carriers -
      the field re-measure's 979 escapes-writable refusals: a carrier
      passed to a graph-proven init-flow callee whose parameter
      demonstrably leaks nothing discharges the escape
      (parameter-effect facts, the plain-call analogue of the
      receiver-effect rung), and a range-value binding over a carrier
      whose element type hands out mutable reach discharges when the
      binding is demonstrably read-only; fail-closed everywhere else.
- [ ] 29. gofresh: maximal-tier reason ranking conforms to the shared
      order (gofresh docs/issues/maximal-tier-reason-ranking.md) - rank
      plumbing replaces the per-file stratum switch and the two-class
      package fold, the shared rank table's packagePath branch is
      fixed, and the unrefinable-class interaction is settled;
      display-only (verdicts unchanged), so it rides after the
      re-measure.
- [ ] 30. gomutant: consumer-surface bounds and visibility (gomutant
      docs/issues: findings-output-unbounded,
      changed-mode-oracle-delta-routing, attest-and-promotion-visibility,
      plan-and-progress-cosmetics) - bounded findings summary by
      default with detail opt-in, capped reason lists, the residue
      row's re-measure signpost, attest echoing disposition and layer,
      the promotion-commit warning, and the two progress cosmetics;
      the four docs delete at close.
- [ ] 31. gomutant: record correctness and lifecycle (gomutant
      docs/issues: detached-record-lifecycle, fresh-stamp-manifest-base,
      growth-drift-promotion-untested) - prune and retarget verbs with
      attestations carried by survivor identity, terminal labeling of
      resolved-dead records, per-subject manifest bases for the fresh
      stamp and Committable, and the growth/drift promotion-shape
      pins; the three docs delete at close.
- [ ] 32. gofresh: init-flow audit completion (gofresh docs/issues:
      object-closure-initializer-address-capture,
      object-closure-selector-store-unaudited,
      object-closure-subtree-appearance-breaks,
      deferred-init-flow-unpinned) - initializer-expression captures
      audited (the remaining false Valid), selector-shaped
      cross-package stores value-audited, writeless subtree
      appearances discharged per the spec's precision sentence, and
      the deferred-init-flow pin; also closes the alias-scan residue
      the spec records: a qualified helper's parameter bound at the
      init call site (init(){setup(Hooks)} with the literal writing
      through setup's param) and a composite-target binding (s.m =
      Hooks then the literal writes s.m) both currently stay invisible
      to the init-alias fixpoint - both are reachable wrong-Valid
      shapes with reviewer reproducers; the four docs delete at close.
- [ ] 33. gofresh: open-world dynamic edges named and refined - the
      field report's biggest cost (caller-supplied dynamic triggered
      by dependency interface dispatch wipes caching for yaml-heavy
      packages, ~25 minutes per run over 929 candidates) with no call
      edge named in the reason; the naming half follows the chunk-27
      pattern, the refinement half narrows the open-world rule over
      proven dependency dispatch.
- [ ] 34. gofresh: startup-walk soundness pair (gofresh docs/issues:
      dotless-module-paths-classified-standard,
      func-value-self-capture) - a dotless module path silently
      disables the whole startup walk, and receiver-stored closures
      launder receiver writes through read-only proofs; both docs
      delete at close.
- [ ] 35. gofresh: verdict precision and validation cost (gofresh
      docs/issues: enumeration-targets-over-approximated,
      validation-manifest-evaluation-unshared,
      fresh-mutation-in-module-scratch) - dispatch target sets stop
      dragging initializer content into siblings, producer validation
      shares manifest evaluation, and disciplined in-module scratch
      goes recordless; three docs delete at close.
- [ ] 36. gofresh: analysis-surface structure (gofresh docs/issues:
      one-dispatch-site-classifier, observation-facts-struct) - one
      call-site judgment and one observation-facts shape, collapsing
      the five partial classifier copies and the three hand-built View
      literals; two docs delete at close.
- [ ] 37. cross-tool: runtimeinput producer facade (gofresh
      docs/issues/runtimeinput-producer-facade, gomutant
      docs/issues/oracle-scratch-namespaces) - one facade for the
      completed-observation conjunction across stipulator, gomutant,
      and pew, carrying the scratch-namespace declaration surface that
      stops union-equality churn; both docs delete at close.
- [ ] 38. gomutant: hot-loop committable evidence (gomutant
      docs/issues: staged-snapshot-run-mode, env-input-oracle-policy,
      runtime-input-provenance) - staged-index measurement collapses
      the attest-promote-commit trail, the reviewed exemption record
      unblocks the repo-root idiom, and producer-output provenance
      stops re-measures the evidence already covers; three docs delete
      at close.
- [ ] 39a. gomutant: oracle-process CPU oversubscription - concurrent
      mutant jobs each spawn full-width go toolchain children
      (jobs x NumCPU runnable threads, quadratic in cores at the
      default), starving the host; cap inner parallelism at the spawn
      sites (GOMAXPROCS and -p at max(1, NumCPU/jobs) in the oracle
      env) and run oracle processes at low scheduling priority; the
      jobs default stands.
- [ ] 39. gomutant: campaign robustness and cost (gomutant
      docs/issues: decision-build-locality,
      ephemeral-replacement-outside-oracle-closure,
      post-completion-cpu-tail) - one broken target stops aborting the
      campaign, out-of-closure overlays stop reading as survivors, and
      the post-completion spin is profiled and closed; three docs
      delete at close.
- [ ] 40. gomutant: init bodies as measured subjects (gomutant
      docs/issues/init-functions-as-subjects) - the classic
      silent-fault carrier becomes measurable end-to-end; doc deletes
      at close.
- [ ] 41. cross-tool: the MCP surface contract (gomutant
      docs/issues/mcp-long-running-runs, stipulator
      docs/issues/mcp-progress-not-observed) - the standing principle
      lands in both MCP specs: the MCP surface outranks the CLI and
      serves an LLM in a harness - minimal output, maximal usefulness;
      both surfaces audited against it, cancellation propagation and
      live progress included; both docs delete at close.
- [ ] 42. stipulator: correctness batch (stipulator docs/issues:
      term-matcher-ascii-boundaries, partitions-uncapped-seam-unpinned,
      scope-prefix-boundary-semantics, witness-store-gc,
      gopter-property-recognition) - rune-boundary term matching, the
      seam pin, boundary-aware scoping with the dropped-diagnostic
      fix, store eviction for departed identities, and gopter witness
      classification; five docs delete at close.
- [ ] 43. stipulator: publication ladder collapse (stipulator
      docs/issues/publication-ladder-collapse) - one publication
      ladder, one closing validation; doc deletes at close.
- [ ] 44. pew: trust, cost, and the derivation loop (pew docs/issues:
      recorded-config-trust, per-benchmark-view-builds,
      derivation-ab-mode) - read-side recording validation, per-package
      view sharing, and pew ab replacing the hand stash cycle; three
      docs delete at close.
- [ ] 45. stipulator: slice frontier soundness (stipulator
      docs/issues/slice-frontier-uncertainty) - typed frontiers gain
      the closure model's sound floor and dispositions over
      reflection, build tags, and init effects; doc deletes at close.
- [ ] 46. stipulator: witness fingerprints bind closure content to the
      consuming compile (stipulator
      docs/issues/closure-edit-revert-inside-run-span) - the
      edit-revert-inside-span residual closes with the record
      redesign; doc deletes at close.
- [x] 47. gofresh: func-field calls discharge under the
      environment-free registration audit - the second re-measure's
      unchanged 979 escapes-writable refusals: the leak-free engine
      admits a call through a func-typed field of a bound entry (the
      target is a field read, arguments keep the argument loop), and
      the pre-existing Signature-classification hole this exposes -
      a registered function value whose closure environment can write
      state the settled verdict assumed stable - closes with a
      composition-level audit: every direct store of a function-carrying
      value into a carrier must be environment-free (plain named
      functions, method expressions, audited literals); any other
      value shape refuses the carrier with a named culprit, and the
      init-exempt regions gain the carrier-argument deferral the spec
      always owed them.
- [x] 48. gofresh: binding-argument deferral in the leak-free engine -
      a bound entry's field passed as an argument to a plain named
      function (the classifier's equalCols(header, class.columns)
      shape) defers to that parameter's leak-free fact exactly as a
      carrier argument does, resolved over the same persisted facts,
      absence refusing.
- [x] 49. gofresh: returned-entry disposition - a helper returning a
      carrier-bound entry (the registry's registeredClass shape) hands
      the alias to its caller; the caller-side judgment prices the
      returned entry like a binding, the returned-alias rung's plain
      analogue.
- [x] 50. gofresh: method calls through leak-free bindings defer to
      receiver-read-only facts - the third re-measure's standing
      factClassRegistry escape (757): a value-receiver read
      (class.admissionSpelling()) refuses the binding proof though the
      receiver-read-only fact already proves it; the MethodVal arm
      collects wanted method keys exactly as the argument deferral
      collects parameter keys, carried through the existing MethodUses
      channel, absence refusing.
- [x] 51. gofresh: constructor-result registration audit - the third
      re-measure's registers-function-values family (normativeThresholds
      across four duties packages, officialCurrencyCatalog): a carrier
      initialized from a plain named in-package constructor
      (var K = generated()) audits the constructor's returned
      registrations instead of poisoning as an opaque call result -
      result expressions judged by the environment audit over the
      constructor body with parameters assumed environment-free (the
      caller judges the arguments), locals flowing into results
      audited like carrier stores; the proof persists as a per-package
      return-env-free fact so foreign constructor chains
      (threshold.MustRows over cite.Must arguments - cerebro's
      generated shape) resolve at composition through a deferred
      env-call channel, arguments judged recursively with deferrals
      compounding, absence keeping the poison.
- [x] 55. gofresh: receiver-read-only return shapes widen to writeless
      constructions - a value-receiver method returning a composite
      literal whose element values are receiver reads of
      non-alias-handing types (threshold's Rule() RuleID{value:
      t.entry.rule}) or a conversion of the receiver to a
      non-alias-handing type (foral's String() string(p)) proves
      read-only; alias-handing element types and conversions keep the
      refusal.
- [ ] 56. gofresh: registered-population parameter proof for func-field
      calls - a carrier field passed as an argument to a call through
      a func-valued field of the same leak-free binding (the
      near-match loop's class.near(header, class.columns)) defers to
      the field position's registered population: every value the
      environment audit admits into that field must prove the
      parameter leak-free (named functions by their persisted
      parameter facts, audited literals judged at registration,
      constructor results through the return-env-free channel), any
      unproven registrant keeping the escape.
- [ ] 57. gofresh: carrier index extraction admissions - a comma-ok
      existence read discarding the extracted element (the
      membership-validation shape) is writeless on any carrier, and a
      call whose callee is an index read of an env-free-audited
      carrier (the dispatch-table shape legs[token](inv)) admits with
      arguments judged like the func-field call's; extraction that
      binds or hands out the element keeps the escape.
- [x] 60. gofresh: constructor bodies derive - the fifth probe grounds
      the generated-threshold chain in building constructors
      (threshold.MustRegistry, money.mustCurrencyCatalog): the
      return-environment-free judgment gains a caller-judged derivation
      class - a range binding over a parameter or judged value is
      judged, a field read of a judged value is judged, an append of
      judged elements onto a judged local stays judged, a conversion
      of a judged value is judged, and a generic plain-named
      constructor call records a dependency edge exactly as a plain
      one (the proof judges the generic body, type parameters falling
      to the signature walk's fail-closed default) - every other
      derivation keeps the refusal, and writes through any judged
      binding break it exactly as today.
- [x] 61. gofresh: aggregate writes of judged values derive - the sixth
      review's anchor trace: both field chains now die at their last
      link, a judged value written into the result aggregate under
      construction (temporal.NewRegistry's series[coord] = s,
      mustCurrencyCatalog's c.current = current); an element, field, or
      dereference write whose WRITTEN VALUE judges becomes a source of
      the written base instead of a break - the base stays judged
      exactly when everything stored into it judges - while unjudged
      written values keep the break; completes the
      building-constructor derivation the anchors need.
- [x] 62. gofresh: unlinked-backing binds in the derivation class -
      the alias-pair recorder links only whole-identifier binds and
      append bases, so every other bind whose source shares mutable
      backing defeats both the break propagation and the store union,
      each shape probe-confirmed as a composed false Valid on HEAD
      through the constructor door: a call of a judged plain named
      callee returning its argument (func id(s []handler) []handler {
      return s }; write through the result swaps the argument's
      element), an element read of a reach-bearing element (x :=
      s[0] with s []*catalog; x.current write mutates s's pointee; x
      := m["d"] with map-of-slice elements alike), a conversion
      (m2 := table(m); m2 write mutates m), and a composite-literal
      source embedding a tracked value (h := holder{rows: rows};
      h.rows[0] write mutates the parameter's storage, param and
      local-only bases alike); either every such bind
      links the target to the reach-bearing tracked names its source
      expression reaches - conservative pairing, breaks and stores
      propagating only when a write occurs - or the leak-free proof
      gains an argument-flows-to-result bit deciding call-result
      links precisely.
- [x] 63. gofresh: element reads of judged containers derive - the
      seventh probe isolates the field registries' next links: v :=
      m[k], v := s[i], and the comma-ok map read all refuse today, and
      every temporal registry constructor binds through them; a read
      of a judged container's element is judged (the container's
      store-set invariant already guarantees element judgment), the
      bind recording the alias link chunk 62 introduces so writes
      through the read binding keep propagating - the admission is
      sound only on top of those links, which is why 62 lands first;
      the comma-ok second result is boolean and free.
- [x] 64. gofresh: audited-pure standard callees join the derivation
      class - slices.Clone(rows) in the keyed-registry constructor
      refuses as an unproven foreign callee (probe-confirmed; the
      error-path returns are already free - error values carry no
      signature); a small audited set of value-plane standard helpers
      (slices.Clone and the clone/sort/collect family) derives its
      result from its carrier arguments, alias-linked like any other
      backing-sharing bind; distinct from chunk 53's
      unaudited-standard-operation named verdicts, which live on a
      different refusal arm.
- [ ] 65. gofresh: argument-position address captures share backing -
      the chunk-62 review's fifth and sixth clause-family members,
      probe-confirmed reproducing before that chunk: an address
      capture rooted at a call (sink(&id(s)[0]) with sink writing
      through the pointer) fires nothing because the capture arm is
      ident-root-only, and a composite literal embedding a tracked
      value hands out reach in argument position (sink(&holder{rows:
      rows}) writing p.rows[0]; return rows composed Valid) where the
      literal exemption is only sound for bind- and return-position
      captures; the fail-closed extension must be position- and
      root-kind-aware - call roots break their reached names, literal
      roots stay fresh where the bind link and returned-literal audit
      cover them but link or break in argument position - a blind
      reroute of the capture arm through the fail-closed break helper
      would spuriously refuse every return &T{field: param}
      constructor.
- [ ] 66. gofresh + consumers: vouched third-party dynamic state -
      field report: any graph carrying go-openapi/strfmt.Default
      (every sigstore/rekor consumer) trips the shared-dynamic-state
      downgrade with no discharge path - the tools cannot prove a
      third-party global init-only, so runtime evidence is
      permanently unverifiable and records never promote to the repo
      layer (a committed findings document stays empty by design);
      the fix direction is a caller-declared vouch - the consumer
      accepts a named third-party package-scope variable as stable,
      the declaration riding config like bracket paths do, the
      verdict recording the vouch so acceptance is auditable, not
      silent; opens with a design discussion (trust boundary: who
      may vouch, where it is declared, how it surfaces in verdicts)
      before implementation.
- [ ] 67. gomutant: attestation anchors on position shift - field
      report: attestations recorded before a later edit shed on
      position shift as designed, but some re-anchored onto
      same-shaped NEIGHBORING mutants (each audited correct in the
      field instance, but the permissiveness is unaudited); an
      attestation's equivalence reasoning is site-specific, so the
      anchor should key enough site content that a same-shaped
      mutant at a different site never inherits it; measure the
      re-anchor rate, tighten the key, and pin the
      no-cross-site-inheritance property.
- [ ] 68. gomutant: property-suite oracle prerequisites - field
      report: rapid-based suites need a pinned seed plus a
      no-failfile setting to be usable oracles at all (unpinned
      property suites are nondeterministic oracles - verdicts
      unreproducible); preflight detects a property-runtime
      dependency in the oracle's graph and states the prerequisite
      (or refuses the oracle as nondeterministic) instead of leaving
      the discovery to the user mid-campaign.
- [ ] 69. gofresh: the parameter break distinguishes shared storage
      from held values - the ninth probe's instrumented trace:
      temporal.NewRegistry is the field chains' sole dead link, and
      it refuses because the fresh containers it builds (groups, g,
      series) join the parameter's alias component through value
      flow (r := range rows; g.versions = append(.., r.Version);
      series[coord] = s), so the parameter-component break treats
      every store into fresh storage as a write into the caller's -
      the accumulate-into-fresh-containers pattern every registry
      constructor uses; the linking gains direction: header-sharing
      binds (whole identifiers, conversions, append target and base,
      slice steps, call results, reach-bearing element reads - the
      landed refusal families, all preserved) stay symmetric storage
      aliases firing the parameter break, while a struct-value copy
      read out of a parameter (range value, field read, element read
      of a value element) records a directional held-reach link -
      top-level slot writes into the holder's own storage join the
      store set without breaking the caller's assumption, and any
      write whose chain crosses a dereference below the root
      fail-closes into the break (the held copy's interior may reach
      the caller's backing); opens with the spec read and the
      two-relation design settled before code.
- [ ] 70. gofresh + stipulator: verdict explanation as a supported
      surface - every refusal this train chased needed the same three
      artifacts, rebuilt twice as throwaway harnesses: the per-package
      fact dump, the composition trace naming the dependency edge that
      failed to resolve, and the per-function refusal trace naming the
      innermost refusing expression with its position; gofresh grows
      an explain entry point (given a package and symbol, the full
      derivation chain from verdict to refusing expression), and
      stipulator passes it through as an MCP verb so "why is this
      witness uncacheable" is one call in the dev hot loop instead of
      a scratch test file; MCP-first per the standing surface
      priority, minimal output, the chain not the prose; opens with a
      design discussion (verb shape, output form, how much of the
      fact vocabulary becomes public surface) before implementation.
- [ ] 71. gomutant: explain for survival and promotion - the same
      capability for the mutation plane: why a mutant survived (which
      oracle, which execution bucket, what the candidate evidence
      was), why a record has not promoted to the repo layer (the
      field report's empty findings.json took a session to diagnose
      from outside); one explain verb over the findings document.
- [ ] 72. pew: explain for attribution - why an attribution verdict
      failed and what changed between recordings, over the recorded
      provenance conjunction; closes the explain family so every
      tool's verdict answers "why" without instrumentation.
- [ ] 59. gofresh: signature-typed handouts judged on the value plane -
      the leak-free judgment consumes a rooted signature-typed result
      as a scalar copy (the reach walk admits no signature), so a
      registered or returned literal handing out a captured method
      value proves environment-free while the value carries a mutable
      receiver (reachable through the init-body registered-literal
      door on HEAD and the constructor door alike); a rooted
      signature-typed handout refuses unless the held value provably
      derives from environment-free sources, and the audit clause's
      capture-leak-freedom definition gains the value plane; overlaps
      the tracked func-value-self-capture family where receiver fields
      hold the closure.
- [ ] 58. gofresh: parameter-forwarding chains across packages - a
      function forwarding its parameter to a foreign callee's
      parameter (NewRETALawRegistry's rows to proposition.New) records
      a conditional leak-free fact naming the foreign parameter it
      depends on, resolved at composition to a fixed point exactly as
      the env-call channel resolves, cycles and absence refusing.
- [ ] 53. gofresh: audited-pure standard-set additions the named
      verdicts justify - source-audit math/big value constructors,
      time.Date, reflect.DeepEqual, and interface-type references of
      the fmt.Stringer shape (the second re-measure's 131 named
      refusals on value constructors and comparators).
- [ ] 54. gofresh: subtest and fuzz drivers on the witness path -
      testing.Run and testing.Fuzz reached by witnesses (176 named
      refusals) are the standard subtest idiom; whether harness-internal
      subtest execution joins the audited-harness admission for the
      maximal scan needs its own design pass.
- [ ] 52. gofresh: init-flow fill precision and cross-carrier aliasing -
      a retention-only parameter fact class admits the synchronous
      init-flow fill through a writing parameter that the leak-free
      deferral conservatively refuses (the single-fact-class
      conservatism the spec records), the same class extends the
      receiver position (a method call on a carrier in an exempt
      region marks nothing today - Registry.Keep() launching a
      goroutine with its receiver composes Valid, while blanket
      receiver deferral would refuse every legitimate init method
      fill), and carrier-to-carrier aliasing (one carrier assigned or
      copied from another in init flow) links the aliased keys so a
      mutation of either refuses both - today the shared backing
      splits across keys unlinked.
- [ ] 16. re-measure the cerebro check against the warm floor (requires
      the machine with cerebro checked out): policy gains
      excluded_paths [".claude"] and bracket_paths for go.mod, cmd, and
      the spec-doc tree; closes stipulator
      docs/issues/cerebro-uncacheable-mass-measured.md (the chunk-5, 7,
      8, and 9 fixes) and the two gofresh docs at their close-outs.
- [x] 17. gofresh: open the startup-effect-precision plan
      (charter gofresh docs/issues/startup-effect-precision.md;
      dotless-module-paths, one-dispatch-site-classifier, and
      runtimeinput-producer-facade ride it per their Lands lines).
- [x] 18. stipulator: incremental witness publication (stipulator
      docs/issues/witness-evidence-published-only-at-run-end.md) — the
      run's drop-path decision moves to witness completion (or a staged
      install-then-confirm), so a dying check keeps every record it
      produced; the degraded path still publishes nothing.
- [x] 19. stipulator + gofresh: bracket digest sharing within a run
      (stipulator docs/issues/cold-check-bracket-digest-amplification.md)
      — one digest of an unchanged bracket tree serves every witness in
      the run, with mid-run mutation of bracketed trees still detected;
      mechanism home (gofresh per-process memo vs run-scoped reuse in
      the witness runner) decided at triage.
- [x] 20. gofresh: memo-store consumer control (gofresh
      docs/issues/memo-store-ownership.md) — consumers gain
      disable/redirect control over the persistent memo store, one
      knob covering both memo classes (unconditional effect scans and
      the view-enabled observability memo).
- [x] 21. gofresh: shared-dynamic-state mutation precision (gofresh
      docs/issues/shared-dynamic-state-any-use-downgrade.md) — the
      any-use marking of alias carriers narrows to demonstrated
      mutation, init-exempt startup state recognizes the harness
      registration tables, and the downgrade's reason string
      distinguishes its channel from signature dynamism; chunk 16's
      re-measure re-runs after this lands (its warm floor is
      unreachable while the downgrade sweeps the corpus).
- [x] 22. gofresh: init-only-reachable registration state (gofresh
      docs/issues/init-only-reachable-registration-state.md) - a
      mutation inside an unexported helper whose every reference is,
      transitively, an initializer expression or init body is init
      flow (user decision: full tool-side precision; the fail-closed
      and workload-directive alternatives declined).
- [x] 23. gofresh: receiver-effect facts (gofresh
      docs/issues/receiver-effect-facts.md) - per-package method facts
      record whether a method writes receiver-reachable state, so a
      pointer-receiver method call on a package-level carrier marks
      mutation only when the method (or anything it hands the receiver
      to) demonstrably writes; unknown methods stay fail-closed
      address captures. Includes generic receivers and the audited
      synchronization set (sync.Mutex/RWMutex lock operations are
      receiver-neutral by source audit - lock state cannot change
      dispatch) per the user's build-all-rungs decision.
- [x] 24. gofresh: returned-alias disposition (gofresh
      docs/issues/returned-alias-disposition.md) - a value returned
      off receiver-reachable state is an alias handout; the discharge
      needs object-closure-style treatment of returned interface and
      alias values (the field registry returns reflect.Type), else the
      read stays fail-closed.
