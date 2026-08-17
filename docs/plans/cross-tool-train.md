# Cross-tool train: overlay cost, run-ephemera classification, gomutant throughput

The active roadmap across gofresh, gomutant, stipulator, and pew. Each
chunk is one commit in its named repo, run through the full adversarial
loop there; gofresh chunks release before consumer chunks bump. WIP = 1.

Chunk numbers are stable identifiers, never order. Execution order
lives in the list below and only there; chartering a new chunk appends
its checkbox but never inserts into the order - insertion is a
deliberate edit of this list, stated in the chartering commit. Incoming
field reports triage into three bands: blocking-a-user (defects
stopping another agent's loop now), current-arc (serves the measured
floor), and tail (ergonomics, refactors). Every deferral slots into a
chunk of this order (user direction 2026-08-15): condition-parked
`Lands:` lines are retired as a practice - new deferrals charter or
fold into a numbered chunk, and the existing condition-parked backlog
re-slots at its sweep chunk.

Execution order (user-confirmed 2026-08-09; explain family pulled
together per user direction same day): 69, 73, then 70, 71, 72 as one
consecutive family - the explain capability is diagnosis
infrastructure for the working loop across all four repos, shared
chain machinery in gofresh, each tool integrating it over its own
verdict domain, every refusal carrying a handle to its derivation
through the surfaces agents already use - then 66, then 81
(blocking-a-user: an oracle OOM burst pins the reporting user's host
during campaigns; 82 rides the tail with 80), then the
discharge tail 56, 56a, 56b, 57, 58, 59, 53, 54, 52, then stipulator ergonomics
74, 75, 76, 77, 78, then 79, 67, 68, 65, then 85 (blocking-a-user,
inserted per the chunk-81 precedent: the undeclared tool-minted
oracle TMPDIR leaves every temp-touching oracle runtime-unverifiable
in a reporting consumer's campaign), then the
startup-effect-precision plan activation decision with 29-46 (80
rides beside 39a - the same oversubscription mechanism, one repo
each; 38a follows that pair, inserted on the field-report band
2026-08-14: the pre-commit consumer loop's persistence trust; 86 and
87 follow 38a, inserted 2026-08-15 - 86 is the
startup-effect-precision activation decision's vehicle carrying the
demonstrated zero-reuse chain, and 87 the backlog re-slot sweep the
same-day deferral doctrine requires; 88 and 90 ride together at the
tail after 46 - the build-dimension pair, one repo each per the
39a/80 precedent - with 89 after them, all three chartered at 87's
sweep), then 16
(floor re-measure and close-outs), then 15 (pew, opens with a user
design discussion). The startup-effect-precision plan ACTIVATED
2026-08-15 at chunk 86 (in-authority: its charter names the startup
tier as the field corpus's binding constraint, and the demonstrated
zero-reuse observability chain - chunk 86's doc - is stronger
activating evidence than the chartering histogram); its open chunks
execute interleaved with this order's remaining block, WIP=1 across
both plans.

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
- [x] 29. gofresh: maximal-tier reason ranking conforms to the shared
      order (gofresh docs/issues/maximal-tier-reason-ranking.md) - rank
      plumbing replaces the per-file stratum switch and the two-class
      package fold, the shared rank table's packagePath branch is
      fixed, and the unrefinable-class interaction is settled;
      display-only (verdicts unchanged), so it rides after the
      re-measure.
- [x] 30. gomutant: consumer-surface bounds and visibility (gomutant
      docs/issues: findings-output-unbounded,
      changed-mode-oracle-delta-routing, attest-and-promotion-visibility,
      plan-and-progress-cosmetics) - bounded findings summary by
      default with detail opt-in, capped reason lists, the residue
      row's re-measure signpost, attest echoing disposition and layer,
      the promotion-commit warning, and the two progress cosmetics;
      the four docs delete at close.
- [x] 31. gomutant: record correctness and lifecycle (gomutant
      docs/issues: detached-record-lifecycle, fresh-stamp-manifest-base,
      growth-drift-promotion-untested) - prune and retarget verbs with
      attestations carried by survivor identity, terminal labeling of
      resolved-dead records, per-subject manifest bases for the fresh
      stamp and Committable, and the growth/drift promotion-shape
      pins; the three docs delete at close.
- [x] 32. gofresh: init-flow audit completion (gofresh docs/issues:
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
- [x] 33. gofresh: open-world dynamic edges named and refined - the
      field report's biggest cost (caller-supplied dynamic triggered
      by dependency interface dispatch wipes caching for yaml-heavy
      packages, ~25 minutes per run over 929 candidates) with no call
      edge named in the reason; the naming half follows the chunk-27
      pattern, the refinement half narrows the open-world rule over
      proven dependency dispatch.
- [x] 34. gofresh: startup-walk soundness pair (gofresh docs/issues:
      dotless-module-paths-classified-standard,
      func-value-self-capture) - a dotless module path silently
      disables the whole startup walk, and receiver-stored closures
      launder receiver writes through read-only proofs; both docs
      delete at close.
- [x] 35. gofresh: verdict precision and validation cost (gofresh
      docs/issues: enumeration-targets-over-approximated,
      validation-manifest-evaluation-unshared,
      fresh-mutation-in-module-scratch) - dispatch target sets stop
      dragging initializer content into siblings and producer
      validation shares manifest evaluation; two docs delete at close,
      and the in-module scratch widening redefers on a
      field-measurement trigger - feasible and sound in principle,
      zero measured mass, no consumer the flow discipline admits
      (closed at chunk 16 on that measurement; doc deleted,
      git-history only).
- [x] 36. gofresh: analysis-surface structure (gofresh docs/issues:
      one-dispatch-site-classifier, observation-facts-struct) - one
      call-site judgment and one observation-facts shape, collapsing
      the five partial classifier copies and the three hand-built View
      literals; two docs delete at close.
- [x] 37. cross-tool: runtimeinput producer facade (gofresh
      docs/issues/runtimeinput-producer-facade, gomutant
      docs/issues/oracle-scratch-namespaces) - one facade for the
      completed-observation conjunction across stipulator, gomutant,
      and pew, carrying the scratch-namespace declaration surface that
      stops union-equality churn; both docs delete at close.
- [x] 38. gomutant: hot-loop committable evidence (gomutant
      docs/issues: staged-snapshot-run-mode, env-input-oracle-policy,
      runtime-input-provenance) - staged-index measurement collapses
      the attest-promote-commit trail, the reviewed exemption record
      unblocks the repo-root idiom, and producer-output provenance
      stops re-measures the evidence already covers; three docs delete
      at close.
- [x] 39a. gomutant: oracle-process CPU oversubscription - concurrent
      mutant jobs each spawn full-width go toolchain children
      (jobs x NumCPU runnable threads, quadratic in cores at the
      default), starving the host; cap inner parallelism at the spawn
      sites (GOMAXPROCS and -p at max(1, NumCPU/jobs) in the oracle
      env) and run oracle processes at low scheduling priority; the
      jobs default stands.
- [x] 38a. gomutant: the pre-commit consumer loop's findings persist
      (gomutant docs/issues: campaign-persists-zero-findings-on-dirty-trees,
      campaign-lock-sits-beside-tracked-document) - field report
      (ocifs): four dirty-tree campaigns completed with real measured
      counts yet the repo document stayed empty at every version it
      ever carried and every summary said 0 cached; verify the
      chunk-38 staged line end-to-end against a pinned pre-commit
      consumer loop (persistence plus later-run reuse), diagnose the
      machine-local overlay's zero run-to-run reuse on the field
      shape, make non-persistence loud (an empty repo document after a
      measuring campaign states its cause in the summary), grow the
      version surface the field report lacked (--version/version), and
      stop the by-design .campaign lock from landing in consumer
      commits (tool-minted ignore beside the tracked document plus the
      lifecycle line in consumer docs); both docs delete at close.
- [x] 39. gomutant: campaign robustness and cost (gomutant
      docs/issues: decision-build-locality,
      ephemeral-replacement-outside-oracle-closure,
      post-completion-cpu-tail) - one broken target stops aborting the
      campaign, out-of-closure overlays stop reading as survivors, and
      the post-completion spin is profiled and closed; three docs
      delete at close.
- [x] 40. gomutant: init bodies as measured subjects (gomutant
      docs/issues/init-functions-as-subjects) - the classic
      silent-fault carrier becomes measurable end-to-end; doc deletes
      at close.
- [x] 41. cross-tool: the MCP surface contract (gomutant
      docs/issues/mcp-long-running-runs, stipulator
      docs/issues/mcp-progress-not-observed; folded 2026-08-14:
      gomutant docs/issues/mcp-server-refuses-newer-cli-document -
      a version-ahead refusal names its probable cause and the
      restart/upgrade signal instead of a bare range error - and
      gomutant docs/issues/killed-mutant-oracle-scratch-residue -
      the consumer-hygiene paragraph rides the audited consumer
      surfaces) - the standing principle
      lands in both MCP specs: the MCP surface outranks the CLI and
      serves an LLM in a harness - minimal output, maximal usefulness;
      both surfaces audited against it, cancellation propagation and
      live progress included; the resolving docs delete at close.
- [x] 42. stipulator: correctness batch (stipulator docs/issues:
      term-matcher-ascii-boundaries, partitions-uncapped-seam-unpinned,
      scope-prefix-boundary-semantics, witness-store-gc,
      gopter-property-recognition) - rune-boundary term matching, the
      seam pin, boundary-aware scoping with the dropped-diagnostic
      fix, store eviction for departed identities, and gopter witness
      classification; five docs delete at close.
- [x] 43. stipulator: publication ladder collapse (stipulator
      docs/issues/publication-ladder-collapse) - one publication
      ladder, one closing validation; doc deletes at close.
- [x] 44. pew: trust, cost, and the derivation loop (pew docs/issues:
      recorded-config-trust, per-benchmark-view-builds,
      derivation-ab-mode) - read-side recording validation, per-package
      view sharing, and pew ab replacing the hand stash cycle; three
      docs delete at close.
- [x] 45. stipulator: slice frontier soundness (stipulator
      docs/issues/slice-frontier-uncertainty) - typed frontiers gain
      the closure model's sound floor and dispositions over
      reflection, build tags, and init effects; doc deletes at close.
- [x] 46. stipulator: witness fingerprints bind closure content to the
      consuming compile (stipulator
      docs/issues/closure-edit-revert-inside-run-span) - the
      edit-revert-inside-span residual closes with the record
      redesign; doc deletes at close. Also folds: dedup the facts
      context path's double slice (Slice then SliceFloor re-slicing
      internally) behind one shared frontier; retire the unconditional
      "_test" path trims in ReachedPackages and splitSymbol
      (misfold/no-resolve for a real package path ending "_test") in
      favor of the floor walk's build-identity fold.
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
- [x] 56. gofresh: registered-population parameter proof for func-field
      calls - a carrier field passed as an argument to a call through
      a func-valued field of the same leak-free binding (the
      near-match loop's class.near(header, class.columns)) defers to
      the field position's registered population: every value the
      environment audit admits into that field must prove the
      parameter leak-free (named functions by their persisted
      parameter facts, audited literals judged at registration,
      constructor results through the return-env-free channel), any
      unproven registrant keeping the escape.
- [x] 56a. gofresh: composition-refused deferrals earn explain chains -
      ExplainDynamicState returns an empty chain for any culprit whose
      escape is decided at composition rather than fact time (a
      deferred argument mark whose parameter never proves, a deferred
      method use, a field-position population refusal): the fact-time
      hooks observe only immediate marks, so the re-derivation sees a
      discharged read where the verdict saw a refused deferral.
      Surface the deferral's use site and the unproven resolvent
      (parameter key, method key, or registrant) as chain links across
      all three deferral channels, within the explain vocabulary.
- [x] 56b. gofresh: explain chain arm parity with the verdict ranking -
      a variable with direct escape sites plus an unproven method
      deferral chains as escape while the verdict reason says mutated
      (the verdict ranks mutation first); merge sites and unresolved
      deferrals into one chain whose arm and link order follow the
      verdict's ranking. Vouch-discharged variables keep deriving
      their chains by explicit contract (REQ-vouch-recorded: the vouch
      suppresses the verdict's downgrade, never the derivation a
      caller audits) - the originally chartered no-chain gate
      contradicted that sentence and was reversed in review.
- [x] 57. gofresh: carrier index extraction admissions - a comma-ok
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
- [x] 65. gofresh: argument-position address captures share backing -
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
- [x] 66. gofresh + consumers: vouched third-party dynamic state -
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
- [x] 67. gomutant: attestation anchors on position shift - field
      report: attestations recorded before a later edit shed on
      position shift as designed, but some re-anchored onto
      same-shaped NEIGHBORING mutants (each audited correct in the
      field instance, but the permissiveness is unaudited); an
      attestation's equivalence reasoning is site-specific, so the
      anchor should key enough site content that a same-shaped
      mutant at a different site never inherits it; measure the
      re-anchor rate, tighten the key, and pin the
      no-cross-site-inheritance property.
- [x] 68. gomutant: property-suite oracle prerequisites - field
      report: rapid-based suites need a pinned seed plus a
      no-failfile setting to be usable oracles at all (unpinned
      property suites are nondeterministic oracles - verdicts
      unreproducible); preflight detects a property-runtime
      dependency in the oracle's graph and states the prerequisite
      (or refuses the oracle as nondeterministic) instead of leaving
      the discovery to the user mid-campaign.
- [x] 69. gofresh: the parameter break distinguishes shared storage
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
- [x] 70. gofresh + stipulator: verdict explanation as a supported
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
- [x] 71. gomutant: explain for survival and promotion - the same
      capability for the mutation plane: why a mutant survived (which
      oracle, which execution bucket, what the candidate evidence
      was), why a record has not promoted to the repo layer (the
      field report's empty findings.json took a session to diagnose
      from outside); one explain verb over the findings document.
- [x] 72. pew: explain for attribution - why an attribution verdict
      failed and what changed between recordings, over the recorded
      provenance conjunction; closes the explain family so every
      tool's verdict answers "why" without instrumentation.
- [x] 73. stipulator: read_spec delivers content over MCP - field
      report (cerebro coverage program): the tool result carries only
      {"bytes": N} through the Claude Code MCP client on every call,
      so the loop that is supposed to orient from requirement text
      falls back to grepping spec files; the no-resource-support
      mirror path must deliver the bundle body in the tool result.
- [x] 74. stipulator: witness-classification verdicts name their
      reason - a bound property test classified as an executed
      example (rapid.Check invoked in a helper, not the bound body)
      reads the generic "needs a property witness or analyzer proof";
      the row names the classification verdict per bound witness -
      "bound witness X classified executed-example: rapid.Check not
      invoked in the bound body" - the field session lost two full
      fix rounds to the trial-and-error discovery.
- [x] 75. stipulator: check ids scopes execution, not just display -
      ids=... still executes the full witness set (2-5 minutes,
      always past the 120s MCP window); a genuinely scoped fast mode
      compiles and covers the named ids only, the verdict flagged
      partial; transforms the bind-check inner loop.
- [x] 76. stipulator: prune does deletion work only - deleting nine
      resolved gap files runs what appears to be a full
      compile/witness pass (>120s); resolved-record deletion should
      be near-instant, and whatever work genuinely must run must be
      named in the phase report.
- [x] 77. stipulator: gap triage gains a read surface - gapsDue
      counts appear in check output but nothing names which gaps are
      due; gap list (id, reason, condition, fired, due) plus
      documenting re-declare as the only edit path.
- [x] 78. stipulator: check summary output diet - view=summary still
      carries the full reds list and the whole uncacheableReasonCounts
      histogram every call; cap reds harder, make the histogram
      opt-in, and add the actionable form - top blockers by witness
      count, one exemplar test each.
- [x] 79. gomutant: ephemeral kill evidence - the verdict returns
      killer name but no test output, forcing a parallel go test
      -overlay re-run per review round (which also litters rapid
      .fail reproduction files agents must clean); return the killing
      test's first ~20 output lines, add runs:N with per-run verdicts
      (property-test killers need "killed N consecutive runs" to
      split deterministic kills from draw luck - the distinction
      caught a real defect in the field), and name oracle_timeout_sec
      in the timeout error.
- [x] 80. stipulator: witness-process CPU oversubscription - field
      report (user, interactive check): the witness spawn bound caps
      package units (witness_concurrency, else GOMAXPROCS/2) but each
      unit is a full-width process tree (go test internal t.Parallel
      at GOMAXPROCS plus build workers), so the product overcommits
      the host exactly like gomutant's 39a; cap inner parallelism at
      the spawn sites (-parallel / GOMAXPROCS in the child env at
      max(1, NumCPU/units)) so units x per-child width stays at most
      the processor count; the unit bound's semantics stand.
- [x] 81. gomutant: oracle memory ceiling - field report (user; the
      host pinned): a runaway-allocation mutant (statement-delete of a
      loop advance in a tree walk that appends per iteration)
      allocates freely inside the oracle's 60s window - the kernel OOM
      killer fired on two mutated test processes at ~30GB anon RSS
      each (journalctl: anon-rss:29303072kB); the verdict records
      correctly as a kill ("panicked before observation finalization"
      evidence), but each event drains RAM, pushes the host into swap,
      and can take down other tooling - the most plausible cause of an
      earlier harness crash. Run each oracle under a resource ceiling:
      GOMEMLIMIT to keep the runtime honest plus a hard cap (cgroup
      memory.max or rlimit), defaulting near RAM/(2 x jobs) and
      configurable; classify a cap-kill exactly as the OOM-kill
      classifies today (kill, runaway-allocation cause) - a host-wide
      pressure event becomes a contained per-mutant verdict. Measured
      non-causes stated in the report and honored at triage: gomutant's
      own process is stable (310-430MB), linker bursts are inherent,
      /tmp build dirs clean promptly, orphaned MCP servers are small.
- [ ] 82. stipulator: capture-group key joiner hardening - review
      finding (adjacent, pre-existing): the group key joins tags, env,
      exclusions, and now vouches with control-byte separators
      (\x00-\x05), and a legal env VALUE containing a separator byte
      can collide two differently-configured invocations into one
      capture group (vouch and exclusion entries now refuse control
      bytes at acceptance; env values legitimately may contain them, so
      refusal is not available there); replace the concatenation with a
      collision-free encoding (length-prefixed or escaped components)
      without changing any collision-free key's identity semantics -
      existing evidence keyed by test identity is unaffected.
- [x] 59. gofresh: signature-typed handouts judged on the value plane -
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
- [x] 58. gofresh: parameter-forwarding chains across packages - a
      function forwarding its parameter to a foreign callee's
      parameter (NewRETALawRegistry's rows to proposition.New) records
      a conditional leak-free fact naming the foreign parameter it
      depends on, resolved at composition to a fixed point exactly as
      the env-call channel resolves, cycles and absence refusing.
- [x] 53. gofresh: audited-pure standard-set additions the named
      verdicts justify - source-audit math/big value constructors,
      time.Date, reflect.DeepEqual, and interface-type references of
      the fmt.Stringer shape (the second re-measure's 131 named
      refusals on value constructors and comparators).
- [x] 54. gofresh: subtest and fuzz drivers on the witness path -
      testing.Run and testing.Fuzz reached by witnesses (176 named
      refusals) are the standard subtest idiom; whether harness-internal
      subtest execution joins the audited-harness admission for the
      maximal scan needs its own design pass.
- [x] 52. gofresh: init-flow fill precision and cross-carrier aliasing -
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
- [x] 16. re-measure the cerebro check against the warm floor (requires
      the machine with cerebro checked out): policy gains
      excluded_paths [".claude"] and bracket_paths for go.mod, cmd, and
      the spec-doc tree; closes stipulator
      docs/issues/cerebro-uncacheable-mass-measured.md (the chunk-5, 7,
      8, and 9 fixes) and the two gofresh docs at their close-outs.
      Also carried the tugboat measurement leg: the exclusion-ordering
      fix (gofresh v0.71.1), reviewed exclusions ("/", somaxconn, the
      sim-bubble roots, .realseam-tmp) and the source-audited vouch
      set landed and every addressed class discharges (tugboat
      728a186); the majority-serve verification MOVED off this chunk -
      the measurement disproved its premise, the residual being
      in-tree dynamic state (ErrCompacted 713, coldBufPool 129,
      frameAccounting 74, ErrSealed 20 - 96% of the corpus) outside
      this train's scope plus the chunk-101 discharge families -
      re-verified when 101 (and the in-tree sentinel/pool line) land:
      a tugboat warm-tree check serves a nonzero witness majority.
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
- [ ] 83. gofresh: callee-argument insertions join the population -
      the chunk-65 review's seventh and eighth clause-family members,
      both reproducing before that chunk: a bind-then-pass capture
      (p := &holder{rows: rows}; sink(p); return rows, sink writing
      p.rows[0]) composes Valid because the plain-named-callee
      dependency edge proves return-position environment-freedom only
      - a callee with no returns resolves vacuously and its writes
      into argument storage are recorded nowhere (the no-address
      spelling sink2(s) with sink2 writing q[0] is the same root);
      and Go's elided address-of in pointer-element composite
      literals (sink([]*holder{{rows: rows}})) carries no UnaryExpr,
      so both the capture arm and the argument-literal walk miss it.
      The spec already demands the mechanism (closure.md: callees
      handed a tracked binding join their own recorded populations
      over the proof's dependency edges) - the edge must carry
      argument-storage insertions, not only return-position freedom,
      and literal detection must include the elided spelling; the
      admission legs (returned literal constructor, bind-position
      literal without a callee) must stay admissible.
- [x] 86. gofresh: oracle-serving observability precision (gofresh
      docs/issues/observability-package-scan-blocks-oracle-serving.md)
      - the demonstrated ocifs zero-reuse chain: the package-scan
      refusal breadth (unsafe.Pointer anywhere in scope) blocks the
      observed-discharge gate for every non-pure oracle in real
      dependency graphs, so consumer evidence never serves; opens with
      the startup-effect-precision plan's activation decision, this
      chain as the activating evidence, and the design pass over the
      precision ladder versus an observability-assertion surface; the
      doc deletes at close.
- [x] 87. cross-tool: deferral backlog re-slot - walk every
      condition-parked issue doc across gofresh, gomutant, stipulator,
      and pew and slot each into a numbered chunk of this order
      (fold, charter, or close-as-obsolete; the 2026-08-15 deferral
      doctrine's sweep); no condition-parked Lands survives the pass.
- [x] 88. gomutant: build-selection oracles (gomutant
      docs/issues/build-selection-oracles.md) - tag-gated and
      toolchain'd oracles become visible end to end: per-selection
      oracle views mirroring stipulator's build-selection resolution,
      the capability boundary the chunk-84 audit recorded; doc deletes
      at close.
- [x] 89. gomutant: mutation-class extensions (gomutant docs/issues:
      structural-mutation-class, integration-mutation-recipes) -
      structural mutants for analyzer-shaped oracles and recipe-shaped
      classes for generator drift, parser guards, and resolver seams;
      both docs delete at close.
- [ ] 91. gomutant: deferred-check-close adoption - the run-end and
      per-window producer validations run full in-process gofresh
      analysis (the chunk-39-diagnosed CPU tail; its visibility half -
      the CLI analysis heartbeat and the pprof handle - landed there);
      gofresh's deferred-close contract is stipulator's closing-cost
      lever, and gomutant's serve path needs the closing-validate
      discipline before adopting it - a design pass, then the
      adoption; ordered after 90; history: `git log --all --
      docs/issues/post-completion-cpu-tail.md` (gomutant - cost-center
      evidence: ~25% of in-process CPU under repeated packages.Load,
      GC a third of samples).
- [ ] 92. gomutant: fold the decision batch (maximal captures) and the
      observed proof union - two back-to-back full observation passes
      over the identical symbol set with the same engines; one
      observed union view set serving both roles halves the warm
      campaign's observation floor. Decision-failure locality already
      landed (39), so the fold is now a pure consolidation; it also
      dispositions the strict/union view-build-loop duplication in
      gomutant freshness.go (the back halves of the two constructors,
      parallel except fault routing). Ordered after 91; history:
      `git log --all -- docs/issues/decision-build-locality.md`
      (gomutant).
- [ ] 93. cross-tool: parenthesized-receiver naming grammar - the
      shared receiver-naming convention (gofresh recvTypeName,
      gomutant's twin, stipulator's Go backend) cannot reduce the
      legal parenthesized receiver form, so such methods are
      unnameable everywhere; gofresh's purity scan additionally minted
      them as plain-function subjects (misattribution risk, loud in
      practice via known/root mismatch). Extend the grammar with the
      ParenExpr unwrap in all three tools in lockstep, or record the
      unnameable form as contract; surfaced by chunk 40's review.
      Ordered after 92.
- [ ] 94. gomutant: line-directive position hazards - pre-existing
      sites read //line-adjusted positions where on-disk identity is
      meant: the _test.go suffix gates (enumerate, surface), the
      candidate catalog's source read (catalog.go fileOf +
      os.ReadFile - measuring ANY target in a //line file fails
      ENOENT on HEAD) and the survivor position anchors minted from
      adjusted names (candidate_edit.go); a //line directive can
      misclassify a file, fail a measurement, or mis-anchor a
      disposition. The init identity, the source-byte read
      (sourceOfContext), and the changed-surface path key landed
      immune in chunk 40 - each pulled forward when the chunk's own
      directive fixture demonstrated its failing path. Audit and
      convert the remaining sites, with directive fixtures. Surfaced
      by chunk 40's review; ordered after 93.
- [ ] 95. gomutant: MCP Tasks adoption - protocol-level operation
      identity, polling, result retrieval after a client deadline, and
      explicit cancellation for long-running runs (the
      mcp-long-running-runs residue; dead-transport detection landed
      long ago). Opens by re-auditing the prerequisites that block it
      at chunk-41 time: the io.modelcontextprotocol/tasks extension
      (SEP-2663) stable in go-sdk (v1.6.1 in use; tasks landed v1.7.0
      beta) AND a consuming agent client that speaks it - neither held
      at charter time; history: `git log --all --
      docs/issues/mcp-long-running-runs.md` (gomutant). Ordered last.
- [ ] 96. gomutant: concurrent ephemeral probe overrides - two
      concurrent probes' width/ceiling snapshot-restores can
      interleave (bounded, self-healing: results never persist, the
      next install resets; the probe-vs-campaign window closed at 41).
      Either the probe claim goes exclusive (serializing concurrent
      probes - a surface-semantics call) or the interleaving is
      recorded as accepted; surfaced by chunk 41's review. Ordered
      after 95.
- [ ] 98. gofresh: stateless-value escape discharge - a package-level
      variable whose initializer is a zero-field struct value cannot be
      observably mutated through any escaped alias (no state to
      mutate; rebinding stays the mutation arm's), so its
      writable-escape refusal proves nothing and discharges;
      reproduced from the field: tugboat's raft.DiscardLogger
      (var L Logger = nopLogger{}) accounted for 285 of 967 uncacheable
      witnesses, the largest in-tree dynamic-state class - discharged
      in-tree meanwhile (tugboat 8968554 makes it a concrete-typed
      var), so the chunk's justification re-bases at triage on
      whatever zero-field-value mass the then-current measure shows;
      zero measured mass closes the chunk unbuilt. Release,
      then the consumer bumps ride.
- [ ] 97. stipulator: cross-platform resolution views - a selection
      declaring GOOS/GOARCH off the host today refuses by name (chunk
      90's boundary); the design question is an on-host resolution-only
      view for cross-platform selections whose witnesses no on-host run
      can grant - what binding/witnessing means there is the chunk's
      charter question.
- [ ] 99. gofresh: guarded deterministic memoization discharge - a
      package-level cache mutated only through a get-or-compute idiom
      (every write path checks-then-fills under a guard: mutex,
      sync.Once, or sync.Map), whose fill derives the value from the
      key alone through functions the env-free proof machinery already
      proves, and from which no cross-key observable escapes (no
      iteration, no len, no deletion, no rebinding, no writable alias
      of keys or values) is observationally warm/cold-equivalent: no
      admitted observation can distinguish a populated cache from an
      empty one, so its mutated-dynamic-state refusal proves nothing
      and discharges structurally. The proof rides the existing fact
      derivation, which already spans module-cache dependency packages
      (the field class is third-party: pgregory.net/rapid's
      charClassGens/compiledRegexps/regexpNames/expandedTables memo
      maps, vouched at chunk 16 as the interim); close-out trims the
      then-redundant rapid vouches from the tugboat policy and
      re-measures. The idiom is a pattern with an adversarial
      complement - a fill pure but unprovably so stays a vouch - so
      the chunk narrows the vouch surface, never claims to empty it.
      Sequenced after 98 (same discharge family; 98's is the larger
      measured mass). Release, then the consumer bumps ride.
- [ ] 100. gofresh: in-module scratch discharge - reads of a
      module-interior directory the test itself mints, writes, and
      removes (self-generated feedback, no environment input) classify
      as runtime inputs no bracket can cover and seal the observation;
      the chunk-35 close of this widening rested on "zero measured
      mass in either corpus", and the chunk-16 exclusion-ordering fix
      unmasked that the mass was hidden behind the "/" refusal all
      along: tugboat's .realseam-tmp WAL smoke tier is 129 of 972
      witnesses (excluded at chunk 16 as the interim caller
      assertion). Design reasoning recoverable via
      git log --all -- docs/issues/fresh-mutation-in-module-scratch.md;
      triage re-derives against the then-current measure. Release,
      then the consumer bumps ride.
- [ ] 101. gofresh: audited-construction discharge reaches carrier
      stores, and errors.New joins the audited set - storing an
      audited-construction carrier (a reflect.TypeOf constant) into a
      struct field marks the SOURCE package variable "is mutated" even
      though the store copies the interface value and no write through
      the copy can reach the shared object (reproduced: a yaml.v3-shaped
      fixture fires the mutation arm at the composite-literal store
      with the field never written and differently named; the plain
      var-binding shape discharges) - the discharge must consult the
      same audited-construction proof on the mutation arm's
      store/capture shapes it already consults on bindings and
      escapes. Same family: var Err = errors.New("...") sentinels
      (never assigned, pointee unexported and unwritable from outside
      the errors package) refuse as "escapes writable"/"is mutated" -
      tugboat's ErrCompacted/ErrSealed class - and errors.New is as
      auditable a construction as reflect.TypeOf. Field mass at
      chunk 16: yaml.v3's seven type constants (15 witnesses, vouched
      as the interim) and the in-tree sentinel classes. Coordinates
      with the audited-pooling-set owner's line of work before
      touching the discharge. Release, then the consumer bumps ride.
- [x] 90. stipulator: goos/race build dimensions bind (stipulator
      docs/issues/goos-race-build-dimensions.md) - the resolution-view
      identity extends past the tags/toolchain pair to the
      GOOS/GOARCH/race dimensions, symmetric with discovery; rides
      beside 88 as the build-dimension pair; doc deletes at close.
      Also folds: the witness capture-group key's missing
      build-selection dimensions (module mode, PGO profile, extra
      binary arguments) - two invocations differing only there share
      one analysis view today.
- [x] 84. stipulator: build-tagged symbols bind (stipulator
      docs/issues/build-tagged-symbol-binding.md) - binding-side
      resolution loads one package view per distinct build selection
      in the accepted policy (execution discovery is already
      tag-aware; Resolve is not), so tag-gated tests - the dst leg's
      witnesses - resolve, shape-hash, and bind; witness evidence
      keys to the declaring view so tag-gated edits invalidate the
      right witnesses. Consumers: tugboat REQ-node-support-stability's
      dst-schedule witness gap, and tugboat lifecycle chunk 12's four
      invariant gaps whose property-class enforcement is DST arms -
      the field deadline: lands before that chunk's close-out.
- [x] 85. gomutant: tool-minted oracle TMPDIR declared at ingest
      (gomutant docs/issues/oracle-ephemeral-root-undeclared.md) -
      field report, blocking-a-user band: oracleScratch mints one
      out-of-module TMPDIR per oracle process tree but ingest never
      declares it, so every testing.TempDir-touching oracle is
      runtime-unverifiable - survivors bucket unstable-oracle instead
      of triageable buckets and records never reuse (719 of ~1400
      candidates' survivors unbucketed in the reporting campaign);
      one seam: thread the minted root to processObservationContext
      as runtimeinput.WithEphemeralTempRoot, which the root satisfies
      by construction; rides with a named decision-line reason for
      mutant-written tree drift; the doc deletes at close. Appended
      unordered - execution-order insertion is the user's call
      (chunk-81 precedent pulls blocking-a-user forward).
