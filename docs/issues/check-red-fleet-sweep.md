# stipulator check red: three requirements uncovered (fleet sweep 2026-10-12)

The weekly fleet sweep's `stipulator check` over this repo fails: 59
red rows, three of them violations no gap excuses —

- REQ-fresh-evidence-support — needs a property witness or analyzer
  proof (invariant) (+1 more);
- REQ-inputs-outcome-method — bound witness
  `TestOutcomeSupportBindsActualExecutionAndRecordedSubject`
  classified example: no property driver or analyzer call in the
  bound body (+3 more);
- REQ-inputs-producer-premises — needs a property witness or analyzer
  proof (invariant) (+1 more).

The other 56 rows are excused uncovered rows of the pass class
(example-classified witnesses on property clauses, and invariant
clauses awaiting their proof) and are not this doc's. The previous
measured verdict (2026-09-28: 45 rows, violations on
REQ-fresh-fingerprint-data, REQ-fresh-observation-data and
REQ-guard-buildconfig) has cleared — those three now read excused —
and the 2026-10-05 run was NOT MEASURED, so these three violations
are new since 09-28. They are the requirements the train's sixth
re-audit relayed to the evidence-model owner on 2026-10-07: the
consumer specs still claim a completed observation built the old way
(REQ-inputs-producer-premises / REQ-inputs-outcome-method), and the
assertion lane REQ-inputs-outcome-method and REQ-fresh-evidence-support
govern holds behind the active plan's outcome capability — so the
reds are evidence-class obligations the active sequence already
schedules, not a regression in a landed witness. Undiagnosed beyond
that mapping; this doc records the fact.

Scanned: the index and all 50 docs it lists. None tracks the check or
names the three requirements (entropy-reach-through-tls-handshakes
mentions a check verdict as its reporting channel only). The
2026-09-28 check-red doc closed at chunk 281 and is gone. Rows
disjoint; no scheduled trigger duplicated.

Lands: tooling-redesign 4.4 — the chunk that binds the generated
producer-premise witness as REQ-inputs-producer-premises' required
evidence class; REQ-fresh-evidence-support's and
REQ-inputs-outcome-method's property-class evidence ride 4.2's
evidence selection under the declared model and 4.3's released
outcome capability ahead of it, the same release cluster. The sweep's
next gofresh verdict reading `pass` closes it.
