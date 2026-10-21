# Claim-directed implementation evidence

## Governing proposition

Gofresh judges applicability of a recorded result under its declared model. The
result owner supplies the actual execution, outcome, contributing population and
exclusion-span facts under the existing assertion rules. Gofresh establishes the
selection, implementation and dependency properties on which its reuse judgment
depends. It does not independently prove that a test passed or predict its next
execution. These boundaries come from [evidence](../specs/evidence.md), especially
result-model, authority-account, unit-binding and historical-implementation rules.

Removing an approval mapping replaces its behavioral authority with checked
reasoning over selected inputs. It does not require one particular proof method.
The [implementation contract](../specs/implementation-verification.md) permits
compositional claims, checked invariants and claim-specific exclusion. Complete
execution reconstruction is appropriate only when the consuming proposition needs
that relation. Finite progress, exact returned values, source/native equality and
complete operation-outcome relations are different claims, not default
prerequisites for every effect bound.

The decision is the conjunction of final native applicability and the consumer's
own result conditions. Native applicability combines established producing
support, complete dependency/guard agreement, compatible proof premises and
successful closing. Neither side supplies a missing fact on the other side.
In particular, historical applicability is not a theorem that a fresh execution
will produce the same verdict.

## Evidence boundary

The architecture separates the following responsibilities:

| Responsibility | Authority and owner |
|---|---|
| Selected source, build and artifact inputs | Immutable coherent observations, with their complete selection dependencies |
| Conservative implementation blockers | Facts about what the base analysis has not established; independent of a later unit's evidence |
| Value, dependence, frame, callback and coverage properties | Independently checked claims with explicit scope, premises and dependencies |
| Applicability of those claims at a use | Checked argument, alias, context, selected-instance and phase associations |
| Actual execution, result and population | Existing executor/consumer responsibility; not inferred from package PASS or an empty capture |
| Evidence selection and closing | Unit-local admission over immutable facts; independent for siblings and retries |
| Historical reuse | Sufficient retained proof inputs and reasoning plus current dependency, rule, premise and guard agreement |

A consumer's execution assertion supplies no unproved native frame, runtime
isolation, compiler substitution or input-dependence property. Conversely, a
checked implementation theorem supplies no receipt that a particular process or
callback actually ran. If a derivation consumes a subject-terminal fact, that
fact must have its own established binding; process normality includes failing
tests and is not that fact.

Base identity must not become evidence-dependent mutable state. Artifact analysis
can refine a unit's disposition without rewriting its shared snapshot or a
sibling's obligations. Closing revalidates the base dependencies and the selected
claims, rather than comparing a refined classification against a newly computed
unrefined classification. Observation obligations are selected over the actual
runnable roster. Source-supported subjects do not acquire observation assertions
merely because the implementation proof uses an inspected artifact.

Owning a selected generation does not require retaining every SSA program for
the lifetime of every record. Proof acquisition must use that generation's owned
inputs; durable evidence retains the immutable inputs and reasoning it needs,
not mutable analysis handles. Representation sharing changes cost, never premise
ownership or another unit's admission.

The maximal scan retains classifications over the whole selected test-binary
source scope. Equal classifications at several sites may share one obligation:
discharge must then cover or exclude **all** matching origins and occurrences.
Referenced package/symbol coordinates locate candidates, not exact call sites or
proof coverage. This grouped scope avoids duplicating the selected-source
checker's occurrence association. Consumer-tier openness, shared-state,
ambiguous-identity and externality obligations remain independent of the maximal
effects and of which diagnostic is displayed. A budget cut in shared-state
analysis does not neutralize the other obligations.

Retained typed inputs mean inputs actually captured in the generation. An
ordinary scan memo can avoid loading entirely; a roots-only load can lack a
dependency body. Neither case supplies those missing proof inputs. A concrete
implementation acquisition must establish its required input coverage and
generation association before accepting claims, on cold and warm paths alike.
Retaining a load alone establishes no selected assembly-action ownership, complete
source/native binding or safe concurrent use of mutable analysis state.

## Proof demand and composition

Start from the public judgment and identify the smallest property needed to
discharge each blocker. Each requested property must identify its actual consumer,
scope, available evidence and missing premises. Expand a callee only to establish
one of those premises. This is an obligation structure, not a new general-purpose
proof-graph platform or a second execution API.

A checked summary may abstract values which its consumer does not need. Its frame
still accounts for relevant reads, writes, aliases, escapes, callbacks,
exceptional control and interference. The checker establishes invariant
initiation/preservation and call-site applicability from selected inputs; a
summary name or matching digest supplies no semantics. Recursion can use checked
induction rather than repeated unfolding. Safety reasoning need not establish
termination. A normal-return postcondition cannot supply effects before failure
or a complete outcome relation.

Existing scalar, source-region, activation, assembly and native checkers remain
possible producers of such evidence. Their conditional conclusions are retained
as conditional; combining them does not erase open premises. A finite activation
interpreter is useful for genuinely finite constructions, but is not the required
representation of every runtime protocol. A complete-cut native checker must not
be used to demand bounded progress from an operation whose relevant contract is
only preservation under possible suspension.

The difficult boundary is actual runtime ownership and integrity. For example,
an irrelevant returned clock value does not prove that its implementation cannot
modify protected state. An unknown string from stack inspection does not establish
a read-only frame. Runtime-private storage, valid switched stacks and absence of
callbacks must be established where consumed; they cannot be introduced as named
axioms. Changing from replay to invariant checking relocates these obligations,
not removes them.

## Producing and historical scope

Evidence is admitted for the exact producing scope. Selected replacements,
inline instances, dispatch and relevant initialization remain covered. A theorem
about an unused out-of-line function cannot describe the contributing inline
instance. An optimized empty callback still needs its selected source association
and applicable entry conditions.

For historical reuse, retain enough immutable evidence to check the original
artifact theorem after deleting the executable and disposable caches. Current
checking need not prove all permitted rebuilds equivalent or inspect a new
artifact. It must still establish complete current selection agreement,
compatible rules/premises and applicable runtime guards. New production requires
its own bound admission. Artifact equality alone is not a behavior theorem.

## Decisive qualification

The ordinary optimized `TestScalar`/`utf16.IsSurrogate` stock and harmless-custom
case is the first complete consumer, not a replacement synthetic invocation.
Required qualification goes through snapshot, retained-artifact binding,
registration, actual execution, closing, native-record serialization and ordinary
checking. Local conditional proofs do not count as this result.

The same path must preserve these distinctions:

- A harmless selected-body change receives a fresh generic derivation; no approval
  row, hidden purity assertion or disabled optimization is introduced.
- An ambient input, hidden write, changed callback, initialization or cleanup
  interference defeats the affected claim unless its influence is established.
- The retained POPCNT/fallback adversary cannot obtain authority from the nominal
  Go fallback or artifact identity while its runtime selector remains unguarded.
- A foreign artifact/contribution, missing producing premise or closing drift
  cannot borrow a sibling's proof or repair history.
- Cold, warm and discarded-cache checks have the same authority, including after
  the historical executable is removed.
- Skipped subjects and convincing completion output are not execution evidence;
  the consumer's result acceptance and Gofresh's semantic admission remain
  separately exercised.

Mechanism feasibility is unestablished until this composition closes. If a
remaining proof needs unchecked runtime ownership or an expanded trust premise,
name that exact missing fact and resolve the boundary before commissioning more
compiler, scheduler or interpreter machinery. A small auxiliary experiment is
justified only by that concrete consumer requirement; it is not another substitute
acceptance milestone.
