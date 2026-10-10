# Evidence and result applicability

Gofresh judges whether recorded evidence licenses reuse under a declared result
model. The result owner executes, interprets and stores its result. Source and
input agreement are evidence for that judgment, not a promise that every future
execution takes the same schedule or produces identical timing samples.

The [overview](overview.md) defines freshness verdicts and their guard ladder.
[Runtime inputs](runtime-inputs.md) define process completion, operation-outcome
support, identity-only observations and their encodings. [Purity](purity.md)
defines the distinct caller-responsible assertion channels. The authority and
ownership rules here apply to those forms alike; they do not broaden an
admitted observation operation or supply a missing producing premise.

## Claims and authority

**result model** (term): the result owner's declared meaning of a result, the
contributing subjects and executions, and the conditions under which evidence
can justify reusing it. A code-result or measurement kind selects applicable
guard obligations; it does not describe every condition the consumer needs.
Execution-model assertions and consumer-owned pins add their own conditions.

**REQ-fresh-result-model** (behavior): A freshness judgment MUST state
applicability under the result's declared model rather than certify an
unqualified future outcome. The judgment preserves the model's authority and
scope, including attributable caller assumptions. It does not certify suite
health, coverage of a requested population, a mutation kill, statistical
significance, a regression tolerance, quiet execution conditions or the
authenticity of historical provenance. Those are separate claims of the result
owner; none follows from a valid fingerprint alone. A consumer's further
conditions remain required even when all native freshness guards hold.

**authority class** (term): the ground on which a particular fact is accepted.
An observed fact records what a producing or checking operation actually
observed within its surface and span. A derived fact has an admitted proof or
derivation over identified inputs. An asserted fact is an explicit,
attributable responsibility accepted under a named assertion rule. Unknown or
unsupported is the absence of sufficient authority for the claim. These
classes describe individual claims; an execution can have an observed
terminal event, derived outcome support and caller-asserted scope at once.

**REQ-fresh-authority-account** (invariant): Evidence construction, checking and
composition MUST preserve the authority class, scope and prerequisites of
each accepted claim. Observation identities alone do not establish that all
inputs were observed; completion alone does not establish operation outcomes;
a derived outcome inventory alone does not establish an execution; and an
assertion remains an assertion even when its resulting guards match. Unknown,
absent or incompatible support supplies no positive evidence. Hashes, seals,
successful decoding, set union and current reconstruction establish none of
the missing historical premises. Explicit purity keeps its specified override
authority without relabeling the observation or overriding externality and
real guard drift.

## Producing evidence and current applicability

**producing evidence** (term): the immutable historical facts and attributable
assertions attached to the result that was actually produced, including its
source/build identity, contributing execution bindings and admitted support.
A readable historical result can retain this evidence while being stale or
unverifiable for a present operation.

**applicability endpoint** (term): the current identity to which an explicitly
licensed transformation has shown an existing result applicable. It is
separate from the original producing identity. The inert test-variant
extension is governed by REQ-fresh-applicability-transform; its presence is
neither a new execution nor evidence of different original inputs.

**REQ-fresh-producing-evidence** (invariant): A check or applicability
transformation MUST retain the original result's producing evidence and
support class, whether it accepts or refuses present reuse. A licensed
endpoint changes only the independently justified applicability facts;
repeated transformations retain the original producing identity and support.
A representation-only migration changes no authority, and a subsequent
execution produces its own evidence rather than repairing missing facts about
an earlier one. Record-only support validation judges recognized stored
evidence without observing present runtime values; it is neither a current
freshness judgment nor authentication of the stored history.

Three activities remain distinct: admitting established producing evidence,
deriving present facts for an authorized applicability transformation, and
preparing obligations that an execution must actually satisfy. A final check
cannot replace the third with the second. Trust authorization and permission
to attempt additional analysis are also separate: a larger analysis budget
does not authorize an assertion, and exhausting that budget does not turn
unknown support into evidence.

## Source-derived certificates

**static derivation certificate** (term): evidence for a cached fact computed
from source, configuration and an identified derivation, such as declaration
resolution or witness classification. Its producer is the derivation, not an
execution of the subject it describes. It can be valid without any subject
process having run, but says nothing about that subject's runtime outcome.

**REQ-fresh-static-certificate** (invariant): Reuse of a source-derived
certificate MUST depend on every input that can change its claimed fact,
including source membership and content, selected views and their relevant
precedence, resolved configuration, classifier or derivation identity, and
the policy and toolchain content that any admitted analysis depends on.
Changing an unrecorded dependency prevents serving from that certificate.
Missing or incompatible dependencies require re-derivation or an explicit
unknown answer, never a fabricated execution receipt. Re-deriving a static
certificate cannot supply completion, observation or outcome evidence for a
historical subject execution. A consumer that composes several certificates
retains every contributing dependency and its authority boundary.

The dependency set is claim-specific: a declaration lookup, a cross-selection
seeding judgment and an executed witness verdict need not share one scope.
A native analysis memo caches a source-derived fact too; its reuse obeys the
same complete-dependency rule even though it is disposable cache data rather
than a consumer's durable execution record.
A certificate for one selected view cannot justify a fact that was computed
from several views unless it carries those dependencies too. A logical lookup
address is not itself this dependency evidence, and the current source of a
fact is not a substitute for the source under which a stored fact derived.

## Dependency and compatibility identities

A logical record address identifies the requested result, not the evidence
needed to serve it. A producing identity describes the inputs of the original
production. A derivation identity identifies the rules that computed a fact;
a memo identity additionally includes its complete dependencies and cache
representation. A wire version determines how bytes are read. A compatibility
identity determines whether recognized evidence still establishes the claim
being checked. Equality on one of these axes is not equality on the others.

A source-equivalence identity can intentionally ignore layout or ordinary
comments. A cached payload that embeds source coordinates has additional
dependencies: it needs sufficient source identity to reproduce those
coordinates, or it derives them outside the cached payload from the current
coherent snapshot. Public behavior equivalence does not promise byte-equal
diagnostics across source spellings it deliberately treats as equivalent.

**REQ-fresh-dependency-identities** (invariant): Every memoized or recorded
derived claim MUST carry or identify all dependencies needed to justify its
reuse, including selected toolchain source content and admission policy when
the claim depends on audited standard-library semantics. Neither unchanged
reported version nor an admitted/not-admitted Boolean substitutes for those
dependencies. A memo representation change can require recomputation without
invalidating semantically compatible historical evidence; a changed proof,
outcome or admission rule that changes what evidence establishes requires a
distinguishable compatibility judgment even when the bytes still decode. A
recognized compatibility rule can preserve only the authority it establishes;
missing historical dependencies cannot be supplied by reading today's tree or
by inserting today's identity during decoding. Without sufficient recognized
support the dependent claim is unavailable, though independent applicable
evidence and explicit assertions retain their own specified authority.

Content admission concerns the files selected by the analysis' actual build
configuration and the policy governing them. It is separate from language
series compatibility and the reported toolchain label. Correctness of the
compiler/linker and integrity of toolchain-mediated caches remain the stated
model premises; those premises do not exempt legitimate changes to the
selected source content from the content-admission or dependency judgments.

Producing and checking snapshots each establish their own present facts. A
current content digest can reject a dependent historical claim or participate
in an explicitly licensed compatibility check; it cannot certify which bytes
an earlier execution used. Source/build and runtime drift retain their own
refusal precedence, and evidence compatibility never bypasses a failing guard.
Readable history with unsupported evidence remains history, not a current
pass. No new wire fields or alternate encodings are implied by these identity
roles; a published record format determines which roles it can represent.

## Ownership vocabulary

The following roles identify responsibility rather than prescribe language
types or a particular public signature:

- An **analysis session** owns immutable effective operation configuration:
  source-selection intent and its resolution policy, analysis environment,
  admitted assertion sources, loading services and cancellation/cost policy.
  Its lifetime is one judged operation, not a server process.
- An **analysis snapshot** owns one coherent generation of source, guards,
  declarations and derived facts. Lazy computation and memo serving do not
  change which generation those facts describe. Selecting a subset preserves
  the selected facts and their provenance rather than observing a new tree.
- A **unit transaction** owns the selected producing or checking obligations,
  its contributing execution bindings and evidence, and its closing interval.
  Sharing a snapshot does not share another unit's attachments or closing seal.
- **Durable evidence** is the native producing record and any independently
  licensed applicability endpoint. The consumer stores that native form beside
  its own result and domain facts, not a second inventory of native fields.
- A **judgment** is the final applicability answer and its causes, scope and
  accepted authorities. A value awaiting a required closing validation is
  provisional and carries no permission to publish or consume it as final.

The result owner remains responsible for truthful execution scope, harness
completion, the actual environment and the declared hold-still spans. A
scope-safe construction prevents accidental borrowing; it cannot authenticate
a caller that lies about an execution or prove absence of mutation-and-restore
between agreeing observations. The sampling and exclusion limits stated by
REQ-fresh-coherent-view, REQ-fresh-producer-view and
REQ-inputs-observation-coherence remain unchanged.
