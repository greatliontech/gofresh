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

[Implementation verification](implementation-verification.md) governs derived
semantic claims about selected implementations. Dependency identity identifies
the inputs to that judgment; it does not confer their behavioral meaning.

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
the inference rules, checked subordinate claims and selected implementation
content that the analysis depends on.
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
derived claim MUST preserve these identity and authority boundaries:

- **complete-dependencies** — Every dependency needed to justify reuse is carried
  or identified, including selected implementation content, inference rules and
  checked subordinate claims when implementation semantics are used. Unchanged
  reported versions and admission Booleans cannot substitute for dependencies.
- **semantic-authority** — Dependence identity concerns the actual build's
  selected inputs, separately from checked derivations of their semantics.
  Neither is a language-series judgment or toolchain label. Compiler/linker
  correctness and toolchain-mediated-cache integrity neither exempt selected
  content changes nor assert implementation behavior beyond the foundational
  premises of REQ-impl-premise-boundary. Existing admission-policy identities
  identify inference and compatibility rules, not approved implementations.
- **compatibility** — A memo representation change may require recomputation
  without invalidating semantically compatible history. A changed proof, outcome
  or inference rule that changes what evidence establishes requires a
  distinguishable compatibility judgment even when bytes still decode. A
  recognized compatibility rule preserves only the authority it establishes;
  unsupported dependent claims are unavailable while independent evidence and
  explicit assertions retain their own specified authority.
- **historical-dependencies** — Missing historical dependencies cannot be supplied
  from today's tree or inserted during decoding. Producing and checking snapshots
  each establish their own present facts; a current digest can reject a historical
  claim or participate in a licensed compatibility check, but cannot certify
  which bytes an earlier execution used. Unsupported readable history remains
  history, not a current pass.
- **guard-precedence** — Source/build and runtime drift retain their ordinary
  refusal precedence. Evidence compatibility never bypasses a failing guard.
- **representation** — These identity roles imply no new wire fields or alternate
  encodings; a published record format determines which roles it can represent.

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
- A **build binding** associates an executor's successful-build declaration
  with that snapshot and package. Its inspected form additionally owns observed
  retained-artifact inputs under REQ-fresh-inspected-artifact; the declaration
  alone supplies none of those observations or their authority.
- A **runtime binding** selects an immutable actual process directory and
  complete environment over that source/build generation. Runtime-dependent
  guards and checking use that binding; its creation supplies no execution,
  attachment or closing authority. Different bindings can share the same
  compilation facts and retained package artifact.
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

## Unit obligations and closing

**REQ-fresh-unit-roster** (invariant): A producing unit MUST account for the
complete set of executions contributing to its result independently of which
observation records arrive. Each contributor is registered with its subject
scope, process binding, actual environment and selected obligations before
that execution starts. Registration can be incremental while the unit is
open; starting close fixes the roster and refuses late registration or
attachment. Exactly one terminal disposition settles each registered
contribution. Retransmitting the same finalized evidence can be idempotent,
but supplies no second execution; conflicting dispositions refuse. A
registered process that never started is named as such, not as a completed
empty execution. A missing disposition prevents successful closing, and an
incomplete disposition cannot contribute supported completion. The executor
still owns the truth that no unregistered execution contributed; a missing
record cannot define that execution out of the result.

**REQ-fresh-unit-bindings** (invariant): Producing evidence MUST remain bound
to its prepared unit, source/build identity, contributing subjects, process
identity, frame and actual normalized environment. Evidence cannot be
borrowed from a sibling unit, a separate diagnostic process, another subject,
or an unlicensed transformed executable even where individual hashes agree.
Binding does not authenticate a dishonest executor, nor does it replace any
independently required completion, outcome, locality or attribution evidence.
Source-derived certificates use their derivation dependencies instead of
inventing these execution bindings.

**REQ-fresh-unit-close** (invariant): A unit MUST expose reusable final evidence
or a consumable final judgment only after all of its selected obligations and
closing checks have succeeded. Closing is a terminal transition for that
unit's mutable registration and attachment state, including when closing
fails or is cancelled; a retry uses a new unit rather than reopening the old
one. Closed or failed units do not seal a shared immutable snapshot against
other units. A sibling selects all relevant immutable facts and provenance,
including analysis cuts and applicability obligations, but owns independent
contributions and closing state. A later sibling's preparation is not a
prerequisite for closing an already complete unit. Consumer publication may
still fail after a successful close; failure does not claim a durable write
or discard the separately committed prefix of other units.

**REQ-fresh-unit-exclusion** (invariant): The result owner MUST protect the
relevant source and build inputs across producing preparation, execution and
closing validation, and the relevant runtime inputs across execution,
finalization and each composition/check interval. The validated dependencies
remain protected until publication or consumption of the final judgment.
These are unit-specific hold-still obligations, not a prescribed global lock.
Endpoint re-observation detects ordinary persistent motion; it does not prove
absence of mutation-and-restore or establish an atomic filesystem/environment
snapshot. An owner allowing the excluded interval cannot claim the evidence
was bound to its producing or checking span. Cancellation does not waive the
exclusion while any permitted finalization is still observing inputs.

**REQ-fresh-final-evidence-selection** (behavior): A final check MUST select
admissible established evidence automatically within the result owner's
declared model, without requiring the caller to repeat ordinary-versus-observed
selection at each checking stage. Any required producing obligation is selected
and established before its execution; checking-time analysis cannot replace
that preparation or repair missing historical support. Authorization to use
an assertion and authorization to attempt additional costly analysis remain
explicit. An applicability transformation likewise needs its own license;
automatic evidence selection does not silently extend an endpoint. Decisive
source or guard mismatches can reject before optional refinements, while a
request for a complete inventory still receives a complete account rather
than a cheap refusal presented as that inventory.

An ordinarily completed failing test can satisfy its completion obligation;
its failed outcome is still the result owner's claim. A crashed or killed
process cannot become complete from its output prefix. A static certificate,
identity-only observation, incomplete process and supported observation have
different permitted uses; closing preserves those distinctions rather than
requiring every unit to claim an executed, supported success.

Operation cancellation prevents new producing work. A consumer can finish
already-paid successful work in a separately declared, bounded closing phase,
using the context it supplies for that phase and retaining the interruption
in the operation's account. The library does not continue a cancelled entry
under a private uncancellable context. Closing expiry yields no final reusable
answer from that unit; an earlier independently committed unit remains kept.

## Explicit built-artifact production

**REQ-fresh-built-unit** (behavior): The explicit built-artifact producing form
MUST bind its snapshot, declared successful build and contributing execution
without exposing mutable analysis or transaction state. The session owns copied
build description and accepted assertion sets; its complete vouch set
is caller-resolved in canonical `import-path.Variable` identity form, with no
additional implicit repository-file read or re-interpretation as CLI flag syntax.
Each immutable runtime binding owns a copied runtime description over the
snapshot. Its directory defaults to the build directory, a relative value
resolving against that directory, and supplies the actual process PWD. An omitted
runtime environment inherits the complete build environment; an explicitly empty
environment remains empty apart from that derived PWD. Different runtime
descriptions do not require another source/build observation or change compilation
identity. Production, runtime observation and checking use the selected binding's
same normalized environment. Measurement results retain their applicable runtime
guards under that environment; code results gain no measurement-only guards.
The executor builds the selected
package artifact under the snapshot's build description, retains it unchanged
and declares its successful construction through a snapshot/package-bound
identity. This is an attributable executor assertion, not binary authentication
or a proof that an arbitrary compiler followed the description. The execution
uses that artifact under the runtime description; a compiling go command under
the latter is not that execution. The singleton form admits one subject and exactly one
contributing process per unit; a second registration refuses. Registration fixes
the process identity, capture path and observation declarations before execution,
with an exclusively assigned capture protected through finalization. Malformed
scratch namespace declarations refuse before frame/proof preparation or reservation
of the contribution, using the runtime-input namespace grammar. A relative
capture path resolves against the admitted runtime directory; execution and
finalization receive that same absolute coordinate, preserving a symlink/parent
path's filesystem meaning rather than lexically cancelling its components.
Submission
accepts only its opaque contribution handle and one explicit normal, abnormal or
never-started terminal disposition. Normality includes harness completion and
flush, not merely a zero exit code, and says nothing about sample success. A
never-started process produces no executed fingerprint. Closing freezes the
roster before work, owns finalization and validation under its context, and
returns the native fingerprint, terminal fact, observation support class and
final native judgment only on success. Supported observation, identity-only
guards and incomplete capture remain distinct. A deliberately identity-only
diagnostic unit selects no producing outcome proof, and completion cannot
promote its evidence to supported observation. An abort that wins before closing
commits its final state ends the unpublished unit, cancels its library-owned
work and prevents final evidence from escaping. An already closed unit is
unchanged; caller cancellation retains its attribution if it also occurred.
Stopping the executed process and disposing of its capture remain the executor's
responsibility. Checking an existing fingerprint selects admissible established
evidence and closes its own interval before returning a final judgment. Neither
operation seals the shared snapshot or supplies missing historical obligations.
Source inventories, native compartment ledgers and explanation facts are
caller-owned projections of that same immutable snapshot; explanation facts
supply no execution or observation premise. An inert-compartment extension is
separately requested, retains producing evidence and returns its checked native
endpoint and companion ledger only after its own closing validation.
The result owner retains sample acceptance, actual execution truth, hold-still
protection through publication and the separate durable-write disposition.

**REQ-fresh-inspected-artifact** (behavior): The existing snapshot/package build
binding MUST admit an explicitly selected inspected retained-artifact form for
the producing units of REQ-fresh-built-unit and REQ-fresh-package-unit, with
these obligations:

- **execution-coordinate** — The input names the actual retained regular file
  the executor will execute for the bound package build. A relative coordinate
  resolves under the snapshot's build directory, independently of the runtime
  directory. Resolution preserves the filesystem meaning of symlink and `..`
  components rather than lexically cancelling them. A missing, unreadable or
  non-regular target supplies no inspected binding. Detached bytes, an executor
  label or a caller-supplied digest cannot substitute for observing this file.
- **agreeing-capture** — Inspection completely reads and hashes the selected
  file under the caller's context and establishes agreeing observations of the
  execution coordinate, retained file and full content under the coherent-view
  capture discipline. A partial read or disagreement refuses inspection. File
  metadata alone is insufficient. The binding owns immutable observed bytes,
  their digest, observed target-identity facts and the execution coordinate;
  later filesystem changes cannot mutate that analysis input.
- **snapshot-ownership** — The inspected input belongs to the snapshot's captured
  source/build generation and the declared package. Caller input is copied;
  changing it after inspection cannot change the binding. Registration checks
  snapshot and package ownership, not merely equal labels or digests. Runtime
  bindings may share these immutable inputs, but units retain independent
  contributors, observations and closing seals. The declaration-only build
  binding remains available and acquires no inspected facts implicitly.
- **executor-responsibility** — Inspection does not authenticate the declaration
  that the file was built under this snapshot's description or that a contributing
  process executed it. The executor retains those truths, the existing package
  build and subject scope, and protection of the retained artifact and its
  execution-path resolution from inspection through execution, closing and
  publication. A different executable or independent rebuild is not that
  execution. Agreeing samples cannot exclude mutation-and-restore between them;
  the existing caller-owned exclusion obligation remains explicit.
- **registration-validation** — Before a producing contribution using an inspected
  binding is successfully registered, registration re-observes the execution
  coordinate and complete file content. It compares the target's observed
  regular-file identity and complete content with the captured observations.
  Observed target-identity or content disagreement, unreadability or loss of
  regular-file status refuses registration. Namespace changes or identity reuse
  leaving all compared observations equal are not proven absent; excluding
  those changes remains the executor's responsibility.
  A remembered digest, metadata agreement or reading only an old open file cannot
  replace re-observation through the execution coordinate. No contributing
  execution may begin on the strength of a pending validation.
- **closing-validation** — Before committing successful closing or exposing final
  subject evidence or judgment, producing close repeats the execution-coordinate
  and full-content validation for every inspected binding used by the unit,
  after ordinary process-observation finalization and the other selected closing
  observations. Failure yields none, even if
  source, build and runtime guards agree. The failure identifies the unavailable
  observation or demonstrated artifact disagreement without asserting which binary
  actually executed. A normally completed process retains its supplied terminal
  disposition and observation facts established by the existing finalization path
  in the non-authorizing process account; artifact refusal does not erase them or
  convert them into reusable evidence. Artifact disagreement alone does not skip
  normal-completion finalization. Facts not established remain unknown, including
  when cancellation or a winning abort prevents completing that work. Protection
  after the comparison remains caller-owned; validation does not establish an
  atomic observation-to-publication interval.
- **cancellation-and-isolation** — Potentially expensive inspection, registration
  validation and closing re-observation honor their existing caller-owned phase
  contexts. Cancellation or an abort that wins the unit's existing lifecycle
  prevents successful registration or final evidence from escaping; partial reads
  supply no inspected fact. Pending validation cannot register past the unit's
  closing or abort boundary. Failure or cancellation of one unit does not mutate
  the shared immutable artifact input or seal another unit. Existing cancellation,
  abort, finalization and process-account rules retain their precedence.
- **authority-boundary** — Observed bytes, path and digest are implementation
  inputs, not a proof of native behavior, compiler correspondence, inline coverage,
  actual execution, observation completeness or operation outcomes. Inspection
  selects no new result model and discharges no maximal-tier blocker. Any use for
  runtime reuse still requires independently checked implementation coverage and
  semantic evidence under REQ-impl-build-selection and the existing authority
  contracts. Ordinary source/build/runtime guards and explicit assertion rules
  continue to apply.
- **applicability-boundary** — Successful inspection and span validation establish
  only the additional producing-span fact. They do not make artifact identity a
  new persisted applicability guard of an ordinary fingerprint or assert that its
  record represents native implementation evidence. Absence of artifact fields in
  such a record is therefore not a missing required guard for its unchanged
  ordinary evidence channel, and its inspection supplies no stronger reuse claim.
  Current or historical native-artifact-dependent reuse requires separately
  represented producing evidence and an explicitly governed current-artifact
  selection and comparison. A present inspection cannot add that authority to an
  old record, and artifact-free checking cannot implicitly select an artifact.

**REQ-fresh-checking-unit** (behavior): Checking a batch of existing native
records MUST admit an independently closing transaction over a declared subject
set and runtime binding. Different candidate variants for a subject can be
judged within that transaction without lending evidence between candidates.
Evidence selection is automatic under REQ-fresh-final-evidence-selection; an
inert-compartment extension remains an explicit request. Answers before closing
are provisional, including transformed endpoints and ledgers. Only successful
closing grants final judgments or checked transformed evidence; failure,
cancellation or abort grants none and ends the transaction. Closing validates
all selected obligations, not just the last candidate. A checking transaction
owns no producing contribution, cannot synthesize historical execution support
and cannot seal its snapshot, runtime binding or another transaction. A singleton
check uses this same lifecycle. The caller retains protection of the checked
dependencies through consumption of the final judgment.

## Package-process production

The freshness unit and the consumer's publication group need not have the same
membership. A package can have an original execution and several isolation
attempts, while each stored witness selects just one producing execution. An
attempt's actual failures remain in the consumer's operation account even when
another attempt supplies an independently eligible witness. Grouping publication
does not license unioning their evidence or replacing the original history.

**REQ-fresh-package-unit** (behavior): The built-artifact producing boundary MUST
admit package-process production under these obligations:

- **subject-scope** — One package-test process covers a nonempty, explicitly
  selected subject set from one package, fixed before preparation, deduplicated
  in first request order and owned by the unit. Every executed subject belongs
  to it, including those for which no reusable record is wanted. Later results
  or observations cannot define the executed set. Unknown members refuse as a
  complete batch before producing work. A declared single-subject model refuses
  a larger set; the package form does not change accepted assertion policy.
- **process-binding** — One process has one retained-artifact binding, frame,
  actual environment, exclusively assigned capture and explicit terminal
  disposition. A second registration refuses. The observation stream has no
  per-subject attribution: each subject's fingerprint retains all process
  identities and refusals beside its own source/proof and assertion facts.
- **outcome-scope** — Outcome support is prepared over the whole selected set
  and requires every member's admitted inventory, not just published members.
  Unsupported inventory preserves identity-only evidence; package isolation and
  normal completion do not establish outcome support. A subject's purity override
  changes neither process observation authority nor a sibling's judgment.
- **closing-protocol** — Closing finalizes the capture once and exposes
  subject-indexed native evidence and judgments only after the whole execution's
  closing validation succeeds. The final account retains the process and artifact,
  actual terminal assertion and separate observation-completeness and outcome-support
  dispositions, not per-test verdicts or durable-write receipts. Missing registration
  or terminal disposition, a never-started process, failed validation, cancellation
  or a winning abort exposes no executed subject evidence. An ordinarily completed
  failing test can complete normally; an abnormal process cannot gain supported
  evidence from an earlier passing row or complete-looking log.
- **process-account** — A separate non-authorizing account remains available when
  reusable closing refuses. It retains the registered process and artifact,
  supplied terminal disposition and already-established observation facts, with
  unknown or incomplete dispositions for unfinished work. It supplies no reusable
  fingerprint, final applicability judgment or transferable producing support.
  Reading it performs no observation or cancelled work; a completed-process account
  is not a successful closing or durable-publication receipt.
- **runtime-failure-finalization** — Finalization records established observation
  facts before refusing a demonstrated runtime-input span failure. The structured
  closing failure carries the deciding runtime-input cause; diagnostics are a
  projection. No finalized subject evidence escapes, while the process account
  retains the typed guard failure, terminal disposition and attribution. Caller
  cancellation and a winning abort retain their precedence.
- **transaction-isolation** — Singleton and package forms share these lifecycle
  rules. Each retry owns a new transaction, frame, obligations, attachments and
  closing seal, neither repairing nor absorbing an earlier attempt. Immutable
  snapshot facts may be shared, but one unit's completion or failure seals no
  other. A source-drift retry requires a new snapshot. Consumer-wide retry
  selection, package publication and outcome aggregation remain the owner's
  responsibilities. The package form implies no new manifest or fingerprint encoding.
