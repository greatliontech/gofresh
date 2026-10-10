# Control authority

The operation's result owner admits intent, resolves defaults and passes one
effective description to shared analysis and execution. A different spelling
for CLI and MCP readers is not a different authority. Numeric defaults and wire
schemas belong to the owning tool's contract; the semantic ownership and
precedence below apply to their admission and composition.

## Authority ledger

The families below govern every control within their named domain. An exact
flag or field can have a reader-specific spelling while retaining this one
meaning. A new independent meaning needs its own declared authority rather
than falling through to an inherited default.

**REQ-control-authority** (invariant): An exposed control MUST have one
authoritative meaning, owner, scope, omitted-value rule, precedence and
observable consequence. Admission distinguishes omitted, explicit empty,
disabled and explicit values wherever they mean different things. Conflicting
or ambiguous competing meanings refuse before the work they would govern;
an implicit last-writer rule cannot contradict the effective description.
Coordinates, normalized environments, identities, routing, accounting and
rendering derive from that description rather than becoming independent
policy choices. A control cannot change authority merely by being supplied
through another face, callback, cache or configuration source. The governing
family meanings are the following ledger.

| Control family | Owner and scope | Omission/default | Precedence and consequence |
|---|---|---|---|
| Project selection | Consumer, one operation | Configured startup default; MCP request selection below | Explicit request replaces the default; normal tool root discovery resolves it. Relative inputs remain associated with that operation. |
| Evidence root and process directory | Producing/checking unit | Tool-derived coordinates for its declared model | Distinct roles: a containing evidence root does not change package loading or invent the child's cwd. Conflicting bindings refuse. |
| Target, subject, benchmark and requirement selection | Result owner, requested operation | The verb's declared inventory/discovery rule | Explicit inventory replaces derivation; explicit empty stays empty. Report filters do not silently narrow the work or a global verdict. |
| Oracle selection | Mutation-result owner, target and selected build | Derive according to the targeting contract | Explicit inventory, including empty, is one alternative to derivation. Coverage and output subscriptions cannot remove required tests. |
| Build selection and analysis environment | Result owner, session | Omission follows authorized inheritance from admitted policy/environment | A declared empty tag set clears inherited tags; a nonempty set replaces them, never unions accidentally. One complete normalized environment drives every analysis of that description. |
| Producing environment and build inputs | Execution owner, actual process | Derived from the admitted description, with defaults resolved before preparation | Actual inherited environment, executable flags and opaque content inputs are distinct facts. A default-consuming input such as auto-PGO still belongs to the build. Analysis environment cannot stand in for a different producer environment. |
| Measurement effort | Result owner, invocation or target | The verb/policy's declared count, duration, candidate or repetition default | Explicit effort replaces its default. One effective count governs metadata and the process; a second raw spelling cannot silently override it. Less work is not equivalent evidence. |
| Raw process arguments | Execution owner, one process | Empty argument vector | Preserve order and behavior-bearing tokens. Known owned options follow their one authority; ambiguous tokens stay identity-bearing or are refused, never discarded by a prefix heuristic. |
| Command lifetime | Operation owner | Face/verb-specific declared timeout | Limits the requested operation, not an oracle verdict's meaning. Cancellation remains reported even when a permitted closing phase banks paid work. |
| Oracle verdict bound | Mutation-result owner, oracle process | Baseline-derived where the contract declares it | An explicit bound replaces derivation; distinguish timeout attribution from parent cancellation, resource refusal and build failure. |
| Optional analysis budget | Analysis owner, stated analysis pass | Unbounded unless supplied | Exhaustion makes the affected proof unavailable; it neither cancels unrelated completed evidence nor grants missing support. |
| Memory and width policy | Operator plus consumer execution owner, process family and admitted children | Host-derived only where the operator supplied no overriding policy | Explicit operator limits retain their documented precedence. Parent collection targets, child limits, worker bounds and physical spawn admission are separate quantities. Unit conversion never wraps or silently changes the policy class. |
| Source purity and externality | Source author, selected declaration | No assertion | Selected source directives keep their meaning in every consumer. Explicit externality outranks purity or observation evidence; conflicting declarations refuse. |
| Policy/caller purity | Accepted policy or caller, named operation/subjects | No assertion | Explicit and attributable, with the existing override scope only. Discovery, a passing run and missing evidence cannot synthesize consent. |
| Dependency vouches and execution-model assertions | Reviewed declaration owner, exact identities/model | No additional acceptance beyond the selected standing source | The configured standing source and explicit extension form one effective set. Declining a source and supplying another is deliberate; mutable-local state is not converted into a dependency vouch. |
| Brackets, exclusions and scratch namespaces | Result owner, producing unit and its inputs | No declaration | Brackets bind a span, exclusions assert irrelevance, namespaces license a named scratch behavior. None is a generic ignore rule or permission to suppress another class of evidence. |
| Bindings, clause claims, consent, gaps and dispositions | Specification author/reviewer, declared corpus identities | No new grant or automatic authoring | Discovery can propose, never accept policy, bind evidence, infer consent, fire a manual gap or widen a clause claim. |
| Record location, baseline reference, force and staged operation | Consumer/caller, operation and result store | The verb's declared storage/reference/measurement policy | Explicit choices govern their own roles. Location or layer movement does not change producing authority; forced measurement does not strengthen its outcome by itself. |
| Evidence compatibility and applicability extension | Shared evidence rules plus result owner's admitted model | Ordinary checking of established evidence; no unrequested transformation | Recognized native compatibility governs support. A separately authorized endpoint transformation retains original producing history and all remaining guards. |
| Diagnostic execution and instrumentation | Result owner versus observer, respectively | No extra execution from an observer | Diagnostic workload has its own admitted policy. Read-only reporting cannot start probes or mutate commands; deliberate process-policy hooks belong to the execution owner. |
| Statistical acceptance | Measurement-result owner, requested comparison population and metrics | Informational comparison may show a subset; an enforcing gate defaults to complete requested coverage, current admissible working-side evidence and known compatible conditions | Authorized partial scope is explicit. Metrics, significance, magnitude and execution hygiene retain their own authority; historical variation cannot increase tolerance automatically. A displayed interval does not set the acceptance rule. |
| Run hygiene and pinning | Measurement operator, actual execution | The verb's documented hygiene/pinning policy | Warning versus refusal is explicit and separate from comparison eligibility. Derive the CPU set from the chosen policy; no machine-equality claim proves quietness. |
| Views, JSON, verbosity and progress | Surface reader, response | The verb's documented projection | Presentation changes neither measurement work nor evidence authority. Omitted rows are counted; a bounded response does not imply an incomplete store is complete. |
| Witness evaluation versus inspection | Specification-result owner, accepted policy and explicit evaluation | Inspections use available facts without measuring witnesses | Stipulator's check owns measurement. Current/stale/missing/NoOutcome/partial accounts remain distinct; unknown neither grants a witness nor authorizes evidence-based deletion. |
| Memo location and optional refinement | Analysis owner, session/generation | Shared default cache and admitted analysis policy | A valid memo hit preserves the meaning and authority of a completed derivation. Cold work can exhaust a budget that a warm hit satisfies; cache absence or corruption grants no stronger authority. Refinement cannot replace missed producing preparation. |

The shared library owns environment normalization, admitted evidence methods,
dependency identities and native record grammar. The consumer owns accepted
execution policy, actual subject/process scope, result meaning and storage.
An omnibus additive repository policy cannot silently merge those owners:
resource defaults are not repository facts, selection replacement is not set
union, and source assertions are not interchangeable with operation policy.

**REQ-control-execution-description** (invariant): Preparation, execution,
recording and checking MUST use the same admitted effective meaning for
each producing control, preserving requested intent separately where useful.
Positive resource values are range-checked before conversion; explicit empty
inventories cannot expand to default work. A typed control and raw arguments
cannot describe different actual execution. Unrecognized argument arity,
option-looking values and positional tokens are not classified runtime-only
by spelling alone. Inputs consumed by default toolchain behavior belong to
the effective build description. Validation and default resolution precede
expensive work or writes whose purpose that refusal would defeat.

## Standing trust

**REQ-control-trust-source** (behavior): The consumer MUST identify the
standing source and explicit extensions that authorize an operation's trust
declarations. Gomutant's normal standing set is the selected tree's vouches
file with explicitly scoped extensions; Stipulator's is its accepted policy,
which deliberately declines the library's repository file. Pew's ordinary
judgments use their selected store's standing set. Each diagnostic A/B side
uses that side's default module-store standing set, including the ref side's
own declaration, rather than silently importing the working side's set.
Diagnostic output placement does not choose or alter that source. Missing
standing files contribute no entries, malformed or unreadable selected files
refuse according to the owning contract, and withdrawing an acceptance is
judged against the current operation's selected policy. Source purity and
externality remain selected-declaration facts, not entries inferred from the
standing vouch source. Any alternative source or extension has explicit scope
and attribution; discovery never accepts new trust on the author's behalf.

## Project-bound MCP operations

**REQ-control-request-project** (behavior): A project-bound MCP operation MUST
accept one optional request `cwd`, resolved without a process-wide directory
change or mutable active project. Omission uses the server's configured
default directory, resolved once at startup from its launch directory. A
relative request value resolves against that same default, never the prior
request. An explicitly empty value is invalid rather than an alternative
spelling of omission. Normal tool-specific root discovery then determines
the operation's resolved project root, which the response identifies. An
invalid or disallowed selection refuses before expensive work or writes and
never falls back silently. Static guidance is project-independent and needs
no selector.

**REQ-control-project-isolation** (invariant): Concurrent operations selecting
different projects MUST retain unambiguous root identity in declarations,
trust sourcing, cache keys, stores, locks, relative inputs, subprocesses,
progress, errors, resources and recovery handles. A default project's
server-supplied vouches do not implicitly authorize another project; any
cross-project assertion requires its own explicit scope. Root selection
confers no new filesystem access or write permission, and each tool's
existing confinement obligations remain in force. Unqualified legacy
resource identities resolve against the configured default project; qualified
identities and operation handles cannot borrow another project's state.
Retained per-project state is bounded. Physical memory/worker admission and
process-wide runtime limits remain shared where their resources are shared,
not partitioned into fictitious independent capacity per root.

These obligations govern the existing Gomutant and Stipulator MCP surfaces.
They do not require a new transport for a tool without an MCP workflow. Each
surface specifies its concrete schema and root-qualified resource encoding
together with its guidance; changing the selector does not change evidence-root
or process-directory semantics.
