# The compartment ledger is not stated to be a function of the compartment hash

REQ-closure-test-variant-compartment defines the test-variant
compartment hash as a fold over each compartment member's relative
file name and content hash, and the compartment ledger
(`View.TestVariantLedger`) as the declaration-level read over the same
compartment. The ledger additionally depends on each member's kind as
`go list` reports it — compiled Go file, embedded data, other compiled
input — which the hash does not fold: two compartments with equal
hashes are equal in members and bytes, and a kind flip without a
member-set or content change has no known construction, but the spec
does not state the entailment "equal compartment hash ⇒ equal ledger".

A consumer now depends on it: stipulator's witness store persists one
ledger per compartment hash, content-addressed, and diffs it for the
witness-freshness carve-out. If the entailment failed, the consumer's
failure mode is a non-inert diff — the witness re-executes — never a
wrong serve.

Resolution: state the entailment in REQ-closure-test-variant-compartment
as an invariant with a property witness over generated compartments
(equal hashes ⇒ equal ledgers), or fold the kind facts into the hash so
the entailment is by construction.

Lands: user decision
