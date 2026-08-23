# Sibling unverifiable-reason families should name their channels too

The shared-dynamic-state reasons now name their discharge channel
(REQ-closure-shared-dynamic-state-reason); the review of that change
enumerated the sibling families still dead-ended, with the in-repo
precedent ("ambiguous subject identity: …; rename one declaration to
address either" already names its lift):

- "reaches <pkg> (external system call)" (closure/maximal.go) —
  channels exist (`//gofresh:pure` on the reaching function;
  completed-observation substitution), none named. The
  highest-traffic dead end: syscall-reaching benchmarks (wal-class
  durability arms) land here.
- "subject accepts caller-supplied dynamic behavior" (view.go) —
  channel is closing the constraint at the caller or the purity
  directive; not named.
- "reaches testing.X (test runtime …)" — no channel exists; honest
  as-is; excluded.

Same fix shape as the landed family: the clause chosen where the
reason is composed, boundary-aware where channels have boundaries,
channel-and-identity as the contract with CLI spellings only
illustrated (consumers differ in how vouches and directives are
supplied).

Lands: with the next change to either reason's composition site, or
when a field report shows one of these dead-ending an operator again.
