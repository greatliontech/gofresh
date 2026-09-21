# A refused in-module path is spelled absolute in the inputs' identity

The classifier's refusal reason spells the refused path absolute
(`external directory input: /home/me/src/checkout/mod/link` for an
in-module symbolic link resolving outside the tree, and the hashing
pass's resolved-target refusal likewise), and that reason is the
manifest entry the runtime-input digest folds. Chunk 279 took the
observation's attribution — the producing process's own directory — out
of the identity, so a refused OS root or volatile object yields one
manifest, digest, and reason from any checkout; a refused path INSIDE
the module still names its checkout, so a measurement of the same tree
from another checkout, or after moving the repository, yields a
different manifest and digest for that instability, and a consumer
comparing recorded evidence whole sheds every attestation on the
finding. A refused path outside the module (a sibling directory of the
checkout) is external state — the classifier keys it by its absolute
path, which is the object's identity — and is not this residual.

## The fork

- Spell an in-module refused path module-relative in the clause: the
  identity becomes checkout-independent, and every consumer's exemption
  record keyed on such a clause (gomutant's) re-keys once, every record
  carrying one re-measures once — a reason-grammar change under
  REQ-inputs-refusal-attribution's split rule (the clause is what a
  consumer keys on).
- Keep the absolute spelling: a moved checkout re-measures such records
  and sheds their attestations, as today.

Lands: user decision — the fork above.
