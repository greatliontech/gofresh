# Invalid scratch declarations survive producing preparation

Lands: docs/plans/tooling-redesign.md 5.1t, at the shared registration
boundary before the next consumer migration.

`Unit.Register` copies `ProcessDescription.ScratchNamespaces`, captures the
frame and prepares evidence without applying the existing
`runtimeinput.ValidateScratchNamespace` grammar. A declaration such as
`{Dir: ".", Pattern: "bad/name"}` therefore reaches an executable contribution.
Closing later discovers the malformed declaration during input ingestion.
This is an input-decidable refusal paid for after execution, contrary to
REQ-fresh-preparation.

This path is source-traced; its permanent deciding test remains to be written.
Use the existing declaration validator at the owning preparation boundary,
with malformed directory/pattern and valid namespace controls. Pin refusal
before frame/proof work and before a consumer can execute the contribution.
Do not turn genuine post-execution capture failure into a preparation error,
or duplicate the namespace grammar in the unit or consumer.
