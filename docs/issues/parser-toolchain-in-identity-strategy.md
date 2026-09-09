# The parser's toolchain scopes the ledger memo but not the identity strategy

REQ-closure-test-variant-compartment scopes the compartment ledger's
parse memo by a parse-strategy version and the toolchain identity, so a
parser change never serves a stale ledger from the memo; the identity
strategy a consumer keys ledgers by (REQ-closure-identity-strategy)
composes the parse-strategy version but not the toolchain that parsed.
A consumer keying a persisted ledger per compartment hash, listing
configuration, and identity strategy therefore keys across a toolchain
upgrade whose parser reads the same bytes differently — a delta that
diffs non-inertly at worst, never a wrong serve — while the memo
already treats that upgrade as a new derivation. Whether the toolchain
should ride the identity strategy (every consumer re-measuring on each
toolchain move) or the ledger's parse be pinned to a syntax version
independent of the toolchain is a design call.

Lands: user decision
