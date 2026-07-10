# Stipulator coverage lacks required witness classes

Lands: when binding evidence classifications are next revised, or before the
next release.

## Context

The corpus compiles, every binding is fresh and shape-valid, and all executed
witnesses pass, but the coverage gate remains red because eight requirements
lack the stronger evidence class their requirement kind requires:

- `REQ-closure-coverage`, `REQ-closure-floor`,
  `REQ-closure-mutable-local`, `REQ-fresh-commit-independent`, and
  `REQ-guard-cache` need a property witness or analyzer proof.
- `REQ-fresh-fingerprint-data` and `REQ-purity-input` need an analyzer proof.
- `REQ-inputs-absent-asserted` needs an executed witness.

The missing classifications predate the build-selection work; ordinary tests
passing cannot turn an example witness into proof of an invariant or structural
claim.

## Resolution

Bind the existing strongest applicable tests as property witnesses where they
actually quantify over the claim, add analyzer proofs for structural shapes,
and add an executed witness for the absent-runtime-manifest behavior. If an
existing test does not establish the required class, strengthen it rather than
relabeling it.
