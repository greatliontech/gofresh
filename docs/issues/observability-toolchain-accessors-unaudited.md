# Toolchain accessors are unaudited in the observability analyzer

Lands: when the observability audit next extends, or when a consumer's
non-pure toolchain-reading witnesses first need observation proofs.

## Observed

`runtime.GOROOT` classifies "reaches unaudited standard operation" in
the observability analysis, and a path derived from it fails the
identity-argument admission (`observableIdentityArgument` requires a
constant string; `freshPathValue` admits only fresh sources). A non-pure
test reading a toolchain file — maximal-unverifiable through file I/O,
so proof-dependent — can therefore never carry an observation proof,
even though the read itself is guard-covered at observation time
(REQ-inputs-guard-covered pins it under the toolchain guard) and the
manifest rightly skips it. Consumer evidence: a stipulator witness
fixture reading GOROOT/VERSION publishes only under a purity assertion;
the proof leg refuses with the unaudited reason.

## Resolution

Audit the toolchain accessors: classify `runtime.GOROOT` (its value is
pinned by the toolchain guard) and admit guard-pinned path provenance
through the identity-argument walk, so a read the observation layer
guard-covers is equally admissible to the proof. The same reasoning
extends to the module-cache root accessors when one exists.
