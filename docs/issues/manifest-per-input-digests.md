# Per-input digests in the runtime-input manifest

Lands: when a gofresh consumer needs moved-input attribution (naming *which* observed
input changed, not only that the combined digest moved), or when the manifest encoding
is next revised

## Gap

The runtime-input manifest records observed identities and one combined digest
(REQ-inputs-guard): a digest mismatch says *an* input moved, never *which*. A consumer
explaining a stale verdict can enumerate the watched identities (Describe,
REQ-inputs-path-identities) but cannot attribute the movement — with per-input
digests recorded alongside each identity, an explanation could re-hash each input and
name the moved ones.

## Why not folded into the explanation surface when it landed

Per-input digests change the manifest encoding (a version-2 wire format) and the
combined-digest derivation. The encoding is persisted contract carried inside
consumers' stores — pew recordings, stipulator witness records, gomutant candidate
evidence — so the break invalidates and forces regeneration of every store that
embeds a manifest, across three consumers. That is a deliberate cross-repo decision
with its own migration moment, not a side effect of one consumer's explain view.

## Resolution sketch

Version-2 manifest: each env entry carries the recorded value hash (already computed
per entry during digesting) and each path entry a per-path content digest; the
combined digest folds the per-entry digests. Version-1 manifests are refused on the
clean-break rule — affected recordings go stale and regenerate. An explanation API
then reports recorded vs current per input.
