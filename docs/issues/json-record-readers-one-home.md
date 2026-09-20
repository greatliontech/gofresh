# Two JSON record readers with two refusal ladders

gofresh reads two JSON records it owns: the runtime-input manifest
(`runtimeinput.parseManifest`: unknown fields refused, trailing data
refused through `requireJSONEnd`, a canonical re-encode equality check)
and the fingerprint record (`Fingerprint.UnmarshalJSON`:
`uniqueObjectFields` with its own trailing-data check, `isJSONNull`, the
same canonical re-encode check). The primitives — a unique-key object
walk, the null test, the end-of-input test, the canonical-bytes
comparison — are spelled twice with different refusal wordings, and a
third record kind would spell them a third time.

Collapse: one internal reader (an `internal/jsonrecord` package) owning
the four primitives under the caller's object noun; both decoders read
it. Invariants preserved: every refusal each decoder makes today, in
its wording; the manifest's version and validation ladder stay the
manifest's. The two canonical-bytes checks are not one rule: the
manifest compares its raw bytes (base64-framed, never nested), the
fingerprint compares compacted bytes (nested in a parent document that
may indent it) — the collapsed reader carries the whitespace rule as a
caller's choice, never one policy for both.

Lands: 243
