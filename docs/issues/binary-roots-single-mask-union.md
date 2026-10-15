# Binary-scoped root inventory: one all-roots walk

The binary-root inventory uses the attributed root machinery — batched
attributed RTA analyses and per-root provenance walks for a union that needs
no per-root separation. A single all-roots walk is a candidate for computing
that union without materializing the per-root maps; equivalence needs to be
established over the binary's complete root and instantiation inventory.
The per-root path stays for the per-subject (single-subject) scoping,
which genuinely needs attribution.

Lands: docs/plans/tooling-redesign.md 7.8.

Measure any cost change under 7.7. Preserve conservative open-world fallback,
cancellation and the existing rooted-program release; do not replace the
per-subject path where the consumer actually needs attribution.
