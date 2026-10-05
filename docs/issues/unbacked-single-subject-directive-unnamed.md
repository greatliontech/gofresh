# An unbacked `//gofresh:single-subject` directive is not named under the package-process attestation

Filed 2026-10-05 from stipulator chunk 309 (the witness engine attests
the package-process execution model).

The own-code discharge of a mutable-local dynamic-capable variable is
two-leg: the author's `//gofresh:single-subject` directive on the
declaration and the caller's single-subject attestation on the engine
(REQ-closure-shared-dynamic-state). A consumer attesting the
package-process model instead (gomutant, stipulator) meets such a
declaration with the directive present and the attestation absent, and
the refusal's channel text still reads "dischargeable by restructuring
the state, or by the //gofresh:single-subject directive on the
declaration under the caller's single-subject attestation"
(dynamicstate.go, dischargeChannel's mutable-local arm) — a remedy the
author has already taken and the consumer cannot complete, since its
processes run a package's subjects together by construction.

Expected: under an attestation that does not back the directive, the
reason names the directive as present and unbacked by the attested
model — "its //gofresh:single-subject directive is backed by no
single-subject attestation here; dischargeable by restructuring the
state" — so the uncacheable face states the one remedy left, and a
consumer's spec sentence ("the engine's refusal stands whole on the
uncacheable face") reproduces an honest reason. The composer has both
facts at hand (the directive-covered set and the attestation flags).

Lands: cross-tool train chunk 310 (a release; the consumers read the
text at their bumps).
