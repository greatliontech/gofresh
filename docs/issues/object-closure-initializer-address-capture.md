# Address capture in a package-level initializer expression escapes the object-closure audit

Soundness hole, false-Valid direction. The spec requires any init-flow
address capture of an interface variable to break its object closure
("an init-flow appearance the audit cannot attribute — … an address
capture … — breaks the closure from whichever package performs it",
initializer expressions being init flow). The audit's address-capture
arm runs only on function bodies; the `GenDecl` arm audits only each
ValueSpec's own names and values and never inspects initializer value
expressions for captures. The mutation walk likewise exempts
initializer expressions (except nested-literal interiors).

Reproducer: package `reg`: `var Err error; func Get() error { return
Err }` — Err object-closed (nil zero value). Package `user`: `var P =
&reg.Err` then `func init() { *P = &impl{} }` with `impl` a mutable
pointer-receiver error. The capture `&reg.Err` sits in an initializer
expression, so no audit arm sees it; the store `*P = &impl{}` is an
init-body store whose target subtree contains no interface variable
(`P` is `*error`), so `failTargets` finds nothing. No mutation, no
break — Err stays opaque, its escape through `Get` discharges, the
verdict is Valid while every holder shares a mutable `*impl` at
runtime.

Fix shape: run the address-capture (and range/indirect) fail arms over
package-level initializer value expressions exactly as over audited
function bodies — a `failTargets`-style walk of each ValueSpec value
for `&x` captures reaching interface package variables (nested
function literals excluded as program code, as everywhere).

Empirically demonstrated: a probe module of exactly this shape returns
a Valid verdict with no downgrade reason. The reproducer above is
complete — port it as the regression fixture when this lands.

Lands: cross-tool train chunk 32.
