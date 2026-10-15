# net/url's parsing operations read GODEBUG, which no code-result guard pins

`url.Parse`, `ParseRequestURI`, `ParseQuery`, `JoinPath`, and the URL
methods `Parse`, `Query`, and `UnmarshalBinary` reach the package's
two GODEBUG settings (`urlstrictcolons` through `parseHost`,
`urlmaxqueryparams` through `parseQuery`), read through the runtime's
debug registry. The runtime-config guard captures GODEBUG for a
timing result only (REQ-guard-runtimeconfig; `guard/guard.go`'s
code-result capture and compare skip it), and the registry is
re-derived in-process by any `Setenv("GODEBUG", …)`, which a sibling
subject can perform under a bracket that never sees it. So the
parsing half of net/url stays refused while the escaping and
composition half is admitted by symbol; the historical report's
`url.Parse` — the field's ~23 refusals — is not lifted.

The recorded reproduction: `url.ParseQuery("a=1&b=2")` yields two values under the
default and an error under `GODEBUG=urlmaxqueryparams=1`, with every
code-result guard unchanged between the two processes.

Two candidate mechanisms require a complete authority argument:

1. GODEBUG joins the code-result guard (`buildConfigOSEnvKeys` or a
   new key of the runtime-config guard captured for CodeResult) —
   sound against the process-level channel; the in-process Setenv
   channel then needs a poisoning rule: a package whose subject
   mutates GODEBUG marks every GODEBUG-reading admission in the
   binary, the shared-dynamic-state shape one level down.
2. The effective settings ride the observation bracket as a recorded
   input (the value each admitted read observed), so a moved setting
   stales the record like any observed input.

REQ-guard-runtime-relevance already requires behavior-affecting runtime
configuration to be accounted for in a code result. Derive the implementation
from that contract, including in-process mutation and shared-process scope;
neither a start-of-process environment comparison alone nor an unobserved
effective setting licenses admission. The parsing operations remain refused
until that authority exists. The report's count does not make this a product
decision or justify a blanket parsing admission.

Lands: docs/plans/tooling-redesign.md 7.8.
