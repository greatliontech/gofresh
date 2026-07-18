# ForTest keying misattributes intermediate recompiled dependencies' subjects

**Status:** open. Filed 2026-07-18 while auditing variant handling in the
subject scan.

## Fault (demonstrated mechanism)

`go list -test` sets `ForTest` on every package recompiled for a test
binary, not only on the two packages that hold the test files. For a
package `a` whose external test imports `r`, and `r` imports `a`:

```
example.com/m/a [example.com/m/a.test]        ForTest: example.com/m/a
example.com/m/r [example.com/m/a.test]        ForTest: example.com/m/a   <-- intermediate dep
example.com/m/a_test [example.com/m/a.test]   ForTest: example.com/m/a
```

(verified against go1.26 `go list -test -deps -json`; go/packages copies the
field verbatim.)

`purity.go`'s subject scan keys a visited package by `ForTest` whenever it
is non-empty, intending "a test variant declares subjects of the package
under test". That is true for `a [a.test]` and `a_test [a.test]`, but not
for `r [a.test]`: it declares subjects of `r`. A scan requesting **only
`a`** already fails: `r [a.test]` sits in the visited import graph of
`a_test [a.test]` regardless of what was requested, `ForTest` keys it to
`a`, and `requestedPackages["…/a"]` admits it, so every declaration in `r`
is recorded as a subject of **`a`**:

- `known[{a, G}]` becomes true for a symbol `a` never declares, and
- when `a` declares a symbol with the same name as one of `r`'s — with the
  module shape above, `ScanPureDirectivesIn(dir, "example.com/m/a")` and
  `G` declared in both packages — the two file:offset keys differ and the
  scan hard-fails the whole request with `gofresh: ambiguous subject
  example.com/m/a.G resolves to …/a/a.go:… and …/r/r.go:…`, exactly as if
  two real declarations collided.

## Root

`ForTest != ""` is not "this variant's declarations belong to the package
under test"; only the in-package variant (`PkgPath == ForTest`) and the
external test package (the `pkg_test` package of `ForTest`) satisfy that.
Intermediate recompiled dependencies carry `ForTest` too and must keep
their own `PkgPath` identity.

**Lands:** when a requested package's test binary recompiles any
dependency (an `r [p.test]` variant in the visited graph) and that
dependency's declarations must stay attributed to their own package —
a single requested package whose external test imports a dependency that
imports it back suffices to trigger the fault.
