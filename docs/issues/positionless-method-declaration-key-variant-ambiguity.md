# Position-less methods get build-variant-dependent declaration keys — spurious ambiguous-subject failure

**Status:** open. Filed 2026-07-18 from a consumer integration (pew
recording protodb's `internal/db` benchmarks).

## Fault (demonstrated)

`pew run ./internal/db` in
`github.com/greatliontech/protodb` fails the whole package:

```
gofresh: ambiguous subject
github.com/greatliontech/protodb/internal/db.RetryableError.Error
resolves to github.com/greatliontech/protodb/internal/db:func (error).Error() string
and github.com/greatliontech/protodb/internal/db [github.com/greatliontech/protodb/internal/db.test]:func (error).Error() string
```

Reproduced with gofresh v0.10.4. Minimal shape: a package whose
top-level scope holds a type (or alias) whose method set includes a
method declared with NO source position — the canonical case is a
universe-interface method promoted through embedding:

```go
package p

type E = interface { error }   // or: type T struct { error }
```

plus any in-package `_test.go` file, analyzed with
`packages.Config{Tests: true}`.

## Diagnosis

`purity.go`'s subject scan records every method-set member with a
declaration key (`record(subject, objectDeclarationKey(p, method))`)
and treats two differing keys for one subject as ambiguity. For an
object with a real position the key is `file:offset` —
build-variant-independent. But the universe `error` interface's
`Error` method carries `token.NoPos`, so `objectDeclarationKey` falls
to its fallback branch, `fmt.Sprintf("%s:%d", pkg.ID, obj.Pos())` —
and under `Tests: true` the SAME source package is visited twice with
DIFFERENT IDs (`pkg` and `pkg [pkg.test]`). One source subject, two
keys, spurious hard failure of the whole package.

## Fix shape

Make the fallback key build-variant-independent: key position-less
objects by something stable across variants — e.g.
`pkg.PkgPath:obj.Pos()` (genuinely different declarations in real
files always take the `file:offset` branch, so the ambiguity guard's
power is preserved), or a dedicated `universe:<name>` key for objects
in `types.Universe`. `nodeDeclarationKey`'s identical fallback gets
the same treatment for symmetry (its AST nodes always have positions
in practice, but the two helpers should not diverge).

**Lands:** before a consumer package holding an embedded-`error` (or
any universe-method-bearing) top-level type can be analyzed with
`Tests: true` — concretely, pew recording protodb's `internal/db` is
blocked on exactly this
(protodb `docs/issues/2026-07-18-pew-baseline-recording-blocked.md`).
