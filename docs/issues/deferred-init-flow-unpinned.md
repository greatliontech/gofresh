# "A deferred init call stays init flow" is implemented but unpinned

The spec's init-only class keeps deferred calls in init flow ("a
deferred init call stays init flow"). The implementation satisfies
this implicitly — the reference-region scan does not intercept
`DeferStmt`, so a deferred call inherits the enclosing region — but no
test exercises a `defer helper()` registration, so the behavior is one
refactor away from silently flipping (an explicit `DeferStmt` arm
added for any other reason would likely poison it). Pin it: a fixture
where an initializer-driven function defers the registering helper and
the subject stays Valid.

Lands: cross-tool train chunk 32.
