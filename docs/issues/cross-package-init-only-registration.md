# Exported registration constructors refuse per-package init-only proof

The field's registration pattern is an exported generic constructor
(`func NewKey[T any](name string)`) mutating a package registry, called
exclusively from sibling packages' package-level initializers. The
init-only-reachable helper class is deliberately per-package and
refuses exported functions - any package could call one at runtime -
so the whole corpus keeps the downgrade through one provable-in-fact
startup pattern.

Mechanism (the chunk-22 fixed point lifted to composition): mutation
facts attribute each mutation to its enclosing function; every fact
additionally records, per foreign function it references, whether all
its references are init flow (initializer expressions, init bodies,
and functions themselves proven init-only) or any is program code;
composition runs the init-only fixed point over the whole graph - a
mutation inside a function every package proves reachable only from
init flow is startup-deterministic exactly as chunk 22's in-package
class. Fail-closed on any value reference, go-statement callee, or
program-code caller anywhere; fact-strategy bump.

Lands: cross-tool train chunk 25.
