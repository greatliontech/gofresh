# A dependency package's nested closure is outside the object drain's scan

The subject tier's object drain scans a referenced initializer's
content — a first-party function reached by value, its nested closures
now included (the value scan walks an anonymous function's body when
it meets it). A dependency package's function reached the same way is
refused by the drain's package-class filter before that arm: its
nested closure's effects are never scanned by the drain, exactly the
first-party shape the narrowed-dispatch chunk fixed, one package class
over. Nothing is unsound today — a dependency's content is judged by
its own persisted facts and the resolution-by-operand route excludes
the class — but a dependency's closure reached only by reference keeps
its effects unseen by the subject tier.

The fix shape is a design question, not a one-line arm: whether the
drain should scan dependency bodies at all (the pinned-package facts
are the dependency tier's judgment, and walking standard bodies is
deliberately refused), or whether the dependency facts should carry a
per-function effect summary the drain consults for a referenced
function. Hoisting the scan above the class filter would walk standard
bodies the design leaves unwalked.

Lands: cross-tool train chunk 192
