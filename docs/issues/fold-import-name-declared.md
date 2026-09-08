# The file fold binds an unnamed import to its path, not its declared name

The maximal tier's per-file scan is syntactic: it binds an unnamed
import to an identifier derived from the import path — the last
element, past a trailing major-version element since chunk 117
(math/rand/v2 binds rand). A package whose declared name differs from
its path in any other way — a dotted last element (gopkg.in/yaml.v3
declares yaml), a renamed package clause — binds the wrong identifier,
so its selectors resolve to no package and the fold classifies nothing
for them; the subject walk, which has type information, still
classifies every reach the subject makes, so the hole is the fold's
sibling-declaration backstop alone, and today no importable package in
the classified or always-external sets carries such a name (the
standard library's one dotted-version path, crypto/internal/entropy/v1.0.0,
is internal and never folded; the fold's binding rule is pinned against
every importable standard package's declared name). The derived
name binds only as a secondary where no import binds it as a primary
and no second import derives it, so a misderived name can hide a
classification only when nothing else spells that identifier; two
unnamed imports whose last elements coincide refuse the file
fail-closed — the language forbids the clash when both declare their
last element, and the fold cannot tell that case from two renamed
package clauses (`a/client` declaring aclient beside `b/client`
declaring bclient — legal, pure, refused). Reading the declared name
from the listing removes this whole family.

Fix shape: the fold reads the declared name from the loaded package
(the listing already carries each import's package clause), or the
walk tier supplies the name map — either way one source, never a
second path-shape rule.

Lands: when a classified or always-external package's declared name
differs from its path's last element (a toolchain or dependency
change the audited-set audit walks), or with the next maximal-tier
change.
