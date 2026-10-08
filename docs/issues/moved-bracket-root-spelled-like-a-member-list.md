# A moved-bracket root whose own name parses as a labelled member list collides with the root before the segment

Lands: cross-tool train chunk 315 (gofresh's next release; a rider: the
one composer and its pin)

REQ-inputs-refusal-attribution's moved-bracket split is prefix-first:
the clause ends at the first ` [` whose suffix parses as a labelled
member list. A member whose own name carries the list's framing travels
quoted (memberListName), so the split holds there — the clause's
recorded residual is a MEMBER garbled the same on both sides of a
consumer's match. The ROOT is spelled unquoted (bracket.go's
`root.id.displayPath()`), so a bracket root directory named like a
labelled list — `fix [added: x]` — splits to `observation bracket
moved: fix`: a consumer's entry naming the real root is refused at load
(it carries the form) while an entry for the sibling root `fix` accepts
the move — an asymmetric collision onto another root's clause, not the
symmetric garble the clause records. Found by gomutant 324.A's review
(the exemption record's match keys on the clause).

The derivable remedy: spell a root display path that carries the list's
framing quoted, as members are (one quoting rule over the root and the
members), so the split never reads a root's own segment as the list;
the clause's residual sentence then covers the root by the same rule.
A pin: a root named `fix [added: x]` moved → the clause keeps the
root whole; the sibling root's clause differs.
