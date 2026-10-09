# The two attribution splits could share one quoted-string-then-tail helper

Lands: 243 (the vestigial/dead sweep — a fold of two parsers onto one shape).

Surfaced by the review of chunk 315's third change set (2026-10-09).
`splitBracketAttribution` (the moved-bracket reason: a quoted root
consumed whole as one Go quoted string, then exactly ` [<list>]` to the
end) and `splitAttribution` (the ` — ` path: the operation, its quoted
name and its quoted directory, or the recorded path's quoted spelling
and quoted target, to the end) each parse "a Go quoted string, then
exactly this tail" by hand; `quotedThen` already has that shape for the
latter. One helper over `strconv.QuotedPrefix` with the tail as its
argument would make the two splits one grammar with two tails. The
bare-root scan's iteration past the first ` [` (the prefix loop) serves
only reasons composed before roots were quoted; it stays while such
reasons can reach the split (a consumer's stored clause), and is the
same filing's second item once they cannot.
