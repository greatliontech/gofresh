# The two attribution splits could share one quoted-string-then-tail helper

Lands: docs/plans/tooling-redesign.md 5.6.

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
same filing's second item once they cannot. Preserve both historical bare-root
handling and canonical re-key idempotence; sharing a quoted-string primitive
does not make the two attribution tails interchangeable.
