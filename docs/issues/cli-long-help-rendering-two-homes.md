# Pew's CLI long help omits the shared prose pointer

A knobbed CLI verb's shared long-help projection is the registration's
knobless help followed by its prose pointer. Gomutant and Stipulator already
read that projection. Pew's `cmd/pew/guidance.go` still returns
`GuidanceRegistration("cli", verb).Help`, and its guidance pin compares the
Help-only form. The residual is the missing pointer, not a join still copied
in all three consumers.

Registration.LongHelp is the one rendering (the help, a blank line,
the prose pointer; the help alone on a Document's own projection).

Lands: docs/plans/tooling-redesign.md 8.3.

Make Pew's renderer and its drift pin read the shared long-help projection,
with a literal pointer anchor. This is separate from the adopted Coverage lint
and the remaining local default and served-string grammars.
