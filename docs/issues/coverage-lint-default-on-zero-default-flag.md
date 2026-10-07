# The CLI coverage lint is silent on a default parenthetical over a zero-default flag

`guidance.Document.Coverage` on the cli surface refuses a knob that spells
"default" outside the `(default …)` form when the registered flag prints a
non-zero default (the registration's fact). The other case is unjudged: a
knob carrying a `(default X)` parenthetical on a flag whose default is
pflag's zero — cobra prints nothing there, and `Knob.Usage` drops the
parenthetical unconditionally, so the served usage loses the default and
any prose packed into the same parenthetical with nothing printed in its
place (stipulator's two `--backend` knobs, `(default go; a claim's defaults
to the call's)` on nil string arrays, found at stipulator 272's projection
fold; both reworded there). The rule the served string needs: a
`(default …)` form belongs only on a flag whose registration prints one.

The gofresh half landed at cross-tool train chunk 300 (2026-10-07):
the rule the served string needs is Coverage's zero-default arm.

Lands: the consumer bumps reading gofresh's 300 release — stipulator
290r, gomutant 324, pew 320 — where each coverage binding runs the
amended judgment over its document.
