# A build selection whose tags constrain no standard-library file is refused as unwalked

The toolchain audit lists, per Go release, the selections whose
standard-library delta was walked (the empty selection and `race`);
any other tag set is refused as unwalked — observation admissions
disabled, proofs stripped, serving degraded to execution — until its
delta is walked and listed. A tag that appears in no build constraint
under GOROOT/src has an empty delta by construction: the standard
library compiles to the same files with or without it. gomutant's
`integration` tag (its own test suites' selection, chunk 284) is one:
measured 2026-09-30, zero files under GOROOT/src of go1.27.0-dst.14
carry an `integration` constraint, yet `-tags=integration` is refused
and gomutant's integration campaign cannot serve.

The derivation: a selection whose every tag is absent from the
standard library's build constraints (a scan of `//go:build` lines
and `_GOOS`/`_GOARCH`-style name suffixes under GOROOT/src, memoized
per toolchain) is admitted with the base selection's audit; a tag any
standard-library file names keeps the listed-or-refused rule. The
selections axis in closure/toolchainaudit.go and its refusal message
gain the derived arm; REQ-closure-toolchain-audit (or the clause that
states the listed-selection rule) is amended to state it.

Lands: cross-tool train chunk 303 (chartered at 284's tick; a
release — gomutant's integration campaign and any consumer's private
tag read it at their next bump).
