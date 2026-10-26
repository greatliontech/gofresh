# Fleet sweep provenance check reads an install path the tools have left (fleet sweep 2026-10-26)

The weekly fleet sweep's binary-provenance section reports every tool
binary as `NO BINARY installed` — gomutant, pew and stipulator alike —
while the same sweep's preflight found all three on PATH and its
findings-store, check and pew sections ran them to verdicts. The
gatherer (`scripts/fleet-sweep.sh`, the provenance loop) stats a fixed
`~/go/bin/<tool>`; the installed binaries are
`~/.local/bin/{gomutant,stipulator,pew}` (Go ELF executables, not
wrappers), and `~/go/bin` now carries third-party tools only. The
2026-10-19 sweep read all three from `~/go/bin` (gomutant
1e5ff06fbff3 match, pew 7683672d6e03 SKEW, stipulator 1f90e1479658
SKEW), so the install destination moved between the two sweeps.

Two consequences. The provenance fact itself — installed vcs.revision
against the repo's last build input, plus the dirty-build stamp — is
unmeasured for every tool while the paths disagree; the SKEW the
2026-10-19 sweep reported for pew and stipulator is neither confirmed
nor cleared. And the gatherer renders the unreadable path as a
per-tool red fact rather than a NOT MEASURED line, the inversion the
sweep's three-valued vocabulary exists to prevent: a tool the
preflight proved present cannot be an estate red for being absent.

Fix shape: resolve each binary the way the preflight and the sections
already do (`command -v <tool>`, or `go env GOBIN` with the
`$GOPATH/bin` fallback — one resolution, not two), and render a tool
on PATH whose path the stat cannot read as NOT MEASURED. The
runbook's standing response to a provenance SKEW (`go install` in the
named repo) stays the response once the line can read again.

Lands: 2.1 (the canonical plan, `docs/plans/plan.md`) — the plan's
next chunk and the first consumer rebuilt on the new foundation; the
provenance line is how the sweep verifies that install, and it cannot
read match until the gatherer looks where `go install` puts the
binary. An earlier gatherer fix closes it sooner. Closing
observation: the provenance section naming a revision for all three
tools.
