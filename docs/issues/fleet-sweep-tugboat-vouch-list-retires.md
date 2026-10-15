# Retire the fleet sweep's duplicate Tugboat vouch list

Field report from tugboat: `scripts/fleet-sweep.sh` carries
tugboat's standing pew vouch list by hand with the comment that it
"stays until tugboat's store carries benchmarks/vouches, at which
point it" retires. tugboat commit b62d299 (2026-09-29, pushed) lands
both file homes with the identical six-entry set:

- `benchmarks/vouches` — pew's home (REQ-pew-vouch-source: every
  judged verb over the store reads it; `--vouch` extends, never
  removes).
- `vouches` at the tree root — gomutant's home (execution.md's
  vouch-file clause).

Entries: `github.com/zeebo/xxh3:key`, `pgregory.net/rapid:anyRuneGen`,
`go.uber.org/goleak:_osStderr`,
`google.golang.org/grpc:globalDialOptions`,
`google.golang.org/grpc:globalPerTargetDialOptions`,
`google.golang.org/grpc:globalServerOptions` — the audited set the
sweep mirrors today, byte-for-byte.

The six-entry file exists in Tugboat's store. The mirror is the second home
REQ-pew-vouch-source names as a drift hazard: an extra acceptance in one copy
can suppress a refusal on that surface alone. Confirm the effective standing
set through a non-measuring judgment with the flags omitted, then retire the
script's duplicate list. File presence is source evidence, not a claim that
such a no-flags confirmation has run. No benchmark or campaign is needed to
answer which trust source the selected store reads.

Lands: docs/plans/tooling-redesign.md 7.3.
