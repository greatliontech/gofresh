# The fleet sweep's tugboat `--vouch` list: its stated retirement condition fired

Field report from tugboat (filed uncommitted in this tree, the
standing channel). `scripts/fleet-sweep.sh` (lines 38–48) carries
tugboat's standing pew vouch list by hand with the comment that it
"stays until tugboat's store carries benchmarks/vouches, at which
point it" retires. tugboat commit b62d299 (2026-09-29, pushed) lands
both file homes with the identical six-entry set:

- `benchmarks/vouches` — pew's home (REQ-pew-vouch-source: every
  judged verb over the store reads it; `--vouch` extends, never
  removes).
- `vouches` at the tree root — gomutant's home (execution.md's
  vouch-file clause, train chunk 246).

Entries: `github.com/zeebo/xxh3:key`, `pgregory.net/rapid:anyRuneGen`,
`go.uber.org/goleak:_osStderr`,
`google.golang.org/grpc:globalDialOptions`,
`google.golang.org/grpc:globalPerTargetDialOptions`,
`google.golang.org/grpc:globalServerOptions` — the audited set the
sweep mirrors today, byte-for-byte.

The mirror is now the second home REQ-pew-vouch-source names as the
drift hazard (an extra vouch in one copy suppresses a real
unverifiable verdict on that surface alone). tugboat has not yet
observed a judged run reading the files (its first whole-store
`pew status` and first campaign of the resumption are the
confirmation, this week); the sweep's next run over tugboat is the
same confirmation from this side — if the store's `pew-vouches`
audit row carries the six identities with the flag list removed, the
list retires; if not, the file is not being read and that is a pew
field report.

Lands: awaiting triage (the script's own condition; the sweep's next
tugboat run is the check).
