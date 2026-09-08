# The consumers' vouch homes fold into the engine's file at their bumps

`Lands: pew's and stipulator's next gofresh bump past v0.99.0 (the
release carrying REQ-vouch-input's file channel); gomutant's arm closed
at its bump, cross-tool train chunk 163`

The engine now reads the repository's reviewed vouch set itself
(REQ-vouch-input: `vouches` at the root the engine is opened at, in
union with the option's set). Until each consumer bumps, three homes
coexist and the bump of each must hold "one set has one home":

- pew reads its store's `vouches` (REQ-pew-vouch-source, the store root
  named by `--bench-dir`) through its own copy of the grammar
  (`cmd/pew/vouchfile.go`, `parseDynamicStateVouches`); at its bump it
  either points its readers at the engine's file (the module root, not
  the store root — a spec change on pew's side) or passes its store set
  through the option with `WithoutRepositoryVouches`, and deletes the
  duplicated reader.
- gomutant's `--vouch` flags extend the file's set since its bump to
  v0.99.0 (chunk 163; its guidance says so); the fleet-sweep gatherer's
  mirrored flag list can go once the repository file carries the
  standing set.
- stipulator's policy-declared `DynamicStateVouches`
  (`GoInvocationConfig`) becomes a third home in union with the file at
  its bump unless the policy declines the file; its bump names which.
- `docs/fleet-sweep.md` describes the `vouches` file as pew-store-owned
  and wants one line once delegation lands.
