# Handoff — consume and delete

Written 2026-10-09 by the gofresh-root train session. This file and the
`handoff/` directory beside it are a one-time pointer for whoever merges
this work with the other agent's: read it, do or reassign what remains,
then delete both (`git rm handoff.md handoff/`). Nothing durable lives
here — the durable record is the commits, the plan
(docs/plans/cross-tool-train.md) and the issue docs named below.

## Landed today (all pushed)

- gofresh 315 closed: ac829b3 (the dst selection judged by content, its
  harness premise stated and keyed; released v0.114.0), 2297115 (the
  digest traversal and package walk check their context), 9afea00 (a
  moved-bracket root spelled under the members' rule; the exported
  idempotent re-key `runtimeinput.CanonicalMovedBracketClause`), tick
  db4dd31 (315 [x]; 338 chartered). CI green on all; 9afea00/db4dd31's
  release had not been observed at the handoff — check `gh release list`.
- godst 6a6db7c on greatliontech/godst main: the fork's test-log writer
  swallowed host write errors inside a simulation bubble (Write answered
  `len(p), nil`), so an exit-0 binary could carry a test log missing a
  block of records — the reason gofresh refuses to list the dst
  selections. Fixed: `dstHostStreamWrite` returns the first unabsorbed
  error with a prefix count, the test-log writer returns it (the buffered
  writer sticks, StopTestLog fails the binary as upstream does), the
  framework-stream callers drop it as before; pin
  src/testing/dst_testlog_test.go; test:dst runs package testing. Four
  review rounds; the fork's gates (test:untagged, test:api, test:dst,
  test:inert-diff) green locally.
- Riders filed: gomutant docs/issues/moved-bracket-root-clause-quoted.md
  (Lands 302 — the bump's load-time re-key calls
  `CanonicalMovedBracketClause`, never a copied predicate); gofresh
  docs/issues/attribution-splits-one-quoted-string-helper.md (Lands 243);
  gofresh docs/issues/godst-testlog-writer-swallows-write-errors.md
  (Lands 338 — the walk of the dst selection's moved keys, the digests).
- The evidence-model owner was told (pew's handoff doc, "315 input"):
  the listing premise sits in runtime-inputs' completion vocabulary.

## In flight: godst 338, the release

On greatliontech/godst: the matrix (run 37949379157) and ci on 6a6db7c
went GREEN at 15:32 UTC (every leg, both architectures); the release
commit a91cc85 (`chore(dst): VERSION go1.27.1-dst.14`, time
2026-10-09T15:32:42Z) and the annotated tag `go1.27.1-dst.14` are
pushed; the `release` workflow on the tag was running at the handoff
(~7 min; the release exists when its assets — the src and
linux-amd64/arm64 tarballs, the toolchain module files, SHA256SUMS — are
attached: `gh release view go1.27.1-dst.14 -R greatliontech/godst`). A
failed workflow is not a release: fix forward on main, cut dst.15.
Then:

4. Install it as the running build on every machine that runs the fleet:
   `task install` from the clone at the release commit (or
   `task install TARBALL=<the linux-amd64 asset>`); it flips
   `~/.local/godst/current` and rewrites `~/.local/bin/go`. Every gofresh
   pin that reads the host's build re-measures: the canary refuses until
   the new toolchain's rows are listed — do step 5 at once, before any
   other gofresh run on that machine.

## Next: gofresh 338, the re-listing (a release)

Design in handoff/design338.md. Under the new build:

- Print the new toolchain's rows with the canary: a throwaway worktree
  with `TestAuditedToolchainCoversRunningToolchain`'s `t.Fatalf` turned
  into `t.Errorf`, run `go test -run TestAuditedToolchainCoversRunningToolchain ./closure/`
  on the host (its four listed selections), then with
  `GOFLAGS=-tags=dst` and `GOFLAGS='-tags=dst -race'` for the two dst
  rows (ten / eleven keys: the 315 walk's set plus os/signal). Insert the
  printed digests into closure/toolchainaudit.go by chain inheritance —
  handoff/insertrows.py is the shape (a row gains a key only where its
  measured digest differs from what its Base chain carries); the root row
  `go1.27.1-dst.14` (Base none; every key moved off dst.13 — testing at
  least), its race / plan9/amd64 / cgo0 deltas, and `go1.27.1-dst.14 dst`
  (Base the root) / `go1.27.1-dst.14 dst race` (Base the race row).
- Apply handoff/edit338g.py from the gofresh root (anchors dry-checked
  against db4dd31): `listedSelection.Since` — the two dst entries carry
  `Since: "go1.27.1-dst.14"`; `demandedOf`/`godstCounter`; the canary
  skips a selection the running build is not asked to list (an older
  godst build; a stock build runs every selection); the pin
  TestDstSelectionIsJudgedByContentNeverByTag's godst arm: on a listed
  build both dst forms admit by the build's own dst row (closest ==
  version+suffix), on an older build they refuse with testing among the
  moved keys; the clause REQ-closure-observability-toolchain-key's
  parenthetical naming the release.
- Then: `stipulator pin --req REQ-closure-observability-toolchain-key`
  (re-consent), `stipulator compile`, the records view
  (`stipulator verify --no-test --view bindings`, every REQ row
  current+resolved), the closure tier whole, probes (demandedOf's counter
  rule; the pin's listed arm; a row digest flipped), a fresh reviewer per
  the doctrine, the commit chain's assertions, push — CI releases.
- Close-out: promote the walk's record from
  docs/issues/godst-testlog-writer-swallows-write-errors.md into the
  rows' comment (one line per moved key and its class; testing's delta is
  the fix itself, os/signal's its dst.go fence — re-walk both against the
  installed source), delete the doc and its README row (wrap-aware cite
  sweep first: the plan's 338 entry cites it), flip 338 [x] in the plan
  with the tag named, and tell the user the dst legs now serve.

## State to know

- The other machine may still run go1.27.1-dst.13: its gofresh canary
  stays green (the dst selections are not demanded of an older build);
  its dst legs stay refused until it installs dst.14.
- Lessons specific to the fork: tests of a std package run from
  `<clone>/src` under `GOROOT=<clone> GOTOOLCHAIN=local <clone>/bin/go`;
  gomutant's ephemeral probe cannot aim at a GOROOT tree (its oracle's
  `go` is the installed launcher) — mutants there are hand edits against
  the staged copy; `task test:inert-diff` needs
  `DST_STOCK_GOROOT=~/sdk/go1.27.1` when `go` on PATH is the dst launcher.
- Untriaged incoming for the next stipulator chunk open: stipulator
  80d41a4 docs/issues/discovery-exit137-memory-target.md (a bldc field
  report; `Lands: user decision` — derive it at the open).
- The lane after 338: gomutant 302, stipulator 226, gofresh 330, gomutant
  187, stipulator 249, gofresh 240 … (docs/plans/cross-tool-train.md's
  order sentence).
