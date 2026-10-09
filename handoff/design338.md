# 338 — godst's test-log writer propagates write errors; a build; the dst rows re-listed

## The fork (greatliontech/godst, main = the go1.27.1 line; latest release go1.27.1-dst.13)

Change set 1 (staged, in review): src/testing/dst_hostio.go — dstHostStreamWrite
returns (written, err); the framework-stream callers drop it; dstTestlogWriter's
in-bubble leg writeFromBubble returns it; the pin dst_testlog_test.go.
Evidence: make.bash over the staged tree; `go test -tags dst ./testing/` pins +
untagged short green; four hand mutants killed (p338/); the whole testing tree
under both modes (m338/t3, t4).

The release, per docs/dst/releases.md "Cutting a release":
1. push the fix to main (the `ci` smoke workflow runs, ~20 min);
2. dispatch the `matrix` workflow on main (`gh workflow run matrix.yml -R
   greatliontech/godst --ref main`; ~15 min); a red leg blocks;
3. the release commit on top: VERSION = `go1.27.1-dst.14` + `time <RFC3339 now>`
   (N = 1 + max over every *-dst.* tag — 13 → 14), subject `chore(dst): VERSION
   go1.27.1-dst.14`;
4. `git tag -a go1.27.1-dst.14 -m …` on it; push main and the tag; the `release`
   workflow attaches the assets (~7 min); a failed workflow is no release.
5. Install here: `task install` from the clone at the release commit (builds
   with make.bash -distpack, validates, flips ~/.local/godst/current, writes the
   launcher) — or `task install TARBALL=<downloaded asset>`. The fleet's running
   build becomes go1.27.1-dst.14: EVERY gofresh pin that reads the host's build
   re-measures (the canary refuses until the new toolchain's rows are listed —
   the gofresh change set below lands immediately after, before any other run).

## gofresh (change set 2, a release)

The canary under go1.27.1-dst.14: the root row (every key that moved off dst.13 —
testing at least, plus whatever dst.14's VERSION/time stamping moves: none in
src), the race / plan9 / cgo0 rows for the new toolchain, and NOW the dst
selections listed: listedSelections gains {" dst", -tags dst} and {" dst race",
-tags dst -race} (310's withdrawn entries), the two delta rows over the new
root ("go1.27.1-dst.14 dst" Base "go1.27.1-dst.14": the ten keys; "… dst race"
Base "… race": the eleven) — their digests the canary's prints; the walk's
record in docs/issues/godst-testlog-writer-swallows-write-errors.md covers the
keys whose digests equal the walked ones (os/signal, testing move with the fix:
re-walk them — testing's delta is this very fix (the writer's return), os/signal
unchanged unless the build moved it).

The clause: REQ-closure-observability-toolchain-key's premise sentence stands
(the listing asserts it; the fork now satisfies it); the row comment records
the fix that made the listing possible (the tag).

The pin TestDstSelectionIsJudgedByContentNeverByTag: its godst arm asserted
REFUSAL with testing moved — under a build whose dst selection IS listed, the
arm must flip: a godst build whose dst rows are listed admits both forms by
its own dst rows (closest = root+" dst" / root+" dst race"); an unlisted godst
build refuses naming testing. The arm decides by the running build's listing
(movedKeys over the dst selection: empty → the listed arm, else the refusal
arm asserting testing among the moved keys). The stock arm unchanged.

The issue docs/issues/godst-testlog-writer-swallows-write-errors.md: deleted
at the gofresh close-out (Lands 338 met) — its walk promoted into the rows'
comment (the keys and their classes, one line each) per promote-then-delete;
the plan's 338 entry [x]; 338's tick names the release tag and the gofresh
release.

Order: fork change set → review → push → matrix → release commit + tag →
release workflow → install → gofresh change set → review → push (release).
The dst.13 build stays installed under ~/.local/godst/go1.27.1-dst.13 (the
install keeps versioned prefixes); the gofresh rows for dst.13 stay listed.
