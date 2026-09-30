# The dst-selection walk's trigger fired: tugboat's first judged run over a dst-tagged selection (2026-09-29)

Field report from tugboat (filed uncommitted in this tree, the
standing channel). `walk-dst-selection-for-audit-key.md` carries
`Lands: with the first judged run over a dst-tagged build selection
(tugboat DST-leg campaigns are the first candidate — currently paused
with the tool phase ...)`. The pause lifted 2026-09-29 and the first
run happened: `stipulator check` over tugboat's accepted policy
(three invocations — `dst` with `-tags dst`, `dst-race` with
`-tags dst -race`, and plain `race`) under the installed toolchain
go1.27.0-dst.14 (gofresh v0.107.0-era binaries, rebuilt 2026-09-29).

What the run printed, verbatim, on the unaudited-toolchain face (twice
at compile, once more at discovery):

    gofresh: toolchain-unaudited — toolchain-selection audit: selection "dst" under go1.27.0-dst.14 is unwalked — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution) until the selection delta is walked and listed (closure/toolchainaudit.go)
    gofresh: toolchain-unaudited — toolchain-selection audit: selection "dst,race" under go1.27.0-dst.14 is unwalked — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution) until the selection delta is walked and listed (closure/toolchainaudit.go)

The refusal is sound and loud — exactly what train chunk 126's
two-axis key promised — and the cost it names is now the consumer's
steady state: `executing dst-race: 1073 subjects in 18 packages` and
`executing dst: 1069 subjects in 18 packages` re-execute on every
check with no observation proof to serve from; only the plain `race`
invocation (1023 subjects; `go1.27.0-dst.14` lists `""` and `"race"`)
can ever be served. tugboat's own cacheability work
(stipulator-policy-vouch-set: the standing vouch set entering the
policy) can only be measured on that one invocation until the walk
lands — the dst legs are its DST tier, the half of the corpus the
policy exists for.

Selections to list, per the existing doc: `dst` and `dst,race` for
the flavor installed when the chunk opens — the table is keyed per
release, so a listing under one flavor helps no host on another
(`go1.27.0-dst.15` as of 2026-09-30; ~/.local/godst carries
dst.10–dst.15, `current` → dst.15). The walk's scope is the existing
doc's (time/dst_tz.go, testing/dst_hostio.go, sync's dst-and-race
hook seam, the os fault-injection surface — dst.15's delta over
dst.14, a flock's release deferred to the last shared mapping in
os/dst_fs.go, dst_flock_linux.go and dst_mmap_linux.go, lies inside
it).

Lands: cross-tool train chunk 297 (the dst-selection walk, chartered from this
report at chunk 289's record; this report fires walk-dst-selection-for-audit-key's
trigger — the two are one work item and land together).
