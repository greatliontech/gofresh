# A runtime-input classification names `/` for every subject while the input list is empty

Lands: cross-tool train chunk 292 (its open triages
this — the trigger below FIRED 2026-10-02).

Attributed occurrence (protodb, 2026-10-02, the standing channel): a
campaign over protodb's clean tree disqualified all 54 machine-local
records across internal/db, raftstore, tugboat and raftboot with
`runtime-unverifiable evidence: external directory input: /; attributed
to open "/" in <package dir>` — the attribution 259 added names the
operation (open) and the process's directory, and protodb finds no
`os.Open("/")` in its code: a directory sync walking up to the root, or
a library's statfs/openat of `/`, are the candidates. What the report
asks for is the CALL that opens `/`. The testlog carries no caller PC,
so the call site is either a godst/toolchain question (a caller frame
on the logged operation) or a gofresh diagnostic over the manifest's
neighbours (the operations logged just before the `/` open, bounded) —
292's open decides which, and whether an open of `/` by a directory
sync (an openat on the parent chain) is an input at all.

Former trigger: the next report of this reason carrying its attribution — 259 landed
REQ-inputs-refusal-attribution (a classification refusal names the harness
operation, its quoted logged name, and the quoted working directory it
resolved in, after a ` — ` separator; RefusalClause is the consumer's
split), so the next record reads `external directory input: / — open "/" in
"<package dir>"` or names the traversal; the `/` itself did not reproduce at
259's open (pb's every package, run plainly with a test log, logs no
operation resolving to `/`; a campaign over ExtractZip with an archive-only
oracle went machine-local on a moved bracket and a dirty stamp — gomutant
258's shape — and the derived-union campaign stalled in freshness proofs —
gomutant 257's shape), and gomutant's divergence stamp — one target-side
reason copied onto every evidence subject with the manifests left empty, the
report's two "impossible" facts — is filed in gomutant
(divergence-reason-stamped-on-every-evidence-subject, Lands 258).

Field report (greatliontech/pb, gofresh v0.102.0 through gomutant
v0.57.11-0.20260919151557-ee9616fd4b7b, and v0.99.0 before it): a
campaign over `internal/archive.ExtractZip` and `writeMember` (a
union over 486 subjects) leaves every one of the record's 243
evidence subjects — the target's and every oracle's — with
`runtimeReason: "external directory input: /"` and
`runtimeInputs: ""`, so the record is runtime-unverifiable and stays
machine-local. A syscall trace of the same tests (`strace -f`, every
syscall, the extraction tests selected) touches no path named `/`;
the tests' scratch is a declared namespace under
`internal/archive/testdata/scratch`, gitignored, and the tree is
clean.

The classifier (`runtimeinput.classifyPath`, the "external directory
input" arm after `relUnder` fails and `classifyProbe` finds a
directory) is being handed the literal `/` for subjects whose input
manifest is empty — an origin the record does not carry, so the
consumer cannot say which observation, environment form, or default
produced it. Expected: a runtime input names the observation that
produced it, and an empty manifest classifies as no input, never as
the filesystem root.
