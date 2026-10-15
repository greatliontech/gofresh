# A runtime-input classification names `/` for every subject while the input list is empty

Lands: docs/plans/tooling-redesign.md 8.3.

The remaining request is truthful diagnostic attribution of the call that
opened `/`. The test-log vocabulary records open/stat/chdir, not the purpose
of an open: a directory opened for sync and one opened for listing cannot be
distinguished from that operation alone. Keep the classification fail-closed.
A caller-frame capability needs an actual harness/toolchain implementation;
a sorted manifest's neighbours cannot identify the caller or reconstruct log
order. Diagnose the native observation separately from any consumer's copied
refusal on a record with an empty manifest.

Attributed occurrence (protodb, 2026-10-02, the standing channel): a
campaign over protodb's clean tree disqualified all 54 machine-local
records across internal/db, raftstore, tugboat and raftboot with
`runtime-unverifiable evidence: external directory input: /; attributed
to open "/" in <package dir>` — the attribution 259 added names the
operation (open) and the process's directory, and protodb finds no
`os.Open("/")` in its code: a directory sync walking up to the root, or
a library's statfs/openat of `/`, are the candidates. What the report
asks for is the CALL that opens `/`. The testlog carries no caller PC,
so the call-site request requires additional provenance. The candidates in
the report are hypotheses, not a demonstrated source of the logged open.

Earlier investigation recorded no operation resolving to `/` in pb's plain
test-log runs. An archive-only ExtractZip campaign instead went machine-local
on a moved bracket and a dirty stamp; the derived-union campaign stalled in
freshness proofs. Gomutant's divergence stamp could copy one target-side
reason onto every evidence subject while leaving their manifests empty. That
separate record-attribution case is filed in Gomutant as
`divergence-reason-stamped-on-every-evidence-subject`.

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

That record shape does not prove the classifier consumed an empty manifest
and invented `/`: the consumer's divergence attribution can copy a reason
without copying the corresponding manifest. REQ-inputs-refusal-attribution
now separates comparison identity from diagnostic attribution. Preserve that
separation when improving the account, and reproduce the exact producing
record path before attributing the old empty-manifest report to the classifier.
