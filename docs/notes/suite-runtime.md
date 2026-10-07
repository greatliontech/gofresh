# Full-suite runtime investigation

The root and closure packages exhausted the 30-minute plain-test package budget
while individual tests continued to complete. Preserving the compiler cache
selection separately from the isolated proof cache allowed the complete plain
suite to pass within that budget. No timeout or test selection was weakened.

## Reproduced workload

Two tests active when the full run timed out complete independently:

- `TestProvenInitFlowStoresAuditedForObjectClosure`: seven temporary-module cases.
- `TestAttributedAnalysisCoversGenericMethods`: tier-2 analysis followed by
  observability analysis of the generic-method fixture.

Diagnostic CPU/allocation profiles were captured with `go test`, outside
Stipulator, under shared machine coordination. They are attribution runs, not
quiet statistical performance recordings. Profile data and matching binaries
were taken under a scratch directory that did not persist; re-measure before reading them.

## Evidence

The root test's initial run took about 9.74 seconds with 1.17 seconds of parent
CPU samples. Its allocation profile attributed about 210 MB of 331 MB to file
reads, dominated by repeated standard-library source-digest work. Parent profiles
do not include the CPU consumed by child Go commands.

The closure test's initial run took about 13.19 seconds with 6.64 seconds of parent
CPU samples and about 1.24 GB of allocation. Type checking, SSA construction and
GC dominate; the test performs two distinct whole-program analyses.

Both package test mains isolate gofresh proofs by changing `XDG_CACHE_HOME`.
Without an explicit `GOCACHE`, that also changes the child Go tool's compiler
cache. A diagnostic intervention setting `GOCACHE` to the native selection before
the test main changes XDG retained every test assertion and reduced the observed
runs to about 5.80 and 5.17 seconds respectively. These single observations support
the cache-isolation mechanism; they are not statistical improvement claims.

## Correction and remaining checks

The test harness now pins the effective Go build cache before isolating the
gofresh proof cache. Explicit caller cache selection is preserved; absent
selection is resolved by Go, not guessed from a host path. Gofresh's own proofs
remain isolated, including tests that select another private XDG root.

With the correction, `go test -json -count=1 -timeout=30m ./...` completed:
the root package took 1009.485 seconds and closure took 1244.920 seconds.
The unchanged short-suite and vet checks also passed. These full-suite times
are diagnostic observations under shared machine coordination, not statistical
performance claims.

Repeated content hashing is required by the
source-audit contract and cannot be replaced by metadata-only reuse. Live heap
retention is not established by an allocation profile. Cancellation gaps in
source hashing/index traversal are separate from these background-context tests
and need their own causal verification before a production change.
