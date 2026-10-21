# Full-suite runtime investigation

## Retaining gate timings

The existing full-test task accepts additional Go test flags after `--`. For a
required full gate, set `GATE_TIMINGS` to a writable file outside the checkout and
retain timing events from that same execution:

```sh
task test -- -json > "$GATE_TIMINGS"
```

This adds no test execution and preserves the ordinary full-suite population,
count and timeout. Rank top-level test completion events separately from subtests;
adding both double-counts nested work. Package elapsed times are separate totals,
not the sum of concurrently running packages. Retain the raw events, selected
toolchain and command beside any summary. These wall times include subprocess and
scheduling waits. Parent CPU/allocation profiles require separate interpretation:
they do not attribute child Go-command CPU, and cumulative allocation is not live
heap retention. Use detailed profiling for measured dominant or regressed work,
rather than adding a profiling run to every changeset.

## Assembly-validation allocation

An October 2026 attribution run over the closure package at `2e04355` recorded
777 passing top-level tests. The process-wide CPU profiler conflicted with
`TestPGOBuildCopiesRetainImportBindings`, which starts its own real PGO profile;
that test failed before its workload ran. The run is profiling evidence, not a
passing full gate or a comparable complete workload. Ordinary full-gate timing
collection therefore uses JSON alone; CPU profiling should target compatible
workloads. The preceding uninstrumented full gate passed.

The parent profile sampled approximately 330 GB of cumulative allocation and
attributed about 35.5% of parent CPU samples to `runtime.gcDrain`. Type checking,
parsing and SSA construction were substantial separate costs. Assembly-input
observation accounted for approximately 46 GB of cumulative buffer allocation,
including repeated validation of already-retained contents. These figures do not
measure retained memory or child Go-command CPU.

Validation now compares each reread block directly with the retained observation.
It still reads the complete file, compares every byte, checks identity and path
resolution, performs before/after stat checks, and preserves watcher boundaries,
cancellation and cumulative read accounting. Initial acquisition still owns the
bytes needed by its consumers. No content check was replaced with metadata reuse
or a digest assumption.

Five one-second repetitions of `BenchmarkInputValidation` before and after the
change, under exclusive benchmark coordination with Go 1.27.1 on linux/amd64,
gave these medians for the same warm 8,388,600-byte file:

| Validation | Time/op | Bytes allocated/op | Allocations/op |
|---|---:|---:|---:|
| Retain a second file copy | 2.604 ms | 16,746,706 | 32 |
| Streaming exact comparison | 1.040 ms | 35,016 | 24 |

This isolates the validation mechanism: approximately 2.5 times faster and
99.8% less allocation for that workload. It is not a full-suite speedup estimate.
The benchmark includes installed namespace watches and an independent read
budget per iteration; it does not recreate the whole acquisition.

The subsequent ordinary full gate, retaining JSON events without a CPU profiler,
passed with root at 557.099 seconds and closure at 1175.283 seconds; the PGO fixture
passed too. The preceding ordinary gate was 558.198 and 1166.664 seconds. These
shared-machine observations show no demonstrated whole-gate speed improvement.
The largest closure matrix still took 143.73 seconds. Further gate reduction
requires attribution and safe reuse of parsing/type preparation while preserving
each fixture's independent program and judgments, not extrapolation from the
file-validation benchmark.

## Earlier investigation

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
retention is not established by an allocation profile. Cancellation in
source hashing and index traversal is separate from these background-context
tests: the digest traversal checks its context before every file read and
the package-file walk at every entry
(REQ-closure-observability-toolchain-key; closure/toolchainsource_cancel_test.go
pins the exits), so a construction cancelled during either ends at the next
boundary; the memo's stamp walks — judging a record, writing one — are
unchecked, each bounded by one walk of the listed directories.
