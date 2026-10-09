# The godst testlog writer drops a failed write inside a simulation bubble

Lands: chunk 338 (godst: the test-log writer propagates a write error —
`dstHostStreamWrite`'s `writeFull` returns the errno it swallows and
`dstTestlogWriter.Write` returns it, so the harness's buffered writer
sticks and `StopTestLog` fails the binary; a build cut from the fix;
then gofresh's canary re-lists the dst rows over that build).

Found by the review of chunk 315's first change set (2026-10-09),
reading go1.27.1-dst.13's testing package: under the `dst` tag
`testing.go` wraps the `-test.testlogfile` file in `dstWrapTestlogWriter`
on every dst build; inside a simulation bubble `Write` hands the bytes
to `dstHostStreamWrite` and always answers `len(p), nil`, and that
stream's `writeFull` returns quietly on any errno but EINTR/EAGAIN —
a partial write followed by an error leaves a torn line, a failed
write drops the chunk. On a stock build the same buffered writer sees
`f.Write`'s error, the error sticks, `StopTestLog`'s flush returns it
and the binary fails ("can't write"): fail-closed. On the dst build
the buffer never sees an error, so a transient fault during an
in-bubble flush (ENOSPC on a nearly full tmpfs freed before the run
ends, EDQUOT) exits 0 with a well-formed test log missing
`open`/`stat`/`getenv` records.

Gofresh's capture reads the test log as the observation's input under
the producer facade's ladder (runtimeinput/producer.go: the completion
receipt, abnormal completion, outcome support, the capture, the header,
the operation model, the frame, the environment): a result owner's
completion receipt over an exit-0 binary with a dropped block passes,
and the header check sees whole lines, so the dropped identities never
enter the finalized guards — an under-pin no reader of the record can
detect (a cleanly missing block of whole lines is indistinguishable
from a quiet test). The harness's write propagation is thus a premise
of identity finalization and of any completion receipt taken over that
harness — runtime-inputs' observation-completeness terms
(REQ-inputs-identity-facade, REQ-inputs-producer-premises; the result
owner supplies the harness's completion criterion), and the
evidence-model owner's territory, told through pew's handoff doc. The
premise's implementation — testing's writer wrapper and
testing/internal/testdeps' buffered writes with StopTestLog's flush
error — is keyed: both are seeds of the audited surface (testdeps is
reached by the generated test main alone, by no table's dependencies),
so a build changing either moves a key and the listing instruction
names the premise. Listing the dst selections would open the
first path on which such a record is served, so they stay unlisted:
REQ-closure-observability-toolchain-key states the premise a listing
asserts beside the admissions, and the content pin keeps both dst forms
refusing on a godst build.

The walk of the moved keys (the delta read against every admission;
the record covers the keys whose digests equal the walked ones below —
a build carrying the fix moves testing's key at least, and every other
key whose digest differs is re-walked before its row lists):

- The method: every gated branch a moved key's constant enables, not
  the tagged files alone — time's `dst_tz.go` is a build constant and
  a linknamed fence predicate, while the live behaviour sits in
  `zoneinfo.go` (`(*Location).get` answers `&utcLoc` for `Local` and a
  host-assigned `time.Local` while the fence is active) and
  `sys_unix.go` (zoneinfo reads answer ENOENT) — none reaches an
  admitted symbol: the fixed-argument table excludes Local, UTC, the
  Unix constructors and LoadLocation; the virtual clock is the
  runtime's, never admitted.
- sync (hooked under `dst && race` alone) and internal/sync
  (`dst_mutex_on.go` under `dst`, `dst_on.go` under `dst && race`):
  `runtime_dstSyncAcquire` is a scheduler yield (a decision point)
  inside Mutex.Lock/Unlock beside the event records, and a starvation
  threshold — the audited receiver methods' values and memo semantics
  hold; a yield is a schedule, not a value.
- testing's `dst_hostio.go`: chatty output through an atomic host
  stream inside a bubble with "=== NAME" headers (not the test log);
  the test-log writer the defect above — the premise this doc names.
- syscall's `dst_env.go`: a per-process copy-on-write environment that
  never calls `runtimeSetenv`; `os.Getenv` logs before `syscall.Getenv`
  and an unmodified key reads the host's value — sound. The raw
  dispatch intercepts fsync/flock/close/fallocate/mmap/futex/renameat2
  and a virtual clock: always-external effect classes, no pure
  admission; the linkname-target floor's three targets
  (runtime.getAuxv, runtime.vgetrandom, syscall.prlimit) appear in no
  dst file.
- os: `Stat`, `Lstat` and `Chdir` dispatch to the simulator BEFORE
  their test-log call (`dstStatName`, `dstChdir` return first when the
  simulated filesystem is active; `Readlink` and `Getwd` log nothing on
  the stock harness either); `OpenFile`, `openDir`, `StartProcess` and
  `(*File).Stat` log before their hooks.
  Sound not by ordering but by the host-isolation invariant: the
  simulated filesystem is in-memory and never sees the host ("the host
  filesystem is never visible under a run", `os/dst_fs.go`), `dstActive`
  is process-global for the run, so an unlogged simulated stat reads
  program state and the host cwd never moves; a logged `OpenFile` of a
  simulated path over-pins a host path the program never read (safe,
  refusal noise at most).
- os/signal (`dst.go`, keyed since the harness premise's seed joined
  the surface): a build constant and a linknamed fence predicate;
  `Notify`, `Ignore`, `Reset` and `Stop` panic inside an active bubble
  ("unsupported under deterministic simulation") — none is an
  admission (the package carries no pure symbol), and a panic is an
  effect the harness fails the test on. Of the eleven packages the
  seed pulls, os/signal alone carries a dst file.
- sysrand's deterministic source leaves the entropy class fail-closed;
  the maps delegate's deterministic iteration names no admission;
  runtime and net carry no pure admission (the simulated network, the
  pagecache and crash-tear hooks are effect classes).

The measurement (re-taken on the seeded surface): under
go1.27.1-dst.13 the `dst` selection moves ten keys off the build's
default chain, `dst -race` eleven (sync joins; internal/sync and the
runtime differ between the two forms) — the walked digests, the
comparison basis for a re-walk:

- `dst` (ten keys off `go1.27.1-dst.13`): crypto/internal/sysrand
  40f004f1405bd100aa2ba80cf760273b219d4ed917ef6ab8e5c916de5369f18e,
  internal/runtime/maps
  c1ad78efb177dfc5cab631c5200dae7445c58f3bd1fec1c6c7c24f7c948a832b,
  internal/sync
  068a9611d8af122a69baf9935a6bcde725954b6bf2487e6e9c0c828d92866a95,
  net f56f472bcfc20b44959c14dd2296ed4a302acbd402631f2115cf629c63996754,
  os 0d7ec920c5ea2ab71904489ce462f5fe3744a65e1080ee7a4074e9f2927659e4,
  os/signal
  675fe77339e1fb6936ff10e593910db58e9e0af7d9868f930ca9180c6fcee521,
  runtime
  f76b4fd33c10387e3f8aa68c268aaceae5b4ad3d05a285637d17f12482d95655,
  syscall
  acddbae294709beb040bd65c3384214f8153535d1d8af3169dbd32c2581e488d,
  testing
  37db613f965152d53668d588f5b8f877d6dfa7ad39bfe01137ed283992d2eafd,
  time 057b80e75745c0f88423489a53959220ef1078ae732e8dd5fdbf802d4cbec53b.
- `dst -race` (eleven keys off `go1.27.1-dst.13 race`): the same but
  internal/sync
  3d70c31393537e325cdfda20117ffcc25d46c5bcf376caf3ec042212571fcccf,
  runtime
  949f2049d1917b29b6994bf214182a87cc5a914f59b0645752b71d15a5c8dc74,
  and sync
  49313795240ce33d2176080d525f23378006f7c72607a523c32a164cf304a4f4.

The other installed godst builds (go1.27.0-dst.10…15, go1.27.1-dst.12)
are not the fleet's running build and stay unlisted the same way.
