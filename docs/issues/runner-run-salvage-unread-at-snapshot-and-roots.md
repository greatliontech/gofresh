# Two policy spawns discard the answer Run salvages beside ErrWaitDelay

`gotool.Runner.Run` returns a cleanly exited command's complete stdout
BESIDE `exec.ErrWaitDelay` when a descendant held the pipe past the
containment's wait delay, and leaves the serve decision to the caller:
`SampleGoVersion` serves the first line when it is a go version. Two
sites under a contained runner discard the salvage instead:
`Runner.TakeEnvSnapshot` (the `go env -json` snapshot every consumer's
pass reader and gomutant's tree take) returns the error, and
`runtimeinput.resolveRoots` (the roots probe every observation ingest
runs under the consumer's `ProducerIngest.Runner`) fails closed, so an
observation under a go wrapper whose housekeeping child outlives the
answer degrades to "classification roots unresolved" on every ingest —
a perpetual re-measure where the answer was on the pipe. gomutant's own
listing (`go list -deps -test`) serves the salvaged answer (chunk 278's
runner fold states the consumer's rule in REQ-exec-go-command-runner).

## Collapse sketch

One salvage rule at `Run`'s two structured readers: the snapshot parses
the salvaged JSON (a complete document parses; a torn one refuses as
today), the roots probe reads its three lines when all three are
present. Pinned by a `go` shim leaving a sleeper on stdout, the shape
stipulator's chunk 221 and gomutant's runner fold pin.

Lands: gofresh chunk 279 (a rider on its release: the consumer bumps
behind it read the served answers).
