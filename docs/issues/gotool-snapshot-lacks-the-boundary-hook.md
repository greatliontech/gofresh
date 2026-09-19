# gotool's environment snapshot has no boundary hook

`gotool.Runner{Prepare}` is the boundary hook every go invocation a
consumer spawns can take — the process group, the cancel and wait
delay — and `Runner.Run` and `Runner.SampleGoVersion` read it, but
`TakeEnvSnapshot` is a free function over the bare runner: a consumer
whose spec puts its `go env` sample inside an owned process boundary
(stipulator's REQ-go-owned-processes) cannot adopt the snapshot without
leaving that boundary, so it keeps its own nine-key `go env` query
beside the snapshot. A `Runner.TakeEnvSnapshot` form, with the free
function its bare-runner shorthand as for `SampleGoVersion`, lets the
last consumer sample join the one snapshot.

Lands: cross-tool train chunk 241
