# gotool.Run discards the answer a wait-delay expiry leaves behind

`Runner.Run` returns no output beside an error, so a `go env GOVERSION`
whose process exited with its answer written but whose descendant — a
wrapper's housekeeping child holding the output pipe — outlived the
runner's `WaitDelay` reaches the consumer as `exec.ErrWaitDelay` with
the answer gone. stipulator's own sampler takes the first line the
process wrote in exactly that case (a shim pin witnesses it) rather
than refuse a toolchain sample over a wrapper's housekeeping, so it
cannot move onto `Runner.SampleGoVersion` without regressing that
witnessed behaviour. The form that lets it: `Run` returns the output
it read beside `exec.ErrWaitDelay` when the process itself exited
cleanly (the consumer decides whether the partial answer serves), or
`SampleGoVersion` takes the first line itself under that one error.

Lands: cross-tool train chunk 241
