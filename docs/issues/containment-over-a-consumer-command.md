# gotool's containment has no form over a consumer's own command

gotool.Containment (the process-group boundary: Setpgid, the group
sweep on cancellation, ESRCH read as process-done, the bounded wait,
the quit signal and its grace) is applied by Runner alone, and Runner
prepares `go <args>` only. Every consumer that spawns something other
than the go command under the same boundary rule carries a hand copy:
gomutant's oracle process files (the test binary; the Windows arm its
own job object), stipulator's resolver child, and pew's runCommand
(`taskset -c N go` and the prebuilt test binary) — three copies of one
rule, each pinned on its own, each named a deviation at its consumer's
bump (gomutant 278.E, stipulator 272.B, pew 275.B).

The fold: an exported form over an arbitrary command —
`Containment.Command(ctx, dir, env, name, args...)` preparing the
consumer's command under the same policy Runner.Command applies to
`go` (Dir, the derived environment, Prepare, the boundary), or the
boundary alone over a prepared *exec.Cmd — so the rule has one home
and the consumers' copies delete at their next bumps.

Invariants preserved: REQ-fresh-go-command-policy's boundary limb
(the plain runner carries none; a containment sweeps the group and
bounds the wait); the Windows job-object question stays its own
filing (containment-windows-job-object).

Lands: cross-tool train chunk 281 (chartered at pew 275's tick: the
containment's consumer-command form, a release before the three
consumers' next bumps).
