# Containment's Windows arm has no Job Object

`gotool.Containment` (REQ-fresh-go-command-policy's process-boundary
rule) contains a Windows child by starting it in its own process group
and ending the tree with `taskkill /T` on cancellation. gomutant's
oracle needs more on Windows: a Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (every descendant dies with the
job, not by a best-effort tree walk that a fast-forking descendant
escapes), the job's priority class (the oracle's low scheduling
priority, REQ-exec-oracle-parallelism there), the suspended start that
assigns the process before it runs, and a cancelled flag the job kill
sets as the one source of truth for "the oracle did not exit on its
own" (a job termination exits every process with the tool's own code,
so an exit-code reading cannot tell a kill from a failing test). So
gomutant's Windows oracle prepares its command under the plain runner
and installs its own job-object containment over it
(gomutant internal/engine/process_windows.go), while its Unix oracle
rides Containment — the fleet's one containment has two shapes on
Windows.

## The fork

- Containment grows a Job Object arm on Windows: every consumer's go
  command on Windows ends with its job (a stronger boundary than the
  tree kill), gofresh takes `golang.org/x/sys/windows` and the
  suspended-start/assign/resume dance, and a consumer's post-kill
  reading (the cancelled flag) needs a seam gofresh would have to
  expose.
- gomutant keeps its own Windows containment: gofresh's Windows arm
  stays the tree kill, and the oracle's job object stays a consumer
  shape beside it.

The tradeoff is the fleet's Windows behaviour and gofresh's dependency
surface against one containment implementation.

Lands: user decision — the fork above.
