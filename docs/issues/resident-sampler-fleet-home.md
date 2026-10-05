# The resident-set sampler has one home in stipulator and two consumers to come

stipulator's `internal/resident` (chunk 307: the process's VmRSS/VmHWM
and its live descendants' from /proc, the host's MemAvailable, the
ceiling derivation with the operator's limit taken once, the per-tree
readings the spawn admission reserves against) is the fleet's one
resident sampler, and it is stipulator-internal. gomutant 308 states
the run's per-phase resident line on both faces "in 307's words" and
bounds its server under a ceiling; pew's measurements have the same
need. A second copy in gomutant would be the duplication the fleet
refuses (the gotool precedent: one home in gofresh, the consumers
compose).

Expected: `gofresh/resident` — the sampler, the host reading, the
ceiling derivation and the operator-limit rule — moved from
stipulator's package with its pins, exported as the fleet's one home
(stipulator folds onto it at its next bump; gomutant reads it at 308;
pew at its next bump). The ceiling's derivation stays each consumer's
policy (stipulator's Available/2 floored at 1 GiB; gomutant's oracle
ceiling total/2·jobs floored at 1 GiB): the home offers the readings
and the install rule, not one fleet number.

Lands: cross-tool train chunk 310 (a release; gomutant 308 reads it).
