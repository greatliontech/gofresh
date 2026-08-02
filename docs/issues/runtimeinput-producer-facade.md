# three producers carry near-identical observation wiring; the facade home is here

stipulator (internal/backends/golang/observe.go), gomutant, and pew
(internal/run/observe.go, landed 45a9061) each hand-assemble the same
completed-observation conjunction: symlink-resolved frame roots, a
pre-spawn CaptureBracketContext over the package directory with the
VCS exclusion, the test-log-header check, FromTestLogEnv with the
completed-process/bracket/exclusion options and the four
classification roots, and the incomplete fallback discipline. pew's
review measured the drift risk directly: its first copy diverged from
the siblings on ingest-environment fidelity (PWD) before review caught
it. A runtimeinput facade owning frame capture + ingest (caller
supplies identity, roots, and the process env; the facade owns the
header check, option assembly, and fallback shape) would collapse the
three copies and make the next producer correct by construction.

Lands: the next gofresh plan.
