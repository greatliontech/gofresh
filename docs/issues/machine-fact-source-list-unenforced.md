# Machine-fact source list is not enforced against the gatherer's actual opens

`guard.MachineFactSources` is the single source of truth the
runtime-input machine-fact allowlist derives from, and
`TestMachineFactSourcesNameTheGathererReads` pins the list's literal
content — but nothing proves the gatherer opens ONLY listed files. A
future `gatherFacts` edit that reads a new proc file (say
`/proc/version`) without extending the list keeps every test green
while reintroducing the defect class the list exists to prevent: an
unallowlisted gatherer read classifies as an ordinary volatile proc
input and permanently stalls every machine-fact-gathering witness.

Enforcement shape: trace `gatherFacts`' opens (the repo's own
observation harness can — run it under a testlog capture and assert the
opened set equals `MachineFactSources`), or route every gatherer read
through a single open helper that checks membership.

Lands: when gatherFacts next gains or changes a fact source, or when
the observation harness gains a self-tracing test surface.
