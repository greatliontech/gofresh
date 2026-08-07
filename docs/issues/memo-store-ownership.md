# Persistent memo store writes global state without consumer control

The closure package owns a persistent memo store under the user cache
directory (`closure/internal/cachefile`: `$XDG_CACHE_HOME/gofresh/...`),
and the effect-scan memos write there unconditionally — any consumer
process that runs closure analysis (stipulator check, gomutant, pew,
this repo's own tests) writes global user state as a side effect, with
no API to disable, redirect, or attribute the writes. Hermetic
environments (CI sandboxes forbidding cache writes) have no recourse,
and per-consumer cleanup is impossible because all consumers share one
undifferentiated tree.

The sharing itself is a documented, deliberate design: entries are
pure content-keyed caches ("the key IS the freshness"), deletable
wholesale, and one shared store lets any tool analyzing the same code
reuse another's scans. The defect is the absence of consumer control,
not the default location.

Adjacent dead surface, same disposition point: `SetMemoScope` (the
opt-in observability memo) is called by no consumer — the memo
machinery it gates never runs in any tool. Decide together: give the
observability memo the same consumer-controlled enablement, or retire
the opt-in surface.

Not a correctness defect: no entry is trusted beyond its content key;
a missing or deleted store only costs recomputation.

Lands: cross-tool train chunk 20.
