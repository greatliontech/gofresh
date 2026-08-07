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

The observability memo (`SetMemoScope`) is not a separate case: the
opt-in is exercised internally by the view layer (`view.go` sets the
scope from the proof-strategy version and code guards), so every
view-consuming tool writes it too. Consumer control must cover both
memo classes — the unconditional effect scans and the view-enabled
observability memo — through one knob.

Not a correctness defect: no entry is trusted beyond its content key;
a missing or deleted store only costs recomputation.

Lands: cross-tool train chunk 20.
