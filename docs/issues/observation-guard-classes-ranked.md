# Three observation classes block ~97% of gofresh's witness serving

Lands: when runtime-input observation next gains a guard-covered or
ephemeral class, or when a consumer prioritizes warming a
toolchain-heavy corpus.

## Observed

Per-test uncacheable attribution over gofresh's own corpus (464 of 465
witnesses unpublishable) ranks the refusing classes:

- ~300: post-run drift on `$GOCACHE` paths (`runtimeinputs (moved: path
  ~/.cache/go-build/...)`) — in-process go/packages loads read
  content-addressed build-cache entries that churn under concurrent
  builds. Build-cache entries are content-addressed: an entry's content
  never changes under its name, so reads of existing entries are
  pinned by construction. GOCACHE as a guard-covered root was
  deliberately deferred when GOROOT/GOMODCACHE landed; this measurement
  is the case for landing it.
- 128: `external directory input: /tmp` — t.TempDir machinery reads the
  ambient temp root. Ephemeral per-process temp trees are fresh by
  construction; an ephemeral classification (or TMPDIR-scoped
  exclusion contract) would clear the class.
- 18: `/proc/cpuinfo`, `/proc/meminfo` — exactly what the machine guard
  pins; a machine-guard-covered classification clears them.
- Residue (~14): genuine file-I/O proof refusals, `/dev/null`, stat
  metadata — individually reviewable.

## Resolution

Land the classes in leverage order: GOCACHE guard-covered
(content-addressed immutability as the admission argument, with the
same fail-closed resolution discipline as the toolchain root), the
ephemeral temp-tree class, the machine-guard-covered proc reads. Each
carries its own spec clause and soundness argument; none requires
consumer changes beyond passing the root.
