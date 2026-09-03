# The attributed-RTA slice is one machine word wide

Every reachability fact of an attributed walk carries one bit per
subject of the slice (closure/attribution.go's subjectMask, a uint64),
so a slice holds at most 64 subjects and a package with more is proven
in several walks over the shared program. The width's cost curve,
measured over gofresh's own closure package (237 subjects, cold memo):
16 subjects per slice 81s, 32 76s, 64 73s, peak RSS flat within five
percent — each slice re-walks the program, so fewer slices are faster.
Widening the mask (a two-word or bitset mask) would let a package of
up to 128 or more subjects prove in one walk; the memory cost is one
extra word per attributed fact against an SSA-dominated peak, and the
kept-on-cancel granularity coarsens with the slice.

The widening touches every site that builds or folds a mask as a raw
uint64 — the roots and instantiation maps and the test-mask fold in
closure/attribution.go, and the reachability result and seed maps in
closure/internal/rta — which the compiler names when the mask type
moves, and the width guard the alias absorbs.

Lands: user decision (a performance trade against cancel granularity
and per-fact memory; no measured hotspot names it today).
