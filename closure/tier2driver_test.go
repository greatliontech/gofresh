package closure

import "fmt"

// computeTier2Result runs the per-subject precise-analysis pipeline the
// observability proof is built on — program load, subject rooting,
// package listing, attributed reachability, and the analyzer projection —
// for a single subject, returning the raw analyzer result. A symbol that
// cannot be rooted in the loaded test-binary program is a subject-local
// error naming the subject; a name declared by both the package and its
// external test package errors naming the ambiguity.
//
// The program and listing are loaded locally and released with the call
// unless already cached on the Hasher: table tests share one Hasher
// across many fixture packages, and retaining every whole-program SSA
// would grow peak memory with the table instead of the largest single
// test binary.
func computeTier2Result(h *Hasher, pkgPath, symbol string) (tier2Result, error) {
	prog := h.progs[pkgPath]
	if prog == nil {
		var err error
		prog, err = loadEnv(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
		if err != nil {
			return tier2Result{}, err
		}
	}
	if prog.roots[symbol] == nil {
		if prog.ambiguous[symbol] {
			return tier2Result{}, fmt.Errorf("closure: subject name %s is ambiguous in %s (declared by both the package and its external test package)", symbol, pkgPath)
		}
		return tier2Result{}, fmt.Errorf("closure: subject %s not found in %s", symbol, pkgPath)
	}
	_, retainList := h.lists[pkgPath]
	metas, err := h.list(pkgPath)
	if err != nil {
		return tier2Result{}, err
	}
	defer func() {
		if !retainList {
			delete(h.lists, pkgPath)
		}
	}()
	reachable, err := attributedReachableSets(h.ctx, prog, []Subject{{Package: pkgPath, Symbol: symbol}})
	if err != nil {
		return tier2Result{}, err
	}
	return h.tier2ReachableWithFresh(newTier2Base(h, prog, metas), reachable[0], false)
}
