package closure

import (
	"fmt"

	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// computeTier2ResultAndReach runs the per-subject precise-analysis pipeline
// the observability proof is built on — program load, subject rooting,
// package listing, attributed reachability, and the analyzer projection —
// for a single subject, returning the raw analyzer result plus the names of
// the subject-reachable functions (the attribution surface the analyzer
// projects), so root-resolution tests assert reach directly. A symbol that
// cannot be rooted in the loaded test-binary program is a subject-local
// error naming the subject; a name declared by both the package and its
// external test package errors naming the ambiguity.
//
// The program and listing are loaded locally and released with the call
// unless already cached on the Hasher: table tests share one Hasher
// across many fixture packages, and retaining every whole-program SSA
// would grow peak memory with the table instead of the largest single
// test binary.
func computeTier2ResultAndReach(h *Hasher, pkgPath, symbol string) (tier2Result, map[string]bool, error) {
	prog := h.progs[pkgPath]
	if prog == nil {
		var err error
		prog, err = progpkg.Load(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
		if err != nil {
			return tier2Result{}, nil, err
		}
	}
	if prog.Roots[symbol] == nil {
		if prog.Ambiguous[symbol] {
			return tier2Result{}, nil, fmt.Errorf("closure: subject name %s is ambiguous in %s (declared by both the package and its external test package)", symbol, pkgPath)
		}
		return tier2Result{}, nil, fmt.Errorf("closure: subject %s not found in %s", symbol, pkgPath)
	}
	_, retainList := h.lists[pkgPath]
	metas, err := h.list(pkgPath)
	if err != nil {
		return tier2Result{}, nil, err
	}
	defer func() {
		if !retainList {
			delete(h.lists, pkgPath)
		}
	}()
	reachable, err := attributedReachableSets(h.ctx, true, prog, []Subject{{Package: pkgPath, Symbol: symbol}})
	if err != nil {
		return tier2Result{}, nil, err
	}
	result, err := h.tier2Reachable(newTier2Base(h, prog, metas), reachable[0])
	if err != nil {
		return tier2Result{}, nil, err
	}
	reach := make(map[string]bool, len(reachable[0].functions))
	for fn := range reachable[0].functions {
		if fn != nil {
			reach[fn.String()] = true
		}
	}
	return result, reach, nil
}

func computeTier2Result(h *Hasher, pkgPath, symbol string) (tier2Result, error) {
	result, _, err := computeTier2ResultAndReach(h, pkgPath, symbol)
	return result, err
}
