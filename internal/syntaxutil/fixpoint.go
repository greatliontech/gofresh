package syntaxutil

// SolveLeastFixedPoint computes the least fixed point of set over deps: any
// key in deps whose every edge target satisfies satisfied is added to set
// until convergence.
func SolveLeastFixedPoint[K comparable, D comparable](set map[K]bool, deps map[K]map[D]bool, satisfied func(D) bool) {
	for changed := true; changed; {
		changed = false
		for k, edges := range deps {
			if set[k] {
				continue
			}
			ok := true
			for dep := range edges {
				if !satisfied(dep) {
					ok = false
					break
				}
			}
			if ok {
				set[k] = true
				changed = true
			}
		}
	}
}

// SolveReachFixedPoint computes the reachability least fixed point of set over
// deps: any key in deps with at least one edge target satisfying triggered is
// added to set until convergence.
func SolveReachFixedPoint[K comparable, D comparable](set map[K]bool, deps map[K]map[D]bool, triggered func(D) bool) {
	for changed := true; changed; {
		changed = false
		for k, edges := range deps {
			if set[k] {
				continue
			}
			for dep := range edges {
				if triggered(dep) {
					set[k] = true
					changed = true
					break
				}
			}
		}
	}
}

// PropagateBFS expands set in O(V + E) time over the directed or undirected
// adjacency map adj starting from all keys initially marked true in set.
func PropagateBFS[K comparable](set map[K]bool, adj map[K]map[K]bool) {
	if len(set) == 0 || len(adj) == 0 {
		return
	}
	queue := make([]K, 0, len(set))
	for k, ok := range set {
		if ok {
			queue = append(queue, k)
		}
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for next := range adj[cur] {
			if !set[next] {
				set[next] = true
				queue = append(queue, next)
			}
		}
	}
}

// SolveBipartiteLFP computes the joint least fixed point over two coupled key
// spaces: any candidate in candidatesA satisfying satisfiedA is added to setA,
// and any candidate in candidatesB satisfying satisfiedB is added to setB,
// iterating monotonically until neither set grows.
func SolveBipartiteLFP[A, B comparable](
	setA map[A]bool,
	candidatesA map[A]bool,
	satisfiedA func(A) bool,
	setB map[B]bool,
	candidatesB map[B]bool,
	satisfiedB func(B) bool,
) {
	for changed := true; changed; {
		changed = false
		for a, ok := range candidatesA {
			if !ok || setA[a] {
				continue
			}
			if satisfiedA(a) {
				setA[a] = true
				changed = true
			}
		}
		for b, ok := range candidatesB {
			if !ok || setB[b] {
				continue
			}
			if satisfiedB(b) {
				setB[b] = true
				changed = true
			}
		}
	}
}

// PruneUnsatisfiedDeps returns a fresh dependency map retaining only keys k in
// deps where !satisfiedK(k), with each retained key mapped to the non-empty
// subset of its dependency targets d where !satisfiedD(d).
func PruneUnsatisfiedDeps[K, D comparable](
	deps map[K]map[D]bool,
	satisfiedK func(K) bool,
	satisfiedD func(D) bool,
) map[K]map[D]bool {
	out := make(map[K]map[D]bool)
	for k, wants := range deps {
		if satisfiedK != nil && satisfiedK(k) {
			continue
		}
		var edges map[D]bool
		for d, active := range wants {
			if !active {
				continue
			}
			if satisfiedD != nil && satisfiedD(d) {
				continue
			}
			if edges == nil {
				edges = make(map[D]bool)
			}
			edges[d] = true
		}
		if len(edges) > 0 {
			out[k] = edges
		}
	}
	return out
}
