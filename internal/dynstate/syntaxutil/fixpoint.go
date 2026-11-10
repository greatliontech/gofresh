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
