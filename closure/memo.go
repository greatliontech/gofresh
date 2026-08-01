package closure

// SetMemoScope enables the persistent observability memo under scope -
// the analysis identity outside the source closure: the caller supplies
// the proof-strategy version and the code guards, and the memo key adds
// the package test-binary closure hash, completing the pure function's
// input identity (REQ-closure-observability-memo). An empty scope
// disables memoization. The memo lives under the user cache directory;
// a missing, unreadable, or corrupt entry recomputes silently - the key
// IS the freshness, so no entry is ever trusted beyond it.
func (h *Hasher) SetMemoScope(scope string) {
	h.memoScope = scope
}

// observabilityDirName is the observability memo's sibling user-cache
// directory under the shared cache-file mechanism.
const observabilityDirName = "observability"

// loadMemo returns the persisted proofs for (scope, closureKey), empty
// on any failure - the memo is a cache, never a record.
func loadMemo(scope, closureKey string) map[string]Observability {
	var proofs map[string]Observability
	if !loadCacheEntry(observabilityDirName, scope, closureKey, &proofs) {
		return nil
	}
	return proofs
}

// storeMemo merges proofs into the (scope, closureKey) entry with an
// atomic replace; failures are silent - a lost store costs one
// recomputation, never a wrong proof.
func storeMemo(scope, closureKey string, proofs map[string]Observability) {
	mergeCacheEntry(observabilityDirName, scope, closureKey, proofs)
}

// testBinaryClosureKey is the memo-key identity of everything the
// package's analyzed test binary is built from: the core closure hash
// joined with the test-variant compartment identity. The compartment
// rides as its own axis because the partition keeps test-only bytes out
// of the core contributions (REQ-closure-test-variant-compartment) while
// the analyzed program compiles them all the same — a key equating the
// test binary with the core alone serves stale proofs after test-only
// edits (REQ-closure-observability-memo).
func (h *Hasher) testBinaryClosureKey(pkgPath string) (string, error) {
	if key, ok := h.testBinaryKeys[pkgPath]; ok {
		return key, nil
	}
	mh, err := h.maximalHash(pkgPath)
	if err != nil {
		return "", err
	}
	// maximalHash derives and records the compartment identity for the
	// package as a side effect, so the axis is in hand.
	key := mh + "\x00" + h.testVariants[pkgPath].hash
	if h.testBinaryKeys != nil {
		h.testBinaryKeys[pkgPath] = key
	}
	return key, nil
}

// groupMemo resolves one package group's memo: the closure key keying
// it and the already-proven subjects. A key-derivation failure
// disables the memo for the group - fail-open to recomputation.
func (h *Hasher) groupMemo(pkgPath string) (closureHash string, proofs map[string]Observability) {
	if h.memoScope == "" {
		return "", nil
	}
	key, err := h.testBinaryClosureKey(pkgPath)
	if err != nil {
		return "", nil
	}
	return key, loadMemo(h.memoScope, key)
}
