package closure

import (
	"github.com/greatliontech/gofresh/closure/internal/testvariant"
)

// The test-variant compartment lives in internal/testvariant; the aliases
// keep the public surface and the package-local names in place.
type (
	TestVariantLedger            = testvariant.TestVariantLedger
	TestVariantDeclaration       = testvariant.TestVariantDeclaration
	TestVariantFileHeader        = testvariant.TestVariantFileHeader
	TestVariantDelta             = testvariant.TestVariantDelta
	TestVariantDeclarationChange = testvariant.TestVariantDeclarationChange
	TestVariantHeaderChange      = testvariant.TestVariantHeaderChange
)

// EmptyTestVariantClosure re-exports the no-test-files compartment identity.
const EmptyTestVariantClosure = testvariant.EmptyTestVariantClosure

// DiffTestVariantLedgers classifies the delta between two compartment
// ledgers (REQ-closure-test-variant-compartment).
func DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta {
	return testvariant.DiffTestVariantLedgers(before, after)
}

// TestVariantLedger returns the declaration ledger of pkgPath's test-variant
// compartment, computed from the same file reads as the compartment hash and
// memoized for the Hasher's lifetime. The returned value is caller-owned.
func (h *Hasher) TestVariantLedger(pkgPath string) (TestVariantLedger, error) {
	if identity, ok := h.testVariants[pkgPath]; ok {
		return identity.Ledger.Clone(), nil
	}
	// This path discards the contributions it computes — the ledger and
	// compartment derive from the walk's own file reads — so a stale
	// armed memo entry from a prior batch call is unobservable here; a
	// future consumer of contributions on this path must reset h.contribs
	// like the batch entries do.
	if _, _, err := h.maximalContributionsAndFiles(pkgPath); err != nil {
		return TestVariantLedger{}, err
	}
	return h.testVariants[pkgPath].Ledger.Clone(), nil
}
