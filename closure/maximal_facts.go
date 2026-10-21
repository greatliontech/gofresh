package closure

import (
	"cmp"
	"slices"
)

// MaximalIdentity is the comparable source and derivation dependency identity of a
// maximal closure. Its fields have the same meanings as the corresponding
// Closure fields. Identity agreement alone establishes no semantic authority.
type MaximalIdentity struct {
	Hash             string
	TestVariants     string
	ToolchainContent string
	AdmissionPolicy  string
}

// BlockerKind identifies a conservative external-effect classification. It is
// neither an approval of an implementation nor an occurrence identifier.
type BlockerKind uint8

// These kinds project the existing maximal scan's classifications.
const (
	BlockerOpaque             BlockerKind = BlockerKind(externalEffectOpaque)
	BlockerStandardInput      BlockerKind = BlockerKind(externalEffectStandardInput)
	BlockerFormattedOutput    BlockerKind = BlockerKind(externalEffectFormattedOutput)
	BlockerEnvironment        BlockerKind = BlockerKind(externalEffectEnvironment)
	BlockerFileIO             BlockerKind = BlockerKind(externalEffectFileIO)
	BlockerFilesystemMutation BlockerKind = BlockerKind(externalEffectFilesystemMutation)
	BlockerPathMutation       BlockerKind = BlockerKind(externalEffectPathMutation)
	BlockerTestRuntime        BlockerKind = BlockerKind(externalEffectTestRuntime)
	BlockerNetwork            BlockerKind = BlockerKind(externalEffectNetwork)
	BlockerPlugin             BlockerKind = BlockerKind(externalEffectPlugin)
	BlockerNative             BlockerKind = BlockerKind(externalEffectNative)
	BlockerLinkage            BlockerKind = BlockerKind(externalEffectLinkage)
	BlockerUnauditedStandard  BlockerKind = BlockerKind(externalEffectUnauditedStandard)
)

// Blocker is a caller-owned projection of a conservative classification, covering
// ALL matching origins and occurrences in the subject's selected test-binary
// source closure. Scans deduplicate classifications across files, declarations
// and package/test-variant nodes; this value is not an exact occurrence inventory.
// Discharging its obligation requires covering or excluding that whole scope.
// A package or symbol lookup alone cannot discharge it.
type Blocker struct {
	Kind BlockerKind
	// Package and Symbol locate referenced candidates where the scan knows them,
	// not originating nodes, call sites or proof coverage. Either may be empty.
	Package string
	Symbol  string
	// Detail retains the scan's classification-specific payload, when present.
	Detail string
	// Reason is diagnostic text, not a semantic discriminator or discharge key.
	Reason string
	// Observable and Unrefinable retain the scan's existing flags. They supply
	// neither observation completeness nor independent implementation authority.
	Observable  bool
	Unrefinable bool
}

// MaximalFacts contains a maximal identity, the complete maximal scan's blocker
// classifications and its preferred diagnostic. These are constructible base data,
// not checked proof authority, evidence-dependent refinement or consumer-tier
// refusals. ComputeMaximalFactsBatch returns caller-owned values. An immutable
// snapshot accepting a caller's value must Clone it at its ownership boundary.
// The zero value is unavailable and its Closure projection fails closed.
type MaximalFacts struct {
	Identity MaximalIdentity
	// Effects is the complete set of conservative classifications, with each
	// entry covering the whole scope documented by Blocker. It says nothing
	// about completeness of the separate precise observation analysis.
	Effects []Blocker
	// Diagnostic is the preferred human-readable reason, including a possible
	// import-only candidate when Effects is empty. It selects no authority.
	Diagnostic string
}

func newMaximalFacts(identity MaximalIdentity, effects []externalEffect, preferred string) MaximalFacts {
	owned := make([]Blocker, len(effects))
	for i, effect := range effects {
		owned[i] = Blocker{
			Kind: BlockerKind(effect.kind), Package: effect.packagePath,
			Symbol: effect.symbol, Detail: effect.detail, Reason: effect.reason,
			Observable: effect.observable, Unrefinable: effect.unrefinable,
		}
	}
	// The scan's first-occurrence order is not semantic. Canonicalize all fields
	// so equivalent complete scans compare equally even if their traversal moves.
	slices.SortFunc(owned, func(a, b Blocker) int {
		if order := cmp.Or(cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Package, b.Package), cmp.Compare(a.Symbol, b.Symbol),
			cmp.Compare(a.Detail, b.Detail), cmp.Compare(a.Reason, b.Reason)); order != 0 {
			return order
		}
		if a.Observable != b.Observable {
			if a.Observable {
				return 1
			}
			return -1
		}
		if a.Unrefinable != b.Unrefinable {
			if a.Unrefinable {
				return 1
			}
			return -1
		}
		return 0
	})
	return MaximalFacts{Identity: identity, Effects: owned, Diagnostic: preferred}
}

// Clone returns an independently owned copy, including the effect slice.
func (f MaximalFacts) Clone() MaximalFacts {
	f.Effects = slices.Clone(f.Effects)
	return f
}

// Closure projects the ordinary maximal-tier result, preserving the preferred
// diagnostic even when it came from an import candidate and no blocker exists.
// An unavailable value refuses rather than implying an empty, supported scan.
func (f MaximalFacts) Closure() Closure {
	result := Closure{
		Hash:             f.Identity.Hash,
		TestVariants:     f.Identity.TestVariants,
		ToolchainContent: f.Identity.ToolchainContent,
		AdmissionPolicy:  f.Identity.AdmissionPolicy,
		Unverifiable:     len(f.Effects) != 0 || f.Identity.Hash == "",
		Reason:           f.Diagnostic,
	}
	if f.Identity.Hash == "" {
		result.Reason = "maximal facts unavailable"
	}
	return result
}

// Equal compares identity, every blocker field in order and the preferred
// diagnostic. Batch results use canonical effect order. Agreement of just the
// Closure projection is insufficient.
func (f MaximalFacts) Equal(other MaximalFacts) bool {
	return f.Identity == other.Identity && f.Diagnostic == other.Diagnostic &&
		slices.Equal(f.Effects, other.Effects)
}
