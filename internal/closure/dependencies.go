package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
)

// ToolchainContent identifies every standard package's selected source files
// in this construction. It is independent of the reported version and of the
// admission policy. Empty means that complete content could not be read.
func (h *Hasher) ToolchainContent() string { return h.source.Content }

// AdmissionPolicy identifies the data governing the source audit, separately
// from derivation versions and memo representation.
func (h *Hasher) AdmissionPolicy() string { return h.source.Policy }

type policyInputs struct {
	verifier    string
	asmVerifier string
	audit       string
	packages    map[string]bool
	linknames   map[string]bool
	seeds       []string
}

// capturePolicyInputs owns every input before keying or deriving a policy.
// Production inventories change only through source edits; tests may replace
// them between calls. The memo holds no aliases into either form.
func capturePolicyInputs() policyInputs {
	packages := map[string]bool{}
	toolchain.AppendPolicyPackages(packages)
	for k, v := range cprep.AllowedPureAsmStandardHeaders {
		packages["pure-asm-hdr-allow:"+k] = v
	}
	linknames := map[string]bool{}
	for k, v := range cprep.AllowedPureLinknameTargets {
		linknames["pure-link2:"+k] = v
	}
	for k, v := range cprep.AllowedPureSingleArgLinknames {
		linknames["pure-link1:"+k] = v
	}
	for k, v := range cprep.AllowedPureAsmCrossPkgSymbols {
		linknames["pure-asm-sym:"+k] = v
	}
	return policyInputs{
		verifier:    toolchainVerifierVersion,
		asmVerifier: asmverify.NonStdAsmVerifierVersion,
		audit:       auditset.Identity(),
		packages:    packages,
		linknames:   linknames,
		seeds:       surfaceSeeds(),
	}
}

func admissionPolicy() string {
	return capturePolicyInputs().derive()
}

func (in policyInputs) derive() string {
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@2", in.verifier, in.asmVerifier, in.audit,
		in.packages, in.linknames, seeds})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
