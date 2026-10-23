package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"sort"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// ToolchainContent identifies every standard package's selected source files
// in this construction. It is independent of the reported version and of the
// admission policy. Empty means that complete content could not be read.
func (h *Hasher) ToolchainContent() string { return h.source.Content }

// AdmissionPolicy identifies the data governing the source audit, separately
// from derivation versions and memo representation.
func (h *Hasher) AdmissionPolicy() string { return h.source.Policy }

type policyInputs struct {
	verifier  string
	audit     string
	packages  map[string]bool
	linknames map[string]bool
	seeds     []string
}

// capturePolicyInputs owns every input before keying or deriving a policy.
// Production inventories change only through source edits; tests may replace
// them between calls. The memo holds no aliases into either form.
func capturePolicyInputs() policyInputs {
	packages := maps.Clone(classBPackages)
	for k, v := range pureDelegatePackages {
		packages["pure-delegate:"+k] = v
	}
	for k, v := range allowedPureSupportImports {
		packages["pure-import:"+k] = v
	}
	for k, v := range forbiddenPureTimeSelectors {
		packages["pure-time-forbid:"+k] = v
	}
	for k, v := range allowedPureMathRandSelectors {
		packages["pure-rand-allow:"+k] = v
	}
	for k, v := range allowedPureRuntimeSelectors {
		packages["pure-runtime-allow:"+k] = v
	}
	for k, v := range forbiddenPureFmtSelectors {
		packages["pure-fmt-forbid:"+k] = v
	}
	for k, v := range allowedPureFilepathliteSyscallSelectors {
		packages["pure-filepathlite-syscall-allow:"+k] = v
	}
	for k, v := range allowedPureFilepathliteWindowsSelectors {
		packages["pure-filepathlite-windows-allow:"+k] = v
	}
	linknames := maps.Clone(auditedLinknameTargets)
	for k, v := range allowedPureLinknameTargets {
		linknames["pure-link2:"+k] = v
	}
	for k, v := range allowedPureSingleArgLinknames {
		linknames["pure-link1:"+k] = v
	}
	return policyInputs{
		verifier:  toolchainVerifierVersion,
		audit:     auditset.Identity(),
		packages:  packages,
		linknames: linknames,
		seeds:     surfaceSeeds(),
	}
}

var sourcePolicyMemo policyMemo

func admissionPolicy() string {
	return sourcePolicyMemo.value(capturePolicyInputs())
}

func (in policyInputs) derive() string {
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@2", in.verifier, in.audit,
		in.packages, in.linknames, seeds})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
