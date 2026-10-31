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
	for k, v := range allowedPureSupportImports {
		packages["pure-import:"+k] = v
	}
	for k, v := range allowedPureCryptoInternalFIPS140Selectors {
		packages["pure-fips140-allow:"+k] = v
	}
	for k, v := range allowedPureBoringCipherSelectors {
		packages["pure-boring-cipher-allow:"+k] = v
	}
	for k, v := range allowedPureFIPS140OnlyFIPSSelectors {
		packages["pure-fips140only-fips-allow:"+k] = v
	}
	for k, v := range allowedPureFIPS140OnlyDRBGSelectors {
		packages["pure-fips140only-drbg-allow:"+k] = v
	}
	for k, v := range allowedPureSHAGodebugSettings {
		packages["pure-sha-godebug-allow:"+k] = v
	}
	for k, v := range allowedPureFmtSelectors {
		packages["pure-fmt-allow:"+k] = v
	}
	for k, v := range allowedPureMathSelectors {
		packages["pure-math-allow:"+k] = v
	}
	for k, v := range allowedPureReflectSelectors {
		packages["pure-reflect-allow:"+k] = v
	}
	for k, v := range allowedPureFilepathliteSyscallSelectors {
		packages["pure-filepathlite-syscall-allow:"+k] = v
	}
	for k, v := range allowedPureFilepathliteWindowsSelectors {
		packages["pure-filepathlite-windows-allow:"+k] = v
	}
	for k, v := range allowedPureMathRandSelectors {
		packages["pure-rand-allow:"+k] = v
	}
	for k, v := range allowedPureRuntimeSelectors {
		packages["pure-runtime-allow:"+k] = v
	}
	for k, v := range allowedPureSyncSelectors {
		packages["pure-sync-allow:"+k] = v
	}
	for k, v := range allowedPureSyncAtomicSelectors {
		packages["pure-sync-atomic-allow:"+k] = v
	}
	for k, v := range allowedPureTimeSelectors {
		packages["pure-time-allow:"+k] = v
	}
	for k, v := range allowedPureAsmStandardHeaders {
		packages["pure-asm-hdr-allow:"+k] = v
	}
	linknames := maps.Clone(auditedLinknameTargets)
	for k, v := range allowedPureLinknameTargets {
		linknames["pure-link2:"+k] = v
	}
	for k, v := range allowedPureSingleArgLinknames {
		linknames["pure-link1:"+k] = v
	}
	for k, v := range allowedPureAsmCrossPkgSymbols {
		linknames["pure-asm-sym:"+k] = v
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
