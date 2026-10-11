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
// from derivation versions and memo representation. Labels are documentary:
// the effective row-chain inventories, not their labels, enter the identity.
func (h *Hasher) AdmissionPolicy() string { return h.source.Policy }

type policyInputs struct {
	audit     string
	packages  map[string]bool
	linknames map[string]bool
	seeds     []string
	rows      []toolchainSourceRow
}

// capturePolicyInputs owns every input before keying or deriving a policy.
// Production inventories change only through source edits; tests may replace
// them between calls. The memo holds no aliases into either form.
func capturePolicyInputs() policyInputs {
	rows := slices.Clone(auditedToolchainSources)
	for i := range rows {
		rows[i].Packages = maps.Clone(rows[i].Packages)
	}
	return policyInputs{audit: auditset.Identity(), packages: maps.Clone(classBPackages),
		linknames: maps.Clone(auditedLinknameTargets), seeds: surfaceSeeds(), rows: rows}
}

var sourcePolicyMemo policyMemo

func admissionPolicy() string {
	return sourcePolicyMemo.value(capturePolicyInputs())
}

func (in policyInputs) derive() string {
	rows := make([]string, 0, len(in.rows))
	for _, row := range in.rows {
		data, _ := json.Marshal(rowChain(in.rows, row.Label))
		rows = append(rows, string(data))
	}
	sort.Strings(rows)
	rows = slices.Compact(rows)
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@1", in.audit,
		in.packages, in.linknames, seeds, rows})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
