package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func admissionPolicy() string {
	rows := make([]string, 0, len(auditedToolchainSources))
	for _, row := range auditedToolchainSources {
		data, _ := json.Marshal(rowChain(auditedToolchainSources, row.Label))
		rows = append(rows, string(data))
	}
	sort.Strings(rows)
	rows = slices.Compact(rows)
	seeds := surfaceSeeds()
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@1", auditset.Identity(),
		classBPackages, auditedLinknameTargets, seeds, rows})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
