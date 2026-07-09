package guard

import "encoding/json"

// MachineFacts are the STABLE-identity facts that affect a timing measurement (REQ-guard-machine).
// It deliberately holds no transient run conditions (governor, turbo, thermal,
// load): those are run hygiene (the caller's run hygiene), not machine identity, so they cannot enter
// the fingerprint by construction. (TestMachineFactsExcludesTransient guards this.)
type MachineFacts struct {
	CPUModel      string `json:"cpu_model"`
	PhysicalCores int    `json:"physical_cores"`
	LogicalCores  int    `json:"logical_cores"`
	TotalRAMBytes uint64 `json:"total_ram_bytes"`
	OS            string `json:"os"`
	KernelVersion string `json:"kernel_version"`
}

// Fingerprint is a stable digest of the facts. Equal facts ⇒ equal fingerprint
// (the exact-equality machine guard, REQ-guard-equality); any change ⇒ a different fingerprint.
func (f MachineFacts) Fingerprint() string {
	b, _ := json.Marshal(f) // struct field order is stable
	return digest(string(b))
}
