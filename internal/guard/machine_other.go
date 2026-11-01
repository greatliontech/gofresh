//go:build !linux

package guard

import "fmt"

// gatherFacts on non-Linux platforms fails closed until that OS has a stable
// machine-identity implementation. A weak runtime-only fingerprint would collide
// across different hosts and permit false-valid reuse across machines (REQ-guard-machine).
func gatherFacts() (MachineFacts, error) {
	return MachineFacts{}, fmt.Errorf("provenance: machine fingerprint unsupported on this OS")
}

// MachineFactSources is empty where no gatherer exists: nothing is read,
// so nothing is allowlisted (REQ-inputs-machine-identity).
var MachineFactSources []string

// VolatileOSRoots is empty where no kernel-synthesized volatile
// filesystem surface exists (REQ-inputs-volatile-os-roots).
var VolatileOSRoots []string
