//go:build !linux

package guard

import "fmt"

// gatherFacts on non-Linux platforms fails closed until that OS has a stable
// machine-identity implementation. A weak runtime-only fingerprint would collide
// across different hosts and permit false-valid reuse across machines (REQ-guard-machine).
func gatherFacts() (MachineFacts, error) {
	return MachineFacts{}, fmt.Errorf("provenance: machine fingerprint unsupported on this OS")
}
