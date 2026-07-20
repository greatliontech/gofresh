package guard

// CurrentMachineFacts gathers the stable machine identity
// (REQ-guard-machine's fact list) from the running host.
func CurrentMachineFacts() (MachineFacts, error) {
	return gatherFacts()
}
