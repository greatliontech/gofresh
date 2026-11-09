//go:build !linux || android

package gotool

import "os/exec"

func isContained(_ *exec.Cmd) bool { return false }

// Other platforms retain the prepared command's own cancellation and drain
// boundary. No signal may target its numeric group after Wait reaps the leader.
func runCollected(cmd *exec.Cmd, _ bool) error { return cmd.Run() }
