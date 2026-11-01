// Package helper reaches a non-admitted runtime surface from outside
// the subject's own package, so the subject-tier classification — not
// the maximal AST scan of the test file — must catch it.
package helper

import "runtime"

// Cores reports the scheduler-visible core count.
func Cores() int { return runtime.NumCPU() }
