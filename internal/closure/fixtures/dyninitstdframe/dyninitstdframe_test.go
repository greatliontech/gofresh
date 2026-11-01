// Package dyninitstdframe pins the enumeration narrowing's std-frame
// keep as load-bearing: an init-planted comparator handed to a
// standard-library generic as a plain argument reaches a dispatch
// site inside the std frame, where no operand proof ever runs - the
// whole-mask drag must never drop there, so the comparator's latent
// write refuses the subject at the subject tier.
package dyninitstdframe

import (
	"os"
	"slices"
	"testing"
)

var hooks []func(int, int) int

var boot = func() int {
	hooks = append(hooks, func(a, b int) int {
		_ = os.WriteFile("boot.txt", []byte("x"), 0o600)
		return a - b
	})
	return len(hooks)
}()

// RunSort is enumeration-closed through driveSort's direct call; the
// driver is referenced nowhere and never executes, so the write stays
// latent.
func RunSort(check func(int) int, n int) int {
	s := []int{2, 1}
	slices.SortFunc(s, hooks[0])
	return check(n) + s[0] - s[0] + boot - boot
}

func driveSort() int { return RunSort(func(n int) int { return n }, 1) }

func TestNothing(t *testing.T) {}
