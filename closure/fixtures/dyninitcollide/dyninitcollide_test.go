// Package dyninitcollide pins the enumeration-target narrowing: an
// init-flow closure of matching signature is address-taken under every
// mask, but an enumeration-closed subject's pinned operand set can
// never carry it, so it must not drag its latent effect into the
// subject's scan.
package dyninitcollide

import (
	"os"
	"testing"
)

// Run is enumeration-closed: its only reference is the direct static
// test call passing a closed literal.
func Run(check func(int) int, n int) int { return check(n) }

// hooks receives an init-registered closure matching Run's dispatch
// signature; the closure is never called during initialization, so its
// write is latent - visible to a subject only if the whole-mask target
// set drags it in.
var hooks []func(int) int

var boot = func() int {
	f := func(n int) int {
		_ = os.WriteFile("boot.txt", []byte("x"), 0o600)
		return n
	}
	hooks = append(hooks, f)
	return len(hooks)
}()

func TestRun(t *testing.T) {
	if Run(func(n int) int { return n + boot - boot }, 1) != 1 {
		t.Fatal("wrong")
	}
}

