// Package dyninitbound pins the enumeration-target narrowing's value
// provenance: init-planted values that are not anonymous closures — a
// method value materialized in a package initializer (the shape go1.27's
// encoding/json/v2 plants for base32 bound methods in every test binary)
// and a named function registered there — collide with a closed
// subject's dispatch signature under every mask, and must stay out of
// its target set exactly as an init-parented closure does.
package dyninitbound

import (
	"os"
	"testing"
)

// Run is enumeration-closed: its only reference is the direct static
// test call passing a closed literal.
func Run(check func(int) int, n int) int { return check(n) }

type lener struct{ path string }

// EncLen mutates the filesystem: visible to a subject only if the
// init-planted method value drags into its target set.
func (l lener) EncLen(n int) int {
	_ = os.WriteFile(l.path, []byte("x"), 0o600)
	return n
}

// named mutates the filesystem: visible to a subject only if the
// init-planted function reference drags into its target set.
func named(n int) int {
	_ = os.WriteFile("named.txt", []byte("x"), 0o600)
	return n
}

var std = lener{path: "enc.txt"}

// Both registrations happen in a user init body: the method value
// creates a parentless synthetic bound wrapper (the go1.27
// encoding/json/v2 shape), the named reference takes a plain function
// address — neither is an init-parented closure itself, so a
// parent-shaped narrowing misses both. The subject flow references
// nothing that reaches the registrations textually — the object walk
// prices any transitively referenced declaration's content on its own
// conservative terms — so this fixture pins exactly the RTA
// signature-collision channel: address-taken under every mask by the
// init roots, visible to the subject only through its dispatch target
// set.
var hooks []func(int) int

func init() {
	hooks = append(hooks, std.EncLen, named)
}

func TestRun(t *testing.T) {
	if Run(func(n int) int { return n + 1 }, 1) != 2 {
		t.Fatal("wrong")
	}
}
