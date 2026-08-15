package unsafesibling

import (
	"os"
	"testing"
)

// TestCleanRead never reaches the sibling grammar file's unsafe
// declarations: its observability proof must not be pre-blocked by
// the package scan on their account.
func TestCleanRead(*testing.T) {
	_, _ = os.ReadFile("fixture.txt")
}

// TestReachesUnsafe carries an unsafe-typed value through its own
// walk and must refuse at the subject tier.
func TestReachesUnsafe(*testing.T) {
	p := Carry(nil)
	_ = p
}
