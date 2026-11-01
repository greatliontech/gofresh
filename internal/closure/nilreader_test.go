package closure

import (
	"context"
	"strings"
	"testing"
)

// A nil reader refuses at every entry — never a nil dereference deep in
// a load.
func TestNilReaderRefusesAtEveryEntry(t *testing.T) {
	ctx := context.Background()
	if _, err := NewAt(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("NewAt(nil) = %v", err)
	}
	if _, err := NewBracketAt(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("NewBracketAt(nil) = %v", err)
	}
	if _, err := LoadViewPackages(ctx, nil, nil, "x"); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("LoadViewPackages(nil) = %v", err)
	}
	if _, err := LoadViewGraph(ctx, nil, nil, "x"); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("LoadViewGraph(nil) = %v", err)
	}
}
