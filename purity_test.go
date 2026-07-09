package gofresh

import (
	"os/exec"
	"testing"
)

// TestScanPureDirectives pins REQ-purity-directive: the scanner marks exactly the
// symbols carrying //gofresh:pure — a function and a method (named "Type.Method") —
// and leaves their directive-less neighbours unmarked.
func TestScanPureDirectives(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const pkg = "github.com/greatliontech/gofresh/internal/puredirective"
	pred, err := ScanPureDirectives(pkg)
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	cases := []struct {
		symbol string
		want   bool
	}{
		{"Asserted", true},
		{"NotAsserted", false},
		{"T.Asserted", true},
		{"T.NotAsserted", false},
	}
	for _, tc := range cases {
		if got := pred(Subject{Package: pkg, Symbol: tc.symbol}); got != tc.want {
			t.Errorf("%s: pure=%v, want %v", tc.symbol, got, tc.want)
		}
	}
}
