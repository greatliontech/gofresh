package gofresh

import (
	"runtime"
	"strings"
	"testing"
)

// The skew check compares language series only, on both sides: patch
// and vendor flavors of one series agree; a different series refuses
// naming both versions; an unidentifiable version on either side
// refuses (unidentifiable is not agreement).
func TestToolchainSkewComparesLanguageSeries(t *testing.T) {
	if err := ToolchainSkew(runtime.Version()); err != nil {
		t.Fatalf("self-comparison skewed: %v", err)
	}
	for _, agree := range [][2]string{
		{"go1.27.0", "go1.27.0-dst.10"},
		{"go1.27.0-dst.10", "go1.27.5"},
		{"go1.26.5-X:nodwarf5", "go1.26.0"},
		{"go1.27.0 linux/amd64", "go1.27.0"},
		{"go3.1.0", "go3.1.9"}, // any digit major: future series must agree with themselves
	} {
		if err := toolchainSkew(agree[0], agree[1]); err != nil {
			t.Fatalf("same-series %v skewed: %v", agree, err)
		}
	}
	// The exec-sampled shapes: a trailing newline (and CRLF) on a
	// STOCK string must identify — the flavored variant passes even
	// without trimming (the suffix swallows it), so the stock shape
	// is the real anchor.
	for _, sampled := range []string{"go1.27.0\n", "go1.27.0\r\n", "go1.27.0-dst.10\n"} {
		if got := languageSeries(sampled); got != "go1.27" {
			t.Fatalf("languageSeries(%q) = %q, want go1.27 — exec-sampled trailing whitespace must trim", sampled, got)
		}
	}
	// The current devel shape (cmd/dist emits "go1.NN-devel_<hash> <date>",
	// deliberately Lang-compatible) identifies through the space cut.
	if got := languageSeries("go1.28-devel_abc123 Wed Aug 20 10:00:00 2026 +0000"); got != "go1.28" {
		t.Fatalf("devel shape = %q, want go1.28", got)
	}
	err := toolchainSkew("go1.26.5-X:nodwarf5", "go1.27.0-dst.10")
	if err == nil || !strings.Contains(err.Error(), "go1.26") || !strings.Contains(err.Error(), "go1.27") {
		t.Fatalf("older-frontend skew = %v, want both series named", err)
	}
	// The refusal is DIRECTIONAL within a major: a newer frontend
	// reads older language under the Go 1 compatibility promise — the
	// declared-toolchain workflow (--toolchain go1.26.x under a
	// go1.27 binary) must pass.
	if err := toolchainSkew("go1.27.0-dst.10", "go1.26.5"); err != nil {
		t.Fatalf("newer frontend over older ambient refused: %v", err)
	}
	// Across majors the promise has no basis: refuse BOTH directions.
	if err := toolchainSkew("go3.0.1", "go1.27.0"); err == nil || !strings.Contains(err.Error(), "cross-major") {
		t.Fatalf("go3 frontend over go1 ambient = %v, want the cross-major refusal", err)
	}
	if err := toolchainSkew("go1.27.0", "go3.0.1"); err == nil || !strings.Contains(err.Error(), "cross-major") {
		t.Fatalf("go1 frontend over go3 ambient = %v, want the cross-major refusal", err)
	}
	// TWO unidentifiable versions are not an agreement of anything.
	if err := toolchainSkew("devel +abc", "devel +abc"); err == nil {
		t.Fatal("two unidentifiable versions read as agreement")
	}
	// Unidentifiable on EITHER side refuses.
	for _, bad := range []string{"", "devel +abc123", "1.27.0", "gogarbage"} {
		// The refusal names its true cause: an unidentifiable version
		// reads "unidentifiable", never a series mismatch against an
		// empty language — the message is the operator's rebuild cue.
		if err := toolchainSkew(bad, "go1.27.0"); err == nil || !strings.Contains(err.Error(), "unidentifiable") {
			t.Fatalf("unidentifiable binary %q: %v, want the unidentifiable refusal", bad, err)
		}
		if err := toolchainSkew("go1.27.0", bad); err == nil || !strings.Contains(err.Error(), "unidentifiable") {
			t.Fatalf("unidentifiable ambient %q: %v, want the unidentifiable refusal", bad, err)
		}
	}
}

// languageSeries normalizes real toolchain shapes onto the canonical
// go/version.Lang and stays fail-closed on garbage Lang rejects.
// The exported wrapper attributes runtime.Version() to the BINARY
// side of the message: a swapped labeling would point the operator's
// rebuild at the wrong toolchain.
func TestToolchainSkewLabelsTheBinarySide(t *testing.T) {
	self := runtime.Version()
	series := languageSeries(self)
	// A far-future ambient: the binary's frontend predates it, the
	// refusing direction.
	ambient := "go99.1.0"
	err := ToolchainSkew(ambient)
	if err == nil {
		t.Fatal("newer-series ambient did not skew")
	}
	// Each version's LANGUAGE annotation must be its own — a crossed
	// annotation points the operator's rebuild at the wrong series.
	if !strings.Contains(err.Error(), "binary built with "+self+" (language "+series+")") {
		t.Fatalf("skew message %q does not annotate the binary %q with its own series %q", err.Error(), self, series)
	}
	if !strings.Contains(err.Error(), "ambient toolchain "+ambient+" (language "+languageSeries(ambient)+")") {
		t.Fatalf("skew message %q does not annotate the ambient %q with its own series", err.Error(), ambient)
	}
}

func TestLanguageSeriesNormalizesRealShapes(t *testing.T) {
	cases := map[string]string{
		"go1.27.0":             "go1.27",
		"go1.27":               "go1.27",
		"go1.27.0-dst.10":      "go1.27",
		"go1.26.5-X:nodwarf5":  "go1.26",
		"go1.27rc1":            "go1.27",
		"go1.27.0 linux/amd64": "go1.27",
		"go1.10.4":             "go1.10", // never confused with go1.1
		"go2.0.1":              "go2.0",
	}
	for in, want := range cases {
		if got := languageSeries(in); got != want {
			t.Fatalf("languageSeries(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "go", "gox.y", "1.27", "go1.27.0.0-x", "garbage-go1.27.0"} {
		if got := languageSeries(bad); got != "" {
			t.Fatalf("languageSeries(%q) = %q, want refusal", bad, got)
		}
	}
	// The canonical grammar is the contract: go/version.Lang reads a
	// trailing alpha run as pre-release kind ("go1.27garbage" ≡ the
	// "go1.27rc1" shape), and this helper inherits that judgment
	// rather than second-guessing the stdlib parser.
	if got := languageSeries("go1.27garbage"); got != "go1.27" {
		t.Fatalf("languageSeries(go1.27garbage) = %q, want the canonical grammar's go1.27", got)
	}
}
