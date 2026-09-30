package gotool

import (
	"go/version"
	"reflect"
	"runtime"
	"testing"
)

// One version grammar, gofresh's own, exported: a GOVERSION value — stock,
// flavored, experiment-suffixed, release-candidate, platform-suffixed,
// or the current development-build spelling — answers the canonical
// series, its pair, and its release tags; the legacy "devel …"
// spelling, a `go version` line, and what go/version's grammar
// refuses answer nothing, the tags nil, never empty
// (REQ-fresh-toolchain-skew).
func TestVersionGrammarIsOneAcrossTheForms(t *testing.T) {
	for _, c := range []struct {
		in     string
		series string
		major  int
		minor  int
		ok     bool
		tags   int
	}{
		{"go1.27.0", "go1.27", 1, 27, true, 27},
		{"go1.27", "go1.27", 1, 27, true, 27},
		{"go1.27.1\n", "go1.27", 1, 27, true, 27},
		{"go1.27.0-dst.10", "go1.27", 1, 27, true, 27},
		{"go1.26.5-X:nodwarf5", "go1.26", 1, 26, true, 26},
		{"go1.27rc1", "go1.27", 1, 27, true, 27},
		{"go1.27.0 linux/amd64", "go1.27", 1, 27, true, 27},
		{"go1.27.0 linux/amd64 x", "go1.27", 1, 27, true, 27}, // the FIRST space cuts
		{"go1.10.4", "go1.10", 1, 10, true, 10},               // never confused with go1.1
		{"go1.27garbage", "go1.27", 1, 27, true, 27},
		{"go1.28-devel_abc123 Wed Aug 20 10:00:00 2026 +0000", "go1.28", 1, 28, true, 28}, // a devel build spelled version-first
		{"go1.0", "go1", 1, 0, true, 0},                                                   // the canonical grammar's spelling of the go1.0 language
		{"go2.0.1", "go2.0", 2, 0, true, 0},
		{"go2.1.0", "go2.1", 2, 1, true, 0},                                        // no release tags outside major 1
		{"go0.5", "go0.5", 0, 5, true, 0},                                          // a major-0 series exists under Lang; no ladder outside major 1
		{"go0", "go0.0", 0, 0, true, 0},                                            // Lang spells go0 with its minor, unlike go1
		{"go1.99999999999999999999.0", "go1.99999999999999999999", 0, 0, false, 0}, // Lang bounds the digits' form, not their length: an overflow is no pair
		{"go99999999999999999999.1", "go99999999999999999999.1", 0, 0, false, 0},
		{"go1.4096", "go1.4096", 1, 4096, true, 4096}, // the ladder's bound, inclusive
		{"go1.4097", "go1.4097", 1, 4097, true, 0},    // past it, no ladder
		{"", "", 0, 0, false, 0},
		{"go", "", 0, 0, false, 0},
		{"gox.y", "", 0, 0, false, 0},
		{"1.27", "", 0, 0, false, 0},
		{"go1.27.0.0-x", "", 0, 0, false, 0},
		{"garbage-go1.27.0", "", 0, 0, false, 0},
		{"devel go1.28-abc1234 Thu Sep 30 00:00:00 2026 +0000", "", 0, 0, false, 0},
		{"go version go1.27.1 linux/amd64", "", 0, 0, false, 0},
	} {
		if got := LanguageSeries(c.in); got != c.series {
			t.Errorf("LanguageSeries(%q) = %q, want %q", c.in, got, c.series)
		}
		major, minor, ok := ParseGoVersion(c.in)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("ParseGoVersion(%q) = %d, %d, %v; want %d, %d, %v", c.in, major, minor, ok, c.major, c.minor, c.ok)
		}
		tags := ReleaseTags(c.in)
		if len(tags) != c.tags {
			t.Errorf("ReleaseTags(%q) = %d tags, want %d", c.in, len(tags), c.tags)
		}
		if c.tags == 0 && tags != nil {
			t.Errorf("ReleaseTags(%q) = %#v, want nil (a caller branches on nil)", c.in, tags)
		}
		if c.tags > 0 && (tags[0] != "go1.1" || tags[len(tags)-1] != c.series) {
			t.Errorf("ReleaseTags(%q) = %v … %v, want go1.1 … %s", c.in, tags[0], tags[len(tags)-1], c.series)
		}
	}
	// The running toolchain's own version parses to the series the
	// canonical parser gives it.
	if got, want := LanguageSeries(runtime.Version()), version.Lang(runtime.Version()); got != want {
		t.Fatalf("the running toolchain's series %q, go/version says %q", got, want)
	}
	if !reflect.DeepEqual(ReleaseTags("go1.3"), []string{"go1.1", "go1.2", "go1.3"}) {
		t.Fatalf("ReleaseTags(go1.3) = %v", ReleaseTags("go1.3"))
	}
}
