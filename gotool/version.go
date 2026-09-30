package gotool

import (
	"fmt"
	"go/version"
	"strconv"
	"strings"
)

// LanguageSeries derives the "goMAJOR.MINOR" language series of a Go
// toolchain version as `go env GOVERSION` reports it ("go1.27.1",
// "go1.27.1-dst.13", "go1.26.5-X:nodwarf5", "go1.27rc1") through the
// canonical go/version.Lang after one normalization — the value
// trimmed and cut at its first space, so a trailing platform tuple
// ("go1.27.0 linux/amd64") or the newline exec's Output carries is
// dropped. Lang's own grammar reads vendor flavors, experiment
// suffixes, release candidates and the current development-build
// spelling ("go1.28-devel_abc123 …" reads as go1.28: a development
// cycle sets its release's language) as suffixes of the series, and
// whatever it rejects — the legacy "devel go1.28-…" spelling, whose
// first field is no version; a `go version` line; a string Lang's
// grammar refuses — answers "": the canonical parser's judgment is the
// contract, fail-closed, the one grammar gofresh's series judgment
// reads, exported for every consumer's floor and release-tag
// derivation (REQ-fresh-toolchain-skew).
func LanguageSeries(v string) string {
	v = strings.TrimSpace(v)
	v, _, _ = strings.Cut(v, " ")
	return version.Lang(v)
}

// ParseGoVersion is LanguageSeries as a (major, minor) pair; ok is
// false when the series is "" or a number in it overflows int — the
// canonical grammar bounds the digits' form, not their length. The
// grammar spells the go1.0 language "go1", with no minor: that series
// is (1, 0).
func ParseGoVersion(v string) (major, minor int, ok bool) {
	series := LanguageSeries(v)
	if series == "" {
		return 0, 0, false
	}
	majorText, minorText, found := strings.Cut(strings.TrimPrefix(series, "go"), ".")
	if !found {
		minorText = "0"
	}
	major, majorErr := strconv.Atoi(majorText)
	minor, minorErr := strconv.Atoi(minorText)
	if majorErr != nil || minorErr != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// ReleaseTagsBound is the most minors the release-tag ladder derives:
// a go1.N series past it answers nil rather than a ladder no toolchain
// ever set — a GOVERSION spells the toolchain's VERSION file, so only
// a crafted or corrupt one reaches it, and an unbounded ladder would
// allocate without limit.
const ReleaseTagsBound = 4096

// ReleaseTags derives the go/build release tags ("go1.1" … "go1.N") a
// go1.N toolchain sets — go/build derives them from the toolchain's
// compile-time internal/goversion.Version, so a release candidate or
// a development build of go1.N sets go1.N as its release does; nil —
// never an empty non-nil slice, which a caller branching on nil would
// install as no tags — when v carries no series, its major is not 1,
// or its minor passes ReleaseTagsBound, leaving a caller's own
// defaults in place.
func ReleaseTags(v string) []string {
	// A failed parse answers major 0, which the major rule rejects.
	major, minor, _ := ParseGoVersion(v)
	if major != 1 || minor < 1 || minor > ReleaseTagsBound {
		return nil
	}
	tags := make([]string, 0, minor)
	for i := 1; i <= minor; i++ {
		tags = append(tags, fmt.Sprintf("go1.%d", i))
	}
	return tags
}
