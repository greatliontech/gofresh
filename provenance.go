package gofresh

import (
	"fmt"
	"go/version"
	"runtime"
	"strings"
)

// Tool provenance: a binary embedding this engine drives an ambient
// `go` toolchain for loading, building, and test execution. When the
// binary's OWN build toolchain and the ambient one disagree on the
// LANGUAGE series (go1.26 vs go1.27), the compiled-in stdlib
// frontend (go/types, go/parser) faces source shapes it predates:
// parse refusals, analysis panics, and silently shifted evidence. A
// judged run must refuse that state loudly — the refusal is
// DIRECTIONAL within a major (an older frontend refuses newer
// sources; a newer one reads older language under the Go 1
// compatibility promise) and total across majors — instead of
// degrading target by target.
//
// Scope: the check witnesses the STDLIB frontend series only. The
// x/tools layers are a module pin of the embedding tool, not a
// toolchain property — their language support is exercised by each
// tool's language-shape canary suite, never inferable here.
//
// Sampling contract: ambient MUST be the version of the `go` that
// will actually serve the run's loads and test executions — sampled
// IN THE TARGET MODULE'S DIRECTORY (`go env GOVERSION` there), never
// the tool's own cwd: under GOTOOLCHAIN=auto, cmd/go re-execs a
// per-module selected toolchain, and a cwd-sampled version can agree
// while the module's selected toolchain skews — exactly the state
// this check exists to refuse. (The same dir-relativity rule the
// guard evidence already binds to.)

// ToolchainSkew reports the breaking direction of a language-series
// disagreement between the running binary's build toolchain and the
// ambient toolchain as an error; nil means the binary's frontend can
// judge the ambient's sources. Within a major the refusal is
// DIRECTIONAL: a frontend OLDER than the ambient series breaks (it
// predates the sources' language — the field class), while a NEWER
// frontend reads older language under the Go 1 compatibility
// promise — refusing that direction would break the legitimate
// declared-toolchain workflows (measuring under a pinned older
// toolchain from a current binary). Across majors the promise has no
// basis and BOTH directions refuse. An unidentifiable version on
// either side refuses — unidentifiable is not agreement.
func ToolchainSkew(ambient string) error {
	return toolchainSkew(runtime.Version(), ambient)
}

// toolchainSkew is the two-sided core, testable on both inputs.
func toolchainSkew(binary, ambient string) error {
	bs := languageSeries(binary)
	as := languageSeries(ambient)
	if bs == "" || as == "" {
		return fmt.Errorf("gofresh: toolchain provenance: binary built with %q, ambient toolchain %q: unidentifiable language series — refusing to judge under an unidentifiable frontend", binary, ambient)
	}
	if majorOf(bs) != majorOf(as) {
		// The backward-compatibility law the newer-frontend direction
		// rests on is the Go 1 promise, scoped WITHIN a major: across
		// majors there is no promise in either direction, and the
		// fail-closed posture refuses both.
		return fmt.Errorf("gofresh: toolchain provenance: binary built with %s (language %s), ambient toolchain %s (language %s): cross-major toolchains carry no compatibility promise in either direction — rebuild the tool on the ambient toolchain's major", binary, bs, ambient, as)
	}
	if version.Compare(bs, as) < 0 {
		return fmt.Errorf("gofresh: toolchain provenance: binary built with %s (language %s), ambient toolchain %s (language %s): the compiled-in frontend predates the sources the run loads — rebuild the tool on the ambient toolchain", binary, bs, ambient, as)
	}
	return nil
}

// majorOf cuts the major from a "goMAJOR.MINOR" series.
func majorOf(series string) string {
	major, _, _ := strings.Cut(strings.TrimPrefix(series, "go"), ".")
	return major
}

// languageSeries derives the "goMAJOR.MINOR" language series via the
// canonical go/version.Lang after one normalization: a trailing
// platform tuple ("go1.27.0 linux/amd64") cuts at the space. Lang's
// own grammar already reads vendor flavors ("go1.27.0-dst.10",
// "go1.26.5-X:nodwarf5") as pre-release suffixes of the series, and
// anything it rejects yields "" — the canonical parser's judgment is
// the contract, fail-closed on garbage.
func languageSeries(v string) string {
	// TrimSpace first: the prescribed sampling (`go env GOVERSION`
	// via exec Output) carries a trailing newline, which Lang's
	// grammar rejects on a STOCK version string while a flavored
	// one swallows it in the discarded suffix — an asymmetry that
	// passes flavored dev hosts and bricks stock fleet hosts.
	v = strings.TrimSpace(v)
	v, _, _ = strings.Cut(v, " ")
	return version.Lang(v)
}
