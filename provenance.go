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
// judged run must refuse that state loudly instead of degrading
// target by target.
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

// ToolchainSkew reports a language-series disagreement between the
// running binary's build toolchain and the ambient toolchain as an
// error; nil means the series agree. An unidentifiable version on
// either side is a skew — unidentifiable is not agreement.
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
	if bs != as {
		return fmt.Errorf("gofresh: toolchain provenance: binary built with %s (language %s), ambient toolchain %s (language %s): the compiled-in frontend predates or postdates the sources the run loads — rebuild the tool on the ambient toolchain", binary, bs, ambient, as)
	}
	return nil
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
