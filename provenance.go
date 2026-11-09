package gofresh

import (
	"context"
	"errors"
	"fmt"
	"go/version"
	"os/exec"
	"strings"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
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
	return toolchainSkew(closure.AnalyzingFrontend(), ambient)
}

// toolchainSkew is the two-sided core, testable on both inputs.
func toolchainSkew(binary, ambient string) error {
	bs := gotool.LanguageSeries(binary)
	as := gotool.LanguageSeries(ambient)
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

// ToolchainProvenanceError is the typed refusal returned when a session's
// selected toolchain is unidentifiable or skews from the analyzing frontend
// (REQ-fresh-toolchain-skew).
type ToolchainProvenanceError struct{ Err error }

func (e *ToolchainProvenanceError) Error() string { return e.Err.Error() }
func (e *ToolchainProvenanceError) Unwrap() error { return e.Err }

func checkSnapshotToolchainProvenance(snapshot *gotool.EnvSnapshot) error {
	ambient := snapshot.Value("GOVERSION")
	if err := ToolchainSkew(ambient); err != nil {
		return &ToolchainProvenanceError{Err: err}
	}
	return nil
}

// ToolchainSelection summarizes the resolved toolchain content, admission
// policy, and any selection-audit degradation notice for a build configuration.
type ToolchainSelection struct {
	ToolchainContent string
	AdmissionPolicy  string
	SelectionNotice  string
}

func firstPrepare(prepare []func(*exec.Cmd)) func(*exec.Cmd) {
	var active []func(*exec.Cmd)
	for _, fn := range prepare {
		if fn != nil {
			active = append(active, fn)
		}
	}
	if len(active) == 0 {
		return nil
	}
	if len(active) == 1 {
		return active[0]
	}
	return func(cmd *exec.Cmd) {
		for _, fn := range active {
			fn(cmd)
		}
	}
}

// ResolveToolchainSelection resolves the toolchain content, admission policy,
// and selection-audit notice for build under an optional command-preparation hook.
func ResolveToolchainSelection(ctx context.Context, build BuildDescription, prepare ...func(*exec.Cmd)) (ToolchainSelection, error) {
	refreshTraceFromEnv()
	if ctx == nil {
		return ToolchainSelection{}, errors.New("gofresh: nil toolchain selection context")
	}
	if err := ctx.Err(); err != nil {
		return ToolchainSelection{}, err
	}
	if build.Directory == "" {
		return ToolchainSelection{}, errors.New("gofresh: toolchain selection requires a build directory")
	}
	if build.Environment == nil {
		return ToolchainSelection{}, errors.New("gofresh: build environment must be explicitly provided")
	}
	var snapshot *gotool.EnvSnapshot
	if build.GoEnv != nil {
		var err error
		snapshot, err = gotool.EnvSnapshotFromValues(build.GoEnv)
		if err != nil {
			return ToolchainSelection{}, err
		}
	}
	reader := gotool.PrimedEnvReader(gotool.Runner{Prepare: firstPrepare(prepare)}, gotool.Coordinate(build.Directory), build.Environment, snapshot)
	return resolveToolchainSelection(ctx, reader, build.Flags...)
}

func resolveToolchainSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (ToolchainSelection, error) {
	refreshTraceFromEnv()
	if ctx == nil {
		return ToolchainSelection{}, errors.New("gofresh: nil toolchain selection context")
	}
	if err := ctx.Err(); err != nil {
		return ToolchainSelection{}, err
	}
	if reader == nil {
		return ToolchainSelection{}, errors.New("gofresh: nil environment reader")
	}
	content, policy, notice, err := closure.ResolveToolchainSelection(ctx, reader, buildFlags)
	if err != nil {
		return ToolchainSelection{}, err
	}
	return ToolchainSelection{
		ToolchainContent: content,
		AdmissionPolicy:  policy,
		SelectionNotice:  notice,
	}, nil
}

// ToolchainSelection resolves the toolchain content, admission policy, and
// selection-audit notice for the session's admitted build configuration.
func (s *Session) ToolchainSelection(ctx context.Context) (ToolchainSelection, error) {
	if s == nil || s.dir == "" {
		return ToolchainSelection{}, errors.New("gofresh: uninitialized session")
	}
	return resolveToolchainSelection(ctx, s.newPassReader(), s.buildFlags...)
}
