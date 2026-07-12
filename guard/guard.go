// Package guard captures and compares the environment facts that decide whether a
// cached result is still valid — the toolchain, build-configuration, machine, and
// runtime-configuration guards (spec guards.md). Guard values are plain data: the
// caller owns how a fingerprint is serialized and stored (REQ-fresh-fingerprint-data),
// and supplies commit/dirty from its own git layer, since validity is
// commit-independent (REQ-fresh-commit-independent) and dirty is a baseline policy.
//
// Guards split by what they bear on (REQ-fresh-guard-set): the toolchain and
// build-configuration guards determine the compiled binary, so they apply to every
// result (code guards); the machine and runtime-configuration guards move a timing
// measurement but not a pass/fail outcome, so they apply only to a measurement.
package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/processenv"
)

// Guards are the captured guard values for one result. Every field is a digest or
// identity string compared by exact equality (REQ-guard-equality).
type Guards struct {
	Toolchain     string // `go version` identity (code guard)
	BuildConfig   string // build-affecting settings digest (code guard)
	Machine       string // machine fingerprint (measurement guard)
	RuntimeConfig string // Go runtime-config env digest (measurement guard)
}

// Kind classifies a cached result for guard selection (REQ-fresh-guard-set).
type Kind int

const (
	invalidKind Kind = iota
	// CodeResult is a pass/fail-style result (a test verdict, a mutation kill):
	// only the code guards apply.
	CodeResult
	// Measurement is a timing result (a benchmark): the measurement guards apply
	// in addition to the code guards.
	Measurement
)

// Capture gathers code-result guard values. Use CaptureFor for a measurement.
// moduleDir is the directory `go`
// resolves the toolchain and build environment in — a go.mod toolchain directive
// and GOTOOLCHAIN are relative to it, so it must be the directory the result is
// produced in — while the machine and runtime-config guards are host and process
// facts independent of it.
// buildInputs are the build-affecting parts of the caller's invocation that gofresh
// cannot observe from `go env`: CLI flags passed to `go test`/`go build` outside
// GOFLAGS (-tags, -gcflags, -ldflags, -pgo) and PGO profile content (the caller
// passes a content digest, not the path). The caller supplies what it used, the same
// way it supplies commit/dirty; digesting them closes the false-valid hole where a
// build-input change leaves buildconfig unmoved (REQ-guard-buildconfig,
// REQ-guard-buildconfig-failclosed). None used ⇒ pass none.
func Capture(moduleDir string, buildInputs ...string) (Guards, error) {
	return CaptureFor(moduleDir, CodeResult, buildInputs...)
}

// CaptureFor gathers the guard values applicable to kind.
func CaptureFor(moduleDir string, kind Kind, buildInputs ...string) (Guards, error) {
	return CaptureForContext(context.Background(), moduleDir, kind, buildInputs...)
}

// CaptureContext is Capture with caller-owned cancellation for subprocess-backed guards.
func CaptureContext(ctx context.Context, moduleDir string, buildInputs ...string) (Guards, error) {
	return CaptureForContext(ctx, moduleDir, CodeResult, buildInputs...)
}

// CaptureForContext is CaptureFor with caller-owned cancellation for subprocess-backed guards.
func CaptureForContext(ctx context.Context, moduleDir string, kind Kind, buildInputs ...string) (Guards, error) {
	return captureForContext(ctx, moduleDir, kind, buildInputs, gatherFacts, runtimeConfig)
}

// CaptureForContextEnv is CaptureForContext with env as the complete process
// environment used by Go subprocesses and environment-backed guards.
func CaptureForContextEnv(ctx context.Context, moduleDir string, env []string, kind Kind, buildInputs ...string) (Guards, error) {
	normalized, err := processenv.Normalize(env)
	if err != nil {
		return Guards{}, fmt.Errorf("guard: %w", err)
	}
	return captureForContextEnv(ctx, moduleDir, normalized, kind, buildInputs, gatherFacts, runtimeConfigEnv)
}

func captureForContext(ctx context.Context, moduleDir string, kind Kind, buildInputs []string, machine func() (MachineFacts, error), runtimeGuard func() string) (Guards, error) {
	return captureForContextEnv(ctx, moduleDir, os.Environ(), kind, buildInputs, machine, func([]string) string { return runtimeGuard() })
}

func captureForContextEnv(ctx context.Context, moduleDir string, env []string, kind Kind, buildInputs []string, machine func() (MachineFacts, error), runtimeGuard func([]string) string) (Guards, error) {
	if kind != CodeResult && kind != Measurement {
		return Guards{}, fmt.Errorf("guard: invalid result kind %d", kind)
	}
	tc, err := toolchainContextEnv(ctx, moduleDir, env)
	if err != nil {
		return Guards{}, err
	}
	bc, err := buildConfigContextEnv(ctx, moduleDir, env, buildInputs)
	if err != nil {
		return Guards{}, err
	}
	guards := Guards{Toolchain: tc, BuildConfig: bc}
	if kind == CodeResult {
		return guards, nil
	}
	facts, err := machine()
	if err != nil {
		return Guards{}, err
	}
	guards.Machine = facts.Fingerprint()
	guards.RuntimeConfig = runtimeGuard(env)
	return guards, nil
}

// Compare reports the first applicable guard whose recorded and current values
// differ under kind's policy, or "" if every applicable guard holds. A recorded
// value that is empty — a guard never captured, e.g. an old recording — is a
// mismatch, since validity requires proof and an unevaluable guard is not proof
// (REQ-guard-completeness). Comparison is exact equality (REQ-guard-equality).
func Compare(recorded, current Guards, kind Kind) string {
	if kind != CodeResult && kind != Measurement {
		return "kind"
	}
	pairs := []struct{ name, rec, cur string }{
		{"toolchain", recorded.Toolchain, current.Toolchain},
		{"buildconfig", recorded.BuildConfig, current.BuildConfig},
	}
	if kind == Measurement {
		pairs = append(pairs,
			struct{ name, rec, cur string }{"machine", recorded.Machine, current.Machine},
			struct{ name, rec, cur string }{"runtimeconfig", recorded.RuntimeConfig, current.RuntimeConfig},
		)
	}
	for _, p := range pairs {
		if p.rec == "" || p.rec != p.cur {
			return p.name
		}
	}
	return ""
}

// toolchain is the `go version` identity minus the redundant leading prefix — e.g.
// "go1.26.4 linux/amd64", including any custom or experiment suffix, which affects
// code generation and so must be part of the guard.
func toolchain(dir string) (string, error) {
	return toolchainContext(context.Background(), dir)
}

func toolchainContext(ctx context.Context, dir string) (string, error) {
	return toolchainContextEnv(ctx, dir, os.Environ())
}

func toolchainContextEnv(ctx context.Context, dir string, env []string) (string, error) {
	out, err := gotool.RunInContextEnv(ctx, dir, env, "version")
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "go version "), nil
}

// buildConfigGoEnvKeys are the go-env-reported build-affecting settings hashed into
// the buildconfig guard (REQ-guard-buildconfig): the target platform, the codegen
// feature level, the cgo toolchain environment, and build flags. GOOS/GOARCH live
// here — not in the machine guard — because they are code-determining (a
// cross-compile changes the binary and thus any result), so they must be checked
// even when the measurement guards are off.
var buildConfigGoEnvKeys = []string{
	"GOOS", "GOARCH",
	"GOAMD64", "GOARM", "GOARM64", "GO386", "GOEXPERIMENT",
	"CGO_ENABLED", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS",
	"CC", "CXX", "PKG_CONFIG", "GOFLAGS",
}

// buildConfigOSEnvKeys are the pkg-config search variables — plain OS env, not go
// env vars — that change which .pc files cgo resolves and thus the compiled code.
var buildConfigOSEnvKeys = []string{"PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR"}

// buildConfig digests the build-affecting settings that can change generated code
// without moving the toolchain, machine, or source guards: the observable `go env`
// settings and OS pkg-config vars, plus the caller-supplied buildInputs (its CLI
// build flags and PGO profile content — the parts of the build invocation gofresh
// cannot observe). An unparseable `go env` output fails closed
// (REQ-guard-buildconfig-failclosed) rather than digesting a partial value.
func buildConfig(dir string, buildInputs []string) (string, error) {
	return buildConfigContext(context.Background(), dir, buildInputs)
}

func buildConfigContext(ctx context.Context, dir string, buildInputs []string) (string, error) {
	return buildConfigContextEnv(ctx, dir, os.Environ(), buildInputs)
}

func buildConfigContextEnv(ctx context.Context, dir string, env, buildInputs []string) (string, error) {
	out, err := gotool.RunInContextEnv(ctx, dir, env, "env", "-json")
	if err != nil {
		return "", err
	}
	return buildConfigDigestEnv(out, env, buildInputs)
}

// buildConfigDigest parses the `go env -json` output and digests the build-affecting
// settings plus buildInputs. A malformed env output fails closed with an error
// (REQ-guard-buildconfig-failclosed) rather than digesting a partial value.
func buildConfigDigest(envJSON []byte, buildInputs []string) (string, error) {
	return buildConfigDigestEnv(envJSON, os.Environ(), buildInputs)
}

func buildConfigDigestEnv(envJSON []byte, processEnv, buildInputs []string) (string, error) {
	var env map[string]string
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return "", fmt.Errorf("guard: parse go env: %w", err)
	}
	vals := map[string]string{}
	for _, k := range buildConfigGoEnvKeys {
		vals[k] = env[k]
	}
	for _, k := range buildConfigOSEnvKeys {
		vals[k], _ = processenv.Lookup(processEnv, k)
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "env %d:%s %d:%s\n", len(k), k, len(vals[k]), vals[k])
	}
	// Caller-supplied build invocation, in the order given (the caller keeps it
	// stable across capture and check).
	for _, in := range buildInputs {
		fmt.Fprintf(&b, "buildinput %d:%s\n", len(in), in)
	}
	return digest(b.String()), nil
}

// runtimeConfigEnvKeys are the Go runtime-configuration environment variables the
// measured process inherits. The runtime reads them before execution, so they move
// allocation/scheduling behavior with no other guard moving; they are transient, so
// excluded from the machine fingerprint. Only explicitly-set values are captured —
// an unset GOMAXPROCS defers to the core count the machine guard already covers.
var runtimeConfigEnvKeys = []string{"GOGC", "GODEBUG", "GOMEMLIMIT", "GOMAXPROCS"}

// runtimeConfig digests the runtime-config environment (fixed key order; values not
// stored in clear text).
func runtimeConfig() string {
	return runtimeConfigEnv(os.Environ())
}

func runtimeConfigEnv(env []string) string {
	var b strings.Builder
	for _, k := range runtimeConfigEnvKeys {
		value, _ := processenv.Lookup(env, k)
		fmt.Fprintf(&b, "%s=%s\n", k, value)
	}
	return digest(b.String())
}

// digest is a short stable content hash used for the machine and buildconfig
// fingerprints.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32]
}
