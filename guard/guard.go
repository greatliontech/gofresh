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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
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

// Capture gathers the guard values applicable to kind under the pass's
// reader: its directory is the one `go` resolves the toolchain and
// build environment in — a go.mod toolchain directive and GOTOOLCHAIN
// are relative to it, so it must be the directory the result is
// produced in — its environment the complete process environment of
// the Go subprocesses and environment-backed guards (refused when
// malformed or duplicated), its snapshot the pass's one `go env -json`
// read the build-config digest takes byte for byte (a direct probe
// would return the same bytes, so the digest cannot drift), and its
// runner the spawn of the toolchain guard's `go version`, which always
// probes live: its string carries the HOST platform that `go env`'s
// target GOOS/GOARCH does not describe. The measurement guard's
// runtime-config digest is computed from runtimeEnv — the environment
// the measured processes actually run under, when it differs from the
// analysis env (a caller injecting a GOMAXPROCS cap into the processes
// it spawns): the runtime reads these keys before execution, so they
// move scheduling behaviour with no other guard moving, and digesting
// them from a stand-in environment would let evidence serve across a
// width the measured process never saw. Toolchain and build-config
// guards stay on the reader's environment — they describe the analysis
// identity. buildInputs are the build-relevant inputs the caller passed
// OUTSIDE GOFLAGS — CLI flags to `go test`/`go build` (-tags, -gcflags,
// -ldflags, -pgo) and PGO profile content as a content digest, never a
// path (GOFLAGS itself is digested from the environment): the caller
// supplies what it used, the same way it supplies commit/dirty, and
// digesting them closes the false-valid hole where a build-input change
// leaves buildconfig unmoved (REQ-guard-buildconfig,
// REQ-guard-buildconfig-failclosed). None used ⇒ pass none.
func Capture(ctx context.Context, reader *gotool.EnvReader, runtimeEnv []string, kind Kind, buildInputs ...string) (Guards, error) {
	if reader == nil {
		return Guards{}, errors.New("guard: nil environment reader")
	}
	// The input-decidable refusals come before the pass's one spawn.
	if kind != CodeResult && kind != Measurement {
		return Guards{}, fmt.Errorf("guard: invalid result kind %d", kind)
	}
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return Guards{}, fmt.Errorf("guard: %w", err)
	}
	normalizedRuntime, err := gotool.NormalizeEnv(runtimeEnv)
	if err != nil {
		return Guards{}, fmt.Errorf("guard: runtime env: %w", err)
	}
	// The pass's snapshot is taken through the caller's reader — so the
	// caller's later keys read it too — and the guard's own reader
	// carries the normalized environment primed with it: one probe per
	// pass, whichever reader asks first (REQ-guard-buildconfig).
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return Guards{}, err
	}
	pass := gotool.PrimedEnvReader(reader.Runner, reader.Dir, normalized, snapshot)
	return captureFor(ctx, pass, kind, buildInputs, gatherFacts, func([]string) string { return runtimeConfig(normalizedRuntime) })
}

func captureFor(ctx context.Context, reader *gotool.EnvReader, kind Kind, buildInputs []string, machine func() (MachineFacts, error), runtimeGuard func([]string) string) (Guards, error) {
	if kind != CodeResult && kind != Measurement {
		return Guards{}, fmt.Errorf("guard: invalid result kind %d", kind)
	}
	env := reader.Env
	tc, err := toolchainOf(ctx, reader.Runner, reader.Dir, env)
	if err != nil {
		return Guards{}, err
	}
	// The build-config digest reads the pass's one snapshot — the bytes a
	// direct probe would return, so the digest cannot drift — and the
	// toolchain guard's `go version` stays a live probe through the
	// runner: it carries the host platform.
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return Guards{}, err
	}
	bc, err := buildConfigDigest(snapshot.JSON, env, buildInputs)
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

// toolchainOf is the `go version` identity minus the redundant leading prefix — e.g.
// "go1.26.4 linux/amd64", including any custom or experiment suffix, which affects
// code generation and so must be part of the guard.
func toolchainOf(ctx context.Context, runner gotool.Runner, dir string, env []string) (string, error) {
	out, err := runner.Run(ctx, dir, env, "version")
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

// buildConfigDigest parses the `go env -json` output and digests the build-affecting
// settings plus buildInputs. A malformed env output fails closed with an error
// (REQ-guard-buildconfig-failclosed) rather than digesting a partial value.
func buildConfigDigest(envJSON []byte, processEnv, buildInputs []string) (string, error) {
	var env map[string]string
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return "", fmt.Errorf("guard: parse go env: %w", err)
	}
	vals := map[string]string{}
	for _, k := range buildConfigGoEnvKeys {
		vals[k] = env[k]
	}
	for _, k := range buildConfigOSEnvKeys {
		vals[k], _ = gotool.LookupEnv(processEnv, k)
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
func runtimeConfig(env []string) string {
	var b strings.Builder
	for _, k := range runtimeConfigEnvKeys {
		value, _ := gotool.LookupEnv(env, k)
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
