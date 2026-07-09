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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
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
	// CodeResult is a pass/fail-style result (a test verdict, a mutation kill):
	// only the code guards apply.
	CodeResult Kind = iota
	// Measurement is a timing result (a benchmark): the measurement guards apply
	// in addition to the code guards.
	Measurement
)

// Capture gathers the current guard values. moduleDir is the directory `go`
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
	tc, err := toolchain(moduleDir)
	if err != nil {
		return Guards{}, err
	}
	bc, err := buildConfig(moduleDir, buildInputs)
	if err != nil {
		return Guards{}, err
	}
	facts, err := gatherFacts()
	if err != nil {
		return Guards{}, err
	}
	return Guards{
		Toolchain:     tc,
		BuildConfig:   bc,
		Machine:       facts.Fingerprint(),
		RuntimeConfig: runtimeConfig(),
	}, nil
}

// Compare reports the first applicable guard whose recorded and current values
// differ under kind's policy, or "" if every applicable guard holds. A recorded
// value that is empty — a guard never captured, e.g. an old recording — is a
// mismatch, since validity requires proof and an unevaluable guard is not proof
// (REQ-guard-completeness). Comparison is exact equality (REQ-guard-equality).
func Compare(recorded, current Guards, kind Kind) string {
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

// Cache memoizes Capture by module dir for the life of one command invocation.
// Every fact Capture gathers is per-module or per-machine — `go version`/`go env`
// subprocesses and the machine facts — so a multi-package run over one module
// captures once instead of once per package. Errors are memoized too. A Cache is
// not safe for concurrent use.
type Cache struct {
	entries map[string]captureResult
}

type captureResult struct {
	guards Guards
	err    error
}

// NewCache returns an empty capture cache for one command invocation.
func NewCache() *Cache { return &Cache{entries: map[string]captureResult{}} }

// Capture returns the guards for moduleDir and buildInputs, computing them once and
// reusing the result (or error) on later calls with the same dir and inputs.
func (c *Cache) Capture(moduleDir string, buildInputs ...string) (Guards, error) {
	key := moduleDir + "\x00" + strings.Join(buildInputs, "\x00")
	if r, ok := c.entries[key]; ok {
		return r.guards, r.err
	}
	g, err := Capture(moduleDir, buildInputs...)
	c.entries[key] = captureResult{guards: g, err: err}
	return g, err
}

// toolchain is the `go version` identity minus the redundant leading prefix — e.g.
// "go1.26.4 linux/amd64", including any custom or experiment suffix, which affects
// code generation and so must be part of the guard.
func toolchain(dir string) (string, error) {
	out, err := gotool.RunIn(dir, "version")
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
	out, err := gotool.RunIn(dir, "env", "-json")
	if err != nil {
		return "", err
	}
	var env map[string]string
	if err := json.Unmarshal(out, &env); err != nil {
		return "", fmt.Errorf("guard: parse go env: %w", err)
	}
	vals := map[string]string{}
	for _, k := range buildConfigGoEnvKeys {
		vals[k] = env[k]
	}
	for _, k := range buildConfigOSEnvKeys {
		vals[k] = os.Getenv(k)
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, vals[k])
	}
	// Caller-supplied build invocation, in the order given (the caller keeps it
	// stable across capture and check).
	for _, in := range buildInputs {
		fmt.Fprintf(&b, "buildinput=%s\n", in)
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
	var b strings.Builder
	for _, k := range runtimeConfigEnvKeys {
		fmt.Fprintf(&b, "%s=%s\n", k, os.Getenv(k))
	}
	return digest(b.String())
}

// digest is a short stable content hash used for the machine and buildconfig
// fingerprints.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32]
}
