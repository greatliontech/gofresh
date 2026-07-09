package guard

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestCaptureNonEmpty(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	g, err := Capture(t.TempDir())
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	for name, v := range map[string]string{
		"toolchain": g.Toolchain, "buildconfig": g.BuildConfig,
		"machine": g.Machine, "runtimeconfig": g.RuntimeConfig,
	} {
		if v == "" {
			t.Errorf("guard %s captured empty", name)
		}
	}
}

// TestCompareCodeVsMeasurement pins the guard-set policy (REQ-fresh-guard-set): the
// code guards (toolchain, buildconfig) apply to every result; the measurement
// guards (machine, runtimeconfig) apply only to a Measurement. A machine drift is
// invisible to a CodeResult (a test verdict is not moved by the machine) but caught
// for a Measurement.
func TestCompareCodeVsMeasurement(t *testing.T) {
	base := Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"}

	machineDrift := base
	machineDrift.Machine = "m2"
	if got := Compare(base, machineDrift, CodeResult); got != "" {
		t.Errorf("CodeResult with machine drift: got mismatch %q, want none", got)
	}
	if got := Compare(base, machineDrift, Measurement); got != "machine" {
		t.Errorf("Measurement with machine drift: got %q, want machine", got)
	}

	rcDrift := base
	rcDrift.RuntimeConfig = "rc2"
	if got := Compare(base, rcDrift, CodeResult); got != "" {
		t.Errorf("CodeResult with runtimeconfig drift: got %q, want none", got)
	}
	if got := Compare(base, rcDrift, Measurement); got != "runtimeconfig" {
		t.Errorf("Measurement with runtimeconfig drift: got %q, want runtimeconfig", got)
	}

	// A code guard is caught under either kind.
	tcDrift := base
	tcDrift.Toolchain = "tc2"
	for _, k := range []Kind{CodeResult, Measurement} {
		if got := Compare(base, tcDrift, k); got != "toolchain" {
			t.Errorf("kind %v with toolchain drift: got %q, want toolchain", k, got)
		}
	}
}

// TestCompareCompleteness pins REQ-guard-completeness: a recorded guard value that
// is empty (never captured) is a mismatch, not a pass — validity requires proof.
func TestCompareCompleteness(t *testing.T) {
	current := Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"}
	missing := current
	missing.BuildConfig = ""
	if got := Compare(missing, current, CodeResult); got != "buildconfig" {
		t.Errorf("missing recorded buildconfig: got %q, want buildconfig", got)
	}
	// The load-bearing case: a guard empty in BOTH recorded and current must still be
	// a mismatch — empty equals empty is not proof of validity, so it never reads as
	// valid (REQ-guard-completeness).
	if got := Compare(Guards{}, Guards{}, CodeResult); got != "toolchain" {
		t.Errorf("all-empty guards: got %q, want a mismatch — an unevaluable guard is not proof", got)
	}
}

// TestBuildConfigKeysIncludeTargetPlatform pins the refinement structurally: GOOS
// and GOARCH are digested into the buildconfig (code) guard. Placing them only in
// the machine guard would leave a cross-compile a false-valid hole for a caller
// that runs the measurement guards off. A behavioral env-change test cannot isolate
// this — changing GOARCH also perturbs correlated feature-level keys — so the key
// membership is the precise pin.
func TestBuildConfigKeysIncludeTargetPlatform(t *testing.T) {
	has := func(k string) bool {
		for _, x := range buildConfigGoEnvKeys {
			if x == k {
				return true
			}
		}
		return false
	}
	if !has("GOOS") || !has("GOARCH") {
		t.Errorf("buildconfig keys must digest GOOS and GOARCH (code-determining), got %v", buildConfigGoEnvKeys)
	}
}

// TestBuildConfigSensitive is the behavioral sanity that buildConfig digests its
// keys at all: a GOFLAGS change (an isolated build-flag key) moves the digest.
func TestBuildConfigSensitive(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	base, err := buildConfig(dir)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	t.Setenv("GOFLAGS", "-tags=integration")
	changed, err := buildConfig(dir)
	if err != nil {
		t.Fatalf("buildConfig (changed): %v", err)
	}
	if changed == base {
		t.Error("GOFLAGS change did not move buildconfig")
	}
}

// TestMachineFingerprintExcludesTargetArch pins that GOARCH left the machine guard:
// the machine fingerprint carries no target-arch field, so it stays stable across a
// cross-compile (which buildconfig now covers).
func TestMachineFingerprintExcludesTargetArch(t *testing.T) {
	b, err := json.Marshal(MachineFacts{CPUModel: "x", PhysicalCores: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "arch") {
		t.Errorf("machine fingerprint contains an arch field (%s); target arch must ride buildconfig", b)
	}
}

// TestMachineFactsExcludesTransient pins REQ-guard-machine-transient structurally:
// the fingerprint holds no transient run condition, so one cannot enter by
// construction.
func TestMachineFactsExcludesTransient(t *testing.T) {
	transient := []string{"governor", "turbo", "boost", "thermal", "throttle", "load", "pin"}
	tp := reflect.TypeOf(MachineFacts{})
	for i := 0; i < tp.NumField(); i++ {
		name := strings.ToLower(tp.Field(i).Name)
		for _, bad := range transient {
			if strings.Contains(name, bad) {
				t.Errorf("MachineFacts field %q is a transient run condition; it must not enter the fingerprint", tp.Field(i).Name)
			}
		}
	}
}

func TestFingerprintStableAndSensitive(t *testing.T) {
	f := MachineFacts{CPUModel: "Ryzen", PhysicalCores: 8, LogicalCores: 16, TotalRAMBytes: 1 << 34, OS: "linux", KernelVersion: "7.0"}
	if f.Fingerprint() != f.Fingerprint() {
		t.Error("fingerprint not stable")
	}
	g := f
	g.TotalRAMBytes = 1 << 35
	if g.Fingerprint() == f.Fingerprint() {
		t.Error("fingerprint insensitive to a RAM change")
	}
}

func TestRuntimeConfigSensitive(t *testing.T) {
	base := runtimeConfig()
	t.Setenv("GOGC", "off")
	if runtimeConfig() == base {
		t.Error("runtimeconfig insensitive to a GOGC change")
	}
}

// TestCaptureCacheMemoizes pins the per-invocation cache: a second call for the same
// dir returns the memoized result rather than recomputing.
func TestCaptureCacheMemoizes(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	c := NewCache()
	first, err := c.Capture(dir)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	// Change the runtime-config environment: a fresh direct Capture would see it,
	// the cache must not (it returns the memoized value).
	t.Setenv("GOGC", "off")
	second, err := c.Capture(dir)
	if err != nil {
		t.Fatalf("Capture (second): %v", err)
	}
	if second != first {
		t.Errorf("cache recomputed: %+v != %+v", second, first)
	}
}
