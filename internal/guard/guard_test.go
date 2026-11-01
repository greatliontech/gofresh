package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/greatliontech/gofresh/gotool"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entry names both.
func ambientCapture(moduleDir string, kind Kind, buildInputs ...string) (Guards, error) {
	return captureUnderSnapshot(context.Background(), moduleDir, os.Environ(), kind, nil, buildInputs...)
}

func captureUnder(ctx context.Context, moduleDir string, env []string, kind Kind, buildInputs ...string) (Guards, error) {
	return captureUnderSnapshot(ctx, moduleDir, env, kind, nil, buildInputs...)
}

// captureUnderSnapshot is the one reader-building form the two above
// reduce to: a plain runner's reader over dir and env, primed with the
// snapshot when one is given.
func captureUnderSnapshot(ctx context.Context, moduleDir string, env []string, kind Kind, snapshot *gotool.EnvSnapshot, buildInputs ...string) (Guards, error) {
	return Capture(ctx, gotool.PrimedEnvReader(gotool.Runner{}, moduleDir, env, snapshot), env, kind, buildInputs...)
}

func TestCaptureNonEmpty(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	g, err := ambientCapture(t.TempDir(), Measurement)
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

func TestCodeCaptureSkipsMeasurementSupport(t *testing.T) {
	machineCalled := false
	runtimeCalled := false
	g, err := captureFor(context.Background(), gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), os.Environ()), CodeResult, nil,
		func() (MachineFacts, error) {
			machineCalled = true
			return MachineFacts{}, errors.New("unsupported")
		},
		func([]string) string {
			runtimeCalled = true
			return "runtime"
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if machineCalled || runtimeCalled {
		t.Fatalf("code capture evaluated measurement support: machine=%v runtime=%v", machineCalled, runtimeCalled)
	}
	if g.Toolchain == "" || g.BuildConfig == "" || g.Machine != "" || g.RuntimeConfig != "" {
		t.Fatalf("code guards = %+v", g)
	}
}

func TestMeasurementCaptureRequiresMachineSupport(t *testing.T) {
	want := errors.New("unsupported")
	_, err := captureFor(context.Background(), gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), os.Environ()), Measurement, nil,
		func() (MachineFacts, error) { return MachineFacts{}, want },
		func([]string) string { return "runtime" },
	)
	if !errors.Is(err, want) {
		t.Fatalf("measurement capture error = %v, want %v", err, want)
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

func TestCompareFactsRetainsAxisAndMissingEvidence(t *testing.T) {
	base := Guards{Toolchain: "t", BuildConfig: "b", Machine: "m", RuntimeConfig: "r"}
	for _, tc := range []struct {
		axis Axis
		set  func(*Guards, string)
	}{
		{ToolchainAxis, func(g *Guards, s string) { g.Toolchain = s }},
		{BuildConfigAxis, func(g *Guards, s string) { g.BuildConfig = s }},
		{MachineAxis, func(g *Guards, s string) { g.Machine = s }},
		{RuntimeConfigAxis, func(g *Guards, s string) { g.RuntimeConfig = s }},
	} {
		for _, value := range []string{"", "changed"} {
			for _, producing := range []bool{true, false} {
				rec, cur := base, base
				if producing {
					tc.set(&rec, value)
				} else {
					tc.set(&cur, value)
				}
				got := CompareFacts(rec, cur, Measurement)
				want := Mismatch{Axis: tc.axis, Missing: value == ""}
				if got != want || Compare(rec, cur, Measurement) != tc.axis.String() {
					t.Fatalf("comparison = %+v, want %+v", got, want)
				}
				if tc.axis == MachineAxis || tc.axis == RuntimeConfigAxis {
					if got := CompareFacts(rec, cur, CodeResult); got != (Mismatch{}) {
						t.Fatalf("code judgment read measurement guard: %+v", got)
					}
				}
			}
		}
	}
	if got := CompareFacts(base, base, Kind(99)); got != (Mismatch{Axis: KindAxis}) {
		t.Fatalf("unsupported kind = %+v", got)
	}
	if got := CompareFacts(Guards{}, base, Measurement); got != (Mismatch{Axis: ToolchainAxis, Missing: true}) {
		t.Fatalf("first missing guard = %+v", got)
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

// TestBuildConfigFailsClosed pins REQ-guard-buildconfig-failclosed: an unparseable
// go env output is refused with an error, never digested to a partial value that
// could stay stable across different generated code.
func TestBuildConfigFailsClosed(t *testing.T) {
	if _, err := buildConfigDigest([]byte("{not valid json"), os.Environ(), nil); err == nil {
		t.Error("malformed go env: want error (fail closed), got nil")
	}
	if _, err := buildConfigDigest([]byte(`{"GOOS":"linux"}`), os.Environ(), nil); err != nil {
		t.Errorf("well-formed env: unexpected error %v", err)
	}
}

// FuzzCompareCompleteness is a property witness for REQ-guard-completeness: for any
// guards, if an applicable recorded guard value is empty, Compare reports a mismatch
// — an unevaluable guard is never read as valid.
func FuzzCompareCompleteness(f *testing.F) {
	f.Add("tc", "bc", "m", "rc", "tc", "bc", "m", "rc", true)
	f.Add("", "bc", "m", "rc", "tc", "bc", "m", "rc", false)
	f.Fuzz(func(t *testing.T, rTc, rBc, rM, rRc, cTc, cBc, cM, cRc string, measurement bool) {
		rec := Guards{Toolchain: rTc, BuildConfig: rBc, Machine: rM, RuntimeConfig: rRc}
		cur := Guards{Toolchain: cTc, BuildConfig: cBc, Machine: cM, RuntimeConfig: cRc}
		kind := CodeResult
		if measurement {
			kind = Measurement
		}
		mismatch := Compare(rec, cur, kind)
		emptyApplicable := rec.Toolchain == "" || rec.BuildConfig == "" ||
			(kind == Measurement && (rec.Machine == "" || rec.RuntimeConfig == ""))
		if emptyApplicable && mismatch == "" {
			t.Fatalf("empty applicable guard read as valid: rec=%+v kind=%v", rec, kind)
		}
	})
}

// TestBuildConfigDigestsBuildInputs pins that caller-supplied build inputs (CLI
// flags outside GOFLAGS, PGO profile content) move the buildconfig digest — closing
// the false-valid hole where a build-invocation change gofresh cannot observe left
// the guard unmoved (REQ-guard-buildconfig).
func TestBuildConfigDigestsBuildInputs(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	base, err := buildConfigOfT(t, dir, os.Environ(), nil)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	withFlags, err := buildConfigOfT(t, dir, os.Environ(), []string{"-tags=integration"})
	if err != nil {
		t.Fatalf("buildConfig (flags): %v", err)
	}
	if withFlags == base {
		t.Error("a caller build input did not move buildconfig")
	}
	withPGO, err := buildConfigOfT(t, dir, os.Environ(), []string{"pgo:deadbeef"})
	if err != nil {
		t.Fatalf("buildConfig (pgo): %v", err)
	}
	if withPGO == withFlags {
		t.Error("distinct build inputs collide in the digest")
	}
}

func TestBuildConfigInputsAreUnambiguous(t *testing.T) {
	env := []byte(`{}`)
	one, err := buildConfigDigest(env, os.Environ(), []string{"input=x\nbuildinput=input=y"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := buildConfigDigest(env, os.Environ(), []string{"input=x", "input=y"})
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("distinct ordered build-input sequences share a digest")
	}
}

// TestBuildConfigSensitive is the behavioral sanity that buildConfig digests its
// keys at all: a GOFLAGS change (an isolated build-flag key) moves the digest.
func TestBuildConfigSensitive(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	base, err := buildConfigOfT(t, dir, os.Environ(), nil)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	t.Setenv("GOFLAGS", "-tags=integration")
	changed, err := buildConfigOfT(t, dir, os.Environ(), nil)
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
	base := runtimeConfig(os.Environ())
	t.Setenv("GOGC", "off")
	if runtimeConfig(os.Environ()) == base {
		t.Error("runtimeconfig insensitive to a GOGC change")
	}
}

func TestRuntimeConfigSeparatesEmbeddedEnvironmentEntries(t *testing.T) {
	// Moving a key-shaped suffix between these values preserves the old
	// delimiter-only encoding but changes the runtime's effective GOGC.
	first := []string{"GOGC=200\nGODEBUG=x", "GODEBUG=y"}
	second := []string{"GOGC=200", "GODEBUG=x\nGODEBUG=y"}
	if runtimeConfig(first) == runtimeConfig(second) {
		t.Fatal("distinct runtime configurations share a guard")
	}
	for _, env := range [][]string{nil, first, second} {
		var legacy strings.Builder
		for _, key := range runtimeConfigEnvKeys {
			value := ""
			for _, entry := range env {
				if strings.HasPrefix(entry, key+"=") {
					value = strings.TrimPrefix(entry, key+"=")
				}
			}
			fmt.Fprintf(&legacy, "%s=%s\n", key, value)
		}
		if runtimeConfig(env) == digest(legacy.String()) {
			t.Fatal("historical delimiter-only guard retained reuse eligibility")
		}
	}
}

func TestRuntimeConfigValueBoundaries(t *testing.T) {
	// Quantify the delimiter-shifting collision family rather than checking
	// just one pair. Environment values exclude NUL, but may contain newlines.
	property := func(a, b, c string) bool {
		if strings.ContainsRune(a+b+c, 0) {
			return true
		}
		first := []string{"GOGC=" + a + "\nGODEBUG=" + b, "GODEBUG=" + c}
		second := []string{"GOGC=" + a, "GODEBUG=" + b + "\nGODEBUG=" + c}
		return runtimeConfig(first) != runtimeConfig(second)
	}
	if err := quick.Check(property, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureRuntimeAdmission(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		env  []string
		kind Kind
	}{
		{"nil context", nil, nil, CodeResult},
		{"cancelled context", cancelled, nil, CodeResult},
		{"missing kind", t.Context(), nil, invalidKind},
		{"unknown kind", t.Context(), nil, Kind(99)},
		{"duplicate environment", t.Context(), []string{"A=1", "A=2"}, CodeResult},
		{"malformed environment", t.Context(), []string{"A"}, Measurement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CaptureRuntime(tc.ctx, tc.env, tc.kind)
			if err == nil || got != (RuntimeGuards{}) {
				t.Fatalf("invalid runtime capture admitted: %+v %v", got, err)
			}
			if tc.ctx == cancelled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
	if got, err := CaptureRuntime(t.Context(), []string{}, CodeResult); err != nil || got != (RuntimeGuards{}) {
		t.Fatalf("code capture required measurement facts: %+v %v", got, err)
	}
}

func TestRuntimeCaptureCancellationOutranksMachineAnswer(t *testing.T) {
	for _, machineError := range []error{nil, errors.New("probe refused")} {
		ctx, cancel := context.WithCancel(t.Context())
		got, err := captureRuntimeFor(ctx, nil, Measurement, func() (MachineFacts, error) {
			cancel()
			return MachineFacts{CPUModel: "captured"}, machineError
		}, func([]string) string {
			t.Fatal("cancelled machine capture continued into runtime capture")
			return ""
		})
		cancel()
		if !errors.Is(err, context.Canceled) || got != (RuntimeGuards{}) {
			t.Fatalf("cancelled machine capture returned an answer: %+v %v", got, err)
		}
	}
}

func TestCaptureUsesSuppliedEnvironmentForGuards(t *testing.T) {
	replace := func(env []string, key, value string) []string {
		prefix := key + "="
		result := make([]string, 0, len(env)+1)
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				result = append(result, entry)
			}
		}
		return append(result, prefix+value)
	}
	firstEnv := replace(os.Environ(), "GOGC", "100")
	firstEnv = replace(firstEnv, "PKG_CONFIG_PATH", "/first")
	secondEnv := replace(os.Environ(), "GOGC", "off")
	secondEnv = replace(secondEnv, "PKG_CONFIG_PATH", "/second")
	first, err := captureUnder(context.Background(), t.TempDir(), firstEnv, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	second, err := captureUnder(context.Background(), t.TempDir(), secondEnv, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if first.RuntimeConfig == second.RuntimeConfig {
		t.Fatal("supplied GOGC did not move runtime-config guard")
	}
	if first.BuildConfig == second.BuildConfig {
		t.Fatal("supplied PKG_CONFIG_PATH did not move build-config guard")
	}
}

// Two independent probes of one environment digest alike: a capture
// primed with a snapshot taken earlier equals one whose reader probes
// for itself, so the pass's batching of probes can never move a
// recorded guard (REQ-guard-buildconfig).
func TestPrimedAndProbedCapturesDigestAlike(t *testing.T) {
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), "", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	live, err := captureUnder(context.Background(), "", os.Environ(), CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	snapped, err := captureUnderSnapshot(context.Background(), "", os.Environ(), CodeResult, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if live != snapped {
		t.Fatalf("snapshot capture diverged from live capture:\n live    %+v\n snapped %+v", live, snapped)
	}
}

// The measurement guard's runtime-config digest reads runtimeEnv — the
// environment the measured processes run under — while the toolchain and
// build-config guards read env, the analysis identity: a runtime-only
// key injected into the measured processes moves the runtime guard and
// nothing else, and the same key in env alone moves nothing the runtime
// guard reads.
func TestCaptureDigestsRuntimeConfigFromTheRuntimeEnvironment(t *testing.T) {
	setKey := func(env []string, key, value string) []string {
		prefix := key + "="
		result := make([]string, 0, len(env)+1)
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				result = append(result, entry)
			}
		}
		return append(result, prefix+value)
	}
	env := setKey(os.Environ(), "GOGC", "100")
	dir := t.TempDir()
	base, err := Capture(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, env), env, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	runtimeOnly, err := Capture(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, env), setKey(env, "GOGC", "off"), Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeOnly.RuntimeConfig == base.RuntimeConfig {
		t.Error("a runtime-only GOGC change did not move the runtime-config guard")
	}
	if runtimeOnly.Toolchain != base.Toolchain || runtimeOnly.BuildConfig != base.BuildConfig {
		t.Error("a runtime-only change moved an analysis-identity guard")
	}
	analysisOnly, err := Capture(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, setKey(env, "GOGC", "off")), env, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if analysisOnly.RuntimeConfig != base.RuntimeConfig {
		t.Error("an analysis-env GOGC change moved the runtime-config guard, which reads runtimeEnv")
	}
}

// Capture refuses a nil reader and a malformed environment before any
// probe, and digests under the normalized environment.
func TestCaptureRefusesANilReaderAndAMalformedEnvironment(t *testing.T) {
	ctx := context.Background()
	if _, err := Capture(ctx, nil, os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("Capture(nil) = %v", err)
	}
	// An out-of-range kind refuses before any spawn.
	spawned := false
	silent := gotool.NewEnvReader(gotool.Runner{Prepare: func(*exec.Cmd) { spawned = true }}, t.TempDir(), os.Environ())
	if _, err := Capture(ctx, silent, os.Environ(), Kind(7)); err == nil || !strings.Contains(err.Error(), "invalid result kind") || spawned {
		t.Fatalf("an invalid kind: err = %v, spawned = %v; want the refusal with no spawn", err, spawned)
	}
	dup := append(append([]string(nil), os.Environ()...), "GOFLAGS=a", "GOFLAGS=b")
	if _, err := Capture(ctx, gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), dup), os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "guard:") {
		t.Fatalf("a duplicated key captured: %v", err)
	}
}

// A capture through an unprimed reader takes the pass's one snapshot
// through THAT reader, so the caller's later keys read it: one `go env
// -json` for the pass, whichever side asks first.
func TestCapturePrimesTheCallersReader(t *testing.T) {
	ctx := context.Background()
	snapshots := 0
	r := gotool.NewEnvReader(gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 2 && cmd.Args[1] == "env" && cmd.Args[2] == "-json" {
			snapshots++
		}
	}}, t.TempDir(), os.Environ())
	if _, err := Capture(ctx, r, os.Environ(), CodeResult); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Value(ctx, "GOFLAGS"); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("%d snapshots for one pass, want 1 (the capture primed the caller's reader)", snapshots)
	}
}

// The toolchain guard read from the pass's snapshot is byte-identical
// to the `go version` line minus its prefix — the former live probe's
// value — on the running toolchain, under a target platform in the
// environment too (the host keys, never GOOS/GOARCH), so no recorded
// guard moves and the pass pays one spawn for both code guards
// (REQ-guard-toolchain).
func TestToolchainGuardIsGoVersionsOwnForm(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	ctx := context.Background()
	dir := t.TempDir()
	env := os.Environ()
	out, err := gotool.Runner{}.Run(ctx, dir, env, "version")
	if err != nil {
		t.Fatal(err)
	}
	live := strings.TrimPrefix(strings.TrimSpace(string(out)), "go version ")
	reader := gotool.NewEnvReader(gotool.Runner{}, dir, env)
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := toolchainOf(snapshot); err != nil || got != live {
		t.Fatalf("toolchain guard %q (%v), `go version` says %q", got, err, live)
	}
	// A target platform in the environment is the build-configuration
	// guard's business: `go version` still prints the host platform,
	// and so must the derived guard — the host keys, never GOOS/GOARCH.
	cross := gotool.SetEnv(gotool.SetEnv(env, "GOOS", "windows"), "GOARCH", "arm64")
	out, err = gotool.Runner{}.Run(ctx, dir, cross, "version")
	if err != nil {
		t.Fatal(err)
	}
	if crossLive := strings.TrimPrefix(strings.TrimSpace(string(out)), "go version "); crossLive != live {
		t.Fatalf("`go version` moved under a target platform: %q vs %q", crossLive, live)
	}
	crossSnapshot, err := gotool.NewEnvReader(gotool.Runner{}, dir, cross).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := toolchainOf(crossSnapshot); err != nil || got != live {
		t.Fatalf("toolchain guard %q (%v) under GOOS=windows GOARCH=arm64, want the host's %q", got, err, live)
	}
	// The capture reads the same value, and pays the reader's one
	// snapshot for it: no `go version` spawn beside the `go env -json`.
	spawns := 0
	counted := gotool.NewEnvReader(gotool.Runner{Prepare: func(c *exec.Cmd) { spawns++ }}, dir, env)
	g, err := Capture(ctx, counted, env, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if g.Toolchain != live {
		t.Fatalf("captured toolchain guard %q, want %q", g.Toolchain, live)
	}
	if spawns != 1 {
		t.Fatalf("the capture paid %d go spawns for its code guards, want the one snapshot", spawns)
	}
	// A document that answers no version, or no host platform (a shim,
	// a toolchain before GOVERSION existed), is no identity: the capture
	// refuses naming the missing key, never a non-empty guard over an
	// empty part. The program resolves through the parent's PATH
	// (Program's rule), so the shim goes there; these arms are the
	// test's last.
	shim := t.TempDir()
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, missing := range []string{"GOVERSION", "GOHOSTOS", "GOHOSTARCH"} {
		document := map[string]string{"GOFLAGS": "", "GOVERSION": "go1.99.0", "GOHOSTOS": "linux", "GOHOSTARCH": "amd64"}
		delete(document, missing)
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shim, "go"), []byte("#!/bin/sh\necho '"+string(body)+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		shimmed := gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ())
		if g, err := Capture(ctx, shimmed, os.Environ(), CodeResult); err == nil || !strings.Contains(err.Error(), "no "+missing) {
			t.Fatalf("a document without %s captured %+v, %v; want a refusal naming it", missing, g, err)
		}
	}
}

// buildConfigOfT digests the build config of dir under env as the
// guard does: the pass's one snapshot, then the digest over its bytes.
func buildConfigOfT(t *testing.T, dir string, env, buildInputs []string) (string, error) {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		return "", err
	}
	return buildConfigDigest(snapshot.JSON, env, buildInputs)
}
