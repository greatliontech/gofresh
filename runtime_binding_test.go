package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/quick"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestRuntimeBindingsShareGenerationAcrossPackages(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes two retained package artifacts")
	}
	if runtime.GOOS != "linux" {
		t.Skip("supported immutable-environment observations require Linux")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/bindings\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var subjects []Subject
	for _, name := range []string{"a", "b"} {
		pkgDir := filepath.Join(dir, name)
		if err := os.Mkdir(pkgDir, 0700); err != nil {
			t.Fatal(err)
		}
		const source = `package bound
import ("os"; "testing")
func TestRuntime(t *testing.T) {
 if os.Getenv("BOUND_VALUE") != "delivered" { t.Fatal("wrong process environment") }
 t.Log("actual-pwd=" + os.Getenv("PWD"))
}
`
		if err := os.WriteFile(filepath.Join(pkgDir, "p_test.go"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, Subject{Package: "example.com/bindings/" + name, Symbol: "TestRuntime"})
	}
	buildEnv := gotool.SetEnv(gotool.SetEnv(os.Environ(), "GOENV", "off"), "BOUND_VALUE", "compiler-only")
	runEnv := gotool.SetEnv(buildEnv, "BOUND_VALUE", "delivered")
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: buildEnv, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	facts := snapshot.view.facts
	priorObserve, priorGuardDir := viewTestHooks.observe, viewTestHooks.guardDir
	defer func() { viewTestHooks.observe, viewTestHooks.guardDir = priorObserve, priorGuardDir }()
	passes := 0
	viewTestHooks.observe = func() { passes++ }
	viewTestHooks.guardDir = func(got string) {
		if got != dir {
			t.Errorf("source/build observation moved to runtime directory %q", got)
		}
	}
	a := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "a", Environment: runEnv})
	b := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "b", Environment: runEnv})
	if passes != 0 || a.Snapshot() != snapshot || b.Snapshot() != snapshot {
		t.Fatal("runtime binding observed or replaced the source/build generation")
	}
	bindings := []*RuntimeBinding{a, b}
	failed, err := a.BeginPackage([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := failed.Close(t.Context()); !errors.Is(err, ErrUnitIncomplete) || len(result.Subjects) != 0 {
		t.Fatalf("incomplete sibling exposed evidence: %+v %v", result, err)
	}
	cancelled, err := b.BeginPackage([]Subject{subjects[1]})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := cancelled.Close(ctx); !errors.Is(err, context.Canceled) || len(result.Subjects) != 0 {
		t.Fatalf("cancelled sibling exposed evidence: %+v %v", result, err)
	}
	artifacts := make([]BuildBinding, len(subjects))
	binaries := make([]string, len(subjects))
	for i, subject := range subjects {
		build, err := snapshot.BuildDescription(subject.Package)
		if err != nil {
			t.Fatal(err)
		}
		binaries[i] = filepath.Join(t.TempDir(), "package.test")
		if out, err := runner.Run(t.Context(), build.Directory, build.Environment, "test", "-c", "-o", binaries[i], build.Package); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
		artifacts[i], err = snapshot.BindBuilt(subject.Package, subject.Package+"-retained")
		if err != nil {
			t.Fatal(err)
		}
	}
	run := func(binding *RuntimeBinding, i int) Fingerprint {
		t.Helper()
		u, err := binding.BeginPackage([]Subject{subjects[i]})
		if err != nil {
			t.Fatal(err)
		}
		defer u.Abort()
		c, err := u.Register(t.Context(), artifacts[i], ProcessDescription{Identity: "actual-process", Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		if pwd, _ := gotool.LookupEnv(c.Environment(), "PWD"); pwd != c.Directory() {
			t.Fatalf("process PWD=%q, directory=%q", pwd, c.Directory())
		}
		cmd, err := runner.Program(t.Context(), c.Directory(), c.Environment(), binaries[i], "-test.v", "-test.run=^TestRuntime$", "-test.testlogfile="+c.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "actual-pwd="+c.Directory()) {
			t.Fatalf("actual process: %v\n%s", err, out)
		}
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		result, err := u.Close(t.Context())
		if err != nil || result.Observation != SupportedObservation || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("bound closing: %+v %v", result, err)
		}
		fp := result.Subjects[0].Fingerprint
		inputs, err := runtimeinput.Describe(fp.RuntimeInputs, dir)
		if err != nil || !slices.Contains(inputs.EnvNames, "PWD") || !slices.Contains(inputs.EnvNames, "BOUND_VALUE") {
			t.Fatalf("honest runtime inventory: %+v %v", inputs, err)
		}
		if fp.Guards.Machine != "" || fp.Guards.RuntimeConfig != "" {
			t.Fatal("code record acquired measurement guards")
		}
		return fp
	}
	records := []Fingerprint{run(a, 0), run(b, 1)}
	for i, binding := range bindings {
		if verdict, err := binding.Check(t.Context(), subjects[i], records[i]); err != nil || verdict.Status != Valid {
			t.Fatalf("same binding check: %+v %v", verdict, err)
		}
		if verdict, err := bindings[1-i].Check(t.Context(), subjects[i], records[i]); err != nil || verdict.Status != Stale || !strings.Contains(verdict.Reason, "PWD") {
			t.Fatalf("cross-PWD check: %+v %v", verdict, err)
		}
	}
	// A new binding can execute the very same retained artifact. It cannot
	// overwrite either an old binding or the record already produced under it.
	before := passes
	rebound := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "b", Environment: gotool.SetEnv(runEnv, "UNREAD_RUNTIME_VALUE", "other")})
	if passes != before {
		t.Fatal("rebinding loaded source")
	}
	recordB := run(rebound, 0)
	if recordB.Guards != records[0].Guards || recordB.RuntimeDigest == records[0].RuntimeDigest {
		t.Fatal("runtime rebinding changed build guards or hid observed PWD motion")
	}
	if verdict, err := a.Check(t.Context(), subjects[0], records[0]); err != nil || verdict.Status != Valid {
		t.Fatalf("new binding mutated old binding: %+v %v", verdict, err)
	}
	later, err := session.Snapshot(t.Context(), subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := later.BindBuilt(subjects[0].Package, artifacts[0].identity)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.BeginIdentity(subjects[0])
	if err != nil {
		t.Fatal(err)
	}
	defer u.Abort()
	if _, err := u.Register(t.Context(), foreign, ProcessDescription{Identity: "borrowed"}); err == nil {
		t.Fatal("equal artifact identity crossed snapshot generations")
	}
	if snapshot.view.facts != facts || facts.guards != records[0].Guards || session.engine.producerEnvSet {
		t.Fatal("a binding or later generation mutated shared compilation state")
	}
	if got, err := a.CurrentFacts(t.Context(), subjects[0]); err != nil || got.Guards != records[0].Guards || got.RuntimeInputs != "" {
		t.Fatalf("later generation changed an old binding's immutable facts: %+v %v", got.Guards, err)
	}
}

func TestRuntimeBindingGuardAgreementAndClosing(t *testing.T) {
	if testing.Short() {
		t.Skip("observes source and runtime guard generations")
	}
	if runtime.GOOS != "linux" {
		t.Skip("measurement support requires Linux")
	}
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	prior := viewTestHooks.runtimeGuards
	defer func() { viewTestHooks.runtimeGuards = prior }()
	samples, machine := 0, "machine-a"
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { samples++; g.Machine = machine }
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if samples != 0 || snapshot.view.facts.guards.Machine != "" || snapshot.view.facts.guards.RuntimeConfig != "" {
		t.Fatal("source/build generation captured runtime guards")
	}
	a := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=100"}})
	if samples != 2 {
		t.Fatalf("recording-time runtime samples=%d, want agreement pair", samples)
	}
	fp, err := a.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	b := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200"}})
	other, err := b.CurrentFacts(t.Context(), subject)
	if err != nil || other.Guards.BuildConfig != fp.Guards.BuildConfig || other.Guards.RuntimeConfig == fp.Guards.RuntimeConfig {
		t.Fatalf("runtime configuration did not separate from compilation: %+v %v", other.Guards, err)
	}
	if got, err := b.Check(t.Context(), subject, fp); err != nil || got.Status != Stale || got.Reason != "runtimeconfig" {
		t.Fatalf("runtime-only drift: %+v %v", got, err)
	}
	v, err := a.newView([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := v.Sibling([]Subject{subject})
	if err != nil || sibling.runtime != v.runtime || sibling.guards() != fp.Guards {
		t.Fatalf("sibling lost its immutable runtime binding: %v", err)
	}
	seed, err := v.newSeededValidationView(t.Context())
	if err != nil || seed.runtime != v.runtime || seed.guards() != fp.Guards {
		t.Fatalf("seeded validation lost its runtime binding: %v", err)
	}
	if _, err := v.CaptureObserved(t.Context(), subject); err != nil {
		t.Fatalf("observability refinement used different guards: %v", err)
	}
	machine = "machine-b"
	c := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=100"}})
	if c.runtime.guards.Machine != machine || a.runtime.guards.Machine != "machine-a" {
		t.Fatal("new binding did not capture its own immutable machine observation")
	}
	if got, err := c.Check(t.Context(), subject, fp); err != nil || got.Status != Stale || got.Reason != "machine" {
		t.Fatalf("fresh binding ignored machine change: %+v %v", got, err)
	}
	if got, err := a.Check(t.Context(), subject, fp); !errors.Is(err, ErrViewChanged) || got != (Verdict{}) {
		t.Fatalf("old binding published before closing runtime drift: %+v %v", got, err)
	}
	if _, err := seed.newSeededValidationView(t.Context()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("seeded validation forgot old machine: %v", err)
	}
	if err := sibling.reobserveBase(t.Context()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("sibling comparison forgot old machine: %v", err)
	}
	if _, err := sibling.CaptureObserved(t.Context(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("refinement failed to close its runtime guards: %v", err)
	}
	// Binding refusal leaves all previously admitted bindings intact.
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { samples++; g.Machine = string(rune('a' + samples)) }
	if got, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{}); !errors.Is(err, ErrViewChanged) || got != nil {
		t.Fatalf("torn machine binding admitted: nonnil=%t error=%v", got != nil, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	viewTestHooks.runtimeGuards = func(*guard.RuntimeGuards) { cancel() }
	if got, err := snapshot.BindRuntime(ctx, RuntimeDescription{}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancelled runtime binding admitted: nonnil=%t error=%v", got != nil, err)
	}
	viewTestHooks.runtimeGuards = func(g *guard.RuntimeGuards) { g.Machine = "machine-a" }
	if got, err := a.Check(t.Context(), subject, fp); err != nil || got.Status != Valid {
		t.Fatalf("refused bindings damaged old binding: %+v %v", got, err)
	}
}

func TestRuntimeBindingEnvironmentOwnership(t *testing.T) {
	dir := t.TempDir()
	snapshot := &Snapshot{session: &Session{build: BuildDescription{Directory: dir, Environment: []string{"INHERITED=yes", "PWD=wrong"}}}, view: &View{kind: CodeResult}}
	for _, tc := range []struct {
		env  []string
		want []string
	}{
		{nil, []string{"INHERITED=yes", "PWD=" + dir}},
		{[]string{}, []string{"PWD=" + dir}},
		{[]string{"PWD=wrong", "EMPTY="}, []string{"EMPTY=", "PWD=" + dir}},
	} {
		binding := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: tc.env})
		if !slices.Equal(binding.runtime.env, tc.want) {
			t.Fatalf("runtime environment=%q, want %q", binding.runtime.env, tc.want)
		}
	}
	for _, env := range [][]string{{"DUP=1", "DUP=2"}, {"not-an-entry"}, {"=value"}} {
		if b, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{Environment: env}); err == nil || b != nil {
			t.Fatalf("malformed complete environment admitted: %q", env)
		}
	}
	if b, err := snapshot.BindRuntime(nil, RuntimeDescription{}); err == nil || b != nil {
		t.Fatal("nil binding context admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if b, err := snapshot.BindRuntime(ctx, RuntimeDescription{}); !errors.Is(err, context.Canceled) || b != nil {
		t.Fatalf("cancelled admission: %v %v", b, err)
	}
	// Every valid ordering and caller mutation has the same canonical owned
	// result. This property covers arbitrary values, including empty values.
	if err := quick.Check(func(value uint64, reverse bool) bool {
		alpha := "ALPHA=" + strings.Repeat("x", int(value%97))
		env := []string{alpha, "BETA=", "PWD=ignored"}
		if reverse {
			slices.Reverse(env)
		}
		b, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{Environment: env})
		if err != nil {
			return false
		}
		want := []string{alpha, "BETA=", "PWD=" + dir}
		for i := range env {
			env[i] = "BROKEN=changed"
		}
		return slices.Equal(b.runtime.env, want) && slices.IsSorted(b.runtime.env) && b.runtime.dir == dir
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotAndCodeBindingNeedNoMachineSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("observes code and measurement snapshots with unavailable machine support")
	}
	prior := guard.MachineFactSources
	guard.MachineFactSources = nil
	defer func() { guard.MachineFactSources = prior }()
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{CodeResult, Measurement} {
		snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, kind)
		if err != nil {
			t.Fatalf("snapshot required measurement support: %v", err)
		}
		binding, err := snapshot.BindRuntime(t.Context(), RuntimeDescription{})
		if kind == Measurement {
			if err == nil || binding != nil {
				t.Fatal("measurement binding ignored unavailable machine support")
			}
			continue
		}
		if err != nil {
			t.Fatalf("code binding probed machine support: %v", err)
		}
		fp, err := binding.CurrentFacts(t.Context(), subject)
		if err != nil || fp.Guards.Machine != "" || fp.Guards.RuntimeConfig != "" {
			t.Fatalf("code binding captured measurement guards: %+v %v", fp.Guards, err)
		}
		if got, err := binding.Check(t.Context(), subject, fp); err != nil || got.Status != Valid {
			t.Fatalf("code closing required machine support: %+v %v", got, err)
		}
	}
}
