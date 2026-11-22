package gofresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func TestUnitAndProducerFacadeRealTestingChdirEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux outcome method and PWD testlog sequence")
	}
	root := t.TempDir()
	pkgDir := filepath.Join(root, "internal", "cmd")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/chdire2e\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "fixture.txt"), []byte("initial-fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const cleanTestSrc = `package cmd

import (
	"os"
	"testing"
)

func TestUsesChdirAndTempScratch(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := os.ReadDir("."); err != nil {
		t.Fatal(err)
	}
}

func TestEnvReaderSibling(t *testing.T) {
	_ = os.Getenv("CHDIRE2E_CONFIG")
}

//gofresh:pure
func TestPureRelativeFileSibling(t *testing.T) {
	data, err := os.ReadFile("fixture.txt")
	if err != nil || len(data) == 0 {
		t.Fatalf("ReadFile(fixture.txt): %v", err)
	}
}
`
	if err := os.WriteFile(filepath.Join(pkgDir, "cmd_test.go"), []byte(cleanTestSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg := "example.com/chdire2e/internal/cmd"
	subChdir := Subject{Package: pkg, Symbol: "TestUsesChdirAndTempScratch"}
	subEnv := Subject{Package: pkg, Symbol: "TestEnvReaderSibling"}
	subRel := Subject{Package: pkg, Symbol: "TestPureRelativeFileSibling"}

	env := gotool.SetEnv(os.Environ(), "CHDIRE2E_CONFIG", "v1")
	runner := gotool.Runner{}
	session, err := NewSession(t.Context(), BuildDescription{
		Directory:   root,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subChdir, subEnv, subRel}, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: pkgDir})
	buildDesc, err := snapshot.BuildDescription(pkg)
	if err != nil {
		t.Fatalf("BuildDescription: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "cmd.test")
	buildArgs := append([]string{"test", "-c", "-o", binary}, buildDesc.Flags...)
	buildArgs = append(buildArgs, buildDesc.Package)
	if out, err := runner.Run(t.Context(), buildDesc.Directory, buildDesc.Environment, buildArgs...); err != nil {
		t.Fatalf("go test -c: %v\n%s", err, out)
	}
	built, err := snapshot.BindBuilt(pkg, "cmd-test-bin")
	if err != nil {
		t.Fatalf("BindBuilt: %v", err)
	}

	// 1. Solo execution of TestEnvReaderSibling succeeds with SupportedObservation
	// (no assume_pure) because unreached TestUsesChdirAndTempScratch no longer
	// poisons sibling Tier-2 package scans when TrackedChdirSafe holds.
	soloUnit, err := binding.Begin(subEnv)
	if err != nil {
		t.Fatalf("Begin(subEnv): %v", err)
	}
	soloFinal, err := soloUnit.Execute(t.Context(), built, ProcessDescription{
		Identity: "solo-env",
		Capture:  filepath.Join(t.TempDir(), "solo.testlog"),
	}, func(ctx context.Context, c Contribution) (Terminal, error) {
		cmd, err := testProgramCmd(ctx, c.Directory(), c.Environment(), binary,
			"-test.v", "-test.run=^TestEnvReaderSibling$", "-test.testlogfile="+c.Capture())
		if err != nil {
			return Terminal{}, err
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("solo run failed: %v\n%s", err, out)
		}
		return Terminal{Kind: NormalCompletion}, nil
	})
	if err != nil {
		t.Fatalf("solo Execute: %v", err)
	}
	if soloFinal.Observation != SupportedObservation || soloFinal.Verdict.Status != Valid {
		t.Fatalf("solo final = (obs=%v, verdict=%+v), want SupportedObservation + Valid", soloFinal.Observation, soloFinal.Verdict)
	}

	// 2. Shared-process PackageExecution running BOTH TestUsesChdirAndTempScratch
	// and TestPureRelativeFileSibling in one binary invocation:
	// - TestUsesChdirAndTempScratch stays Unverifiable (reaches testing.Chdir)
	// - TestPureRelativeFileSibling is Valid with its post-restoration relative
	//   read of fixture.txt bound in RuntimeInputs, and editing fixture.txt turns
	//   its check Verdict Stale!
	scratchRoot := t.TempDir()
	batchUnit, err := binding.BeginPackage([]Subject{subChdir, subRel})
	if err != nil {
		t.Fatalf("BeginPackage: %v", err)
	}
	capturePath := filepath.Join(t.TempDir(), "batch.testlog")
	batchFinal, err := batchUnit.Execute(t.Context(), built, ProcessDescription{
		Identity:    "batch-chdir",
		Capture:     capturePath,
		ScratchRoot: scratchRoot,
	}, func(ctx context.Context, c Contribution) (Terminal, error) {
		runEnv := gotool.SetEnv(c.Environment(), "TMPDIR", scratchRoot)
		cmd, err := testProgramCmd(ctx, c.Directory(), runEnv, binary,
			"-test.v", "-test.run=^(TestUsesChdirAndTempScratch|TestPureRelativeFileSibling)$", "-test.testlogfile="+c.Capture())
		if err != nil {
			return Terminal{}, err
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("batch run failed: %v\n%s", err, out)
		}
		return Terminal{Kind: NormalCompletion}, nil
	})
	if err != nil {
		t.Fatalf("batch Execute: %v", err)
	}
	if batchFinal.Observation != IdentityObservation {
		t.Fatalf("batch Observation = %v, want IdentityObservation", batchFinal.Observation)
	}
	if batchFinal.Subjects[0].Verdict.Status != Unverifiable || !strings.Contains(batchFinal.Subjects[0].Verdict.Reason, "testing.Chdir") {
		t.Fatalf("TestUsesChdirAndTempScratch verdict = %+v, want Unverifiable (testing.Chdir)", batchFinal.Subjects[0].Verdict)
	}
	if batchFinal.Subjects[1].Verdict.Status != Valid {
		t.Fatalf("TestPureRelativeFileSibling verdict = %+v, want Valid", batchFinal.Subjects[1].Verdict)
	}
	relFP := batchFinal.Subjects[1].Fingerprint

	acct, ok := batchUnit.Account()
	if !ok || acct.Inputs.Unverifiable {
		t.Fatalf("batch Account.Inputs = %+v (ok=%v), want verifiable", acct.Inputs, ok)
	}

	// Mutating fixture.txt must invalidate relFP with RuntimeInputsCause!
	if err := os.WriteFile(filepath.Join(pkgDir, "fixture.txt"), []byte("mutated-fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reSession, err := NewSession(t.Context(), BuildDescription{
		Directory:   root,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	reSnap, err := reSession.Snapshot(t.Context(), []Subject{subRel}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	reBind := bindTestRuntime(t, reSnap, RuntimeDescription{Directory: pkgDir})
	staleVerdict, err := reBind.Check(t.Context(), subRel, relFP)
	if err != nil {
		t.Fatalf("Check after fixture edit: %v", err)
	}
	if staleVerdict.Status != Stale || staleVerdict.Ground.Cause.Kind != RuntimeInputsCause {
		t.Fatalf("Check after fixture edit = %+v, want Stale (RuntimeInputsCause)", staleVerdict)
	}

	// 3. Negative end-to-end control: adding a reachable raw os.Chdir test in the
	// binary revokes tracked-chdir support, sealing working-directory change!
	if err := os.WriteFile(filepath.Join(pkgDir, "fixture.txt"), []byte("initial-fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rawChdirSrc := cleanTestSrc + `
func TestRawOSChdir(t *testing.T) {
	_ = os.Chdir(".")
}
`
	if err := os.WriteFile(filepath.Join(pkgDir, "cmd_test.go"), []byte(rawChdirSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	badSession, err := NewSession(t.Context(), BuildDescription{
		Directory:   root,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	badSnap, err := badSession.Snapshot(t.Context(), []Subject{subChdir, subRel}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	badBind := bindTestRuntime(t, badSnap, RuntimeDescription{Directory: pkgDir})
	badBuilt, err := badSnap.BindBuilt(pkg, "bad-cmd-bin")
	if err != nil {
		t.Fatal(err)
	}
	badUnit, err := badBind.BeginIdentity(subRel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badUnit.Execute(t.Context(), badBuilt, ProcessDescription{
		Identity:    "bad-chdir",
		Capture:     capturePath,
		ScratchRoot: scratchRoot,
	}, func(context.Context, Contribution) (Terminal, error) {
		return Terminal{Kind: NormalCompletion}, nil
	}); err != nil {
		t.Fatalf("badUnit.Execute: %v", err)
	}
	badAcct, ok := badUnit.Account()
	if !ok || !badAcct.Inputs.Unverifiable {
		t.Fatalf("expected raw os.Chdir binary to revoke tracked-chdir support and seal Unverifiable, got %+v (ok=%v)", badAcct.Inputs, ok)
	}
}

func TestPrepareTrackedChdirSupportCutUnavailableAndProgressAccounting(t *testing.T) {
	if cache, err := testenv.GoBuildCache(t.Context(), os.Environ()); err == nil && cache != "" {
		t.Setenv("GOCACHE", cache)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/cutchdir\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "p_test.go"), []byte("package cutchdir\nimport \"testing\"\nfunc TestChdir(t *testing.T) { t.Chdir(t.TempDir()) }\nfunc TestPure(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var phases []string
	env := os.Environ()
	session, err := NewSession(t.Context(), BuildDescription{
		Directory:   root,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{
		Execution: PackageExecution,
		Progress: func(p Progress) {
			phases = append(phases, p.Phase)
		},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	subPure := Subject{Package: "example.com/cutchdir", Symbol: "TestPure"}
	subChdir := Subject{Package: "example.com/cutchdir", Symbol: "TestChdir"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subPure, subChdir}, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	frame := runtimeinput.CaptureProducerFrame(t.Context(), root, root, runtimeinput.FrameOptions{})

	// Cancelled call emits "cancelled" progress phase.
	cancelCtx, cancel := context.WithCancel(t.Context())
	cancel()
	phases = nil
	if _, err := snapshot.prepareTrackedChdirSupport(cancelCtx, frame, "example.com/cutchdir"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if !slices.Contains(phases, "cancelled") {
		t.Fatalf("expected cancelled progress phase, got %v", phases)
	}

	// Normal call populates persisted proofs memo, and a fresh Snapshot's
	// prepareTrackedChdirSupport emits "served" via beginOperation + accountPass.
	if _, err := snapshot.prepareTrackedChdirSupport(t.Context(), frame, "example.com/cutchdir"); err != nil {
		t.Fatalf("prepareTrackedChdirSupport: %v", err)
	}
	snapshot2, err := session.Snapshot(t.Context(), []Subject{subPure, subChdir}, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot 2: %v", err)
	}
	phases = nil
	if _, err := snapshot2.prepareTrackedChdirSupport(t.Context(), frame, "example.com/cutchdir"); err != nil {
		t.Fatalf("warm prepareTrackedChdirSupport: %v", err)
	}
	if !slices.Contains(phases, "served") {
		t.Fatalf("expected served progress phase on warm prepareTrackedChdirSupport, got %v", phases)
	}

	// Simulate an analysis-budget cut recorded during ensureObservable on a
	// snapshot with hasObserved == false: both validate and sibling.validate
	// must surface ErrAnalysisUnavailable.
	snapshot.mu.Lock()
	snapshot.cutUnavailable = fmt.Errorf("simulated cut: %w", ErrAnalysisUnavailable)
	snapshot.mu.Unlock()

	sibling, err := snapshot.sibling([]Subject{subPure})
	if err != nil {
		t.Fatalf("sibling: %v", err)
	}
	if err := sibling.validate(t.Context()); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("sibling.validate = %v, want ErrAnalysisUnavailable", err)
	}
	if err := snapshot.validate(t.Context()); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("snapshot.validate = %v, want ErrAnalysisUnavailable", err)
	}
}
