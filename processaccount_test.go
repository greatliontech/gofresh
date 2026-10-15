package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestProcessAccountIsOwnedDataWithoutProducingCapability(t *testing.T) {
	// Check the actual public value graph, not documentation or field names.
	// Even an embedded capability must not escape through this reporting API.
	forbidden := []reflect.Type{
		reflect.TypeFor[Fingerprint](), reflect.TypeFor[Verdict](),
		reflect.TypeFor[runtimeinput.Observation](), reflect.TypeFor[runtimeinput.OutcomeSupport](),
		reflect.TypeFor[runtimeinput.ProducerFrame](), reflect.TypeFor[Contribution](),
	}
	var inspect func(reflect.Type)
	inspect = func(typ reflect.Type) {
		t.Helper()
		if slices.Contains(forbidden, typ) || typ.NumMethod() != 0 {
			t.Fatalf("process account exposes capability %v", typ)
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				inspect(typ.Field(i).Type)
			}
		case reflect.String, reflect.Bool, reflect.Uint8:
		default:
			t.Fatalf("process account contains non-owned data %v", typ)
		}
	}
	inspect(reflect.TypeFor[ProcessAccount]())
	for _, account := range []func() (ProcessAccount, bool){
		(*Unit)(nil).Account, (*PackageUnit)(nil).Account,
		(&Unit{}).Account, (&PackageUnit{}).Account,
	} {
		if got, ok := account(); ok || got != (ProcessAccount{}) {
			t.Fatalf("uninitialized unit invented an execution: %+v %t", got, ok)
		}
	}
}

func TestProcessAccountPreservesFinalizedFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes retained artifacts across closing dispositions")
	}
	if runtime.GOOS != "linux" {
		t.Skip("admitted immutable-environment outcome support requires Linux")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	env := gotool.SetEnv(os.Environ(), "OUTCOME_VALUE", "accounted")
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "account.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(t.Context(), build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build retained artifact: %v\n%s", err, output)
	}
	bound, err := snapshot.BindBuilt(subject.Package, "retained-account-artifact")
	if err != nil {
		t.Fatal(err)
	}
	register := func(t *testing.T) (*PackageUnit, Contribution) {
		t.Helper()
		u, err := binding.BeginPackage([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(u.Abort)
		if got, ok := u.Account(); ok || got != (ProcessAccount{}) {
			t.Fatalf("unregistered unit invented an execution: %+v %t", got, ok)
		}
		c, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := u.Account()
		want := ProcessAccount{Process: t.Name(), Artifact: "retained-account-artifact", Prepared: true}
		if !ok || got != want {
			t.Fatalf("registered account = %+v, want %+v", got, want)
		}
		return u, c
	}
	run := func(t *testing.T, c Contribution) {
		t.Helper()
		cmd, err := runner.Program(t.Context(), c.Directory(), c.Environment(), binary, "-test.v", "-test.run=^TestRead$", "-test.testlogfile="+c.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "=== RUN   TestRead") {
			t.Fatalf("retained artifact execution: %v\n%s", err, output)
		}
	}
	// The expected reporting bytes come from the native finalizer's public
	// CompletedState boundary, before any deliberate closing refusal.
	completed := func(t *testing.T, c Contribution) (runtimeinput.State, string, string) {
		t.Helper()
		x := c.execution
		receipt, err := x.frame.Completion(x.process.Identity, c.Environment(), x.terminal.Reason)
		if err != nil {
			t.Fatal(err)
		}
		in := runtimeinput.ProducerIngest{Identity: x.process.Identity, Env: c.Environment(), Completion: receipt, Outcome: x.support, Runner: runner}
		observe := x.frame.Observe
		if x.outcomeReason != "" {
			observe = x.frame.ObserveInputs
		}
		observation, reason, err := observe(t.Context(), c.Capture(), in)
		if err != nil {
			t.Fatal(err)
		}
		state, err := runtimeinput.CompletedState(observation)
		if err != nil {
			t.Fatal(err)
		}
		return state, reason, observation.Attribution
	}
	var closed *PackageUnit
	var closedAccount ProcessAccount
	t.Run("successful account owns canonical data", func(t *testing.T) {
		u, c := register(t)
		run(t, c)
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		want, reason, attribution := completed(t, c)
		result, err := u.Close(t.Context())
		if err != nil || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid {
			t.Fatalf("close: %+v %v", result, err)
		}
		account, ok := u.Account()
		if !ok || account.Observation != SupportedObservation || account.Inputs != want || account.ObservationReason != reason || account.Attribution != attribution || !account.Inputs.OK {
			t.Fatalf("finalized account: %+v, want native state %+v", account, want)
		}
		fp := result.Subjects[0].Fingerprint
		if account.Inputs.Manifest != fp.RuntimeInputs || account.Inputs.Digest != fp.RuntimeDigest || account.Observation != result.Observation || account.Terminal != result.Terminal || account.OutcomeReason != result.OutcomeReason {
			t.Fatal("successful close and process account disagree")
		}
		inputs, err := runtimeinput.Describe(account.Inputs.Manifest, dir)
		if err != nil || !slices.Contains(inputs.EnvNames, "OUTCOME_VALUE") {
			t.Fatalf("actual process read missing from account: %+v %v", inputs, err)
		}
		closed, closedAccount = u, account
		account.Inputs = runtimeinput.State{Manifest: "caller replacement", Reason: "changed"}
		account.Terminal = Terminal{Kind: NeverStarted, Reason: "changed"}
		account.Process = "changed"
		if err := os.Remove(c.Capture()); err != nil {
			t.Fatal(err)
		}
		u.Abort()
		if got, _ := u.Account(); got != closedAccount {
			t.Fatalf("returned data, removed capture or abort changed closed account: %+v", got)
		}
	})
	for _, ending := range []string{"missing terminal", "never started", "cancelled", "aborted"} {
		t.Run(ending+" stays unknown", func(t *testing.T) {
			u, c := register(t)
			terminal := Terminal{}
			if ending == "never started" {
				terminal = Terminal{Kind: NeverStarted, Reason: "no execution slot"}
			} else if ending == "cancelled" || ending == "aborted" {
				run(t, c)
				terminal = Terminal{Kind: NormalCompletion}
			}
			if terminal.Kind != 0 {
				if err := u.Submit(c, terminal); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := u.Account()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if ending == "cancelled" {
				cancel()
			} else if ending == "aborted" {
				u.Abort()
			}
			result, err := u.Close(ctx)
			if err == nil || !reflect.DeepEqual(result, FinalizedProcess{}) {
				t.Fatalf("unfinalized execution returned evidence: %+v %v", result, err)
			}
			if ending == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation lost: %v", err)
			}
			if err := os.Remove(c.Capture()); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			got, ok := u.Account()
			if !ok || got != before || got.Terminal != terminal || got.Observation != UnknownObservation || got.Inputs != (runtimeinput.State{}) {
				t.Fatalf("unfinalized account invented observations: %+v", got)
			}
		})
	}
	for _, missing := range []bool{false, true} {
		name := "abnormal completion"
		if missing {
			name = "missing capture"
		}
		t.Run(name, func(t *testing.T) {
			u, c := register(t)
			terminal := Terminal{Kind: NormalCompletion}
			if !missing {
				// A complete-looking flushed capture cannot override the
				// executor's abnormal terminal assertion.
				run(t, c)
				terminal = Terminal{Kind: AbnormalCompletion, Reason: "harness killed after output"}
			}
			if err := u.Submit(c, terminal); err != nil {
				t.Fatal(err)
			}
			want, reason, attribution := completed(t, c)
			result, err := u.Close(t.Context())
			if err != nil || result.Observation != IncompleteObservation {
				t.Fatalf("incomplete closing: %+v %v", result, err)
			}
			got, ok := u.Account()
			if !ok || got.Terminal != terminal || got.Observation != IncompleteObservation || got.ObservationReason == "" || got.ObservationReason != reason || got.Inputs != want || got.Attribution != attribution || !got.Inputs.Unverifiable || got.Inputs.Manifest == "" {
				t.Fatalf("incomplete native state lost: %+v, want %+v", got, want)
			}
		})
	}
	t.Run("identity-only singleton", func(t *testing.T) {
		u, err := binding.BeginIdentity(subject)
		if err != nil {
			t.Fatal(err)
		}
		defer u.Abort()
		c, err := u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		run(t, c)
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		want, reason, attribution := completed(t, c)
		result, err := u.Close(t.Context())
		if err != nil || result.Observation != IdentityObservation {
			t.Fatalf("identity-only closing: %+v %v", result, err)
		}
		got, ok := u.Account()
		if !ok || got.Observation != IdentityObservation || got.Inputs != want || got.ObservationReason != reason || got.Attribution != attribution || got.OutcomeReason == "" {
			t.Fatalf("identity-only account promoted or lost native data: %+v", got)
		}
	})
	for _, cancelled := range []bool{false, true} {
		name := "abort after observation"
		if cancelled {
			name = "caller cancellation outranks abort after observation"
		}
		t.Run(name, func(t *testing.T) {
			u, c := register(t)
			run(t, c)
			if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			want, _, _ := completed(t, c)
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			prior := viewTestHooks.observe
			defer func() { viewTestHooks.observe = prior }()
			pause := sync.OnceFunc(func() { close(entered); <-resume })
			viewTestHooks.observe = pause
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type closing struct {
				result FinalizedProcess
				err    error
			}
			done := make(chan closing, 1)
			go func() { result, err := u.Close(ctx); done <- closing{result, err} }()
			select {
			case <-entered:
			case got := <-done:
				t.Fatalf("close missed post-observation barrier: %v", got.err)
			case <-time.After(30 * time.Second):
				t.Fatal("close did not reach post-observation barrier")
			}
			before, ok := u.Account()
			if !ok || before.Inputs != want || before.Observation != SupportedObservation {
				t.Errorf("facts unavailable during closing: %+v", before)
			}
			u.Abort()
			wantErr := ErrUnitAborted
			if cancelled {
				cancel()
				wantErr = context.Canceled
			}
			release()
			got := <-done
			if !errors.Is(got.err, wantErr) || !reflect.DeepEqual(got.result, FinalizedProcess{}) {
				t.Fatalf("aborted close published evidence or lost cause: %+v %v", got.result, got.err)
			}
			if err := os.Remove(c.Capture()); err != nil {
				t.Fatal(err)
			}
			if account, _ := u.Account(); account != before {
				t.Fatalf("abort or report read changed finalized facts: %+v", account)
			}
		})
	}
	for _, singleton := range []bool{false, true} {
		name := "package source drift"
		if singleton {
			name = "singleton source drift"
		}
		t.Run(name, func(t *testing.T) {
			// Both public Close forms must suppress every reusable result,
			// while retaining the exact observation established before refusal.
			var c Contribution
			var account func() (ProcessAccount, bool)
			var abort func()
			var submit func(Contribution, Terminal) error
			var closeUnit func() (bool, error)
			if singleton {
				u, err := binding.Begin(subject)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(u.Abort)
				c, err = u.Register(t.Context(), bound, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
				if err != nil {
					t.Fatal(err)
				}
				account, abort, submit = u.Account, u.Abort, u.Submit
				closeUnit = func() (bool, error) {
					result, err := u.Close(t.Context())
					return result == (Finalized{}), err
				}
			} else {
				u, contribution := register(t)
				c = contribution
				account, abort, submit = u.Account, u.Abort, u.Submit
				closeUnit = func() (bool, error) {
					result, err := u.Close(t.Context())
					return reflect.DeepEqual(result, FinalizedProcess{}), err
				}
			}
			run(t, c)
			if err := submit(c, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(dir, "observed_test.go")
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(sourcePath, source, 0600); err != nil {
					t.Error(err)
				}
			}()
			changed := strings.Replace(string(source), "OUTCOME_VALUE", "CHANGED_SOURCE", 1)
			if err := os.WriteFile(sourcePath, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			// Source motion also moves the producing bracket. Compare the
			// canonical native state of that actual span, including its refusal.
			want, reason, attribution := completed(t, c)
			if zero, err := closeUnit(); !errors.Is(err, ErrViewChanged) || !zero {
				t.Fatalf("source drift exposed evidence: zero=%t %v", zero, err)
			}
			got, ok := account()
			if !ok || got.Process != t.Name() || got.Artifact != "retained-account-artifact" || !got.Prepared || got.Terminal != (Terminal{Kind: NormalCompletion}) || got.Observation != SupportedObservation || got.Inputs != want || got.ObservationReason != reason || got.Attribution != attribution {
				t.Fatalf("refused closing lost process facts: %+v, want native state %+v", got, want)
			}
			if err := os.Remove(c.Capture()); err != nil {
				t.Fatal(err)
			}
			abort()
			if later, _ := account(); later != got {
				t.Fatal("failed unit account changed on abort or capture deletion")
			}
		})
	}
	if closed == nil {
		t.Fatal("independently closed fixture did not complete")
	}
	if got, _ := closed.Account(); got != closedAccount {
		t.Fatal("later independent units changed the closed process account")
	}
}

func TestProcessAccountDuringRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("prepares a real process at a deterministic registration boundary")
	}
	if runtime.GOOS != "linux" {
		t.Skip("fixture expects admitted immutable-environment outcome support")
	}
	dir := writeSupportedViewModule(t)
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	bound, err := snapshot.BindBuilt(subject.Package, "declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, cancelled := range []bool{false, true} {
		name := "prepared"
		if cancelled {
			name = "failed reservation"
		}
		t.Run(name, func(t *testing.T) {
			u, err := binding.Begin(subject)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			entered, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			u.producing.view.beforeOutcomeIssue = func() { close(entered); <-resume }
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type registered struct {
				c   Contribution
				err error
			}
			done := make(chan registered, 1)
			go func() {
				c, err := u.Register(ctx, bound, ProcessDescription{Identity: "reserved-process"})
				done <- registered{c, err}
			}()
			select {
			case <-entered:
			case got := <-done:
				t.Fatalf("preparation missed barrier: %v", got.err)
			case <-time.After(30 * time.Second):
				t.Fatal("preparation did not reach barrier")
			}
			want := ProcessAccount{Process: "reserved-process", Artifact: "declared-artifact"}
			if got, ok := u.Account(); !ok || got != want {
				t.Errorf("pending reservation account: %+v %t", got, ok)
			}
			if cancelled {
				cancel()
			}
			release()
			result := <-done
			if cancelled {
				if !errors.Is(result.err, context.Canceled) || result.c != (Contribution{}) {
					t.Fatalf("cancelled reservation returned a handle: %+v", result)
				}
			} else {
				if result.err != nil {
					t.Fatal(result.err)
				}
				want.Prepared = true
				// Concurrent reads observe either side of the terminal
				// submission, never a partially populated terminal fact.
				var readers sync.WaitGroup
				readers.Go(func() {
					for range 100 {
						got, ok := u.Account()
						if !ok || (got.Terminal != (Terminal{}) && got.Terminal != (Terminal{Kind: NeverStarted, Reason: "no execution"})) {
							t.Errorf("torn concurrent submission account: %+v", got)
						}
					}
				})
				if err := u.Submit(result.c, Terminal{Kind: NeverStarted, Reason: "no execution"}); err != nil {
					t.Error(err)
				}
				readers.Wait()
				want.Terminal = Terminal{Kind: NeverStarted, Reason: "no execution"}
			}
			u.Abort()
			if got, ok := u.Account(); !ok || got != want {
				t.Fatalf("settled reservation account: %+v, want %+v", got, want)
			}
		})
	}
}

func TestProcessAccountRetainsObservationComputedBeforeAbort(t *testing.T) {
	// Model the interleaving between finalization returning and its account
	// being retained: Abort can acquire the unit mutex first. The observation
	// was already computed; recording its facts must grant no closing authority.
	const reason = "process killed"
	observation, err := runtimeinput.Incomplete(t.TempDir(), "terminated-process", reason, []string{})
	if err != nil {
		t.Fatal(err)
	}
	want, err := runtimeinput.CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	terminal := Terminal{Kind: AbnormalCompletion, Reason: reason}
	u := &PackageUnit{producing: &producingUnit{
		phase: unitClosing, snapshot: &Snapshot{},
		execution: &unitExecution{process: ProcessDescription{Identity: "terminated-process"},
			artifact: "retained-artifact", ready: true, terminal: terminal, cancel: func() {}},
	}}
	u.Abort()
	if err := u.producing.recordObservation(observation, reason); err != nil {
		t.Fatal(err)
	}
	account, ok := u.Account()
	if !ok || account.Process != "terminated-process" || account.Terminal != terminal || account.Observation != IncompleteObservation || account.Inputs != want || account.ObservationReason != reason {
		t.Fatalf("abort suppressed already-computed facts: %+v", account)
	}
	result, err := u.Close(t.Context())
	if !errors.Is(err, ErrUnitClosed) || !reflect.DeepEqual(result, FinalizedProcess{}) {
		t.Fatalf("retaining computed facts reopened the aborted unit: %+v %v", result, err)
	}
}
