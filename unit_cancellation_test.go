package gofresh

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestUnitRegistrationCancellationRetainsCallerCause(t *testing.T) {
	if testing.Short() {
		t.Skip("prepares a real observation proof at a deterministic closing boundary")
	}
	dir := writeSupportedViewModule(t)
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, RuntimeDescription{}, SessionPolicy{Execution: PackageExecution})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := snapshot.BindBuilt(subject.Package, "declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{"singleton", "package"} {
		for _, ending := range []string{"close", "abort"} {
			for _, cancellation := range []string{"live caller", "cancelled caller"} {
				t.Run(form+"/"+ending+"/"+cancellation, func(t *testing.T) {
					var transaction *producingUnit
					var register func(context.Context, BuildBinding, ProcessDescription) (Contribution, error)
					var end func()
					if form == "singleton" {
						u, err := snapshot.Begin(subject)
						if err != nil {
							t.Fatal(err)
						}
						transaction, register = u.producing, u.Register
						t.Cleanup(u.Abort)
						end = u.Abort
						if ending == "close" {
							end = func() {
								result, err := u.Close(t.Context())
								if !errors.Is(err, ErrUnitIncomplete) || result != (Finalized{}) {
									t.Fatalf("pending singleton closed: %+v %v", result, err)
								}
							}
						}
					} else {
						u, err := snapshot.BeginPackage([]Subject{subject})
						if err != nil {
							t.Fatal(err)
						}
						transaction, register = u.producing, u.Register
						t.Cleanup(u.Abort)
						end = u.Abort
						if ending == "close" {
							end = func() {
								result, err := u.Close(t.Context())
								if !errors.Is(err, ErrUnitIncomplete) || len(result.Subjects) != 0 || result.Process != "" {
									t.Fatalf("pending package closed: %+v %v", result, err)
								}
							}
						}
					}
					prepared, resume := make(chan struct{}), make(chan struct{})
					release := sync.OnceFunc(func() { close(resume) })
					defer release()
					transaction.view.beforeOutcomeIssue = func() { close(prepared); <-resume }
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					type result struct {
						contribution Contribution
						err          error
					}
					done := make(chan result, 1)
					go func() {
						c, err := register(ctx, bound, ProcessDescription{Identity: "paused-process"})
						done <- result{c, err}
					}()
					select {
					case <-prepared:
					case got := <-done:
						t.Fatalf("preparation did not reach pause: %v", got.err)
					case <-time.After(30 * time.Second):
						t.Fatal("preparation did not reach pause")
					}
					want := ErrUnitClosed
					if cancellation == "cancelled caller" {
						cancel()
						want = context.Canceled
					}
					end()
					release()
					select {
					case got := <-done:
						if !errors.Is(got.err, want) || got.contribution != (Contribution{}) {
							t.Fatalf("terminal registration = %+v, want no contribution and %v", got, want)
						}
					case <-time.After(30 * time.Second):
						t.Fatal("terminal registration did not finish")
					}
				})
			}
		}
	}
}
