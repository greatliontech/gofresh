package gofresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

// These inexpensive filesystem controls use a scope-only snapshot. They claim
// file inspection and ownership, not a real build or contributing execution.
func artifactScopeFixture(t *testing.T) (*Snapshot, string) {
	t.Helper()
	dir := t.TempDir()
	return &Snapshot{session: &Session{build: BuildDescription{Directory: dir}}, view: &View{packages: []string{"example.com/artifact"}}}, dir
}

func writeArtifactFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactCaptureAndPersistentMotion(t *testing.T) {
	for _, motion := range []string{"unchanged", "content", "same size and time", "same-byte replacement", "removed", "directory"} {
		t.Run(motion, func(t *testing.T) {
			snapshot, dir := artifactScopeFixture(t)
			path := filepath.Join(dir, "package.test")
			original := []byte("original artifact bytes")
			writeArtifactFixture(t, path, original)
			description := ArtifactDescription{Identity: "retained", Path: "package.test"}
			bound, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", description)
			if err != nil {
				t.Fatal(err)
			}
			description.Identity, description.Path = "changed", "missing"
			copyBinding := bound
			if bound.inspected == nil || bound.inspected != copyBinding.inspected || bound.identity != "retained" || bound.inspected.path != path || !bytes.Equal(bound.inspected.bytes, original) || bound.inspected.digest != sha256.Sum256(original) {
				t.Fatal("binding does not own the declared immutable observation")
			}
			switch motion {
			case "content":
				writeArtifactFixture(t, path, []byte("different length"))
			case "same size and time":
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				writeArtifactFixture(t, path, bytes.Repeat([]byte{'x'}, len(original)))
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "same-byte replacement":
				// Keeping the old inode alive makes replacement identity decisive,
				// even though an old descriptor still reads precisely the right bytes.
				old, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer old.Close()
				writeArtifactFixture(t, path+".new", original)
				if err := os.Rename(path+".new", path); err != nil {
					t.Fatal(err)
				}
			case "removed", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if motion == "directory" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = copyBinding.inspected.validate(t.Context())
			if motion == "unchanged" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrViewChanged) {
				t.Fatalf("persistent %s not refused as view motion: %v", motion, err)
			}
			if !bytes.Equal(bound.inspected.bytes, original) || bound.inspected.digest != sha256.Sum256(original) {
				t.Fatal("filesystem motion changed the owned analysis input")
			}
		})
	}
}

func TestArtifactCoordinatePreservesSymlinkParent(t *testing.T) {
	snapshot, dir := artifactScopeFixture(t)
	child := filepath.Join(dir, "real", "child")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(dir, "via")); err != nil {
		t.Fatal(err)
	}
	writeArtifactFixture(t, filepath.Join(dir, "package.test"), []byte("lexically cleaned wrong file"))
	writeArtifactFixture(t, filepath.Join(dir, "real", "package.test"), []byte("selected file"))
	path := "via" + string(filepath.Separator) + ".." + string(filepath.Separator) + "package.test"
	bound, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", ArtifactDescription{Identity: "retained", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if string(bound.inspected.bytes) != "selected file" || bound.inspected.path != dir+string(filepath.Separator)+path {
		t.Fatalf("filesystem path meaning changed: %q %q", bound.inspected.path, bound.inspected.bytes)
	}
	other := filepath.Join(dir, "other", "child")
	if err := os.MkdirAll(other, 0700); err != nil {
		t.Fatal(err)
	}
	writeArtifactFixture(t, filepath.Join(dir, "other", "package.test"), []byte("selected file"))
	if err := os.Remove(filepath.Join(dir, "via")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "via")); err != nil {
		t.Fatal(err)
	}
	if err := bound.inspected.validate(t.Context()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("same-byte symlink retarget accepted: %v", err)
	}
}

func TestArtifactStreamingBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 65535, 65536, 65537, 3*65536 + 17} {
		t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
			snapshot, dir := artifactScopeFixture(t)
			path := filepath.Join(dir, "retained.test")
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i*31 + i/251)
			}
			writeArtifactFixture(t, path, data)
			binding, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", ArtifactDescription{Identity: "retained", Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(binding.inspected.bytes, data) || binding.inspected.digest != sha256.Sum256(data) {
				t.Fatal("capture changed the artifact's complete content")
			}
			if err := binding.inspected.validate(t.Context()); err != nil {
				t.Fatalf("unchanged artifact refused: %v", err)
			}
			for _, offset := range []int{0, 65535, 65536, size - 1} {
				if offset < 0 || offset >= size {
					continue
				}
				data[offset] ^= 1
				writeArtifactFixture(t, path, data)
				if err := binding.inspected.validate(t.Context()); !errors.Is(err, ErrViewChanged) {
					t.Fatalf("changed byte %d escaped comparison: %v", offset, err)
				}
				data[offset] ^= 1
				writeArtifactFixture(t, path, data)
				if err := binding.inspected.validate(t.Context()); err != nil {
					t.Fatalf("independent equal-content comparison refused: %v", err)
				}
			}
		})
	}
}

func TestArtifactAdmissionRefusals(t *testing.T) {
	snapshot, dir := artifactScopeFixture(t)
	writeArtifactFixture(t, filepath.Join(dir, "regular"), []byte("bytes"))
	for _, description := range []ArtifactDescription{{Identity: "x"}, {Path: "regular"}, {Identity: "x", Path: "missing"}, {Identity: "x", Path: dir}} {
		if bound, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", description); err == nil || bound != (BuildBinding{}) {
			t.Fatalf("invalid input returned inspected binding: %+v %v", description, err)
		}
	}
	description := ArtifactDescription{Identity: "x", Path: "regular"}
	for _, s := range []*Snapshot{nil, {}, snapshot} {
		pkg := "example.com/artifact"
		if s == snapshot {
			pkg = "example.com/another"
		}
		if bound, err := s.BindArtifact(t.Context(), pkg, description); err == nil || bound != (BuildBinding{}) {
			t.Fatalf("invalid scope returned binding: %+v %v", bound, err)
		}
	}
	if bound, err := snapshot.BindArtifact(nil, "example.com/artifact", description); err == nil || bound != (BuildBinding{}) {
		t.Fatalf("nil context returned binding: %+v %v", bound, err)
	}
	plain, err := snapshot.BindBuilt("example.com/artifact", "x")
	if err != nil || plain.inspected != nil {
		t.Fatalf("identity-only declaration acquired inspected inputs: %+v %v", plain, err)
	}
	t.Run("unreadable regular file", func(t *testing.T) {
		path := filepath.Join(dir, "unreadable")
		writeArtifactFixture(t, path, []byte("protected"))
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if file, err := os.Open(path); err == nil {
			file.Close()
			t.Skip("this user can read files without mode read permission")
		}
		if bound, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", ArtifactDescription{Identity: "x", Path: path}); err == nil || bound != (BuildBinding{}) {
			t.Fatalf("unreadable regular file admitted: %+v %v", bound, err)
		}
	})
}

// A context probe makes cancellation and motion occur at observation boundaries
// without a reader callback that could supply arbitrary artifact bytes.
type artifactProbeContext struct {
	context.Context
	checks int
	probe  func(int)
}

func (c *artifactProbeContext) Err() error {
	c.checks++
	c.probe(c.checks)
	return c.Context.Err()
}

func TestArtifactCaptureCancellationAndAgreement(t *testing.T) {
	snapshot, dir := artifactScopeFixture(t)
	path := filepath.Join(dir, "package.test")
	original := bytes.Repeat([]byte{'a'}, 512*1024)
	writeArtifactFixture(t, path, original)
	description := ArtifactDescription{Identity: "retained", Path: path}
	// Sweep entry, interior chunk reads, EOF, the independent reopen and the
	// final return. No cancelled entry may return even a partially built handle.
	count := &artifactProbeContext{Context: t.Context(), probe: func(int) {}}
	if _, err := snapshot.BindArtifact(count, "example.com/artifact", description); err != nil {
		t.Fatal(err)
	}
	for stop := 1; stop <= count.checks; stop++ {
		ctx, cancel := context.WithCancel(t.Context())
		probe := &artifactProbeContext{Context: ctx, probe: func(n int) {
			if n == stop {
				cancel()
			}
		}}
		bound, err := snapshot.BindArtifact(probe, "example.com/artifact", description)
		cancel()
		if !errors.Is(err, context.Canceled) || bound != (BuildBinding{}) {
			t.Fatalf("cancellation at observation boundary %d returned a binding: %v", stop, err)
		}
	}
	bound, err := snapshot.BindArtifact(t.Context(), "example.com/artifact", description)
	if err != nil {
		t.Fatal(err)
	}
	validation := &artifactProbeContext{Context: t.Context(), probe: func(int) {}}
	if err := bound.inspected.validate(validation); err != nil {
		t.Fatal(err)
	}
	for stop := 1; stop <= validation.checks; stop++ {
		ctx, cancel := context.WithCancel(t.Context())
		probe := &artifactProbeContext{Context: ctx, probe: func(n int) {
			if n == stop {
				cancel()
			}
		}}
		err := bound.inspected.validate(probe)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("validation cancellation at boundary %d lost its cause: %v", stop, err)
		}
	}
	for _, replacement := range []bool{false, true} {
		writeArtifactFixture(t, path, original)
		// At this interior read boundary, some old bytes are already captured.
		// Rewriting those bytes must be caught by the independent full observation;
		// replacing the path must also be caught while the original FD is alive.
		probe := &artifactProbeContext{Context: t.Context(), probe: func(n int) {
			if n != 8 {
				return
			}
			if replacement {
				writeArtifactFixture(t, path+".new", original)
				if err := os.Rename(path+".new", path); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte{'b'}, 0)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
		}}
		if bound, err := snapshot.BindArtifact(probe, "example.com/artifact", description); !errors.Is(err, ErrViewChanged) || bound != (BuildBinding{}) {
			t.Fatalf("motion during capture (replacement=%t) admitted: %v", replacement, err)
		}
	}
}

func TestArtifactClosingValidationFollowsViewObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained package-test artifact across closing observations")
	}
	ctx := t.Context()
	dir := t.TempDir()
	writeArtifactFixture(t, filepath.Join(dir, "go.mod"), []byte("module example.com/artifactclose\n\ngo 1.27.0\n"))
	writeArtifactFixture(t, filepath.Join(dir, "p_test.go"), []byte(`package artifactclose
import ("os"; "testing")
func TestValue(t *testing.T) {
 if os.Getenv("FRESH_ARTIFACT_CLOSE_VALUE") != "present" { t.Fatal("wrong process environment") }
}
`))
	subject := Subject{Package: "example.com/artifactclose", Symbol: "TestValue"}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	env := gotool.SetEnv(os.Environ(), "FRESH_ARTIFACT_CLOSE_VALUE", "present")
	session, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{})
	build, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	// The retained file is outside the source tree and every runtime bracket.
	// Only the inspected-artifact comparison can observe its content motion.
	binary := filepath.Join(t.TempDir(), "package.test")
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(ctx, build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	bound, err := snapshot.BindArtifact(ctx, subject.Package, ArtifactDescription{Identity: "retained", Path: binary})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []bool{false, true} {
		name := "unchanged"
		if mutate {
			name = "motion_during_view_validation"
		}
		t.Run(name, func(t *testing.T) {
			u, err := execution.BeginPackage([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			contribution, err := u.Register(ctx, bound, ProcessDescription{Identity: "actual-process", Capture: filepath.Join(t.TempDir(), "capture")})
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := runner.Program(ctx, contribution.Directory(), contribution.Environment(), binary, "-test.v", "-test.run=^TestValue$", "-test.testlogfile="+contribution.Capture())
			if err != nil {
				t.Fatal(err)
			}
			if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "--- PASS: TestValue") {
				t.Fatalf("actual retained execution: %v\n%s", err, output)
			}
			if err := u.Submit(contribution, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			var writer *os.File
			if mutate {
				// Reaping the process need not immediately release the executable's
				// write exclusion. Acquire the mutation capability before closing,
				// but change no bytes until the sealed-view observation below.
				// Keep the same inode: replacement would not test content motion.
				ready, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				for {
					writer, err = os.OpenFile(binary, os.O_WRONLY, 0)
					if !errors.Is(err, syscall.ETXTBSY) {
						break
					}
					select {
					case <-ready.Done():
						t.Fatalf("executed artifact remained unwritable: %v: %v", ready.Err(), err)
					case <-time.After(time.Millisecond):
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
			}
			observed := false
			var finalizedAccount ProcessAccount
			priorObserve := viewTestHooks.observe
			defer func() { viewTestHooks.observe = priorObserve }()
			viewTestHooks.observe = func() {
				// CheckObservedBatch can observe too. The seal identifies the
				// actual View.Validate interval, after those earlier checks.
				u.producing.view.mu.Lock()
				sealed := u.producing.view.sealed
				u.producing.view.mu.Unlock()
				if !sealed || observed {
					return
				}
				observed = true
				var ok bool
				finalizedAccount, ok = u.Account()
				if !ok || finalizedAccount.Terminal.Kind != NormalCompletion || finalizedAccount.Observation == UnknownObservation || finalizedAccount.Observation == IncompleteObservation || finalizedAccount.Inputs.Manifest == "" {
					t.Fatalf("view validation preceded normal process finalization: %+v", finalizedAccount)
				}
				if mutate {
					_, err := writer.WriteAt([]byte{bound.inspected.bytes[0] ^ 0xff}, 0)
					closeErr := writer.Close()
					if err != nil || closeErr != nil {
						t.Fatalf("artifact motion: write=%v close=%v", err, closeErr)
					}
				}
			}
			result, closeErr := u.Close(ctx)
			viewTestHooks.observe = priorObserve
			if !observed {
				t.Fatal("closing did not reach the sealed view observation")
			}
			// Keep the changed artifact in place: even after motion, all ordinary
			// source/runtime closing observations succeed independently. Thus an
			// ErrViewChanged below cannot be supplied by that guard channel.
			if err := u.producing.view.Validate(ctx); err != nil {
				t.Fatalf("artifact fixture contaminated ordinary view validation: %v", err)
			}
			if mutate {
				if !errors.Is(closeErr, ErrViewChanged) || !reflect.DeepEqual(result, FinalizedProcess{}) {
					t.Fatalf("late artifact motion escaped closing: subjects=%d err=%v", len(result.Subjects), closeErr)
				}
			} else if closeErr != nil || len(result.Subjects) != 1 || result.Subjects[0].Subject != subject || result.Terminal.Kind != NormalCompletion {
				t.Fatalf("unchanged closing control: %+v %v", result, closeErr)
			}
			account, ok := u.Account()
			if !ok || !reflect.DeepEqual(account, finalizedAccount) {
				t.Fatalf("closing lost established process facts: before=%+v after=%+v", finalizedAccount, account)
			}
		})
	}
}

func TestArtifactRetainedPackageExecutionAndSpan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained package-test artifact and checks producing spans")
	}
	ctx := t.Context()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module example.com/artifact\n\ngo 1.27.0\n",
		"p_test.go": `package artifact
import ("os"; "testing")
func TestFile(t *testing.T) { data, err := os.ReadFile("input"); if err != nil || string(data) != "present" { t.Fatalf("input: %q %v", data, err) } }
func TestOther(t *testing.T) {}
`,
	} {
		writeArtifactFixture(t, filepath.Join(dir, name), []byte(source))
	}
	subject := Subject{Package: "example.com/artifact", Symbol: "TestFile"}
	other := Subject{Package: subject.Package, Symbol: "TestOther"}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Execution: PackageExecution, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{subject, other}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeArtifactFixture(t, filepath.Join(runtimeDir, "input"), []byte("present"))
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: runtimeDir})
	build, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "retained", "package.test")
	if err := os.Mkdir(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"test", "-c", "-o", binary}, build.Flags...)
	args = append(args, build.Package)
	if output, err := runner.Run(ctx, build.Directory, build.Environment, args...); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	bound, err := snapshot.BindArtifact(ctx, subject.Package, ArtifactDescription{Identity: "retained", Path: filepath.Join("retained", "package.test")})
	if err != nil {
		t.Fatal(err)
	}
	if bound.inspected.path != binary {
		t.Fatalf("artifact coordinate did not use build directory: %q", bound.inspected.path)
	}
	plain, err := snapshot.BindBuilt(subject.Package, "retained")
	if err != nil {
		t.Fatal(err)
	}
	var prior Finalized
	for _, binding := range []BuildBinding{plain, bound, bound} {
		u, err := execution.Begin(subject)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(u.Abort)
		contribution, err := u.Register(ctx, binding, ProcessDescription{Identity: "actual-process", Capture: filepath.Join(t.TempDir(), "capture"), BracketPaths: []string{"input"}})
		if err != nil {
			t.Fatal(err)
		}
		cmd, err := runner.Program(ctx, contribution.Directory(), contribution.Environment(), binary, "-test.v", "-test.run=^TestFile$", "-test.testlogfile="+contribution.Capture())
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "--- PASS: TestFile") {
			t.Fatalf("actual retained execution: %v\n%s", err, output)
		}
		if err := u.Submit(contribution, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
		}
		final, err := u.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if final.Terminal.Kind != NormalCompletion || final.Observation != IdentityObservation || final.Verdict.Status != Unverifiable {
			t.Fatalf("inspection promoted unsupported file outcome: %+v", final)
		}
		if binding.inspected != nil && !reflect.DeepEqual(final, prior) {
			t.Fatalf("inspection changed ordinary evidence or authority:\nplain=%+v\ninspected=%+v", prior, final)
		}
		prior = final
	}
	// This is ordinary evidence: inspection introduced no hidden applicability
	// requirement. Artifact-free checking retains the same refusal and authority.
	writeArtifactFixture(t, binary, []byte("artifact no longer retained for a future execution"))
	if verdict, err := execution.Check(ctx, subject, prior.Fingerprint); err != nil || verdict.Status != prior.Verdict.Status {
		t.Fatalf("artifact-free checking changed the ordinary channel: %+v %v", verdict, err)
	}
	writeArtifactFixture(t, binary, bound.inspected.bytes)
	for _, form := range []string{"singleton", "package"} {
		t.Run(form+" mechanical span controls", func(t *testing.T) {
			// The following controls simulate executor terminal assertions and an
			// empty capture solely to exercise lifecycle validation. They make no
			// claim that these mutated fixture files were executed.
			newUnit := func(t *testing.T) *producingUnit {
				t.Helper()
				if form == "singleton" {
					u, err := execution.BeginIdentity(subject)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(u.Abort)
					return u.producing
				}
				u, err := execution.BeginPackage([]Subject{subject, other})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(u.Abort)
				return u.producing
			}
			for _, phase := range []string{"registration", "close"} {
				for _, motion := range []string{"same-size mutation", "same-byte replacement", "unreadable"} {
					t.Run(phase+"/"+motion, func(t *testing.T) {
						path := filepath.Join(t.TempDir(), "mechanical-artifact")
						data := []byte("mechanical file, never executed")
						writeArtifactFixture(t, path, data)
						binding, err := snapshot.BindArtifact(ctx, subject.Package, ArtifactDescription{Identity: "mechanical", Path: path})
						if err != nil {
							t.Fatal(err)
						}
						u := newUnit(t)
						capture := filepath.Join(t.TempDir(), "capture")
						if phase == "close" {
							c, err := u.register(ctx, binding, ProcessDescription{Identity: "simulated", Capture: capture})
							if err != nil {
								t.Fatal(err)
							}
							writeArtifactFixture(t, capture, []byte("# test log\n"))
							if err := u.submit(c, Terminal{Kind: NormalCompletion}); err != nil {
								t.Fatal(err)
							}
						}
						switch motion {
						case "same-size mutation":
							writeArtifactFixture(t, path, bytes.Repeat([]byte{'x'}, len(data)))
						case "same-byte replacement":
							writeArtifactFixture(t, path+".new", data)
							if err := os.Rename(path+".new", path); err != nil {
								t.Fatal(err)
							}
						case "unreadable":
							if err := os.Remove(path); err != nil {
								t.Fatal(err)
							}
						}
						if phase == "registration" {
							c, err := u.register(ctx, binding, ProcessDescription{Identity: "simulated", Capture: capture})
							if !errors.Is(err, ErrViewChanged) || c != (Contribution{}) {
								t.Fatalf("motion admitted at registration: %+v %v", c, err)
							}
						} else {
							result, err := u.close(ctx)
							if !errors.Is(err, ErrViewChanged) || !reflect.DeepEqual(result, FinalizedProcess{}) {
								t.Fatalf("artifact motion escaped close: %+v %v", result, err)
							}
							account, ok := u.account()
							if !ok || account.Terminal.Kind != NormalCompletion || account.Observation == UnknownObservation || account.Inputs.Manifest == "" {
								t.Fatalf("artifact refusal erased finalized process facts: %+v", account)
							}
						}
					})
				}
			}
		})
	}
	borrowedSnapshot := *snapshot
	borrowed, err := borrowedSnapshot.BindArtifact(ctx, subject.Package, ArtifactDescription{Identity: bound.identity, Path: binary})
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []BuildBinding{{}, borrowed, {snapshot: snapshot, pkg: "example.com/other", identity: bound.identity, inspected: bound.inspected}} {
		u, err := execution.Begin(subject)
		if err != nil {
			t.Fatal(err)
		}
		if c, err := u.Register(ctx, wrong, ProcessDescription{Identity: "borrowed"}); err == nil || c != (Contribution{}) || u.producing.execution != nil {
			t.Fatalf("wrong scope reserved inspected input: %+v %v", c, err)
		}
		u.Abort()
	}
	for _, ending := range []string{"close", "abort", "caller cancellation"} {
		t.Run("pending inspected registration/"+ending, func(t *testing.T) {
			u, err := execution.Begin(subject)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			started, resume := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			u.producing.view.beforeOutcomeIssue = func() { close(started); <-resume }
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			type answer struct {
				c   Contribution
				err error
			}
			done := make(chan answer, 1)
			go func() {
				c, err := u.Register(ctx, bound, ProcessDescription{Identity: "pending"})
				done <- answer{c, err}
			}()
			select {
			case <-started:
			case got := <-done:
				t.Fatalf("registration did not reach preparation boundary: %v", got.err)
			case <-time.After(30 * time.Second):
				t.Fatal("registration did not reach preparation boundary")
			}
			want := ErrUnitClosed
			switch ending {
			case "close":
				if result, err := u.Close(t.Context()); !errors.Is(err, ErrUnitIncomplete) || result != (Finalized{}) {
					t.Fatalf("pending registration closed: %+v %v", result, err)
				}
			case "abort":
				u.Abort()
			case "caller cancellation":
				cancel()
				want = context.Canceled
			}
			release()
			select {
			case got := <-done:
				if !errors.Is(got.err, want) || got.c != (Contribution{}) {
					t.Fatalf("pending inspected input escaped termination: %+v %v", got.c, got.err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("terminated registration did not finish")
			}
			if err := bound.inspected.validate(t.Context()); err != nil {
				t.Fatalf("unit termination invalidated shared input: %v", err)
			}
		})
	}
}

func TestCompileTestBinaryAndExecuteHelpers(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles and executes a test binary through Snapshot and RuntimeBinding helpers")
	}
	ctx := t.Context()
	dir := t.TempDir()
	writeArtifactFixture(t, filepath.Join(dir, "go.mod"), []byte("module example.com/exechelper\n\ngo 1.27.0\n"))
	writeArtifactFixture(t, filepath.Join(dir, "p_test.go"), []byte(`package exechelper
import "testing"
func TestHelper(t *testing.T) {}
`))
	subject := Subject{Package: "example.com/exechelper", Symbol: "TestHelper"}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	session, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: os.Environ(), Flags: []string{"-trimpath"}, Inputs: []string{}}, SessionPolicy{Execution: SingleSubjectExecution, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(ctx, []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := snapshot.BuildDescription(subject.Package)
	if err != nil {
		t.Fatal(err)
	}
	gotArgs := desc.TestCompileArgs("/tmp/out.test", "-vet=off")
	wantArgs := []string{"test", "-c", "-o", "/tmp/out.test", "-trimpath", "-vet=off", "example.com/exechelper"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("TestCompileArgs = %v, want %v", gotArgs, wantArgs)
	}
	declOnly, err := snapshot.BindBuilt(subject.Package, "decl-only")
	if err != nil {
		t.Fatal(err)
	}
	if declOnly.Package() != subject.Package || declOnly.Identity() != "decl-only" || declOnly.Path() != "" || declOnly.Digest() != "" || declOnly.Bytes() != nil {
		t.Fatalf("declaration-only accessors = (%q, %q, %q, %q, %v)", declOnly.Package(), declOnly.Identity(), declOnly.Path(), declOnly.Digest(), declOnly.Bytes())
	}
	if err := declOnly.Validate(ctx); err == nil {
		t.Fatal("declaration-only Validate succeeded")
	}

	binary := filepath.Join(t.TempDir(), "exechelper.test")
	compiled, err := snapshot.CompileTestBinary(ctx, subject.Package, binary, "-vet=off")
	if err != nil {
		t.Fatalf("CompileTestBinary: %v", err)
	}
	if compiled.Package() != subject.Package || compiled.Path() != binary || !strings.HasPrefix(compiled.Digest(), "sha256:") || compiled.Identity() != compiled.Digest() {
		t.Fatalf("compiled accessors = (%q, %q, %q, %q)", compiled.Package(), compiled.Path(), compiled.Digest(), compiled.Identity())
	}
	raw := compiled.Bytes()
	if len(raw) == 0 {
		t.Fatal("compiled Bytes returned empty")
	}
	raw[0] ^= 0xff
	if err := compiled.Validate(ctx); err != nil {
		t.Fatalf("mutating caller copy of Bytes corrupted binding: %v", err)
	}
	rebound, err := snapshot.BindArtifactByDigest(ctx, subject.Package, binary)
	if err != nil {
		t.Fatalf("BindArtifactByDigest: %v", err)
	}
	if rebound.Digest() != compiled.Digest() {
		t.Fatalf("BindArtifactByDigest digest = %q, want %q", rebound.Digest(), compiled.Digest())
	}

	runtimeBinding := bindTestRuntime(t, snapshot, RuntimeDescription{})
	capture := filepath.Join(t.TempDir(), "capture.log")
	finalized, err := runtimeBinding.Execute(ctx, subject, compiled, ProcessDescription{Identity: "helper-run", Capture: capture}, func(ctx context.Context, c Contribution) (Terminal, error) {
		cmd, err := runner.Program(ctx, c.Directory(), c.Environment(), compiled.Path(), "-test.run=^TestHelper$", "-test.testlogfile="+c.Capture())
		if err != nil {
			return Terminal{}, err
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return Terminal{}, fmt.Errorf("run binary: %w\n%s", err, out)
		}
		return Terminal{Kind: NormalCompletion}, nil
	})
	if err != nil {
		t.Fatalf("RuntimeBinding.Execute: %v", err)
	}
	if finalized.Verdict.Status != Valid || finalized.Terminal.Kind != NormalCompletion {
		t.Fatalf("finalized = %+v, want Valid NormalCompletion", finalized)
	}

	u, err := runtimeBinding.Begin(subject)
	if err != nil {
		t.Fatal(err)
	}
	runBoom := errors.New("callback boom")
	if _, err := u.Execute(ctx, compiled, ProcessDescription{Identity: "boom-run"}, func(context.Context, Contribution) (Terminal, error) {
		return Terminal{}, runBoom
	}); !errors.Is(err, runBoom) {
		t.Fatalf("u.Execute callback error = %v, want %v", err, runBoom)
	}
	if _, err := u.Close(ctx); !errors.Is(err, ErrUnitClosed) {
		t.Fatalf("u.Close after failed Execute = %v, want ErrUnitClosed", err)
	}
}
