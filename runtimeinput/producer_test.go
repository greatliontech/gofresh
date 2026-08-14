package runtimeinput

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func producerModule(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	for path, content := range map[string]string{
		filepath.Join(root, "go.mod"):       "module example.com/prod\n\ngo 1.26\n",
		filepath.Join(pkgDir, "pkg.go"):     "package pkg\n",
		filepath.Join(pkgDir, "fixture"):    "data",
		filepath.Join(root, ".git", "HEAD"): "ref\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, pkgDir
}

func writeTestlog(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proc.testlog")
	if err := os.WriteFile(path, []byte("# test log\n"+lines), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The facade's completed path reproduces the hand-assembled conjunction
// byte for byte: same frame, same options, same manifest and digest -
// the producers' correctness-by-construction claim
// (REQ-inputs-producer-facade).
func TestProducerFacadeMatchesHandAssembly(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	if frame.Reason() != "" {
		t.Fatalf("frame refused: %q", frame.Reason())
	}
	logPath := writeTestlog(t, "getenv PRODUCER_PROBE\nopen fixture\nopen "+
		filepath.Join(frame.Root, ".git", "HEAD")+"\nopen "+frame.Root+"\n")
	env := []string{"PRODUCER_PROBE=1", "PWD=" + pkgDir}
	observation, reason, err := frame.Observe(context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env})
	if err != nil || reason != "" {
		t.Fatalf("facade observe = reason %q, err %v", reason, err)
	}
	facade, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decode(facade.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range decoded.Paths {
		// Every read in this fixture lies under the module, so a non-rel
		// identity would mean the leak walk below no longer covers the
		// classification's output shape.
		if entry.Kind != pathRel {
			t.Fatalf("identity %+v is not module-relative; the exclusion walk cannot audit it", entry.pathID)
		}
		if entry.Path == "." || entry.Path == ".git" || strings.HasPrefix(entry.Path, ".git/") {
			t.Fatalf("identity %q leaked past the facade-owned ingest exclusions", entry.Path)
		}
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	hand, err := FromTestLogEnv(log, frame.Root, frame.PkgDir, env,
		WithCompletedProcess("worker"), WithBracket(*frame.bracket),
		WithExcludedPaths(".", ".git"))
	if err != nil {
		t.Fatal(err)
	}
	handState, err := CompletedState(hand)
	if err != nil {
		t.Fatal(err)
	}
	if facade.Manifest != handState.Manifest || facade.Digest != handState.Digest {
		t.Fatalf("facade diverged from hand assembly:\n facade %+v\n hand   %+v", facade, handState)
	}
	if facade.Unverifiable {
		t.Fatalf("fixture observation unverifiable: %q", facade.Reason)
	}
}

// Every fail-closed shape yields an incomplete observation carrying its
// reason, never manifest bytes and never the no-inputs assertion
// (REQ-inputs-producer-facade).
func TestProducerFacadeFailsClosed(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := []string{"PWD=" + pkgDir}
	t.Run("caller health verdict wins", func(t *testing.T) {
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: env, IncompleteReason: "process timed out"})
		if err != nil || reason != "process timed out" {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("missing capture", func(t *testing.T) {
		_, reason, err := frame.Observe(context.Background(), filepath.Join(t.TempDir(), "missing.testlog"), ProducerIngest{Identity: "worker", Env: env})
		if err != nil || reason != "test process produced no runtime-input log" {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("headerless capture", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.testlog")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, reason, err := frame.Observe(context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
		if err != nil || !strings.Contains(reason, "no test-log header") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("capture truncated inside the header line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "truncated.testlog")
		if err := os.WriteFile(path, []byte("# test log"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, reason, err := frame.Observe(context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
		if err != nil || !strings.Contains(reason, "no test-log header") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("out-of-tree package refuses at capture", func(t *testing.T) {
		outside := t.TempDir()
		refused := CaptureProducerFrame(context.Background(), root, outside, FrameOptions{})
		if refused.Reason() == "" || !strings.Contains(refused.Reason(), "outside the tree") {
			t.Fatalf("frame = %+v, want the out-of-tree refusal", refused)
		}
		_, reason, err := refused.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: env})
		if err != nil || reason != refused.Reason() {
			t.Fatalf("reason = %q, err %v, want the frame's own refusal", reason, err)
		}
	})
	t.Run("unreadable capture folds to incomplete", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		path := writeTestlog(t, "")
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		_, reason, err := frame.Observe(context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
		if err != nil || !strings.Contains(reason, "testlog capture unreadable") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("ingestion failure folds to incomplete", func(t *testing.T) {
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{
			Identity:          "worker",
			Env:               env,
			ScratchNamespaces: []ScratchNamespace{{Dir: "x", Pattern: "a/b"}},
		})
		if err != nil || !strings.Contains(reason, "testlog ingestion failed") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("missing PWD", func(t *testing.T) {
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: []string{"HOME=/home/x"}})
		if err != nil || !strings.Contains(reason, "no PWD") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("parent-inherited PWD", func(t *testing.T) {
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: []string{"PWD=" + root}})
		if err != nil || !strings.Contains(reason, "does not name the package directory") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
}

// The declaration vocabulary assembles: classification roots and
// scratch namespaces reach the ingest options - pinned through the
// ephemeral-root admission dropping the root's identity
// (REQ-inputs-producer-facade).
func TestProducerFacadeAssemblesDeclarations(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	scratch := t.TempDir()
	logPath := writeTestlog(t, "open "+filepath.Join(scratch, "sub", "x")+"\n")
	env := []string{"PWD=" + pkgDir}
	with, reason, err := frame.Observe(context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env, Roots: ClassificationRoots{EphemeralTemp: scratch}})
	if err != nil || reason != "" {
		t.Fatalf("observe = reason %q, err %v", reason, err)
	}
	without, _, err := frame.Observe(context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env})
	if err != nil {
		t.Fatal(err)
	}
	withState, err := CompletedState(with)
	if err != nil {
		t.Fatal(err)
	}
	withoutState, err := CompletedState(without)
	if err != nil {
		t.Fatal(err)
	}
	if withState.Manifest == withoutState.Manifest {
		t.Fatal("the ephemeral-root declaration did not reach the ingest options")
	}
}

// A symlinked tree prefix resolves before containment and framing: the
// frame carries resolved directories, so the package classifies inside
// the tree and the ingest binds (REQ-inputs-producer-facade).
func TestProducerFrameResolvesSymlinkedRoot(t *testing.T) {
	root, _ := producerModule(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	frame := CaptureProducerFrame(context.Background(), link, filepath.Join(link, "pkg"), FrameOptions{})
	if frame.reason != "" {
		t.Fatalf("symlinked frame refused: %q", frame.reason)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Root != resolvedRoot || frame.PkgDir != filepath.Join(resolvedRoot, "pkg") {
		t.Fatalf("frame = %+v, want resolved directories", frame)
	}
	if frame.PkgRel != "pkg" {
		t.Fatalf("PkgRel = %q, want the module-relative package path", frame.PkgRel)
	}
	// A producer that spawned under the unresolved link pins the link
	// path as PWD; the frame accepts it because both names resolve to
	// the same directory.
	_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{
		Identity: "worker",
		Env:      []string{"PWD=" + filepath.Join(link, "pkg")},
	})
	if err != nil || reason != "" {
		t.Fatalf("link-path PWD refused: reason %q, err %v", reason, err)
	}
}
