package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
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

// captureGuards exercises the facade's identity-guard assembly independently of
// execution-bound support. These fixtures deliberately include filesystem
// observations, for which the current outcome method grants no support.
func captureGuards(frame ProducerFrame, ctx context.Context, path string, in ProducerIngest) (Observation, string, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, "", err
	}
	log, reason, err := readProducerLog(ctx, path)
	if err != nil {
		return Observation{}, "", err
	}
	if reason != "" {
		return frame.incomplete(ctx, in, reason)
	}
	return frame.captureBytes(ctx, log, in)
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
	observation, reason, err := captureGuards(frame, context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env})
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
	hand, err := FromTestLog(log, frame.Root, frame.PkgDir, env,
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
		receipt, err := frame.Completion("worker", env, "process timed out")
		if err != nil {
			t.Fatal(err)
		}
		_, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: env, Completion: receipt})
		if err != nil || reason != "process timed out" {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("missing capture", func(t *testing.T) {
		_, reason, err := captureGuards(frame, context.Background(), filepath.Join(t.TempDir(), "missing.testlog"), ProducerIngest{Identity: "worker", Env: env})
		if err != nil || reason != "test process produced no runtime-input log" {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("headerless capture", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.testlog")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, reason, err := captureGuards(frame, context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
		if err != nil || !strings.Contains(reason, "no test-log header") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("capture truncated inside the header line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "truncated.testlog")
		if err := os.WriteFile(path, []byte("# test log"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, reason, err := captureGuards(frame, context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
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
		_, reason, err := captureGuards(refused, context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: env})
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
		_, reason, err := captureGuards(frame, context.Background(), path, ProducerIngest{Identity: "worker", Env: env})
		if err != nil || !strings.Contains(reason, "testlog capture unreadable") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("ingestion failure folds to incomplete", func(t *testing.T) {
		_, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, ""), ProducerIngest{
			Identity:          "worker",
			Env:               env,
			ScratchNamespaces: []ScratchNamespace{{Dir: "x", Pattern: "a/b"}},
		})
		if err != nil || !strings.Contains(reason, "testlog ingestion failed") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("missing PWD", func(t *testing.T) {
		_, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: []string{"HOME=/home/x"}})
		if err != nil || !strings.Contains(reason, "no PWD") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
	t.Run("parent-inherited PWD", func(t *testing.T) {
		_, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: []string{"PWD=" + root}})
		if err != nil || !strings.Contains(reason, "does not name the package directory") {
			t.Fatalf("reason = %q, err %v", reason, err)
		}
	})
}

// The declaration vocabulary assembles: a minted scratch root and
// scratch namespaces reach the ingest options - pinned through the
// ephemeral-root admission dropping the root's identity, against an
// environment whose own temp root lies elsewhere
// (REQ-inputs-producer-facade).
func TestProducerFacadeAssemblesDeclarations(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	scratch := t.TempDir()
	logPath := writeTestlog(t, "open "+filepath.Join(scratch, "sub", "x")+"\n")
	env := producerEnv(pkgDir, "TMPDIR="+t.TempDir())
	with, reason, err := captureGuards(frame, context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env, ScratchRoot: scratch})
	if err != nil || reason != "" {
		t.Fatalf("observe = reason %q, err %v", reason, err)
	}
	without, _, err := captureGuards(frame, context.Background(), logPath, ProducerIngest{Identity: "worker", Env: env})
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
	_, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, ""), ProducerIngest{
		Identity: "worker",
		Env:      []string{"PWD=" + filepath.Join(link, "pkg")},
	})
	if err != nil || reason != "" {
		t.Fatalf("link-path PWD refused: reason %q, err %v", reason, err)
	}
}

// producerEnv is a complete producer environment for pkgDir: the
// toolchain-resolving settings of the test process, PWD pinned to the
// package directory, and the given overrides.
func producerEnv(pkgDir string, overrides ...string) []string {
	values := map[string]string{"PWD": pkgDir, "GOENV": "off", "GOFLAGS": ""}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "PATH", "HOME", "GOROOT", "GOMODCACHE", "GOCACHE", "GOPATH", "GOTOOLCHAIN", "XDG_CACHE_HOME":
			values[key] = value
		}
	}
	for _, entry := range overrides {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

// manifestOf observes logText under env through frame and returns the
// completed manifest, failing the test on any incomplete shape.
func manifestOf(t *testing.T, frame ProducerFrame, env []string, logText string) string {
	t.Helper()
	observation, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, logText), ProducerIngest{Identity: "worker", Env: env})
	if err != nil || reason != "" {
		t.Fatalf("observe = reason %q, err %v", reason, err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	return state.Manifest
}

// The guard-covered roots are resolved from the process environment: a
// read inside the toolchain the environment names records nothing, while
// the same read of an undeclared tree is observed (REQ-inputs-guard-covered).
func TestProducerFacadeResolvesGuardRootsFromTheEnvironment(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := producerEnv(pkgDir)
	goroot, err := (gotool.Runner{}).Run(context.Background(), pkgDir, env, "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(strings.TrimSpace(string(goroot)), "VERSION")
	if _, err := os.Stat(pinned); err != nil {
		t.Skipf("toolchain carries no VERSION file: %v", err)
	}
	empty := manifestOf(t, frame, env, "")
	if got := manifestOf(t, frame, env, "open "+pinned+"\n"); got != empty {
		t.Fatal("a read under the environment's GOROOT was observed; the root was not resolved from the environment")
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := manifestOf(t, frame, env, "open "+outside+"\n"); got == empty {
		t.Fatal("a read outside every root recorded nothing")
	}
	// The module cache and the build cache resolve the same way: a read
	// of extracted module content or a cache object under the roots the
	// environment names records nothing.
	modCache, buildCache := t.TempDir(), t.TempDir()
	modFile := filepath.Join(modCache, "example.com", "dep@v1.0.0", "dep.go")
	cacheObject := filepath.Join(buildCache, "ab", "abcd-d")
	for _, path := range []string{modFile, cacheObject} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cacheEnv := producerEnv(pkgDir, "GOMODCACHE="+modCache, "GOCACHE="+buildCache)
	cacheEmpty := manifestOf(t, frame, cacheEnv, "")
	if manifestOf(t, frame, cacheEnv, "open "+modFile+"\n") != cacheEmpty {
		t.Fatal("a read under the environment's GOMODCACHE was observed")
	}
	if manifestOf(t, frame, cacheEnv, "open "+cacheObject+"\n") != cacheEmpty {
		t.Fatal("a read under the environment's GOCACHE was observed")
	}
	if manifestOf(t, frame, env, "open "+modFile+"\n") == empty {
		t.Fatal("a read under another environment's module cache recorded nothing")
	}
	// A cache the environment places at the tree root (or containing
	// it) declares no root: the tree's own content stays observed.
	data := filepath.Join(pkgDir, "data.txt")
	if err := os.WriteFile(data, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, inTree := range []string{root, filepath.Dir(root)} {
		treeEnv := producerEnv(pkgDir, "GOMODCACHE="+inTree)
		if manifestOf(t, frame, treeEnv, "open "+data+"\n") == manifestOf(t, frame, treeEnv, "") {
			t.Fatalf("GOMODCACHE=%s admitted a read of the tree's own content", inTree)
		}
	}
}

// A cancelled context is the caller's cancellation, never an
// environment fault recorded as an incomplete observation — at the
// entry, and again when the cancellation lands inside the roots
// resolution, where the toolchain's failure would otherwise be blamed
// on the environment.
func TestProducerFacadeReportsCancellationAsTheCallersError(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, reason, err := frame.Observe(ctx, writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: producerEnv(pkgDir)})
	if err == nil || reason != "" {
		t.Fatalf("observe = reason %q, err %v; want the context error", reason, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	// An environment the memo has never seen, so the resolution spawns
	// under the cancelled context.
	withRuntimeTestHooks(runtimeTestHookSet{beforeRoots: cancel}, func() {
		_, reason, err = captureGuards(frame, ctx, writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: producerEnv(pkgDir, "GOFLAGS=-tags=cancelled")})
	})
	if err == nil || reason != "" {
		t.Fatalf("mid-observation cancellation: reason %q, err %v; want the context error", reason, err)
	}
}

// The temp root is the environment's TMPDIR: an absent deeper read under
// it records nothing, an in-tree TMPDIR declares no root, and an
// environment under which the toolchain cannot answer fails closed with
// a named reason (REQ-inputs-ephemeral-root, REQ-inputs-producer-facade).
func TestProducerFacadeResolvesTheTempRootFromTheEnvironment(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	scratch := t.TempDir()
	read := "open " + filepath.Join(scratch, "sub", "x") + "\n"
	env := producerEnv(pkgDir, "TMPDIR="+scratch)
	if manifestOf(t, frame, env, read) != manifestOf(t, frame, env, "") {
		t.Fatal("an absent read under the environment's TMPDIR was observed")
	}
	elsewhere := producerEnv(pkgDir, "TMPDIR="+t.TempDir())
	if manifestOf(t, frame, elsewhere, read) == manifestOf(t, frame, elsewhere, "") {
		t.Fatal("a read under another environment's scratch recorded nothing")
	}
	inTree := filepath.Join(root, "scratch")
	if err := os.MkdirAll(inTree, 0o755); err != nil {
		t.Fatal(err)
	}
	inTreeEnv := producerEnv(pkgDir, "TMPDIR="+inTree)
	inTreeRead := "open " + filepath.Join(inTree, "sub", "x") + "\n"
	if manifestOf(t, frame, inTreeEnv, inTreeRead) == manifestOf(t, frame, inTreeEnv, "") {
		t.Fatal("an in-tree TMPDIR declared an ephemeral root")
	}
	broken := producerEnv(pkgDir, "GOTOOLCHAIN=go9.99.99+auto")
	if _, err := (gotool.Runner{}).Run(context.Background(), pkgDir, broken, "env", "GOROOT"); err == nil {
		t.Skip("the toolchain answers under an invalid GOTOOLCHAIN; no failing environment to pin")
	}
	_, reason, err := captureGuards(frame, context.Background(), writeTestlog(t, ""), ProducerIngest{Identity: "worker", Env: broken})
	if err != nil || !strings.Contains(reason, "classification roots unresolved") {
		t.Fatalf("reason = %q, err %v", reason, err)
	}
}

// The go command's own temp root is an ephemeral root exactly as the
// process temp root is: the root's stat, a testing per-test directory's
// object and a work-tree object under GOTMPDIR, absent at ingest,
// record nothing — under the environment's setting and under the go
// env file's alike, as `go env` answers it — where the root's stat
// under no such setting is an external input; a GOTMPDIR inside the
// tree declares nothing (REQ-inputs-ephemeral-root).
func TestProducerFacadeDeclaresTheGoCommandsTempRoot(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	goTemp := t.TempDir()
	perTest := filepath.Join(goTemp, "TestF123", "001", "data")
	work := filepath.Join(goTemp, "go-build123", "b001", "_testmain.go")
	withSetting := producerEnv(pkgDir, "GOTMPDIR="+goTemp)
	empty := manifestOf(t, frame, withSetting, "")
	if manifestOf(t, frame, withSetting, "stat "+goTemp+"\nopen "+perTest+"\nopen "+work+"\n") != empty {
		t.Fatal("a read under the environment's GOTMPDIR was observed")
	}
	// The go env file's setting, with none in the environment: the
	// toolchain answers the file's value and the root is declared.
	fileTemp := t.TempDir()
	goEnv := filepath.Join(t.TempDir(), "go.env")
	if err := os.WriteFile(goEnv, []byte("GOTMPDIR="+fileTemp+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile := producerEnv(pkgDir, "GOENV="+goEnv)
	if manifestOf(t, frame, fromFile, "stat "+fileTemp+"\n") != manifestOf(t, frame, fromFile, "") {
		t.Fatal("the root's stat under the go env file's GOTMPDIR was observed")
	}
	// The root's own identity is the discriminating read: an absent
	// deeper object records nothing under any root or none, while the
	// directory itself is an external input where no setting names it.
	env := producerEnv(pkgDir)
	if manifestOf(t, frame, env, "stat "+goTemp+"\n") == manifestOf(t, frame, env, "") {
		t.Fatal("the root's stat under a GOTMPDIR the environment does not set recorded nothing")
	}
	data := filepath.Join(pkgDir, "data.txt")
	if err := os.WriteFile(data, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	inTree := producerEnv(pkgDir, "GOTMPDIR="+root)
	if manifestOf(t, frame, inTree, "open "+data+"\n") == manifestOf(t, frame, inTree, "") {
		t.Fatal("a GOTMPDIR at the tree root admitted a read of the tree's own content")
	}
}

func TestIncompleteCaptureHonorsCancellationAtBothBoundaries(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	in := supportedIngest(t, frame, "worker", producerEnv(dir))
	for _, checks := range []int{0, 1} {
		ctx := &cancelAfterChecks{Context: context.Background(), after: checks}
		obs, _, err := frame.incomplete(ctx, in, "missing support")
		if !errors.Is(err, context.Canceled) || obs.OK {
			t.Fatalf("cancel after %d checks returned evidence: %+v %v", checks, obs, err)
		}
	}
}

func TestIncompleteCaptureSkipsAmbientRootLookupWhenCancelled(t *testing.T) {
	if os.Getenv("GOFRESH_CAPTURE_CANCEL_CHILD") == "1" {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := (ProducerFrame{}).incomplete(ctx, ProducerIngest{Identity: "refused-frame"}, "frame unavailable")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled refusal = %v", err)
		}
		return
	}
	tmp := t.TempDir()
	selfBin := filepath.Join(tmp, "self.test")
	if err := os.Symlink(os.Args[0], selfBin); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmp, "capture.log")
	cmd := exec.Command(selfBin, "-test.run=^TestIncompleteCaptureSkipsAmbientRootLookupWhenCancelled$", "-test.testlogfile="+path)
	cmd.Env = append(os.Environ(), "GOFRESH_CAPTURE_CANCEL_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cancelled capture child: %v\n%s", err, output)
	}
	log, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(log), "# test log\n") {
		t.Fatalf("missing capture header: %q", log)
	}
	if strings.Contains(string(log), "\ngetenv PWD\n") {
		t.Fatalf("cancelled incomplete construction consulted the ambient root: %q", log)
	}
}

func TestCaptureReaderDoesNotReadAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	read := false
	reader := outcomeReadFunc(func(p []byte) (int, error) { read = true; return copy(p, "data"), io.EOF })
	n, err := (captureReader{ctx: ctx, Reader: reader}).Read(make([]byte, 16))
	if read || n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reader performed I/O: read=%v n=%d err=%v", read, n, err)
	}
}

func TestReadProducerLogRetainsCaptureFailureAndCancellation(t *testing.T) {
	good := writeTestlog(t, "getenv VALUE\n")
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		path  string
		after int
	}{
		{"", 0}, {missing, 1}, {good, 4},
	} {
		_, _, err := readProducerLog(&cancelAfterChecks{Context: context.Background(), after: tc.after}, tc.path)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel after %d checks at %q: %v", tc.after, tc.path, err)
		}
	}
	for _, tc := range []struct{ path, want string }{
		{"", "no capture file was attached"},
		{missing, "produced no runtime-input log"},
		{filepath.Join(t.TempDir(), "bad\x00path"), "bad\\x00path"},
		{t.TempDir(), "capture unreadable"},
	} {
		data, reason, err := readProducerLog(context.Background(), tc.path)
		if err != nil || len(data) != 0 || !strings.Contains(reason, tc.want) {
			t.Fatalf("capture %q: data=%q reason=%q err=%v; want %q", tc.path, data, reason, err, tc.want)
		}
	}
	data, reason, err := readProducerLog(context.Background(), good)
	if err != nil || reason != "" || string(data) != "# test log\ngetenv VALUE\n" {
		t.Fatalf("valid capture lost: %q %q %v", data, reason, err)
	}
}

func TestEnvironmentLogChecksCancellationBeforeScreening(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, log := range []string{"", "# test log\n", "open fixture\n"} {
		if _, err := environmentLog(ctx, []byte(log)); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled screen of %q: %v", log, err)
		}
	}
}

func TestReadProducerLogClosesItsFile(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("requires /proc/self/fd")
	}
	good := writeTestlog(t, "")
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(good), alias); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "headerless")
	if err := os.WriteFile(bad, []byte("not a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path          string
		ctx                 context.Context
		rejected, cancelled bool
	}{
		{"successful", good, context.Background(), false, false},
		{"symlinked spelling", filepath.Join(alias, filepath.Base(good)), context.Background(), false, false},
		{"header rejected", bad, context.Background(), true, false},
		{"read failure", t.TempDir(), context.Background(), true, false},
		{"cancelled after open", good, &cancelAfterChecks{Context: context.Background(), after: 1}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			_, reason, err := readProducerLog(tc.ctx, tc.path)
			if tc.cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled capture: %v", err)
				}
			} else if err != nil || (reason != "") != tc.rejected {
				t.Fatalf("capture: %q %v", reason, err)
			}
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if opened, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name())); err == nil && os.SameFile(info, opened) {
					t.Fatalf("capture retained file descriptor %s", entry.Name())
				}
			}
		})
	}
}

const supportedSubject = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// This package-level fixture supplies an already-proved empty/environment-only
// inventory. Engine integration tests separately exercise the real analysis
// issuer. No filesystem outcome is vouched for by this fixture.
func supportedIngest(t *testing.T, frame ProducerFrame, identity string, env []string) ProducerIngest {
	t.Helper()
	completion, err := frame.Completion(identity, env, "")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := frame.OutcomeBinding(identity, env)
	if err != nil {
		t.Fatal(err)
	}
	return ProducerIngest{Identity: identity, Env: env, Completion: completion, Outcome: outcome.Prepare(binding, []string{supportedSubject}, "")}
}

func TestProducerRequiresIndependentExecutionPremises(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=value")
	good := supportedIngest(t, frame, "worker", env)
	cases := []struct {
		name        string
		change      func(*ProducerIngest)
		log, reason string
	}{
		{"supported", func(*ProducerIngest) {}, "getenv OUTCOME\n", ""},
		{"receipt missing", func(in *ProducerIngest) { in.Completion = CompletionReceipt{} }, "", "completion receipt unavailable"},
		{"support missing", func(in *ProducerIngest) { in.Outcome = OutcomeSupport{} }, "", "outcome support unavailable"},
		{"unsupported inventory", func(in *ProducerIngest) {
			binding, err := frame.OutcomeBinding(in.Identity, in.Env)
			if err != nil {
				t.Fatal(err)
			}
			in.Outcome = outcome.Prepare(binding, []string{supportedSubject}, "file outcomes not supported")
		}, "", "file outcomes not supported"},
		{"wrong process", func(in *ProducerIngest) { in.Identity = "other" }, "", "completion receipt belongs"},
		{"wrong environment", func(in *ProducerIngest) { in.Env = producerEnv(dir, "OUTCOME=changed") }, "", "completion receipt belongs"},
		{"wrong support process", func(in *ProducerIngest) { in.Outcome = supportedIngest(t, frame, "other", env).Outcome }, "", "outcome support belongs"},
		{"wrong support environment", func(in *ProducerIngest) {
			in.Outcome = supportedIngest(t, frame, "worker", producerEnv(dir, "OUTCOME=changed")).Outcome
		}, "", "outcome support belongs"},
		{"abnormal completion", func(in *ProducerIngest) {
			var err error
			in.Completion, err = frame.Completion("worker", env, "process killed")
			if err != nil {
				t.Fatal(err)
			}
		}, "", "process killed"},
		{"file contradicts inventory", func(*ProducerIngest) {}, "open fixture\n", "does not cover"},
		{"exclusion cannot hide contradiction", func(in *ProducerIngest) { in.ExcludedPaths = []string{frame.PkgRel + "/fixture"} }, "open fixture\n", "does not cover"},
		{"unknown operation", func(*ProducerIngest) {}, "unknown ignored\n", "does not cover"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.change(&in)
			obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, tc.log), in)
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if reason != "" || obs.Unverifiable || !HasOutcomeSupport(obs.Manifest, supportedSubject) {
					t.Fatalf("supported=%+v, reason=%q", obs, reason)
				}
			} else if !strings.Contains(reason, tc.reason) || !obs.Unverifiable || HasOutcomeSupport(obs.Manifest, supportedSubject) {
				t.Fatalf("refusal=%+v reason=%q want %q", obs, reason, tc.reason)
			}
		})
	}
	copyFrame := frame
	if _, reason, err := copyFrame.Observe(context.Background(), writeTestlog(t, ""), good); err != nil || reason != "" {
		t.Fatalf("copied frame=%q %v", reason, err)
	}
	other := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	if _, reason, err := other.Observe(context.Background(), writeTestlog(t, ""), good); err != nil || !strings.Contains(reason, "completion receipt belongs") {
		t.Fatalf("independent frame=%q %v", reason, err)
	}
	for _, path := range []string{"", t.TempDir() + "/missing"} {
		if obs, reason, err := frame.Observe(context.Background(), path, good); err != nil || reason == "" || HasOutcomeSupport(obs.Manifest, supportedSubject) {
			t.Fatalf("missing capture=%+v %q %v", obs, reason, err)
		}
	}
}

func TestOutcomeBindingPreservesEnvironmentBytes(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	a := producerEnv(dir, "OUTCOME=\xff")
	b := producerEnv(dir, "OUTCOME=\xfe")
	first := supportedIngest(t, frame, "worker", a)
	second := supportedIngest(t, frame, "worker", b)
	ba, err := frame.OutcomeBinding("worker", a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := frame.OutcomeBinding("worker", b)
	if err != nil {
		t.Fatal(err)
	}
	if ba == bb {
		t.Error("distinct environment bytes share an execution binding")
	}
	for _, receipt := range []bool{true, false} {
		in := second
		want := "outcome support belongs"
		if receipt {
			in.Completion = first.Completion
			want = "completion receipt belongs"
		} else {
			in.Outcome = first.Outcome
		}
		obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), in)
		if err != nil || !strings.Contains(reason, want) || !obs.Unverifiable || HasOutcomeSupport(obs.Manifest, supportedSubject) {
			t.Fatalf("raw environment mismatch: %+v %q %v", obs, reason, err)
		}
	}
}

func TestOutcomePremiseInputsAndExportedSubjects(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir)
	for _, process := range []string{"", "bad\nprocess", "bad\x00process", "\xff"} {
		if _, err := frame.OutcomeBinding(process, env); err == nil {
			t.Fatalf("accepted process %q", process)
		}
		if _, err := frame.Completion(process, env, ""); err == nil {
			t.Fatalf("accepted receipt process %q", process)
		}
	}
	for _, malformed := range [][]string{{"A=one", "A=two"}, {"missing-equals"}, {"=empty-name"}, {"A=bad\x00value"}} {
		if _, err := frame.OutcomeBinding("worker", malformed); err == nil {
			t.Fatalf("accepted environment %q", malformed)
		}
		if _, err := frame.Completion("worker", malformed, ""); err == nil {
			t.Fatalf("accepted receipt environment %q", malformed)
		}
	}
	in := supportedIngest(t, frame, "worker", env)
	invalidIngest := in
	invalidIngest.Env = []string{"missing-equals"}
	if _, reason := frame.completionPremise(invalidIngest); !strings.Contains(reason, "binding invalid") {
		t.Fatalf("malformed binding reported as another premise: %q", reason)
	}
	exported := in.Outcome.Subjects()
	exported[0] = strings.Repeat("b", 64)
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), in)
	if err != nil || reason != "" || !HasOutcomeSupport(obs.Manifest, supportedSubject) || HasOutcomeSupport(obs.Manifest, exported[0]) {
		t.Fatalf("exported subjects altered opaque support: %+v %q %v", obs, reason, err)
	}
}

func TestIdentityFacadePreservesGuardsWithoutGrantingOutcomes(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir)
	in := supportedIngest(t, frame, "worker", env)
	empty, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, ""), in)
	if err != nil || reason != "" || !empty.OK || empty.Manifest == "" || empty.Unverifiable || HasOutcomeSupport(empty.Manifest, supportedSubject) {
		t.Fatalf("identity-only empty capture: %+v %v", empty, err)
	}
	observation, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, "open fixture\n"), in)
	if err != nil || reason != "" || observation.Unverifiable {
		t.Fatalf("identity capture: %+v %v", observation, err)
	}
	paths, err := ModuleRelPaths(observation.Manifest)
	if err != nil || len(paths) != 1 || paths[0] != "pkg/fixture" {
		t.Fatalf("identity paths=%v %v", paths, err)
	}
	if HasOutcomeSupport(observation.Manifest, supportedSubject) {
		t.Fatal("identity capture granted outcomes")
	}
	binding, err := frame.OutcomeBinding("worker", env)
	if err != nil {
		t.Fatal(err)
	}
	for _, support := range []OutcomeSupport{{}, outcome.Prepare(binding, []string{supportedSubject}, "unsupported file inventory")} {
		withoutSupport := in
		withoutSupport.Outcome = support
		got, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, "open fixture\n"), withoutSupport)
		if err != nil || reason != "" || !got.OK || got.Unverifiable || got.State != observation.State || HasOutcomeSupport(got.Manifest, supportedSubject) {
			t.Fatalf("unavailable outcomes lost identity guards: %+v %v", got, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := Current(context.Background(), observation.Manifest, root, env)
	if err != nil || current.Digest == observation.Digest {
		t.Fatalf("identity guard missed movement: %+v %v", current, err)
	}
	for _, modify := range []func(*ProducerIngest){
		func(in *ProducerIngest) { in.Completion = CompletionReceipt{} },
		func(in *ProducerIngest) { in.Identity = "another process" },
		func(in *ProducerIngest) {
			var err error
			in.Completion, err = frame.Completion(in.Identity, in.Env, "process aborted")
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		bad := in
		modify(&bad)
		obs, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, "open fixture\n"), bad)
		if err != nil || reason == "" || !obs.Unverifiable {
			t.Fatalf("invalid completion yielded identity evidence: %+v %v", obs, err)
		}
		paths, err := ModuleRelPaths(obs.Manifest)
		if err != nil || len(paths) != 0 {
			t.Fatalf("uncompleted capture retained identities: %v %v", paths, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if obs, _, err := frame.ObserveInputs(ctx, writeTestlog(t, ""), in); !errors.Is(err, context.Canceled) || obs.OK {
		t.Fatalf("cancelled identity capture=%+v %v", obs, err)
	}
}

func TestIdentityFacadeDistinguishesCaptureFailureFromUnguardedIdentity(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	in := supportedIngest(t, frame, "worker", producerEnv(dir))
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		obs, reason, err := frame.ObserveInputs(context.Background(), path, in)
		if err != nil || reason == "" || !obs.Unverifiable {
			t.Fatalf("capture failure lost its disposition: %+v %q %v", obs, reason, err)
		}
	}
	headerless := filepath.Join(t.TempDir(), "headerless")
	if err := os.WriteFile(headerless, []byte("getenv HOME\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reason, err := frame.ObserveInputs(context.Background(), headerless, in); err != nil || !strings.Contains(reason, "header") {
		t.Fatalf("headerless capture=%q %v", reason, err)
	}
	// A captured read outside the bracket is a finalized, unguarded identity,
	// not a failed capture. Both forms are unverifiable; only one has a reason
	// in the facade's completion-disposition channel.
	outside := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(outside, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, "open "+outside+"\n"), in)
	if err != nil || reason != "" || !obs.Unverifiable || obs.Reason == "" {
		t.Fatalf("unguarded identity confused with capture failure: %+v %q %v", obs, reason, err)
	}
}

func TestScratchRootDeclarationPreservesEnvironmentValues(t *testing.T) {
	root, dir := producerModule(t)
	scratch := t.TempDir()
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "TMPDIR="+scratch)
	in := supportedIngest(t, frame, "worker", env)
	in.ScratchRoot = scratch
	obs, reason, err := frame.ObserveInputs(context.Background(), writeTestlog(t, "getenv TMPDIR\nstat "+scratch+"\n"), in)
	if err != nil || reason != "" || obs.Unverifiable {
		t.Fatalf("scratch capture = %+v %q %v", obs, reason, err)
	}
	paths, err := Paths(obs.Manifest, root)
	if err != nil || len(paths) != 0 {
		t.Fatalf("declared root recorded a filesystem identity: %v %v", paths, err)
	}
	unchanged, err := Current(context.Background(), obs.Manifest, root, env)
	if err != nil || unchanged.Unverifiable || unchanged.Digest != obs.Digest {
		t.Fatalf("scratch capture did not bind the delivered environment: %+v %v", unchanged, err)
	}
	changed, err := Current(context.Background(), obs.Manifest, root, producerEnv(dir, "TMPDIR="+t.TempDir()))
	if err != nil || changed.Digest == obs.Digest {
		t.Fatalf("root declaration erased the logged environment value: %+v %v", changed, err)
	}
}

func TestProducerKeepsOneEnvironmentSnapshot(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=original")
	original := slices.Clone(env)
	in := supportedIngest(t, frame, "worker", env)
	called := false
	in.Runner.Prepare = func(*exec.Cmd) {
		called = true
		for i, entry := range env {
			if strings.HasPrefix(entry, "OUTCOME=") {
				env[i] = "OUTCOME=changed"
			}
		}
	}
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), in)
	if err != nil || reason != "" || !called {
		t.Fatalf("observe=%q %v, hook=%t", reason, err, called)
	}
	current, err := Current(context.Background(), obs.Manifest, root, original)
	if err != nil || current != obs.State {
		t.Fatalf("finalization did not retain its bound environment: %+v %v", current, err)
	}
}

type outcomeReadFunc func([]byte) (int, error)

func (f outcomeReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestCaptureCancellationCannotBecomeIncompleteEvidence(t *testing.T) {
	for _, terminal := range []error{nil, io.EOF, io.ErrUnexpectedEOF} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := outcomeReadFunc(func(p []byte) (int, error) {
			n := copy(p, "headerless capture")
			cancel()
			return n, terminal
		})
		data, err := io.ReadAll(captureReader{ctx: ctx, Reader: reader})
		if !errors.Is(err, context.Canceled) || len(data) != 0 {
			t.Fatalf("capture read under cancellation: %q %v", data, err)
		}
	}
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	in := supportedIngest(t, frame, "worker", producerEnv(dir))
	path := filepath.Join(t.TempDir(), "headerless")
	if err := os.WriteFile(path, []byte("not a log"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background(), after: 1}
	obs, reason, err := frame.Observe(ctx, path, in)
	if !errors.Is(err, context.Canceled) || obs.OK || reason != "" {
		t.Fatalf("early refusal recorded cancellation: %+v %q %v", obs, reason, err)
	}
	screen := &cancelAfterChecks{Context: context.Background(), after: 8}
	if _, err := environmentLog(screen, []byte(strings.Repeat("getenv VALUE\n", 64))); !errors.Is(err, context.Canceled) {
		t.Fatalf("operation screen ignored cancellation: %v", err)
	}
	// OS errors may contain arbitrary path bytes. Their attribution must not
	// make the incomplete manifest itself unrepresentable.
	obs, reason, err = frame.Observe(context.Background(), filepath.Join(t.TempDir(), "bad\x00path"), in)
	if err != nil || !obs.Unverifiable || !strings.Contains(reason, "capture unreadable") {
		t.Fatalf("unreadable capture lost its disposition: %+v %q %v", obs, reason, err)
	}
}

func FuzzOutcomeBindingRetainsEnvironmentBytes(f *testing.F) {
	f.Add("\xff", "\xfe")
	f.Add("\xff", "\ufffd")
	f.Add("value\nOTHER=entry", "value")
	f.Fuzz(func(t *testing.T, a, b string) {
		// NUL is outside the environment grammar; every other byte, including
		// invalid UTF-8, remains in the generated value domain.
		a, b = strings.ReplaceAll(a, "\x00", "\x01"), strings.ReplaceAll(b, "\x00", "\x01")
		frame := ProducerFrame{span: new(outcome.Span)}
		first, err := frame.OutcomeBinding("worker", []string{"VALUE=" + a, "OTHER=fixed"})
		if err != nil {
			t.Fatal(err)
		}
		second, err := frame.OutcomeBinding("worker", []string{"OTHER=fixed", "VALUE=" + b})
		if err != nil {
			t.Fatal(err)
		}
		if (first == second) != (a == b) {
			t.Fatal("binding changed equality of normalized environment bytes")
		}
		separate, err := frame.OutcomeBinding("worker", []string{"A=" + a, "B=" + b})
		if err != nil {
			t.Fatal(err)
		}
		for _, separator := range []string{"", "\n"} {
			joined, err := frame.OutcomeBinding("worker", []string{"A=" + a + separator + "B=" + b})
			if err != nil {
				t.Fatal(err)
			}
			if separate == joined {
				t.Fatal("binding lost an environment-entry boundary")
			}
		}
	})
}

func TestOutcomeSupportSurvivesWithoutPromotion(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=value")
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), supportedIngest(t, frame, "worker", env))
	if err != nil || reason != "" {
		t.Fatalf("observe=%q %v", reason, err)
	}
	current, err := Current(context.Background(), obs.Manifest, root, env)
	if err != nil || current != obs.State {
		t.Fatalf("current=%+v %v; want %+v", current, err, obs.State)
	}
	abs, err := Absolute(obs, root, env)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := Relative(abs, root, env)
	if err != nil || rel.State != obs.State {
		t.Fatalf("conversion=%+v %v", rel, err)
	}
	adopted, err := Adopt(obs.Manifest, root, "adopted", env)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Merge(root, env)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(root, env, empty, obs, adopted)
	if err != nil || merged.State != obs.State {
		t.Fatalf("supported union=%+v %v", merged, err)
	}
	plain, err := FromTestLog([]byte("getenv OUTCOME\n"), root, dir, env, WithCompletedProcess("identity-only"), WithBracket(*frame.bracket))
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := Incomplete(root, "incomplete", "unsupported outcomes", env)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []Observation{plain, incomplete} {
		for _, pair := range [][]Observation{{obs, other}, {other, obs}} {
			union, err := Merge(root, env, pair...)
			if err != nil {
				t.Fatal(err)
			}
			if HasOutcomeSupport(union.Manifest, supportedSubject) {
				t.Fatal("merge upgraded unsupported child")
			}
			reentered, err := Adopt(union.Manifest, root, "again", env)
			if err != nil {
				t.Fatal(err)
			}
			if HasOutcomeSupport(reentered.Manifest, supportedSubject) {
				t.Fatal("adoption upgraded unsupported union")
			}
		}
	}
	if HasOutcomeSupport(obs.Manifest, strings.Repeat("b", 64)) {
		t.Fatal("another subject borrowed support")
	}
	old := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}`))
	if _, err := Adopt(old, root, "old", env); err == nil {
		t.Fatal("adopted old manifest")
	}
	if HasOutcomeSupport(old, supportedSubject) {
		t.Fatal("old manifest gained support")
	}
}

func TestProducerCancellationReachesClosingBracket(t *testing.T) {
	root, dir := producerModule(t)
	for i := 0; i < 128; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("input-%d", i)), []byte("value"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir)
	in := supportedIngest(t, frame, "worker", env)
	in.Roots = &Roots{}
	path := writeTestlog(t, "")
	// Warm the roots independently: the later cancellation budgets reach the
	// finalizer's bracket walk, rather than an incidental go-env subprocess.
	if _, reason, err := frame.Observe(context.Background(), path, in); err != nil || reason != "" {
		t.Fatalf("warm observe: %q %v", reason, err)
	}
	for _, after := range []int{0, 8, 32, 64} {
		ctx := &cancelAfterChecks{Context: context.Background(), after: after}
		obs, reason, err := frame.Observe(ctx, path, in)
		if !errors.Is(err, context.Canceled) || reason != "" || obs.OK || obs.Manifest != "" {
			t.Fatalf("cancel after %d checks: %+v %q %v", after, obs, reason, err)
		}
	}
}

func TestOutcomeManifestRefusesInconsistentSupport(t *testing.T) {
	for _, m := range []manifest{
		{Version: 1},
		{Version: manifestVersion, Outcome: outcome.Method},
		{Version: manifestVersion, Subjects: []string{supportedSubject}},
		{Version: manifestVersion, Outcome: "unknown", Subjects: []string{supportedSubject}},
		{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{"not a digest"}},
		{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{supportedSubject}, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "file"}, Digest: testEntryDigest}}},
	} {
		if _, err := encode(m); err == nil {
			t.Fatalf("encoded inconsistent support: %+v", m)
		}
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decode(base64.RawURLEncoding.EncodeToString(data)); err == nil {
			t.Fatalf("decoded inconsistent support: %+v", m)
		}
	}
}

func TestManifestDigestPinsTheWireFold(t *testing.T) {
	plain := manifest{Version: manifestVersion, Env: []envInput{{Name: "A", Digest: testEntryDigest}}, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "file"}, Digest: strings.Repeat("1", 32)}}, Unverifiable: []string{"reason"}}
	if got := manifestDigest(plain); got != "d18d3f32277111a932627632314b8d4c" {
		t.Fatalf("identity-only wire digest = %q", got)
	}
	supported := manifest{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{supportedSubject}, Env: []envInput{{Name: "A", Digest: testEntryDigest}}}
	if got := manifestDigest(supported); got != "bcc147977722ca16ce145847c2ab6a41" {
		t.Fatalf("supported wire digest = %q", got)
	}
}

func FuzzOutcomeEvidenceMergePreservesSupport(f *testing.F) {
	f.Add(byte(0), byte(0), byte(0), []byte("supported processes"))
	f.Add(byte(0), byte(1), byte(0), []byte("identity-only child"))
	f.Add(byte(2), byte(0), byte(3), []byte("incomplete child"))
	f.Add(byte(3), byte(3), byte(0), []byte("zero-process identities"))
	f.Add(byte(4), byte(0), byte(3), []byte("movement beside support and empty evidence"))
	f.Add(byte(2), byte(4), byte(1), []byte("movement beside incomplete evidence"))
	f.Fuzz(func(t *testing.T, left, right, third byte, data []byte) {
		makeObservation := func(mode byte, index int) (Observation, string) {
			if mode%5 == 3 {
				obs, err := Merge(".", []string{})
				if err != nil {
					t.Fatal(err)
				}
				return obs, ""
			}
			key := sha256.Sum256(append([]byte{byte(index)}, data...))
			subject := hex.EncodeToString(key[:])
			m := manifest{Version: manifestVersion}
			switch mode % 5 {
			case 0:
				m.Outcome, m.Subjects = outcome.Method, []string{subject}
			case 2:
				m.Unverifiable = []string{"operation-outcome support unavailable"}
			case 4:
				m.BracketMoved = true
				m.Unverifiable = []string{"observation bracket moved: data"}
			}
			state, err := stateFromManifest(context.Background(), m, ".", []string{})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decode(state.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			again, err := encode(decoded)
			if err != nil || again != state.Manifest {
				t.Fatalf("noncanonical roundtrip: %v", err)
			}
			return newObservation(state, fmt.Sprintf("process-%d", index), "fixture"), subject
		}
		a, keyA := makeObservation(left, 0)
		b, keyB := makeObservation(right, 1)
		c, keyC := makeObservation(third, 2)
		ab, err := Merge(".", []string{}, a, b)
		if err != nil {
			t.Fatal(err)
		}
		ba, err := Merge(".", []string{}, b, a)
		if err != nil || ba.State != ab.State {
			t.Fatalf("commutativity: %v", err)
		}
		idempotent, err := Merge(".", []string{}, ab, ab)
		if err != nil || idempotent.State != ab.State {
			t.Fatalf("idempotence: %v", err)
		}
		lhs, err := Merge(".", []string{}, ab, c)
		if err != nil {
			t.Fatal(err)
		}
		bc, err := Merge(".", []string{}, b, c)
		if err != nil {
			t.Fatal(err)
		}
		rhs, err := Merge(".", []string{}, a, bc)
		if err != nil || lhs.State != rhs.State {
			t.Fatalf("associativity: %v", err)
		}
		if lhs.BracketMoved != (left%5 == 4 || right%5 == 4 || third%5 == 4) {
			t.Fatal("merge promoted or lost demonstrated movement")
		}
		eligible := func(mode byte) bool { return mode%5 == 0 || mode%5 == 3 }
		want := eligible(left) && eligible(right) && eligible(third)
		for _, key := range []string{keyA, keyB, keyC} {
			if HasOutcomeSupport(lhs.Manifest, key) != (want && key != "") {
				t.Fatal("merge promoted or lost outcome support")
			}
		}
	})
}
