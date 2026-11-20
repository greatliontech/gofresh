package runtimeinput

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/trace"
	"pgregory.net/rapid"
)

func referenceSplitTestLogLines(data []byte) ([]string, bool) {
	if len(data) == 0 {
		return nil, false
	}
	missingTrailingNL := data[len(data)-1] != '\n'
	parts := bytes.Split(data, []byte{'\n'})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out, missingTrailingNL
}

func TestRapidNextTestLogLineBytesEquivalence(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		bufSize := rapid.IntRange(16, 128).Draw(t, "bufSize")
		segments := rapid.SliceOfN(rapid.OneOf(
			rapid.Just([]byte("# test log\n")),
			rapid.Just([]byte("\n")),
			rapid.Just([]byte("\r\n")),
			rapid.Just([]byte("getenv FOO\r\n")),
			rapid.Just([]byte("open a\x00b\n")),
			rapid.SliceOfN(rapid.Byte(), 0, 300),
		), 0, 20).Draw(t, "segments")
		raw := bytes.Join(segments, nil)

		wantLines, wantMissingNL := referenceSplitTestLogLines(raw)

		br := bufio.NewReaderSize(bytes.NewReader(raw), bufSize)
		var scratch []byte
		var gotLines []string
		gotMissingNL := false
		for {
			line, hasNL, eof, err := nextTestLogLineBytes(br, &scratch)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eof {
				break
			}
			if !hasNL {
				gotMissingNL = true
			}
			gotLines = append(gotLines, string(line))
		}
		if gotMissingNL != wantMissingNL || !slices.Equal(gotLines, wantLines) {
			t.Fatalf("mismatch for len=%d bufSize=%d:\ngot  lines=%q missingNL=%v\nwant lines=%q missingNL=%v",
				len(raw), bufSize, gotLines, gotMissingNL, wantLines, wantMissingNL)
		}
	})
}

func FuzzTestLogStreamChunkInvariance(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("# test log"))
	f.Add([]byte("# test log\n"))
	f.Add([]byte("# test log\r\n"))
	f.Add([]byte("# test log\ngetenv FOO\r\n"))
	f.Add([]byte("# test log\ngetenv PWD\nopen fixture.txt\n"))
	f.Add([]byte("# test log\nchdir /tmp\nopen rel.txt\ngetenv PWD\n"))
	f.Add([]byte("# test log\nopen a\x00b\n\xffbadop arg"))

	root := f.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "fixture.txt"), []byte("hello\n"), 0o644); err != nil {
		f.Fatal(err)
	}
	bracket, err := CaptureBracket(context.Background(), root, []string{"pkg"})
	if err != nil {
		f.Fatal(err)
	}
	env := []string{"PATH=/usr/bin", "PWD=" + pkgDir}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		opts := []TestLogOption{
			WithCompletedProcess("fuzz-worker"),
			WithBracket(bracket),
		}
		fullObs, err1 := FromTestLog(data, root, pkgDir, env, opts...)
		chunkedReader := bufio.NewReaderSize(bytes.NewReader(data), 16)
		streamObs, err2 := fromTestLogStream(context.Background(), chunkedReader, root, pkgDir, normalized, opts...)
		if (err1 != nil) != (err2 != nil) {
			t.Fatalf("error mismatch: FromTestLog=%v vs stream=%v", err1, err2)
		}
		if err1 != nil {
			return
		}
		if fullObs.State != streamObs.State || fullObs.Attribution != streamObs.Attribution {
			t.Fatalf("observation mismatch:\nfull   = %+v (attr=%q)\nstream = %+v (attr=%q)",
				fullObs.State, fullObs.Attribution, streamObs.State, streamObs.Attribution)
		}
		if _, wantMissingNL := referenceSplitTestLogLines(data); wantMissingNL {
			m, err := decode(streamObs.Manifest)
			if err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			if !streamObs.Unverifiable || !slices.Contains(m.Unverifiable, "malformed testlog line") {
				t.Fatalf("missing trailing newline failed to record malformed testlog line: %+v (%v)", streamObs.State, m.Unverifiable)
			}
		}
	})
}

func TestTrackedChdirBalancedExcursionsDedupAndFromTestLogFile(t *testing.T) {
	root, pkgDir := producerModule(t)
	subDir := filepath.Join(pkgDir, "testdata", "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "sibling.txt"), []byte("sibling\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratchRoot := t.TempDir()
	goneTemp := filepath.Join(scratchRoot, "TestVersionSurfaces001")
	outsideFile := filepath.Join(t.TempDir(), "ext.txt")
	if err := os.WriteFile(outsideFile, []byte("ext\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	if frame.Reason() != "" {
		t.Fatalf("CaptureProducerFrame: %s", frame.Reason())
	}
	env := producerEnv(pkgDir)
	receipt, err := frame.Completion("pkg-test", env, "")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate real Go testing.(*common).Chdir(t.TempDir()) + nested in-module
	// t.Chdir(subDir) + self t.Chdir(pkgDir) + sibling relative open, including
	// in-excursion `getenv PWD` emitted by c.Setenv("PWD", dir) and os.Getwd(),
	// plus 500 repeated opens of outsideFile to verify deduplication.
	var sb strings.Builder
	sb.WriteString("# test log\n")
	// 1. Excursion into absent-at-ingest temp dir with in-excursion getenv PWD & scratch reads.
	sb.WriteString("open .\n")
	sb.WriteString("chdir " + goneTemp + "\n")
	sb.WriteString("getenv PWD\n")
	sb.WriteString("open go.mod\n")
	sb.WriteString("stat .\n")
	sb.WriteString("getenv PWD\n")
	sb.WriteString("chdir " + pkgDir + "\n")
	// 2. Nested excursion: subDir -> pkgDir -> subDir -> pkgDir.
	sb.WriteString("chdir " + subDir + "\n")
	sb.WriteString("open nested.txt\n")
	sb.WriteString("chdir " + pkgDir + "\n")
	sb.WriteString("chdir " + subDir + "\n")
	sb.WriteString("chdir " + pkgDir + "\n")
	// 3. Self excursion: pkgDir -> pkgDir.
	sb.WriteString("chdir " + pkgDir + "\n")
	sb.WriteString("chdir " + pkgDir + "\n")
	// 4. Post-restoration sibling relative read.
	sb.WriteString("open sibling.txt\n")
	for range 500 {
		sb.WriteString("stat " + filepath.Dir(outsideFile) + "\n")
	}

	logPath := filepath.Join(t.TempDir(), "testlog.txt")
	if err := os.WriteFile(logPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	roots := &Roots{}
	// 1. With valid TrackedChdirSupport: observation is verifiable, temp excursion
	// is elided, in-excursion nested.txt and post-excursion sibling.txt are recorded,
	// PWD is recorded without process-local refusal, and Absolute conversion succeeds.
	var (
		classifyCalls int
		obs           Observation
		reason        string
	)
	withRuntimeTestHooks(runtimeTestHookSet{
		classifyStat: func(p string) (os.FileInfo, error) {
			classifyCalls++
			return os.Stat(p)
		},
	}, func() {
		obs, reason, err = frame.ObserveInputs(context.Background(), logPath, ProducerIngest{
			Identity:     "pkg-test",
			Env:          env,
			Roots:        roots,
			Completion:   receipt,
			TrackedChdir: frame.PrepareTrackedChdir(true),
			ScratchRoot:  scratchRoot,
		})
	})
	if err != nil || reason != "" {
		t.Fatalf("ObserveInputs with TrackedChdirSupport: reason=%q err=%v", reason, err)
	}
	if obs.Unverifiable {
		t.Fatalf("expected verifiable observation under balanced tracked chdir, got Reason=%q Manifest=%s", obs.Reason, obs.Manifest)
	}
	if classifyCalls > 5 {
		t.Fatalf("expected duplicate external dir stats to be deduplicated, got %d classifyStat probes", classifyCalls)
	}
	absObs, err := Absolute(obs, root, gotool.SetEnv(env, "PWD", root))
	if err != nil || absObs.Unverifiable {
		t.Fatalf("Absolute conversion after tracked chdir failed: obs=%+v err=%v", absObs, err)
	}

	// Verify FromTestLogFile matches FromTestLog byte-for-byte on identity-only options.
	rawBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	bkt, err := CaptureBracket(context.Background(), root, []string{"pkg"})
	if err != nil {
		t.Fatal(err)
	}
	fromBytes, err := FromTestLog(rawBytes, root, pkgDir, env, WithCompletedProcess("w"), WithBracket(bkt))
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := FromTestLogFile(context.Background(), logPath, root, pkgDir, env, WithCompletedProcess("w"), WithBracket(bkt))
	if err != nil {
		t.Fatal(err)
	}
	if fromBytes.State != fromFile.State || fromBytes.Attribution != fromFile.Attribution {
		t.Fatalf("FromTestLogFile != FromTestLog:\nfile=%+v\nbytes=%+v", fromFile.State, fromBytes.State)
	}

	// 2. Forged/foreign TrackedChdirSupport or zero capability refuses to unseal
	// and emits runtimeinput.chdir.untracked.
	foreignFrame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	for _, badCap := range []TrackedChdirSupport{
		{},
		frame.PrepareTrackedChdir(false),
		foreignFrame.PrepareTrackedChdir(true),
	} {
		rec := trace.NewRecorder()
		traceCtx := trace.WithSink(context.Background(), rec)
		untrackedObs, r, err := frame.ObserveInputs(traceCtx, logPath, ProducerIngest{
			Identity:     "pkg-test",
			Env:          env,
			Roots:        roots,
			Completion:   receipt,
			TrackedChdir: badCap,
			ScratchRoot:  scratchRoot,
		})
		if err != nil || r != "" {
			t.Fatalf("untracked ObserveInputs error: r=%q err=%v", r, err)
		}
		if !untrackedObs.Unverifiable {
			t.Fatalf("bad capability %+v unsealed chdir!", badCap)
		}
		m, err := decode(untrackedObs.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(m.Unverifiable, "working-directory change") || !slices.Contains(m.Unverifiable, "process-local environment input: PWD") {
			t.Fatalf("expected working-directory change and PWD seals, got %v", m.Unverifiable)
		}
		if len(rec.ByName("runtimeinput.chdir.untracked")) == 0 {
			t.Fatalf("missing runtimeinput.chdir.untracked trace event: %+v", rec.Events())
		}
	}
}

func TestTrackedChdirUnbalancedAndAmbiguousCausalTraces(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := producerEnv(pkgDir)
	receipt, err := frame.Completion("pkg-test", env, "")
	if err != nil {
		t.Fatal(err)
	}
	scratchRoot := t.TempDir()
	goneA := filepath.Join(scratchRoot, "A")
	goneB := filepath.Join(scratchRoot, "B")

	cases := []struct {
		name      string
		lines     string
		wantTrace string
		wantPWD   bool
	}{
		{
			name:      "aborted_excursion_followed_by_balanced_excursion",
			lines:     "chdir " + goneA + "\ngetenv PWD\nchdir " + goneB + "\nchdir " + pkgDir + "\n",
			wantTrace: "runtimeinput.chdir.unbalanced",
			wantPWD:   true,
		},
		{
			name:      "unrestored_single_excursion_without_pwd",
			lines:     "chdir " + goneA + "\n",
			wantTrace: "runtimeinput.chdir.unbalanced",
			wantPWD:   false,
		},
		{
			name:      "relative_chdir_target_ambiguous",
			lines:     "chdir sub\ngetenv PWD\nchdir " + pkgDir + "\n",
			wantTrace: "runtimeinput.chdir.ambiguous",
			wantPWD:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath := writeTestlog(t, tc.lines)
			rec := trace.NewRecorder()
			traceCtx := trace.WithSink(context.Background(), rec)
			obs, reason, err := frame.ObserveInputs(traceCtx, logPath, ProducerIngest{
				Identity:     "pkg-test",
				Env:          env,
				Roots:        &Roots{},
				Completion:   receipt,
				TrackedChdir: frame.PrepareTrackedChdir(true),
				ScratchRoot:  scratchRoot,
			})
			if err != nil || reason != "" {
				t.Fatalf("ObserveInputs: reason=%q err=%v", reason, err)
			}
			if !obs.Unverifiable {
				t.Fatalf("expected unverifiable observation, got %+v", obs)
			}
			m, err := decode(obs.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(m.Unverifiable, "working-directory change") {
				t.Fatalf("missing working-directory change in %v", m.Unverifiable)
			}
			if slices.Contains(m.Unverifiable, "process-local environment input: PWD") != tc.wantPWD {
				t.Fatalf("PWD seal presence = %v, want %v (unverifiable=%v)", !tc.wantPWD, tc.wantPWD, m.Unverifiable)
			}
			if len(rec.ByName(tc.wantTrace)) == 0 {
				t.Fatalf("expected trace event %q, got %+v", tc.wantTrace, rec.Events())
			}
		})
	}
}

type failingMidStreamReader struct {
	prefix []byte
	err    error
}

func (r *failingMidStreamReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return 0, r.err
}

func TestProducerStreamingRefusalPrecedenceMidStreamReadAndOutcomeScreen(t *testing.T) {
	root, pkgDir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	bracketless := ProducerFrame{Root: root, PkgDir: pkgDir, reason: "no bracket"}
	env := producerEnv(pkgDir)
	badPWDEnv := gotool.SetEnv(env, "PWD", root)

	in := supportedIngest(t, frame, "worker", env)

	// Step 4 (mid-stream read error) outranks Step 6 (unsupported op), Step 7 (no bracket), and Step 8 (bad PWD).
	ioBoom := errors.New("synthetic mid-stream EIO")
	for _, tc := range []struct {
		name  string
		f     ProducerFrame
		env   []string
		reqOut bool
	}{
		{"happy_frame_supported", frame, env, true},
		{"happy_frame_inputs", frame, env, false},
		{"bracketless_frame", bracketless, env, true},
		{"bad_pwd_frame", frame, badPWDEnv, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(&failingMidStreamReader{
				prefix: []byte("open disallowed\n"),
				err:    ioBoom,
			}, 16)
			localIn := in
			localIn.Env = tc.env
			obs, reason, err := tc.f.captureStream(context.Background(), br, localIn, nil, tc.reqOut)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !obs.Unverifiable || !strings.Contains(reason, "testlog capture unreadable") || !strings.Contains(reason, "synthetic mid-stream EIO") {
				t.Fatalf("Step 4 did not outrank later steps: reason=%q obs=%+v", reason, obs)
			}
		})
	}

	// Step 6 (unsupported op under requireOutcomes) outranks Step 7 (bracketless) and Step 8 (bad PWD).
	for _, tc := range []struct {
		name string
		f    ProducerFrame
		env  []string
	}{
		{"step6_beats_step7_bracketless", bracketless, env},
		{"step6_beats_step8_bad_pwd", frame, badPWDEnv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader("getenv OK\nopen disallowed\n"))
			localIn := in
			localIn.Env = tc.env
			obs, reason, err := tc.f.captureStream(context.Background(), br, localIn, nil, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !obs.Unverifiable || reason != "operation-outcome support does not cover the captured operations" {
				t.Fatalf("Step 6 did not outrank later steps: reason=%q obs=%+v", reason, obs)
			}
		})
	}
}

func TestRapidTrackedChdirStackAndDedupReferenceInterpreter(t *testing.T) {
	root, pkgDir := producerModule(t)
	subA := filepath.Join(pkgDir, "subA")
	subB := filepath.Join(pkgDir, "subB")
	for _, d := range []string{subA, subB} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "root.txt"), []byte("r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subA, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subB, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratchRoot := t.TempDir()
	tempX := filepath.Join(scratchRoot, "tx")
	tempY := filepath.Join(scratchRoot, "ty")

	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	env := producerEnv(pkgDir)
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		t.Fatal(err)
	}
	roots := &Roots{}
	resolved, err := resolveRoots(context.Background(), roots, gotool.Runner{}, frame.Root, frame.PkgDir, normalized)
	if err != nil {
		t.Fatal(err)
	}

	dirs := []string{pkgDir, subA, subB, tempX, tempY}
	rapid.Check(t, func(rt *rapid.T) {
		tracked := rapid.Bool().Draw(rt, "tracked")
		bufSize := rapid.IntRange(16, 128).Draw(rt, "bufSize")
		numOps := rapid.IntRange(1, 18).Draw(rt, "numOps")

		var lines []string
		lines = append(lines, "# test log")
		cwd := pkgDir
		var stack []string
		sawChdir := false
		sawPostUntrackedPWD := false
		sawInExcursionPWD := false

		for range numOps {
			kind := rapid.IntRange(0, 4).Draw(rt, "kind")
			switch kind {
			case 0: // balanced push or pop
				if len(stack) > 0 && rapid.Bool().Draw(rt, "pop") {
					target := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					lines = append(lines, "chdir "+target)
					cwd = target
				} else {
					target := dirs[rapid.IntRange(0, len(dirs)-1).Draw(rt, "dir")]
					if len(stack) > 0 && stack[len(stack)-1] == target {
						stack = stack[:len(stack)-1]
					} else {
						stack = append(stack, cwd)
					}
					lines = append(lines, "chdir "+target)
					cwd = target
				}
				sawChdir = true
			case 1: // getenv PWD
				lines = append(lines, "getenv PWD")
				if !tracked && sawChdir {
					sawPostUntrackedPWD = true
				}
				if tracked && (len(stack) != 0 || cwd != pkgDir) {
					sawInExcursionPWD = true
				}
			case 2, 3: // open existing file (with optional duplicates)
				var rel string
				switch cwd {
				case pkgDir:
					rel = "root.txt"
				case subA:
					rel = "a.txt"
				case subB:
					rel = "b.txt"
				default:
					rel = "scratch.txt"
				}
				repeats := rapid.IntRange(1, 4).Draw(rt, "repeats")
				for range repeats {
					lines = append(lines, "open "+rel)
				}
			case 4: // close all open excursions
				for len(stack) > 0 {
					target := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					lines = append(lines, "chdir "+target)
					cwd = target
					sawChdir = true
				}
			}
		}
		payload := []byte(strings.Join(lines, "\n") + "\n")
		opts := []TestLogOption{
			WithCompletedProcess("prop"),
			WithBracket(*frame.bracket),
			func(cfg *testLogConfig) { cfg.trackedChdir = tracked },
		}
		opts = append(opts, producerClassificationOptions(resolved, frame.Root, scratchRoot, nil, nil)...)

		obsChunked, err := fromTestLogStream(context.Background(), bufio.NewReaderSize(bytes.NewReader(payload), bufSize), frame.Root, frame.PkgDir, normalized, opts...)
		if err != nil {
			rt.Fatalf("fromTestLogStream: %v", err)
		}
		obsWide, err := fromTestLogStream(context.Background(), bufio.NewReaderSize(bytes.NewReader(payload), 64*1024), frame.Root, frame.PkgDir, normalized, opts...)
		if err != nil {
			rt.Fatalf("fromTestLogStream wide: %v", err)
		}
		if !reflect.DeepEqual(obsChunked.State, obsWide.State) {
			rt.Fatalf("buffer size changed state: %+v vs %+v", obsChunked.State, obsWide.State)
		}

		balanced := len(stack) == 0 && cwd == pkgDir
		wantWdSeal := (!tracked && sawChdir) || (tracked && !balanced)
		wantPWDSeal := (!tracked && sawPostUntrackedPWD) || (tracked && !balanced && sawInExcursionPWD)

		m, err := decode(obsChunked.Manifest)
		if err != nil {
			rt.Fatalf("decode: %v", err)
		}
		if slices.Contains(m.Unverifiable, "working-directory change") != wantWdSeal {
			rt.Fatalf("tracked=%v balanced=%v sawChdir=%v: wdSeal mismatch in %v\nlog:\n%s",
				tracked, balanced, sawChdir, m.Unverifiable, fmt.Sprintf("%s", payload))
		}
		if slices.Contains(m.Unverifiable, "process-local environment input: PWD") != wantPWDSeal {
			rt.Fatalf("tracked=%v balanced=%v: pwdSeal mismatch in %v\nlog:\n%s",
				tracked, balanced, m.Unverifiable, fmt.Sprintf("%s", payload))
		}
		if tracked && balanced && obsChunked.Unverifiable {
			rt.Fatalf("balanced tracked excursion should be verifiable, got %v\nlog:\n%s", m.Unverifiable, payload)
		}
	})
}

func TestTrackedChdirSymlinkCanonicalizationAndRefusal(t *testing.T) {
	rawRoot := t.TempDir()
	root, err := filepath.EvalSymlinks(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.MkdirAll(filepath.Join(pkgDir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/sym\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "fixture.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Symlinked ScratchRoot (modeling macOS /var/folders -> /private/var/folders):
	// outer excursion logs resolved path, nested excursion logs lexical symlinked path;
	// canonicalization equates both so chdirStack pops cleanly to 0.
	outerScratch := t.TempDir()
	realScratch, err := filepath.EvalSymlinks(outerScratch)
	if err != nil {
		t.Fatal(err)
	}
	realTmp := filepath.Join(realScratch, "real-var")
	if err := os.MkdirAll(realTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	aliasTmp := filepath.Join(realScratch, "alias-var")
	if err := os.Symlink(realTmp, aliasTmp); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	env := gotool.SetEnv(os.Environ(), "PWD", pkgDir)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	receipt, err := frame.Completion("sym-proc", env, "")
	if err != nil {
		t.Fatal(err)
	}
	roots := &Roots{}

	macStyleLog := strings.Join([]string{
		"# test log",
		"chdir " + filepath.Join(realTmp, "TestMac", "001"),
		"getenv PWD",
		"chdir " + filepath.Join(aliasTmp, "TestMac", "001"),
		"chdir " + filepath.Join(aliasTmp, "TestMac", "001"),
		"chdir " + pkgDir,
		"open fixture.txt",
		"",
	}, "\n")
	macLogPath := filepath.Join(t.TempDir(), "mac.testlog")
	if err := os.WriteFile(macLogPath, []byte(macStyleLog), 0o644); err != nil {
		t.Fatal(err)
	}
	macObs, reason, err := frame.ObserveInputs(context.Background(), macLogPath, ProducerIngest{
		Identity:     "sym-proc",
		Env:          env,
		Roots:        roots,
		Completion:   receipt,
		TrackedChdir: frame.PrepareTrackedChdir(true),
		ScratchRoot:  aliasTmp,
	})
	if err != nil || reason != "" || macObs.Unverifiable {
		t.Fatalf("expected symlinked ScratchRoot canonicalization to succeed, got reason=%q err=%v obs=%+v", reason, err, macObs)
	}

	// 1b. Nested symlinked GOTMPDIR inside outer ScratchRoot (r[0] = realScratch,
	// r[1] = realScratch/go-tmp-link -> realGoTmp): canonicalization must continue
	// past r[0] to r[1] rather than aborting on the symlinked GOTMPDIR ancestor.
	realGoTmp := filepath.Join(realScratch, "real-gotmp")
	if err := os.MkdirAll(realGoTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	linkGoTmp := filepath.Join(realScratch, "go-tmp-link")
	if err := os.Symlink(realGoTmp, linkGoTmp); err != nil {
		t.Fatal(err)
	}
	nestedEnv := gotool.SetEnv(env, "GOTMPDIR", linkGoTmp)
	nestedReceipt, err := frame.Completion("sym-nested", nestedEnv, "")
	if err != nil {
		t.Fatal(err)
	}
	nestedGoTmpLog := strings.Join([]string{
		"# test log",
		"chdir " + filepath.Join(realGoTmp, "TestGoTmp", "001"),
		"chdir " + filepath.Join(linkGoTmp, "TestGoTmp", "001"),
		"chdir " + filepath.Join(linkGoTmp, "TestGoTmp", "001"),
		"chdir " + pkgDir,
		"open fixture.txt",
		"",
	}, "\n")
	nestedGoTmpPath := filepath.Join(t.TempDir(), "gotmp.testlog")
	if err := os.WriteFile(nestedGoTmpPath, []byte(nestedGoTmpLog), 0o644); err != nil {
		t.Fatal(err)
	}
	nestedObs, reason, err := frame.ObserveInputs(context.Background(), nestedGoTmpPath, ProducerIngest{
		Identity:     "sym-nested",
		Env:          nestedEnv,
		Roots:        &Roots{},
		Completion:   nestedReceipt,
		TrackedChdir: frame.PrepareTrackedChdir(true),
		ScratchRoot:  realScratch,
	})
	if err != nil || reason != "" || nestedObs.Unverifiable {
		t.Fatalf("expected nested symlinked GOTMPDIR canonicalization to succeed, got reason=%q err=%v obs=%+v", reason, err, nestedObs)
	}

	// 2. Surviving leaf or intermediate symlink target inside module/testdata refuses
	// tracked chdir with runtimeinput.chdir.ambiguous instead of desynchronizing chdirStack.
	if err := os.MkdirAll(filepath.Join(pkgDir, "real_sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkToPkg := filepath.Join(pkgDir, "testdata", "alias")
	if err := os.Symlink(pkgDir, linkToPkg); err != nil {
		t.Fatal(err)
	}
	for _, badTarget := range []string{linkToPkg, filepath.Join(linkToPkg, "real_sub")} {
		spoofLog := strings.Join([]string{
			"# test log",
			"chdir " + pkgDir,
			"chdir " + badTarget,
			"getenv PWD",
			"open fixture.txt",
			"chdir " + pkgDir,
			"chdir " + pkgDir,
			"",
		}, "\n")
		spoofPath := filepath.Join(t.TempDir(), "spoof.testlog")
		if err := os.WriteFile(spoofPath, []byte(spoofLog), 0o644); err != nil {
			t.Fatal(err)
		}
		rec := trace.NewRecorder()
		spoofObs, reason, err := frame.ObserveInputs(trace.WithSink(context.Background(), rec), spoofPath, ProducerIngest{
			Identity:      "sym-proc",
			Env:           env,
			Roots:         roots,
			Completion:    receipt,
			TrackedChdir:  frame.PrepareTrackedChdir(true),
			ExcludedPaths: []string{"pkg/testdata"},
		})
		if err != nil || reason != "" {
			t.Fatalf("ObserveInputs spoof(%s): reason=%q err=%v", badTarget, reason, err)
		}
		if !spoofObs.Unverifiable || len(rec.ByName("runtimeinput.chdir.ambiguous")) == 0 {
			t.Fatalf("expected symlinked chdir target %s to emit runtimeinput.chdir.ambiguous and seal Unverifiable, got obs=%+v events=%+v", badTarget, spoofObs, rec.Events())
		}
	}

	// 3. Vanished non-ephemeral chdir target refuses with runtimeinput.chdir.ambiguous.
	vanishedLog := strings.Join([]string{
		"# test log",
		"chdir " + filepath.Join(pkgDir, "vanished-sub"),
		"chdir " + pkgDir,
		"",
	}, "\n")
	vanishedPath := filepath.Join(t.TempDir(), "vanished.testlog")
	if err := os.WriteFile(vanishedPath, []byte(vanishedLog), 0o644); err != nil {
		t.Fatal(err)
	}
	rec2 := trace.NewRecorder()
	vanishedObs, reason, err := frame.ObserveInputs(trace.WithSink(context.Background(), rec2), vanishedPath, ProducerIngest{
		Identity:     "sym-proc",
		Env:          env,
		Roots:        roots,
		Completion:   receipt,
		TrackedChdir: frame.PrepareTrackedChdir(true),
	})
	if err != nil || reason != "" || !vanishedObs.Unverifiable || len(rec2.ByName("runtimeinput.chdir.ambiguous")) == 0 {
		t.Fatalf("expected vanished non-ephemeral chdir target to seal Unverifiable, got reason=%q err=%v obs=%+v", reason, err, vanishedObs)
	}
}

func TestProducerSetupFailureStillEnforcesOutcomeAndReadPrecedence(t *testing.T) {
	rawRoot := t.TempDir()
	root, err := filepath.EvalSymlinks(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/prec\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := gotool.SetEnv(os.Environ(), "PWD", pkgDir)
	frame := CaptureProducerFrame(context.Background(), root, pkgDir, FrameOptions{})
	binding, err := frame.OutcomeBinding("prec-proc", env)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := frame.Completion("prec-proc", env, "")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "unsupported.testlog")
	if err := os.WriteFile(logPath, []byte("# test log\nopen foo.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ExcludedPaths = [""] fails applyTestLogOptions (Step 10) before
	// reading br: verify ObserveInputs surfaces Step 10 while Observe (requireOutcomes == true)
	// drains br and surfaces Step 6 ahead of Step 10!
	_, step10Reason, err := frame.ObserveInputs(context.Background(), logPath, ProducerIngest{
		Identity:      "prec-proc",
		Env:           env,
		Roots:         &Roots{},
		Completion:    receipt,
		ExcludedPaths: []string{""},
	})
	if err != nil || !strings.HasPrefix(step10Reason, "testlog ingestion failed:") {
		t.Fatalf("ObserveInputs step10Reason = %q, err = %v; want Step 10 ingestion failure", step10Reason, err)
	}
	obs, reason, err := frame.Observe(context.Background(), logPath, ProducerIngest{
		Identity:      "prec-proc",
		Env:           env,
		Roots:         &Roots{},
		Completion:    receipt,
		Outcome:       outcome.Prepare(binding, []string{"sub1"}, ""),
		ExcludedPaths: []string{""},
	})
	if err != nil {
		t.Fatalf("Observe err = %v", err)
	}
	if reason != "operation-outcome support does not cover the captured operations" || !obs.Unverifiable {
		t.Fatalf("reason = %q, want Step 6 unsupported-operation refusal outranking Step 10 setup failure (obs=%+v)", reason, obs)
	}
}
