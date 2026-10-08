package runtimeinput

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
	path := filepath.Join(t.TempDir(), "capture.log")
	cmd := exec.Command(os.Args[0], "-test.run=^TestIncompleteCaptureSkipsAmbientRootLookupWhenCancelled$", "-test.testlogfile="+path)
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
