package harnesslog

import (
	"os"
	"testing"
)

func TestReadFileFatal(t *testing.T) {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatalf("empty baseline: %q", data)
	}
}

func TestReadFileLogAndError(t *testing.T) {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		t.Error(err)
	}
	t.Log("read bytes:", len(data))
	t.Logf("read %d bytes", len(data))
	if len(data) == 0 {
		t.Errorf("empty baseline")
	}
}

// executeFailureFixture stays false at runtime; reachability analysis does
// not evaluate it, so the failure methods stay statically reached.
var executeFailureFixture bool

func TestReadFileSkipAndFail(t *testing.T) {
	if _, err := os.ReadFile("baseline.txt"); err != nil {
		t.Skip("no baseline:", err)
	}
	if len("baseline") == 0 {
		t.Skipf("impossible length")
	}
	if executeFailureFixture {
		t.Fail()
		if t.Failed() {
			t.FailNow()
		}
		t.SkipNow()
	}
}

// TestLocalTBFatal reaches the harness failure channel through a
// locally-closed testing.TB value, so the call is an RTA-resolved
// interface dispatch decided by the dynamic-target admission rather
// than a static call.
func TestLocalTBFatal(t *testing.T) {
	var tb testing.TB
	tb = t
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		tb.Fatal(err)
	}
	if len(data) == 0 {
		tb.Fatalf("empty baseline")
	}
}

// TestLogOnly reaches nothing but the harness logging channel: the
// observation proof grants, while the legacy projection must still
// refuse to call it verifiable — an audited harness call is not purity
// evidence.
func TestLogOnly(t *testing.T) {
	t.Log("baseline fixture heartbeat")
}

// TestBoundMethodFatal reaches the harness failure channel through a
// bound method value: the SSA wrapper carries the method object, so the
// admission must classify it exactly as the direct call form.
func TestBoundMethodFatal(t *testing.T) {
	fail := t.Fatal
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		fail(err)
	}
	if len(data) == 0 {
		fail("empty baseline")
	}
}
