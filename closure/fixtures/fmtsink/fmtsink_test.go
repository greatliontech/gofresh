package fmtsink

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestFprintfBuffer(t *testing.T) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "value %d", 1)
	if b.Len() == 0 {
		t.Fatal("empty")
	}
}

func TestFprintlnBuilder(t *testing.T) {
	var b strings.Builder
	fmt.Fprintln(&b, "value")
	if b.Len() == 0 {
		t.Fatal("empty")
	}
}

func TestFprintfHelperBuffer(t *testing.T) {
	var b bytes.Buffer
	formatInto(&b, 1)
	if b.Len() == 0 {
		t.Fatal("empty")
	}
}

func TestFprintfPhiBuffers(t *testing.T) {
	var a, b bytes.Buffer
	w := io.Writer(&a)
	if len(strings.Repeat("a", 2)) > 1 {
		w = &b
	}
	fmt.Fprintf(w, "value %d", 1)
}

func TestFprintfCallResult(t *testing.T) {
	fmt.Fprintf(newWriter(), "value %d", 1)
}

func TestFprintfPhiCallEscape(t *testing.T) {
	var a bytes.Buffer
	w := io.Writer(&a)
	if len(strings.Repeat("a", 2)) > 1 {
		w = newWriter()
	}
	fmt.Fprintf(w, "value %d", 1)
}

func TestFprintfHelperMixed(t *testing.T) {
	var b bytes.Buffer
	formatMixed(&b, 1)
	formatMixed(newWriter(), 2)
}

func formatInto(w io.Writer, n int) {
	fmt.Fprintf(w, "value %d", n)
}

func formatMixed(w io.Writer, n int) {
	fmt.Fprintf(w, "mixed %d", n)
}

func newWriter() io.Writer {
	return &bytes.Buffer{}
}

// shared and cfg pin the concrete-expression arm: a *bytes.Buffer
// expression pins the sink type regardless of which instance it
// denotes — global and field-loaded buffers admit exactly as a direct
// Write on the audited type would.
var shared bytes.Buffer

type holder struct{ Buf *bytes.Buffer }

var cfg = holder{Buf: &bytes.Buffer{}}

func TestFprintfGlobalBuffer(t *testing.T) {
	fmt.Fprintf(&shared, "value %d", 1)
	if shared.Len() == 0 {
		t.Fatal("empty")
	}
}

func TestFprintfFieldBuffer(t *testing.T) {
	fmt.Fprintf(cfg.Buf, "value %d", 1)
	if cfg.Buf.Len() == 0 {
		t.Fatal("empty")
	}
}

// nullWriter is in-memory in fact but outside the audited sink pair —
// the admission is a bounded audit, not an inference.
type nullWriter struct{}

func (*nullWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestFprintfLocalWriterType(t *testing.T) {
	fmt.Fprintf(&nullWriter{}, "value %d", 1)
}
