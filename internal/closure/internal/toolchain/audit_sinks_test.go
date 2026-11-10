package toolchain

import (
	"strings"
	"testing"
)

const validInternalTestlogSrc = `package testlog

import "sync/atomic"

type Interface interface {
	Getenv(key string)
	Stat(file string)
	Open(file string)
	Chdir(dir string)
}

var logger atomic.Pointer[Interface]

func SetLogger(impl Interface) {
	if !logger.CompareAndSwap(nil, &impl) {
		panic("testlog: SetLogger must be called only once")
	}
}

func Logger() Interface {
	impl := logger.Load()
	if impl == nil {
		return nil
	}
	return *impl
}

func Getenv(name string) {
	if log := Logger(); log != nil {
		log.Getenv(name)
	}
}

func Open(name string) {
	if log := Logger(); log != nil {
		log.Open(name)
	}
}

func Stat(name string) {
	if log := Logger(); log != nil {
		log.Stat(name)
	}
}
`

func TestVerifyInternalTestlogAndTestdepsAST(t *testing.T) {
	files := mustParseTestFiles(t, validInternalTestlogSrc)
	if err := VerifyInternalTestlogPackageAST(files); err != nil {
		t.Fatalf("VerifyInternalTestlogPackageAST(valid): %v", err)
	}

	// Mutate Getenv to call log.Stat instead of log.Getenv: must fail.
	badGetenv := strings.Replace(validInternalTestlogSrc, "log.Getenv(name)", "log.Stat(name)", 1)
	if err := VerifyInternalTestlogPackageAST(mustParseTestFiles(t, badGetenv)); err == nil {
		t.Fatal("expected mutated Getenv dispatcher to be rejected")
	}

	// Mutate SetLogger to drop panic on duplicate registration: must fail.
	badSetLogger := strings.Replace(validInternalTestlogSrc, `panic("testlog: SetLogger must be called only once")`, `return`, 1)
	if err := VerifyInternalTestlogPackageAST(mustParseTestFiles(t, badSetLogger)); err == nil {
		t.Fatal("expected SetLogger without panic to be rejected")
	}

	// VerifyTestdepsPackageAST rejects init() and missing internal/testlog import.
	badTestdeps := mustParseTestFiles(t, `package testdeps

func init() {}
`)
	if err := VerifyTestdepsPackageAST(badTestdeps); err == nil {
		t.Fatal("expected testdeps with init() to be rejected")
	}
}

const validBufioWriterSrc = `package bufio

import (
	"io"
	"unicode/utf8"
)

const defaultBufSize = 4096

type Writer struct {
	err error
	buf []byte
	n   int
	wr  io.Writer
}

func NewWriterSize(w io.Writer, size int) *Writer {
	b, ok := w.(*Writer)
	if ok && len(b.buf) >= size {
		return b
	}
	if size <= 0 {
		size = defaultBufSize
	}
	return &Writer{
		buf: make([]byte, size),
		wr:  w,
	}
}

func NewWriter(w io.Writer) *Writer {
	return NewWriterSize(w, defaultBufSize)
}

func (b *Writer) Flush() error {
	if b.err != nil {
		return b.err
	}
	if b.n == 0 {
		return nil
	}
	n, err := b.wr.Write(b.buf[0:b.n])
	if n < b.n && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 && n < b.n {
			copy(b.buf[0:b.n-n], b.buf[n:b.n])
		}
		b.n -= n
		b.err = err
		return err
	}
	b.n = 0
	return nil
}

func (b *Writer) Available() int { return len(b.buf) - b.n }

func (b *Writer) AvailableBuffer() []byte {
	return b.buf[b.n:][:0]
}

func (b *Writer) Buffered() int { return b.n }

func (b *Writer) Write(p []byte) (nn int, err error) {
	for len(p) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 {
			n, b.err = b.wr.Write(p)
		} else {
			n = copy(b.buf[b.n:], p)
			b.n += n
			b.Flush()
		}
		nn += n
		p = p[n:]
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], p)
	b.n += n
	nn += n
	return nn, nil
}

func (b *Writer) WriteByte(c byte) error {
	if b.err != nil {
		return b.err
	}
	if b.Available() <= 0 && b.Flush() != nil {
		return b.err
	}
	b.buf[b.n] = c
	b.n++
	return nil
}

func (b *Writer) WriteRune(r rune) (size int, err error) {
	if uint32(r) < utf8.RuneSelf {
		err = b.WriteByte(byte(r))
		if err != nil {
			return 0, err
		}
		return 1, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	n := b.Available()
	if n < utf8.UTFMax {
		if b.Flush(); b.err != nil {
			return 0, b.err
		}
		n = b.Available()
		if n < utf8.UTFMax {
			return b.WriteString(string(r))
		}
	}
	size = utf8.EncodeRune(b.buf[b.n:], r)
	b.n += size
	return size, nil
}

func (b *Writer) WriteString(s string) (int, error) {
	var sw io.StringWriter
	tryStringWriter := true
	nn := 0
	for len(s) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 && sw == nil && tryStringWriter {
			sw, tryStringWriter = b.wr.(io.StringWriter)
		}
		if b.Buffered() == 0 && tryStringWriter {
			n, b.err = sw.WriteString(s)
		} else {
			n = copy(b.buf[b.n:], s)
			b.n += n
			b.Flush()
		}
		nn += n
		s = s[n:]
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], s)
	b.n += n
	nn += n
	return nn, nil
}
`

func TestVerifyBufioWriterAST(t *testing.T) {
	files := mustParseTestFiles(t, validBufioWriterSrc)
	if err := VerifyBufioWriterAST(files); err != nil {
		t.Fatalf("VerifyBufioWriterAST(valid): %v", err)
	}

	// Mutate Flush to drop sticky b.err = err assignment: must fail.
	badFlush := strings.Replace(validBufioWriterSrc, "b.err = err", "", 1)
	if err := VerifyBufioWriterAST(mustParseTestFiles(t, badFlush)); err == nil {
		t.Fatal("expected Flush dropping sticky b.err = err to be rejected")
	}

	// Mutate WriteByte to drop sticky error guard: must fail.
	badWriteByte := strings.Replace(validBufioWriterSrc, "func (b *Writer) WriteByte(c byte) error {\n\tif b.err != nil {\n\t\treturn b.err\n\t}\n", "func (b *Writer) WriteByte(c byte) error {\n", 1)
	if err := VerifyBufioWriterAST(mustParseTestFiles(t, badWriteByte)); err == nil {
		t.Fatal("expected WriteByte without sticky error guard to be rejected")
	}
}
