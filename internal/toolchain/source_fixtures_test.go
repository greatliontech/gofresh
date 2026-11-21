package toolchain

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
	"os/exec"
)

type listPkg = gotool.ListedPackage

func TestMain(m *testing.M) {
	trace.Refresh(os.Getenv(trace.EnvTrace), os.Getenv(trace.EnvTraceFile))
	if cache, err := testenv.GoBuildCache(context.Background(), os.Environ()); err == nil && cache != "" {
		_ = os.Setenv("GOCACHE", cache)
	}
	tmp, err := os.MkdirTemp("", "gofresh-toolchain-test-cache-*")
	if err == nil {
		_ = os.Setenv("XDG_CACHE_HOME", tmp)
	}
	tmpRun, err := os.MkdirTemp("", "gofresh-toolchain-tmp-*")
	if err == nil {
		_ = os.Setenv("TMPDIR", tmpRun)
	}
	code := m.Run()
	if tmp != "" {
		_ = os.RemoveAll(tmp)
	}
	if tmpRun != "" {
		_ = os.RemoveAll(tmpRun)
	}
	testenv.CleanupShared()
	os.Exit(code)
}

func resolveAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (Selection, error) {
	return ResolveSelection(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags)
}

var (
	cachedHostSnapshotMu  sync.Mutex
	cachedHostSnapshotVal *gotool.EnvSnapshot
)

func cachedHostSnapshotOnce() (*gotool.EnvSnapshot, error) {
	cachedHostSnapshotMu.Lock()
	defer cachedHostSnapshotMu.Unlock()
	if cachedHostSnapshotVal != nil {
		return cachedHostSnapshotVal, nil
	}
	snap, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), ".", os.Environ())
	if err != nil {
		return nil, err
	}
	cachedHostSnapshotVal = snap
	return snap, nil
}

func snapshotFor(t *testing.T, dir string, env []string) *gotool.EnvSnapshot {
	t.Helper()
	s, err := (gotool.Runner{}).TakeEnvSnapshot(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fmtSprintErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func isolatedToolchainSource(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "go")
	cmd := exec.CommandContext(t.Context(), "cp", "-a", "--reflink=auto", runtime.GOROOT(), root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy: %s %v", out, err)
	}
	t.Setenv("GOROOT", root)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return root
}

// cgoEnabled reports the go command's resolved CGO_ENABLED — the
// setting every listing obeys: without cgo the go command refuses a
// race listing.
func cgoEnabled(t *testing.T) bool {
	t.Helper()
	snapshot, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Value("CGO_ENABLED") == "1"
}

func isolateProofCache(t *testing.T) {
	t.Helper()
	cache, err := testenv.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

func writeFile(t testing.TB, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeTree materialises files under dir (directories created as
// needed; a path ending in "/" is an empty directory).
func writeTree(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func listingEnv(goflags, gowork string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "GOENV" || key == "GOFLAGS" || key == "GOWORK" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GOENV=off", "GOFLAGS="+goflags, "GOWORK="+gowork)
}

func environmentWith(settings ...string) []string {
	base := os.Environ()
	keys := make(map[string]bool, len(settings))
	for _, entry := range settings {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = true
	}
	out := make([]string, 0, len(base)+len(settings))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !keys[key] {
			out = append(out, entry)
		}
	}
	return append(out, settings...)
}

func requireBareAxis(t *testing.T, name, notice, attribution string) {
	t.Helper()
	if !strings.HasPrefix(notice, "toolchain-selection audit: "+attribution+" — ") {
		t.Errorf("%s: attribution %q is not the notice's axis (%q)", name, attribution, notice)
	}
	for _, forbidden := range []string{"admission", "walked against", "never admitted", "listed and readable", "—"} {
		if strings.Contains(attribution, forbidden) {
			t.Errorf("%s: attribution %q carries %q — consequence or remedy text", name, attribution, forbidden)
		}
	}
}

type cancelAfterContext struct {
	context.Context
	remaining int
}

func (c *cancelAfterContext) Err() error {
	if c.remaining <= 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

// Synthetic stdlib fixture sources shared across hermetic and integration
// toolchain-surface verifier tests.
const syntheticInternalTestlogSrc = `package testlog
import "sync/atomic"
type Interface interface {
	Getenv(string)
	Stat(string)
	Open(string)
	Chdir(string)
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
func Chdir(name string) {
	if log := Logger(); log != nil {
		log.Chdir(name)
	}
}
`

const syntheticOSSrc = `package os
import (
	"errors"
	"internal/testlog"
	"io"
	"syscall"
)
var ErrInvalid = errors.New("invalid argument")
var ErrClosed = errors.New("file already closed")
type PathError struct {
	Op   string
	Path string
	Err  error
}
func (e *PathError) Error() string { return e.Op }
type pollFD struct {
	Sysfd int
}
func (fd *pollFD) Read(p []byte) (int, error)  { return 0, io.EOF }
func (fd *pollFD) Write(p []byte) (int, error) { return len(p), nil }
func (fd *pollFD) Fchdir() error               { return nil }
func (fd *pollFD) Close() error                { return nil }
type file struct {
	pfd  pollFD
	name string
}
type File struct {
	*file
}
func newFile(fd int, name string) *File {
	return &File{&file{pfd: pollFD{Sysfd: fd}, name: name}}
}
func Exit(code int) {
	if code == 0 && testlog.PanicOnExit0() {
		panic("os.Exit(0)")
	}
	syscall.Exit(code)
}
func Getenv(key string) string {
	testlog.Getenv(key)
	return ""
}
func LookupEnv(key string) (string, bool) {
	testlog.Getenv(key)
	return "", false
}
func Open(name string) (*File, error) {
	return OpenFile(name, 0, 0)
}
func Create(name string) (*File, error) {
	return OpenFile(name, 1, 0o666)
}
func OpenFile(name string, flag int, perm uint32) (*File, error) {
	testlog.Open(name)
	return openFileNolog(name, flag, perm)
}
func openFileNolog(name string, flag int, perm uint32) (*File, error) {
	r, err := syscall.Open(name, flag, perm)
	if err != nil {
		return nil, &PathError{Op: "open", Path: name, Err: err}
	}
	return newFile(r, name), nil
}
func openDir(name string) (*File, error) {
	testlog.Open(name)
	return &File{&file{name: name}}, nil
}
func statOrZero(f *File) int64 {
	return 0
}
func readFileContents(statSize int64, read func([]byte) (int, error)) ([]byte, error) {
	var buf [1]byte
	_, err := read(buf[:])
	if err == io.EOF {
		return nil, nil
	}
	return nil, err
}
func (f *File) Read(b []byte) (int, error) {
	if err := f.checkValid("read"); err != nil {
		return 0, err
	}
	return f.pfd.Read(b)
}
func ReadFile(name string) ([]byte, error) {
	f, err := Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readFileContents(statOrZero(f), f.Read)
}
func ReadDir(name string) ([]any, error) {
	f, err := openDir(name)
	_ = f
	return nil, err
}
func Stat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Lstat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Getwd() (string, error) {
	dir, err := syscall.Getwd()
	return dir, err
}
func Chdir(dir string) error {
	if e := syscall.Chdir(dir); e != nil {
		testlog.Open(dir)
		return &PathError{Op: "chdir", Path: dir, Err: e}
	}
	if log := testlog.Logger(); log != nil {
		wd, err := Getwd()
		if err == nil {
			log.Chdir(wd)
		}
	}
	return nil
}
func (f *File) checkValid(op string) error {
	if f == nil {
		return ErrInvalid
	}
	return nil
}
func (f *File) wrapErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	return &PathError{Op: op, Path: f.name, Err: err}
}
func (f *File) Write(b []byte) (n int, err error) {
	if err := f.checkValid("write"); err != nil {
		return 0, err
	}
	n, e := f.write(b)
	if n < 0 {
		n = 0
	}
	if n != len(b) {
		err = io.ErrShortWrite
	}
	if e != nil {
		err = f.wrapErr("write", e)
	}
	return n, err
}
func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}
func (f *File) write(b []byte) (n int, err error) {
	n, err = f.pfd.Write(b)
	return n, err
}
func (f *File) Fd() uintptr {
	return f.fd()
}
func (f *File) fd() uintptr {
	if f == nil {
		return ^(uintptr(0))
	}
	return uintptr(f.pfd.Sysfd)
}
func (f *File) Close() error {
	if f == nil {
		return ErrInvalid
	}
	return f.file.close()
}
func (file *file) close() error {
	if file == nil {
		return syscall.EINVAL
	}
	var err error
	if e := file.pfd.Close(); e != nil {
		err = &PathError{Op: "close", Path: file.name, Err: e}
	}
	return err
}
func (f *File) Chdir() error {
	if err := f.checkValid("chdir"); err != nil {
		return err
	}
	if e := f.pfd.Fchdir(); e != nil {
		return f.wrapErr("chdir", e)
	}
	if l := testlog.Logger(); l != nil {
		wd, err := Getwd()
		if err == nil {
			l.Chdir(wd)
		}
	}
	return nil
}
`

const syntheticBufioSrc = `package bufio
import "io"
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
func (b *Writer) Available() int { return len(b.buf) - b.n }
func (b *Writer) Buffered() int  { return b.n }
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

const syntheticTestdepsSrc = `package testdeps
import (
	"bufio"
	"internal/testlog"
	"io"
	"strings"
	"sync"
)
type TestDeps struct{}
type testLog struct {
	mu  sync.Mutex
	w   *bufio.Writer
	set bool
}
func (l *testLog) Getenv(key string) { l.add("getenv", key) }
func (l *testLog) Open(name string)  { l.add("open", name) }
func (l *testLog) Stat(name string)  { l.add("stat", name) }
func (l *testLog) Chdir(name string) { l.add("chdir", name) }
func (l *testLog) add(op, name string) {
	if strings.Contains(name, "\n") || name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w == nil {
		return
	}
	l.w.WriteString(op)
	l.w.WriteByte(' ')
	l.w.WriteString(name)
	l.w.WriteByte('\n')
}
var log testLog
func (TestDeps) StartTestLog(w io.Writer) {
	log.mu.Lock()
	log.w = bufio.NewWriter(w)
	if !log.set {
		log.set = true
		testlog.SetLogger(&log)
		log.w.WriteString("# test log\n")
	}
	log.mu.Unlock()
}
func (TestDeps) StopTestLog() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	err := log.w.Flush()
	log.w = nil
	return err
}
`

const syntheticTestingInlineSrc = `package testing
import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
)
var testlog = flag.String("test.testlogfile", "", "")
type common struct {
	ctx      context.Context
	cleanups []func()
}
func (c *common) checkFuzzFn(string) {}
func (c *common) checkParallel()     {}
func (c *common) Fatal(...any)       {}
func (c *common) Fatalf(string, ...any) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
func (c *common) Cleanup(f func()) {
	c.checkFuzzFn("Cleanup")
	c.cleanups = append(c.cleanups, f)
}
func (c *common) runCleanup() {
	for len(c.cleanups) > 0 {
		last := len(c.cleanups) - 1
		cleanup := c.cleanups[last]
		c.cleanups = c.cleanups[:last]
		cleanup()
	}
}
func (c *common) Setenv(key, value string) {
	c.checkFuzzFn("Setenv")
	prevValue, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		c.Fatalf("setenv: %v", err)
	}
	if ok {
		c.Cleanup(func() { os.Setenv(key, prevValue) })
	} else {
		c.Cleanup(func() { os.Unsetenv(key) })
	}
}
func (c *common) Chdir(dir string) {
	c.checkFuzzFn("Chdir")
	oldwd, err := os.Open(".")
	if err != nil {
		c.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		c.Fatal(err)
	}
	switch runtime.GOOS {
	case "windows", "plan9":
	default:
		if !filepath.IsAbs(dir) {
			dir, err = os.Getwd()
			if err != nil {
				c.Fatal(err)
			}
		}
		c.Setenv("PWD", dir)
	}
	c.Cleanup(func() {
		err := oldwd.Chdir()
		oldwd.Close()
		if err != nil {
			panic(err)
		}
	})
}
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps  testDeps
	tests []InternalTest
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func (t *T) Chdir(dir string) {
	t.checkParallel()
	t.common.Chdir(dir)
}
func MainStart(d testDeps) *M { return &M{deps: d} }
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() int {
	flag.Parse()
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		_ = runTests(m.tests)
		if err := m.deps.StopTestLog(); err != nil {
			panic(err)
		}
		if err := f.Close(); err != nil {
			os.Exit(2)
		}
		return 0
	}
	_ = runTests(m.tests)
	return 0
}
`

const syntheticTestingSplitSrc = `package testing
import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)
var (
	initRan     bool
	testlog     *string
	matchList   *string
	cpuProfile  *string
	testlogFile *os.File
)
func Init() {
	if initRan {
		return
	}
	initRan = true
	testlog = flag.String("test.testlogfile", "", "")
	matchList = flag.String("test.list", "", "")
	cpuProfile = flag.String("test.cpuprofile", "", "")
}
type common struct {
	ctx      context.Context
	cleanups []func()
}
func (c *common) checkFuzzFn(string)    {}
func (c *common) checkParallel()        {}
func (c *common) Fatal(...any)          {}
func (c *common) Fatalf(string, ...any) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
func (c *common) Cleanup(f func()) {
	c.checkFuzzFn("Cleanup")
	c.cleanups = append(c.cleanups, f)
}
func (c *common) runCleanup() {
	for len(c.cleanups) > 0 {
		last := len(c.cleanups) - 1
		cleanup := c.cleanups[last]
		c.cleanups = c.cleanups[:last]
		cleanup()
	}
}
func (c *common) Setenv(key, value string) {
	c.checkFuzzFn("Setenv")
	prevValue, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		c.Fatalf("setenv: %v", err)
	}
	if ok {
		c.Cleanup(func() { os.Setenv(key, prevValue) })
	} else {
		c.Cleanup(func() { os.Unsetenv(key) })
	}
}
func (c *common) Chdir(dir string) {
	c.checkFuzzFn("Chdir")
	oldwd, err := os.Open(".")
	if err != nil {
		c.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		c.Fatal(err)
	}
	switch runtime.GOOS {
	case "windows", "plan9":
	default:
		if !filepath.IsAbs(dir) {
			dir, err = os.Getwd()
			if err != nil {
				c.Fatal(err)
			}
		}
		c.Setenv("PWD", dir)
	}
	c.Cleanup(func() {
		err := oldwd.Chdir()
		oldwd.Close()
		if err != nil {
			panic(err)
		}
	})
}
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps      testDeps
	tests     []InternalTest
	afterOnce sync.Once
	exitCode  int
	numRun    int
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func (t *T) Chdir(dir string) {
	t.checkParallel()
	t.common.Chdir(dir)
}
func MainStart(d testDeps, tests []InternalTest) *M {
	Init()
	return &M{deps: d, tests: tests}
}
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() (code int) {
	defer func() {
		code = m.exitCode
	}()
	m.numRun++
	if !flag.Parsed() {
		flag.Parse()
	}
	if *matchList != "" {
		m.exitCode = 0
		return
	}
	m.before()
	defer m.after()
	m.startAlarm()
	if !runTests(m.tests) {
		m.exitCode = 1
		return
	}
	m.exitCode = 0
	return
}
func (m *M) before() {
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return
		}
		_ = f.Close()
	}
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		testlogFile = f
	}
}
func (m *M) after() {
	m.afterOnce.Do(func() {
		m.writeProfiles()
	})
}
func (m *M) writeProfiles() {
	if *testlog != "" {
		if err := m.deps.StopTestLog(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		if err := testlogFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
	}
	if *cpuProfile != "" {
		coverReport()
	}
}
func coverReport() {
	if _, err := os.Create("cov"); err != nil {
		os.Exit(2)
	}
}
func (m *M) startAlarm() {
	_ = time.AfterFunc(time.Minute, func() {
		m.after()
		panic("test timed out")
	})
}
`

func mustMutateFixture(t *testing.T, src, old, new string) string {
	t.Helper()
	if !strings.Contains(src, old) {
		t.Fatalf("fixture source does not contain %q", old)
	}
	return strings.Replace(src, old, new, 1)
}
