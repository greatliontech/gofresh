package toolchain

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const validTestingChdirSetenvCleanupSrc = `package testing

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type common struct {
	mu          sync.RWMutex
	cleanups    []func()
	cleanupName string
	hasSub      bool
}

type T struct {
	common
}

type B struct {
	common
}

func (c *common) checkParallel()    {}
func (c *common) checkFuzzFn(string) {}
func (c *common) Fatal(...any)      {}
func (c *common) Fatalf(string, ...any) {}

func (c *common) Cleanup(f func()) {
	fn := func() {
		c.cleanupName = "cleanup"
		defer func() {
			c.cleanupName = ""
		}()
		f()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanups = append(c.cleanups, fn)
}

func (c *common) runCleanup(ph int) (panicVal any) {
	for {
		var cleanup func()
		c.mu.Lock()
		if len(c.cleanups) > 0 {
			last := len(c.cleanups) - 1
			cleanup = c.cleanups[last]
			c.cleanups = c.cleanups[:last]
		}
		c.mu.Unlock()
		if cleanup == nil {
			return nil
		}
		cleanup()
	}
}

func (c *common) Setenv(key, value string) {
	c.checkFuzzFn("Setenv")
	prevValue, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		c.Fatalf("cannot set environment variable: %v", err)
	}
	if ok {
		c.Cleanup(func() {
			os.Setenv(key, prevValue)
		})
	} else {
		c.Cleanup(func() {
			os.Unsetenv(key)
		})
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
			panic("testing.Chdir: " + err.Error())
		}
	})
}

func (t *T) Setenv(key, value string) {
	t.checkParallel()
	t.common.Setenv(key, value)
}

func (t *T) Chdir(dir string) {
	t.checkParallel()
	t.common.Chdir(dir)
}
`

func TestVerifyTestingChdirAndOSFileChdirMatrix(t *testing.T) {
	if err := verifyTestingChdirAST(mustParseTestFiles(t, validTestingChdirSetenvCleanupSrc)); err != nil {
		t.Fatalf("verifyTestingChdirAST(valid): %v", err)
	}

	testingRejects := []struct {
		name string
		src  string
	}{
		{"missing_check_parallel_in_t_chdir", strings.Replace(validTestingChdirSetenvCleanupSrc, "func (t *T) Chdir(dir string) {\n\tt.checkParallel()\n", "func (t *T) Chdir(dir string) {\n", 1)},
		{"missing_check_parallel_in_t_setenv", strings.Replace(validTestingChdirSetenvCleanupSrc, "func (t *T) Setenv(key, value string) {\n\tt.checkParallel()\n", "func (t *T) Setenv(key, value string) {\n", 1)},
		{"fifo_cleanup_pop_rejected", strings.Replace(validTestingChdirSetenvCleanupSrc, "last := len(c.cleanups) - 1\n\t\t\tcleanup = c.cleanups[last]\n\t\t\tc.cleanups = c.cleanups[:last]", "cleanup = c.cleanups[0]\n\t\t\tc.cleanups = c.cleanups[1:]", 1)},
		{"missing_panic_on_restore_error", strings.Replace(validTestingChdirSetenvCleanupSrc, `panic("testing.Chdir: " + err.Error())`, `return`, 1)},
		{"missing_pwd_setenv", strings.Replace(validTestingChdirSetenvCleanupSrc, "\t\tc.Setenv(\"PWD\", dir)\n", "", 1)},
		{"t_chdir_skips_common_delegate", strings.Replace(validTestingChdirSetenvCleanupSrc, "t.common.Chdir(dir)", "_ = os.Chdir(dir)", 1)},
		{"cleanup_early_return_before_append", strings.Replace(validTestingChdirSetenvCleanupSrc, "c.mu.Lock()\n\tdefer c.mu.Unlock()\n\tc.cleanups = append(c.cleanups, fn)", "if c.hasSub { return }\n\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\tc.cleanups = append(c.cleanups, fn)", 1)},
		{"cleanup_wrapper_conditional_skip", strings.Replace(validTestingChdirSetenvCleanupSrc, "\t\tf()\n", "\t\tif c.hasSub { return }\n\t\tf()\n", 1)},
		{"run_cleanup_missing_drain_loop", strings.Replace(validTestingChdirSetenvCleanupSrc, "\tfor {\n", "\t{\n", 1)},
		{"run_cleanup_dead_branch_pop", strings.Replace(validTestingChdirSetenvCleanupSrc, "\tfor {\n", "\tif c.hasSub { return nil }\n\tfor {\n", 1)},
		{"cleanups_slice_cleared_elsewhere", validTestingChdirSetenvCleanupSrc + "\nfunc (c *common) wipe() { c.cleanups = nil }\n"},
		{"cleanups_slice_addr_taken", validTestingChdirSetenvCleanupSrc + "\nfunc (c *common) addr() *[]func() { return &c.cleanups }\n"},
		{"run_cleanup_overwrites_popped_var", strings.Replace(validTestingChdirSetenvCleanupSrc, "\t\tif cleanup == nil {", "\t\tcleanup = nil\n\t\tif cleanup == nil {", 1)},
		{"run_cleanup_closure_overwrites_popped_var", strings.Replace(validTestingChdirSetenvCleanupSrc, "\t\tif cleanup == nil {", "\t\tfunc() { cleanup = nil }()\n\t\tif cleanup == nil {", 1)},
		{"cond_loop_incdec_last_var", strings.Replace(validTestingChdirSetenvCleanupSrc, "func (c *common) runCleanup(ph int) (panicVal any) {\n\tfor {\n\t\tvar cleanup func()\n\t\tc.mu.Lock()\n\t\tif len(c.cleanups) > 0 {\n\t\t\tlast := len(c.cleanups) - 1\n\t\t\tcleanup = c.cleanups[last]\n\t\t\tc.cleanups = c.cleanups[:last]\n\t\t}\n\t\tc.mu.Unlock()\n\t\tif cleanup == nil {\n\t\t\treturn nil\n\t\t}\n\t\tcleanup()\n\t}", "func (c *common) runCleanup() {\n\tfor len(c.cleanups) > 0 {\n\t\tlast := len(c.cleanups) - 1\n\t\tlast--\n\t\tcleanup := c.cleanups[last]\n\t\tc.cleanups = c.cleanups[:last]\n\t\tcleanup()\n\t}", 1)},
		{"cleanups_slice_copied_elsewhere", validTestingChdirSetenvCleanupSrc + "\nfunc (c *common) clobber() { copy(c.cleanups, make([]func(), len(c.cleanups))) }\n"},
		{"cleanups_slice_aliased_elsewhere", validTestingChdirSetenvCleanupSrc + "\nfunc (c *common) alias() { s := c.cleanups; if len(s) > 0 { s[0] = nil } }\n"},
	}
	for _, tc := range testingRejects {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyTestingChdirAST(mustParseTestFiles(t, tc.src)); err == nil {
				t.Fatalf("expected verifyTestingChdirAST to reject %s", tc.name)
			}
		})
	}

	posixFileChdir := `package os

import "internal/testlog"

func (f *File) Chdir() error {
	if err := f.checkValid("chdir"); err != nil {
		return err
	}
	if e := f.pfd.Fchdir(); e != nil {
		return f.wrapErr("chdir", e)
	}
	if log := testlog.Logger(); log != nil {
		wd, err := Getwd()
		if err == nil {
			log.Chdir(wd)
		}
	}
	return nil
}
`
	plan9FileChdir := `package os

import (
	"internal/testlog"
	"syscall"
)

func (f *File) incref(op string) error {
	if f == nil {
		return ErrInvalid
	}
	return nil
}

func (f *File) Chdir() error {
	if err := f.incref("chdir"); err != nil {
		return err
	}
	defer f.decref()
	if e := syscall.Fchdir(f.sysfd); e != nil {
		return &PathError{Op: "chdir", Path: f.name, Err: e}
	}
	if log := testlog.Logger(); log != nil {
		wd, err := Getwd()
		if err == nil {
			log.Chdir(wd)
		}
	}
	return nil
}
`
	osReserved := map[string]bool{"nil": true, "error": true, "testlog": true, "syscall": true}
	noopSkip := func(ast.Stmt, *ast.FuncDecl) bool { return false }

	for _, validSrc := range []string{posixFileChdir, plan9FileChdir} {
		files := mustParseTestFiles(t, validSrc)
		idx, err := indexPackageAST("os", files, nil, map[string]bool{"internal/testlog": true, "syscall": true})
		if err != nil {
			t.Fatal(err)
		}
		fn := idx.typeMethods["File"]["Chdir"]
		if err := verifyOSFileChdir(fn, idx.typeMethods["File"]["incref"], idx.funcFile, idx.fileImportSet("internal/testlog"), idx.fileImportSet("syscall"), osReserved, noopSkip); err != nil {
			t.Fatalf("verifyOSFileChdir(valid): %v", err)
		}
	}

	// Mutating POSIX (*File).Chdir to omit log.Chdir(wd) must fail.
	noLog := strings.Replace(posixFileChdir, "\tif log := testlog.Logger(); log != nil {\n\t\twd, err := Getwd()\n\t\tif err == nil {\n\t\t\tlog.Chdir(wd)\n\t\t}\n\t}\n", "", 1)
	noLogFiles := mustParseTestFiles(t, noLog)
	noLogIdx, _ := indexPackageAST("os", noLogFiles, nil, map[string]bool{"internal/testlog": true, "syscall": true})
	if err := verifyOSFileChdir(noLogIdx.typeMethods["File"]["Chdir"], nil, noLogIdx.funcFile, noLogIdx.fileImportSet("internal/testlog"), noLogIdx.fileImportSet("syscall"), osReserved, noopSkip); err == nil {
		t.Fatal("expected POSIX (*File).Chdir without testlog.Logger().Chdir(wd) to be rejected")
	}
}

func TestLiveGodstOSAndRuntimeASTVerifiers(t *testing.T) {
	goBin := "/home/nikolas/.local/godst/go1.27.4-dst.17/go/bin/go"
	if _, err := os.Stat(goBin); err != nil {
		t.Skip("godst dst.17 not installed locally")
	}
	for _, tc := range []struct {
		goos string
		tags string
	}{
		{"linux", ""},
		{"linux", "-tags=dst"},
		{"windows", ""},
		{"windows", "-tags=dst"},
	} {
		t.Run(tc.goos+"_"+tc.tags, func(t *testing.T) {
			args := []string{"list"}
			if tc.tags != "" {
				args = append(args, tc.tags)
			}
			args = append(args, "-f", "{{.Dir}}\n{{range .GoFiles}}{{.}}\n{{end}}", "os")
			cmd := exec.Command(goBin, args...)
			cmd.Env = append(os.Environ(), "GOOS="+tc.goos, "GOARCH=amd64", "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list os: %v\n%s", err, out)
			}
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			dir := lines[0]
			fset := token.NewFileSet()
			var files []*ast.File
			pullMap := map[string]string{}
			anyLink := map[string]bool{}
			for _, name := range lines[1:] {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				src := string(raw)
				if err := verifyHarnessFileDirectives("os", src, nil, nil, pullMap, anyLink); err != nil {
					t.Fatalf("verifyHarnessFileDirectives(%s): %v", name, err)
				}
				f, err := parser.ParseFile(fset, name, raw, 0)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, f)
			}
			if err := VerifyOSPackageASTAndLog(t, files, pullMap, anyLink); err != nil {
				t.Fatalf("verifyOSPackageAST: %v", err)
			}
		})
	}
}

func VerifyOSPackageASTAndLog(t *testing.T, files []*ast.File, pullMap map[string]string, anyLink map[string]bool) error {
	t.Helper()
	_, err := verifyOSPackageAST(files, pullMap, anyLink)
	return err
}
