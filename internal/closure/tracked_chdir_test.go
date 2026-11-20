package closure

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func TestBinaryTrackedChdirSafeMatrixAndCausalTraces(t *testing.T) {
	t.Run("positive_sibling_isolation_and_const_non_pwd_setenv", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/chdirsafe\n\ngo 1.26\n")
		writeFile(t, dir, "lib.go", `package chdirsafe

import (
	"os"
	"text/template"
	"io"
)

type viewData struct {
	Title string
}

func RenderTitle(w io.Writer, title string) error {
	tmpl, err := template.New("t").Parse("{{.Title}}")
	if err != nil {
		return err
	}
	return tmpl.Execute(w, &viewData{Title: title})
}

func ReadEnv() string {
	return os.Getenv("CHDIRSAFE_CFG")
}
`)
		writeFile(t, dir, "lib_test.go", `package chdirsafe

import (
	"bytes"
	"testing"
)

func TestUsesChdir(t *testing.T) {
	t.Chdir(t.TempDir())
}

func TestTemplateSibling(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderTitle(&buf, "hi")
}

func TestSiblingEnvReader(t *testing.T) {
	_ = ReadEnv()
}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		// Tier-1 maximal scan must remain blocked so PackageExecution units still
		// select runtime testlog observation when TestUsesChdir is in the package.
		maxEffects, _, err := h.maximalExternalEffects("example.com/chdirsafe")
		if err != nil {
			t.Fatalf("maximalExternalEffects: %v", err)
		}
		if !hasAnyMaximalBlocker(true, maxEffects) {
			t.Fatalf("expected Tier-1 maximal scan to retain testing.Chdir blocker, got %+v", maxEffects)
		}

		subChdir := Subject{Package: "example.com/chdirsafe", Symbol: "TestUsesChdir"}
		subTmpl := Subject{Package: "example.com/chdirsafe", Symbol: "TestTemplateSibling"}
		subSibling := Subject{Package: "example.com/chdirsafe", Symbol: "TestSiblingEnvReader"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subChdir, subTmpl, subSibling})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[subChdir].TrackedChdirSafe || proofs[subChdir].Observable || !strings.Contains(proofs[subChdir].Reason, "testing.Chdir") {
			t.Fatalf("TestUsesChdir proof = %+v, want TrackedChdirSafe=true Observable=false (testing.Chdir)", proofs[subChdir])
		}
		if !proofs[subTmpl].TrackedChdirSafe {
			t.Fatalf("TestTemplateSibling proof = %+v, want TrackedChdirSafe=true", proofs[subTmpl])
		}
		if !proofs[subSibling].TrackedChdirSafe || !proofs[subSibling].Observable {
			t.Fatalf("TestSiblingEnvReader proof = %+v, want TrackedChdirSafe=true Observable=true", proofs[subSibling])
		}
		if len(rec.ByName("closure.tracked_chdir.reject")) != 0 {
			t.Fatalf("unexpected tracked_chdir rejection trace: %+v", rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("positive_testmain_const_non_pwd_setenv_keeps_tracked_chdir_safe", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/tmainenv\n\ngo 1.26\n")
		writeFile(t, dir, "p_test.go", `package tmainenv
import ("os"; "testing")
func TestMain(m *testing.M) {
	_ = os.Setenv("XDG_CACHE_HOME", "/tmp/isolated")
	_ = os.Unsetenv("GOMEMLIMIT")
	os.Exit(m.Run())
}
func TestChdir(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())
}
func TestSibling(t *testing.T) {}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		sub := Subject{Package: "example.com/tmainenv", Symbol: "TestSibling"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=true with const non-PWD TestMain env setup, got %+v (events=%+v)", proofs[sub], rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("positive_unix_dup_poll_read_and_close_safe", func(t *testing.T) {
		if cachedUnixListPkgOnce() == nil {
			t.Skip("golang.org/x/sys/unix unavailable in test cache")
		}
		h, rec := newTracedFullSyntaxHasherAt(t, "", nil)
		markHasherEligible(h)
		supplyInMemoryPackage(t, h, "example.com/unixsafe", map[string]map[string]string{
			"example.com/unixsafe": {
				"p.go": `package unixsafe
import (
	"os"
	"golang.org/x/sys/unix"
)
func ProbeStdin() {
	fd, err := unix.Dup(int(os.Stdin.Fd()))
	if err != nil {
		return
	}
	defer unix.Close(fd)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	_, _ = unix.Poll(poll, 0)
	var buf [16]byte
	_, _ = unix.Read(fd, buf[:])
}
`,
				"p_test.go": `package unixsafe
import "testing"
func TestDup(t *testing.T) { ProbeStdin() }
func TestChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func TestPure(t *testing.T) {}
`,
			},
		})
		subPure := Subject{Package: "example.com/unixsafe", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subPure})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[subPure].TrackedChdirSafe {
			t.Fatalf("TestPure proof = %+v, want TrackedChdirSafe=true (events=%+v)", proofs[subPure], rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("positive_gomutant_style_tempdir_with_child_symlink_and_cmd_dir", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/gomutstyle\n\ngo 1.26\n")
		writeFile(t, dir, "p_test.go", `package gomutstyle
import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestChildSymlinkUnderTempDir(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "deep", "real")
	_ = os.MkdirAll(real, 0o755)
	_ = os.Symlink(real, filepath.Join(base, "link"))
	t.Chdir(base)
}

func runSubproc() {
	cmd := exec.Command("true")
	cmd.Dir = "."
	_ = cmd
}

func TestSiblingExecWithoutChdir(t *testing.T) {
	runSubproc()
}

func TestCmdAfterSingleTempDirChdir(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "f.go"), []byte("package p\n"), 0o644)
	t.Chdir(root)
	runSubproc()
}

func TestPure(t *testing.T) {}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		sub := Subject{Package: "example.com/gomutstyle", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=true for intact TempDir roots, got %+v (events=%+v)", proofs[sub], rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("positive_cobra_style_root_cmd_after_single_tempdir_chdir", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/cobrastyle\n\ngo 1.26\n")
		writeFile(t, dir, "p_test.go", `package cobrastyle
import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type subcmd struct {
	name string
	run  func()
}

func buildRootCmd() []subcmd {
	return []subcmd{
		{name: "version", run: func() {}},
		{name: "clean", run: func() {
			_ = os.RemoveAll("/tmp/nonexistent-x")
			_ = os.Symlink("a", "/tmp/nonexistent-y")
			_ = exec.Command("true")
		}},
	}
}

func TestVersionSurfaces(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte("bad\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(d)
	t.Setenv("PATH", t.TempDir())
	for _, c := range buildRootCmd() {
		if c.name == "version" {
			c.run()
		}
	}
}

func TestPure(t *testing.T) {}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		sub := Subject{Package: "example.com/cobrastyle", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=true for cobra-style TestVersionSurfaces, got %+v (events=%+v)", proofs[sub], rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("positive_persistent_subdir_chdir_without_tempdir_or_fsmut", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/persistsub\n\ngo 1.26\n")
		writeFile(t, dir, "p_test.go", `package persistsub
import "testing"
func markHelper(tb testing.TB) { tb.Helper() }
func TestSubdir(t *testing.T) {
	markHelper(t)
	t.Chdir("testdata")
}
func TestPure(t *testing.T) {}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		sub := Subject{Package: "example.com/persistsub", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if !proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=true for persistent subdir Chdir, got %+v (events=%+v)", proofs[sub], rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	negativeCases := []struct {
		name       string
		src        string
		wantReason string
	}{
		{
			name: "direct_os_chdir",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) { _ = os.Chdir("/tmp") }
func TestSibling(t *testing.T) { t.Chdir(t.TempDir()) }
func TestPure(t *testing.T) {}
`,
			wantReason: "reaches_os_chdir",
		},
		{
			name: "os_file_chdir",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) {
	f, err := os.Open(".")
	if err == nil { _ = f.Chdir(); _ = f.Close() }
}
func TestPure(t *testing.T) {}
`,
			wantReason: "reaches_os_chdir",
		},
		{
			name: "os_chdir_func_value",
			src: `package neg
import ("os"; "testing")
var sink any
func TestBad(t *testing.T) { sink = os.Chdir }
func TestPure(t *testing.T) {}
`,
			wantReason: "os_dir_or_env_func_value",
		},
		{
			name: "syscall_chdir",
			src: `package neg
import ("syscall"; "testing")
func TestBad(t *testing.T) { _ = syscall.Chdir("/tmp") }
func TestPure(t *testing.T) {}
`,
			wantReason: "reaches_syscall_chdir",
		},
		{
			name: "syscall_raw_sys_chdir_const",
			src: `package neg
import ("syscall"; "testing")
func TestBad(t *testing.T) { _, _, _ = syscall.Syscall(syscall.SYS_CHDIR, 0, 0, 0) }
func TestPure(t *testing.T) {}
`,
			wantReason: "forbidden_or_dynamic_std_syscall",
		},
		{
			name: "syscall_dynamic_trap",
			src: `package neg
import ("syscall"; "testing")
var dynTrap uintptr = 32
func TestBad(t *testing.T) { _, _, _ = syscall.Syscall(dynTrap, 0, 0, 0) }
func TestPure(t *testing.T) {}
`,
			wantReason: "forbidden_or_dynamic_std_syscall",
		},
		{
			name: "testing_setenv_pwd",
			src: `package neg
import "testing"
func TestBad(t *testing.T) { t.Setenv("PWD", "/tmp") }
func TestPure(t *testing.T) {}
`,
			wantReason: "dynamic_or_pwd_testing_setenv",
		},
		{
			name: "testing_tb_setenv_dynamic_key",
			src: `package neg
import "testing"
var dynKey = "FOO"
func helper(tb testing.TB) { tb.Setenv(dynKey, "1") }
func TestBad(t *testing.T) { helper(t) }
func TestPure(t *testing.T) {}
`,
			wantReason: "dynamic_or_pwd_testing_tb_setenv",
		},
		{
			name: "os_setenv_pwd",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) { _ = os.Setenv("PWD", "/tmp") }
func TestPure(t *testing.T) {}
`,
			wantReason: "dynamic_or_pwd_os_env",
		},
		{
			name: "os_clearenv",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) { os.Clearenv() }
func TestPure(t *testing.T) {}
`,
			wantReason: "reaches_os_clearenv",
		},
		{
			name: "startup_init_testing_chdir",
			src: `package neg
import "testing"
func init() { (&testing.T{}).Chdir("/tmp") }
func TestPure(t *testing.T) {}
`,
			wantReason: "startup_testing_chdir",
		},
		{
			name: "testmain_testing_chdir",
			src: `package neg
import ("os"; "testing")
func TestMain(m *testing.M) {
	(&testing.T{}).Chdir("/tmp")
	os.Exit(m.Run())
}
func TestPure(t *testing.T) {}
`,
			wantReason: "testmain_testing_chdir",
		},
		{
			name: "reflective_method_call",
			src: `package neg
import ("os"; "reflect"; "testing")
func TestBad(t *testing.T) {
	f, _ := os.Open(".")
	reflect.ValueOf(f).MethodByName("Chdir").Call(nil)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "reflective_dispatch",
		},
		{
			name: "template_boxes_os_file",
			src: `package neg
import ("io"; "os"; "testing"; "text/template")
func TestBad(t *testing.T) {
	f, _ := os.Open(".")
	tmpl, _ := template.New("x").Parse("{{.Chdir}}")
	_ = tmpl.Execute(io.Discard, f)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "template_exposes_os_file",
		},
		{
			name: "unconfined_unsafe_pointer",
			src: `package neg
import ("testing"; "unsafe")
var g unsafe.Pointer
func TestBad(t *testing.T) {
	x := 1
	g = unsafe.Pointer(&x)
}
func TestSiblingChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func TestPure(t *testing.T) {}
`,
			wantReason: "unconfined_unsafe",
		},
		{
			name: "symlink_in_tempdir_chdir",
			src: `package neg
import ("os"; "path/filepath"; "testing")
func TestBad(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "alias")
	_ = os.Symlink(".", alias)
	t.Chdir(alias)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "removeall_active_tempdir",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	_ = os.RemoveAll(dir)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "cross_subtest_tempdir_handle",
			src: `package neg
import "testing"
func TestBad(t *testing.T) {
	t.Run("sub", func(st *testing.T) {
		t.Chdir(st.TempDir())
	})
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "testmain_once_do_testing_chdir",
			src: `package neg
import ("os"; "sync"; "testing")
func TestMain(m *testing.M) {
	var once sync.Once
	once.Do(func() { (&testing.T{}).Chdir("/tmp") })
	os.Exit(m.Run())
}
func TestPure(t *testing.T) {}
`,
			wantReason: "testmain_testing_chdir",
		},
		{
			name: "custom_chdir_interface_invoke",
			src: `package neg
import "testing"
type customChdirer interface { Chdir(string) }
func invokeCustom(c customChdirer, d string) { c.Chdir(d) }
func TestBad(t *testing.T) { invokeCustom(t, t.TempDir()) }
func TestPure(t *testing.T) {}
`,
			wantReason: "non_tb_chdir_invoke",
		},
		{
			name: "custom_setenv_pwd_invoke",
			src: `package neg
import "testing"
type envSetter interface { Setenv(string, string) }
func setBad(e envSetter) { e.Setenv("PWD", "/tmp") }
func TestBad(t *testing.T) { setBad(t) }
func TestPure(t *testing.T) {}
`,
			wantReason: "dynamic_or_pwd_setenv_invoke",
		},
		{
			name: "syscall_exec",
			src: `package neg
import ("syscall"; "testing")
func TestBad(t *testing.T) { _ = syscall.Exec("/bin/true", nil, nil) }
func TestPure(t *testing.T) {}
`,
			wantReason: "reaches_syscall_chdir",
		},
		{
			name: "filepath_dir_of_join_bypass",
			src: `package neg
import ("os"; "path/filepath"; "testing")
func TestBad(t *testing.T) {
	base := t.TempDir()
	child := filepath.Join(base, "x")
	sameBase := filepath.Dir(child)
	_ = os.RemoveAll(sameBase)
	_ = os.Symlink(".", sameBase)
	t.Chdir(base)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "readdir_temp_scan_bypass",
			src: `package neg
import ("os"; "testing")
func TestBad(t *testing.T) {
	base := t.TempDir()
	entries, _ := os.ReadDir(os.TempDir())
	for _, e := range entries {
		_ = os.RemoveAll(e.Name())
		_ = os.Symlink(".", e.Name())
	}
	t.Chdir(base)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "join_dir_into_exec_args",
			src: `package neg
import ("os/exec"; "path/filepath"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	_ = exec.Command("rm", "-rf", filepath.Dir(filepath.Join(root, "x")))
	t.Chdir(root)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "self_assigned_handle_no_hang",
			src: `package neg
import "testing"
func TestBad(t *testing.T) {
	_ = t.TempDir()
	var tb *testing.T
	_ = func() *testing.T { return tb }
	tb = tb
	tb.Chdir("")
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "self_assigned_dir_no_vacuous_temp",
			src: `package neg
import "testing"
func TestBad(t *testing.T) {
	_ = t.TempDir()
	var d string
	_ = func() string { return d }
	d = d
	t.Chdir(d)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "chdir_target_not_intact_tempdir",
		},
		{
			name: "cross_subtest_artifact_dir",
			src: `package neg
import "testing"
func TestBad(t *testing.T) {
	t.Run("sub", func(st *testing.T) {
		t.Chdir(st.ArtifactDir())
	})
}
func TestPure(t *testing.T) {}
`,
			wantReason: "non_temp_target_with_tempdir_or_artifactdir",
		},
		{
			name: "bound_tempdir_via_sync_oncevalue",
			src: `package neg
import ("sync"; "testing")
func TestBad(t *testing.T) {
	t.Run("sub", func(st *testing.T) {
		get := sync.OnceValue(st.TempDir)
		t.Chdir(get())
	})
}
func TestPure(t *testing.T) {}
`,
			wantReason: "non_temp_target_with_tempdir_or_artifactdir",
		},
		{
			name: "mode2_evil_stringer_in_t_log",
			src: `package neg
import ("os"; "testing")
type evilInt int
func (evilInt) String() string {
	_ = os.RemoveAll("/tmp/nonexistent-x")
	_ = os.Symlink("a", "/tmp/nonexistent-y")
	return "ok"
}
func TestBad(t *testing.T) {
	d := t.TempDir()
	t.Log(evilInt(1))
	t.Chdir(d)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_impure_or_cyclic_prefix",
		},
		{
			name: "mode2_test_called_by_another_test",
			src: `package neg
import ("os"; "testing")
func helperRemove() { _ = os.RemoveAll("/tmp/nonexistent-x") }
func TestTarget(t *testing.T) {
	d := t.TempDir()
	t.Chdir(d)
	helperRemove()
}
func TestCaller(t *testing.T) {
	TestTarget(t)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_fn_called_by_go_code",
		},
		{
			name: "tempdir_written_as_writefile_bytes_with_exec",
			src: `package neg
import ("os"; "os/exec"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile("/tmp/nonexistent-leak", []byte(root), 0o644)
	_ = exec.Command("true")
	t.Chdir(root)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_tempdir_escapes",
		},
		{
			name: "mode2_global_any_stringer_in_t_log",
			src: `package neg
import ("os"; "testing")
type evilInt int
func (evilInt) String() string {
	_ = os.RemoveAll("/tmp/nonexistent-x")
	_ = os.Symlink("a", "/tmp/nonexistent-y")
	return "ok"
}
var globalMsg any = evilInt(1)
func TestBad(t *testing.T) {
	d := t.TempDir()
	t.Log(globalMsg)
	t.Chdir(d)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_impure_or_cyclic_prefix",
		},
		{
			name: "mode1_global_stringer_removeall_in_nested_chdir",
			src: `package neg
import ("os"; "testing")
type evilRemover int
func (evilRemover) String() string {
	_ = os.RemoveAll("/tmp/nonexistent-x")
	return "ok"
}
var globalRemover any = evilRemover(1)
func TestBad(t *testing.T) {
	d := t.TempDir()
	t.Chdir(d)
	t.Log(globalRemover)
	t.Chdir(t.TempDir())
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_multi_chdir_in_cone",
		},
		{
			name: "symlink_tempdir_to_fixed_path_with_exec",
			src: `package neg
import ("os"; "os/exec"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	_ = os.Symlink(root, "/tmp/fixed-leak")
	_ = exec.Command("true")
	t.Chdir(root)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_tempdir_escapes",
		},
		{
			name: "symlink_tempdir_to_dotdot_escape_with_exec",
			src: `package neg
import ("os"; "os/exec"; "path/filepath"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	_ = os.Symlink(root, filepath.Join(root, "..", "fixed-leak"))
	_ = exec.Command("true")
	t.Chdir(root)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_tempdir_escapes",
		},
		{
			name: "two_step_symlink_escape_with_exec",
			src: `package neg
import ("os"; "os/exec"; "path/filepath"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	_ = os.Symlink("/tmp", filepath.Join(root, "escape"))
	_ = os.Symlink(root, filepath.Join(root, "escape", "leaked_root"))
	_ = exec.Command("true")
	t.Chdir(root)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_tempdir_escapes",
		},
		{
			name: "relative_symlink_after_chdir_with_exec",
			src: `package neg
import ("os"; "os/exec"; "testing")
func TestBad(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	_ = os.Symlink("/tmp", "escape")
	_ = exec.Command("true")
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_fn_direct_fsmut",
		},
		{
			name: "getwd_into_exec_with_nested_chdir",
			src: `package neg
import ("os"; "os/exec"; "testing")
func TestBad(t *testing.T) {
	d := t.TempDir()
	t.Chdir(d)
	wd, _ := os.Getwd()
	_ = exec.Command("rm", "-rf", wd)
	t.Chdir(t.TempDir())
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_multi_chdir_in_cone",
		},
		{
			name: "exec_in_prefix_before_chdir",
			src: `package neg
import ("os/exec"; "testing")
func spawnHelper() { _ = exec.Command("true") }
func TestBad(t *testing.T) {
	d := t.TempDir()
	spawnHelper()
	t.Chdir(d)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_impure_or_cyclic_prefix",
		},
		{
			name: "defer_testing_chdir_with_removeall",
			src: `package neg
import ("os"; "testing")
func dropDir() { _ = os.RemoveAll("/tmp/nonexistent-x") }
func TestBad(t *testing.T) {
	d := t.TempDir()
	defer t.Chdir(d)
	dropDir()
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_deferred_or_async_chdir",
		},
		{
			name: "goroutine_testing_chdir",
			src: `package neg
import "testing"
func asyncChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func TestBad(t *testing.T) {
	go asyncChdir(t)
}
func TestPure(t *testing.T) {}
`,
			wantReason: "goroutine_testing_chdir",
		},
		{
			name: "spawn_closure_from_test_root",
			src: `package neg
import "testing"
func asyncChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func spawnFn(f func()) { go func() { f() }() }
func TestBad(t *testing.T) {
	spawnFn(func() { asyncChdir(t) })
}
func TestPure(t *testing.T) {}
`,
			wantReason: "goroutine_testing_chdir",
		},
		{
			name: "waitgroup_go_testing_chdir",
			src: `package neg
import ("sync"; "testing")
func asyncChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func TestBad(t *testing.T) {
	var wg sync.WaitGroup
	wg.Go(func() { asyncChdir(t) })
	wg.Wait()
}
func TestPure(t *testing.T) {}
`,
			wantReason: "goroutine_testing_chdir",
		},
		{
			name: "time_afterfunc_testing_chdir",
			src: `package neg
import ("testing"; "time")
func asyncChdir(t *testing.T) { t.Chdir(t.TempDir()) }
func TestBad(t *testing.T) {
	_ = time.AfterFunc(0, func() { asyncChdir(t) })
}
func TestPure(t *testing.T) {}
`,
			wantReason: "goroutine_testing_chdir",
		},
		{
			name: "benchmark_runparallel_testing_chdir",
			src: `package neg
import "testing"
func asyncBenchChdir(b *testing.B) { b.Chdir(b.TempDir()) }
func BenchmarkBad(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			asyncBenchChdir(b)
		}
	})
}
func TestPure(t *testing.T) {}
`,
			wantReason: "goroutine_testing_chdir",
		},
		{
			name: "mode2_select_in_prefix",
			src: `package neg
import ("os"; "testing")
func dropDir() { _ = os.RemoveAll("/tmp/nonexistent-x") }
func TestBad(t *testing.T) {
	d := t.TempDir()
	select {
	default:
	}
	t.Chdir(d)
	dropDir()
}
func TestPure(t *testing.T) {}
`,
			wantReason: "mode2_impure_or_cyclic_prefix",
		},
	}

	if !isStdRawSyscallFunc("syscall", "Call") {
		t.Fatal("expected syscall.(*Proc/*LazyProc).Call to be classified as raw std syscall")
	}

	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			const pkgPath = "example.com/negcase"
			dir := t.TempDir()
			writeFile(t, dir, "go.mod", "module "+pkgPath+"\n\ngo 1.26\n")
			writeFile(t, dir, "neg_test.go", tc.src)
			h, rec := newTracedInMemoryHasherAt(t, dir, nil)
			sub := Subject{Package: pkgPath, Symbol: "TestPure"}
			proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
			if err != nil {
				t.Fatalf("ComputeObservabilityBatch: %v", err)
			}
			if proofs[sub].TrackedChdirSafe {
				t.Fatalf("expected TrackedChdirSafe=false for %s, got %+v", tc.name, proofs[sub])
			}
			if !hasTraceEventReason(rec, "closure.tracked_chdir.reject", tc.wantReason) {
				t.Fatalf("missing closure.tracked_chdir.reject reason %q in events %+v", tc.wantReason, rec.ByName("closure.tracked_chdir.reject"))
			}
		})
	}

	t.Run("negative_unix_chdir_rejected", func(t *testing.T) {
		if cachedUnixListPkgOnce() == nil {
			t.Skip("golang.org/x/sys/unix unavailable in test cache")
		}
		h, rec := newTracedFullSyntaxHasherAt(t, "", nil)
		markHasherEligible(h)
		supplyInMemoryPackage(t, h, "example.com/unixbad", map[string]map[string]string{
			"example.com/unixbad": {
				"p_test.go": `package unixbad
import (
	"testing"
	"golang.org/x/sys/unix"
)
func TestBad(t *testing.T) { _ = unix.Chdir("/tmp") }
func TestPure(t *testing.T) {}
`,
			},
		})
		sub := Subject{Package: "example.com/unixbad", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=false when unix.Chdir is reachable, got %+v", proofs[sub])
		}
		if !hasTraceEventReason(rec, "closure.tracked_chdir.reject", "forbidden_or_dynamic_asm_syscall") {
			t.Fatalf("missing forbidden_or_dynamic_asm_syscall trace reason in %+v", rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("negative_unaudited_toolchain_rejected", func(t *testing.T) {
		badRoot := testenv.UnauditedTagGOROOT(t, os.Environ())
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir), "go.mod", "module example.com/unaud\n\ngo 1.26\n")
		writeFile(t, filepath.Join(dir), "p_test.go", `package unaud
import "testing"
func TestChdir(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())
}
func TestPure(t *testing.T) {}
`)
		env := gotool.SetEnv(os.Environ(), "GOROOT", badRoot)
		h, rec := newTracedInMemoryHasherAt(t, dir, env, "-tags=badstd")
		sub := Subject{Package: "example.com/unaud", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected TrackedChdirSafe=false under unaudited toolchain, got %+v", proofs[sub])
		}
		if !hasTraceEventReason(rec, "closure.tracked_chdir.reject", "unaudited_toolchain") {
			t.Fatalf("missing unaudited_toolchain trace reason in %+v", rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("negative_carrier_returning_asm_syscall_stub_rejected", func(t *testing.T) {
		var asmSrc string
		switch runtime.GOARCH {
		case "amd64":
			asmSrc = "#include \"textflag.h\"\nTEXT ·RawCall(SB),NOSPLIT,$0-32\n\tJMP syscall·RawSyscall(SB)\n"
		case "arm64":
			asmSrc = "#include \"textflag.h\"\nTEXT ·RawCall(SB),NOSPLIT,$0-32\n\tB syscall·RawSyscall(SB)\n"
		default:
			t.Skip("amd64/arm64 assembly test")
		}
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/asmcarrier\n\ngo 1.26\n")
		writeFile(t, dir, "stub.go", `package asmcarrier
import "syscall"
func RawCall(trap uintptr) (fn func(), r2, err uintptr)
func CallGetpid() { _, _, _ = RawCall(syscall.SYS_GETPID) }
`)
		writeFile(t, dir, "stub_"+runtime.GOARCH+".s", asmSrc)
		writeFile(t, dir, "stub_test.go", `package asmcarrier
import "testing"
func TestAsm(t *testing.T) { CallGetpid() }
func TestPure(t *testing.T) {}
`)
		h, rec := newTracedInMemoryHasherAt(t, dir, nil)
		sub := Subject{Package: "example.com/asmcarrier", Symbol: "TestPure"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{sub})
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		if proofs[sub].TrackedChdirSafe {
			t.Fatalf("expected carrier-returning asm syscall stub to reject TrackedChdirSafe, got %+v", proofs[sub])
		}
		if !hasTraceEventReason(rec, "closure.tracked_chdir.reject", "unverified_bodyless") {
			t.Fatalf("missing unverified_bodyless trace reason in %+v", rec.ByName("closure.tracked_chdir.reject"))
		}
	})

	t.Run("cancelled_unrooted_group_does_not_poison_memo", func(t *testing.T) {
		isolateProofCache(t)
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/unrootcancel\n\ngo 1.26\n")
		writeFile(t, dir, "p_test.go", `package unrootcancel
import "testing"
func TestReal(t *testing.T) { t.Chdir(t.TempDir()) }
`)
		subMissing := Subject{Package: "example.com/unrootcancel", Symbol: "TestDoesNotExist"}
		// Warm program load on an uncancelled Hasher, then cancel before ComputeObservabilityBatch.
		ctx, cancel := context.WithCancel(context.Background())
		h1, err := newAtEnv(ctx, dir, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		markHasherEligible(h1)
		primeHasherFromDir(t, h1, dir)
		t.Cleanup(func() { unprimeHasher(h1) })
		cancel()
		if _, err := h1.ComputeObservabilityBatch([]Subject{subMissing}); err == nil {
			t.Fatal("expected cancelled ComputeObservabilityBatch to fail")
		}

		h2, _ := newTracedInMemoryHasherAt(t, dir, nil)
		proofs, err := h2.ComputeObservabilityBatch([]Subject{subMissing})
		if err != nil {
			t.Fatalf("uncancelled ComputeObservabilityBatch: %v", err)
		}
		if !proofs[subMissing].TrackedChdirSafe {
			t.Fatalf("expected uncancelled unrooted proof to report TrackedChdirSafe=true without poisoned memo, got %+v", proofs[subMissing])
		}
	})

	t.Run("unrooted_group_propagates_list_error", func(t *testing.T) {
		emptyDir := t.TempDir()
		h, err := newAtEnv(context.Background(), emptyDir, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		prog, _, _ := buildInMemorySSA(t, "", "example.com/listfail", map[string]map[string]string{
			"example.com/listfail": {
				"p_test.go": `package listfail
import "testing"
func TestPresent(t *testing.T) {}
`,
			},
		})
		h.progs["example.com/listfail"] = prog
		delete(h.lists, "example.com/listfail")
		if _, err := h.ComputeObservabilityBatch([]Subject{{Package: "example.com/listfail", Symbol: "TestMissing"}}); err == nil {
			t.Fatal("expected ComputeObservabilityBatch on unrooted group to propagate h.list error")
		}
	})
}
