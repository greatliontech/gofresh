//go:build linux && !android

package assemblycapture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMutationEventOverflowAndIncompleteRefuse(t *testing.T) {
	for _, mask := range []uint32{unix.IN_Q_OVERFLOW, unix.IN_IGNORED, unix.IN_UNMOUNT} {
		s := testInputs(t, t.Context(), Limits{})
		event := make([]byte, unix.SizeofInotifyEvent)
		binary.NativeEndian.PutUint32(event[4:], mask)
		if err := s.watch.acceptEvents(event); err == nil {
			t.Fatalf("incomplete notification mask %#x accepted", mask)
		}
	}
	s := testInputs(t, t.Context(), Limits{})
	if err := s.watch.acceptEvents([]byte{0}); err == nil {
		t.Fatal("torn event accepted")
	}
	event := make([]byte, unix.SizeofInotifyEvent)
	binary.NativeEndian.PutUint32(event[12:], ^uint32(0))
	if err := s.watch.acceptEvents(event); err == nil {
		t.Fatal("unbounded event name accepted")
	}
	s = testInputs(t, t.Context(), Limits{Events: 1})
	s.watch.entries[1] = &watchInterest{names: map[string]bool{"selected": true}}
	event = make([]byte, unix.SizeofInotifyEvent)
	binary.NativeEndian.PutUint32(event, 1)
	binary.NativeEndian.PutUint32(event[4:], unix.IN_CREATE)
	if err := s.watch.acceptEvents(append(event, event...)); err == nil {
		t.Fatal("unrelated event stream escaped cumulative bound")
	}
}

func TestPreprocessPreservesDirectKernelPathResolution(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "cwd")
	target := filepath.Join(root, "other", "child")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(cwd, "chosen.h"), "#define OP SETNE\n")
	put(t, filepath.Join(root, "other", "chosen.h"), "#define OP SETEQ\n")
	if err := os.Symlink(target, filepath.Join(cwd, "link")); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(cwd, "main.s")
	put(t, source, "#include \"link/../chosen.h\"\nOP AL\n")
	s := testInputs(t, t.Context(), Limits{})
	provider, lookups, err := preprocess(s, Invocation{CWD: cwd}, source)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(providerText(provider), "SETEQ AL") || len(lookups) != 1 || lookups[0].Selected != cwd+"/link/../chosen.h" {
		t.Fatalf("direct lookup was lexically cleaned: %s %+v", providerText(provider), lookups)
	}
	if err = s.validate(); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(root, "other", "chosen.h"), "#define OP SETNE\n")
	put(t, filepath.Join(root, "other", "chosen.h"), "#define OP SETEQ\n")
	if err = s.validate(); err == nil {
		t.Fatal("symlink-resolved target write-and-restore escaped observation")
	}
}

func TestMutationObservationFailsClosed(t *testing.T) {
	for _, kind := range []string{"content-restore", "ancestor-rename", "symlink-replace", "lost-watch", "budget"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "dir", "input.h")
			put(t, path, "#define VALUE 1\n")
			limits := Limits{}
			if kind == "budget" {
				limits.Watches = 1
			}
			s := testInputs(t, t.Context(), limits)
			if kind == "symlink-replace" {
				link := filepath.Join(root, "alias.h")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			_, err := s.read(path)
			if kind == "budget" {
				if err == nil {
					t.Fatal("watch budget exhaustion accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.validate(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "content-restore":
				put(t, path, "#define VALUE 2\n")
				put(t, path, "#define VALUE 1\n")
			case "ancestor-rename":
				if err = os.Rename(filepath.Dir(path), filepath.Join(root, "away")); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(filepath.Join(root, "away"), filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "symlink-replace":
				target, err := os.Readlink(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "lost-watch":
				for wd := range s.watch.entries {
					if _, err := unix.InotifyRmWatch(s.watch.fd, uint32(wd)); err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if err = s.validate(); err == nil {
				t.Fatal("incomplete or moved mutation observation accepted")
			}
		})
	}
}

func TestCompilerImportConfigurationBindsWholeOwnedGraph(t *testing.T) {
	p := Package{ID: "root", Imports: map[string]string{"declared": "declared [root.test]"}}
	a := &capturedAction{inv: Invocation{CWD: "/work"}, parsed: parsedTool{flags: map[string][]string{"importcfg": {"/work/importcfg"}}}, inputs: map[string]fileObservation{"/work/importcfg": {data: []byte("packagefile declared=/work/declared.a\npackagefile implicit=/work/implicit.a\n")}}}
	outputs := map[string]string{"/work/declared.a": "declared [root.test]", "/work/implicit.a": "implicit [root.test]"}
	selected := map[string]Package{"declared [root.test]": {ID: "declared [root.test]", Path: "declared"}, "implicit [root.test]": {ID: "implicit [root.test]", Path: "implicit"}}
	if err := checkImports(a, p, outputs, selected); err != nil {
		t.Fatal(err)
	}
	outputs["/work/implicit.a"] = "foreign"
	if err := checkImports(a, p, outputs, selected); err == nil {
		t.Fatal("unowned implicit build input accepted")
	}
	outputs["/work/implicit.a"] = "declared [root.test]"
	if err := checkImports(a, p, outputs, selected); err == nil {
		t.Fatal("wrong object package namespace accepted")
	}
	outputs["/work/implicit.a"] = "implicit [root.test]"
	outputs["/work/declared.a"] = "declared"
	if err := checkImports(a, p, outputs, selected); err == nil {
		t.Fatal("wrong exact explicit import variant accepted")
	}
}

func TestCompilerRejectsUnownedSourceAndEffectiveOptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	put(t, path, "package p\n")
	inputs := testInputs(t, t.Context(), Limits{})
	o, err := inputs.read(path)
	if err != nil {
		t.Fatal(err)
	}
	p := Package{ID: "p", Path: "p", GoFiles: []string{path}}
	s := &Selection{request: Request{Dir: dir}, goenv: map[string]string{}, packages: map[string]Package{"p": p}, files: map[string]fileObservation{path: o}}
	c := &captureServer{selection: s}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"foreign-source", []string{"-p", "p", "-o", "out.a", filepath.Join(dir, "other.go")}},
		{"extra-source", []string{"-p", "p", "-o", "out.a", path, path}},
		{"package", []string{"-p", "q", "-o", "out.a", path}},
		{"optimization", []string{"-p", "p", "-N", "-o", "out.a", path}},
	} {
		t.Run(test.name, func(t *testing.T) {
			put(t, filepath.Join(dir, "other.go"), "package p\n")
			input := testInputs(t, t.Context(), Limits{})
			inv, parsed, err := parseInvocation(input, Invocation{Tool: "/tools/compile", CWD: dir, Instance: "p", Args: test.args})
			if err != nil {
				t.Fatal(err)
			}
			if err = c.prepare(&capturedAction{inv: inv, parsed: parsed}, input); err == nil {
				t.Fatal("inconsistent source/compiler action accepted")
			}
		})
	}
}
