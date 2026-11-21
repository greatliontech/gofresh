package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func TestToolchainMemoRejectsIncompleteInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("reads and corrupts a private standard-library memo")
	}
	if !stampsTrusted {
		t.Skip("this platform never serves the listing memo")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/surface\n\ngo 1.27\n"})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	flags := []string{"-tags=dup"}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, flags)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	original := read()
	stringsMemoKey := verifiedPackageMemoKey("strings", original.Packages["strings"])
	withToolchainTestHooks(toolchainTestHookSet{
		packageVerdictOverride: func(memoKey string) (verifiedPackageVerdict, bool) {
			if memoKey == stringsMemoKey {
				return verifiedPackageVerdict{OK: false}, true
			}
			return verifiedPackageVerdict{}, false
		},
	}, func() {
		if toolchainSourceDegradation(snapshot.Value("GOVERSION"), original, nil).audited() {
			t.Fatal("unverified strings control unexpectedly admitted")
		}
		if again := read(); listings != 1 || !reflect.DeepEqual(again, original) {
			t.Fatal("valid unchanged memo did not serve")
		}
		scope := toolchainSourceScope(snapshot, flags, surfaceSeeds())
		path, err := cachefile.Path(sourceDigestsDirName, scope, "listing")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for name, corrupt := range map[string]func(*surfaceListing){
			"empty":              func(l *surfaceListing) { l.Packages = nil },
			"missing package":    func(l *surfaceListing) { l.Packages = l.Packages[1:] },
			"missing files":      func(l *surfaceListing) { l.Packages[0].Files = nil },
			"missing stamps":     func(l *surfaceListing) { l.Discovery[0].Entries = nil },
			"missing discovery":  func(l *surfaceListing) { l.Discovery = nil },
			"missing commitment": func(l *surfaceListing) { l.Integrity = "" },
			"admission label":    func(l *surfaceListing) { l.Packages[0].Audited = !l.Packages[0].Audited },
		} {
			t.Run(name, func(t *testing.T) {
				var envelope cachefile.Envelope
				if err := json.Unmarshal(data, &envelope); err != nil {
					t.Fatal(err)
				}
				var listing surfaceListing
				if err := json.Unmarshal(envelope.Payload, &listing); err != nil {
					t.Fatal(err)
				}
				corrupt(&listing)
				envelope.Payload, err = json.Marshal(listing)
				if err != nil {
					t.Fatal(err)
				}
				broken, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, broken, 0o600); err != nil {
					t.Fatal(err)
				}
				before := listings
				got := read()
				if listings != before+1 || !reflect.DeepEqual(got, original) || toolchainSourceDegradation(snapshot.Value("GOVERSION"), got, nil).audited() {
					t.Fatal("incomplete inventory served or changed admission")
				}
			})
		}
	})
}

// TestDigestTraversalEndsAtTheNextFileBoundary pins the digest
// traversal's check point (REQ-closure-observability-toolchain-key: the
// digests are read on every construction and the traversal checks its
// context before every file read): a context cancelled while the
// audited surface is being digested ends the traversal at the next file
// boundary — the file the cancellation lands on is the last one read
// and the construction answers the cancellation — and the listing
// record the memo stored before the digests were read, the completed
// listing's own, stands under the live seeds' scope.
func TestDigestTraversalEndsAtTheNextFileBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const stopAt = 3
	reads := 0
	var err error
	withToolchainTestHooks(toolchainTestHookSet{
		digestRead: func(name string) {
			reads++
			if reads == stopAt {
				cancel()
			}
		},
	}, func() {
		_, err = resolveAtEnv(ctx, ".", environmentWith())
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a construction cancelled mid-digest answered %v, want the cancellation", err)
	}
	if reads != stopAt {
		t.Fatalf("the traversal read %d files with the cancellation at read %d, want exactly that many: the next boundary ends it", reads, stopAt)
	}
	snapshot, err := gotool.NewEnvReader(gotool.Runner{}, ".", os.Environ()).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the completed listing's record does not stand after the cancelled digest traversal: %v", err)
	}
}

func TestFinalDigestReadCannotCompleteACancelledConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("counts the selected standard-library reads")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	env := environmentWith()
	reads := 0
	withToolchainTestHooks(toolchainTestHookSet{
		digestRead: func(string) { reads++ },
	}, func() {
		if _, err := resolveAtEnv(t.Context(), ".", env); err != nil {
			t.Fatal(err)
		}
	})
	last := reads
	if last == 0 {
		t.Fatal("no selected file was read")
	}
	for _, notice := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		reads = 0
		var err error
		withToolchainTestHooks(toolchainTestHookSet{
			digestRead: func(string) {
				reads++
				if reads == last {
					cancel()
				}
			},
		}, func() {
			if notice {
				_, _, _, err = ResolveToolchainSelection(ctx, gotool.NewEnvReader(gotool.Runner{}, ".", env), nil)
			} else {
				_, err = resolveAtEnv(ctx, ".", env)
			}
		})
		cancel()
		if reads != last || !errors.Is(err, context.Canceled) {
			t.Fatalf("notice=%t final-read cancellation: reads=%d/%d error=%v", notice, reads, last, err)
		}
	}
}

// TestDstSelectionIsJudgedByContentNeverByTag pins structural content
// verification over `-tags dst` without any fork-specific or tag-specific
// hardcoding (REQ-closure-observability-toolchain-key): on both stock and
// custom dst-capable toolchains the running selection passes structural
// verification unconditionally, and injecting an unapproved dst-tagged file into
// an overlaid GOROOT refuses `-tags dst` while leaving the plain selection
// admitted.
func TestDstSelectionIsJudgedByContentNeverByTag(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	base, err := resolveAtEnv(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	if !base.Audited() {
		t.Fatalf("the running toolchain failed structural verification under its default selection: %s", base.Notice())
	}
	cgo := cgoEnabled(t)
	for _, sel := range []struct {
		suffix string
		flags  []string
		cgo    bool
	}{
		{" dst", []string{"-tags", "dst"}, false},
		{" dst race", []string{"-tags", "dst", "-race"}, true},
	} {
		if sel.cgo && !cgo {
			continue
		}
		h, err := resolveAtEnv(ctx, ".", environmentWith(), sel.flags...)
		if err != nil {
			t.Fatal(err)
		}
		if !h.Audited() {
			t.Fatalf("the %q selection on the running toolchain refused: %s", sel.suffix, h.Notice())
		}
	}

	snap, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	goroot := snap.Value("GOROOT")
	origGetwd, err := os.ReadFile(filepath.Join(goroot, "src/os/getwd.go"))
	if err != nil {
		t.Fatal(err)
	}
	origFilePosix, err := os.ReadFile(filepath.Join(goroot, "src/os/file_posix.go"))
	if err != nil {
		t.Fatal(err)
	}
	hookedGetwd := strings.Replace(
		string(origGetwd),
		"func Getwd() (dir string, err error) {\n",
		"func Getwd() (dir string, err error) {\n\tif gofreshSimOverlay {\n\t\tif wd, handled, werr := gofreshTryGetwd(); handled {\n\t\t\treturn wd, werr\n\t\t}\n\t}\n",
		1,
	)
	hookedFilePosix := strings.Replace(
		string(origFilePosix),
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n",
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n\tif gofreshSimOverlay {\n\t\tif s := gofreshStateOf(f.file); s != nil {\n\t\t\treturn nil\n\t\t}\n\t}\n",
		1,
	)
	if hookedGetwd == string(origGetwd) || hookedFilePosix == string(origFilePosix) {
		t.Fatal("failed to locate hook insertion anchors in GOROOT src/os")
	}

	const simRuntimeClean = `//go:build simoverlay

package runtime

import "internal/runtime/atomic"

var gofreshSimFlag atomic.Uint32

func gofreshSimEnable() {
	gofreshSimFlag.Store(1)
}

func gofreshSimGate() bool {
	return gofreshSimFlag.Load() != 0
}
`
	const simOSOff = `//go:build !simoverlay

package os

const gofreshSimOverlay = false

func gofreshTryGetwd() (string, bool, error) { return "", false, nil }
func gofreshStateOf(_ *file) *int            { return nil }
`
	const simOSOn = `//go:build simoverlay

package os

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

const gofreshSimOverlay = true

//go:linkname gofreshOSGate runtime.gofreshSimGate
func gofreshOSGate() bool

type gofreshSimTable[T any, S any] struct {
	spine atomic.Pointer[S]
	count int
}

func (t *gofreshSimTable[T, S]) get(idx int) *S {
	sp := t.spine.Load()
	if sp == nil || idx < 0 || idx > t.count {
		return nil
	}
	return sp
}

func (t *gofreshSimTable[T, S]) register(s *S) {
	t.count++
	t.spine.Store(s)
}

var gofreshSimStates gofreshSimTable[file, int]

func gofreshSimStats() int {
	return gofreshSimStates.count
}

func gofreshSimIdx(f *file) (int, bool) {
	return int(uintptr(unsafe.Pointer(f))), true
}

func gofreshStateOf(f *file) *int {
	idx, ok := gofreshSimIdx(f)
	if !ok {
		return nil
	}
	s := gofreshSimStates.get(idx)
	runtime.KeepAlive(f)
	return s
}

func gofreshRegisterSim(_ *file) {
	if !gofreshOSGate() {
		return
	}
	v := 1
	gofreshSimStates.register(&v)
}

func gofreshTryGetwd() (string, bool, error) {
	if !gofreshOSGate() {
		return "", false, nil
	}
	gofreshRegisterSim(nil)
	return "/sim", true, nil
}
`
	simGOROOT, simValidEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/strings/gofresh_dst_unapproved.go": "//go:build dst\n\npackage strings\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshDstUnapproved\nfunc gofreshDstUnapproved() {}\n",
		"src/runtime/gofresh_sim_overlay.go":    simRuntimeClean,
		"src/os/gofresh_sim_off.go":             simOSOff,
		"src/os/gofresh_sim_on.go":              simOSOn,
		"src/os/getwd.go":                       hookedGetwd,
		"src/os/file_posix.go":                  hookedFilePosix,
		"src/image/color/gofresh_sim_trigger.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc ActivateSim() { gofreshPullEnable() }\n",
	})
	withSimFiles := func(extra map[string]string, fn func([]string)) {
		t.Helper()
		type savedEntry struct {
			path string
			data []byte
		}
		var saved []savedEntry
		var created []string
		for rel, content := range extra {
			target := filepath.Join(simGOROOT, filepath.FromSlash(rel))
			if prev, err := os.ReadFile(target); err == nil {
				saved = append(saved, savedEntry{path: target, data: prev})
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			} else {
				created = append(created, target)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, target := range created {
				_ = os.Remove(target)
			}
			for _, s := range saved {
				_ = os.Remove(s.path)
				if err := os.WriteFile(s.path, s.data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}()
		fn(simValidEnv)
	}
	simPlain, err := resolveAtEnv(ctx, ".", simValidEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !simPlain.Audited() {
		t.Fatalf("plain selection over overlaid GOROOT refused: %s", simPlain.Notice())
	}
	dstOverlay, err := resolveAtEnv(ctx, ".", simValidEnv, "-tags", "dst")
	if err != nil {
		t.Fatal(err)
	}
	if dstOverlay.Audited() || !strings.Contains(dstOverlay.Attribution(), "moved in 1 keys: strings") {
		t.Fatalf("dst selection with unapproved strings file: audited=%v attribution=%q", dstOverlay.Audited(), dstOverlay.Attribution())
	}
	simActive, err := resolveAtEnv(ctx, ".", simValidEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !simActive.Audited() {
		t.Fatalf("simoverlay selection with verified inactive runtime gate and state table refused: %s", simActive.Notice())
	}

	goversion := snap.Value("GOVERSION")
	evalSimNegative := func(name string, extra map[string]string) selectionDegradation {
		t.Helper()
		var deg selectionDegradation
		withSimFiles(extra, func(_ []string) {
			d := sourceDigests{
				Content:   simActive.source.Content,
				Policy:    simActive.source.Policy,
				Packages:  maps.Clone(simActive.source.Packages),
				inventory: maps.Clone(simActive.source.inventory),
			}
			touchedPkgs := map[string]bool{}
			for rel := range extra {
				clean := filepath.ToSlash(filepath.Clean(rel))
				switch {
				case strings.HasPrefix(clean, "pkg/include/"):
					touchedPkgs["runtime"] = true
				case strings.HasPrefix(clean, "src/"):
					pkgPath := path.Dir(strings.TrimPrefix(clean, "src/"))
					touchedPkgs[pkgPath] = true
				}
			}
			buf := make([]byte, 32*1024)
			for pkgPath := range touchedPkgs {
				lp, ok := d.inventory[pkgPath]
				if !ok {
					t.Fatalf("%s: package %s not in std inventory", name, pkgPath)
				}
				files := slices.Clone(lp.Files)
				for rel := range extra {
					clean := filepath.ToSlash(filepath.Clean(rel))
					if strings.HasPrefix(clean, "src/"+pkgPath+"/") {
						base := path.Base(clean)
						if !strings.Contains( clean[len("src/"+pkgPath+"/"):], "/") && !slices.Contains(files, base) {
							files = append(files, base)
						}
					}
				}
				slices.Sort(files)
				lp.Files = files
				digest, err := digestListedPackageBuffered(ctx, lp, buf)
				if err != nil {
					t.Fatalf("%s: digest %s: %v", name, pkgPath, err)
				}
				lp.digest = digest
				d.inventory[pkgPath] = lp
				if lp.Audited {
					d.Packages[pkgPath] = digest
				}
			}
			var err error
			deg, err = toolchainSourceDegradationContext(ctx, goversion, d, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		return deg
	}

	// Negative 1: runtime calls the gate mutator directly.
	if deg := evalSimNegative("called runtime mutator", map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean + "\nfunc gofreshBootActivate() { gofreshSimEnable() }\n",
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with called runtime mutator: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 2: another audited surface package pulls the runtime gate mutator via //go:linkname.
	if deg := evalSimNegative("linkname-pulled runtime mutator", map[string]string{
		"src/testing/gofresh_pull_mutator.go": "//go:build simoverlay\n\npackage testing\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n",
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with linkname-pulled runtime mutator: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 3: state-table register is reachable without the inactive runtime gate.
	simUngatedTable := strings.Replace(simOSOn, "\tif !gofreshOSGate() {\n\t\treturn\n\t}\n", "", 1) + "\nfunc GofreshReachableRegister() { gofreshRegisterSim(nil) }\n"
	if deg := evalSimNegative("ungated state-table register", map[string]string{
		"src/os/gofresh_sim_on.go": simUngatedTable,
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with ungated state-table register: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 4: genuinely off-surface std package (image/color) activates runtime gate at startup,
	// via push-linkname, or via assembly/header symbol references (including macro expansion,
	// pkg/include headers, middle-dot whitespace/comments, token pasting, or direct flag writes).
	if slices.Contains(auditedSurfaceTables(), "image/color") {
		t.Fatal("image/color unexpectedly joined auditedSurfaceTables; test requires an off-surface std package")
	}
	// Positive controls for Negative 4: benign runtime assembly and benign off-surface cgo C file
	// must keep the selection audited so the negative cases below cannot pass from go list errors.
	benignFiles := map[string]string{
		"pkg/include/gofresh_bridge.h":             "#define NOOP_ASM RET\n",
		"src/runtime/gofresh_bridge_benign.s":      "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nTEXT ·gofreshRuntimeAsmNoop(SB),$0-0\n\tNOOP_ASM\n",
		"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
	}
	if cgo {
		benignFiles["src/image/color/gofresh_sim_cgo.go"] = "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n"
		benignFiles["src/image/color/gofresh_sim_ext.c"] = "//go:build simoverlay\n\nvoid gofreshBenignC(void) {}\n"
		benignFiles["src/runtime/cgo/gofresh_bridge.h"] = "#define BENIGN_STR(x) #x\n"
		benignFiles["src/runtime/cgo/gofresh_bridge_ok.c"] = "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nconst char *gofreshBenignRuntimeCgo(void) { return BENIGN_STR(ok); }\n"
	}
	withSimFiles(benignFiles, func(benignEnv []string) {
		benignH, err := resolveAtEnv(ctx, ".", benignEnv, "-tags", "simoverlay")
		if err != nil {
			t.Fatal(err)
		}
		if !benignH.Audited() {
			t.Fatalf("benign runtime assembly / off-surface cgo C file refused: %s", benignH.Notice())
		}
	})

	for _, tc := range []struct {
		name    string
		cgoOnly bool
		files   map[string]string
	}{
		{
			name: "off-surface startup init pull-linkname",
			files: map[string]string{
				"src/image/color/gofresh_sim_boot.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc init() { gofreshPullEnable() }\n",
			},
		},
		{
			name: "off-surface startup var initializer pull-linkname",
			files: map[string]string{
				"src/image/color/gofresh_sim_boot.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc bootHelper() int { gofreshPullEnable(); return 1 }\n\nvar _ = bootHelper()\n",
			},
		},
		{
			name: "off-surface push-linkname overriding runtime mutator",
			files: map[string]string{
				"src/image/color/gofresh_sim_push.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPushEnable runtime.gofreshSimEnable\nfunc gofreshPushEnable() {}\n",
			},
		},
		{
			name: "off-surface assembly middle-dot whitespace",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL runtime · gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface assembly middle-dot block comment",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL runtime/*c*/·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface local header macro runtime prefix",
			files: map[string]string{
				"src/image/color/gofresh_local.h":   "#define R runtime\n",
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#include \"gofresh_local.h\"\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL R·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface pkg/include header macro runtime prefix",
			files: map[string]string{
				"pkg/include/gofresh_inc.h":         "#define RINC runtime\n",
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#include \"gofresh_inc.h\"\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL RINC·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface parameterized macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define CALLRT(s) CALL runtime·s(SB)\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALLRT(gofreshSimEnable)\n\tRET\n",
			},
		},
		{
			name: "off-surface token-paste macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define PASTE(a,b) a##b\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL PASTE(run,time)·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface assembly direct gate flag write",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tMOVL $1, runtime·gofreshSimFlag(SB)\n\tRET\n",
			},
		},
		{
			name:    "off-surface c adjacent string literal runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\nextern void gofreshEnableC(void) __asm__(\"runtime.\" \"gofreshSimEnable\");\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name:    "off-surface c hex escape runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\nextern void gofreshEnableC(void) __asm__(\"runtime.\\x67ofreshSimEnable\");\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name:    "off-surface c stringize macro runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\n#define RTSYM(x) extern void gofreshEnableC(void) __asm__(\"runtime.\" #x);\nRTSYM(gofreshSimEnable)\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name: "off-surface multiline parameterized macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define CALLRT(s) CALL runtime·s(SB)\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALLRT(\n\t\tgofreshSimEnable\n\t)\n\tRET\n",
			},
		},
		{
			name: "off-surface runtime header assembly external pull",
			files: map[string]string{
				"pkg/include/gofresh_bridge.h":             "#define EXT_PKG image/color\n",
				"src/runtime/gofresh_bridge.s":             "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nTEXT ·gofreshRuntimeAsmNoop(SB),$0-0\n\tCALL EXT_PKG·gofreshBridgeEnable(SB)\n\tRET\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
			},
		},
		{
			name:    "off-surface runtime/cgo header stringize external pull",
			cgoOnly: true,
			files: map[string]string{
				"src/runtime/cgo/gofresh_bridge.h":         "#define EXT_CALL(pkg, fn) extern void gofreshBridge(void) __asm__(#pkg \".\" #fn);\n",
				"src/runtime/cgo/gofresh_bridge.c":         "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nEXT_CALL(image/color, gofreshBridgeEnable)\nvoid gofreshRuntimeNoop(void) { gofreshBridge(); }\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
			},
		},
		{
			name: "off-surface runtime method linkname external pull",
			files: map[string]string{
				"src/runtime/gofresh_bridge_method.go":     "//go:build simoverlay\n\npackage runtime\n\nimport _ \"unsafe\"\n\n//go:linkname rtBridgeMethod image/color.(*Palette).gofreshBridgeMethod\nfunc rtBridgeMethod(*struct{})\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc (p *Palette) gofreshBridgeMethod() { simEnable() }\n",
			},
		},
	} {
		if tc.cgoOnly && !cgo {
			continue
		}
		deg := evalSimNegative(tc.name, tc.files)
		if deg.audited() || !strings.Contains(deg.axis, "os") {
			t.Fatalf("%s: audited=%v attribution=%q", tc.name, deg.audited(), deg.axis)
		}
	}
}

// TestListingMemoRecordLandsUnderTheLiveSeedsScope pins the memo's
// wiring (REQ-closure-observability-toolchain-key's listing memo): a
// listing is stored under the scope the live surface seeds make and
// under no other seed list's, so a record of another surface rule is
// never the one a construction finds.
func TestListingMemoRecordLandsUnderTheLiveSeedsScope(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	runner := gotool.Runner{}
	snapshot, err := gotool.NewEnvReader(runner, dir, os.Environ()).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil); err != nil {
		t.Fatal(err)
	}
	live, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("no listing record under the live seeds' scope: %v", err)
	}
	other, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, []string{"runtime", "sync/atomic", "testing"}), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatalf("a listing record under another seed list's scope: %s", other)
	}
}

// The running toolchain's surface digests under the default selection:
// every surface package present with a digest (the runtime and the
// reached delegates included), the race selection moving exactly the
// race seams, and the listing memo serving the second read without a
// listing while the tree stands (REQ-closure-observability-toolchain-key).
func TestToolchainSourceDigestsReadTheRunningToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	reader := gotool.NewEnvReader(runner, dir, os.Environ())
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range auditedSurfaceTables() {
		if p == "golang.org/x/sys/unix" {
			continue // a module package, never the toolchain's
		}
		if d.Packages[p] == "" {
			t.Errorf("no digest for the surface package %s", p)
		}
	}
	for _, p := range []string{"crypto/internal/fips140", "vendor/golang.org/x/net/http2/hpack", "internal/godebug", "runtime", "internal/runtime/atomic", "unsafe", "runtime/cgo", "runtime/race"} {
		if d.Packages[p] == "" {
			t.Errorf("no digest for the reached package %s", p)
		}
	}
	if listings != 1 {
		t.Fatalf("the first read listed %d times, want once", listings)
	}
	again, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil || !reflect.DeepEqual(again, d) {
		t.Fatalf("the memo-served digests differ: %v %+v", err, again)
	}
	if listings != 1 {
		t.Fatalf("the second read listed again (%d listings); the memo serves it", listings)
	}
	race, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, []string{"-race"})
	if err != nil {
		t.Fatal(err)
	}
	// The race selection differs from the default in exactly the race
	// seams the listing's race rows carry as their delta: internal/race
	// selects race.go for norace.go (sync's delegate, the real instrumentation
	// behind the race.Enabled guards), sync/atomic selects race.s for
	// asm.s (the atomics routed through the runtime's instrumented
	// forms), the runtime and its sys delegate select their race files,
	// and the detector's runtime (runtime/race, a link-time seed) its
	// race-tagged files — all judged inert for every admission under
	// either selection; every other surface package selects the same
	// files.
	var differs []string
	for k, v := range race.Packages {
		if d.Packages[k] != v {
			differs = append(differs, k)
		}
	}
	sort.Strings(differs)
	if !reflect.DeepEqual(differs, []string{"internal/race", "internal/runtime/sys", "runtime", "runtime/race", "sync/atomic"}) {
		t.Fatalf("the race selection differs from the default in %v, want the race seams alone", differs)
	}
}

// A package the go command could not load refuses the listing by name
// through the parser — the shim's listing carries an Error entry — and
// a package the selection gives no file (a platform none of its files
// build on) is the empty selection, digested as the empty sequence.
func TestListingErrorsRefuseByNameAndTheEmptySelectionDigests(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the listing shim is a shell script")
	}
	isolateProofCache(t)
	ctx := context.Background()
	root := t.TempDir()
	empty := filepath.Join(root, "src", "plugin")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	listingJSON := filepath.Join(root, "listing.json")
	shim := filepath.Join(root, "golist.sh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec cat "+listingJSON+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			cmd.Path = shim
		}
	}}
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+root+`","GoFiles":["a.go"],"Error":{"Err":"import cycle not allowed"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil); err == nil || !strings.Contains(err.Error(), "package strings failed to load: import cycle not allowed") {
		t.Fatalf("a listing error digested instead of refusing by name: %v", err)
	}
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"plugin","Standard":true,"Dir":"`+empty+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := digestFiles(ctx, empty, nil); d.Packages["plugin"] != want {
		t.Fatalf("the empty selection digests %q, want the empty sequence %q", d.Packages["plugin"], want)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// The memo scope is the explicit build flags verbatim and the pass
// snapshot's identity — every setting the go command reports: GOFLAGS
// (the go command merges and overrides it itself, so the scope never
// re-derives the merge), the platform, cgo, the experiment and FIPS
// module sets, the root and version — one value for one environment,
// so a record never serves a listing it was not taken under.
func TestToolchainSourceScopeDiscriminatesEveryAxis(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	snapshot := func(settings ...string) *gotool.EnvSnapshot {
		t.Helper()
		given := map[string]bool{}
		for _, setting := range settings {
			key, _, _ := strings.Cut(setting, "=")
			given[key] = true
		}
		for _, setting := range []string{"GOENV=off", "GOEXPERIMENT=", "GOFLAGS=", "GOFIPS140=off"} {
			if key, _, _ := strings.Cut(setting, "="); !given[key] {
				settings = append(settings, setting)
			}
		}
		s, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, environmentWith(settings...))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := snapshot()
	if got, want := toolchainSourceScope(base, nil, surfaceSeeds()), toolchainSourceScope(snapshot(), nil, surfaceSeeds()); got != want {
		t.Errorf("one environment, two scopes: %q vs %q", got, want)
	}
	if got, same := toolchainSourceScope(base, []string{"-tags=netgo"}, surfaceSeeds()), toolchainSourceScope(base, nil, surfaceSeeds()); got == same {
		t.Errorf("the explicit flags do not key the scope: %q", got)
	}
	for _, axis := range []string{"GOFLAGS=-tags=netgo", "GOEXPERIMENT=fieldtrack", "GOOS=plan9", "GOARCH=arm64", "CGO_ENABLED=0", "GOFIPS140=latest"} {
		if got, same := toolchainSourceScope(snapshot(axis), nil, surfaceSeeds()), toolchainSourceScope(base, nil, surfaceSeeds()); got == same {
			t.Errorf("%s does not key the scope: %q", axis, got)
		}
	}
	if got := toolchainSourceScope(base, nil, surfaceSeeds()); !strings.Contains(got, "GOVERSION="+base.Value("GOVERSION")) || !strings.Contains(got, "GOROOT="+base.Value("GOROOT")) {
		t.Errorf("the scope names neither the version nor the GOROOT: %q", got)
	}
	// An explicit flag over GOFLAGS is the go command's merge, not the
	// scope's: the two shapes are two scopes whatever they select.
	if a, b := toolchainSourceScope(snapshot("GOFLAGS=-tags=netgo"), []string{"-tags=dup"}, surfaceSeeds()), toolchainSourceScope(base, []string{"-tags=dup,netgo"}, surfaceSeeds()); a == b {
		t.Error("an explicit flag over GOFLAGS shares a scope with their union")
	}
}

// The memo serves a listing only over the tree it was taken over, end
// to end: a standard library planted in a temporary tree (the go
// command's listing answered by a shim) lists once, serves the second
// read without a listing, and after one planted file is edited in
// place re-lists on the third read with the package's digest moved —
// the listing never decides which bytes are compiled from a tree that
// moved, and the digests are always the files' own.
func TestToolchainSourceMemoRelistsAMovedTree(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the listing shim is a shell script")
	}
	isolateProofCache(t)
	ctx := context.Background()
	root := t.TempDir()
	pkgDir := filepath.Join(root, "src", "strings")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("strings.go", "package strings\n")
	write("other.go", "//go:build never\n\npackage strings\n")
	listingJSON := filepath.Join(root, "listing.json")
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+pkgDir+`","GoFiles":["strings.go"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(root, "golist.sh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec cat "+listingJSON+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
			cmd.Path = shim
		}
	}}
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	first := read()
	if want, _ := digestFiles(ctx, pkgDir, []string{"strings.go"}); first.Packages["strings"] != want || listings != 1 {
		t.Fatalf("first read: digest %q (want %q), %d listings", first.Packages["strings"], want, listings)
	}
	wantListings := 1
	if !stampsTrusted {
		wantListings = 2 // no change time here: every read lists
	}
	if again := read(); again.Packages["strings"] != first.Packages["strings"] || listings != wantListings {
		t.Fatalf("second read: %d listings over an unchanged tree, want %d", listings, wantListings)
	}
	// The tree moves under the same scope: the unselected file's
	// constraint edited in place (its selection may now differ) —
	// re-listed; the shim now selects it, and the digest moves.
	write("other.go", "package strings\n\nfunc Other() {}\n")
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+pkgDir+`","GoFiles":["other.go","strings.go"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	third := read()
	if listings != wantListings+1 {
		t.Fatalf("a moved tree served the stale listing (%d listings)", listings)
	}
	if want, _ := digestFiles(ctx, pkgDir, []string{"other.go", "strings.go"}); third.Packages["strings"] != want || third.Packages["strings"] == first.Packages["strings"] {
		t.Fatalf("the digest did not follow the moved tree: %q, want %q", third.Packages["strings"], want)
	}
	// A selected file edited in place: its stamp re-lists (the same
	// files selected) and the digest follows the new bytes.
	write("strings.go", "package strings\n\nfunc Edited() {}\n")
	fourth := read()
	if want, _ := digestFiles(ctx, pkgDir, []string{"other.go", "strings.go"}); fourth.Packages["strings"] != want || fourth.Packages["strings"] == third.Packages["strings"] {
		t.Fatalf("an edited selected file left the digest: %q, want %q", fourth.Packages["strings"], want)
	}
}

func TestToolchainSourceScopeIgnoresModulePathsAndServesDigestMemo(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	isolateProofCache(t)
	ctx := context.Background()
	modA := t.TempDir()
	modB := t.TempDir()
	writeTree(t, modA, map[string]string{"go.mod": "module example.com/moda\n\ngo 1.26\n"})
	writeTree(t, modB, map[string]string{"go.mod": "module example.com/modb\n\ngo 1.26\n"})
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	snapA, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, modA, env)
	if err != nil {
		t.Fatal(err)
	}
	snapB, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, modB, env)
	if err != nil {
		t.Fatal(err)
	}
	scopeA := toolchainSourceScope(snapA, nil, surfaceSeeds())
	scopeB := toolchainSourceScope(snapB, nil, surfaceSeeds())
	if scopeA != scopeB {
		t.Fatalf("distinct modules under same toolchain produced different scopes:\nA: %s\nB: %s", scopeA, scopeB)
	}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	first, err := toolchainSourceDigests(ctx, runner, modA, env, snapA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listings != 1 {
		t.Fatalf("cold listings = %d, want 1", listings)
	}
	second, err := toolchainSourceDigests(ctx, runner, modB, env, snapB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listings != 1 {
		t.Fatalf("warm cross-module listings = %d, want 1", listings)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("warm cross-module digests differed from cold digests")
	}
	// An empty package digest in the memoized map is rejected by sourceDigestsFromMemo.
	l := surfaceListing{
		Version:  sourceDigestsVersion,
		Packages: []listedPackage{{ImportPath: "strings", Audited: true}, {ImportPath: "archive/tar", Audited: false}},
	}
	if _, ok := sourceDigestsFromMemo(l, map[string]string{"strings": "", "archive/tar": "abc"}); ok {
		t.Fatal("sourceDigestsFromMemo accepted empty digest for audited package")
	}
	if _, ok := sourceDigestsFromMemo(l, map[string]string{"strings": "abc", "archive/tar": ""}); ok {
		t.Fatal("sourceDigestsFromMemo accepted empty digest for non-audited package")
	}
}

func TestToolchainSurfaceAdmitsCrossTargetSelections(t *testing.T) {
	if testing.Short() {
		t.Skip("lists cross-target standard libraries")
	}
	isolateProofCache(t)
	ctx := t.Context()
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		settings []string
	}{
		{"linux_amd64", []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"windows_amd64", []string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"plan9_amd64", []string{"GOOS=plan9", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"darwin_arm64", []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0"}},
		{"wasip1_wasm", []string{"GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0"}},
		{"js_wasm", []string{"GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0"}},
	} {
		env, err := gotool.NormalizeEnv(environmentWith(tc.settings...))
		if err != nil {
			t.Fatalf("%s NormalizeEnv: %v", tc.name, err)
		}
		reader := gotool.NewEnvReader(gotool.Runner{}, dir, env)
		snapshot, err := reader.Snapshot(ctx)
		if err != nil {
			t.Fatalf("%s Snapshot: %v", tc.name, err)
		}
		d, err := toolchainSourceDigests(ctx, gotool.Runner{}, dir, env, snapshot, nil)
		if err != nil {
			t.Fatalf("%s toolchainSourceDigests: %v", tc.name, err)
		}
		if failed := verifyToolchainSurface(d); len(failed) != 0 {
			var details []string
			for _, pkg := range failed {
				details = append(details, pkg+": "+fmtSprintErr(verifyListedPackage(d.inventory[pkg])))
			}
			t.Fatalf("%s surface verification failed on %v (%v)", tc.name, failed, details)
		}
	}
}

func TestToolchainListingTracksFIPSAliasSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("clones and retargets a supported FIPS source selection")
	}
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "symlink-root"}[linked], func(t *testing.T) {
			testFIPSAliasSelection(t, linked)
		})
	}
}

func testFIPSAliasSelection(t *testing.T, linked bool) {
	t.Helper()
	root := isolatedToolchainSource(t)
	if linked {
		path := filepath.Join(root, "lib", "fips140")
		outside := filepath.Join(t.TempDir(), "fips140")
		if err := os.Rename(path, outside); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOFIPS140", "inprocess")
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Cleanup(func() {
		// Go normally makes extracted module directories read-only. They are
		// this fixture's private cache, so restore traversal/removal permissions.
		_ = filepath.WalkDir(cache, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return err
		})
	})
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/fipsdep\n\ngo 1.27\n"})
	env := listingEnv("-modcacherw", "off")
	snapshot := snapshotFor(t, dir, env)
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), gotool.Runner{}, dir, env, snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := read()
	if again := read(); again.Content != before.Content {
		t.Fatal("unchanged FIPS selection moved")
	}
	alias := filepath.Join(root, "lib", "fips140", "inprocess.txt")
	if err := os.WriteFile(alias, []byte("v1.0.0-c2097c7c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	warm := read()
	path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !(linked && os.IsNotExist(err)) {
		t.Fatal(err)
	}
	cold := read()
	if before.Content == cold.Content || warm.Content != cold.Content {
		t.Fatalf("FIPS retarget: before=%s warm=%s cold=%s", before.Content, warm.Content, cold.Content)
	}
}

func TestToolchainListingDoesNotCacheSymlinkSelectionInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("changes followed source and embed selection inputs")
	}
	for _, directoryLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "excluded-file", true: "embedded-directory"}[directoryLink], func(t *testing.T) {
			root := isolatedToolchainSource(t)
			outside := t.TempDir()
			if directoryLink {
				writeTree(t, outside, map[string]string{
					"p.go":           "package stdembed\nimport \"embed\"\n//go:embed assets\nvar Files embed.FS\n",
					"assets/one.txt": "one", "assets/deep/empty/": "",
				})
				if err := os.Symlink(outside, filepath.Join(root, "src", "stdembed")); err != nil {
					t.Fatal(err)
				}
				writeTree(t, root, map[string]string{"src/anchor/p.go": "package anchor\nimport _ \"stdembed\"\n"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "//go:build never\n\npackage strings\n"})
				if err := os.Symlink(filepath.Join(outside, "extra.go"), filepath.Join(root, "src", "strings", "extra.go")); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"go.mod": "module example.com/linkselection\n\ngo 1.27\n", "main.go": "package main\nimport (\"fmt\"; \"strings\")\nfunc main() { fmt.Print(strings.Compare(\"a\", \"a\")) }\n"})
			env := listingEnv("", "off")
			snapshot := snapshotFor(t, dir, env)
			listings := 0
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				if cmd.Args[1] == "list" {
					listings++
				}
			}}
			read := func() sourceDigests {
				t.Helper()
				d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, nil)
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			before := read()
			if again := read(); again.Content != before.Content {
				t.Fatal("unchanged symlink-bearing selection moved")
			}
			priorListings := listings
			if directoryLink {
				if _, present := before.inventory["stdembed"]; !present {
					t.Fatal("selected symlink package was absent")
				}
				writeTree(t, outside, map[string]string{"assets/deep/empty/new.txt": "new"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "package strings\nfunc init() { panic(\"new selected initializer\") }\n"})
				cmd := exec.CommandContext(t.Context(), "go", "run", ".")
				cmd.Dir, cmd.Env = dir, env
				if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "new selected initializer") {
					t.Fatalf("fresh program missed selected initializer: %s %v", out, err)
				}
			}
			after := read()
			if after.Content == before.Content || listings != priorListings+1 {
				t.Fatal("changed symlink target did not move selection")
			}
			if priorListings != 2 {
				t.Fatal("symlink-bearing discovery served an unsupported memo")
			}
			path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("unsupported discovery persisted: %v", err)
			}
		})
	}
}

func TestAuditedExperimentRejectsUnverifiedSourceChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, gotool.Runner{}, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deg := toolchainSourceDegradation("rebuilt-toolchain", d, nil); !deg.audited() {
		t.Fatalf("verified content rejected under a different label: %s", deg.notice())
	}
	for _, key := range []string{"internal/goexperiment", "runtime", "strings"} {
		changed := d
		changed.Packages = maps.Clone(d.Packages)
		changed.Packages[key] = "unverified-source-change"
		deg := toolchainSourceDegradation("rebuilt-toolchain", changed, nil)
		if deg.audited() || !strings.Contains(deg.notice(), key) {
			t.Fatalf("changed %s admitted or not named: %s", key, deg.notice())
		}
	}
}

func parseTestPackageDirGoAndAsm(t *testing.T, dir string) ([]*ast.File, []string, map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	var goSrcs []string
	asmSrcs := map[string]string{}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".go" && ext != ".s" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s/%s): %v", dir, name, err)
		}
		if ext == ".s" {
			asmSrcs[name] = string(raw)
			continue
		}
		f, err := parser.ParseFile(fset, name, raw, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s/%s): %v", dir, name, err)
		}
		files = append(files, f)
		goSrcs = append(goSrcs, string(raw))
	}
	return files, goSrcs, asmSrcs
}

func discoverAvailableGoBinaries(t *testing.T) []string {
	t.Helper()
	var candidates []string
	if p, err := exec.LookPath("go"); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, "/usr/bin/go")
	seenReal := map[string]bool{}
	var out []string
	for _, cand := range candidates {
		info, err := os.Stat(cand)
		if err != nil || info.IsDir() {
			continue
		}
		realPath := cand
		if rp, err := filepath.EvalSymlinks(cand); err == nil {
			realPath = rp
		}
		if seenReal[realPath] {
			continue
		}
		seenReal[realPath] = true
		out = append(out, cand)
	}
	if len(out) == 0 {
		t.Fatal("no go toolchain binaries discovered")
	}
	return out
}

func TestMultiToolchainSelectionAuditAndRuntimeDebug(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns cross-target go list std subprocesses")
	}
	ctx := context.Background()
	workDir := t.TempDir()
	baseEnv := os.Environ()
	goBins := discoverAvailableGoBinaries(t)

	type targetSpec struct {
		goos   string
		goarch string
		flags  []string
	}
	targets := []targetSpec{
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "amd64", flags: []string{"-tags=dst"}},
		{goos: "linux", goarch: "386"},
		{goos: "linux", goarch: "arm64"},
		{goos: "linux", goarch: "ppc64le"},
		{goos: "linux", goarch: "riscv64"},
		{goos: "linux", goarch: "loong64"},
		{goos: "linux", goarch: "s390x"},
		{goos: "wasip1", goarch: "wasm"},
		{goos: "darwin", goarch: "arm64"},
		{goos: "windows", goarch: "amd64"},
		{goos: "windows", goarch: "amd64", flags: []string{"-tags=dst"}},
	}

	for _, goBin := range goBins {
		verBytes, err := exec.Command(goBin, "version").Output()
		if err != nil {
			t.Fatalf("%s version: %v", goBin, err)
		}
		verLabel := strings.TrimSpace(string(verBytes))
		gorootBytes, err := exec.Command(goBin, "env", "GOROOT").Output()
		if err != nil {
			t.Fatalf("%s env GOROOT: %v", goBin, err)
		}
		goroot := strings.TrimSpace(string(gorootBytes))

		t.Run(filepath.Base(filepath.Dir(filepath.Dir(goBin)))+"_"+filepath.Base(goBin), func(t *testing.T) {
			dbgDir := filepath.Join(goroot, "src", "runtime", "debug")
			dbgFiles, dbgSrcs, dbgAsms := parseTestPackageDirGoAndAsm(t, dbgDir)
			if err := verifyRuntimeDebugPackage(ctx, dbgFiles, dbgSrcs, dbgAsms, nil); err != nil {
				t.Fatalf("%s: verifyRuntimeDebugPackage(%s): %v", verLabel, dbgDir, err)
			}
			rtDir := filepath.Join(goroot, "src", "runtime")
			rtFiles, rtSrcs, _ := parseTestPackageDirGoAndAsm(t, rtDir)
			if err := verifyRuntimeModinfoAST(rtFiles, rtSrcs, nil); err != nil {
				t.Fatalf("%s: verifyRuntimeModinfoAST(%s): %v", verLabel, rtDir, err)
			}

			for _, tgt := range targets {
				name := tgt.goos + "_" + tgt.goarch
				if len(tgt.flags) > 0 {
					name += "_dst"
				}
				t.Run(name, func(t *testing.T) {
					env := testenv.EnvWithGoBinAndTarget(baseEnv, goBin, tgt.goos, tgt.goarch)
					reader := &gotool.EnvReader{
						Runner: gotool.Runner{Prepare: func(cmd *exec.Cmd) { cmd.Path = goBin }},
						Dir:    workDir,
						Env:    env,
					}
					content, policy, notice, err := ResolveToolchainSelection(ctx, reader, tgt.flags)
					if err != nil {
						t.Fatalf("%s (%v): ResolveToolchainSelection error: %v", verLabel, tgt, err)
					}
					if notice != "" || content == "" || policy == "" {
						t.Fatalf("%s (%v): selection degraded: content=%q policy=%q notice=%q", verLabel, tgt, content, policy, notice)
					}
				})
			}
		})
	}
}
