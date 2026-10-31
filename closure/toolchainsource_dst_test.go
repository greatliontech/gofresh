package closure

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

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
	base, err := newAtEnv(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	if !base.SelectionAudited() {
		t.Fatalf("the running toolchain failed structural verification under its default selection: %s", base.SelectionNotice())
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
		h, err := newAtEnv(ctx, ".", environmentWith(), sel.flags...)
		if err != nil {
			t.Fatal(err)
		}
		if !h.SelectionAudited() {
			t.Fatalf("the %q selection on the running toolchain refused: %s", sel.suffix, h.SelectionNotice())
		}
	}

	_, overlayEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/strings/gofresh_dst_unapproved.go": "//go:build dst\n\npackage strings\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshDstUnapproved\nfunc gofreshDstUnapproved() {}\n",
	})
	plainOverlay, err := newAtEnv(ctx, ".", overlayEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !plainOverlay.SelectionAudited() {
		t.Fatalf("plain selection over dst-overlaid GOROOT refused: %s", plainOverlay.SelectionNotice())
	}
	dstOverlay, err := newAtEnv(ctx, ".", overlayEnv, "-tags", "dst")
	if err != nil {
		t.Fatal(err)
	}
	if dstOverlay.SelectionAudited() || !strings.Contains(dstOverlay.SelectionAttribution(), "moved in 1 keys: strings") {
		t.Fatalf("dst selection with unapproved strings file: audited=%v attribution=%q", dstOverlay.SelectionAudited(), dstOverlay.SelectionAttribution())
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
	_, simValidEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean,
		"src/os/gofresh_sim_off.go":          simOSOff,
		"src/os/gofresh_sim_on.go":           simOSOn,
		"src/os/getwd.go":                    hookedGetwd,
		"src/os/file_posix.go":               hookedFilePosix,
	})
	simPlain, err := newAtEnv(ctx, ".", simValidEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !simPlain.SelectionAudited() {
		t.Fatalf("plain selection over inactive-gate GOROOT refused: %s", simPlain.SelectionNotice())
	}
	simActive, err := newAtEnv(ctx, ".", simValidEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !simActive.SelectionAudited() {
		t.Fatalf("simoverlay selection with verified inactive runtime gate and state table refused: %s", simActive.SelectionNotice())
	}

	// Negative 1: runtime calls the gate mutator directly.
	_, simMutCalledEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean + "\nfunc gofreshBootActivate() { gofreshSimEnable() }\n",
		"src/os/gofresh_sim_off.go":          simOSOff,
		"src/os/gofresh_sim_on.go":           simOSOn,
		"src/os/getwd.go":                    hookedGetwd,
		"src/os/file_posix.go":               hookedFilePosix,
	})
	simMutCalled, err := newAtEnv(ctx, ".", simMutCalledEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if simMutCalled.SelectionAudited() || !strings.Contains(simMutCalled.SelectionAttribution(), "os") {
		t.Fatalf("simoverlay with called runtime mutator: audited=%v attribution=%q", simMutCalled.SelectionAudited(), simMutCalled.SelectionAttribution())
	}

	// Negative 2: another audited surface package pulls the runtime gate mutator via //go:linkname.
	_, simMutPulledEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean,
		"src/os/gofresh_sim_off.go":          simOSOff,
		"src/os/gofresh_sim_on.go":           simOSOn,
		"src/os/getwd.go":                    hookedGetwd,
		"src/os/file_posix.go":               hookedFilePosix,
		"src/testing/gofresh_pull_mutator.go": "//go:build simoverlay\n\npackage testing\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n",
	})
	simMutPulled, err := newAtEnv(ctx, ".", simMutPulledEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if simMutPulled.SelectionAudited() || !strings.Contains(simMutPulled.SelectionAttribution(), "os") {
		t.Fatalf("simoverlay with linkname-pulled runtime mutator: audited=%v attribution=%q", simMutPulled.SelectionAudited(), simMutPulled.SelectionAttribution())
	}

	// Negative 3: state-table register is reachable without the inactive runtime gate.
	simUngatedTable := strings.Replace(simOSOn, "\tif !gofreshOSGate() {\n\t\treturn\n\t}\n", "", 1) + "\nfunc GofreshReachableRegister() { gofreshRegisterSim(nil) }\n"
	_, simUngatedEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean,
		"src/os/gofresh_sim_off.go":          simOSOff,
		"src/os/gofresh_sim_on.go":           simUngatedTable,
		"src/os/getwd.go":                    hookedGetwd,
		"src/os/file_posix.go":               hookedFilePosix,
	})
	simUngated, err := newAtEnv(ctx, ".", simUngatedEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if simUngated.SelectionAudited() || !strings.Contains(simUngated.SelectionAttribution(), "os") {
		t.Fatalf("simoverlay with ungated state-table register: audited=%v attribution=%q", simUngated.SelectionAudited(), simUngated.SelectionAttribution())
	}

	// Negative 4: genuinely off-surface std package (image/color) activates runtime gate at startup,
	// via push-linkname, or via assembly/header symbol references (including macro expansion,
	// pkg/include headers, middle-dot whitespace/comments, token pasting, or direct flag writes).
	if slices.Contains(auditedSurfaceTables(), "image/color") {
		t.Fatal("image/color unexpectedly joined auditedSurfaceTables; test requires an off-surface std package")
	}
	// Positive controls for Negative 4: benign runtime assembly and benign off-surface cgo C file
	// must keep the selection audited so the negative cases below cannot pass from go list errors.
	{
		_, benignAsmEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
			"src/runtime/gofresh_sim_overlay.go":       simRuntimeClean,
			"src/os/gofresh_sim_off.go":                simOSOff,
			"src/os/gofresh_sim_on.go":                 simOSOn,
			"src/os/getwd.go":                          hookedGetwd,
			"src/os/file_posix.go":                     hookedFilePosix,
			"pkg/include/gofresh_bridge.h":             "#define NOOP_ASM RET\n",
			"src/runtime/gofresh_bridge_benign.s":      "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nTEXT ·gofreshRuntimeAsmNoop(SB),$0-0\n\tNOOP_ASM\n",
			"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
		})
		benignAsmH, err := newAtEnv(ctx, ".", benignAsmEnv, "-tags", "simoverlay")
		if err != nil {
			t.Fatal(err)
		}
		if !benignAsmH.SelectionAudited() {
			t.Fatalf("benign runtime assembly + non-startup off-surface pull refused: %s", benignAsmH.SelectionNotice())
		}
	}
	if cgo {
		_, benignCgoEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
			"src/runtime/gofresh_sim_overlay.go":  simRuntimeClean,
			"src/os/gofresh_sim_off.go":           simOSOff,
			"src/os/gofresh_sim_on.go":            simOSOn,
			"src/os/getwd.go":                     hookedGetwd,
			"src/os/file_posix.go":                hookedFilePosix,
			"src/image/color/gofresh_sim_cgo.go":   "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
			"src/image/color/gofresh_sim_ext.c":    "//go:build simoverlay\n\nvoid gofreshBenignC(void) {}\n",
			"src/runtime/cgo/gofresh_bridge.h":     "#define BENIGN_STR(x) #x\n",
			"src/runtime/cgo/gofresh_bridge_ok.c":  "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nconst char *gofreshBenignRuntimeCgo(void) { return BENIGN_STR(ok); }\n",
		})
		benignCgoH, err := newAtEnv(ctx, ".", benignCgoEnv, "-tags", "simoverlay")
		if err != nil {
			t.Fatal(err)
		}
		if !benignCgoH.SelectionAudited() {
			t.Fatalf("benign off-surface cgo C file refused: %s", benignCgoH.SelectionNotice())
		}
	}

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
		files := map[string]string{
			"src/runtime/gofresh_sim_overlay.go": simRuntimeClean,
			"src/os/gofresh_sim_off.go":          simOSOff,
			"src/os/gofresh_sim_on.go":           simOSOn,
			"src/os/getwd.go":                    hookedGetwd,
			"src/os/file_posix.go":               hookedFilePosix,
		}
		for k, v := range tc.files {
			files[k] = v
		}
		_, env := testenv.OverlayGOROOTEnv(t, environmentWith(), files)
		h, err := newAtEnv(ctx, ".", env, "-tags", "simoverlay")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "os") {
			t.Fatalf("%s: audited=%v attribution=%q", tc.name, h.SelectionAudited(), h.SelectionAttribution())
		}
	}

	// Off-surface non-startup exported function pulling runtime.gofreshSimEnable via //go:linkname:
	// the toolchain selection remains audited because startup cannot flip the gate, a sibling subject
	// in the same test binary linking image/color remains observable (including over os.Getenv),
	// and any subject calling that off-surface function is refused at both tiers.
	_, simOffSurfFnEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go":     simRuntimeClean,
		"src/os/gofresh_sim_off.go":              simOSOff,
		"src/os/gofresh_sim_on.go":               simOSOn,
		"src/os/getwd.go":                        hookedGetwd,
		"src/os/file_posix.go":                   hookedFilePosix,
		"src/image/color/gofresh_sim_trigger.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc ActivateSim() { gofreshPullEnable() }\n",
	})
	modDir := t.TempDir()
	writeTree(t, modDir, map[string]string{
		"go.mod": "module example.com/offsurface\n\ngo 1.24\n",
		"sub_test.go": `package offsurface

import (
	"image/color"
	"os"
	"strings"
	"testing"
)

func TestCallsOffSurfaceTrigger(t *testing.T) {
	color.ActivateSim()
}

func TestCleanOffSurfaceSibling(t *testing.T) {
	_ = os.Getenv("GOFRESH_OFFSURFACE_CLEAN")
	if strings.TrimSpace(" ok ") != "ok" {
		t.Fatal("unexpected trim result")
	}
}
`,
	})
	modView, err := newAtEnv(ctx, modDir, simOffSurfFnEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !modView.SelectionAudited() {
		t.Fatalf("off-surface non-startup trigger unexpectedly invalidated selection: %s", modView.SelectionNotice())
	}
	trigSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCallsOffSurfaceTrigger"}
	cleanSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCleanOffSurfaceSibling"}
	obs, err := modView.ComputeObservabilityBatch([]Subject{trigSubj, cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs[trigSubj].Observable {
		t.Fatalf("subject calling off-surface gate activator admitted as observable: %+v", obs[trigSubj])
	}
	t2Trig, _, err := computeTier2ResultAndReach(modView, trigSubj.Package, trigSubj.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	if !t2Trig.unverifiable {
		t.Fatalf("tier2 admitted subject calling off-surface gate activator: %+v", t2Trig)
	}
	if !obs[cleanSubj].Observable {
		t.Fatalf("clean sibling subject in off-surface test refused: %+v", obs[cleanSubj])
	}
}

func TestHarnessPremisePackagesAreSurfaceSeedsAndVerified(t *testing.T) {
	for _, p := range []string{"internal/testlog", "testing", "testing/internal/testdeps"} {
		if !slices.Contains(auditedSurfaceTables(), p) || !slices.Contains(harnessPremisePackages, p) {
			t.Errorf("the harness premise package %s is not a surface seed", p)
		}
	}
	for _, version := range []string{"go1.27.1-dst.13", "go1.27.2-dst.15", "go1.28.0-dst.99"} {
		d := sourceDigests{Packages: map[string]string{"testing": "unlisted-content"}}
		if toolchainSourceDegradation(version, d, nil).audited() {
			t.Fatalf("version %q admitted unverified harness content", version)
		}
	}
}

// TestListingScopeFollowsTheSurfaceRule pins the listing memo's scope
// against the surface rule (REQ-closure-observability-toolchain-key's
// listing memo): the scope carries the surface seeds' digest, so two
// seed lists — the rule before and after a seed joins — make two scopes
// and a warm record of the old surface is never served to the new
// rule; the same list makes the same scope.
func TestListingScopeFollowsTheSurfaceRule(t *testing.T) {
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), ".", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	before := []string{"runtime", "sync/atomic", "testing"}
	after := []string{"runtime", "sync/atomic", "testing", "testing/internal/testdeps"}
	if a, b := toolchainSourceScope(snapshot, nil, before), toolchainSourceScope(snapshot, nil, after); a == b {
		t.Fatalf("a seed joining the surface kept the listing scope %q", a)
	}
	if a, b := toolchainSourceScope(snapshot, nil, after), toolchainSourceScope(snapshot, nil, slices.Clone(after)); a != b {
		t.Fatalf("the same seeds made two scopes: %q vs %q", a, b)
	}
	if a, b := toolchainSourceScope(snapshot, nil, surfaceSeeds()), toolchainSourceScope(snapshot, nil, before); a == b {
		t.Fatalf("the live seeds scope as a three-seed rule: %q", a)
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
