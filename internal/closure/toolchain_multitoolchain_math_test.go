package closure

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
	"github.com/greatliontech/gofresh/internal/gotool"
)

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
	candidates := []string{
		"/usr/bin/go",
		"/home/nikolas/.local/godst/go1.27.2-dst.15/go/bin/go",
		"/home/nikolas/.local/godst/go1.27.4-dst.17/go/bin/go",
	}
	if p, err := exec.LookPath("go"); err == nil {
		candidates = append(candidates, p)
	}
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

func envWithGoBinAndTarget(baseEnv []string, goBin, goos, goarch string) []string {
	binDir := filepath.Dir(goBin)
	gorootOut, err := exec.Command(goBin, "env", "GOROOT").Output()
	goroot := strings.TrimSpace(string(gorootOut))
	var out []string
	var origPath string
	for _, kv := range baseEnv {
		switch {
		case strings.HasPrefix(kv, "GOROOT="),
			strings.HasPrefix(kv, "GOOS="),
			strings.HasPrefix(kv, "GOARCH="),
			strings.HasPrefix(kv, "GOFLAGS="),
			strings.HasPrefix(kv, "CGO_ENABLED="):
			continue
		case strings.HasPrefix(kv, "PATH="):
			origPath = strings.TrimPrefix(kv, "PATH=")
		default:
			out = append(out, kv)
		}
	}
	newPath := binDir
	if origPath != "" {
		newPath += string(os.PathListSeparator) + origPath
	}
	out = append(out, "PATH="+newPath, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	if err == nil && goroot != "" {
		out = append(out, "GOROOT="+goroot)
	}
	return out
}

func TestMultiToolchainSelectionAuditAndRuntimeDebug(t *testing.T) {
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
			// Verify real GOROOT runtime/debug package AST + assembly and runtime modinfo AST.
			dbgDir := filepath.Join(goroot, "src", "runtime", "debug")
			dbgFiles, dbgSrcs, dbgAsms := parseTestPackageDirGoAndAsm(t, dbgDir)
			if err := toolchain.VerifyRuntimeDebugPackage(ctx, dbgFiles, dbgSrcs, dbgAsms, nil); err != nil {
				t.Fatalf("%s: VerifyRuntimeDebugPackage(%s): %v", verLabel, dbgDir, err)
			}
			rtDir := filepath.Join(goroot, "src", "runtime")
			rtFiles, rtSrcs, _ := parseTestPackageDirGoAndAsm(t, rtDir)
			if err := toolchain.VerifyRuntimeModinfoAST(rtFiles, rtSrcs, nil); err != nil {
				t.Fatalf("%s: VerifyRuntimeModinfoAST(%s): %v", verLabel, rtDir, err)
			}

			for _, tgt := range targets {
				name := tgt.goos + "_" + tgt.goarch
				if len(tgt.flags) > 0 {
					name += "_dst"
				}
				t.Run(name, func(t *testing.T) {
					env := envWithGoBinAndTarget(baseEnv, goBin, tgt.goos, tgt.goarch)
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

func TestMathTwoTierAdmissionsAcrossArchitectures(t *testing.T) {
	ctx := context.Background()
	modDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte("module example.com/mathtiers\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgSrc := `package mathtiers

import "math"

func UseTier1Exact(x float64) float64 {
	b := math.Float64bits(x)
	y := math.Float64frombits(b)
	return math.Abs(y) + math.Floor(y) + math.Ceil(y) + math.Sqrt(math.Pi) + math.Pow10(2) + math.RoundToEven(y)
}

func UseTier2Transcendental(x float64) float64 {
	return math.Sin(x) + math.Cos(x) + math.Log(x) + math.Atan2(x, 1.0) + math.J0(x)
}

func UseTier2SincosExp2(x float64) float64 {
	s, c := math.Sincos(x)
	return s + c + math.Exp2(x)
}

func UseExpAndPow(x float64) float64 {
	return math.Exp(x) + math.Pow(x, 2.0) + math.Gamma(x)
}

func UseIntrinsicFMA(x, y, z float64) float64 {
	return math.FMA(x, y, z)
}
`
	if err := os.WriteFile(filepath.Join(modDir, "mathtiers.go"), []byte(pkgSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	baseEnv := os.Environ()

	// Tier-1 MaximalClosure: UseTier1Exact alone is Verifiable; adding Sin/Exp/FMA is Unverifiable at Tier 1.
	t.Run("tier1_maximal_exact_only", func(t *testing.T) {
		tier1Dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tier1Dir, "go.mod"), []byte("module example.com/exactonly\n\ngo 1.24\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		exactSrc := `package exactonly

import "math"

func Exact(x float64) float64 {
	return math.Copysign(math.Hypot(x, math.E), -1) + math.Trunc(x) + math.Mod(x, 2) + math.Remainder(x, 2)
}
`
		if err := os.WriteFile(filepath.Join(tier1Dir, "exact.go"), []byte(exactSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		env := envWithGoBinAndTarget(baseEnv, goBin, "linux", "amd64")
		reader := &gotool.EnvReader{
			Runner: gotool.Runner{Prepare: func(cmd *exec.Cmd) { cmd.Path = goBin }},
			Dir:    tier1Dir,
			Env:    env,
		}
		h, err := NewAt(ctx, reader)
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		exactSubj := Subject{Package: "example.com/exactonly", Symbol: "Exact"}
		maxMap, _, err := h.ComputeMaximalBatch([]Subject{exactSubj})
		if err != nil {
			t.Fatalf("ComputeMaximalBatch: %v", err)
		}
		res := maxMap[exactSubj]
		if res.Unverifiable {
			t.Fatalf("expected Tier-1 exact math package to be verifiable, got reason=%q", res.Reason)
		}
	})

	archExpectations := []struct {
		goarch              string
		wantTranscendental  bool // Sin, Cos, Log, Atan2, J0
		wantSincosExp2      bool // Sincos, Exp2
		wantExpPow          bool // Exp, Pow, Gamma
		wantIntrinsicFMA    bool // FMA (always false!)
	}{
		{
			goarch:             "amd64",
			wantTranscendental: true,
			wantSincosExp2:     true,
			wantExpPow:         false, // archExp reads runtime internal/cpu useFMA
			wantIntrinsicFMA:   false,
		},
		{
			goarch:             "arm64",
			wantTranscendental: true,
			wantSincosExp2:     true,
			wantExpPow:         true, // arm64 Exp/Pow/Gamma are CPU-feature-free
			wantIntrinsicFMA:   false,
		},
		{
			goarch:             "s390x",
			wantTranscendental: false, // stubs_s390x.s reads hasVX and writes *vectorfacility
			wantSincosExp2:     true,  // Sincos and Exp2 are pure Go on s390x
			wantExpPow:         false,
			wantIntrinsicFMA:   false,
		},
	}

	subjects := []Subject{
		{Package: "example.com/mathtiers", Symbol: "UseTier1Exact"},
		{Package: "example.com/mathtiers", Symbol: "UseTier2Transcendental"},
		{Package: "example.com/mathtiers", Symbol: "UseTier2SincosExp2"},
		{Package: "example.com/mathtiers", Symbol: "UseExpAndPow"},
		{Package: "example.com/mathtiers", Symbol: "UseIntrinsicFMA"},
	}

	for _, tc := range archExpectations {
		t.Run(tc.goarch, func(t *testing.T) {
			env := envWithGoBinAndTarget(baseEnv, goBin, "linux", tc.goarch)
			reader := &gotool.EnvReader{
				Runner: gotool.Runner{Prepare: func(cmd *exec.Cmd) { cmd.Path = goBin }},
				Dir:    modDir,
				Env:    env,
			}
			h, err := NewAt(ctx, reader)
			if err != nil {
				t.Fatalf("NewAt(%s): %v", tc.goarch, err)
			}
			if !h.SelectionAudited() {
				t.Fatalf("SelectionAudited(%s) = false: %s", tc.goarch, h.SelectionNotice())
			}

			// Whole-package MaximalClosure must refuse mathtiers because it calls Sin/Exp/FMA.
			maxMap, _, err := h.ComputeMaximalBatch(subjects[:1])
			if err != nil {
				t.Fatalf("ComputeMaximalBatch(%s): %v", tc.goarch, err)
			}
			if !maxMap[subjects[0]].Unverifiable {
				t.Fatalf("ComputeMaximalBatch(%s): expected Unverifiable=true on package calling Sin/Exp/FMA", tc.goarch)
			}

			obsMap, err := h.ComputeObservabilityBatch(subjects)
			if err != nil {
				t.Fatalf("ComputeObservabilityBatch(%s): %v", tc.goarch, err)
			}
			wantBySym := map[string]bool{
				"UseTier1Exact":          true,
				"UseTier2Transcendental": tc.wantTranscendental,
				"UseTier2SincosExp2":     tc.wantSincosExp2,
				"UseExpAndPow":           tc.wantExpPow,
				"UseIntrinsicFMA":        tc.wantIntrinsicFMA,
			}
			for _, subj := range subjects {
				obs := obsMap[subj]
				want := wantBySym[subj.Symbol]
				if obs.Observable != want {
					t.Fatalf("%s/%s: Observable=%v (reason=%q), want %v", tc.goarch, subj.Symbol, obs.Observable, obs.Reason, want)
				}
			}

			// Verify FMA is never present in h.source.pureDelegates.
			if slices.Contains(sortedKeys(h.source.pureDelegates), "math:FMA") {
				t.Fatalf("%s: math:FMA must never be admitted into pureDelegates", tc.goarch)
			}
		})
	}
}
