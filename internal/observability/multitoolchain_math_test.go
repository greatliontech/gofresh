package observability

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func TestMathTwoTierAdmissionsAcrossArchitectures(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns cross-target go list std and SSA loads across architectures")
	}
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
		env := testenv.EnvWithGoBinAndTarget(baseEnv, goBin, "linux", "amd64")
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
		goarch             string
		wantTranscendental bool // Sin, Cos, Log, Atan2, J0
		wantSincosExp2     bool // Sincos, Exp2
		wantExpPow         bool // Exp, Pow, Gamma
		wantIntrinsicFMA   bool // FMA (always false!)
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
			env := testenv.EnvWithGoBinAndTarget(baseEnv, goBin, "linux", tc.goarch)
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

			// Verify FMA is never present in h.PureDelegates().
			if h.PureDelegates()["math:FMA"] {
				t.Fatalf("%s: math:FMA must never be admitted into pureDelegates", tc.goarch)
			}
		})
	}
}
