package buildflags

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"pgregory.net/rapid"
)

func TestValidateRejectsOverlay(t *testing.T) {
	for _, flags := range [][]string{
		{"-overlay=overlay.json"}, {"-overlay", "overlay.json"},
		{"--overlay=overlay.json"}, {"--overlay", "overlay.json"},
	} {
		if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, t.TempDir(), os.Environ()), flags); err == nil || !strings.Contains(err.Error(), "-overlay") {
			t.Fatalf("Validate(%v) = %v, want overlay refusal", flags, err)
		}
	}
}

func TestValidateRejectsPersistentOverlay(t *testing.T) {
	dir := t.TempDir()
	goenv := filepath.Join(dir, "goenv")
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-overlay=overlay.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOFLAGS", "")

	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), []string{"-tags=special"}); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("Validate with persistent overlay = %v, want refusal", err)
	}
}

func TestValidateHandlesQuotedAndMalformedGOFLAGS(t *testing.T) {
	dir := t.TempDir()
	// A quoted flag value containing "-overlay=foo" as a substring of another
	// flag's argument is not an overlay flag.
	envNonOverlay := gotool.SetEnv(os.Environ(), "GOFLAGS", `"-ldflags=-X main.v=-overlay=foo"`)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envNonOverlay), nil); err != nil {
		t.Fatalf("Validate(quoted non-overlay GOFLAGS) = %v, want nil", err)
	}

	// A quoted overlay flag with spaces in its path is still rejected.
	envQuotedOverlay := gotool.SetEnv(os.Environ(), "GOFLAGS", `"-overlay=/tmp/with space/overlay.json"`)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envQuotedOverlay), nil); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("Validate(quoted overlay GOFLAGS) = %v, want overlay refusal", err)
	}

	// Malformed quoting in GOFLAGS recorded in an EnvSnapshot is rejected.
	shimDir := t.TempDir()
	shimPath := filepath.Join(shimDir, "go")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\nprintf '{\"GOVERSION\":\"go1.26.0\",\"GOFLAGS\":\"'\"'\"'-tags=unterminated\"}\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	envMalformed := gotool.SetEnv(os.Environ(), "PATH", shimDir)
	if err := Validate(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, envMalformed), nil); err == nil || !strings.Contains(err.Error(), "parse GOFLAGS") {
		t.Fatalf("Validate(malformed GOFLAGS) = %v, want parse GOFLAGS error", err)
	}
}

type oracleBuildVCSFlag string

func (f *oracleBuildVCSFlag) IsBoolFlag() bool { return true }
func (f *oracleBuildVCSFlag) String() string   { return string(*f) }
func (f *oracleBuildVCSFlag) Set(s string) error {
	if s == "auto" {
		*f = "auto"
		return nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("neither auto nor bool")
	}
	*f = oracleBuildVCSFlag(strconv.FormatBool(b))
	return nil
}

func oracleEffectiveBuildVCS(goFlagsParsed, explicit []string) (string, error) {
	mode := oracleBuildVCSFlag("auto")
	newFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("build", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Var(&mode, "buildvcs", "")
		fs.Bool("race", false, "")
		fs.Bool("trimpath", false, "")
		fs.Bool("v", false, "")
		fs.String("ldflags", "", "")
		fs.String("gcflags", "", "")
		fs.String("tags", "", "")
		fs.Int("p", 1, "")
		return fs
	}
	for _, gf := range goFlagsParsed {
		if gf == "--" {
			break
		}
		if err := newFS().Parse([]string{gf}); err != nil {
			return "", err
		}
	}
	if err := newFS().Parse(explicit); err != nil {
		return "", err
	}
	return string(mode), nil
}

func TestEffectiveBuildVCSMatrix(t *testing.T) {
	cases := []struct {
		name       string
		goflagsEnv string
		explicit   []string
		want       string
		wantErr    bool
	}{
		{"default_empty", "", nil, "auto", false},
		{"bare_single_dash_in_goflags", "-buildvcs", nil, "true", false},
		{"bare_double_dash_in_explicit", "", []string{"--buildvcs"}, "true", false},
		{"bare_does_not_consume_next_arg", "", []string{"-buildvcs", "false"}, "true", false},
		{"explicit_false_overrides_goflags_true", "-buildvcs=1", []string{"-buildvcs=0"}, "false", false},
		{"explicit_auto_overrides_goflags_false", "--buildvcs=false", []string{"--buildvcs=auto"}, "auto", false},
		{"canonical_bool_spellings", "-buildvcs=TRUE", []string{"-buildvcs=FALSE"}, "false", false},
		{"canonical_bool_true_spelling", "-buildvcs=FALSE", []string{"-buildvcs=t"}, "true", false},
		{"stops_at_double_dash_in_goflags", "-buildvcs=false -- -buildvcs=true", nil, "false", false},
		{"stops_at_double_dash_in_explicit", "-buildvcs=false", []string{"--", "-buildvcs=true"}, "false", false},
		{"quoted_ldflags_in_goflags_ignored", `"-ldflags=-X main.v=-buildvcs=false"`, nil, "auto", false},
		{"separate_arg_ldflags_in_explicit_not_spoofed", "", []string{"-ldflags", "-buildvcs=false"}, "auto", false},
		{"separate_arg_double_dash_gcflags_in_explicit", "-buildvcs=true", []string{"--gcflags", "-buildvcs=false"}, "true", false},
		{"invalid_value_rejected", "", []string{"-buildvcs=maybe"}, "", true},
		{"empty_value_rejected", "", []string{"-buildvcs="}, "", true},
		{"invalid_goflags_value_rejected", "-buildvcs=bogus", []string{"-buildvcs=false"}, "", true},
		{"malformed_goflags_quote_rejected", `'-buildvcs=false`, nil, "", true},
		{"triple_dash_buildvcs_rejected", "", []string{"---buildvcs=false"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EffectiveBuildVCS(tc.goflagsEnv, tc.explicit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("EffectiveBuildVCS(%q, %v) = %q, nil; want error", tc.goflagsEnv, tc.explicit, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("EffectiveBuildVCS(%q, %v) = (%q, %v), want (%q, nil)", tc.goflagsEnv, tc.explicit, got, err, tc.want)
			}
		})
	}
}

func TestPropertyEffectiveBuildVCSMatchesFlagSetOracle(t *testing.T) {
	goFlagGen := rapid.SampledFrom([]string{
		"-race", "-trimpath", `-ldflags=-s -w`, "-tags=netgo",
		"-buildvcs", "--buildvcs",
		"-buildvcs=auto", "--buildvcs=auto",
		"-buildvcs=true", "-buildvcs=false", "-buildvcs=1", "-buildvcs=0",
		"-buildvcs=TRUE", "--buildvcs=FALSE",
		"-buildvcs=invalid", "-buildvcs=", "---buildvcs=false",
	})
	explicitAtomGen := rapid.OneOf(
		rapid.Map(goFlagGen, func(s string) []string { return []string{s} }),
		rapid.SampledFrom([][]string{
			{"--"},
			{"-ldflags", "-buildvcs=false"},
			{"--gcflags", "-buildvcs"},
			{"-tags", "purego"},
			{"-p", "4"},
		}),
	)
	rapid.Check(t, func(rt *rapid.T) {
		gfSlice := rapid.SliceOfN(goFlagGen, 0, 5).Draw(rt, "goFlags")
		goFlagsEnv, err := Join(gfSlice)
		if err != nil {
			rt.Fatalf("Join(%v): %v", gfSlice, err)
		}
		expChunks := rapid.SliceOfN(explicitAtomGen, 0, 5).Draw(rt, "explicit")
		var explicit []string
		for _, ch := range expChunks {
			explicit = append(explicit, ch...)
		}
		got, gotErr := EffectiveBuildVCS(goFlagsEnv, explicit)
		want, wantErr := oracleEffectiveBuildVCS(gfSlice, explicit)
		if (gotErr != nil) != (wantErr != nil) {
			rt.Fatalf("error mismatch for GOFLAGS=%q explicit=%v: got (%q, %v), oracle (%q, %v)", goFlagsEnv, explicit, got, gotErr, want, wantErr)
		}
		if gotErr == nil && got != want {
			rt.Fatalf("mode mismatch for GOFLAGS=%q explicit=%v: got %q, oracle %q", goFlagsEnv, explicit, got, want)
		}
	})
}

func FuzzEffectiveBuildVCS(f *testing.F) {
	f.Add("", "-buildvcs=false", "-race")
	f.Add("-buildvcs", "--", "-buildvcs=false")
	f.Add(`"-ldflags=-X main.x=-buildvcs=false"`, "-ldflags", "-buildvcs=false")
	f.Add("'-buildvcs=unterminated", "", "")
	f.Add("--buildvcs=auto", "---buildvcs", "")
	f.Fuzz(func(t *testing.T, goflagsEnv, exp1, exp2 string) {
		var explicit []string
		if exp1 != "" {
			explicit = append(explicit, exp1)
		}
		if exp2 != "" {
			explicit = append(explicit, exp2)
		}
		got, err := EffectiveBuildVCS(goflagsEnv, explicit)
		if err == nil && got != "auto" && got != "true" && got != "false" {
			t.Fatalf("EffectiveBuildVCS(%q, %v) returned non-canonical value %q", goflagsEnv, explicit, got)
		}
	})
}
