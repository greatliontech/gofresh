package gotool

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestValidateRejectsOverlay(t *testing.T) {
	for _, flags := range [][]string{
		{"-overlay=overlay.json"}, {"-overlay", "overlay.json"},
		{"--overlay=overlay.json"}, {"--overlay", "overlay.json"},
	} {
		if err := ValidateBuildFlags(context.Background(), NewEnvReader(Runner{}, t.TempDir(), os.Environ()), flags); err == nil || !strings.Contains(err.Error(), "-overlay") {
			t.Fatalf("ValidateBuildFlags(%v) = %v, want overlay refusal", flags, err)
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

	if err := ValidateBuildFlags(context.Background(), NewEnvReader(Runner{}, dir, os.Environ()), []string{"-tags=special"}); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("ValidateBuildFlags with persistent overlay = %v, want refusal", err)
	}
}

func TestValidateHandlesQuotedAndMalformedGOFLAGS(t *testing.T) {
	dir := t.TempDir()
	// A quoted flag value containing "-overlay=foo" as a substring of another
	// flag's argument is not an overlay flag.
	envNonOverlay := SetEnv(os.Environ(), "GOFLAGS", `"-ldflags=-X main.v=-overlay=foo"`)
	if err := ValidateBuildFlags(context.Background(), NewEnvReader(Runner{}, dir, envNonOverlay), nil); err != nil {
		t.Fatalf("ValidateBuildFlags(quoted non-overlay GOFLAGS) = %v, want nil", err)
	}

	// A quoted overlay flag with spaces in its path is still rejected.
	envQuotedOverlay := SetEnv(os.Environ(), "GOFLAGS", `"-overlay=/tmp/with space/overlay.json"`)
	if err := ValidateBuildFlags(context.Background(), NewEnvReader(Runner{}, dir, envQuotedOverlay), nil); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("ValidateBuildFlags(quoted overlay GOFLAGS) = %v, want overlay refusal", err)
	}

	// Malformed quoting in GOFLAGS recorded in an EnvSnapshot is rejected.
	shimDir := t.TempDir()
	shimPath := filepath.Join(shimDir, "go")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\nprintf '{\"GOVERSION\":\"go1.26.0\",\"GOFLAGS\":\"'\"'\"'-tags=unterminated\"}\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	envMalformed := SetEnv(os.Environ(), "PATH", shimDir)
	if err := ValidateBuildFlags(context.Background(), NewEnvReader(Runner{}, dir, envMalformed), nil); err == nil || !strings.Contains(err.Error(), "parse GOFLAGS") {
		t.Fatalf("ValidateBuildFlags(malformed GOFLAGS) = %v, want parse GOFLAGS error", err)
	}
}

func TestQuotedFieldsRoundTripAndRefusals(t *testing.T) {
	for _, bad := range []string{`'-tags=x`, `"-ldflags=x`, "a 'b"} {
		if _, err := QuotedFields(bad); err == nil {
			t.Fatalf("QuotedFields(%q) succeeded, want unterminated quote error", bad)
		}
	}
	if _, err := JoinQuotedFields([]string{"bad\x00nul"}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("JoinQuotedFields(NUL) = %v, want NUL refusal", err)
	}
	if _, err := JoinQuotedFields([]string{`both ' and " with space`}); err == nil {
		t.Fatal("JoinQuotedFields(mixed quotes) succeeded, want refusal")
	}
	rapid.Check(t, func(rt *rapid.T) {
		fields := rapid.SliceOfN(rapid.SampledFrom([]string{
			"", "-race", "plain", "two words", `has 'single'`, `has "double"`, "'leading", `"leading`, "line\nbreak",
		}), 0, 6).Draw(rt, "fields")
		joined, err := JoinQuotedFields(fields)
		if err != nil {
			rt.Fatalf("JoinQuotedFields(%q): %v", fields, err)
		}
		got, err := QuotedFields(joined)
		if err != nil {
			rt.Fatalf("QuotedFields(%q): %v", joined, err)
		}
		if !slices.Equal(got, fields) {
			rt.Fatalf("round-trip mismatch: got %q, want %q (joined %q)", got, fields, joined)
		}
	})
}

func FuzzQuotedFields(f *testing.F) {
	f.Add("")
	f.Add("-race -trimpath")
	f.Add(`'-ldflags=-X main.v="1 2"' "two words"`)
	f.Add("'-unterminated")
	f.Add("a\x00b")
	f.Fuzz(func(t *testing.T, text string) {
		fields1, err1 := QuotedFields(text)
		fields2, err2 := QuotedFields(text)
		if (err1 != nil) != (err2 != nil) || !slices.Equal(fields1, fields2) {
			t.Fatalf("QuotedFields non-deterministic on %q", text)
		}
		if err1 != nil {
			return
		}
		joined, jerr := JoinQuotedFields(fields1)
		if jerr != nil {
			return
		}
		back, berr := QuotedFields(joined)
		if berr != nil || !slices.Equal(back, fields1) {
			t.Fatalf("QuotedFields(JoinQuotedFields(%q)) = (%q, %v)", fields1, back, berr)
		}
	})
}

// oracleBuildVCSFlag mirrors cmd/go/internal/work/build.go's buildvcsFlag.
type oracleBuildVCSFlag string

func (f *oracleBuildVCSFlag) IsBoolFlag() bool { return true }
func (f *oracleBuildVCSFlag) String() string   { return string(*f) }
func (f *oracleBuildVCSFlag) Set(s string) error {
	if s == "" || s == "auto" {
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

// oracleEffectiveBuildVCS mirrors cmd/go's InitGOFLAGS + SetFromGOFLAGS +
// FlagSet.Parse over AddBuildFlags.
func oracleEffectiveBuildVCS(goFlagsParsed, explicit []string) (string, error) {
	mode := oracleBuildVCSFlag("auto")
	newFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("build", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Var(&mode, "buildvcs", "")
		fs.Bool("race", false, "")
		fs.Bool("trimpath", false, "")
		fs.Bool("artifacts", false, "")
		fs.Bool("retracted", false, "")
		fs.Bool("v", false, "")
		fs.String("ldflags", "", "")
		fs.String("gcflags", "", "")
		fs.String("tags", "", "")
		fs.String("debug-actiongraph", "", "")
		fs.String("debug-runtime-trace", "", "")
		fs.String("debug-trace", "", "")
		fs.String("f", "", "")
		fs.String("reuse", "", "")
		fs.String("outputdir", "", "")
		fs.Int("p", 1, "")
		fs.Int("parallel", 1, "")
		return fs
	}
	checkFS := newFS()
	for _, gf := range goFlagsParsed {
		if !strings.HasPrefix(gf, "-") || gf == "-" || gf == "--" ||
			strings.HasPrefix(gf, "---") || strings.HasPrefix(gf, "-=") || strings.HasPrefix(gf, "--=") {
			return "", fmt.Errorf("non-flag in GOFLAGS: %q", gf)
		}
		name, val, hasValue := gf, "", false
		if eq := strings.IndexByte(gf, '='); eq >= 0 {
			name, val, hasValue = gf[:eq], gf[eq+1:], true
		}
		if strings.HasPrefix(name, "--") {
			name = name[1:]
		}
		f := checkFS.Lookup(name[1:])
		if f == nil {
			continue
		}
		type boolFlag interface {
			flag.Value
			IsBoolFlag() bool
		}
		if fb, ok := f.Value.(boolFlag); ok && fb.IsBoolFlag() {
			if hasValue {
				if err := checkFS.Set(f.Name, val); err != nil {
					return "", err
				}
			} else if err := checkFS.Set(f.Name, "true"); err != nil {
				return "", err
			}
		} else {
			if !hasValue {
				return "", fmt.Errorf("flag needs argument in GOFLAGS: %q", gf)
			}
			if err := checkFS.Set(f.Name, val); err != nil {
				return "", err
			}
		}
	}
	if err := checkFS.Parse(explicit); err != nil {
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
		{"bare_does_not_consume_next_arg_and_stops_at_positional", "", []string{"-buildvcs", "false", "-buildvcs=false"}, "true", false},
		{"explicit_false_overrides_goflags_true", "-buildvcs=1", []string{"-buildvcs=0"}, "false", false},
		{"explicit_auto_overrides_goflags_false", "--buildvcs=false", []string{"--buildvcs=auto"}, "auto", false},
		{"empty_equals_value_resolves_to_auto", "-buildvcs=true", []string{"-buildvcs="}, "auto", false},
		{"empty_equals_in_goflags_resolves_to_auto", "-buildvcs=", nil, "auto", false},
		{"canonical_bool_spellings", "-buildvcs=TRUE", []string{"-buildvcs=FALSE"}, "false", false},
		{"canonical_bool_true_spelling", "-buildvcs=FALSE", []string{"-buildvcs=t"}, "true", false},
		{"stops_at_double_dash_in_explicit", "-buildvcs=false", []string{"--", "-buildvcs=true"}, "false", false},
		{"stops_at_single_dash_positional_in_explicit", "-buildvcs=false", []string{"-", "-buildvcs=true"}, "false", false},
		{"quoted_ldflags_in_goflags_ignored", `"-ldflags=-X main.v=-buildvcs=false"`, nil, "auto", false},
		{"separate_arg_ldflags_in_explicit_not_spoofed", "", []string{"-ldflags", "-buildvcs=false"}, "auto", false},
		{"separate_arg_double_dash_gcflags_in_explicit", "-buildvcs=true", []string{"--gcflags", "-buildvcs=false"}, "true", false},
		{"separate_arg_debug_actiongraph_not_spoofed", "-buildvcs=true", []string{"-debug-actiongraph", "-buildvcs=false"}, "true", false},
		{"separate_arg_debug_runtime_trace_not_spoofed", "-buildvcs=true", []string{"-debug-runtime-trace", "-buildvcs=false"}, "true", false},
		{"separate_arg_debug_trace_not_spoofed", "-buildvcs=true", []string{"-debug-trace", "-buildvcs=false"}, "true", false},
		{"separate_arg_list_format_not_spoofed", "-buildvcs=true", []string{"-f", "-buildvcs=false"}, "true", false},
		{"separate_arg_list_reuse_not_spoofed", "-buildvcs=true", []string{"-reuse", "-buildvcs=false"}, "true", false},
		{"separate_arg_test_outputdir_not_spoofed", "-buildvcs=true", []string{"-outputdir", "-buildvcs=false"}, "true", false},
		{"separate_arg_test_parallel_consumes_int", "", []string{"-parallel", "4", "-buildvcs=false"}, "false", false},
		{"other_subcommand_bool_flag_in_goflags_ignored", "-t -cache -artifacts -buildvcs=false", []string{"-artifacts"}, "false", false},
		{"double_dash_in_goflags_rejected", "-buildvcs=false -- -buildvcs=true", nil, "", true},
		{"bare_value_flag_in_goflags_rejected", "-ldflags -buildvcs=false", nil, "", true},
		{"unknown_bare_flag_in_explicit_fails_closed", "-buildvcs=true", []string{"-unknownflag", "-buildvcs=false"}, "", true},
		{"truncated_separate_arg_in_explicit_rejected", "", []string{"-debug-actiongraph"}, "", true},
		{"invalid_value_rejected", "", []string{"-buildvcs=maybe"}, "", true},
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

func TestEffectiveBuildVCSAgreesWithRealCmdGo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/bvcs\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Verify real cmd/go accepts -buildvcs= without error and rejects "--" in GOFLAGS.
	baseEnv, err := NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Runner{}).Run(context.Background(), dir, SetEnv(baseEnv, "GOFLAGS", "-buildvcs="), "list", "-buildvcs=", "."); err != nil {
		t.Fatalf("cmd/go rejected -buildvcs=: %v", err)
	}
	if _, err := (Runner{}).Run(context.Background(), dir, SetEnv(baseEnv, "GOFLAGS", "-t -cache -artifacts -buildvcs=false"), "list", "."); err != nil {
		t.Fatalf("cmd/go rejected cross-subcommand boolean flags in GOFLAGS: %v", err)
	}
	if _, err := (Runner{}).Run(context.Background(), dir, SetEnv(baseEnv, "GOFLAGS", "--"), "list", "."); err == nil {
		t.Fatal("cmd/go accepted '--' inside GOFLAGS")
	}
	graphFile := filepath.Join(t.TempDir(), "-buildvcs=false")
	if _, err := (Runner{}).Run(context.Background(), dir, SetEnv(baseEnv, "GOFLAGS", "-buildvcs=false"), "list", "-debug-actiongraph", graphFile, "."); err != nil {
		t.Fatalf("cmd/go rejected -debug-actiongraph: %v", err)
	}
}

func TestPropertyEffectiveBuildVCSMatchesFlagSetOracle(t *testing.T) {
	goFlagGen := rapid.SampledFrom([]string{
		"-race", "-trimpath", "-artifacts", "-retracted", `-ldflags=-s -w`, "-tags=netgo",
		"-t", "-cache",
		"-buildvcs", "--buildvcs",
		"-buildvcs=", "--buildvcs=",
		"-buildvcs=auto", "--buildvcs=auto",
		"-buildvcs=true", "-buildvcs=false", "-buildvcs=1", "-buildvcs=0",
		"-buildvcs=TRUE", "--buildvcs=FALSE",
		"-buildvcs=invalid", "---buildvcs=false", "--", "-ldflags",
	})
	explicitAtomGen := rapid.OneOf(
		rapid.Map(goFlagGen, func(s string) []string { return []string{s} }),
		rapid.SampledFrom([][]string{
			{"--"},
			{"-"},
			{"./..."},
			{"false"},
			{"-ldflags", "-buildvcs=false"},
			{"--gcflags", "-buildvcs"},
			{"-debug-actiongraph", "-buildvcs=false"},
			{"-debug-runtime-trace", "-buildvcs=true"},
			{"-debug-trace", "-buildvcs=0"},
			{"-f", "-buildvcs=false"},
			{"-reuse", "-buildvcs=false"},
			{"-outputdir", "-buildvcs=false"},
			{"-parallel", "4"},
			{"-tags", "purego"},
			{"-p", "4"},
		}),
	)
	rapid.Check(t, func(rt *rapid.T) {
		gfSlice := rapid.SliceOfN(goFlagGen, 0, 5).Draw(rt, "goFlags")
		goFlagsEnv, err := JoinQuotedFields(gfSlice)
		if err != nil {
			rt.Fatalf("JoinQuotedFields(%v): %v", gfSlice, err)
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
	f.Add("-buildvcs=", "--", "-buildvcs=false")
	f.Add(`"-ldflags=-X main.x=-buildvcs=false"`, "-debug-actiongraph", "-buildvcs=false")
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

func TestParseListingRejectsMalformedStreamsStrayClosersAndLoadErrors(t *testing.T) {
	pkgs, err := ParseListing(strings.NewReader(" \n\t "))
	if err != nil || len(pkgs) != 0 {
		t.Fatalf("empty stream = (%v, %v), want empty nil", pkgs, err)
	}
	valid := `{"ImportPath":"example.com/a","Name":"a","GoFiles":["a.go"]}
{"ImportPath":"example.com/b","Name":"b","Standard":true}`
	pkgs, err = ParseListing(strings.NewReader(valid))
	if err != nil || len(pkgs) != 2 || pkgs[0].ImportPath != "example.com/a" || pkgs[1].ImportPath != "example.com/b" {
		t.Fatalf("valid stream = (%+v, %v)", pkgs, err)
	}
	for _, bad := range []string{
		`null`,
		`[]`,
		`"pkg"`,
		`123`,
		`{"ImportPath":"ok/pkg","Dir":"/x"}` + "\n" + `}{"ImportPath":"bad/pkg","Error":{"Err":"boom"}}`,
		`{"ImportPath":"ok/pkg","Dir":"/x"}` + "\n" + `]`,
		`{"ImportPath":"bad/pkg","Error":{"Err":"cannot find package"}}`,
		`{"ImportPath":"bad/pkg","Error":{"Err":""}}`,
		`{"ImportPath":`,
	} {
		if got, err := ParseListing(strings.NewReader(bad)); err == nil {
			t.Fatalf("ParseListing(%q) = %+v, nil; want fail-closed error", bad, got)
		}
	}
}

func FuzzParseListing(f *testing.F) {
	f.Add(`{"ImportPath":"example.com/a","Name":"a"}`)
	f.Add(`{"ImportPath":"ok"}\n}{"ImportPath":"bad","Error":{"Err":"x"}}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, stream string) {
		p1, e1 := ParseListing(strings.NewReader(stream))
		p2, e2 := ParseListing(strings.NewReader(stream))
		if (e1 != nil) != (e2 != nil) || !reflect.DeepEqual(p1, p2) {
			t.Fatalf("ParseListing non-deterministic on %q", stream)
		}
		if e1 == nil {
			for _, p := range p1 {
				if p.Error != nil {
					t.Fatalf("ParseListing admitted package with Error: %+v", p)
				}
			}
		}
	})
}

func TestListedPackageOwnVariantOfDisambiguatesDirectoryAndTestMain(t *testing.T) {
	const pkg = "example.com/p"
	baseDir := "/repo/p"
	for _, wantTrue := range []ListedPackage{
		{ImportPath: pkg + " [" + pkg + ".test]", Name: "p", ForTest: pkg, Dir: baseDir},
		{ImportPath: pkg + "_test [" + pkg + ".test]", Name: "p_test", ForTest: pkg, Dir: baseDir},
	} {
		if !wantTrue.OwnVariantOf(pkg, baseDir) {
			t.Fatalf("OwnVariantOf(%+v) = false, want true", wantTrue)
		}
	}
	for _, wantFalse := range []ListedPackage{
		{ImportPath: pkg + ".test", Name: "main", ForTest: pkg, Dir: baseDir},
		{ImportPath: pkg + "_test [" + pkg + ".test]", Name: "dep", ForTest: pkg, Dir: "/repo/p_test"},
		{ImportPath: "example.com/dep [" + pkg + ".test]", Name: "dep", ForTest: pkg, Dir: "/repo/dep"},
		{ImportPath: pkg, Name: "p", Dir: baseDir},
	} {
		if wantFalse.OwnVariantOf(pkg, baseDir) {
			t.Fatalf("OwnVariantOf(%+v) = true, want false", wantFalse)
		}
	}
}
