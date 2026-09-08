package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The FlagSet forms are admitted beside the registration families: a
// set an initializer constructs and registers into package-level
// storage rides the sink judgment through its receiver, and a subject
// touching none of the storage proves observable; a subject-time read
// of the default set keeps the standard-global refusal, and the parsed
// state readers keep their class (REQ-closure-observability-analysis's
// FlagSet forms).
func TestFlagSetFormsRideTheRegistrationJudgment(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/flagset\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"customset", "package customset\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customset\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int { return 7 }\n", ""},
		{"customread", "package customread\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customread\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int {\n\tif verbose {\n\t\treturn 1\n\t}\n\treturn 7\n}\n", "flag-registered state"},
		// The fold admits the selector; the walk's standard-global arm
		// refuses the subject-time read of the default set.
		{"defaultread", "package defaultread\n\nimport \"flag\"\n\nfunc Subject() *flag.FlagSet { return flag.CommandLine }\n", "reaches standard global flag.CommandLine"},
		// The parsed-state readers and Parse itself keep their class on
		// either set, refused by name at the walk's call fallback (the
		// fold's selector arm sees only a package-qualified identifier,
		// which these method calls do not spell).
		{"defaultargs", "package defaultargs\n\nimport \"flag\"\n\nfunc Subject() int { return len(flag.CommandLine.Args()) }\n", "reaches unaudited standard operation flag.Args"},
		{"customparse", "package customparse\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"customparse\", flag.ContinueOnError)\n\nfunc Subject() error { return set.Parse(nil) }\n", "reaches unaudited standard operation flag.Parse"},
		{"setname", "package setname\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"setname\", flag.ContinueOnError)\n\nfunc Subject() string { return set.Name() }\n", "reaches unaudited standard operation flag.Name"},
		// Constructing a set is an allocation in every flow; the
		// ErrorHandling accessor rides the constant's name.
		{"subjectnew", "package subjectnew\n\nimport \"flag\"\n\nfunc Subject() flag.ErrorHandling { return flag.NewFlagSet(\"s\", flag.PanicOnError).ErrorHandling() }\n", ""},
		// Subject-flow registration keeps the exclusion whole through
		// the storage judgment: a local target poisons the sink.
		{"subjectreg", "package subjectreg\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tset := flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\tset.BoolVar(&v, \"v\", false, \"fixture flag\")\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// A startup-flow replacement of the default set adds no channel:
		// the storage judgment is per registration call, set-blind.
		{"defaultreplace", "package defaultreplace\n\nimport \"flag\"\n\nfunc init() { flag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError) }\n\nfunc Subject() int { return 7 }\n", ""},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/flagset/" + tc.pkg, Symbol: "Subject"})
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/flagset/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.Contains(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
	}
}
