package observability

import (
	"context"

	"go/token"
	"go/types"
	"os"
	"path/filepath"

	"runtime"

	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/auditset"

	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/toolchain"
)

// An unaudited selection degrades every stdlib admission to the
// ordinary fail-closed classification — the same posture as an
// unlisted toolchain — at the admission functions themselves.
func TestUnauditedSelectionDisablesAdmissions(t *testing.T) {
	if auditedStandardSymbol(true, "sync", "Lock") == auditedStandardSymbol(false, "sync", "Lock") {
		t.Error("sync admission ignores the selection verdict")
	}
	if classBPureStandard(true, "fmt", "Sprintf") == classBPureStandard(false, "fmt", "Sprintf") {
		t.Error("class-B admission ignores the selection verdict")
	}
	if isSourceOnlyStandardPackage(true, "bytes") == isSourceOnlyStandardPackage(false, "bytes") {
		t.Error("source-only set ignores the selection verdict")
	}
	if auditedHarnessLogging(true, "testing", "Fatal") == auditedHarnessLogging(false, "testing", "Fatal") {
		t.Error("harness-logging admission ignores the selection verdict")
	}
}

// The end-to-end refusal: a Hasher constructed over an unlisted
// surface — the listing emptied under the test — degrades stdlib
// admissions for real analyses: a subject observable under the listed
// toolchain refuses, with the ordinary fail-closed classification
// carrying the reason (the verdict threads from construction to the
// admission sites, not merely honored as a parameter).
func TestUnlistedSurfaceRefusesObservability(t *testing.T) {
	isolateProofCache(t)
	listed := newInMemoryHasher(t)
	if !listed.SelectionAudited() {
		t.Skipf("running toolchain unlisted (the canary covers it): %s", listed.SelectionNotice())
	}
	subject := Subject{Package: "github.com/greatliontech/gofresh/internal/closure/testdata/observable", Symbol: "TestReadFile"}
	supplyRegisteredFixtures(t, listed, subject.Package)
	listedObs, err := listed.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := listedObs[subject]; !o.Observable {
		t.Fatalf("fixture assumption moved: TestReadFile not observable under the listed toolchain: %+v", o)
	}
	var unlisted *Prover
	var unlistedObs map[Subject]Observability
	toolchain.WithUnverifiedPackageForTest("strings", func() {
		unlisted = newInMemoryHasher(t)
		supplyRegisteredFixtures(t, unlisted, subject.Package)
		if unlisted.SelectionAudited() || !strings.Contains(unlisted.SelectionAttribution(), "moved in") {
			t.Fatalf("an unverified surface admitted: %v %q", unlisted.SelectionAudited(), unlisted.SelectionAttribution())
		}
		unlistedObs, err = unlisted.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
	})
	if o := unlistedObs[subject]; o.Observable {
		t.Fatalf("the unlisted analysis kept the observability proof — the verdict never reached the admission sites: %+v", o)
	}
}

// TestLanguageShapeCanaries runs the language-shape canary corpus
// (testenv.ShapeEntries) through this frontend — load, precise analysis,
// observability — pinning each entry's DISPOSITION, not merely the
// absence of one failure string: a probe showed the
// any-disposition tolerance green over an unjudged shape, so a
// release flipping a disposition in either direction is a red canary
// here. Runs under the CI matrix's next-rc leg like every test.
func TestLanguageShapeCanaries(t *testing.T) {
	for _, entry := range testenv.ShapeEntries() {
		t.Run(entry.Name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range entry.TestFiles() {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			h, err := newAt(dir)
			if err != nil {
				t.Errorf("canary load: %v", err)
				return
			}
			subject := Subject{Package: "example.com/shape", Symbol: "Subject"}
			fixtures := newFixturePrograms(t, h)
			fixtures.supply(t, subject.Package)
			if _, err := computeTier2Result(h, subject.Package, subject.Symbol); err != nil {
				t.Errorf("canary precise analysis: %v", err)
				return
			}
			fixtures.supply(t, subject.Package)
			proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Errorf("canary observability: %v", err)
				return
			}
			proof, ok := proofs[subject]
			if !ok {
				t.Errorf("canary produced no disposition: %+v", proofs)
				return
			}
			if proof.Observable != entry.SubjectObservable {
				t.Errorf("disposition = %+v, corpus pins observable=%v", proof, entry.SubjectObservable)
			}
			if entry.SubjectReason != "" && !strings.Contains(proof.Reason, entry.SubjectReason) {
				t.Errorf("refusal reason %q does not carry the pinned cause %q", proof.Reason, entry.SubjectReason)
			}
			if strings.Contains(proof.Reason, "unsupported analysis shape") {
				t.Errorf("canary refused on an analysis-class failure: %+v", proof)
			}
		})
	}
}

func TestPositionBearingProofMemoTracksSourceSpelling(t *testing.T) {
	cache, dir := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	const source = "package escape\nimport \"flag\"\nvar quiet bool\nfunc register(p *bool) { flag.BoolVar(p, \"memo.quiet\", false, \"fixture\") }\nfunc init() { register(&quiet) }\nfunc Prod() int { return 7 }\n"
	writeTree(t, dir, map[string]string{
		"go.mod":             "module example.com/positions\n\ngo 1.27\n",
		"escape/escape.go":   source,
		"consumer/p.go":      "package consumer\nimport \"example.com/positions/escape\"\nfunc Prod() int { return escape.Prod() }\n",
		"consumer/p_test.go": "package consumer\nimport \"testing\"\nfunc TestProd(t *testing.T) { Prod() }\n",
	})
	subject := Subject{Package: "example.com/positions/consumer", Symbol: "TestProd"}
	read := func() (Closure, Observability, bool) {
		t.Helper()
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		h.SetAnalysisScope(AnalysisScope{ProofStrategy: "position-test", Toolchain: "toolchain", BuildConfig: "build"})
		cls, _, err := h.ComputeMaximalBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return cls[subject], proofs[subject], h.ServedSummary()["observability proof"][subject.Package]
	}
	before, oldProof, served := read()
	if served || oldProof.Observable || !strings.Contains(oldProof.Reason, "escape.go:4:") {
		t.Fatalf("position control: %+v served=%t", oldProof, served)
	}
	if _, unchanged, served := read(); !served || unchanged != oldProof {
		t.Fatal("unchanged proof did not serve identically")
	}
	writeTree(t, dir, map[string]string{"escape/escape.go": strings.Replace(source, "func register", "\n\nfunc register", 1)})
	after, warm, served := read()
	if before.Hash != after.Hash || before.TestVariants != after.TestVariants {
		t.Fatal("layout edit moved public canonical source equivalence")
	}
	if served || warm == oldProof || !strings.Contains(warm.Reason, "escape.go:6:") {
		t.Fatalf("stale position served=%t: %+v", served, warm)
	}
	if err := os.RemoveAll(filepath.Join(cache, "gofresh")); err != nil {
		t.Fatal(err)
	}
	_, cold, served := read()
	if served || cold != warm {
		t.Fatalf("discarded-cache proof differs: warm=%+v cold=%+v", warm, cold)
	}
}

// The FlagSet forms are admitted beside the registration families: a set an
// initializer constructs and registers into package-level storage rides the
// sink judgment through its receiver, and a subject touching none of the
// storage proves observable; a subject-time read of the default set keeps the
// standard-global refusal, and the parsed state readers keep their class
// (REQ-closure-observability-flag-registration's FlagSet forms).
func TestFlagSetFormsRideTheRegistrationJudgment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/flagset\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"customset", "package customset\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customset\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int { return 7 }\n", ""},
		// A package-held set never parsed is proven (every Parse closes
		// vacuously): its storage holds the default forever, ordinary
		// initialized state a subject may read.
		{"customread", "package customread\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customread\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int {\n\tif verbose {\n\t\treturn 1\n\t}\n\treturn 7\n}\n", ""},
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
		// A function-local set registering the function's own local is
		// proven: the storage is that function's, no command line
		// reaches it.
		{"subjectreg", "package subjectreg\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tset := flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\tset.BoolVar(&v, \"v\", false, \"fixture flag\")\n\treturn v\n}\n", ""},
		// The default set replaced by a constructed one is never proven:
		// the standard bodies load flag.CommandLine unscanned, so the
		// package-level families' registrations keep the mark.
		{"defaultreplaceread", "package defaultreplaceread\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc init() {\n\tflag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n\tflag.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
		// The swapped-in set is never proven even as a method-form
		// receiver: the harness parses the command line into whatever
		// flag.CommandLine holds, a load the standard bodies make.
		{"defaultreplacemethod", "package defaultreplacemethod\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc init() {\n\tflag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n\tflag.CommandLine.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
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
	h, err := newAt(dir)
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

// A FlagSet the program itself closes is ordinary state: its
// registrations mark and poison nothing and its Parse is admitted in
// the flow that proves it, while every shape the provenance cannot
// close keeps the mark-and-poison judgment
// (REQ-closure-observability-flag-registration's FlagSet provenance rule).
func TestClosedFlagSetsAreOrdinaryState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/flagprov\n\ngo 1.26\n")
	// An os.Args reference refuses at the file fold before any
	// provenance question, so the command line reaches a set only
	// through the standard bodies — the default set, never proven.
	pkgSet := func(name, parse, subject string) string {
		return "package " + name + "\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"" + name + "\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n" + parse + "}\n\n" + subject + "\n"
	}
	readVerbose := "func Subject() bool { return verbose }"
	cases := []struct{ pkg, source, refusal string }{
		// Package-held set, parsed in init from a literal: the storage
		// is initializer-written package state.
		{"startupclosed", pkgSet("startupclosed", "\t_ = set.Parse([]string{\"-v\"})\n", readVerbose), ""},
		{"startupnil", pkgSet("startupnil", "\t_ = set.Parse(nil)\n", readVerbose), ""},
		{"startupempty", pkgSet("startupempty", "\t_ = set.Parse([]string{})\n", readVerbose), ""},
		// A computed argument is not the program's literal: unproven,
		// so the startup walk refuses Parse by name.
		{"startupcomputed", pkgSet("startupcomputed", "\t_ = set.Parse(args())\n", "func args() []string { return []string{\"-v\"} }\n\n"+readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		{"startupsliced", pkgSet("startupsliced", "\t_ = set.Parse([]string{\"-v\", \"x\"}[:1])\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		// A subject-flow Parse of a package-held set writes package
		// state where the walk cannot see the write: unproven, and Parse
		// keeps its class.
		{"startupparsesubject", pkgSet("startupparsesubject", "", "func Subject() bool {\n\t_ = set.Parse([]string{\"-v\"})\n\treturn verbose\n}"), "flag-registered state"},
		{"startupparseonly", pkgSet("startupparseonly", "", "func Subject() error { return set.Parse([]string{\"-v\"}) }"), "reaches unaudited standard operation flag.Parse"},
		// A site launched as a goroutine or placed in a closure literal
		// is not the initializer's own frame: the write races or
		// outlives the flow that would prove it, so the set stays
		// unproven and the startup walk refuses its Parse by name.
		{"gostartup", pkgSet("gostartup", "\tgo func() { _ = set.Parse([]string{\"-v\"}) }()\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		{"closurestartup", pkgSet("closurestartup", "\tfunc() { _ = set.Parse([]string{\"-v\"}) }()\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		// The holder stored outside initializer flow is a set the
		// initializer does not own.
		{"startupsetup", "package startupsetup\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set *flag.FlagSet\n\nfunc Setup() { set = flag.NewFlagSet(\"s\", flag.ContinueOnError) }\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
		// The value family's package-level storage on a proven set is
		// initializer-written state; the same set left unproven keeps
		// the mark.
		{"startupvalueptr", "package startupvalueptr\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\nvar verbose = set.Bool(\"v\", false, \"fixture flag\")\n\nfunc init() { _ = set.Parse([]string{\"-v\"}) }\n\nfunc Subject() bool { return *verbose }\n", ""},
		{"startupvalueusage", "package startupvalueusage\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\nvar verbose = set.Bool(\"v\", false, \"fixture flag\")\n\nfunc init() { set.Usage = nil }\n\nfunc Subject() bool { return *verbose }\n", "flag-registered state"},
		// Any other use of the set — a field write, an escape into a
		// helper, a second store into the holder — keeps it unproven:
		// Parse-free, so the surviving refusal is the mark itself.
		{"startupusage", pkgSet("startupusage", "\tset.Usage = func() {}\n", readVerbose), "flag-registered state"},
		{"startupescape", pkgSet("startupescape", "\tuse(set)\n", "func use(*flag.FlagSet) {}\n\n"+readVerbose), "flag-registered state"},
		{"startuprestore", pkgSet("startuprestore", "\tset = flag.NewFlagSet(\"again\", flag.ContinueOnError)\n", readVerbose), "flag-registered state"},
		// Function-local set, local storage, literal Parse: the subject's
		// own state in every form.
		{"localclosed", "package localclosed\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", ""},
		{"localvalue", "package localvalue\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tv := fs.Bool(\"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn *v\n}\n", ""},
		{"localstruct", "package localstruct\n\nimport \"flag\"\n\ntype opts struct{ v bool }\n\nfunc Subject() bool {\n\tvar o opts\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&o.v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn o.v\n}\n", ""},
		// A computed argument on a local set keeps the poison.
		{"localcomputed", "package localcomputed\n\nimport \"flag\"\n\nfunc args() []string { return []string{\"-v\"} }\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse(args())\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// A write through the result is the function's own storage.
		{"localwrite", "package localwrite\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tv := fs.Bool(\"v\", false, \"fixture flag\")\n\t*v = true\n\t_ = fs.Parse(nil)\n\treturn *v\n}\n", ""},
		// A goroutine-launched Parse on a local set races the subject.
		{"golocal", "package golocal\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tgo fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The local storage's address held in package state outlives
		// the frame: an escape, poisoned as on every other set.
		{"localescapeaddr", "package localescapeaddr\n\nimport \"flag\"\n\nvar esc *bool\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tesc = &v\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn *esc\n}\n", "BoolVar target is not a package-level variable"},
		// The local storage's address passed to a helper is an escape
		// of the storage alone, the set itself proven.
		{"localescapecall", "package localescapecall\n\nimport \"flag\"\n\nfunc use(*bool) {}\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tuse(&v)\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The result stored into package state keeps the mark.
		{"localvalueglobal", "package localvalueglobal\n\nimport \"flag\"\n\nvar late *bool\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tlate = fs.Bool(\"v\", false, \"fixture flag\")\n\t_ = fs.Parse(nil)\n\treturn *late\n}\n", "flag-registered state"},
		// A local set registering package-level storage: the mark stays
		// on the storage Parse writes in subject flow.
		{"localglobalroot", "package localglobalroot\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn verbose\n}\n", "flag-registered state"},
		// A local set handed to a helper escapes the proving function.
		{"localescape", "package localescape\n\nimport \"flag\"\n\nfunc register(fs *flag.FlagSet, v *bool) { fs.BoolVar(v, \"v\", false, \"fixture flag\") }\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tregister(fs, &v)\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The parsed-state readers keep their class on a proven set.
		{"localreader", "package localreader\n\nimport \"flag\"\n\nfunc Subject() int {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\t_ = fs.Parse([]string{\"a\"})\n\treturn fs.NArg()\n}\n", "reaches unaudited standard operation flag.NArg"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/flagprov/" + tc.pkg, Symbol: "Subject"})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/flagprov/" + tc.pkg, Symbol: "Subject"}]
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

func TestOutcomeInventorySeparatesAdmissionFromDerivation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the immutable environment outcome method is audited for Linux")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/outcomes\n\ngo 1.26\n")
	cases := []struct {
		name, source string
		observable   bool
		supported    bool
	}{
		{"empty", `import "testing"
func TestSubject(t *testing.T) { if 1 + 1 != 2 { t.Fatal("arithmetic") } }`, true, true},
		{"pure", `import "testing"
func TestSubject(t *testing.T) {}`, true, true},
		{"getenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, true, true},
		{"lookup", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.LookupEnv("OUTCOME_VALUE") }`, true, true},
		{"failure", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); t.Error("ordinary failure") }`, true, true},
		{"pacing", `import ("os"; "testing")
func BenchmarkSubject(b *testing.B) { b.ResetTimer(); b.StopTimer(); b.StartTimer(); for b.Loop() { _ = os.Getenv("OUTCOME_VALUE") }; _ = b.N }`, true, true},
		{"subtest", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }) }`, true, true},
		{"subtestfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _, _ = os.ReadFile("input.txt") }) }`, true, false},
		{"file", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mixed", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mainenv", `import ("os"; "testing")
func TestMain(m *testing.M) { _ = os.Getenv("OUTCOME_VALUE"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, true},
		{"mainfile", `import ("os"; "testing")
func TestMain(m *testing.M) { _, _ = os.ReadFile("input.txt"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, false},
		{"initenv", `import ("os"; "testing")
var value = os.Getenv("OUTCOME_VALUE")
func TestSubject(t *testing.T) { _ = value }`, false, false},
		{"mutation", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed"); _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"siblingmutation", `import ("os"; "testing")
func TestOther(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed") }
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"cleanupenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _ = os.Getenv("OUTCOME_VALUE") }) }`, false, false},
		{"cleanupfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _, _ = os.ReadFile("input.txt") }) }`, false, false},
	}
	var subjects []Subject
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.name), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.name+"/subject_test.go", "package "+tc.name+"\n"+tc.source+"\n")
		symbol := "TestSubject"
		if tc.name == "pacing" {
			symbol = "BenchmarkSubject"
		}
		subjects = append(subjects, Subject{Package: "example.com/outcomes/" + tc.name, Symbol: symbol})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !h.SelectionAudited() {
		t.Fatalf("test requires audited toolchain: %s", h.SelectionNotice())
	}
	scope := AnalysisScope{ProofStrategy: "outcome-inventory-test@1", Toolchain: "test-selection", BuildConfig: "build"}
	h.SetAnalysisScope(scope)
	cold, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		proof := cold[subjects[i]]
		wantMethod := ""
		if tc.supported {
			wantMethod = ImmutableEnvironmentOutcomes
		}
		if proof.Observable != tc.observable || proof.OutcomeMethod != wantMethod {
			t.Errorf("%s = %+v; want observable=%t method=%q", tc.name, proof, tc.observable, wantMethod)
		}
	}
	// The cold fill is complete before these independent readers begin. Each
	// reader owns its hasher; the parent keeps the cache home and source stable.
	t.Run("after cold", func(t *testing.T) {
		t.Run("warm", func(t *testing.T) {
			t.Parallel()
			warmHasher, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			warmHasher.SetAnalysisScope(scope)
			warmHasher.OnProgress(func(phase, pkg string) {
				if phase == "load" || phase == "prove" {
					t.Errorf("warm inventory recomputed %s for %s", phase, pkg)
				}
			})
			warm, err := warmHasher.ComputeObservabilityBatch(subjects)
			if err != nil {
				t.Fatal(err)
			}
			for _, subject := range subjects {
				if warm[subject] != cold[subject] {
					t.Errorf("warm %s = %+v; cold %+v", subject.Package, warm[subject], cold[subject])
				}
			}
		})
		// The source model, not the analyzer's host platform, selects the method.
		t.Run("other platform", func(t *testing.T) {
			t.Parallel()
			other, err := newAtEnv(context.Background(), dir, environmentWith("GOOS=plan9", "GOARCH=amd64"))
			if err == nil {
				primeHasherFromDir(t, other, dir)
			}
			if err != nil {
				t.Fatal(err)
			}
			proofs, err := other.ComputeObservabilityBatch(subjects[:3])
			if err != nil {
				t.Fatal(err)
			}
			for subject, proof := range proofs {
				if proof.OutcomeMethod != "" {
					t.Errorf("unaudited outcome platform granted %s: %+v", subject.Symbol, proof)
				}
			}
		})
		// Keep the analyzed Linux snapshot and an empty effect set; independently
		// withdraw the audit verdict so neither the platform guard nor an ordinary
		// external-effect refusal can hide a missing outcome-audit prerequisite.
		t.Run("unaudited", func(t *testing.T) {
			t.Parallel()
			unaudited, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			unaudited.SetSelectionForTest(toolchain.Selection{})
			pure := Subject{Package: "example.com/outcomes/pure", Symbol: "TestSubject"}
			unsupported, err := unaudited.ComputeObservabilityBatch([]Subject{pure})
			if err != nil {
				t.Fatal(err)
			}
			if proof := unsupported[pure]; !proof.Observable || proof.OutcomeMethod != "" {
				t.Fatalf("empty effects under unaudited Linux selection = %+v; want observable without outcome support", proof)
			}
		})
	})
}

func FuzzOutcomeInventoryRejectsUnsupportedEffects(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 2, 1})
	f.Add([]byte{3})
	f.Add([]byte{})
	f.Add([]byte{4, 5, 6})
	f.Add([]byte{4, 7, 6})
	f.Fuzz(func(t *testing.T, grammar []byte) {
		var effects []externalEffect
		want := ImmutableEnvironmentOutcomes
		for _, b := range grammar {
			var effect externalEffect
			switch b % 8 {
			case 0:
				effect, _ = classBEffect("os", "Getenv")
				effect.Observable = true
			case 1:
				effect, _ = classBEffect("os", "LookupEnv")
				effect.Observable = true
			case 2:
				effect, _ = classBEffect("os", "ReadFile")
				effect.Observable = true
				want = ""
			case 3:
				effect, _ = classBEffect("os", "Getenv")
				want = ""
			case 4:
				effect = harnessLoggingEffect("Error")
			case 5:
				pacing := []string{"Loop", "ResetTimer", "StartTimer", "StopTimer", "B.N"}
				effect = harnessPacingEffect(pacing[int(b/8)%len(pacing)])
			case 6:
				effect = harnessSubtestDriverEffect()
			case 7:
				effect, _ = classBEffect("testing", "TempDir")
				effect.Observable = true
				want = ""
			}
			effects = append(effects, effect)
		}
		for split := 0; split <= len(effects); split++ {
			if got := immutableEnvironmentMethod(effects[:split], effects[split:]); got != want {
				t.Fatalf("partition %d of %v gave %q; want %q", split, grammar, got, want)
			}
		}
	})
}

// The observability tier attributes an unaudited selection at the
// batch's return — past the memo, so a cold pass and a warm pass served
// from the memo render the same single attribution — and an audited
// selection attributes nothing (REQ-closure-refusal-channels,
// REQ-closure-observability-memo).
func TestObservabilityRefusalAttributesTheUnauditedSelection(t *testing.T) {
	isolateProofCache(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/attributed\n\ngo 1.26\n",
		"read.go": "package attributed\n\nimport \"os\"\n\nfunc Read(name string) int {\n\tb, _ := os.ReadFile(name)\n\treturn len(b)\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/attributed", Symbol: "Read"}
	probe, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.SelectionAudited() {
		t.Fatalf("audited probe refused: %s", probe.SelectionNotice())
	}
	isolateProofCache(t)

	axis := " (judged under an unaudited toolchain selection: the audited surface of " + runtime.Version() + " moved in 1 keys: strings)"
	toolchain.WithUnverifiedPackageForTest("strings", func() {
		var cold Observability
		for pass, want := range []int{1, 0} {
			h, err := newAt(dir, "-tags=dup")
			if err != nil {
				t.Fatal(err)
			}
			h.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "t", BuildConfig: "badstd"})
			loads := 0
			h.OnProgress(func(phase, _ string) {
				if phase == "load" || phase == "prove" {
					loads++
				}
			})
			proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			if (loads == 0) != (want == 0) {
				t.Fatalf("pass %d emitted %d load/prove events, want %s", pass, loads, map[int]string{1: "a cold derivation", 0: "a memo serve"}[want])
			}
			proof := proofs[subject]
			if proof.Observable || !strings.HasSuffix(proof.Reason, axis) || strings.Count(proof.Reason, "judged under") != 1 {
				t.Fatalf("pass %d under unaudited selection: %+v, want the refusal with the axis appended once", pass, proof)
			}
			if pass == 0 {
				cold = proof
			} else if proof != cold {
				t.Fatalf("warm proof %+v differs from cold %+v", proof, cold)
			}
		}
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if proof := proofs[subject]; strings.Contains(proof.Reason, "judged under") {
		t.Fatalf("audited selection attributed: %+v", proof)
	}
}

func FuzzToolchainFloorLattice(f *testing.F) {
	f.Add("fmt", "Sprint", "//go:linkname a runtime.getAuxv\n", true)
	f.Add("os", "Getenv", "//go:linkname a runtime.unapproved\n", false)
	f.Add("reflect", "DeepEqual", "// normal comment\n", true)
	f.Add("testing", "Fatal", "//go:noescape\n", true)

	f.Fuzz(func(t *testing.T, pkg, sym, commentLine string, audited bool) {
		if classBPureStandard(false, pkg, sym) {
			t.Fatalf("classBPureStandard admitted (%q, %q) when audited=false", pkg, sym)
		}
		if isSourceOnlyStandardPackage(false, pkg) {
			t.Fatalf("isSourceOnlyStandardPackage admitted %q when audited=false", pkg)
		}
		if auditedStandardSymbol(false, pkg, sym) {
			t.Fatalf("auditedStandardSymbol admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedHarnessLogging(false, pkg, sym) {
			t.Fatalf("auditedHarnessLogging admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedHarnessPacing(false, pkg, sym) {
			t.Fatalf("auditedHarnessPacing admitted (%q, %q) when audited=false", pkg, sym)
		}
		if fmtFprintFamily(false, pkg, sym) {
			t.Fatalf("fmtFprintFamily admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedLinknamesOnly(false, commentLine) && strings.Contains(commentLine, "//go:linkname") {
			t.Fatalf("auditedLinknamesOnly admitted %q when audited=false", commentLine)
		}
		gorootEff := symbolExternalEffect(externalEffectUnauditedStandard, "runtime", "GOROOT", "reaches unaudited standard operation runtime.GOROOT")
		gomaxEff := symbolExternalEffect(externalEffectUnauditedStandard, "runtime", "GOMAXPROCS", "reaches unaudited standard operation runtime.GOMAXPROCS")
		if maximalObservabilityBlocker(audited, gorootEff) || !maximalObservabilityBlocker(audited, gomaxEff) {
			t.Fatal("maximalObservabilityBlocker misclassified runtime.GOROOT vs runtime.GOMAXPROCS")
		}
	})
}

func FuzzAuditedStdlibClosure(f *testing.F) {
	f.Add("fmt", "Sprint", true, uint8(0))
	f.Add("os", "Getenv", false, uint8(1))
	f.Add("reflect", "DeepEqual", true, uint8(2))
	f.Add("testing", "Fatal", true, uint8(3))
	f.Add("crypto/rand", "Read", true, uint8(4))

	driver := harnessSubtestDriverForTest(f)
	atomicPkg := types.NewPackage("sync/atomic", "atomic")
	tparam := types.NewTypeParam(types.NewTypeName(token.NoPos, atomicPkg, "T", nil), types.NewInterfaceType(nil, nil))
	atomicGeneric := types.NewNamed(types.NewTypeName(token.NoPos, atomicPkg, "Pointer", nil), types.NewStruct(nil, nil), nil)
	atomicGeneric.SetTypeParams([]*types.TypeParam{tparam})

	f.Fuzz(func(t *testing.T, pkg, sym string, audited bool, choice uint8) {
		if isSourceOnlyStandardPackage(true, pkg) {
			if auditset.AlwaysExternalPackage(pkg) {
				t.Fatalf("package %q is both source-only audited-pure and always-external", pkg)
			}
			if _, ok := classBEffect(pkg, sym); ok {
				t.Fatalf("package %q is source-only audited-pure but has classBEffect for %q", pkg, sym)
			}
		}

		for _, forbiddenReflect := range []string{"ValueOf", "Value", "MakeFunc", "Call", "Method", "MethodByName", "Set", "Pointer", "UnsafePointer"} {
			if classBPureStandard(audited, "reflect", forbiddenReflect) || auditedStandardSymbol(audited, "reflect", forbiddenReflect) {
				t.Fatalf("reflect dispatch/value surface %q was admitted", forbiddenReflect)
			}
		}
		if classBPureStandard(audited, "reflect", "DeepEqual") != audited || classBPureStandard(audited, "reflect", "TypeOf") != audited {
			t.Fatalf("reflect DeepEqual/TypeOf admission did not track audited=%v", audited)
		}
		for _, entropyOp := range []string{"Read", "Text", "Int", "Prime"} {
			eff, ok := classBEffect("crypto/rand", entropyOp)
			if !ok || eff.Kind != externalEffectNative || !strings.Contains(eff.Reason, "(entropy)") || !maximalObservabilityBlocker(audited, eff) {
				t.Fatalf("crypto/rand.%s classification = (%+v, %v), want blocking native entropy effect", entropyOp, eff, ok)
			}
		}
		if isSourceOnlyStandardPackage(audited, "math/rand") || isSourceOnlyStandardPackage(audited, "math/rand/v2") {
			t.Fatal("math/rand or math/rand/v2 admitted as source-only pure standard package")
		}
		fprintEff := symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Fprintf", "reaches fmt.Fprintf")
		if fmtFprintFamily(audited, "fmt", "Println") || fmtFprintFamily(audited, "fmt", "Fprintf") != audited || maximalObservabilityBlocker(audited, fprintEff) != !audited {
			t.Fatalf("fmtFprintFamily / maximalObservabilityBlocker misclassified Println vs Fprintf under audited=%v", audited)
		}
		logOps := []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"}
		if auditedHarnessLogging(audited, "testing", logOps[int(choice)%len(logOps)]) != audited || auditedHarnessLogging(audited, "testing", "Verbose") {
			t.Fatal("auditedHarnessLogging misclassified logging method vs Verbose")
		}
		paceOps := []string{"N", "Loop", "ResetTimer", "StartTimer", "StopTimer"}
		if auditedHarnessPacing(audited, "testing", paceOps[int(choice)%len(paceOps)]) != audited || auditedHarnessPacing(audited, "testing", "Elapsed") {
			t.Fatal("auditedHarnessPacing misclassified pacing vs Elapsed")
		}
		if auditedHarnessSubtestDriver(audited, driver) != audited {
			t.Fatalf("auditedHarnessSubtestDriver(audited=%v) != %v", audited, audited)
		}
		runEff := symbolExternalEffect(externalEffectTestRuntime, "testing", "Run", "reaches testing.Run")
		fuzzEff := symbolExternalEffect(externalEffectTestRuntime, "testing", "Fuzz", "reaches testing.Fuzz")
		if maximalObservabilityBlocker(audited, runEff) || maximalObservabilityBlocker(audited, fuzzEff) {
			t.Fatal("testing.Run or testing.Fuzz blocked at maximal package-scan floor")
		}

		elemType := types.Type(types.Typ[types.Int])
		if choice%2 == 1 {
			elemType = types.Typ[types.String]
		}
		inst, err := types.Instantiate(nil, atomicGeneric, []types.Type{elemType}, false)
		if err != nil {
			t.Fatal(err)
		}
		if elem, ok := refconfine.AuditedAtomicPointerElem(audited, inst.(*types.Named)); ok != audited || (ok && elem != elemType) {
			t.Fatalf("AuditedAtomicPointerElem(%v) = (%v, %v)", audited, elem, ok)
		}
		harnessPkg := types.NewPackage("example.com/propcheck", "propcheck")
		closedCtx := types.NewNamed(
			types.NewTypeName(token.NoPos, harnessPkg, "Context", nil),
			types.NewStruct([]*types.Var{types.NewField(token.NoPos, harnessPkg, "seed", types.Typ[types.Uint64], false)}, nil),
			nil,
		)
		openCtx := types.NewNamed(
			types.NewTypeName(token.NoPos, harnessPkg, "Context", nil),
			types.NewStruct([]*types.Var{types.NewField(token.NoPos, harnessPkg, "Seed", types.Typ[types.Uint64], false)}, nil),
			nil,
		)
		vp := &propharness.VerifiedPackage{
			PkgPath:       "example.com/propcheck",
			PkgName:       "propcheck",
			PrimaryDriver: "Verify",
			HandleStructs: map[string]bool{"Context": true},
		}
		verifiedMap := map[string]*propharness.VerifiedPackage{"example.com/propcheck": vp}
		if !propertyHarnessHandleType(types.NewPointer(closedCtx), verifiedMap) || propertyHarnessHandleType(types.NewPointer(openCtx), verifiedMap) {
			t.Fatal("propertyHarnessHandleType misclassified unexported-field vs exported-field handle struct")
		}
	})
}
