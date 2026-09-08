package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A FlagSet the program itself closes is ordinary state: its
// registrations mark and poison nothing and its Parse is admitted in
// the flow that proves it, while every shape the provenance cannot
// close keeps the mark-and-poison judgment
// (REQ-closure-observability-analysis's FlagSet provenance rule).
func TestClosedFlagSetsAreOrdinaryState(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	h, err := NewAt(dir)
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
