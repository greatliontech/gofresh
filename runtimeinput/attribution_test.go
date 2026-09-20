package runtimeinput

import (
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

// A classification refusal names the observation that produced its path
// (REQ-inputs-refusal-attribution): the operation, its quoted logged
// name, and the quoted working directory it resolved in — the process's
// own directory for every operation, the traversal for a name that
// reaches the root — after the clause and its separator, so a consumer
// matching the class keeps matching; a stat of the root is no refusal
// (REQ-inputs-external-dir-existence).
func TestClassificationRefusalNamesItsObservation(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	depth := strings.Count(filepath.Clean(packageDir), string(filepath.Separator))
	traversal := strings.TrimSuffix(strings.Repeat("../", depth+1), "/")
	log := []byte("open /\n" + "open " + traversal + "\n" + "stat /\n")
	volatile := len(guard.VolatileOSRoots) > 0 // the volatile-OS arm is a Linux shape
	if volatile {
		log = append(log, "stat /proc/stat\n"...)
	}
	log = append(log, "chdir /\n"...) // last: the chdir moves the tracked directory
	state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg := strconv.Quote(packageDir)
	want := []string{
		`external directory input: / — open "/" in ` + pkg,
		`external directory input: / — open ` + strconv.Quote(traversal) + ` in ` + pkg,
		`external directory input: / — chdir "/" in ` + pkg,
		"working-directory change",
	}
	if volatile {
		want = append(want, `volatile OS input: /proc/stat — stat "/proc/stat" in `+pkg)
	}
	got := append([]string(nil), m.Unverifiable...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unverifiable reasons\n got %q\nwant %q", got, want)
	}
	if !state.Unverifiable || !strings.HasPrefix(state.Reason, "external directory input: / — ") {
		t.Fatalf("the state's reason is not the attributed refusal: %q", state.Reason)
	}
	rootBound := false
	for _, id := range m.Paths {
		if id.Path == "/" {
			rootBound = true
		}
	}
	if !rootBound {
		t.Fatalf("the stat of the root bound no existence identity: %+v", m.Paths)
	}
	// No refusal, no attribution: an in-tree open records an identity
	// and adds no reason.
	state, err = FromTestLog([]byte("open fixture.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := decode(state.Manifest); len(m.Unverifiable) != 0 {
		t.Fatalf("an admitted read carried a reason: %q", m.Unverifiable)
	}
	// A working directory the observation refused (non-UTF-8) still
	// attributes representably: the state is unverifiable, never an
	// error (REQ-inputs-observation-disposition).
	state, err = FromTestLog(append(append([]byte("chdir /tmp/"), 0xff), []byte("\nopen ../\n")...), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatalf("a refused working directory made the observation an error: %v", err)
	}
	if !state.Unverifiable {
		t.Fatal("a refused working directory left the observation verifiable")
	}
	m, err = decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	sawQuoted := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, `open "../" in "/tmp/\xff"`) {
			sawQuoted = true
		}
	}
	if !sawQuoted {
		t.Fatalf("the refused directory was not quoted into the attribution: %q", m.Unverifiable)
	}
}

// RefusalClause is the split a consumer keys on: the attribution is the
// one well-formed suffix, so a separator inside a quoted name or
// directory, or inside the refused path of an attributed reason, never
// cuts the clause; a reason with no attribution is its own clause, the
// text channel's one residual (an unattributed path ending in the
// attribution's shape) recorded (REQ-inputs-refusal-attribution).
func TestRefusalClauseSurvivesSeparatorsInNames(t *testing.T) {
	sep := attributionSeparator
	cases := []struct{ reason, clause string }{
		{"external directory input: /" + sep + `open "/" in "/pkg"`, "external directory input: /"},
		{"volatile OS input: /proc/a" + sep + "b" + sep + `stat "/proc/a` + sep + `b" in "/pkg"`, "volatile OS input: /proc/a" + sep + "b"},
		{"external directory input: /" + sep + `open "../" in "/home/me/src/Project` + sep + `old/pkg"`, "external directory input: /"},
		{"external directory input: /x" + sep + `open "a` + sep + `open \"b\" in \"c\"" in "/pkg"`, "external directory input: /x"},
		{"external directory input: /mod/escape" + sep + `recorded path "escape" resolves to "/tmp/out` + sep + `side" outside the tree`, "external directory input: /mod/escape"},
		// A refused path carrying a whole attribution-shaped segment
		// followed by more path: the fake does not run to the end.
		{"external directory input: /x" + sep + `open "a" in "b"/c` + sep + `open "/x` + sep + `open \"a\" in \"b\"/c" in "/pkg"`, "external directory input: /x" + sep + `open "a" in "b"/c`},
		// A refused path carrying an unquoted operation word after a
		// separator: an operation without its quoted name is no suffix.
		{"volatile OS input: /proc/a" + sep + "open b" + sep + `stat "/proc/a` + sep + `open b" in "/pkg"`, "volatile OS input: /proc/a" + sep + "open b"},
		{"unhashable runtime input: /x" + sep + "y", "unhashable runtime input: /x" + sep + "y"},
		{"working-directory change", "working-directory change"},
		// The one residual of the text channel, recorded: an UNATTRIBUTED
		// reason whose refused path itself ends in the attribution's
		// shape — a path deliberately named with a quote — is split.
		{"unhashable runtime input: /x" + sep + `open "a" in "b"`, "unhashable runtime input: /x"},
	}
	for _, c := range cases {
		if got := RefusalClause(c.reason); got != c.clause {
			t.Errorf("RefusalClause(%q) = %q, want %q", c.reason, got, c.clause)
		}
	}
	// The production attribution round-trips through the split for every
	// operation of the one vocabulary; an operation outside it attributes
	// nothing (the reason stays its own clause), so a consumer's clause
	// match never meets an attribution the split cannot parse.
	for _, op := range attributionOps {
		reason := attributed("volatile OS input: /proc/a"+sep+"b", op, "/proc/a"+sep+"b", "/p"+sep+"kg")
		if got := RefusalClause(reason); got != "volatile OS input: /proc/a"+sep+"b" {
			t.Fatalf("the %s attribution does not round-trip: %q -> %q", op, reason, got)
		}
	}
	if got := attributed("external directory input: /", "rename", "/", "/pkg"); got != "external directory input: /" {
		t.Fatalf("an operation outside the vocabulary was attributed: %q", got)
	}
}
