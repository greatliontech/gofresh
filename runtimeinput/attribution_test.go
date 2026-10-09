package runtimeinput

import (
	"context"
	"os"
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
// reaches the root — after the clause and its separator, on the
// constructed state's attribution (the first refusal's); the manifest
// carries the clause, one entry per distinct clause, and the state's
// reason is the clause, so a consumer matching the class keeps
// matching; a stat of the root is no refusal
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
	want := []string{"external directory input: /", "working-directory change"}
	if volatile {
		want = append(want, "volatile OS input: /proc/stat")
	}
	got := append([]string(nil), m.Unverifiable...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unverifiable reasons\n got %q\nwant %q", got, want)
	}
	if !state.Unverifiable || state.Reason != "external directory input: /" {
		t.Fatalf("the state's reason is not the clause: %q", state.Reason)
	}
	// The first refusal in log order names its observation; the
	// traversal's own attribution names the traversal (pinned below).
	if state.Attribution != `open "/" in `+pkg {
		t.Fatalf("the state's attribution is not the first refusal's observation: %q", state.Attribution)
	}
	traversed, err := FromTestLog([]byte("open "+traversal+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if traversed.Attribution != `open `+strconv.Quote(traversal)+` in `+pkg {
		t.Fatalf("the traversal's attribution = %q", traversed.Attribution)
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
	// The state names the sorted manifest's first clause — the open
	// under the refused directory — and its attribution quotes that
	// directory representably.
	if !strings.Contains(state.Attribution, `open "../" in "/tmp/\xff"`) {
		t.Fatalf("the refused directory was not quoted into the attribution: %q", state.Attribution)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, attributionSeparator) {
			t.Fatalf("an attribution entered the manifest: %q", reason)
		}
	}
}

// The attribution is outside the inputs' identity
// (REQ-inputs-refusal-attribution): one testlog measured from two
// checkouts yields one manifest, one digest, and one reason while the
// attributions name each checkout's own directory; a state derived from
// the recorded manifest reproduces the recorded state whole (the
// attribution lives on the observation, outside the state); a merge and
// the identity conversions carry the attribution of the reason they
// name. The attribution attributes the reason the state names — the
// first clause of the sorted manifest, not the first refusal in log
// order — and a merge whose reason is one contributor's carries that
// contributor's.
func TestAttributionIsOutsideTheInputsIdentity(t *testing.T) {
	log := []byte("open /\nstat /\n")
	var states [2]Observation
	var portables [2]string
	for i := range states {
		moduleDir, packageDir := testDirs(t)
		state, err := FromTestLog(log, moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(state.Attribution, ` in `+strconv.Quote(packageDir)) {
			t.Fatalf("checkout %d: attribution %q does not name its own directory", i, state.Attribution)
		}
		states[i] = state
		derived, err := Current(context.Background(), state.Manifest, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if derived != state.State {
			t.Fatalf("checkout %d: the derived state = %+v, want the recorded state whole", i, derived)
		}
		merged, err := Merge(moduleDir, nil, state, state)
		if err != nil {
			t.Fatal(err)
		}
		if merged.Attribution != state.Attribution || merged.Reason != state.Reason {
			t.Fatalf("checkout %d: the merge carried %q / %q", i, merged.Attribution, merged.Reason)
		}
		absolute, err := Absolute(state, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := Relative(absolute, moduleDir, nil)
		if err != nil {
			t.Fatal(err)
		}
		// A conversion converts the directory the attribution names as
		// it converts the identities: module-relative in the portable
		// form, the process's absolute directory again in the absolute
		// form, the operation and name untouched.
		relPkg, err := filepath.Rel(moduleDir, packageDir)
		if err != nil {
			t.Fatal(err)
		}
		portable := strings.TrimSuffix(state.Attribution, strconv.Quote(packageDir)) + strconv.Quote(filepath.ToSlash(relPkg))
		if absolute.Attribution != state.Attribution || relative.Attribution != portable {
			t.Fatalf("checkout %d: the conversions carried %q / %q, want %q / %q", i, absolute.Attribution, relative.Attribution, state.Attribution, portable)
		}
		if back, err := Absolute(relative, moduleDir, nil); err != nil || back.Attribution != state.Attribution {
			t.Fatalf("checkout %d: the absolute form of the portable attribution = %q, %v", i, back.Attribution, err)
		}
		portables[i] = relative.Attribution
		// A directory outside the module keeps its own spelling in
		// both forms: a refusal attributed after a traversal chdir
		// names the directory it happened in.
		left, err := FromTestLog([]byte("chdir /usr\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if left.Attribution != `open "/" in "/usr"` {
			t.Fatalf("checkout %d: the traversal's attribution = %q", i, left.Attribution)
		}
		if outside, err := Relative(left, moduleDir, nil); err != nil || outside.Attribution != left.Attribution {
			t.Fatalf("checkout %d: the portable form moved an outside directory: %q, %v", i, outside.Attribution, err)
		}
	}
	// The portable form is the same in every checkout.
	if portables[0] != portables[1] {
		t.Fatalf("the portable attributions differ across checkouts: %q / %q", portables[0], portables[1])
	}
	// Two clauses, log order against sorted order: the state names the
	// sorted manifest's first clause and the attribution is that clause's.
	moduleDir, packageDir := testDirs(t)
	ordered, err := FromTestLog([]byte("open /usr\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if ordered.Reason != "external directory input: /" || ordered.Attribution != `open "/" in `+strconv.Quote(packageDir) {
		t.Fatalf("reason %q attributed %q, want the sorted first clause and its own attribution", ordered.Reason, ordered.Attribution)
	}
	// A reason with no attributed refusal carries none, whatever other
	// clause the manifest attributes: the vanished-component traversal
	// sorts first and is no classification refusal.
	unattributed, err := FromTestLog([]byte("open gone/../fixture.txt\nopen /\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(unattributed.Reason, "ambiguous parent traversal") || unattributed.Attribution != "" {
		t.Fatalf("reason %q attributed %q, want the traversal's reason with no attribution", unattributed.Reason, unattributed.Attribution)
	}
	// A merge names the union's first clause and carries the attribution
	// of the contributor whose reason it is, whatever the caller's order.
	usr, err := FromTestLog([]byte("open /usr\n"), moduleDir, packageDir, nil, WithCompletedProcess("usr"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	root, err := FromTestLog([]byte("open /\n"), moduleDir, packageDir, nil, WithCompletedProcess("root"), WithBracket(testBracket(t, moduleDir)))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(moduleDir, nil, usr, root)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Reason != root.Reason || merged.Attribution != root.Attribution {
		t.Fatalf("merge = %q attributed %q, want the root contributor's", merged.Reason, merged.Attribution)
	}
	if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
		t.Fatalf("two checkouts' identities differ:\n%+v\n%+v", states[0].State, states[1].State)
	}
	if states[0].Attribution == states[1].Attribution {
		t.Fatalf("two checkouts' attributions agree: %q", states[0].Attribution)
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
	// The moved-bracket reason: its attribution is the bracketed member
	// list after " [", split from the first bracket whose suffix parses;
	// a bracketed segment that is no member list (a label-less one, an
	// unterminated one, one on another clause) is the reason's own.
	cases = append(cases,
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt, b.txt]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt; removed: b.txt]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [recently touched: a.txt (2026-10-07T00:00:00Z)]", "observation bracket moved: fixtures"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [data]", "observation bracket moved: fixtures [data]"},
		struct{ reason, clause string }{"observation bracket moved: fixtures [added: a.txt", "observation bracket moved: fixtures [added: a.txt"},
		struct{ reason, clause string }{"observation bracket moved", "observation bracket moved"},
		struct{ reason, clause string }{"external directory input: /x [added: y]", "external directory input: /x [added: y]"},
		// The recorded residual: a root whose own name carries the form
		// garbles the clause from that bracket on, the same on both
		// sides of a consumer's match.
		struct{ reason, clause string }{"observation bracket moved: fix [added: x] [removed: y]", "observation bracket moved: fix"},
		// A member carrying the list's own framing travels quoted, so
		// the list stays splittable.
		struct{ reason, clause string }{`observation bracket moved: fixtures [added: "a; b.txt", "c]d.txt"]`, "observation bracket moved: fixtures"},
		// A member carrying a bare quote travels quoted too: bare, it
		// would pair with a later quoted member's opening quote and
		// swallow that member's separator.
		struct{ reason, clause string }{`observation bracket moved: data [added: "a\"b", "x; y"; removed: z]`, "observation bracket moved: data"},
	)
	for _, name := range []string{"a; b.txt", "c]d.txt", "[e.txt", `a"b`} {
		if got := memberListName(name); got != strconv.Quote(name) {
			t.Fatalf("memberListName(%q) = %q, want it quoted: it carries the member list's framing", name, got)
		}
	}
	if got := memberListName("plain.txt"); got != "plain.txt" {
		t.Fatalf("memberListName(plain.txt) = %q", got)
	}
	// The walk's clauses quote for representability alone: a bracketed
	// or quoted name is an ordinary member name there.
	for _, name := range []string{"data/a[1]", `data/a"b`, "data/a; b"} {
		if got := representableReasonName(name); got != name {
			t.Fatalf("representableReasonName(%q) = %q, want it bare: the list's framing rule is the list's alone", name, got)
		}
	}
	if got := representableReasonName("a\x00b"); got != strconv.Quote("a\x00b") {
		t.Fatalf("representableReasonName(a\\x00b) = %q, want it quoted", got)
	}
	for _, c := range cases {
		if got := RefusalClause(c.reason); got != c.clause {
			t.Errorf("RefusalClause(%q) = %q, want %q", c.reason, got, c.clause)
		}
	}
	if got := RefusalAttribution("observation bracket moved: fixtures [added: a.txt; removed: b.txt]"); got != "added: a.txt; removed: b.txt" {
		t.Fatalf("the moved-bracket attribution = %q, want the member list without its brackets", got)
	}
	// The builder's attribution, pasted after a clause, round-trips
	// through the split for every operation of the one vocabulary; an
	// operation outside it attributes nothing (an empty field), so a
	// consumer's clause match never meets an attribution the split
	// cannot parse.
	for _, op := range attributionOps {
		attribution := operationAttribution(op, "/proc/a"+sep+"b", "/p"+sep+"kg")
		reason := "volatile OS input: /proc/a" + sep + "b" + sep + attribution
		if got := RefusalClause(reason); got != "volatile OS input: /proc/a"+sep+"b" {
			t.Fatalf("the %s attribution does not round-trip: %q -> %q", op, reason, got)
		}
		if got := RefusalAttribution(reason); got != attribution {
			t.Fatalf("the %s attribution's complement = %q, want %q", op, got, attribution)
		}
	}
	// The resolved-target producer's shape round-trips the same way.
	resolved := "external runtime input target: /w/pkg/l" + sep + "ink" + sep + resolvedTargetAttribution("pkg/l"+sep+"ink", "/srv"+sep+"x")
	if RefusalClause(resolved) != "external runtime input target: /w/pkg/l"+sep+"ink" || RefusalAttribution(resolved) != resolvedTargetAttribution("pkg/l"+sep+"ink", "/srv"+sep+"x") {
		t.Fatalf("the resolved-target attribution does not round-trip: %q -> %q / %q", resolved, RefusalClause(resolved), RefusalAttribution(resolved))
	}
	if got := operationAttribution("rename", "/", "/pkg"); got != "" {
		t.Fatalf("an operation outside the vocabulary was attributed: %q", got)
	}
}

// RefusalAttribution is RefusalClause's complement over the one split:
// the well-formed suffix without its separator, "" where the reason
// carries none (a malformed tail is no attribution), and the fake
// tail on the text channel's one residual — an unattributed reason
// whose refused path ends in the attribution's shape — exactly as its
// clause is the truncated one (REQ-inputs-refusal-attribution).
func TestRefusalAttributionIsTheClauseSplitsComplement(t *testing.T) {
	sep := attributionSeparator
	for _, c := range []struct{ reason, attribution string }{
		{`external directory input: /srv` + sep + `open "/srv" in "/w/pkg"`, `open "/srv" in "/w/pkg"`},
		{`external runtime input target: /w/pkg/link` + sep + `recorded path "pkg/link" resolves to "/srv/x" outside the tree`, `recorded path "pkg/link" resolves to "/srv/x" outside the tree`},
		{`volatile OS input: /proc/a` + sep + `b`, ""},
		{`external directory input: /srv`, ""},
		{`external directory input: /a` + sep + `b` + sep + `stat "/a" in "/w"`, `stat "/a" in "/w"`},
		{`unhashable runtime input: /x` + sep + `open "a" in "b"`, `open "a" in "b"`},
	} {
		clause, attribution := RefusalClause(c.reason), RefusalAttribution(c.reason)
		if attribution != c.attribution {
			t.Errorf("RefusalAttribution(%q) = %q, want %q", c.reason, attribution, c.attribution)
		}
		if attribution == "" && clause != c.reason {
			t.Errorf("an unattributed reason %q split its clause to %q", c.reason, clause)
		}
		if attribution != "" && clause+sep+attribution != c.reason {
			t.Errorf("the split of %q does not rejoin: clause %q, attribution %q", c.reason, clause, attribution)
		}
	}
}

// The directory conversion rewrites exactly the operation form and
// passes everything else through — a resolved-target attribution, an
// operation form with trailing text, a string no grammar parses —
// never rewriting a value into a form it was not
// (REQ-inputs-refusal-attribution).
func TestConvertAttributionDirRewritesOnlyTheOperationForm(t *testing.T) {
	upper := func(dir string) string { return strings.ToUpper(dir) }
	for _, c := range []struct{ in, want string }{
		{`open "/x" in "/w/pkg"`, `open "/x" in "/W/PKG"`},
		{`stat "a b" in "rel/dir"`, `stat "a b" in "REL/DIR"`},
		{`open "/x" in "/w/pkg" trailing`, `open "/x" in "/w/pkg" trailing`},
		{`recorded path "pkg/link" resolves to "/srv/x" outside the tree`, `recorded path "pkg/link" resolves to "/srv/x" outside the tree`},
		{`rename "/x" in "/w"`, `rename "/x" in "/w"`},
		{`open /x in "/w"`, `open /x in "/w"`},
		{"", ""},
	} {
		if got := convertAttributionDir(c.in, upper); got != c.want {
			t.Errorf("convertAttributionDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A refused path inside the module is spelled module-relative in its
// clause: one tree in two checkouts, each carrying a symbolic link to
// the same external directory and to the same external file, yields one
// manifest, one digest and one reason — the clauses name `escape` and
// `escapefile`, never the checkout's absolute path — while the
// attribution names the recorded path and its target
// (REQ-inputs-refusal-attribution's spelling rule, the identity clause's
// "keyed by what was measured, never by the checkout root").
func TestInModuleRefusedPathSpellsModuleRelative(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var states [2]Observation
	for i := range states {
		moduleDir, packageDir := testDirs(t)
		if err := os.Symlink(outside, filepath.Join(moduleDir, "escape")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "f.txt"), filepath.Join(moduleDir, "escapefile")); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../escape\nopen ../escapefile\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escape", "escapefile")))
		if err != nil {
			t.Fatal(err)
		}
		if !state.Unverifiable {
			t.Fatalf("checkout %d: the escaping links were admitted: %+v", i, state.State)
		}
		for _, abs := range []string{moduleDir, packageDir} {
			if strings.Contains(state.Reason, abs) || strings.Contains(state.Manifest, abs) {
				t.Fatalf("checkout %d: the identity names the checkout %q: reason %q", i, abs, state.Reason)
			}
		}
		// The bracket's capture reaches the hashing pass first and
		// wraps its refusal; the refused path is spelled relative there
		// and the attribution names the recorded path and its target.
		if clause := RefusalClause(state.Reason); !strings.HasSuffix(clause, "external directory input: escape") {
			t.Fatalf("checkout %d: the clause = %q, want the module-relative spelling", i, clause)
		}
		if attribution := RefusalAttribution(state.Reason); attribution != `recorded path "escape" resolves to `+strconv.Quote(outside)+` outside the tree` {
			t.Fatalf("checkout %d: the attribution = %q, want the recorded path and its target", i, attribution)
		}
		states[i] = state
	}
	if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
		t.Fatalf("two checkouts' identities differ:\n%+v\n%+v", states[0].State, states[1].State)
	}
	// No manifest clause spells the checkout: every refused in-module
	// path is relative there too.
	m, err := decode(states[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unverifiable) == 0 {
		t.Fatal("the manifest carries no refusal")
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(RefusalClause(reason), "/") {
			t.Fatalf("a manifest clause spells an in-module path absolute: %q", reason)
		}
	}
	// The file link alone, under a bracket covering it: the target
	// refusal spells it relative as well.
	moduleDir, packageDir := testDirs(t)
	if err := os.Symlink(filepath.Join(outside, "f.txt"), filepath.Join(moduleDir, "escapefile")); err != nil {
		t.Fatal(err)
	}
	file, err := FromTestLog([]byte("open ../escapefile\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escapefile")))
	if err != nil {
		t.Fatal(err)
	}
	if clause := RefusalClause(file.Reason); !strings.HasSuffix(clause, "external runtime input target: escapefile") {
		t.Fatalf("the file link's clause = %q, want the module-relative spelling", clause)
	}
}

// A module reached through a symlinked prefix spells an escaping link
// relative all the same: the coverage walk resolves the module root
// before following the chain, and the clause names the link as the
// tree spells it, never as the resolved host path.
func TestEscapingLinkSpellsRelativeUnderASymlinkedPrefix(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "mod", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	view := filepath.Join(t.TempDir(), "view")
	if err := os.Symlink(real, view); err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Join(view, "mod")
	packageDir := filepath.Join(moduleDir, "pkg")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(moduleDir, "escape")); err != nil {
		t.Fatal(err)
	}
	// The bracket root is the link itself: its resolved position holds
	// the input, the link hop lies outside it, and the coverage refusal
	// names the hop.
	state, err := FromTestLog([]byte("open ../escape\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "escape")))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, "(symlink outside every bracket root: escape)") {
			found = true
		}
		if strings.Contains(reason, real) || strings.Contains(reason, view) {
			t.Fatalf("a clause spells the host path: %q", reason)
		}
	}
	if !found {
		t.Fatalf("the escaping link is not named relative: %v", m.Unverifiable)
	}
}

// A moved bracket's member list is its attribution: the manifest
// carries the clause alone (a member's modification time never enters
// the identity) and the observation's attribution field carries the
// list, as a classification refusal's does
// (REQ-inputs-refusal-attribution).
func TestMovedBracketMemberListIsTheAttribution(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(filepath.Join(moduleDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	// Two members join: a plain name, and one carrying the list's
	// separator, which the writer quotes so the list stays splittable.
	for _, name := range []string{"b.txt", "x; y.txt"} {
		if err := os.WriteFile(filepath.Join(moduleDir, "data", name), []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state, err := FromTestLog([]byte("open ../data/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if state.Reason != "observation bracket moved: data" || state.Attribution != `added: b.txt, "x; y.txt"` {
		t.Fatalf("reason %q attributed %q, want the clause alone and the member list", state.Reason, state.Attribution)
	}
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range m.Unverifiable {
		if strings.Contains(reason, " [") {
			t.Fatalf("a member list entered the manifest: %q", reason)
		}
	}
}

// TestMovedBracketRootSpelledLikeAMemberList pins the root's quoting
// (REQ-inputs-refusal-attribution): a bracket root whose own name
// carries the member list's framing travels quoted, as a member does,
// so the clause keeps the root whole — the split consumes the quoted
// root and reads the list after it — and a sibling root's clause
// differs; the whole-reason forms that collided unquoted (`fix [added:
// x` and `fix [added: x] y` before a member list) split at the list.
func TestMovedBracketRootSpelledLikeAMemberList(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	for _, root := range []string{"fix", "fix [added: x]", "fix [added: x", "fix [added: x] y", `a"b`, "a]b", "a; b", `"x"`} {
		if err := os.MkdirAll(filepath.Join(moduleDir, root), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(moduleDir, root, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{"fix [added: x]", "fix [added: x", "fix [added: x] y", `a"b`, "a]b", "a; b", `"x"`} {
		bracket := testBracket(t, moduleDir, root)
		if err := os.WriteFile(filepath.Join(moduleDir, root, "b.txt"), []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../"+root+"/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
		if err != nil {
			t.Fatal(err)
		}
		want := "observation bracket moved: " + strconv.Quote(root)
		if state.Reason != want || state.Attribution != "added: b.txt" {
			t.Fatalf("root %q: reason %q attributed %q, want %q and the member list", root, state.Reason, state.Attribution, want)
		}
		clause, attribution, ok := splitBracketAttribution(state.Reason + " [" + state.Attribution + "]")
		if !ok || clause != want || attribution != "added: b.txt" {
			t.Fatalf("root %q: the whole reason split to %q / %q (%v), want the quoted root whole", root, clause, attribution, ok)
		}
		if clause == "observation bracket moved: fix" {
			t.Fatalf("root %q collided with the sibling root fix", root)
		}
		// The quoted root's list must be a well-formed attribution:
		// an unterminated or unlabelled list after the root refuses
		// the split whole, never yielding a garbage attribution.
		for _, malformed := range []string{want + " [added: b.txt", want + " [junk]", want + " []"} {
			if c, a, ok := splitBracketAttribution(malformed); ok || c != malformed || a != "" {
				t.Fatalf("root %q: the malformed %q split to %q / %q (%v), want refused whole", root, malformed, c, a, ok)
			}
		}
	}
	// A reason composed before roots were quoted — a bare root beginning
	// with a quote the quoted-root arm cannot parse — splits by the bare
	// scan, the pre-quoting answer; one whose bare root BEGINS with a
	// valid quoted literal followed by more name is refused whole (the
	// recorded choice: falling through would let a quoted root followed
	// by a malformed list mis-split).
	if c, a, ok := splitBracketAttribution(`observation bracket moved: "a [added: b]`); !ok || c != `observation bracket moved: "a` || a != "added: b" {
		t.Fatalf("a pre-quoting reason with a stray quote split to %q / %q (%v), want the bare scan's answer", c, a, ok)
	}
	if legacy := `observation bracket moved: "x" y [added: b]`; true {
		if c, a, ok := splitBracketAttribution(legacy); ok || c != legacy || a != "" {
			t.Fatalf("a pre-quoting reason whose root begins with a quoted literal split to %q / %q (%v), want refused whole", c, a, ok)
		}
	}
	// The exported spelling is the composer's: a plain root bare, a
	// framing-bearing one quoted — a consumer's re-key reads it.
	if MovedBracketClause("fix") != "observation bracket moved: fix" || MovedBracketClause("fix [added: x]") != `observation bracket moved: "fix [added: x]"` {
		t.Fatalf("MovedBracketClause spells %q / %q", MovedBracketClause("fix"), MovedBracketClause("fix [added: x]"))
	}
	// The re-key is idempotent: a pre-quoting bare key of a
	// framing-bearing root re-keys to the quoted spelling; a canonical
	// quoted key and a plain root's key come back unchanged, however
	// often applied; a foreign clause is untouched; the recorded
	// ambiguity — a bare root that is itself a quoted literal of a
	// framing-bearing name — reads as canonical.
	for _, tc := range []struct{ stored, want string }{
		{"observation bracket moved: fix [added: x]", `observation bracket moved: "fix [added: x]"`},
		{`observation bracket moved: "fix [added: x]"`, `observation bracket moved: "fix [added: x]"`},
		{"observation bracket moved: fix", "observation bracket moved: fix"},
		{"observation bracket moved: a; b", `observation bracket moved: "a; b"`},
		{"observation bracket moved", "observation bracket moved"},
		// A stored bare root literally named with quotes around a plain
		// name is not canonical (the spelling would not quote `fix`), so
		// it re-keys to the quoted spelling of its own quoted name.
		{`observation bracket moved: "fix"`, `observation bracket moved: "\"fix\""`},
		{"open /etc/passwd: outside the module", "open /etc/passwd: outside the module"},
		// The recorded ambiguity: a legacy bare root literally named
		// `"fix [added: x]"` is the same text as the canonical key of
		// `fix [added: x]`, so it reads as canonical and is not re-keyed.
		{`observation bracket moved: "fix [added: x]"`, `observation bracket moved: "fix [added: x]"`},
	} {
		got := CanonicalMovedBracketClause(tc.stored)
		if got != tc.want || CanonicalMovedBracketClause(got) != got {
			t.Fatalf("CanonicalMovedBracketClause(%q) = %q (again %q), want %q and a fixed point", tc.stored, got, CanonicalMovedBracketClause(got), tc.want)
		}
	}
	// The sibling root's own clause, unquoted: a plain name travels bare.
	bracket := testBracket(t, moduleDir, "fix")
	if err := os.WriteFile(filepath.Join(moduleDir, "fix", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := FromTestLog([]byte("open ../fix/a.txt\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if state.Reason != "observation bracket moved: fix" {
		t.Fatalf("the plain root's clause %q, want it bare", state.Reason)
	}
}
