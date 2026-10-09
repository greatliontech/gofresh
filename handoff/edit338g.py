#!/usr/bin/env python3
# gofresh 338 (after the godst release go1.27.1-dst.14 is installed as
# the running build): the dst selections listed FROM that release —
# listedSelection gains Since (the first godst release whose harness
# satisfies the listing's premise); the canary demands a selection of a
# godst build only from its Since release on (a stock build runs every
# selection: the tag selects nothing there); the pin's godst arm reads
# the host's build: listed → both forms admitted by the build's own dst
# rows, unlisted (older than Since) → refused with testing among the
# moved keys; the clause's premise sentence names the release. The rows
# themselves are inserted by insertrows338.py from the canary's prints
# under the new build. Run from the gofresh root; anchors read from the
# file; the script's exit gates everything after it.
def edit(p, pairs):
    s = open(p).read()
    for old, new in pairs:
        assert s.count(old) == 1, (p, old[:80], s.count(old))
        s = s.replace(old, new)
    open(p, "w").write(s)
    print("edited", p)

edit("closure/toolchainaudit.go", [
 ("""var listedSelections = []listedSelection{
	{},
	{Suffix: " race", Flags: []string{"-race"}},
	{Suffix: " plan9/amd64", Env: []string{"GOOS=plan9", "GOARCH=amd64"}},
	{Suffix: " cgo0", Env: []string{"CGO_ENABLED=0"}},
}

// listedSelection is one selection the listing hosts list: the label
// suffix after the version and the environment settings and build
// flags that select it; its row is a delta over the host's default
// row.
type listedSelection struct {
	Suffix string
""",
  """var listedSelections = []listedSelection{
	{},
	{Suffix: " race", Flags: []string{"-race"}},
	{Suffix: " plan9/amd64", Env: []string{"GOOS=plan9", "GOARCH=amd64"}},
	{Suffix: " cgo0", Env: []string{"CGO_ENABLED=0"}},
	// The godst fork's deterministic-simulation selection, listed from
	// the release whose testing harness propagates a failed test-log
	// write (go1.27.1-dst.14; before it the harness dropped the write
	// inside a simulation bubble — the listing's premise failed, so the
	// selection stays unlisted on those builds and the canary does not
	// demand it there). On a stock toolchain the tag selects no
	// standard file and the selection admits by the base chain.
	{Suffix: " dst", Flags: []string{"-tags", "dst"}, Since: "go1.27.1-dst.14"},
	{Suffix: " dst race", Flags: []string{"-tags", "dst", "-race"}, Since: "go1.27.1-dst.14"},
}

// listedSelection is one selection the listing hosts list: the label
// suffix after the version and the environment settings and build
// flags that select it; its row is a delta over the host's default
// row. Since, when set, names the first godst release the selection is
// listed from: a godst build older than it is not asked to list the
// selection (the listing's harness premise fails there — stated at the
// entry), every other build is.
type listedSelection struct {
	Suffix string
"""),
])
s = open("closure/toolchainaudit.go").read()
# the struct's fields: add Since after Flags (anchor the closing brace of the struct)
import re
m = re.search(r"type listedSelection struct \{\n\tSuffix string\n(.*?)\n\}\n", s, re.S)
assert m, "listedSelection struct"
body = m.group(1)
assert "Since" not in body
s = s.replace(m.group(0), "type listedSelection struct {\n\tSuffix string\n" + body + "\n\tSince  string\n}\n", 1)
s = s.rstrip("\n") + """

// demandedOf reports whether a listing host running version demands the
// selection: every selection without Since, and one with Since for a
// build that is not a godst release older than Since (a godst release
// is `goX.Y.Z-dst.N`, ordered by N — the fork's global counter).
func (sel listedSelection) demandedOf(version string) bool {
	if sel.Since == "" {
		return true
	}
	have, ok := godstCounter(version)
	if !ok {
		return true
	}
	since, ok := godstCounter(sel.Since)
	return !ok || have >= since
}

// godstCounter reads the godst release counter N of `goX.Y.Z-dst.N`,
// false for any other version string.
func godstCounter(version string) (int, bool) {
	i := strings.LastIndex(version, "-dst.")
	if i < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(version[i+len("-dst."):])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
"""
open("closure/toolchainaudit.go", "w").write(s)
print("edited closure/toolchainaudit.go (Since, demandedOf, godstCounter)")

edit("closure/audited_test.go", [
 ("""	for _, sel := range listedSelections {
		h, err := newAtEnv(context.Background(), ".", environmentWith(sel.Env...), sel.Flags...)
""",
  """	for _, sel := range listedSelections {
		if !sel.demandedOf(runtime.Version()) {
			t.Logf("the %q selection is listed from %s; not demanded of %s", sel.Suffix, sel.Since, runtime.Version())
			continue
		}
		h, err := newAtEnv(context.Background(), ".", environmentWith(sel.Env...), sel.Flags...)
"""),
])

edit("closure/toolchainsource_dst_test.go", [
 ("""		if godst == nil {
			// A godst build: the hook files move keys; no chain lists
			// them while the fork's harness premise fails. The refusal
			// names the moved keys under its bound, and testing — the
			// premise's own key — sorts past it under the race
			// detector, so its membership is read from the moved set.
			moved, _ := movedKeys(h.source, auditedToolchainSources)
			if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") || !slices.Contains(moved, "testing") {
				t.Fatalf("the %q selection on a godst build: audited=%v, moved %v, attribution %q, want a refusal with testing among the moved keys — the harness premise's key did not move: re-walk where the fork's test-log writer lives", sel.suffix, h.SelectionAudited(), moved, h.SelectionAttribution())
			}
			t.Logf("godst build: the %q selection refuses — %s", sel.suffix, h.SelectionAttribution())
			continue
		}
""",
  """		if godst == nil {
			moved, closest := movedKeys(h.source, auditedToolchainSources)
			listed := listedSelections[len(listedSelections)-2:]
			demanded := listed[0].demandedOf(snapshot.Value("GOVERSION"))
			if demanded {
				// A godst build from the release whose harness
				// propagates a failed test-log write: the selection is
				// listed over the build's own dst rows — admitted, the
				// closest chain its own.
				if !h.SelectionAudited() || len(moved) != 0 || closest != snapshot.Value("GOVERSION")+sel.suffix {
					t.Fatalf("the %q selection on the listed godst build: audited=%v, moved %v, closest %q, want admitted by the build's own dst row %q", sel.suffix, h.SelectionAudited(), moved, closest, snapshot.Value("GOVERSION")+sel.suffix)
				}
				t.Logf("listed godst build: the %q selection admits by %q", sel.suffix, closest)
				continue
			}
			// A godst build older than the listing's Since: the hook
			// files move keys; no chain lists them while the fork's
			// harness premise fails. The refusal names the moved keys
			// under its bound, and testing — the premise's own key —
			// sorts past it under the race detector, so its membership
			// is read from the moved set.
			if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") || !slices.Contains(moved, "testing") {
				t.Fatalf("the %q selection on a godst build older than %s: audited=%v, moved %v, attribution %q, want a refusal with testing among the moved keys — the harness premise's key did not move: re-walk where the fork's test-log writer lives", sel.suffix, listed[0].Since, h.SelectionAudited(), moved, h.SelectionAttribution())
			}
			t.Logf("godst build older than %s: the %q selection refuses — %s", listed[0].Since, sel.suffix, h.SelectionAttribution())
			continue
		}
"""),
])

edit("docs/specs/closure.md", [
 ("""or fails the binary — so a selection whose harness drops a failed write
is unlistable until a build propagates it, whatever its hook files admit,
and the packages implementing the premise (testing and its test-log
""",
  """or fails the binary — so a selection whose harness drops a failed write
is unlistable until a build propagates it, whatever its hook files admit
(the godst fork's dst selections are listed from go1.27.1-dst.14, the
release whose harness propagates the error, and demanded of no older
godst build), and the packages implementing the premise (testing and its
test-log
"""),
])
print("ALL EDITS APPLIED (rows pending: insertrows338.py over the canary's prints)")
