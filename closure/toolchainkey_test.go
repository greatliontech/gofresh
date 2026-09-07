package closure

import (
	"strings"
	"testing"
)

// One audited experiment toolchain reports itself two ways — the
// space-separated runtime spelling and the hyphenated VERSION-file
// spelling — and the audit tables list one: both spellings resolve to
// the same release and selection rows and the same experiment set,
// while an unlisted release, an unlisted experiment, and a flavor the
// tables never saw keep missing under both spellings, and only an
// experiment-set tail folds (a vendor flavor spelled "-X:…" is not an
// experiment set) (REQ-closure-observability-analysis's exact-version
// keying clause).
func TestToolchainKeyFoldsTheHyphenatedExperimentSpelling(t *testing.T) {
	for _, spelling := range []string{"go1.27.0 X:nodwarf5", "go1.27.0-X:nodwarf5"} {
		if !auditedToolchainSourceFor(spelling) {
			t.Errorf("%q: listed release not admitted", spelling)
		}
		selections := auditedToolchainSelections[toolchainKey(spelling)]
		if !selections[""] || !selections["race"] {
			t.Errorf("%q: default and race selections = %v, want both listed", spelling, selections)
		}
		if exp := experimentOf(spelling); exp != "nodwarf5" {
			t.Errorf("%q: experiment = %q, want nodwarf5", spelling, exp)
		}
	}
	for _, untouched := range []string{"go1.27.0 X:nodwarf5", "go1.27.0", "go1.27.0-dst.14", "go1.27.0-X:Flavor", "go1.27.0-X:", "go1.27.0-X:a,,b", "go1.27.0-X:no-dwarf"} {
		if toolchainKey(untouched) != untouched {
			t.Errorf("%q: the key rewrote a spelling other than a hyphenated experiment set: %q", untouched, toolchainKey(untouched))
		}
	}
	if toolchainKey("go1.27.0-X:nodwarf5,rangefunc") != "go1.27.0 X:nodwarf5,rangefunc" {
		t.Fatal("a multi-experiment set did not fold")
	}
	if experimentOf("go1.27.0") != "" || experimentOf("go1.27.0-dst.14") != "" {
		t.Fatal("a default-experiment version reads a non-empty experiment set")
	}
	for _, unlisted := range []string{"go1.26.0-X:nodwarf5", "go1.26.0 X:nodwarf5", "go1.27.0-X:unwalked", "go1.27.0 X:unwalked", "go1.27.0-dst.1-X:nodwarf5", "go1.27.0-dst.1 X:nodwarf5"} {
		if auditedToolchainSourceFor(unlisted) || auditedToolchainSelections[toolchainKey(unlisted)]["race"] {
			t.Errorf("%q admitted under the folded key", unlisted)
		}
	}
}

// The hyphenated identity drives the whole selection-notice path — the
// release axis, the default and race selections, and an explicit or
// inherited GOEXPERIMENT — exactly as the space spelling does, and an
// unlisted hyphenated release names the audit key to list.
func TestHyphenatedToolchainThroughTheSelectionNotice(t *testing.T) {
	const hyphenated = "go1.27.0-X:nodwarf5"
	for _, tc := range []struct {
		name         string
		flags        []string
		goflags, exp string
	}{
		{"default selection, inherited experiment", nil, "", ""},
		{"race selection, inherited experiment", []string{"-race"}, "", ""},
		{"race via GOFLAGS, explicit experiment", nil, "-race", "nodwarf5"},
	} {
		if notice := toolchainSelectionNoticeFor(hyphenated, tc.flags, tc.goflags, tc.exp); notice != "" {
			t.Errorf("%s: notice = %q, want admitted", tc.name, notice)
		}
	}
	if notice := toolchainSelectionNoticeFor(hyphenated, nil, "", "otherexp"); !strings.Contains(notice, "differs from the binary's baked experiment set") {
		t.Errorf("differing GOEXPERIMENT under the hyphenated spelling: %q", notice)
	}
	notice := toolchainSelectionNoticeFor("go1.26.0-X:nodwarf5", nil, "", "")
	if !strings.Contains(notice, "release go1.26.0-X:nodwarf5") || !strings.Contains(notice, `audit key "go1.26.0 X:nodwarf5"`) {
		t.Errorf("unlisted hyphenated release notice does not name the key to list: %q", notice)
	}
}
