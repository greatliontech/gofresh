package closure

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// auditedToolchainReleases is the exact-version key of every
// toolchain-source audit in this package: the standard-library
// admissions (the audited-pure package set, the class-B pure
// operations, the audited sync/pool/reflect symbols, the atomic
// transparency, the harness logging and subtest-driver channels, the
// writer-sink admission) are properties of SPECIFIC toolchain source,
// audited release by release, and no other release inherits a proof —
// exactly the discipline the version-pinned module audits and the
// property-harness audit already follow. An unlisted release keeps
// every symbol's ordinary fail-closed classification: proofs refuse
// loudly until the release's delta is walked and the release listed
// (TestAuditedToolchainCoversRunningToolchain is the canary that makes
// a toolchain move fail as one named test instead of a scatter of
// fixture flips). The key is the FULL version string, experiment and
// vendor flavors included, because both select source: a GOEXPERIMENT
// changes build-tagged file selection (go1.27's jsonv2 experiment
// swaps the encoding/json engine) and a vendor flavor patches the
// tree outright (godst).
//
// The audit record per listed release lives in the commit that lists
// it (recover with `git log --all -- closure/toolchainaudit.go`); the
// go1.26.0→go1.27.0 walk (every audited package's non-test
// delta re-verified against the admission bar, encoding/base32
// first-audited into the source-only set, the godst delta verified
// build-tag-inert for the audited surface) landed with the go1.27
// listing. The walks' method is whole-dir: each audited package's
// non-test SOURCE FILES are read in full — platform-split files
// included, exactly as the dst.12–dst.14 records below name their
// plan9/illumos/windows deltas — so a GOOS/GOARCH selection of an
// audited package selects among walked files and needs no key axis;
// the memo scopes carry the platform through the build
// configuration.
var auditedToolchainReleases = map[string]bool{
	// Stock go1.27.0 (the CI matrix's toolchain), audited by the
	// go1.26.0→go1.27.0 delta walk.
	"go1.27.0": true,
	// The nodwarf5-experiment build of the same source (the system
	// toolchain): DWARF-only experiment, no build-tagged source
	// selection in the audited surface.
	"go1.27.0 X:nodwarf5": true,
	// godst releases on the go1.27.0 base: the fork's delta intersects
	// the audited surface at sync, time, AND testing (the chatty
	// printer's host-stream slot and bubble output legs, the wrapped
	// testlog writer), and every hook is dead code in the DEFAULT
	// build selection behind compile-time constants and identity stubs
	// (dstHookEnabled, dstMutexVirtualStarvation, dstTZBuild,
	// dstFrameworkStreamEnabled, the untagged dstWrapTestlogWriter
	// returning its argument). These audits cover the default
	// selection ONLY: a `-tags dst` analysis selects the live hook
	// bodies, whose audit is an open filing
	// (docs/issues/walk-dst-selection-for-audit-key.md).
	"go1.27.0-dst.10": true,
	"go1.27.0-dst.11": true,
	// dst.12's delta over dst.11 is one change: os.(*File).Stat gains
	// a testlog.Stat record on every platform (godst 48c7e688), plus
	// its test. Beyond strengthening the file-I/O class's
	// testlog-visibility premise (a previously invisible fd-based
	// metadata read becomes logged), the new record also CHANGES
	// ingest classification: entries fd-stat'd by stdlib internals
	// (ReadFile's buffer-sizing stat) classify metadata-bound, and an
	// fd-stat outside a declared bracket stat root newly adds the
	// "stat metadata input" unverifiable reason — both over-report
	// (over-pin/refuse, never falsely serve), and dst.13 removes the
	// non-escaping internal stat from the log. No audited symbol's
	// body otherwise changed; the dead-code hook posture is dst.11's.
	"go1.27.0-dst.12": true,
	// dst.13's delta over dst.12: the fd-stat log line moves to the
	// public method alone — stdlib-internal stats whose FileInfo never
	// escapes (ReadFile's buffer-sizing stat via the new fstatNolog)
	// no longer log, so the record matches what the subject could
	// read: an explicit f.Stat() logs, os.ReadFile logs its open only.
	// Same audited-surface intersection as dst.12 (the testlog
	// premise, now drawn at the observable boundary); no audited
	// symbol's body otherwise changed. dst.13 applied the rule at one
	// of five internal call sites; dst.14 completes it.
	"go1.27.0-dst.13": true,
	// dst.14's delta over dst.13: the four remaining non-escaping
	// internal fd-stats route through the nolog core (Getwd fallback
	// hop, plan9 openDirNolog, illumos zero-copy check, windows
	// readdir error-shaping); CopyFS's source stat stays logged - its
	// mode escapes into the destination. Same audited-surface
	// intersection as dst.13; no audited symbol's body otherwise
	// changed.
	"go1.27.0-dst.14": true,
}

// auditedToolchainSelections is the second axis of the key: per listed
// release, the audited BUILD SELECTIONS — canonical sorted tag-set
// keys, "" the default selection. The audits above cover the default
// selection of each listed release; a selection whose tags swap
// audited bodies is outside the key until its own delta is walked and
// the selection listed here.
//
// The "race" selection is listed by the selection walk landing with
// this axis: no audited package has a non-test file whose build
// constraint mentions a tag the -race selection sets — the only
// race-mentioning files across the audited surface are sync's godst
// hook seam (dst_on.go, `//go:build dst && race`; dst_off.go its
// complement — selected identically under plain -race and under the
// default) and two test-only files (sync/pool_test.go and
// regexp/exec2_test.go, both `!race`, never in an analyzed plain
// package). Audited packages carry OTHER build-constrained files —
// platform splits ride the whole-dir walk method recorded above,
// and unwalked tag keys refuse; the claim here is exactly the race
// one.
// Every audited package's selected non-test source is therefore
// byte-identical under the race selection, so the default audit
// covers it verbatim; the race-mode difference (internal/race's
// real instrumentation behind sync's race.Enabled guards, and the
// compiler's instrumentation) changes no analyzed source and
// introduces no effect any admission bar prices. The dst selection
// stays unlisted until its own delta walk (time/dst_tz.go,
// testing/dst_hostio.go, the os fault-injection seam against the
// observation producer model) — a dst-tagged analysis refuses
// admissions loudly rather than inheriting the default audit
// (docs/issues/walk-dst-selection-for-audit-key.md).
var auditedToolchainSelections = map[string]map[string]bool{
	"go1.27.0":            {"": true, "race": true},
	"go1.27.0 X:nodwarf5": {"": true, "race": true},
	"go1.27.0-dst.10":     {"": true, "race": true},
	"go1.27.0-dst.11":     {"": true, "race": true},
	"go1.27.0-dst.12":     {"": true, "race": true},
	"go1.27.0-dst.13":     {"": true, "race": true},
	"go1.27.0-dst.14":     {"": true, "race": true},
}

// auditedToolchainSource reports whether the running toolchain's
// standard-library source is one the audited sets' claims were
// verified against — the VERSION axis alone, the default build
// selection's key. The running binary's version is the loaded view's
// version by construction: judged runs refuse binary/ambient toolchain
// skew before any analysis (the fleet's provenance guards), and this
// package's own suite runs under the toolchain that loads its views.
func auditedToolchainSource() bool {
	return auditedToolchainReleases[runtime.Version()]
}

// selectionAuditKey canonicalizes a producing build's EFFECTIVE flag
// set to the selection axis of the audit key: the -tags values (both
// "-tags=x,y" and the two-argument form) union the sanitizer tags the
// flags select (-race, -msan, -asan and their explicit boolean value
// forms), sorted and comma-joined; "" is the default selection. ok is
// false when a flag defeats classification (a bare "-tags" missing
// its value, a sanitizer flag with an unparsable value) — an
// unclassifiable selection is never admitted.
func selectionAuditKey(buildFlags []string) (key string, ok bool) {
	tags := map[string]bool{}
	sanitizer := func(flag, name string) (selected, matched, ok bool) {
		if flag == "-"+name {
			return true, true, true
		}
		if v, cut := strings.CutPrefix(flag, "-"+name+"="); cut {
			on, err := strconv.ParseBool(v)
			return on, true, err == nil
		}
		return false, false, true
	}
	for i := 0; i < len(buildFlags); i++ {
		flag := buildFlags[i]
		if strings.HasPrefix(flag, "--") {
			flag = flag[1:]
		}
		if v, cut := strings.CutPrefix(flag, "-tags="); cut {
			for _, tag := range strings.FieldsFunc(strings.Trim(v, `"'`), func(r rune) bool { return r == ',' || r == ' ' }) {
				tags[tag] = true
			}
			continue
		}
		if flag == "-tags" {
			if i+1 >= len(buildFlags) {
				return "", false
			}
			i++
			for _, tag := range strings.FieldsFunc(buildFlags[i], func(r rune) bool { return r == ',' || r == ' ' }) {
				tags[tag] = true
			}
			continue
		}
		for _, name := range []string{"race", "msan", "asan"} {
			selected, matched, parsed := sanitizer(flag, name)
			if matched {
				if !parsed {
					return "", false
				}
				if selected {
					tags[name] = true
				}
				break
			}
		}
	}
	if len(tags) == 0 {
		return "", true
	}
	sorted := make([]string, 0, len(tags))
	for tag := range tags {
		sorted = append(sorted, tag)
	}
	sort.Strings(sorted)
	return strings.Join(sorted, ","), true
}

// binaryExperiment is the GOEXPERIMENT this binary's toolchain was
// built with, as the version string carries it ("go1.27.0 X:nodwarf5"
// → "nodwarf5"; "" for the default experiment set).
func binaryExperiment() string {
	if _, exp, ok := strings.Cut(runtime.Version(), " X:"); ok {
		return exp
	}
	return ""
}

// AuditedToolchainSelection is the full two-axis key over the
// analysis' EFFECTIVE selection — the go command merges GOFLAGS into
// every invocation, GOEXPERIMENT swaps build-tagged standard-library
// source, and GOOS/GOARCH select per-platform files, so the verdict
// derives from the explicit build flags joined with the resolved
// environment, never the flags alone. goflags is the resolved
// effective GOFLAGS value (go env GOFLAGS — environment and config
// file both); goexperiment is the analysis environment's value,
// empty meaning this binary's own default, and one differing from
// the binary's baked experiment refuses fail-closed (experiment
// flavors are version-axis listings, never inherited). GOOS/GOARCH
// selection needs no axis: the delta walks read every audited
// package's non-test source whole — platform-split files included
// (the dst walks' plan9/windows/illumos deltas are in the listing
// records above) — so platform selections of the audited packages
// ride the same walked source, and the memo scopes carry the
// platform through BuildConfig. The verdict is true only when the release AND the
// effective tag selection are both listed; every audited-set
// consultation answers through it — a tag-swapped view degrades
// every stdlib admission to the ordinary fail-closed classification
// exactly as an unlisted release does
// (REQ-closure-observability-analysis's exact-version keying clause;
// the purity tier's audited admissions answer from the same list).
func AuditedToolchainSelection(buildFlags []string, goflags, goexperiment string) bool {
	return ToolchainSelectionNotice(buildFlags, goflags, goexperiment) == ""
}

// ToolchainSelectionNotice renders the two-axis audit's fail-closed
// consequence for the analysis' effective selection, "" exactly when
// the release and selection are both listed — the admission bool and
// this rendering are one derivation, so the texts can never disagree
// with the verdict. The rendering is owned here, at the same seam that
// owns discharge-channel reasons, so every consumer serves the same
// notice; callers prepend attribution (which invocation or
// configuration authored the selection). The notice names the axis
// that misses — the running release, an environment GOEXPERIMENT
// differing from the binary's baked set, a flag defeating selection
// classification, or the canonical selection key — with the walk that
// would list it.
func ToolchainSelectionNotice(buildFlags []string, goflags, goexperiment string) string {
	return toolchainSelectionNotice(auditedToolchainSource(), runtime.Version(), binaryExperiment(), auditedToolchainSelections[runtime.Version()], buildFlags, goflags, goexperiment)
}

// toolchainSelectionNotice is the rendering over explicit axis inputs,
// so a test can drive the worlds the exported entry cannot reach on a
// listed toolchain (the unlisted-release branch foremost).
func toolchainSelectionNotice(sourceListed bool, version, bakedExperiment string, listedSelections map[string]bool, buildFlags []string, goflags, goexperiment string) string {
	const consequence = " — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution)"
	if !sourceListed {
		return "toolchain-selection audit: release " + version + " is not listed" + consequence + " until the release delta is walked and listed"
	}
	if goexperiment != "" && goexperiment != bakedExperiment {
		return "toolchain-selection audit: environment GOEXPERIMENT " + strconv.Quote(goexperiment) + " under " + version + " differs from the binary's baked experiment set" + consequence + "; experiment flavors are version-axis listings, never inherited"
	}
	effective := append(append([]string(nil), buildFlags...), strings.Fields(goflags)...)
	key, ok := selectionAuditKey(effective)
	if !ok {
		return fmt.Sprintf("toolchain-selection audit: effective build flags %q (explicit plus GOFLAGS) under %s defeat selection classification%s; an unclassifiable selection is never admitted", effective, version, consequence)
	}
	if listedSelections[key] {
		return ""
	}
	return fmt.Sprintf("toolchain-selection audit: selection %q under %s is unwalked%s until the selection delta is walked and listed", key, version, consequence)
}

// ToolchainSelectionNoticeResolvedContext is the resolving entry of the
// notice for callers without a Hasher (a consumer attributing the
// degradation at its own configuration tier): it reads the effective
// GOFLAGS and GOEXPERIMENT under the caller's environment —
// snapshot-first when one is supplied, one go env read otherwise — and
// answers ToolchainSelectionNotice over them. Resolution failure
// returns its error so the caller fails loudly instead of silently
// losing the notice.
func ToolchainSelectionNoticeResolvedContext(ctx context.Context, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot) (string, error) {
	goflags, goexperiment, err := resolveSelectionEnv(ctx, dir, env, snapshot)
	if err != nil {
		return "", err
	}
	return ToolchainSelectionNotice(buildFlags, goflags, goexperiment), nil
}

// SelectionAudited reports this Hasher's two-axis toolchain-selection
// audit verdict — a constructor-resolved verdict with an empty notice,
// one derivation with the rendering: the consumer-tier scans (purity,
// dynamic state) and the view surfaces answer their audited-set
// consultations from the same verdict the closure tiers thread
// internally. An unresolved (zero-value) Hasher refuses.
func (h *Hasher) SelectionAudited() bool {
	return h.selectionResolved && h.selectionNotice == ""
}

// SelectionNotice is the Hasher's owned degradation rendering, ""
// exactly when the selection is audited — the biconditional holds for
// the unresolved zero value too, which refuses with its own notice.
func (h *Hasher) SelectionNotice() string {
	if !h.selectionResolved {
		return "toolchain-selection audit: verdict unresolved — this Hasher was built without construction, so every standard-library admission refuses fail-closed"
	}
	return h.selectionNotice
}

// resolveSelectionEnv reads the two selection-bearing go-env values:
// from the pass's snapshot when the caller holds one, else one
// combined go env invocation.
func resolveSelectionEnv(ctx context.Context, dir string, env []string, snapshot *gotool.EnvSnapshot) (goflags, goexperiment string, err error) {
	if snapshot != nil {
		return snapshot.Value("GOFLAGS"), snapshot.Value("GOEXPERIMENT"), nil
	}
	out, err := gotool.RunInContextEnv(ctx, dir, env, "env", "GOFLAGS", "GOEXPERIMENT")
	if err != nil {
		return "", "", err
	}
	// One line per requested key plus a trailing newline; empty values
	// are empty lines, so split first and count, never trim first.
	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return "", "", fmt.Errorf("toolchain selection: go env returned %d values, want 2", len(lines))
	}
	return strings.TrimRight(lines[0], "\r"), strings.TrimRight(lines[1], "\r"), nil
}
