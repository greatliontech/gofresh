package closure

import "runtime"

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
// listing.
var auditedToolchainReleases = map[string]bool{
	// Stock go1.27.0 (the CI matrix's toolchain), audited by the
	// go1.26.0→go1.27.0 delta walk.
	"go1.27.0": true,
	// The nodwarf5-experiment build of the same source (the system
	// toolchain): DWARF-only experiment, no build-tagged source
	// selection in the audited surface.
	"go1.27.0-X:nodwarf5": true,
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
	// (docs/issues/dst-tagged-selection-outside-audit-key.md).
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

// auditedToolchainSource reports whether the running toolchain's
// standard-library source is one the audited sets' claims were
// verified against. The running binary's version is the loaded view's
// version by construction: judged runs refuse binary/ambient toolchain
// skew before any analysis (the fleet's provenance guards), and this
// package's own suite runs under the toolchain that loads its views.
func auditedToolchainSource() bool {
	return auditedToolchainReleases[runtime.Version()]
}

// AuditedToolchainSource is the cross-tier form of the key: the purity
// tier's audited synchronization/pooling/immutable-type admissions are
// the same toolchain-source claims this package's symbol sets carry,
// and both tiers must answer from one list
// (REQ-closure-observability-analysis's exact-version keying clause).
func AuditedToolchainSource() bool {
	return auditedToolchainSource()
}
