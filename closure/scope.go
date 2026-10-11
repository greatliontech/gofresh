package closure

import (
	"sort"
	"strings"
)

// AnalysisScope is the analysis identity outside the source closure,
// set once per pass: the strategy versions of the two derivations the
// caller owns, the code guards, hasher-owned selected source and admission
// policy, the execution attestations, and the
// caller's vouch set. Every persistent memo that depends on any of
// these renders its own scope from this one value, naming exactly the
// axes it reads — the observability proofs, the typed testing scan,
// the dynamic-state facts, and the view scan — so an axis one memo needs
// cannot be joined by hand at one site and forgotten at another, and an
// axis a memo does not depend on (the proof-strategy version, for the
// typed testing scan) never widens its misses. The listing memo and the
// classification-root resolution also need their environment; the listing
// additionally depends on selected standard source. The zero value arms
// nothing: every memo stays inert
// and every pass recomputes. The Hasher reads the proof and testing-scan
// renderings; the fact strategy, the attestations, and the vouches key
// the facts and the view scan the observation pass derives, and the
// attestations and vouches are also what that derivation applies — one
// source for what a memo is keyed on and what the pass computed.
type AnalysisScope struct {
	// ProofStrategy versions the observability proof derivation;
	// FactStrategy the shared-dynamic-state fact derivation and the
	// view scan built on it.
	ProofStrategy, FactStrategy string
	// Toolchain and BuildConfig are the code guards — the identity the
	// type environment and every classification table depend on.
	Toolchain, BuildConfig string
	// SingleSubject and PackageProcess are the caller's execution
	// attestations: they change what the derived facts record, so
	// attested and unattested sessions never serve each other.
	SingleSubject, PackageProcess bool
	// Vouches are the caller's dynamic-state vouch identities; a vouch
	// is load-bearing for the discharges a scan records.
	Vouches []string
	// Only a constructed Hasher supplies these dependencies. A caller's
	// reported guards cannot stand in for the content the hasher analyzed.
	toolchainContent, admissionPolicy string
}

// Each rendering is empty when its strategy or any required guard/dependency
// is absent: a rendering never carries a partial identity.

// guards is the key every type-level memo shares: the code guards of
// the analyzed selection and the analyzing frontend's version — the
// proofs, facts, and scans a memo holds are the analyzing frontend's
// own derivations (go/types, SSA), which a newer frontend may derive
// differently and the skew check permits to read older records
// (REQ-closure-identity-strategy).
func (s AnalysisScope) guards() string {
	return s.Toolchain + "|" + s.BuildConfig + "|" + AnalyzingFrontend() + "|" + s.toolchainContent + "|" + s.admissionPolicy
}

func (s AnalysisScope) completeGuards() bool {
	return s.Toolchain != "" && s.BuildConfig != "" && s.toolchainContent != "" && s.admissionPolicy != ""
}

// Proofs is the observability memo's scope: the proof-strategy version
// and the guard key (the code guards and the analyzing frontend).
func (s AnalysisScope) Proofs() string {
	if s.ProofStrategy == "" || !s.completeGuards() {
		return ""
	}
	return s.ProofStrategy + "|" + s.guards()
}

// TestingScan is the typed testing-effect scan memo's scope: its own
// strategy version and the guard key (the code guards the type environment
// depends on and the analyzing frontend).
func (s AnalysisScope) TestingScan() string {
	if !s.completeGuards() {
		return ""
	}
	return testingScanStrategy + "|" + s.guards()
}

// Facts is the dynamic-state fact memo's scope: the fact-strategy
// version, the guard key (the code guards and the analyzing frontend),
// and the execution attestations, which change
// what a fact records.
func (s AnalysisScope) Facts() string {
	if s.FactStrategy == "" || !s.completeGuards() {
		return ""
	}
	scope := s.FactStrategy + "|" + s.guards()
	if s.SingleSubject {
		scope += "|single-subject-execution"
	}
	if s.PackageProcess {
		scope += "|package-process-execution"
	}
	return scope
}

// Scan is the view scan memo's scope: the facts' scope joined with the
// sorted vouch set, since a vouch is load-bearing for the discharges an
// entry records.
func (s AnalysisScope) Scan() string {
	facts := s.Facts()
	if facts == "" {
		return ""
	}
	keys := append([]string(nil), s.Vouches...)
	sort.Strings(keys)
	return facts + "|vouches:" + strings.Join(keys, ",")
}
