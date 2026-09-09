package closure

import "runtime"

// AnalyzingFrontend is the version of the Go frontend this process
// analyzes with — runtime.Version() of the analyzing binary, never the
// analyzed selection's toolchain (a guard). Every persistent memo keys
// on it as a cache-miss defense: a miss costs one recomputation, and a
// type-level derivation (proofs, facts, scans) is the analyzing
// frontend's own work. The closure identity does not compose it, by
// design: the canonical member form is a go/scanner token stream and
// the ledger's declarations a go/parser walk over valid Go sources,
// whose tokenization and parse Go's compatibility promise fixes in the
// forward direction (a newer frontend reads older language; new syntax
// appears only in sources that changed), so composing the frontend
// into IdentityStrategy would move every fleet record on each upgrade
// of a consumer's build toolchain for hashes that did not move; the
// reverse direction — a source newer than the frontend — is refused at
// the provenance boundary by the toolchain-skew check, which reads this
// same spelling (REQ-closure-identity-strategy, REQ-fresh-toolchain-skew).
func AnalyzingFrontend() string { return runtime.Version() }
