// Package testvariant is the vocabulary of a package's test-variant
// compartment (REQ-closure-test-variant-compartment): the declaration
// ledger persisted beside a compartment hash, the delta between two
// ledgers and its inertness classification, and the empty compartment's
// identity. The compartment's computation lives with the closure engine.
package testvariant

import (
	"sort"
)

// EmptyTestVariantClosure is the test-variant compartment identity of a package
// with no test files: the empty-file-set hash under the same name\x00sha256
// discipline as every other compartment. It is a stable constant — a recorded
// compartment equal to it stays valid for as long as the package has no test
// files — and it is never the empty string, so an empty recorded compartment
// unambiguously identifies a recording that predates the partition
// (REQ-closure-test-variant-compartment).
const EmptyTestVariantClosure = "e3b0c44298fc1c149afbf4c8996fb924"

// TestVariantLedger is the declaration-level read surface over a package's
// test-variant compartment: every top-level declaration in the compartment's Go
// files and a per-file header identity over each file's non-declaration
// remainder. It is data for a consumer to persist at capture and diff at check;
// gofresh renders no judgment about which deltas are benign
// (REQ-closure-test-variant-compartment).
type TestVariantLedger struct {
	// Declarations is sorted by (File, Kind, Receiver, Name, Hash).
	Declarations []TestVariantDeclaration
	// FileHeaders is sorted by File and carries one entry per compartment
	// file: for a compiled Go member the hash covers the non-declaration
	// remainder — package clause, imports, build constraints, and comments
	// outside declarations; for every other member (embedded data,
	// whatever its name) it covers the whole file, with Embedded set.
	FileHeaders []TestVariantFileHeader
}

// TestVariantDeclaration identifies one top-level declaration in a compartment
// file. Kind is one of "func", "method", "init", "var", "const", "type", or
// "directive" — a directive-shaped comment (//go:… other than //go:build)
// ledgered wherever it sits, its Name the directive verb (e.g. "go:linkname");
// TestMain is an ordinary "func" whose name stays visible to the consumer.
// Receiver is the receiver type's source text for methods and empty otherwise.
// Hash is 32 hex characters of SHA-256 over the declaration's source range,
// its doc comment included; for a grouped var/const/type declaration the range
// is the individual spec, so sibling entries in one group move independently.
// Positions Go gives semantics are folded into the hash alongside the bytes:
// a const spec's ordinal within its group (iota and implicit expression
// repetition depend on it), and a var spec's or an init function's ordinal in
// its file (package-level initialization order depends on it) — so a
// value-shifting insertion or an order-sensitive reorder surfaces as changed
// declarations, never as a silent add or an empty delta.
type TestVariantDeclaration struct {
	File     string // relative to the package directory
	Kind     string
	Name     string
	Receiver string
	Hash     string
	// Package is the declaring file's package clause name — the base name
	// for the in-package variant, the "_test"-suffixed name for the
	// external one — so a consumer can tell same-named declarations of the
	// two compartment packages apart (a method's receiver type resolves
	// within its own package only). Unlike References it is NOT derivable
	// from the hash-pinned bytes (the clause lives in the file header), so
	// it is part of the diff identity: a package-clause-only rename
	// re-homes every declaration semantically (methods re-attach across
	// same-named types, unexported access changes) and surfaces as removed
	// and added declarations, never as an empty delta. It stays outside
	// the content hash.
	Package string
	// References is the declaration's referenced-name list: every identifier
	// appearing in its declaring node — selector members, receiver and
	// parameter type names, and local names included; the blank identifier
	// excluded — deduplicated and sorted. It is a syntax-only
	// over-approximation of the top-level names the declaration's compiled
	// code can resolve by identifier, derived from the bytes the hash
	// vouches for: equal hashes carry equal reference lists, except an
	// omitted-list const spec, whose fold also tracks its group's governing
	// expression list — there the governing spec's declared names always
	// ride the fold, the blank name included (naming the ledger entry
	// itself when the governor declares nothing else), and a change in
	// that list is the governing entry's own movement, so a consumer
	// walking current references still observes every movement an
	// unchanged declaration can textually repeat. It is
	// served for a consumer to attribute a compartment delta to the
	// declarations that can reach it; gofresh itself renders no
	// reachability judgment. Directive entries carry none.
	References []string
}

// TestVariantFileHeader is one compartment file's non-declaration identity.
// A compiled Go member's hash covers its non-declaration remainder; every
// other member — embedded data whatever its name, a .go-named testdata
// fixture included — carries Embedded true and a whole-content hash,
// because its bytes feed unchanged code rather than declare any; a
// non-Go compiled input is never a member (the variant node repeats the
// base's SFiles and CFiles) (REQ-closure-test-variant-compartment).
type TestVariantFileHeader struct {
	File     string // relative to the package directory
	Hash     string
	Embedded bool
}

// TestVariantDelta is the classified difference between two compartment
// ledgers — a recorded one and a current one. Added, Changed, and Removed are
// sorted with the ledger's declaration ordering; HeaderChanges is sorted by
// file. It is data plus Go semantics: Inert reports whether the delta can
// change the behavior of any unchanged declaration, and nothing about what a
// consumer should do with that fact (REQ-closure-test-variant-compartment).
type TestVariantDelta struct {
	Added   []TestVariantDeclaration
	Changed []TestVariantDeclarationChange
	Removed []TestVariantDeclaration
	// HeaderChanges carries every file whose header identity moved: an empty
	// Before is a file new to the compartment, an empty After a file that
	// left it.
	HeaderChanges []TestVariantHeaderChange
}

// TestVariantDeclarationChange pairs a declaration's recorded and current
// ledger entries.
type TestVariantDeclarationChange struct {
	Before TestVariantDeclaration
	After  TestVariantDeclaration
}

// TestVariantHeaderChange is one file's header-identity movement. Embedded
// reports that either side is an embedded (non-compiled) member, whose
// movement defeats inertness fail-closed.
type TestVariantHeaderChange struct {
	File     string
	Before   string // empty when the file is new to the compartment
	After    string // empty when the file left the compartment
	Embedded bool
}

// Inert reports whether this delta is behavior-inert for unchanged code: no
// declaration changed or was removed, and every added declaration is one no
// unchanged declaration can observe — a plain function (no receiver, not init,
// not TestMain), a const, or a type (an accompanying method would be its own
// added "method" entry and defeat inertness). The rejected kinds each name a
// mechanism reaching unchanged code: a package var's initializer runs during
// test-binary initialization; an init function likewise; TestMain replaces
// the harness entry wrapping every unchanged test; a method can flip
// interface satisfaction observed by unchanged type assertions and dispatch.
// Additions that shift what an existing declaration means are not silent
// adds: positional semantics — a const's ordinal in its group, a var's or an
// init's ordinal in its file — are folded into declaration hashes (see
// TestVariantDeclaration), so an insertion that shifts iota siblings or a
// reorder of initialization surfaces as Changed and defeats inertness here.
// Go-file header-only changes — imports, build-constraint text, comments
// outside declarations — do not defeat inertness: this is the one place the
// judgment leans on the partition rule, because test-only dependency NODES
// stay in the core closure, so the core equality under which a consumer sees
// this delta already proves no new dependency package entered the test
// binary, making an import edit among already-present packages init-benign.
// Compiler and linker directives are NOT header content: they are ledgered
// as their own "directive" entries wherever they sit (see
// TestVariantDeclaration), and the unknown-kind default below fails closed
// on them — a //go:debug or //go:linkname addition is never inert.
// An embedded (non-compiled) member's delta defeats inertness fail-closed —
// whatever its name, a .go-named testdata fixture included: its bytes feed
// unchanged declarations that read it, and its whole content is its header,
// so a header move IS a content move.
func (d TestVariantDelta) Inert() bool {
	if len(d.Changed) != 0 || len(d.Removed) != 0 {
		return false
	}
	for _, added := range d.Added {
		switch added.Kind {
		case "const", "type":
		case "func":
			if added.Name == "TestMain" {
				return false
			}
		default: // method, init, var, and anything unrecognized fail closed
			return false
		}
	}
	for _, header := range d.HeaderChanges {
		if header.Embedded {
			return false
		}
	}
	return true
}

// DiffTestVariantLedgers classifies the delta from a recorded ledger to a
// current one. Declarations are matched by (File, Package, Kind, Receiver,
// Name) — the package clause is diff identity, so an entry recorded without
// one (a pre-clause ledger) matches nothing and classifies removed;
// entries sharing that identity (several init functions in one file) pair by
// sorted hash, surplus recorded entries reporting as removed and surplus
// current ones as added. The result is deterministic for any two ledgers.
func DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta {
	type identity struct {
		file, pkg, kind, receiver, name string
	}
	group := func(declarations []TestVariantDeclaration) (map[identity][]TestVariantDeclaration, []identity) {
		grouped := make(map[identity][]TestVariantDeclaration, len(declarations))
		var order []identity
		for _, declaration := range declarations {
			key := identity{declaration.File, declaration.Package, declaration.Kind, declaration.Receiver, declaration.Name}
			if _, ok := grouped[key]; !ok {
				order = append(order, key)
			}
			grouped[key] = append(grouped[key], declaration)
		}
		return grouped, order
	}
	recorded, recordedOrder := group(before.Declarations)
	current, currentOrder := group(after.Declarations)
	var delta TestVariantDelta
	for _, key := range recordedOrder {
		was := recorded[key]
		now := current[key]
		shared := map[string]int{}
		for _, declaration := range now {
			shared[declaration.Hash]++
		}
		var leftBefore []TestVariantDeclaration
		for _, declaration := range was {
			if shared[declaration.Hash] > 0 {
				shared[declaration.Hash]--
				continue
			}
			leftBefore = append(leftBefore, declaration)
		}
		var leftAfter []TestVariantDeclaration
		matched := map[string]int{}
		for _, declaration := range was {
			matched[declaration.Hash]++
		}
		for _, declaration := range now {
			if matched[declaration.Hash] > 0 {
				matched[declaration.Hash]--
				continue
			}
			leftAfter = append(leftAfter, declaration)
		}
		for i := 0; i < len(leftBefore) && i < len(leftAfter); i++ {
			delta.Changed = append(delta.Changed, TestVariantDeclarationChange{Before: leftBefore[i], After: leftAfter[i]})
		}
		if len(leftBefore) > len(leftAfter) {
			delta.Removed = append(delta.Removed, leftBefore[len(leftAfter):]...)
		}
		if len(leftAfter) > len(leftBefore) {
			delta.Added = append(delta.Added, leftAfter[len(leftBefore):]...)
		}
	}
	for _, key := range currentOrder {
		if _, ok := recorded[key]; !ok {
			delta.Added = append(delta.Added, current[key]...)
		}
	}
	headers := func(ledger TestVariantLedger) map[string]TestVariantFileHeader {
		byFile := make(map[string]TestVariantFileHeader, len(ledger.FileHeaders))
		for _, header := range ledger.FileHeaders {
			byFile[header.File] = header
		}
		return byFile
	}
	recordedHeaders := headers(before)
	currentHeaders := headers(after)
	for _, header := range before.FileHeaders {
		now, ok := currentHeaders[header.File]
		if !ok {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, Before: header.Hash, Embedded: header.Embedded})
			continue
		}
		if now.Hash != header.Hash || now.Embedded != header.Embedded {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, Before: header.Hash, After: now.Hash, Embedded: header.Embedded || now.Embedded})
		}
	}
	for _, header := range after.FileHeaders {
		if _, ok := recordedHeaders[header.File]; !ok {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, After: header.Hash, Embedded: header.Embedded})
		}
	}
	sortDeclarations := func(declarations []TestVariantDeclaration) {
		sort.Slice(declarations, func(i, j int) bool { return LessDeclaration(declarations[i], declarations[j]) })
	}
	sortDeclarations(delta.Added)
	sortDeclarations(delta.Removed)
	sort.Slice(delta.Changed, func(i, j int) bool { return LessDeclaration(delta.Changed[i].After, delta.Changed[j].After) })
	sort.Slice(delta.HeaderChanges, func(i, j int) bool { return delta.HeaderChanges[i].File < delta.HeaderChanges[j].File })
	return delta
}

// LessDeclaration is the ledger's canonical declaration order: by file,
// kind, receiver, and name.
func LessDeclaration(a, b TestVariantDeclaration) bool {
	switch {
	case a.File != b.File:
		return a.File < b.File
	case a.Kind != b.Kind:
		return a.Kind < b.Kind
	case a.Receiver != b.Receiver:
		return a.Receiver < b.Receiver
	case a.Name != b.Name:
		return a.Name < b.Name
	default:
		return a.Hash < b.Hash
	}
}

// Clone returns a caller-owned deep copy of the ledger.
func (l TestVariantLedger) Clone() TestVariantLedger {
	declarations := append([]TestVariantDeclaration(nil), l.Declarations...)
	for i := range declarations {
		declarations[i].References = append([]string(nil), declarations[i].References...)
	}
	return TestVariantLedger{
		Declarations: declarations,
		FileHeaders:  append([]TestVariantFileHeader(nil), l.FileHeaders...),
	}
}
