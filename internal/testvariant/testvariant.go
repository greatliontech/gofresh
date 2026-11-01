// Package testvariant is the vocabulary of a package's test-variant
// compartment (REQ-closure-test-variant-ledger): the declaration
// ledger persisted beside a compartment hash, the delta between two
// ledgers and its inertness classification, and the empty compartment's
// identity. The compartment's computation lives with the closure engine.
package testvariant

import (
	"go/ast"
	"go/parser"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// BindingStrategy identifies the complete syntax-derived binding evidence.
// A missing or unknown strategy cannot establish inertness; old evidence must
// be recaptured, never upgraded by filling in this value.
const BindingStrategy = "gofresh/test-variant-bindings@1"

// EmptyTestVariantClosure is the test-variant compartment identity of a package
// with no test files: the empty-file-set hash under the same name\x00sha256
// discipline as every other compartment. It is a stable constant — a recorded
// compartment equal to it stays valid for as long as the package has no test
// files — and it is never the empty string, so an empty recorded compartment
// unambiguously identifies a recording that predates the partition
// (REQ-closure-test-variant-identity).
const EmptyTestVariantClosure = "e3b0c44298fc1c149afbf4c8996fb924"

// TestVariantLedger is the declaration-level read surface over a package's
// test-variant compartment: every top-level declaration in the compartment's Go
// files and a per-file header identity over each file's non-declaration
// remainder, plus binding evidence for compiled test and base files. Complete
// ledger keys include the core identity, compartment, configuration and strategy.
// It is data for a consumer to persist at capture and diff at check;
// gofresh renders no judgment about which deltas are benign
// (REQ-closure-test-variant-ledger).
type TestVariantLedger struct {
	BindingStrategy string
	// BaseFiles carries binding evidence for production Go files recompiled
	// with the in-package tests. Its bytes belong to the core, not the compartment.
	// Only File and Bindings are populated; Hash is empty and Embedded false.
	BaseFiles []TestVariantFileHeader
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
	// served to attribute a compartment delta to the declarations that
	// can reach it (InertForSubject). Directive entries carry none.
	References []string
}

// TestVariantFileHeader is one compartment file's non-declaration identity.
// A compiled Go member's hash covers its non-declaration remainder; every
// other member — embedded data whatever its name, a .go-named testdata
// fixture included — carries Embedded true and a whole-content hash,
// because its bytes feed unchanged code rather than declare any; a
// non-Go compiled input is never a member (the variant node repeats the
// base's SFiles and CFiles) (REQ-closure-test-variant-ledger).
type TestVariantFileHeader struct {
	File     string // relative to the package directory
	Hash     string
	Embedded bool
	// Bindings is syntax-derived scope evidence for a compiled member. Nil
	// means no evidence, not an empty reference surface.
	Bindings *TestVariantFileBindings
}

// TestVariantFileBindings describes names that unchanged code can resolve.
// References conservatively includes local names and selector members, like
// declaration References. Imports records effective local names and import
// paths; blank imports cannot bind names, and dot imports expose an unknown
// set of names. An empty import Name is unresolved and defeats inertness.
type TestVariantFileBindings struct {
	Package    string
	References []string
	Imports    []TestVariantImport
}

// TestVariantImport is one file-scoped import binding. Name is the effective
// local name (including "_" and "."), not the path's last component.
type TestVariantImport struct {
	Name string
	Path string
}

// TestVariantDelta is the classified difference between two compartment
// ledgers — a recorded one and a current one. Added, Changed, and Removed are
// sorted with the ledger's declaration ordering; HeaderChanges is sorted by
// file. It is data plus Go semantics: Inert reports whether the delta can
// change the behavior of any unchanged declaration, and nothing about what a
// consumer should do with that fact (REQ-closure-test-variant-inertness).
type TestVariantDelta struct {
	// BindingsPreserved is proof from recognized complete ledgers, including
	// production files. A zero or manually assembled delta carries no proof.
	BindingsPreserved bool
	Added             []TestVariantDeclaration
	Changed           []TestVariantDeclarationChange
	Removed           []TestVariantDeclaration
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
// unchanged declaration can observe under the conservative binding checks — a
// plain function (no receiver, not init, not TestMain), a const, or a type (an
// accompanying method would be its own added "method" entry and defeat
// inertness). The rejected kinds each name a
// mechanism reaching unchanged code: a package var's initializer runs during
// test-binary initialization; an init function likewise; TestMain replaces
// the harness entry wrapping every unchanged test; a method can flip
// interface satisfaction observed by unchanged type assertions and dispatch.
// Position-shifting additions are not silent adds: positional semantics —
// a const's ordinal in its group, a var's or an
// init's ordinal in its file — are folded into declaration hashes (see
// TestVariantDeclaration), so an insertion that shifts iota siblings or a
// reorder of initialization surfaces as Changed and defeats inertness here.
// Complete versioned binding evidence covers compiled test and base files:
// added package names must not intersect existing same-package reference
// surfaces, and used import names must retain their bindings. The reference
// over-approximation may refuse a local/selector-name collision. Dot-import
// changes refuse whenever a file has references. Comments and build constraints
// remain benign under unchanged membership and declarations. Core equality is
// still a consumer precondition: it guards dependency initialization, but cannot
// by itself prove import-alias stability.
// Compiler and linker directives are NOT header content: they are ledgered
// as their own "directive" entries wherever they sit (see
// TestVariantDeclaration), and the unknown-kind default below fails closed
// on them — a //go:debug or //go:linkname addition is never inert.
// An embedded (non-compiled) member's delta defeats inertness fail-closed —
// whatever its name, a .go-named testdata fixture included: its bytes feed
// unchanged declarations that read it, and its whole content is its header,
// so a header move IS a content move.
func inertAddedDeclaration(added TestVariantDeclaration) bool {
	switch added.Kind {
	case "const", "type":
		return true
	case "func":
		return added.Name != "TestMain"
	default: // method, init, var, directive, and anything unrecognized fail closed
		return false
	}
}

func (d TestVariantDelta) Inert() bool {
	if !d.BindingsPreserved {
		return false
	}
	if len(d.Changed) != 0 || len(d.Removed) != 0 {
		return false
	}
	for _, added := range d.Added {
		if !inertAddedDeclaration(added) {
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

type declarationIdentity struct {
	file, pkg, kind, receiver, name string
}

func idOfDeclaration(d TestVariantDeclaration) declarationIdentity {
	return declarationIdentity{d.File, d.Package, d.Kind, d.Receiver, d.Name}
}

func receiverTypeName(recv string) string {
	if recv == "" {
		return ""
	}
	expr, err := parser.ParseExpr(recv)
	if err != nil {
		return ""
	}
	for {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
}

// InertForSubject reports whether the delta from before to after is behavior-inert
// for subjectSymbol (a top-level declaration name or "Type.Method" method
// reference). When DiffTestVariantLedgers(before, after).Inert() holds, the
// delta is inert for every unchanged declaration in the package and returns
// true immediately. Otherwise, InertForSubject computes the transitive
// syntactic reference cone of subjectSymbol across before.Declarations
// (including all init, var, directive, and TestMain declarations and any
// compartment declarations referenced by BaseFiles, propagating exported
// references from "_test" to the base package and matching methods by reachable
// receiver type) and reports true only when no declaration in that cone changed
// or was removed, every added declaration is an inert kind (plain func other
// than TestMain, const, or type) whose name does not shadow any reachable or
// base-file reference, no embedded file header changed, and every file
// containing a reachable declaration retains its package and import bindings
// for all reachable references (REQ-closure-test-variant-inertness).
func InertForSubject(before, after TestVariantLedger, subjectSymbol string) bool {
	if subjectSymbol == "" || strings.HasPrefix(subjectSymbol, "init#") {
		return false
	}
	recv, name, hasDot := strings.Cut(subjectSymbol, ".")
	if !hasDot {
		recv, name = "", subjectSymbol
	}
	if name == "" || (hasDot && recv == "") || strings.Contains(name, ".") {
		return false
	}
	d := DiffTestVariantLedgers(before, after)
	if d.Inert() {
		return true
	}
	if before.BindingStrategy != BindingStrategy || after.BindingStrategy != BindingStrategy {
		return false
	}
	if !reflect.DeepEqual(before.BaseFiles, after.BaseFiles) {
		return false
	}
	oldFiles, ok := ledgerFileBindings(before)
	if !ok {
		return false
	}
	nowFiles, ok := ledgerFileBindings(after)
	if !ok {
		return false
	}
	for _, header := range d.HeaderChanges {
		if header.Embedded {
			return false
		}
	}
	for _, added := range d.Added {
		if !inertAddedDeclaration(added) {
			return false
		}
	}

	baseRefsByPkg := map[string]map[string]bool{}
	for _, base := range before.BaseFiles {
		if base.Bindings == nil {
			continue
		}
		refs := baseRefsByPkg[base.Bindings.Package]
		if refs == nil {
			refs = map[string]bool{}
			baseRefsByPkg[base.Bindings.Package] = refs
		}
		for _, ref := range base.Bindings.References {
			refs[ref] = true
		}
	}

	afterByKey := make(map[declarationIdentity][]TestVariantDeclaration, len(after.Declarations))
	for _, decl := range after.Declarations {
		key := idOfDeclaration(decl)
		afterByKey[key] = append(afterByKey[key], decl)
	}

	matchesSubject := func(decl TestVariantDeclaration) bool {
		if hasDot {
			return decl.Kind == "method" && decl.Name == name && receiverTypeName(decl.Receiver) == recv
		}
		return decl.Kind != "method" && decl.Kind != "directive" && decl.Kind != "init" && decl.Name == name
	}

	reachableNamesByPkg := map[string]map[string]bool{}
	reachableFileRefs := map[string]map[string]bool{}
	reachableFiles := map[string]bool{}
	reachableDecls := make([]bool, len(before.Declarations))
	reachableIdentity := map[declarationIdentity]bool{}

	addName := func(pkg, ref string) {
		if ref == "" {
			return
		}
		names := reachableNamesByPkg[pkg]
		if names == nil {
			names = map[string]bool{}
			reachableNamesByPkg[pkg] = names
		}
		names[ref] = true
		if basePkg, isExt := strings.CutSuffix(pkg, "_test"); isExt && ast.IsExported(ref) {
			baseNames := reachableNamesByPkg[basePkg]
			if baseNames == nil {
				baseNames = map[string]bool{}
				reachableNamesByPkg[basePkg] = baseNames
			}
			baseNames[ref] = true
		}
	}
	addFileRef := func(file, ref string) {
		if ref == "" {
			return
		}
		refs := reachableFileRefs[file]
		if refs == nil {
			refs = map[string]bool{}
			reachableFileRefs[file] = refs
		}
		refs[ref] = true
	}
	markDecl := func(i int) bool {
		if reachableDecls[i] {
			return false
		}
		reachableDecls[i] = true
		decl := before.Declarations[i]
		id := idOfDeclaration(decl)
		reachableIdentity[id] = true
		reachableFiles[decl.File] = true
		if decl.Name != "" && decl.Name != "_" {
			addName(decl.Package, decl.Name)
		}
		if decl.Kind == "method" {
			if rt := receiverTypeName(decl.Receiver); rt != "" {
				addName(decl.Package, rt)
			}
		}
		for _, ref := range decl.References {
			addName(decl.Package, ref)
			addFileRef(decl.File, ref)
		}
		for _, afterDecl := range afterByKey[id] {
			for _, ref := range afterDecl.References {
				addName(decl.Package, ref)
				addFileRef(decl.File, ref)
			}
		}
		return true
	}

	rooted := false
	for i, decl := range before.Declarations {
		if matchesSubject(decl) {
			rooted = true
			markDecl(i)
			continue
		}
		switch {
		case decl.Kind == "init", decl.Kind == "var", decl.Kind == "directive", decl.Kind == "func" && decl.Name == "TestMain":
			markDecl(i)
		case decl.Kind == "method":
			rt := receiverTypeName(decl.Receiver)
			if rt == "" || baseRefsByPkg[decl.Package][rt] {
				markDecl(i)
			}
		default:
			if decl.Name != "_" && baseRefsByPkg[decl.Package][decl.Name] {
				markDecl(i)
			}
		}
	}
	for _, base := range before.BaseFiles {
		if base.Bindings == nil {
			continue
		}
		if slices.Contains(base.Bindings.References, name) && (!hasDot || slices.Contains(base.Bindings.References, recv)) {
			rooted = true
			addName(base.Bindings.Package, name)
			if hasDot {
				addName(base.Bindings.Package, recv)
			}
		}
	}
	if !rooted {
		return false
	}

	for {
		progressed := false
		for i, decl := range before.Declarations {
			if reachableDecls[i] {
				continue
			}
			if decl.Kind == "method" {
				rt := receiverTypeName(decl.Receiver)
				if rt == "" || reachableNamesByPkg[decl.Package][rt] {
					progressed = markDecl(i) || progressed
				}
				continue
			}
			if decl.Name == "_" && decl.Kind != "const" {
				continue
			}
			if reachableNamesByPkg[decl.Package][decl.Name] {
				progressed = markDecl(i) || progressed
			}
		}
		if !progressed {
			break
		}
	}

	for _, change := range d.Changed {
		if reachableIdentity[idOfDeclaration(change.Before)] {
			return false
		}
	}
	for _, removed := range d.Removed {
		if reachableIdentity[idOfDeclaration(removed)] {
			return false
		}
	}
	for _, added := range d.Added {
		if added.Name == "_" {
			if added.Kind == "const" && reachableNamesByPkg[added.Package]["_"] {
				return false
			}
			continue
		}
		if reachableNamesByPkg[added.Package][added.Name] || baseRefsByPkg[added.Package][added.Name] {
			return false
		}
		if ast.IsExported(added.Name) && reachableNamesByPkg[added.Package+"_test"][added.Name] {
			return false
		}
	}

	for file := range reachableFiles {
		b, n := oldFiles[file], nowFiles[file]
		if b == nil || n == nil || n.Package != b.Package {
			return false
		}
		was, next := fileImportsMap(b), fileImportsMap(n)
		refs := reachableFileRefs[file]
		if len(refs) != 0 && was["."] != next["."] {
			return false
		}
		for ref := range refs {
			if was[ref] != next[ref] {
				return false
			}
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
	delta.BindingsPreserved = bindingsPreserved(before, after, delta.Added)
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
		BindingStrategy: l.BindingStrategy,
		BaseFiles:       cloneHeaders(l.BaseFiles),
		Declarations:    declarations,
		FileHeaders:     cloneHeaders(l.FileHeaders),
	}
}

func cloneHeaders(headers []TestVariantFileHeader) []TestVariantFileHeader {
	result := append([]TestVariantFileHeader(nil), headers...)
	for i := range result {
		if b := result[i].Bindings; b != nil {
			copy := *b
			copy.References = append([]string(nil), b.References...)
			copy.Imports = append([]TestVariantImport(nil), b.Imports...)
			result[i].Bindings = &copy
		}
	}
	return result
}

func ledgerFileBindings(l TestVariantLedger) (map[string]*TestVariantFileBindings, bool) {
	m := map[string]*TestVariantFileBindings{}
	for _, group := range [][]TestVariantFileHeader{l.BaseFiles, l.FileHeaders} {
		for _, h := range group {
			if h.Bindings == nil && h.Embedded {
				continue
			}
			if h.Bindings == nil {
				return nil, false
			}
			for _, imp := range h.Bindings.Imports {
				if imp.Name == "" {
					return nil, false
				}
			}
			if _, dup := m[h.File]; dup {
				return nil, false
			}
			m[h.File] = h.Bindings
		}
	}
	for _, declaration := range l.Declarations {
		if b := m[declaration.File]; b == nil || b.Package != declaration.Package {
			return nil, false
		}
	}
	return m, true
}

func fileImportsMap(b *TestVariantFileBindings) map[string]string {
	m := map[string]string{}
	for _, i := range b.Imports {
		if i.Name != "_" {
			m[i.Name] += i.Path + "\x00"
		}
	}
	return m
}

func bindingsPreserved(before, after TestVariantLedger, added []TestVariantDeclaration) bool {
	if before.BindingStrategy != BindingStrategy || after.BindingStrategy != BindingStrategy {
		return false
	}
	// The caller guards the core, but the evidence must also describe the
	// same base files. Never accept a truncated or mixed-generation ledger.
	if !reflect.DeepEqual(before.BaseFiles, after.BaseFiles) {
		return false
	}
	old, ok := ledgerFileBindings(before)
	if !ok {
		return false
	}
	now, ok := ledgerFileBindings(after)
	if !ok {
		return false
	}
	for file, b := range old {
		n := now[file]
		if n == nil || n.Package != b.Package {
			return false
		}
		was, next := fileImportsMap(b), fileImportsMap(n)
		if len(b.References) != 0 && was["."] != next["."] {
			return false
		}
		for _, ref := range b.References {
			if was[ref] != next[ref] {
				return false
			}
			for _, a := range added {
				if a.Name != "_" && a.Package == b.Package && a.Name == ref {
					return false
				}
			}
		}
	}
	return true
}
