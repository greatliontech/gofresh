package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/closure"
	"golang.org/x/tools/go/packages"
)

// dynamicStateFact is one package's contribution to the shared-dynamic-state
// downgrade (REQ-closure-shared-dynamic-state) plus its method-directive
// declarations: everything the analysis needs from the package's syntax, so a
// version-pinned package's syntax never loads twice per key.
type dynamicStateFact struct {
	// Declares holds the package's dynamic-capable package-level variable
	// keys (package path + name). Standard-library packages declare none
	// here by construction — the downgrade analysis has always excluded
	// module-less packages from its declaration side.
	Declares []string `json:"declares,omitempty"`
	// Mutates holds the variable keys this package's code demonstrably
	// mutates after initialization — writes, growth/deletion, sends,
	// address captures, pointer-receiver method uses, rebindings —
	// judged fail-closed by carrier shape.
	Mutates []string `json:"mutates,omitempty"`
	// Escapes holds the alias-carrier variable keys this package's code
	// hands to code that may write them — call arguments, stores,
	// returns, bindings, method calls, type assertions. An escape is
	// mutation-equivalent unless the variable is object-closed in its
	// declaring package.
	Escapes []string `json:"escapes,omitempty"`
	// Opaque holds the declaring package's object-closed interface
	// variable keys: initializer and every init-flow store are audited
	// immutable constructions, so no holder of the value can mutate the
	// shared object.
	Opaque []string `json:"opaque,omitempty"`
	// ReceiverReadOnly holds the full method keys (package path,
	// receiver type, method) this package declares and proves unable to
	// write receiver-reachable state.
	ReceiverReadOnly []string `json:"receiverReadOnly,omitempty"`
	// MethodUses holds deferred method-use marks: variable key and
	// method key joined by NUL. At composition the use is discharged
	// only when the method key is proven read-only by its declaring
	// fact; otherwise the variable marks mutated - fail-closed.
	MethodUses []string `json:"methodUses,omitempty"`
	// ParamLeakFree holds the parameter keys (package path, function
	// name, zero-based parameter index joined by NUL) this package
	// declares and proves unable to write, retain, or hand out the
	// bound value.
	ParamLeakFree []string `json:"paramLeakFree,omitempty"`
	// ParamUses holds deferred call-argument marks: variable key and
	// callee parameter key joined by NUL. At composition the use is
	// discharged only when the parameter is proven leak-free by its
	// declaring fact; otherwise the variable marks escaped -
	// fail-closed, init flow included, because an alias outlives
	// initialization.
	ParamUses []string `json:"paramUses,omitempty"`
	// AttributedUses holds carrier uses recorded inside plain named
	// functions - function key, variable key, and use class joined by
	// NUL - discharged at composition when the graph proves the
	// function init-only, promoted to their immediate class otherwise.
	AttributedUses []string `json:"attributedUses,omitempty"`
	// FuncRefs holds reference-region edges for plain named functions -
	// callee key and region joined by NUL, the region "init", "prog",
	// or a caller's function key - composed to the graph-wide init-only
	// fixed point.
	FuncRefs []string `json:"funcRefs,omitempty"`
	// OpacityBreaks holds interface variable keys - own or foreign -
	// whose object-closure this package's init flow breaks: a
	// non-audited, indirect, or address-capturing init store. Unioned at
	// composition so a cross-package init store fails the declaring
	// package's opacity.
	OpacityBreaks []string `json:"opacityBreaks,omitempty"`
	// EnvCarrying holds the variable keys - own or foreign - into which
	// this package's direct code stores a function-carrying value that is
	// not provably environment-free. Unioned at composition: a carrier
	// holding such a value refuses every observer with a named culprit -
	// a registered closure's environment can write state the settled
	// verdict assumed stable.
	EnvCarrying []string `json:"envCarrying,omitempty"`
	// EnvCallUses holds deferred constructor-registration marks:
	// variable key and callee function key (package path, function name
	// NUL-joined) joined by \x01. At composition the store is admitted
	// only when the callee's return-environment-free proof resolves;
	// otherwise the variable joins the environment-audit refusals -
	// fail-closed.
	EnvCallUses []string `json:"envCallUses,omitempty"`
	// ReturnEnvFree holds the function keys (package path, function
	// name NUL-joined) this package declares and proves to return only
	// environment-free values given environment-free arguments.
	ReturnEnvFree []string `json:"returnEnvFree,omitempty"`
	// ReturnEnvDeps holds conditional edges of those proofs: function
	// key and callee function key joined by \x01 - the proof resolves
	// only when every edge target resolves, cycles and absence failing
	// closed.
	ReturnEnvDeps []string `json:"returnEnvDeps,omitempty"`
	// PureMethods and ExternalMethods map "Recv.Method" to the declaration
	// key of a method declaration carrying the respective directive, so a
	// method promoted into a scanned type honors its directive without the
	// declaring package's syntax in hand (REQ-purity-directive,
	// REQ-external-directive).
	PureMethods     map[string]string `json:"pureMethods,omitempty"`
	ExternalMethods map[string]string `json:"externalMethods,omitempty"`
}

// dynamicStateFactOf derives one typed package's fact. Pure function of the
// package's selected syntax and type environment.
func dynamicStateFactOf(p *packages.Package) dynamicStateFact {
	var fact dynamicStateFact
	mutated, escaped, opaque, breaks := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	initOnly := initOnlyReachableHelpers(p)
	methodUses := map[string]map[string]bool{}
	paramUses := map[string]map[string]bool{}
	var attributedUses []attributedUse
	funcRefs := map[string]map[string]bool{}
	envCarrying := map[string]bool{}
	recordDynamicGlobalUses(p, mutated, escaped, initOnly, methodUses, paramUses, &attributedUses)
	recordFunctionReferenceRegions(p, initOnly, funcRefs)
	recordOpaqueDynamicVars(p, opaque, breaks)
	envCalls := map[string]map[string]bool{}
	recordEnvCarryingRegistrations(p, envCarrying, envCalls)
	for key := range envCarrying {
		fact.EnvCarrying = append(fact.EnvCarrying, key)
	}
	sort.Strings(fact.EnvCarrying)
	for varKey, callees := range envCalls {
		for callee := range callees {
			fact.EnvCallUses = append(fact.EnvCallUses, varKey+"\x01"+callee)
		}
	}
	sort.Strings(fact.EnvCallUses)
	for _, use := range attributedUses {
		class := "m"
		if use.escape {
			class = "e"
		}
		if use.method != "" {
			class = "d\x00" + use.method
		}
		fact.AttributedUses = append(fact.AttributedUses, use.fn+"\x00"+use.key+"\x00"+class)
	}
	sort.Strings(fact.AttributedUses)
	for callee, regions := range funcRefs {
		for region := range regions {
			// The callee key and a caller-key region each carry their
			// own NUL, so the edge frames with a distinct separator.
			fact.FuncRefs = append(fact.FuncRefs, callee+"\x01"+region)
		}
	}
	sort.Strings(fact.FuncRefs)
	readOnly := receiverReadOnlyMethods(p)
	for method := range readOnly {
		if p.Types != nil {
			fact.ReceiverReadOnly = append(fact.ReceiverReadOnly, p.Types.Path()+"\x00"+method)
		}
	}
	sort.Strings(fact.ReceiverReadOnly)
	for varKey, methodKeys := range methodUses {
		for methodKey := range methodKeys {
			fact.MethodUses = append(fact.MethodUses, varKey+"\x00"+methodKey)
		}
	}
	sort.Strings(fact.MethodUses)
	if p.Types != nil {
		paramLeakFree := paramLeakFreeFunctions(p, readOnly)
		for paramKey := range paramLeakFree {
			fact.ParamLeakFree = append(fact.ParamLeakFree, p.Types.Path()+"\x00"+paramKey)
		}
		envFree, envDeps := returnEnvFreeFunctions(p, paramLeakFree, readOnly)
		for fnName := range envFree {
			fnKey := p.Types.Path() + "\x00" + fnName
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range envDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, fnKey+"\x01"+callee)
			}
		}
		sort.Strings(fact.ReturnEnvFree)
		sort.Strings(fact.ReturnEnvDeps)
	}
	sort.Strings(fact.ParamLeakFree)
	for varKey, paramKeys := range paramUses {
		for paramKey := range paramKeys {
			fact.ParamUses = append(fact.ParamUses, varKey+"\x00"+paramKey)
		}
	}
	sort.Strings(fact.ParamUses)
	for key := range mutated {
		fact.Mutates = append(fact.Mutates, key)
	}
	sort.Strings(fact.Mutates)
	for key := range escaped {
		fact.Escapes = append(fact.Escapes, key)
	}
	sort.Strings(fact.Escapes)
	for key := range opaque {
		fact.Opaque = append(fact.Opaque, key)
	}
	sort.Strings(fact.Opaque)
	for key := range breaks {
		fact.OpacityBreaks = append(fact.OpacityBreaks, key)
	}
	sort.Strings(fact.OpacityBreaks)
	if p.Types != nil && p.Module != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if variable, ok := scope.Lookup(name).(*types.Var); ok && typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
				fact.Declares = append(fact.Declares, dynamicVarKey(variable))
			}
		}
		sort.Strings(fact.Declares)
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			recv := recvTypeName(fd)
			if recv == "" {
				continue
			}
			key := recv + "." + fd.Name.Name
			if hasDirective(fd.Doc, "//gofresh:pure") {
				if fact.PureMethods == nil {
					fact.PureMethods = map[string]string{}
				}
				fact.PureMethods[key] = nodeDeclarationKey(p, fd.Name)
			}
			if hasDirective(fd.Doc, "//gofresh:external") {
				if fact.ExternalMethods == nil {
					fact.ExternalMethods = map[string]string{}
				}
				fact.ExternalMethods[key] = nodeDeclarationKey(p, fd.Name)
			}
		}
	}
	return fact
}

// processFactCache serves version-pinned package facts within one process.
// Keyed by (scope, bucket, package path) — the same complete identity the
// persistent memo trusts, so a hit is sound wherever the persistent entry
// would be.
var processFactCache sync.Map

// viewDynamicState is the per-pass dynamic-state derivation over one view's
// metadata graph: fresh facts for every mutable-local node from the pass's
// own typed load, memoized facts for version-pinned modules (persistent under
// factScope, in-process always), standard-library nodes skipped — inert by
// construction: their declaration side is excluded and toolchain source
// cannot reach module variables (imports are acyclic).
type viewDynamicState struct {
	// facts by type-checker package path; test-variant facts merge into the
	// same key exactly as their compilations collapse there.
	facts map[string][]dynamicStateFact
	// downgraded maps each package whose graph carries mutated shared
	// dynamic state — every subject of such a package is unverifiable —
	// to one culprit description naming the owning package and variable.
	downgraded map[string]string
	// vouchDischarges maps each view package to the canonical sorted
	// comma-joined caller-vouch identities that discharged would-be
	// culprits reachable from it (REQ-vouch-recorded); absent when no
	// vouch was load-bearing for the package.
	vouchDischarges map[string]string
}

// methodDirectives resolves a promoted method's purity and externality
// directives from its declaring package's fact — the declaration keys, empty
// when absent. Toolchain source is not an authoring surface for gofresh
// directives, so standard-library methods resolve to none by construction.
func (s *viewDynamicState) methodDirectives(m *types.Func) (pureKey, externalKey string) {
	if s == nil || m == nil || m.Pkg() == nil {
		return "", ""
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", ""
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return "", ""
	}
	key := named.Obj().Name() + "." + m.Name()
	for _, fact := range s.facts[m.Pkg().Path()] {
		if pureKey == "" {
			pureKey = fact.PureMethods[key]
		}
		if externalKey == "" {
			externalKey = fact.ExternalMethods[key]
		}
	}
	return pureKey, externalKey
}

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, load *closure.ViewLoad, viewPackages []string, vouches map[string]bool) (*viewDynamicState, error) {
	meta, err := hasher.GraphMetadata(viewPackages...)
	if err != nil {
		return nil, err
	}
	state := &viewDynamicState{facts: map[string][]dynamicStateFact{}, downgraded: map[string]string{}}

	// Mutable-local facts come from the pass's own typed load — content
	// observed every pass, never cached (REQ-closure-mutable-local). The
	// load's roots are matched to metadata nodes by listing identity so a
	// local dependency's own test variants (loaded only because Tests is a
	// load-wide setting) contribute nothing the metadata graph doesn't name.
	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	matched := map[string]bool{}
	for _, pkg := range load.Packages() {
		listing := pkg.PkgPath
		if pkg.ForTest != "" {
			listing = pkg.PkgPath + " [" + pkg.ForTest + ".test]"
		}
		node, ok := nodesByListing[listing]
		if !ok || node.Class != closure.MutableLocalPackage || node.TestMain {
			// The toolchain-generated test-main package is startup
			// scaffolding, not an analysis surface: its registration
			// tables contribute neither declarations nor mutations
			// (REQ-closure-shared-dynamic-state).
			continue
		}
		matched[listing] = true
		state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg))
	}
	// An intermediate recompilation ("r [a.test]") exists only inside a test
	// binary's graph: it is scanned from its own compilation — test-added
	// methods can lawfully change its selections, and its plain form need
	// not even compile — through one dependency-expanded load of the tested
	// packages, performed only when the test-cycle shape exists.
	var testedWithIntermediates []string
	seenTested := map[string]bool{}
	for _, node := range meta {
		if node.Class == closure.StandardPackage || matched[node.ImportPath] || node.TestMain || node.ForTest == "" {
			continue
		}
		if node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test" {
			continue
		}
		if !seenTested[node.ForTest] {
			seenTested[node.ForTest] = true
			testedWithIntermediates = append(testedWithIntermediates, node.ForTest)
		}
	}
	if len(testedWithIntermediates) > 0 {
		sort.Strings(testedWithIntermediates)
		graphLoad, err := closure.LoadViewGraphEnv(ctx, dir, env, buildFlags, testedWithIntermediates...)
		if err != nil {
			return nil, err
		}
		packages.Visit(graphLoad.Packages(), nil, func(pkg *packages.Package) {
			if pkg.ForTest == "" {
				return
			}
			listing := pkg.PkgPath + " [" + pkg.ForTest + ".test]"
			node, ok := nodesByListing[listing]
			if !ok || node.Class == closure.StandardPackage || matched[listing] {
				return
			}
			matched[listing] = true
			state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg))
		})
	}
	for _, node := range meta {
		if node.TestMain || node.Class == closure.StandardPackage || matched[node.ImportPath] {
			continue
		}
		if node.Class == closure.PinnedPackage && node.ForTest == "" {
			// The pinned fact path below derives it or fails loudly.
			continue
		}
		if node.Class == closure.PinnedPackage && (node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test") {
			// A test variant of a module-cache-resident package: the view
			// packages are the only test-expanded ones, and a subject
			// package inside the read-only cache has no runnable tests to
			// vouch for it — name the refusal rather than surfacing it as
			// a coverage gap.
			return nil, fmt.Errorf("gofresh: dynamic-state scan: view package %s resolves into the module cache; module-cache-resident subjects are unsupported", node.ForTest)
		}
		return nil, fmt.Errorf("gofresh: dynamic-state scan did not cover package %s", node.ImportPath)
	}

	// Version-pinned facts: in-process cache, then the persistent memo,
	// then one batched typed load of the missing packages. The bucket key
	// completes the pure function's identity with the module pin and its
	// import-cone version signature — a dependency bump that could reshape
	// a carrier type moves the key (REQ-closure-dynamic-state-memo).
	buckets, unkeyable := pinnedBuckets(meta)
	var missing []closure.GraphPackage
	persisted := map[string]map[string]json.RawMessage{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage || node.ForTest != "" || node.TestMain {
			continue
		}
		if unkeyable[node.Pin] {
			// Part of this module's type environment is mutable-local: no
			// key can pin its fact, so it derives fresh every pass and
			// enters no cache layer (REQ-closure-dynamic-state-memo).
			missing = append(missing, node)
			continue
		}
		bucket := buckets[node.Pin]
		cacheKey := factScope + "\x00" + bucket + "\x00" + node.PkgPath
		if cached, ok := processFactCache.Load(cacheKey); ok {
			state.facts[node.PkgPath] = append(state.facts[node.PkgPath], cached.(dynamicStateFact))
			continue
		}
		if persisted[bucket] == nil {
			if facts := closure.LoadDynamicStateFacts(factScope, bucket); facts != nil {
				persisted[bucket] = facts
			} else {
				persisted[bucket] = map[string]json.RawMessage{}
			}
		}
		if raw, ok := persisted[bucket][node.PkgPath]; ok {
			var fact dynamicStateFact
			if json.Unmarshal(raw, &fact) == nil {
				processFactCache.Store(cacheKey, fact)
				state.facts[node.PkgPath] = append(state.facts[node.PkgPath], fact)
				continue
			}
		}
		missing = append(missing, node)
	}
	if len(missing) > 0 {
		patterns := make([]string, 0, len(missing))
		for _, node := range missing {
			patterns = append(patterns, node.PkgPath)
		}
		sort.Strings(patterns)
		if viewTestHooks.dynamicStateMissLoad != nil {
			viewTestHooks.dynamicStateMissLoad(patterns)
		}
		missLoad, err := closure.LoadViewPackagesEnv(ctx, dir, env, buildFlags, patterns...)
		if err != nil {
			return nil, err
		}
		derived := map[string]dynamicStateFact{}
		for _, pkg := range missLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynamicStateFactOf(pkg)
		}
		store := map[string]map[string]json.RawMessage{}
		for _, node := range missing {
			fact, ok := derived[node.PkgPath]
			if !ok {
				return nil, fmt.Errorf("gofresh: dynamic-state scan did not load pinned package %s", node.PkgPath)
			}
			state.facts[node.PkgPath] = append(state.facts[node.PkgPath], fact)
			if unkeyable[node.Pin] {
				continue
			}
			bucket := buckets[node.Pin]
			processFactCache.Store(factScope+"\x00"+bucket+"\x00"+node.PkgPath, fact)
			if raw, err := json.Marshal(fact); err == nil {
				if store[bucket] == nil {
					store[bucket] = map[string]json.RawMessage{}
				}
				store[bucket][node.PkgPath] = raw
			}
		}
		for bucket, facts := range store {
			closure.StoreDynamicStateFacts(factScope, bucket, facts)
		}
	}

	// Compose: the demonstrated-mutation and escape unions across the
	// graph, the declaring package's opacity intersection, then per-node
	// declaration matching and reachability from each view package's
	// variants — exactly the whole-graph walk's semantics
	// (REQ-closure-shared-dynamic-state), with standard-library subgraphs
	// pruned as inert. A key opens its declaring package on a
	// demonstrated mutation anywhere, or on an escape anywhere unless
	// every declaring fact judges the variable object-closed.
	mutated := map[string]bool{}
	escaped := map[string]bool{}
	envCarrying := map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.Mutates {
				mutated[key] = true
			}
			for _, key := range fact.Escapes {
				escaped[key] = true
			}
			for _, key := range fact.EnvCarrying {
				envCarrying[key] = true
			}
		}
	}
	// Deferred constructor registrations resolve against the
	// return-environment-free union to a least fixed point over the
	// proofs' dependency edges - a conditional proof resolves only when
	// every callee it depends on resolves, so cycles and absent foreign
	// proofs fail closed; an unresolved callee keeps the store's poison
	// (REQ-closure-shared-dynamic-state).
	envFreeDeclared := map[string]bool{}
	envFreeDeps := map[string]map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.ReturnEnvFree {
				envFreeDeclared[key] = true
			}
			for _, edge := range fact.ReturnEnvDeps {
				fnKey, callee, ok := strings.Cut(edge, "\x01")
				if !ok {
					continue
				}
				if envFreeDeps[fnKey] == nil {
					envFreeDeps[fnKey] = map[string]bool{}
				}
				envFreeDeps[fnKey][callee] = true
			}
		}
	}
	envFreeResolved := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for fnKey := range envFreeDeclared {
			if envFreeResolved[fnKey] {
				continue
			}
			ok := true
			for callee := range envFreeDeps[fnKey] {
				if !envFreeResolved[callee] {
					ok = false
					break
				}
			}
			if ok {
				envFreeResolved[fnKey] = true
				changed = true
			}
		}
	}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, use := range fact.EnvCallUses {
				varKey, callee, ok := strings.Cut(use, "\x01")
				if !ok {
					// A malformed entry cannot attribute its store - the
					// fact carrying it is not trusted, fail-closed like
					// every malformed-fact arm.
					for _, key := range fact.Declares {
						envCarrying[key] = true
					}
					continue
				}
				if !envFreeResolved[callee] {
					envCarrying[varKey] = true
				}
			}
		}
	}
	// Deferred method uses resolve against the read-only union: a use
	// whose method no fact proves read-only marks the variable mutated
	// - fail-closed, the address-capture semantics the call site
	// withheld (REQ-closure-shared-dynamic-state).
	readOnly := map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.ReceiverReadOnly {
				readOnly[key] = true
			}
		}
	}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, use := range fact.MethodUses {
				varKey, methodKey, ok := strings.Cut(use, "\x00")
				if !ok {
					// A malformed entry cannot attribute its use; the
					// fact that carries it is not trusted - every key
					// it declares marks mutated, fail-closed.
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if !readOnly[methodKey] {
					mutated[varKey] = true
				}
			}
		}
	}
	// Deferred call-argument uses resolve against the leak-free
	// parameter union: a use whose callee parameter no fact proves
	// leak-free marks the variable escaped - fail-closed, init flow
	// included, because an alias outlives initialization
	// (REQ-closure-shared-dynamic-state).
	paramLeakFree := map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.ParamLeakFree {
				paramLeakFree[key] = true
			}
		}
	}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, use := range fact.ParamUses {
				parts := strings.SplitN(use, "\x00", 2)
				if len(parts) != 2 || strings.Count(parts[1], "\x00") != 2 {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if !paramLeakFree[parts[1]] {
					escaped[parts[0]] = true
				}
			}
		}
	}
	// The cross-package init-only fixed point: a plain named function is
	// init flow when every reference to it, in every fact, is init flow
	// or comes from a function itself proven init flow; "prog" poisons,
	// absence of references fails closed. Attributed uses of proven
	// functions discharge; the rest promote to their immediate class.
	refRegions := map[string]map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, edge := range fact.FuncRefs {
				callee, region, ok := strings.Cut(edge, "\x01")
				if !ok {
					continue
				}
				if refRegions[callee] == nil {
					refRegions[callee] = map[string]bool{}
				}
				refRegions[callee][region] = true
			}
		}
	}
	initOnlyFn := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for fn, regions := range refRegions {
			if initOnlyFn[fn] {
				continue
			}
			// "prog" resolves like any region key: no function carries
			// that name, so a program-code reference is permanently
			// unresolvable and the class refuses - no special arm.
			ok := true
			for region := range regions {
				if region == "init" {
					continue
				}
				if !initOnlyFn[region] {
					ok = false
					break
				}
			}
			if ok {
				initOnlyFn[fn] = true
				changed = true
			}
		}
	}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, use := range fact.AttributedUses {
				parts := strings.Split(use, "\x00")
				if len(parts) < 4 {
					// A malformed attribution cannot be judged - the
					// fact carrying it is not trusted, fail-closed
					// exactly as the malformed method-use arm.
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				fn := parts[0] + "\x00" + parts[1]
				key, class := parts[2], parts[3]
				if class == "e" {
					// An escape never discharges by init flow: the alias
					// outlives initialization, exactly as in an init body.
					// Only a proven leak-free consumer discharges an
					// escape, and those uses defer as ParamUses instead
					// of attributing (REQ-closure-shared-dynamic-state).
					escaped[key] = true
					continue
				}
				if refRegions[fn] != nil && initOnlyFn[fn] {
					continue
				}
				switch {
				case class == "d" && len(parts) >= 6:
					if !readOnly[parts[4]+"\x00"+parts[5]] {
						mutated[key] = true
					}
				default:
					mutated[key] = true
				}
			}
		}
	}
	notOpaque := map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			opaque := make(map[string]bool, len(fact.Opaque))
			for _, key := range fact.Opaque {
				opaque[key] = true
			}
			for _, key := range fact.Declares {
				if !opaque[key] {
					notOpaque[key] = true
				}
			}
			for _, key := range fact.OpacityBreaks {
				notOpaque[key] = true
			}
		}
	}
	// A caller vouch discharges a would-be culprit in a version-pinned
	// dependency (REQ-vouch-discharge): the variable is judged as if
	// proven init-only, and the discharge is recorded per owning package
	// so subjects reaching it carry the acceptance in their evidence
	// (REQ-vouch-recorded). A vouch naming mutable-local source confers
	// nothing — code the caller can edit is fixed, not vouched.
	pinnedPkg := map[string]bool{}
	for _, node := range meta {
		if node.Class == closure.PinnedPackage {
			pinnedPkg[node.PkgPath] = true
		}
	}
	vouchDischarged := map[string][]string{}
	// dischargedSeen keys by owning package AND identity: a fact
	// declaring a foreign key (the persisted-fact channel, fail-closed
	// elsewhere) must not steal another package's discharge record - a
	// subject reaching only the second declarer still carries the
	// acceptance (REQ-vouch-recorded).
	dischargedSeen := map[string]bool{}
	vouchedOut := func(pkgPath, key string) bool {
		if !vouches[key] || !pinnedPkg[pkgPath] {
			return false
		}
		if seen := pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			vouchDischarged[pkgPath] = append(vouchDischarged[pkgPath], key)
		}
		return true
	}
	// openWorld maps each open package to one culprit description — the
	// downgrade's refusal must name the owning package and variable.
	openWorld := map[string]string{}
	pkgPaths := make([]string, 0, len(state.facts))
	for pkgPath := range state.facts {
		pkgPaths = append(pkgPaths, pkgPath)
	}
	sort.Strings(pkgPaths)
	for _, pkgPath := range pkgPaths {
		// Mutations outrank escapes in the culprit text; within a rank
		// the sorted key order makes the reason deterministic.
		// Every declared key is consulted in every rank even after a
		// culprit opens the package: the vouch-discharge record must
		// name every load-bearing vouch, not the ones lexical order
		// happened to reach first (REQ-vouch-recorded); the first
		// unvouched hit per rank order still names the culprit.
		for _, fact := range state.facts[pkgPath] {
			for _, key := range fact.Declares {
				if mutated[key] && !vouchedOut(pkgPath, key) {
					if _, ok := openWorld[pkgPath]; !ok {
						openWorld[pkgPath] = key + " is mutated"
					}
				}
			}
		}
		for _, fact := range state.facts[pkgPath] {
			for _, key := range fact.Declares {
				if escaped[key] && notOpaque[key] && !vouchedOut(pkgPath, key) {
					if _, ok := openWorld[pkgPath]; !ok {
						openWorld[pkgPath] = key + " escapes writable"
					}
				}
			}
		}
		// A carrier holding a function value outside the environment-free
		// audit refuses regardless of use shape: any admitted read path
		// can extract and execute the value, and its environment can
		// write state the settled verdict assumed stable.
		for _, fact := range state.facts[pkgPath] {
			for _, key := range fact.Declares {
				if envCarrying[key] && !vouchedOut(pkgPath, key) {
					if _, ok := openWorld[pkgPath]; !ok {
						openWorld[pkgPath] = key + " registers function values outside the environment-free audit"
					}
				}
			}
		}
	}
	imports := make(map[string][]string, len(meta))
	classes := make(map[string]closure.PackageClass, len(meta))
	pkgPathOf := make(map[string]string, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		classes[node.ImportPath] = node.Class
		pkgPathOf[node.ImportPath] = node.PkgPath
	}
	isView := make(map[string]bool, len(viewPackages))
	for _, pkgPath := range viewPackages {
		isView[pkgPath] = true
	}
	var walk func(listing string, seen map[string]bool) string
	walk = func(listing string, seen map[string]bool) string {
		if seen[listing] {
			return ""
		}
		seen[listing] = true
		if classes[listing] == closure.StandardPackage {
			return ""
		}
		if culprit, ok := openWorld[pkgPathOf[listing]]; ok {
			return pkgPathOf[listing] + ": " + culprit
		}
		for _, imported := range imports[listing] {
			if _, ok := pkgPathOf[imported]; !ok {
				continue
			}
			if culprit := walk(imported, seen); culprit != "" {
				return culprit
			}
		}
		return ""
	}
	for _, node := range meta {
		root := node.PkgPath
		if node.ForTest != "" {
			root = node.ForTest
		} else if node.TestMain {
			continue
		}
		if !isView[root] || state.downgraded[root] != "" {
			continue
		}
		if culprit := walk(node.ImportPath, map[string]bool{}); culprit != "" {
			state.downgraded[root] = culprit
		}
	}
	if len(vouchDischarged) > 0 {
		// The discharge record is per view package: every vouch that
		// suppressed a culprit in a package the subject's graph reaches
		// rides its evidence, so acceptance is auditable and never silent
		// (REQ-vouch-recorded). Unlike the culprit walk this one never
		// short-circuits — the record carries every load-bearing vouch.
		state.vouchDischarges = map[string]string{}
		perRoot := map[string]map[string]bool{}
		var collect func(listing string, seen, acc map[string]bool)
		collect = func(listing string, seen, acc map[string]bool) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if classes[listing] == closure.StandardPackage {
				return
			}
			for _, key := range vouchDischarged[pkgPathOf[listing]] {
				acc[key] = true
			}
			for _, imported := range imports[listing] {
				if _, ok := pkgPathOf[imported]; !ok {
					continue
				}
				collect(imported, seen, acc)
			}
		}
		for _, node := range meta {
			root := node.PkgPath
			if node.ForTest != "" {
				root = node.ForTest
			} else if node.TestMain {
				continue
			}
			if !isView[root] {
				continue
			}
			acc := perRoot[root]
			if acc == nil {
				acc = map[string]bool{}
				perRoot[root] = acc
			}
			collect(node.ImportPath, map[string]bool{}, acc)
		}
		for root, acc := range perRoot {
			if len(acc) == 0 {
				continue
			}
			keys := make([]string, 0, len(acc))
			for key := range acc {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			state.vouchDischarges[root] = strings.Join(keys, ",")
		}
	}
	return state, nil
}

// pinnedBuckets derives, per pinned module, the memo bucket completing its
// facts' input identity: the module's own pin plus the version signature of
// every pinned module reachable from its packages — its type environment's
// complete version surface (standard library rides the scope's toolchain).
// A pinned module whose cone reaches any mutable-local node is unkeyable —
// part of its type environment carries no version signal, so its facts must
// derive fresh every pass and never enter any cache layer
// (REQ-closure-dynamic-state-memo, REQ-closure-mutable-local).
func pinnedBuckets(meta []closure.GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	imports := make(map[string][]string, len(meta))
	pins := make(map[string]string, len(meta))
	local := make(map[string]bool, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		if node.Class == closure.PinnedPackage {
			pins[node.ImportPath] = node.Pin
		}
		if node.Class == closure.MutableLocalPackage {
			local[node.ImportPath] = true
		}
	}
	reachable := func(from string) (pinSet map[string]bool, localReached bool) {
		pinSet = map[string]bool{}
		seen := map[string]bool{}
		var walk func(string)
		walk = func(listing string) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if pin := pins[listing]; pin != "" {
				pinSet[pin] = true
			}
			if local[listing] {
				localReached = true
			}
			for _, imported := range imports[listing] {
				walk(imported)
			}
		}
		walk(from)
		return pinSet, localReached
	}
	coneByModule := map[string]map[string]bool{}
	unkeyable = map[string]bool{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage {
			continue
		}
		pinSet, localReached := reachable(node.ImportPath)
		if localReached {
			unkeyable[node.Pin] = true
			continue
		}
		if coneByModule[node.Pin] == nil {
			coneByModule[node.Pin] = map[string]bool{}
		}
		for pin := range pinSet {
			coneByModule[node.Pin][pin] = true
		}
	}
	buckets = make(map[string]string, len(coneByModule))
	for pin, cone := range coneByModule {
		if unkeyable[pin] {
			continue
		}
		keys := make([]string, 0, len(cone))
		for k := range cone {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(fmt.Sprintf("%q", keys)))
		buckets[pin] = pin + "|" + hex.EncodeToString(sum[:8])
	}
	return buckets, unkeyable
}
