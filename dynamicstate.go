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
	"strconv"
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
	// PoolDischarges holds the package-level sync.Pool variable keys
	// whose Get/Put calls in this package's syntax the caller's
	// single-subject-process attestation discharged at recording —
	// present only in facts derived under the attestation. At
	// composition the keys reachable from a subject ride its evidence,
	// so the load-bearing attestation is auditable and never silent —
	// the vouch-recording discipline (REQ-vouch-recorded).
	PoolDischarges []string `json:"poolDischarges,omitempty"`
	// ReceiverReadOnly holds the full method keys (package path,
	// receiver type, method) this package declares and proves unable to
	// write receiver-reachable state.
	ReceiverReadOnly []string `json:"receiverReadOnly,omitempty"`
	// ReceiverRetentionFree holds the retention grade of the same
	// keys: the method never escapes or outlives its receiver, writes
	// through it tolerated - the sole grade init-flow receiver
	// deferrals resolve against; read-only never substitutes, a
	// reading method can still retain its receiver.
	ReceiverRetentionFree []string `json:"receiverRetentionFree,omitempty"`
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
	// ParamLeakFreeDeps holds conditional leak-free edges: the owning
	// parameter key and one dependency parameter key (both full: package
	// path, function name, index NUL-joined) \x01-joined. The owner
	// proves at composition only when every edge target proves - a
	// least fixed point exactly as the constructor proofs resolve,
	// cycles and absence refusing.
	ParamLeakFreeDeps []string `json:"paramLeakFreeDeps,omitempty"`
	// ParamRetentionFree holds the retention-only grade of the same
	// keys: the parameter provably never retains or hands out the bound
	// value, while writes through it are tolerated - the grade an
	// init-flow argument defers to, where direct stores are already
	// exempt. Recorded only where the leak-free grade failed; consumers
	// union the two.
	ParamRetentionFree []string `json:"paramRetentionFree,omitempty"`
	// ParamRetentionFreeDeps holds the retention grade's conditional
	// edges, encoded exactly as ParamLeakFreeDeps and resolved in the
	// same least fixed point, an edge satisfiable by either grade of
	// its target.
	ParamRetentionFreeDeps []string `json:"paramRetentionFreeDeps,omitempty"`
	// ParamUses holds deferred call-argument marks: variable key and
	// callee parameter key joined by NUL. At composition the use is
	// discharged only when the parameter is proven leak-free by its
	// declaring fact; otherwise the variable marks escaped -
	// fail-closed, init flow included, because an alias outlives
	// initialization.
	ParamUses []string `json:"paramUses,omitempty"`
	// InitParamUses holds the exempt-region deferred call-argument
	// marks, encoded exactly as ParamUses: a carrier argument from an
	// init body, an init-only helper, or an initializer expression. At
	// composition the use discharges when the parameter is proven
	// leak-free OR retention-free - a write through the parameter is
	// init-flow's own exempt store - and marks escaped otherwise.
	InitParamUses []string `json:"initParamUses,omitempty"`
	// InitMethodUses holds the exempt-region deferred method-call
	// marks: variable key and method key joined by NUL - a statically
	// dispatched method call on a carrier receiver in init flow. At
	// composition the use discharges when the method is proven
	// receiver-read-only OR receiver-retention-free - a write through
	// the receiver is init-flow's own exempt store - and marks escaped
	// otherwise.
	InitMethodUses []string `json:"initMethodUses,omitempty"`
	// CarrierLinks holds cross-carrier storage links: two variable keys
	// \x01-joined - an init-flow bind or store made one carrier an
	// alias of another, so the pair shares one backing. At composition
	// mutation, escape, and environment marks cross every link
	// symmetrically and transitively.
	CarrierLinks []string `json:"carrierLinks,omitempty"`
	// FieldParamUses holds deferred field-position argument marks:
	// variable key, then field name and zero-based parameter index
	// NUL-joined, the two parts joined by \x01 - a binding of the
	// carrier passed a rooted alias-handing argument through a
	// func-signature field call. At composition the use is discharged
	// only when the carrier's whole registered population proves that
	// field position leak-free; otherwise the variable marks escaped -
	// fail-closed.
	FieldParamUses []string `json:"fieldParamUses,omitempty"`
	// ElemParamUses holds deferred dispatch-argument marks: the
	// escaping variable key, the dispatch carrier's variable key (the
	// element-population owner - a callee-position index read of it
	// supplied the callee), and the zero-based parameter index, all
	// \x01-joined. At composition the use is discharged only when the
	// owner's element population proves the position leak-free;
	// otherwise the escaping variable marks escaped - fail-closed.
	ElemParamUses []string `json:"elemParamUses,omitempty"`
	// FieldParamDefer holds registered-population deferrals: variable
	// key, field position (field name, parameter index NUL-joined), and
	// callee parameter key, \x01-joined - one admitted registrant's
	// parameter proof obligation, resolved against the leak-free union.
	FieldParamDefer []string `json:"fieldParamDefer,omitempty"`
	// FieldParamPoison holds registered-population refusals: a bare
	// variable key poisons the carrier's whole population, a variable
	// key with a field position (index -1 covering every index) poisons
	// that position - an admitted registrant the classification cannot
	// prove.
	FieldParamPoison []string `json:"fieldParamPoison,omitempty"`
	// ReturnFieldParamDefer and ReturnFieldParamPoison are the
	// constructor-side population records, keyed by the function key of
	// a proven return-environment-free constructor instead of a variable
	// key: carriers registered from the constructor's results join these
	// marks through their EnvCallUses pairs, transitively over the
	// proof's dependency edges.
	ReturnFieldParamDefer  []string `json:"returnFieldParamDefer,omitempty"`
	ReturnFieldParamPoison []string `json:"returnFieldParamPoison,omitempty"`
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
	// OpaqueDeps holds conditional object-closed edges: the owning
	// interface variable key and one sibling variable key \x01-joined.
	// The owner's audited construction chains through the sibling (the
	// wrapped-sentinel idiom: fmt.Errorf over an object-closed
	// variable), so the owner stays opaque exactly while the sibling
	// does — resolved at composition by break propagation over the
	// unioned edge set, whatever the declaration or store order
	// (REQ-closure-shared-dynamic-state).
	OpaqueDeps []string `json:"opaqueDeps,omitempty"`
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
// package's selected syntax and type environment plus the caller-attested
// single-subject-process execution model — the attestation changes what the
// fact records (the audited pooling set's discharge), so it is part of every
// fact-cache identity the fact is stored under
// (REQ-closure-dynamic-state-memo).
func dynamicStateFactOf(p *packages.Package, singleSubject bool) dynamicStateFact {
	var fact dynamicStateFact
	mutated, escaped, opaque, breaks := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	initOnly := initOnlyReachableHelpers(p)
	methodUses := map[string]map[string]bool{}
	paramUses := map[string]map[string]bool{}
	initParamUses := map[string]map[string]bool{}
	initMethodUses := map[string]map[string]bool{}
	carrierLinks := map[string]map[string]bool{}
	fieldUses := map[string]map[string]bool{}
	elemUses := map[string]map[string]bool{}
	var attributedUses []attributedUse
	funcRefs := map[string]map[string]bool{}
	envCarrying := map[string]bool{}
	var poolDischarged map[string]bool
	if singleSubject {
		poolDischarged = map[string]bool{}
	}
	recordDynamicGlobalUses(p, mutated, escaped, initOnly, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks, &attributedUses, singleSubject, poolDischarged)
	for key := range poolDischarged {
		fact.PoolDischarges = append(fact.PoolDischarges, key)
	}
	sort.Strings(fact.PoolDischarges)
	recordFunctionReferenceRegions(p, initOnly, funcRefs)
	opaqueDeps := map[string]map[string]bool{}
	recordOpaqueDynamicVars(p, opaque, breaks, opaqueDeps)
	for own, ownDeps := range opaqueDeps {
		for dep := range ownDeps {
			fact.OpaqueDeps = append(fact.OpaqueDeps, own+"\x01"+dep)
		}
	}
	sort.Strings(fact.OpaqueDeps)
	envCalls := map[string]map[string]bool{}
	fieldDefer := map[string]map[string]bool{}
	fieldPoison := map[string]map[string]bool{}
	recordEnvCarryingRegistrations(p, envCarrying, envCalls, fieldDefer, fieldPoison)
	for varKey, entries := range fieldDefer {
		for entry := range entries {
			fact.FieldParamDefer = append(fact.FieldParamDefer, varKey+"\x01"+entry)
		}
	}
	sort.Strings(fact.FieldParamDefer)
	for varKey, entries := range fieldPoison {
		for entry := range entries {
			if entry == "" {
				fact.FieldParamPoison = append(fact.FieldParamPoison, varKey)
			} else {
				fact.FieldParamPoison = append(fact.FieldParamPoison, varKey+"\x01"+entry)
			}
		}
	}
	sort.Strings(fact.FieldParamPoison)
	for varKey, wants := range fieldUses {
		for want := range wants {
			fact.FieldParamUses = append(fact.FieldParamUses, varKey+"\x01"+want)
		}
	}
	sort.Strings(fact.FieldParamUses)
	for argKey, wants := range elemUses {
		for want := range wants {
			fact.ElemParamUses = append(fact.ElemParamUses, argKey+"\x01"+want)
		}
	}
	sort.Strings(fact.ElemParamUses)
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
	retentionMethods := receiverRetentionFreeMethods(p, readOnly)
	for method := range readOnly {
		if p.Types != nil {
			fact.ReceiverReadOnly = append(fact.ReceiverReadOnly, p.Types.Path()+"\x00"+method)
		}
	}
	sort.Strings(fact.ReceiverReadOnly)
	for method := range retentionMethods {
		if p.Types != nil {
			fact.ReceiverRetentionFree = append(fact.ReceiverRetentionFree, p.Types.Path()+"\x00"+method)
		}
	}
	sort.Strings(fact.ReceiverRetentionFree)
	for varKey, methodKeys := range methodUses {
		for methodKey := range methodKeys {
			fact.MethodUses = append(fact.MethodUses, varKey+"\x00"+methodKey)
		}
	}
	sort.Strings(fact.MethodUses)
	if p.Types != nil {
		paramLeakFree, paramDeps, paramRetention, paramRetentionDeps := paramLeakFreeFunctions(p, readOnly, retentionMethods)
		for paramKey := range paramLeakFree {
			fact.ParamLeakFree = append(fact.ParamLeakFree, p.Types.Path()+"\x00"+paramKey)
		}
		for paramKey, edges := range paramDeps {
			ownKey := p.Types.Path() + "\x00" + paramKey
			for dep := range edges {
				fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, ownKey+"\x01"+dep)
			}
		}
		sort.Strings(fact.ParamLeakFreeDeps)
		for paramKey := range paramRetention {
			fact.ParamRetentionFree = append(fact.ParamRetentionFree, p.Types.Path()+"\x00"+paramKey)
		}
		for paramKey, edges := range paramRetentionDeps {
			ownKey := p.Types.Path() + "\x00" + paramKey
			for dep := range edges {
				fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, ownKey+"\x01"+dep)
			}
		}
		sort.Strings(fact.ParamRetentionFree)
		sort.Strings(fact.ParamRetentionFreeDeps)
		envFree, envDeps, retFieldDefer, retFieldPoison := returnEnvFreeFunctions(p, paramLeakFree, readOnly)
		for fnName := range envFree {
			fnKey := p.Types.Path() + "\x00" + fnName
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range envDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, fnKey+"\x01"+callee)
			}
			for entry := range retFieldDefer[fnName] {
				fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, fnKey+"\x01"+entry)
			}
			for entry := range retFieldPoison[fnName] {
				if entry == "" {
					fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, fnKey)
				} else {
					fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, fnKey+"\x01"+entry)
				}
			}
		}
		sort.Strings(fact.ReturnEnvFree)
		sort.Strings(fact.ReturnEnvDeps)
		sort.Strings(fact.ReturnFieldParamDefer)
		sort.Strings(fact.ReturnFieldParamPoison)
	}
	sort.Strings(fact.ParamLeakFree)
	for varKey, paramKeys := range paramUses {
		for paramKey := range paramKeys {
			fact.ParamUses = append(fact.ParamUses, varKey+"\x00"+paramKey)
		}
	}
	sort.Strings(fact.ParamUses)
	for varKey, paramKeys := range initParamUses {
		for paramKey := range paramKeys {
			fact.InitParamUses = append(fact.InitParamUses, varKey+"\x00"+paramKey)
		}
	}
	sort.Strings(fact.InitParamUses)
	for varKey, methodKeys := range initMethodUses {
		for methodKey := range methodKeys {
			fact.InitMethodUses = append(fact.InitMethodUses, varKey+"\x00"+methodKey)
		}
	}
	sort.Strings(fact.InitMethodUses)
	for keyA, others := range carrierLinks {
		for keyB := range others {
			fact.CarrierLinks = append(fact.CarrierLinks, keyA+"\x01"+keyB)
		}
	}
	sort.Strings(fact.CarrierLinks)
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
	// attestationDischarges maps each view package to the canonical
	// sorted comma-joined variable keys whose discharge the caller's
	// single-subject-process attestation carried — a pool variable's
	// admitted Get/Put, the audited mapping set's named bookkeeping —
	// reachable from it; absent when the attestation was not
	// load-bearing for the package. Recorded on subject evidence like a
	// vouch discharge, auditable and never silent (REQ-vouch-recorded).
	attestationDischarges map[string]string
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

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, load *closure.ViewLoad, viewPackages []string, vouches map[string]bool, singleSubject bool) (*viewDynamicState, error) {
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
		state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg, singleSubject))
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
			state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg, singleSubject))
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
			derived[pkg.PkgPath] = dynamicStateFactOf(pkg, singleSubject)
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
	resolution := newDeferralResolution(state.facts, func(fact dynamicStateFact) {
		for _, key := range fact.Declares {
			mutated[key] = true
		}
	})
	envFreeResolved := resolution.envFreeResolved
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
	readOnly := resolution.readOnly
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
			// An exempt-region method call on a carrier receiver
			// discharges through the receiver retention grade alone: a
			// write through the receiver is init flow's own exempt
			// store, only escape or outliving refuses - and the
			// read-only grade never substitutes, a reading method can
			// still retain its receiver
			// (REQ-closure-shared-dynamic-state).
			for _, use := range fact.InitMethodUses {
				varKey, methodKey, ok := strings.Cut(use, "\x00")
				if !ok {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if !resolution.receiverRetention[methodKey] {
					escaped[varKey] = true
				}
			}
		}
	}
	// Deferred call-argument uses resolve against the leak-free
	// parameter union: a use whose callee parameter no fact proves
	// leak-free marks the variable escaped - fail-closed, init flow
	// included, because an alias outlives initialization
	// (REQ-closure-shared-dynamic-state).
	paramLeakFree := resolution.paramLeakFree
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
			// An exempt-region use additionally discharges through the
			// retention grade: a write through the parameter is init
			// flow's own exempt store, only retention or a handout
			// refuses (REQ-closure-shared-dynamic-state).
			for _, use := range fact.InitParamUses {
				parts := strings.SplitN(use, "\x00", 2)
				if len(parts) != 2 || strings.Count(parts[1], "\x00") != 2 {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if !paramLeakFree[parts[1]] && !resolution.paramRetentionFree[parts[1]] {
					escaped[parts[0]] = true
				}
			}
		}
	}
	// Deferred field-position argument uses resolve against the carrier's
	// registered population: every admitted registrant of the field either
	// deferred its parameter to the leak-free union or poisoned the
	// position, and constructor-supplied registrants join through the
	// carrier's EnvCallUses pairs, transitively over the proofs'
	// dependency edges. Any poison, any unproven deferral, any unresolved
	// constructor, and any malformed record keeps the escape - fail-closed
	// (REQ-closure-shared-dynamic-state).
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, use := range fact.FieldParamUses {
				varKey, position, ok := strings.Cut(use, "\x01")
				if !ok || !fieldPosition(position, 0) {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				field, idx, _ := strings.Cut(position, "\x00")
				if ok, _ := resolution.fieldPopulationProves(varKey, field, idx); !ok {
					escaped[varKey] = true
				}
			}
			for _, use := range fact.ElemParamUses {
				parts := strings.SplitN(use, "\x01", 3)
				if len(parts) != 3 {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if n, err := strconv.Atoi(parts[2]); err != nil || n < 0 || strconv.Itoa(n) != parts[2] {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if ok, _ := resolution.fieldPopulationProves(parts[1], elemPositionField, parts[2]); !ok {
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
	// Cross-carrier storage links: an init-flow bind of one carrier
	// from another made the pair one backing, so mutation, escape, and
	// environment marks cross every link symmetrically and transitively
	// - a mark on either side refuses both
	// (REQ-closure-shared-dynamic-state).
	linkAdj := map[string]map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, link := range fact.CarrierLinks {
				a, b, ok := strings.Cut(link, "\x01")
				if !ok || a == "" || b == "" {
					for _, key := range fact.Declares {
						mutated[key] = true
					}
					continue
				}
				if linkAdj[a] == nil {
					linkAdj[a] = map[string]bool{}
				}
				if linkAdj[b] == nil {
					linkAdj[b] = map[string]bool{}
				}
				linkAdj[a][b] = true
				linkAdj[b][a] = true
			}
		}
	}
	for changed := len(linkAdj) > 0; changed; {
		changed = false
		for a, others := range linkAdj {
			for b := range others {
				if mutated[a] && !mutated[b] {
					mutated[b] = true
					changed = true
				}
				if escaped[a] && !escaped[b] {
					escaped[b] = true
					changed = true
				}
				if envCarrying[a] && !envCarrying[b] {
					envCarrying[b] = true
					changed = true
				}
			}
		}
	}
	notOpaque := resolution.notOpaque
	// A caller vouch discharges a would-be culprit in a version-pinned
	// dependency (REQ-vouch-discharge): the variable is judged as if
	// proven init-only, and the discharge is recorded per owning package
	// so subjects reaching it carry the acceptance in their evidence
	// (REQ-vouch-recorded). A vouch naming mutable-local source confers
	// nothing — code the caller can edit is fixed, not vouched
	// (REQ-vouch-dependency-boundary).
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
	// The audited mapping set: golang.org/x/sys/unix's package-level
	// mapper — a Mutex-guarded address-to-length map with mmap/munmap
	// function fields, written by every Mmap/Munmap call as pure
	// process-local bookkeeping fed only by the analyzed program's own
	// mapping calls (audited at the version-pinned source). Under the
	// caller-attested single-subject-process execution model every
	// write site lies in the subject's own rooted flow, so mapper
	// contents are a function of the analyzed source and the subject
	// alone and the marks discharge exactly like a vouch — grounded in
	// source audit plus the attestation instead of a caller claim, the
	// version-pinned module only (a mutable-local checkout keeps every
	// mark), every other variable keeping its own judgment, and the
	// mapping syscalls' external effects keeping their observability
	// classification. Load-bearing discharges ride subject evidence
	// with the pooling set's (REQ-closure-shared-dynamic-state,
	// REQ-vouch-recorded). Grows only by source audit.
	mappingDischarged := map[string][]string{}
	auditedMappingOut := func(pkgPath, key string) bool {
		if !singleSubject || !pinnedPkg[pkgPath] {
			return false
		}
		if pkgPath != "golang.org/x/sys/unix" || key != "golang.org/x/sys/unix.mapper" {
			return false
		}
		if seen := "mapping\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			mappingDischarged[pkgPath] = append(mappingDischarged[pkgPath], key)
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
				if mutated[key] && !vouchedOut(pkgPath, key) && !auditedMappingOut(pkgPath, key) {
					if _, ok := openWorld[pkgPath]; !ok {
						openWorld[pkgPath] = key + " is mutated"
					}
				}
			}
		}
		for _, fact := range state.facts[pkgPath] {
			for _, key := range fact.Declares {
				if escaped[key] && notOpaque[key] && !vouchedOut(pkgPath, key) && !auditedMappingOut(pkgPath, key) {
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
				if envCarrying[key] && !vouchedOut(pkgPath, key) && !auditedMappingOut(pkgPath, key) {
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
	// collectReachable builds a per-view-package record from per-owning-
	// package acceptance keys: every key in a package the view package's
	// graph reaches joins its canonical sorted comma-joined record.
	// Unlike the culprit walk this one never short-circuits — the record
	// carries every load-bearing acceptance (REQ-vouch-recorded).
	collectReachable := func(source map[string][]string) map[string]string {
		result := map[string]string{}
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
			for _, key := range source[pkgPathOf[listing]] {
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
			result[root] = strings.Join(keys, ",")
		}
		return result
	}
	if len(vouchDischarged) > 0 {
		// The discharge record is per view package: every vouch that
		// suppressed a culprit in a package the subject's graph reaches
		// rides its evidence, so acceptance is auditable and never silent
		// (REQ-vouch-recorded).
		state.vouchDischarges = collectReachable(vouchDischarged)
	}
	// The single-subject attestation's audit record is the vouch
	// discipline's parallel: every variable whose discharge the
	// attestation carried — a pool variable's admitted Get/Put
	// (recorded in the facts at derivation time) or the audited mapping
	// set's composition-time discharge — in a package the view
	// package's graph reaches, rides subject evidence
	// (REQ-vouch-recorded).
	attestationDischarged := map[string][]string{}
	attestationSeen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		for _, fact := range state.facts[pkgPath] {
			for _, key := range fact.PoolDischarges {
				if seen := pkgPath + "\x00" + key; !attestationSeen[seen] {
					attestationSeen[seen] = true
					attestationDischarged[pkgPath] = append(attestationDischarged[pkgPath], key)
				}
			}
		}
	}
	for pkgPath, keys := range mappingDischarged {
		for _, key := range keys {
			if seen := pkgPath + "\x00" + key; !attestationSeen[seen] {
				attestationSeen[seen] = true
				attestationDischarged[pkgPath] = append(attestationDischarged[pkgPath], key)
			}
		}
	}
	if len(attestationDischarged) > 0 {
		state.attestationDischarges = collectReachable(attestationDischarged)
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

// deferralResolution is the composed proof state every deferred mark
// resolves against - the leak-free parameter union, the receiver
// read-only union, the return-environment-free fixed point, and the
// registered field populations. One derivation serves both the verdict
// composition and the explain re-derivation, so a chain's resolution
// can never disagree with the verdict's (REQ-explain-chain). The
// malformed callback observes each fact carrying an unparseable
// population record - the composition marks the fact's declared keys,
// the explain path passes nil and lets the verdict's marks stand.
type deferralResolution struct {
	paramLeakFree map[string]bool
	// paramRetentionFree is the retention-only grade: never retains or
	// hands out, writes tolerated - the grade init-flow deferrals
	// resolve against, unioned with paramLeakFree (leak-free implies
	// retention-free).
	paramRetentionFree map[string]bool
	readOnly           map[string]bool
	// receiverRetention is the method-side retention grade: never
	// escapes or outlives the receiver, writes tolerated - init-flow
	// receiver deferrals resolve against it unioned with readOnly.
	receiverRetention map[string]bool
	// notOpaque is the opacity intersection: a declared key is opaque -
	// object-closed, escapes never refusing - only when every declaring
	// fact judges it so and no fact breaks it. Escape-kind refusals gate
	// on membership here, in the verdict composition and in explain
	// chains alike (REQ-explain-chain).
	notOpaque       map[string]bool
	envFreeResolved map[string]bool
	envFreeDeps     map[string]map[string]bool
	fieldDeferAt    map[string][]string
	fieldPoisonAt   map[string]bool
	retDeferAt      map[string][]string
	retPoisonAt     map[string]bool
	ctorsOf         map[string][]string
}

func newDeferralResolution(allFacts map[string][]dynamicStateFact, malformed func(fact dynamicStateFact)) *deferralResolution {
	r := &deferralResolution{
		paramLeakFree:      map[string]bool{},
		paramRetentionFree: map[string]bool{},
		readOnly:           map[string]bool{},
		receiverRetention:  map[string]bool{},
		notOpaque:          map[string]bool{},
		envFreeResolved:    map[string]bool{},
		envFreeDeps:        map[string]map[string]bool{},
		fieldDeferAt:       map[string][]string{},
		fieldPoisonAt:      map[string]bool{},
		retDeferAt:         map[string][]string{},
		retPoisonAt:        map[string]bool{},
		ctorsOf:            map[string][]string{},
	}
	if malformed == nil {
		malformed = func(dynamicStateFact) {}
	}
	envFreeDeclared := map[string]bool{}
	declaredKeys := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	paramDeps := map[string]map[string]bool{}
	retentionDeps := map[string]map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.ParamLeakFree {
				r.paramLeakFree[key] = true
			}
			for _, edge := range fact.ParamLeakFreeDeps {
				own, dep, ok := strings.Cut(edge, "\x01")
				if !ok || strings.Count(own, "\x00") != 2 || strings.Count(dep, "\x00") != 2 {
					malformed(fact)
					continue
				}
				if paramDeps[own] == nil {
					paramDeps[own] = map[string]bool{}
				}
				paramDeps[own][dep] = true
			}
			for _, key := range fact.ParamRetentionFree {
				r.paramRetentionFree[key] = true
			}
			for _, edge := range fact.ParamRetentionFreeDeps {
				own, dep, ok := strings.Cut(edge, "\x01")
				if !ok || strings.Count(own, "\x00") != 2 || strings.Count(dep, "\x00") != 2 {
					malformed(fact)
					continue
				}
				if retentionDeps[own] == nil {
					retentionDeps[own] = map[string]bool{}
				}
				retentionDeps[own][dep] = true
			}
			for _, key := range fact.ReceiverReadOnly {
				r.readOnly[key] = true
			}
			for _, key := range fact.ReceiverRetentionFree {
				r.receiverRetention[key] = true
			}
			opaque := make(map[string]bool, len(fact.Opaque))
			for _, key := range fact.Opaque {
				opaque[key] = true
			}
			for _, key := range fact.Declares {
				declaredKeys[key] = true
				if !opaque[key] {
					r.notOpaque[key] = true
				}
			}
			for _, key := range fact.OpacityBreaks {
				r.notOpaque[key] = true
			}
			for _, edge := range fact.OpaqueDeps {
				own, dep, ok := strings.Cut(edge, "\x01")
				if !ok || own == "" || dep == "" || strings.Contains(own, "\x00") || strings.Contains(dep, "\x00") {
					malformed(fact)
					continue
				}
				if opaqueDeps[own] == nil {
					opaqueDeps[own] = map[string]bool{}
				}
				opaqueDeps[own][dep] = true
			}
			for _, key := range fact.ReturnEnvFree {
				envFreeDeclared[key] = true
			}
			for _, edge := range fact.ReturnEnvDeps {
				fnKey, callee, ok := strings.Cut(edge, "\x01")
				if !ok {
					continue
				}
				if r.envFreeDeps[fnKey] == nil {
					r.envFreeDeps[fnKey] = map[string]bool{}
				}
				r.envFreeDeps[fnKey][callee] = true
			}
		}
	}
	// The conditional leak-free least fixed point: a cross-package
	// parameter-forwarding chain proves only when every edge target
	// proves - cycles and absent foreign proofs fail closed
	// (REQ-closure-shared-dynamic-state).
	for changed := true; changed; {
		changed = false
		for own, edges := range paramDeps {
			if r.paramLeakFree[own] {
				continue
			}
			ok := true
			for dep := range edges {
				if !r.paramLeakFree[dep] {
					ok = false
					break
				}
			}
			if ok {
				r.paramLeakFree[own] = true
				changed = true
			}
		}
	}
	// The retention grade's least fixed point runs after the leak-free
	// one - an edge is satisfiable by either grade of its target, a
	// leak-free hop retaining nothing a fortiori; cycles and absence
	// refuse identically (REQ-closure-shared-dynamic-state).
	for changed := true; changed; {
		changed = false
		for own, edges := range retentionDeps {
			if r.paramRetentionFree[own] || r.paramLeakFree[own] {
				continue
			}
			ok := true
			for dep := range edges {
				if !r.paramRetentionFree[dep] && !r.paramLeakFree[dep] {
					ok = false
					break
				}
			}
			if ok {
				r.paramRetentionFree[own] = true
				changed = true
			}
		}
	}
	// Opacity break propagation over the conditional object-closed
	// edges: a variable whose audited construction chains through a
	// sibling (the wrapped-sentinel idiom) falls exactly when the
	// sibling falls, to a fixed point over the unioned edge set — so
	// declaration and store order never decide, a break recorded by ANY
	// fact fells the whole chain, and a cycle of mutually chained
	// stores with no break stays closed: every store into the cycle
	// passed the audit, so every reachable object is an audited
	// construction whatever order the stores ran in
	// (REQ-closure-shared-dynamic-state).
	for changed := true; changed; {
		changed = false
		for own, edges := range opaqueDeps {
			if r.notOpaque[own] {
				continue
			}
			for dep := range edges {
				// An undeclared referent - a module-less package's
				// variable, which no fact audits - refuses fail-closed
				// exactly as a broken one (REQ-closure-shared-dynamic-state).
				if r.notOpaque[dep] || !declaredKeys[dep] {
					r.notOpaque[own] = true
					changed = true
					break
				}
			}
		}
	}
	// The return-environment-free least fixed point: a conditional proof
	// resolves only when every callee it depends on resolves - cycles and
	// absent foreign proofs fail closed (REQ-closure-shared-dynamic-state).
	for changed := true; changed; {
		changed = false
		for fnKey := range envFreeDeclared {
			if r.envFreeResolved[fnKey] {
				continue
			}
			ok := true
			for callee := range r.envFreeDeps[fnKey] {
				if !r.envFreeResolved[callee] {
					ok = false
					break
				}
			}
			if ok {
				r.envFreeResolved[fnKey] = true
				changed = true
			}
		}
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, entry := range fact.FieldParamDefer {
				parts := strings.SplitN(entry, "\x01", 3)
				if len(parts) != 3 || !fieldPosition(parts[1], 0) || strings.Count(parts[2], "\x00") != 2 {
					malformed(fact)
					continue
				}
				at := parts[0] + "\x01" + parts[1]
				r.fieldDeferAt[at] = append(r.fieldDeferAt[at], parts[2])
			}
			for _, entry := range fact.FieldParamPoison {
				key, position, ok := strings.Cut(entry, "\x01")
				if ok && !fieldPosition(position, -1) {
					malformed(fact)
					continue
				}
				if !ok {
					r.fieldPoisonAt[key] = true
				} else {
					r.fieldPoisonAt[key+"\x01"+position] = true
				}
			}
			for _, entry := range fact.ReturnFieldParamDefer {
				parts := strings.SplitN(entry, "\x01", 3)
				if len(parts) != 3 || strings.Count(parts[0], "\x00") != 1 || !fieldPosition(parts[1], 0) || strings.Count(parts[2], "\x00") != 2 {
					malformed(fact)
					continue
				}
				at := parts[0] + "\x01" + parts[1]
				r.retDeferAt[at] = append(r.retDeferAt[at], parts[2])
			}
			for _, entry := range fact.ReturnFieldParamPoison {
				key, position, ok := strings.Cut(entry, "\x01")
				if strings.Count(key, "\x00") != 1 || (ok && !fieldPosition(position, -1)) {
					malformed(fact)
					continue
				}
				if !ok {
					r.retPoisonAt[key] = true
				} else {
					r.retPoisonAt[key+"\x01"+position] = true
				}
			}
			for _, use := range fact.EnvCallUses {
				if varKey, callee, ok := strings.Cut(use, "\x01"); ok {
					r.ctorsOf[varKey] = append(r.ctorsOf[varKey], callee)
				}
			}
		}
	}
	return r
}

// fieldPopulationProves resolves one field-position use against the
// carrier's registered population. On failure the second result names
// the unproven deferred parameter key when one decided it - empty when
// a poison or an unresolved constructor decided
// (REQ-closure-shared-dynamic-state, REQ-explain-chain).
func (r *deferralResolution) fieldPopulationProves(varKey, field, idx string) (bool, string) {
	position := field + "\x00" + idx
	anyIdx := field + "\x00-1"
	if r.fieldPoisonAt[varKey] || r.fieldPoisonAt[varKey+"\x01"+anyIdx] || r.fieldPoisonAt[varKey+"\x01"+position] {
		return false, ""
	}
	for _, paramKey := range r.fieldDeferAt[varKey+"\x01"+position] {
		if !r.paramLeakFree[paramKey] {
			return false, paramKey
		}
	}
	seen := map[string]bool{}
	stack := append([]string(nil), r.ctorsOf[varKey]...)
	for len(stack) > 0 {
		fnKey := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[fnKey] {
			continue
		}
		seen[fnKey] = true
		if !r.envFreeResolved[fnKey] {
			return false, ""
		}
		if r.retPoisonAt[fnKey] || r.retPoisonAt[fnKey+"\x01"+anyIdx] || r.retPoisonAt[fnKey+"\x01"+position] {
			return false, ""
		}
		for _, paramKey := range r.retDeferAt[fnKey+"\x01"+position] {
			if !r.paramLeakFree[paramKey] {
				return false, paramKey
			}
		}
		for dep := range r.envFreeDeps[fnKey] {
			stack = append(stack, dep)
		}
	}
	return true, ""
}

// fieldPosition validates a persisted field-position part - field name
// and parameter index NUL-joined, the index a decimal integer at or
// above minIdx (uses and deferrals require 0; poisons admit -1 as the
// every-index cover). Anything else is a malformed record.
func fieldPosition(part string, minIdx int) bool {
	field, idx, ok := strings.Cut(part, "\x00")
	if !ok || field == "" || strings.Contains(idx, "\x00") {
		return false
	}
	n, err := strconv.Atoi(idx)
	// Canonical spelling only: "00" or "+0" would build a position no
	// recorded mark matches, and a defer-only population would then
	// prove empty - fail-open through a corrupted fact.
	return err == nil && n >= minIdx && strconv.Itoa(n) == idx
}
