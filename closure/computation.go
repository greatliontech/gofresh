package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// computationRules identifies the language-computation checker, not an approved
// implementation. Its facts are pass-local; the policy identity includes the
// rules so dependent persisted judgments cannot inherit changed semantics.
//
// The claim bounds the selected source SSA, not whichever implementation the
// compiler emits for a source-level callee. Native freshness additionally needs
// a checked compiler-body binding; source availability cannot supply it. The
// source claim neither guarantees termination nor equates timings. Measurement
// consumers still owe their existing machine, runtime and caller-owned
// run-condition guards. An explicit hook is checked
// even when its result is discarded: adding a delay or an input read cannot be
// excused as timing noise. Compiler-inserted instrumentation not represented by
// the selected source is outside this grammar; compilation itself retains only
// the existing language/compiler premise (REQ-impl-premise-boundary).
const computationRules = "gofresh/source-computation@1"

// computationCandidates is only a cost gate. The checked certificate and typed
// symbol binding, not this predicate, decide whether a blocker is discharged.
func computationCandidates(effects []externalEffect) bool {
	if len(effects) == 0 {
		return false
	}
	for _, effect := range effects {
		if effect.kind != externalEffectUnauditedStandard || effect.packagePath == "" || effect.symbol == "" || effect.unrefinable {
			return false
		}
	}
	return true
}

// computationContext specializes only callable parameters. Scalar arguments stay
// universally quantified: the claim concerns every value, not a sampled run.
type computationContext struct {
	fn       *ssa.Function
	bindings []*ssa.Function // parallel to fn.Params; nil at scalar positions
}

// computationCertificate proposes an inventory, never a positive conclusion.
// The checker reconstructs source initialization and checks every instruction
// and call against this inventory (REQ-impl-independent-check).
type computationCertificate struct {
	root     *computationContext
	startup  []*computationContext
	contexts []*computationContext
}

type computationFailure struct {
	function *ssa.Function
	at       token.Pos
	premise  string
	phase    computationPhase
	entry    computationContext
	path     *computationFailurePath
}

type computationPhase uint8

const (
	computationSourcePhase computationPhase = iota
	computationSubjectPhase
	computationStartupPhase
)

// computationCallEdge retains the actual specialization on each side of a
// failed call. Function identity alone loses a callback parameter's binding.
type computationCallEdge struct {
	caller, callee computationContext
	at             token.Pos
}

// Failure paths are immutable cons lists: propagation creates one new edge,
// never mutates a subordinate refusal or copies a depth-sized path at each hop.
type computationFailurePath struct {
	edge computationCallEdge
	next *computationFailurePath
}

// computationRefusalAccount is the caller-owned structured refusal projection.
// Every slice belongs to this projection's caller; none
// aliases the certificate, another projection, or the stored refusal.
type computationRefusalAccount struct {
	function *ssa.Function
	at       token.Pos
	premise  string
	phase    computationPhase
	entry    computationContext
	calls    []computationCallEdge
}

func copyComputationContext(c computationContext) computationContext {
	return computationContext{fn: c.fn, bindings: slices.Clone(c.bindings)}
}

func (f *computationFailure) account() computationRefusalAccount {
	account := computationRefusalAccount{function: f.function, at: f.at, premise: f.premise, phase: f.phase, entry: copyComputationContext(f.entry)}
	for path := f.path; path != nil; path = path.next {
		account.calls = append(account.calls, computationCallEdge{
			caller: copyComputationContext(path.edge.caller),
			callee: copyComputationContext(path.edge.callee), at: path.edge.at,
		})
	}
	return account
}

func computationCallFailure(err error, caller, callee *computationContext, at token.Pos) error {
	var failure *computationFailure
	if !errors.As(err, &failure) {
		return err
	}
	propagated := *failure
	propagated.path = &computationFailurePath{edge: computationCallEdge{
		caller: copyComputationContext(*caller), callee: copyComputationContext(*callee), at: at,
	}, next: failure.path}
	return &propagated
}

func computationEntryFailure(err error, entry *computationContext, phase computationPhase) error {
	var failure *computationFailure
	if !errors.As(err, &failure) {
		return err
	}
	attributed := *failure
	attributed.phase, attributed.entry = phase, copyComputationContext(*entry)
	return &attributed
}

func (f *computationFailure) Error() string {
	if f.function != nil {
		return fmt.Sprintf("%s: %s", f.function, f.premise)
	}
	return f.premise
}

func computationRefusal(fn *ssa.Function, at token.Pos, premise string) error {
	return &computationFailure{function: fn, at: at, premise: premise}
}

// computationSource is an input view, not a proof. Both proposal and checking
// read the same selected SSA and syntax; only checking grants authority.
type computationSource struct {
	prog  *program
	metas []listPkg
	owner *selectedSourceOwner
}

func computationPackageInputs(m listPkg, subjectPackage string) error {
	if m.ForTest != "" || m.IsGeneratedTestMainFor(subjectPackage) {
		return computationRefusal(nil, token.NoPos, "test-binary startup is outside the computation grammar")
	}
	if len(m.CgoFiles)+len(m.CFiles)+len(m.CXXFiles)+len(m.MFiles)+len(m.HFiles)+len(m.FFiles)+len(m.SFiles)+len(m.SwigFiles)+len(m.SwigCXXFiles)+len(m.SysoFiles)+len(m.EmbedFiles) != 0 {
		return computationRefusal(nil, token.NoPos, "opaque selected package inputs: "+m.ImportPath)
	}
	return nil
}

// declarations establishes the narrow source boundary: every listed source
// package is present, has exactly the selected Go files, has no source-level
// variables or opaque compilation inputs, and contributes all explicit init
// bodies. Generated package-init guards are not source state: with no variable
// initialization, the source semantics are exactly these init bodies and the
// recursively enumerated imports. No absent callable body is admitted here.
func (s computationSource) declarations(ctx context.Context) (map[*ssa.Function]bool, []*ssa.Function, error) {
	if s.prog == nil || s.prog.Prog == nil {
		return nil, nil, computationRefusal(nil, token.NoPos, "selected program is absent")
	}
	metas := make(map[string]listPkg, len(s.metas))
	for _, m := range s.metas {
		if _, duplicate := metas[m.ImportPath]; duplicate {
			return nil, nil, computationRefusal(nil, token.NoPos, "duplicate selected package")
		}
		metas[m.ImportPath] = m
	}
	seen := map[string]bool{}
	decls := map[*ssa.Function]bool{}
	var inits []*ssa.Function
	for _, p := range s.prog.Pkgs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		m, ok := metas[p.ID]
		if !ok || seen[p.ID] || p.Types == nil || p.TypesInfo == nil || p.Fset == nil || s.prog.Prog.Package(p.Types) == nil {
			return nil, nil, computationRefusal(nil, token.NoPos, "incomplete selected package binding: "+p.ID)
		}
		seen[p.ID] = true
		if err := computationPackageInputs(m, s.prog.PkgPath); err != nil {
			return nil, nil, err
		}
		files := map[string]bool{}
		for _, name := range m.GoFiles {
			files[filepath.Clean(filepath.Join(m.Dir, name))] = true
		}
		if len(files) == 0 || len(files) != len(p.CompiledGoFiles) || len(p.Syntax) != len(files) {
			return nil, nil, computationRefusal(nil, token.NoPos, "incomplete selected source: "+p.ID)
		}
		for i, file := range p.Syntax {
			name := filepath.Clean(p.Fset.PositionFor(file.Pos(), false).Filename)
			if !files[name] || name != filepath.Clean(p.CompiledGoFiles[i]) {
				return nil, nil, computationRefusal(nil, file.Pos(), "selected source disagrees with syntax: "+p.ID)
			}
			delete(files, name)
			for _, group := range file.Comments {
				for _, comment := range group.List {
					if strings.HasPrefix(comment.Text, "//go:") && !strings.HasPrefix(comment.Text, "//go:build ") {
						return nil, nil, computationRefusal(nil, comment.Pos(), "unsupported implementation directive")
					}
				}
			}
			for _, declaration := range file.Decls {
				switch d := declaration.(type) {
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						return nil, nil, computationRefusal(nil, d.Pos(), "package storage is outside the computation grammar")
					}
				case *ast.FuncDecl:
					obj, _ := p.TypesInfo.Defs[d.Name].(*types.Func)
					if obj == nil {
						return nil, nil, computationRefusal(nil, d.Pos(), "function declaration has no selected binding")
					}
					fn := s.prog.Prog.FuncValue(obj)
					if fn != nil && d.Body != nil {
						decls[fn] = true
					}
					if d.Recv == nil && d.Name.Name == "init" {
						if fn == nil || d.Body == nil {
							return nil, nil, computationRefusal(fn, d.Pos(), "initializer body is absent")
						}
						inits = append(inits, fn)
					}
				}
			}
		}
		for _, imported := range p.Imports {
			if imported == nil || !slices.Contains(s.prog.Pkgs, imported) {
				return nil, nil, computationRefusal(nil, token.NoPos, "imported source package is absent: "+p.ID)
			}
		}
	}
	if len(seen) != len(metas) {
		return nil, nil, computationRefusal(nil, token.NoPos, "selected package inventory is incomplete")
	}
	return decls, inits, nil
}

func sameComputationContext(a, b *computationContext) bool {
	return a != nil && b != nil && a.fn == b.fn && slices.Equal(a.bindings, b.bindings)
}

func computationTarget(value ssa.Value, context *computationContext) *ssa.Function {
	switch v := value.(type) {
	case *ssa.Function:
		return v
	case *ssa.Parameter:
		for i, parameter := range context.fn.Params {
			if v == parameter && i < len(context.bindings) {
				return context.bindings[i]
			}
		}
	}
	return nil
}

// computationCallContext describes the operand binding only. It does not
// classify the call's effects or accept the target's implementation.
func computationCallContext(call *ssa.CallCommon, parent *computationContext) *computationContext {
	if call == nil || call.IsInvoke() {
		return nil
	}
	fn := computationTarget(call.Value, parent)
	if fn == nil || len(call.Args) != len(fn.Params) {
		return nil
	}
	child := &computationContext{fn: fn, bindings: make([]*ssa.Function, len(fn.Params))}
	for i, parameter := range fn.Params {
		if _, callable := parameter.Type().Underlying().(*types.Signature); callable {
			child.bindings[i] = computationTarget(call.Args[i], parent)
		}
	}
	return child
}

const computationContextLimit = 4096

// addContext enforces the search bound at insertion, including while a single
// body or initializer list expands. A duplicate at capacity costs no new slot.
func (cert *computationCertificate) addContext(ctx context.Context, candidate *computationContext) (*computationContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, prior := range cert.contexts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sameComputationContext(candidate, prior) {
			return prior, nil
		}
	}
	if len(cert.contexts) >= computationContextLimit {
		return nil, computationRefusal(candidate.fn, candidate.fn.Pos(), "computation context bound exhausted")
	}
	cert.contexts = append(cert.contexts, candidate)
	return candidate, nil
}

// computationSearchPath records the first discovered route to one proposed
// context. Each retained context owns at most one parent link; full paths are
// copied only when projecting a refusal, never at every search expansion.
// A root link identifies a real subject or initializer entry, not a fabricated
// call from the subject into startup. Duplicate contexts keep their first route.
type computationSearchPath struct {
	context *computationContext
	parent  *computationSearchPath
	at      token.Pos
	phase   computationPhase // meaningful at an entry (parent == nil)
}

func (path *computationSearchPath) refusal(err error) error {
	var failure *computationFailure
	if !errors.As(err, &failure) {
		// Cancellation stays the context error and need not traverse a path.
		return err
	}
	for path.parent != nil {
		err = computationCallFailure(err, path.parent.context, path.context, path.at)
		path = path.parent
	}
	return computationEntryFailure(err, path.context, path.phase)
}

// proposeComputation collects a finite context/call inventory. Unresolved sites
// remain in the original bodies for the checker to reject; omission is never an
// admission. Cycles are inventoried, not assumed sound.
func proposeComputation(ctx context.Context, source computationSource, root *ssa.Function) (*computationCertificate, error) {
	_, inits, err := source.declarations(ctx)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, computationRefusal(nil, token.NoPos, "root is absent")
	}
	cert := &computationCertificate{}
	paths := map[*computationContext]*computationSearchPath{}
	add := func(path *computationSearchPath) (*computationContext, error) {
		context, err := cert.addContext(ctx, path.context)
		if err != nil {
			return nil, path.refusal(err)
		}
		if paths[context] == nil {
			paths[context] = path
		}
		return context, nil
	}
	cert.root, err = add(&computationSearchPath{
		context: &computationContext{fn: root, bindings: make([]*ssa.Function, len(root.Params))},
		phase:   computationSubjectPhase,
	})
	if err != nil {
		return nil, err
	}
	for _, init := range inits {
		entry, err := add(&computationSearchPath{
			context: &computationContext{fn: init, bindings: make([]*ssa.Function, len(init.Params))},
			phase:   computationStartupPhase,
		})
		if err != nil {
			return nil, err
		}
		cert.startup = append(cert.startup, entry)
	}
	for i := 0; i < len(cert.contexts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent := cert.contexts[i]
		for _, block := range parent.fn.Blocks {
			for _, instruction := range block.Instrs {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if call, ok := instruction.(*ssa.Call); ok {
					if child := computationCallContext(call.Common(), parent); child != nil {
						if _, err := add(&computationSearchPath{context: child, parent: paths[parent], at: instruction.Pos()}); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cert, nil
}

// computationSelection refuses instrumentation not represented in source SSA.
// These are unsupported configuration mechanisms, not approved implementations.
func (h *Hasher) computationSelection() error {
	flags, err := h.PassReader().Value(h.ctx, "GOFLAGS")
	if err != nil {
		return err
	}
	for _, flag := range append(strings.Fields(flags), h.buildFlags...) {
		if !computationOptionSupported(flag) {
			return computationRefusal(nil, token.NoPos, "unsupported instrumentation or compilation option: "+flag)
		}
	}
	return nil
}

func computationOptionSupported(flag string) bool {
	name, _, _ := strings.Cut(strings.TrimLeft(strings.Trim(flag, "\"'"), "-"), "=")
	switch name {
	case "race", "msan", "asan", "cover", "covermode", "coverpkg", "gcflags", "gccgoflags", "ldflags", "toolexec", "compiler", "buildmode", "linkshared", "pkgdir", "overlay":
		return false
	}
	return true
}

// loadComputation observes source afresh for this maximal batch. It deliberately
// does not read Hasher.progs: that cache may hold another public call's program.
func (h *Hasher) loadComputation(pkgPath string) (computationSource, error) {
	if err := h.computationSelection(); err != nil {
		return computationSource{}, err
	}
	metas, err := h.list(pkgPath)
	if err != nil {
		return computationSource{}, err
	}
	// Metadata refusals precede the expensive SSA load. The checker repeats
	// this gate against the bound inventory; preflight is not proof evidence.
	for _, meta := range metas {
		if err := computationPackageInputs(meta, pkgPath); err != nil {
			return computationSource{}, err
		}
	}
	h.emitProgress("load", pkgPath)
	prog, err := progpkg.Load(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
	return computationSource{prog: prog, metas: metas}, err
}
