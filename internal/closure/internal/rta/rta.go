// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rta implements attributed Rapid Type Analysis (RTA), adapted from
// golang.org/x/tools/go/callgraph/rta v0.46.0 with the v0.50 runtime-type
// signature traversal and alias normalization. It preserves RTA's reachability
// semantics while attributing every fact to the bitmask of subjects (up to 64
// per batch) that discovered it, isolating verified property-harness internal
// standard-library types onto a separate plane, and supporting incremental
// fixed-point extension via Analyzer.Extend.
package rta

import (
	"context"
	"fmt"
	"go/types"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/types/typeutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// Result holds the bitmask-attributed reachability and dynamic-dispatch tables
// produced by an RTA pass.
type Result struct {
	Reachable           map[*ssa.Function]uint64
	Resolved            map[ssa.CallInstruction]uint64
	Targets             map[ssa.CallInstruction]map[*ssa.Function]uint64
	HarnessStdReachable map[*ssa.Function]uint64
	HarnessStdTargets   map[ssa.CallInstruction]map[*ssa.Function]uint64
}

// Seeds carries per-subject facts established outside the walk — the
// caller-enumeration closure of a dynamic-carrying subject hands the
// walk exactly what enumerable callers can pass: function values become
// dispatch candidates (address-taken under the subject's mask, so the
// subject's own dynamic sites resolve to them and their bodies join the
// subject's reachability only if actually dispatched), and materialized
// concrete types enter the runtime-type walk (so interface dispatch on
// a parameter enumerates them and their exported method sets stay
// visible). Seeding never forces reachability by itself: an undispatched
// candidate contributes nothing, mirroring RTA's own address-taken
// semantics.
type Seeds struct {
	AddrTaken    map[*ssa.Function]uint64
	RuntimeTypes []TypeSeed
	// HarnessPkg, when non-empty, names a mechanically verified
	// property-testing harness package whose internal standard-library call
	// graph executes on an isolated runtime-type plane so harness-internal
	// standard-library error/template/codec types never pollute non-harness
	// interface invoke sites, while non-stdlib callbacks and methods
	// dispatched through those standard-library helpers promote back to
	// Reachable.
	HarnessPkg      string
	UserPkgs        map[string]bool
	HarnessStdRoots map[*ssa.Function]uint64
}

// TypeSeed is one concrete type materialized at an enumerated caller
// site, entering the runtime-type walk under the subjects of Masks.
type TypeSeed struct {
	Type  types.Type
	Masks uint64
}

// Analyzer holds the monotone fixed-point state of an attributed RTA walk so
// callers that discover additional roots or seeds (such as testing.T.Cleanup
// or testing.F.Fuzz callbacks) can advance the existing fixed point via Extend
// without re-walking the program from scratch.
type Analyzer struct {
	r *attributedRTA
}

// NewAnalyzer returns a new incremental attributed RTA analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Result returns the analyzer's current attributed RTA result, or nil if no
// roots have been analyzed.
func (a *Analyzer) Result() *Result {
	if a == nil || a.r == nil {
		return nil
	}
	return a.r.result
}

// attributedRTA is the working state of RTA. Every mask is bounded to one
// batch of at most 64 subjects.
type attributedRTA struct {
	result             *Result
	prog               *ssa.Program
	hasher             typeutil.Hasher
	harnessPkg         string
	harnessOnlyTesting bool
	userPkgs           map[string]bool
	hasReflect         bool

	reflectValueCall         *ssa.Function
	reflectValueCallSlice    *ssa.Function
	reflectMethodFuncs       map[*ssa.Function]bool
	reflectSingleMethodFuncs map[*ssa.Function]bool
	reflectWriteFuncs        map[*ssa.Function]reflectWriteKind
	reflectMethodMasks       uint64
	reflectWriteMasks        [numReflectWriteKinds]uint64
	trampolineAsserts        map[*ssa.TypeAssert]bool
	closedMethodCalls        map[*ssa.Call]closedMethodCallInfo
	// current is the function whose body the walk is visiting - the
	// recover boundary's provenance for unsupported-shape panics.
	current *ssa.Function

	worklist []*ssa.Function
	pending  map[*ssa.Function]uint64
	queued   map[*ssa.Function]bool

	harnessWorklist []*ssa.Function
	harnessPending  map[*ssa.Function]uint64
	harnessQueued   map[*ssa.Function]bool

	// Signature -> map[function]subject mask.
	addrTakenFuncsBySig        typeutil.Map
	harnessAddrTakenFuncsBySig typeutil.Map
	// Signature -> map[dynamic call site]subject mask.
	dynCallSites        typeutil.Map
	harnessDynCallSites typeutil.Map
	// Interface -> map[invoke site]subject mask.
	invokeSites        typeutil.Map
	harnessInvokeSites typeutil.Map
	// Receiverless signature -> subject mask of closed v.Method(i).Interface().(S) assertions.
	directReflectMethodSigs typeutil.Map
	// Receiverless signature -> subject mask of type-asserted function signatures.
	reflectAssertSigs typeutil.Map
	// Per-kind receiverless signature -> subject mask of reflect-writable container function slots.
	reflectWriteSigs [numReflectWriteKinds]typeutil.Map
	// Receiverless signature -> map[method function]subject mask of runtime-type methods.
	runtimeMethodFuncs typeutil.Map

	concreteTypes         typeutil.Map
	interfaceTypes        typeutil.Map
	runtimeTypes          typeutil.Map // accessible runtime type -> subject mask
	traversedTypes        typeutil.Map // structurally descended type -> subject mask
	harnessRuntimeTypes   typeutil.Map // harness-internal stdlib runtime type -> subject mask
	harnessTraversedTypes typeutil.Map // harness-internal stdlib descended type -> subject mask
	writableTypes         typeutil.Map // reflect-writable container traversal -> subject mask
	embedROTypes          typeutil.Map // embedded-unexported-field traversal -> subject mask

	typeParamSeen       map[types.Type]bool
	pureHarnessStdTypes map[types.Type]bool
	pkgPaths            map[*ssa.Function]string
	unwrappedCallees    map[*ssa.Function]*ssa.Function
	globalReadMasks     map[*ssa.Global]uint64
	pendingGlobalFuncs  map[*ssa.Global][]pendingGlobalFunc
}

func newAttributedRTA(prog *ssa.Program, seeds *Seeds) *attributedRTA {
	hasher := typeutil.MakeHasher()
	r := &attributedRTA{
		result: &Result{
			Reachable: make(map[*ssa.Function]uint64),
			Resolved:  make(map[ssa.CallInstruction]uint64),
			Targets:   make(map[ssa.CallInstruction]map[*ssa.Function]uint64),
		},
		prog:          prog,
		hasher:        hasher,
		pending:       make(map[*ssa.Function]uint64),
		queued:        make(map[*ssa.Function]bool),
		typeParamSeen: make(map[types.Type]bool),
	}
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	r.directReflectMethodSigs.SetHasher(hasher)
	r.reflectAssertSigs.SetHasher(hasher)
	for k := range numReflectWriteKinds {
		r.reflectWriteSigs[k].SetHasher(hasher)
	}
	r.runtimeMethodFuncs.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)
	r.runtimeTypes.SetHasher(hasher)
	r.traversedTypes.SetHasher(hasher)
	r.writableTypes.SetHasher(hasher)
	r.embedROTypes.SetHasher(hasher)

	r.enableHarnessPlane(seeds)
	r.initReflectMetadata(prog)
	return r
}

func (r *attributedRTA) enableHarnessPlane(seeds *Seeds) {
	if seeds == nil || seeds.HarnessPkg == "" {
		return
	}
	if r.harnessPkg == "" {
		r.harnessPkg = seeds.HarnessPkg
		r.userPkgs = seeds.UserPkgs
		r.result.HarnessStdReachable = make(map[*ssa.Function]uint64)
		r.result.HarnessStdTargets = make(map[ssa.CallInstruction]map[*ssa.Function]uint64)
		r.harnessPending = make(map[*ssa.Function]uint64)
		r.harnessQueued = make(map[*ssa.Function]bool)
		r.harnessAddrTakenFuncsBySig.SetHasher(r.hasher)
		r.harnessDynCallSites.SetHasher(r.hasher)
		r.harnessInvokeSites.SetHasher(r.hasher)
		r.harnessRuntimeTypes.SetHasher(r.hasher)
		r.harnessTraversedTypes.SetHasher(r.hasher)
	}
	if !r.harnessOnlyTesting {
		for root, m := range seeds.HarnessStdRoots {
			if m != 0 && r.funcPkgPath(root) == "testing" {
				r.harnessOnlyTesting = true
				break
			}
		}
	}
}

func (r *attributedRTA) addReachable(f *ssa.Function, masks uint64) {
	if f == nil {
		// MethodValue returns nil for interface and parameterized
		// receivers and LookupMethod can miss: a nil enqueued here
		// crashes the walk into an unsupported-shape refusal.
		return
	}
	delta := masks &^ r.result.Reachable[f]
	if delta == 0 {
		return
	}
	r.result.Reachable[f] |= delta
	r.pending[f] |= delta
	if !r.queued[f] {
		r.queued[f] = true
		r.worklist = append(r.worklist, f)
	}
}

func (r *attributedRTA) addHarnessStdReachable(f *ssa.Function, masks uint64) {
	if f == nil || masks == 0 {
		return
	}
	if !r.isHarnessInternalStdPkg(r.funcPkgPath(f)) {
		r.addReachable(f, masks)
		return
	}
	delta := masks &^ r.result.HarnessStdReachable[f]
	if delta == 0 {
		return
	}
	r.result.HarnessStdReachable[f] |= delta
	r.harnessPending[f] |= delta
	if !r.harnessQueued[f] {
		r.harnessQueued[f] = true
		r.harnessWorklist = append(r.harnessWorklist, f)
	}
}

func (r *attributedRTA) visitFunc(f *ssa.Function, masks uint64, harnessStdPlane bool) {
	r.current = f
	// addRuntimeType(reflect.Value) marks reflect.Value's own method set
	// (including anonymous iterator closures in Methods/Seq/Seq2) reachable
	// whenever a reflect.Value is formatted or boxed, and package "testing"
	// invokes reflect.Value.Call internally in testing/fuzz.go on (*testing.F).Fuzz
	// targets that attribution roots explicitly. Only uses originating outside
	// "reflect" and "testing" activate reflective method-value or container-write
	// propagation.
	callerPkg := r.funcPkgPath(f)
	callerIsHarness := !harnessStdPlane && r.harnessPkg != "" && callerPkg == r.harnessPkg
	ignoreReflectCallee := !r.hasReflect || harnessStdPlane || callerPkg == "reflect" || callerPkg == "testing" || strings.HasPrefix(f.Synthetic, "wrapper ")
	var space [32]*ssa.Value
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands := instr.Operands(space[:0])
			switch instr := instr.(type) {
			case ssa.CallInstruction:
				call := instr.Common()
				if call.IsInvoke() {
					if harnessStdPlane {
						r.visitHarnessStdInvoke(instr, masks)
					} else {
						r.visitInvoke(instr, masks)
					}
				} else if g := call.StaticCallee(); g != nil {
					if harnessStdPlane || (callerIsHarness && r.isHarnessInternalStdPkg(r.funcPkgPath(g))) {
						r.addHarnessStdReachable(g, masks)
					} else {
						// Static edges inherit exactly the caller's newly reached subjects.
						r.addReachable(g, masks)
					}
					if !ignoreReflectCallee {
						r.noteReflectCallSite(instr, g, masks)
					}
				} else if _, ok := call.Value.(*ssa.Builtin); !ok {
					if harnessStdPlane {
						r.visitHarnessStdDynCall(instr, masks)
					} else {
						r.visitDynCall(instr, masks)
					}
				}
				rands = rands[1:]
			case *ssa.MakeInterface:
				if (harnessStdPlane || callerIsHarness) && r.isPureHarnessInternalStdType(instr.X.Type()) {
					r.addHarnessStdRuntimeType(instr.X.Type(), masks, false)
				} else {
					r.addRuntimeType(instr.X.Type(), masks, false)
					if !harnessStdPlane {
						r.addWritableRuntimeType(instr.X.Type(), masks, false)
					}
				}
			case *ssa.TypeAssert:
				if !harnessStdPlane {
					if sig, ok := types.Unalias(instr.AssertedType).Underlying().(*types.Signature); ok {
						if !r.isTypedCallbackTrampolineAssert(f, instr) {
							r.addReflectAssertSig(sig, masks)
						}
					} else if !types.IsInterface(types.Unalias(instr.AssertedType).Underlying()) {
						r.addWritableRuntimeType(instr.AssertedType, masks, false)
					}
				}
			case *ssa.MakeClosure:
				if onlyDirectCallCallee(instr) {
					rands = rands[1:]
				} else if g := onlyStaticGlobalStoreTarget(instr); g != nil {
					if fn, ok := instr.Fn.(*ssa.Function); ok {
						r.visitGlobalStoredFunc(g, fn, masks, harnessStdPlane, !ignoreReflectCallee)
						rands = rands[1:]
					}
				}
			}
			for _, op := range rands {
				switch v := (*op).(type) {
				case *ssa.Function:
					if store, isStore := instr.(*ssa.Store); isStore && op == &store.Val && op != &store.Addr {
						if g := staticGlobalStoreRoot(store.Addr); g != nil {
							r.visitGlobalStoredFunc(g, v, masks, harnessStdPlane, !ignoreReflectCallee)
							continue
						}
					}
					if harnessStdPlane {
						r.visitHarnessStdAddrTakenFunc(v, masks)
					} else {
						r.visitAddrTakenFunc(v, masks)
						if !ignoreReflectCallee {
							r.noteReflectCalleeUse(v, masks)
						}
					}
				case *ssa.Global:
					if !isPureStaticGlobalStoreAddrOp(instr, op, v) {
						r.noteGlobalRead(v, masks)
					}
				}
			}
		}
	}
}

// onlyDirectCallCallee reports whether a closure creation is used exclusively
// as the callee operand of direct call/go/defer instructions (where
// StaticCallee resolves it directly) and never escapes as a first-class value.
func onlyDirectCallCallee(mk *ssa.MakeClosure) bool {
	if mk == nil {
		return false
	}
	refs := mk.Referrers()
	if refs == nil || len(*refs) == 0 {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case ssa.CallInstruction:
			c := r.Common()
			if c == nil || c.IsInvoke() || c.Value != mk {
				return false
			}
			for _, arg := range c.Args {
				if arg == mk {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func (r *attributedRTA) checkNonParameterizedRoots(roots map[*ssa.Function]uint64) error {
	for root := range roots {
		if root == nil {
			continue
		}
		// An instance carries its origin's TypeParams; what makes a
		// root parameterized is an EMPTY argument list (an origin) or
		// an argument still mentioning a type parameter (a
		// parameterized instance) - a fully concrete instance roots
		// like any plain function.
		generic := root.TypeParams().Len() > 0 || (root.Signature != nil && root.Signature.RecvTypeParams() != nil)
		if !generic {
			continue
		}
		args := root.TypeArgs()
		parameterized := len(args) == 0
		for _, arg := range args {
			if r != nil {
				if r.hasTypeParam(arg) {
					parameterized = true
					break
				}
			} else if ContainsTypeParam(arg, nil) {
				parameterized = true
				break
			}
		}
		if parameterized {
			return fmt.Errorf("closure: attributed reachability: parameterized root %s", root.String())
		}
	}
	return nil
}

// Analyze performs attributed RTA for up to 64 subjects at once. roots maps
// each root function to the subjects for which it is an independent-analysis
// root. The walk mirrors upstream RTA, whose internal assertions panic on
// shapes it cannot classify; the boundary converts any such panic into an
// error so an unsupported shape degrades to per-subject unavailable evidence
// in the embedding process — fail-closed, never a crash.
func Analyze(ctx context.Context, roots map[*ssa.Function]uint64, seeds *Seeds) (*Result, error) {
	return NewAnalyzer().Extend(ctx, roots, seeds)
}

// Extend advances the analyzer's attributed RTA fixed point with roots and
// seeds, initializing the analyzer on its first call.
func (a *Analyzer) Extend(ctx context.Context, roots map[*ssa.Function]uint64, seeds *Seeds) (result *Result, err error) {
	var start time.Time
	traceEnabled := trace.Enabled(ctx, trace.DomainClosure, "")
	if traceEnabled {
		start = time.Now()
	}
	var r *attributedRTA
	if a != nil {
		r = a.r
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			site := ""
			if r != nil && r.current != nil {
				site = " (visiting " + r.current.String() + ")"
			}
			result, err = nil, fmt.Errorf("closure: attributed reachability: unsupported analysis shape: %v%s", recovered, site)
		}
	}()
	if ctx == nil {
		return nil, fmt.Errorf("closure: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	if r == nil && len(roots) == 0 && (seeds == nil || len(seeds.HarnessStdRoots) == 0) {
		return nil, nil
	}
	if err := r.checkNonParameterizedRoots(roots); err != nil {
		return nil, err
	}
	if seeds != nil {
		if err := r.checkNonParameterizedRoots(seeds.HarnessStdRoots); err != nil {
			return nil, err
		}
	}
	if r == nil {
		var prog *ssa.Program
		for root := range roots {
			if root != nil {
				prog = root.Prog
				break
			}
		}
		if prog == nil && seeds != nil {
			for root := range seeds.HarnessStdRoots {
				if root != nil {
					prog = root.Prog
					break
				}
			}
		}
		if prog == nil {
			return nil, nil
		}
		r = newAttributedRTA(prog, seeds)
		if a != nil {
			a.r = r
		}
	} else if seeds != nil {
		r.enableHarnessPlane(seeds)
	}

	// Seeds precede root processing so a subject's first-visited dynamic
	// site already sees its enumerated candidates and types; the visit
	// maps are delta-driven, so order affects nothing but avoids a
	// re-walk.
	if seeds != nil {
		for f, masks := range seeds.AddrTaken {
			if f != nil && masks != 0 {
				r.seedAddrTakenFunc(f, masks)
			}
		}
		for _, seed := range seeds.RuntimeTypes {
			if seed.Type != nil && seed.Masks != 0 {
				r.addRuntimeType(seed.Type, seed.Masks, false)
				r.addWritableRuntimeType(seed.Type, seed.Masks, false)
			}
		}
		for root, masks := range seeds.HarnessStdRoots {
			r.addHarnessStdReachable(root, masks)
		}
	}
	for root, masks := range roots {
		r.addReachable(root, masks)
	}
	if err := r.drainWorklists(ctx); err != nil {
		return nil, err
	}
	if traceEnabled {
		trace.Emit(ctx, trace.DomainClosure, "rta.analyze.done", "",
			trace.Int("roots", len(roots)),
			trace.Int("reachable", len(r.result.Reachable)),
			trace.Int("resolved", len(r.result.Resolved)),
			trace.Int("targets", len(r.result.Targets)),
			trace.Int("harness_std_reachable", len(r.result.HarnessStdReachable)),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
	}
	return r.result, nil
}

func (r *attributedRTA) drainWorklists(ctx context.Context) error {
	for len(r.worklist) > 0 || len(r.harnessWorklist) > 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		if len(r.worklist) > 0 {
			var shadow []*ssa.Function
			shadow, r.worklist = r.worklist, shadow
			for _, f := range shadow {
				if err := ctx.Err(); err != nil {
					return fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				r.queued[f] = false
				masks := r.pending[f]
				delete(r.pending, f)
				r.visitFunc(f, masks, false)
			}
		}
		if len(r.harnessWorklist) > 0 {
			var hShadow []*ssa.Function
			hShadow, r.harnessWorklist = r.harnessWorklist, hShadow
			for _, f := range hShadow {
				if err := ctx.Err(); err != nil {
					return fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				r.harnessQueued[f] = false
				masks := r.harnessPending[f]
				delete(r.harnessPending, f)
				r.visitFunc(f, masks, true)
			}
		}
	}
	r.current = nil
	return nil
}
