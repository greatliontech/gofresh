package dynstate

import (
	"encoding/json"
	"fmt"
	"go/types"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

func TestAnalyzeConeAllFactFieldsCorruptionAndForeignPoisonMatrix(t *testing.T) {
	const (
		ownerPkg = "example.com/owner"
		impPkg   = "example.com/imp"
		ownerVar = "example.com/owner.Reg"
	)

	corruptByField := map[string]func(*Fact){
		"Declares":                  func(f *Fact) { f.Declares = append(f.Declares, "bad\x00key") },
		"Mutates":                   func(f *Fact) { f.Mutates = []string{""} },
		"Escapes":                   func(f *Fact) { f.Escapes = []string{"bad\x00key"} },
		"ExportedSeams":             func(f *Fact) { f.ExportedSeams = []syntaxutil.ExportedSeam{{Key: ownerVar}} },
		"NonSeqFuncUses":            func(f *Fact) { f.NonSeqFuncUses = []syntaxutil.FuncKey{{}} },
		"SeqFuncEdges":              func(f *Fact) { f.SeqFuncEdges = []syntaxutil.FuncDepEdge{{}} },
		"ParallelFuncs":             func(f *Fact) { f.ParallelFuncs = []syntaxutil.FuncKey{{}} },
		"ParallelEdges":             func(f *Fact) { f.ParallelEdges = []syntaxutil.FuncDepEdge{{}} },
		"ReceiverReadOnly":          func(f *Fact) { f.ReceiverReadOnly = []syntaxutil.FuncKey{{}} },
		"ReceiverReadOnlyDeps":      func(f *Fact) { f.ReceiverReadOnlyDeps = []syntaxutil.FuncDepEdge{{}} },
		"ReceiverReadOnlyParamDeps": func(f *Fact) { f.ReceiverReadOnlyParamDeps = []syntaxutil.FuncParamDepEdge{{}} },
		"ReceiverRetentionFree":     func(f *Fact) { f.ReceiverRetentionFree = []syntaxutil.FuncKey{{}} },
		"NonMutatingMethods":        func(f *Fact) { f.NonMutatingMethods = []syntaxutil.FuncKey{{Pkg: "other/pkg", Name: "T.M"}} },
		"MethodUses":                func(f *Fact) { f.MethodUses = []syntaxutil.VarMethodUse{{Key: ownerVar}} },
		"InitMethodUses":            func(f *Fact) { f.InitMethodUses = []syntaxutil.VarMethodUse{{Key: ownerVar}} },
		"ParamLeakFree":             func(f *Fact) { f.ParamLeakFree = []syntaxutil.ParamKey{{Index: -1}} },
		"ParamLeakFreeDeps":         func(f *Fact) { f.ParamLeakFreeDeps = []syntaxutil.ParamDepEdge{{}} },
		"ParamLeakFreeMethodDeps":   func(f *Fact) { f.ParamLeakFreeMethodDeps = []syntaxutil.ParamMethodDepEdge{{}} },
		"ParamRetentionFree":        func(f *Fact) { f.ParamRetentionFree = []syntaxutil.ParamKey{{Index: -1}} },
		"ParamRetentionFreeDeps":    func(f *Fact) { f.ParamRetentionFreeDeps = []syntaxutil.ParamDepEdge{{}} },
		"ParamUses": func(f *Fact) {
			f.ParamUses = []syntaxutil.VarParamUse{{Key: ownerVar, Param: syntaxutil.ParamKey{Index: -1}}}
		},
		"InitParamUses": func(f *Fact) {
			f.InitParamUses = []syntaxutil.VarParamUse{{
				Key:   ownerVar,
				Param: syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: ownerPkg, Name: "G"}, Index: 0},
				Func:  syntaxutil.FuncKey{Pkg: ownerPkg, Name: "Encl"},
			}}
		},
		"FieldParamUses": func(f *Fact) { f.FieldParamUses = []syntaxutil.FieldPosKey{{Owner: ownerVar, Index: -1}} },
		"ElemParamUses": func(f *Fact) {
			f.ElemParamUses = []syntaxutil.ElemParamUse{{Key: ownerVar, Owner: ownerVar, Index: -1}}
		},
		"FieldParamDefer": func(f *Fact) {
			f.FieldParamDefer = []syntaxutil.FieldParamDefer{{Pos: syntaxutil.FieldPosKey{Owner: ownerVar, Field: "F", Index: 0}, Param: syntaxutil.ParamKey{Index: -1}}}
		},
		"FieldParamPoison": func(f *Fact) {
			f.FieldParamPoison = []syntaxutil.FieldParamPoison{{Owner: ownerVar, HasPos: true, Field: "F", Index: -2}}
		},
		"ReturnFieldParamDefer":  func(f *Fact) { f.ReturnFieldParamDefer = []syntaxutil.ReturnFieldParamDefer{{}} },
		"ReturnFieldParamPoison": func(f *Fact) { f.ReturnFieldParamPoison = []syntaxutil.ReturnFieldParamPoison{{}} },
		"AttributedUses":         func(f *Fact) { f.AttributedUses = []syntaxutil.AttributedUse{{Key: ownerVar}} },
		"FuncRefs":               func(f *Fact) { f.FuncRefs = []syntaxutil.FuncRef{{}} },
		"Opaque":                 func(f *Fact) { f.Opaque = []string{""} },
		"OpacityBreaks":          func(f *Fact) { f.OpacityBreaks = []string{""} },
		"OpaqueDeps":             func(f *Fact) { f.OpaqueDeps = []syntaxutil.OpaqueDep{{Own: ownerVar}} },
		"CarrierLinks":           func(f *Fact) { f.CarrierLinks = []syntaxutil.CarrierLink{{From: ownerVar}} },
		"EnvCarrying":            func(f *Fact) { f.EnvCarrying = []string{""} },
		"EnvCarryingFns": func(f *Fact) {
			f.EnvCarryingFns = []syntaxutil.VarFuncUse{{Key: ownerVar, Func: syntaxutil.FuncKey{Pkg: impPkg, Name: "H"}}}
		},
		"EnvCallable":            func(f *Fact) { f.EnvCallable = []string{""} },
		"EnvCallUses":            func(f *Fact) { f.EnvCallUses = []syntaxutil.EnvCallUse{{Key: ownerVar}} },
		"EnvCallParamUses":       func(f *Fact) { f.EnvCallParamUses = []syntaxutil.EnvCallParamUse{{Key: ownerVar}} },
		"EnvCallMethodUses":      func(f *Fact) { f.EnvCallMethodUses = []syntaxutil.EnvCallMethodUse{{Key: ownerVar}} },
		"ReturnEnvFree":          func(f *Fact) { f.ReturnEnvFree = []syntaxutil.FuncKey{{}} },
		"ReturnEnvDeps":          func(f *Fact) { f.ReturnEnvDeps = []syntaxutil.FuncDepEdge{{}} },
		"ReturnEnvParamDeps":     func(f *Fact) { f.ReturnEnvParamDeps = []syntaxutil.FuncParamDepEdge{{}} },
		"ReturnEnvMethodDeps":    func(f *Fact) { f.ReturnEnvMethodDeps = []syntaxutil.FuncDepEdge{{}} },
		"ParamInsertionFree":     func(f *Fact) { f.ParamInsertionFree = []syntaxutil.ParamKey{{Index: -1}} },
		"ReturnEnvInsertionDeps": func(f *Fact) { f.ReturnEnvInsertionDeps = []syntaxutil.FuncInsertionDepEdge{{}} },
		"ParamInsertionDeps":     func(f *Fact) { f.ParamInsertionDeps = []syntaxutil.ParamInsertionDepEdge{{}} },
		"ParamInsertionParamDeps": func(f *Fact) {
			f.ParamInsertionParamDeps = []syntaxutil.ParamDepEdge{{}}
		},
		"ParamInsertionMethodDeps": func(f *Fact) {
			f.ParamInsertionMethodDeps = []syntaxutil.ParamMethodDepEdge{{}}
		},
		"PureMethods":        func(f *Fact) { f.PureMethods = map[string]string{"": "v"} },
		"ExternalMethods":    func(f *Fact) { f.ExternalMethods = map[string]string{"T.M": ""} },
		"PoolDischarges":     func(f *Fact) { f.PoolDischarges = []string{"unqualified"} },
		"PoolMutates":        func(f *Fact) { f.PoolMutates = []string{"unqualified"} },
		"PoolEscapes":        func(f *Fact) { f.PoolEscapes = []string{"unqualified"} },
		"PoolAttributedUses": func(f *Fact) { f.PoolAttributedUses = []syntaxutil.AttributedUse{{Key: ownerVar}} },
		"SingleSubjectVars":  func(f *Fact) { f.SingleSubjectVars = []string{"unqualified"} },
		"MappingDischarges":  func(f *Fact) { f.MappingDischarges = []string{"unqualified"} },
		"MemoDischarges":     func(f *Fact) { f.MemoDischarges = []string{"unqualified"} },
		"OnceMemoTypes":      func(f *Fact) { f.OnceMemoTypes = []syntaxutil.OnceMemoTypeFact{{}} },
		"OnceMemoCandidates": func(f *Fact) {
			f.OnceMemoCandidates = []syntaxutil.OnceMemoVarCandidate{{
				Key:         "other.pkg.V",
				Type:        syntaxutil.TypeRef{Pkg: ownerPkg, Name: "M"},
				Constructor: syntaxutil.FuncKey{Pkg: ownerPkg, Name: "NewM"},
			}}
		},
		"HarnessDischarges": func(f *Fact) { f.HarnessDischarges = []string{ownerVar} },
		"ProtoClusters":     func(f *Fact) { f.ProtoClusters = []protoaudit.ProtoClusterFact{{}} },
		"ReadOnlyVarAliases": func(f *Fact) {
			f.ReadOnlyVarAliases = []syntaxutil.ReadOnlyVarAlias{{
				Key:    "other.pkg.A",
				Target: ownerVar,
			}}
		},
		"ProtoRuntimeTypes": func(f *Fact) { f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{}} },
		"StaticCompositeGlobals": func(f *Fact) {
			f.StaticCompositeGlobals = []syntaxutil.StaticCompositeGlobalFact{{
				Key:        "other.pkg.Desc",
				GuardTypes: []syntaxutil.TypeRef{{Pkg: ownerPkg, Name: "Desc"}},
			}}
		},
		"MutatedStructTypes": func(f *Fact) { f.MutatedStructTypes = []syntaxutil.TypeRef{{}} },
		"ConditionalStructMutations": func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{}}
		},
		"ReflectedIfaceMethodSets": func(f *Fact) {
			f.ReflectedIfaceMethodSets = []syntaxutil.ReflectedIfaceFact{{MethodSet: "b\x1fa"}}
		},
		"NoPostInitCarrierWrites": func(f *Fact) {
			f.NoPostInitCarrierWrites = false
			f.CarrierImportCalls = []string{"example.com/other"}
		},
		"CarrierImportCalls": func(f *Fact) {
			f.NoPostInitCarrierWrites = true
			f.CarrierImportCalls = []string{""}
		},
		"DirectVarWrites":  func(f *Fact) { f.DirectVarWrites = []string{"unqualified"} },
		"NonMethodVarUses": func(f *Fact) { f.NonMethodVarUses = []string{"unqualified"} },
	}

	factType := reflect.TypeFor[Fact]()
	if len(corruptByField) != factType.NumField() {
		t.Fatalf("corruptByField covers %d fields, Fact has %d fields", len(corruptByField), factType.NumField())
	}
	for i := 0; i < factType.NumField(); i++ {
		fname := factType.Field(i).Name
		corrupt, ok := corruptByField[fname]
		if !ok {
			t.Fatalf("Fact.%s missing from corruption matrix", fname)
		}
		t.Run("self_"+fname, func(t *testing.T) {
			f := Fact{
				Declares:       []string{ownerVar},
				MemoDischarges: []string{ownerVar},
			}
			corrupt(&f)
			meta := []GraphPackage{{
				ImportPath: ownerPkg,
				PkgPath:    ownerPkg,
				Class:      MutableLocalPackage,
			}}
			malformedCalls := 0
			res := AnalyzeCone(ConeQuery{
				Meta:          meta,
				Facts:         map[string][]Fact{ownerPkg: {f}},
				ViewPackage:   ownerPkg,
				SingleSubject: true,
				OnMalformed:   func(Fact) { malformedCalls++ },
			})
			if malformedCalls != 1 {
				t.Fatalf("OnMalformed called %d times, want 1", malformedCalls)
			}
			if res.State.Downgraded == "" {
				t.Fatalf("corrupted Fact.%s failed open in Compose: %+v", fname, res.State)
			}
			if res.NonVouchDischarged[ownerVar] {
				t.Fatalf("corrupted Fact.%s remained in NonVouchDischarged", fname)
			}
		})
	}

	// Verify foreign-key malformed entries in an empty-Declares importer Fact
	// poison ownerVar in BOTH Compose and NonVouchDischargedVars (keeping them in lockstep).
	foreignTargetFields := []string{
		"ExportedSeams",
		"MethodUses",
		"InitMethodUses",
		"ParamUses",
		"InitParamUses",
		"FieldParamUses",
		"ElemParamUses",
		"AttributedUses",
		"PoolAttributedUses",
		"CarrierLinks",
		"EnvCarryingFns",
		"EnvCallUses",
		"EnvCallParamUses",
		"EnvCallMethodUses",
	}
	for _, fname := range foreignTargetFields {
		t.Run("foreign_poison_"+fname, func(t *testing.T) {
			ownerFact := Fact{
				Declares:       []string{ownerVar},
				MemoDischarges: []string{ownerVar},
			}
			var impFact Fact
			corruptByField[fname](&impFact)
			meta := []GraphPackage{
				{ImportPath: impPkg, PkgPath: impPkg, Imports: []string{ownerPkg}, Class: MutableLocalPackage},
				{ImportPath: ownerPkg, PkgPath: ownerPkg, Class: PinnedPackage, Pin: "example.com/owner@v1.0.0"},
			}
			res := AnalyzeCone(ConeQuery{
				Meta:          meta,
				Facts:         map[string][]Fact{impPkg: {impFact}, ownerPkg: {ownerFact}},
				ViewPackage:   impPkg,
				SingleSubject: true,
			})
			if res.State.Downgraded == "" {
				t.Fatalf("foreign malformed %s failed open in Compose", fname)
			}
			if res.NonVouchDischarged[ownerVar] {
				t.Fatalf("foreign malformed %s left %s in NonVouchDischarged while Compose downgraded", fname, ownerVar)
			}
		})
	}

	t.Run("foreign_malformed_alias_revokes_owner_once_memo", func(t *testing.T) {
		memoType := syntaxutil.TypeRef{Pkg: ownerPkg, Name: "Memo"}
		ctorFn := syntaxutil.FuncKey{Pkg: ownerPkg, Name: "NewMemo"}
		ownerFact := Fact{
			Declares: []string{ownerVar},
			Escapes:  []string{ownerVar},
			OnceMemoTypes: []syntaxutil.OnceMemoTypeFact{{
				Type:         memoType,
				Constructors: []syntaxutil.FuncKey{ctorFn},
				GuardTypes:   []syntaxutil.TypeRef{memoType},
			}},
			OnceMemoCandidates: []syntaxutil.OnceMemoVarCandidate{{
				Key:         ownerVar,
				Type:        memoType,
				Constructor: ctorFn,
			}},
		}
		impFact := Fact{
			ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{Key: "", Target: ownerVar}},
		}
		meta := []GraphPackage{
			{ImportPath: impPkg, PkgPath: impPkg, Imports: []string{ownerPkg}, Class: MutableLocalPackage},
			{ImportPath: ownerPkg, PkgPath: ownerPkg, Class: PinnedPackage, Pin: "example.com/owner@v1.0.0"},
		}
		res := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         map[string][]Fact{impPkg: {impFact}, ownerPkg: {ownerFact}},
			ViewPackage:   impPkg,
			SingleSubject: true,
		})
		if res.State.Downgraded == "" {
			t.Fatalf("foreign malformed ReadOnlyVarAliases failed open in Compose")
		}
		if res.NonVouchDischarged[ownerVar] {
			t.Fatalf("foreign malformed ReadOnlyVarAliases left %s in NonVouchDischarged while Compose downgraded", ownerVar)
		}
	})
}

func TestAnalyzeConeOwnerUnprovenInvariantsAndOpGoWriteTracking(t *testing.T) {
	t.Run("env_call_uses_leaves_owner_unproven_unset", func(t *testing.T) {
		const (
			pkg = "example.com/p"
			v   = "example.com/p.Reg"
		)
		provenCtor := syntaxutil.FuncKey{Pkg: pkg, Name: "MakeClean"}
		unprovenCtor := syntaxutil.FuncKey{Pkg: pkg, Name: "MakeDirty"}

		cleanFact := Fact{
			Declares:      []string{v},
			EnvCallUses:   []syntaxutil.EnvCallUse{{Key: v, Callee: provenCtor}},
			ReturnEnvFree: []syntaxutil.FuncKey{provenCtor},
		}
		cleanRes := AnalyzeCone(ConeQuery{Facts: map[string][]Fact{pkg: {cleanFact}}})
		if cleanRes.Deferral.OwnerUnproven[v] {
			t.Fatal("proven EnvCallUses unexpectedly set OwnerUnproven")
		}
		if ok, _ := cleanRes.Deferral.FieldPopulationProves(v, "F", 0); !ok {
			t.Fatal("FieldPopulationProves failed on proven EnvCallUses")
		}

		dirtyFact := Fact{
			Declares:    []string{v},
			EnvCallUses: []syntaxutil.EnvCallUse{{Key: v, Callee: unprovenCtor}},
		}
		dirtyRes := AnalyzeCone(ConeQuery{Facts: map[string][]Fact{pkg: {dirtyFact}}})
		if dirtyRes.Deferral.OwnerUnproven[v] {
			t.Fatal("unproven EnvCallUses must leave OwnerUnproven unset and gate via CtorsOf")
		}
		if ok, _ := dirtyRes.Deferral.FieldPopulationProves(v, "F", 0); ok {
			t.Fatal("FieldPopulationProves unexpectedly succeeded on unproven CtorsOf")
		}
	})

	t.Run("unlinked_field_isolation_linked_propagation_and_opaque_insulation", func(t *testing.T) {
		const (
			pkg         = "example.com/p"
			varUnlinked = "example.com/p.Unlinked"
			varA        = "example.com/p.A"
			varB        = "example.com/p.B"
			varSen      = "example.com/p.ErrClosed"
		)
		unprovenParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: pkg, Name: "SetBad"}, Index: 0}
		provenParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: pkg, Name: "SetGood"}, Index: 0}
		fact := Fact{
			Declares:      []string{varUnlinked, varA, varB, varSen},
			Opaque:        []string{varSen},
			ParamLeakFree: []syntaxutil.ParamKey{provenParam},
			FieldParamDefer: []syntaxutil.FieldParamDefer{
				{Pos: syntaxutil.FieldPosKey{Owner: varUnlinked, Field: "Bad", Index: 0}, Param: unprovenParam},
				{Pos: syntaxutil.FieldPosKey{Owner: varUnlinked, Field: "Good", Index: 0}, Param: provenParam},
				{Pos: syntaxutil.FieldPosKey{Owner: varA, Field: "Bad", Index: 0}, Param: unprovenParam},
			},
			FieldParamUses: []syntaxutil.FieldPosKey{
				{Owner: varUnlinked, Field: "Bad", Index: 0},
				{Owner: varA, Field: "Bad", Index: 0},
			},
			CarrierLinks: []syntaxutil.CarrierLink{
				{From: varA, To: varB},
				{From: varA, To: varSen},
			},
		}
		res := AnalyzeCone(ConeQuery{Facts: map[string][]Fact{pkg: {fact}}})
		if res.Deferral.OwnerUnproven[varUnlinked] {
			t.Fatal("unlinked varUnlinked's failed FieldParamUse must not set OwnerUnproven[varUnlinked]")
		}
		if ok, _ := res.Deferral.FieldPopulationProves(varUnlinked, "Good", 0); !ok {
			t.Fatal("proven sibling field Good on varUnlinked must still succeed")
		}
		if !res.Deferral.OwnerUnproven[varB] {
			t.Fatal("linked neighbor varB must receive OwnerUnproven from varA's failed FieldParamUse")
		}
		if res.Deferral.OwnerUnproven[varSen] {
			t.Fatal("closed sentinel varSen must remain insulated from OwnerUnproven propagation")
		}
	})

	t.Run("pool_execution_gating_and_non_vouch_exclusion", func(t *testing.T) {
		const (
			pkg  = "example.com/p"
			pool = "example.com/p.pool"
		)
		fact := Fact{
			Declares:       []string{pool},
			PoolDischarges: []string{pool},
			PoolMutates:    []string{pool},
		}
		meta := []GraphPackage{{ImportPath: pkg, PkgPath: pkg, Class: MutableLocalPackage}}

		unattested := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         map[string][]Fact{pkg: {fact}},
			ViewPackage:   pkg,
			SingleSubject: false,
		})
		if !unattested.Deferral.OwnerUnproven[pool] || unattested.State.Downgraded == "" {
			t.Fatalf("unattested PoolMutates must set OwnerUnproven and downgrade: %+v", unattested.State)
		}
		if unattested.NonVouchDischarged[pool] {
			t.Fatal("PoolDischarges must never populate NonVouchDischarged")
		}

		attested := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         map[string][]Fact{pkg: {fact}},
			ViewPackage:   pkg,
			SingleSubject: true,
		})
		if attested.Deferral.OwnerUnproven[pool] || attested.State.Downgraded != "" {
			t.Fatalf("attested PoolDischarges must discharge under SingleSubject: %+v", attested.State)
		}
		if !strings.Contains(attested.State.AttestationDischarges, pool) {
			t.Fatalf("missing pool in AttestationDischarges: %q", attested.State.AttestationDischarges)
		}
		if attested.NonVouchDischarged[pool] {
			t.Fatal("PoolDischarges must remain excluded from NonVouchDischarged even under SingleSubject")
		}
	})

	t.Run("op_go_addr_and_array_slice_disqualify_single_write_and_sentinel", func(t *testing.T) {
		pkg := mustTypecheckPackage(t, "example.com/goescape", map[string]string{
			"p.go": `package goescape

import "errors"

var (
	ErrClean     = errors.New("clean")
	ErrGoAddr    = errors.New("goaddr")
	ErrGoClosure = errors.New("goclosure")
	RegClean     []func() string
	RegGoAddr    []func() string
)

func takePtr(*error) {}
func takeFnPtr(*func() string) {}

func registerClean(fn func() string) {
	RegClean = append(RegClean, func() string { return fn() })
}

func registerGoAddr(fn func() string) {
	RegGoAddr = append(RegGoAddr, func() string { return fn() })
}

func init() {
	cleanLocalFn := func() string { return "a" }
	goAddrLocalFn := func() string { return "b" }
	go takeFnPtr(&goAddrLocalFn)
	registerClean(cleanLocalFn)
	registerGoAddr(goAddrLocalFn)
}

func Spawn() {
	go takePtr(&ErrGoAddr)
	go func() {
		_ = &ErrGoClosure
	}()
}
`,
		})
		fact := FactOf(true, pkg)
		if !slices.Contains(fact.Opaque, "example.com/goescape.ErrClean") {
			t.Fatalf("ErrClean missing from Opaque: %+v", fact.Opaque)
		}
		if slices.Contains(fact.Opaque, "example.com/goescape.ErrGoAddr") {
			t.Fatalf("ErrGoAddr taken by address in OpGo remained Opaque: %+v", fact.Opaque)
		}
		if slices.Contains(fact.Opaque, "example.com/goescape.ErrGoClosure") {
			t.Fatalf("ErrGoClosure taken by address inside OpGo closure remained Opaque: %+v", fact.Opaque)
		}
		if slices.Contains(fact.EnvCarrying, "example.com/goescape.RegClean") {
			t.Fatalf("RegClean unexpectedly marked EnvCarrying: %+v", fact.EnvCarrying)
		}
		if !slices.Contains(fact.EnvCarrying, "example.com/goescape.RegGoAddr") {
			t.Fatalf("RegGoAddr over OpGo address-taken goAddrFn missed EnvCarrying: %+v", fact.EnvCarrying)
		}
	})

	t.Run("once_do_addressed_wrapper_evicts_aliased_fresh_slice", func(t *testing.T) {
		pkg := mustTypecheckPackage(t, "example.com/onceaddr", map[string]string{
			"p.go": `package onceaddr

import "sync"

type CleanBox struct {
	once sync.Once
	a    [][]int
}

func (c *CleanBox) Get() int {
	c.once.Do(func() {
		s := make([][]int, 1)
		c.a = s
		c.a[0] = []int{2}
	})
	return c.a[0][0]
}

type AddressedWrapperBox struct {
	once sync.Once
	a    [][]int
}

func (c *AddressedWrapperBox) Get() int {
	c.once.Do(func() {
		s := make([][]int, 1)
		box := [1][][]int{s}
		p := &box
		_ = p
		c.a = s
		c.a[0] = []int{2}
	})
	return len(c.a)
}
`,
		})
		fact := FactOf(true, pkg)
		cleanMethod := syntaxutil.FuncKey{Pkg: "example.com/onceaddr", Name: "CleanBox.Get"}
		addrMethod := syntaxutil.FuncKey{Pkg: "example.com/onceaddr", Name: "AddressedWrapperBox.Get"}
		if !slices.Contains(fact.ReceiverReadOnly, cleanMethod) {
			t.Fatalf("CleanBox.Get missing from ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
		}
		if slices.Contains(fact.ReceiverReadOnly, addrMethod) {
			t.Fatalf("AddressedWrapperBox.Get with &box alias remained ReceiverReadOnly: %+v", fact.ReceiverReadOnly)
		}
	})

	t.Run("sibling_variant_malformed_poisons_clean_variant_declares", func(t *testing.T) {
		const (
			pkg = "example.com/p"
			v   = "example.com/p.V"
		)
		meta := []GraphPackage{{ImportPath: pkg, PkgPath: pkg, Class: MutableLocalPackage}}
		malformedVariant := Fact{MemoDischarges: []string{"unqualified"}}
		cleanVariant := Fact{Declares: []string{v}, MemoDischarges: []string{v}}
		res := AnalyzeCone(ConeQuery{
			Meta:        meta,
			Facts:       map[string][]Fact{pkg: {malformedVariant, cleanVariant}},
			ViewPackage: pkg,
		})
		if res.State.Downgraded == "" || res.NonVouchDischarged[v] {
			t.Fatalf("malformed sibling variant failed to poison clean variant Declares: state=%+v nvd=%+v", res.State, res.NonVouchDischarged)
		}
	})

	t.Run("multi_root_meta_permutation_and_cone_buckets_parity", func(t *testing.T) {
		meta := []GraphPackage{
			{ImportPath: "example.com/app.test", PkgPath: "example.com/app.test", TestMain: true, Imports: []string{"example.com/app [example.com/app.test]", "example.com/app_test [example.com/app.test]"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/app_test [example.com/app.test]", PkgPath: "example.com/app_test", ForTest: "example.com/app", Imports: []string{"example.com/app [example.com/app.test]", "example.com/extdep"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/app [example.com/app.test]", PkgPath: "example.com/app", ForTest: "example.com/app", Imports: []string{"fmt", "example.com/pindep"}, Class: MutableLocalPackage},
			{ImportPath: "fmt", PkgPath: "fmt", Imports: []string{"example.com/stdinternal"}, Class: StandardPackage},
			{ImportPath: "example.com/stdinternal", PkgPath: "example.com/stdinternal", Class: PinnedPackage, Pin: "example.com/stdinternal@v1.0.0"},
			{ImportPath: "example.com/pindep", PkgPath: "example.com/pindep", Class: PinnedPackage, Pin: "example.com/pindep@v1.0.0"},
			{ImportPath: "example.com/extdep", PkgPath: "example.com/extdep", Class: PinnedPackage, Pin: "example.com/extdep@v2.0.0"},
		}
		facts := map[string][]Fact{
			"example.com/app":         {{Declares: []string{"example.com/app.Local"}, Mutates: []string{"example.com/app.Local"}}},
			"example.com/app_test":    {{Declares: []string{"example.com/app_test.ExtTestVar"}, Mutates: []string{"example.com/app_test.ExtTestVar"}}},
			"example.com/pindep":      {{Declares: []string{"example.com/pindep.Pin"}, Mutates: []string{"example.com/pindep.Pin"}}},
			"example.com/extdep":      {{Declares: []string{"example.com/extdep.Ext"}, Mutates: []string{"example.com/extdep.Ext"}}},
			"example.com/stdinternal": {{Declares: []string{"example.com/stdinternal.Hidden"}, Mutates: []string{"example.com/stdinternal.Hidden"}}},
		}
		byListing := map[string]GraphPackage{}
		for _, n := range meta {
			byListing[n.ImportPath] = n
		}
		factsByListing := map[string]Fact{
			"example.com/app [example.com/app.test]": {Declares: []string{"example.com/app.Local"}, Mutates: []string{"example.com/app.Local"}},
			"example.com/pindep":                     {Declares: []string{"example.com/pindep.Pin"}, Mutates: []string{"example.com/pindep.Pin"}},
			"example.com/extdep":                     {Declares: []string{"example.com/extdep.Ext"}, Mutates: []string{"example.com/extdep.Ext"}},
			"example.com/stdinternal":                {Declares: []string{"example.com/stdinternal.Hidden"}, Mutates: []string{"example.com/stdinternal.Hidden"}},
		}
		_, baseConeFacts := Cone(meta, byListing, factsByListing, "example.com/app")
		baseBuckets, baseUnkey := PinnedBuckets(meta)
		baseRes := AnalyzeCone(ConeQuery{
			Meta:        meta,
			Facts:       facts,
			ViewPackage: "example.com/app",
			Vouches:     map[string]bool{"example.com/pindep.Pin": true},
		})
		for _, c := range baseRes.State.RootCulprits {
			if c.Key == "example.com/stdinternal.Hidden" {
				t.Fatal("StandardPackage boundary failed to prune transitive imports in AnalyzeCone")
			}
		}
		// In-package root ("example.com/app") must precede external test root ("example.com/app_test")
		// regardless of Meta slice ordering!
		if baseRes.State.CulpritPkg != "example.com/app" || baseRes.State.CulpritSym != "Local" {
			t.Fatalf("unexpected primary culprit: %s.%s", baseRes.State.CulpritPkg, baseRes.State.CulpritSym)
		}

		rng := rand.New(rand.NewPCG(17, 99))
		for trial := 0; trial < 20; trial++ {
			perm := slices.Clone(meta)
			rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
			_, permConeFacts := Cone(perm, byListing, factsByListing, "example.com/app")
			if !reflect.DeepEqual(permConeFacts, baseConeFacts) {
				t.Fatalf("Cone facts changed under Meta permutation on trial %d", trial)
			}
			gotB, gotU := PinnedBuckets(perm)
			if !reflect.DeepEqual(gotB, baseBuckets) || !reflect.DeepEqual(gotU, baseUnkey) {
				t.Fatalf("PinnedBuckets changed under Meta permutation on trial %d", trial)
			}
			permRes := AnalyzeCone(ConeQuery{
				Meta:        perm,
				Facts:       facts,
				ViewPackage: "example.com/app",
				Vouches:     map[string]bool{"example.com/pindep.Pin": true},
			})
			if !reflect.DeepEqual(permRes.State, baseRes.State) {
				t.Fatalf("ConeState changed under Meta permutation on trial %d:\ngot:  %+v\nwant: %+v", trial, permRes.State, baseRes.State)
			}
		}
	})

	t.Run("once_memo_rejects_auto_addr_mutated_value_global_and_converted_writes", func(t *testing.T) {
		meta, pkgs, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{{
			pkgPath: "example.com/oncememoglobal",
			src: `package oncememoglobal

import (
	"errors"
	"sync"
)

type flag bool

func (f *flag) Enable() { *f = true }

type bytesAlias []byte

var (
	cleanFlag      = flag(false)
	poisonedFlag   = flag(false)
	convertedClear = bytesAlias{1, 2}
	convertedWrite = bytesAlias{3, 4}
)

func EnablePoison() {
	poisonedFlag.Enable()
	clear(([]byte)(convertedClear))
	(([]byte)(convertedWrite))[0] = 9
}

func computeClean() (string, error) {
	if bool(cleanFlag) {
		return "", errors.New("clean")
	}
	return "ok", nil
}

type CleanMemo struct {
	once sync.Once
	val  string
	err  error
}

func NewCleanMemo() *CleanMemo { return &CleanMemo{} }

func (m *CleanMemo) Get() (string, error) {
	m.once.Do(func() {
		m.val, m.err = computeClean()
	})
	return m.val, m.err
}

func computePoisoned() (string, error) {
	if bool(poisonedFlag) {
		return "", errors.New("poisoned")
	}
	return "ok", nil
}

type PoisonedMemo struct {
	once sync.Once
	val  string
	err  error
}

func NewPoisonedMemo() *PoisonedMemo { return &PoisonedMemo{} }

func (m *PoisonedMemo) Get() (string, error) {
	m.once.Do(func() {
		m.val, m.err = computePoisoned()
	})
	return m.val, m.err
}

func computeConvertedClear() (string, error) {
	if len(convertedClear) > 0 && convertedClear[0] == 0 {
		return "", errors.New("cleared")
	}
	return "ok", nil
}

type ConvertedClearMemo struct {
	once sync.Once
	val  string
	err  error
}

func NewConvertedClearMemo() *ConvertedClearMemo { return &ConvertedClearMemo{} }

func (m *ConvertedClearMemo) Get() (string, error) {
	m.once.Do(func() {
		m.val, m.err = computeConvertedClear()
	})
	return m.val, m.err
}

func computeConvertedWrite() (string, error) {
	if len(convertedWrite) > 0 && convertedWrite[0] == 9 {
		return "", errors.New("written")
	}
	return "ok", nil
}

type ConvertedWriteMemo struct {
	once sync.Once
	val  string
	err  error
}

func NewConvertedWriteMemo() *ConvertedWriteMemo { return &ConvertedWriteMemo{} }

func (m *ConvertedWriteMemo) Get() (string, error) {
	m.once.Do(func() {
		m.val, m.err = computeConvertedWrite()
	})
	return m.val, m.err
}

var (
	cleanDefault          = NewCleanMemo()
	poisonedDefault       = NewPoisonedMemo()
	convertedClearDefault = NewConvertedClearMemo()
	convertedWriteDefault = NewConvertedWriteMemo()
)

func ReadAll() (string, error) {
	if _, err := cleanDefault.Get(); err != nil {
		return "", err
	}
	if _, err := poisonedDefault.Get(); err != nil {
		return "", err
	}
	if _, err := convertedClearDefault.Get(); err != nil {
		return "", err
	}
	return convertedWriteDefault.Get()
}
`,
		}})
		fact := facts["example.com/oncememoglobal"][0]
		if len(fact.OnceMemoTypes) != 1 || fact.OnceMemoTypes[0].Type.Name != "CleanMemo" {
			t.Fatalf("OnceMemoTypes = %+v, want [CleanMemo]", fact.OnceMemoTypes)
		}
		res := AnalyzeCone(ConeQuery{
			Meta:        meta,
			Facts:       facts,
			ViewPackage: "example.com/oncememoglobal",
		})
		if !res.NonVouchDischarged["example.com/oncememoglobal.cleanDefault"] {
			t.Fatalf("cleanDefault missing from NonVouchDischarged: %+v", res.NonVouchDischarged)
		}
		for _, bad := range []string{
			"example.com/oncememoglobal.poisonedDefault",
			"example.com/oncememoglobal.convertedClearDefault",
			"example.com/oncememoglobal.convertedWriteDefault",
		} {
			if res.NonVouchDischarged[bad] {
				t.Fatalf("mutated global allowed %s into NonVouchDischarged: %+v", bad, res.NonVouchDischarged)
			}
		}
		memoPkg := pkgs["example.com/oncememoglobal"]
		fc := newPkgFlowCache(true, memoPkg)
		cleanVar := memoPkg.Types.Scope().Lookup("cleanFlag").(*types.Var)
		if _, ok := fc.singleWritePkgGlobalInit(memoPkg, cleanVar); !ok || fc.varHasExplicitWriteOrAddr(memoPkg, cleanVar) {
			t.Fatal("cleanFlag unexpectedly disqualified in pkgFlowCache")
		}
		for _, mutatedName := range []string{"poisonedFlag", "convertedClear", "convertedWrite"} {
			gv := memoPkg.Types.Scope().Lookup(mutatedName).(*types.Var)
			if _, ok := fc.singleWritePkgGlobalInit(memoPkg, gv); ok {
				t.Fatalf("%s unexpectedly accepted by singleWritePkgGlobalInit", mutatedName)
			}
			if !fc.varHasExplicitWriteOrAddr(memoPkg, gv) {
				t.Fatalf("%s missed by varHasExplicitWriteOrAddr", mutatedName)
			}
		}
	})

	t.Run("range_body_return_preserves_interface_result_types", func(t *testing.T) {
		pkgConfined := mustTypecheckPackage(t, "example.com/rangeretok", map[string]string{
			"p.go": `package rangeretok

type item struct {
	p  *int
	cb func()
}

var (
	DirectItems []item
	RangeItems  []item
)

func pickDirect() any {
	s := DirectItems
	if len(s) > 0 {
		return s[0].cb
	}
	return nil
}

func pickRange() any {
	s := RangeItems
	for _, it := range s {
		return it.cb
	}
	return nil
}

func CheckNonNil() bool {
	return pickDirect() != nil && pickRange() != nil
}
`,
			"extra.go": `package rangeretok

type box struct {
	p *int
	n int
}

func BoxStructDirect(bs []box) any {
	if len(bs) > 0 {
		return bs[0].n
	}
	return nil
}

func BoxStructRange(bs []box) any {
	for _, b := range bs {
		return b.n
	}
	return nil
}
`,
		})
		factConfined := FactOf(true, pkgConfined)
		if slices.Contains(factConfined.Escapes, "example.com/rangeretok.DirectItems") {
			t.Fatalf("DirectItems unexpectedly escaped in confined consumer: %v", factConfined.Escapes)
		}
		if slices.Contains(factConfined.Escapes, "example.com/rangeretok.RangeItems") {
			t.Fatalf("RangeItems falsely escaped on return inside range body: %v", factConfined.Escapes)
		}
		directParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/rangeretok", Name: "BoxStructDirect"}, Index: 0}
		rangeParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/rangeretok", Name: "BoxStructRange"}, Index: 0}
		if slices.Contains(factConfined.ParamLeakFree, directParam) != slices.Contains(factConfined.ParamLeakFree, rangeParam) {
			t.Fatalf("ParamLeakFree mismatch between BoxStructDirect and BoxStructRange: %+v", factConfined.ParamLeakFree)
		}
		if slices.Contains(factConfined.ParamLeakFree, rangeParam) {
			t.Fatalf("BoxStructRange unexpectedly admitted into ParamLeakFree: %+v", factConfined.ParamLeakFree)
		}
	})
}

func TestPropertyAnalyzeConeWrapperEquivalenceAndMonotonicity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		pkgs := []string{"example.com/root", "example.com/mid", "example.com/leaf"}
		classes := []PackageClass{
			MutableLocalPackage,
			rapid.SampledFrom([]PackageClass{MutableLocalPackage, PinnedPackage}).Draw(rt, "midClass"),
			rapid.SampledFrom([]PackageClass{MutableLocalPackage, PinnedPackage}).Draw(rt, "leafClass"),
		}
		meta := []GraphPackage{
			{ImportPath: pkgs[0], PkgPath: pkgs[0], Imports: []string{pkgs[1]}, Class: classes[0]},
			{ImportPath: pkgs[1], PkgPath: pkgs[1], Imports: []string{pkgs[2]}, Class: classes[1], Pin: "example.com/mid@v1.0.0"},
			{ImportPath: pkgs[2], PkgPath: pkgs[2], Class: classes[2], Pin: "example.com/leaf@v1.0.0"},
		}

		facts := map[string][]Fact{}
		allVars := make([]string, 0, len(pkgs)*2)
		for pi, pkg := range pkgs {
			v0 := pkg + ".V0"
			v1 := pkg + ".V1"
			allVars = append(allVars, v0, v1)
			f := Fact{Declares: []string{v0, v1}}

			for _, vk := range []string{v0, v1} {
				switch rapid.IntRange(0, 4).Draw(rt, fmt.Sprintf("mark_%d_%s", pi, vk)) {
				case 1:
					f.Mutates = append(f.Mutates, vk)
				case 2:
					f.Escapes = append(f.Escapes, vk)
				case 3:
					f.Opaque = append(f.Opaque, vk)
					f.Escapes = append(f.Escapes, vk)
				case 4:
					fn := syntaxutil.FuncKey{Pkg: pkg, Name: "Make_" + vk[len(pkg)+1:]}
					f.EnvCallUses = append(f.EnvCallUses, syntaxutil.EnvCallUse{Key: vk, Callee: fn})
					if rapid.Bool().Draw(rt, "envFree_"+vk) {
						f.ReturnEnvFree = append(f.ReturnEnvFree, fn)
					}
				}
				switch rapid.IntRange(0, 4).Draw(rt, fmt.Sprintf("dis_%d_%s", pi, vk)) {
				case 1:
					f.MappingDischarges = append(f.MappingDischarges, vk)
				case 2:
					f.MemoDischarges = append(f.MemoDischarges, vk)
				case 3:
					f.SingleSubjectVars = append(f.SingleSubjectVars, vk)
				case 4:
					f.PoolDischarges = append(f.PoolDischarges, vk)
					if rapid.Bool().Draw(rt, "poolMut_"+vk) {
						f.PoolMutates = append(f.PoolMutates, vk)
					}
				}
				if rapid.IntRange(0, 5).Draw(rt, "directWrite_"+vk) == 0 {
					f.DirectVarWrites = append(f.DirectVarWrites, vk)
				}
			}
			if pi+1 < len(pkgs) && rapid.Bool().Draw(rt, fmt.Sprintf("link_%d", pi)) {
				f.CarrierLinks = append(f.CarrierLinks, syntaxutil.CarrierLink{
					From: v0,
					To:   pkgs[pi+1] + ".V0",
				})
			}
			facts[pkg] = []Fact{f}
		}

		singleSubject := rapid.Bool().Draw(rt, "singleSubject")
		packageProcess := !singleSubject && rapid.Bool().Draw(rt, "packageProcess")

		// 1. Wrapper exactness (with Vouches == nil).
		q := ConeQuery{
			Meta:           meta,
			Facts:          facts,
			ViewPackage:    pkgs[0],
			SingleSubject:  singleSubject,
			PackageProcess: packageProcess,
		}
		ac := AnalyzeCone(q)
		wantState := Compose(meta, facts, pkgs[0], nil, singleSubject, packageProcess)
		wantNVD := NonVouchDischargedVars(meta, facts, singleSubject)
		wantEA := ResolveEnvAudit(facts, nil)
		if !reflect.DeepEqual(ac.State, wantState) {
			rt.Fatalf("AnalyzeCone.State != Compose:\ngot:  %+v\nwant: %+v", ac.State, wantState)
		}
		if !reflect.DeepEqual(ac.NonVouchDischarged, wantNVD) {
			rt.Fatalf("AnalyzeCone.NonVouchDischarged != NonVouchDischargedVars:\ngot:  %+v\nwant: %+v", ac.NonVouchDischarged, wantNVD)
		}
		if !reflect.DeepEqual(ac.EnvAudit, wantEA) {
			rt.Fatalf("AnalyzeCone.EnvAudit != ResolveEnvAudit")
		}
		if !singleSubject {
			wantDef := NewDeferralResolution(facts, nil)
			if !reflect.DeepEqual(ac.Deferral, wantDef) {
				rt.Fatalf("AnalyzeCone.Deferral != NewDeferralResolution when SingleSubject==false")
			}
		}

		// 2. Compose <-> NonVouchDischarged lockstep when Vouches == nil:
		// No variable in RootCulprits may appear in NonVouchDischarged!
		culpritSet := map[string]bool{}
		for _, c := range ac.State.RootCulprits {
			culpritSet[c.Key] = true
			if ac.NonVouchDischarged[c.Key] {
				rt.Fatalf("variable %s is both a RootCulprit and in NonVouchDischarged!", c.Key)
			}
		}

		// 3. Meta permutation invariance.
		permMeta := []GraphPackage{meta[2], meta[0], meta[1]}
		permAC := AnalyzeCone(ConeQuery{
			Meta:           permMeta,
			Facts:          facts,
			ViewPackage:    pkgs[0],
			SingleSubject:  singleSubject,
			PackageProcess: packageProcess,
		})
		if !reflect.DeepEqual(permAC.State, ac.State) || !reflect.DeepEqual(permAC.NonVouchDischarged, ac.NonVouchDischarged) {
			rt.Fatalf("AnalyzeCone not invariant to Meta permutation")
		}

		// 4. Execution-model monotonicity: SingleSubject=true can never introduce new culprits
		// or lose NonVouchDischarged entries relative to SingleSubject=false.
		acFalse := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: pkgs[0], SingleSubject: false})
		acTrue := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: pkgs[0], SingleSubject: true})
		falseCulprits := map[string]bool{}
		for _, c := range acFalse.State.RootCulprits {
			falseCulprits[c.Key] = true
		}
		for _, c := range acTrue.State.RootCulprits {
			if !falseCulprits[c.Key] {
				rt.Fatalf("SingleSubject=true introduced culprit %s absent under SingleSubject=false", c.Key)
			}
		}
		for k := range acFalse.NonVouchDischarged {
			if !acTrue.NonVouchDischarged[k] {
				rt.Fatalf("SingleSubject=true lost NonVouchDischarged key %s", k)
			}
		}

		// 5. Variant-intersection monotonicity: adding a second variant Fact for pkgs[1]
		// stripped of discharges can only shrink NonVouchDischarged and grow culprits.
		stripped := facts[pkgs[1]][0]
		stripped.MappingDischarges = nil
		stripped.MemoDischarges = nil
		stripped.SingleSubjectVars = nil
		varFacts := map[string][]Fact{
			pkgs[0]: facts[pkgs[0]],
			pkgs[1]: {facts[pkgs[1]][0], stripped},
			pkgs[2]: facts[pkgs[2]],
		}
		acVar := AnalyzeCone(ConeQuery{Meta: meta, Facts: varFacts, ViewPackage: pkgs[0], SingleSubject: singleSubject})
		if acVar.NonVouchDischarged[pkgs[1]+".V0"] || acVar.NonVouchDischarged[pkgs[1]+".V1"] {
			rt.Fatalf("stripped second variant failed to revoke NonVouchDischarged on %s: %+v", pkgs[1], acVar.NonVouchDischarged)
		}
		for k := range acVar.NonVouchDischarged {
			if !ac.NonVouchDischarged[k] {
				rt.Fatalf("adding stripped variant grew NonVouchDischarged on %s", k)
			}
		}
		varCulprits := map[string]bool{}
		for _, c := range acVar.State.RootCulprits {
			varCulprits[c.Key] = true
		}
		for k := range culpritSet {
			if !varCulprits[k] {
				rt.Fatalf("adding stripped variant dropped culprit %s", k)
			}
		}
		_ = allVars
	})
}

func FuzzAnalyzeConeAllFields(f *testing.F) {
	seedFact := Fact{
		Declares:          []string{"example.com/a.V", "example.com/a.Closed", "example.com/a.Alias", "example.com/a.Desc"},
		Mutates:           []string{"example.com/a.V", "example.com/a.Alias", "example.com/a.Desc"},
		Opaque:            []string{"example.com/a.Closed"},
		Escapes:           []string{"example.com/a.Closed"},
		MemoDischarges:    []string{"example.com/a.V"},
		ReturnEnvFree:     []syntaxutil.FuncKey{{Pkg: "example.com/a", Name: "New"}},
		ParamLeakFree:     []syntaxutil.ParamKey{{Func: syntaxutil.FuncKey{Pkg: "example.com/a", Name: "Read"}, Index: 0}},
		SingleSubjectVars: []string{"example.com/a.V"},
		CarrierLinks:      []syntaxutil.CarrierLink{{From: "example.com/a.V", To: "example.com/b.W"}},
		ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
			Key:               "example.com/a.Alias",
			Target:            "example.com/a.Desc",
			DirectMethodsOnly: true,
		}},
		StaticCompositeGlobals: []syntaxutil.StaticCompositeGlobalFact{{
			Key:        "example.com/a.Desc",
			GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/a", Name: "DescTable"}},
		}},
	}
	rawSeed, err := json.Marshal(map[string][]Fact{
		"example.com/a": {seedFact},
		"example.com/b": {{Declares: []string{"example.com/b.W"}, Escapes: []string{"example.com/b.W"}}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rawSeed, uint8(1))
	f.Add([]byte(`{"example.com/a":[{"declares":["bad"],"carrierLinks":[{"from":"example.com/a.V"}]}]}`), uint8(0))
	f.Add([]byte(`{"pgregory.net/rapid":[{"declares":["pgregory.net/rapid.g"],"harnessDischarges":["pgregory.net/rapid.g"]}]}`), uint8(2))

	f.Fuzz(func(t *testing.T, data []byte, mode uint8) {
		var facts map[string][]Fact
		if err := json.Unmarshal(data, &facts); err != nil || len(facts) == 0 {
			return
		}
		if len(facts) > 8 {
			return
		}
		var pkgs []string
		for k, slice := range facts {
			if len(slice) > 4 {
				facts[k] = slice[:4]
			}
			pkgs = append(pkgs, k)
		}
		slices.Sort(pkgs)
		meta := make([]GraphPackage, 0, len(pkgs))
		for i, pkg := range pkgs {
			var imps []string
			if i+1 < len(pkgs) {
				imps = []string{pkgs[i+1]}
			}
			cls := MutableLocalPackage
			if (i+int(mode))%2 == 1 {
				cls = PinnedPackage
			}
			meta = append(meta, GraphPackage{
				ImportPath: pkg,
				PkgPath:    pkg,
				Imports:    imps,
				Class:      cls,
				Pin:        pkg + "@v1.0.0",
			})
		}
		q := ConeQuery{
			Meta:           meta,
			Facts:          facts,
			ViewPackage:    pkgs[0],
			SingleSubject:  mode&1 != 0,
			PackageProcess: mode&1 == 0 && mode&2 != 0,
		}
		r1 := AnalyzeCone(q)
		r2 := AnalyzeCone(q)
		if !reflect.DeepEqual(r1.State, r2.State) || !reflect.DeepEqual(r1.NonVouchDischarged, r2.NonVouchDischarged) {
			t.Fatalf("non-deterministic AnalyzeCone output")
		}
		for _, c := range r1.State.RootCulprits {
			if r1.NonVouchDischarged[c.Key] {
				t.Fatalf("RootCulprit %s present in NonVouchDischarged", c.Key)
			}
		}
	})
}
