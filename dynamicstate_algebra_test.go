package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The culprit walk both reachability scopings share records exactly the
// discharged prefix: every culprit before the first survivor, in the
// evidence's sorted form, and none after it — the survivor names the
// downgrade. Seven carriers in key order: five discharged, the sixth
// mutated in the subject's own rooted flow, the seventh dischargeable
// but past the survivor (REQ-closure-shared-dynamic-state-reachability,
// REQ-vouch-recorded).
func TestCulpritDischargeRecordsTheSortedPrefix(t *testing.T) {
	const decls = "var a = map[string]func(){}\nvar b = map[string]func(){}\nvar c = map[string]func(){}\nvar d = map[string]func(){}\nvar e = map[string]func(){}\nvar f = map[string]func(){}\nvar g = map[string]func(){}\n\nfunc mutA() { a[\"k\"] = nil }\nfunc mutB() { b[\"k\"] = nil }\nfunc mutC() { c[\"k\"] = nil }\nfunc mutD() { d[\"k\"] = nil }\nfunc mutE() { e[\"k\"] = nil }\nfunc mutF() { f[\"k\"] = nil }\nfunc mutG() { g[\"k\"] = nil }\n\n"
	const prefix = "example.com/view.a,example.com/view.b,example.com/view.c,example.com/view.d,example.com/view.e"
	t.Run("attested per-subject scoping", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\n"+decls+"func F() int {\n\tmutF()\n\treturn len(a) + len(b) + len(c) + len(d) + len(e) + len(f) + len(g)\n}\n")
		fingerprint, verdict := captureFingerprint(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.f is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming f — the rooted mutator", verdict)
		}
		if fingerprint.SingleSubjectDischarges != prefix {
			t.Fatalf("evidence = %q, want the sorted discharged prefix %q", fingerprint.SingleSubjectDischarges, prefix)
		}
	})
	t.Run("package-process scoping", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/view\n\ngo 1.26\n",
			"view.go":      "package view\n\n" + decls + "func F() int { return len(a) + len(b) + len(c) + len(d) + len(e) + len(f) + len(g) }\n",
			"view_test.go": "package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tmutF()\n\tif F() < 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		}
		dir := writeModuleTree(t, files)
		fingerprint, verdict := captureFingerprint(t, dir, Subject{Package: "example.com/view", Symbol: "TestF"}, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.f is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming f — the harness-rooted mutator", verdict)
		}
		if fingerprint.PackageProcessDischarges != prefix {
			t.Fatalf("evidence = %q, want the sorted discharged prefix %q", fingerprint.PackageProcessDischarges, prefix)
		}
	})
}

// captureFingerprint captures and checks one subject, returning the
// fingerprint beside the verdict for evidence assertions.
func captureFingerprint(t *testing.T, dir string, subject Subject, opts ...option) (Fingerprint, Verdict) {
	t.Helper()
	return captureCheckFP(t, dir, subject, opts...)
}

// A fact survives serialization with its mutation, declaration, and
// method-directive content intact, and the promoted-method lookup resolves
// directives from the deserialized fact (REQ-closure-dynamic-state-memo,
// REQ-purity-directive, REQ-external-directive).
func TestDynamicStateFactRoundTripCarriesMutationsAndMethodDirectives(t *testing.T) {
	pkgs := parseAndTypecheckDAG(t, "", map[string]map[string]string{
		"example.com/factsrc": {
			"lib.go": `package factsrc

import (
	"errors"
	"sync"
)

var pool sync.Pool

func Recycle() {
	v := pool.Get()
	pool.Put(v)
}

var Hook func()

var ErrSentinel = errors.New("sentinel")

var Hooks = map[string]func(){}

var Bound []func() int

func seed() {
	c := new(int)
	Bound = []func() int{func() int { (*c)++; return *c }}
}

var _ = boot()

func boot() bool {
	seed()
	return true
}

func take(map[string]func()) {}

func Escape() { take(Hooks) }

func Pass() map[string]func() { return Hooks }

func Rebind() { Hook = nil }

type Widget int

//gofresh:pure
func (Widget) Pure() int { return 1 }

//gofresh:external
func (Widget) External() int { return 2 }
`,
		},
	})
	var plain *types.Package
	var fact dynamicStateFact
	for _, p := range pkgs {
		if p.PkgPath == "example.com/factsrc" && p.ForTest == "" {
			fact = dynamicStateFactOf(true, p, false)
			plain = p.Types
		}
	}
	if plain == nil {
		t.Fatal("fixture package not loaded")
	}
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	var restored dynamicStateFact
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fact, restored) {
		t.Fatalf("fact did not round-trip:\n before %+v\n after  %+v", fact, restored)
	}
	wantKey := "example.com/factsrc.Hook"
	if !contains(restored.Declares, wantKey) {
		t.Fatalf("fact lost declaration content: %+v", restored)
	}
	if !slices.Contains(restored.AttributedUses, syntaxutil.AttributedUse{Func: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "Rebind"}, Key: "example.com/factsrc.Hook"}) {
		t.Fatalf("fact lost the attributed mutation - a dropped attribution silently discharges a runtime rebind: %+v", restored)
	}
	if !slices.Contains(restored.FuncRefs, syntaxutil.FuncRef{Callee: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "take"}, Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionFunc, Caller: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "Escape"}}}) {
		t.Fatalf("fact lost the reference-region edge - a dropped edge starves the fixed point: %+v", restored.FuncRefs)
	}
	if !slices.Contains(restored.AttributedUses, syntaxutil.AttributedUse{Func: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "Pass"}, Key: "example.com/factsrc.Hooks", Escape: true}) {
		t.Fatalf("fact lost the attributed escape - a dropped attribution silently closes an open package: %+v", restored)
	}
	if !slices.Contains(restored.ParamUses, syntaxutil.VarParamUse{Key: "example.com/factsrc.Hooks", Param: syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "take"}, Index: 0}}) {
		t.Fatalf("fact lost the deferred call-argument mark - a dropped deferral silently closes an open package: %+v", restored.ParamUses)
	}
	if !slices.Contains(restored.ParamLeakFree, syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/factsrc", Name: "take"}, Index: 0}) {
		t.Fatalf("fact lost the leak-free parameter proof - a dropped proof refuses every deferred argument: %+v", restored.ParamLeakFree)
	}
	if !contains(restored.Opaque, "example.com/factsrc.ErrSentinel") {
		t.Fatalf("fact lost opacity content: %+v", restored)
	}
	if !contains(restored.EnvCarrying, "example.com/factsrc.Bound") {
		t.Fatalf("fact lost the environment-audit mark - a dropped mark keeps a capturing registration settled: %+v", restored.EnvCarrying)
	}
	if restored.PureMethods["Widget.Pure"] == "" || restored.ExternalMethods["Widget.External"] == "" {
		t.Fatalf("fact lost method directives: %+v", restored)
	}

	state := &viewDynamicState{cones: map[string]map[string][]dynamicStateFact{"example.com/factsrc": {"example.com/factsrc": {restored}}}}
	widget, ok := plain.Scope().Lookup("Widget").(*types.TypeName)
	if !ok {
		t.Fatal("Widget type missing")
	}
	methods := types.NewMethodSet(widget.Type())
	var pureKey, externalKey string
	for i := 0; i < methods.Len(); i++ {
		method := methods.At(i).Obj().(*types.Func)
		p, x := state.methodDirectives("example.com/factsrc", method)
		if method.Name() == "Pure" {
			pureKey = p
		}
		if method.Name() == "External" {
			externalKey = x
		}
	}
	if pureKey == "" || externalKey == "" {
		t.Fatalf("promoted-method directive lookup failed: pure=%q external=%q", pureKey, externalKey)
	}

	// The pooling-discharge audit record: absent from an unattested
	// fact, present in an attested one, and surviving serialization —
	// a dropped record silently hides the load-bearing attestation
	// (REQ-vouch-recorded, REQ-closure-shared-dynamic-state).
	if len(restored.PoolDischarges) != 0 {
		t.Fatalf("unattested fact carries pool discharges: %+v", restored.PoolDischarges)
	}
	var attested dynamicStateFact
	for _, p := range pkgs {
		if p.PkgPath == "example.com/factsrc" && p.ForTest == "" {
			attested = dynamicStateFactOf(true, p, true)
		}
	}
	rawAttested, err := json.Marshal(attested)
	if err != nil {
		t.Fatal(err)
	}
	var restoredAttested dynamicStateFact
	if err := json.Unmarshal(rawAttested, &restoredAttested); err != nil {
		t.Fatal(err)
	}
	if !contains(restoredAttested.PoolDischarges, "example.com/factsrc.pool") {
		t.Fatalf("attested fact lost the pooling-discharge record: %+v", restoredAttested.PoolDischarges)
	}
}

// A malformed insertion claim marks its fact instead of resolving: a
// two-segment ParamInsertionFree key (a function key misfiled as a
// parameter key) must not enter the declared set, where the cross-kind
// union would let it discharge a return-proof edge it never proved
// (the chunk-83 review's M2).
func TestResolveEnvAuditRefusesMisfiledInsertionKeys(t *testing.T) {
	fnKey := syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "Make"}
	badParam := syntaxutil.ParamKey{Func: fnKey, Index: -1}
	misfiled := dynamicStateFact{
		ParamInsertionFree: []syntaxutil.ParamKey{badParam},
	}
	marked := 0
	e := resolveEnvAudit(map[string][]dynamicStateFact{"example.com/dep": {misfiled}}, func(dynamicStateFact) { marked++ })
	if marked == 0 {
		t.Fatal("misfiled insertion key did not mark the fact malformed")
	}
	if e.InsDeclared[badParam] || e.InsResolved[badParam] {
		t.Fatal("misfiled insertion key entered the declared set")
	}
	if e.DepResolved(syntaxutil.FuncAuditTarget(fnKey)) {
		t.Fatal("misfiled key discharges a return-proof dependency")
	}
}

// dischargeCut classifies a reachability analysis's failure by the two
// contexts: an operation cancelled during the analysis propagates its
// own cancellation TYPED as the context's — even when the budget's
// deadline had already fired and the analysis error wraps it — a budget
// cut returns the downgraded set, and any other failure is the
// operation's error (REQ-fresh-context).
func TestDischargeCutClassifiesByTheTwoContexts(t *testing.T) {
	downgraded := []Subject{{Package: "example.com/p", Symbol: "F"}}
	expired, cancelExpired := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelExpired()
	<-expired.Done()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	analysisErr := fmt.Errorf("closure: analysis cancelled: %w", context.DeadlineExceeded)
	if cut, err := dischargeCut(cancelled, expired, downgraded, analysisErr); cut != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("operation cancelled after the budget fired: cut=%v err=%v, want the operation's cancellation typed Canceled", cut, err)
	}
	if cut, err := dischargeCut(context.Background(), expired, downgraded, analysisErr); err != nil || !cut[downgraded[0]] || len(cut) != 1 {
		t.Fatalf("budget cut: cut=%v err=%v, want the downgraded set", cut, err)
	}
	other := errors.New("closure: load failed")
	if cut, err := dischargeCut(context.Background(), context.Background(), downgraded, other); cut != nil || err != other {
		t.Fatalf("other failure: cut=%v err=%v, want the error itself", cut, err)
	}
}

func FuzzSharedDynamicStateInvariants(f *testing.F) {
	f.Add("V", "M", "H", true, false, false, uint8(0))
	f.Add("Cache", "Read", "InitHelper", false, true, true, uint8(1))
	f.Add("State", "Write", "Setup", true, true, false, uint8(2))
	f.Add("Reg", "Lookup", "Build", false, false, false, uint8(3))
	f.Add("Tbl", "Inspect", "Populate", true, true, true, uint8(4))

	f.Fuzz(func(t *testing.T, rawVar, rawMethod, rawHelper string, hasProof, singleSubject, packageProcess bool, mode uint8) {
		sanitizeIdent := func(s, fallback string) string {
			out := strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
					return r
				}
				return -1
			}, s)
			if out == "" {
				return fallback
			}
			if len(out) > 16 {
				out = out[:16]
			}
			return strings.ToUpper(out[:1]) + out[1:]
		}
		varName := sanitizeIdent(rawVar, "V")
		methodName := sanitizeIdent(rawMethod, "M")
		helperName := sanitizeIdent(rawHelper, "H")
		if methodName == varName {
			methodName += "Method"
		}
		if helperName == varName || helperName == methodName {
			helperName += "Helper"
		}

		// 1. In-memory AST/types fact derivation: carrier-free vs dynamic-capable types,
		// atomic.Pointer[T] transparency, mutex-bracketed atomic.Pointer hook store,
		// audited sync.Mutex/sync.Once discharges, opaque sentinel construction,
		// SingleSubjectVars directive, and PoolDischarges under singleSubject
		// (REQ-closure-shared-dynamic-state, REQ-closure-shared-dynamic-state-carrier-free,
		// REQ-closure-shared-dynamic-state-atomic, REQ-closure-shared-dynamic-state-mutation-shape,
		// REQ-closure-shared-dynamic-state-audited-discharges,
		// REQ-closure-shared-dynamic-state-escape-narrowings,
		// REQ-closure-shared-dynamic-state-directive, REQ-closure-shared-dynamic-state-pool).
		src := fmt.Sprintf(`package p
import (
	"errors"
	"sync"
	"sync/atomic"
)

var ScalarInt = 42
var AtomicInt atomic.Pointer[int]
var PoolVar sync.Pool
var ErrSentinel = errors.New("sentinel")

type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookOnce sync.Once
	hookPtr atomic.Pointer[hookSet]
)

//gofresh:single-subject
var %s []func()

func UsePoolAndHooks() {
	x := PoolVar.Get()
	PoolVar.Put(x)
	hookOnce.Do(func() {})
	hookMu.Lock()
	defer hookMu.Unlock()
	defer hookPtr.Store(nil)
	hookPtr.Store(&hookSet{onEvent: func() {}})
	if h := hookPtr.Load(); h != nil && h.onEvent != nil {
		h.onEvent()
	}
}
`, varName)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		info := &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		typesPkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/p", fset, []*ast.File{file}, info)
		if err != nil {
			t.Fatalf("typecheck: %v", err)
		}
		pkg := &packages.Package{
			ID:        "example.com/p",
			Name:      "p",
			PkgPath:   "example.com/p",
			Fset:      fset,
			Syntax:    []*ast.File{file},
			Types:     typesPkg,
			TypesInfo: info,
			Module:    &packages.Module{Path: "example.com/p"},
		}
		derived := dynamicStateFactOf(true, pkg, singleSubject)
		varKey := "example.com/p." + varName
		scalarKey := "example.com/p.ScalarInt"
		atomicIntKey := "example.com/p.AtomicInt"
		hookPtrKey := "example.com/p.hookPtr"
		sentinelKey := "example.com/p.ErrSentinel"
		poolKey := "example.com/p.PoolVar"
		for _, d := range derived.Declares {
			if d == scalarKey || d == atomicIntKey {
				t.Fatalf("carrier-free variable %s declared as dynamic-capable", d)
			}
		}
		if !slices.Contains(derived.Declares, hookPtrKey) {
			t.Fatalf("expected dynamic-capable atomic.Pointer %s in Declares, got %v", hookPtrKey, derived.Declares)
		}
		if len(derived.Mutates) != 0 || len(derived.Escapes) != 0 || len(derived.EnvCarrying) != 0 {
			t.Fatalf("mutex-bracketed hookPtr or sync.Once/Mutex marked dynamic state: %+v", derived)
		}
		for _, u := range derived.AttributedUses {
			if u.Key == hookPtrKey {
				t.Fatalf("mutex-bracketed hookPtr recorded in AttributedUses: %+v", u)
			}
		}
		if !slices.Contains(derived.Opaque, sentinelKey) {
			t.Fatalf("expected %s in Opaque, got %v", sentinelKey, derived.Opaque)
		}
		if !slices.Contains(derived.SingleSubjectVars, varKey) {
			t.Fatalf("expected %s in SingleSubjectVars, got %v", varKey, derived.SingleSubjectVars)
		}
		if singleSubject {
			if len(derived.PoolDischarges) != 1 || derived.PoolDischarges[0] != poolKey || len(derived.AttributedUses) != 0 {
				t.Fatalf("expected PoolDischarges=[%s] and empty AttributedUses when singleSubject=true, got PoolDischarges=%v AttributedUses=%v", poolKey, derived.PoolDischarges, derived.AttributedUses)
			}
		} else {
			if len(derived.PoolDischarges) != 0 || len(derived.AttributedUses) == 0 {
				t.Fatalf("expected no PoolDischarges and PoolVar AttributedUses when singleSubject=false, got PoolDischarges=%v AttributedUses=%v", derived.PoolDischarges, derived.AttributedUses)
			}
		}

		// 2. Composition invariants across deferred proofs, init-flow aliasing, opacity breaks,
		// value-plane population joins, audited mapping/memoization pins, generated proto/gRPC
		// two-leg discharges, and reachability culprit sites
		// (REQ-closure-shared-dynamic-state-init-flow, REQ-closure-shared-dynamic-state-receiver-proof,
		// REQ-closure-shared-dynamic-state-parameter-facts, REQ-closure-shared-dynamic-state-registration-audit,
		// REQ-closure-shared-dynamic-state-leak-free, REQ-closure-shared-dynamic-state-init-aliasing,
		// REQ-closure-shared-dynamic-state-mapping, REQ-closure-shared-dynamic-state-memo,
		// REQ-closure-shared-dynamic-state-proto, REQ-closure-shared-dynamic-state-reachability).
		meta := []closure.GraphPackage{
			{
				ImportPath: "example.com/p",
				PkgPath:    "example.com/p",
				Class:      closure.MutableLocalPackage,
				Imports:    []string{"example.com/dep", "golang.org/x/sys/unix", "gopkg.in/yaml.v3", "google.golang.org/protobuf/runtime/protoimpl", "google.golang.org/grpc"},
			},
			{
				ImportPath: "example.com/dep",
				PkgPath:    "example.com/dep",
				Class:      closure.PinnedPackage,
				Pin:        "example.com/dep@v1.0.0",
			},
			{
				ImportPath: "golang.org/x/sys/unix",
				PkgPath:    "golang.org/x/sys/unix",
				Class:      closure.PinnedPackage,
				Pin:        "golang.org/x/sys@v0.48.0",
			},
			{
				ImportPath: "gopkg.in/yaml.v3",
				PkgPath:    "gopkg.in/yaml.v3",
				Class:      closure.PinnedPackage,
				Pin:        "gopkg.in/yaml.v3@v3.0.1",
			},
			{
				ImportPath: "google.golang.org/protobuf/runtime/protoimpl",
				PkgPath:    "google.golang.org/protobuf/runtime/protoimpl",
				Class:      closure.PinnedPackage,
				Pin:        "google.golang.org/protobuf@v1.36.11",
			},
			{
				ImportPath: "google.golang.org/grpc",
				PkgPath:    "google.golang.org/grpc",
				Class:      closure.PinnedPackage,
				Pin:        "google.golang.org/grpc@v1.82.1",
			},
		}

		depVar := "example.com/dep." + varName
		aliasVar := "example.com/dep.Alias" + varName
		opaqueVar := "example.com/dep.Opaque" + varName
		protoVar := "example.com/p.File_p_proto"
		grpcVar := "example.com/p.Service_Desc"
		methodKey := syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "T." + methodName}
		paramKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/dep", Name: helperName}, Index: 0}
		paramDepKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/dep", Name: helperName + "Leaf"}, Index: 0}
		ctorKey := syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "Make" + helperName}
		ctorDepKey := syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "MakeLeaf" + helperName}

		var depFact dynamicStateFact
		depFact.Declares = []string{depVar, aliasVar, opaqueVar}
		depFact.Opaque = []string{opaqueVar}
		depFact.Escapes = []string{opaqueVar}
		depFact.CarrierLinks = []syntaxutil.CarrierLink{{From: depVar, To: aliasVar}}

		switch mode % 5 {
		case 0:
			// Deferred method use vs ReceiverReadOnly proof (REQ-closure-shared-dynamic-state-receiver-proof).
			depFact.MethodUses = []syntaxutil.VarMethodUse{{Key: depVar, Method: methodKey}}
			if hasProof {
				depFact.ReceiverReadOnly = []syntaxutil.FuncKey{methodKey}
			}
		case 1:
			// Deferred call-argument use + conditional ParamLeakFreeDeps fixed point
			// (REQ-closure-shared-dynamic-state-parameter-facts).
			depFact.ParamUses = []syntaxutil.VarParamUse{{Key: depVar, Param: paramKey}}
			depFact.ParamLeakFreeDeps = []syntaxutil.ParamDepEdge{{Own: paramKey, Dep: paramDepKey}}
			if hasProof {
				depFact.ParamLeakFree = []syntaxutil.ParamKey{paramDepKey}
			}
		case 2:
			// Deferred constructor registration + ReturnEnvDeps & ReturnEnvInsertionDeps fixed point
			// (REQ-closure-shared-dynamic-state-registration-audit, REQ-closure-shared-dynamic-state-parameter-facts).
			depFact.EnvCallUses = []syntaxutil.EnvCallUse{{Key: depVar, Callee: ctorKey}}
			depFact.ReturnEnvFree = []syntaxutil.FuncKey{ctorKey}
			depFact.ReturnEnvDeps = []syntaxutil.FuncDepEdge{{Func: ctorKey, Callee: ctorDepKey}}
			depFact.ReturnEnvInsertionDeps = []syntaxutil.FuncInsertionDepEdge{{Func: ctorKey, Dep: syntaxutil.ParamAuditTarget(paramDepKey)}}
			if hasProof {
				depFact.ReturnEnvFree = []syntaxutil.FuncKey{ctorKey, ctorDepKey}
				depFact.ParamInsertionFree = []syntaxutil.ParamKey{paramDepKey}
			}
		case 3:
			// Init-flow method use vs ReceiverRetentionFree proof (ReceiverReadOnly does NOT substitute;
			// REQ-closure-shared-dynamic-state-init-flow, REQ-closure-shared-dynamic-state-receiver-proof).
			depFact.InitMethodUses = []syntaxutil.VarMethodUse{{Key: depVar, Method: methodKey}}
			if hasProof {
				depFact.ReceiverRetentionFree = []syntaxutil.FuncKey{methodKey}
			} else {
				depFact.ReceiverReadOnly = []syntaxutil.FuncKey{methodKey}
			}
		default:
			// Value-plane field-position argument deferral vs registered population proof
			// (REQ-closure-shared-dynamic-state-leak-free).
			posKey := syntaxutil.FieldPosKey{Owner: depVar, Field: "Fn", Index: 0}
			depFact.FieldParamUses = []syntaxutil.FieldPosKey{posKey}
			depFact.FieldParamDefer = []syntaxutil.FieldParamDefer{{Pos: posKey, Param: paramKey}}
			if hasProof {
				depFact.ParamLeakFree = []syntaxutil.ParamKey{paramKey}
			}
		}

		protoInitFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "file_p_proto_init"}
		builderType := syntaxutil.TypeRef{Pkg: "google.golang.org/protobuf/runtime/protoimpl", Name: "TypeBuilder"}
		msgInfoType := syntaxutil.TypeRef{Pkg: "google.golang.org/protobuf/runtime/protoimpl", Name: "MessageInfo"}
		svcDescType := syntaxutil.TypeRef{Pkg: "google.golang.org/grpc", Name: "ServiceDesc"}

		allFacts := map[string][]dynamicStateFact{
			"example.com/p": {
				{
					Declares:          []string{varKey, protoVar, grpcVar},
					SingleSubjectVars: []string{varKey},
					ProtoClusters: []protoaudit.ProtoClusterFact{{
						InitFn:      protoInitFn,
						Vars:        []string{protoVar},
						BuilderType: builderType,
						MsgType:     msgInfoType,
					}},
					GrpcServiceVars: []protoaudit.GrpcServiceVarFact{{
						Key:     grpcVar,
						SvcDesc: svcDescType,
					}},
					FuncRefs: []syntaxutil.FuncRef{{
						Callee: protoInitFn,
						Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit},
					}},
					Mutates: []string{varKey, protoVar, grpcVar},
				},
			},
			"example.com/dep": {depFact},
			"golang.org/x/sys/unix": {{
				Declares:          []string{"golang.org/x/sys/unix.mapper"},
				MappingDischarges: []string{"golang.org/x/sys/unix.mapper"},
				Mutates:           []string{"golang.org/x/sys/unix.mapper"},
			}},
			"gopkg.in/yaml.v3": {{
				Declares:       []string{"gopkg.in/yaml.v3.structMap"},
				MemoDischarges: []string{"gopkg.in/yaml.v3.structMap"},
				Mutates:        []string{"gopkg.in/yaml.v3.structMap"},
			}},
			"google.golang.org/protobuf/runtime/protoimpl": {{
				ProtoRuntimeTypes: []protoaudit.ProtoRuntimeTypeFact{
					{Type: builderType, Role: protoaudit.ProtoRoleBuilder},
					{Type: msgInfoType, Role: protoaudit.ProtoRoleMessage},
				},
			}},
			"google.golang.org/grpc": {{}},
		}

		// When singleSubject=true, varKey (SingleSubjectVars), protoVar (ProtoClusters +
		// ProtoRuntimeTypes), and grpcVar (GrpcServiceVars) in example.com/p are discharged,
		// and unix.mapper / yaml.structMap are discharged by structural MappingDischarges /
		// MemoDischarges; depVar depends on hasProof.
		cone := composeDynamicState(meta, allFacts, "example.com/p", nil, singleSubject, packageProcess)
		if !singleSubject {
			if cone.downgraded == "" {
				t.Fatal("expected downgrade when singleSubject=false and varKey is mutated without attestation")
			}
			if packageProcess && !strings.Contains(cone.downgraded, "backed by no single-subject attestation") {
				t.Fatalf("expected packageProcess unbacked-directive channel in %q", cone.downgraded)
			}
			if !packageProcess && !strings.Contains(cone.downgraded, "//gofresh:single-subject directive on the declaration") {
				t.Fatalf("expected standard directive channel in %q", cone.downgraded)
			}
		} else {
			if hasProof && cone.downgraded != "" {
				t.Fatalf("expected clean composition when proof holds and singleSubject=true, got downgrade=%q", cone.downgraded)
			}
			if !hasProof && cone.downgraded == "" {
				t.Fatalf("expected downgrade when proof is absent (mode=%d)", mode%5)
			}
			// Breaking opacity on opaqueVar causes its escape to downgrade even when hasProof=true.
			if hasProof {
				brokenFact := depFact
				brokenFact.OpacityBreaks = []string{opaqueVar}
				allFacts["example.com/dep"] = []dynamicStateFact{brokenFact}
				brokenCone := composeDynamicState(meta, allFacts, "example.com/p", nil, true, packageProcess)
				if !strings.Contains(brokenCone.downgraded, opaqueVar+" escapes writable") {
					t.Fatalf("expected opacity break on %s to surface escape culprit, got %q", opaqueVar, brokenCone.downgraded)
				}
			}
		}

		// Carrier link propagation: if depVar marks mutated/escaped/envCarrying, aliasVar shares the mark.
		links := carrierLinkGraph(allFacts, func(dynamicStateFact) {})
		if !links[depVar][aliasVar] || !links[aliasVar][depVar] {
			t.Fatalf("carrierLinkGraph did not record symmetric link between %s and %s", depVar, aliasVar)
		}

		// Reachability dischargeCulprits stops at the first culprit whose site is reached or unattributed.
		vds := &viewDynamicState{
			rootCulprits: map[string][]dynCulprit{
				"example.com/p": {{pkgPath: "example.com/dep", key: depVar}},
			},
			culpritSites: map[string]map[string]culpritSiteSet{
				"example.com/p": {
					depVar: {fns: map[string]bool{"example.com/p.Caller": true}},
				},
			},
		}
		surv, _, dis := dischargeCulprits(closure.RootedFunctions{Complete: true, Fns: map[string]bool{}}, vds, "example.com/p")
		if surv != "" || !dis[depVar] {
			t.Fatalf("unreachable culprit was not discharged: surv=%q dis=%v", surv, dis)
		}
		survReached, _, _ := dischargeCulprits(closure.RootedFunctions{Complete: true, Fns: map[string]bool{"example.com/p.Caller": true}}, vds, "example.com/p")
		if survReached == "" {
			t.Fatal("reachable culprit was erroneously discharged")
		}
	})
}

// The chain's link order is the derivation's own: the registration
// store first, then each unresolved dependency edge in walk order, then
// the innermost refusing expression — a permutation is a different
// derivation and must not pass (REQ-explain-chain's "names, in order").
func TestExplainChainLinkOrder(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc inner() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nfunc gen() map[string]handler {\n\treturn inner()\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm != "environment-audit" {
		t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
	}
	// Derivation order: the edge into gen precedes the edge into inner
	// (walk depth), and every edge precedes every refusal.
	genEdgeAt, innerEdgeAt, firstRefusalAt := -1, -1, -1
	lastEdgeAt := -1
	for i, l := range chain.Links {
		switch l.Kind {
		case "edge":
			lastEdgeAt = i
			if strings.HasSuffix(l.Callee, ".gen") && genEdgeAt == -1 {
				genEdgeAt = i
			}
			if strings.HasSuffix(l.Callee, ".inner") && innerEdgeAt == -1 {
				innerEdgeAt = i
			}
		case "refusal":
			if firstRefusalAt == -1 {
				firstRefusalAt = i
			}
		}
	}
	if genEdgeAt == -1 || innerEdgeAt == -1 || firstRefusalAt == -1 {
		t.Fatalf("chain lacks the expected links: %+v", chain)
	}
	if !(genEdgeAt < innerEdgeAt && lastEdgeAt < firstRefusalAt) {
		t.Fatalf("links out of derivation order (gen=%d inner=%d lastEdge=%d refusal=%d): %+v",
			genEdgeAt, innerEdgeAt, lastEdgeAt, firstRefusalAt, chain)
	}
}

// When a store link exists (a direct registration-literal store), it
// leads the chain: the registration store site is named first
// (REQ-explain-chain's "names, in order, the registration store site").
func TestExplainChainStoreLinkLeads(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": `package reg

type counter struct{ n int }

func (c *counter) Next(n int) int {
	c.n += n
	return c.n
}

type handler func(n int) int

var shared = &counter{}

var Registry = map[string]handler{"k": shared.Next}

func Count() int { return len(Registry) }
`,
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if len(chain.Links) == 0 || chain.Links[0].Kind != "store" {
		t.Fatalf("store link does not lead the chain: %+v", chain)
	}
}

// A refusal that is the fixed point of a dependency cycle has no single
// refusing expression: the chain ends at the edges — no refusal link,
// the deepest link an edge (REQ-explain-chain's edge termination).
func TestExplainChainCycleEndsAtEdges(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc gen(depth int) []handler {\n\tif depth > 0 {\n\t\treturn more(depth - 1)\n\t}\n\treturn nil\n}\n\nfunc more(depth int) []handler {\n\treturn gen(depth)\n}\n\nvar Registry = gen(3)\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm == "" {
		t.Fatal("cycle fixture did not refuse (chain empty) - the registration proved; the cycle clause's only pin is dead, strengthen the fixture")
	}
	for _, l := range chain.Links {
		if l.Kind == "refusal" {
			t.Fatalf("a cycle fixed point produced a refusal link: %+v", chain)
		}
	}
	if len(chain.Links) == 0 || chain.Links[len(chain.Links)-1].Kind != "edge" {
		t.Fatalf("cycle chain does not end at the edges: %+v", chain)
	}
}

// A refusing function whose package is outside the loaded scope has no
// derivable refusing expression: the walk terminates at the edge with
// no refusal site (REQ-explain-chain's edge termination, outside-scope
// shape). The contrast arm pins that the termination comes from the
// scope boundary, not from a walk defect: the same dependency shape
// with the package loaded names its refusal site. Unit-level because
// the shape is not fixturable hermetically - a replaced dependency
// loads with syntax and a parse-broken dependency refuses the whole
// view (see TestExplainChainReplacedDepIsInScope).
func TestExplainEnvAuditOutsideScopeEndsAtEdges(t *testing.T) {
	const culprit = "example.com/reg.Registry"
	facts := map[string][]dynamicStateFact{
		"example.com/reg": {{
			EnvCarrying: []string{culprit},
			EnvCallUses: []syntaxutil.EnvCallUse{{Key: culprit, Callee: syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "Make"}}},
		}},
	}
	edges, refusedFn, refusedPath := envAuditTrail(map[string][]*packages.Package{}, facts, map[string]bool{culprit: true}, "Registry")
	if len(edges) == 0 {
		t.Fatalf("outside-scope callee produced no edge: %+v", edges)
	}
	if refusedFn != "" || refusedPath != "" {
		t.Fatalf("outside-scope callee produced a refusal site: %q in %q", refusedFn, refusedPath)
	}
	edges, refusedFn, refusedPath = envAuditTrail(map[string][]*packages.Package{"example.com/dep": {{}}}, facts, map[string]bool{culprit: true}, "Registry")
	if len(edges) == 0 || refusedFn != "Make" || refusedPath != "example.com/dep" {
		t.Fatalf("in-scope contrast arm did not name the refusal site: edges=%+v fn=%q path=%q", edges, refusedFn, refusedPath)
	}
}

// An insertion condition renders with its parameter context and walks
// to the refusing site - never a raw NUL, never a spurious edge for a
// resolved condition, and an unresolved insertion claim's own edges
// chain onward (REQ-explain-chain; the chunk-83 review's M1).
func TestExplainEnvAuditInsertionChain(t *testing.T) {
	const culprit = "example.com/reg.Registry"
	genFn := syntaxutil.FuncKey{Pkg: "example.com/reg", Name: "Gen"}
	sinkParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "Sink"}, Index: 0}
	fillParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/dep", Name: "Fill"}, Index: 1}
	facts := map[string][]dynamicStateFact{
		"example.com/reg": {{
			EnvCarrying:   []string{culprit},
			EnvCallUses:   []syntaxutil.EnvCallUse{{Key: culprit, Callee: genFn}},
			ReturnEnvFree: []syntaxutil.FuncKey{genFn},
			ReturnEnvInsertionDeps: []syntaxutil.FuncInsertionDepEdge{
				{Func: genFn, Dep: syntaxutil.ParamAuditTarget(sinkParam)},
				{Func: genFn, Dep: syntaxutil.ParamAuditTarget(fillParam)},
			},
		}},
		"example.com/dep": {{
			// Fill's parameter resolves; Sink's is undeclared - only
			// Sink may contribute an edge and the refusal site.
			ParamInsertionFree: []syntaxutil.ParamKey{fillParam},
		}},
	}
	edges, refusedFn, refusedPath := envAuditTrail(map[string][]*packages.Package{"example.com/dep": {{}}}, facts, map[string]bool{culprit: true}, "Registry")
	if refusedFn != "Sink" || refusedPath != "example.com/dep" {
		t.Fatalf("refusal site = %q in %q, want Sink in example.com/dep", refusedFn, refusedPath)
	}
	sawInsertionEdge := false
	for _, e := range edges {
		if strings.ContainsRune(e.Symbol+e.Callee+e.Package, 0) {
			t.Fatalf("chain link carries a raw NUL: %+v", e)
		}
		if strings.Contains(e.Callee, "Fill") {
			t.Fatalf("resolved insertion condition contributed a spurious edge: %+v", e)
		}
		if e.Callee == "example.com/dep.Sink (parameter 0)" {
			sawInsertionEdge = true
		}
	}
	if !sawInsertionEdge {
		t.Fatalf("no edge renders the insertion condition with its parameter context: %+v", edges)
	}
}

// The deferral arm's bound is real: a culprit with more deferral
// observations than the link cap truncates with the omission counted
// and the deepest deciding site kept (REQ-explain-bounded's deferral
// arm).
func TestExplainDeferralChainBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar sink []entry\n\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "func grab%d(es []entry) int {\n\tsink = es\n\treturn len(es)\n}\n\n", i)
	}
	b.WriteString("func Count() int {\n\tn := 0\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "\tn += grab%d(Registry)\n", i)
	}
	b.WriteString("\treturn n\n}\n")
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": b.String(),
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm == "" || len(chain.Links) == 0 {
		t.Fatalf("deferral fixture produced no chain: %+v", chain)
	}
	if len(chain.Links) > chainLinkCap {
		t.Fatalf("chain exceeds the link cap: %d > %d", len(chain.Links), chainLinkCap)
	}
	if chain.Omitted == 0 {
		t.Fatalf("30 deferral observations did not trip the bound: links=%d omitted=%d", len(chain.Links), chain.Omitted)
	}
	// The deepest deciding site survives the bound: naive tail
	// truncation would end at an interior grab; the protected last link
	// is the final deferral site (REQ-explain-bounded's deepest-kept).
	if last := chain.Links[len(chain.Links)-1]; !strings.Contains(last.Callee, "grab29") {
		t.Fatalf("deepest deciding site did not survive the bound: %+v", last)
	}
}

// The signature-dynamism refusal names the term conferring openness —
// the first type parameter, receiver, or parameter whose type carries
// dynamic reach — and its channel, so the operator bounds exactly that
// type; the term is the persisted open-world fact itself
// (REQ-closure-refusal-channels).
func TestOpenWorldRefusalNamesTheConferringTerm(t *testing.T) {
	for name, tc := range map[string]struct{ source, subject, term string }{
		"function parameter": {"package view\n\nfunc F(f func()) { f() }\n", "F", "parameter f func()"},
		"unnamed parameter":  {"package view\n\nfunc F(int, func()) {}\n", "F", "parameter #2 func()"},
		"blank parameter":    {"package view\n\nfunc F(_ func()) {}\n", "F", "parameter #1 func()"},
		"interface receiver": {"package view\n\ntype R struct{ h func() }\n\nfunc (r R) F() { r.h() }\n", "R.F", "receiver view.R"},
		"type parameter":     {"package view\n\nfunc F[T any](t T) {}\n", "F", "type parameter T constrained by any"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: tc.subject})
			want := "subject accepts caller-supplied dynamic behavior through its " + tc.term + " (dischargeable by bounding that type away from dynamic carriers, or by " + closure.PurityResponsibility + ")"
			if verdict.Status != Unverifiable || verdict.Reason != want {
				t.Fatalf("verdict = %+v, want the open-world refusal naming %q", verdict, tc.term)
			}
		})
	}
	t.Run("closed signature carries no term", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nfunc F(n int) int { return n + 1 }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid", verdict)
		}
	})
}
