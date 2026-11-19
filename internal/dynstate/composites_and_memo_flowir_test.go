package dynstate

import (
	"context"
	"fmt"
	"go/types"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
	"pgregory.net/rapid"
)

func TestMain(m *testing.M) {
	trace.Refresh(os.Getenv(trace.EnvTrace), os.Getenv(trace.EnvTraceFile))
	os.Exit(m.Run())
}

func TestReadOnlyVarAliasesAuthorityTiersAndConfinement(t *testing.T) {
	t.Run("static_composite_formB_and_formA_chain_is_attestation_free", func(t *testing.T) {
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "example.com/schema",
				src: `package schema

type Endpoint struct {
	Name    string
	Handler func(int) (int, error)
}

type RouteTable struct {
	Service   string
	Endpoints []Endpoint
}
`,
			},
			{
				pkgPath: "example.com/provider",
				imports: []string{"example.com/schema"},
				src: `package provider

import "example.com/schema"

func handlePing(x int) (int, error) { return x + 1, nil }

var BaseTable = schema.RouteTable{
	Service: "echo",
	Endpoints: []schema.Endpoint{
		{Name: "Ping", Handler: handlePing},
	},
}

var TablePtr = &BaseTable
var PtrRoot = &schema.RouteTable{
	Service: "direct",
	Endpoints: []schema.Endpoint{
		{Name: "Pong", Handler: handlePing},
	},
}
`,
			},
			{
				pkgPath: "example.com/consumer",
				imports: []string{"example.com/provider"},
				src: `package consumer

import "example.com/provider"

var Hop1 = provider.TablePtr
var Hop2 = Hop1
var PtrAlias = provider.PtrRoot

func CallEndpoint(x int) (int, error) {
	fn := Hop2.Endpoints[0].Handler
	if fn != nil {
		return fn(x)
	}
	return PtrAlias.Endpoints[0].Handler(x)
}
`,
			},
		})

		for _, singleSubject := range []bool{false, true} {
			ac := AnalyzeCone(ConeQuery{
				Meta:          meta,
				Facts:         facts,
				ViewPackage:   "example.com/consumer",
				SingleSubject: singleSubject,
			})
			if ac.State.Downgraded != "" {
				t.Fatalf("singleSubject=%v downgraded: %q (culprits=%+v)", singleSubject, ac.State.Downgraded, ac.State.RootCulprits)
			}
			if ac.State.AttestationDischarges != "" {
				t.Fatalf("singleSubject=%v recorded unexpected AttestationDischarges for attestation-free StaticCompositeGlobals: %q", singleSubject, ac.State.AttestationDischarges)
			}
			for _, want := range []string{
				"example.com/provider.BaseTable",
				"example.com/provider.TablePtr",
				"example.com/provider.PtrRoot",
				"example.com/consumer.Hop1",
				"example.com/consumer.Hop2",
				"example.com/consumer.PtrAlias",
			} {
				if !ac.NonVouchDischarged[want] {
					t.Fatalf("singleSubject=%v missing %s in NonVouchDischarged: %+v", singleSubject, want, ac.NonVouchDischarged)
				}
			}
		}
	})

	t.Run("cluster_alias_chain_preserves_single_subject_attestation_tier", func(t *testing.T) {
		initFn := syntaxutil.FuncKey{Pkg: "example.com/pb", Name: "file_x_init"}
		meta := []GraphPackage{
			{ImportPath: "example.com/app", PkgPath: "example.com/app", Imports: []string{"example.com/mid"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/mid", PkgPath: "example.com/mid", Imports: []string{"example.com/pb"}, Class: PinnedPackage, Pin: "example.com/mid@v1.0.0"},
			{ImportPath: "example.com/pb", PkgPath: "example.com/pb", Imports: []string{"example.com/rt"}, Class: PinnedPackage, Pin: "example.com/pb@v1.0.0"},
			{ImportPath: "example.com/rt", PkgPath: "example.com/rt", Class: PinnedPackage, Pin: "example.com/rt@v1.0.0"},
		}
		facts := map[string][]Fact{
			"example.com/rt": {{
				InitBuilders: []syntaxutil.InitBuilderFact{{
					Type:          syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "TypeBuilder"},
					BuildMethod:   "Build",
					OutIfaceField: "File",
					CapsuleSliceFields: []syntaxutil.BuilderSliceSpec{{
						Field:    "ExtensionInfos",
						ElemType: syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "ExtensionInfo"},
					}},
				}},
				LazyOnceCapsuleTypes: []syntaxutil.LazyOnceCapsuleType{{
					Type:       syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "ExtensionInfo"},
					GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/rt", Name: "ExtGuard"}},
				}},
			}},
			"example.com/pb": {{
				Declares: []string{"example.com/pb.E_Opt"},
				Mutates:  []string{"example.com/pb.E_Opt"},
				FuncRefs: []syntaxutil.FuncRef{{
					Callee: initFn,
					Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit},
				}},
				InitSettledClusters: []syntaxutil.InitSettledClusterFact{{
					InitFn:        initFn,
					Vars:          []string{"example.com/pb.E_Opt"},
					BuilderType:   syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "TypeBuilder"},
					BuildMethod:   "Build",
					OutIfaceField: "File",
					SliceBindings: []syntaxutil.ClusterCapsuleSliceBinding{{
						Field:         "ExtensionInfos",
						CapsuleType:   syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "ExtensionInfo"},
						StaticLiteral: true,
					}},
				}},
				NoPostInitCarrierWrites: true,
			}},
			"example.com/mid": {{
				Declares: []string{"example.com/mid.MidExt"},
				Mutates:  []string{"example.com/mid.MidExt"},
				ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
					Key:               "example.com/mid.MidExt",
					Target:            "example.com/pb.E_Opt",
					DirectMethodsOnly: true,
				}},
			}},
			"example.com/app": {{
				Declares: []string{"example.com/app.AppExt"},
				Mutates:  []string{"example.com/app.AppExt"},
				ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
					Key:               "example.com/app.AppExt",
					Target:            "example.com/mid.MidExt",
					DirectMethodsOnly: false,
				}},
			}},
		}

		acShared := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         facts,
			ViewPackage:   "example.com/app",
			SingleSubject: false,
		})
		if acShared.State.Downgraded == "" {
			t.Fatal("InitSettledClusters alias chain unexpectedly discharged without SingleSubject attestation")
		}
		for _, k := range []string{"example.com/pb.E_Opt", "example.com/mid.MidExt", "example.com/app.AppExt"} {
			if acShared.NonVouchDischarged[k] {
				t.Fatalf("SingleSubject=false leaked attested %s into NonVouchDischarged", k)
			}
		}

		acSingle := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         facts,
			ViewPackage:   "example.com/app",
			SingleSubject: true,
		})
		if acSingle.State.Downgraded != "" {
			t.Fatalf("SingleSubject=true downgraded attested alias chain: %q", acSingle.State.Downgraded)
		}
		gotAtt := strings.Split(acSingle.State.AttestationDischarges, ",")
		for _, want := range []string{"example.com/app.AppExt", "example.com/mid.MidExt", "example.com/pb.E_Opt"} {
			if !acSingle.NonVouchDischarged[want] {
				t.Fatalf("SingleSubject=true missing %s in NonVouchDischarged", want)
			}
			if !slices.Contains(gotAtt, want) {
				t.Fatalf("SingleSubject=true missing %s in AttestationDischarges %q", want, acSingle.State.AttestationDischarges)
			}
		}
	})

	t.Run("once_memo_alias_chain_direct_methods_and_downstream_revocation", func(t *testing.T) {
		buildOnceMemoDAG := func(consumerSrc string, extraConsumerTestSrc string) ([]GraphPackage, map[string][]Fact) {
			specs := []orderedPkgSpec{
				{
					pkgPath: "example.com/docmemo",
					src: `package docmemo

import "sync"

type Doc struct {
	once sync.Once
	text string
	err  error
}

func NewDoc() *Doc {
	return &Doc{}
}

func (d *Doc) Text() (string, error) {
	d.once.Do(func() {
		d.text, d.err = "computed", nil
	})
	return d.text, d.err
}

var DefaultDoc = NewDoc()
`,
				},
				{
					pkgPath: "example.com/midmemo",
					imports: []string{"example.com/docmemo"},
					src: `package midmemo

import "example.com/docmemo"

var MidAlias = docmemo.DefaultDoc

func ReadMid() (string, error) {
	return MidAlias.Text()
}
`,
				},
				{
					pkgPath: "example.com/leafuse",
					imports: []string{"example.com/midmemo"},
					src:     consumerSrc,
				},
			}
			meta, pkgs, facts := mustTypecheckOrderedDAG(t, specs)
			if extraConsumerTestSrc != "" {
				stdPkg := mustTypecheckWithStdImp(t, inMemoryStdImporter(t), "example.com/leafuse", map[string]string{
					"pkg.go":      consumerSrc,
					"pkg_test.go": extraConsumerTestSrc,
				}, map[string]*types.Package{
					"example.com/docmemo": pkgs["example.com/docmemo"].Types,
					"example.com/midmemo": pkgs["example.com/midmemo"].Types,
				})
				facts["example.com/leafuse"] = append(facts["example.com/leafuse"], FactOf(true, stdPkg))
			}
			return meta, facts
		}

		// Clean Form A chain (DefaultDoc -> MidAlias -> LeafAlias) discharges all three attestation-free.
		metaClean, factsClean := buildOnceMemoDAG(`package leafuse

import "example.com/midmemo"

var LeafAlias = midmemo.MidAlias

func UseClean() (string, error) {
	return LeafAlias.Text()
}
`, "")
		acClean := AnalyzeCone(ConeQuery{Meta: metaClean, Facts: factsClean, ViewPackage: "example.com/leafuse"})
		if acClean.State.Downgraded != "" || acClean.State.AttestationDischarges != "" {
			t.Fatalf("clean OnceMemo Form A chain state = %+v", acClean.State)
		}
		for _, want := range []string{
			"example.com/docmemo.DefaultDoc",
			"example.com/midmemo.MidAlias",
			"example.com/leafuse.LeafAlias",
		} {
			if !acClean.NonVouchDischarged[want] {
				t.Fatalf("clean OnceMemo Form A chain failed to discharge %s: %+v", want, acClean.NonVouchDischarged)
			}
		}

		// Form B (`var FormBAlias = &ByValDoc`) sets DirectMethodsOnly=false, so OnceMemo never propagates across Form B.
		metaFormB, _, factsFormB := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "example.com/valmemo",
				src: `package valmemo

import "sync"

type Doc struct {
	once sync.Once
	text string
	err  error
}

func (d *Doc) Text() (string, error) {
	d.once.Do(func() { d.text, d.err = "v", nil })
	return d.text, d.err
}

var ByValDoc Doc
var FormBAlias = &ByValDoc

func UseFormB() (string, error) { return FormBAlias.Text() }
`,
			},
		})
		acFormB := AnalyzeCone(ConeQuery{Meta: metaFormB, Facts: factsFormB, ViewPackage: "example.com/valmemo"})
		if acFormB.NonVouchDischarged["example.com/valmemo.FormBAlias"] {
			t.Fatalf("Form B alias (&ByValDoc) unexpectedly inherited OnceMemo discharge: %+v", acFormB.NonVouchDischarged)
		}

		// Downstream non-method use (`fmt.Sprint(LeafAlias)`) revokes DirectMethodsOnly on LeafAlias,
		// propagating effectiveNonMethodUsed backward through MidAlias all the way to DefaultDoc.
		metaFmt, factsFmt := buildOnceMemoDAG(`package leafuse

import (
	"fmt"
	"example.com/midmemo"
)

var LeafAlias = midmemo.MidAlias

func UseNonMethod() string {
	s, _ := LeafAlias.Text()
	return fmt.Sprint(LeafAlias) + s
}
`, "")
		acFmt := AnalyzeCone(ConeQuery{Meta: metaFmt, Facts: factsFmt, ViewPackage: "example.com/leafuse"})
		for _, revoked := range []string{
			"example.com/docmemo.DefaultDoc",
			"example.com/midmemo.MidAlias",
			"example.com/leafuse.LeafAlias",
		} {
			if acFmt.NonVouchDischarged[revoked] {
				t.Fatalf("downstream non-method alias use failed to revoke %s: %+v", revoked, acFmt.NonVouchDischarged)
			}
		}

		// Cross-variant _test.go non-method use on LeafAlias also revokes the entire chain.
		metaTestVar, factsTestVar := buildOnceMemoDAG(`package leafuse

import "example.com/midmemo"

var LeafAlias = midmemo.MidAlias

func UseClean() (string, error) {
	return LeafAlias.Text()
}
`, `package leafuse

import "fmt"

func TestInspectAlias() string {
	return fmt.Sprint(LeafAlias)
}
`)
		acTestVar := AnalyzeCone(ConeQuery{Meta: metaTestVar, Facts: factsTestVar, ViewPackage: "example.com/leafuse"})
		for _, revoked := range []string{
			"example.com/docmemo.DefaultDoc",
			"example.com/midmemo.MidAlias",
			"example.com/leafuse.LeafAlias",
		} {
			if acTestVar.NonVouchDischarged[revoked] {
				t.Fatalf("_test.go variant non-method alias use failed to revoke %s: %+v", revoked, acTestVar.NonVouchDischarged)
			}
		}

		// Direct fact-level DirectMethodsOnly=false alias edge (even with empty NonMethodVarUses)
		// must seed effectiveNonMethodUsed on both the alias and its OnceMemo target.
		memoT := syntaxutil.TypeRef{Pkg: "example.com/m", Name: "Doc"}
		ctorK := syntaxutil.FuncKey{Pkg: "example.com/m", Name: "NewDoc"}
		acDirectDMOFalse := AnalyzeCone(ConeQuery{
			Meta: []GraphPackage{
				{ImportPath: "example.com/c", PkgPath: "example.com/c", Imports: []string{"example.com/m"}, Class: MutableLocalPackage},
				{ImportPath: "example.com/m", PkgPath: "example.com/m", Class: PinnedPackage, Pin: "example.com/m@v1.0.0"},
			},
			Facts: map[string][]Fact{
				"example.com/m": {{
					Declares:           []string{"example.com/m.Root"},
					Mutates:            []string{"example.com/m.Root"},
					OnceMemoTypes:      []syntaxutil.OnceMemoTypeFact{{Type: memoT, Constructors: []syntaxutil.FuncKey{ctorK}, GuardTypes: []syntaxutil.TypeRef{memoT}}},
					OnceMemoCandidates: []syntaxutil.OnceMemoVarCandidate{{Key: "example.com/m.Root", Type: memoT, Constructor: ctorK}},
				}},
				"example.com/c": {{
					Declares: []string{"example.com/c.Alias"},
					Mutates:  []string{"example.com/c.Alias"},
					ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
						Key:               "example.com/c.Alias",
						Target:            "example.com/m.Root",
						DirectMethodsOnly: false,
					}},
				}},
			},
			ViewPackage: "example.com/c",
		})
		if acDirectDMOFalse.NonVouchDischarged["example.com/m.Root"] || acDirectDMOFalse.NonVouchDischarged["example.com/c.Alias"] {
			t.Fatalf("DirectMethodsOnly=false alias failed to revoke OnceMemo target and alias: %+v", acDirectDMOFalse.NonVouchDischarged)
		}
	})

	t.Run("cycles_non_capsule_targets_and_invalid_alias_shapes_never_discharge", func(t *testing.T) {
		meta := []GraphPackage{{ImportPath: "example.com/p", PkgPath: "example.com/p", Class: MutableLocalPackage}}
		facts := map[string][]Fact{
			"example.com/p": {{
				Declares: []string{
					"example.com/p.CycA", "example.com/p.CycB",
					"example.com/p.PoolSrc", "example.com/p.PoolAlias",
					"example.com/p.MapSrc", "example.com/p.MapAlias",
					"example.com/p.MemoSrc", "example.com/p.MemoAlias",
					"example.com/p.SSSrc", "example.com/p.SSAlias",
					"example.com/p.VouchSrc", "example.com/p.VouchAlias",
				},
				Escapes: []string{
					"example.com/p.CycA", "example.com/p.CycB",
					"example.com/p.PoolAlias", "example.com/p.MapAlias",
					"example.com/p.MemoAlias", "example.com/p.SSAlias", "example.com/p.VouchAlias",
				},
				PoolDischarges:    []string{"example.com/p.PoolSrc"},
				PoolMutates:       []string{"example.com/p.PoolSrc"},
				MappingDischarges: []string{"example.com/p.MapSrc"},
				Mutates:           []string{"example.com/p.MapSrc", "example.com/p.MemoSrc", "example.com/p.SSSrc", "example.com/p.VouchSrc"},
				MemoDischarges:    []string{"example.com/p.MemoSrc"},
				SingleSubjectVars: []string{"example.com/p.SSSrc"},
				ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{
					{Key: "example.com/p.CycA", Target: "example.com/p.CycB", DirectMethodsOnly: true},
					{Key: "example.com/p.CycB", Target: "example.com/p.CycA", DirectMethodsOnly: true},
					{Key: "example.com/p.PoolAlias", Target: "example.com/p.PoolSrc", DirectMethodsOnly: true},
					{Key: "example.com/p.MapAlias", Target: "example.com/p.MapSrc", DirectMethodsOnly: true},
					{Key: "example.com/p.MemoAlias", Target: "example.com/p.MemoSrc", DirectMethodsOnly: true},
					{Key: "example.com/p.SSAlias", Target: "example.com/p.SSSrc", DirectMethodsOnly: true},
					{Key: "example.com/p.VouchAlias", Target: "example.com/p.VouchSrc", DirectMethodsOnly: true},
				},
			}},
		}
		for _, singleSubject := range []bool{false, true} {
			ac := AnalyzeCone(ConeQuery{
				Meta:          meta,
				Facts:         facts,
				ViewPackage:   "example.com/p",
				Vouches:       map[string]bool{"example.com/p.VouchSrc": true},
				SingleSubject: singleSubject,
			})
			for _, forbidden := range []string{
				"example.com/p.CycA", "example.com/p.CycB",
				"example.com/p.PoolAlias", "example.com/p.MapAlias",
				"example.com/p.MemoAlias", "example.com/p.SSAlias", "example.com/p.VouchAlias",
			} {
				if ac.NonVouchDischarged[forbidden] {
					t.Fatalf("singleSubject=%v illegally discharged %s via ReadOnlyVarAliases", singleSubject, forbidden)
				}
				hasCulprit := slices.ContainsFunc(ac.State.RootCulprits, func(c Culprit) bool { return c.Key == forbidden })
				if !hasCulprit {
					t.Fatalf("singleSubject=%v failed to surface %s as RootCulprit: %+v", singleSubject, forbidden, ac.State.RootCulprits)
				}
			}
		}

		pkgShapes := mustTypecheckPackage(t, "example.com/shapes", map[string]string{
			"shapes.go": `package shapes

import "bytes"

type NonEmpty struct{ fn func() }
type Empty struct{}

var Base = &NonEmpty{}
var DoublePtr = &Base
var Reassigned = Base
var AddrTaken = Base
var StdBuf = &bytes.Buffer{}
var StdAlias = StdBuf
var EmptyVal Empty
var EmptyAlias = &EmptyVal

func Touch() (**NonEmpty, *bytes.Buffer, *Empty) {
	Reassigned = nil
	p := &AddrTaken
	return p, StdAlias, EmptyAlias
}
`,
		})
		shapeFact := FactOf(true, pkgShapes)
		if len(shapeFact.ReadOnlyVarAliases) != 0 {
			t.Fatalf("invalid alias shapes unexpectedly admitted into ReadOnlyVarAliases: %+v", shapeFact.ReadOnlyVarAliases)
		}

		// A malformed ReadOnlyVarAliases entry in any cone package must set
		// anyMalformedNonMethodVarUse so OnceMemoCandidates fail closed.
		malMeta := []GraphPackage{
			{ImportPath: "example.com/malalias", PkgPath: "example.com/malalias", Imports: []string{"example.com/onceroot"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/onceroot", PkgPath: "example.com/onceroot", Class: PinnedPackage, Pin: "example.com/onceroot@v1.0.0"},
		}
		onceType := syntaxutil.TypeRef{Pkg: "example.com/onceroot", Name: "MemoS"}
		ctorFn := syntaxutil.FuncKey{Pkg: "example.com/onceroot", Name: "NewMemoS"}
		malFacts := map[string][]Fact{
			"example.com/malalias": {{
				ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
					Key:               "wrong.pkg.Alias",
					Target:            "example.com/onceroot.Root",
					DirectMethodsOnly: true,
				}},
			}},
			"example.com/onceroot": {{
				Declares: []string{"example.com/onceroot.Root"},
				Mutates:  []string{"example.com/onceroot.Root"},
				OnceMemoTypes: []syntaxutil.OnceMemoTypeFact{{
					Type:         onceType,
					Constructors: []syntaxutil.FuncKey{ctorFn},
					GuardTypes:   []syntaxutil.TypeRef{onceType},
				}},
				OnceMemoCandidates: []syntaxutil.OnceMemoVarCandidate{{
					Key:         "example.com/onceroot.Root",
					Type:        onceType,
					Constructor: ctorFn,
				}},
			}},
		}
		acMal := AnalyzeCone(ConeQuery{Meta: malMeta, Facts: malFacts, ViewPackage: "example.com/malalias"})
		if acMal.NonVouchDischarged["example.com/onceroot.Root"] {
			t.Fatalf("OnceMemoCandidate unexpectedly survived malformed ReadOnlyVarAliases: %+v", acMal.NonVouchDischarged)
		}
	})
}

func TestStaticCompositeGlobalsClosedSchemaAndRevocation(t *testing.T) {
	baseSchemaSrc := `package desc

type UnaryFn func(int) (int, error)
type StreamFn func(any) error

type ServiceContract interface {
	Serve()
}

type ContractStub struct{ tag int }
func (*ContractStub) Serve() {}

type EndpointSpec struct {
	Route   string
	Handler UnaryFn
	Meta    any
}

type StreamSpec struct {
	Channel string
	Run     StreamFn
}

type HeaderSpec struct {
	Version int
	Strict  bool
}

type RouteTable struct {
	Name      string
	Header    HeaderSpec
	Endpoints []EndpointSpec
	Streams   [2]StreamSpec
	Contract  any
	Metadata  string
}
`
	baseProviderSrc := `package svc

import "example.com/desc"

func handleEcho(v int) (int, error) { return v, nil }
func handleRaw(v int) (int, error)  { return v + 1, nil }
func streamItems(_ any) error       { return nil }

var ValTable = desc.RouteTable{
	Name:   "svc.Echo",
	Header: desc.HeaderSpec{Version: 3, Strict: true},
	Endpoints: []desc.EndpointSpec{
		{Route: "/echo", Handler: handleEcho, Meta: "ro"},
		{Route: "/raw", Handler: desc.UnaryFn(handleRaw), Meta: nil},
	},
	Streams: [2]desc.StreamSpec{
		{Channel: "events", Run: streamItems},
		{Channel: "idle", Run: nil},
	},
	Contract: (*desc.ContractStub)(nil),
	Metadata: "echo.proto",
}

var PtrTable = &desc.RouteTable{
	Name:     "svc.Direct",
	Header:   desc.HeaderSpec{Version: 1},
	Contract: 7,
	Metadata: "direct.proto",
}
`
	// Escape &svc.ValTable and svc.PtrTable from init()-reachable exported Export()
	// without mutating RouteTable, so both globals sit in Fact.Escapes and genuinely
	// require StaticCompositeGlobals to discharge!
	baseConsumerSrc := `package app

import (
	"example.com/desc"
	"example.com/svc"
)

func Export() (*desc.RouteTable, *desc.RouteTable) {
	return &svc.ValTable, svc.PtrTable
}

func init() {
	_, _ = Export()
}
`

	t.Run("positive_closed_schema_by_value_and_pointer_roots", func(t *testing.T) {
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/svc"}, src: baseConsumerSrc},
		})
		svcFact := facts["example.com/svc"][0]
		if len(svcFact.StaticCompositeGlobals) != 2 {
			t.Fatalf("StaticCompositeGlobals = %+v, want 2 entries (PtrTable, ValTable)", svcFact.StaticCompositeGlobals)
		}
		for _, sc := range svcFact.StaticCompositeGlobals {
			for _, wantGuard := range []syntaxutil.TypeRef{
				{Pkg: "example.com/desc", Name: "EndpointSpec"},
				{Pkg: "example.com/desc", Name: "HeaderSpec"},
				{Pkg: "example.com/desc", Name: "RouteTable"},
				{Pkg: "example.com/desc", Name: "StreamSpec"},
			} {
				if !slices.Contains(sc.GuardTypes, wantGuard) {
					t.Fatalf("%s GuardTypes %+v missing %+v", sc.Key, sc.GuardTypes, wantGuard)
				}
			}
		}
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("clean StaticCompositeGlobals cone downgraded: %q", ac.State.Downgraded)
		}
		if ac.State.AttestationDischarges != "" {
			t.Fatalf("unexpected AttestationDischarges: %q", ac.State.AttestationDischarges)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("positive_non_empty_iface_formatted_via_confined_helper_pkg", func(t *testing.T) {
		errfmtSrc := `package errfmt
import (
	"errors"
	"fmt"
)
var Sentinel = errors.New("sentinel")
type prefixErr struct{ s string }
func (e *prefixErr) Error() string { return e.s }
func New(f string, x ...any) error {
	for i := 0; i < len(x); i++ {
		if pe, ok := x[i].(*prefixErr); ok {
			x[i] = pe.s
		}
	}
	return &prefixErr{s: fmt.Sprintf(f, x...)}
}
`
		wrapSrc := `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/errfmt"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Check() error {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	return errfmt.New("%v", s)
}
`
		appSrc := `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) {
	return &svc.ValTable, svc.PtrTable
}
func init() {
	_ = wrap.Check()
	local := 1
	var unrelated any = &local
	reflect.ValueOf(unrelated).Elem().SetInt(2)
	_, _ = Export()
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/errfmt", src: errfmtSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/errfmt", "example.com/svc"}, src: wrapSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/svc", "example.com/wrap"}, src: appSrc},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("clean confined variadic formatter cone downgraded: %q (errfmt=%+v wrap=%+v app=%+v)",
				ac.State.Downgraded,
				facts["example.com/errfmt"][0].ReflectedIfaceMethodSets,
				facts["example.com/wrap"][0].ReflectedIfaceMethodSets,
				facts["example.com/app"][0].ReflectedIfaceMethodSets)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("positive_distinct_method_signature_same_name_does_not_revoke", func(t *testing.T) {
		wrapSrc := `package wrap
import (
	"example.com/desc"
	"example.com/svc"
)
type OpZero interface{ Op() string }
type holder struct{ P *desc.RouteTable }
func (*holder) Op() string { return "ok" }
func Box() OpZero { return &holder{P: svc.PtrTable} }
`
		appSrc := `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
type OpOne interface{ Op(int) string }
type unrelated struct{ V int }
func (*unrelated) Op(int) string { return "x" }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	_ = wrap.Box()
	var u OpOne = &unrelated{V: 1}
	reflect.ValueOf(u).Elem().Field(0).SetInt(2)
	_, _ = Export()
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/svc", "example.com/wrap"}, src: appSrc},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("distinct method signature downgraded: %q", ac.State.Downgraded)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("positive_confined_unexported_context_key_does_not_revoke", func(t *testing.T) {
		wrapSrc := `package wrap
import (
	"context"
	"example.com/desc"
	"example.com/svc"
)
type ctxKey struct{}
type holder struct{ p *desc.RouteTable }
func Attach(ctx context.Context) string {
	ctx = context.WithValue(ctx, ctxKey{}, &holder{p: svc.PtrTable})
	h, _ := ctx.Value(ctxKey{}).(*holder)
	if h == nil {
		return ""
	}
	return h.p.Name
}
`
		appSrc := `package app
import (
	"context"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	_ = wrap.Attach(context.Background())
	_, _ = Export()
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/svc", "example.com/wrap"}, src: appSrc},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("confined context key downgraded: %q", ac.State.Downgraded)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("positive_confined_context_key_with_clean_delegating_custom_context_does_not_revoke", func(t *testing.T) {
		wrapSrc := `package wrap
import (
	"context"
	"example.com/desc"
	"example.com/svc"
)
type ctxKey struct{}
type metaKey struct{}
type holder struct{ p *desc.RouteTable }
type delegatingCtx struct {
	context.Context
	tag string
}
func (d *delegatingCtx) Value(key any) any {
	if key == (metaKey{}) {
		return d.tag
	}
	return d.Context.Value(key)
}
func Attach(ctx context.Context) string {
	wrapped := &delegatingCtx{Context: ctx, tag: "ok"}
	ctx = context.WithValue(wrapped, ctxKey{}, &holder{p: svc.PtrTable})
	h, _ := ctx.Value(ctxKey{}).(*holder)
	if h == nil {
		return ""
	}
	return h.p.Name
}
`
		appSrc := `package app
import (
	"context"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	_ = wrap.Attach(context.Background())
	_, _ = Export()
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/svc", "example.com/wrap"}, src: appSrc},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("clean delegating custom context downgraded: %q", ac.State.Downgraded)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("per_pkg_inferred_generic_method_val_call_records_mutated_struct", func(t *testing.T) {
		genSrc := `package genmut
type Box[T any] struct { V *T }
func (b Box[T]) Clobber() {
	var z T
	*b.V = z
}
`
		midSrc := `package mid
import (
	"example.com/desc"
	"example.com/genmut"
)
func Make(p *desc.RouteTable) genmut.Box[desc.RouteTable] {
	return genmut.Box[desc.RouteTable]{V: p}
}
`
		appSrc := `package app
import (
	"example.com/mid"
	"example.com/svc"
)
func Run() {
	b := mid.Make(svc.PtrTable)
	b.Clobber()
}
`
		_, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/genmut", src: genSrc},
			{pkgPath: "example.com/mid", imports: []string{"example.com/desc", "example.com/genmut"}, src: midSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/mid", "example.com/svc"}, src: appSrc},
		})
		wantRef := syntaxutil.TypeRef{Pkg: "example.com/desc", Name: "RouteTable"}
		if !slices.Contains(facts["example.com/app"][0].MutatedStructTypes, wantRef) {
			t.Fatalf("app MutatedStructTypes = %+v, missing %+v from inferred generic MethodVal call", facts["example.com/app"][0].MutatedStructTypes, wantRef)
		}
	})

	t.Run("dotless_user_module_admitted", func(t *testing.T) {
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "myroutes/spec",
				src: `package spec

type Entry struct {
	Path string
	Fn   func() int
}
type Table struct {
	Entries []Entry
}
`,
			},
			{
				pkgPath: "myroutes/app",
				imports: []string{"myroutes/spec"},
				src: `package app

import "myroutes/spec"

func one() int { return 1 }

var Routes = spec.Table{
	Entries: []spec.Entry{{Path: "/ok", Fn: one}},
}

func init() { _ = Export() }
func Export() *spec.Table { return &Routes }
`,
			},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "myroutes/app"})
		if ac.State.Downgraded != "" || !ac.NonVouchDischarged["myroutes/app.Routes"] {
			t.Fatalf("dotless user module StaticCompositeGlobal failed: state=%+v nvd=%+v", ac.State, ac.NonVouchDischarged)
		}
	})

	t.Run("sealed_eface_union_typed_sync_pool_and_const_dead_branch_admitted", func(t *testing.T) {
		unionSrc := `package unionpkg
import (
	"fmt"
	"unsafe"
)
type doNotCompare [0]func()
type ifaceHeader struct {
	_    [0]any
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer {
	return (*ifaceHeader)(unsafe.Pointer(&t)).Type
}
var (
	nilType    = typeOf(nil)
	boolType   = typeOf(*new(bool))
	stringType = typeOf(*new(string))
	bytesType  = typeOf(*new([]byte))
)
type rawVal struct {
	doNotCompare
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func ValueOfBool(b bool) Value {
	if b {
		return Value{typ: boolType, num: 1}
	}
	return Value{typ: boolType, num: 0}
}
func ValueOfString(s string) Value {
	return Value{typ: stringType, ptr: unsafe.Pointer(unsafe.StringData(s)), num: uint64(len(s))}
}
func ValueOfBytes(b []byte) Value {
	return Value{typ: bytesType, ptr: unsafe.Pointer(unsafe.SliceData(b)), num: uint64(len(b))}
}
func ValueOfStringer(s fmt.Stringer) Value {
	return valueOfIface(s)
}
func valueOfIface(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data}
}
func (v Value) getString() string {
	return unsafe.String((*byte)(v.ptr), v.num)
}
func (v Value) getBytes() []byte {
	return unsafe.Slice((*byte)(v.ptr), v.num)
}
func (v Value) getIface() (x any) {
	*(*ifaceHeader)(unsafe.Pointer(&x)) = ifaceHeader{Type: v.typ, Data: v.ptr}
	return x
}
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("not bytes")
	}
}
func (v Value) Stringer() fmt.Stringer {
	switch s := v.getIface().(type) {
	case fmt.Stringer:
		return s
	default:
		panic("not stringer")
	}
}
func (v Value) Interface() any {
	switch v.typ {
	case nilType:
		return nil
	case boolType:
		return v.num != 0
	case stringType:
		return v.getString()
	case bytesType:
		return v.getBytes()
	default:
		return v.getIface()
	}
}
`
		poolAndNilSrc := `package helperpkg
import (
	"fmt"
	"sync"
	"example.com/desc"
	"example.com/svc"
	"example.com/unionpkg"
)
const fastPathEnabled = true
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
type entry struct {
	s fmt.Stringer
}
var entryPool = sync.Pool{
	New: func() any { return new([]entry) },
}
func sinkNilOnly(a any) string {
	if a == nil {
		return "nil"
	}
	return "set"
}
func Check(h *holder) string {
	buf := entryPool.Get().(*[]entry)
	items := (*buf)[:0]
	items = append(items, entry{s: &holder{p: svc.PtrTable}})
	*buf = items[:0]
	entryPool.Put(buf)
	if !fastPathEnabled {
		var deadAny any = &holder{p: svc.PtrTable}
		_ = sinkNilOnly(deadAny)
	}
	u := unionpkg.ValueOfStringer(&holder{p: svc.PtrTable})
	_ = u.Stringer().String()
	if fastPathEnabled && h != nil {
		return h.String()
	}
	return sinkNilOnly(h)
}
`
		appSrc := `package app
import (
	"example.com/desc"
	"example.com/helperpkg"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	_ = helperpkg.Check(nil)
	_, _ = Export()
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/unionpkg", src: unionSrc},
			{pkgPath: "example.com/helperpkg", imports: []string{"example.com/desc", "example.com/svc", "example.com/unionpkg"}, src: poolAndNilSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/helperpkg", "example.com/svc"}, src: appSrc},
		})
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
		if !ac.NonVouchDischarged["example.com/svc.ValTable"] || !ac.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("sealed eface union + typed sync.Pool + const dead branch unexpectedly revoked StaticCompositeGlobals: nvd=%+v state=%+v", ac.NonVouchDischarged, ac.State)
		}
		pinnedMeta := slices.Clone(meta)
		for i := range pinnedMeta {
			if pinnedMeta[i].PkgPath == "example.com/unionpkg" || pinnedMeta[i].PkgPath == "example.com/helperpkg" {
				pinnedMeta[i].Class = PinnedPackage
				pinnedMeta[i].Pin = pinnedMeta[i].PkgPath + "@v1.0.0"
			}
		}
		acVouched := AnalyzeCone(ConeQuery{
			Meta:          pinnedMeta,
			Facts:         facts,
			ViewPackage:   "example.com/app",
			SingleSubject: true,
			Vouches: map[string]bool{
				"example.com/helperpkg.entryPool": true,
				"example.com/unionpkg.nilType":    true,
				"example.com/unionpkg.boolType":   true,
				"example.com/unionpkg.stringType": true,
				"example.com/unionpkg.bytesType":  true,
			},
		})
		if acVouched.State.Downgraded != "" || !acVouched.NonVouchDischarged["example.com/svc.ValTable"] || !acVouched.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("sealed eface union + typed sync.Pool + const dead branch failed full cone discharge: state=%+v nvd=%+v", acVouched.State, acVouched.NonVouchDischarged)
		}
	})

	t.Run("capsule_reflect_safe_pkg_any_boxed_wrapper_flagro_bypass_marks_capsule_mutated", func(t *testing.T) {
		implSrc := `package impl
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 42
	atomic.StoreUint32(&mi.done, 1)
}
type wrapper struct {
	mi *MessageInfo
}
type shadow struct {
	GoReflectType string
}
func SmuggleAndCorrupt(mi *MessageInfo) {
	var a any = &wrapper{mi: mi}
	hdr := (*[2]unsafe.Pointer)(unsafe.Pointer(&a))
	p := *(*unsafe.Pointer)(hdr[1])
	(*shadow)(p).GoReflectType = "corrupted"
}
`
		_, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/impl", src: implSrc},
		})
		wantRef := syntaxutil.TypeRef{Pkg: "example.com/impl", Name: "MessageInfo"}
		if !slices.Contains(facts["example.com/impl"][0].MutatedStructTypes, wantRef) {
			t.Fatalf("impl MutatedStructTypes = %+v, missing %+v on any-boxed wrapper flagRO bypass", facts["example.com/impl"][0].MutatedStructTypes, wantRef)
		}
	})

	t.Run("unaddressed_local_value_struct_copy_with_goto_and_capsule_value_child_guards", func(t *testing.T) {
		implSrc := `package impl
import (
	"sync"
	"sync/atomic"
)
type valueCoderFuncs struct {
	tag int
}
type coderFieldInfo struct {
	funcs valueCoderFuncs
}
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	cf            *coderFieldInfo
}
func makeFuncs() (funcs valueCoderFuncs) {
	funcs.tag = 7
	return funcs
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.cf = &coderFieldInfo{funcs: makeFuncs()}
	mi.cf.funcs.tag = 9
	atomic.StoreUint32(&mi.done, 1)
}
func InspectCopy(mi *MessageInfo) int {
	mi.initOnce()
	var local valueCoderFuncs
	if mi.cf == nil {
		goto doneLabel
	}
	local = mi.cf.funcs
	local.tag = 99
doneLabel:
	return local.tag
}
`
		appSrc := `package app
import (
	"example.com/desc"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) {
	cp := svc.ValTable
	if cp.Header.Version < 0 {
		goto doneCopy
	}
	cp.Name = "local-only"
	cp.Header.Version = 2
	cp.Endpoints = nil
doneCopy:
	_ = cp
	return &svc.ValTable, svc.PtrTable
}
`
		meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/impl", src: implSrc},
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/app", imports: []string{"example.com/desc", "example.com/svc"}, src: appSrc},
		})
		implFact := facts["example.com/impl"][0]
		wantChildGuard := syntaxutil.TypeRef{Pkg: "example.com/impl", Name: "valueCoderFuncs"}
		sawMsgGuard := false
		for _, ct := range implFact.LazyOnceCapsuleTypes {
			if ct.Type.Name == "MessageInfo" && slices.Contains(ct.GuardTypes, wantChildGuard) {
				sawMsgGuard = true
			}
		}
		if !sawMsgGuard {
			t.Fatalf("MessageInfo GuardTypes missing value-contained child valueCoderFuncs: %+v", implFact.LazyOnceCapsuleTypes)
		}
		if slices.Contains(implFact.MutatedStructTypes, wantChildGuard) {
			t.Fatalf("impl MutatedStructTypes unexpectedly marked unaddressed local valueCoderFuncs: %+v", implFact.MutatedStructTypes)
		}
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" || !ac.NonVouchDischarged["example.com/svc.ValTable"] || !ac.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("unaddressed local value copy with goto unexpectedly revoked StaticCompositeGlobals: state=%+v nvd=%+v", ac.State, ac.NonVouchDischarged)
		}
	})

	t.Run("capsule_pkg_unsafe_iface_addr_or_composite_reflect_valueof_disables_capsule_reflect_safe", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			corrupt string
		}{
			{
				name: "unsafe_pointer_addr_of_non_empty_iface",
				corrupt: `func Corrupt(s fmt.Stringer) {
	hdr := (*[2]unsafe.Pointer)(unsafe.Pointer(&s))
	b := (*box)(hdr[1])
	b.mi.cf.label = "corrupted"
}`,
			},
			{
				name: "reflect_valueof_slice_of_non_empty_iface",
				corrupt: `func Corrupt(s fmt.Stringer) {
	ptr := unsafe.Pointer(reflect.ValueOf([]fmt.Stringer{s}).Index(0).Elem().Pointer())
	(*box)(ptr).mi.cf.label = "corrupted"
}`,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				implSrc := `package impl
import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
var _ = reflect.ValueOf
type shadowCF struct{ label string }
type shadowMI struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	cf            *shadowCF
}
type coderFieldInfo struct{ label string }
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	cf            *coderFieldInfo
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.cf = &coderFieldInfo{label: "clean"}
	atomic.StoreUint32(&mi.done, 1)
}
type box struct{ mi *shadowMI }
type msgBox struct{ mi *MessageInfo }
func (*msgBox) String() string { return "ok" }
func NewBox(mi *MessageInfo) *msgBox { return &msgBox{mi: mi} }
` + tc.corrupt + "\n"
				pbSrc := `package pb
import (
	"fmt"
	"example.com/impl"
)
var Msg impl.MessageInfo
func AsStringer() fmt.Stringer { return impl.NewBox(&Msg) }
`
				appSrc := `package app
import (
	"example.com/impl"
	"example.com/pb"
)
func Run() { impl.Corrupt(pb.AsStringer()) }
`
				meta, _, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
					{pkgPath: "example.com/impl", src: implSrc},
					{pkgPath: "example.com/pb", imports: []string{"example.com/impl"}, src: pbSrc},
					{pkgPath: "example.com/app", imports: []string{"example.com/impl", "example.com/pb"}, src: appSrc},
				})
				implFact := facts["example.com/impl"][0]
				sawMsg := false
				for _, ct := range implFact.LazyOnceCapsuleTypes {
					if ct.Type.Name == "MessageInfo" {
						sawMsg = true
						if ct.CapsuleReflectSafe {
							t.Fatalf("%s unexpectedly marked MessageInfo CapsuleReflectSafe=true: %+v", tc.name, ct)
						}
					}
				}
				if !sawMsg {
					t.Fatalf("%s failed to recognize MessageInfo as LazyOnceCapsuleType: %+v", tc.name, implFact.LazyOnceCapsuleTypes)
				}
				ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
				if ac.NonVouchDischarged["example.com/pb.Msg"] {
					t.Fatalf("%s unexpectedly discharged pb.Msg: %+v", tc.name, ac.NonVouchDischarged)
				}
			})
		}
	})

	for _, tc := range []struct {
		name        string
		descSrc     string
		providerSrc string
		consumerSrc string
		extraSpecs  []orderedPkgSpec
	}{
		{
			name:        "stdlib_methodless_struct_rejected",
			providerSrc: "package svc\nimport (\n\t\"testing\"\n\t\"example.com/desc\"\n)\nvar _ desc.RouteTable\nvar ValTable = testing.InternalTest{Name: \"t\"}\nvar PtrTable = &testing.InternalTest{Name: \"t\"}\n",
			consumerSrc: "package app\nimport (\n\t\"testing\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nvar _ desc.RouteTable\nfunc Export() (*testing.InternalTest, *testing.InternalTest) { return &svc.ValTable, svc.PtrTable }\nfunc init() { _, _ = Export() }\n",
		},
		{
			name:    "root_struct_declaring_method_rejected",
			descSrc: baseSchemaSrc + "\nfunc (r *RouteTable) Label() string { return r.Name }\n",
		},
		{
			name:    "nested_slice_elem_struct_declaring_method_rejected",
			descSrc: baseSchemaSrc + "\nfunc (e EndpointSpec) Label() string { return e.Route }\n",
		},
		{
			name: "omitted_zero_mutex_field_rejected",
			descSrc: strings.Replace(
				strings.Replace(baseSchemaSrc, "package desc\n", "package desc\nimport \"sync\"\n", 1),
				"type HeaderSpec struct {",
				"type HeaderSpec struct {\n\tmu sync.Mutex", 1),
		},
		{
			name: "omitted_zero_chan_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tCh chan int", 1),
		},
		{
			name: "omitted_zero_pointer_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tNext *EndpointSpec", 1),
		},
		{
			name: "omitted_zero_map_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tTags map[string]string", 1),
		},
		{
			name: "omitted_zero_uintptr_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tRaw uintptr", 1),
		},
		{
			name: "omitted_zero_scalar_slice_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tNums []int", 1),
		},
		{
			name: "unnamed_nested_struct_field_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"Strict  bool",
				"Strict  bool\n\tAnon struct{ X int }", 1),
		},
		{
			name: "empty_named_substruct_rejected",
			descSrc: strings.Replace(baseSchemaSrc,
				"type HeaderSpec struct {\n\tVersion int\n\tStrict  bool\n}",
				"type HeaderSpec struct {}", 1),
			providerSrc: strings.Replace(
				strings.Replace(baseProviderSrc, "HeaderSpec{Version: 3, Strict: true}", "HeaderSpec{}", 1),
				"HeaderSpec{Version: 1}", "HeaderSpec{}", 1),
		},
		{
			name: "closure_in_function_field_rejected",
			providerSrc: strings.Replace(baseProviderSrc,
				"Handler: handleEcho",
				"Handler: func(v int) (int, error) { return v, nil }", 1) + "\nfunc init() { PtrTable = nil }\n",
		},
		{
			name: "non_nil_concrete_struct_in_interface_field_rejected",
			providerSrc: strings.Replace(baseProviderSrc,
				"Contract: (*desc.ContractStub)(nil)",
				"Contract: desc.ContractStub{}", 1) + "\nfunc init() { PtrTable = nil }\n",
		},
		{
			name: "unsafe_pointer_in_typed_nil_interface_rejected",
			descSrc: strings.Replace(
				strings.Replace(baseSchemaSrc, "package desc\n", "package desc\nimport \"unsafe\"\n", 1),
				"type ContractStub struct{ tag int }",
				"type ContractStub struct{ p unsafe.Pointer }", 1),
			providerSrc: strings.Replace(baseProviderSrc, "Contract: 7,", "Contract: (*desc.ContractStub)(nil),", 1),
		},
		{
			name:        "non_const_scalar_init_rejected",
			providerSrc: "package svc\nimport \"example.com/desc\"\nfunc dynName() string { return \"x\" }\nvar ValTable = desc.RouteTable{Name: dynName()}\nvar PtrTable = &desc.RouteTable{Name: dynName()}\n",
		},
		{
			name: "make_slice_in_composite_lit_rejected",
			providerSrc: strings.Replace(baseProviderSrc,
				"Endpoints: []desc.EndpointSpec{\n\t\t{Route: \"/echo\", Handler: handleEcho, Meta: \"ro\"},\n\t\t{Route: \"/raw\", Handler: desc.UnaryFn(handleRaw), Meta: nil},\n\t}",
				"Endpoints: make([]desc.EndpointSpec, 1)", 1) + "\nfunc init() { PtrTable = nil }\n",
		},
		{
			name:        "intra_pkg_subplace_field_write_rejected",
			providerSrc: baseProviderSrc + "\nfunc init() { ValTable.Metadata = \"bad\"; PtrTable.Metadata = \"bad\" }\n",
		},
		{
			name:        "intra_pkg_subslice_rejected",
			providerSrc: baseProviderSrc + "\nfunc init() { _ = ValTable.Endpoints[:1]; PtrTable = nil }\n",
		},
		{
			name:        "intra_pkg_addr_of_ptr_root_rejected",
			providerSrc: baseProviderSrc + "\nfunc init() { ValTable = desc.RouteTable{}; _ = &PtrTable }\n",
		},
		{
			name:        "intra_pkg_non_scalar_subplace_arg_rejected",
			providerSrc: baseProviderSrc + "\nfunc sink([]desc.EndpointSpec) {}\nfunc init() { PtrTable = nil; sink(ValTable.Endpoints) }\n",
		},
		{
			name:        "cross_pkg_direct_guard_struct_mutation_revokes",
			consumerSrc: baseConsumerSrc + "\nfunc MutateOther(e *desc.EndpointSpec) { e.Route = \"mut\" }\n",
		},
		{
			name:        "cross_pkg_clear_builtin_on_guard_slice_revokes",
			consumerSrc: baseConsumerSrc + "\nfunc ClearSlice(s []desc.EndpointSpec) { clear(s) }\n",
		},
		{
			name:        "cross_pkg_slices_reverse_generic_mutation_revokes",
			consumerSrc: "package app\nimport (\n\t\"slices\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() { var s []desc.EndpointSpec; slices.Reverse(s); _, _ = Export() }\n",
		},
		{
			name:        "cross_pkg_sort_slice_mutation_revokes",
			consumerSrc: "package app\nimport (\n\t\"sort\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() { s := svc.ValTable.Endpoints; sort.Slice(s, func(i, j int) bool { return i < j }); _, _ = Export() }\n",
		},
		{
			name:        "cross_pkg_unsafe_slicedata_on_guard_slice_revokes",
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() { var s []desc.EndpointSpec; _ = unsafe.SliceData(s); _, _ = Export() }\n",
		},
		{
			name:        "cross_pkg_empty_interface_var_box_and_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar sneak any = &svc.ValTable\n\treflect.ValueOf(sneak).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_closure_any_param_box_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tfn := func(a any) { reflect.ValueOf(a).Elem().Field(0).SetString(\"evil\") }\n\tfn(&svc.ValTable)\n\tfn(svc.PtrTable)\n\t_, _ = Export()\n}\n",
		},
		{
			name: "dotless_third_party_fmt_spoof_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "fmt",
					src: `package fmt
import "reflect"
func Sprintf(_ string, a ...any) string {
	if len(a) > 0 {
		reflect.ValueOf(a[0]).Elem().Field(0).SetString("spoof")
	}
	return ""
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = fmt.Sprintf(\"%v\", &svc.ValTable)\n\t_ = fmt.Sprintf(\"%v\", svc.PtrTable)\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_generic_struct_instantiation_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
type Mutator[T any] struct { Slice []T }
func (m Mutator[T]) Run() {
	var z T
	if len(m.Slice) > 0 {
		m.Slice[0] = z
	}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcp := svc.ValTable\n\tvar r interface{ Run() } = genmut.Mutator[desc.EndpointSpec]{Slice: cp.Endpoints}\n\tr.Run()\n\tsvc.PtrTable = nil\n}\n",
		},
		{
			name: "cross_pkg_generic_method_sig_instantiation_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
type Zeroer[T any] struct{}
func (Zeroer[T]) Mut(p *T) {
	var z T
	*p = z
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar m interface{ Mut(*desc.RouteTable) } = genmut.Zeroer[desc.RouteTable]{}\n\tm.Mut(&svc.ValTable)\n\tm.Mut(svc.PtrTable)\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_generic_direct_method_val_call_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
type Box[T any] struct { V *T }
func NewBox[T any](p *T) Box[T] { return Box[T]{V: p} }
func (b Box[T]) Clobber() {
	var z T
	*b.V = z
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tb := genmut.NewBox(&desc.RouteTable{})\n\tb.V = svc.PtrTable\n\tb.Clobber()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_generic_direct_method_expr_call_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
type Box[T any] struct{}
func (Box[T]) Clobber(p *T) {
	var z T
	*p = z
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tgenmut.Box[desc.RouteTable].Clobber(genmut.Box[desc.RouteTable]{}, svc.PtrTable)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_multihop_unsafe_pointer_revokes",
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tp := svc.PtrTable\n\tpp := &p\n\t_ = unsafe.Pointer(pp)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_multihop_unsafe_slice_revokes",
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tp := svc.PtrTable\n\tpp := &p\n\t_ = unsafe.Slice(pp, 1)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_context_withvalue_roundtrip_revokes",
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := context.WithValue(context.Background(), \"k\", svc.PtrTable)\n\treflect.ValueOf(ctx.Value(\"k\")).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_sync_map_roundtrip_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"sync\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar sm sync.Map\n\tv, _ := sm.LoadOrStore(\"k\", svc.PtrTable)\n\treflect.ValueOf(v).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_slog_anyvalue_roundtrip_revokes",
			consumerSrc: "package app\nimport (\n\t\"log/slog\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\treflect.ValueOf(slog.AnyValue(svc.PtrTable).Any()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_errors_as_target_revokes",
			consumerSrc: "package app\nimport (\n\t\"errors\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcp := svc.ValTable\n\t_ = errors.As(nil, &cp.Endpoints[0])\n\tsvc.PtrTable = nil\n}\n",
		},
		{
			name:        "cross_pkg_runtime_setfinalizer_revokes",
			consumerSrc: "package app\nimport (\n\t\"runtime\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\truntime.SetFinalizer(svc.PtrTable, nil)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_cmp_or_any_revokes",
			consumerSrc: "package app\nimport (\n\t\"cmp\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ta := cmp.Or[any](svc.PtrTable, nil)\n\treflect.ValueOf(a).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_append_slice_any_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ts := append([]any(nil), svc.PtrTable)\n\treflect.ValueOf(s[0]).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_map_any_key_index_revokes",
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tm := map[any]int{}\n\tm[svc.PtrTable] = 1\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "cross_pkg_non_empty_interface_carrier_box_revokes",
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ P *desc.RouteTable }\nfunc (holder) String() string { return \"\" }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar s fmt.Stringer = holder{P: svc.PtrTable}\n\treflect.ValueOf(s).Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_non_empty_interface_box_and_reflect_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (holder) String() string { return "" }
func Wrap() fmt.Stringer { return holder{P: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\treflect.ValueOf(wrap.Wrap()).Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_upward_global_stash_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/stash",
					src: `package stash
var Saved any
func Put(x ...any) {
	if len(x) > 0 {
		Saved = x[0]
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/stash", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/stash"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Stash() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	stash.Put(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/stash\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\twrap.Stash()\n\treflect.ValueOf(stash.Saved).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_two_call_iface_global_swap_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/swap",
					src: `package swap
import "fmt"
var saved fmt.Stringer
func Call(x ...any) {
	if len(x) > 0 {
		if out, ok := x[0].(*any); ok {
			*out = saved
		} else if s, ok := x[0].(fmt.Stringer); ok {
			saved = s
		}
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/swap", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/swap"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Stash() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	swap.Call(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/swap\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\twrap.Stash()\n\tvar out any\n\tswap.Call(&out)\n\treflect.ValueOf(out).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_stdlib_json_unmarshal_sink_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/jmut",
					src: `package jmut
import "encoding/json"
func Apply(x ...any) {
	if len(x) > 0 {
		_ = json.Unmarshal([]byte("{}"), x[0])
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/jmut", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/jmut"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Mut() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	jmut.Apply(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/jmut\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = jmut.Apply\n\twrap.Mut()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_unexported_struct_field_smuggle_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/smug",
					src: `package smug
type myErr struct{ args []any }
func (*myErr) Error() string { return "err" }
func New(x ...any) error { return &myErr{args: x} }
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/smug", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/smug"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func WrapErr() error {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	return smug.New(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/smug\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = smug.New\n\terr := wrap.WrapErr()\n\t_ = reflect.ValueOf(err).Elem().UnsafePointer()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_panic_channel_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/pchan",
					src: `package pchan
func Throw(x ...any) {
	if len(x) > 0 {
		panic(x[0])
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/pchan", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/pchan"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Boom() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	pchan.Throw(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/pchan\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = pchan.Throw\n\tfunc() {\n\t\tdefer func() {\n\t\t\tif r := recover(); r != nil {\n\t\t\t\treflect.ValueOf(r).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t\t\t}\n\t\t}()\n\t\twrap.Boom()\n\t}()\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "composite_wrapping_non_empty_iface_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ P *desc.RouteTable }\nfunc (*holder) String() string { return \"\" }\ntype outer struct{ S fmt.Stringer }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar s fmt.Stringer = &holder{P: svc.PtrTable}\n\treflect.ValueOf(outer{S: s}).Field(0).Elem().Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "indirect_call_any_param_box_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/stash",
					src: `package stash
import "reflect"
func Mut(x any) { reflect.ValueOf(x).Elem().Field(0).Elem().Field(0).SetString("evil") }
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/stash", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/stash"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Run() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	fn := stash.Mut
	fn(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/stash\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = stash.Mut\n\twrap.Run()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "composite_slice_any_arg_to_imported_pkg_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/stash",
					src: `package stash
import "reflect"
func MutSlice(xs []any) { reflect.ValueOf(xs[0]).Elem().Field(0).Elem().Field(0).SetString("evil") }
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/stash", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/stash"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Run() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	xs := []any{s}
	stash.MutSlice(xs)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/stash\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = stash.MutSlice\n\twrap.Run()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_any_helper_bridge_error_wrapper_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/bridge",
					src: `package bridge
import "fmt"
type WrappedErr struct{ Inner fmt.Stringer }
func (*WrappedErr) Error() string { return "" }
func Wrap(x any) error { return &WrappedErr{Inner: x.(fmt.Stringer)} }
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/bridge", "example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/bridge"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "" }
func Get() error {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	return bridge.Wrap(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/bridge\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = bridge.Wrap\n\terr := wrap.Get()\n\treflect.ValueOf(err).Elem().Field(0).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "confined_sync_map_non_empty_iface_assert_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"reflect\"\n\t\"sync\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ P *desc.RouteTable }\nfunc (*holder) String() string { return \"\" }\nvar sm sync.Map\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tsm.Store(\"k\", &holder{P: svc.PtrTable})\n\tif v, ok := sm.Load(\"k\"); ok {\n\t\ts := v.(fmt.Stringer)\n\t\treflect.ValueOf(s).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t}\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "sync_map_comma_ok_any_assert_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"sync\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nvar sm sync.Map\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tsm.Store(\"k\", svc.PtrTable)\n\tif v, ok := sm.Load(\"k\"); ok {\n\t\tif a, ok2 := v.(any); ok2 {\n\t\t\treflect.ValueOf(a).Elem().Field(0).SetString(\"evil\")\n\t\t}\n\t}\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "confined_context_key_non_empty_iface_assert_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"fmt\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype ctxKey struct{}\ntype holder struct{ P *desc.RouteTable }\nfunc (*holder) String() string { return \"\" }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := context.WithValue(context.Background(), ctxKey{}, &holder{P: svc.PtrTable})\n\tif s, ok := ctx.Value(ctxKey{}).(fmt.Stringer); ok {\n\t\treflect.ValueOf(s).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t}\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "untyped_context_key_roundtrip_revokes",
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype ctxKey struct{}\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := context.WithValue(context.Background(), ctxKey{}, svc.PtrTable)\n\tv := ctx.Value(ctxKey{})\n\treflect.ValueOf(v).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unexported_holder_field_reflect_newat_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ p *desc.RouteTable }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar a any = &holder{p: svc.PtrTable}\n\tf := reflect.ValueOf(a).Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_unexported_holder_field_reflect_newat_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func Box() any { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tf := reflect.ValueOf(wrap.Box()).Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "by_value_substruct_on_method_bearing_ptr_reflect_revokes",
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ Sub desc.RouteTable }\nfunc (*holder) String() string { return \"\" }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\th := holder{Sub: svc.ValTable}\n\tvar s fmt.Stringer = &h\n\treflect.ValueOf(s).Elem().Field(0).Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "zero_arg_generic_factory_returning_mutator_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
func MakeMutator[T any]() func(*T) {
	return func(p *T) {
		var z T
		*p = z
	}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tmut := genmut.MakeMutator[desc.RouteTable]()\n\tmut(svc.PtrTable)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "atomic_store_pointer_raw_unsafe_laundering_revokes",
			consumerSrc: "package app\nimport (\n\t\"sync/atomic\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar slot unsafe.Pointer\n\tatomic.StorePointer(&slot, unsafe.Pointer(svc.PtrTable))\n\t(*shadow)(slot).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "atomic_load_pointer_raw_unsafe_laundering_revokes",
			consumerSrc: "package app\nimport (\n\t\"sync/atomic\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ttypedSlot := svc.PtrTable\n\traw := atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&typedSlot)))\n\t(*shadow)(raw).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unexported_slice_field_reflect_clear_without_unsafe_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ items []desc.EndpointSpec }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\th := &holder{items: svc.ValTable.Endpoints}\n\tvar a any = h\n\treflect.ValueOf(a).Elem().Field(0).Clear()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "spoofed_value_func_leaking_context_key_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"context"
	"example.com/desc"
	"example.com/svc"
)
type ctxKey struct{}
type holder struct{ p *desc.RouteTable }
var LeakedKey any
func WithValue(_ context.Context, k, _ any) context.Context {
	LeakedKey = k
	return nil
}
func Attach(ctx context.Context) context.Context {
	_ = WithValue(ctx, ctxKey{}, 0)
	return context.WithValue(ctx, ctxKey{}, &holder{p: svc.PtrTable})
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := wrap.Attach(context.Background())\n\tf := reflect.ValueOf(ctx.Value(wrap.LeakedKey)).Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_reflect_value_boundary_handoff_flagro_bypass_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func Extract() reflect.Value {
	return reflect.ValueOf(&holder{p: svc.PtrTable})
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tf := wrap.Extract().Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "confined_context_key_mismatched_lookup_assert_reflect_on_ctx_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/ctxwrap",
					imports: []string{"example.com/wrap"},
					src: `package ctxwrap
import (
	"context"
	"example.com/wrap"
)
type ctxKey struct{}
type otherIface interface{ Other() }
func Unused(ctx context.Context) { _ = ctx.Value(ctxKey{}).(otherIface) }
func Attach(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, wrap.Box())
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/ctxwrap\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := ctxwrap.Attach(context.Background())\n\tf := reflect.ValueOf(ctx).Elem().Field(1).Elem().Elem().Field(0)\n\t(*shadowRoute)(f.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_reflect_value_field_handoff_clear_without_local_field_call_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ items []desc.EndpointSpec }
func ExtractField() reflect.Value {
	return reflect.ValueOf(&holder{items: svc.ValTable.Endpoints}).Elem().Field(0)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\twrap.ExtractField().Clear()\n\tsvc.PtrTable = nil\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_reflect_valueof_pointer_method_unsafe_cast_without_field_call_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Get() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\traw := unsafe.Pointer(reflect.ValueOf(wrap.Get()).Pointer())\n\tp := *(*unsafe.Pointer)(raw)\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "unexported_struct_wrapping_reflect_value_handoff_bypass_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ items []desc.EndpointSpec }
type RVBox struct{ v reflect.Value }
func Extract() RVBox {
	return RVBox{v: reflect.ValueOf(&holder{items: svc.ValTable.Endpoints}).Elem().Field(0)}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tb := wrap.Extract()\n\t(*reflect.Value)(unsafe.Pointer(&b)).Clear()\n\tsvc.PtrTable = nil\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "range_over_reflect_value_overwriting_new_born_local_pointer_bypass_revokes",
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ p *desc.RouteTable }\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := reflect.New(reflect.TypeFor[int]())\n\tfor _, rv = range []reflect.Value{reflect.ValueOf(&holder{p: svc.PtrTable})} {\n\t\tptr := rv.Elem().Field(0).UnsafePointer()\n\t\t(*shadowRoute)(ptr).Name = \"evil\"\n\t}\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unexported_iface_field_single_pkg_reflect_clear_without_unsafe_revokes",
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype holder struct{ items []desc.EndpointSpec }\nfunc (*holder) String() string { return \"\" }\ntype outer struct{ s fmt.Stringer }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\to := outer{s: &holder{items: svc.ValTable.Endpoints}}\n\treflect.ValueOf(&o).Elem().Field(0).Elem().Elem().Field(0).Clear()\n\tsvc.PtrTable = nil\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_unexported_iface_field_any_erasure_and_flagro_bypass_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "" }
type outer struct{ s fmt.Stringer }
func Box() any { return outer{s: &holder{p: svc.PtrTable}} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tf := reflect.ValueOf(wrap.Box()).Field(0).Elem().Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "split_pkg_non_variadic_any_stash_and_downstream_flagro_bypass_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/stash",
					src: `package stash
var Saved any
func Put(x any) { Saved = x }
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/stash", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/stash"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "" }
func Run() {
	var s fmt.Stringer = &holder{p: svc.PtrTable}
	stash.Put(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/stash\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\twrap.Run()\n\tf := reflect.ValueOf(stash.Saved).Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "custom_context_value_method_stealing_unexported_key_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/thief",
					src: `package thief
import "context"
var Stolen any
type Ctx struct{ context.Context }
func (c *Ctx) Value(k any) any {
	Stolen = k
	return c.Context.Value(k)
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"context"
	"example.com/desc"
	"example.com/svc"
)
type ctxKey struct{}
type holder struct{ P *desc.RouteTable }
func Attach(ctx context.Context) context.Context {
	out := context.WithValue(ctx, ctxKey{}, &holder{P: svc.PtrTable})
	_ = out.Value(ctxKey{}).(*holder)
	return out
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/thief\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := wrap.Attach(&thief.Ctx{Context: context.Background()})\n\tv := ctx.Value(thief.Stolen)\n\treflect.ValueOf(v).Elem().Field(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "confined_context_key_reflect_flagro_bypass_on_context_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"context"
	"example.com/desc"
	"example.com/svc"
)
type ctxKey struct{}
type holder struct{ p *desc.RouteTable }
func Attach(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &holder{p: svc.PtrTable})
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"context\"\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tctx := wrap.Attach(context.Background())\n\tf := reflect.ValueOf(ctx).Elem().Field(1).Elem().Elem().Field(0)\n\treflect.NewAt(f.Type().Elem(), f.UnsafePointer()).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "unsafe_pointer_on_non_empty_iface_header_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ts := wrap.Box()\n\thdr := (*[2]unsafe.Pointer)(unsafe.Pointer(&s))\n\tp := *(*unsafe.Pointer)(hdr[1])\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "unsafe_pointer_on_fresh_composite_wrapping_iface_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\thdr := (*[2]unsafe.Pointer)(unsafe.Pointer(&struct{ S fmt.Stringer }{S: wrap.Box()}))\n\tp := *(*unsafe.Pointer)(hdr[1])\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "unsafe_slicedata_on_fresh_slice_of_non_empty_iface_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\traw := unsafe.Pointer(unsafe.SliceData([]fmt.Stringer{wrap.Box()}))\n\thdr := (*[2]unsafe.Pointer)(raw)\n\tp := *(*unsafe.Pointer)(hdr[1])\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "fresh_arg_generic_callee_stashing_type_mutator_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/genmut",
					src: `package genmut
import "fmt"
var Mut func(fmt.Stringer)
func Install[T any](_ *T) {
	Mut = func(s fmt.Stringer) {
		var z T
		*s.(interface{ Get() *T }).Get() = z
	}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/desc\"\n\t\"example.com/genmut\"\n\t\"example.com/svc\"\n)\ntype holder struct{ P *desc.RouteTable }\nfunc (h *holder) String() string      { return \"ok\" }\nfunc (h *holder) Get() *desc.RouteTable { return h.P }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tgenmut.Install(&desc.RouteTable{})\n\tvar s fmt.Stringer = &holder{P: svc.PtrTable}\n\tgenmut.Mut(s)\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_unboxed_any_caller_flagro_bypass_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var nilType = typeOf(nil)
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
}
type Value rawVal
func ValueOfStringer(s fmt.Stringer) Value {
	var v any = s
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data}
}
func (v Value) getIface() (x any) {
	*(*ifaceHeader)(unsafe.Pointer(&x)) = ifaceHeader{Type: v.typ, Data: v.ptr}
	return x
}
func (v Value) Interface() any {
	switch v.typ {
	case nilType:
		return nil
	default:
		return v.getIface()
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc", "example.com/unionpkg"},
					src: `package wrap
import (
	"example.com/desc"
	"example.com/svc"
	"example.com/unionpkg"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() unionpkg.Value { return unionpkg.ValueOfStringer(&holder{p: svc.PtrTable}) }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tf := reflect.ValueOf(wrap.Box().Interface()).Elem().Field(0)\n\t(*shadow)(f.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_header_word1_data_read_in_typeof_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Data }
var nilType = typeOf(nil)
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
}
type Value rawVal
func ValueOfStringer(s fmt.Stringer) Value {
	var v any = s
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data}
}
func (v Value) getIface() (x any) {
	*(*ifaceHeader)(unsafe.Pointer(&x)) = ifaceHeader{Type: v.typ, Data: v.ptr}
	return x
}
func (v Value) Interface() any {
	switch v.typ {
	case nilType:
		return nil
	default:
		return v.getIface()
	}
}
`,
				},
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc", "example.com/unionpkg"},
					src: `package wrap
import (
	"example.com/desc"
	"example.com/svc"
	"example.com/unionpkg"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() unionpkg.Value { return unionpkg.ValueOfStringer(&holder{p: svc.PtrTable}) }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\t_ = wrap.Box().Interface()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_getbytes_without_bytestype_case_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) BytesUnguarded() []byte { return v.getBytes() }\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\tb := u.BytesUnguarded()\n\tp := *(*unsafe.Pointer)(unsafe.Pointer(&b[0]))\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_fallthrough_into_bytestype_case_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) BadBytes() []byte {\n\tswitch v.typ {\n\tdefault:\n\t\tfallthrough\n\tcase bytesType:\n\t\treturn v.getBytes()\n\t}\n}\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\tb := u.BadBytes()\n\tp := *(*unsafe.Pointer)(unsafe.Pointer(&b[0]))\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_ptr_receiver_mutates_typ_to_bytestype_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v *rawVal) Overwrite(other rawVal) { *v = other }\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) Bytes() []byte {\n\tswitch v.typ {\n\tcase bytesType:\n\t\treturn v.getBytes()\n\tdefault:\n\t\tpanic(\"no\")\n\t}\n}\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\tu.Overwrite(pack([]byte(\"12345678\")))\n\t_ = u.Bytes()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "sync_pool_unchecked_get_any_reflect_flagro_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/poolwrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package poolwrap
import (
	"fmt"
	"sync"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
type entry struct{ s fmt.Stringer }
var p = sync.Pool{New: func() any { return new(entry) }}
func Leak() any {
	p.Put(&entry{s: &holder{p: svc.PtrTable}})
	return p.Get()
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/poolwrap\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := reflect.ValueOf(poolwrap.Leak()).Elem().Field(0).Elem().Elem().Field(0)\n\t(*shadow)(rv.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "sync_pool_local_get_var_unasserted_return_reflect_flagro_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/poolwrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package poolwrap
import (
	"fmt"
	"sync"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
type entry struct{ s fmt.Stringer }
var p = sync.Pool{New: func() any { return new(entry) }}
func Typed() *entry {
	v := p.Get()
	return v.(*entry)
}
func Leak() any {
	p.Put(&entry{s: &holder{p: svc.PtrTable}})
	v := p.Get()
	return v
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/poolwrap\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := reflect.ValueOf(poolwrap.Leak()).Elem().Field(0).Elem().Elem().Field(0)\n\t(*shadow)(rv.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "non_const_runtime_bool_and_nil_guard_fallthrough_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/nilwrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package nilwrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
var runtimeFlag = false
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
type outer struct{ s fmt.Stringer }
func MaybeNil(o *outer) any {
	if runtimeFlag && o != nil {
		return nil
	}
	return o
}
func Box() any {
	return MaybeNil(&outer{s: &holder{p: svc.PtrTable}})
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/nilwrap\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := reflect.ValueOf(nilwrap.Box()).Elem().Field(0).Elem().Elem().Field(0)\n\t(*shadow)(rv.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "goto_past_nil_guard_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/gotowrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package gotowrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
var bypass = true
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
type outer struct{ s fmt.Stringer }
func Sneak(o *outer) any {
	if bypass {
		goto afterGuard
	}
	if o != nil {
		return nil
	}
afterGuard:
	return o
}
func Box() any {
	return Sneak(&outer{s: &holder{p: svc.PtrTable}})
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/gotowrap\"\n\t\"example.com/svc\"\n)\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := reflect.ValueOf(gotowrap.Box()).Elem().Field(0).Elem().Elem().Field(0)\n\t(*shadow)(rv.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_struct_conversion_extracts_ptr_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) Bytes() []byte {\n\tswitch v.typ {\n\tcase bytesType:\n\t\treturn v.getBytes()\n\tdefault:\n\t\tpanic(\"no\")\n\t}\n}\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\te := struct {\n\t\ttyp unsafe.Pointer\n\t\tptr unsafe.Pointer\n\t\tnum uint64\n\t}(u)\n\tp := *(*unsafe.Pointer)(e.ptr)\n\t(*shadow)(p).Name = \"evil\"\n\t_ = u.Bytes\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_unguarded_unsafe_string_stringdata_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) leakAsString() string { return unsafe.String((*byte)(v.ptr), v.num) }\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ts := pack(wrap.Box()).leakAsString()\n\tp := *(*unsafe.Pointer)(unsafe.Pointer(unsafe.StringData(s)))\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_embedded_zero_sized_promoted_ptr_method_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype pad [0]byte\nfunc (p *pad) corrupt() { *(*unsafe.Pointer)(unsafe.Pointer(p)) = bytesType }\ntype rawVal struct {\n\tpad\n\ttyp     unsafe.Pointer\n\tptr     unsafe.Pointer\n\tcorrupt uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, corrupt: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.corrupt) }\nfunc (v rawVal) Bytes() []byte {\n\tswitch v.typ {\n\tcase bytesType:\n\t\treturn v.getBytes()\n\tdefault:\n\t\tpanic(\"no\")\n\t}\n}\ntype shadow struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\tu.pad.corrupt()\n\tb := u.Bytes()\n\tp := *(*unsafe.Pointer)(unsafe.Pointer(&b[0]))\n\t(*shadow)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "provably_nil_named_slice_auto_addr_ptr_method_fill_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/slwrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package slwrap
import (
	"example.com/desc"
	"example.com/svc"
)
type holderSlice []*desc.RouteTable
func (s *holderSlice) Fill(p *desc.RouteTable) { *s = holderSlice{p} }
func Sneak() any {
	var s holderSlice
	if s != nil {
		return nil
	}
	s.Fill(svc.PtrTable)
	return s
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/slwrap\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\treflect.ValueOf(slwrap.Sneak()).Index(0).Elem().Field(0).SetString(\"evil\")\n\t_, _ = Export()\n}\n",
		},
		{
			name: "capsule_reflect_safe_pkg_foreign_holder_static_composite_revokes",
			descSrc: strings.Replace(baseSchemaSrc, "package desc\n", "package desc\nimport (\n\t\"fmt\"\n\t\"sync\"\n\t\"sync/atomic\"\n\t\"unsafe\"\n)\n", 1) + `
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type Holder struct {
	p *RouteTable
}
func (*Holder) String() string { return "h" }
func NewHolder(r *RouteTable) *Holder { return &Holder{p: r} }
type shadowRoute struct {
	Name string
}
func Corrupt(s fmt.Stringer) {
	hdr := (*[2]unsafe.Pointer)(unsafe.Pointer(&s))
	p := *(*unsafe.Pointer)(hdr[1])
	(*shadowRoute)(p).Name = "evil"
}
`,
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar s fmt.Stringer = desc.NewHolder(svc.PtrTable)\n\tdesc.Corrupt(s)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "outer_addressed_local_value_struct_mutated_in_closure_revokes",
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nvar escaped *desc.RouteTable\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tvar cp desc.RouteTable\n\tescaped = &cp\n\tfn := func() { cp.Name = \"evil\" }\n\tfn()\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unaddressed_local_value_struct_slice_clear_revokes",
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcp := svc.ValTable\n\tclear(cp.Endpoints)\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unaddressed_local_value_struct_slice_index_field_write_revokes",
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcp := svc.ValTable\n\tcp.Endpoints[0].Route = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unnamed_struct_embedded_ptr_field_write_revokes",
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcp := struct{ *desc.RouteTable }{RouteTable: svc.PtrTable}\n\tcp.Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name:        "unsafe_pointer_on_struct_param_carrying_ptr_field_revokes",
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype box struct{ p *desc.RouteTable }\ntype shadowRoute struct{ Name string }\ntype shadowBox struct{ p *shadowRoute }\nfunc corrupt(b *box) { (*shadowBox)(unsafe.Pointer(b)).p.Name = \"evil\" }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcorrupt(&box{p: svc.PtrTable})\n\t_, _ = Export()\n}\n",
		},
		{
			name: "unsafe_pointer_on_struct_param_carrying_iface_slice_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceSliceBox struct{ s []fmt.Stringer }\ntype rawSliceBox struct{ s [][2]unsafe.Pointer }\ntype shadowRoute struct{ Name string }\nfunc corrupt(b *ifaceSliceBox) {\n\traw := (*rawSliceBox)(unsafe.Pointer(b))\n\tp := *(*unsafe.Pointer)(raw.s[0][1])\n\t(*shadowRoute)(p).Name = \"evil\"\n}\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tcorrupt(&ifaceSliceBox{s: []fmt.Stringer{wrap.Box()}})\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_subfield_addr_overwrite_typ_tag_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype rawVal struct {\n\tpad [0]byte\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) Bytes() []byte {\n\tswitch v.typ {\n\tcase bytesType:\n\t\treturn v.getBytes()\n\tdefault:\n\t\tpanic(\"no\")\n\t}\n}\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\t*(*unsafe.Pointer)(unsafe.Pointer(&u.pad)) = bytesType\n\tb := u.Bytes()\n\tp := *(*unsafe.Pointer)(unsafe.Pointer(&b[0]))\n\t(*shadowRoute)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_ptr_to_struct_conversion_extracts_ptr_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype ifaceHeader struct {\n\tType unsafe.Pointer\n\tData unsafe.Pointer\n}\nfunc typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }\nvar bytesType = typeOf(*new([]byte))\ntype rawVal struct {\n\ttyp unsafe.Pointer\n\tptr unsafe.Pointer\n\tnum uint64\n}\nfunc pack(v any) rawVal {\n\tp := (*ifaceHeader)(unsafe.Pointer(&v))\n\treturn rawVal{typ: p.Type, ptr: p.Data, num: 8}\n}\nfunc (v rawVal) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }\nfunc (v rawVal) Bytes() []byte {\n\tswitch v.typ {\n\tcase bytesType:\n\t\treturn v.getBytes()\n\tdefault:\n\t\tpanic(\"no\")\n\t}\n}\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := pack(wrap.Box())\n\tep := (*struct {\n\t\ttyp unsafe.Pointer\n\t\tptr unsafe.Pointer\n\t\tnum uint64\n\t})(&u)\n\tp := *(*unsafe.Pointer)(ep.ptr)\n\t(*shadowRoute)(p).Name = \"evil\"\n\t_ = u.Bytes\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_cross_pkg_reflect_valueof_field_pointer_without_interface_method_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var bytesType = typeOf(*new([]byte))
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func pack(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data, num: 8}
}
func ValueOfStringer(s fmt.Stringer) Value { return pack(s) }
func (v Value) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("no")
	}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/unionpkg\"\n\t\"example.com/wrap\"\n)\ntype shadowRoute struct{ Name string }\ntype shadowHolder struct{ p *shadowRoute }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := unionpkg.ValueOfStringer(wrap.Box())\n\traw := reflect.ValueOf(u).Field(1).UnsafePointer()\n\t(*shadowHolder)(raw).p.Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "opaque_foreign_struct_non_capsule_pkg_pointer_arg_iface_header_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/evilop",
					src: `package evilop
import (
	"fmt"
	"unsafe"
)
type Pointer unsafe.Pointer
type Opaque struct{ s fmt.Stringer }
type shadowRoute struct{ Name string }
func Make(s fmt.Stringer) Opaque { return Opaque{s: s} }
func Corrupt(p Pointer) {
	hdr := (*[2]unsafe.Pointer)(unsafe.Pointer(p))
	raw := *(*unsafe.Pointer)(hdr[1])
	(*shadowRoute)(raw).Name = "evil"
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/evilop\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype carrier struct{ op evilop.Opaque }\nfunc passToEvil(c *carrier) { evilop.Corrupt(evilop.Pointer(c)) }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tpassToEvil(&carrier{op: evilop.Make(wrap.Box())})\n\t_, _ = Export()\n}\n",
		},
		{
			name: "foreign_ptr_wrapper_non_offset0_carrier_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/cappkg",
					src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func MessageStateOf(p Pointer) *messageState {
	return (*messageState)(unsafe.Pointer(p))
}
func (ms *messageState) HasInfo() bool {
	return atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi))) != nil
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/cappkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype badCarrier struct {\n\ts     fmt.Stringer\n\tstate cappkg.MessageState\n}\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tc := &badCarrier{s: wrap.Box()}\n\t_ = cappkg.MessageStateOf(cappkg.Pointer(c)).HasInfo()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "foreign_ptr_wrapper_mismatched_store_message_info_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/cappkg",
					src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func MessageStateOf(p Pointer) *messageState {
	return (*messageState)(unsafe.Pointer(p))
}
func (ms *messageState) StoreMessageInfo(mi *MessageInfo) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi)), unsafe.Pointer(mi))
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/cappkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype spoofCarrier struct {\n\tstate cappkg.MessageState\n\ts     fmt.Stringer\n}\nvar spoofMI cappkg.MessageInfo\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tc := &spoofCarrier{s: wrap.Box()}\n\tcappkg.MessageStateOf(cappkg.Pointer(c)).StoreMessageInfo(&spoofMI)\n\t_, _ = Export()\n}\n",
		},
		{
			name: "foreign_atomic_load_pointer_mismatched_slot_types_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/cappkg",
					src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
func AtomicLoadPointer(src, dst Pointer) {
	*(*unsafe.Pointer)(unsafe.Pointer(dst)) = atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(src)))
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/cappkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tsrc := svc.PtrTable\n\tvar dst *shadowRoute\n\tcappkg.AtomicLoadPointer(cappkg.Pointer(&src), cappkg.Pointer(&dst))\n\tdst.Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "foreign_atomic_load_pointer_spoofed_body_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/cappkg",
					src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type rawString struct {
	Data unsafe.Pointer
	Len  int
}
func AtomicLoadPointer(src, dst Pointer) {
	*(*unsafe.Pointer)(dst) = atomic.LoadPointer((*unsafe.Pointer)(src))
	*(*rawString)(*(*unsafe.Pointer)(src)) = rawString{}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/cappkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tsrc := svc.PtrTable\n\tvar dst *desc.RouteTable\n\tcappkg.AtomicLoadPointer(cappkg.Pointer(&src), cappkg.Pointer(&dst))\n\t_, _ = Export()\n}\n",
		},
		{
			name: "foreign_ptr_wrapper_non_capsule_opaque_struct_in_capsule_pkg_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/cappkg",
					src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type NonCapsule struct {
	tag int
}
type Opaque struct {
	nc *NonCapsule
}
type opaquePriv Opaque
func WrapOpaque(p Pointer) *opaquePriv {
	return (*opaquePriv)(unsafe.Pointer(p))
}
type rawString struct {
	Data unsafe.Pointer
	Len  int
}
func (op *opaquePriv) CorruptNextIface() {
	hdr := (*[2]unsafe.Pointer)(unsafe.Pointer(uintptr(unsafe.Pointer(op)) + unsafe.Sizeof(*op)))
	*(*rawString)(*(*unsafe.Pointer)(hdr[1])) = rawString{}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"fmt\"\n\t\"example.com/cappkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype carrier struct {\n\top cappkg.Opaque\n\ts  fmt.Stringer\n}\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tc := &carrier{s: wrap.Box()}\n\tcappkg.WrapOpaque(cappkg.Pointer(c)).CorruptNextIface()\n\t_, _ = Export()\n}\n",
		},
		{
			name: "cross_pkg_reflect_valueof_factory_without_local_mutator_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/rvpkg",
					src: `package rvpkg
import (
	"fmt"
	"reflect"
)
func ToValue(s fmt.Stringer) reflect.Value {
	return reflect.ValueOf(s)
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"example.com/desc\"\n\t\"example.com/rvpkg\"\n\t\"example.com/svc\"\n\t\"example.com/wrap\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\trv := rvpkg.ToValue(wrap.Box()).Elem().Field(0)\n\t(*shadowRoute)(rv.UnsafePointer()).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_cross_pkg_unsafe_pointer_addr_without_reflect_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var bytesType = typeOf(*new([]byte))
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func pack(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data, num: 8}
}
func ValueOfStringer(s fmt.Stringer) Value { return pack(s) }
func (v Value) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("no")
	}
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n\t\"example.com/unionpkg\"\n\t\"example.com/wrap\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\tu := unionpkg.ValueOfStringer(wrap.Box())\n\traw := (*[2]unsafe.Pointer)(unsafe.Pointer(&u))[1]\n\tp := *(*unsafe.Pointer)(raw)\n\t(*shadowRoute)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_boxed_in_non_empty_iface_reflected_field_pointer_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type Token interface {
	IsToken()
}
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var bytesType = typeOf(*new([]byte))
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func (Value) IsToken() {}
func pack(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data, num: 8}
}
func ValueOfStringer(s fmt.Stringer) Value { return pack(s) }
func (v Value) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("no")
	}
}
`,
				},
				{
					pkgPath: "example.com/boxpkg",
					imports: []string{"example.com/unionpkg", "example.com/wrap"},
					src: `package boxpkg
import (
	"example.com/unionpkg"
	"example.com/wrap"
)
func MakeToken() unionpkg.Token {
	return unionpkg.ValueOfStringer(wrap.Box())
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n\t\"example.com/boxpkg\"\n\t\"example.com/desc\"\n\t\"example.com/svc\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\ttok := boxpkg.MakeToken()\n\traw := unsafe.Pointer(reflect.ValueOf(tok).Field(1).Pointer())\n\tp := *(*unsafe.Pointer)(raw)\n\t(*shadowRoute)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
		{
			name: "eface_union_boxed_in_non_empty_iface_two_pkg_uintptr_pointer_split_revokes",
			extraSpecs: []orderedPkgSpec{
				{
					pkgPath: "example.com/wrap",
					imports: []string{"example.com/desc", "example.com/svc"},
					src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`,
				},
				{
					pkgPath: "example.com/unionpkg",
					src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type Token interface {
	IsToken()
}
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var bytesType = typeOf(*new([]byte))
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func (Value) IsToken() {}
func pack(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data, num: 8}
}
func ValueOfStringer(s fmt.Stringer) Value { return pack(s) }
func (v Value) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("no")
	}
}
`,
				},
				{
					pkgPath: "example.com/reflpkg",
					imports: []string{"example.com/unionpkg", "example.com/wrap"},
					src: `package reflpkg
import (
	"reflect"
	"example.com/unionpkg"
	"example.com/wrap"
)
func ExtractAddr() uintptr {
	var tok unionpkg.Token = unionpkg.ValueOfStringer(wrap.Box())
	return reflect.ValueOf(tok).Field(1).Pointer()
}
`,
				},
			},
			consumerSrc: "package app\nimport (\n\t\"unsafe\"\n\t\"example.com/desc\"\n\t\"example.com/reflpkg\"\n\t\"example.com/svc\"\n)\ntype shadowRoute struct{ Name string }\nfunc Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }\nfunc init() {\n\traw := unsafe.Pointer(reflpkg.ExtractAddr())\n\tp := *(*unsafe.Pointer)(raw)\n\t(*shadowRoute)(p).Name = \"evil\"\n\t_, _ = Export()\n}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dSrc := baseSchemaSrc
			if tc.descSrc != "" {
				dSrc = tc.descSrc
			}
			pSrc := baseProviderSrc
			if tc.providerSrc != "" {
				pSrc = tc.providerSrc
			}
			cSrc := baseConsumerSrc
			if tc.consumerSrc != "" {
				cSrc = tc.consumerSrc
			}
			appImports := []string{"example.com/desc", "example.com/svc"}
			for _, ex := range tc.extraSpecs {
				appImports = append(appImports, ex.pkgPath)
			}
			specs := []orderedPkgSpec{
				{pkgPath: "example.com/desc", src: dSrc},
				{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: pSrc},
			}
			specs = append(specs, tc.extraSpecs...)
			specs = append(specs, orderedPkgSpec{pkgPath: "example.com/app", imports: appImports, src: cSrc})
			meta, _, facts := mustTypecheckOrderedDAG(t, specs)
			if (tc.consumerSrc == "" || tc.name == "stdlib_methodless_struct_rejected") && len(facts["example.com/svc"][0].StaticCompositeGlobals) != 0 {
				t.Fatalf("%s unexpectedly derived StaticCompositeGlobals in producer Fact: %+v", tc.name, facts["example.com/svc"][0].StaticCompositeGlobals)
			}
			ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
			if ac.State.Downgraded == "" {
				t.Fatalf("%s unexpectedly discharged cleanly: nvd=%+v", tc.name, ac.NonVouchDischarged)
			}
			if ac.NonVouchDischarged["example.com/svc.ValTable"] || ac.NonVouchDischarged["example.com/svc.PtrTable"] {
				t.Fatalf("%s left ValTable or PtrTable in NonVouchDischarged: %+v", tc.name, ac.NonVouchDischarged)
			}
		})
	}

	t.Run("capsule_guard_struct_scope_excludes_non_capsule_struct", func(t *testing.T) {
		routeRef := syntaxutil.TypeRef{Pkg: "example.com/desc", Name: "RouteTable"}
		capRef := syntaxutil.TypeRef{Pkg: "example.com/cappkg", Name: "MessageInfo"}
		meta := []GraphPackage{
			{ImportPath: "example.com/app", PkgPath: "example.com/app", Imports: []string{"example.com/cappkg", "example.com/svc"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/cappkg", PkgPath: "example.com/cappkg", Class: PinnedPackage, Pin: "example.com/cappkg@v1.0.0"},
			{ImportPath: "example.com/svc", PkgPath: "example.com/svc", Imports: []string{"example.com/desc"}, Class: PinnedPackage, Pin: "example.com/svc@v1.0.0"},
			{ImportPath: "example.com/desc", PkgPath: "example.com/desc", Class: PinnedPackage, Pin: "example.com/desc@v1.0.0"},
		}
		facts := map[string][]Fact{
			"example.com/app": {{
				Mutates: []string{"example.com/svc.PtrTable"},
				ConditionalStructMutations: []syntaxutil.ConditionalStructMutation{{
					Struct:                 routeRef,
					ForeignReflectPkg:      "example.com/cappkg",
					BoxedConcreteMethodSet: "String:func()()",
				}},
			}},
			"example.com/cappkg": {{
				LazyOnceCapsuleTypes: []syntaxutil.LazyOnceCapsuleType{{
					Type:               capRef,
					CapsuleReflectSafe: true,
				}},
				ReflectedIfaceMethodSets: []syntaxutil.ReflectedIfaceFact{{
					MethodSet: "String:func()()",
				}},
			}},
			"example.com/svc": {{
				Declares: []string{"example.com/svc.PtrTable"},
				StaticCompositeGlobals: []syntaxutil.StaticCompositeGlobalFact{{
					Key:        "example.com/svc.PtrTable",
					GuardTypes: []syntaxutil.TypeRef{routeRef},
				}},
			}},
			"example.com/desc": {{}},
		}
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
		if ac.State.Downgraded == "" || ac.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("ForeignReflectPkg exemption leaked beyond capsule GuardTypes onto RouteTable: state=%+v nvd=%+v", ac.State, ac.NonVouchDischarged)
		}
	})

	t.Run("capsule_reflect_safe_non_empty_iface_addr_and_composite_valueof", func(t *testing.T) {
		baseCap := `package cappkg
import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
var (
	_ = fmt.Sprint
	_ = reflect.TypeOf
	_ unsafe.Pointer
)
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
`
		pkgClean := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": baseCap})
		factClean := FactOf(true, pkgClean)
		if len(factClean.LazyOnceCapsuleTypes) == 0 {
			t.Fatalf("clean capsule package produced zero LazyOnceCapsuleTypes")
		}
		for _, ct := range factClean.LazyOnceCapsuleTypes {
			if !ct.CapsuleReflectSafe {
				t.Fatalf("clean capsule was not marked CapsuleReflectSafe: %+v", factClean.LazyOnceCapsuleTypes)
			}
		}

		for _, bad := range []struct {
			name  string
			extra string
		}{
			{
				name:  "unsafe_iface_addr_without_struct_cast",
				extra: "func RawData(s fmt.Stringer) unsafe.Pointer { return (*[2]unsafe.Pointer)(unsafe.Pointer(&s))[1] }\n",
			},
			{
				name:  "reflect_valueof_iface_slice_elem",
				extra: "func UnwrapSlice(s []fmt.Stringer) reflect.Value { return reflect.ValueOf(s).Index(0).Elem() }\n",
			},
			{
				name: "self_matching_reflect_typeof_on_iface_arg",
				extra: `type selfUnwrapper struct{ goType reflect.Type }
func NewSelfUnwrapper(s fmt.Stringer) *selfUnwrapper { return &selfUnwrapper{goType: reflect.TypeOf(s)} }
func (u *selfUnwrapper) Unwrap(s fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	if rv.Type() != u.goType {
		panic("mismatch")
	}
	return rv
}
`,
			},
			{
				name: "post_guard_iife_rv_reassignment",
				extra: `type iifeUnwrapper struct{ goType reflect.Type }
type localMsg struct{ x int }
func NewIIFEUnwrapper() *iifeUnwrapper { return &iifeUnwrapper{goType: reflect.TypeOf((*localMsg)(nil))} }
func (u *iifeUnwrapper) Unwrap(s fmt.Stringer, bad fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	if rv.Type() != u.goType {
		panic("mismatch")
	}
	func() {
		rv = reflect.ValueOf(any(bad))
	}()
	return rv
}
`,
			},
		} {
			pkgBad := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": baseCap + bad.extra})
			factBad := FactOf(true, pkgBad)
			if len(factBad.LazyOnceCapsuleTypes) == 0 {
				t.Fatalf("%s produced zero LazyOnceCapsuleTypes", bad.name)
			}
			for _, ct := range factBad.LazyOnceCapsuleTypes {
				if ct.CapsuleReflectSafe {
					t.Fatalf("%s unexpectedly marked CapsuleReflectSafe: %+v", bad.name, factBad.LazyOnceCapsuleTypes)
				}
			}
		}
	})

	t.Run("foreign_atomic_load_and_init_pointer_identical_slots_preserved", func(t *testing.T) {
		specs := []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{
				pkgPath: "example.com/cappkg",
				src: `package cappkg
import (
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
func AtomicLoadPointer(src, dst Pointer) {
	*(*unsafe.Pointer)(unsafe.Pointer(dst)) = atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(src)))
}
func AtomicInitializePointer(src, dst Pointer) {
	if !atomic.CompareAndSwapPointer((*unsafe.Pointer)(src), unsafe.Pointer(nil), *(*unsafe.Pointer)(dst)) {
		*(*unsafe.Pointer)(unsafe.Pointer(dst)) = atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(src)))
	}
}
`,
			},
			{
				pkgPath: "example.com/app",
				imports: []string{"example.com/cappkg", "example.com/desc", "example.com/svc"},
				src: `package app
import (
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
)
type opaqueSub struct {
	state cappkg.MessageState
	val   int
}
type opaqueParent struct {
	state cappkg.MessageState
	sub   *opaqueSub
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	p := &opaqueParent{}
	sv := &opaqueSub{val: 1}
	cappkg.AtomicInitializePointer(cappkg.Pointer(&p.sub), cappkg.Pointer(&sv))
	var rv *opaqueSub
	cappkg.AtomicLoadPointer(cappkg.Pointer(&p.sub), cappkg.Pointer(&rv))
	_, _ = Export()
}
`,
			},
		}
		meta, _, facts := mustTypecheckOrderedDAG(t, specs)
		ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
		if ac.State.Downgraded != "" {
			t.Fatalf("valid identical-slot AtomicLoadPointer/AtomicInitializePointer unexpectedly downgraded: %+v", ac.State)
		}
		if !ac.NonVouchDischarged["example.com/svc.ValTable"] || !ac.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("expected ValTable and PtrTable in NonVouchDischarged, got %+v", ac.NonVouchDischarged)
		}
	})

	t.Run("capsule_wrapper_offset_instantiation_and_multihop_cast_guards", func(t *testing.T) {
		baseWrap := `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) Elem() pointer { return pointer{p: *(*unsafe.Pointer)(p.p)} }
func (p pointer) SetString(v string) { *(*string)(p.p) = v }
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func (ms *messageState) pointer() pointer { return pointer{p: unsafe.Pointer(ms)} }
`
		miRef := syntaxutil.TypeRef{Pkg: "example.com/cappkg", Name: "MessageInfo"}
		pkgClean := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{
			"cap.go": baseWrap + `func UseApplied(ms *messageState, sf reflect.StructField) {
	ms.pointer().Apply(offsetOf(sf)).SetString("ok")
}
`,
		})
		factClean := FactOf(true, pkgClean)
		if slices.Contains(factClean.MutatedStructTypes, miRef) {
			t.Fatalf("clean offset-applied capsule wrapper unexpectedly marked MessageInfo mutated: %+v", factClean.MutatedStructTypes)
		}
		sawMsgCap := false
		for _, ct := range factClean.LazyOnceCapsuleTypes {
			if ct.Type.Name == "MessageInfo" {
				sawMsgCap = true
				if !ct.CapsuleReflectSafe {
					t.Fatalf("clean offset-applied capsule wrapper was not marked CapsuleReflectSafe: %+v", factClean.LazyOnceCapsuleTypes)
				}
			}
		}
		if !sawMsgCap {
			t.Fatalf("expected MessageInfo LazyOnceCapsuleType on clean capsule wrapper, got %+v", factClean.LazyOnceCapsuleTypes)
		}

		for _, mutCase := range []struct {
			name  string
			extra string
		}{
			{
				name:  "unoffset_base_pointer_elem_deref",
				extra: "func CorruptBase(ms *messageState) { ms.pointer().Elem().SetString(\"evil\") }\n",
			},
			{
				name:  "array_container_allocates_wrapper_by_value",
				extra: "var backing [1]messageState\nfunc LeakWrapper() *messageState { return &backing[0] }\n",
			},
			{
				name:  "make_slice_allocates_wrapper_by_value",
				extra: "func MakeWrappers() *messageState { s := make([]messageState, 1); return &s[0] }\n",
			},
		} {
			pkgBad := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": baseWrap + mutCase.extra})
			factBad := FactOf(true, pkgBad)
			if !slices.Contains(factBad.MutatedStructTypes, miRef) {
				t.Fatalf("%s failed to mark MessageInfo in MutatedStructTypes: %+v", mutCase.name, factBad.MutatedStructTypes)
			}
		}

		for _, castCase := range []struct {
			name  string
			extra string
		}{
			{
				name: "double_ptr_cast_to_mutated_struct",
				extra: `type targetS struct{ x int }
func MutateTarget(t *targetS) { t.x = 1 }
func CastDoublePtr(raw unsafe.Pointer) **targetS { return (**targetS)(raw) }
`,
			},
			{
				name: "array_ptr_cast_to_mutated_struct",
				extra: `type targetS struct{ x int }
func MutateTarget(t *targetS) { t.x = 1 }
func CastArrayPtr(raw unsafe.Pointer) *[1]targetS { return (*[1]targetS)(raw) }
`,
			},
		} {
			pkgBad := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": baseWrap + castCase.extra})
			factBad := FactOf(true, pkgBad)
			for _, ct := range factBad.LazyOnceCapsuleTypes {
				if ct.CapsuleReflectSafe {
					t.Fatalf("%s unexpectedly marked CapsuleReflectSafe despite unsafe cast reaching mutated struct: %+v", castCase.name, factBad.LazyOnceCapsuleTypes)
				}
			}
		}
	})

	t.Run("capsule_struct_or_guard_mutation_revokes_wrapper_and_foreign_reflect_exemptions", func(t *testing.T) {
		routeRef := syntaxutil.TypeRef{Pkg: "example.com/desc", Name: "RouteTable"}
		capRef := syntaxutil.TypeRef{Pkg: "example.com/cappkg", Name: "MessageInfo"}
		guardRef := syntaxutil.TypeRef{Pkg: "example.com/cappkg", Name: "Methods"}
		wrapParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/cappkg", Name: "Wrap"}, Index: 0}
		copyFn := syntaxutil.FuncKey{Pkg: "example.com/cappkg", Name: "AtomicLoadPointer"}
		meta := []GraphPackage{
			{ImportPath: "example.com/app", PkgPath: "example.com/app", Imports: []string{"example.com/cappkg", "example.com/svc"}, Class: MutableLocalPackage},
			{ImportPath: "example.com/cappkg", PkgPath: "example.com/cappkg", Class: PinnedPackage, Pin: "example.com/cappkg@v1.0.0"},
			{ImportPath: "example.com/svc", PkgPath: "example.com/svc", Imports: []string{"example.com/desc"}, Class: PinnedPackage, Pin: "example.com/svc@v1.0.0"},
			{ImportPath: "example.com/desc", PkgPath: "example.com/desc", Class: PinnedPackage, Pin: "example.com/desc@v1.0.0"},
		}
		for _, mutRef := range []syntaxutil.TypeRef{capRef, guardRef} {
			facts := map[string][]Fact{
				"example.com/app": {{
					Mutates:            []string{"example.com/svc.PtrTable"},
					MutatedStructTypes: []syntaxutil.TypeRef{mutRef},
					ConditionalStructMutations: []syntaxutil.ConditionalStructMutation{{
						Struct:                  routeRef,
						UnlessSafeCapsuleStruct: capRef,
						UnlessSafeCapsuleParam:  wrapParam,
					}},
				}},
				"example.com/cappkg": {{
					LazyOnceCapsuleTypes: []syntaxutil.LazyOnceCapsuleType{{
						Type:                   capRef,
						GuardTypes:             []syntaxutil.TypeRef{guardRef},
						CapsuleReflectSafe:     true,
						SafePtrWrapperParams:   []syntaxutil.ParamKey{wrapParam},
						SafeAtomicPtrCopyFuncs: []syntaxutil.FuncKey{copyFn},
					}},
				}},
				"example.com/svc": {{
					Declares: []string{"example.com/svc.PtrTable"},
					StaticCompositeGlobals: []syntaxutil.StaticCompositeGlobalFact{{
						Key:        "example.com/svc.PtrTable",
						GuardTypes: []syntaxutil.TypeRef{routeRef},
					}},
				}},
				"example.com/desc": {{}},
			}
			ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
			if ac.State.Downgraded == "" || ac.NonVouchDischarged["example.com/svc.PtrTable"] {
				t.Fatalf("mutating %s failed to revoke capsule wrapper exemption: state=%+v nvd=%+v", mutRef.Key(), ac.State, ac.NonVouchDischarged)
			}
		}
	})

	t.Run("cross_pkg_capsule_literal_sibling_field_and_internal_reflect_type_ctor_revoke", func(t *testing.T) {
		capRuntimeSrc := `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type Pointer unsafe.Pointer
type pointer struct{ p unsafe.Pointer }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
func (p pointer) AsIfaceOf(t reflect.Type) any { return p.AsValueOf(t).Interface() }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	fieldOff      offset
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.fieldOff = offsetOf(mi.GoReflectType.Elem().Field(1))
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func Wrap(p Pointer) *messageState { return (*messageState)(unsafe.Pointer(p)) }
func (ms *messageState) pointer() pointer { return pointer{p: unsafe.Pointer(ms)} }
func (ms *messageState) StoreMessageInfo(mi *MessageInfo) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi)), unsafe.Pointer(mi))
}
func (ms *messageState) LoadMessageInfo() *MessageInfo {
	return (*MessageInfo)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi))))
}
func (ms *messageState) MutateField1() {
	mi := ms.LoadMessageInfo()
	mi.initOnce()
	rv := ms.pointer().Apply(mi.fieldOff).AsValueOf(mi.GoReflectType.Elem().Field(1).Type).Elem()
	if rv.Kind() == reflect.Ptr && rv.Elem().Kind() == reflect.Struct {
		rv.Elem().Field(0).SetString("evil")
	}
}
`
		for _, tc := range []struct {
			name   string
			appSrc string
		}{
			{
				name: "cross_pkg_capsule_literal_and_unverified_setter",
				appSrc: `package app
import (
	"reflect"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
)
type fakeMsg struct {
	state cappkg.MessageState
	table *desc.RouteTable
}
var forged = cappkg.MessageInfo{GoReflectType: reflect.TypeOf((*fakeMsg)(nil))}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := &fakeMsg{table: svc.PtrTable}
	ws := cappkg.Wrap(cappkg.Pointer(m))
	ws.StoreMessageInfo(&forged)
	ws.MutateField1()
	_, _ = Export()
}
`,
			},
			{
				name: "sibling_struct_field_on_wrapped_message_mutated_via_offset",
				appSrc: `package app
import (
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
)
type fakeMsg struct {
	state cappkg.MessageState
	Table *desc.RouteTable
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := &fakeMsg{Table: svc.PtrTable}
	_ = cappkg.Wrap(cappkg.Pointer(m))
	_, _ = Export()
}
`,
			},
		} {
			specs := []orderedPkgSpec{
				{pkgPath: "example.com/desc", src: baseSchemaSrc},
				{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
				{pkgPath: "example.com/cappkg", src: capRuntimeSrc},
				{pkgPath: "example.com/app", imports: []string{"example.com/cappkg", "example.com/desc", "example.com/svc"}, src: tc.appSrc},
			}
			meta, _, facts := mustTypecheckOrderedDAG(t, specs)
			ac := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: true})
			if ac.State.Downgraded == "" || ac.NonVouchDischarged["example.com/svc.ValTable"] || ac.NonVouchDischarged["example.com/svc.PtrTable"] {
				t.Fatalf("%s unexpectedly discharged cleanly: state=%+v nvd=%+v", tc.name, ac.State, ac.NonVouchDischarged)
			}
		}

		// Sibling /internal/ package calling an exported converter constructor with reflect.TypeOf(iface) must revoke.
		internalSpecs := []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{
				pkgPath: "example.com/internal/cappkg",
				src: `package cappkg
import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type conv struct{ goType reflect.Type }
func NewConverter(t reflect.Type) *conv { return &conv{goType: t} }
func (c *conv) Unwrap(s fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
func init() {
	_ = NewConverter(reflect.TypeOf(int(0)))
}
`,
			},
			{
				pkgPath: "example.com/internal/sib",
				imports: []string{"example.com/desc", "example.com/svc", "example.com/internal/cappkg"},
				src: `package sib
import (
	"fmt"
	"reflect"
	"example.com/desc"
	"example.com/internal/cappkg"
	"example.com/svc"
)
type holder struct{ P *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Corrupt() {
	var s fmt.Stringer = &holder{P: svc.PtrTable}
	rv := cappkg.NewConverter(reflect.TypeOf(s)).Unwrap(s)
	rv.Elem().Field(0).Elem().Field(0).SetString("evil")
}
`,
			},
			{
				pkgPath: "example.com/app",
				imports: []string{"example.com/desc", "example.com/svc", "example.com/internal/sib"},
				src: `package app
import (
	"example.com/desc"
	"example.com/internal/sib"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	sib.Corrupt()
	_, _ = Export()
}
`,
			},
		}
		metaInt, _, factsInt := mustTypecheckOrderedDAG(t, internalSpecs)
		miInternalRef := syntaxutil.TypeRef{Pkg: "example.com/internal/cappkg", Name: "MessageInfo"}
		if !slices.Contains(factsInt["example.com/internal/sib"][0].MutatedStructTypes, miInternalRef) {
			t.Fatalf("sibling /internal/ NewConverter call failed to mark MessageInfo in MutatedStructTypes: %+v", factsInt["example.com/internal/sib"][0].MutatedStructTypes)
		}
		acInt := AnalyzeCone(ConeQuery{Meta: metaInt, Facts: factsInt, ViewPackage: "example.com/app", SingleSubject: true})
		if acInt.State.Downgraded == "" {
			t.Fatalf("sibling /internal/ NewConverter attack unexpectedly discharged cleanly: %+v", acInt.State)
		}

		// Converter struct rebinding and IfStmt.Init reassignment must revoke CapsuleReflectSafe.
		for _, badConv := range []struct {
			name string
			body string
		}{
			{
				name: "converter_struct_rebind_smuggles_interface_gotype",
				body: `type conv struct{ goType reflect.Type }
type rawConv struct{ goType reflect.Type }
func Smuggle(s fmt.Stringer) reflect.Value {
	rc := &rawConv{goType: reflect.TypeOf(s)}
	c := (*conv)(rc)
	return c.Unwrap(s)
}
func init() { _ = &conv{goType: reflect.TypeOf(int(0))} }
func (c *conv) Unwrap(s fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
`,
			},
			{
				name: "if_init_stmt_on_type_guard_rejected",
				body: `type conv struct{ goType reflect.Type }
func init() { _ = &conv{goType: reflect.TypeOf(int(0))} }
func (c *conv) Unwrap(s fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	if x := 1; rv.Type() != c.goType {
		_ = x
		panic("mismatch")
	}
	return rv
}
`,
			},
			{
				name: "converter_recv_reassigned_before_type_guard_rejected",
				body: `type conv struct{ goType reflect.Type }
var altConv = &conv{goType: reflect.TypeOf(int(0))}
func (c *conv) Unwrap(s fmt.Stringer) reflect.Value {
	rv := reflect.ValueOf(s)
	c = altConv
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
`,
			},
		} {
			pkgBad := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{
				"cap.go": `package cappkg
import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
` + badConv.body,
			})
			factBad := FactOf(true, pkgBad)
			for _, ct := range factBad.LazyOnceCapsuleTypes {
				if ct.CapsuleReflectSafe {
					t.Fatalf("%s unexpectedly marked CapsuleReflectSafe: %+v", badConv.name, factBad.LazyOnceCapsuleTypes)
				}
			}
		}
	})

	t.Run("capsule_wrapper_zero_offset_provenance_omitted_embed_and_unapplied_cast_guards", func(t *testing.T) {
		baseWrap := `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
var invalidOffset = ^offset(0)
type pointer struct{ p unsafe.Pointer }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) SetString(v string) { *(*string)(p.p) = v }
type MessageInfo struct {
	GoReflectType string
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func (ms *messageState) pointer() pointer { return pointer{p: unsafe.Pointer(ms)} }
`
		miRef := syntaxutil.TypeRef{Pkg: "example.com/cappkg", Name: "MessageInfo"}
		cleanEmbed := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{
			"cap.go": baseWrap + `type innerOff struct{ off offset }
type outerOff struct {
	innerOff
	tag int
}
func makeInner(sf reflect.StructField) innerOff {
	in := innerOff{off: invalidOffset}
	in.off = offsetOf(sf)
	return in
}
func UseCleanEmbed(ms *messageState, sf reflect.StructField) {
	o := outerOff{innerOff: makeInner(sf), tag: 1}
	ms.pointer().Apply(o.off).SetString("ok")
}
`,
		})
		if slices.Contains(FactOf(true, cleanEmbed).MutatedStructTypes, miRef) {
			t.Fatal("clean initialized embedded struct offset unexpectedly marked MessageInfo mutated")
		}

		for _, bad := range []struct {
			name  string
			extra string
		}{
			{
				name:  "zero_declared_local_offset_passed_to_apply",
				extra: "func Bad(ms *messageState) { var z offset; ms.pointer().Apply(z).SetString(\"evil\") }\n",
			},
			{
				name:  "zero_instantiated_struct_field_offset_passed_to_apply",
				extra: "type holder struct{ off offset }\nfunc Make() holder { return holder{off: invalidOffset} }\nfunc Bad(ms *messageState) { var h holder; _ = Make(); ms.pointer().Apply(h.off).SetString(\"evil\") }\n",
			},
			{
				name: "omitted_embedded_struct_field_leaves_zero_offset",
				extra: `type innerOff struct{ off offset }
type outerOff struct {
	innerOff
	tag int
}
func makeInner() innerOff { return innerOff{off: invalidOffset} }
func Bad(ms *messageState) {
	_ = makeInner()
	o := outerOff{tag: 1}
	ms.pointer().Apply(o.off).SetString("evil")
}
`,
			},
			{
				name:  "array_composite_escapes_base_pointer",
				extra: "func Bad(ms *messageState) [1]pointer { return [1]pointer{ms.pointer()} }\n",
			},
			{
				name:  "chained_apply_on_already_applied_pointer",
				extra: "func Bad(ms *messageState, sf1, sf2 reflect.StructField) { _ = ms.pointer().Apply(offsetOf(sf1)).Apply(offsetOf(sf2)) }\n",
			},
			{
				name:  "elem_child_base_pointer_raw_mutator_without_apply",
				extra: "func (p pointer) Elem() pointer { return pointer{p: *(*unsafe.Pointer)(p.p)} }\nfunc Bad(ms *messageState, sf reflect.StructField) { ms.pointer().Apply(offsetOf(sf)).Elem().SetString(\"evil\") }\n",
			},
			{
				name:  "closed_raw_ptr_field_interface_ptr_cast",
				extra: "func (p pointer) AsAnyPtr() *any { return (*any)(p.p) }\nfunc Bad(ms *messageState, sf reflect.StructField) *any { return ms.pointer().Apply(offsetOf(sf)).AsAnyPtr() }\n",
			},
			{
				name:  "closed_raw_ptr_field_array_ptr_cast",
				extra: "func (p pointer) AsTwoWords() *[2]unsafe.Pointer { return (*[2]unsafe.Pointer)(p.p) }\nfunc Bad(ms *messageState, sf reflect.StructField) *[2]unsafe.Pointer { return ms.pointer().Apply(offsetOf(sf)).AsTwoWords() }\n",
			},
			{
				name:  "closed_raw_ptr_field_uintptr_ptr_cast",
				extra: "func (p pointer) AsUintptr() *uintptr { return (*uintptr)(p.p) }\nfunc Bad(ms *messageState, sf reflect.StructField) *uintptr { return ms.pointer().Apply(offsetOf(sf)).AsUintptr() }\n",
			},
			{
				name:  "direct_raw_field_read_outside_pointer_methods",
				extra: "func Bad(ms *messageState) { *(*string)(ms.pointer().p) = \"evil\" }\n",
			},
			{
				name: "base_pointer_as_iface_of_shadow_type_pun",
				extra: `func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
func (p pointer) AsIfaceOf(t reflect.Type) any { return p.AsValueOf(t).Interface() }
type shadow struct{ p *MessageInfo }
func Bad(ms *messageState) any { return ms.pointer().AsIfaceOf(reflect.TypeOf(shadow{})) }
`,
			},
			{
				name: "base_pointer_as_value_of_shadow_type_pun",
				extra: `func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type shadow struct{ p *MessageInfo }
func Bad(ms *messageState) any { return ms.pointer().AsValueOf(reflect.TypeOf(shadow{})).Interface() }
`,
			},
			{
				name: "smuggled_base_pointer_inside_isnil_extra_stmt",
				extra: `var stash pointer
func (p pointer) CheckNil() bool {
	stash = p
	return p.p == nil
}
func Bad(ms *messageState) {
	_ = ms.pointer().CheckNil()
	stash.SetString("evil")
}
`,
			},
			{
				name: "tuple_forwarding_smuggles_base_pointer_into_any_params",
				extra: `func pair(ms *messageState) (pointer, int) { return ms.pointer(), 1 }
func sink(a, b any) { _, _ = a, b }
func Bad(ms *messageState) { sink(pair(ms)) }
`,
			},
			{
				name: "tuple_forwarding_smuggles_base_pointer_into_typed_callee",
				extra: `func pair(ms *messageState) (pointer, int) { return ms.pointer(), 1 }
func take(p pointer, _ int) { p.SetString("evil") }
func Bad(ms *messageState) { take(pair(ms)) }
`,
			},
			{
				name: "closed_raw_ptr_carrier_slice_cast_smuggles_interface",
				extra: `type anySliceElem interface{ M() }
func (p pointer) ReadCarrierSlice() anySliceElem { return (*(*[]anySliceElem)(p.p))[0] }
func Bad(ms *messageState, sf reflect.StructField) anySliceElem {
	return ms.pointer().Apply(offsetOf(sf)).ReadCarrierSlice()
}
`,
			},
			{
				name: "multi_return_pointer_slice_smuggles_base_pointer",
				extra: `func (p pointer) PointerSlice() []pointer { return *(*[]pointer)(p.p) }
func slicePair(ms *messageState, sf reflect.StructField) ([]pointer, bool) {
	return ms.pointer().Apply(offsetOf(sf)).PointerSlice(), true
}
func Bad(ms *messageState, sf reflect.StructField) {
	s, _ := slicePair(ms, sf)
	s[0].SetString("evil")
}
`,
			},
			{
				name: "multi_return_reflect_value_overwrites_fresh_rv_with_raw",
				extra: `func pointerOfValue(v reflect.Value) pointer { return pointer{p: unsafe.Pointer(v.Pointer())} }
func rawPair(v reflect.Value) (reflect.Value, bool) { return v, true }
func Bad(sf reflect.StructField, raw reflect.Value, cond bool) {
	rv := reflect.New(sf.Type)
	if cond {
		rv, _ = rawPair(raw)
	}
	pointerOfValue(rv).Apply(0).SetString("evil")
}
`,
			},
			{
				name: "comma_ok_assign_to_struct_field_smuggles_base_pointer",
				extra: `type boxPtr struct{ pt pointer }
func pairOk(ms *messageState) (pointer, bool) { return ms.pointer(), true }
func Bad(ms *messageState) {
	var b boxPtr
	var ok bool
	b.pt, ok = pairOk(ms)
	_ = ok
	b.pt.SetString("evil")
}
`,
			},
			{
				name: "range_assign_to_struct_field_smuggles_base_pointer",
				extra: `type boxPtr struct{ pt pointer }
func (p pointer) PointerSlice() []pointer { return *(*[]pointer)(p.p) }
func Bad(ms *messageState, sf reflect.StructField) {
	var b boxPtr
	for _, b.pt = range ms.pointer().Apply(offsetOf(sf)).PointerSlice() {
		b.pt.SetString("evil")
	}
}
`,
			},
			{
				name: "range_key_over_pointer_map_smuggles_raw_pointer",
				extra: `func Bad(m map[pointer]int) {
	for k := range m {
		k.SetString("evil")
	}
}
`,
			},
			{
				name: "type_switch_implicit_case_smuggles_raw_pointer",
				extra: `func Bad(ms *messageState, sf reflect.StructField, x any) {
	b := ms.pointer()
	switch v := x.(type) {
	case pointer:
		b = v
	}
	b.Apply(offsetOf(sf)).SetString("evil")
}
`,
			},
			{
				name: "variadic_slice_copy_overwrites_applied_element_with_base_pointer",
				extra: `func (p pointer) PointerSlice() []pointer { return *(*[]pointer)(p.p) }
func vs(base []pointer, xs ...pointer) {
	copy(xs, base)
	xs[0].SetString("evil")
}
func Bad(ms *messageState, sf1, sf2 reflect.StructField) {
	vs(ms.pointer().Apply(offsetOf(sf1)).PointerSlice(), ms.pointer().Apply(offsetOf(sf2)))
}
`,
			},
			{
				name: "struct_conversion_teleports_base_pointer_across_distinct_field_vars",
				extra: `type holderA struct{ p pointer }
type holderB struct{ p pointer }
func Bad(ms *messageState, sf reflect.StructField) {
	a := holderA{p: ms.pointer()}
	b := holderB{p: ms.pointer().Apply(offsetOf(sf))}
	b = holderB(a)
	b.p.SetString("evil")
}
`,
			},
			{
				name: "ptr_to_struct_conversion_teleports_base_pointer_across_distinct_field_vars",
				extra: `type holderA struct{ p pointer }
type holderB struct{ p pointer }
func Bad(ms *messageState, sf reflect.StructField) {
	a := holderA{p: ms.pointer().Apply(offsetOf(sf))}
	pb := (*holderB)(&a)
	pb.p = ms.pointer()
	a.p.SetString("evil")
}
`,
			},
			{
				name: "method_expr_call_shifts_param_index_dropping_base_pointer",
				extra: `type helper struct{}
func (h helper) Sink(p1, p2 pointer) {
	_ = p1
	p2.SetString("evil")
}
func Bad(ms *messageState, sf reflect.StructField) {
	app := ms.pointer().Apply(offsetOf(sf))
	(helper{}).Sink(app, app)
	(helper).Sink(helper{}, app, ms.pointer())
}
`,
			},
			{
				name: "indirect_method_expr_value_call_shifts_param_index",
				extra: `type helper struct{}
func (h helper) Sink(p1, p2 pointer) {
	_ = p1
	p2.SetString("evil")
}
func Bad(ms *messageState, sf reflect.StructField) {
	app := ms.pointer().Apply(offsetOf(sf))
	(helper{}).Sink(app, app)
	fn := (helper).Sink
	fn(helper{}, app, ms.pointer())
}
`,
			},
			{
				name: "ellipsis_call_drops_reflect_value_raw_provenance",
				extra: `func pointerOfValue(v reflect.Value) pointer { return pointer{p: unsafe.Pointer(v.Pointer())} }
var zeroOffset = offset(0)
var staticTarget struct{ s string }
func sinkRV(rv reflect.Value, rest ...int) {
	_ = rest
	pointerOfValue(rv).Apply(zeroOffset).SetString("evil")
}
func Bad(sf reflect.StructField) {
	sinkRV(reflect.New(sf.Type))
	var ints []int
	sinkRV(reflect.ValueOf(&staticTarget), ints...)
}
`,
			},
		} {
			pkgBad := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": baseWrap + bad.extra})
			factBad := FactOf(true, pkgBad)
			if !slices.Contains(factBad.MutatedStructTypes, miRef) {
				t.Fatalf("%s failed to mark MessageInfo in MutatedStructTypes: %+v", bad.name, factBad.MutatedStructTypes)
			}
		}

		capGoTypeBase := `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
type ifaceHeader struct{ typ, data unsafe.Pointer }
func pointerOfIface(v any) pointer { return pointer{p: (*ifaceHeader)(unsafe.Pointer(&v)).data} }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) SetString(v string) { *(*string)(p.p) = v }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
func (p pointer) AsIfaceOf(t reflect.Type) any { return p.AsValueOf(t).Interface() }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	size          int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func (ms *messageState) pointer() pointer { return pointer{p: unsafe.Pointer(ms)} }
func (ms *messageState) messageInfo() *MessageInfo { return ms.mi }
type msgWrapper struct {
	p  pointer
	mi *MessageInfo
}
func (mi *MessageInfo) WrapIface(m any) *msgWrapper {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("type mismatch")
	}
	return &msgWrapper{p: pointerOfIface(m), mi: mi}
}
func (w *msgWrapper) Unwrap() any      { return w.p.AsIfaceOf(w.mi.GoReflectType.Elem()) }
func (ms *messageState) Unwrap() any   { return ms.pointer().AsIfaceOf(ms.messageInfo().GoReflectType.Elem()) }
`
		pkgPairedClean := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": capGoTypeBase})
		if slices.Contains(FactOf(true, pkgPairedClean).MutatedStructTypes, miRef) {
			t.Fatalf("clean paired AsIfaceOf/WrapIface capsule unexpectedly marked MessageInfo mutated: %+v", FactOf(true, pkgPairedClean).MutatedStructTypes)
		}
		for _, badPair := range []struct {
			name  string
			extra string
		}{
			{
				name: "non_capsule_receiver_type_guard_forgery_into_pointer_of_iface",
				extra: `type forger struct{ gt reflect.Type }
func (f *forger) Wrap(v any, sf reflect.StructField) {
	if reflect.TypeOf(v) != f.gt {
		panic("mismatch")
	}
	pointerOfIface(v).Apply(offsetOf(sf)).SetString("evil")
}
`,
			},
			{
				name: "intra_pkg_keyed_composite_lit_forges_capsule_goreflecttype",
				extra: `type shadow struct{ s string }
func Forge(ms *messageState) any {
	bad := &MessageInfo{GoReflectType: reflect.TypeOf((*shadow)(nil))}
	_ = bad
	return ms.pointer().AsIfaceOf(ms.messageInfo().GoReflectType.Elem())
}
`,
			},
			{
				name: "intra_pkg_positional_composite_lit_forges_capsule_goreflecttype",
				extra: `type shadow struct{ s string }
func Forge(ms *messageState) any {
	bad := &MessageInfo{reflect.TypeOf((*shadow)(nil)), sync.Mutex{}, 0, 0}
	_ = bad
	return ms.pointer().AsIfaceOf(ms.messageInfo().GoReflectType.Elem())
}
`,
			},
			{
				name: "cross_paired_as_iface_of_mismatched_capsule_goreflecttype",
				extra: `func CrossUnwrap(ms *messageState, other *MessageInfo) any {
	return ms.pointer().AsIfaceOf(other.GoReflectType.Elem())
}
`,
			},
			{
				name: "unpaired_pair_wrapper_composite_lit_mismatches_pointer_and_capsule",
				extra: `func CrossWrap(mi, other *MessageInfo, m any) *msgWrapper {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("mismatch")
	}
	return &msgWrapper{p: pointerOfIface(m), mi: other}
}
`,
			},
		} {
			pkgBadPair := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{"cap.go": capGoTypeBase + badPair.extra})
			factBadPair := FactOf(true, pkgBadPair)
			if !slices.Contains(factBadPair.MutatedStructTypes, miRef) {
				t.Fatalf("%s failed to mark MessageInfo in MutatedStructTypes: %+v", badPair.name, factBadPair.MutatedStructTypes)
			}
		}

		for _, rawBody := range []struct {
			name string
			code string
		}{
			{
				name: "direct_composite_lit_raw_pointer",
				code: `func RawBypass(raw unsafe.Pointer) **targetS {
	pt := pointer{p: raw}
	return pt.TargetDoublePtr()
}`,
			},
			{
				name: "pointer_of_named_pointer_constructor_bypass",
				code: `type Pointer unsafe.Pointer
func pointerOf(p Pointer) pointer { return pointer{p: unsafe.Pointer(p)} }
func RawBypass(raw Pointer) **targetS {
	return pointerOf(raw).TargetDoublePtr()
}`,
			},
		} {
			pkgUnapplied := mustTypecheckPackage(t, "example.com/cappkg", map[string]string{
				"cap.go": baseWrap + `type targetS struct{ x int }
func MutateTarget(t *targetS) { t.x = 1 }
func (p pointer) TargetDoublePtr() **targetS { return (**targetS)(p.p) }
func UseApplied(ms *messageState, sf reflect.StructField) **targetS {
	return ms.pointer().Apply(offsetOf(sf)).TargetDoublePtr()
}
` + rawBody.code + "\n",
			})
			for _, ct := range FactOf(true, pkgUnapplied).LazyOnceCapsuleTypes {
				if ct.CapsuleReflectSafe {
					t.Fatalf("%s unexpectedly kept CapsuleReflectSafe: %+v", rawBody.name, ct)
				}
			}
		}
	})

	t.Run("formatted_pointer_identity_uintptr_forgery_and_cross_iface_assertion_bridges", func(t *testing.T) {
		wrapSrc := `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type holder struct{ p *desc.RouteTable }
func (*holder) String() string { return "ok" }
func Box() fmt.Stringer { return &holder{p: svc.PtrTable} }
`
		// Formatting without raw uintptr->unsafe.Pointer in the cone must remain clean.
		cleanSpecs := []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: baseSchemaSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
			{
				pkgPath: "example.com/app",
				imports: []string{"example.com/desc", "example.com/svc", "example.com/wrap"},
				src: `package app
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
var Formatted = fmt.Sprintf("%p", wrap.Box())
`,
			},
		}
		metaClean, _, factsClean := mustTypecheckOrderedDAG(t, cleanSpecs)
		acClean := AnalyzeCone(ConeQuery{Meta: metaClean, Facts: factsClean, ViewPackage: "example.com/app", SingleSubject: true})
		if acClean.State.Downgraded != "" || !acClean.NonVouchDischarged["example.com/svc.PtrTable"] {
			t.Fatalf("benign fmt.Sprintf without uintptr->unsafe.Pointer unexpectedly downgraded: state=%+v nvd=%+v", acClean.State, acClean.NonVouchDischarged)
		}

		for _, atk := range []struct {
			name  string
			specs []orderedPkgSpec
		}{
			{
				name: "reflect_value_pointer_formatted_decimal_without_unsafe_in_reflector",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/reflfmt",
						imports: []string{"example.com/wrap"},
						src: `package reflfmt
import (
	"fmt"
	"reflect"
	"example.com/wrap"
)
func LeakDecimal() string {
	return fmt.Sprintf("%d", reflect.ValueOf(wrap.Box()).Pointer())
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/reflfmt", "example.com/svc"},
						src: `package app
import (
	"strconv"
	"unsafe"
	"example.com/desc"
	"example.com/reflfmt"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	u, _ := strconv.ParseUint(reflfmt.LeakDecimal(), 10, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "fmt_percent_p_on_interface_plus_cross_pkg_uintptr_cast",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/fmtpkg",
						imports: []string{"example.com/wrap"},
						src: `package fmtpkg
import (
	"fmt"
	"example.com/wrap"
)
func HexAddr() string { return fmt.Sprintf("%p", wrap.Box()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/fmtpkg", "example.com/svc"},
						src: `package app
import (
	"strconv"
	"unsafe"
	"example.com/desc"
	"example.com/fmtpkg"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	u, _ := strconv.ParseUint(fmtpkg.HexAddr(), 0, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "unsafe_ptr_carrier_boxed_via_type_dispatch_only_any_param",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/unionpkg",
						src: `package unionpkg
import (
	"fmt"
	"unsafe"
)
type Token interface{ IsToken() }
type ifaceHeader struct {
	Type unsafe.Pointer
	Data unsafe.Pointer
}
func typeOf(t any) unsafe.Pointer { return (*ifaceHeader)(unsafe.Pointer(&t)).Type }
var bytesType = typeOf(*new([]byte))
type rawVal struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
	num uint64
}
type Value rawVal
func (Value) IsToken() {}
func pack(v any) Value {
	p := (*ifaceHeader)(unsafe.Pointer(&v))
	return Value{typ: p.Type, ptr: p.Data, num: 8}
}
func asToken(x any) Token {
	switch v := x.(type) {
	case Token:
		return v
	default:
		return nil
	}
}
func BoxToken(s fmt.Stringer) Token { return asToken(pack(s)) }
func (v Value) getBytes() []byte { return unsafe.Slice((*byte)(v.ptr), v.num) }
func (v Value) Bytes() []byte {
	switch v.typ {
	case bytesType:
		return v.getBytes()
	default:
		panic("no")
	}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/svc", "example.com/unionpkg", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"unsafe"
	"example.com/desc"
	"example.com/svc"
	"example.com/unionpkg"
	"example.com/wrap"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	tok := unionpkg.BoxToken(wrap.Box())
	raw := reflect.ValueOf(tok).Field(1).UnsafePointer()
	p := *(*unsafe.Pointer)(raw)
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "cross_interface_type_dispatch_bridge_to_reflected_target_interface",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/ifaces", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/ifaces"
	"example.com/svc"
)
var _ ifaces.Marker = (*bothHolder)(nil)
type bothHolder struct{ p *desc.RouteTable }
func (*bothHolder) String() string { return "ok" }
func (*bothHolder) Mark()          {}
func Box() fmt.Stringer { return &bothHolder{p: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/bridge",
						imports: []string{"example.com/ifaces"},
						src: `package bridge
import (
	"fmt"
	"example.com/ifaces"
)
func coerce(x any) ifaces.Marker {
	if m, ok := x.(ifaces.Marker); ok {
		return m
	}
	return nil
}
func ToMarker(s fmt.Stringer) ifaces.Marker { return coerce(s) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/bridge", "example.com/desc", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/bridge"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := bridge.ToMarker(wrap.Box())
	raw := reflect.ValueOf(m).Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "empty_iface_reflect_value_boundary_escape_plus_cross_pkg_erased_unexported_field",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/eraser",
						imports: []string{"example.com/wrap"},
						src: `package eraser
import "example.com/wrap"
func AsAny() any { return wrap.Box() }
`,
					},
					{
						pkgPath: "example.com/rvfactory",
						imports: []string{"example.com/eraser"},
						src: `package rvfactory
import (
	"reflect"
	"example.com/eraser"
)
func MakeRV() reflect.Value { return reflect.ValueOf(eraser.AsAny()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/rvfactory", "example.com/svc"},
						src: `package app
import (
	"example.com/desc"
	"example.com/rvfactory"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	raw := rvfactory.MakeRV().Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_exported_nested_iface_boxed_into_marker",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import (
	"fmt"
	"example.com/ifaces"
)
type box struct{ S fmt.Stringer }
func (*box) Mark() {}
func AsMarker(s fmt.Stringer) ifaces.Marker { return &box{S: s} }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := smuggle.AsMarker(wrap.BoxExp())
	reflect.ValueOf(m).Elem().Field(0).Elem().Field(0).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_unexported_nested_iface_boxed_into_marker",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import (
	"fmt"
	"example.com/ifaces"
)
type box struct{ s fmt.Stringer }
func (*box) Mark() {}
func AsMarker(s fmt.Stringer) ifaces.Marker { return &box{s: s} }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := smuggle.AsMarker(wrap.Box())
	raw := reflect.ValueOf(m).Elem().Field(0).Elem().Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_exported_nested_iface_split_any_return_and_flagro_bypass",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import (
	"fmt"
	"example.com/ifaces"
)
type box struct{ S fmt.Stringer }
func (*box) Mark() {}
func AsMarker(s fmt.Stringer) ifaces.Marker { return &box{S: s} }
`,
					},
					{
						pkgPath: "example.com/rvstep",
						imports: []string{"example.com/ifaces"},
						src: `package rvstep
import (
	"reflect"
	"example.com/ifaces"
)
func StepFieldAny(m ifaces.Marker) any {
	return reflect.ValueOf(m).Elem().Field(0).Interface()
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/rvstep", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/rvstep"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	anyVal := rvstep.StepFieldAny(smuggle.AsMarker(wrap.Box()))
	raw := reflect.ValueOf(anyVal).Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_nested_any_boxed_into_marker",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces", "example.com/wrap"},
						src: `package smuggle
import (
	"example.com/ifaces"
	"example.com/wrap"
)
type anyBox struct{ V any }
func (*anyBox) Mark() {}
func PackAny() ifaces.Marker { return &anyBox{V: wrap.Box()} }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/smuggle", "example.com/svc"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	m := smuggle.PackAny()
	raw := reflect.ValueOf(m).Elem().Field(0).Elem().Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "fmt_errorf_percent_w_wraps_error_holder_unwrapped_via_reflect",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wraperr",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wraperr
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type errHolder struct{ p *desc.RouteTable }
func (*errHolder) Error() string { return "err" }
func BoxErr() error { return fmt.Errorf("wrap: %w", &errHolder{p: svc.PtrTable}) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/svc", "example.com/wraperr"},
						src: `package app
import (
	"errors"
	"reflect"
	"example.com/desc"
	"example.com/svc"
	"example.com/wraperr"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	u := errors.Unwrap(wraperr.BoxErr())
	raw := reflect.ValueOf(u).Elem().Field(0).UnsafePointer()
	(*shadowRoute)(raw).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "fmt_sprintf_double_percent_shifts_directive_index_to_percent_p",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/fmtpkg",
						imports: []string{"example.com/wrap"},
						src: `package fmtpkg
import (
	"fmt"
	"example.com/wrap"
)
func ShiftedHex() string { return fmt.Sprintf("100%% %T %p", 0, wrap.Box()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/fmtpkg", "example.com/svc"},
						src: `package app
import (
	"strconv"
	"strings"
	"unsafe"
	"example.com/desc"
	"example.com/fmtpkg"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	parts := strings.Fields(fmtpkg.ShiftedHex())
	u, _ := strconv.ParseUint(parts[len(parts)-1], 0, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "fmt_sprintf_dynamic_width_trailing_extra_arg_pointer_leak",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/fmtpkg",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package fmtpkg
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type box struct{ p *desc.RouteTable }
func ExtraHex() string { return fmt.Sprintf("%*T", 4, 0, &box{p: svc.PtrTable}) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/fmtpkg", "example.com/svc"},
						src: `package app
import (
	"strconv"
	"unsafe"
	"example.com/desc"
	"example.com/fmtpkg"
	"example.com/svc"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	u, _ := strconv.ParseUint(fmtpkg.ExtraHex(), 0, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "cross_pkg_param_leak_free_fmt_percent_p_on_any_param",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/fmtpkg",
						src: `package fmtpkg
import "fmt"
func HexAddr(a any) string { return fmt.Sprintf("%p", a) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/fmtpkg", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"strconv"
	"unsafe"
	"example.com/desc"
	"example.com/fmtpkg"
	"example.com/svc"
	"example.com/wrap"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	u, _ := strconv.ParseUint(fmtpkg.HexAddr(wrap.Box()), 0, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	(*shadowRoute)(p).Name = "evil"
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "capsule_message_with_user_iface_field_passed_to_safe_ptr_wrapper",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/cappkg",
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type Pointer unsafe.Pointer
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	off           offset
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.off = offsetOf(mi.GoReflectType.Elem().Field(1))
	atomic.StoreUint32(&mi.done, 1)
}
func (mi *MessageInfo) MutateViaReflect(ms *messageState) {
	if atomic.LoadUint32(&mi.done) == 0 {
		mi.initOnce()
	}
	rv := ms.pointer().Apply(mi.off).AsValueOf(mi.GoReflectType.Elem().Field(1).Type).Elem()
	_ = rv
}
type MessageState struct {
	mi *MessageInfo
}
type messageState MessageState
func (ms *messageState) pointer() pointer { return pointer{p: unsafe.Pointer(ms)} }
func (ms *messageState) LoadMessageInfo() *MessageInfo {
	return (*MessageInfo)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi))))
}
func (ms *messageState) StoreMessageInfo(mi *MessageInfo) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&ms.mi)), unsafe.Pointer(mi))
}
type Builder struct {
	File            []byte
	NumEnums        int32
	NumMessages     int32
	GoTypes         []any
	MessageInfos    []MessageInfo
}
func (b Builder) Build() {
	for i := int32(0); i < b.NumMessages; i++ {
		b.MessageInfos[i].GoReflectType = reflect.TypeOf(b.GoTypes[b.NumEnums+i])
	}
}
type Export struct{}
func (Export) MessageStateOf(p Pointer) *messageState { return (*messageState)(unsafe.Pointer(p)) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"fmt"
	"unsafe"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
type MyMsg struct {
	state cappkg.MessageState
	Desc  fmt.Stringer
}
var msgTypes = make([]cappkg.MessageInfo, 1)
var goTypes = []any{(*MyMsg)(nil)}
func init() {
	cappkg.Builder{
		NumMessages:  1,
		GoTypes:      goTypes,
		MessageInfos: msgTypes,
	}.Build()
	m := &MyMsg{Desc: wrap.Box()}
	ms := cappkg.Export{}.MessageStateOf(cappkg.Pointer(unsafe.Pointer(m)))
	if ms.LoadMessageInfo() == nil {
		ms.StoreMessageInfo(&msgTypes[0])
	}
	msgTypes[0].MutateViaReflect(ms)
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
`,
					},
				},
			},
			{
				name: "sibling_internal_reflect_type_constructor_revokes_unexported_capsule_struct",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/internal/cappkg",
						imports: []string{"example.com/ifaces"},
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"example.com/ifaces"
)
type convImpl struct{ goType reflect.Type }
func (c *convImpl) Unwrap(m ifaces.Marker) reflect.Value {
	rv := reflect.ValueOf(m)
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
func NewConverter(t reflect.Type) *convImpl { return &convImpl{goType: t} }
func init()                                 { _ = NewConverter(reflect.TypeOf(int(0))) }
type messageInfo struct {
	mu   sync.Mutex
	done uint32
	size int
}
func (mi *messageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *messageInfo
}
`,
					},
					{
						pkgPath: "example.com/internal/sib",
						imports: []string{"example.com/ifaces", "example.com/internal/cappkg", "example.com/wrap"},
						src: `package sib
import (
	"fmt"
	"reflect"
	"example.com/ifaces"
	"example.com/internal/cappkg"
	"example.com/wrap"
)
type box struct{ S fmt.Stringer }
func (*box) Mark() {}
func Exploit() {
	var m ifaces.Marker = &box{S: wrap.BoxExp()}
	c := cappkg.NewConverter(reflect.TypeOf((*box)(nil)))
	c.Unwrap(m).Elem().Field(0).Elem().Field(0).SetString("evil")
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/internal/sib", "example.com/svc"},
						src: `package app
import (
	"example.com/desc"
	"example.com/internal/sib"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	sib.Exploit()
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "converter_typeof_foreign_scalar_struct_mutates_static_composite_directly",
				specs: []orderedPkgSpec{
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/desc",
						src: `package desc
type ScalarBox struct{ Name string }
`,
					},
					{
						pkgPath: "example.com/svc",
						imports: []string{"example.com/desc"},
						src: `package svc
import "example.com/desc"
var ValTable = desc.ScalarBox{Name: "v"}
var PtrTable = &desc.ScalarBox{Name: "p"}
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/desc", "example.com/ifaces", "example.com/svc"},
						src: `package smuggle
import (
	"example.com/desc"
	"example.com/ifaces"
	"example.com/svc"
)
type MarkerBox struct{ V desc.ScalarBox }
func (*MarkerBox) Mark() {}
var BoxGlobal = &MarkerBox{V: desc.ScalarBox{Name: "g"}}
func GetTables() (*desc.ScalarBox, *desc.ScalarBox) { return &svc.ValTable, svc.PtrTable }
func AsMarker(m *MarkerBox) ifaces.Marker            { return m }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						imports: []string{"example.com/ifaces", "example.com/smuggle"},
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"example.com/ifaces"
	"example.com/smuggle"
)
type convImpl struct{ goType reflect.Type }
func (c *convImpl) Unwrap(m ifaces.Marker) reflect.Value {
	rv := reflect.ValueOf(m)
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
func NewBoxConv() *convImpl { return &convImpl{goType: reflect.TypeOf((*smuggle.MarkerBox)(nil))} }
type MessageInfo struct {
	mu   sync.Mutex
	done uint32
	size int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/smuggle", "example.com/svc"},
						src: `package app
import (
	"example.com/cappkg"
	"example.com/smuggle"
	"example.com/svc"
)
func Export() any { return smuggle.BoxGlobal }
func init() {
	_, _ = svc.ValTable, svc.PtrTable
	rv := cappkg.NewBoxConv().Unwrap(smuggle.AsMarker(smuggle.BoxGlobal))
	rv.Elem().Field(0).Field(0).SetString("evil")
	_ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_array_of_any_via_registry_callback_seeds_cb_pkg",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
type Registry interface{ Register(Marker) }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import "example.com/ifaces"
type anyArrBox struct{ Items [1]any }
func (*anyArrBox) Mark() {}
func PackInto(x any, r ifaces.Registry) { r.Register(&anyArrBox{Items: [1]any{x}}) }
`,
					},
					{
						pkgPath: "example.com/caller",
						imports: []string{"example.com/ifaces", "example.com/smuggle", "example.com/wrap"},
						src: `package caller
import (
	"example.com/ifaces"
	"example.com/smuggle"
	"example.com/wrap"
)
func Forward(r ifaces.Registry) { smuggle.PackInto(wrap.BoxExp(), r) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/caller", "example.com/desc", "example.com/ifaces", "example.com/svc"},
						src: `package app
import (
	"reflect"
	"example.com/caller"
	"example.com/desc"
	"example.com/ifaces"
	"example.com/svc"
)
type reg struct{}
func (*reg) Register(m ifaces.Marker) {
	reflect.ValueOf(m).Elem().Field(0).Index(0).Elem().Elem().Field(0).Elem().Field(0).SetString("evil")
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	caller.Forward(&reg{})
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "converter_typeof_foreign_concrete_struct_unwraps_nested_iface",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import (
	"fmt"
	"example.com/ifaces"
)
type Box struct{ S fmt.Stringer }
func (*Box) Mark() {}
func AsMarker(s fmt.Stringer) ifaces.Marker { return &Box{S: s} }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						imports: []string{"example.com/ifaces", "example.com/smuggle"},
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"example.com/ifaces"
	"example.com/smuggle"
)
type convImpl struct{ goType reflect.Type }
func (c *convImpl) Unwrap(m ifaces.Marker) reflect.Value {
	rv := reflect.ValueOf(m)
	if rv.Type() != c.goType {
		panic("mismatch")
	}
	return rv
}
func NewBoxConv() *convImpl { return &convImpl{goType: reflect.TypeOf((*smuggle.Box)(nil))} }
type MessageInfo struct {
	mu   sync.Mutex
	done uint32
	size int
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.size = 1
	atomic.StoreUint32(&mi.done, 1)
}
type MessageState struct {
	mi *MessageInfo
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"example.com/cappkg"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	rv := cappkg.NewBoxConv().Unwrap(smuggle.AsMarker(wrap.BoxExp()))
	rv.Elem().Field(0).Elem().Field(0).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "capsule_message_with_user_iface_without_messagestateof_call",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
type ifaceHeader struct{ typ, data unsafe.Pointer }
func pointerOfIface(v any) pointer { return pointer{p: (*ifaceHeader)(unsafe.Pointer(&v)).data} }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	off           offset
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.off = offsetOf(mi.GoReflectType.Elem().Field(1))
	atomic.StoreUint32(&mi.done, 1)
}
func (mi *MessageInfo) MutateViaIface(m any) {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("mismatch")
	}
	if atomic.LoadUint32(&mi.done) == 0 {
		mi.initOnce()
	}
	rv := pointerOfIface(m).Apply(mi.off).AsValueOf(mi.GoReflectType.Elem().Field(1).Type).Elem()
	rv.Elem().Field(0).Elem().Field(0).SetString("evil")
}
type MessageState struct {
	mi *MessageInfo
}
type Builder struct {
	File         []byte
	NumEnums     int32
	NumMessages  int32
	GoTypes      []any
	MessageInfos []MessageInfo
}
func (b Builder) Build() {
	for i := int32(0); i < b.NumMessages; i++ {
		b.MessageInfos[i].GoReflectType = reflect.TypeOf(b.GoTypes[b.NumEnums+i])
	}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"fmt"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
type MyMsg struct {
	state cappkg.MessageState
	Desc  fmt.Stringer
}
var msgTypes = make([]cappkg.MessageInfo, 1)
var goTypes = []any{(*MyMsg)(nil)}
func init() {
	cappkg.Builder{
		NumMessages:  1,
		GoTypes:      goTypes,
		MessageInfos: msgTypes,
	}.Build()
	m := &MyMsg{Desc: wrap.BoxExp()}
	msgTypes[0].MutateViaIface(m)
	_, _ = Export()
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_array_of_any_activates_deferred_param_leak",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import "example.com/ifaces"
type anyArrBox [1]any
func (anyArrBox) Mark() {}
func Pack(x any) ifaces.Marker { return anyArrBox{x} }
`,
					},
					{
						pkgPath: "example.com/caller",
						imports: []string{"example.com/ifaces", "example.com/smuggle", "example.com/wrap"},
						src: `package caller
import (
	"example.com/ifaces"
	"example.com/smuggle"
	"example.com/wrap"
)
func Forward() ifaces.Marker { return smuggle.Pack(wrap.BoxExp()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/caller", "example.com/desc", "example.com/svc"},
						src: `package app
import (
	"reflect"
	"example.com/caller"
	"example.com/desc"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	reflect.ValueOf(caller.Forward()).Index(0).Elem().Elem().Field(0).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "concrete_box_carrying_unexported_any_field_activates_flagro_cone",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/ifaces"},
						src: `package smuggle
import "example.com/ifaces"
type unexpAnyBox struct{ v any }
func (*unexpAnyBox) Mark() {}
func Pack(x any) ifaces.Marker { return &unexpAnyBox{v: x} }
`,
					},
					{
						pkgPath: "example.com/caller",
						imports: []string{"example.com/ifaces", "example.com/smuggle", "example.com/wrap"},
						src: `package caller
import (
	"example.com/ifaces"
	"example.com/smuggle"
	"example.com/wrap"
)
func Forward() ifaces.Marker { return smuggle.Pack(wrap.Box()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/caller", "example.com/desc", "example.com/svc"},
						src: `package app
import (
	"reflect"
	"example.com/caller"
	"example.com/desc"
	"example.com/svc"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	reflect.ValueOf(caller.Forward()).Elem().Field(0).Elem().Elem().Field(0).Elem().FieldByName("Endpoints").Clear()
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "reflect_value_call_invokes_callback_with_extracted_field",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/reflcall",
						src: `package reflcall
import (
	"fmt"
	"reflect"
)
func Invoke(s fmt.Stringer, cb func(any)) {
	f := reflect.ValueOf(s).Elem().Field(0)
	reflect.ValueOf(cb).Call([]reflect.Value{f})
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/reflcall", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/reflcall"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	reflcall.Invoke(wrap.BoxExp(), func(a any) {
		reflect.ValueOf(a).Elem().Field(0).SetString("evil")
	})
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "reflect_append_writes_extracted_value_into_spare_capacity_slice",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/reflapp",
						src: `package reflapp
import (
	"fmt"
	"reflect"
)
func Stash(s fmt.Stringer, getBuf func() []any) {
	f := reflect.ValueOf(s).Elem().Field(0)
	_ = reflect.Append(reflect.ValueOf(getBuf()), f)
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/reflapp", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/reflapp"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	var backing [1]any
	reflapp.Stash(wrap.BoxExp(), func() []any { return backing[:0] })
	reflect.ValueOf(backing[0]).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "reflect_value_interface_written_through_callback_returned_pointer",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/reflptr",
						src: `package reflptr
import (
	"fmt"
	"reflect"
)
func StoreThrough(s fmt.Stringer, getDst func() *any) {
	*getDst() = reflect.ValueOf(s).Elem().Field(0).Interface()
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/reflptr", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/reflptr"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	var out any
	reflptr.StoreThrough(wrap.BoxExp(), func() *any { return &out })
	reflect.ValueOf(out).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "reflect_value_interface_appended_into_callback_spare_capacity_slice",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct {
	P   *desc.RouteTable
	buf []any
}
func (*expHolder) String() string { return "ok" }
func (h *expHolder) Buf() []any   { return h.buf }
func BoxExpWithBuf(buf []any) fmt.Stringer { return &expHolder{P: svc.PtrTable, buf: buf} }
`,
					},
					{
						pkgPath: "example.com/reflbuf",
						src: `package reflbuf
import (
	"fmt"
	"reflect"
)
func AppendInto(s fmt.Stringer) {
	if bh, ok := s.(interface{ Buf() []any }); ok {
		_ = append(bh.Buf(), reflect.ValueOf(s).Elem().Field(0).Interface())
	}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/reflbuf", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/reflbuf"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	var backing [1]any
	reflbuf.AppendInto(wrap.BoxExpWithBuf(backing[:0]))
	reflect.ValueOf(backing[0]).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "panic_carrier_interface_recovered_and_flagro_mutated_cross_package",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/thrower",
						imports: []string{"example.com/wrap"},
						src: `package thrower
import "example.com/wrap"
func Throw() { panic(wrap.Box()) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/svc", "example.com/thrower"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
	"example.com/thrower"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	func() {
		defer func() {
			r := recover()
			raw := reflect.ValueOf(r).Elem().Field(0).UnsafePointer()
			(*shadowRoute)(raw).Name = "evil"
		}()
		thrower.Throw()
	}()
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "panic_concrete_struct_wrapping_interface_recovered_and_mutated",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/svc"}, src: wrapSrc},
					{
						pkgPath: "example.com/thrower",
						imports: []string{"example.com/wrap"},
						src: `package thrower
import (
	"fmt"
	"example.com/wrap"
)
type panicBox struct{ s fmt.Stringer }
func ThrowBox() { panic(panicBox{s: wrap.Box()}) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/svc", "example.com/thrower"},
						src: `package app
import (
	"reflect"
	"example.com/desc"
	"example.com/svc"
	"example.com/thrower"
)
type shadowRoute struct{ Name string }
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	func() {
		defer func() {
			r := recover()
			raw := reflect.ValueOf(r).Field(0).Elem().Elem().Field(0).UnsafePointer()
			(*shadowRoute)(raw).Name = "evil"
		}()
		thrower.ThrowBox()
	}()
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "legacy_capsule_message_with_unexported_iface_field_extracts_across_package",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type ProtoMessage interface{ ProtoReflect() }
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
type ifaceHeader struct{ typ, data unsafe.Pointer }
func pointerOfIface(v any) pointer { return pointer{p: (*ifaceHeader)(unsafe.Pointer(&v)).data} }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	off           offset
	ft            reflect.Type
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	sf := mi.GoReflectType.Elem().Field(1)
	mi.off = offsetOf(sf)
	mi.ft = sf.Type
	atomic.StoreUint32(&mi.done, 1)
}
type msgWrap struct {
	p  pointer
	mi *MessageInfo
}
func (mi *MessageInfo) MessageOf(m any) *msgWrap {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("mismatch")
	}
	return &msgWrap{p: pointerOfIface(m), mi: mi}
}
func (w *msgWrap) ExtractField1() any {
	if atomic.LoadUint32(&w.mi.done) == 0 {
		w.mi.initOnce()
	}
	return w.p.Apply(w.mi.off).AsValueOf(w.mi.ft).Elem().Interface()
}
type MessageState struct {
	mi *MessageInfo
}
type Export struct{}
func (Export) LegacyExtract(m ProtoMessage) any {
	if m == nil {
		return nil
	}
	mi := &MessageInfo{GoReflectType: reflect.TypeOf(m)}
	return mi.MessageOf(m).ExtractField1()
}
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/cappkg"},
						src: `package smuggle
import (
	"fmt"
	"example.com/cappkg"
)
type smuggleMsg struct {
	Pad  int
	desc fmt.Stringer
}
func (*smuggleMsg) ProtoReflect() {}
func Hide(s fmt.Stringer) cappkg.ProtoMessage { return &smuggleMsg{Pad: 1, desc: s} }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	ext := cappkg.Export{}.LegacyExtract(smuggle.Hide(wrap.BoxExp()))
	reflect.ValueOf(ext).Elem().Field(0).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "legacy_capsule_other_opaque_struct_smuggling_revokes",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						src: `package cappkg
import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type ProtoMessage interface{ ProtoReflect() }
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
type ifaceHeader struct{ typ, data unsafe.Pointer }
func pointerOfIface(v any) pointer { return pointer{p: (*ifaceHeader)(unsafe.Pointer(&v)).data} }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	off           offset
	ft            reflect.Type
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	sf := mi.GoReflectType.Elem().Field(1)
	mi.off = offsetOf(sf)
	mi.ft = sf.Type
	atomic.StoreUint32(&mi.done, 1)
}
type msgWrap struct {
	p  pointer
	mi *MessageInfo
}
func (mi *MessageInfo) MessageOf(m any) *msgWrap {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("mismatch")
	}
	return &msgWrap{p: pointerOfIface(m), mi: mi}
}
func (w *msgWrap) ExtractField1() any {
	if atomic.LoadUint32(&w.mi.done) == 0 {
		w.mi.initOnce()
	}
	return w.p.Apply(w.mi.off).AsValueOf(w.mi.ft).Elem().Interface()
}
type MessageState struct {
	mi *MessageInfo
}
type innerOpaque struct {
	pad    int
	secret fmt.Stringer
}
type OtherOpaque struct {
	in *innerOpaque
}
func WrapOpaque(s fmt.Stringer) OtherOpaque {
	return OtherOpaque{in: &innerOpaque{pad: 1, secret: s}}
}
type Export struct{}
func (Export) LegacyExtract(m ProtoMessage) any {
	if m == nil {
		return nil
	}
	mi := &MessageInfo{GoReflectType: reflect.TypeOf(m)}
	return mi.MessageOf(m).ExtractField1()
}
`,
					},
					{
						pkgPath: "example.com/smuggle",
						imports: []string{"example.com/cappkg"},
						src: `package smuggle
import (
	"fmt"
	"example.com/cappkg"
)
type smuggleMsg struct {
	Pad int
	op  cappkg.OtherOpaque
}
func (*smuggleMsg) ProtoReflect() {}
func Hide(s fmt.Stringer) cappkg.ProtoMessage {
	return &smuggleMsg{Pad: 1, op: cappkg.WrapOpaque(s)}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/smuggle", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"unsafe"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/smuggle"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	ext := cappkg.Export{}.LegacyExtract(smuggle.Hide(wrap.BoxExp()))
	tmp := reflect.New(reflect.TypeOf(ext)).Elem()
	tmp.Set(reflect.ValueOf(ext))
	inRV := tmp.Field(0)
	secRV := reflect.NewAt(inRV.Type().Elem(), unsafe.Pointer(inRV.Pointer())).Elem().Field(1)
	reflect.NewAt(secRV.Type(), unsafe.Pointer(secRV.UnsafeAddr())).Elem().Elem().Elem().Field(0).Elem().Field(0).SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "cluster_message_without_messagestate_embedding_with_user_iface_field",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/cappkg",
						src: `package cappkg
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type offset uintptr
func offsetOf(f reflect.StructField) offset { return offset(f.Offset) }
type pointer struct{ p unsafe.Pointer }
type ifaceHeader struct{ typ, data unsafe.Pointer }
func pointerOfIface(v any) pointer { return pointer{p: (*ifaceHeader)(unsafe.Pointer(&v)).data} }
func (p pointer) IsNil() bool { return p.p == nil }
func (p pointer) Apply(f offset) pointer { return pointer{p: unsafe.Pointer(uintptr(p.p) + uintptr(f))} }
func (p pointer) AsValueOf(t reflect.Type) reflect.Value { return reflect.NewAt(t, p.p) }
type MessageInfo struct {
	GoReflectType reflect.Type
	mu            sync.Mutex
	done          uint32
	off           offset
}
func (mi *MessageInfo) initOnce() {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	if mi.done == 1 {
		return
	}
	mi.off = offsetOf(mi.GoReflectType.Elem().Field(1))
	atomic.StoreUint32(&mi.done, 1)
}
func (mi *MessageInfo) MutateViaIface(m any) {
	if reflect.TypeOf(m) != mi.GoReflectType {
		panic("mismatch")
	}
	if atomic.LoadUint32(&mi.done) == 0 {
		mi.initOnce()
	}
	rv := pointerOfIface(m).Apply(mi.off).AsValueOf(mi.GoReflectType.Elem().Field(1).Type).Elem()
	rv.Elem().Field(0).Elem().Field(0).SetString("evil")
}
type MessageState struct {
	mi *MessageInfo
}
type Builder struct {
	File         []byte
	NumEnums     int32
	NumMessages  int32
	GoTypes      []any
	MessageInfos []MessageInfo
}
func (b Builder) Build() {
	for i := int32(0); i < b.NumMessages; i++ {
		b.MessageInfos[i].GoReflectType = reflect.TypeOf(b.GoTypes[b.NumEnums+i])
	}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/cappkg", "example.com/desc", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"fmt"
	"example.com/cappkg"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
type MyMsg struct {
	Pad  int
	Desc fmt.Stringer
}
var msgTypes = make([]cappkg.MessageInfo, 1)
var goTypes = []any{(*MyMsg)(nil)}
func init() {
	cappkg.Builder{
		NumMessages:  1,
		GoTypes:      goTypes,
		MessageInfos: msgTypes,
	}.Build()
	m := &MyMsg{Pad: 1, Desc: wrap.BoxExp()}
	msgTypes[0].MutateViaIface(m)
	_, _ = Export()
}
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
`,
					},
				},
			},
			{
				name: "fmt_sprint_array_of_extracted_reflect_interface_uintptr_forgery",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/ifaces", "example.com/svc"},
						src: `package wrap
import (
	"example.com/desc"
	"example.com/ifaces"
	"example.com/svc"
)
type innerPtr struct{ p *desc.RouteTable }
type markerHolder struct{ sub *innerPtr }
func (*markerHolder) Mark() {}
func BoxMarker() ifaces.Marker { return &markerHolder{sub: &innerPtr{p: svc.PtrTable}} }
`,
					},
					{
						pkgPath: "example.com/sneak",
						imports: []string{"example.com/ifaces"},
						src: `package sneak
import (
	"fmt"
	"reflect"
	"example.com/ifaces"
)
func Leak(m ifaces.Marker) string {
	return fmt.Sprint([1]any{reflect.ValueOf(m).Elem().Field(0).Interface()})
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/sneak", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"strconv"
	"strings"
	"unsafe"
	"example.com/desc"
	"example.com/sneak"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	s := strings.Trim(sneak.Leak(wrap.BoxMarker()), "[]")
	u, _ := strconv.ParseUint(s, 0, 64)
	subPtr := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	reflect.NewAt(reflect.TypeOf(""), subPtr).Elem().SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "fmt_sprint_array_of_any_pointer_identity_uintptr_forgery",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/ifaces",
						src: `package ifaces
type Marker interface{ Mark() }
`,
					},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/ifaces", "example.com/svc"},
						src: `package wrap
import (
	"example.com/desc"
	"example.com/ifaces"
	"example.com/svc"
)
type markerHolder struct{ p *desc.RouteTable }
func (*markerHolder) Mark() {}
func BoxMarker() ifaces.Marker { return &markerHolder{p: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/fmtpkg",
						src: `package fmtpkg
import "fmt"
func HexArr(a any) string { return fmt.Sprint([1]any{a}) }
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/desc", "example.com/fmtpkg", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"reflect"
	"strconv"
	"strings"
	"unsafe"
	"example.com/desc"
	"example.com/fmtpkg"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	s := strings.Trim(fmtpkg.HexArr(wrap.BoxMarker()), "[]")
	u, _ := strconv.ParseUint(s, 0, 64)
	p := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(u)))
	reflect.NewAt(reflect.TypeOf(""), p).Elem().SetString("evil")
	_, _ = Export()
}
`,
					},
				},
			},
			{
				name: "cross_pkg_global_store_of_reflect_value_interface_revokes",
				specs: []orderedPkgSpec{
					{pkgPath: "example.com/desc", src: baseSchemaSrc},
					{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: baseProviderSrc},
					{
						pkgPath: "example.com/wrap",
						imports: []string{"example.com/desc", "example.com/svc"},
						src: `package wrap
import (
	"fmt"
	"example.com/desc"
	"example.com/svc"
)
type expHolder struct{ P *desc.RouteTable }
func (*expHolder) String() string { return "ok" }
func BoxExp() fmt.Stringer { return &expHolder{P: svc.PtrTable} }
`,
					},
					{
						pkgPath: "example.com/stash",
						src: `package stash
//gofresh:single-subject
var Saved any
`,
					},
					{
						pkgPath: "example.com/bridge",
						imports: []string{"example.com/stash"},
						src: `package bridge
import (
	"fmt"
	"reflect"
	"example.com/stash"
)
func Smuggle(s fmt.Stringer) {
	stash.Saved = reflect.ValueOf(s).Elem().Field(0).Interface()
}
`,
					},
					{
						pkgPath: "example.com/corruptor",
						imports: []string{"example.com/stash"},
						src: `package corruptor
import (
	"reflect"
	"example.com/stash"
)
func Mutate() {
	if stash.Saved != nil {
		reflect.ValueOf(stash.Saved).Elem().Field(0).SetString("evil")
	}
}
`,
					},
					{
						pkgPath: "example.com/app",
						imports: []string{"example.com/bridge", "example.com/corruptor", "example.com/desc", "example.com/svc", "example.com/wrap"},
						src: `package app
import (
	"example.com/bridge"
	"example.com/corruptor"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	bridge.Smuggle(wrap.BoxExp())
	corruptor.Mutate()
	_, _ = Export()
}
`,
					},
				},
			},
		} {
			metaAtk, _, factsAtk := mustTypecheckOrderedDAG(t, atk.specs)
			if atk.name == "legacy_capsule_message_with_unexported_iface_field_extracts_across_package" ||
				atk.name == "legacy_capsule_other_opaque_struct_smuggling_revokes" {
				caps := factsAtk["example.com/cappkg"][0].LazyOnceCapsuleTypes
				if !slices.ContainsFunc(caps, func(ct syntaxutil.LazyOnceCapsuleType) bool {
					return ct.Type.Name == "MessageInfo" && ct.CapsuleReflectSafe
				}) {
					t.Fatalf("expected clean MessageInfo with CapsuleReflectSafe=true in cappkg, got %+v", caps)
				}
			}
			if atk.name == "sibling_internal_reflect_type_constructor_revokes_unexported_capsule_struct" {
				caps := factsAtk["example.com/internal/cappkg"][0].LazyOnceCapsuleTypes
				if !slices.ContainsFunc(caps, func(ct syntaxutil.LazyOnceCapsuleType) bool {
					return ct.Type.Name == "messageInfo" && ct.CapsuleReflectSafe
				}) {
					t.Fatalf("expected clean unexported messageInfo with CapsuleReflectSafe=true in cappkg, got %+v", caps)
				}
			}
			if atk.name == "converter_typeof_foreign_scalar_struct_mutates_static_composite_directly" {
				caps := factsAtk["example.com/cappkg"][0].LazyOnceCapsuleTypes
				if slices.ContainsFunc(caps, func(ct syntaxutil.LazyOnceCapsuleType) bool { return ct.CapsuleReflectSafe }) {
					t.Fatalf("foreign scalar struct TypeOf unexpectedly kept CapsuleReflectSafe=true: %+v", caps)
				}
				continue
			}
			acAtk := AnalyzeCone(ConeQuery{Meta: metaAtk, Facts: factsAtk, ViewPackage: "example.com/app", SingleSubject: true})
			if acAtk.State.Downgraded == "" || acAtk.NonVouchDischarged["example.com/svc.ValTable"] || acAtk.NonVouchDischarged["example.com/svc.PtrTable"] {
				t.Fatalf("%s unexpectedly discharged cleanly: state=%+v nvd=%+v", atk.name, acAtk.State, acAtk.NonVouchDischarged)
			}
		}
	})
}

func TestUnifiedFlowIRMemoizersAndMappingRegions(t *testing.T) {
	t.Run("memo_discharges_rwmutex_helper_cone_and_pointer_identity_guards", func(t *testing.T) {
		cleanMemoSrc := `package rwmemo

import (
	"fmt"
	"reflect"
	"sync"
)

type structInfo struct {
	label  string
	fields map[string]int
}

var (
	cacheMu sync.RWMutex
	cache   = map[reflect.Type]*structInfo{}
)

func buildInfoLocked(rt reflect.Type) *structInfo {
	m := make(map[string]int, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type == rt {
			m[f.Name] = -1
		} else {
			m[f.Name] = i
		}
	}
	return &structInfo{
		label:  fmt.Sprintf("type:%s", rt),
		fields: m,
	}
}

func lookupInfo(rt reflect.Type) *structInfo {
	cacheMu.RLock()
	si, ok := cache[rt]
	if ok {
		cacheMu.RUnlock()
		return si
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if si, ok = cache[rt]; !ok {
		si = buildInfoLocked(rt)
		cache[rt] = si
	}
	return si
}

func LabelOf(v any) string {
	return lookupInfo(reflect.TypeOf(v)).label
}
`
		pkgClean := mustTypecheckPackage(t, "example.com/rwmemo", map[string]string{"memo.go": cleanMemoSrc})
		factClean := FactOf(true, pkgClean)
		if !slices.Contains(factClean.MemoDischarges, "example.com/rwmemo.cache") {
			t.Fatalf("clean RWMutex helper memoizer missing from MemoDischarges: %+v", factClean.MemoDischarges)
		}

		for _, neg := range []struct {
			name string
			src  string
		}{
			{
				name: "array_wrapped_pointer_identity_compare",
				src: strings.Replace(cleanMemoSrc,
					"si = buildInfoLocked(rt)",
					"si = buildInfoLocked(rt)\n\t\tif [1]*structInfo{si} == [1]*structInfo{nil} { return si }", 1),
			},
			{
				name: "switch_pointer_identity_compare",
				src: strings.Replace(cleanMemoSrc,
					"si = buildInfoLocked(rt)",
					"si = buildInfoLocked(rt)\n\t\tvar other *structInfo\n\t\tswitch si { case other: return si }", 1),
			},
			{
				name: "post_store_protected_map_mutation",
				src: strings.Replace(cleanMemoSrc,
					"cache[rt] = si",
					"cache[rt] = si\n\t\tsi.fields[\"late\"] = 99", 1),
			},
			{
				name: "fmt_trailing_unformatted_struct_arg",
				src: strings.Replace(cleanMemoSrc,
					"fmt.Sprintf(\"type:%s\", rt)",
					"fmt.Sprintf(\"fixed\", rt)", 1),
			},
			{
				name: "outside_cone_protected_ptr_equality_leak",
				src:  cleanMemoSrc + "\nfunc SameCached(a, b any) bool { return lookupInfo(reflect.TypeOf(a)) == lookupInfo(reflect.TypeOf(b)) }\n",
			},
			{
				name: "unlocked_map_read_outside_lock_region",
				src: strings.Replace(cleanMemoSrc,
					"cacheMu.RLock()",
					"_ = cache[rt]\n\tcacheMu.RLock()", 1),
			},
			{
				name: "seen_before_hit_miss_boolean_divergence",
				src: `package rwmemo
import (
	"reflect"
	"sync"
)
type structInfo struct{ n int }
var (
	cacheMu sync.Mutex
	cache   = map[reflect.Type]*structInfo{}
)
func SeenBefore(rt reflect.Type) bool {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if _, ok := cache[rt]; ok {
		return true
	}
	si := &structInfo{n: 1}
	cache[rt] = si
	return false
}
`,
			},
			{
				name: "cold_vs_warm_local_mismatch",
				src: strings.Replace(cleanMemoSrc,
					"if si, ok = cache[rt]; !ok {\n\t\tsi = buildInfoLocked(rt)\n\t\tcache[rt] = si\n\t}\n\treturn si",
					"if si, ok = cache[rt]; ok {\n\t\treturn si\n\t}\n\twarm := buildInfoLocked(rt)\n\tcold := &structInfo{label: \"cold\"}\n\tcache[rt] = warm\n\treturn cold", 1),
			},
			{
				name: "hit_vs_miss_field_projection_divergence",
				src: `package rwmemo
import (
	"reflect"
	"sync"
)
type structInfo struct{ a, b string }
var (
	cacheMu sync.Mutex
	cache   = map[reflect.Type]*structInfo{}
)
func Lookup(rt reflect.Type) string {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if si, ok := cache[rt]; ok {
		return si.a
	}
	si := &structInfo{a: "warm", b: "cold"}
	cache[rt] = si
	return si.b
}
`,
			},
			{
				name: "overwrite_entry_on_cache_hit",
				src: `package rwmemo
import (
	"reflect"
	"sync"
)
type structInfo struct{ label string }
var (
	cacheMu sync.Mutex
	cache   = map[reflect.Type]*structInfo{}
)
func Lookup(rt reflect.Type) string {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if si, ok := cache[rt]; ok {
		next := &structInfo{label: "warm"}
		cache[rt] = next
		return si.label
	}
	si := &structInfo{label: "cold"}
	cache[rt] = si
	return si.label
}
`,
			},
			{
				name: "helper_returning_nil_entry",
				src:  strings.Replace(cleanMemoSrc, "return &structInfo{\n\t\tlabel:  fmt.Sprintf(\"type:%s\", rt),\n\t\tfields: m,\n\t}", "if rt.Bits() == 0 { return nil }\n\treturn &structInfo{label: fmt.Sprintf(\"type:%s\", rt), fields: m}", 1),
			},
			{
				name: "hit_closure_rebinds_entry_holder",
				src: `package rwmemo
import (
	"reflect"
	"sync"
)
type structInfo struct{ label string }
var (
	mu    sync.RWMutex
	cache = map[reflect.Type]*structInfo{}
)
func Lookup(rt reflect.Type) string {
	mu.Lock()
	defer mu.Unlock()
	if si, ok := cache[rt]; ok {
		clobber := func() { si = &structInfo{label: "warm-evil"} }
		clobber()
		return si.label
	}
	si := &structInfo{label: "cold"}
	cache[rt] = si
	return si.label
}
`,
			},
			{
				name: "loop_break_clobbers_fresh_var_to_nil",
				src: `package rwmemo
import (
	"reflect"
	"sync"
)
type structInfo struct{ label string }
var (
	mu    sync.RWMutex
	cache = map[reflect.Type]*structInfo{}
)
func Lookup(rt reflect.Type) string {
	mu.Lock()
	defer mu.Unlock()
	if si, ok := cache[rt]; ok {
		return si.label
	}
	si := &structInfo{label: "cold"}
	for {
		si = nil
		break
	}
	cache[rt] = si
	return si.label
}
`,
			},
		} {
			t.Run(neg.name, func(t *testing.T) {
				p := mustTypecheckPackage(t, "example.com/rwmemo", map[string]string{"memo.go": neg.src})
				f := FactOf(true, p)
				if slices.Contains(f.MemoDischarges, "example.com/rwmemo.cache") {
					t.Fatalf("%s unexpectedly admitted into MemoDischarges: %+v", neg.name, f.MemoDischarges)
				}
			})
		}

		// Dotless third-party "reflect" package spoofing must never satisfy MemoDischarges.
		_, _, spoofFacts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "reflect",
				src: `package reflect
type Type interface{ Name() string }
var seq int
type fakeType struct{ n int }
func (fakeType) Name() string { return "x" }
func TypeOf(any) Type { seq++; return fakeType{n: seq} }
`,
			},
			{
				pkgPath: "example.com/spoofmemo",
				src: `package spoofmemo
import (
	"reflect"
	"sync"
)
type info struct{ s string }
var (
	mu sync.Mutex
	m  = map[reflect.Type]*info{}
)
func get(t reflect.Type) string {
	mu.Lock()
	defer mu.Unlock()
	v, ok := m[t]
	if !ok {
		v = &info{s: "const"}
		m[t] = v
	}
	return v.s
}
func Get(x any) string { return get(reflect.TypeOf(x)) }
`,
			},
		})
		if slices.Contains(spoofFacts["example.com/spoofmemo"][0].MemoDischarges, "example.com/spoofmemo.m") {
			t.Fatal("dotless third-party reflect package spoof unexpectedly admitted into MemoDischarges")
		}

		// Single-value nil-guarded lookup (`if si != nil { return si.label }`) with a
		// pre-store error early return must discharge cleanly.
		singleValMemoPkg := mustTypecheckPackage(t, "example.com/svlmemo", map[string]string{
			"memo.go": `package svlmemo
import (
	"errors"
	"reflect"
	"sync"
)
type structInfo struct{ label string }
var (
	mu    sync.Mutex
	cache = map[reflect.Type]*structInfo{}
)
func lookup(rt reflect.Type) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	si := cache[rt]
	if si != nil {
		return si.label, nil
	}
	if rt.Kind() != reflect.Struct {
		return "", errors.New("not struct")
	}
	si = &structInfo{label: rt.Name()}
	cache[rt] = si
	return si.label, nil
}
func Label(v any) (string, error) { return lookup(reflect.TypeOf(v)) }
`,
		})
		if !slices.Contains(FactOf(true, singleValMemoPkg).MemoDischarges, "example.com/svlmemo.cache") {
			t.Fatal("clean single-value nil-guarded MemoDischarges with pre-store error return rejected")
		}

		// Dotless third-party "bytes" Buffer spoofing must never satisfy fmt.Fprintf(&buf, ...) in the compute cone.
		_, _, spoofBytesFacts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "bytes",
				src: `package bytes
var writes int
type Buffer struct{}
func (b *Buffer) Write(p []byte) (int, error) {
	writes++
	return len(p), nil
}
`,
			},
			{
				pkgPath: "example.com/spooffprintf",
				imports: []string{"bytes"},
				src: `package spooffprintf
import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
)
type info struct{ s string }
var (
	mu sync.Mutex
	m  = map[reflect.Type]*info{}
)
func get(t reflect.Type) string {
	mu.Lock()
	defer mu.Unlock()
	v, ok := m[t]
	if ok {
		return v.s
	}
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "%s", t)
	v = &info{s: "ok"}
	m[t] = v
	return v.s
}
`,
			},
		})
		if slices.Contains(spoofBytesFacts["example.com/spooffprintf"][0].MemoDischarges, "example.com/spooffprintf.m") {
			t.Fatal("dotless third-party bytes.Buffer spoof unexpectedly admitted in fmt.Fprintf compute cone")
		}
	})

	t.Run("once_memo_sibling_map_range_error_switch_and_pointer_compare_guards", func(t *testing.T) {
		cleanOnceSrc := `package oncememo

import (
	"errors"
	"sync"
)

type DocData struct {
	Label string
	byID  map[string]int
}

func parseDoc() (*DocData, error) {
	d := &DocData{Label: "ok", byID: make(map[string]int)}
	d.byID["a"] = 1
	d.byID["b"] = 2
	return d, errors.New("empty")
}

type Index struct {
	once sync.Once
	doc  *DocData
	err  error
}

func NewIndex() *Index { return &Index{} }

func (ix *Index) Load() (*DocData, error) {
	ix.once.Do(func() {
		ix.doc, ix.err = parseDoc()
	})
	return ix.doc, ix.err
}

func (ix *Index) Sum() (int, error) {
	d, err := ix.Load()
	switch err {
	case nil:
	default:
	}
	total := 0
	for _, v := range d.byID {
		total += v
	}
	return total, err
}

var GlobalIndex = NewIndex()
func Use() (int, error) { return GlobalIndex.Sum() }
`
		pClean := mustTypecheckPackage(t, "example.com/oncememo", map[string]string{"once.go": cleanOnceSrc})
		fClean := FactOf(true, pClean)
		if len(fClean.OnceMemoTypes) != 1 || len(fClean.OnceMemoCandidates) != 1 {
			t.Fatalf("clean OnceMemo failed: types=%+v cands=%+v", fClean.OnceMemoTypes, fClean.OnceMemoCandidates)
		}

		for _, neg := range []struct {
			name string
			src  string
		}{
			{
				name: "map_range_inside_once_do_compute_cone",
				src: strings.Replace(cleanOnceSrc,
					"return d, errors.New(\"empty\")",
					"sum := 0\n\tfor _, v := range d.byID { sum += v }\n\t_ = sum\n\treturn d, errors.New(\"empty\")", 1),
			},
			{
				name: "array_wrapped_pointer_compare_in_once_do",
				src: strings.Replace(cleanOnceSrc,
					"return d, errors.New(\"empty\")",
					"type node struct{ x int }\n\tp1, p2 := &node{}, &node{}\n\tif [1]*node{p1} == [1]*node{p2} { return d, nil }\n\treturn d, errors.New(\"empty\")", 1),
			},
			{
				name: "switch_pointer_compare_in_sibling_method",
				src: strings.Replace(cleanOnceSrc,
					"total := 0",
					"type node struct{ x int }\n\tp1, p2 := &node{}, &node{}\n\tswitch p1 { case p2: return 0, nil }\n\ttotal := 0", 1),
			},
			{
				name: "unexported_struct_ptr_field_addr_marks_guard_struct",
				src: strings.Replace(cleanOnceSrc,
					"byID  map[string]int",
					"byID  map[string]int\n\tsub   *DocSub", 1) + "\ntype DocSub struct{ N int }\nfunc sinkSub(**DocSub) {}\nfunc ClobberSub(d *DocData) { sinkSub(&d.sub) }\n",
			},
		} {
			t.Run(neg.name, func(t *testing.T) {
				p := mustTypecheckPackage(t, "example.com/oncememo", map[string]string{"once.go": neg.src})
				f := FactOf(true, p)
				if neg.name == "unexported_struct_ptr_field_addr_marks_guard_struct" {
					if !slices.Contains(f.MutatedStructTypes, syntaxutil.TypeRef{Pkg: "example.com/oncememo", Name: "DocData"}) {
						t.Fatalf("expected DocData in MutatedStructTypes on &d.sub, got %+v", f.MutatedStructTypes)
					}
				}
				if len(f.OnceMemoTypes) != 0 {
					t.Fatalf("%s unexpectedly admitted OnceMemoTypes: %+v", neg.name, f.OnceMemoTypes)
				}
			})
		}
	})

	t.Run("mapping_discharges_lock_regions_and_syscall_leaf_coupling", func(t *testing.T) {
		cleanMapperSrc := `package mmapper

import (
	"sync"
	"syscall"
	"unsafe"
)

type mapper struct {
	sync.Mutex
	active map[*byte][]byte
	mmap   func(uintptr, uintptr) (uintptr, error)
	munmap func(uintptr, uintptr) error
}

func sysMmap(addr, length uintptr) (uintptr, error) {
	r0, _, e1 := syscall.Syscall6(syscall.SYS_MMAP, addr, length, 0, 0, 0, 0)
	if e1 != 0 {
		return 0, e1
	}
	return r0, nil
}

func sysMunmap(addr, length uintptr) error {
	_, _, e1 := syscall.Syscall(syscall.SYS_MUNMAP, addr, length, 0)
	if e1 != 0 {
		return e1
	}
	return nil
}

func (m *mapper) Map(length int) ([]byte, error) {
	if length <= 0 {
		return nil, syscall.EINVAL
	}
	addr, err := m.mmap(0, uintptr(length))
	if err != nil {
		return nil, err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)
	p := &b[cap(b)-1]
	m.Lock()
	if length == 1 {
		m.Unlock()
		return b, nil
	}
	m.active[p] = b
	m.Unlock()
	return b, nil
}

func (m *mapper) Unmap(data []byte) error {
	if len(data) == 0 || len(data) != cap(data) {
		return syscall.EINVAL
	}
	p := &data[cap(data)-1]
	m.Lock()
	b := m.active[p]
	if b == nil {
		m.Unlock()
		return syscall.EINVAL
	}
	delete(m.active, p)
	m.Unlock()
	return m.munmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

var defaultMapper = &mapper{
	active: make(map[*byte][]byte),
	mmap:   sysMmap,
	munmap: sysMunmap,
}

func RunMap() ([]byte, error) {
	return defaultMapper.Map(4096)
}
`
		pClean := mustTypecheckPackage(t, "example.com/mmapper", map[string]string{"map.go": cleanMapperSrc})
		fClean := FactOf(true, pClean)
		if !slices.Contains(fClean.MappingDischarges, "example.com/mmapper.defaultMapper") {
			t.Fatalf("clean branching lock-region mapper missing from MappingDischarges: %+v", fClean.MappingDischarges)
		}

		for _, neg := range []struct {
			name string
			src  string
		}{
			{
				name: "active_map_write_before_lock",
				src: strings.Replace(cleanMapperSrc,
					"m.Lock()\n\tif length == 1",
					"m.active[p] = b\n\tm.Lock()\n\tif length == 1", 1),
			},
			{
				name: "early_return_without_unlock",
				src: strings.Replace(cleanMapperSrc,
					"if length == 1 {\n\t\tm.Unlock()\n\t\treturn b, nil\n\t}",
					"if length == 1 {\n\t\treturn b, nil\n\t}", 1),
			},
			{
				name: "panic_under_non_deferred_lock",
				src: strings.Replace(cleanMapperSrc,
					"m.active[p] = b",
					"if length == 13 { panic(\"boom\") }\n\tm.active[p] = b", 1),
			},
			{
				name: "missing_kernel_syscall_leaf",
				src: strings.Replace(cleanMapperSrc,
					"r0, _, e1 := syscall.Syscall6(syscall.SYS_MMAP, addr, length, 0, 0, 0, 0)\n\tif e1 != 0 {\n\t\treturn 0, e1\n\t}\n\treturn r0, nil",
					"return addr, nil", 1),
			},
			{
				name: "pure_go_observer_method_without_syscall",
				src: cleanMapperSrc + `
func (m *mapper) IsMapped(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	return m.active[p] != nil
}
`,
			},
			{
				name: "delete_active_method_without_munmap_syscall",
				src: cleanMapperSrc + `
func (m *mapper) Evict(data []byte) {
	if len(data) == 0 {
		return
	}
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	delete(m.active, p)
}
`,
			},
			{
				name: "legacy_slice_header_over_preallocated_make_slice",
				src: strings.Replace(cleanMapperSrc,
					"b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)",
					"type sliceHdr struct { Data unsafe.Pointer; Len int; Cap int }\n\tb := make([]byte, length)\n\thdr := (*sliceHdr)(unsafe.Pointer(&b))\n\thdr.Data = unsafe.Pointer(addr)", 1),
			},
			{
				name: "legacy_slice_header_conditional_data_write",
				src: strings.Replace(cleanMapperSrc,
					"b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)",
					"type sliceHdr struct { Data unsafe.Pointer; Len int; Cap int }\n\tvar b []byte\n\thdr := (*sliceHdr)(unsafe.Pointer(&b))\n\tif length > 8 {\n\t\thdr.Data = unsafe.Pointer(addr)\n\t}", 1),
			},
		} {
			t.Run(neg.name, func(t *testing.T) {
				p := mustTypecheckPackage(t, "example.com/mmapper", map[string]string{"map.go": neg.src})
				f := FactOf(true, p)
				if slices.Contains(f.MappingDischarges, "example.com/mmapper.defaultMapper") {
					t.Fatalf("%s unexpectedly admitted into MappingDischarges: %+v", neg.name, f.MappingDischarges)
				}
			})
		}
	})

	t.Run("sync_map_data_memo_rejects_non_zero_init", func(t *testing.T) {
		p := mustTypecheckPackage(t, "example.com/syncmapinit", map[string]string{
			"sm.go": `package syncmapinit

import "sync"

func makePrepopulated() sync.Map { return sync.Map{} }

var zeroMap sync.Map
var emptyLitMap = sync.Map{}
var copiedMap = makePrepopulated()

func LookupZero(k string) string {
	v, _ := zeroMap.LoadOrStore(k, "val")
	s, _ := v.(string)
	return s
}

func LookupEmptyLit(k string) string {
	v, _ := emptyLitMap.LoadOrStore(k, "val")
	s, _ := v.(string)
	return s
}

func LookupCopied(k string) string {
	v, _ := copiedMap.LoadOrStore(k, "val")
	s, _ := v.(string)
	return s
}
`,
		})
		f := FactOf(true, p)
		for _, au := range f.AttributedUses {
			if au.Key == "example.com/syncmapinit.zeroMap" || au.Key == "example.com/syncmapinit.emptyLitMap" {
				t.Fatalf("zero/empty sync.Map memoizer unexpectedly recorded AttributedUse: %+v", au)
			}
		}
		hasCopiedUse := slices.ContainsFunc(f.AttributedUses, func(au syntaxutil.AttributedUse) bool {
			return au.Key == "example.com/syncmapinit.copiedMap" && au.Func.Name == "LookupCopied"
		})
		if !hasCopiedUse {
			t.Fatalf("non-zero-initialized sync.Map failed to record AttributedUse on LookupCopied: %+v", f.AttributedUses)
		}
	})
}

func TestPropertyAliasChainAndStaticCompositeTierInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		pkgs := []string{"example.com/obs", "example.com/top", "example.com/mid", "example.com/base"}
		meta := []GraphPackage{
			{ImportPath: pkgs[0], PkgPath: pkgs[0], Imports: []string{pkgs[1], pkgs[2], pkgs[3]}, Class: MutableLocalPackage},
			{ImportPath: pkgs[1], PkgPath: pkgs[1], Imports: []string{pkgs[2], pkgs[3]}, Class: MutableLocalPackage},
			{ImportPath: pkgs[2], PkgPath: pkgs[2], Imports: []string{pkgs[3]}, Class: PinnedPackage, Pin: "example.com/mid@v1.0.0"},
			{ImportPath: pkgs[3], PkgPath: pkgs[3], Class: PinnedPackage, Pin: "example.com/base@v1.0.0"},
		}

		// Draw root variable kind in example.com/base:
		// 0 = StaticCompositeGlobal, 1 = InitSettledCluster, 2 = OnceMemoCandidate, 3 = MemoDischarge, 4 = Undischarged.
		rootKind := rapid.IntRange(0, 4).Draw(rt, "rootKind")
		guardMutated := rapid.Bool().Draw(rt, "guardMutated")
		rootDirectWrite := rapid.Bool().Draw(rt, "rootDirectWrite")
		midDirectWrite := rapid.Bool().Draw(rt, "midDirectWrite")
		topDirectWrite := rapid.Bool().Draw(rt, "topDirectWrite")
		midDMO := rapid.Bool().Draw(rt, "midDMO")
		topDMO := rapid.Bool().Draw(rt, "topDMO")
		midNonMethod := rapid.Bool().Draw(rt, "midNonMethod")
		topNonMethod := rapid.Bool().Draw(rt, "topNonMethod")
		singleSubject := rapid.Bool().Draw(rt, "singleSubject")

		rootVar := "example.com/base.Root"
		midVar := "example.com/mid.Alias1"
		topVar := "example.com/top.Alias2"
		guardType := syntaxutil.TypeRef{Pkg: "example.com/base", Name: "GuardS"}
		onceType := syntaxutil.TypeRef{Pkg: "example.com/base", Name: "MemoS"}
		ctorFn := syntaxutil.FuncKey{Pkg: "example.com/base", Name: "NewMemoS"}
		initFn := syntaxutil.FuncKey{Pkg: "example.com/base", Name: "file_init"}

		baseFact := Fact{
			Declares:                []string{rootVar},
			Mutates:                 []string{rootVar},
			NoPostInitCarrierWrites: true,
		}
		switch rootKind {
		case 0:
			baseFact.StaticCompositeGlobals = []syntaxutil.StaticCompositeGlobalFact{{
				Key:        rootVar,
				GuardTypes: []syntaxutil.TypeRef{guardType},
			}}
		case 1:
			baseFact.FuncRefs = []syntaxutil.FuncRef{{
				Callee: initFn,
				Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit},
			}}
			baseFact.InitBuilders = []syntaxutil.InitBuilderFact{{
				Type:          syntaxutil.TypeRef{Pkg: "example.com/base", Name: "TB"},
				BuildMethod:   "Build",
				OutIfaceField: "File",
				CapsuleSliceFields: []syntaxutil.BuilderSliceSpec{{
					Field:    "ExtensionInfos",
					ElemType: syntaxutil.TypeRef{Pkg: "example.com/base", Name: "Ext"},
				}},
			}}
			baseFact.LazyOnceCapsuleTypes = []syntaxutil.LazyOnceCapsuleType{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/base", Name: "Ext"},
				GuardTypes: []syntaxutil.TypeRef{guardType},
			}}
			baseFact.InitSettledClusters = []syntaxutil.InitSettledClusterFact{{
				InitFn:        initFn,
				Vars:          []string{rootVar},
				BuilderType:   syntaxutil.TypeRef{Pkg: "example.com/base", Name: "TB"},
				BuildMethod:   "Build",
				OutIfaceField: "File",
				SliceBindings: []syntaxutil.ClusterCapsuleSliceBinding{{
					Field:         "ExtensionInfos",
					CapsuleType:   syntaxutil.TypeRef{Pkg: "example.com/base", Name: "Ext"},
					StaticLiteral: true,
				}},
			}}
		case 2:
			baseFact.OnceMemoTypes = []syntaxutil.OnceMemoTypeFact{{
				Type:         onceType,
				Constructors: []syntaxutil.FuncKey{ctorFn},
				GuardTypes:   []syntaxutil.TypeRef{guardType, onceType},
			}}
			baseFact.OnceMemoCandidates = []syntaxutil.OnceMemoVarCandidate{{
				Key:         rootVar,
				Type:        onceType,
				Constructor: ctorFn,
			}}
		case 3:
			baseFact.MemoDischarges = []string{rootVar}
		}

		midFact := Fact{
			Declares: []string{midVar},
			Mutates:  []string{midVar},
			ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
				Key:               midVar,
				Target:            rootVar,
				DirectMethodsOnly: midDMO,
			}},
		}

		topFact := Fact{
			Declares: []string{topVar},
			Mutates:  []string{topVar},
			ReadOnlyVarAliases: []syntaxutil.ReadOnlyVarAlias{{
				Key:               topVar,
				Target:            midVar,
				DirectMethodsOnly: topDMO,
			}},
		}

		var obsFact Fact
		if rootDirectWrite {
			obsFact.DirectVarWrites = append(obsFact.DirectVarWrites, rootVar)
		}
		if midDirectWrite {
			obsFact.DirectVarWrites = append(obsFact.DirectVarWrites, midVar)
		}
		if topDirectWrite {
			obsFact.DirectVarWrites = append(obsFact.DirectVarWrites, topVar)
		}
		if midNonMethod {
			obsFact.NonMethodVarUses = append(obsFact.NonMethodVarUses, midVar)
		}
		if topNonMethod {
			obsFact.NonMethodVarUses = append(obsFact.NonMethodVarUses, topVar)
		}
		if guardMutated {
			obsFact.MutatedStructTypes = []syntaxutil.TypeRef{guardType}
		}

		facts := map[string][]Fact{
			pkgs[0]: {obsFact},
			pkgs[1]: {topFact},
			pkgs[2]: {midFact},
			pkgs[3]: {baseFact},
		}

		ac := AnalyzeCone(ConeQuery{
			Meta:          meta,
			Facts:         facts,
			ViewPackage:   pkgs[0],
			SingleSubject: singleSubject,
		})

		midValidAlias := !midDirectWrite
		topValidAlias := !topDirectWrite
		midDMOEff := midValidAlias && midDMO
		topDMOEff := topValidAlias && topDMO

		topEffNM := topNonMethod || !topDMOEff
		midEffNM := midNonMethod || !midDMOEff || topEffNM
		rootEffNM := midEffNM

		var wantRootDischarged, wantMidDischarged, wantTopDischarged bool
		var wantAttested bool
		switch rootKind {
		case 0:
			wantRootDischarged = !rootDirectWrite && !guardMutated
			wantMidDischarged = wantRootDischarged && midValidAlias
			wantTopDischarged = wantMidDischarged && topValidAlias
		case 1:
			if singleSubject {
				wantRootDischarged = !rootDirectWrite && !guardMutated
				wantMidDischarged = wantRootDischarged && midValidAlias
				wantTopDischarged = wantMidDischarged && topValidAlias
				wantAttested = true
			}
		case 2:
			wantRootDischarged = !rootDirectWrite && !guardMutated && !rootEffNM
			wantMidDischarged = wantRootDischarged && midDMOEff && !midEffNM
			wantTopDischarged = wantMidDischarged && topDMOEff && !topEffNM
		case 3:
			wantRootDischarged = !rootDirectWrite
			wantMidDischarged = false
			wantTopDischarged = false
		case 4:
			wantRootDischarged = false
			wantMidDischarged = false
			wantTopDischarged = false
		}

		for _, chk := range []struct {
			key  string
			want bool
		}{
			{rootVar, wantRootDischarged},
			{midVar, wantMidDischarged},
			{topVar, wantTopDischarged},
		} {
			if got := ac.NonVouchDischarged[chk.key]; got != chk.want {
				rt.Fatalf("NonVouchDischarged[%s] = %v, want %v (rootKind=%d guardMut=%v writes=[%v,%v,%v] dmo=[%v,%v] nm=[%v,%v] single=%v)",
					chk.key, got, chk.want, rootKind, guardMutated, rootDirectWrite, midDirectWrite, topDirectWrite, midDMO, topDMO, midNonMethod, topNonMethod, singleSubject)
			}
			hasCulprit := slices.ContainsFunc(ac.State.RootCulprits, func(c Culprit) bool { return c.Key == chk.key })
			if hasCulprit == chk.want {
				rt.Fatalf("RootCulprit[%s] = %v, want %v", chk.key, hasCulprit, !chk.want)
			}
		}

		var wantAttList []string
		if wantAttested {
			if wantRootDischarged {
				wantAttList = append(wantAttList, rootVar)
			}
			if wantMidDischarged {
				wantAttList = append(wantAttList, midVar)
			}
			if wantTopDischarged {
				wantAttList = append(wantAttList, topVar)
			}
			slices.Sort(wantAttList)
		}
		wantAttStr := strings.Join(wantAttList, ",")
		if ac.State.AttestationDischarges != wantAttStr {
			rt.Fatalf("AttestationDischarges = %q, want %q", ac.State.AttestationDischarges, wantAttStr)
		}

		if gotCompose := Compose(meta, facts, pkgs[0], nil, singleSubject, false); !reflect.DeepEqual(gotCompose, ac.State) {
			rt.Fatalf("Compose != AnalyzeCone.State: %+v vs %+v", gotCompose, ac.State)
		}
		if gotNVD := NonVouchDischargedVars(meta, facts, singleSubject); !reflect.DeepEqual(gotNVD, ac.NonVouchDischarged) {
			rt.Fatalf("NonVouchDischargedVars != AnalyzeCone.NonVouchDischarged: %+v vs %+v", gotNVD, ac.NonVouchDischarged)
		}
		_ = fmt.Sprint
	})
}

func TestDynstateTraceCausalReasonsAndZeroDisabledCost(t *testing.T) {
	meta, pkgs, facts := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
		{
			pkgPath: "example.com/cand",
			src: `package cand
import (
	"reflect"
	"sync"
)
type BadComposite struct {
	Fn   func() int
	Mut  chan int
}
func noop() int { return 1 }
var Comp = BadComposite{Fn: noop}

var BadMemo = map[reflect.Type]int{}

type BadOnce struct {
	once sync.Once
	val  []int
}
func (b *BadOnce) Get(x int) []int {
	b.once.Do(func() { b.val = []int{x} })
	return b.val
}
`,
		},
		{
			pkgPath: "example.com/mapcand",
			src: `package mapcand
import (
	"sync"
	"syscall"
)
type badMapper struct {
	sync.Mutex
	mmap func() error
}
var m = &badMapper{}
var _ = syscall.EINVAL
`,
		},
	})

	eventField := func(ev trace.Event, key string) string {
		for _, f := range ev.Fields {
			if f.Key == key {
				return f.Str
			}
		}
		return ""
	}

	t.Run("exact_causal_reject_reasons_and_zero_unrelated_noise", func(t *testing.T) {
		rec := trace.NewRecorder()
		baseCtx, cancel := context.WithCancel(context.Background())
		ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
		defer func() {
			cancel()
			_ = trace.Enabled(ctx, trace.DomainDynstate, "")
		}()

		_ = FactOfCtx(ctx, true, pkgs["example.com/cand"])
		mapCandTypesOnly := *pkgs["example.com/mapcand"]
		mapCandTypesOnly.Imports = nil
		_ = FactOfCtx(ctx, true, &mapCandTypesOnly)

		rejects := rec.ByName("dynstate.discharge.reject")
		hasReject := func(target, kind, symbol, reason string) bool {
			for _, ev := range rejects {
				if ev.Target == target &&
					eventField(ev, "kind") == kind &&
					eventField(ev, "symbol") == symbol &&
					eventField(ev, "reason") == reason {
					return true
				}
			}
			return false
		}

		if !hasReject("example.com/cand", "static_composite", "example.com/cand.Comp", "schema_rejected") {
			t.Fatalf("missing static_composite schema_rejected trace event; got %+v", rejects)
		}
		if !hasReject("example.com/cand", "memo", "example.com/cand.BadMemo", "nil, exported, or multi-def mapVar") {
			t.Fatalf("missing memo exported-mapVar trace event; got %+v", rejects)
		}
		if !hasReject("example.com/cand", "once_memo_type", "example.com/cand.BadOnce", "struct_verification_failed") {
			t.Fatalf("missing once_memo_type struct_verification_failed trace event; got %+v", rejects)
		}
		if !hasReject("example.com/mapcand", "mapping", "example.com/mapcand.m", "missing_mutex_or_active_or_callables") {
			t.Fatalf("missing mapping missing_mutex_or_active_or_callables trace event; got %+v", rejects)
		}
		for _, ev := range rejects {
			if ev.Target == "example.com/cand" && eventField(ev, "kind") == "mapping" {
				t.Fatalf("unexpected noisy mapping reject in non-syscall package: %+v", ev)
			}
			if ev.Target == "example.com/cand" && eventField(ev, "kind") == "memo" && eventField(ev, "symbol") == "example.com/cand.Comp" {
				t.Fatalf("unexpected noisy memo reject on non-map global: %+v", ev)
			}
			if ev.Target == "example.com/cand" && eventField(ev, "kind") == "once_memo_type" && eventField(ev, "symbol") == "example.com/cand.BadComposite" {
				t.Fatalf("unexpected noisy once_memo_type reject on struct without sync.Once: %+v", ev)
			}
			if ev.Target == "example.com/cand" && eventField(ev, "kind") == "static_composite" && eventField(ev, "symbol") == "example.com/cand.BadMemo" {
				t.Fatalf("unexpected noisy static_composite reject on map global: %+v", ev)
			}
		}
	})

	t.Run("zero_disabled_trace_allocation_overhead", func(t *testing.T) {
		if trace.AnyEnabled() {
			t.Skip("ambient GOFRESH_TRACE is active")
		}
		_, extPkgs, _ := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{
				pkgPath: "example.com/extcand",
				src: `package extcand
import (
	"fmt"
	"reflect"
	"sort"
)
func Inspect(s fmt.Stringer) {
	nums, _ := reflect.ValueOf(s).Interface().([]int)
	sort.IntSlice(nums).Sort()
}
`,
			},
		})
		candPkg := pkgs["example.com/cand"]
		extCandPkg := extPkgs["example.com/extcand"]
		ctx := context.Background()
		allocsFactNil := testing.AllocsPerRun(20, func() {
			_ = FactOfCtx(nil, true, candPkg)
			_ = FactOfCtx(nil, true, extCandPkg)
		})
		allocsFactCtx := testing.AllocsPerRun(20, func() {
			_ = FactOfCtx(ctx, true, candPkg)
			_ = FactOfCtx(ctx, true, extCandPkg)
		})
		if allocsFactCtx > allocsFactNil {
			t.Fatalf("disabled trace added allocations to FactOfCtx: ctx=%v vs nil=%v", allocsFactCtx, allocsFactNil)
		}

		qNil := ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/cand", SingleSubject: true}
		qCtx := ConeQuery{Ctx: ctx, Meta: meta, Facts: facts, ViewPackage: "example.com/cand", SingleSubject: true}
		allocsConeNil := testing.AllocsPerRun(50, func() {
			_ = AnalyzeCone(qNil)
		})
		allocsConeCtx := testing.AllocsPerRun(50, func() {
			_ = AnalyzeCone(qCtx)
		})
		if allocsConeCtx > allocsConeNil {
			t.Fatalf("disabled trace added allocations to AnalyzeCone: ctx=%v vs nil=%v", allocsConeCtx, allocsConeNil)
		}
	})
}

func TestReflectInterfaceExtractedSliceAndPtrInPlaceMutationsRevokeDischarges(t *testing.T) {
	descSrc := `package desc
type EndpointSpec struct {
	Route   string
	Handler func() int
}
type RouteTable struct {
	Name      string
	Endpoints []EndpointSpec
}
`
	svcSrc := `package svc
import "example.com/desc"
func one() int { return 1 }
var ValTable = desc.RouteTable{
	Name:      "v1",
	Endpoints: []desc.EndpointSpec{{Route: "/ok", Handler: one}},
}
var PtrTable = &desc.RouteTable{
	Name:      "p1",
	Endpoints: []desc.EndpointSpec{{Route: "/ptr", Handler: one}},
}
`
	sealedSrc := `package sealed
type Token interface{ SealedInternal(Token) }
`
	evilSrc := `package evil
import "reflect"
type ByteMutator struct {
	B []byte
}
func (m *ByteMutator) String() string {
	if len(m.B) > 0 {
		m.B[0] ^= 0xff
	}
	return "mutated"
}
type RVHook interface {
	InvokeRV(reflect.Value) int
}
func RunHook(h RVHook, rv reflect.Value) int {
	return h.InvokeRV(rv)
}
func RunHookMap(m map[any]int, rv reflect.Value) int {
	for k := range m {
		if h, ok := k.(RVHook); ok {
			return h.InvokeRV(rv)
		}
	}
	return 0
}
func RunHookAny(v any, rv reflect.Value) int {
	if h, ok := reflect.ValueOf(v).Call(nil)[0].Interface().(RVHook); ok {
		return h.InvokeRV(rv)
	}
	return 0
}
func RunHookIfaceAny(v any, rv reflect.Value) int {
	if h, ok := v.(RVHook); ok {
		return h.InvokeRV(rv)
	}
	return 0
}
type RVPoker struct{}
func (RVPoker) Poke(rv reflect.Value) {
	rv.Elem().FieldByName("Name").SetString("tampered")
}
func PokePair(_ int, rv reflect.Value) {
	rv.Elem().FieldByName("Name").SetString("tampered")
}
type RVSlice []reflect.Value
func (s RVSlice) Poke() {
	s[0].Elem().FieldByName("Name").SetString("tampered")
}
func RunZeroArg(fn func()) {
	fn()
}
var Slot reflect.Value
func PokeSlot() {
	Slot.Elem().FieldByName("Name").SetString("tampered")
}
var Ch = make(chan reflect.Value, 1)
func PokeChan() {
	rv := <-Ch
	rv.Elem().FieldByName("Name").SetString("tampered")
}
func MutateAny(x any) {
	reflect.ValueOf(x).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
}
func MutateGen[T any](x T) {
	reflect.ValueOf(x).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
}
type AnyBox struct {
	Slot any
}
func NewAnyBox() (*AnyBox, func()) {
	b := &AnyBox{}
	return b, func() { MutateAny(b.Slot) }
}
func AllocAnySlice() ([]any, func()) {
	s := make([]any, 1)
	return s, func() { MutateAny(s[0]) }
}
type RVSource interface {
	MakeRV() reflect.Value
}
func ConsumeRVSource(src RVSource) {
	src.MakeRV().Elem().FieldByName("Name").SetString("tampered")
}
func ConsumeCloser(c any) {
	if src, ok := c.(RVSource); ok {
		src.MakeRV().Elem().FieldByName("Name").SetString("tampered")
	}
}
type GenSink[T any] struct{}
func (GenSink[T]) Consume(v T) {
	ConsumeCloser(v)
}
func ConsumeUnwrappedError(err error) {
	if u, ok := err.(interface{ Unwrap() error }); ok {
		ConsumeCloser(u.Unwrap())
	}
}
`
	wrapSrc := `package wrap
import (
	"bytes"
	"io"
	"sort"
	"example.com/desc"
	"example.com/internal/sealed"
	"example.com/svc"
)
type View interface{ ViewDesc() }
type Swapper interface{ Swap(int, int) }
type SealedMeta interface {
	Meta() string
	sealed.Token
}
type SealedChain interface {
	GetMeta() SealedMeta
	sealed.Token
}
type SealedWriterSource interface {
	Writer() interface{ WriteString(string) (int, error) }
	sealed.Token
}
type SealedSorter interface {
	SortInPlace()
	sealed.Token
}
type metaImpl struct{ label string }
func (m metaImpl) Meta() string               { return m.label }
func (metaImpl) SealedInternal(sealed.Token) {}
type chainImpl struct{ m SealedMeta }
func (c chainImpl) GetMeta() SealedMeta       { return c.m }
func (chainImpl) SealedInternal(sealed.Token) {}
type wsImpl struct{ w io.StringWriter }
func (s wsImpl) Writer() interface{ WriteString(string) (int, error) } { return s.w }
func (wsImpl) SealedInternal(sealed.Token)                             {}
type intSorter sort.IntSlice
func (s intSorter) SortInPlace()              { sort.IntSlice(s).Sort() }
func (intSorter) SealedInternal(sealed.Token) {}
type OuterSealedWS struct {
	WS SealedWriterSource
}
func (OuterSealedWS) SealedInternal(sealed.Token) {}
type holder struct {
	Table    *desc.RouteTable
	Raw      []byte
	Nums     []int
	Sorted   sort.IntSlice
	Tags     map[string]int
	Writer   io.Writer
	Sealed   SealedMeta
	Chain    SealedChain
	SealedWS SealedWriterSource
	OuterWS  OuterSealedWS
	Sorter   SealedSorter
	Ch       chan int
}
func (*holder) ViewDesc() {}
func MakeView() View {
	buf := new(bytes.Buffer)
	sm := metaImpl{label: "v1"}
	ws := wsImpl{w: buf}
	return &holder{
		Table:    svc.PtrTable,
		Raw:      []byte{1, 2, 3},
		Nums:     []int{3, 1, 2},
		Sorted:   sort.IntSlice{3, 1, 2},
		Tags:     map[string]int{"k": 1},
		Writer:   buf,
		Sealed:   sm,
		Chain:    chainImpl{m: sm},
		SealedWS: ws,
		OuterWS:  OuterSealedWS{WS: ws},
		Sorter:   intSorter{3, 1, 2},
		Ch:       make(chan int, 1),
	}
}
`
	t.Run("positive_readonly_formatter_with_local_and_unexported_struct_slices_stays_discharged", func(t *testing.T) {
		rec := trace.NewRecorder()
		baseCtx, cancel := context.WithCancel(context.Background())
		ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
		defer func() {
			cancel()
			_ = trace.Enabled(ctx, trace.DomainDynstate, "")
		}()
		meta, pkgs, _ := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
			{pkgPath: "example.com/desc", src: descSrc},
			{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: svcSrc},
			{pkgPath: "example.com/internal/sealed", src: sealedSrc},
			{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/internal/sealed", "example.com/svc"}, src: wrapSrc},
			{
				pkgPath: "example.com/fmtter",
				imports: []string{"example.com/wrap"},
				src: `package fmtter
import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"example.com/wrap"
)
type methodAndName struct {
	method reflect.Value
	name   string
}
type records struct {
	recs [][2]string
}
func (rs *records) add(k, v string) {
	rs.recs = append(rs.recs, [2]string{k, v})
}
func (rs *records) Append(v reflect.Value, accessors ...methodAndName) {
	for _, a := range accessors {
		if a.method.IsValid() {
			rv := a.method.Call(nil)[0]
			rs.add(a.name, rv.String())
		}
	}
	if v.Kind() == reflect.Interface {
		rs.add("kind", v.Type().String())
	}
}
func joinStrings(ss []string, multi bool) string {
	if multi {
		return strings.Join(ss, ";")
	}
	return strings.Join(ss, ",")
}
func FormatState(s fmt.State, vw wrap.View) {
	if s.Flag('+') {
		_, _ = io.WriteString(s, FormatView(s, vw))
	}
}
func FormatView(w io.Writer, vw wrap.View) string {
	var rs records
	v := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface()
	switch x := v.(type) {
	case []byte:
		rs.add("raw", string(fmt.Append(nil, fmt.Sprintf("%x", x))))
	}
	if tb, ok := reflect.TypeAssert[[]byte](reflect.ValueOf(vw).Elem().FieldByName("Raw")); ok {
		rs.add("ta", fmt.Sprintf("%x", tb))
	}
	if sm, ok := reflect.ValueOf(vw).Elem().FieldByName("Sealed").Interface().(wrap.SealedMeta); ok {
		rs.add("meta", sm.Meta())
		smRV := reflect.ValueOf(sm)
		rs.Append(smRV, methodAndName{method: smRV.MethodByName("Meta"), name: "mcall"})
	}
	if sc, ok := reflect.ValueOf(vw).Elem().FieldByName("Chain").Interface().(wrap.SealedChain); ok {
		sub := reflect.ValueOf(sc).MethodByName("GetMeta").Call(nil)[0]
		rs.add("chain", sub.MethodByName("Meta").Call(nil)[0].String())
	}
	var ss []string
	for _, r := range rs.recs {
		ss = append(ss, r[0]+"="+strings.Join(strings.Split(r[1], "\n"), "\n\t"))
	}
	out := joinStrings(ss, false)
	_, _ = fmt.Fprintf(w, "%s", out)
	_, _ = io.WriteString(w, out)
	return out
}
`,
			},
			{
				pkgPath: "example.com/app",
				imports: []string{"example.com/desc", "example.com/fmtter", "example.com/svc", "example.com/wrap"},
				src: `package app
import (
	"bytes"
	"example.com/desc"
	"example.com/fmtter"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	var buf bytes.Buffer
	_ = fmtter.FormatView(&buf, wrap.MakeView())
	_, _ = Export()
}
`,
			},
		})
		facts := make(map[string][]Fact, len(pkgs))
		for _, p := range pkgs {
			facts[p.PkgPath] = []Fact{FactOfCtx(ctx, true, p)}
		}
		ac := AnalyzeCone(ConeQuery{Ctx: ctx, Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
		if ac.State.Downgraded != "" {
			t.Fatalf("read-only formatter unexpectedly downgraded StaticCompositeGlobals: %q (culprits=%v)", ac.State.Downgraded, ac.State.RootCulprits)
		}
		for _, want := range []string{"example.com/svc.ValTable", "example.com/svc.PtrTable"} {
			if !ac.NonVouchDischarged[want] {
				t.Fatalf("missing %s in NonVouchDischarged: %+v", want, ac.NonVouchDischarged)
			}
		}
		for _, ev := range rec.ByName("dynstate.iface.reflected") {
			if ev.Target == "example.com/fmtter" {
				for _, f := range ev.Fields {
					if f.Key == "method_set" && strings.HasPrefix(f.Str, "ViewDesc:") {
						t.Fatalf("read-only formatter unexpectedly emitted reflected ViewDesc event: %+v", ev)
					}
				}
			}
		}
	})

	for _, tc := range []struct {
		name              string
		corruptSrc        string
		corruptImports    []string
		appExtraImports   []string
		appCall           string
		skipExtractEscape bool
	}{
		{
			name: "index_write_on_extracted_byte_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	b[0] ^= 0xff
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "clear_builtin_on_extracted_byte_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	clear(b)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "copy_builtin_into_extracted_byte_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	copy(b, []byte{9})
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "append_into_subsliced_extracted_byte_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	_ = append(b[:0], 0xff)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "extracted_byte_slice_returned_across_pkg_and_mutated_by_caller_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func ExtractBytes(vw wrap.View) []byte {
	return reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
}
`,
			appCall: `corrupt.ExtractBytes(wrap.MakeView())[0] ^= 0xff`,
		},
		{
			name: "delete_builtin_on_extracted_scalar_map_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	m := reflect.ValueOf(vw).Elem().FieldByName("Tags").Interface().(map[string]int)
	delete(m, "k")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "sort_intslice_concrete_recv_method_on_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"sort"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	nums := reflect.ValueOf(vw).Elem().FieldByName("Sorted").Interface().(sort.IntSlice)
	nums.Sort()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "method_bearing_slice_conv_boxed_in_external_iface_swap_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"sort"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	nums := reflect.ValueOf(vw).Elem().FieldByName("Nums").Interface().([]int)
	var sw wrap.Swapper = sort.IntSlice(nums)
	sw.Swap(0, 1)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "unnamed_struct_conv_into_unexported_struct_slice_field_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
type records struct {
	recs []byte
}
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	r := records(struct{ recs []byte }{b})
	clear(r.recs)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "unexported_helper_param_called_with_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func wipe(buf []byte) {
	clear(buf)
}
func Tamper(vw wrap.View) {
	wipe([]byte{1, 2})
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	wipe(b)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "func_value_escaped_unexported_helper_param_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func wipe(buf []byte) {
	clear(buf)
}
func Tamper(vw wrap.View) {
	fn := wipe
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	fn(b)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "ptr_field_write_on_extracted_struct_ptr_revokes",
			corruptImports: []string{"example.com/desc", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/desc"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	tbl := reflect.ValueOf(vw).Elem().FieldByName("Table").Interface().(*desc.RouteTable)
	tbl.Name = "tampered"
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "slice_to_array_ptr_conv_index_write_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	p := (*[1]byte)(b)
	p[0] ^= 0xff
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "generic_type_param_slice_index_write_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func wipe[S ~[]byte](buf S) {
	buf[0] ^= 0xff
}
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	wipe(b)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "fmt_append_spare_cap_into_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"fmt"
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	_ = fmt.Append(b[:0], "tampered")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "log_setoutput_with_extracted_writer_revokes",
			corruptSrc: `package corrupt
import (
	"io"
	"log"
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	w := reflect.ValueOf(vw).Elem().FieldByName("Writer").Interface().(io.Writer)
	log.SetOutput(w)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "stdlib_sort_interface_swap_on_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"sort"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	si := reflect.ValueOf(vw).Elem().FieldByName("Sorted").Interface().(sort.Interface)
	si.Swap(0, 1)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "external_unsealed_swapper_iface_swap_on_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	sw := reflect.ValueOf(vw).Elem().FieldByName("Sorted").Interface().(wrap.Swapper)
	sw.Swap(0, 1)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "bound_method_val_sort_on_extracted_slice_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"sort"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	nums := reflect.ValueOf(vw).Elem().FieldByName("Sorted").Interface().(sort.IntSlice)
	fn := nums.Sort
	fn()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "foreign_method_composite_lit_stringer_mutator_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"fmt"
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	_ = fmt.Sprint(&evil.ByteMutator{B: b})
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "foreign_ptr_receiver_struct_conv_stringer_mutator_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"fmt"
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b := reflect.ValueOf(vw).Elem().FieldByName("Raw").Interface().([]byte)
	box := evil.ByteMutator(struct{ B []byte }{b})
	_ = fmt.Sprint(&box)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:            "typeassert_cross_pkg_any_return_revokes",
			appExtraImports: []string{"reflect"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Extract(vw wrap.View) any {
	v, _ := reflect.TypeAssert[any](reflect.ValueOf(vw).Elem().FieldByName("Table"))
	return v
}
`,
			appCall: `reflect.ValueOf(corrupt.Extract(wrap.MakeView())).Elem().FieldByName("Name").SetString("tampered")`,
		},
		{
			name: "typeassert_extracted_byte_slice_index_write_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	b, _ := reflect.TypeAssert[[]byte](reflect.ValueOf(vw).Elem().FieldByName("Raw"))
	b[0] ^= 0xff
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "reflect_methodbyname_sort_call_on_field_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	reflect.ValueOf(vw).Elem().FieldByName("Sorted").MethodByName("Sort").Call(nil)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "reflect_methodbyname_writestring_call_with_indexed_result_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	out := reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem().MethodByName("WriteString").Call([]reflect.Value{
		reflect.ValueOf("tampered"),
	})
	return int(out[0].Int())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "reflect_value_chan_close_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	reflect.ValueOf(vw).Elem().FieldByName("Ch").Close()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "reflect_value_chan_recv_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	_, _ = reflect.ValueOf(vw).Elem().FieldByName("Ch").Recv()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "switch_fallthrough_unsealed_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	sm := reflect.ValueOf(vw).Elem().FieldByName("Sealed").Interface().(wrap.SealedMeta)
	rv := reflect.ValueOf(sm)
	switch 0 {
	case 0:
		rv = reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem()
		fallthrough
	default:
	}
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "for_init_post_reassigned_unsealed_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	sm := reflect.ValueOf(vw).Elem().FieldByName("Sealed").Interface().(wrap.SealedMeta)
	total := 0
	for rv, i := reflect.ValueOf(sm), 0; i < 2; rv, i = reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem(), i+1 {
		if i == 1 {
			out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
			total += int(out[0].Int())
		}
	}
	return total
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "unexported_struct_exported_method_external_iface_reflect_call_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) InvokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func Tamper(vw wrap.View) int {
	return evil.RunHook(&hookImpl{}, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "unexported_struct_exported_method_intra_pkg_nested_iface_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) InvokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func runNested(hooks []interface{ InvokeRV(reflect.Value) int }, rv reflect.Value) int {
	return hooks[0].InvokeRV(rv)
}
func Tamper(vw wrap.View) int {
	return runNested([]interface{ InvokeRV(reflect.Value) int }{&hookImpl{}}, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "unexported_struct_unexported_method_intra_pkg_nested_iface_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) invokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func runNested(hooks []interface{ invokeRV(reflect.Value) int }, rv reflect.Value) int {
	return hooks[0].invokeRV(rv)
}
func Tamper(vw wrap.View) int {
	return runNested([]interface{ invokeRV(reflect.Value) int }{&hookImpl{}}, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "chained_reflect_call_into_unsealed_result_iface_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	ws := reflect.ValueOf(vw).Elem().FieldByName("SealedWS").Interface().(wrap.SealedWriterSource)
	wRV := reflect.ValueOf(ws).MethodByName("Writer").Call(nil)[0]
	out := wRV.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "unindexed_void_reflect_call_len_result_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	ss := reflect.ValueOf(vw).Elem().FieldByName("Sorter").Interface().(wrap.SealedSorter)
	res := reflect.ValueOf(ss).MethodByName("SortInPlace").Call(nil)
	return len(res)
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "indexed_void_mutator_on_sealed_iface_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	ss := reflect.ValueOf(vw).Elem().FieldByName("Sorter").Interface().(wrap.SealedSorter)
	return int(reflect.ValueOf(ss).MethodByName("SortInPlace").Call(nil)[0].Int())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "reflect_value_seq_on_chan_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	for range reflect.ValueOf(vw).Elem().FieldByName("Ch").Seq() {
		break
	}
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "local_iface_method_call_passing_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type localPoker interface {
	Poke(reflect.Value)
}
func Tamper(vw wrap.View) {
	var p localPoker = evil.RVPoker{}
	p.Poke(reflect.ValueOf(vw).Elem().FieldByName("Table"))
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "cross_pkg_tuple_arg_passing_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func pairRV(vw wrap.View) (int, reflect.Value) {
	return 1, reflect.ValueOf(vw).Elem().FieldByName("Table")
}
func Tamper(vw wrap.View) {
	evil.PokePair(pairRV(vw))
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name: "outer_sealed_struct_with_level1_field_chained_reflect_call_revokes",
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) int {
	ov := reflect.ValueOf(vw).Elem().FieldByName("OuterWS").Interface().(wrap.OuterSealedWS)
	wRV := reflect.ValueOf(ov).FieldByName("WS").MethodByName("Writer").Call(nil)[0]
	out := wRV.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "unexported_struct_exported_method_map_key_iface_escape_reflect_call_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) InvokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func Tamper(vw wrap.View) int {
	m := map[any]int{}
	m[&hookImpl{}] = 1
	return evil.RunHookMap(m, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "unexported_struct_exported_method_tuple_return_iface_escape_reflect_call_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) InvokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func pair() (int, *hookImpl) {
	return 1, &hookImpl{}
}
func boxPair() (int, any) {
	return pair()
}
func Tamper(vw wrap.View) int {
	n, h := boxPair()
	return n + evil.RunHookIfaceAny(h, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:           "unexported_struct_exported_method_closure_sig_iface_escape_reflect_call_revokes",
			corruptImports: []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type hookImpl struct{}
func (h *hookImpl) InvokeRV(rv reflect.Value) int {
	out := rv.MethodByName("WriteString").Call([]reflect.Value{reflect.ValueOf("tampered")})
	return int(out[0].Int())
}
func Tamper(vw wrap.View) int {
	var fn any = func() *hookImpl {
		return &hookImpl{}
	}
	return evil.RunHookAny(fn, reflect.ValueOf(vw).Elem().FieldByName("Writer").Elem())
}
`,
			appCall: `_ = corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "cross_pkg_method_recv_carrying_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	s := evil.RVSlice{reflect.ValueOf(vw).Elem().FieldByName("Table")}
	s.Poke()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "cross_pkg_bound_method_val_carrying_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	s := evil.RVSlice{reflect.ValueOf(vw).Elem().FieldByName("Table")}
	evil.RunZeroArg(s.Poke)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "cross_pkg_global_slot_assign_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			appExtraImports:   []string{"example.com/evil"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	evil.Slot = reflect.ValueOf(vw).Elem().FieldByName("Table")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView()); evil.PokeSlot()`,
		},
		{
			name:              "cross_pkg_chan_send_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			appExtraImports:   []string{"example.com/evil"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	evil.Ch <- reflect.ValueOf(vw).Elem().FieldByName("Table")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView()); evil.PokeChan()`,
		},
		{
			name:              "already_erased_any_passed_to_cross_pkg_any_param_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	var a any = vw
	evil.MutateAny(a)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "type_assert_to_any_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	a := vw.(any)
	reflect.ValueOf(a).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "type_switch_case_any_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	switch a := vw.(type) {
	case any:
		reflect.ValueOf(a).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
	}
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "range_assign_to_any_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	var a any
	for _, a = range []wrap.View{vw} {
		reflect.ValueOf(a).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
	}
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "one_tuple_append_into_any_slice_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func pairSliceView(vw wrap.View) ([]any, wrap.View) {
	return nil, vw
}
func Tamper(vw wrap.View) {
	s := append(pairSliceView(vw))
	reflect.ValueOf(s[0]).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "intra_pkg_generic_type_param_to_any_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/wrap"
)
func idAny[T any](x T) any {
	return x
}
func Tamper(vw wrap.View) {
	a := idAny(vw)
	reflect.ValueOf(a).Elem().FieldByName("Table").Elem().FieldByName("Name").SetString("tampered")
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "cross_pkg_generic_type_param_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	evil.MutateGen(vw)
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "subprojected_unexported_field_foreign_box_any_store_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"example.com/evil"
	"example.com/wrap"
)
type localState struct {
	box *evil.AnyBox
}
func Tamper(vw wrap.View) {
	b, run := evil.NewAnyBox()
	st := localState{box: b}
	var a any = vw
	st.box.Slot = a
	run()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "foreign_result_any_slice_copy_reflect_mutation_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"example.com/evil"
	"example.com/wrap"
)
func Tamper(vw wrap.View) {
	s, run := evil.AllocAnySlice()
	copy(s, []any{vw})
	run()
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "type_assert_extract_any_slice_from_param_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/wrap"},
			appExtraImports:   []string{"example.com/evil"},
			corruptSrc: `package corrupt
import "example.com/wrap"
func Fill(x any, vw wrap.View) {
	if s, ok := x.([]any); ok {
		copy(s, []any{vw})
	}
}
`,
			appCall: `s, run := evil.AllocAnySlice(); corrupt.Fill(s, wrap.MakeView()); run()`,
		},
		{
			name:              "callback_iface_param_exposing_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type rvMaker struct {
	vw wrap.View
}
func (m rvMaker) MakeRV() reflect.Value {
	return reflect.ValueOf(m.vw).Elem().FieldByName("Table")
}
func Tamper(vw wrap.View) {
	evil.ConsumeRVSource(rvMaker{vw: vw})
}
`,
			appCall: `corrupt.Tamper(wrap.MakeView())`,
		},
		{
			name:              "concrete_boxed_into_io_closer_exposing_reflect_value_method_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/wrap"},
			appExtraImports:   []string{"example.com/evil"},
			corruptSrc: `package corrupt
import (
	"io"
	"reflect"
	"example.com/wrap"
)
type rvCloser struct {
	vw wrap.View
}
func (rvCloser) Close() error { return nil }
func (m rvCloser) MakeRV() reflect.Value {
	return reflect.ValueOf(m.vw).Elem().FieldByName("Table")
}
func NewCloser(vw wrap.View) io.Closer {
	return rvCloser{vw: vw}
}
`,
			appCall: `evil.ConsumeCloser(corrupt.NewCloser(wrap.MakeView()))`,
		},
		{
			name:              "typed_nil_concrete_arg_to_foreign_call_exposing_reflect_value_method_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type rvCloser struct{}
func (*rvCloser) Close() error { return nil }
func (*rvCloser) MakeRV() reflect.Value {
	return reflect.ValueOf(wrap.MakeView()).Elem().FieldByName("Table")
}
func Tamper() {
	evil.ConsumeCloser((*rvCloser)(nil))
}
`,
			appCall: `_ = wrap.MakeView(); corrupt.Tamper()`,
		},
		{
			name:              "empty_struct_composite_lit_arg_to_generic_method_exposing_reflect_value_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/evil", "example.com/wrap"},
			corruptSrc: `package corrupt
import (
	"io"
	"reflect"
	"example.com/evil"
	"example.com/wrap"
)
type rvCloser struct{}
func (rvCloser) Close() error { return nil }
func (rvCloser) MakeRV() reflect.Value {
	return reflect.ValueOf(wrap.MakeView()).Elem().FieldByName("Table")
}
func Tamper() {
	var s evil.GenSink[io.Closer]
	s.Consume(rvCloser{})
}
`,
			appCall: `_ = wrap.MakeView(); corrupt.Tamper()`,
		},
		{
			name:              "fmt_errorf_wrap_empty_struct_exposing_reflect_value_method_revokes",
			skipExtractEscape: true,
			corruptImports:    []string{"example.com/wrap"},
			appExtraImports:   []string{"example.com/evil"},
			corruptSrc: `package corrupt
import (
	"fmt"
	"reflect"
	"example.com/wrap"
)
type rvErr struct{}
func (rvErr) Error() string { return "err" }
func (rvErr) MakeRV() reflect.Value {
	return reflect.ValueOf(wrap.MakeView()).Elem().FieldByName("Table")
}
func MakeErr() error {
	return fmt.Errorf("wrap: %w", rvErr{})
}
`,
			appCall: `_ = wrap.MakeView(); evil.ConsumeUnwrappedError(corrupt.MakeErr())`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := trace.NewRecorder()
			baseCtx, cancel := context.WithCancel(context.Background())
			ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
			defer func() {
				cancel()
				_ = trace.Enabled(ctx, trace.DomainDynstate, "")
			}()
			cImps := tc.corruptImports
			if len(cImps) == 0 {
				cImps = []string{"example.com/wrap"}
			}
			appImps := append([]string{"example.com/corrupt", "example.com/desc", "example.com/svc", "example.com/wrap"}, tc.appExtraImports...)
			var extraImportLines strings.Builder
			for _, imp := range tc.appExtraImports {
				extraImportLines.WriteString("\t\"" + imp + "\"\n")
			}
			meta, pkgs, _ := mustTypecheckOrderedDAG(t, []orderedPkgSpec{
				{pkgPath: "example.com/desc", src: descSrc},
				{pkgPath: "example.com/svc", imports: []string{"example.com/desc"}, src: svcSrc},
				{pkgPath: "example.com/internal/sealed", src: sealedSrc},
				{pkgPath: "example.com/evil", src: evilSrc},
				{pkgPath: "example.com/wrap", imports: []string{"example.com/desc", "example.com/internal/sealed", "example.com/svc"}, src: wrapSrc},
				{pkgPath: "example.com/corrupt", imports: cImps, src: tc.corruptSrc},
				{
					pkgPath: "example.com/app",
					imports: appImps,
					src: "package app\nimport (\n" + extraImportLines.String() + `	"example.com/corrupt"
	"example.com/desc"
	"example.com/svc"
	"example.com/wrap"
)
func Export() (*desc.RouteTable, *desc.RouteTable) { return &svc.ValTable, svc.PtrTable }
func init() {
	` + tc.appCall + `
	_, _ = Export()
}
`,
				},
			})
			facts := make(map[string][]Fact, len(pkgs))
			for _, p := range pkgs {
				facts[p.PkgPath] = []Fact{FactOfCtx(ctx, true, p)}
			}
			ac := AnalyzeCone(ConeQuery{Ctx: ctx, Meta: meta, Facts: facts, ViewPackage: "example.com/app", SingleSubject: false})
			if ac.State.Downgraded == "" || ac.NonVouchDischarged["example.com/svc.ValTable"] || ac.NonVouchDischarged["example.com/svc.PtrTable"] {
				t.Fatalf("%s failed to revoke StaticCompositeGlobals: state=%+v nvd=%+v", tc.name, ac.State, ac.NonVouchDischarged)
			}
			if !tc.skipExtractEscape {
				sawExtractEsc := false
				for _, ev := range rec.ByName("dynstate.extract.escape") {
					if ev.Target == "example.com/corrupt" {
						sawExtractEsc = true
						break
					}
				}
				if !sawExtractEsc {
					t.Fatalf("%s missing causal dynstate.extract.escape event on example.com/corrupt: events=%+v", tc.name, rec.Events())
				}
			}
			sawViewDescRefl := false
			for _, ev := range rec.ByName("dynstate.iface.reflected") {
				if ev.Target == "example.com/corrupt" {
					for _, f := range ev.Fields {
						if f.Key == "method_set" && strings.HasPrefix(f.Str, "ViewDesc:") {
							sawViewDescRefl = true
						}
					}
				}
			}
			if !sawViewDescRefl {
				t.Fatalf("%s missing causal dynstate.iface.reflected ViewDesc event on example.com/corrupt: events=%+v", tc.name, rec.Events())
			}
		})
	}
}

func TestNonProtoSyntheticCapsuleClusterConeDischargesAndRefusals(t *testing.T) {
	const valPkgSrc = `package valpkg

import "unsafe"

type CatalogIface interface {
	SchemaName() string
}

type SpecIface interface {
	SpecID() int
}

type Datum struct {
	ptr unsafe.Pointer
	raw []byte
	num uint64
}

func FromBytes(b []byte) Datum { return Datum{raw: b, num: 1} }
func (d Datum) Present() bool   { return d.num != 0 }
func (d Datum) AnyVal() any {
	if d.raw != nil {
		return d.raw
	}
	return d.num
}
func (d Datum) RawBytes() []byte { return d.raw }
`

	const rawBuildSrc = `package rawbuild

import (
	"bytes"
	"sync"
	"sync/atomic"

	"example.com/valpkg"
)

type datumHolder struct {
	val  valpkg.Datum
	snap []byte
}

func makeDatumHolder(v valpkg.Datum) datumHolder {
	dh := datumHolder{val: v}
	if b, ok := v.AnyVal().([]byte); ok {
		dh.snap = append(([]byte)(nil), b...)
	}
	return dh
}

func (dh *datumHolder) get() valpkg.Datum {
	if len(dh.snap) > 0 && !bytes.Equal(dh.snap, dh.val.RawBytes()) {
		panic("mutated snapshot")
	}
	return dh.val
}

type catalogMeta struct {
	count int
}

type rawCatalog struct {
	name string
	mu   sync.Mutex
	done uint32
	sub  catalogMeta
	tags []TagSpec
	recs []RecordSpec
	exts []ExtSpec
}

func (c *rawCatalog) lazyInit() {
	if atomic.LoadUint32(&c.done) == 0 {
		c.initOnce()
	}
}

func (c *rawCatalog) initOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done == 1 {
		return
	}
	c.sub.count = len(c.recs)
	for i := range c.recs {
		c.recs[i].resolveDefault()
	}
	atomic.StoreUint32(&c.done, 1)
}

func (c *rawCatalog) SchemaName() string {
	c.lazyInit()
	return c.name
}

func (c *rawCatalog) Meta() *catalogMeta {
	c.lazyInit()
	return &c.sub
}

type TagSpec struct {
	id int
}

func (ts *TagSpec) SpecID() int { return ts.id }

type RecordSpec struct {
	id   int
	wire []byte
	Def  datumHolder
	Note int
}

func (rs *RecordSpec) SpecID() int { return rs.id }

func (rs *RecordSpec) resolveDefault() {
	if v := rs.Def.val; v.Present() {
		rs.Def = makeDatumHolder(v)
	}
}

func (rs *RecordSpec) DefaultDatum() valpkg.Datum {
	return rs.Def.get()
}

type ExtSpec struct {
	id int
}

func (es *ExtSpec) SpecID() int { return es.id }

type RawBundle struct {
	Catalog     valpkg.CatalogIface
	TagSpecs    []TagSpec
	RecordSpecs []RecordSpec
	ExtSpecs    []ExtSpec
}

type RawAssembler struct {
	RawWire []byte
	NumTags int
	NumRecs int
	NumExts int
}

func (ra RawAssembler) Assemble() RawBundle {
	cat := &rawCatalog{
		name: string(ra.RawWire),
		tags: make([]TagSpec, ra.NumTags),
		recs: make([]RecordSpec, ra.NumRecs),
		exts: make([]ExtSpec, ra.NumExts),
	}
	for i := range cat.recs {
		cat.recs[i].wire = append(([]byte)(nil), ra.RawWire...)
		cat.recs[i].Def = makeDatumHolder(valpkg.FromBytes(cat.recs[i].wire))
	}
	return RawBundle{
		Catalog:     cat,
		TagSpecs:    cat.tags,
		RecordSpecs: cat.recs,
		ExtSpecs:    cat.exts,
	}
}
`

	const schemaCapSrc = `package schemacap

import (
	"reflect"
	"sync"
	"sync/atomic"

	"example.com/valpkg"
)

type TagCapsule struct {
	ReflectTyp reflect.Type
	Spec       valpkg.SpecIface
}

type recordDetail struct {
	fieldCount int
}

type RecordCapsule struct {
	ReflectTyp reflect.Type
	Spec       valpkg.SpecIface
	mu         sync.Mutex
	done       uint32
	sub        recordDetail
}

func (rc *RecordCapsule) init() {
	if atomic.LoadUint32(&rc.done) == 0 {
		rc.initSlow()
	}
}

func (rc *RecordCapsule) initSlow() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.done == 1 {
		return
	}
	rc.sub.fieldCount = rc.Spec.SpecID()
	atomic.StoreUint32(&rc.done, 1)
}

func (rc *RecordCapsule) Detail() *recordDetail {
	rc.init()
	return &rc.sub
}

type ExtCapsule struct {
	GuardSlot any
	spec      valpkg.SpecIface
	mu        sync.Mutex
	done      uint32
	resolved  int
}

func InitExtCapsule(ec *ExtCapsule, sp valpkg.SpecIface) {
	ec.spec = sp
}

func (ec *ExtCapsule) init() {
	if atomic.LoadUint32(&ec.done) == 1 {
		return
	}
	ec.initSlow()
}

func (ec *ExtCapsule) initSlow() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if ec.done == 1 {
		return
	}
	if ec.GuardSlot == nil {
		ec.GuardSlot = ec.spec.SpecID()
	}
	ec.resolved = 1
	atomic.StoreUint32(&ec.done, 1)
}

func (ec *ExtCapsule) Resolved() int {
	ec.init()
	return ec.resolved
}
`

	const typeBuildSrc = `package typebuild

import (
	"reflect"

	"example.com/rawbuild"
	"example.com/schemacap"
	"example.com/valpkg"
)

type BuiltSchema struct {
	Catalog valpkg.CatalogIface
}

type SchemaBuilder struct {
	Sub            rawbuild.RawAssembler
	TypeSamples    []any
	TagCapsules    []schemacap.TagCapsule
	RecordCapsules []schemacap.RecordCapsule
	ExtCapsules    []schemacap.ExtCapsule
}

func (b SchemaBuilder) Construct() BuiltSchema {
	rb := b.Sub.Assemble()
	if len(b.TagCapsules) != len(rb.TagSpecs) {
		panic("tag mismatch")
	}
	if len(b.RecordCapsules) != len(rb.RecordSpecs) {
		panic("record mismatch")
	}
	if len(b.ExtCapsules) != len(rb.ExtSpecs) {
		panic("ext mismatch")
	}
	for i := range rb.TagSpecs {
		b.TagCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[i])
		b.TagCapsules[i].Spec = &rb.TagSpecs[i]
	}
	for i := range rb.RecordSpecs {
		b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.TagCapsules)+i])
		b.RecordCapsules[i].Spec = &rb.RecordSpecs[i]
	}
	for i := range rb.ExtSpecs {
		schemacap.InitExtCapsule(&b.ExtCapsules[i], &rb.ExtSpecs[i])
	}
	return BuiltSchema{Catalog: rb.Catalog}
}
`

	const genPkgSrc = `package genpkg

import (
	"example.com/rawbuild"
	"example.com/schemacap"
	"example.com/typebuild"
	"example.com/valpkg"
)

type SampleTag int

type SampleRecord struct {
	Code int
}

var schemaCatalog valpkg.CatalogIface

var rawWire = []byte("schema_v1")

var typeSamples = []any{
	(SampleTag)(0),
	(*SampleRecord)(nil),
}

var tagCaps = make([]schemacap.TagCapsule, 1)
var recCaps = make([]schemacap.RecordCapsule, 1)
var extCaps = []schemacap.ExtCapsule{
	{GuardSlot: (*int32)(nil)},
}

func init() {
	schemaInit()
}

func schemaInit() {
	if schemaCatalog != nil {
		return
	}
	out := typebuild.SchemaBuilder{
		Sub: rawbuild.RawAssembler{
			RawWire: rawWire,
			NumTags: 1,
			NumRecs: 1,
			NumExts: 1,
		},
		TypeSamples:    typeSamples,
		TagCapsules:    tagCaps,
		RecordCapsules: recCaps,
		ExtCapsules:    extCaps,
	}.Construct()
	schemaCatalog = out.Catalog
	rawWire = nil
	typeSamples = nil
}

func ReadSchemaName() string {
	return schemaCatalog.SchemaName()
}
`

	baseSpecs := func() []orderedPkgSpec {
		return []orderedPkgSpec{
			{pkgPath: "example.com/valpkg", src: valPkgSrc},
			{pkgPath: "example.com/rawbuild", imports: []string{"example.com/valpkg"}, src: rawBuildSrc},
			{pkgPath: "example.com/schemacap", imports: []string{"example.com/valpkg"}, src: schemaCapSrc},
			{pkgPath: "example.com/typebuild", imports: []string{"example.com/rawbuild", "example.com/schemacap", "example.com/valpkg"}, src: typeBuildSrc},
			{pkgPath: "example.com/genpkg", imports: []string{"example.com/rawbuild", "example.com/schemacap", "example.com/typebuild", "example.com/valpkg"}, src: genPkgSrc},
		}
	}

	t.Run("positive_single_subject_discharges_and_multi_subject_refuses", func(t *testing.T) {
		meta, pkgs, _ := mustTypecheckOrderedDAG(t, baseSpecs())
		facts := make(map[string][]Fact, len(pkgs))
		for _, p := range pkgs {
			facts[p.PkgPath] = []Fact{FactOfCtx(context.Background(), true, p)}
		}
		acSingle := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/genpkg", SingleSubject: true})
		if acSingle.State.Downgraded != "" || len(acSingle.State.RootCulprits) != 0 {
			t.Fatalf("expected SingleSubject=true clean discharge, got state=%+v", acSingle.State)
		}
		for _, wantVar := range []string{
			"example.com/genpkg.schemaCatalog",
			"example.com/genpkg.typeSamples",
			"example.com/genpkg.tagCaps",
			"example.com/genpkg.recCaps",
			"example.com/genpkg.extCaps",
		} {
			if !acSingle.NonVouchDischarged[wantVar] {
				t.Fatalf("expected %s in NonVouchDischarged, got %+v", wantVar, acSingle.NonVouchDischarged)
			}
		}
		acMulti := AnalyzeCone(ConeQuery{Meta: meta, Facts: facts, ViewPackage: "example.com/genpkg", SingleSubject: false})
		if acMulti.State.Downgraded == "" {
			t.Fatalf("expected SingleSubject=false to retain cluster globals as stateful, got %+v", acMulti.State)
		}
	})

	type negConeCase struct {
		name           string
		mutatePkg      string
		oldSnippet     string
		newSnippet     string
		extraSnippet   string
		wantEvent      string
		wantKind       string
		wantSymbol     string
		wantReason     string
	}

	negCases := []negConeCase{
		{
			name:       "a_untyped_nil_guard_slot",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "{GuardSlot: (*int32)(nil)}",
			newSnippet: "{GuardSlot: nil}",
			wantEvent:  "dynstate.discharge.reject",
			wantKind:   "init_cluster",
			wantSymbol: "example.com/genpkg.schemaInit",
			wantReason: "missing_exported_write_guard_field",
		},
		{
			name:         "b_non_builder_init_helper_ref",
			mutatePkg:    "example.com/genpkg",
			extraSnippet: "\nfunc TouchHelper(ec *schemacap.ExtCapsule, sp valpkg.SpecIface) { schemacap.InitExtCapsule(ec, sp) }\n",
			wantEvent:    "dynstate.discharge.reject",
			wantKind:     "capsule_type",
			wantSymbol:   "example.com/schemacap.ExtCapsule",
			wantReason:   "non_builder_init_helper_ref",
		},
		{
			name:       "c_omitted_bytes_equal_snapshot_panic",
			mutatePkg:  "example.com/rawbuild",
			oldSnippet: "if len(dh.snap) > 0 && !bytes.Equal(dh.snap, dh.val.RawBytes()) {\n\t\tpanic(\"mutated snapshot\")\n\t}",
			newSnippet: "_ = bytes.Equal",
			wantEvent:  "dynstate.discharge.reject",
			wantKind:   "init_builder",
			wantSymbol: "example.com/typebuild.SchemaBuilder",
			wantReason: "unverified_sub_builder",
		},
		{
			name:       "d_substruct_addr_before_once_init_dominance",
			mutatePkg:  "example.com/schemacap",
			oldSnippet: "func (rc *RecordCapsule) Detail() *recordDetail {\n\trc.init()\n\treturn &rc.sub\n}",
			newSnippet: "func (rc *RecordCapsule) Detail() *recordDetail {\n\tif rc.done == 99 {\n\t\trc.init()\n\t}\n\treturn &rc.sub\n}",
			wantEvent:  "dynstate.discharge.reject",
			wantKind:   "init_cluster",
			wantSymbol: "example.com/genpkg.schemaInit",
			wantReason: "unverified_capsule_type",
		},
		{
			name:       "e_misaligned_sample_slice_offset",
			mutatePkg:  "example.com/typebuild",
			oldSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.TagCapsules)+i])",
			newSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[i])",
			wantEvent:  "dynstate.discharge.reject",
			wantKind:   "init_cluster",
			wantSymbol: "example.com/genpkg.schemaInit",
			wantReason: "unverified_builder",
		},
		{
			name:         "f_guard_type_mutated",
			mutatePkg:    "example.com/genpkg",
			extraSnippet: "\nfunc CorruptGuard(rs *rawbuild.RecordSpec) { rs.Note = 7 }\n",
			wantEvent:    "dynstate.discharge.reject",
			wantKind:     "init_builder",
			wantSymbol:   "example.com/rawbuild.RawAssembler",
			wantReason:   "guard_type_mutated",
		},
	}

	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := trace.NewRecorder()
			baseCtx, cancel := context.WithCancel(context.Background())
			ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
			defer func() {
				cancel()
				_ = trace.Enabled(ctx, trace.DomainDynstate, "")
			}()

			specs := baseSpecs()
			mutated := false
			for i := range specs {
				if specs[i].pkgPath == tc.mutatePkg {
					if tc.oldSnippet != "" {
						if !strings.Contains(specs[i].src, tc.oldSnippet) {
							t.Fatalf("missing oldSnippet in %s", tc.mutatePkg)
						}
						specs[i].src = strings.Replace(specs[i].src, tc.oldSnippet, tc.newSnippet, 1)
					}
					specs[i].src += tc.extraSnippet
					mutated = true
				}
			}
			if !mutated {
				t.Fatalf("mutatePkg %s not found", tc.mutatePkg)
			}

			meta, pkgs, _ := mustTypecheckOrderedDAG(t, specs)
			facts := make(map[string][]Fact, len(pkgs))
			for _, p := range pkgs {
				facts[p.PkgPath] = []Fact{FactOfCtx(ctx, true, p)}
			}
			ac := AnalyzeCone(ConeQuery{Ctx: ctx, Meta: meta, Facts: facts, ViewPackage: "example.com/genpkg", SingleSubject: true})
			if ac.NonVouchDischarged["example.com/genpkg.schemaCatalog"] {
				t.Fatalf("%s unexpectedly discharged schemaCatalog: state=%+v nvd=%+v", tc.name, ac.State, ac.NonVouchDischarged)
			}

			matched := false
			for _, ev := range rec.ByName(tc.wantEvent) {
				if ev.StringField("kind") == tc.wantKind &&
					ev.StringField("symbol") == tc.wantSymbol &&
					ev.StringField("reason") == tc.wantReason {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("%s missing causal %s(kind=%q, symbol=%q, reason=%q); events=%+v",
					tc.name, tc.wantEvent, tc.wantKind, tc.wantSymbol, tc.wantReason, rec.Events())
			}
		})
	}
}
