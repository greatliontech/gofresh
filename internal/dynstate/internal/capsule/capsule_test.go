package capsule

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

type multiPkgImporter struct {
	std  types.Importer
	pkgs map[string]*types.Package
}

func (m *multiPkgImporter) Import(path string) (*types.Package, error) {
	if p, ok := m.pkgs[path]; ok {
		return p, nil
	}
	return m.std.Import(path)
}

type testPkgSpec struct {
	pkgPath string
	src     string
}

func typecheckOrderedPkgs(t *testing.T, specs []testPkgSpec) map[string]*packages.Package {
	t.Helper()
	imp := &multiPkgImporter{
		std:  importer.Default(),
		pkgs: make(map[string]*types.Package, len(specs)),
	}
	out := make(map[string]*packages.Package, len(specs))
	for _, sp := range specs {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "p.go", sp.src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", sp.pkgPath, err)
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Instances:  make(map[*ast.Ident]types.Instance),
		}
		conf := types.Config{Importer: imp}
		tpkg, err := conf.Check(sp.pkgPath, fset, []*ast.File{file}, info)
		if err != nil {
			t.Fatalf("typecheck %s: %v", sp.pkgPath, err)
		}
		imp.pkgs[sp.pkgPath] = tpkg
		imports := make(map[string]*packages.Package)
		for _, dep := range tpkg.Imports() {
			if dp, ok := out[dep.Path()]; ok {
				imports[dep.Path()] = dp
			}
		}
		out[sp.pkgPath] = &packages.Package{
			PkgPath:   sp.pkgPath,
			Fset:      fset,
			Syntax:    []*ast.File{file},
			Types:     tpkg,
			TypesInfo: info,
			Imports:   imports,
		}
	}
	return out
}

func typecheckSinglePkg(t *testing.T, pkgPath, src string) *packages.Package {
	t.Helper()
	return typecheckOrderedPkgs(t, []testPkgSpec{{pkgPath: pkgPath, src: src}})[pkgPath]
}

func TestDeriveNonMutatingMethodsAndNoPostInitCarrierWrites(t *testing.T) {
	p := typecheckSinglePkg(t, "example.com/p", `package p

import (
	"reflect"
	"sync"
	"sync/atomic"
)

type Reader struct {
	n int
}

func (r *Reader) helper() int {
	x := r.n + 1
	return x
}

func (r *Reader) ReadCount() int {
	return r.helper()
}

func (r *Reader) MutateCount() {
	r.n++
}

type CatalogIface interface {
	CatalogLabel() string
}

type ReadOnlyTagCapsule struct {
	ReflectTyp reflect.Type
	Label      string
}

type LockedRecordCapsule struct {
	ReflectTyp reflect.Type
	mu         sync.Mutex
	done       uint32
	size       int
}

func (rc *LockedRecordCapsule) initOnce() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.done == 1 {
		return
	}
	rc.size = 42
	atomic.StoreUint32(&rc.done, 1)
}
`)
	idx := refconfine.BuildPkgIndex(p)
	methods := DeriveNonMutatingMethods(true, p, idx)
	want := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.ReadCount"}
	bad := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Reader.MutateCount"}
	foundWant := false
	for _, m := range methods {
		if m == want {
			foundWant = true
		}
		if m == bad {
			t.Fatalf("unexpected mutating method in DeriveNonMutatingMethods: %v", m)
		}
	}
	if !foundWant {
		t.Fatalf("expected %v in DeriveNonMutatingMethods, got %v", want, methods)
	}
	if clean, culprits := DeriveNoPostInitCarrierWrites(true, p, idx, idx.InitOnly, nil); !clean || len(culprits) > 0 {
		t.Fatalf("expected DeriveNoPostInitCarrierWrites=(true, nil) on carrier-clean package, got (%v, %v)", clean, culprits)
	}

	_, _, capsules, _, _, _, _ := DeriveCapsuleAndStructFacts(true, p, idx, nil, nil, idx.InitOnly, nil, nil)
	byName := map[string]syntaxutil.LazyOnceCapsuleType{}
	for _, ct := range capsules {
		if !ct.Valid() {
			t.Fatalf("invalid LazyOnceCapsuleType: %+v", ct)
		}
		byName[ct.Type.Name] = ct
	}
	if _, ok := byName["LockedRecordCapsule"]; !ok {
		t.Fatalf("expected LockedRecordCapsule in capsules, got %+v", capsules)
	}
	if _, ok := byName["ReadOnlyTagCapsule"]; !ok {
		t.Fatalf("expected ReadOnlyTagCapsule in capsules, got %+v", capsules)
	}
}

const (
	synthValPkgSrc = `package valpkg

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

func FromBytes(b []byte) Datum {
	return Datum{raw: b, num: 1}
}

func (d Datum) Present() bool {
	return d.num != 0
}

func (d Datum) AnyVal() any {
	if d.raw != nil {
		return d.raw
	}
	return d.num
}

func (d Datum) RawBytes() []byte {
	return d.raw
}
`

	synthRawBuildSrc = `package rawbuild

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

	synthSchemaCapSrc = `package schemacap

import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"example.com/valpkg"
)

type TagCapsule struct {
	ReflectTyp reflect.Type
	Spec       valpkg.SpecIface
}

type recordDetail struct {
	fieldCount int
}

type cachedSummary struct {
	code int
}

type summarySlot struct {
	ptr unsafe.Pointer
}

func (s *summarySlot) get(rc *RecordCapsule) *cachedSummary {
	p := atomic.LoadPointer(&s.ptr)
	if p != nil {
		return (*cachedSummary)(p)
	}
	v := &cachedSummary{code: rc.Spec.SpecID()}
	atomic.CompareAndSwapPointer(&s.ptr, nil, unsafe.Pointer(v))
	return (*cachedSummary)(atomic.LoadPointer(&s.ptr))
}

type RecordCapsule struct {
	ReflectTyp reflect.Type
	Spec       valpkg.SpecIface
	mu         sync.Mutex
	done       uint32
	sub        recordDetail
	summary    summarySlot
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

func (rc *RecordCapsule) SummaryCode() int {
	return rc.summary.get(rc).code
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

	synthTypeBuildSrc = `package typebuild

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
	AltExtCapsules []schemacap.ExtCapsule
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
	for i := range b.AltExtCapsules {
		schemacap.InitExtCapsule(&b.AltExtCapsules[i], &rb.ExtSpecs[0])
	}
	return BuiltSchema{Catalog: rb.Catalog}
}
`

	synthGenPkgSrc = `package genpkg

import (
	"reflect"
	"unsafe"

	"example.com/rawbuild"
	"example.com/schemacap"
	"example.com/typebuild"
	"example.com/valpkg"
)

type SampleTag int

type SampleRecord struct {
	Code int
}

const rawWireConst = "schema_v1"
var mutableWireStr = "schema_v1"

func impureTagCount() int { return 1 }
func MutateWireStr()      { mutableWireStr = "mutated" }

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
	type localAnchor struct{}
	out := typebuild.SchemaBuilder{
		Sub: rawbuild.RawAssembler{
			RawWire: unsafe.Slice(unsafe.StringData(rawWireConst), len(rawWireConst)),
			NumTags: int(len(reflect.TypeOf(localAnchor{}).PkgPath())*0 + 1),
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
`
)

func TestSyntheticNonProtoCapsuleBuilderAndCluster(t *testing.T) {
	t.Run("positive_derivation", func(t *testing.T) {
		rec := trace.NewRecorder()
		baseCtx, cancel := context.WithCancel(context.Background())
		ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
		defer func() {
			cancel()
			_ = trace.Enabled(ctx, trace.DomainDynstate, "")
		}()

		pkgs := typecheckOrderedPkgs(t, []testPkgSpec{
			{pkgPath: "example.com/valpkg", src: synthValPkgSrc},
			{pkgPath: "example.com/rawbuild", src: synthRawBuildSrc},
			{pkgPath: "example.com/schemacap", src: synthSchemaCapSrc},
			{pkgPath: "example.com/typebuild", src: synthTypeBuildSrc},
			{pkgPath: "example.com/genpkg", src: synthGenPkgSrc},
		})

		rawPkg := pkgs["example.com/rawbuild"]
		_, rawBuilders, _, rawMutated, rawConds, _, _ := DeriveCapsuleAndStructFactsCtx(
			ctx, true, rawPkg, refconfine.BuildPkgIndex(rawPkg), nil, nil, nil, nil, nil,
		)
		if len(rawBuilders) != 1 || !rawBuilders[0].CoversImmutableCapsules || rawBuilders[0].Type.Name != "RawAssembler" || rawBuilders[0].BuildMethod != "Assemble" || rawBuilders[0].OutIfaceField != "Catalog" {
			t.Fatalf("unexpected rawBuilders: %+v; events=%+v", rawBuilders, rec.Events())
		}
		if len(rawMutated) != 0 {
			t.Fatalf("expected zero mutated structs in rawbuild, got %+v; events=%+v", rawMutated, rec.Events())
		}
		foundPresentCond := false
		for _, cm := range rawConds {
			if cm.RequireNonMutatingMethod == (syntaxutil.FuncKey{Pkg: "example.com/valpkg", Name: "Datum.Present"}) {
				foundPresentCond = true
			}
		}
		if !foundPresentCond {
			t.Fatalf("expected ConditionalStructMutation for Datum.Present, got %+v", rawConds)
		}

		capPkg := pkgs["example.com/schemacap"]
		_, _, capTypes, capMutated, _, _, _ := DeriveCapsuleAndStructFactsCtx(
			ctx, true, capPkg, refconfine.BuildPkgIndex(capPkg), nil, nil, nil, nil, nil,
		)
		if len(capMutated) != 0 {
			t.Fatalf("expected zero mutated structs in schemacap, got %+v; events=%+v", capMutated, rec.Events())
		}

		tbPkg := pkgs["example.com/typebuild"]
		_, capBuilders, _, tbMutated, _, _, _ := DeriveCapsuleAndStructFactsCtx(
			ctx, true, tbPkg, refconfine.BuildPkgIndex(tbPkg), nil, nil, nil, nil, nil,
		)
		for _, m := range tbMutated {
			if m.Pkg != "example.com/typebuild" || m.Name != "SchemaBuilder" {
				t.Fatalf("unexpected mutated struct in typebuild: %+v; events=%+v", tbMutated, rec.Events())
			}
		}
		if len(capBuilders) != 1 || capBuilders[0].CoversImmutableCapsules || capBuilders[0].Type.Name != "SchemaBuilder" ||
			capBuilders[0].BuildMethod != "Construct" || capBuilders[0].OutIfaceField != "Catalog" ||
			capBuilders[0].SubBuilder != (syntaxutil.TypeRef{Pkg: "example.com/rawbuild", Name: "RawAssembler"}) {
			t.Fatalf("unexpected capBuilders: %+v", capBuilders)
		}
		wantHelper := syntaxutil.FuncKey{Pkg: "example.com/schemacap", Name: "InitExtCapsule"}
		if !slices.Equal(capBuilders[0].AllowedHelpers, []syntaxutil.FuncKey{wantHelper}) {
			t.Fatalf("expected AllowedHelpers=[%v], got %+v", wantHelper, capBuilders[0].AllowedHelpers)
		}

		capsByName := map[string]syntaxutil.LazyOnceCapsuleType{}
		for _, ct := range capTypes {
			if !ct.Valid() {
				t.Fatalf("invalid LazyOnceCapsuleType: %+v", ct)
			}
			capsByName[ct.Type.Name] = ct
		}
		if tc, ok := capsByName["TagCapsule"]; !ok || !tc.HasExportedReflectType {
			t.Fatalf("expected TagCapsule with HasExportedReflectType=true, got %+v", capsByName["TagCapsule"])
		}
		if rc, ok := capsByName["RecordCapsule"]; !ok || !rc.HasExportedReflectType || !rc.CapsuleReflectSafe {
			t.Fatalf("expected RecordCapsule with HasExportedReflectType=true and CapsuleReflectSafe=true, got %+v", capsByName["RecordCapsule"])
		}
		if ec, ok := capsByName["ExtCapsule"]; !ok || ec.InitHelper != wantHelper || !slices.Equal(ec.ExportedWriteGuardFields, []string{"GuardSlot"}) {
			t.Fatalf("expected ExtCapsule with InitHelper=%v and ExportedWriteGuardFields=[GuardSlot], got %+v", wantHelper, capsByName["ExtCapsule"])
		}

		genPkg := pkgs["example.com/genpkg"]
		clusters, _, _, _, _, _, _ := DeriveCapsuleAndStructFacts(
			true, genPkg, refconfine.BuildPkgIndex(genPkg), nil, nil, nil, nil, nil,
		)
		if len(clusters) != 1 || !clusters[0].Valid() {
			t.Fatalf("expected 1 valid InitSettledClusterFact, got %+v", clusters)
		}
		foundExtBinding := false
		for _, sb := range clusters[0].SliceBindings {
			if sb.Field == "ExtCapsules" {
				foundExtBinding = true
				if !sb.StaticLiteral || !slices.Equal(sb.NonNilExportedNames, []string{"GuardSlot"}) {
					t.Fatalf("expected ExtCapsules StaticLiteral=true with NonNilExportedNames=[GuardSlot], got %+v", sb)
				}
			}
		}
		if !foundExtBinding {
			t.Fatalf("missing ExtCapsules binding in %+v", clusters[0])
		}
	})

	type negCase struct {
		name         string
		targetPkg    string
		mutatePkg    string
		oldSnippet   string
		newSnippet   string
		wantStruct   string
		wantReason   string
		checkCluster func(t *testing.T, clusters []syntaxutil.InitSettledClusterFact)
	}

	negCases := []negCase{
		{
			name:       "unguarded_exported_write_in_once_cone",
			targetPkg:  "example.com/schemacap",
			mutatePkg:  "example.com/schemacap",
			oldSnippet: "if ec.GuardSlot == nil {\n\t\tec.GuardSlot = ec.spec.SpecID()\n\t}",
			newSnippet: "ec.GuardSlot = ec.spec.SpecID()",
			wantStruct: "example.com/schemacap.ExtCapsule",
			wantReason: "unguarded_exported_field_write_in_once_cone",
		},
		{
			name:       "untyped_nil_guard_slot_excluded_from_non_nil_exported_names",
			targetPkg:  "example.com/genpkg",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "{GuardSlot: (*int32)(nil)}",
			newSnippet: "{GuardSlot: nil}",
			checkCluster: func(t *testing.T, clusters []syntaxutil.InitSettledClusterFact) {
				if len(clusters) != 1 {
					t.Fatalf("expected 1 cluster fact, got %+v", clusters)
				}
				for _, sb := range clusters[0].SliceBindings {
					if sb.Field == "ExtCapsules" && slices.Contains(sb.NonNilExportedNames, "GuardSlot") {
						t.Fatalf("untyped nil GuardSlot must NOT be recorded in NonNilExportedNames: %+v", sb)
					}
				}
			},
		},
		{
			name:       "omitted_bytes_equal_snapshot_panic_in_raw_builder",
			targetPkg:  "example.com/rawbuild",
			mutatePkg:  "example.com/rawbuild",
			oldSnippet: "if len(dh.snap) > 0 && !bytes.Equal(dh.snap, dh.val.RawBytes()) {\n\t\tpanic(\"mutated snapshot\")\n\t}",
			newSnippet: "_ = bytes.Equal",
			wantStruct: "example.com/rawbuild.RawAssembler",
			wantReason: "invalid_non_snapshot_field_type",
		},
		{
			name:       "capsule_substruct_addr_before_once_init_dominance",
			targetPkg:  "example.com/schemacap",
			mutatePkg:  "example.com/schemacap",
			oldSnippet: "func (rc *RecordCapsule) Detail() *recordDetail {\n\trc.init()\n\treturn &rc.sub\n}",
			newSnippet: "func (rc *RecordCapsule) Detail() *recordDetail {\n\tif rc.done == 99 {\n\t\trc.init()\n\t}\n\treturn &rc.sub\n}",
			wantStruct: "example.com/schemacap.RecordCapsule",
			wantReason: "substruct_addr_not_dominated_by_once_init",
		},
		{
			name:       "raw_builder_substruct_addr_before_once_init_dominance",
			targetPkg:  "example.com/rawbuild",
			mutatePkg:  "example.com/rawbuild",
			oldSnippet: "func (c *rawCatalog) Meta() *catalogMeta {\n\tc.lazyInit()\n\treturn &c.sub\n}",
			newSnippet: "func (c *rawCatalog) Meta() *catalogMeta {\n\tif c.name == \"never\" {\n\t\tc.lazyInit()\n\t}\n\treturn &c.sub\n}",
			wantStruct: "example.com/rawbuild.RawAssembler",
			wantReason: "substruct_addr_not_dominated_by_once_init",
		},
		{
			name:       "misaligned_sample_slice_prefix_offset",
			targetPkg:  "example.com/typebuild",
			mutatePkg:  "example.com/typebuild",
			oldSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.TagCapsules)+i])",
			newSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[i])",
			wantStruct: "example.com/typebuild.SchemaBuilder",
			wantReason: "misaligned_sample_slice_offset",
		},
		{
			name:       "extra_sample_slice_prefix_offset_on_first_slice",
			targetPkg:  "example.com/typebuild",
			mutatePkg:  "example.com/typebuild",
			oldSnippet: "b.TagCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[i])",
			newSnippet: "b.TagCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.RecordCapsules)+i])",
			wantStruct: "example.com/typebuild.SchemaBuilder",
			wantReason: "misaligned_sample_slice_offset",
		},
		{
			name:       "doubled_sample_slice_prefix_offset",
			targetPkg:  "example.com/typebuild",
			mutatePkg:  "example.com/typebuild",
			oldSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.TagCapsules)+i])",
			newSnippet: "b.RecordCapsules[i].ReflectTyp = reflect.TypeOf(b.TypeSamples[len(b.TagCapsules)+len(b.TagCapsules)+i])",
			wantStruct: "example.com/typebuild.SchemaBuilder",
			wantReason: "misaligned_sample_slice_offset",
		},
		{
			name:       "impure_call_in_cluster_sub_builder_lit",
			targetPkg:  "example.com/genpkg",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "NumRecs: 1,",
			newSnippet: "NumRecs: impureTagCount(),",
			wantStruct: "schemaInit",
			wantReason: "impure_cluster_sub_builder_lit",
		},
		{
			name:       "mutable_string_in_cluster_unsafe_stringdata",
			targetPkg:  "example.com/genpkg",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "RawWire: unsafe.Slice(unsafe.StringData(rawWireConst), len(rawWireConst)),",
			newSnippet: "RawWire: unsafe.Slice(unsafe.StringData(mutableWireStr), len(mutableWireStr)),",
			wantStruct: "schemaInit",
			wantReason: "impure_cluster_sub_builder_lit",
		},
		{
			name:       "out_of_bounds_unsafe_slice_len_in_cluster_sub_builder",
			targetPkg:  "example.com/genpkg",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "RawWire: unsafe.Slice(unsafe.StringData(rawWireConst), len(rawWireConst)),",
			newSnippet: "RawWire: unsafe.Slice(unsafe.StringData(rawWireConst), 4096),",
			wantStruct: "schemaInit",
			wantReason: "impure_cluster_sub_builder_lit",
		},
		{
			name:       "whole_elem_overwrite_on_non_sample_capsule_slice",
			targetPkg:  "example.com/typebuild",
			mutatePkg:  "example.com/typebuild",
			oldSnippet: "schemacap.InitExtCapsule(&b.ExtCapsules[i], &rb.ExtSpecs[i])",
			newSnippet: "b.ExtCapsules[i] = schemacap.ExtCapsule{}",
			wantStruct: "example.com/typebuild.SchemaBuilder",
			wantReason: "invalid_sample_builder_capsule_write",
		},
		{
			name:       "exported_slice_mutation_in_once_cone_despite_sibling_guard",
			targetPkg:  "example.com/schemacap",
			mutatePkg:  "example.com/schemacap",
			oldSnippet: "type RecordCapsule struct {\n\tReflectTyp reflect.Type\n\tSpec       valpkg.SpecIface\n\tmu         sync.Mutex\n\tdone       uint32\n\tsub        recordDetail\n\tsummary    summarySlot\n}\n\nfunc (rc *RecordCapsule) init() {\n\tif atomic.LoadUint32(&rc.done) == 0 {\n\t\trc.initSlow()\n\t}\n}\n\nfunc (rc *RecordCapsule) initSlow() {\n\trc.mu.Lock()\n\tdefer rc.mu.Unlock()\n\tif rc.done == 1 {\n\t\treturn\n\t}\n\trc.sub.fieldCount = rc.Spec.SpecID()",
			newSnippet: "type RecordCapsule struct {\n\tReflectTyp reflect.Type\n\tSpec       valpkg.SpecIface\n\tGuardSlot  any\n\tItems      []any\n\tmu         sync.Mutex\n\tdone       uint32\n\tsub        recordDetail\n\tsummary    summarySlot\n}\n\nfunc (rc *RecordCapsule) init() {\n\tif atomic.LoadUint32(&rc.done) == 0 {\n\t\trc.initSlow()\n\t}\n}\n\nfunc (rc *RecordCapsule) initSlow() {\n\trc.mu.Lock()\n\tdefer rc.mu.Unlock()\n\tif rc.done == 1 {\n\t\treturn\n\t}\n\tif rc.GuardSlot == nil {\n\t\trc.GuardSlot = 1\n\t}\n\ts := rc.Items\n\ts[0] = 1\n\trc.sub.fieldCount = rc.Spec.SpecID()",
			wantStruct: "example.com/schemacap.RecordCapsule",
			wantReason: "unconfined_family_ref_read",
		},
		{
			name:       "duplicate_capsule_slice_var_in_cluster",
			targetPkg:  "example.com/genpkg",
			mutatePkg:  "example.com/genpkg",
			oldSnippet: "ExtCapsules:    extCaps,",
			newSnippet: "ExtCapsules:    extCaps,\n\t\tAltExtCapsules: extCaps,",
			wantStruct: "schemaInit",
			wantReason: "duplicate_cluster_capsule_slice_var",
		},
	}

	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := []testPkgSpec{
				{pkgPath: "example.com/valpkg", src: synthValPkgSrc},
				{pkgPath: "example.com/rawbuild", src: synthRawBuildSrc},
				{pkgPath: "example.com/schemacap", src: synthSchemaCapSrc},
				{pkgPath: "example.com/typebuild", src: synthTypeBuildSrc},
				{pkgPath: "example.com/genpkg", src: synthGenPkgSrc},
			}
			replaced := false
			for i := range specs {
				if specs[i].pkgPath == tc.mutatePkg {
					if !strings.Contains(specs[i].src, tc.oldSnippet) {
						t.Fatalf("missing oldSnippet in %s", tc.mutatePkg)
					}
					specs[i].src = strings.Replace(specs[i].src, tc.oldSnippet, tc.newSnippet, 1)
					replaced = true
				}
			}
			if !replaced {
				t.Fatalf("mutatePkg %s not found", tc.mutatePkg)
			}
			pkgs := typecheckOrderedPkgs(t, specs)

			rec := trace.NewRecorder()
			baseCtx, cancel := context.WithCancel(context.Background())
			ctx := trace.WithFilteredSink(baseCtx, "dynstate", rec)
			defer func() {
				cancel()
				_ = trace.Enabled(ctx, trace.DomainDynstate, "")
			}()

			tp := pkgs[tc.targetPkg]
			clusters, _, _, _, _, _, _ := DeriveCapsuleAndStructFactsCtx(
				ctx, true, tp, refconfine.BuildPkgIndex(tp), nil, nil, nil, nil, nil,
			)
			if tc.checkCluster != nil {
				tc.checkCluster(t, clusters)
				return
			}

			rejects := rec.ByName("dynstate.capsule.reject")
			matched := false
			for _, ev := range rejects {
				if ev.Target == tc.targetPkg &&
					ev.StringField("struct") == tc.wantStruct &&
					ev.StringField("reason") == tc.wantReason {
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("missing causal dynstate.capsule.reject(struct=%q, reason=%q) on %s; got events=%+v",
					tc.wantStruct, tc.wantReason, tc.targetPkg, rejects)
			}
		})
	}
}
