package dynstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/gotool"
)

// PackageClass is the mutability class of one graph package's source.
type PackageClass = gotool.PackageClass

const (
	MutableLocalPackage = gotool.MutableLocalPackage
	StandardPackage     = gotool.StandardPackage
	PinnedPackage       = gotool.PinnedPackage
)

// GraphPackage is one node of a view's test-binary package graph as the
// metadata listing names it.
type GraphPackage = gotool.GraphPackage

// Fact is the per-package summary the shared-dynamic-state derivation extracts
// from one typed package and memoizes for version-pinned modules
// (REQ-closure-dynamic-state-memo).
type Fact struct {
	Declares                   []string                               `json:"declares,omitempty"`
	Mutates                    []string                               `json:"mutates,omitempty"`
	Escapes                    []string                               `json:"escapes,omitempty"`
	ExportedSeams              []syntaxutil.ExportedSeam              `json:"exportedSeams,omitempty"`
	NonSeqFuncUses             []syntaxutil.FuncKey                   `json:"nonSeqFuncUses,omitempty"`
	SeqFuncEdges               []syntaxutil.FuncDepEdge               `json:"seqFuncEdges,omitempty"`
	ParallelFuncs              []syntaxutil.FuncKey                   `json:"parallelFuncs,omitempty"`
	ParallelEdges              []syntaxutil.FuncDepEdge               `json:"parallelEdges,omitempty"`
	ReceiverReadOnly           []syntaxutil.FuncKey                   `json:"receiverReadOnly,omitempty"`
	ReceiverReadOnlyDeps       []syntaxutil.FuncDepEdge               `json:"receiverReadOnlyDeps,omitempty"`
	ReceiverReadOnlyParamDeps  []syntaxutil.FuncParamDepEdge          `json:"receiverReadOnlyParamDeps,omitempty"`
	ReceiverRetentionFree      []syntaxutil.FuncKey                   `json:"receiverRetentionFree,omitempty"`
	NonMutatingMethods         []syntaxutil.FuncKey                   `json:"nonMutatingMethods,omitempty"`
	MethodUses                 []syntaxutil.VarMethodUse              `json:"methodUses,omitempty"`
	InitMethodUses             []syntaxutil.VarMethodUse              `json:"initMethodUses,omitempty"`
	ParamLeakFree              []syntaxutil.ParamKey                  `json:"paramLeakFree,omitempty"`
	ParamLeakFreeDeps          []syntaxutil.ParamDepEdge              `json:"paramLeakFreeDeps,omitempty"`
	ParamLeakFreeMethodDeps    []syntaxutil.ParamMethodDepEdge        `json:"paramLeakFreeMethodDeps,omitempty"`
	ParamRetentionFree         []syntaxutil.ParamKey                  `json:"paramRetentionFree,omitempty"`
	ParamRetentionFreeDeps     []syntaxutil.ParamDepEdge              `json:"paramRetentionFreeDeps,omitempty"`
	ParamUses                  []syntaxutil.VarParamUse               `json:"paramUses,omitempty"`
	InitParamUses              []syntaxutil.VarParamUse               `json:"initParamUses,omitempty"`
	FieldParamUses             []syntaxutil.FieldPosKey               `json:"fieldParamUses,omitempty"`
	ElemParamUses              []syntaxutil.ElemParamUse              `json:"elemParamUses,omitempty"`
	FieldParamDefer            []syntaxutil.FieldParamDefer           `json:"fieldParamDefer,omitempty"`
	FieldParamPoison           []syntaxutil.FieldParamPoison          `json:"fieldParamPoison,omitempty"`
	ReturnFieldParamDefer      []syntaxutil.ReturnFieldParamDefer     `json:"returnFieldParamDefer,omitempty"`
	ReturnFieldParamPoison     []syntaxutil.ReturnFieldParamPoison    `json:"returnFieldParamPoison,omitempty"`
	AttributedUses             []syntaxutil.AttributedUse             `json:"attributedUses,omitempty"`
	FuncRefs                   []syntaxutil.FuncRef                   `json:"funcRefs,omitempty"`
	Opaque                     []string                               `json:"opaque,omitempty"`
	OpacityBreaks              []string                               `json:"opacityBreaks,omitempty"`
	OpaqueDeps                 []syntaxutil.OpaqueDep                 `json:"opaqueDeps,omitempty"`
	CarrierLinks               []syntaxutil.CarrierLink               `json:"carrierLinks,omitempty"`
	EnvCarrying                []string                               `json:"envCarrying,omitempty"`
	EnvCarryingFns             []syntaxutil.VarFuncUse                `json:"envCarryingFns,omitempty"`
	EnvCallable                []string                               `json:"envCallable,omitempty"`
	EnvCallUses                []syntaxutil.EnvCallUse                `json:"envCallUses,omitempty"`
	EnvCallParamUses           []syntaxutil.EnvCallParamUse           `json:"envCallParamUses,omitempty"`
	EnvCallMethodUses          []syntaxutil.EnvCallMethodUse          `json:"envCallMethodUses,omitempty"`
	ReturnEnvFree              []syntaxutil.FuncKey                   `json:"returnEnvFree,omitempty"`
	ReturnEnvDeps              []syntaxutil.FuncDepEdge               `json:"returnEnvDeps,omitempty"`
	ReturnEnvParamDeps         []syntaxutil.FuncParamDepEdge          `json:"returnEnvParamDeps,omitempty"`
	ReturnEnvMethodDeps        []syntaxutil.FuncDepEdge               `json:"returnEnvMethodDeps,omitempty"`
	ParamInsertionFree         []syntaxutil.ParamKey                  `json:"paramInsertionFree,omitempty"`
	ReturnEnvInsertionDeps     []syntaxutil.FuncInsertionDepEdge      `json:"returnEnvInsertionDeps,omitempty"`
	ParamInsertionDeps         []syntaxutil.ParamInsertionDepEdge     `json:"paramInsertionDeps,omitempty"`
	ParamInsertionParamDeps    []syntaxutil.ParamDepEdge              `json:"paramInsertionParamDeps,omitempty"`
	ParamInsertionMethodDeps   []syntaxutil.ParamMethodDepEdge        `json:"paramInsertionMethodDeps,omitempty"`
	PureMethods                map[string]string                      `json:"pureMethods,omitempty"`
	ExternalMethods            map[string]string                      `json:"externalMethods,omitempty"`
	PoolDischarges             []string                               `json:"poolDischarges,omitempty"`
	PoolMutates                []string                               `json:"poolMutates,omitempty"`
	PoolEscapes                []string                               `json:"poolEscapes,omitempty"`
	PoolAttributedUses         []syntaxutil.AttributedUse             `json:"poolAttributedUses,omitempty"`
	SingleSubjectVars          []string                               `json:"singleSubjectVars,omitempty"`
	MappingDischarges          []string                               `json:"mappingDischarges,omitempty"`
	MemoDischarges             []string                               `json:"memoDischarges,omitempty"`
	OnceMemoTypes              []syntaxutil.OnceMemoTypeFact          `json:"onceMemoTypes,omitempty"`
	OnceMemoCandidates         []syntaxutil.OnceMemoVarCandidate      `json:"onceMemoCandidates,omitempty"`
	HarnessDischarges          []string                               `json:"harnessDischarges,omitempty"`
	LazyOnceCapsuleTypes       []syntaxutil.LazyOnceCapsuleType       `json:"lazyOnceCapsuleTypes,omitempty"`
	InitBuilders               []syntaxutil.InitBuilderFact           `json:"initBuilders,omitempty"`
	InitSettledClusters        []syntaxutil.InitSettledClusterFact    `json:"initSettledClusters,omitempty"`
	ReadOnlyVarAliases         []syntaxutil.ReadOnlyVarAlias          `json:"readOnlyVarAliases,omitempty"`
	StaticCompositeGlobals     []syntaxutil.StaticCompositeGlobalFact `json:"staticCompositeGlobals,omitempty"`
	MutatedStructTypes         []syntaxutil.TypeRef                   `json:"mutatedStructTypes,omitempty"`
	ConditionalStructMutations []syntaxutil.ConditionalStructMutation `json:"conditionalStructMutations,omitempty"`
	ReflectedIfaceMethodSets   []syntaxutil.ReflectedIfaceFact        `json:"reflectedIfaceMethodSets,omitempty"`
	NoPostInitCarrierWrites    bool                                   `json:"noPostInitCarrierWrites,omitempty"`
	CarrierImportCalls         []string                               `json:"carrierImportCalls,omitempty"`
	DirectVarWrites            []string                               `json:"directVarWrites,omitempty"`
	NonMethodVarUses           []string                               `json:"nonMethodVarUses,omitempty"`
}

// MethodDirectivesFactOf extracts only the method purity and externality
// directives declared in p, skipping dynamic-state and fixed-point derivation
// for pure-directive-only scans.
func MethodDirectivesFactOf(p *packages.Package) Fact {
	var fact Fact
	recordPackageMethodDirectives(p, &fact)
	return fact
}

func recordPackageMethodDirectives(p *packages.Package, fact *Fact) {
	if p == nil {
		return
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			recv := syntaxutil.RecvTypeName(fd)
			if recv == "" {
				continue
			}
			key := recv + "." + fd.Name.Name
			if syntaxutil.HasDirective(fd.Doc, "//gofresh:pure") {
				if fact.PureMethods == nil {
					fact.PureMethods = map[string]string{}
				}
				fact.PureMethods[key] = syntaxutil.NodeDeclarationKey(p, fd.Name)
			}
			if syntaxutil.HasDirective(fd.Doc, "//gofresh:external") {
				if fact.ExternalMethods == nil {
					fact.ExternalMethods = map[string]string{}
				}
				fact.ExternalMethods[key] = syntaxutil.NodeDeclarationKey(p, fd.Name)
			}
		}
	}
}

type CulpritVerb uint8

const (
	CulpritMutated CulpritVerb = iota + 1
	CulpritEscapes
	CulpritEnvCarrying
)

func (v CulpritVerb) Clause() string {
	switch v {
	case CulpritMutated:
		return " is mutated"
	case CulpritEscapes:
		return " escapes writable"
	case CulpritEnvCarrying:
		return " registers function values outside the environment-free audit"
	default:
		return ""
	}
}

type CulpritChannel uint8

const (
	ChannelCallerVouch CulpritChannel = iota + 1
	ChannelCallerVouchEnvFree
	ChannelRestructureOrDirective
	ChannelRestructureDirectiveSingleSubjectOnly
	ChannelRestructureUnbackedDirective
)

func (ch CulpritChannel) Clause(pkgPath, key string) string {
	switch ch {
	case ChannelRestructureUnbackedDirective:
		return " (its //gofresh:single-subject directive is backed by no single-subject attestation here; dischargeable by restructuring the state)"
	case ChannelRestructureDirectiveSingleSubjectOnly:
		return " (dischargeable by restructuring the state; the //gofresh:single-subject directive discharges only under the caller's single-subject attestation, which the package-process model does not give)"
	case ChannelRestructureOrDirective:
		return " (dischargeable by restructuring the state, or by the //gofresh:single-subject directive on the declaration under the caller's single-subject attestation)"
	case ChannelCallerVouch, ChannelCallerVouchEnvFree:
		imp, bare := pkgPath, key
		if i := strings.LastIndexByte(key, '.'); i >= 0 {
			imp, bare = key[:i], key[i+1:]
		}
		obligation := "initialized once and never written"
		if ch == ChannelCallerVouchEnvFree {
			obligation += ", registering only environment-free function values"
		}
		return " (dischargeable by a caller vouch for " + imp + "." + bare + " — e.g. --vouch " + imp + ":" + bare + " where the consumer takes flags — on a source audit that the variable is " + obligation + ")"
	default:
		return ""
	}
}

// Culprit is one open package's named culprit in the downgrade walk's order
// (REQ-closure-shared-dynamic-state, REQ-closure-shared-dynamic-state-reason).
type Culprit struct {
	PkgPath string
	Key     string
	Verb    CulpritVerb
	Channel CulpritChannel
}

func (c Culprit) ReasonBody() string {
	return c.PkgPath + ": " + c.Key + c.Verb.Clause() + c.Channel.Clause(c.PkgPath, c.Key)
}

func (c Culprit) SubjectParts() (pkg, sym string) {
	imp, bare := c.PkgPath, c.Key
	if i := strings.LastIndexByte(c.Key, '.'); i >= 0 {
		imp, bare = c.Key[:i], keyBare(c.Key, i)
	}
	return imp, bare
}

func keyBare(key string, dot int) string {
	return key[dot+1:]
}

// CulpritSiteSet is one culprit variable's marking-site inventory for the
// per-subject reachability re-judgment (REQ-closure-shared-dynamic-state).
type CulpritSiteSet struct {
	Fns          map[string]bool
	Unattributed bool
}

// ConeState is one view package's composed dynamic-state judgment over its own
// test-binary cone.
type ConeState struct {
	Downgraded            string
	CulpritPkg            string
	CulpritSym            string
	VouchDischarges       string
	AttestationDischarges string
	RootCulprits          []Culprit
	CulpritSites          map[string]CulpritSiteSet
}

// Cone selects the metadata nodes and the facts of one view package's
// test-binary graph out of a view-wide gathering.
func Cone(meta []GraphPackage, byListing map[string]GraphPackage, factsByListing map[string]Fact, viewPackage string) ([]GraphPackage, map[string][]Fact) {
	testVariant := false
	for _, node := range meta {
		if node.PkgPath == viewPackage && node.ForTest == viewPackage {
			testVariant = true
			break
		}
	}
	var roots []string
	for _, node := range meta {
		if (node.PkgPath == viewPackage && node.ForTest == "" && !testVariant) || node.ForTest == viewPackage {
			roots = append(roots, node.ImportPath)
		}
	}
	in := map[string]bool{}
	walkImportCone(
		roots,
		func(listing string) ([]string, bool) {
			node, ok := byListing[listing]
			return node.Imports, ok
		},
		func(listing string) bool {
			in[listing] = true
			return true
		},
	)
	var cone []GraphPackage
	facts := map[string][]Fact{}
	for _, node := range meta {
		if !in[node.ImportPath] {
			continue
		}
		cone = append(cone, node)
		if fact, ok := factsByListing[node.ImportPath]; ok {
			facts[node.PkgPath] = append(facts[node.PkgPath], fact)
		}
	}
	return cone, facts
}

// PinnedBuckets derives, per pinned module, the memo bucket completing its
// facts' input identity (REQ-closure-dynamic-state-memo, REQ-closure-mutable-local).
func PinnedBuckets(meta []GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	imports := make(map[string][]string, len(meta))
	pins := make(map[string]string, len(meta))
	local := make(map[string]bool, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		if node.Class == PinnedPackage {
			pins[node.ImportPath] = node.Pin
		}
		if node.Class == MutableLocalPackage {
			local[node.ImportPath] = true
		}
	}
	coneByModule := map[string]map[string]bool{}
	unkeyable = map[string]bool{}
	for _, node := range meta {
		if node.Class != PinnedPackage {
			continue
		}
		pinSet := map[string]bool{}
		localReached := false
		walkImportCone(
			[]string{node.ImportPath},
			func(listing string) ([]string, bool) {
				imps, ok := imports[listing]
				return imps, ok
			},
			func(listing string) bool {
				if pin := pins[listing]; pin != "" {
					pinSet[pin] = true
				}
				if local[listing] {
					localReached = true
				}
				return true
			},
		)
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
