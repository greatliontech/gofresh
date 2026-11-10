// Package protoaudit mechanically verifies generated protobuf descriptor
// clusters, extension aliases, protobuf runtime struct roles (builder,
// desc_builder, enum, message, extension), gRPC service descriptors, and
// post-init carrier immutability across a package's syntax.
package protoaudit

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// Protobuf runtime struct verification roles (REQ-closure-shared-dynamic-state-proto).
const (
	ProtoRoleBuilder     = "builder"
	ProtoRoleDescBuilder = "desc_builder"
	ProtoRoleEnum        = "enum"
	ProtoRoleMessage     = "message"
	ProtoRoleExtension   = "extension"
)

// ProtoRuntimeTypeFact records that a named struct type in its defining package
// mechanically satisfies one of the deterministic once-initialization or
// descriptor-builder runtime roles. GuardTypes names any struct types whose
// instances are constructed or exposed by this runtime role and therefore must
// remain free of non-fresh mutations across the package graph. SubBuilder names
// any cross-package raw descriptor builder struct delegated to by Build().
type ProtoRuntimeTypeFact struct {
	Type           syntaxutil.TypeRef   `json:"type"`
	Role           string               `json:"role"`
	SubBuilder     syntaxutil.TypeRef   `json:"sub_builder,omitempty"`
	InitHelper     syntaxutil.FuncKey   `json:"init_helper,omitempty"`
	AllowedHelpers []syntaxutil.FuncKey `json:"allowed_helpers,omitempty"`
	GuardTypes     []syntaxutil.TypeRef `json:"guard_types,omitempty"`
}

// Valid reports whether f carries a well-formed TypeRef, known role, and
// role-consistent helper, sub-builder, and guard-type keys.
func (f ProtoRuntimeTypeFact) Valid() bool {
	if !f.Type.Valid() {
		return false
	}
	for _, g := range f.GuardTypes {
		if !g.Valid() {
			return false
		}
	}
	switch f.Role {
	case ProtoRoleBuilder:
		if !f.InitHelper.IsZero() || (!f.SubBuilder.IsZero() && !f.SubBuilder.Valid()) {
			return false
		}
		for _, h := range f.AllowedHelpers {
			if !h.Valid() {
				return false
			}
		}
		return true
	case ProtoRoleDescBuilder:
		return f.SubBuilder.IsZero() && f.InitHelper.IsZero() && len(f.AllowedHelpers) == 0 && len(f.GuardTypes) > 0
	case ProtoRoleExtension:
		if !f.SubBuilder.IsZero() || len(f.AllowedHelpers) > 0 {
			return false
		}
		return f.InitHelper.IsZero() || f.InitHelper.Valid()
	case ProtoRoleEnum:
		return f.SubBuilder.IsZero() && f.InitHelper.IsZero() && len(f.AllowedHelpers) == 0 && len(f.GuardTypes) == 0
	case ProtoRoleMessage:
		return f.SubBuilder.IsZero() && f.InitHelper.IsZero() && len(f.AllowedHelpers) == 0
	}
	return false
}

// ProtoClusterFact records a verified idempotent init-only protobuf file
// descriptor builder cluster in a declaring package.
type ProtoClusterFact struct {
	InitFn      syntaxutil.FuncKey `json:"init_fn"`
	Vars        []string           `json:"vars"`
	BuilderType syntaxutil.TypeRef `json:"builder_type"`
	EnumType    syntaxutil.TypeRef `json:"enum_type,omitempty"`
	MsgType     syntaxutil.TypeRef `json:"msg_type,omitempty"`
	ExtType     syntaxutil.TypeRef `json:"ext_type,omitempty"`
}

// Valid reports whether c carries well-formed function, variable, and participant
// type keys.
func (c ProtoClusterFact) Valid() bool {
	if !c.InitFn.Valid() || len(c.Vars) == 0 || !c.BuilderType.Valid() {
		return false
	}
	for _, v := range c.Vars {
		if !syntaxutil.ValidQualifiedVarKey(v) {
			return false
		}
	}
	if !c.EnumType.IsZero() && !c.EnumType.Valid() {
		return false
	}
	if !c.MsgType.IsZero() && !c.MsgType.Valid() {
		return false
	}
	if !c.ExtType.IsZero() && !c.ExtType.Valid() {
		return false
	}
	return true
}

// ProtoExtAlias records an immutable package-scope extension descriptor alias
// (var E_X = otherpkg.E_Y) that discharges iff Target discharges as a verified
// protobuf cluster variable.
type ProtoExtAlias struct {
	Key    string `json:"key"`
	Target string `json:"target"`
}

// Valid reports whether a names two distinct well-formed variable keys.
func (a ProtoExtAlias) Valid() bool {
	return syntaxutil.ValidQualifiedVarKey(a.Key) && syntaxutil.ValidQualifiedVarKey(a.Target) && a.Key != a.Target
}

// GrpcServiceVarFact records an immutable composite-literal gRPC ServiceDesc
// package variable paired with its descriptor struct types.
type GrpcServiceVarFact struct {
	Key        string             `json:"key"`
	SvcDesc    syntaxutil.TypeRef `json:"svc_desc"`
	MethodDesc syntaxutil.TypeRef `json:"method_desc,omitempty"`
	StreamDesc syntaxutil.TypeRef `json:"stream_desc,omitempty"`
}

// Valid reports whether g carries well-formed variable and descriptor type keys.
func (g GrpcServiceVarFact) Valid() bool {
	if !syntaxutil.ValidQualifiedVarKey(g.Key) || !g.SvcDesc.Valid() {
		return false
	}
	if !g.MethodDesc.IsZero() && !g.MethodDesc.Valid() {
		return false
	}
	if !g.StreamDesc.IsZero() && !g.StreamDesc.Valid() {
		return false
	}
	return true
}

// DeriveProtoAndStructFacts mechanically extracts protobuf descriptor clusters,
// extension aliases, runtime struct role proofs, gRPC service descriptors, and
// non-exempted struct mutations across p.Syntax.
func DeriveProtoAndStructFacts(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
) ([]ProtoClusterFact, []ProtoExtAlias, []ProtoRuntimeTypeFact, []GrpcServiceVarFact, []syntaxutil.TypeRef, []syntaxutil.ConditionalStructMutation) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil, nil, nil, nil, nil, nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if initOnly == nil {
		initOnly = idx.InitOnly
	}
	exempted := map[ast.Node]bool{}
	exemptFamilyByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	exemptReadFields := map[*types.Var]bool{}

	var clusters []ProtoClusterFact
	var extAliases []ProtoExtAlias
	var runtimeTypes []ProtoRuntimeTypeFact
	var grpcVars []GrpcServiceVarFact
	var protoConds []syntaxutil.ConditionalStructMutation

	freshCache := freshstruct.NewFreshLocalsCache(p, idx)
	confinedCacheMaps := freshstruct.FindMutexConfinedConstructorCaches(p, idx)
	if audited {
		clusters, extAliases = deriveProtoClusters(audited, p, idx, initOnly, exempted)
		runtimeTypes, protoConds = deriveProtoRuntimeTypes(p, idx, freshCache, confinedCacheMaps, mutatedVars, exempted, exemptFamilyByFunc, exemptReadFields)
		grpcVars = deriveGrpcServiceVars(audited, p, idx)
	}
	mutatedStructs, condMutations := freshstruct.CollectMutatedStructTypes(p, idx, freshCache, confinedCacheMaps, exempted, exemptFamilyByFunc, exemptReadFields)
	if len(protoConds) > 0 {
		seenCond := make(map[syntaxutil.ConditionalStructMutation]bool, len(condMutations)+len(protoConds))
		merged := make([]syntaxutil.ConditionalStructMutation, 0, len(condMutations)+len(protoConds))
		for _, cm := range condMutations {
			if cm.Valid() && !seenCond[cm] {
				seenCond[cm] = true
				merged = append(merged, cm)
			}
		}
		for _, cm := range protoConds {
			if cm.Valid() && !seenCond[cm] {
				seenCond[cm] = true
				merged = append(merged, cm)
			}
		}
		slices.SortFunc(merged, syntaxutil.ConditionalStructMutation.Compare)
		condMutations = merged
	}
	return clusters, extAliases, runtimeTypes, grpcVars, mutatedStructs, condMutations
}

type intraCandCall struct {
	callee             *types.Func
	hasLocalScalarRecv bool
}

// DeriveNonMutatingMethods mechanically identifies exported methods in p.Types
// that perform zero non-local mutations and call only pure or transitively
// non-mutating intra-package helpers.
func DeriveNonMutatingMethods(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []syntaxutil.FuncKey {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil
	}
	isScalarPtrRecv := func(fn *types.Func) *types.Var {
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() == nil {
			return nil
		}
		ptr, isP := types.Unalias(sig.Recv().Type()).(*types.Pointer)
		if !isP || refconfine.TypeContainsRefOrPointer(ptr.Elem()) {
			return nil
		}
		return sig.Recv()
	}

	cands := map[*types.Func]*ast.FuncDecl{}
	scalarPtrHelpers := map[*types.Func]bool{}
	intraCallsByCand := map[*types.Func][]intraCandCall{}

	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types {
			continue
		}
		scalarRecv := isScalarPtrRecv(fn)
		localVars := map[*types.Var]bool{}
		localScalarVars := map[*types.Var]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, isID := n.(*ast.Ident); isID {
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil && !dv.IsField() && dv.Parent() != p.Types.Scope() {
					localVars[dv] = true
					if !refconfine.TypeContainsRefOrPointer(dv.Type()) {
						localScalarVars[dv] = true
					}
				}
			}
			return true
		})
		if fd.Type != nil && fd.Type.Results != nil {
			for _, field := range fd.Type.Results.List {
				for _, nm := range field.Names {
					if dv, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && dv != nil {
						localVars[dv] = true
					}
				}
			}
		}
		usedScalarRecvWrite := false
		isPureLocalLHS := func(expr ast.Expr) bool {
			expr = ast.Unparen(expr)
			if id, isID := expr.(*ast.Ident); isID {
				if id.Name == "_" {
					return true
				}
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil {
					return localVars[dv]
				}
				if uv, ok := p.TypesInfo.Uses[id].(*types.Var); ok && uv != nil {
					return localVars[uv]
				}
				return false
			}
			if scalarRecv != nil {
				if star, isStar := expr.(*ast.StarExpr); isStar {
					if rid, isID := ast.Unparen(star.X).(*ast.Ident); isID && p.TypesInfo.Uses[rid] == scalarRecv {
						usedScalarRecvWrite = true
						return true
					}
				}
			}
			return false
		}
		okLocal := true
		var intraCalls []intraCandCall
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !okLocal || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.SendStmt:
				okLocal = false
				return false
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if !isPureLocalLHS(lhs) {
						okLocal = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if !isPureLocalLHS(x.X) {
					okLocal = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !isPureLocalLHS(x.Key)) || (x.Value != nil && !isPureLocalLHS(x.Value)) {
						okLocal = false
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if id, isID := ast.Unparen(x.X).(*ast.Ident); isID {
						uv, _ := p.TypesInfo.Uses[id].(*types.Var)
						if uv != nil && localVars[uv] && !refconfine.TypeContainsRefOrPointer(uv.Type()) {
							return true
						}
					}
					okLocal = false
					return false
				}
			case *ast.CallExpr:
				if tv, okTV := p.TypesInfo.Types[x.Fun]; okTV && tv.IsType() {
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "len", "cap", "min", "max", "panic", "recover", "new", "make":
							return true
						}
						okLocal = false
						return false
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee == nil {
					okLocal = false
					return false
				}
				callee = callee.Origin()
				if sig, okSig := callee.Type().(*types.Signature); okSig && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
					for _, arg := range x.Args {
						if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(arg)) {
							okLocal = false
							return false
						}
					}
					return true
				}
				if isPureNonRetainingStdCallee(callee) && callee.Name() != "Lock" && !strings.HasPrefix(callee.Name(), "Store") && !strings.HasPrefix(callee.Name(), "Add") && callee.Name() != "Put" {
					return true
				}
				if callee.Pkg() == p.Types {
					hasScalarRecv := false
					if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
						if lv := syntaxutil.LookupIdentVar(p.TypesInfo, sel.X); lv != nil && localScalarVars[lv] {
							hasScalarRecv = true
						}
					}
					intraCalls = append(intraCalls, intraCandCall{
						callee:             callee,
						hasLocalScalarRecv: hasScalarRecv,
					})
					return true
				}
				okLocal = false
				return false
			}
			return true
		})
		if okLocal {
			cands[fn] = fd
			if len(intraCalls) > 0 {
				intraCallsByCand[fn] = intraCalls
			}
			if usedScalarRecvWrite {
				scalarPtrHelpers[fn] = true
			}
		}
	}

	for {
		changed := false
		for fn := range cands {
			callsOK := true
			for _, ic := range intraCallsByCand[fn] {
				if cands[ic.callee] == nil || (scalarPtrHelpers[ic.callee] && !ic.hasLocalScalarRecv) {
					callsOK = false
					break
				}
			}
			if !callsOK {
				delete(cands, fn)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	pkgPath := p.Types.Path()
	var out []syntaxutil.FuncKey
	for fn, fd := range cands {
		if scalarPtrHelpers[fn] || !fn.Exported() || fd.Recv == nil {
			continue
		}
		recvName := syntaxutil.RecvTypeName(fd)
		if recvName == "" {
			continue
		}
		fk := syntaxutil.FuncKey{Pkg: pkgPath, Name: recvName + "." + fn.Name()}
		if fk.Valid() {
			out = append(out, fk)
		}
	}
	slices.SortFunc(out, syntaxutil.FuncKey.Compare)
	return out
}

func isPureNonRetainingStdCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "bytes", "cmp", "encoding/binary", "errors", "fmt", "go/token", "hash/fnv",
		"io", "math", "math/bits", "slices", "sort", "strconv", "strings",
		"unicode", "unicode/utf16", "unicode/utf8":
		return true
	case "reflect":
		name := fn.Name()
		if strings.HasPrefix(name, "Set") || strings.HasPrefix(name, "Make") || name == "Append" || name == "AppendSlice" || name == "Copy" || name == "Call" || name == "CallSlice" || name == "Swapper" {
			return false
		}
		return true
	case "sync":
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			rt := sig.Recv().Type()
			if ptr, isP := types.Unalias(rt).(*types.Pointer); isP {
				rt = ptr.Elem()
			}
			if syntaxutil.IsNamedInPkg(rt, "sync", "Mutex") || syntaxutil.IsNamedInPkg(rt, "sync", "RWMutex") || syntaxutil.IsNamedInPkg(rt, "sync", "Once") || syntaxutil.IsNamedInPkg(rt, "sync", "Pool") {
				return true
			}
		}
		return false
	case "sync/atomic":
		return strings.HasPrefix(fn.Name(), "Load") || fn.Name() == "AddInt32" || fn.Name() == "AddUint32" || fn.Name() == "AddInt64" || fn.Name() == "AddUint64" || fn.Name() == "StoreUint32" || fn.Name() == "StoreInt32"
	}
	return false
}

func containsSyncOrAtomicCarrier(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isN := t.(*types.Named); isN && named.Obj() != nil && named.Obj().Pkg() != nil {
			pkgPath := named.Obj().Pkg().Path()
			name := named.Obj().Name()
			if (pkgPath == "sync" && (name == "Map" || name == "Pool")) ||
				(pkgPath == "sync/atomic" && (name == "Value" || name == "Pointer" || name == "Uintptr")) {
				hit = true
				return
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Chan:
			hit = true
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func isUnsafePtrOrUintptrScalar(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && (b.Kind() == types.UnsafePointer || b.Kind() == types.Uintptr)
}

func sigAcceptsCarrier(t types.Type) bool {
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Recv() != nil {
		rt := sig.Recv().Type()
		if refconfine.TypeContainsRefOrPointer(rt) || syntaxutil.ContainsUintptr(rt) {
			return true
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if refconfine.TypeContainsRefOrPointer(pt) || syntaxutil.ContainsUintptr(pt) {
			return true
		}
	}
	return false
}

func structFreeOfCarrierHandles(t types.Type) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil || !ok {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				ok = false
			}
		case *types.Interface, *types.Signature, *types.Chan, *types.TypeParam:
			ok = false
		case *types.Pointer:
			ok = false
		case *types.Map:
			ok = false
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(t)
	return ok
}

// DeriveNoPostInitCarrierWrites mechanically checks whether package p cannot
// write or retain any pointer, slice, map, channel, function, interface, or
// uintptr carrier in package-scope state after init, returning any non-stdlib
// cross-package callees to which p forwards carrier-bearing arguments outside init.
func DeriveNoPostInitCarrierWrites(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initOnly map[string]bool,
	directVarWrites []string,
) (bool, []string) {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return false, nil
	}
	if len(p.OtherFiles) > 0 || (len(p.GoFiles) > 0 && len(p.CompiledGoFiles) > len(p.GoFiles)) || len(directVarWrites) > 0 {
		return false, nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if initOnly == nil {
		initOnly = idx.InitOnly
	}
	initConeFDs := map[*ast.FuncDecl]bool{}
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp != nil && imp.Path != nil {
				if uq, err := strconv.Unquote(imp.Path.Value); err == nil && uq == "C" {
					return false, nil
				}
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					return false, nil
				}
			}
		}
		for _, decl := range file.Decls {
			fd, isFD := decl.(*ast.FuncDecl)
			if !isFD {
				continue
			}
			if fd.Body == nil {
				return false, nil
			}
			if fd.Recv == nil && (fd.Name.Name == "init" || initOnly[fd.Name.Name]) {
				initConeFDs[fd] = true
			}
		}
	}
	isPostInitNode := func(n ast.Node) bool {
		if idx.InGoStmt[n] {
			return true
		}
		if idx.InFuncLit[n] {
			cur := idx.ParentMap[n]
			for cur != nil {
				if lit, isLit := cur.(*ast.FuncLit); isLit {
					call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != lit {
						return true
					}
				}
				if fd, isFD := cur.(*ast.FuncDecl); isFD {
					return !initConeFDs[fd]
				}
				cur = idx.ParentMap[cur]
			}
			return false
		}
		fd := idx.SyncEnclFuncDecl(n)
		if fd == nil {
			return false
		}
		return !initConeFDs[fd]
	}

	mutableRefPkgUses := map[*ast.Ident]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil {
			continue
		}
		vt := v.Type()
		if !refconfine.TypeContainsRefOrPointer(vt) && !syntaxutil.ContainsUintptr(vt) {
			continue
		}
		if !v.Exported() && syntaxutil.IsNamedInPkg(vt, "sync", "Pool") {
			for _, uid := range idx.UsesOf[v] {
				if !isPostInitNode(uid) {
					continue
				}
				sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != uid {
					return false, nil
				}
				call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != sel || call.Ellipsis.IsValid() {
					return false, nil
				}
				switch sel.Sel.Name {
				case "Get":
					if len(call.Args) != 0 {
						return false, nil
					}
				case "Put":
					if len(call.Args) != 1 {
						return false, nil
					}
					ptr, isPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer)
					if !isPtr || !structFreeOfCarrierHandles(ptr.Elem()) {
						return false, nil
					}
				default:
					return false, nil
				}
			}
			continue
		}
		if containsSyncOrAtomicCarrier(vt) {
			return false, nil
		}
		if v.Exported() && (refconfine.TypeCarriesMutableRef(vt) || syntaxutil.ContainsUintptr(vt)) {
			return false, nil
		}
		rawPtrScalar := isUnsafePtrOrUintptrScalar(vt)
		carriesMutRef := !rawPtrScalar && refconfine.TypeCarriesMutableRef(vt)
		for _, uid := range idx.UsesOf[v] {
			if !isPostInitNode(uid) {
				continue
			}
			if refconfine.IdentOrExprIsWritten(idx, uid) || freshstruct.IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
				return false, nil
			}
			if rawPtrScalar {
				par := idx.ParentUnparen(uid)
				switch pn := par.(type) {
				case *ast.CaseClause:
				case *ast.BinaryExpr:
					if pn.Op != token.EQL && pn.Op != token.NEQ {
						return false, nil
					}
				case *ast.KeyValueExpr:
					if ast.Unparen(pn.Value) != uid {
						return false, nil
					}
				default:
					return false, nil
				}
				continue
			}
			if call, isCall := idx.ParentUnparen(uid).(*ast.CallExpr); isCall && len(call.Args) > 0 && ast.Unparen(call.Args[0]) == uid {
				if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							return false, nil
						}
					}
				}
			}
			if carriesMutRef {
				mutableRefPkgUses[uid] = true
			}
		}
	}
	if len(mutableRefPkgUses) > 0 {
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index: idx,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				id, isID := expr.(*ast.Ident)
				if !isID || !mutableRefPkgUses[id] {
					return false, false
				}
				t := p.TypesInfo.TypeOf(id)
				return refconfine.IsDirectMutableRef(t), refconfine.TypeCarriesMutableRef(t)
			},
		}) {
			return false, nil
		}
	}

	depSet := map[string]bool{}
	directCalleeIdents := map[*ast.Ident]bool{}
	recordDepCallee := func(orig *types.Func) bool {
		depPkg := orig.Pkg().Path()
		if syntaxutil.IsStandardLibraryPkgPath(depPkg) {
			return isPureNonRetainingStdCallee(orig)
		}
		depSet[depPkg] = true
		return true
	}
	okCalls := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !okCalls || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			curFun := ast.Unparen(call.Fun)
			switch e := curFun.(type) {
			case *ast.IndexExpr:
				curFun = ast.Unparen(e.X)
			case *ast.IndexListExpr:
				curFun = ast.Unparen(e.X)
			}
			switch fn := curFun.(type) {
			case *ast.Ident:
				directCalleeIdents[fn] = true
			case *ast.SelectorExpr:
				directCalleeIdents[fn.Sel] = true
			}
			if !isPostInitNode(call) {
				return true
			}
			if p.TypesInfo.Types[call.Fun].IsType() {
				return true
			}
			if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
				if _, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					return true
				}
			} else if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
				if _, isB := p.TypesInfo.Uses[sel.Sel].(*types.Builtin); isB {
					return true
				}
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && types.IsInterface(selInfo.Recv()) {
					return true
				}
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil {
				return true
			}
			orig := callee.Origin()
			if orig.Pkg() == nil || orig.Pkg() == p.Types {
				return true
			}
			passesCarrier := false
			if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodVal {
					rt := p.TypesInfo.TypeOf(sel.X)
					if refconfine.TypeContainsRefOrPointer(rt) || syntaxutil.ContainsUintptr(rt) {
						passesCarrier = true
					}
				}
			}
			if !passesCarrier {
				for _, arg := range call.Args {
					at := p.TypesInfo.TypeOf(arg)
					if refconfine.TypeContainsRefOrPointer(at) || syntaxutil.ContainsUintptr(at) {
						passesCarrier = true
						break
					}
				}
			}
			if !passesCarrier {
				return true
			}
			if !recordDepCallee(orig) {
				okCalls = false
				return false
			}
			return true
		})
		if !okCalls {
			return false, nil
		}
	}
	for id, obj := range p.TypesInfo.Uses {
		if directCalleeIdents[id] {
			continue
		}
		fn, isFn := obj.(*types.Func)
		if !isFn {
			continue
		}
		orig := fn.Origin()
		if orig.Pkg() == nil || orig.Pkg() == p.Types || !sigAcceptsCarrier(orig.Type()) {
			continue
		}
		if !recordDepCallee(orig) {
			return false, nil
		}
	}

	if len(depSet) == 0 {
		return true, nil
	}
	deps := make([]string, 0, len(depSet))
	for dep := range depSet {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	return true, deps
}

func addExemptStructInFunc(m map[*ast.FuncDecl]map[*types.Named]bool, fd *ast.FuncDecl, st *types.Named) {
	if fd == nil || st == nil {
		return
	}
	sub := m[fd]
	if sub == nil {
		sub = map[*types.Named]bool{}
		m[fd] = sub
	}
	sub[st] = true
}

// CollectDirectCrossPkgVarWrites scans p.Syntax for direct writes, container-mutating
// builtins, or escaping address-takes targeting imported dynamic package-scope variables.
func CollectDirectCrossPkgVarWrites(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []string {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	lookupImportedVar := func(expr ast.Expr) *types.Var {
		switch e := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			if p.TypesInfo.Selections[e] != nil {
				return nil
			}
			if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() &&
				v.Pkg() != nil && v.Pkg() != p.Types && v.Parent() == v.Pkg().Scope() {
				return v
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() &&
				v.Pkg() != nil && v.Pkg() != p.Types && v.Parent() == v.Pkg().Scope() {
				return v
			}
		}
		return nil
	}
	rootImportedVar := func(expr ast.Expr) (*types.Var, bool) {
		cur := ast.Unparen(expr)
		direct := true
		for {
			if v := lookupImportedVar(cur); v != nil {
				return v, direct
			}
			switch e := cur.(type) {
			case *ast.SelectorExpr:
				if p.TypesInfo.Selections[e] == nil {
					return nil, false
				}
				cur = ast.Unparen(e.X)
				direct = false
			case *ast.IndexExpr:
				cur = ast.Unparen(e.X)
				direct = false
			case *ast.SliceExpr:
				cur = ast.Unparen(e.X)
				direct = false
			default:
				return nil, false
			}
		}
	}

	seen := map[string]bool{}
	recordVar := func(v *types.Var) {
		if v != nil && refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			seen[syntaxutil.DynamicVarKey(v)] = true
		}
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if v, _ := rootImportedVar(lhs); v != nil {
						recordVar(v)
					}
				}
			case *ast.IncDecStmt:
				if v, _ := rootImportedVar(x.X); v != nil {
					recordVar(v)
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if x.Key != nil {
						if v, _ := rootImportedVar(x.Key); v != nil {
							recordVar(v)
						}
					}
					if x.Value != nil {
						if v, _ := rootImportedVar(x.Value); v != nil {
							recordVar(v)
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if v, direct := rootImportedVar(x.X); v != nil {
						isByValueStruct := false
						if direct {
							if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && syntaxutil.DerefNamedStruct(v.Type()) != nil {
								isByValueStruct = true
							}
						}
						if !isByValueStruct {
							recordVar(v)
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if len(x.Args) > 0 {
								if v, _ := rootImportedVar(x.Args[0]); v != nil {
									recordVar(v)
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
