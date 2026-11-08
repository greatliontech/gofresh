package dynstate

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// Protobuf runtime struct verification roles (REQ-closure-shared-dynamic-state-proto).
const (
	ProtoRoleBuilder     = "builder"
	ProtoRoleDescBuilder = "desc_builder"
	ProtoRoleEnum        = "enum"
	ProtoRoleMessage     = "message"
	ProtoRoleExtension   = "extension"

	unnamedStructPkgSentinel = "@struct"
)

// TypeRef identifies a package-level named Go struct type by package import path
// and unqualified type name after unaliasing, or a non-empty unnamed Go struct
// type (including type aliases to unnamed structs such as protoiface.Methods)
// by "@struct" and its canonical tag-ignoring structural SHA-256 digest.
type TypeRef struct {
	Pkg  string `json:"pkg"`
	Name string `json:"name"`
}

// TypeRefOfStruct returns the canonical TypeRef for a package-level named struct
// or a non-empty unnamed struct type (after unaliasing and optional single pointer
// dereference). Function-local named structs and zero-field unnamed structs return false.
func TypeRefOfStruct(t types.Type) (TypeRef, bool) {
	ref, _, _, ok := typeRefOfStruct(t)
	return ref, ok
}

// IsZero reports whether r is the empty TypeRef.
func (r TypeRef) IsZero() bool {
	return r.Pkg == "" && r.Name == ""
}

// Valid reports whether r names a non-empty package path and unqualified type
// identifier free of NUL separators.
func (r TypeRef) Valid() bool {
	return r.Pkg != "" && !strings.ContainsRune(r.Pkg, 0) &&
		r.Name != "" && !strings.ContainsAny(r.Name, "\x00.")
}

func (r TypeRef) key() string {
	return r.Pkg + "." + r.Name
}

// ProtoRuntimeTypeFact records that a named struct type in its defining package
// mechanically satisfies one of the deterministic once-initialization or
// descriptor-builder runtime roles. GuardTypes names any struct types whose
// instances are constructed or exposed by this runtime role and therefore must
// remain free of non-fresh mutations across the package graph. SubBuilder names
// any cross-package raw descriptor builder struct delegated to by Build().
type ProtoRuntimeTypeFact struct {
	Type           TypeRef   `json:"type"`
	Role           string    `json:"role"`
	SubBuilder     TypeRef   `json:"sub_builder,omitempty"`
	InitHelper     FuncKey   `json:"init_helper,omitempty"`
	AllowedHelpers []FuncKey `json:"allowed_helpers,omitempty"`
	GuardTypes     []TypeRef `json:"guard_types,omitempty"`
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
	InitFn      FuncKey  `json:"init_fn"`
	Vars        []string `json:"vars"`
	BuilderType TypeRef  `json:"builder_type"`
	EnumType    TypeRef  `json:"enum_type,omitempty"`
	MsgType     TypeRef  `json:"msg_type,omitempty"`
	ExtType     TypeRef  `json:"ext_type,omitempty"`
}

// Valid reports whether c carries well-formed function, variable, and participant
// type keys.
func (c ProtoClusterFact) Valid() bool {
	if !c.InitFn.Valid() || len(c.Vars) == 0 || !c.BuilderType.Valid() {
		return false
	}
	for _, v := range c.Vars {
		if !validQualifiedVarKey(v) {
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
	return validQualifiedVarKey(a.Key) && validQualifiedVarKey(a.Target) && a.Key != a.Target
}

// GrpcServiceVarFact records an immutable composite-literal gRPC ServiceDesc
// package variable paired with its descriptor struct types.
type GrpcServiceVarFact struct {
	Key        string  `json:"key"`
	SvcDesc    TypeRef `json:"svc_desc"`
	MethodDesc TypeRef `json:"method_desc,omitempty"`
	StreamDesc TypeRef `json:"stream_desc,omitempty"`
}

// Valid reports whether g carries well-formed variable and descriptor type keys.
func (g GrpcServiceVarFact) Valid() bool {
	if !validQualifiedVarKey(g.Key) || !g.SvcDesc.Valid() {
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

// deriveProtoAndStructFacts mechanically extracts protobuf descriptor clusters,
// extension aliases, runtime struct role proofs, gRPC service descriptors, and
// non-exempted struct mutations across p.Syntax.
func deriveProtoAndStructFacts(
	audited bool,
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
) ([]ProtoClusterFact, []ProtoExtAlias, []ProtoRuntimeTypeFact, []GrpcServiceVarFact, []TypeRef, []ConditionalStructMutation) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil, nil, nil, nil, nil, nil
	}
	if idx == nil {
		idx = buildPkgSyntaxIndex(p)
	}
	exempted := map[ast.Node]bool{}
	exemptFamilyByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	exemptReadFields := map[*types.Var]bool{}

	var clusters []ProtoClusterFact
	var extAliases []ProtoExtAlias
	var runtimeTypes []ProtoRuntimeTypeFact
	var grpcVars []GrpcServiceVarFact
	var protoConds []ConditionalStructMutation

	if audited {
		clusters, extAliases = deriveProtoClusters(audited, p, idx, initOnly, exempted)
		runtimeTypes, protoConds = deriveProtoRuntimeTypes(p, idx, mutatedVars, exempted, exemptFamilyByFunc, exemptReadFields)
		grpcVars = deriveGrpcServiceVars(audited, p, idx)
	}
	mutatedStructs, condMutations := collectMutatedStructTypes(p, idx, exempted, exemptFamilyByFunc, exemptReadFields)
	if len(protoConds) > 0 {
		seenCond := make(map[ConditionalStructMutation]bool, len(condMutations)+len(protoConds))
		merged := make([]ConditionalStructMutation, 0, len(condMutations)+len(protoConds))
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
		slices.SortFunc(merged, ConditionalStructMutation.Compare)
		condMutations = merged
	}
	return clusters, extAliases, runtimeTypes, grpcVars, mutatedStructs, condMutations
}

func deriveNonMutatingMethods(audited bool, p *packages.Package, idx *pkgSyntaxIndex) []FuncKey {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil
	}
	isScalarPtrRecv := func(fn *types.Func) *types.Var {
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() == nil {
			return nil
		}
		ptr, isP := types.Unalias(sig.Recv().Type()).(*types.Pointer)
		if !isP || TypeContainsRefOrPointer(ptr.Elem()) {
			return nil
		}
		return sig.Recv()
	}

	cands := map[*types.Func]*ast.FuncDecl{}
	scalarPtrHelpers := map[*types.Func]bool{}
	for fn, fd := range idx.funcDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types {
			continue
		}
		scalarRecv := isScalarPtrRecv(fn)
		localVars := map[*types.Var]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, isID := n.(*ast.Ident); isID {
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil && !dv.IsField() && dv.Parent() != p.Types.Scope() {
					localVars[dv] = true
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
						if uv != nil && localVars[uv] && !TypeContainsRefOrPointer(uv.Type()) {
							return true
						}
					}
					okLocal = false
					return false
				}
			}
			return true
		})
		if okLocal {
			cands[fn] = fd
			if usedScalarRecvWrite {
				scalarPtrHelpers[fn] = true
			}
		}
	}

	for {
		changed := false
		for fn, fd := range cands {
			localScalarVars := map[*types.Var]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if id, isID := n.(*ast.Ident); isID {
					if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil && !dv.IsField() && dv.Parent() != p.Types.Scope() && !TypeContainsRefOrPointer(dv.Type()) {
						localScalarVars[dv] = true
					}
				}
				return true
			})
			callsOK := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !callsOK || n == nil {
					return false
				}
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if tv, okTV := p.TypesInfo.Types[call.Fun]; okTV && tv.IsType() {
					return true
				}
				if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "len", "cap", "min", "max", "panic", "recover", "new", "make":
							return true
						}
						callsOK = false
						return false
					}
				}
				callee := resolveCalledFuncObj(p, call.Fun)
				if callee == nil {
					callsOK = false
					return false
				}
				callee = callee.Origin()
				if sig, okSig := callee.Type().(*types.Signature); okSig && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
					for _, arg := range call.Args {
						if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(arg)) {
							callsOK = false
							return false
						}
					}
					return true
				}
				if isPureNonRetainingStdCallee(callee) && callee.Name() != "Lock" && !strings.HasPrefix(callee.Name(), "Store") && !strings.HasPrefix(callee.Name(), "Add") && callee.Name() != "Put" {
					return true
				}
				if callee.Pkg() == p.Types && cands[callee] != nil {
					if scalarPtrHelpers[callee] {
						sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
						if !isSel {
							callsOK = false
							return false
						}
						lv := lookupIdentVar(p, sel.X)
						if lv == nil || !localScalarVars[lv] {
							callsOK = false
							return false
						}
					}
					return true
				}
				callsOK = false
				return false
			})
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
	var out []FuncKey
	for fn, fd := range cands {
		if scalarPtrHelpers[fn] || !fn.Exported() || fd.Recv == nil {
			continue
		}
		recvName := RecvTypeName(fd)
		if recvName == "" {
			continue
		}
		fk := FuncKey{Pkg: pkgPath, Name: recvName + "." + fn.Name()}
		if fk.Valid() {
			out = append(out, fk)
		}
	}
	slices.SortFunc(out, FuncKey.Compare)
	return out
}

func containsUintptr(root types.Type) bool {
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
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.Uintptr || u.Kind() == types.UnsafePointer {
				hit = true
			}
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

func isStandardLibraryPkgPath(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
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
			if isNamedInPkg(rt, "sync", "Mutex") || isNamedInPkg(rt, "sync", "RWMutex") || isNamedInPkg(rt, "sync", "Once") || isNamedInPkg(rt, "sync", "Pool") {
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
		if TypeContainsRefOrPointer(rt) || containsUintptr(rt) {
			return true
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if TypeContainsRefOrPointer(pt) || containsUintptr(pt) {
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
			// Disallow nested pointers other than scalar slices.
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

// deriveNoPostInitCarrierWrites mechanically checks whether package p cannot
// write or retain any pointer, slice, map, channel, function, interface, or
// uintptr carrier in package-scope state after init, returning any non-stdlib
// cross-package callees to which p forwards carrier-bearing arguments outside init.
func deriveNoPostInitCarrierWrites(
	audited bool,
	p *packages.Package,
	idx *pkgSyntaxIndex,
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
		idx = buildPkgSyntaxIndex(p)
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
		if idx.inGoStmt[n] {
			return true
		}
		if idx.inFuncLit[n] {
			// A closure executes synchronously during init if and only if every
			// enclosing FuncLit up to an initConeFD or top-level ValueSpec is
			// immediately invoked as `func(...) { ... }(...)`.
			cur := idx.parentMap[n]
			for cur != nil {
				if lit, isLit := cur.(*ast.FuncLit); isLit {
					call, isCall := idx.parentUnparen(lit).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != lit {
						return true
					}
				}
				if fd, isFD := cur.(*ast.FuncDecl); isFD {
					return !initConeFDs[fd]
				}
				cur = idx.parentMap[cur]
			}
			return false
		}
		fd := idx.syncEnclFuncDecl(n)
		if fd == nil {
			// Package-level ValueSpec initializer runs at init time.
			return false
		}
		return !initConeFDs[fd]
	}

	// 1. Inspect every package-scope variable in p.Types.Scope().
	mutableRefPkgUses := map[*ast.Ident]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil {
			continue
		}
		vt := v.Type()
		if !TypeContainsRefOrPointer(vt) && !containsUintptr(vt) {
			continue
		}
		if !v.Exported() && isNamedInPkg(vt, "sync", "Pool") {
			for _, uid := range idx.usesOf[v] {
				if !isPostInitNode(uid) {
					continue
				}
				sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != uid {
					return false, nil
				}
				call, isCall := idx.parentUnparen(sel).(*ast.CallExpr)
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
					ptr, isPtr := types.Unalias(p.TypesInfo.TypeOf(call.Args[0])).Underlying().(*types.Pointer)
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
		if v.Exported() && (TypeCarriesMutableRef(vt) || containsUintptr(vt)) {
			return false, nil
		}
		rawPtrScalar := isUnsafePtrOrUintptrScalar(vt)
		carriesMutRef := !rawPtrScalar && TypeCarriesMutableRef(vt)
		for _, uid := range idx.usesOf[v] {
			if !isPostInitNode(uid) {
				continue
			}
			if identOrExprIsWritten(idx, uid) || identReachesMutatedOrAddrPrefix(p, idx, uid) {
				return false, nil
			}
			if rawPtrScalar {
				par := idx.parentUnparen(uid)
				switch pn := par.(type) {
				case *ast.CaseClause:
					// Read-only switch comparison tag (`case nilType:`).
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
			if call, isCall := idx.parentUnparen(uid).(*ast.CallExpr); isCall && len(call.Args) > 0 && ast.Unparen(call.Args[0]) == uid {
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
		if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				id, isID := expr.(*ast.Ident)
				if !isID || !mutableRefPkgUses[id] {
					return false, false
				}
				t := p.TypesInfo.TypeOf(id)
				return IsDirectMutableRef(t), TypeCarriesMutableRef(t)
			},
		}) {
			return false, nil
		}
	}

	// 2. Collect cross-package calls outside init (and any value-taken
	// cross-package callables accepting carriers) that may receive carriers.
	depSet := map[string]bool{}
	directCalleeIdents := map[*ast.Ident]bool{}
	recordDepCallee := func(orig *types.Func) bool {
		depPkg := orig.Pkg().Path()
		if isStandardLibraryPkgPath(depPkg) {
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
			callee := resolveCalledFuncObj(p, call.Fun)
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
					if TypeContainsRefOrPointer(rt) || containsUintptr(rt) {
						passesCarrier = true
					}
				}
			}
			if !passesCarrier {
				for _, arg := range call.Args {
					at := p.TypesInfo.TypeOf(arg)
					if TypeContainsRefOrPointer(at) || containsUintptr(at) {
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

// collectDirectCrossPkgVarWrites scans p.Syntax for direct writes, container-mutating
// builtins, or escaping address-takes targeting imported dynamic package-scope variables.
func collectDirectCrossPkgVarWrites(audited bool, p *packages.Package, idx *pkgSyntaxIndex) []string {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = buildPkgSyntaxIndex(p)
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
		if v != nil && TypeMayCarryUnknownDynamic(audited, v.Type()) {
			seen[dynamicVarKey(v)] = true
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
						// Direct &pkg.Desc on a by-value named struct (such as &pb.Greeter_ServiceDesc)
						// is tracked via MutatedStructTypes; all other cross-package address-takes
						// (&pkg.FileVar, &pkg.E_Ext, &pkg.Desc.Field, &pkg.Desc.Methods[0]) poison v.
						isByValueStruct := false
						if direct {
							if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && derefNamedStruct(v.Type()) != nil {
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

func typeRefOfNamedStruct(t types.Type) (TypeRef, *types.Named, bool) {
	n := derefNamedStruct(t)
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return TypeRef{}, nil, false
	}
	// Reject function-local named types (Obj().Parent() != Pkg().Scope()).
	if n.Obj().Parent() != n.Obj().Pkg().Scope() {
		return TypeRef{}, nil, false
	}
	ref := TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
	if !ref.Valid() {
		return TypeRef{}, nil, false
	}
	return ref, n, true
}

func typeRefOfStruct(t types.Type) (TypeRef, *types.Named, *types.Struct, bool) {
	if t == nil {
		return TypeRef{}, nil, nil, false
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	switch u := t.(type) {
	case *types.Named:
		if u.Obj() == nil || u.Obj().Pkg() == nil || u.Obj().Parent() != u.Obj().Pkg().Scope() {
			return TypeRef{}, nil, nil, false
		}
		st, isSt := u.Underlying().(*types.Struct)
		if !isSt {
			return TypeRef{}, nil, nil, false
		}
		ref := TypeRef{Pkg: u.Obj().Pkg().Path(), Name: u.Obj().Name()}
		if !ref.Valid() {
			return TypeRef{}, nil, nil, false
		}
		return ref, u, st, true
	case *types.Struct:
		if u.NumFields() == 0 {
			return TypeRef{}, nil, nil, false
		}
		ref, ok := unnamedStructTypeRef(u)
		if !ok {
			return TypeRef{}, nil, nil, false
		}
		return ref, nil, u, true
	}
	return TypeRef{}, nil, nil, false
}

func unnamedStructTypeRef(st *types.Struct) (TypeRef, bool) {
	if st == nil || st.NumFields() == 0 {
		return TypeRef{}, false
	}
	var b strings.Builder
	if !writeCanonicalType(&b, st, map[types.Type]int{}) {
		return TypeRef{}, false
	}
	sum := sha256.Sum256([]byte(b.String()))
	return TypeRef{Pkg: unnamedStructPkgSentinel, Name: hex.EncodeToString(sum[:])}, true
}

func writeCanonicalType(b *strings.Builder, t types.Type, visiting map[types.Type]int) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	switch u := t.(type) {
	case *types.Basic:
		if u.Kind() == types.Invalid {
			return false
		}
		b.WriteString("B:")
		b.WriteString(strconv.Itoa(int(u.Kind())))
		b.WriteByte(';')
		return true
	case *types.Named:
		obj := u.Obj()
		if obj == nil {
			return false
		}
		if obj.Pkg() == nil {
			b.WriteString("U:")
			b.WriteString(obj.Name())
		} else {
			if obj.Parent() != obj.Pkg().Scope() {
				return false
			}
			b.WriteString("N:")
			b.WriteString(obj.Pkg().Path())
			b.WriteByte('.')
			b.WriteString(obj.Name())
		}
		if targs := u.TypeArgs(); targs.Len() > 0 {
			b.WriteByte('[')
			for i := 0; i < targs.Len(); i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				if !writeCanonicalType(b, targs.At(i), visiting) {
					return false
				}
			}
			b.WriteByte(']')
		}
		b.WriteByte(';')
		return true
	case *types.Pointer:
		b.WriteByte('*')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Slice:
		b.WriteString("[]")
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Array:
		b.WriteByte('[')
		b.WriteString(strconv.FormatInt(u.Len(), 10))
		b.WriteByte(']')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Map:
		b.WriteString("map[")
		if !writeCanonicalType(b, u.Key(), visiting) {
			return false
		}
		b.WriteByte(']')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Chan:
		b.WriteString("chan(")
		b.WriteString(strconv.Itoa(int(u.Dir())))
		b.WriteString("):")
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Struct:
		if id, active := visiting[t]; active {
			b.WriteString("cycle:")
			b.WriteString(strconv.Itoa(id))
			b.WriteByte(';')
			return true
		}
		nextID := len(visiting) + 1
		visiting[t] = nextID
		defer delete(visiting, t)
		b.WriteString("struct{")
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if f.Embedded() {
				b.WriteString("1:")
			} else {
				b.WriteString("0:")
			}
			if !f.Exported() {
				if f.Pkg() == nil {
					return false
				}
				b.WriteString(f.Pkg().Path())
				b.WriteByte('.')
			}
			b.WriteString(f.Name())
			b.WriteByte(':')
			if !writeCanonicalType(b, f.Type(), visiting) {
				return false
			}
			b.WriteByte(';')
		}
		b.WriteByte('}')
		return true
	case *types.Signature:
		if u.TypeParams().Len() > 0 || u.RecvTypeParams().Len() > 0 {
			return false
		}
		if u.Variadic() {
			b.WriteString("func...(")
		} else {
			b.WriteString("func(")
		}
		if params := u.Params(); params != nil {
			for i := 0; i < params.Len(); i++ {
				if !writeCanonicalType(b, params.At(i).Type(), visiting) {
					return false
				}
				b.WriteByte(',')
			}
		}
		b.WriteString(")(")
		if results := u.Results(); results != nil {
			for i := 0; i < results.Len(); i++ {
				if !writeCanonicalType(b, results.At(i).Type(), visiting) {
					return false
				}
				b.WriteByte(',')
			}
		}
		b.WriteByte(')')
		return true
	case *types.Interface:
		if !u.IsMethodSet() {
			return false
		}
		if id, active := visiting[t]; active {
			b.WriteString("icycle:")
			b.WriteString(strconv.Itoa(id))
			b.WriteByte(';')
			return true
		}
		nextID := len(visiting) + 1
		visiting[t] = nextID
		defer delete(visiting, t)
		b.WriteString("interface{")
		for i := 0; i < u.NumMethods(); i++ {
			m := u.Method(i)
			if !m.Exported() {
				if m.Pkg() == nil {
					return false
				}
				b.WriteString(m.Pkg().Path())
				b.WriteByte('.')
			}
			b.WriteString(m.Name())
			b.WriteByte(':')
			if !writeCanonicalType(b, m.Type(), visiting) {
				return false
			}
			b.WriteByte(';')
		}
		b.WriteByte('}')
		return true
	}
	return false
}

func derefAnyStructType(t types.Type) (types.Type, *types.Struct) {
	if t == nil {
		return nil, nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if st, ok := t.Underlying().(*types.Struct); ok {
		return t, st
	}
	return nil, nil
}

func forEachSelectionHopStructType(selInfo *types.Selection, visit func(types.Type)) {
	if selInfo == nil {
		return
	}
	curType, st := derefAnyStructType(selInfo.Recv())
	if curType == nil || st == nil {
		return
	}
	visit(curType)
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		if indices[i] < 0 || indices[i] >= st.NumFields() {
			return
		}
		curType, st = derefAnyStructType(st.Field(indices[i]).Type())
		if curType == nil || st == nil {
			return
		}
		visit(curType)
	}
}

func forEachValueContainedStructType(root types.Type, visit func(types.Type)) {
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if st, isSt := t.Underlying().(*types.Struct); isSt {
			visit(t)
			for i := 0; i < st.NumFields(); i++ {
				walk(st.Field(i).Type())
			}
			return
		}
		if arr, isArr := t.Underlying().(*types.Array); isArr {
			walk(arr.Elem())
		}
	}
	walk(root)
}

// -----------------------------------------------------------------------------
// Family 3A (Part 1): Declaring-package protobuf file descriptor clusters
// -----------------------------------------------------------------------------

func deriveProtoClusters(
	audited bool,
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initOnly map[string]bool,
	exempted map[ast.Node]bool,
) ([]ProtoClusterFact, []ProtoExtAlias) {
	var clusters []ProtoClusterFact
	claimedVars := map[*types.Var]bool{}

	// Deterministic iteration over package functions.
	var fnObjs []*types.Func
	for fn := range idx.funcDecls {
		if fn.Pkg() == p.Types && !fn.Exported() {
			if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil && sig.TypeParams().Len() == 0 &&
				sig.Params().Len() == 0 && sig.Results().Len() == 0 && fn.Name() != "init" {
				if initOnly[fn.Name()] {
					fnObjs = append(fnObjs, fn)
				}
			}
		}
	}
	sort.Slice(fnObjs, func(i, j int) bool { return fnObjs[i].Name() < fnObjs[j].Name() })

	for _, fn := range fnObjs {
		fd := idx.funcDecls[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		cluster, clusterVars, initExempt, ok := verifyProtoClusterInitFunc(audited, p, idx, fn, fd, initOnly)
		if !ok {
			continue
		}
		overlap := false
		for _, v := range clusterVars {
			if claimedVars[v] {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		for _, v := range clusterVars {
			claimedVars[v] = true
		}
		for n := range initExempt {
			exempted[n] = true
		}
		clusters = append(clusters, cluster)
	}

	// Scan package-scope vars for public-import extension aliases: var E_X = otherpkg.E_Y
	var aliases []ProtoExtAlias
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || claimedVars[v] || !TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if idx.defCounts[v] != 1 {
			continue
		}
		ptr, isPtr := types.Unalias(v.Type()).(*types.Pointer)
		if !isPtr || derefNamedStruct(ptr.Elem()) == nil {
			continue
		}
		vs := idx.varSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		sel, isSel := ast.Unparen(vs.Values[0]).(*ast.SelectorExpr)
		if !isSel {
			continue
		}
		targetVar, isVar := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		if !isVar || targetVar.Pkg() == nil || targetVar.Pkg() == p.Types || targetVar.IsField() {
			continue
		}
		if !types.Identical(types.Unalias(v.Type()), types.Unalias(targetVar.Type())) {
			continue
		}
		if !verifyReadOnlyPtrVarUses(p, idx, v) {
			continue
		}
		aliases = append(aliases, ProtoExtAlias{
			Key:    dynamicVarKey(v),
			Target: dynamicVarKey(targetVar),
		})
	}
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].Key != aliases[j].Key {
			return aliases[i].Key < aliases[j].Key
		}
		return aliases[i].Target < aliases[j].Target
	})
	return clusters, aliases
}

func verifyProtoClusterInitFunc(
	audited bool,
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fn *types.Func,
	fd *ast.FuncDecl,
	initOnly map[string]bool,
) (ProtoClusterFact, []*types.Var, map[ast.Node]bool, bool) {
	stmts := fd.Body.List
	if len(stmts) < 3 {
		return ProtoClusterFact{}, nil, nil, false
	}

	// stmts[0]: if FileVar != nil { return }
	guardIf, ok := stmts[0].(*ast.IfStmt)
	if !ok || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 {
		return ProtoClusterFact{}, nil, nil, false
	}
	if ret, isRet := guardIf.Body.List[0].(*ast.ReturnStmt); !isRet || len(ret.Results) != 0 {
		return ProtoClusterFact{}, nil, nil, false
	}
	guardBin, ok := ast.Unparen(guardIf.Cond).(*ast.BinaryExpr)
	if !ok || guardBin.Op != token.NEQ {
		return ProtoClusterFact{}, nil, nil, false
	}
	var fileVar *types.Var
	if isNilIdent(p, guardBin.Y) {
		fileVar = lookupPkgScopeVar(p, guardBin.X)
	} else if isNilIdent(p, guardBin.X) {
		fileVar = lookupPkgScopeVar(p, guardBin.Y)
	}
	if fileVar == nil || idx.defCounts[fileVar] != 1 || !types.IsInterface(fileVar.Type()) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if fvs := idx.varSpecs[fileVar]; fvs == nil || len(fvs.Values) != 0 {
		return ProtoClusterFact{}, nil, nil, false
	}

	// Locate out := BuilderType{...}.Build() and FileVar = out.File in stmts[1:].
	buildIdx := -1
	var outVar *types.Var
	var builderComp *ast.CompositeLit
	var builderRef TypeRef
	for i := 1; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		call, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			continue
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Build" {
			continue
		}
		comp, isComp := ast.Unparen(sel.X).(*ast.CompositeLit)
		if !isComp {
			continue
		}
		ref, _, validRef := typeRefOfNamedStruct(p.TypesInfo.TypeOf(comp))
		if !validRef {
			return ProtoClusterFact{}, nil, nil, false
		}
		if buildIdx != -1 {
			return ProtoClusterFact{}, nil, nil, false
		}
		ov := lookupIdentVar(p, as.Lhs[0])
		if ov == nil || ov.Parent() == p.Types.Scope() {
			return ProtoClusterFact{}, nil, nil, false
		}
		buildIdx = i
		outVar = ov
		builderComp = comp
		builderRef = ref
	}
	if buildIdx == -1 || buildIdx+1 >= len(stmts) {
		return ProtoClusterFact{}, nil, nil, false
	}

	// Verify BuilderType{...} composite literal fields.
	var goTypesVar, depIdxsVar, enumTypesVar, msgTypesVar, extTypesVar *types.Var
	var enumRef, msgRef, extRef TypeRef
	allowedInitUses := map[*types.Var]map[*ast.Ident]bool{}
	allowUse := func(v *types.Var, id *ast.Ident) {
		if allowedInitUses[v] == nil {
			allowedInitUses[v] = map[*ast.Ident]bool{}
		}
		allowedInitUses[v][id] = true
	}

	for _, elt := range builderComp.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			return ProtoClusterFact{}, nil, nil, false
		}
		kID, isID := kv.Key.(*ast.Ident)
		if !isID {
			return ProtoClusterFact{}, nil, nil, false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "File":
			if !verifyDescBuilderSubLit(p, val) {
				return ProtoClusterFact{}, nil, nil, false
			}
		case "GoTypes":
			id, isVID := val.(*ast.Ident)
			v := lookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || goTypesVar != nil || !isAnySliceType(v.Type()) {
				return ProtoClusterFact{}, nil, nil, false
			}
			goTypesVar = v
			allowUse(v, id)
		case "DependencyIndexes":
			v := lookupPkgScopeVar(p, val)
			if v == nil || v.Exported() || depIdxsVar != nil || TypeMayCarryUnknownDynamic(audited, v.Type()) {
				return ProtoClusterFact{}, nil, nil, false
			}
			depIdxsVar = v
		case "EnumInfos":
			id, isVID := val.(*ast.Ident)
			v := lookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || enumTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := sliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			enumTypesVar = v
			enumRef = ref
			allowUse(v, id)
		case "MessageInfos":
			id, isVID := val.(*ast.Ident)
			v := lookupPkgScopeVar(p, val)
			if !isVID || v == nil || v.Exported() || msgTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := sliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			msgTypesVar = v
			msgRef = ref
			allowUse(v, id)
		case "ExtensionInfos":
			v, id, okExt := extractSliceVarOrSubslice(p, val)
			if !okExt || v.Exported() || extTypesVar != nil {
				return ProtoClusterFact{}, nil, nil, false
			}
			ref, okRef := sliceElemStructRef(v.Type())
			if !okRef {
				return ProtoClusterFact{}, nil, nil, false
			}
			extTypesVar = v
			extRef = ref
			allowUse(v, id)
		default:
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	// Verify stmts[buildIdx+1]: FileVar = outVar.File
	fileAssign, ok := stmts[buildIdx+1].(*ast.AssignStmt)
	if !ok || fileAssign.Tok != token.ASSIGN || len(fileAssign.Lhs) != 1 || len(fileAssign.Rhs) != 1 {
		return ProtoClusterFact{}, nil, nil, false
	}
	fileLHSID, isFLHS := ast.Unparen(fileAssign.Lhs[0]).(*ast.Ident)
	if !isFLHS || p.TypesInfo.Uses[fileLHSID] != fileVar {
		return ProtoClusterFact{}, nil, nil, false
	}
	outSel, isOutSel := ast.Unparen(fileAssign.Rhs[0]).(*ast.SelectorExpr)
	if !isOutSel || !isIdentUsingObj(p, outSel.X, outVar) || outSel.Sel.Name != "File" {
		return ProtoClusterFact{}, nil, nil, false
	}
	allowUse(fileVar, guardBinIdent(p, guardBin, fileVar))
	allowUse(fileVar, fileLHSID)

	initExempt := map[ast.Node]bool{}

	// Verify pre-Build statements stmts[1:buildIdx].
	for i := 1; i < buildIdx; i++ {
		st := stmts[i]
		switch s := st.(type) {
		case *ast.DeclStmt:
			if !isEmptyLocalStructTypeDecl(s) {
				return ProtoClusterFact{}, nil, nil, false
			}
		case *ast.ExprStmt:
			// Prerequisite sibling init-only function call: file_other_proto_init()
			call, isCall := ast.Unparen(s.X).(*ast.CallExpr)
			if !isCall || len(call.Args) != 0 {
				return ProtoClusterFact{}, nil, nil, false
			}
			cid, isCID := ast.Unparen(call.Fun).(*ast.Ident)
			if !isCID {
				return ProtoClusterFact{}, nil, nil, false
			}
			callee, isFn := p.TypesInfo.Uses[cid].(*types.Func)
			if !isFn || callee.Pkg() != p.Types || callee.Exported() || !initOnly[callee.Name()] {
				return ProtoClusterFact{}, nil, nil, false
			}
		case *ast.AssignStmt:
			// msgTypes[c].OneofWrappers = []any{(*W)(nil), ...}
			msgID, okWrap := verifyOneofWrappersAssign(p, s, msgTypesVar)
			if !okWrap {
				return ProtoClusterFact{}, nil, nil, false
			}
			allowUse(msgTypesVar, msgID)
			initExempt[s] = true
		case *ast.IfStmt:
			// Legacy: if !protoimpl.UnsafeEnabled { msgTypes[c].Exporter = func(v any, i int) any { ... } }
			msgIDs, assignStmts, okExp := verifyLegacyExporterIfStmt(p, s, msgTypesVar)
			if !okExp {
				return ProtoClusterFact{}, nil, nil, false
			}
			for _, mid := range msgIDs {
				allowUse(msgTypesVar, mid)
			}
			for _, as := range assignStmts {
				initExempt[as] = true
			}
		default:
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	// Verify post-Build statements stmts[buildIdx+2:]: only nil-outs of goTypes, depIdxs, or carrier-free rawDesc.
	for i := buildIdx + 2; i < len(stmts); i++ {
		as, isAs := stmts[i].(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !isNilIdent(p, as.Rhs[0]) {
			return ProtoClusterFact{}, nil, nil, false
		}
		lhsID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		lhsVar := lookupPkgScopeVar(p, as.Lhs[0])
		if !isID || lhsVar == nil || lhsVar.Exported() {
			return ProtoClusterFact{}, nil, nil, false
		}
		if lhsVar == goTypesVar {
			allowUse(goTypesVar, lhsID)
			continue
		}
		if lhsVar == depIdxsVar || !TypeMayCarryUnknownDynamic(audited, lhsVar.Type()) {
			continue
		}
		return ProtoClusterFact{}, nil, nil, false
	}

	// Verify package-wide invariants for each participant variable!
	if !verifyProtoFileVarUses(p, idx, fileVar, allowedInitUses[fileVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if goTypesVar != nil && !verifyProtoGoTypesVar(p, idx, goTypesVar, allowedInitUses[goTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if enumTypesVar != nil && !verifyProtoInfoSliceVar(p, idx, fd, enumTypesVar, allowedInitUses[enumTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	if msgTypesVar != nil && !verifyProtoInfoSliceVar(p, idx, fd, msgTypesVar, allowedInitUses[msgTypesVar]) {
		return ProtoClusterFact{}, nil, nil, false
	}
	var boundExtVars []*types.Var
	if extTypesVar != nil {
		var okExt bool
		boundExtVars, okExt = verifyProtoExtTypesAndVars(p, idx, fd, extTypesVar, allowedInitUses[extTypesVar])
		if !okExt {
			return ProtoClusterFact{}, nil, nil, false
		}
	}

	var allVars []*types.Var
	var varKeys []string
	addClusterVar := func(v *types.Var) {
		if v == nil || !TypeMayCarryUnknownDynamic(audited, v.Type()) {
			return
		}
		allVars = append(allVars, v)
		varKeys = append(varKeys, dynamicVarKey(v))
	}
	addClusterVar(fileVar)
	addClusterVar(goTypesVar)
	addClusterVar(enumTypesVar)
	addClusterVar(msgTypesVar)
	addClusterVar(extTypesVar)
	for _, ev := range boundExtVars {
		addClusterVar(ev)
	}
	if len(varKeys) == 0 {
		return ProtoClusterFact{}, nil, nil, false
	}
	sort.Strings(varKeys)

	return ProtoClusterFact{
		InitFn:      FuncKey{Pkg: p.Types.Path(), Name: fn.Name()},
		Vars:        varKeys,
		BuilderType: builderRef,
		EnumType:    enumRef,
		MsgType:     msgRef,
		ExtType:     extRef,
	}, allVars, initExempt, true
}

func guardBinIdent(p *packages.Package, bin *ast.BinaryExpr, want *types.Var) *ast.Ident {
	if id, ok := ast.Unparen(bin.X).(*ast.Ident); ok && p.TypesInfo.Uses[id] == want {
		return id
	}
	if id, ok := ast.Unparen(bin.Y).(*ast.Ident); ok && p.TypesInfo.Uses[id] == want {
		return id
	}
	return nil
}

func verifyDescBuilderSubLit(p *packages.Package, expr ast.Expr) bool {
	comp, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	clean := true
	ast.Inspect(comp, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			clean = false
			return false
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Parent() == p.Types.Scope() {
				// Only carrier-free rawDesc byte slices may be referenced here.
				if TypeMayCarryUnknownDynamic(true, v.Type()) {
					clean = false
					return false
				}
			}
		}
		return true
	})
	return clean
}

func isEmptyLocalStructTypeDecl(ds *ast.DeclStmt) bool {
	gd, ok := ds.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.TYPE || len(gd.Specs) != 1 {
		return false
	}
	ts, ok := gd.Specs[0].(*ast.TypeSpec)
	if !ok {
		return false
	}
	st, ok := ts.Type.(*ast.StructType)
	return ok && (st.Fields == nil || len(st.Fields.List) == 0)
}

func verifyOneofWrappersAssign(p *packages.Package, as *ast.AssignStmt, msgTypesVar *types.Var) (*ast.Ident, bool) {
	if msgTypesVar == nil || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return nil, false
	}
	sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "OneofWrappers" {
		return nil, false
	}
	ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
	if !ok || !isNonNegConstInt(p, ie.Index) {
		return nil, false
	}
	msgID, ok := ast.Unparen(ie.X).(*ast.Ident)
	if !ok || p.TypesInfo.Uses[msgID] != msgTypesVar {
		return nil, false
	}
	comp, ok := ast.Unparen(as.Rhs[0]).(*ast.CompositeLit)
	if !ok || !isAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return nil, false
	}
	for _, elt := range comp.Elts {
		if !isTypedNilStructPtrInPkg(p, elt, p.Types) {
			return nil, false
		}
	}
	return msgID, true
}

func verifyLegacyExporterIfStmt(p *packages.Package, ifs *ast.IfStmt, msgTypesVar *types.Var) ([]*ast.Ident, []*ast.AssignStmt, bool) {
	if msgTypesVar == nil || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) == 0 {
		return nil, nil, false
	}
	condClean := true
	ast.Inspect(ifs.Cond, func(n ast.Node) bool {
		if !condClean || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			condClean = false
			return false
		}
		return true
	})
	if !condClean {
		return nil, nil, false
	}
	var ids []*ast.Ident
	var assigns []*ast.AssignStmt
	for _, st := range ifs.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return nil, nil, false
		}
		sel, ok := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Exporter" {
			return nil, nil, false
		}
		ie, ok := ast.Unparen(sel.X).(*ast.IndexExpr)
		if !ok || !isNonNegConstInt(p, ie.Index) {
			return nil, nil, false
		}
		msgID, ok := ast.Unparen(ie.X).(*ast.Ident)
		if !ok || p.TypesInfo.Uses[msgID] != msgTypesVar {
			return nil, nil, false
		}
		lit, ok := ast.Unparen(as.Rhs[0]).(*ast.FuncLit)
		if !ok || !isPureLegacyExporterFuncLit(p, lit) {
			return nil, nil, false
		}
		ids = append(ids, msgID)
		assigns = append(assigns, as)
	}
	return ids, assigns, true
}

func isPureLegacyExporterFuncLit(p *packages.Package, lit *ast.FuncLit) bool {
	if lit.Body == nil {
		return false
	}
	clean := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr, *ast.GoStmt, *ast.SendStmt, *ast.FuncLit:
			clean = false
			return false
		case *ast.AssignStmt:
			// Allow only v, ok := v.(*Msg) type-assertion init inside switch/if.
			if x.Tok != token.DEFINE {
				clean = false
				return false
			}
			for _, rhs := range x.Rhs {
				if _, isTA := ast.Unparen(rhs).(*ast.TypeAssertExpr); !isTA {
					clean = false
					return false
				}
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Parent() == p.Types.Scope() {
				clean = false
				return false
			}
		}
		return true
	})
	return clean
}

func verifyProtoFileVarUses(p *packages.Package, idx *pkgSyntaxIndex, fileVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	for _, id := range idx.usesOf[fileVar] {
		if allowedInit[id] {
			continue
		}
		if identIsWrittenOrAddrTaken(idx, id) {
			return false
		}
	}
	return true
}

func verifyProtoGoTypesVar(p *packages.Package, idx *pkgSyntaxIndex, goTypesVar *types.Var, allowedInit map[*ast.Ident]bool) bool {
	if idx.defCounts[goTypesVar] != 1 {
		return false
	}
	vs := idx.varSpecs[goTypesVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok || !isAnySliceType(p.TypesInfo.TypeOf(comp)) {
		return false
	}
	for _, elt := range comp.Elts {
		if !isSafeGoTypesElement(p, elt) {
			return false
		}
	}
	for _, id := range idx.usesOf[goTypesVar] {
		if !allowedInit[id] {
			return false
		}
	}
	return true
}

func isSafeGoTypesElement(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if isNilIdent(p, expr) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	dstType := types.Unalias(p.TypesInfo.Types[call.Fun].Type)
	if _, isPtr := dstType.(*types.Pointer); isPtr {
		return isNilIdent(p, call.Args[0])
	}
	if basic, isBasic := dstType.Underlying().(*types.Basic); isBasic && (basic.Info()&types.IsConstType) != 0 {
		tv := p.TypesInfo.Types[call.Args[0]]
		return tv.Value != nil && !TypeMayCarryUnknownDynamic(true, dstType)
	}
	return false
}

func verifyProtoInfoSliceVar(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initFD *ast.FuncDecl,
	sliceVar *types.Var,
	allowedInit map[*ast.Ident]bool,
) bool {
	if idx.defCounts[sliceVar] != 1 {
		return false
	}
	vs := idx.varSpecs[sliceVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 || !isMakeFixedSliceCall(p, vs.Values[0]) {
		return false
	}
	for _, id := range idx.usesOf[sliceVar] {
		if allowedInit[id] {
			continue
		}
		if idx.enclFunc[id] == initFD {
			return false
		}
		// Outside initFD, sliceVar may only appear as sliceVar[c] (constant non-negative c)
		// and sliceVar[c] may never be assigned, incremented, or field-assigned.
		ie, ok := idx.parentUnparen(id).(*ast.IndexExpr)
		if !ok || ast.Unparen(ie.X) != id || !isNonNegConstInt(p, ie.Index) {
			return false
		}
		iePar := idx.parentUnparen(ie)
		if as, isAs := iePar.(*ast.AssignStmt); isAs {
			for _, lhs := range as.Lhs {
				if ast.Unparen(lhs) == ie {
					return false
				}
			}
		}
		if inc, isInc := iePar.(*ast.IncDecStmt); isInc && ast.Unparen(inc.X) == ie {
			return false
		}
		if rng, isRng := iePar.(*ast.RangeStmt); isRng && rng.Tok == token.ASSIGN &&
			((rng.Key != nil && ast.Unparen(rng.Key) == ie) || (rng.Value != nil && ast.Unparen(rng.Value) == ie)) {
			return false
		}
	}
	return true
}

func verifyProtoExtTypesAndVars(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initFD *ast.FuncDecl,
	extTypesVar *types.Var,
	allowedInit map[*ast.Ident]bool,
) ([]*types.Var, bool) {
	if idx.defCounts[extTypesVar] != 1 {
		return nil, false
	}
	vs := idx.varSpecs[extTypesVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return nil, false
	}
	comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	for _, elt := range comp.Elts {
		sub, isSub := ast.Unparen(elt).(*ast.CompositeLit)
		if !isSub || !verifyExtInfoLiteralElement(p, sub) {
			return nil, false
		}
	}

	var boundVars []*types.Var
	seenVars := map[*types.Var]bool{}
	for _, id := range idx.usesOf[extTypesVar] {
		if allowedInit[id] {
			continue
		}
		if idx.enclFunc[id] != nil || idx.inFuncLit[id] || idx.inGoStmt[id] {
			return nil, false
		}
		// Must be &extTypesVar[c] inside a package-scope var initializer: var E_Foo = &extTypesVar[c]
		ie, ok := idx.parentUnparen(id).(*ast.IndexExpr)
		if !ok || ast.Unparen(ie.X) != id || !isNonNegConstInt(p, ie.Index) {
			return nil, false
		}
		un, ok := idx.parentUnparen(ie).(*ast.UnaryExpr)
		if !ok || un.Op != token.AND {
			return nil, false
		}
		spec, ok := idx.parentUnparen(un).(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 || ast.Unparen(spec.Values[0]) != un {
			return nil, false
		}
		ev, ok := p.TypesInfo.Defs[spec.Names[0]].(*types.Var)
		if !ok || ev == nil || ev.Parent() != p.Types.Scope() || idx.defCounts[ev] != 1 {
			return nil, false
		}
		if !verifyReadOnlyPtrVarUses(p, idx, ev) {
			return nil, false
		}
		if !seenVars[ev] {
			seenVars[ev] = true
			boundVars = append(boundVars, ev)
		}
	}
	return boundVars, true
}

func verifyExtInfoLiteralElement(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "ExtendedType", "ExtensionType":
			if !isSafeExtTypeExpr(p, val) {
				return false
			}
		case "Field", "Name", "Tag", "Filename":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isSafeExtTypeExpr(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if isNilIdent(p, expr) {
		return true
	}
	if tv := p.TypesInfo.Types[expr]; tv.Value != nil && !TypeMayCarryUnknownDynamic(true, tv.Type) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	dst := types.Unalias(p.TypesInfo.Types[call.Fun].Type)
	switch dst.Underlying().(type) {
	case *types.Pointer, *types.Slice:
		return isNilIdent(p, call.Args[0])
	case *types.Basic:
		tv := p.TypesInfo.Types[call.Args[0]]
		return tv.Value != nil
	}
	return false
}

func verifyReadOnlyPtrVarUses(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	for _, id := range idx.usesOf[v] {
		if identIsWrittenOrAddrTaken(idx, id) {
			return false
		}
		par := idx.parentUnparen(id)
		if star, isStar := par.(*ast.StarExpr); isStar {
			if identOrExprIsWritten(idx, star) {
				return false
			}
		}
	}
	_ = p
	return true
}

// -----------------------------------------------------------------------------
// Family 3A (Part 2): Runtime struct role proofs (DescBuilder, Builder, Enum, Message, Ext)
// -----------------------------------------------------------------------------

func deriveProtoRuntimeTypes(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	mutatedVars map[string]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]ProtoRuntimeTypeFact, []ConditionalStructMutation) {
	type candidate struct {
		ref   TypeRef
		named *types.Named
		st    *types.Struct
	}
	var candidates []candidate
	for _, name := range p.Types.Scope().Names() {
		tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		ref := TypeRef{Pkg: p.Types.Path(), Name: tn.Name()}
		if !ref.Valid() {
			continue
		}
		candidates = append(candidates, candidate{ref: ref, named: named, st: st})
	}

	var out []ProtoRuntimeTypeFact
	var conds []ConditionalStructMutation
	builderExempt := map[ast.Node]bool{}
	builderHelperIdents := map[*ast.Ident]bool{}
	confinedCacheMaps := findMutexConfinedConstructorCaches(p, idx)

	// Pass 0: verify raw file descriptor builders (e.g. filedesc.Builder) and their
	// closed write-once descriptor struct families.
	for _, c := range candidates {
		if dbNodes, dbByFunc, dbGuards, okDB := verifyProtoDescBuilderType(p, idx, c.named, c.st, mutatedVars, exemptReadFields); okDB {
			for n := range dbNodes {
				exempted[n] = true
			}
			for fd, fam := range dbByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleDescBuilder,
				GuardTypes: dbGuards,
			})
		}
	}

	// Pass 1: verify descriptor type-builder structs first so their verified Build()
	// initialization writes and extension-init helper calls are recorded before
	// checking message, extension, and enum structs declared in the same package.
	for _, c := range candidates {
		if bNodes, helperIdents, subBuilder, allowedHelpers, bGuards, okB := verifyProtoBuilderType(p, idx, c.named, c.st, mutatedVars); okB {
			for n := range bNodes {
				exempted[n] = true
				builderExempt[n] = true
			}
			for id := range helperIdents {
				builderHelperIdents[id] = true
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:           c.ref,
				Role:           ProtoRoleBuilder,
				SubBuilder:     subBuilder,
				AllowedHelpers: allowedHelpers,
				GuardTypes:     bGuards,
			})
		}
	}

	// Pass 2: verify message, extension, and enum descriptor structs.
	// Verify message roots first so extension info structs referencing *MessageInfo
	// recognize verified message roots as protected immutable descriptors.
	verifiedMsgRoots := map[*types.Named]bool{}
	for _, c := range candidates {
		if mNodes, mByFunc, mGuards, mConds, okM := verifyProtoMessageType(p, idx, c.named, c.st, mutatedVars, builderExempt, verifiedMsgRoots, confinedCacheMaps); okM {
			verifiedMsgRoots[c.named] = true
			for n := range mNodes {
				exempted[n] = true
			}
			for fd, fam := range mByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, mConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleMessage,
				GuardTypes: mGuards,
			})
		}
	}
	for _, c := range candidates {
		if eNodes, eByFunc, initHelper, eGuards, eConds, okE := verifyProtoExtensionType(p, idx, c.named, c.st, mutatedVars, builderExempt, builderHelperIdents, verifiedMsgRoots, confinedCacheMaps); okE {
			for n := range eNodes {
				exempted[n] = true
			}
			for fd, fam := range eByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, eConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleExtension,
				InitHelper: initHelper,
				GuardTypes: eGuards,
			})
		}
	}
	for _, c := range candidates {
		if verifyProtoEnumType(p, idx, c.named, c.st, builderExempt, verifiedMsgRoots) {
			out = append(out, ProtoRuntimeTypeFact{Type: c.ref, Role: ProtoRoleEnum})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type.key() != out[j].Type.key() {
			return out[i].Type.key() < out[j].Type.key()
		}
		return out[i].Role < out[j].Role
	})
	return out, conds
}

func verifyProtoBuilderType(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
) (map[ast.Node]bool, map[*ast.Ident]bool, TypeRef, []FuncKey, []TypeRef, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	// Must have exported GoTypes []any and solely a Build() method returning a struct with exported File interface.
	hasGoTypes := false
	infoElemStructs := map[*types.Named]bool{}
	builderExportedStructFields := map[*types.Var]*types.Named{}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		switch f.Name() {
		case "GoTypes":
			if !f.Exported() || !isAnySliceType(f.Type()) {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			hasGoTypes = true
		case "EnumInfos", "MessageInfos", "ExtensionInfos":
			if !f.Exported() {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			_, elemNamed, okElem := sliceElemNamedStruct(f.Type())
			if !okElem {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			infoElemStructs[elemNamed] = true
		default:
			if f.Exported() {
				if fnamed, isN := types.Unalias(f.Type()).(*types.Named); isN {
					if _, isSt := fnamed.Underlying().(*types.Struct); isSt {
						builderExportedStructFields[f] = fnamed
					}
				}
			}
		}
	}
	if !hasGoTypes || len(infoElemStructs) == 0 || named.NumMethods() != 1 {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	buildFn := named.Method(0)
	if buildFn.Name() != "Build" {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok || !structHasExportedIfaceField(outSt, "File") {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	buildFD := idx.funcDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil || sig.Recv() == nil {
		return nil, nil, TypeRef{}, nil, nil, false
	}
	recvVar := sig.Recv()
	var namedResultOutVar *types.Var
	if sig.Results().At(0).Name() != "" {
		namedResultOutVar = sig.Results().At(0)
	}

	// Detect optional SubBuilder delegation: fbOut := tb.<SubField>.Build().
	var subBuilderRef TypeRef
	var fbOutVar *types.Var
	fbOutSliceFields := map[*types.Var]bool{}
	subCallBad := false
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if subCallBad || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			return true
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Build" {
			return true
		}
		subSel, isSubSel := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !isSubSel {
			return true
		}
		rid, isID := ast.Unparen(subSel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[rid] != recvVar {
			return true
		}
		subFieldObj, _ := p.TypesInfo.Uses[subSel.Sel].(*types.Var)
		subNamed := builderExportedStructFields[subFieldObj]
		if subNamed == nil || subNamed.Obj() == nil || subNamed.Obj().Pkg() == nil {
			subCallBad = true
			return false
		}
		ref := TypeRef{Pkg: subNamed.Obj().Pkg().Path(), Name: subNamed.Obj().Name()}
		if !ref.Valid() || fbOutVar != nil {
			subCallBad = true
			return false
		}
		as, isAs := idx.parentUnparen(call).(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			subCallBad = true
			return false
		}
		lid, isLID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isLID {
			subCallBad = true
			return false
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.defCounts[lv] != 1 {
			subCallBad = true
			return false
		}
		fbSt, isSt := types.Unalias(lv.Type()).Underlying().(*types.Struct)
		if !isSt || !structHasExportedIfaceField(fbSt, "File") {
			subCallBad = true
			return false
		}
		for i := 0; i < fbSt.NumFields(); i++ {
			ff := fbSt.Field(i)
			if ff.Exported() {
				if _, _, okElem := sliceElemNamedStruct(ff.Type()); okElem {
					fbOutSliceFields[ff] = true
				}
			}
		}
		if len(fbOutSliceFields) == 0 {
			subCallBad = true
			return false
		}
		for _, uid := range idx.usesOf[lv] {
			if identIsWrittenOrAddrTaken(idx, uid) {
				subCallBad = true
				return false
			}
		}
		subBuilderRef = ref
		fbOutVar = lv
		return true
	})
	if subCallBad {
		return nil, nil, TypeRef{}, nil, nil, false
	}

	isSubBuilderSliceElemAddr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		ix, isIx := ast.Unparen(un.X).(*ast.IndexExpr)
		if !isIx {
			return false
		}
		sel, isSel := ast.Unparen(ix.X).(*ast.SelectorExpr)
		if !isSel {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != fbOutVar {
			return false
		}
		fObj, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		return fbOutSliceFields[fObj]
	}

	isSubBuilderFileExpr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "File" {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		return isID && p.TypesInfo.Uses[id] == fbOutVar
	}

	directDescStructs := map[*types.Named]bool{}
	isVerifiedDirectDescAlloc := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL {
			return false
		}
		stNamed := derefNamedStruct(p.TypesInfo.TypeOf(cl))
		if stNamed == nil || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || stNamed.Obj().Exported() || stNamed.TypeParams().Len() > 0 {
			return false
		}
		for _, elt := range cl.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
			}
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if !TypeContainsRefOrPointer(vt) || isByteSliceType(vt) {
				continue
			}
			return false
		}
		directDescStructs[stNamed] = true
		return true
	}

	checkDescValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderSliceElemAddr(expr)
		}
		vt := p.TypesInfo.TypeOf(expr)
		if vt != nil && !TypeContainsRefOrPointer(vt) {
			return true
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	checkOutFileValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderFileExpr(expr)
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	// Track local slices derived via slicing from tb.GoTypes (e.g. enumGoTypes, messageGoTypes).
	goTypesDerivedVars := map[*types.Var]bool{}
	isGoTypesExpr := func(expr ast.Expr) bool {
		cur := ast.Unparen(expr)
		for {
			if se, isSE := cur.(*ast.SliceExpr); isSE {
				cur = ast.Unparen(se.X)
				continue
			}
			break
		}
		if sel, isSel := cur.(*ast.SelectorExpr); isSel && sel.Sel.Name == "GoTypes" {
			if id, isID := ast.Unparen(sel.X).(*ast.Ident); isID && p.TypesInfo.Uses[id] == recvVar {
				return true
			}
		}
		if id, isID := cur.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil && goTypesDerivedVars[v] {
				return true
			}
		}
		return false
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
			if lv, _ := p.TypesInfo.Defs[lid].(*types.Var); lv != nil && idx.defCounts[lv] == 1 && isGoTypesExpr(as.Rhs[0]) {
				reassigned := false
				for _, uid := range idx.usesOf[lv] {
					if identIsWrittenOrAddrTaken(idx, uid) {
						reassigned = true
						break
					}
				}
				if !reassigned {
					goTypesDerivedVars[lv] = true
				}
			}
		}
		return true
	})

	isNilDefaultRecvIfaceAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.parentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != sel {
			return false
		}
		lhs := ast.Unparen(as.Lhs[0])
		if !types.IsInterface(p.TypesInfo.TypeOf(lhs)) {
			return false
		}
		cur := lhs
		for {
			s, okS := cur.(*ast.SelectorExpr)
			if !okS {
				return false
			}
			if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
				if p.TypesInfo.Uses[id] != recvVar {
					return false
				}
				break
			}
			cur = ast.Unparen(s.X)
		}
		blk, isBlk := idx.parentMap[as].(*ast.BlockStmt)
		if !isBlk || len(blk.List) != 1 {
			return false
		}
		ifStmt, isIf := idx.parentMap[blk].(*ast.IfStmt)
		if !isIf || ifStmt.Body != blk || ifStmt.Else != nil {
			return false
		}
		bin, isBin := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL {
			return false
		}
		return isNilIdent(p, bin.Y) || isNilIdent(p, bin.X)
	}

	isDescoptsGoTypeAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.parentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
			return false
		}
		ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !isTA || ta.Type == nil || !types.IsInterface(p.TypesInfo.TypeOf(ta)) {
			return false
		}
		ix, isIx := ast.Unparen(ta.X).(*ast.IndexExpr)
		return isIx && isGoTypesExpr(ix.X)
	}

	// Verify Out.File initialization and return paths in buildFD.Body.
	sawOutFileInit := false
	outValid := true
	checkOutCompositeLit := func(cl *ast.CompositeLit) bool {
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := kv.Key.(*ast.Ident)
			if !isID || kid.Name != "File" || !checkOutFileValue(kv.Value) {
				return false
			}
			sawOutFileInit = true
		}
		return true
	}
	if namedResultOutVar != nil {
		for _, uid := range idx.usesOf[namedResultOutVar] {
			par := idx.parentUnparen(uid)
			if sel, isSel := par.(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == uid {
				if as, isAs := idx.parentUnparen(sel).(*ast.AssignStmt); isAs {
					onLHS := false
					for li, l := range as.Lhs {
						if ast.Unparen(l) == sel {
							onLHS = true
							if sel.Sel.Name != "File" || li >= len(as.Rhs) || !checkOutFileValue(as.Rhs[li]) {
								outValid = false
							} else {
								sawOutFileInit = true
							}
						}
					}
					if onLHS {
						continue
					}
				}
				continue
			}
			if _, isRet := par.(*ast.ReturnStmt); isRet {
				continue
			}
			outValid = false
		}
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if !outValid || n == nil {
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) == 0 {
			if namedResultOutVar == nil {
				outValid = false
				return false
			}
			return true
		}
		if len(ret.Results) != 1 {
			outValid = false
			return false
		}
		res := ast.Unparen(ret.Results[0])
		if rid, isID := res.(*ast.Ident); isID {
			if namedResultOutVar == nil || p.TypesInfo.Uses[rid] != namedResultOutVar {
				outValid = false
				return false
			}
			return true
		}
		cl, isCL := res.(*ast.CompositeLit)
		if !isCL || len(cl.Elts) == 0 || !checkOutCompositeLit(cl) {
			outValid = false
			return false
		}
		return true
	})
	if !outValid || !sawOutFileInit {
		return nil, nil, TypeRef{}, nil, nil, false
	}

	// Collect intra-package helper cone + constructed intra-package helper structs (and their methods).
	buildCone := map[*types.Func]bool{buildFn: true}
	constructedStructs := map[*types.Named]bool{}
	coneQueue := []*types.Func{buildFn}
	validBuild := true
	enqueueConstructedStruct := func(stNamed *types.Named) {
		if stNamed == nil || stNamed == named || stNamed == outNamed || infoElemStructs[stNamed] || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || constructedStructs[stNamed] {
			return
		}
		constructedStructs[stNamed] = true
		pset := types.NewMethodSet(types.NewPointer(stNamed))
		for mi := 0; mi < pset.Len(); mi++ {
			mfn, okM := pset.At(mi).Obj().(*types.Func)
			if !okM || mfn == nil {
				validBuild = false
				return
			}
			msig, okSig := mfn.Type().(*types.Signature)
			if !okSig || msig.Recv() == nil {
				validBuild = false
				return
			}
			if types.IsInterface(msig.Recv().Type()) {
				continue
			}
			mfn = mfn.Origin()
			if mfn.Pkg() != p.Types {
				validBuild = false
				return
			}
			if !buildCone[mfn] {
				buildCone[mfn] = true
				coneQueue = append(coneQueue, mfn)
			}
		}
	}
	for k := range directDescStructs {
		enqueueConstructedStruct(k)
	}
	for len(coneQueue) > 0 && validBuild {
		curFn := coneQueue[0]
		coneQueue = coneQueue[1:]
		fd := idx.funcDecls[curFn]
		if fd == nil || fd.Body == nil {
			validBuild = false
			break
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.FuncLit:
				validBuild = false
				return false
			case *ast.CompositeLit:
				enqueueConstructedStruct(derefNamedStruct(p.TypesInfo.TypeOf(x)))
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						enqueueConstructedStruct(derefNamedStruct(p.TypesInfo.TypeOf(x)))
					}
				}
				if callee := resolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
						// Interface method declaration has no concrete FuncDecl body.
					} else if callee.Pkg() == p.Types && !buildCone[callee] {
						buildCone[callee] = true
						coneQueue = append(coneQueue, callee)
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		return nil, nil, TypeRef{}, nil, nil, false
	}

	exempt := map[ast.Node]bool{}
	helperCandidates := map[*types.Func]bool{}
	validHelperCallIdents := map[*ast.Ident]bool{}
	for fn := range buildCone {
		fd := idx.funcDecls[fn]
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					if v.Pkg() == p.Types {
						if v.Exported() || mutatedVars[dynamicVarKey(v)] || !isDeterministicImmutableBuilderGlobal(p, idx, v) {
							validBuild = false
							return false
						}
					} else {
						sel, isSel := idx.parentUnparen(x).(*ast.SelectorExpr)
						if !isSel || sel.Sel != x || fn != buildFn || (!isNilDefaultRecvIfaceAssign(sel) && !isDescoptsGoTypeAssign(sel)) {
							validBuild = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					if !touchesAnyNamedStruct(p, lhs, infoElemStructs) {
						continue
					}
					if fn != buildFn || li >= len(x.Rhs) || !isSafeBuilderInfoAssignment(p, lhs, x.Rhs[li], infoElemStructs, checkDescValue) {
						validBuild = false
						return false
					}
					exempt[x] = true
				}
			case *ast.IncDecStmt:
				if touchesAnyNamedStruct(p, x.X, infoElemStructs) {
					validBuild = false
					return false
				}
			case *ast.CallExpr:
				if fn == buildFn && len(x.Args) >= 2 && !x.Ellipsis.IsValid() {
					var calleeID *ast.Ident
					switch fun := ast.Unparen(x.Fun).(type) {
					case *ast.SelectorExpr:
						calleeID = fun.Sel
					case *ast.Ident:
						calleeID = fun
					}
					if calleeID != nil {
						if selFn, isFn := p.TypesInfo.Uses[calleeID].(*types.Func); isFn && selFn != nil {
							selFn = selFn.Origin()
							if selFn.Exported() && selFn.Pkg() != nil {
								if fnSig, okSig := selFn.Type().(*types.Signature); okSig && fnSig.Recv() == nil {
									if un, isUn := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND && touchesAnyNamedStruct(p, un.X, infoElemStructs) {
										if !checkDescValue(x.Args[1]) {
											validBuild = false
											return false
										}
										for _, extra := range x.Args[2:] {
											et := p.TypesInfo.TypeOf(extra)
											if et == nil || (!isReflectTypeType(et) && TypeContainsRefOrPointer(et)) {
												validBuild = false
												return false
											}
										}
										helperCandidates[selFn] = true
										validHelperCallIdents[calleeID] = true
										exempt[un] = true
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		return nil, nil, TypeRef{}, nil, nil, false
	}

	// Verify all intra-package structs constructed in buildCone (e.g. resolverByIndex, fileDesc)
	// are unexported, non-generic, free of closures/channels/unsafe, and never mutated in p.Syntax.
	guardSet := map[TypeRef]bool{}
	if len(constructedStructs) > 0 {
		for cs := range constructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			if !builderHelperStructFieldsSafe(cs, fbOutVar != nil) {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			ref := TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, TypeRef{}, nil, nil, false
			}
			guardSet[ref] = true
		}
		if pkgHasAnyMutationOnStructs(p, idx, constructedStructs, nil) {
			return nil, nil, TypeRef{}, nil, nil, false
		}
		infoElemPkgs := map[*types.Package]bool{}
		for infoSt := range infoElemStructs {
			if infoSt.Obj() != nil && infoSt.Obj().Pkg() != nil {
				infoElemPkgs[infoSt.Obj().Pkg()] = true
			}
		}
		goTypesCarrierFields := map[*types.Var]bool{}
		for cs := range constructedStructs {
			if cst, okS := cs.Underlying().(*types.Struct); okS {
				for i := 0; i < cst.NumFields(); i++ {
					f := cst.Field(i)
					if !f.Exported() && isAnySliceType(f.Type()) {
						onlyGoTypes := false
						validUses := true
						for _, uid := range idx.usesOf[f] {
							if kv, isKV := idx.parentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
								gsel, isGS := ast.Unparen(kv.Value).(*ast.SelectorExpr)
								if !isGS || gsel.Sel.Name != "GoTypes" {
									validUses = false
									break
								}
								if rid, isID := ast.Unparen(gsel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != recvVar {
									validUses = false
									break
								}
								onlyGoTypes = true
							}
						}
						if validUses && onlyGoTypes {
							goTypesCarrierFields[f] = true
						}
					}
				}
			}
		}
		if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
			AllowReturnFromUnexportedFunc: true,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel {
					return false, false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false, false
				}
				hit := false
				forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if constructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if IsDirectMutableRef(ft) {
					return true, true
				}
				if TypeCarriesMutableRef(ft) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
				if argIdx != 0 || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return false
				}
				if isReflectTypeOfCall(p, call) {
					return true
				}
				ix, isIx := ast.Unparen(arg).(*ast.IndexExpr)
				if !isIx {
					return false
				}
				xsel, isXS := ast.Unparen(ix.X).(*ast.SelectorExpr)
				if !isXS {
					return false
				}
				fv, _ := p.TypesInfo.Uses[xsel.Sel].(*types.Var)
				if fv == nil || !goTypesCarrierFields[fv] {
					return false
				}
				callee := resolveCalledFuncObj(p, call.Fun)
				if callee == nil || !infoElemPkgs[callee.Pkg()] {
					return false
				}
				csig, okSig := callee.Type().(*types.Signature)
				if !okSig || csig.Recv() == nil || csig.Results().Len() != 1 || !types.IsInterface(csig.Results().At(0).Type()) {
					return false
				}
				recvSt, okSt := types.Unalias(csig.Recv().Type()).Underlying().(*types.Struct)
				return okSt && recvSt.NumFields() == 0
			},
		}) {
			return nil, nil, TypeRef{}, nil, nil, false
		}
	}

	var guardTypes []TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].key() < guardTypes[j].key() })
	}

	var allowedHelpers []FuncKey
	for selFn := range helperCandidates {
		allInBuild := true
		for _, id := range idx.usesOf[selFn] {
			if !validHelperCallIdents[id] {
				allInBuild = false
				break
			}
		}
		if allInBuild {
			allowedHelpers = append(allowedHelpers, FuncKey{Pkg: selFn.Pkg().Path(), Name: selFn.Name()})
		}
	}
	slices.SortFunc(allowedHelpers, FuncKey.Compare)
	return exempt, validHelperCallIdents, subBuilderRef, allowedHelpers, guardTypes, true
}

func isSafeBuilderInfoAssignment(
	p *packages.Package,
	lhs, rhs ast.Expr,
	infoElemStructs map[*types.Named]bool,
	checkDesc func(ast.Expr) bool,
) bool {
	lhs = ast.Unparen(lhs)
	rhs = ast.Unparen(rhs)
	switch l := lhs.(type) {
	case *ast.SelectorExpr:
		if l.Sel.Name == "GoReflectType" {
			return isReflectTypeOfCall(p, rhs)
		}
		if l.Sel.Name == "Desc" {
			return !exprIsFuncLit(rhs) && checkDesc(rhs)
		}
		return false
	case *ast.IndexExpr:
		comp, ok := rhs.(*ast.CompositeLit)
		if !ok {
			return false
		}
		st := derefNamedStruct(p.TypesInfo.TypeOf(comp))
		if st == nil || !infoElemStructs[st] {
			return false
		}
		for _, elt := range comp.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kID, isID := kv.Key.(*ast.Ident)
			if !isID {
				return false
			}
			switch kID.Name {
			case "GoReflectType":
				if !isReflectTypeOfCall(p, kv.Value) {
					return false
				}
			case "Desc":
				if exprIsFuncLit(kv.Value) || !checkDesc(kv.Value) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return false
}

func isReflectTypeType(t types.Type) bool {
	return isNamedInPkg(t, "reflect", "Type")
}

func builderHelperStructFieldsSafe(named *types.Named, allowResolverFields bool) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		case *types.Signature, *types.Chan, *types.Map, *types.Pointer, *types.TypeParam:
			ok = false
		case *types.Interface:
			if !allowResolverFields {
				ok = false
			}
		case *types.Slice:
			if isAnySliceType(t) {
				if !allowResolverFields {
					ok = false
				}
				return
			}
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(named)
	return ok
}

func isDeterministicImmutableBuilderGlobal(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	if idx.defCounts[v] != 1 {
		return false
	}
	for _, uid := range idx.usesOf[v] {
		if identIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.parentUnparen(uid)
		if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid {
			if identOrExprIsWritten(idx, ix) {
				return false
			}
			continue
		}
		if !TypeContainsRefOrPointer(v.Type()) {
			continue
		}
		return false
	}
	if !TypeContainsRefOrPointer(v.Type()) {
		return true
	}
	// Map global (e.g. goTypeForPBKind map[Kind]reflect.Type): must be initialized by a
	// composite literal of constant keys and reflect.TypeOf(<const or typed-nil>) values.
	mp, isMap := types.Unalias(v.Type()).Underlying().(*types.Map)
	if !isMap || TypeContainsRefOrPointer(mp.Key()) || !isReflectTypeType(mp.Elem()) {
		return false
	}
	foundSpec := false
	specOK := true
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gd, isGD := decl.(*ast.GenDecl)
			if !isGD || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs, isVS := sp.(*ast.ValueSpec)
				if !isVS {
					continue
				}
				for i, nm := range vs.Names {
					if p.TypesInfo.Defs[nm] != v {
						continue
					}
					foundSpec = true
					if i >= len(vs.Values) {
						specOK = false
						break
					}
					cl, isCL := ast.Unparen(vs.Values[i]).(*ast.CompositeLit)
					if !isCL {
						specOK = false
						break
					}
					for _, elt := range cl.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV || p.TypesInfo.Types[kv.Key].Value == nil || !isReflectTypeOfCall(p, kv.Value) {
							specOK = false
							break
						}
						rc := ast.Unparen(kv.Value).(*ast.CallExpr)
						if len(rc.Args) != 1 || !isSafeExtTypeExpr(p, rc.Args[0]) {
							specOK = false
							break
						}
					}
				}
			}
		}
	}
	return foundSpec && specOK
}

// verifyProtoDescBuilderType mechanically proves that a raw file descriptor
// builder struct (such as google.golang.org/protobuf/internal/filedesc.Builder)
// and its entire closed descriptor struct family are write-once, deterministic,
// goroutine-free, and free of post-initialization mutations across p.Syntax.
func verifyProtoDescBuilderType(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	exemptReadFields map[*types.Var]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []TypeRef, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return nil, nil, nil, false
	}
	hasRawDesc := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Name() == "GoTypes" {
			return nil, nil, nil, false
		}
		if f.Name() == "RawDescriptor" && f.Exported() && isByteSliceType(f.Type()) {
			hasRawDesc = true
		}
	}
	if !hasRawDesc {
		return nil, nil, nil, false
	}

	// Must expose solely Build() Out as its exported method.
	var buildFn *types.Func
	psetBuilder := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < psetBuilder.Len(); i++ {
		m, okM := psetBuilder.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types {
			return nil, nil, nil, false
		}
		if !m.Exported() {
			continue
		}
		if m.Name() != "Build" || buildFn != nil {
			return nil, nil, nil, false
		}
		buildFn = m
	}
	if buildFn == nil {
		return nil, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok || !structHasExportedIfaceField(outSt, "File") {
		return nil, nil, nil, false
	}
	buildFD := idx.funcDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil {
		return nil, nil, nil, false
	}

	descFamily := map[*types.Named]bool{}
	for i := 0; i < outSt.NumFields(); i++ {
		f := outSt.Field(i)
		if f.Exported() {
			if _, elemNamed, okElem := sliceElemNamedStruct(f.Type()); okElem && elemNamed.Obj() != nil && elemNamed.Obj().Pkg() == p.Types {
				descFamily[elemNamed] = true
			}
		}
	}
	if len(descFamily) == 0 {
		return nil, nil, nil, false
	}

	// Discover the concrete intra-package File struct(s) assigned to Out.File in Build() and its callees.
	buildReach := map[*types.Func]bool{buildFn: true}
	bQueue := []*types.Func{buildFn}
	for len(bQueue) > 0 {
		cur := bQueue[0]
		bQueue = bQueue[1:]
		cfd := idx.funcDecls[cur]
		if cfd == nil || cfd.Body == nil {
			return nil, nil, nil, false
		}
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if call, isCall := n.(*ast.CallExpr); isCall {
				if callee := resolveCalledFuncObj(p, call.Fun); callee != nil {
					callee = callee.Origin()
					if sigC, okSig := callee.Type().(*types.Signature); okSig && sigC.Recv() != nil && types.IsInterface(sigC.Recv().Type()) {
						return true
					}
					if callee.Pkg() == p.Types && !buildReach[callee] {
						buildReach[callee] = true
						bQueue = append(bQueue, callee)
					}
				}
			}
			return true
		})
	}

	fileRootStructs := map[*types.Named]bool{}
	outFileValid := true
	for fn := range buildReach {
		cfd := idx.funcDecls[fn]
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if !outFileValid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CompositeLit:
				if derefNamedStruct(p.TypesInfo.TypeOf(x)) == outNamed && outNamed != nil {
					for _, elt := range x.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							outFileValid = false
							return false
						}
						kid, isID := kv.Key.(*ast.Ident)
						if isID && kid.Name == "File" {
							fs := derefNamedStruct(p.TypesInfo.TypeOf(kv.Value))
							if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
								outFileValid = false
								return false
							}
							fileRootStructs[fs] = true
							descFamily[fs] = true
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != "File" {
						continue
					}
					if derefNamedStruct(p.TypesInfo.TypeOf(sel.X)) == outNamed && outNamed != nil {
						if li >= len(x.Rhs) {
							outFileValid = false
							return false
						}
						fs := derefNamedStruct(p.TypesInfo.TypeOf(x.Rhs[li]))
						if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
							outFileValid = false
							return false
						}
						fileRootStructs[fs] = true
						descFamily[fs] = true
					}
				}
			}
			return true
		})
	}
	if !outFileValid || len(fileRootStructs) != 1 {
		return nil, nil, nil, false
	}
	var fileNamed *types.Named
	for fn := range fileRootStructs {
		fileNamed = fn
	}

	// Transitively close descFamily over all intra-package structs reachable through fields,
	// slices, arrays, pointers, or maps, and collect any cross-package value/slice-element structs
	// (such as protoreflect.FileImport and protoreflect.SourceLocation) into extraGuards.
	extraGuards := map[TypeRef]bool{}
	immutableSlicePtrTypes := map[*types.Named]bool{}
	seenWalk := map[types.Type]bool{}
	fieldsValid := true
	var walkType func(owner *types.Named, t types.Type)
	walkType = func(owner *types.Named, t types.Type) {
		if t == nil || !fieldsValid {
			return
		}
		t = types.Unalias(t)
		if isNamedInPkg(t, "sync", "Mutex") {
			if owner != fileNamed {
				fieldsValid = false
			}
			return
		}
		if isNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() == p.Types {
				if _, isSt := n.Underlying().(*types.Struct); isSt {
					if n.TypeParams().Len() > 0 {
						fieldsValid = false
						return
					}
					if !descFamily[n] {
						descFamily[n] = true
						if stN, okS := n.Underlying().(*types.Struct); okS {
							for i := 0; i < stN.NumFields(); i++ {
								walkType(n, stN.Field(i).Type())
							}
						}
					}
					return
				}
				if _, isSl := n.Underlying().(*types.Slice); isSl {
					immutableSlicePtrTypes[n] = true
				}
			} else if ref, _, subSt, okRef := typeRefOfStruct(n); okRef && subSt.NumFields() > 0 && ref.Valid() {
				extraGuards[ref] = true
				return
			}
		}
		if seenWalk[t] {
			return
		}
		seenWalk[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				fieldsValid = false
			}
		case *types.Chan, *types.TypeParam:
			fieldsValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			en, isEN := elem.(*types.Named)
			if !isEN || en.Obj() == nil || en.Obj().Pkg() != p.Types {
				fieldsValid = false
				return
			}
			if _, isSt := en.Underlying().(*types.Struct); !isSt {
				fieldsValid = false
				return
			}
			walkType(owner, elem)
		case *types.Slice:
			walkType(owner, u.Elem())
		case *types.Array:
			walkType(owner, u.Elem())
		case *types.Map:
			walkType(owner, u.Key())
			walkType(owner, u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkType(owner, u.Field(i).Type())
			}
		}
	}
	initialFamily := make([]*types.Named, 0, len(descFamily))
	for fn := range descFamily {
		initialFamily = append(initialFamily, fn)
	}
	for _, fn := range initialFamily {
		if stN, okS := fn.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				walkType(fn, stN.Field(i).Type())
			}
		}
	}
	if !fieldsValid {
		return nil, nil, nil, false
	}

	// Verify immutableSlicePtrTypes (e.g. FileImports) expose zero mutating methods.
	for slNamed := range immutableSlicePtrTypes {
		psetSl := types.NewMethodSet(types.NewPointer(slNamed))
		for i := 0; i < psetSl.Len(); i++ {
			mfn, okM := psetSl.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types {
				return nil, nil, nil, false
			}
			mfd := idx.funcDecls[mfn]
			if mfd == nil || mfd.Body == nil || bodyHasAnyAssignment(p, mfd.Body) {
				return nil, nil, nil, false
			}
		}
	}

	// Locate File's locked once-init method (e.g. (*File).lazyInitOnce).
	fileSt, ok := fileNamed.Underlying().(*types.Struct)
	if !ok {
		return nil, nil, nil, false
	}
	var fileMuField, fileOnceField *types.Var
	for famNamed := range descFamily {
		if famNamed == fileNamed || structEmbedsUnexported(fileSt, famNamed) {
			if fst, okS := famNamed.Underlying().(*types.Struct); okS {
				mu, done := findUnexportedMutexAndUint32(fst)
				if mu != nil {
					fileMuField = mu
				}
				if done != nil {
					fileOnceField = done
				}
			}
		}
	}
	if fileMuField == nil || fileOnceField == nil {
		return nil, nil, nil, false
	}
	var fileOnceFn *types.Func
	psetFile := types.NewMethodSet(types.NewPointer(fileNamed))
	for i := 0; i < psetFile.Len(); i++ {
		m, okM := psetFile.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		mfd := idx.funcDecls[m]
		if mfd != nil && mfd.Body != nil && isLockedOnceInitMethodAllowTailUnlock(p, mfd, fileNamed, fileMuField, fileOnceField) {
			if fileOnceFn != nil {
				return nil, nil, nil, false
			}
			fileOnceFn = m
		}
	}
	if fileOnceFn == nil {
		return nil, nil, nil, false
	}

	// Gate 1: Zero GoStmts anywhere in p.Syntax, and every FuncLit in p.Syntax must
	// satisfy one of the 4 closed deterministic shapes:
	//   (a) Direct callback argument to (sync.Once).Do(func() { ... }).
	//   (b) Memoized 2-statement closure func() R { once.Do(func() { ... }); return cached }
	//       capturing unescaped local once (sync.Once) and cached.
	//   (c) Pure assignment-free comparator callback to sort.Slice.
	//   (d) Pool constructor sync.Pool{New: func() any { return new(T) }} with zero captures.
	receiverOnceDoBlocks := map[*ast.BlockStmt]*types.Named{}
	memoOnceDoBlocks := map[*ast.BlockStmt]bool{}
	allowedBuildLitBlocks := map[*ast.BlockStmt]bool{}
	for _, file := range p.Syntax {
		litOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !litOK || n == nil {
				return false
			}
			if _, isGo := n.(*ast.GoStmt); isGo {
				litOK = false
				return false
			}
			lit, isLit := n.(*ast.FuncLit)
			if !isLit {
				return true
			}
			if memoOnceDoBlocks[lit.Body] {
				return true
			}
			if recvStruct, okDo := classifyOnceDoCallback(p, idx, lit, descFamily); okDo {
				if recvStruct != nil {
					receiverOnceDoBlocks[lit.Body] = recvStruct
				}
				return true
			}
			if innerBody, okMemo := isMemoizedOnceGetterClosure(p, idx, lit); okMemo {
				memoOnceDoBlocks[innerBody] = true
				allowedBuildLitBlocks[lit.Body] = true
				allowedBuildLitBlocks[innerBody] = true
				return true
			}
			if isPureSortSliceComparator(p, idx, lit) || isSyncPoolNewConstructor(p, idx, lit) {
				return true
			}
			litOK = false
			return false
		})
		if !litOK {
			return nil, nil, nil, false
		}
	}

	// Compute initCone (functions reachable ONLY from init()) and buildAndLazyCone
	// (functions reachable ONLY from {init(), Build(), fileOnceFn}).
	var initFDs []*ast.FuncDecl
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Recv == nil && fd.Name.Name == "init" && fd.Body != nil {
				initFDs = append(initFDs, fd)
			}
		}
	}
	initConeFDs := computeExclusiveConeFromRoots(p, idx, initFDs, nil, nil)
	rootFuncs := map[*types.Func]bool{buildFn: true, fileOnceFn: true}
	initAndBuildConeFDs := computeExclusiveConeFromRoots(p, idx, initFDs, rootFuncs, allowedBuildLitBlocks)

	// Gate 2: Package-scope variables in p.Types must belong to closed categories:
	//   - Unexported sync.Pool accessed solely via .Get() / .Put(), OR
	//   - Mutated ONLY inside initConeFDs (or unmutated), never reassigned/mutated/addr-taken post-init.
	// Cross-package globals in p.Syntax must be read-only (or &descopts.<X> passed to a non-writing parameter).
	initOnlyRefGlobals := map[*types.Var]bool{}
	for _, name := range p.Types.Scope().Names() {
		v, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || v == nil {
			continue
		}
		if isNamedInPkg(v.Type(), "sync", "Pool") {
			if v.Exported() || !verifySyncPoolGlobalUses(p, idx, v) {
				return nil, nil, nil, false
			}
			continue
		}
		for _, uid := range idx.usesOf[v] {
			enclFD := idx.syncEnclFuncDecl(uid)
			if initConeFDs[enclFD] {
				continue
			}
			if identIsWrittenOrAddrTaken(idx, uid) {
				return nil, nil, nil, false
			}
			par := idx.parentUnparen(uid)
			if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid && identOrExprIsWritten(idx, ix) {
				return nil, nil, nil, false
			}
			if cid, isCall := par.(*ast.CallExpr); isCall && len(cid.Args) > 0 && ast.Unparen(cid.Args[0]) == uid {
				if fnID, isID := ast.Unparen(cid.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[fnID].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") {
						return nil, nil, nil, false
					}
				}
			}
		}
		if TypeCarriesMutableRef(v.Type()) {
			initOnlyRefGlobals[v] = true
		}
	}
	// Verify cross-package global references across p.Syntax: never mutated; &pkg.Var allowed ONLY when passed to an intra-package parameter whose pointee *param is never written!
	for _, file := range p.Syntax {
		extOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !extOK || n == nil {
				return false
			}
			id, isID := n.(*ast.Ident)
			if !isID {
				return true
			}
			v, isVar := p.TypesInfo.Uses[id].(*types.Var)
			if !isVar || v == nil || v.IsField() || v.Pkg() == nil || v.Pkg() == p.Types || v.Parent() != v.Pkg().Scope() {
				return true
			}
			sel, isSel := idx.parentUnparen(id).(*ast.SelectorExpr)
			if !isSel || sel.Sel != id {
				return true
			}
			if identOrExprIsWritten(idx, sel) {
				extOK = false
				return false
			}
			if un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				if !isReadOnlyPtrCallArg(p, idx, un) {
					extOK = false
					return false
				}
			}
			return true
		})
		if !extOK {
			return nil, nil, nil, false
		}
	}

	// Gate 3: Check File.mu and File.once discipline across p.Syntax, and collect
	// optional unexported-receiver scalar setter methods (e.g. (*stringName).InitJSON).
	fileOnceFD := idx.funcDecls[fileOnceFn]
	exempt := map[ast.Node]bool{}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for _, uid := range idx.usesOf[fileMuField] {
		if !idx.isSyncInFuncDecl(uid, fileOnceFD) {
			return nil, nil, nil, false
		}
	}
	for _, uid := range idx.usesOf[fileOnceField] {
		sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return nil, nil, nil, false
		}
		if idx.isSyncInFuncDecl(uid, fileOnceFD) {
			if un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				exempt[un] = true
			}
			continue
		}
		un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND || !isPureAtomicLoadArg(p, idx, un) {
			return nil, nil, nil, false
		}
		exempt[un] = true
	}

	unexportedScalarSetterFDs := map[*ast.FuncDecl]*types.Named{}
	for famSt := range descFamily {
		if famSt.Obj().Exported() {
			continue
		}
		pset := types.NewMethodSet(types.NewPointer(famSt))
		for i := 0; i < pset.Len(); i++ {
			mfn, okM := pset.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types || !mfn.Exported() {
				continue
			}
			mfd := idx.funcDecls[mfn]
			if mfd == nil || mfd.Body == nil {
				continue
			}
			if isPureReceiverScalarSetter(p, idx, mfd, famSt) {
				allCallsInBuild := true
				for _, cid := range idx.usesOf[mfn] {
					encl := idx.syncEnclFuncDecl(cid)
					if !initAndBuildConeFDs[encl] {
						allCallsInBuild = false
						break
					}
				}
				if allCallsInBuild {
					unexportedScalarSetterFDs[mfd] = famSt
				}
			}
		}
	}

	for fd := range initAndBuildConeFDs {
		if fd != nil && fd.Body != nil && bodyMutatesAnyNonInitGlobal(p, fd.Body, initConeFDs[fd], mutatedVars) {
			return nil, nil, nil, false
		}
		for famSt := range descFamily {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
	}
	for fd, famSt := range unexportedScalarSetterFDs {
		addExemptStructInFunc(exemptByFunc, fd, famSt)
	}

	// Gate 4: Every mutation or address-take on descFamily outside initAndBuildConeFDs
	// and unexportedScalarSetterFDs must either root at a fresh local OR lie synchronously
	// inside a receiver once.Do block mutating only that receiver struct (or memoOnceDoBlocks
	// inside initAndBuildConeFDs), or be a read-only &recv.<SubListField> / &recv.List[i] getter!
	enclosingOnceBlock := func(n ast.Node) (*ast.BlockStmt, *types.Named, bool) {
		cur := n
		for cur != nil {
			if blk, isBlk := cur.(*ast.BlockStmt); isBlk {
				if recvSt, okR := receiverOnceDoBlocks[blk]; okR {
					return blk, recvSt, false
				}
				if memoOnceDoBlocks[blk] {
					// Check that the enclosing FuncDecl of this memoOnceDoBlock is in initAndBuildConeFDs.
					c2 := idx.parentMap[blk]
					for c2 != nil {
						if fd, isFD := c2.(*ast.FuncDecl); isFD {
							return blk, nil, initAndBuildConeFDs[fd]
						}
						c2 = idx.parentMap[c2]
					}
					return nil, nil, false
				}
			}
			if _, isLit := cur.(*ast.FuncLit); isLit {
				// Crossed a non-once FuncLit (e.g. sort.Slice comparator).
				return nil, nil, false
			}
			cur = idx.parentMap[cur]
		}
		return nil, nil, false
	}

	isAllowedDescAddrTake := func(un *ast.UnaryExpr) bool {
		if exempt[un] {
			return true
		}
		inner := ast.Unparen(un.X)
		switch in := inner.(type) {
		case *ast.CompositeLit:
			if litSt := derefNamedStruct(p.TypesInfo.TypeOf(in)); litSt != nil && descFamily[litSt] {
				return true
			}
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[in]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false
			}
			ft := types.Unalias(selInfo.Type())
			if fn, isN := ft.(*types.Named); isN && (descFamily[fn] || immutableSlicePtrTypes[fn]) {
				return true
			}
		case *ast.IndexExpr:
			if elemN := derefNamedStruct(p.TypesInfo.TypeOf(in)); elemN != nil && descFamily[elemN] {
				return true
			}
		}
		return false
	}

	pf := computePackageFreshConstructors(p, idx)

	checkDescMutExpr := func(stmtNode ast.Node, expr ast.Expr) bool {
		if !touchesAnyNamedStruct(p, expr, descFamily) {
			return true
		}
		syncFD := idx.syncEnclFuncDecl(stmtNode)
		if syncFD != nil {
			if initAndBuildConeFDs[syncFD] {
				exempt[stmtNode] = true
				return true
			}
			if setterSt, okS := unexportedScalarSetterFDs[syncFD]; okS && touchesAnyNamedStruct(p, expr, map[*types.Named]bool{setterSt: true}) {
				exempt[stmtNode] = true
				return true
			}
			if pf.isFreshMutationTarget(syncFD, expr) {
				exempt[stmtNode] = true
				return true
			}
		}
		_, recvSt, isMemoBuild := enclosingOnceBlock(stmtNode)
		if isMemoBuild {
			exempt[stmtNode] = true
			return true
		}
		if recvSt != nil {
			// Must mutate receiver recvSt (or SourceLocations.List[i].Next inside SourceLocations.lazyInit).
			if touchesAnyNamedStruct(p, expr, map[*types.Named]bool{recvSt: true}) {
				exempt[stmtNode] = true
				return true
			}
		}
		return false
	}

	for _, file := range p.Syntax {
		mutOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !mutOK || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if !checkDescMutExpr(x, lhs) {
						mutOK = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if !checkDescMutExpr(x, x.X) {
					mutOK = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkDescMutExpr(x, x.Key)) || (x.Value != nil && !checkDescMutExpr(x, x.Value)) {
						mutOK = false
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && touchesAnyNamedStruct(p, x.X, descFamily) {
					syncFD := idx.syncEnclFuncDecl(x)
					if syncFD != nil {
						if initAndBuildConeFDs[syncFD] {
							exempt[x] = true
							return true
						}
						if pf.isFreshAddrOrValue(syncFD, x.X) {
							exempt[x] = true
							return true
						}
					}
					_, recvSt, isMemoBuild := enclosingOnceBlock(x)
					if isMemoBuild || recvSt != nil {
						exempt[x] = true
						return true
					}
					if isAllowedDescAddrTake(x) {
						exempt[x] = true
						return true
					}
					mutOK = false
					return false
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkDescMutExpr(x, x.Args[0]) {
								mutOK = false
								return false
							}
						}
					}
				}
			}
			return true
		})
		if !mutOK {
			return nil, nil, nil, false
		}
	}

	// Gate 5: Read-only confinement on post-init package globals (defaultsCache, defaultsKeys,
	// Surrogate*, empty*) and on unexported slice/map fields of descFamily outside exempted cones!
	snapshotGuardedFields := collectSnapshotGuardedValueFields(p, idx, descFamily, extraGuards, initAndBuildConeFDs, pf)

	// Walk all non-snapshot-guarded fields of descFamily recursively (including fields of
	// cross-package structs like protoreflect.FileImport / SourceLocation and named slices/maps
	// like protoreflect.SourcePath) so any tampered non-snapshot field carrying unsafe.Pointer
	// fails closed and nested cross-package struct/container types enter GuardTypes.
	nonSnapshotExtraGuards := map[TypeRef]bool{}
	seenNonSnap := map[types.Type]bool{}
	nonSnapValid := true
	var walkNonSnapshotType func(t types.Type)
	walkNonSnapshotType = func(t types.Type) {
		if t == nil || !nonSnapValid {
			return
		}
		t = types.Unalias(t)
		if isNamedInPkg(t, "sync", "Mutex") || isNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed || descFamily[n] || immutableSlicePtrTypes[n] {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg() != p.Types {
				switch subU := n.Underlying().(type) {
				case *types.Struct:
					if subU.NumFields() > 0 {
						ref := TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
						if !ref.Valid() {
							nonSnapValid = false
							return
						}
						nonSnapshotExtraGuards[ref] = true
					}
				case *types.Slice, *types.Map:
					ref := TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
					if !ref.Valid() {
						nonSnapValid = false
						return
					}
					nonSnapshotExtraGuards[ref] = true
				}
			}
		}
		if seenNonSnap[t] {
			return
		}
		seenNonSnap[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				nonSnapValid = false
			}
		case *types.Chan, *types.TypeParam:
			nonSnapValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			en, isEN := types.Unalias(u.Elem()).(*types.Named)
			if !isEN || (!descFamily[en] && !immutableSlicePtrTypes[en]) {
				nonSnapValid = false
				return
			}
		case *types.Slice:
			walkNonSnapshotType(u.Elem())
		case *types.Array:
			walkNonSnapshotType(u.Elem())
		case *types.Map:
			walkNonSnapshotType(u.Key())
			walkNonSnapshotType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkNonSnapshotType(u.Field(i).Type())
			}
		}
	}
	for famSt := range descFamily {
		if stN, okS := famSt.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				f := stN.Field(i)
				if snapshotGuardedFields[f] {
					continue
				}
				walkNonSnapshotType(f.Type())
			}
		}
	}
	if !nonSnapValid {
		return nil, nil, nil, false
	}

	isImmPtr := func(t types.Type) bool {
		ptr, okP := types.Unalias(t).(*types.Pointer)
		if !okP {
			return false
		}
		en, okN := types.Unalias(ptr.Elem()).(*types.Named)
		return okN && (descFamily[en] || immutableSlicePtrTypes[en])
	}
	immutableIfaceFields := collectImmutableIfaceFields(p, idx, descFamily, isImmPtr)
	if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			sel, isSel := ast.Unparen(containerExpr).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			fv, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
			return fv != nil && immutableIfaceFields[fv]
		},
		AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
			if callee == nil || call.Ellipsis.IsValid() {
				return false
			}
			orig := callee.Origin()
			sig, okSig := orig.Type().(*types.Signature)
			if !okSig || sig.Recv() == nil {
				return false
			}
			recvT := types.Unalias(sig.Recv().Type())
			if _, isPtr := recvT.(*types.Pointer); isPtr {
				return false
			}
			rn, isRN := recvT.(*types.Named)
			if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
				return false
			}
			if _, isSl := rn.Underlying().(*types.Slice); !isSl {
				return false
			}
			sliceRef := TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
			if !nonSnapshotExtraGuards[sliceRef] {
				return false
			}
			for _, a := range call.Args {
				if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(a)) {
					return false
				}
			}
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if TypeContainsRefOrPointer(sig.Results().At(ri).Type()) {
					return false
				}
			}
			return true
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			if id, isID := ast.Unparen(expr).(*ast.Ident); isID {
				if v, isV := p.TypesInfo.Uses[id].(*types.Var); isV && initOnlyRefGlobals[v] {
					if initConeFDs[idx.syncEnclFuncDecl(id)] {
						return false, false
					}
					ft := v.Type()
					if IsDirectMutableRefWith(ft, isImmPtr) {
						return true, true
					}
					if TypeCarriesMutableRefWith(ft, isImmPtr) {
						return false, true
					}
				}
				return false, false
			}
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || selInfo.Obj().Exported() {
				return false, false
			}
			if fv, isFV := selInfo.Obj().(*types.Var); isFV && snapshotGuardedFields[fv] {
				return false, false
			}
			if isInsideExemptWriteOrAddr(idx, sel, exempt) {
				return false, false
			}
			syncFD := idx.syncEnclFuncDecl(sel)
			if syncFD != nil && (initAndBuildConeFDs[syncFD] || unexportedScalarSetterFDs[syncFD] != nil || pf.isFreshAddrOrValue(syncFD, sel) || pf.isFreshMutationTarget(syncFD, sel)) {
				return false, false
			}
			if _, recvSt, isMemoBuild := enclosingOnceBlock(sel); isMemoBuild || recvSt != nil {
				return false, false
			}
			hit := false
			forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if descFamily[hop] {
					hit = true
				}
			})
			if !hit {
				return false, false
			}
			ft := selInfo.Type()
			if IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
			callee := resolveCalledFuncObj(p, call.Fun)
			return callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "bytes" && callee.Name() == "Equal"
		},
	}) {
		return nil, nil, nil, false
	}

	guardMap := map[TypeRef]bool{}
	for famSt := range descFamily {
		ref := TypeRef{Pkg: p.Types.Path(), Name: famSt.Obj().Name()}
		if !ref.Valid() {
			return nil, nil, nil, false
		}
		guardMap[ref] = true
	}
	for g := range nonSnapshotExtraGuards {
		guardMap[g] = true
	}
	guardTypes := make([]TypeRef, 0, len(guardMap))
	for g := range guardMap {
		guardTypes = append(guardTypes, g)
	}
	sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].key() < guardTypes[j].key() })
	if exemptReadFields != nil {
		memo := map[*types.Named]bool{}
		visiting := map[*types.Named]bool{}
		for famSt := range descFamily {
			st, okS := famSt.Underlying().(*types.Struct)
			if !okS {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				if f.Exported() && isDescFamilyReadConfinedType(f.Type(), descFamily, memo, visiting) {
					exemptReadFields[f] = true
				}
			}
		}
	}
	return exempt, exemptByFunc, guardTypes, true
}

func isDescFamilyReadConfinedType(
	t types.Type,
	descFamily map[*types.Named]bool,
	memo map[*types.Named]bool,
	visiting map[*types.Named]bool,
) bool {
	if t == nil {
		return false
	}
	named, isN := types.Unalias(t).(*types.Named)
	if !isN || !descFamily[named] || named.Obj() == nil {
		return false
	}
	if res, ok := memo[named]; ok {
		return res
	}
	if visiting[named] {
		return false
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		memo[named] = false
		return false
	}
	visiting[named] = true
	defer delete(visiting, named)
	for i := 0; i < st.NumFields(); i++ {
		sf := st.Field(i)
		if !TypeCarriesMutableRef(sf.Type()) {
			continue
		}
		if !sf.Exported() && !sf.Embedded() {
			continue
		}
		if !isDescFamilyReadConfinedType(sf.Type(), descFamily, memo, visiting) {
			memo[named] = false
			return false
		}
	}
	memo[named] = true
	return true
}

func isZeroSizedStatelessField(f *types.Var) bool {
	if f == nil {
		return false
	}
	t := f.Type()
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		if u.NumFields() != 0 {
			return false
		}
	case *types.Array:
		if u.Len() != 0 {
			return false
		}
	default:
		return false
	}
	return types.NewMethodSet(types.NewPointer(t)).Len() == 0
}

func collectImmutableIfaceFields(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	descFamily map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) map[*types.Var]bool {
	cand := map[*types.Var]bool{}
	fieldOwner := map[*types.Var]*types.Named{}
	for ownerNamed := range descFamily {
		st, ok := ownerNamed.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			var elemT types.Type
			switch u := types.Unalias(f.Type()).Underlying().(type) {
			case *types.Slice:
				elemT = u.Elem()
			case *types.Map:
				elemT = u.Elem()
			}
			if elemT == nil {
				continue
			}
			if iface, okI := types.Unalias(elemT).Underlying().(*types.Interface); okI && iface.NumMethods() > 0 {
				cand[f] = true
				fieldOwner[f] = ownerNamed
			}
		}
	}
	if len(cand) == 0 {
		return nil
	}

	unkeyedOwners := map[*types.Named]bool{}
	rangeValField := map[*types.Var]*types.Var{}
	writtenVars := map[*types.Var]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.CompositeLit:
				if len(s.Elts) > 0 {
					if named, isN := types.Unalias(p.TypesInfo.TypeOf(s)).(*types.Named); isN && descFamily[named] {
						for _, elt := range s.Elts {
							if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
								unkeyedOwners[named] = true
								break
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok != token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
						if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
							writtenVars[v] = true
						}
					}
				}
			case *ast.RangeStmt:
				if s.Tok == token.DEFINE && s.Value != nil {
					if vid, isID := ast.Unparen(s.Value).(*ast.Ident); isID {
						if vv, _ := p.TypesInfo.Defs[vid].(*types.Var); vv != nil && idx.defCounts[vv] == 1 {
							if xSel, isSel := ast.Unparen(s.X).(*ast.SelectorExpr); isSel {
								if sf, _ := p.TypesInfo.Uses[xSel.Sel].(*types.Var); sf != nil && cand[sf] {
									rangeValField[vv] = sf
								}
							}
						}
					}
				} else if s.Tok == token.ASSIGN {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if id, isID := ast.Unparen(e).(*ast.Ident); isID && id != nil {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	for v := range writtenVars {
		delete(rangeValField, v)
	}
	for f, owner := range fieldOwner {
		if unkeyedOwners[owner] {
			delete(cand, f)
		}
	}

	isMakeCall := func(e ast.Expr) bool {
		c, isC := ast.Unparen(e).(*ast.CallExpr)
		if !isC || len(c.Args) == 0 {
			return false
		}
		id, isID := ast.Unparen(c.Fun).(*ast.Ident)
		if !isID {
			return false
		}
		b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
		return isB && b.Name() == "make"
	}
	validElem := func(e ast.Expr) bool {
		e = ast.Unparen(e)
		if e == nil {
			return false
		}
		if isImmPtr(p.TypesInfo.TypeOf(e)) {
			return true
		}
		if id, isID := e.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
				if srcF := rangeValField[v]; srcF != nil && cand[srcF] {
					return true
				}
			}
		}
		return false
	}

	changed := true
	for changed {
		changed = false
		for f := range cand {
			okField := true
			for _, uid := range idx.usesOf[f] {
				if kv, isKV := idx.parentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
					rhs := ast.Unparen(kv.Value)
					if isNilIdent(p, rhs) || isMakeCall(rhs) {
						continue
					}
					if cl, isCL := rhs.(*ast.CompositeLit); isCL {
						for _, elt := range cl.Elts {
							val := elt
							if ekv, isEKV := elt.(*ast.KeyValueExpr); isEKV {
								val = ekv.Value
							}
							if !validElem(val) {
								okField = false
								break
							}
						}
						if okField {
							continue
						}
					}
					okField = false
					break
				}
				sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid {
					okField = false
					break
				}
				par := idx.parentUnparen(sel)
				if un, isUn := par.(*ast.UnaryExpr); isUn && un.Op == token.AND {
					okField = false
					break
				}
				if _, isSl := par.(*ast.SliceExpr); isSl {
					okField = false
					break
				}
				if call, isCall := par.(*ast.CallExpr); isCall && len(call.Args) >= 1 && ast.Unparen(call.Args[0]) == sel {
					if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
						if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && (b.Name() == "copy" || b.Name() == "delete" || b.Name() == "clear") {
							okField = false
							break
						}
					}
				}
				if identOrExprIsWritten(idx, sel) {
					as, isAs := par.(*ast.AssignStmt)
					if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
						okField = false
						break
					}
					rhs := ast.Unparen(as.Rhs[0])
					if isNilIdent(p, rhs) || isMakeCall(rhs) {
						continue
					}
					apCall, isAC := rhs.(*ast.CallExpr)
					if !isAC || len(apCall.Args) < 2 || apCall.Ellipsis.IsValid() {
						okField = false
						break
					}
					apID, isID := ast.Unparen(apCall.Fun).(*ast.Ident)
					if !isID {
						okField = false
						break
					}
					if b, isB := p.TypesInfo.Uses[apID].(*types.Builtin); !isB || b.Name() != "append" || !sameFieldTargetExpr(p, sel, apCall.Args[0]) {
						okField = false
						break
					}
					for _, arg := range apCall.Args[1:] {
						if !validElem(arg) {
							okField = false
							break
						}
					}
					if !okField {
						break
					}
					continue
				}
				if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == sel {
					ixPar := idx.parentUnparen(ix)
					if un, isUn := ixPar.(*ast.UnaryExpr); isUn && un.Op == token.AND {
						okField = false
						break
					}
					if identOrExprIsWritten(idx, ix) {
						as, isAs := ixPar.(*ast.AssignStmt)
						if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != ix || !validElem(as.Rhs[0]) {
							okField = false
							break
						}
					}
					continue
				}
			}
			if !okField {
				delete(cand, f)
				changed = true
			}
		}
	}
	return cand
}

func collectSnapshotGuardedValueFields(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	descFamily map[*types.Named]bool,
	extraGuards map[TypeRef]bool,
	initAndBuildConeFDs map[*ast.FuncDecl]bool,
	pf *pkgFreshConstructors,
) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	unkeyedNamedLits := map[*types.Named]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			cl, isCL := n.(*ast.CompositeLit)
			if !isCL || len(cl.Elts) == 0 {
				return true
			}
			named, isN := types.Unalias(p.TypesInfo.TypeOf(cl)).(*types.Named)
			if !isN || !descFamily[named] {
				return true
			}
			for _, elt := range cl.Elts {
				if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
					unkeyedNamedLits[named] = true
					break
				}
			}
			return true
		})
	}
	for ownerNamed := range descFamily {
		if ownerNamed.Obj() == nil || ownerNamed.Obj().Exported() || unkeyedNamedLits[ownerNamed] {
			continue
		}
		ownerSt, ok := ownerNamed.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		snapFields := map[*types.Var]bool{}
		for i := 0; i < ownerSt.NumFields(); i++ {
			f := ownerSt.Field(i)
			if !f.Exported() && isByteSliceType(f.Type()) {
				snapFields[f] = true
			}
		}
		if len(snapFields) == 0 {
			continue
		}
		for i := 0; i < ownerSt.NumFields(); i++ {
			vf := ownerSt.Field(i)
			if vf.Exported() || snapFields[vf] {
				continue
			}
			extNamed, okN := types.Unalias(vf.Type()).(*types.Named)
			if !okN || extNamed.Obj() == nil || extNamed.Obj().Pkg() == nil || extNamed.Obj().Pkg() == p.Types {
				continue
			}
			extRef, _, extSt, okRef := typeRefOfStruct(extNamed)
			if !okRef || !extRef.Valid() || !extraGuards[extRef] {
				continue
			}
			allUnexported := true
			for j := 0; j < extSt.NumFields(); j++ {
				f := extSt.Field(j)
				if f.Exported() && !isZeroSizedStatelessField(f) {
					allUnexported = false
					break
				}
			}
			if !allUnexported {
				continue
			}
			if types.NewMethodSet(types.NewPointer(extNamed)).Len() != types.NewMethodSet(extNamed).Len() {
				continue
			}
			var getterFD *ast.FuncDecl
			var getterRecv *types.Var
			valid := true
			var getterUses []*ast.Ident
			type ctorKV struct {
				fd *ast.FuncDecl
				kv *ast.KeyValueExpr
			}
			var ctorKVs []ctorKV
			var coneUses []*ast.Ident
			for _, uid := range idx.usesOf[vf] {
				syncFD := idx.syncEnclFuncDecl(uid)
				if syncFD == nil {
					valid = false
					break
				}
				if kv, isKV := idx.parentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
					ctorKVs = append(ctorKVs, ctorKV{fd: syncFD, kv: kv})
					continue
				}
				if initAndBuildConeFDs[syncFD] {
					coneUses = append(coneUses, uid)
					continue
				}
				sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid || identOrExprIsWritten(idx, sel) {
					valid = false
					break
				}
				if un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					valid = false
					break
				}
				if getterFD == nil {
					if syncFD.Name == nil || syncFD.Name.IsExported() || syncFD.Recv == nil || len(syncFD.Recv.List) != 1 || len(syncFD.Recv.List[0].Names) != 1 || syncFD.Body == nil {
						valid = false
						break
					}
					rv, _ := p.TypesInfo.Defs[syncFD.Recv.List[0].Names[0]].(*types.Var)
					if rv == nil || !isPtrToNamed(rv.Type(), ownerNamed) {
						valid = false
						break
					}
					getterFD = syncFD
					getterRecv = rv
				} else if syncFD != getterFD {
					valid = false
					break
				}
				rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
				if !isRID || p.TypesInfo.Uses[rid] != getterRecv {
					valid = false
					break
				}
				getterUses = append(getterUses, uid)
			}
			if !valid || getterFD == nil {
				continue
			}
			sf, okGetter := isSnapshotGuardedValueGetter(p, getterFD, getterRecv, vf, snapFields, getterUses)
			if !okGetter || sf == nil {
				continue
			}
			ctorFuncs := map[*types.Func]bool{}
			for _, ck := range ctorKVs {
				if !verifySnapshotValueConstructor(p, idx, pf, ck.fd, ownerNamed, vf, sf, ck.kv) {
					valid = false
					break
				}
				if fn, _ := p.TypesInfo.Defs[ck.fd.Name].(*types.Func); fn != nil {
					ctorFuncs[fn] = true
				}
			}
			if !valid {
				continue
			}
			if !verifyConeSnapshotUses(p, idx, initAndBuildConeFDs, ownerNamed, vf, ctorFuncs, coneUses) {
				continue
			}
			out[vf] = true
		}
	}
	return out
}

func verifySnapshotValueConstructor(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	pf *pkgFreshConstructors,
	fd *ast.FuncDecl,
	ownerNamed *types.Named,
	vf, sf *types.Var,
	kv *ast.KeyValueExpr,
) bool {
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 3 || fd.Recv != nil {
		return false
	}
	fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
	sig, _ := p.TypesInfo.Defs[fd.Name].Type().(*types.Signature)
	if fn == nil || sig == nil || sig.Results().Len() != 1 || !types.Identical(types.Unalias(sig.Results().At(0).Type()), ownerNamed) {
		return false
	}
	paramSet := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		paramSet[sig.Params().At(i)] = true
	}
	valID, isVID := ast.Unparen(kv.Value).(*ast.Ident)
	if !isVID {
		return false
	}
	vParam, _ := p.TypesInfo.Uses[valID].(*types.Var)
	if vParam == nil || !paramSet[vParam] {
		return false
	}
	// Statement 0: dv := ownerNamed{..., vf: vParam, ...} (with sf omitted).
	defStmt, isDef := fd.Body.List[0].(*ast.AssignStmt)
	if !isDef || defStmt.Tok != token.DEFINE || len(defStmt.Lhs) != 1 || len(defStmt.Rhs) != 1 {
		return false
	}
	dvDefID, isDID := ast.Unparen(defStmt.Lhs[0]).(*ast.Ident)
	if !isDID {
		return false
	}
	dvVar, _ := p.TypesInfo.Defs[dvDefID].(*types.Var)
	if dvVar == nil {
		return false
	}
	cl, isCL := ast.Unparen(defStmt.Rhs[0]).(*ast.CompositeLit)
	if !isCL || idx.parentMap[kv] != cl {
		return false
	}
	for _, elt := range cl.Elts {
		ekv, okKV := elt.(*ast.KeyValueExpr)
		if !okKV {
			return false
		}
		if kid, okID := ast.Unparen(ekv.Key).(*ast.Ident); okID && p.TypesInfo.Uses[kid] == sf {
			return false
		}
	}
	// Statement 1: if b, ok := vParam.Interface().([]byte); ok { dv.<sf> = append([]byte(nil), b...) }
	ifStmt, isIf := fd.Body.List[1].(*ast.IfStmt)
	if !isIf || ifStmt.Init == nil || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	initAs, isIAs := ifStmt.Init.(*ast.AssignStmt)
	if !isIAs || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 2 || len(initAs.Rhs) != 1 {
		return false
	}
	bID, okB := ast.Unparen(initAs.Lhs[0]).(*ast.Ident)
	okID, okO := ast.Unparen(initAs.Lhs[1]).(*ast.Ident)
	if !okB || !okO {
		return false
	}
	bVar, _ := p.TypesInfo.Defs[bID].(*types.Var)
	okVar, _ := p.TypesInfo.Defs[okID].(*types.Var)
	if bVar == nil || okVar == nil || !isByteSliceType(bVar.Type()) {
		return false
	}
	ta, isTA := ast.Unparen(initAs.Rhs[0]).(*ast.TypeAssertExpr)
	if !isTA || ta.Type == nil || !isByteSliceType(p.TypesInfo.TypeOf(ta.Type)) {
		return false
	}
	ifaceCall, isIC := ast.Unparen(ta.X).(*ast.CallExpr)
	if !isIC || len(ifaceCall.Args) != 0 {
		return false
	}
	ifaceSel, isIS := ast.Unparen(ifaceCall.Fun).(*ast.SelectorExpr)
	if !isIS || ifaceSel.Sel.Name != "Interface" {
		return false
	}
	if xid, isXID := ast.Unparen(ifaceSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != vParam {
		return false
	}
	if cid, isCID := ast.Unparen(ifStmt.Cond).(*ast.Ident); !isCID || p.TypesInfo.Uses[cid] != okVar {
		return false
	}
	cpAs, isCAs := ifStmt.Body.List[0].(*ast.AssignStmt)
	if !isCAs || cpAs.Tok != token.ASSIGN || len(cpAs.Lhs) != 1 || len(cpAs.Rhs) != 1 {
		return false
	}
	lhsSel, isLS := ast.Unparen(cpAs.Lhs[0]).(*ast.SelectorExpr)
	if !isLS || p.TypesInfo.Uses[lhsSel.Sel] != sf || !pf.isFreshMutationTarget(fd, lhsSel) {
		return false
	}
	if xid, isXID := ast.Unparen(lhsSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != dvVar {
		return false
	}
	apCall, isAC := ast.Unparen(cpAs.Rhs[0]).(*ast.CallExpr)
	if !isAC || len(apCall.Args) != 2 || !apCall.Ellipsis.IsValid() {
		return false
	}
	apID, isAID := ast.Unparen(apCall.Fun).(*ast.Ident)
	if !isAID {
		return false
	}
	if b, isBuiltin := p.TypesInfo.Uses[apID].(*types.Builtin); !isBuiltin || b.Name() != "append" {
		return false
	}
	if !isTypedNilSliceConv(p, apCall.Args[0]) || !isByteSliceType(p.TypesInfo.TypeOf(apCall.Args[0])) {
		return false
	}
	if arg1ID, isA1 := ast.Unparen(apCall.Args[1]).(*ast.Ident); !isA1 || p.TypesInfo.Uses[arg1ID] != bVar {
		return false
	}
	// Statement 2: return dv
	retStmt, isRet := fd.Body.List[2].(*ast.ReturnStmt)
	if !isRet || len(retStmt.Results) != 1 {
		return false
	}
	retID, isRID := ast.Unparen(retStmt.Results[0]).(*ast.Ident)
	return isRID && p.TypesInfo.Uses[retID] == dvVar
}

func verifyConeSnapshotUses(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initAndBuildConeFDs map[*ast.FuncDecl]bool,
	ownerNamed *types.Named,
	vf *types.Var,
	ctorFuncs map[*types.Func]bool,
	coneUses []*ast.Ident,
) bool {
	// Compute snapshotProducingFuncs: verified ctorFuncs plus unexported cone helpers
	// whose every ReturnStmt returns a direct call to a snapshotProducingFuncs function.
	snapshotProducing := map[*types.Func]bool{}
	for fn := range ctorFuncs {
		snapshotProducing[fn] = true
	}
	changed := true
	for changed {
		changed = false
		for fd := range initAndBuildConeFDs {
			if fd == nil || fd.Name == nil || fd.Body == nil || fd.Recv != nil {
				continue
			}
			fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if fn == nil || fn.Exported() || snapshotProducing[fn] {
				continue
			}
			sig, _ := fn.Type().(*types.Signature)
			if sig == nil || sig.Results().Len() != 1 || !types.Identical(types.Unalias(sig.Results().At(0).Type()), ownerNamed) {
				continue
			}
			hasRet := false
			allSnapshot := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !allSnapshot || n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					allSnapshot = false
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				hasRet = true
				if len(ret.Results) != 1 {
					allSnapshot = false
					return false
				}
				rc, isRC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
				if !isRC {
					allSnapshot = false
					return false
				}
				callee := resolveCalledFuncObj(p, rc.Fun)
				if callee == nil || !snapshotProducing[callee] {
					allSnapshot = false
					return false
				}
				return true
			})
			if hasRet && allSnapshot {
				snapshotProducing[fn] = true
				changed = true
			}
		}
	}

	// Verify every direct write `<base>.<holderField> = <rhs>` across p.Syntax where `<holderField>` has type
	// `ownerNamed` occurs synchronously inside `initAndBuildConeFDs` and assigns a `snapshotProducing` call.
	for _, file := range p.Syntax {
		badHolderWrite := false
		ast.Inspect(file, func(n ast.Node) bool {
			if badHolderWrite || n == nil {
				return false
			}
			as, isAs := n.(*ast.AssignStmt)
			if !isAs {
				return true
			}
			for i, lhs := range as.Lhs {
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel {
					continue
				}
				hf, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
				if hf == nil || !hf.IsField() || !types.Identical(types.Unalias(hf.Type()), ownerNamed) {
					continue
				}
				syncFD := idx.syncEnclFuncDecl(as)
				if syncFD == nil || !initAndBuildConeFDs[syncFD] || len(as.Lhs) != len(as.Rhs) || i >= len(as.Rhs) {
					badHolderWrite = true
					return false
				}
				rc, isRC := ast.Unparen(as.Rhs[i]).(*ast.CallExpr)
				if !isRC {
					badHolderWrite = true
					return false
				}
				callee := resolveCalledFuncObj(p, rc.Fun)
				if callee == nil || !snapshotProducing[callee] {
					badHolderWrite = true
					return false
				}
			}
			return true
		})
		if badHolderWrite {
			return false
		}
	}
	if len(coneUses) == 0 {
		return true
	}

	writtenHolders := map[*types.Var]bool{}
	resolvedHolders := map[*types.Var]bool{}
	for _, uid := range coneUses {
		sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return false
		}
		if un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			return false
		}
		holderSel, isHS := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !isHS {
			return false
		}
		holderField, _ := p.TypesInfo.Uses[holderSel.Sel].(*types.Var)
		if holderField == nil || !holderField.IsField() || !types.Identical(types.Unalias(holderField.Type()), ownerNamed) {
			return false
		}
		par := idx.parentUnparen(sel)
		if as, isAs := par.(*ast.AssignStmt); isAs {
			if as.Tok == token.ASSIGN && len(as.Lhs) == 1 && ast.Unparen(as.Lhs[0]) == sel {
				writtenHolders[holderField] = true
				continue
			}
			// Resolution read: if v := <base>.<holderField>.<vf>; v.IsValid() { <base>.<holderField> = <snapshotProducingCall>(...) }
			if as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == sel {
				ifStmt, isIf := idx.parentMap[as].(*ast.IfStmt)
				if !isIf || ifStmt.Init != as || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) != 1 {
					return false
				}
				vID, okVID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
				if !okVID {
					return false
				}
				vVar, _ := p.TypesInfo.Defs[vID].(*types.Var)
				if vVar == nil {
					return false
				}
				condCall, isCC := ast.Unparen(ifStmt.Cond).(*ast.CallExpr)
				if !isCC || len(condCall.Args) != 0 {
					return false
				}
				condSel, isCS := ast.Unparen(condCall.Fun).(*ast.SelectorExpr)
				if !isCS || condSel.Sel.Name != "IsValid" {
					return false
				}
				if xid, isXID := ast.Unparen(condSel.X).(*ast.Ident); !isXID || p.TypesInfo.Uses[xid] != vVar {
					return false
				}
				resAs, isRAs := ifStmt.Body.List[0].(*ast.AssignStmt)
				if !isRAs || resAs.Tok != token.ASSIGN || len(resAs.Lhs) != 1 || len(resAs.Rhs) != 1 {
					return false
				}
				if !sameFieldTargetExpr(p, resAs.Lhs[0], holderSel) {
					return false
				}
				resCall, isRC := ast.Unparen(resAs.Rhs[0]).(*ast.CallExpr)
				if !isRC {
					return false
				}
				callee := resolveCalledFuncObj(p, resCall.Fun)
				if callee == nil || !snapshotProducing[callee] {
					return false
				}
				resolvedHolders[holderField] = true
				continue
			}
		}
		return false
	}
	for hf := range writtenHolders {
		if !resolvedHolders[hf] {
			return false
		}
	}
	return true
}

func isSnapshotGuardedValueGetter(
	p *packages.Package,
	fd *ast.FuncDecl,
	rv *types.Var,
	vf *types.Var,
	snapFields map[*types.Var]bool,
	getterUses []*ast.Ident,
) (*types.Var, bool) {
	stmts := fd.Body.List
	if len(stmts) < 2 || len(getterUses) != 2 {
		return nil, false
	}
	retStmt, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet || len(retStmt.Results) != 1 {
		return nil, false
	}
	retSel, isRS := ast.Unparen(retStmt.Results[0]).(*ast.SelectorExpr)
	if !isRS || p.TypesInfo.Uses[retSel.Sel] != vf {
		return nil, false
	}
	if rid, isID := ast.Unparen(retSel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	ifStmt, isIf := stmts[len(stmts)-2].(*ast.IfStmt)
	if !isIf || ifStmt.Init != nil || ifStmt.Else != nil || ifStmt.Body == nil || len(ifStmt.Body.List) == 0 {
		return nil, false
	}
	lastBodyStmt, isES := ifStmt.Body.List[len(ifStmt.Body.List)-1].(*ast.ExprStmt)
	if !isES {
		return nil, false
	}
	panicCall, isPC := ast.Unparen(lastBodyStmt.X).(*ast.CallExpr)
	if !isPC {
		return nil, false
	}
	pid, isPID := ast.Unparen(panicCall.Fun).(*ast.Ident)
	if !isPID {
		return nil, false
	}
	if pb, isB := p.TypesInfo.Uses[pid].(*types.Builtin); !isB || pb.Name() != "panic" {
		return nil, false
	}
	// Cond must be: len(rv.<sf>) > 0 && !bytes.Equal(rv.<sf>, rv.<vf>.Bytes())
	andExpr, isAnd := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
	if !isAnd || andExpr.Op != token.LAND {
		return nil, false
	}
	lenCmp, isCmp := ast.Unparen(andExpr.X).(*ast.BinaryExpr)
	if !isCmp || lenCmp.Op != token.GTR {
		return nil, false
	}
	if tv := p.TypesInfo.Types[lenCmp.Y]; tv.Value == nil {
		return nil, false
	} else if z, okZ := constant.Int64Val(tv.Value); !okZ || z != 0 {
		return nil, false
	}
	lenCall, isLC := ast.Unparen(lenCmp.X).(*ast.CallExpr)
	if !isLC || len(lenCall.Args) != 1 {
		return nil, false
	}
	lid, isLID := ast.Unparen(lenCall.Fun).(*ast.Ident)
	if !isLID {
		return nil, false
	}
	if lb, isB := p.TypesInfo.Uses[lid].(*types.Builtin); !isB || lb.Name() != "len" {
		return nil, false
	}
	snapSel1, isSS1 := ast.Unparen(lenCall.Args[0]).(*ast.SelectorExpr)
	if !isSS1 {
		return nil, false
	}
	sf, _ := p.TypesInfo.Uses[snapSel1.Sel].(*types.Var)
	if sf == nil || !snapFields[sf] {
		return nil, false
	}
	if rid, isID := ast.Unparen(snapSel1.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	notExpr, isNot := ast.Unparen(andExpr.Y).(*ast.UnaryExpr)
	if !isNot || notExpr.Op != token.NOT {
		return nil, false
	}
	eqCall, isEC := ast.Unparen(notExpr.X).(*ast.CallExpr)
	if !isEC || len(eqCall.Args) != 2 {
		return nil, false
	}
	eqFn := resolveCalledFuncObj(p, eqCall.Fun)
	if eqFn == nil || eqFn.Pkg() == nil || eqFn.Pkg().Path() != "bytes" || eqFn.Name() != "Equal" {
		return nil, false
	}
	isSnapExpr := func(e ast.Expr) bool {
		s, ok := ast.Unparen(e).(*ast.SelectorExpr)
		if !ok || p.TypesInfo.Uses[s.Sel] != sf {
			return false
		}
		r, okR := ast.Unparen(s.X).(*ast.Ident)
		return okR && p.TypesInfo.Uses[r] == rv
	}
	var bytesArg ast.Expr
	if isSnapExpr(eqCall.Args[0]) {
		bytesArg = eqCall.Args[1]
	} else if isSnapExpr(eqCall.Args[1]) {
		bytesArg = eqCall.Args[0]
	} else {
		return nil, false
	}
	bCall, isBC := ast.Unparen(bytesArg).(*ast.CallExpr)
	if !isBC || len(bCall.Args) != 0 || !isByteSliceType(p.TypesInfo.TypeOf(bCall)) {
		return nil, false
	}
	bSel, isBS := ast.Unparen(bCall.Fun).(*ast.SelectorExpr)
	if !isBS || bSel.Sel.Name != "Bytes" {
		return nil, false
	}
	valSel, isVS := ast.Unparen(bSel.X).(*ast.SelectorExpr)
	if !isVS || p.TypesInfo.Uses[valSel.Sel] != vf {
		return nil, false
	}
	if rid, isID := ast.Unparen(valSel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != rv {
		return nil, false
	}
	if (getterUses[0] == valSel.Sel && getterUses[1] == retSel.Sel) ||
		(getterUses[1] == valSel.Sel && getterUses[0] == retSel.Sel) {
		return sf, true
	}
	return nil, false
}

func structEmbedsUnexported(st *types.Struct, target *types.Named) bool {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() && !f.Exported() && types.Unalias(f.Type()) == target {
			return true
		}
	}
	return false
}

func isLockedOnceInitMethodAllowTailUnlock(
	p *packages.Package,
	fd *ast.FuncDecl,
	named *types.Named,
	muField, doneField *types.Var,
) bool {
	if isLockedOnceInitMethod(p, fd, named, muField, doneField) {
		return true
	}
	// Also admit straight-line tail Unlock (e.g. filedesc.(*File).lazyInitOnce):
	//   fd.mu.Lock()
	//   if fd.L2 == nil { ...; atomic.StoreUint32(&fd.once, 1) }
	//   fd.mu.Unlock()
	stmts := fd.Body.List
	if len(stmts) < 3 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	recvVar, ok := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || recvVar == nil || !isPtrToNamed(recvVar.Type(), named) {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[0], recvVar, muField, "Lock", false) || !isFieldMutexCallStmt(p, stmts[len(stmts)-1], recvVar, muField, "Unlock", false) {
		return false
	}
	for _, mid := range stmts[1 : len(stmts)-1] {
		bad := false
		ast.Inspect(mid, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt, *ast.DeferStmt:
				bad = true
				return false
			case *ast.ExprStmt:
				if isFieldMutexCallStmt(p, x, recvVar, muField, "Unlock", false) || isFieldMutexCallStmt(p, x, recvVar, muField, "Lock", false) {
					bad = true
					return false
				}
			}
			return true
		})
		if bad {
			return false
		}
	}
	sawAtomicStore := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if sawAtomicStore || n == nil {
			return false
		}
		call, okC := n.(*ast.CallExpr)
		if !okC || len(call.Args) != 2 {
			return true
		}
		if isAtomicUint32Call(p, call, "StoreUint32") && isAddrOfRecvField(p, call.Args[0], recvVar, doneField) {
			if tv := p.TypesInfo.Types[call.Args[1]]; tv.Value != nil {
				if v, okI := constant.Uint64Val(tv.Value); okI && v > 0 {
					sawAtomicStore = true
					return false
				}
			}
		}
		return true
	})
	return sawAtomicStore
}

func computeExclusiveConeFromRoots(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	initFDs []*ast.FuncDecl,
	extraRootFuncs map[*types.Func]bool,
	allowedLitBlocks map[*ast.BlockStmt]bool,
) map[*ast.FuncDecl]bool {
	enclosingConeFD := func(n ast.Node) *ast.FuncDecl {
		if len(allowedLitBlocks) == 0 {
			return idx.syncEnclFuncDecl(n)
		}
		for cur := idx.parentMap[n]; cur != nil; cur = idx.parentMap[cur] {
			switch x := cur.(type) {
			case *ast.GoStmt:
				return nil
			case *ast.FuncLit:
				if !allowedLitBlocks[x.Body] {
					return nil
				}
			case *ast.FuncDecl:
				return x
			}
		}
		return nil
	}

	forwardReach := func(allowed map[*types.Func]bool) (map[*ast.FuncDecl]bool, map[*types.Func]bool) {
		reachFDs := map[*ast.FuncDecl]bool{}
		reachFuncs := map[*types.Func]bool{}
		var queue []*ast.FuncDecl
		for _, fd := range initFDs {
			if fd != nil && fd.Body != nil && !reachFDs[fd] {
				reachFDs[fd] = true
				queue = append(queue, fd)
			}
		}
		for fn := range extraRootFuncs {
			if fd := idx.funcDecls[fn]; fd != nil && fd.Body != nil {
				reachFuncs[fn] = true
				if !reachFDs[fd] {
					reachFDs[fd] = true
					queue = append(queue, fd)
				}
			}
		}
		for len(queue) > 0 {
			fd := queue[0]
			queue = queue[1:]
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				switch x := n.(type) {
				case *ast.GoStmt:
					return false
				case *ast.FuncLit:
					return allowedLitBlocks[x.Body]
				case *ast.CallExpr:
					callee := resolveCalledFuncObj(p, x.Fun)
					if callee == nil {
						return true
					}
					callee = callee.Origin()
					if callee.Pkg() == p.Types && !callee.Exported() && callee.Name() != "init" &&
						(allowed == nil || allowed[callee]) && !reachFuncs[callee] {
						if cfd := idx.funcDecls[callee]; cfd != nil && cfd.Body != nil {
							reachFuncs[callee] = true
							if !reachFDs[cfd] {
								reachFDs[cfd] = true
								queue = append(queue, cfd)
							}
						}
					}
				}
				return true
			})
		}
		return reachFDs, reachFuncs
	}

	coneFDs, coneFuncs := forwardReach(nil)
	for {
		changed := false
		for fn := range coneFuncs {
			if extraRootFuncs[fn] {
				continue
			}
			uses := idx.usesOf[fn]
			if len(uses) == 0 {
				delete(coneFuncs, fn)
				delete(coneFDs, idx.funcDecls[fn])
				changed = true
				continue
			}
			allInside := true
			for _, uid := range uses {
				call := enclosingCallOfCalleeIdent(idx, uid)
				if call == nil {
					allInside = false
					break
				}
				encl := enclosingConeFD(call)
				if encl == nil || !coneFDs[encl] {
					allInside = false
					break
				}
			}
			if !allInside {
				delete(coneFuncs, fn)
				delete(coneFDs, idx.funcDecls[fn])
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	coneFDs, _ = forwardReach(coneFuncs)
	return coneFDs
}

func classifyOnceDoCallback(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	lit *ast.FuncLit,
	descFamily map[*types.Named]bool,
) (*types.Named, bool) {
	call, isCall := idx.parentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != lit {
		return nil, false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "Do" {
		return nil, false
	}
	fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "sync" || fn.Name() != "Do" {
		return nil, false
	}
	// Receiver sync.Once field: p.once.Do(func() { ... })
	onceSel, isOS := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !isOS || !isNamedInPkg(p.TypesInfo.TypeOf(onceSel), "sync", "Once") {
		return nil, false
	}
	rid, isRID := ast.Unparen(onceSel.X).(*ast.Ident)
	if !isRID {
		return nil, false
	}
	rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
	if rv == nil {
		return nil, false
	}
	recvSt := derefNamedStruct(rv.Type())
	if recvSt == nil || !descFamily[recvSt] {
		return nil, false
	}
	// Ensure enclosure is a method on *recvSt with receiver rv, and lit.Body mutates no globals or other outer vars.
	var enclFD *ast.FuncDecl
	for cur := idx.parentMap[call]; cur != nil; cur = idx.parentMap[cur] {
		if _, isInnerLit := cur.(*ast.FuncLit); isInnerLit {
			return nil, false
		}
		if fd, isFD := cur.(*ast.FuncDecl); isFD {
			enclFD = fd
			break
		}
	}
	if enclFD == nil || enclFD.Recv == nil || len(enclFD.Recv.List) != 1 || len(enclFD.Recv.List[0].Names) != 1 {
		return nil, false
	}
	if p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]] != rv {
		return nil, false
	}
	if bodyMutatesAnyPackageGlobal(p, lit.Body, nil) {
		return nil, false
	}
	return recvSt, true
}

func isMemoizedOnceGetterClosure(p *packages.Package, idx *pkgSyntaxIndex, lit *ast.FuncLit) (*ast.BlockStmt, bool) {
	if lit.Type.Params != nil && len(lit.Type.Params.List) > 0 {
		return nil, false
	}
	if lit.Type.Results == nil || len(lit.Type.Results.List) != 1 || lit.Body == nil || len(lit.Body.List) != 2 {
		return nil, false
	}
	exprStmt, isES := lit.Body.List[0].(*ast.ExprStmt)
	retStmt, isRet := lit.Body.List[1].(*ast.ReturnStmt)
	if !isES || !isRet || len(retStmt.Results) != 1 {
		return nil, false
	}
	doCall, isCall := ast.Unparen(exprStmt.X).(*ast.CallExpr)
	if !isCall || len(doCall.Args) != 1 {
		return nil, false
	}
	doSel, isSel := ast.Unparen(doCall.Fun).(*ast.SelectorExpr)
	if !isSel || doSel.Sel.Name != "Do" {
		return nil, false
	}
	doFn, isFn := p.TypesInfo.Uses[doSel.Sel].(*types.Func)
	if !isFn || doFn.Pkg() == nil || doFn.Pkg().Path() != "sync" || doFn.Name() != "Do" {
		return nil, false
	}
	onceID, isOID := ast.Unparen(doSel.X).(*ast.Ident)
	if !isOID {
		return nil, false
	}
	onceVar, _ := p.TypesInfo.Uses[onceID].(*types.Var)
	if onceVar == nil || onceVar.IsField() || onceVar.Parent() == p.Types.Scope() || !isNamedInPkg(onceVar.Type(), "sync", "Once") || idx.defCounts[onceVar] != 1 {
		return nil, false
	}
	innerLit, isIL := ast.Unparen(doCall.Args[0]).(*ast.FuncLit)
	if !isIL || innerLit.Body == nil {
		return nil, false
	}
	// Return expression must be either cachedVar or &cachedVar for a local cachedVar declared outside lit.
	retExpr := ast.Unparen(retStmt.Results[0])
	if un, isUn := retExpr.(*ast.UnaryExpr); isUn && un.Op == token.AND {
		retExpr = ast.Unparen(un.X)
	}
	cachedID, isCID := retExpr.(*ast.Ident)
	if !isCID {
		return nil, false
	}
	cachedVar, _ := p.TypesInfo.Uses[cachedID].(*types.Var)
	if cachedVar == nil || cachedVar.IsField() || cachedVar.Parent() == p.Types.Scope() || cachedVar.Pos() >= lit.Pos() {
		return nil, false
	}
	// Verify onceVar is used solely in once.Do(...), cachedVar is never mutated outside innerLit.Body,
	// and innerLit.Body mutates no outer variable (directly or via field/element/slice/map writes) other than cachedVar!
	for _, uid := range idx.usesOf[onceVar] {
		if uid != onceID {
			return nil, false
		}
	}
	for _, uid := range idx.usesOf[cachedVar] {
		if uid.Pos() < innerLit.Body.Pos() || uid.Pos() >= innerLit.Body.End() {
			if uid != cachedID {
				return nil, false
			}
		}
	}
	if bodyMutatesAnyPackageGlobal(p, innerLit.Body, nil) {
		return nil, false
	}
	innerDefs := map[*types.Var]bool{}
	ast.Inspect(innerLit.Body, func(n ast.Node) bool {
		if id, isID := n.(*ast.Ident); isID {
			if dv, isV := p.TypesInfo.Defs[id].(*types.Var); isV && dv != nil && dv != cachedVar {
				innerDefs[dv] = true
			}
		}
		return true
	})
	outerMutated := false
	ast.Inspect(innerLit.Body, func(n ast.Node) bool {
		if outerMutated || n == nil {
			return false
		}
		id, isID := n.(*ast.Ident)
		if !isID {
			return true
		}
		uv, isV := p.TypesInfo.Uses[id].(*types.Var)
		if !isV || uv == nil || uv.IsField() || uv == cachedVar || innerDefs[uv] {
			return true
		}
		if identReachesMutatedOrAddrPrefix(p, idx, id) {
			outerMutated = true
			return false
		}
		if bCall, isBC := idx.parentUnparen(id).(*ast.CallExpr); isBC && len(bCall.Args) > 0 && ast.Unparen(bCall.Args[0]) == id {
			if cid, isCID := ast.Unparen(bCall.Fun).(*ast.Ident); isCID {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						outerMutated = true
						return false
					}
				}
			}
		}
		return true
	})
	if outerMutated {
		return nil, false
	}
	return innerLit.Body, true
}

func isPureSortSliceComparator(p *packages.Package, idx *pkgSyntaxIndex, lit *ast.FuncLit) bool {
	call, isCall := idx.parentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 2 || ast.Unparen(call.Args[1]) != lit {
		return false
	}
	callee := resolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "sort" || callee.Name() != "Slice" {
		return false
	}
	return lit.Body != nil && !bodyHasAnyAssignment(p, lit.Body)
}

func isSyncPoolNewConstructor(p *packages.Package, idx *pkgSyntaxIndex, lit *ast.FuncLit) bool {
	kv, isKV := idx.parentUnparen(lit).(*ast.KeyValueExpr)
	if !isKV || ast.Unparen(kv.Value) != lit {
		return false
	}
	kid, isID := kv.Key.(*ast.Ident)
	if !isID || kid.Name != "New" {
		return false
	}
	cl, isCL := idx.parentUnparen(kv).(*ast.CompositeLit)
	if !isCL || !isNamedInPkg(p.TypesInfo.TypeOf(cl), "sync", "Pool") {
		return false
	}
	if lit.Body == nil || len(lit.Body.List) != 1 {
		return false
	}
	ret, isRet := lit.Body.List[0].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 {
		return false
	}
	nc, isNC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isNC || len(nc.Args) != 1 {
		return false
	}
	nid, isNID := ast.Unparen(nc.Fun).(*ast.Ident)
	if !isNID {
		return false
	}
	b, isB := p.TypesInfo.Uses[nid].(*types.Builtin)
	return isB && b.Name() == "new"
}

func bodyHasAnyAssignment(p *packages.Package, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt, *ast.GoStmt, *ast.DeferStmt:
			found = true
			return false
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				found = true
				return false
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

func verifySyncPoolGlobalUses(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	for _, uid := range idx.usesOf[v] {
		sel, isSel := idx.parentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || ast.Unparen(sel.X) != uid || (sel.Sel.Name != "Get" && sel.Sel.Name != "Put") {
			return false
		}
		call, isCall := idx.parentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel {
			return false
		}
	}
	_ = p
	return true
}

func isReadOnlyPtrCallArg(p *packages.Package, idx *pkgSyntaxIndex, un *ast.UnaryExpr) bool {
	call, isCall := idx.parentUnparen(un).(*ast.CallExpr)
	if !isCall {
		return false
	}
	argIdx := -1
	for i, a := range call.Args {
		if ast.Unparen(a) == un {
			argIdx = i
			break
		}
	}
	if argIdx < 0 {
		return false
	}
	callee := resolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() != p.Types {
		return false
	}
	fd := idx.funcDecls[callee.Origin()]
	sig, okSig := callee.Origin().Type().(*types.Signature)
	if fd == nil || fd.Body == nil || !okSig || sig.Variadic() || argIdx >= sig.Params().Len() {
		return false
	}
	pv := sig.Params().At(argIdx)
	for _, uid := range idx.usesOf[pv] {
		if identIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.parentUnparen(uid)
		if star, isStar := par.(*ast.StarExpr); isStar && ast.Unparen(star.X) == uid {
			if identOrExprIsWritten(idx, star) {
				return false
			}
		}
	}
	return true
}

func isPureReceiverScalarSetter(p *packages.Package, idx *pkgSyntaxIndex, fd *ast.FuncDecl, recvStruct *types.Named) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 || fd.Body == nil {
		return false
	}
	rv, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if rv == nil || !isPtrToNamed(rv.Type(), recvStruct) {
		return false
	}
	for _, stmt := range fd.Body.List {
		as, isAs := stmt.(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) {
			return false
		}
		for i, lhs := range as.Lhs {
			sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			rid, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID || p.TypesInfo.Uses[rid] != rv {
				return false
			}
			lt := p.TypesInfo.TypeOf(sel)
			if lt == nil || TypeContainsRefOrPointer(lt) {
				return false
			}
			// RHS must be a constant or scalar parameter with zero calls/FuncLits.
			rhs := ast.Unparen(as.Rhs[i])
			if p.TypesInfo.Types[rhs].Value != nil {
				continue
			}
			if pid, isPID := rhs.(*ast.Ident); isPID {
				if pv, isV := p.TypesInfo.Uses[pid].(*types.Var); isV && pv != nil && !pv.IsField() && pv.Parent() != p.Types.Scope() && !TypeContainsRefOrPointer(pv.Type()) {
					continue
				}
			}
			return false
		}
	}
	_ = idx
	return len(fd.Body.List) > 0
}

func bodyMutatesAnyNonInitGlobal(p *packages.Package, body *ast.BlockStmt, inInit bool, mutatedVars map[string]bool) bool {
	if inInit {
		return false
	}
	return bodyMutatesAnyPackageGlobal(p, body, mutatedVars)
}

func isReflectTypeOfCall(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "reflect" && fn.Name() == "TypeOf"
}

func verifyProtoStructFieldsAndCollectChildren(
	p *packages.Package,
	family map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedMsgRoots map[*types.Named]bool,
	allowExportedAnySlice bool,
) (map[*types.Named]bool, bool) {
	checkExportedFields := func(st *types.Struct, allowAnySlice bool) bool {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if !f.Exported() {
				continue
			}
			if _, isPtr := types.Unalias(f.Type()).(*types.Pointer); !isPtr {
				if subSt, isSt := types.Unalias(f.Type()).Underlying().(*types.Struct); isSt && subSt.NumFields() > 0 {
					return false
				}
			}
			if TypeCarriesMutableRef(f.Type()) && !(allowAnySlice && isAnySliceType(f.Type())) {
				return false
			}
		}
		return true
	}
	for famNamed := range family {
		st, ok := famNamed.Underlying().(*types.Struct)
		if !ok || !checkExportedFields(st, allowExportedAnySlice) {
			return nil, false
		}
	}

	childProtected := map[*types.Named]bool{}
	seen := map[types.Type]bool{}
	valid := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !valid {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if isNamedInPkg(t, "sync", "Mutex") {
			return
		}
		if n, isN := t.(*types.Named); isN && casHelperStructs[n] != nil {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface, *types.Signature:
			return
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				valid = false
			}
		case *types.Chan, *types.TypeParam:
			valid = false
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			elemNamed, isEN := elem.(*types.Named)
			if !isEN || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != p.Types {
				valid = false
				return
			}
			elemSt, isSt := elemNamed.Underlying().(*types.Struct)
			if !isSt {
				valid = false
				return
			}
			if family[elemNamed] || verifiedMsgRoots[elemNamed] {
				return
			}
			if elemNamed.Obj().Exported() || !checkExportedFields(elemSt, false) {
				valid = false
				return
			}
			childProtected[elemNamed] = true
			walk(elem)
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
	for famNamed := range family {
		if st, ok := famNamed.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				walk(st.Field(i).Type())
			}
		}
	}
	if !valid {
		return nil, false
	}
	return childProtected, true
}

func verifyProtoEnumType(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	st *types.Struct,
	builderExempt map[ast.Node]bool,
	verifiedMsgRoots map[*types.Named]bool,
) bool {
	if st.NumFields() == 0 {
		return false
	}
	family := map[*types.Named]bool{named: true}
	childProtected, okFields := verifyProtoStructFieldsAndCollectChildren(p, family, nil, verifiedMsgRoots, false)
	if !okFields || len(childProtected) > 0 {
		return false
	}
	allProtected := map[*types.Named]bool{named: true}
	if pkgHasAnyMutationOnStructs(p, idx, allProtected, builderExempt) {
		return false
	}
	isImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (allProtected[elem] || verifiedMsgRoots[elem])
	}
	return VerifyReadOnlyRefConfinement(p, RefConfineConfig{
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false, false
			}
			if isInsideExemptWriteOrAddr(idx, sel, builderExempt) {
				return false, false
			}
			hit := false
			forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if allProtected[hop] {
					hit = true
				}
			})
			if !hit {
				return false, false
			}
			ft := selInfo.Type()
			if IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && isReflectTypeOfCall(p, call)
		},
	})
}

func verifyProtoMessageType(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	verifiedMsgRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []TypeRef, []ConditionalStructMutation, bool) {
	muField, doneField := findUnexportedMutexAndUint32(st)
	if muField == nil || doneField == nil {
		return nil, nil, nil, nil, false
	}

	// Collect named and any unexported embedded structs declared in p.Types (e.g. reflectMessageInfo, coderMessageInfo).
	family := map[*types.Named]bool{named: true}
	var casHelperStructs map[*types.Named]*ast.FuncDecl
	var casNodesExempt map[ast.Node]bool
	var casGuardTypes []TypeRef
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() && !f.Exported() {
			if emb, ok := types.Unalias(f.Type()).(*types.Named); ok && emb.Obj() != nil && emb.Obj().Pkg() == p.Types {
				if embSt, isSt := emb.Underlying().(*types.Struct); isSt {
					family[emb] = true
					for j := 0; j < embSt.NumFields(); j++ {
						sf := embSt.Field(j)
						if sub, okSub := types.Unalias(sf.Type()).(*types.Named); okSub && sub.Obj() != nil && sub.Obj().Pkg() == p.Types {
							if fdCAS, exCAS, guardsCAS := verifyAtomicCASPointerStruct(p, idx, sub, named); fdCAS != nil {
								if casHelperStructs == nil {
									casHelperStructs = map[*types.Named]*ast.FuncDecl{}
								}
								if casNodesExempt == nil {
									casNodesExempt = map[ast.Node]bool{}
								}
								casHelperStructs[sub] = fdCAS
								for n := range exCAS {
									casNodesExempt[n] = true
								}
								casGuardTypes = append(casGuardTypes, guardsCAS...)
							}
						}
					}
				}
			}
		}
	}
	childProtected, okFields := verifyProtoStructFieldsAndCollectChildren(p, family, casHelperStructs, verifiedMsgRoots, true)
	if !okFields {
		return nil, nil, nil, nil, false
	}

	// Locate the unexported once-initialization method on *named (e.g. initOnce).
	var onceFn *types.Func
	pset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < pset.Len(); i++ {
		m, ok := pset.At(i).Obj().(*types.Func)
		if !ok || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		fd := idx.funcDecls[m]
		if fd != nil && fd.Body != nil && isLockedOnceInitMethod(p, fd, named, muField, doneField) {
			if onceFn != nil {
				return nil, nil, nil, nil, false
			}
			onceFn = m
		}
	}
	if onceFn == nil {
		return nil, nil, nil, nil, false
	}

	ownerRef := TypeRef{Pkg: p.Types.Path(), Name: named.Obj().Name()}
	onceCone := computeExclusiveHelperCone(p, idx, onceFn)
	coneGuards, coneConds, okCone := verifyOnceInitConeImmutability(p, idx, ownerRef, onceFn, family, childProtected, verifiedMsgRoots, mutatedVars, confinedCacheMaps)
	if !okCone {
		return nil, nil, nil, nil, false
	}
	exempt := map[ast.Node]bool{}
	for n := range casNodesExempt {
		exempt[n] = true
	}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for fn := range onceCone {
		fd := idx.funcDecls[fn]
		if fd == nil || fd.Body == nil {
			return nil, nil, nil, nil, false
		}
		if bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, nil, nil, false
		}
		for famSt := range family {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
		for chSt := range childProtected {
			addExemptStructInFunc(exemptByFunc, fd, chSt)
		}
	}
	for casSt, fdCAS := range casHelperStructs {
		addExemptStructInFunc(exemptByFunc, fdCAS, casSt)
	}

	// Verify every mutation, deref-write, or &field across ALL of p.Syntax on family and childProtected:
	// 1. Zero *x = ... whole-struct overwrites on family anywhere in p.Syntax (including inside onceCone!).
	// 2. Zero writes or &field on any EXPORTED field of family anywhere in p.Syntax
	//    (fresh local mi := &MessageInfo{...} composite literals use KeyValueExpr, not AssignStmt).
	// 3. Outside onceCone (and fresh local allocations mi := &MessageInfo{...}), zero writes to any
	//    unexported field of family/childProtected, and &field allowed ONLY for atomic.LoadUint32(&mi.doneField)
	//    or &mi.<unexportedByValueStructField> preceded by once-initialization (recorded in guardTypes).
	guardTypes, okDisc := verifyLockedStructFamilyDiscipline(p, idx, named, family, childProtected, casHelperStructs, verifiedMsgRoots, muField, doneField, onceFn, onceCone, nil, exempt, builderExempt)
	if !okDisc {
		return nil, nil, nil, nil, false
	}
	if len(casGuardTypes) > 0 || len(coneGuards) > 0 {
		gmap := make(map[TypeRef]bool, len(guardTypes)+len(casGuardTypes)+len(coneGuards))
		for _, g := range guardTypes {
			gmap[g] = true
		}
		for _, g := range casGuardTypes {
			gmap[g] = true
		}
		for _, g := range coneGuards {
			gmap[g] = true
		}
		guardTypes = make([]TypeRef, 0, len(gmap))
		for g := range gmap {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].key() < guardTypes[j].key() })
	}
	return exempt, exemptByFunc, guardTypes, coneConds, true
}

func verifyProtoExtensionType(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	builderExempt map[ast.Node]bool,
	builderHelperIdents map[*ast.Ident]bool,
	verifiedMsgRoots map[*types.Named]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, FuncKey, []TypeRef, []ConditionalStructMutation, bool) {
	muField, initField := findUnexportedMutexAndUint32(st)
	if muField == nil || initField == nil {
		return nil, nil, FuncKey{}, nil, nil, false
	}
	family := map[*types.Named]bool{named: true}
	childProtected, okFields := verifyProtoStructFieldsAndCollectChildren(p, family, nil, verifiedMsgRoots, false)
	if !okFields {
		return nil, nil, FuncKey{}, nil, nil, false
	}

	var onceFn *types.Func
	pset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < pset.Len(); i++ {
		m, ok := pset.At(i).Obj().(*types.Func)
		if !ok || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		fd := idx.funcDecls[m]
		if fd != nil && fd.Body != nil && isLockedOnceInitMethod(p, fd, named, muField, initField) {
			if onceFn != nil {
				return nil, nil, FuncKey{}, nil, nil, false
			}
			onceFn = m
		}
	}
	if onceFn == nil {
		return nil, nil, FuncKey{}, nil, nil, false
	}

	ownerRef := TypeRef{Pkg: p.Types.Path(), Name: named.Obj().Name()}
	onceCone := computeExclusiveHelperCone(p, idx, onceFn)
	coneGuards, coneConds, okCone := verifyOnceInitConeImmutability(p, idx, ownerRef, onceFn, family, childProtected, verifiedMsgRoots, mutatedVars, confinedCacheMaps)
	if !okCone {
		return nil, nil, FuncKey{}, nil, nil, false
	}

	// Allow optional exported builder-init function (e.g. InitExtensionInfo(xi *ExtensionInfo, ...))
	// that writes only unexported fields on its *ExtensionInfo parameter and is never called inside p.
	var builderInitFn *types.Func
	for fn, fd := range idx.funcDecls {
		if fn.Pkg() != p.Types || !fn.Exported() || fd.Recv != nil || fd.Body == nil {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Params().Len() < 1 || !isPtrToNamed(sig.Params().At(0).Type(), named) {
			continue
		}
		allUsesInBuilder := true
		for _, id := range idx.usesOf[fn] {
			if !builderHelperIdents[id] {
				allUsesInBuilder = false
				break
			}
		}
		if allUsesInBuilder && verifyExtensionBuilderInitFunc(p, fd, named) {
			if builderInitFn != nil {
				return nil, nil, FuncKey{}, nil, nil, false
			}
			builderInitFn = fn
		}
	}

	exempt := map[ast.Node]bool{}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for fn := range onceCone {
		fd := idx.funcDecls[fn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, FuncKey{}, nil, nil, false
		}
		for famSt := range family {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
		for chSt := range childProtected {
			addExemptStructInFunc(exemptByFunc, fd, chSt)
		}
	}
	var initHelper FuncKey
	if builderInitFn != nil {
		for famSt := range family {
			addExemptStructInFunc(exemptByFunc, idx.funcDecls[builderInitFn], famSt)
		}
		for chSt := range childProtected {
			addExemptStructInFunc(exemptByFunc, idx.funcDecls[builderInitFn], chSt)
		}
		initHelper = FuncKey{Pkg: p.Types.Path(), Name: builderInitFn.Name()}
	}

	guardTypes, okDisc := verifyLockedStructFamilyDiscipline(p, idx, named, family, childProtected, nil, verifiedMsgRoots, muField, initField, onceFn, onceCone, builderInitFn, exempt, builderExempt)
	if !okDisc {
		return nil, nil, FuncKey{}, nil, nil, false
	}
	if len(coneGuards) > 0 {
		gmap := make(map[TypeRef]bool, len(guardTypes)+len(coneGuards))
		for _, g := range guardTypes {
			gmap[g] = true
		}
		for _, g := range coneGuards {
			gmap[g] = true
		}
		guardTypes = make([]TypeRef, 0, len(gmap))
		for g := range gmap {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].key() < guardTypes[j].key() })
	}
	return exempt, exemptByFunc, initHelper, guardTypes, coneConds, true
}

func verifyExtensionBuilderInitFunc(p *packages.Package, fd *ast.FuncDecl, extNamed *types.Named) bool {
	if fd.Type == nil || fd.Type.Params == nil || len(fd.Type.Params.List) == 0 || len(fd.Type.Params.List[0].Names) == 0 {
		return false
	}
	if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
		return false
	}
	param0, _ := p.TypesInfo.Defs[fd.Type.Params.List[0].Names[0]].(*types.Var)
	if param0 == nil || !isPtrToNamed(param0.Type(), extNamed) {
		return false
	}
	ok := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !ok || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if id, isID := ast.Unparen(lhs).(*ast.Ident); isID && id.Name == "_" {
					continue
				}
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel || !isIdentUsingObj(p, sel.X, param0) {
					ok = false
					return false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal || !isPtrToNamed(selInfo.Recv(), extNamed) || selInfo.Obj().Exported() {
					ok = false
					return false
				}
			}
		case *ast.CallExpr, *ast.IncDecStmt, *ast.GoStmt, *ast.FuncLit:
			ok = false
			return false
		}
		return true
	})
	return ok
}

func findUnexportedMutexAndUint32(st *types.Struct) (muField, flagField *types.Var) {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() || f.Embedded() {
			continue
		}
		if isNamedInPkg(f.Type(), "sync", "Mutex") {
			if muField != nil {
				return nil, nil
			}
			muField = f
			continue
		}
		if b, ok := types.Unalias(f.Type()).Underlying().(*types.Basic); ok && b.Kind() == types.Uint32 {
			if flagField == nil {
				flagField = f
			}
		}
	}
	return muField, flagField
}

func isLockedOnceInitMethod(
	p *packages.Package,
	fd *ast.FuncDecl,
	recvNamed *types.Named,
	muField, flagField *types.Var,
) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	if fd.Type == nil || (fd.Type.Results != nil && len(fd.Type.Results.List) > 0) {
		return false
	}
	recvVar, ok := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || recvVar == nil || !isPtrToNamed(recvVar.Type(), recvNamed) {
		return false
	}
	stmts := fd.Body.List
	if len(stmts) < 4 {
		return false
	}
	// stmts[0]: recv.muField.Lock()
	// stmts[1]: defer recv.muField.Unlock()
	if !isFieldMutexCallStmt(p, stmts[0], recvVar, muField, "Lock", false) {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[1], recvVar, muField, "Unlock", true) {
		return false
	}
	// stmts[2]: if recv.flagField == <const> { return } (or != 0)
	guardIf, ok := stmts[2].(*ast.IfStmt)
	if !ok || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 {
		return false
	}
	if ret, isRet := guardIf.Body.List[0].(*ast.ReturnStmt); !isRet || len(ret.Results) != 0 {
		return false
	}
	if !exprMentionsFieldOnRecv(p, guardIf.Cond, recvVar, flagField) {
		return false
	}
	// Must contain atomic.StoreUint32(&recv.flagField, <non-zero>) directly or via defer.
	hasAtomicStore := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if hasAtomicStore || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 2 {
			return true
		}
		if isAtomicUint32Call(p, call, "StoreUint32") && isAddrOfRecvField(p, call.Args[0], recvVar, flagField) {
			if tv := p.TypesInfo.Types[call.Args[1]]; tv.Value != nil {
				if v, okI := constant.Uint64Val(tv.Value); okI && v > 0 {
					hasAtomicStore = true
					return false
				}
			}
		}
		return true
	})
	return hasAtomicStore
}

func computeExclusiveHelperCone(p *packages.Package, idx *pkgSyntaxIndex, root *types.Func) map[*types.Func]bool {
	if root == nil {
		return nil
	}
	coneFDs := computeExclusiveConeFromRoots(p, idx, nil, map[*types.Func]bool{root: true}, nil)
	out := map[*types.Func]bool{root: true}
	for fn, fd := range idx.funcDecls {
		if fd != nil && coneFDs[fd] {
			out[fn] = true
		}
	}
	return out
}

func rootPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	for {
		if v := lookupPkgScopeVar(p, cur); v != nil {
			return v
		}
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				cur = ast.Unparen(e.X)
				continue
			}
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
			continue
		}
		return nil
	}
}

func bodyMutatesAnyPackageGlobal(p *packages.Package, body *ast.BlockStmt, mutatedVars map[string]bool) bool {
	return bodyMutatesAnyPackageGlobalWithAllowed(p, body, mutatedVars, nil, nil)
}

func bodyMutatesAnyPackageGlobalWithAllowed(
	p *packages.Package,
	body *ast.BlockStmt,
	mutatedVars map[string]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	enclFD *ast.FuncDecl,
) bool {
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if v := rootPkgScopeVar(p, lhs); v != nil && v.Pkg() == p.Types {
					if enclFD != nil && confinedCacheMaps[v][enclFD] {
						continue
					}
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if v := rootPkgScopeVar(p, x.X); v != nil && v.Pkg() == p.Types {
				bad = true
				return false
			}
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				if (x.Key != nil && rootPkgScopeVar(p, x.Key) != nil) ||
					(x.Value != nil && rootPkgScopeVar(p, x.Value) != nil) {
					bad = true
					return false
				}
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						if rootPkgScopeVar(p, x.Args[0]) != nil {
							bad = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	_ = mutatedVars
	return bad
}

func isDirectCallFuncLit(idx *pkgSyntaxIndex, lit *ast.FuncLit) bool {
	call, isCall := idx.parentUnparen(lit).(*ast.CallExpr)
	return isCall && ast.Unparen(call.Fun) == lit
}

func isDirectPanicArgWithoutRecover(p *packages.Package, idx *pkgSyntaxIndex, expr ast.Expr) bool {
	call, isC := idx.parentUnparen(expr).(*ast.CallExpr)
	if !isC || len(call.Args) != 1 || call.Ellipsis.IsValid() || ast.Unparen(call.Args[0]) != expr {
		return false
	}
	cid, isID := ast.Unparen(call.Fun).(*ast.Ident)
	if !isID {
		return false
	}
	b, isB := p.TypesInfo.Uses[cid].(*types.Builtin)
	if !isB || b.Name() != "panic" {
		return false
	}
	var scopeBody *ast.BlockStmt
	for cur := idx.parentMap[call]; cur != nil; cur = idx.parentMap[cur] {
		if lit, isLit := cur.(*ast.FuncLit); isLit {
			scopeBody = lit.Body
			break
		}
		if fd, isFD := cur.(*ast.FuncDecl); isFD {
			scopeBody = fd.Body
			break
		}
	}
	if scopeBody == nil {
		return false
	}
	hasRecover := false
	ast.Inspect(scopeBody, func(n ast.Node) bool {
		if hasRecover || n == nil {
			return false
		}
		rc, okRC := n.(*ast.CallExpr)
		if !okRC {
			return true
		}
		rid, okRID := ast.Unparen(rc.Fun).(*ast.Ident)
		if !okRID {
			return true
		}
		if rb, okRB := p.TypesInfo.Uses[rid].(*types.Builtin); okRB && rb.Name() == "recover" {
			hasRecover = true
			return false
		}
		return true
	})
	return !hasRecover
}

func findLocalSyncOnceMemoizers(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	isConeImmPtr func(types.Type) bool,
) map[*ast.FuncLit]*types.Var {
	if fd == nil || fd.Body == nil || funcBodyHasGoto(fd.Body) {
		return nil
	}
	isSafeMemoType := func(t types.Type) bool {
		if t == nil {
			return false
		}
		if iface, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
			return iface.NumMethods() > 0
		}
		return !TypeCarriesMutableRefWith(t, isConeImmPtr)
	}

	uninitLocals := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		vs, okVS := n.(*ast.ValueSpec)
		if !okVS || len(vs.Values) != 0 {
			return true
		}
		for _, nm := range vs.Names {
			if v, okV := p.TypesInfo.Defs[nm].(*types.Var); okV && v != nil && idx.defCounts[v] == 1 && !idx.inFuncLit[nm] && !idx.inGoStmt[nm] {
				uninitLocals[v] = true
			}
		}
		return true
	})

	var out map[*ast.FuncLit]*types.Var
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, okAs := n.(*ast.AssignStmt)
		if !okAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		initID, okID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !okID || idx.inFuncLit[initID] || idx.inGoStmt[initID] {
			return true
		}
		initVar, _ := p.TypesInfo.Defs[initID].(*types.Var)
		if initVar == nil || idx.defCounts[initVar] != 1 {
			return true
		}
		outerLit, okOL := ast.Unparen(as.Rhs[0]).(*ast.FuncLit)
		if !okOL || outerLit.Body == nil || len(outerLit.Body.List) != 1 {
			return true
		}
		if (outerLit.Type.Params != nil && len(outerLit.Type.Params.List) > 0) ||
			(outerLit.Type.Results != nil && len(outerLit.Type.Results.List) > 0) {
			return true
		}
		es, okES := outerLit.Body.List[0].(*ast.ExprStmt)
		if !okES {
			return true
		}
		doCall, okDC := ast.Unparen(es.X).(*ast.CallExpr)
		if !okDC || len(doCall.Args) != 1 {
			return true
		}
		doSel, okDS := ast.Unparen(doCall.Fun).(*ast.SelectorExpr)
		if !okDS || doSel.Sel.Name != "Do" {
			return true
		}
		doFn, okFn := p.TypesInfo.Uses[doSel.Sel].(*types.Func)
		if !okFn || doFn.Pkg() == nil || doFn.Pkg().Path() != "sync" || doFn.Name() != "Do" {
			return true
		}
		onceID, okOID := ast.Unparen(doSel.X).(*ast.Ident)
		if !okOID {
			return true
		}
		onceVar, _ := p.TypesInfo.Uses[onceID].(*types.Var)
		if onceVar == nil || onceVar.IsField() || onceVar.Parent() == p.Types.Scope() ||
			!isNamedInPkg(onceVar.Type(), "sync", "Once") || idx.defCounts[onceVar] != 1 {
			return true
		}
		for _, ouid := range idx.usesOf[onceVar] {
			if ouid != onceID {
				return true
			}
		}
		for _, iuid := range idx.usesOf[initVar] {
			icall, okIC := idx.parentUnparen(iuid).(*ast.CallExpr)
			if !okIC || ast.Unparen(icall.Fun) != iuid || len(icall.Args) != 0 {
				return true
			}
			if _, okIES := idx.parentMap[icall].(*ast.ExprStmt); !okIES {
				return true
			}
		}
		innerLit, okIL := ast.Unparen(doCall.Args[0]).(*ast.FuncLit)
		if !okIL || innerLit.Body == nil || bodyMutatesAnyPackageGlobal(p, innerLit.Body, nil) {
			return true
		}

		innerDefs := map[*types.Var]bool{}
		ast.Inspect(innerLit.Body, func(sn ast.Node) bool {
			if sid, isSID := sn.(*ast.Ident); isSID {
				if dv, okDV := p.TypesInfo.Defs[sid].(*types.Var); okDV && dv != nil {
					innerDefs[dv] = true
				}
			}
			return true
		})
		writtenOuter := map[*types.Var]bool{}
		badOuter := false
		ast.Inspect(innerLit.Body, func(sn ast.Node) bool {
			if badOuter || sn == nil {
				return false
			}
			sid, isSID := sn.(*ast.Ident)
			if !isSID {
				return true
			}
			uv, okUV := p.TypesInfo.Uses[sid].(*types.Var)
			if !okUV || uv == nil || uv.IsField() || uv.Pkg() != p.Types || uv.Parent() == p.Types.Scope() || innerDefs[uv] {
				return true
			}
			if identOrExprIsWritten(idx, sid) {
				writtenOuter[uv] = true
				return true
			}
			if identReachesMutatedOrAddrPrefix(p, idx, sid) {
				badOuter = true
				return false
			}
			return true
		})
		if badOuter || len(writtenOuter) != 1 {
			return true
		}
		var cachedVar *types.Var
		for cv := range writtenOuter {
			cachedVar = cv
		}
		if !uninitLocals[cachedVar] || cachedVar.Pos() >= outerLit.Pos() || !isSafeMemoType(cachedVar.Type()) {
			return true
		}

		isInitCallStmt := func(st ast.Stmt) bool {
			ies, ok := st.(*ast.ExprStmt)
			if !ok {
				return false
			}
			ic, ok := ast.Unparen(ies.X).(*ast.CallExpr)
			if !ok || len(ic.Args) != 0 {
				return false
			}
			iid, ok := ast.Unparen(ic.Fun).(*ast.Ident)
			return ok && p.TypesInfo.Uses[iid] == initVar
		}

		allUsesDominated := true
		for _, cuid := range idx.usesOf[cachedVar] {
			if innerLit.Body.Pos() <= cuid.Pos() && cuid.Pos() < innerLit.Body.End() {
				if un, isUn := idx.parentUnparen(cuid).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					allUsesDominated = false
					break
				}
				continue
			}
			if identIsWrittenOrAddrTaken(idx, cuid) {
				allUsesDominated = false
				break
			}
			if ta, isTA := idx.parentUnparen(cuid).(*ast.TypeAssertExpr); isTA && ast.Unparen(ta.X) == cuid {
				allUsesDominated = false
				break
			}
			dominated := false
			for cur := idx.parentMap[cuid]; cur != nil; cur = idx.parentMap[cur] {
				if blk, isBlk := cur.(*ast.BlockStmt); isBlk {
					for _, bst := range blk.List {
						if bst.Pos() >= cuid.Pos() {
							break
						}
						if isInitCallStmt(bst) && bst.End() <= cuid.Pos() {
							dominated = true
							break
						}
						switch bst.(type) {
						case *ast.ReturnStmt, *ast.BranchStmt, *ast.LabeledStmt:
							break
						}
					}
					if dominated {
						break
					}
				}
				if _, isLit := cur.(*ast.FuncLit); isLit {
					break
				}
				if _, isFD := cur.(*ast.FuncDecl); isFD {
					break
				}
			}
			if !dominated {
				allUsesDominated = false
				break
			}
		}
		if allUsesDominated {
			if out == nil {
				out = map[*ast.FuncLit]*types.Var{}
			}
			out[innerLit] = cachedVar
		}
		return true
	})
	return out
}

func typeMentionsNamedStruct(root types.Type, target *types.Named) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if t == target {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func matchLocalBuilderOnlyAdapter(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	cs *types.Named,
	checkNormalField func(types.Type) bool,
) (builderGuard TypeRef, methodGuards []FuncKey, exemptFields []*types.Var, ok bool) {
	if cs == nil || cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
		return TypeRef{}, nil, nil, false
	}
	if types.NewMethodSet(types.NewPointer(cs)).Len() != types.NewMethodSet(cs).Len() {
		return TypeRef{}, nil, nil, false
	}
	cst, okSt := cs.Underlying().(*types.Struct)
	if !okSt || cst.NumFields() == 0 {
		return TypeRef{}, nil, nil, false
	}

	// Verify cs does not appear in any package-scope variable or any other struct field in p.Types.
	for _, name := range p.Types.Scope().Names() {
		switch obj := p.Types.Scope().Lookup(name).(type) {
		case *types.Var:
			if typeMentionsNamedStruct(obj.Type(), cs) {
				return TypeRef{}, nil, nil, false
			}
		case *types.TypeName:
			if obj.Type() == cs || obj.IsAlias() {
				continue
			}
			if st, isS := obj.Type().Underlying().(*types.Struct); isS {
				for i := 0; i < st.NumFields(); i++ {
					if typeMentionsNamedStruct(st.Field(i).Type(), cs) {
						return TypeRef{}, nil, nil, false
					}
				}
			}
		}
	}

	// Verify every construction of cs across p.Syntax is a by-value CompositeLit passed solely as a
	// KeyValueExpr.Value inside an inline CrossPkgBuilder{...}.Build() call!
	sawLit := false
	validUses := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !validUses || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND && derefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
					validUses = false
					return false
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" && derefNamedStruct(p.TypesInfo.TypeOf(x)) == cs {
						validUses = false
						return false
					}
				}
			case *ast.CompositeLit:
				if types.Unalias(p.TypesInfo.TypeOf(x)) == cs {
					sawLit = true
					kv, isKV := idx.parentUnparen(x).(*ast.KeyValueExpr)
					if !isKV || ast.Unparen(kv.Value) != x {
						validUses = false
						return false
					}
					bLit, isBL := idx.parentUnparen(kv).(*ast.CompositeLit)
					if !isBL {
						validUses = false
						return false
					}
					bSel, isBS := idx.parentUnparen(bLit).(*ast.SelectorExpr)
					if !isBS || ast.Unparen(bSel.X) != bLit || bSel.Sel.Name != "Build" {
						validUses = false
						return false
					}
					bCall, isBC := idx.parentUnparen(bSel).(*ast.CallExpr)
					if !isBC || ast.Unparen(bCall.Fun) != bSel || len(bCall.Args) != 0 {
						validUses = false
						return false
					}
					bNamed, isBN := types.Unalias(p.TypesInfo.TypeOf(bLit)).(*types.Named)
					if !isBN || bNamed.Obj() == nil || bNamed.Obj().Pkg() == nil || bNamed.Obj().Pkg() == p.Types || isStandardLibraryPkgPath(bNamed.Obj().Pkg().Path()) {
						validUses = false
						return false
					}
					ref := TypeRef{Pkg: bNamed.Obj().Pkg().Path(), Name: bNamed.Obj().Name()}
					if !ref.Valid() || (!builderGuard.IsZero() && builderGuard != ref) {
						validUses = false
						return false
					}
					builderGuard = ref
				}
			}
			return true
		})
	}
	if !validUses || !sawLit || builderGuard.IsZero() {
		return TypeRef{}, nil, nil, false
	}

	// Check fields of cs: allow unexported *ForeignNamedStruct fields whose uses in p.Syntax are
	// exclusively direct method calls with carrier-free scalar arguments, recording RequireNonMutatingMethod.
	methodSet := map[FuncKey]bool{}
	for i := 0; i < cst.NumFields(); i++ {
		f := cst.Field(i)
		if f.Exported() {
			return TypeRef{}, nil, nil, false
		}
		if checkNormalField(f.Type()) {
			continue
		}
		ptr, isP := types.Unalias(f.Type()).(*types.Pointer)
		if !isP {
			return TypeRef{}, nil, nil, false
		}
		elemN, isEN := types.Unalias(ptr.Elem()).(*types.Named)
		if !isEN || elemN.Obj() == nil || elemN.Obj().Pkg() == nil || elemN.Obj().Pkg() == p.Types || isStandardLibraryPkgPath(elemN.Obj().Pkg().Path()) {
			return TypeRef{}, nil, nil, false
		}
		if _, isElemSt := elemN.Underlying().(*types.Struct); !isElemSt {
			return TypeRef{}, nil, nil, false
		}
		for _, fuid := range idx.usesOf[f] {
			fsel, isFS := idx.parentUnparen(fuid).(*ast.SelectorExpr)
			if !isFS || fsel.Sel != fuid {
				return TypeRef{}, nil, nil, false
			}
			msel, isMS := idx.parentUnparen(fsel).(*ast.SelectorExpr)
			if !isMS || ast.Unparen(msel.X) != fsel {
				return TypeRef{}, nil, nil, false
			}
			si := p.TypesInfo.Selections[msel]
			if si == nil || si.Kind() != types.MethodVal || selectionCrossesEmbeddedPointer(si) {
				return TypeRef{}, nil, nil, false
			}
			mfn, okM := si.Obj().(*types.Func)
			if !okM || mfn == nil || mfn.Pkg() != elemN.Obj().Pkg() || !mfn.Exported() {
				return TypeRef{}, nil, nil, false
			}
			mcall, isMC := idx.parentUnparen(msel).(*ast.CallExpr)
			if !isMC || ast.Unparen(mcall.Fun) != msel || mcall.Ellipsis.IsValid() {
				return TypeRef{}, nil, nil, false
			}
			for _, marg := range mcall.Args {
				if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(marg)) {
					return TypeRef{}, nil, nil, false
				}
			}
			mk := FuncKey{Pkg: elemN.Obj().Pkg().Path(), Name: elemN.Obj().Name() + "." + mfn.Name()}
			if !mk.Valid() {
				return TypeRef{}, nil, nil, false
			}
			methodSet[mk] = true
		}
		exemptFields = append(exemptFields, f)
	}
	if len(exemptFields) == 0 {
		return TypeRef{}, nil, nil, false
	}
	for mk := range methodSet {
		methodGuards = append(methodGuards, mk)
	}
	slices.SortFunc(methodGuards, FuncKey.Compare)
	return builderGuard, methodGuards, exemptFields, true
}

func verifyOnceInitConeImmutability(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	ownerRef TypeRef,
	onceFn *types.Func,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	verifiedMsgRoots map[*types.Named]bool,
	mutatedVars map[string]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) ([]TypeRef, []ConditionalStructMutation, bool) {
	if onceFn == nil || !ownerRef.Valid() {
		return nil, nil, false
	}
	fullInitCone := map[*types.Func]bool{onceFn: true}
	coneConstructedStructs := map[*types.Named]bool{}
	coneCrossDescStructs := map[*types.Named]bool{}
	var coneLits []*ast.FuncLit
	queue := []*types.Func{onceFn}
	valid := true

	addConeStruct := func(stN *types.Named) {
		if stN == nil || family[stN] || childProtected[stN] || verifiedMsgRoots[stN] {
			return
		}
		if stN.Obj() != nil && stN.Obj().Pkg() != nil && stN.Obj().Pkg() != p.Types && !isStandardLibraryPkgPath(stN.Obj().Pkg().Path()) {
			coneCrossDescStructs[stN] = true
			return
		}
		coneConstructedStructs[stN] = true
	}

	for len(queue) > 0 && valid {
		curFn := queue[0]
		queue = queue[1:]
		fd := idx.funcDecls[curFn]
		if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobalWithAllowed(p, fd.Body, mutatedVars, confinedCacheMaps, fd) {
			return nil, nil, false
		}
		memoLits := findLocalSyncOnceMemoizers(p, idx, fd, func(tp types.Type) bool {
			ptr, ok := types.Unalias(tp).(*types.Pointer)
			if !ok {
				return false
			}
			elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
			return ok && (family[elem] || childProtected[elem] || verifiedMsgRoots[elem])
		})
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt:
				valid = false
				return false
			case *ast.FuncLit:
				if !isDirectCallFuncLit(idx, x) {
					coneLits = append(coneLits, x)
					if memoLits[x] == nil {
						hasMemoInner := false
						var nestedLits []*ast.FuncLit
						ast.Inspect(x.Body, func(sn ast.Node) bool {
							if sn == nil {
								return false
							}
							if _, isG := sn.(*ast.GoStmt); isG {
								valid = false
								return false
							}
							if il, ok := sn.(*ast.FuncLit); ok && il != x {
								if !isDirectCallFuncLit(idx, il) {
									nestedLits = append(nestedLits, il)
								}
								if memoLits[il] != nil {
									hasMemoInner = true
								}
							}
							return true
						})
						if !valid {
							return false
						}
						if !hasMemoInner {
							coneLits = append(coneLits, nestedLits...)
							return false
						}
					}
				}
				return true
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if isDirectPanicArgWithoutRecover(p, idx, x) {
						return true
					}
					if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
						if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
							stN := derefNamedStruct(ptr)
							if stN == nil {
								valid = false
								return false
							}
							addConeStruct(stN)
						}
					}
				}
			case *ast.CompositeLit:
				if lt := p.TypesInfo.TypeOf(x); lt != nil {
					if _, isPtr := types.Unalias(lt).(*types.Pointer); !isPtr {
						if _, isSt := types.Unalias(lt).Underlying().(*types.Struct); isSt {
							if TypeCarriesMutableRef(lt) && types.NewMethodSet(lt).Len() > 0 {
								stN := derefNamedStruct(lt)
								if stN == nil {
									valid = false
									return false
								}
								addConeStruct(stN)
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						if !isDirectPanicArgWithoutRecover(p, idx, x) {
							if ptr, isP := types.Unalias(p.TypesInfo.TypeOf(x)).(*types.Pointer); isP {
								if _, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct); isSt {
									stN := derefNamedStruct(ptr)
									if stN == nil {
										valid = false
										return false
									}
									addConeStruct(stN)
								}
							}
						}
					}
				}
				if callee := resolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
						// Interface method declaration has no concrete FuncDecl body.
					} else if callee.Pkg() == p.Types && !fullInitCone[callee] {
						fullInitCone[callee] = true
						queue = append(queue, callee)
					}
				}
			}
			return true
		})
	}
	if !valid {
		return nil, nil, false
	}

	isConeImmStruct := func(st *types.Named) bool {
		return st != nil && (family[st] || childProtected[st] || verifiedMsgRoots[st] || coneConstructedStructs[st] || coneCrossDescStructs[st])
	}
	isConeImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && isConeImmStruct(elem)
	}

	condSet := map[ConditionalStructMutation]bool{}
	for extSt := range coneCrossDescStructs {
		extRef := TypeRef{Pkg: extSt.Obj().Pkg().Path(), Name: extSt.Obj().Name()}
		if !extRef.Valid() {
			return nil, nil, false
		}
		condSet[ConditionalStructMutation{
			Struct:                  ownerRef,
			GuardStruct:             extRef,
			RequireDescBuilderGuard: true,
		}] = true
	}

	var coneGuards []TypeRef
	if len(coneConstructedStructs) > 0 {
		isEmbeddedNonEmptyIface := func(f *types.Var) bool {
			if !f.Embedded() {
				return false
			}
			iface, ok := types.Unalias(f.Type()).Underlying().(*types.Interface)
			return ok && iface.NumMethods() > 0
		}
		checkConeFieldType := func(root types.Type, rootSamePkgStruct bool) bool {
			seenFieldTypes := map[types.Type]bool{}
			var walk func(t types.Type, inSamePkgStruct bool) bool
			walk = func(t types.Type, inSamePkgStruct bool) bool {
				if t == nil {
					return false
				}
				t = types.Unalias(t)
				if seenFieldTypes[t] {
					return true
				}
				seenFieldTypes[t] = true
				if n, isN := t.(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						// Cross-package named value struct (such as protoreflect.Value or reflect.StructField):
						// reject only if it declares pointer-receiver methods that could mutate an embedded field.
						return types.NewMethodSet(types.NewPointer(n)).Len() == types.NewMethodSet(n).Len()
					}
				}
				switch u := t.Underlying().(type) {
				case *types.Interface, *types.Signature:
					return true
				case *types.Basic:
					return !(inSamePkgStruct && u.Kind() == types.UnsafePointer)
				case *types.Chan, *types.TypeParam:
					return false
				case *types.Pointer:
					elem, isEN := types.Unalias(u.Elem()).(*types.Named)
					return isEN && isConeImmStruct(elem)
				case *types.Slice:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Array:
					return walk(u.Elem(), inSamePkgStruct)
				case *types.Map:
					return walk(u.Key(), inSamePkgStruct) && walk(u.Elem(), inSamePkgStruct)
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						f := u.Field(i)
						if inSamePkgStruct && f.Exported() && !isEmbeddedNonEmptyIface(f) {
							return false
						}
						subSamePkg := inSamePkgStruct
						if subN, isSN := types.Unalias(f.Type()).(*types.Named); isSN && subN.Obj() != nil {
							subSamePkg = subN.Obj().Pkg() == p.Types
						}
						if !walk(f.Type(), subSamePkg) {
							return false
						}
					}
					return true
				}
				return true
			}
			return walk(root, rootSamePkgStruct)
		}

		adapterExemptFields := map[*types.Var]bool{}
		for cs := range coneConstructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, false
			}
			cst, okS := cs.Underlying().(*types.Struct)
			if !okS {
				return nil, nil, false
			}
			normalOK := true
			for i := 0; i < cst.NumFields(); i++ {
				f := cst.Field(i)
				if (f.Exported() && !isEmbeddedNonEmptyIface(f)) || !checkConeFieldType(f.Type(), true) {
					normalOK = false
					break
				}
			}
			if !normalOK {
				bGuard, mGuards, exFields, okAdapter := matchLocalBuilderOnlyAdapter(p, idx, cs, func(ft types.Type) bool {
					return checkConeFieldType(ft, true)
				})
				if !okAdapter {
					return nil, nil, false
				}
				condSet[ConditionalStructMutation{
					Struct:                  ownerRef,
					GuardStruct:             bGuard,
					RequireDescBuilderGuard: true,
				}] = true
				for _, mk := range mGuards {
					condSet[ConditionalStructMutation{
						Struct:                   ownerRef,
						RequireNonMutatingMethod: mk,
					}] = true
				}
				for _, ef := range exFields {
					adapterExemptFields[ef] = true
				}
			}
			ref := TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, false
			}
			coneGuards = append(coneGuards, ref)
		}
		if pkgHasAnyMutationOnStructs(p, idx, coneConstructedStructs, nil) {
			return nil, nil, false
		}
		if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
			IsImmutablePtr:                isConeImmPtr,
			AllowReturnFromUnexportedFunc: true,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel {
					return false, false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false, false
				}
				if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && adapterExemptFields[fObj] {
					return false, false
				}
				hit := false
				forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if coneConstructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if n, isN := types.Unalias(ft).(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() != p.Types {
					if _, isSt := n.Underlying().(*types.Struct); isSt {
						return false, false
					}
				}
				if IsDirectMutableRefWith(ft, isConeImmPtr) {
					return true, true
				}
				if TypeCarriesMutableRefWith(ft, isConeImmPtr) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && isReflectTypeOfCall(p, call)
			},
		}) {
			return nil, nil, false
		}
		sort.Slice(coneGuards, func(i, j int) bool { return coneGuards[i].key() < coneGuards[j].key() })
	}

	if len(coneLits) > 0 {
		memoAllowedWrite := map[*ast.FuncLit]*types.Var{}
		for fn := range fullInitCone {
			for lit, cv := range findLocalSyncOnceMemoizers(p, idx, idx.funcDecls[fn], isConeImmPtr) {
				memoAllowedWrite[lit] = cv
			}
		}

		capturedRefIdents := map[*ast.Ident]bool{}
		for _, lit := range coneLits {
			allowedCachedVar := memoAllowedWrite[lit]
			ast.Inspect(lit.Body, func(n ast.Node) bool {
				if !valid || n == nil {
					return false
				}
				if nl, isNL := n.(*ast.FuncLit); isNL && nl != lit && !isDirectCallFuncLit(idx, nl) {
					return false
				}
				uid, isID := n.(*ast.Ident)
				if !isID {
					return true
				}
				v, isV := p.TypesInfo.Uses[uid].(*types.Var)
				if !isV || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() || v.Pos() >= lit.Pos() {
					return true
				}
				if identOrExprIsWritten(idx, uid) {
					if allowedCachedVar != nil && v == allowedCachedVar {
						return true
					}
					valid = false
					return false
				}
				if un, isUn := idx.parentUnparen(uid).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					if !isConeImmPtr(p.TypesInfo.TypeOf(un)) {
						valid = false
						return false
					}
				}
				if TypeCarriesMutableRefWith(v.Type(), isConeImmPtr) {
					capturedRefIdents[uid] = true
				}
				return true
			})
			if !valid {
				return nil, nil, false
			}
		}
		if len(capturedRefIdents) > 0 {
			if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
				IsImmutablePtr:                isConeImmPtr,
				AllowReturnFromUnexportedFunc: true,
				AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
					return isNamedInPkg(p.TypesInfo.TypeOf(containerExpr), "reflect", "StructField")
				},
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					id, isID := ast.Unparen(expr).(*ast.Ident)
					if !isID || !capturedRefIdents[id] {
						return false, false
					}
					vt := p.TypesInfo.TypeOf(id)
					if IsDirectMutableRefWith(vt, isConeImmPtr) {
						return true, true
					}
					if TypeCarriesMutableRefWith(vt, isConeImmPtr) {
						return false, true
					}
					return false, false
				},
				AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
					return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && isReflectTypeOfCall(p, call)
				},
			}) {
				return nil, nil, false
			}
		}
	}

	var conds []ConditionalStructMutation
	for cm := range condSet {
		conds = append(conds, cm)
	}
	slices.SortFunc(conds, ConditionalStructMutation.Compare)
	return coneGuards, conds, true
}

func verifyAtomicCASPointerStruct(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	named *types.Named,
	rootNamed *types.Named,
) (*ast.FuncDecl, map[ast.Node]bool, []TypeRef) {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() != p.Types || named.Obj().Exported() || named.TypeParams().Len() > 0 || types.NewMethodSet(named).Len() != 0 {
		return nil, nil, nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() != 1 || st.Field(0).Exported() {
		return nil, nil, nil
	}
	b, ok := types.Unalias(st.Field(0).Type()).Underlying().(*types.Basic)
	if !ok || b.Kind() != types.UnsafePointer {
		return nil, nil, nil
	}
	pset := types.NewMethodSet(types.NewPointer(named))
	if pset.Len() != 1 {
		return nil, nil, nil
	}
	m, ok := pset.At(0).Obj().(*types.Func)
	if !ok || m.Pkg() != p.Types {
		return nil, nil, nil
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil, nil, nil
	}
	retPtr, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
	if !ok {
		return nil, nil, nil
	}
	retNamed, ok := types.Unalias(retPtr.Elem()).(*types.Named)
	if !ok || retNamed.Obj() == nil || retNamed.Obj().Pkg() != p.Types || retNamed.Obj().Exported() || retNamed.TypeParams().Len() > 0 {
		return nil, nil, nil
	}
	if _, isSt := retNamed.Underlying().(*types.Struct); !isSt {
		return nil, nil, nil
	}
	fd := idx.funcDecls[m]
	if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobal(p, fd.Body, nil) {
		return nil, nil, nil
	}

	unmutatedRootParams := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if !isPtrToNamed(pv.Type(), rootNamed) {
			continue
		}
		clean := true
		for _, uid := range idx.usesOf[pv] {
			if identIsWrittenOrAddrTaken(idx, uid) {
				clean = false
				break
			}
		}
		if clean {
			unmutatedRootParams[pv] = true
		}
	}

	isValidCASAllocLit := func(expr ast.Expr) bool {
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL || derefNamedStruct(p.TypesInfo.TypeOf(cl)) != retNamed {
			return false
		}
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			val := ast.Unparen(kv.Value)
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if isPtrToNamed(vt, rootNamed) {
				pid, isID := val.(*ast.Ident)
				if !isID {
					return false
				}
				pv, _ := p.TypesInfo.Uses[pid].(*types.Var)
				if pv == nil || !unmutatedRootParams[pv] {
					return false
				}
				continue
			}
			if TypeContainsRefOrPointer(vt) {
				return false
			}
		}
		return true
	}

	allocLocals := map[*types.Var]bool{}
	loadLocals := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID {
			return true
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.defCounts[lv] != 1 {
			return true
		}
		if isValidCASAllocLit(as.Rhs[0]) {
			allocLocals[lv] = true
		} else if rc, isRC := ast.Unparen(as.Rhs[0]).(*ast.CallExpr); isRC && len(rc.Args) == 1 {
			if cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr); isCS {
				if afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func); isFn && afn.Pkg() != nil && afn.Pkg().Path() == "sync/atomic" && afn.Name() != "" && afn.Name() == "LoadPointer" {
					loadLocals[lv] = true
				}
			}
		}
		return true
	})
	for lv := range allocLocals {
		for _, uid := range idx.usesOf[lv] {
			if identIsWrittenOrAddrTaken(idx, uid) {
				delete(allocLocals, lv)
				break
			}
		}
	}
	for lv := range loadLocals {
		for _, uid := range idx.usesOf[lv] {
			if identIsWrittenOrAddrTaken(idx, uid) {
				delete(loadLocals, lv)
				break
			}
		}
	}

	// Every use of st.Field(0) across p.Syntax must lie synchronously inside fd.Body and pass &m.p only to LoadPointer or CompareAndSwapPointer(..., nil, unsafe.Pointer(w)).
	fld := st.Field(0)
	casAddrExempt := map[ast.Node]bool{}
	allowedUnsafeConvs := map[*ast.CallExpr]bool{}
	sawCAS := false
	for _, id := range idx.usesOf[fld] {
		if !idx.isSyncInFuncDecl(id, fd) {
			return nil, nil, nil
		}
		sel, isSel := idx.parentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, nil, nil
		}
		un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return nil, nil, nil
		}
		call, isCall := idx.parentUnparen(un).(*ast.CallExpr)
		if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != un {
			return nil, nil, nil
		}
		selFun, isSF := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSF {
			return nil, nil, nil
		}
		afn, isFn := p.TypesInfo.Uses[selFun.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" {
			return nil, nil, nil
		}
		switch afn.Name() {
		case "LoadPointer":
			if len(call.Args) != 1 {
				return nil, nil, nil
			}
		case "CompareAndSwapPointer":
			if len(call.Args) != 3 || !isNilIdent(p, call.Args[1]) {
				return nil, nil, nil
			}
			conv, isConv := ast.Unparen(call.Args[2]).(*ast.CallExpr)
			if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() {
				return nil, nil, nil
			}
			wExpr := ast.Unparen(conv.Args[0])
			if !isValidCASAllocLit(wExpr) {
				wid, isID := wExpr.(*ast.Ident)
				if !isID {
					return nil, nil, nil
				}
				wv, _ := p.TypesInfo.Uses[wid].(*types.Var)
				if wv == nil || !allocLocals[wv] {
					return nil, nil, nil
				}
			}
			allowedUnsafeConvs[conv] = true
			sawCAS = true
		default:
			return nil, nil, nil
		}
		casAddrExempt[un] = true
	}
	if !sawCAS {
		return nil, nil, nil
	}

	// Zero FuncLits or GoStmts in fd.Body, and every return must return (*retNamed)(p) where p comes from atomic.LoadPointer(&m.p).
	returnsValid := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !returnsValid || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.FuncLit, *ast.GoStmt:
			returnsValid = false
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) != 1 {
			returnsValid = false
			return false
		}
		conv, isConv := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !isPtrToNamed(p.TypesInfo.Types[conv.Fun].Type, retNamed) {
			returnsValid = false
			return false
		}
		src := ast.Unparen(conv.Args[0])
		if rid, isID := src.(*ast.Ident); isID {
			rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
			if rv == nil || !loadLocals[rv] {
				returnsValid = false
				return false
			}
			return true
		}
		rc, isRC := src.(*ast.CallExpr)
		if !isRC || len(rc.Args) != 1 {
			returnsValid = false
			return false
		}
		cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr)
		if !isCS {
			returnsValid = false
			return false
		}
		afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "LoadPointer" {
			returnsValid = false
			return false
		}
		return true
	})
	if !returnsValid {
		return nil, nil, nil
	}

	// Transitively close casTargets over pointer conversions *srcSt -> *dstSt across p.Syntax,
	// failing closed if any conversion from *srcSt targets anything other than an unexported
	// non-generic intra-package named struct.
	casTargets := map[*types.Named]bool{named: true, retNamed: true}
	casPtrConvs := map[*ast.CallExpr]bool{}
	convValid := true
	expanded := true
	for expanded && convValid {
		expanded = false
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !convValid || n == nil {
					return false
				}
				conv, isConv := n.(*ast.CallExpr)
				if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || allowedUnsafeConvs[conv] {
					return true
				}
				argT := types.Unalias(p.TypesInfo.TypeOf(conv.Args[0]))
				srcPtr, isSrcPtr := argT.(*types.Pointer)
				if !isSrcPtr {
					return true
				}
				srcNamed, isSN := types.Unalias(srcPtr.Elem()).(*types.Named)
				if !isSN || !casTargets[srcNamed] {
					return true
				}
				dstT := types.Unalias(p.TypesInfo.Types[conv.Fun].Type)
				dstPtr, isDstPtr := dstT.(*types.Pointer)
				if !isDstPtr {
					convValid = false
					return false
				}
				dstSt, isDN := types.Unalias(dstPtr.Elem()).(*types.Named)
				if !isDN || dstSt == nil || dstSt.Obj() == nil || dstSt.Obj().Pkg() != p.Types || dstSt.Obj().Exported() || dstSt.TypeParams().Len() > 0 {
					convValid = false
					return false
				}
				if _, isStruct := dstSt.Underlying().(*types.Struct); !isStruct {
					convValid = false
					return false
				}
				casPtrConvs[conv] = true
				if !casTargets[dstSt] {
					casTargets[dstSt] = true
					expanded = true
				}
				return true
			})
		}
	}
	if !convValid {
		return nil, nil, nil
	}

	// Verify every struct in casTargets (excluding named itself, checked above) and any
	// value-contained substructs are unexported in p.Types, have zero exported fields,
	// and contain only *rootNamed, carrier-free scalars, or omitted zero-valued value-substructs
	// (such as impl.pointer{p unsafe.Pointer}) that declare zero pointer-receiver methods.
	allCASProtected := map[*types.Named]bool{named: true}
	checkedCASSub := map[*types.Named]bool{}
	var verifyCASStruct func(cn *types.Named, isSub bool) bool
	verifyCASStruct = func(cn *types.Named, isSub bool) bool {
		if cn == nil || cn.Obj() == nil || cn.Obj().Pkg() != p.Types || cn.Obj().Exported() || cn.TypeParams().Len() > 0 {
			return false
		}
		if isSub {
			if checkedCASSub[cn] {
				return true
			}
		} else if allCASProtected[cn] {
			return true
		}
		cst, okS := cn.Underlying().(*types.Struct)
		if !okS {
			return false
		}
		if isSub {
			if types.NewMethodSet(types.NewPointer(cn)).Len() != types.NewMethodSet(cn).Len() {
				return false
			}
			checkedCASSub[cn] = true
		} else {
			allCASProtected[cn] = true
		}
		for i := 0; i < cst.NumFields(); i++ {
			cf := cst.Field(i)
			if cf.Exported() {
				return false
			}
			ft := types.Unalias(cf.Type())
			if !isSub && isPtrToNamed(ft, rootNamed) {
				continue
			}
			elem := ft
			zeroLenArray := false
			for {
				ar, isAr := elem.Underlying().(*types.Array)
				if !isAr {
					break
				}
				if ar.Len() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					zeroLenArray = true
					break
				}
				elem = types.Unalias(ar.Elem())
			}
			if zeroLenArray && types.NewMethodSet(types.NewPointer(ft)).Len() == 0 {
				continue
			}
			if subSt, isSt := elem.Underlying().(*types.Struct); isSt {
				if subN, isSubN := elem.(*types.Named); isSubN {
					if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(subN)).Len() == 0 {
						continue
					}
					if !verifyCASStruct(subN, true) {
						return false
					}
					continue
				}
				if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					continue
				}
				return false
			}
			if !TypeContainsRefOrPointer(elem) {
				continue
			}
			if isSub && elem == ft {
				if ub, isB := elem.Underlying().(*types.Basic); isB && ub.Kind() == types.UnsafePointer {
					continue
				}
			}
			return false
		}
		return true
	}
	for ct := range casTargets {
		if ct == named {
			continue
		}
		if !verifyCASStruct(ct, false) {
			return nil, nil, nil
		}
	}
	if pkgHasAnyMutationOnStructs(p, idx, allCASProtected, casAddrExempt) {
		return nil, nil, nil
	}

	casExempt := make(map[ast.Node]bool, len(casAddrExempt)+len(allowedUnsafeConvs)+len(casPtrConvs))
	for n := range casAddrExempt {
		casExempt[n] = true
	}
	for c := range allowedUnsafeConvs {
		casExempt[c] = true
	}
	for c := range casPtrConvs {
		casExempt[c] = true
	}

	guards := make([]TypeRef, 0, len(allCASProtected))
	for ct := range allCASProtected {
		ref := TypeRef{Pkg: p.Types.Path(), Name: ct.Obj().Name()}
		if !ref.Valid() {
			return nil, nil, nil
		}
		guards = append(guards, ref)
	}
	sort.Slice(guards, func(i, j int) bool { return guards[i].key() < guards[j].key() })
	return fd, casExempt, guards
}

func isInsideExemptWriteOrAddr(idx *pkgSyntaxIndex, n ast.Node, exemptMap map[ast.Node]bool) bool {
	if len(exemptMap) == 0 {
		return false
	}
	cur := n
	for cur != nil {
		switch pNode := idx.parentMap[cur].(type) {
		case *ast.AssignStmt:
			if exemptMap[pNode] {
				for _, lhs := range pNode.Lhs {
					if lhs.Pos() <= n.Pos() && n.End() <= lhs.End() {
						return true
					}
				}
			}
		case *ast.UnaryExpr:
			if pNode.Op == token.AND && exemptMap[pNode] {
				return true
			}
		}
		cur = idx.parentMap[cur]
	}
	return false
}

func isReflectZeroInterfaceCall(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Interface" {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
		return false
	}
	zCall, ok := ast.Unparen(sel.X).(*ast.CallExpr)
	if !ok || len(zCall.Args) != 1 {
		return false
	}
	zSel, ok := ast.Unparen(zCall.Fun).(*ast.SelectorExpr)
	if !ok || zSel.Sel == nil {
		return false
	}
	zFn, ok := p.TypesInfo.Uses[zSel.Sel].(*types.Func)
	return ok && zFn.Pkg() != nil && zFn.Pkg().Path() == "reflect" && zFn.Name() == "Zero"
}

func isSafeProtectedIfaceElemValue(
	p *packages.Package,
	val ast.Expr,
	allProtected map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) bool {
	if isNilIdent(p, val) || isReflectZeroInterfaceCall(p, val) {
		return true
	}
	valT := p.TypesInfo.TypeOf(val)
	if valT == nil {
		return false
	}
	if types.IsInterface(valT) {
		ix, isIX := ast.Unparen(val).(*ast.IndexExpr)
		if !isIX {
			return false
		}
		hitSt, fld := lhsRootFamilyField(p, ix.X, allProtected)
		return hitSt != nil && fld != nil && !fld.Exported()
	}
	return !TypeCarriesMutableRefWith(valT, isImmPtr)
}

func verifyLockedStructFamilyDiscipline(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	rootNamed *types.Named,
	family map[*types.Named]bool,
	childProtected map[*types.Named]bool,
	casHelperStructs map[*types.Named]*ast.FuncDecl,
	verifiedMsgRoots map[*types.Named]bool,
	muField, flagField *types.Var,
	onceFn *types.Func,
	onceCone map[*types.Func]bool,
	builderInitFn *types.Func,
	exempt map[ast.Node]bool,
	builderExempt map[ast.Node]bool,
) ([]TypeRef, bool) {
	allProtected := map[*types.Named]bool{}
	for st := range family {
		allProtected[st] = true
		if len(casHelperStructs) > 0 {
			if uSt, okSt := st.Underlying().(*types.Struct); okSt {
				for i := 0; i < uSt.NumFields(); i++ {
					f := uSt.Field(i)
					casSt, isN := types.Unalias(f.Type()).(*types.Named)
					if !isN || casHelperStructs[casSt] == nil {
						continue
					}
					if f.Exported() {
						return nil, false
					}
					for _, id := range idx.usesOf[f] {
						sel, isSel := idx.parentUnparen(id).(*ast.SelectorExpr)
						if !isSel || sel.Sel != id {
							return nil, false
						}
						msel, isMS := idx.parentUnparen(sel).(*ast.SelectorExpr)
						if !isMS || ast.Unparen(msel.X) != sel {
							return nil, false
						}
						call, isCall := idx.parentUnparen(msel).(*ast.CallExpr)
						if !isCall || ast.Unparen(call.Fun) != msel {
							return nil, false
						}
					}
				}
			}
		}
	}
	for st := range childProtected {
		allProtected[st] = true
	}
	isImmPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		elem, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && (allProtected[elem] || verifiedMsgRoots[elem])
	}

	// Check muField uses: ONLY .Lock() and .Unlock() synchronously inside onceCone!
	for _, id := range idx.usesOf[muField] {
		encl := idx.syncEnclFuncDecl(id)
		if encl == nil {
			return nil, false
		}
		fn, _ := p.TypesInfo.Defs[encl.Name].(*types.Func)
		if fn == nil || !onceCone[fn] {
			return nil, false
		}
		sel, isSel := idx.parentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, false
		}
		msel, isMSel := idx.parentUnparen(sel).(*ast.SelectorExpr)
		if !isMSel || ast.Unparen(msel.X) != sel || (msel.Sel.Name != "Lock" && msel.Sel.Name != "Unlock") {
			return nil, false
		}
		call, isCall := idx.parentUnparen(msel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != msel {
			return nil, false
		}
	}

	// Precompute fresh local *S / S variables per function (e.g. mi := &MessageInfo{...} in legacyLoadMessageInfo).
	type freshFuncInfo struct {
		vars      map[*types.Var]bool
		escapePos map[*types.Var]token.Pos
	}
	freshLocalsByFunc := map[*ast.FuncDecl]freshFuncInfo{}
	getFreshLocals := func(fd *ast.FuncDecl) (map[*types.Var]bool, map[*types.Var]token.Pos) {
		if fd == nil {
			return nil, nil
		}
		if info, ok := freshLocalsByFunc[fd]; ok {
			return info.vars, info.escapePos
		}
		vars, esc := collectFreshLocalStructVars(p, idx, fd)
		freshLocalsByFunc[fd] = freshFuncInfo{vars: vars, escapePos: esc}
		return vars, esc
	}

	fastInitMethods := collectFastOnceWrapperMethods(p, idx, rootNamed, onceFn, flagField)
	guardSet := map[TypeRef]bool{}
	for st := range allProtected {
		if st == rootNamed || st.Obj() == nil {
			continue
		}
		ref := TypeRef{Pkg: p.Types.Path(), Name: st.Obj().Name()}
		if !ref.Valid() {
			return nil, false
		}
		guardSet[ref] = true
	}
	allowExportedWriteInCone := hasDeprecatedExtensionFields(family)

	checkFamilyWriteExpr := func(expr ast.Expr, inAllowedWriter bool, freshVars map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if star, isStar := ast.Unparen(expr).(*ast.StarExpr); isStar {
			if st := derefNamedStruct(p.TypesInfo.TypeOf(star.X)); st != nil {
				if family[st] {
					return false
				}
				if childProtected[st] {
					return inAllowedWriter || isRootedAtFreshLocal(p, star.X, freshVars, freshEsc)
				}
			}
		}
		hitSt, fld := lhsRootFamilyField(p, expr, allProtected)
		if hitSt == nil {
			return true
		}
		if isRootedAtFreshLocal(p, expr, freshVars, freshEsc) {
			return true
		}
		if !inAllowedWriter {
			return false
		}
		if family[hitSt] && fld != nil && fld.Exported() && !allowExportedWriteInCone {
			return false
		}
		return true
	}

	valid := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			syncEncl := idx.syncEnclFuncDecl(n)
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			freshVars, freshEsc := getFreshLocals(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				if builderExempt[x] {
					return true
				}
				for li, lhs := range x.Lhs {
					if !checkFamilyWriteExpr(lhs, inAllowedWriter, freshVars, freshEsc) {
						valid = false
						return false
					}
					if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX && !isRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
						if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
							if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
								if len(x.Lhs) != len(x.Rhs) || !isSafeProtectedIfaceElemValue(p, x.Rhs[li], allProtected, isImmPtr) {
									valid = false
									return false
								}
							}
						}
					}
				}
			case *ast.IncDecStmt:
				if !checkFamilyWriteExpr(x.X, inAllowedWriter, freshVars, freshEsc) {
					valid = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkFamilyWriteExpr(x.Key, inAllowedWriter, freshVars, freshEsc)) ||
						(x.Value != nil && !checkFamilyWriteExpr(x.Value, inAllowedWriter, freshVars, freshEsc)) {
						valid = false
						return false
					}
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if ix, isIX := ast.Unparen(be).(*ast.IndexExpr); isIX && !isRootedAtFreshLocal(p, ix, freshVars, freshEsc) {
							if hitSt, _ := lhsRootFamilyField(p, ix, allProtected); hitSt != nil {
								if elemT := p.TypesInfo.TypeOf(ix); elemT != nil && types.IsInterface(elemT) {
									valid = false
									return false
								}
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkFamilyWriteExpr(x.Args[0], inAllowedWriter, freshVars, freshEsc) {
								valid = false
								return false
							}
							if (b.Name() == "append" || b.Name() == "copy") && !isRootedAtFreshLocal(p, x.Args[0], freshVars, freshEsc) {
								if hitSt, _ := lhsRootFamilyField(p, x.Args[0], allProtected); hitSt != nil {
									if sl, isSl := types.Unalias(p.TypesInfo.TypeOf(x.Args[0])).Underlying().(*types.Slice); isSl && types.IsInterface(sl.Elem()) {
										if b.Name() == "copy" {
											if len(x.Args) < 2 {
												valid = false
												return false
											}
											if srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected); srcHit == nil || srcFld == nil || srcFld.Exported() {
												valid = false
												return false
											}
										} else if x.Ellipsis.IsValid() {
											if len(x.Args) != 2 {
												valid = false
												return false
											}
											srcHit, srcFld := lhsRootFamilyField(p, x.Args[1], allProtected)
											if srcHit == nil || srcFld == nil || srcFld.Exported() {
												valid = false
												return false
											}
										} else {
											for _, elemArg := range x.Args[1:] {
												if !isSafeProtectedIfaceElemValue(p, elemArg, allProtected, isImmPtr) {
													valid = false
													return false
												}
											}
										}
									}
								}
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op != token.AND {
					return true
				}
				if builderExempt[x] || isRootedAtFreshLocal(p, x.X, freshVars, freshEsc) {
					return true
				}
				if sel, isSel := ast.Unparen(x.X).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal && !selectionCrossesEmbeddedPointer(selInfo) {
						hitFamily := false
						forEachSelectionHopStruct(selInfo, func(st *types.Named) {
							if family[st] {
								hitFamily = true
							}
						})
						if hitFamily {
							fld, _ := selInfo.Obj().(*types.Var)
							if fld == flagField {
								// Allowed only as arg[0] of sync/atomic.LoadUint32 or (in onceCone) StoreUint32.
								call, isCall := idx.parentUnparen(x).(*ast.CallExpr)
								if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != x {
									valid = false
									return false
								}
								if isAtomicUint32Call(p, call, "LoadUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								if inAllowedWriter && isAtomicUint32Call(p, call, "StoreUint32") {
									if exempt != nil {
										exempt[x] = true
									}
									return true
								}
								valid = false
								return false
							}
							// Allow returning/observing &recv.<unexportedByValueStructField> (such as
							// &mi.methods or &xi.desc) solely outside onceCone/builderInitFn after a
							// dominating fast-path once-initialization check on recv, recording the
							// field's struct type in GuardTypes so any mutation anywhere in the
							// package graph revokes the role proof.
							if fld != nil && !fld.Exported() && !inAllowedWriter &&
								syncEncl != nil && !idx.inFuncLit[x] && !idx.inGoStmt[x] {
								if fldNamed, isFN := types.Unalias(fld.Type()).(*types.Named); isFN && casHelperStructs[fldNamed] != nil {
									valid = false
									return false
								}
								if _, isPtr := types.Unalias(fld.Type()).(*types.Pointer); !isPtr {
									if subRef, _, subSt, okSub := typeRefOfStruct(fld.Type()); okSub && subRef.Valid() && subSt.NumFields() > 0 &&
										funcEstablishesOnceInitBefore(p, idx, syncEncl, sel.X, x.Pos(), rootNamed, flagField, onceFn, fastInitMethods) {
										guardOK := true
										forEachValueContainedStructType(fld.Type(), func(vt types.Type) {
											if vRef, _, vSt, okV := typeRefOfStruct(vt); okV && vSt.NumFields() > 0 {
												if !vRef.Valid() {
													guardOK = false
													return
												}
												guardSet[vRef] = true
											}
										})
										if guardOK {
											guardSet[subRef] = true
											if exempt != nil {
												exempt[x] = true
											}
											return true
										}
									}
								}
							}
							valid = false
							return false
						}
					}
				}
				if hitSt, _ := lhsRootFamilyField(p, x.X, allProtected); hitSt != nil {
					valid = false
					return false
				}
			}
			return true
		})
	}
	if !valid {
		return nil, false
	}

	if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			hitSt, fld := lhsRootFamilyField(p, containerExpr, allProtected)
			return hitSt != nil && fld != nil && !fld.Exported()
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false, false
			}
			if isInsideExemptWriteOrAddr(idx, sel, builderExempt) {
				return false, false
			}
			syncEncl := idx.syncEnclFuncDecl(sel)
			freshVars, freshEsc := getFreshLocals(syncEncl)
			if isRootedAtFreshLocal(p, sel, freshVars, freshEsc) {
				return false, false
			}
			var enclFn *types.Func
			if syncEncl != nil {
				enclFn, _ = p.TypesInfo.Defs[syncEncl.Name].(*types.Func)
			}
			inAllowedWriter := enclFn != nil && (onceCone[enclFn] || enclFn == builderInitFn)
			fld, _ := selInfo.Obj().(*types.Var)
			hitProtected := false
			hitExportedFamily := false
			forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if allProtected[hop] {
					hitProtected = true
				}
				if family[hop] && fld != nil && fld.Exported() {
					hitExportedFamily = true
				}
			})
			if !hitProtected {
				return false, false
			}
			if inAllowedWriter && !(hitExportedFamily && !allowExportedWriteInCone) {
				return false, false
			}
			ft := selInfo.Type()
			if fn, isFN := types.Unalias(ft).(*types.Named); isFN && casHelperStructs[fn] != nil {
				return false, false
			}
			if IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && isReflectTypeOfCall(p, call)
		},
	}) {
		return nil, false
	}
	var guardTypes []TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].key() < guardTypes[j].key() })
	}
	return guardTypes, true
}

func collectFastOnceWrapperMethods(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	rootNamed *types.Named,
	onceFn *types.Func,
	flagField *types.Var,
) map[*types.Func]bool {
	out := map[*types.Func]bool{}
	if rootNamed == nil || onceFn == nil || flagField == nil {
		return out
	}
	pset := types.NewMethodSet(types.NewPointer(rootNamed))
	for i := 0; i < pset.Len(); i++ {
		m, ok := pset.At(i).Obj().(*types.Func)
		if !ok || m == onceFn || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		sig, okSig := m.Type().(*types.Signature)
		if !okSig || sig.Params().Len() != 0 {
			continue
		}
		fd := idx.funcDecls[m]
		if fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
			continue
		}
		recvVar, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
		if recvVar == nil || !isPtrToNamed(recvVar.Type(), rootNamed) {
			continue
		}
		if stmtsEstablishOnceInitOnVar(p, fd.Body, recvVar, nil, 0, fd.Body.End(), flagField, onceFn, nil) {
			out[m] = true
		}
	}
	return out
}

func funcEstablishesOnceInitBefore(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	recvExpr ast.Expr,
	beforePos token.Pos,
	rootNamed *types.Named,
	flagField *types.Var,
	onceFn *types.Func,
	fastInitMethods map[*types.Func]bool,
) bool {
	if fd == nil || fd.Body == nil || rootNamed == nil || onceFn == nil || flagField == nil {
		return false
	}
	targetVar, getterFn, ok := extractRootTargetAndGetter(p, idx, rootNamed, onceConeSetForGetter(p, idx, onceFn), recvExpr)
	if !ok || targetVar == nil {
		return false
	}

	// Verify targetVar is a single-assignment parameter/receiver or top-level := local
	// with zero reassignments, &targetVar address-takes, closures, or gotos in fd.Body.
	isSigVar := false
	if fn, okFn := p.TypesInfo.Defs[fd.Name].(*types.Func); okFn && fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() == targetVar {
				isSigVar = true
			}
			for i := 0; i < sig.Params().Len(); i++ {
				if sig.Params().At(i) == targetVar {
					isSigVar = true
				}
			}
		}
	}
	var defEnd token.Pos
	if !isSigVar {
		foundTopDef := false
		for _, st := range fd.Body.List {
			as, isAs := st.(*ast.AssignStmt)
			if !isAs || as.Tok != token.DEFINE {
				continue
			}
			for _, lhs := range as.Lhs {
				if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && p.TypesInfo.Defs[lid] == targetVar {
					if foundTopDef {
						return false
					}
					foundTopDef = true
					defEnd = st.End()
				}
			}
		}
		if !foundTopDef {
			return false
		}
	}

	mutatedOrAliased := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if mutatedOrAliased || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.BranchStmt:
			if s.Tok == token.GOTO {
				mutatedOrAliased = true
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				lid, isID := ast.Unparen(lhs).(*ast.Ident)
				if !isID {
					continue
				}
				if s.Tok == token.ASSIGN && p.TypesInfo.Uses[lid] == targetVar {
					mutatedOrAliased = true
					return false
				}
				if s.Tok == token.DEFINE && isSigVar && p.TypesInfo.Defs[lid] == targetVar {
					mutatedOrAliased = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if isIdentUsingObj(p, s.X, targetVar) {
				mutatedOrAliased = true
				return false
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN &&
				((s.Key != nil && isIdentUsingObj(p, s.Key, targetVar)) ||
					(s.Value != nil && isIdentUsingObj(p, s.Value, targetVar))) {
				mutatedOrAliased = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND && isIdentUsingObj(p, s.X, targetVar) {
				mutatedOrAliased = true
				return false
			}
		case *ast.Ident:
			if (p.TypesInfo.Uses[s] == targetVar || p.TypesInfo.Defs[s] == targetVar) && (idx.inFuncLit[s] || idx.inGoStmt[s]) {
				mutatedOrAliased = true
				return false
			}
			if getterFn != nil && p.TypesInfo.Uses[s] == targetVar && s.Pos() <= beforePos {
				sel, isSel := idx.parentUnparen(s).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != s || p.TypesInfo.Uses[sel.Sel] != getterFn {
					mutatedOrAliased = true
					return false
				}
				call, isCall := idx.parentUnparen(sel).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != sel || len(call.Args) != 0 {
					mutatedOrAliased = true
					return false
				}
			}
		}
		return true
	})
	if mutatedOrAliased {
		return false
	}

	return stmtsEstablishOnceInitOnVar(p, fd.Body, targetVar, getterFn, defEnd, beforePos, flagField, onceFn, fastInitMethods)
}

func onceConeSetForGetter(p *packages.Package, idx *pkgSyntaxIndex, onceFn *types.Func) map[*types.Func]bool {
	if onceFn == nil {
		return nil
	}
	return computeExclusiveHelperCone(p, idx, onceFn)
}

func extractRootTargetAndGetter(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	rootNamed *types.Named,
	onceCone map[*types.Func]bool,
	expr ast.Expr,
) (*types.Var, *types.Func, bool) {
	expr = ast.Unparen(expr)
	if id, isID := expr.(*ast.Ident); isID {
		v, ok := p.TypesInfo.Uses[id].(*types.Var)
		if !ok || v == nil || v.IsField() || v.Parent() == p.Types.Scope() || !isPtrToNamed(v.Type(), rootNamed) {
			return nil, nil, false
		}
		return v, nil, true
	}
	call, isCall := expr.(*ast.CallExpr)
	if !isCall || len(call.Args) != 0 {
		return nil, nil, false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel {
		return nil, nil, false
	}
	id, isID := ast.Unparen(sel.X).(*ast.Ident)
	if !isID {
		return nil, nil, false
	}
	v, okV := p.TypesInfo.Uses[id].(*types.Var)
	if !okV || v == nil || v.IsField() || v.Parent() == p.Types.Scope() {
		return nil, nil, false
	}
	fn, okF := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !okF || fn == nil || !isPureLocalRootGetterMethod(p, idx, rootNamed, v.Type(), fn, onceCone) {
		return nil, nil, false
	}
	return v, fn, true
}

func isPureLocalRootGetterMethod(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	rootNamed *types.Named,
	recvType types.Type,
	fn *types.Func,
	onceCone map[*types.Func]bool,
) bool {
	if fn == nil || fn.Exported() || fn.Pkg() != p.Types {
		return false
	}
	wrapNamed := derefNamedStruct(recvType)
	if wrapNamed == nil || wrapNamed.Obj() == nil || wrapNamed.Obj().Pkg() != p.Types || wrapNamed.Obj().Exported() {
		return false
	}
	if _, isPtr := types.Unalias(recvType).(*types.Pointer); !isPtr {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	if !isPtrToNamed(sig.Recv().Type(), wrapNamed) || !isPtrToNamed(sig.Results().At(0).Type(), rootNamed) {
		return false
	}
	fd := idx.funcDecls[fn]
	if fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	mRecv, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if mRecv == nil {
		return false
	}
	stmts := fd.Body.List
	// Shape 1: single `return mRecv.<unexportedField>` where the field and its enclosing structs are never mutated in p.
	if len(stmts) == 1 {
		ret, isRet := stmts[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 {
			return false
		}
		sel, isSel := ast.Unparen(ret.Results[0]).(*ast.SelectorExpr)
		if !isSel || !isIdentUsingObj(p, sel.X, mRecv) {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		fld, _ := selInfo.Obj().(*types.Var)
		if fld == nil || fld.Exported() || !isPtrToNamed(fld.Type(), rootNamed) {
			return false
		}
		return !unexportedWrapperFieldMutatedInPkg(p, idx, fld, false, nil)
	}
	// Shape 2: `mi := mRecv.loadHelper(); [if mi == nil { panic(...) };] return mi`
	// where loadHelper atomically loads an unexported *rootNamed field never written inside onceCone.
	if len(stmts) != 2 && len(stmts) != 3 {
		return false
	}
	as, isAs := stmts[0].(*ast.AssignStmt)
	if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	locID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
	if !isID {
		return false
	}
	locVar, _ := p.TypesInfo.Defs[locID].(*types.Var)
	if locVar == nil || !isPtrToNamed(locVar.Type(), rootNamed) {
		return false
	}
	lcall, isCall := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
	if !isCall || len(lcall.Args) != 0 {
		return false
	}
	lsel, isLSel := ast.Unparen(lcall.Fun).(*ast.SelectorExpr)
	if !isLSel || !isIdentUsingObj(p, lsel.X, mRecv) {
		return false
	}
	loadFn, _ := p.TypesInfo.Uses[lsel.Sel].(*types.Func)
	fld := atomicLoadRootPtrField(p, idx, wrapNamed, rootNamed, loadFn)
	if fld == nil {
		return false
	}
	if len(stmts) == 3 {
		ifs, isIf := stmts[1].(*ast.IfStmt)
		if !isIf || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL ||
			!((isIdentUsingObj(p, bin.X, locVar) && isNilIdent(p, bin.Y)) ||
				(isNilIdent(p, bin.X) && isIdentUsingObj(p, bin.Y, locVar))) {
			return false
		}
		es, isES := ifs.Body.List[0].(*ast.ExprStmt)
		if !isES {
			return false
		}
		pcall, isPC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isPC {
			return false
		}
		pid, isPID := ast.Unparen(pcall.Fun).(*ast.Ident)
		if !isPID {
			return false
		}
		b, isB := p.TypesInfo.Uses[pid].(*types.Builtin)
		if !isB || b.Name() != "panic" {
			return false
		}
	}
	ret, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 || !isIdentUsingObj(p, ret.Results[0], locVar) {
		return false
	}
	return !unexportedWrapperFieldMutatedInPkg(p, idx, fld, true, onceCone)
}

func atomicLoadRootPtrField(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	wrapNamed, rootNamed *types.Named,
	fn *types.Func,
) *types.Var {
	if fn == nil || fn.Pkg() != p.Types {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil
	}
	if !isPtrToNamed(sig.Recv().Type(), wrapNamed) || !isPtrToNamed(sig.Results().At(0).Type(), rootNamed) {
		return nil
	}
	fd := idx.funcDecls[fn]
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 1 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return nil
	}
	recvVar, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if recvVar == nil {
		return nil
	}
	ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 {
		return nil
	}
	// Expect (*RootNamed)(atomic.LoadPointer(...(&recvVar.fld)...)).
	conv, isConv := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !isPtrToNamed(p.TypesInfo.Types[conv.Fun].Type, rootNamed) {
		return nil
	}
	lcall, isLC := ast.Unparen(conv.Args[0]).(*ast.CallExpr)
	if !isLC || len(lcall.Args) != 1 {
		return nil
	}
	lsel, isLS := ast.Unparen(lcall.Fun).(*ast.SelectorExpr)
	if !isLS {
		return nil
	}
	afn, isAF := p.TypesInfo.Uses[lsel.Sel].(*types.Func)
	if !isAF || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "LoadPointer" {
		return nil
	}
	cur := ast.Unparen(lcall.Args[0])
	for range 2 {
		c, isC := cur.(*ast.CallExpr)
		if !isC || len(c.Args) != 1 || !p.TypesInfo.Types[c.Fun].IsType() {
			break
		}
		cur = ast.Unparen(c.Args[0])
	}
	un, isUn := cur.(*ast.UnaryExpr)
	if !isUn || un.Op != token.AND {
		return nil
	}
	fsel, isFS := ast.Unparen(un.X).(*ast.SelectorExpr)
	if !isFS || !isIdentUsingObj(p, fsel.X, recvVar) {
		return nil
	}
	selInfo := p.TypesInfo.Selections[fsel]
	if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
		return nil
	}
	fld, _ := selInfo.Obj().(*types.Var)
	if fld == nil || fld.Exported() || !isPtrToNamed(fld.Type(), rootNamed) {
		return nil
	}
	return fld
}

func unexportedWrapperFieldMutatedInPkg(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fld *types.Var,
	allowDetachedAtomicStore bool,
	onceCone map[*types.Func]bool,
) bool {
	// Identify all named struct types in p.Types that contain fld directly by value.
	holders := map[*types.Named]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i) == fld {
				holders[named] = true
				break
			}
		}
	}
	// Reject any *w = ... whole-struct overwrite on any holder struct in p.Syntax.
	overwritten := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if overwritten || n == nil {
				return false
			}
			as, isAs := n.(*ast.AssignStmt)
			if !isAs {
				return true
			}
			for _, lhs := range as.Lhs {
				if star, isStar := ast.Unparen(lhs).(*ast.StarExpr); isStar {
					if st := derefNamedStruct(p.TypesInfo.TypeOf(star.X)); st != nil && holders[st] {
						overwritten = true
						return false
					}
				}
			}
			return true
		})
	}
	if overwritten {
		return true
	}

	for _, id := range idx.usesOf[fld] {
		// Composite literal key `Struct{fld: val}` has parent KeyValueExpr — initialization, not mutation!
		if kv, isKV := idx.parentUnparen(id).(*ast.KeyValueExpr); isKV && kv.Key == id {
			continue
		}
		sel, isSel := idx.parentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return true
		}
		if identOrExprIsWritten(idx, sel) {
			return true
		}
		if un, isUn := idx.parentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			if isPureAtomicLoadArg(p, idx, un) {
				continue
			}
			if allowDetachedAtomicStore && isDetachedAtomicStoreOnField(p, idx, un, onceCone) {
				continue
			}
			return true
		}
	}
	return false
}

func isDetachedAtomicStoreOnField(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	addrExpr *ast.UnaryExpr,
	onceCone map[*types.Func]bool,
) bool {
	arg := ast.Expr(addrExpr)
	par := idx.parentUnparen(addrExpr)
	for range 2 {
		conv, isConv := par.(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || ast.Unparen(conv.Args[0]) != arg || !p.TypesInfo.Types[conv.Fun].IsType() {
			break
		}
		arg = conv
		par = idx.parentUnparen(conv)
	}
	call, isCall := par.(*ast.CallExpr)
	if !isCall || len(call.Args) != 2 || ast.Unparen(call.Args[0]) != arg {
		return false
	}
	csel, isCS := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isCS {
		return false
	}
	afn, isAF := p.TypesInfo.Uses[csel.Sel].(*types.Func)
	if !isAF || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "StorePointer" {
		return false
	}
	encl := idx.syncEnclFuncDecl(addrExpr)
	if encl == nil {
		return false
	}
	enclFn, _ := p.TypesInfo.Defs[encl.Name].(*types.Func)
	if enclFn == nil || onceCone[enclFn] {
		return false
	}
	// Require zero intra-package callers of enclFn so onceCone/impl cannot overwrite the field mid-method.
	return len(idx.usesOf[enclFn]) == 0
}

func stmtsEstablishOnceInitOnVar(
	p *packages.Package,
	body *ast.BlockStmt,
	targetVar *types.Var,
	getterFn *types.Func,
	afterPos, beforePos token.Pos,
	flagField *types.Var,
	onceFn *types.Func,
	fastInitMethods map[*types.Func]bool,
) bool {
	if body == nil {
		return false
	}
	hasGoto := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hasGoto || n == nil {
			return false
		}
		if br, ok := n.(*ast.BranchStmt); ok && br.Tok == token.GOTO {
			hasGoto = true
			return false
		}
		return true
	})
	if hasGoto {
		return false
	}
	matchesTargetRecv := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if getterFn == nil {
			return isIdentUsingObj(p, expr, targetVar)
		}
		gcall, ok := expr.(*ast.CallExpr)
		if !ok || len(gcall.Args) != 0 {
			return false
		}
		gsel, ok := ast.Unparen(gcall.Fun).(*ast.SelectorExpr)
		if !ok || !isIdentUsingObj(p, gsel.X, targetVar) {
			return false
		}
		return p.TypesInfo.Uses[gsel.Sel] == getterFn
	}
	isZeroArgInitCallOnVar := func(st ast.Stmt) bool {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := ast.Unparen(es.X).(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !matchesTargetRecv(sel.X) {
			return false
		}
		fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
		if !ok || fn == nil {
			return false
		}
		return fn == onceFn || fastInitMethods[fn]
	}

	stmts := body.List
	for i, st := range stmts {
		if afterPos != token.NoPos && st.Pos() < afterPos {
			continue
		}
		if st.End() > beforePos {
			break
		}
		if isZeroArgInitCallOnVar(st) {
			return true
		}
		if getterFn != nil {
			continue
		}
		ifs, ok := st.(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			continue
		}
		holdsAtZero, okCond := condHoldsAtZeroUint32Load(p, ifs.Cond, targetVar, flagField)
		if !okCond {
			continue
		}
		if holdsAtZero && isZeroArgInitCallOnVar(ifs.Body.List[0]) {
			return true
		}
		if !holdsAtZero {
			if _, isRet := ifs.Body.List[0].(*ast.ReturnStmt); isRet && i+1 < len(stmts) && stmts[i+1].End() <= beforePos && isZeroArgInitCallOnVar(stmts[i+1]) {
				return true
			}
		}
	}
	return false
}

func condHoldsAtZeroUint32Load(p *packages.Package, cond ast.Expr, targetVar, flagField *types.Var) (bool, bool) {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return false, false
	}
	isFlagLoad := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		return ok && len(call.Args) == 1 && isAtomicUint32Call(p, call, "LoadUint32") && isAddrOfRecvField(p, call.Args[0], targetVar, flagField)
	}
	constUint := func(expr ast.Expr) (uint64, bool) {
		tv, ok := p.TypesInfo.Types[expr]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int || constant.Sign(tv.Value) < 0 {
			return 0, false
		}
		return constant.Uint64Val(tv.Value)
	}
	op := bin.Op
	var c uint64
	var okC bool
	if isFlagLoad(bin.X) {
		c, okC = constUint(bin.Y)
	} else if isFlagLoad(bin.Y) {
		c, okC = constUint(bin.X)
		switch op {
		case token.LSS:
			op = token.GTR
		case token.LEQ:
			op = token.GEQ
		case token.GTR:
			op = token.LSS
		case token.GEQ:
			op = token.LEQ
		}
	}
	if !okC {
		return false, false
	}
	switch op {
	case token.EQL:
		return c == 0, true
	case token.NEQ:
		return c != 0, true
	case token.LSS:
		return c > 0, true
	case token.LEQ:
		return true, true
	case token.GTR:
		return false, true
	case token.GEQ:
		return c == 0, true
	default:
		return false, false
	}
}

func hasDeprecatedExtensionFields(family map[*types.Named]bool) bool {
	for n := range family {
		st, ok := n.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		hasExt, hasTag := false, false
		for i := 0; i < st.NumFields(); i++ {
			switch st.Field(i).Name() {
			case "ExtendedType":
				hasExt = true
			case "ExtensionType":
				hasTag = true
			}
		}
		if hasExt && hasTag {
			return true
		}
	}
	return false
}

func lhsRootFamilyField(p *packages.Package, expr ast.Expr, family map[*types.Named]bool) (*types.Named, *types.Var) {
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				var matched *types.Named
				forEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if matched == nil && family[st] {
						matched = st
					}
				})
				if matched != nil {
					fld, _ := selInfo.Obj().(*types.Var)
					return matched, fld
				}
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		default:
			return nil, nil
		}
	}
}

// -----------------------------------------------------------------------------
// Family 3B: gRPC ServiceDesc package variables
// -----------------------------------------------------------------------------

func deriveGrpcServiceVars(audited bool, p *packages.Package, idx *pkgSyntaxIndex) []GrpcServiceVarFact {
	var out []GrpcServiceVarFact
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !TypeMayCarryUnknownDynamic(audited, v.Type()) || idx.defCounts[v] != 1 {
			continue
		}
		svcRef, svcNamed, okRef := typeRefOfNamedStruct(v.Type())
		if !okRef {
			continue
		}
		// Must be by-value struct variable (not pointer).
		if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); isPtr {
			continue
		}
		methodRef, streamRef, okShape := verifyGrpcServiceStructShape(svcNamed)
		if !okShape {
			continue
		}
		vs := idx.varSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
		if !ok || !types.Identical(types.Unalias(p.TypesInfo.TypeOf(comp)), svcNamed) {
			continue
		}
		if !verifyGrpcServiceCompositeLit(p, comp) {
			continue
		}
		if !verifyGrpcServiceVarUses(p, idx, v) {
			continue
		}
		out = append(out, GrpcServiceVarFact{
			Key:        dynamicVarKey(v),
			SvcDesc:    svcRef,
			MethodDesc: methodRef,
			StreamDesc: streamRef,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func verifyGrpcServiceStructShape(svcNamed *types.Named) (methodRef, streamRef TypeRef, ok bool) {
	st, isSt := svcNamed.Underlying().(*types.Struct)
	if !isSt {
		return TypeRef{}, TypeRef{}, false
	}
	hasServiceName := false
	hasHandlerType := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			return TypeRef{}, TypeRef{}, false
		}
		switch f.Name() {
		case "ServiceName":
			b, isB := types.Unalias(f.Type()).Underlying().(*types.Basic)
			if !isB || b.Kind() != types.String {
				return TypeRef{}, TypeRef{}, false
			}
			hasServiceName = true
		case "HandlerType":
			if !types.IsInterface(f.Type()) {
				return TypeRef{}, TypeRef{}, false
			}
			hasHandlerType = true
		case "Methods":
			mRef, okM := sliceElemStructRef(f.Type())
			if !okM {
				return TypeRef{}, TypeRef{}, false
			}
			methodRef = mRef
		case "Streams":
			sRef, okS := sliceElemStructRef(f.Type())
			if !okS {
				return TypeRef{}, TypeRef{}, false
			}
			streamRef = sRef
		case "Metadata":
		default:
			return TypeRef{}, TypeRef{}, false
		}
	}
	if !hasServiceName || !hasHandlerType || (methodRef.IsZero() && streamRef.IsZero()) {
		return TypeRef{}, TypeRef{}, false
	}
	return methodRef, streamRef, true
}

func verifyGrpcServiceCompositeLit(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "ServiceName":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil || tv.Value.Kind() != constant.String {
				return false
			}
		case "Metadata":
			if !isNilIdent(p, val) {
				if tv := p.TypesInfo.Types[val]; tv.Value == nil {
					return false
				}
			}
		case "HandlerType":
			// Typed-nil pointer to interface: (*SvcServer)(nil)
			call, isCall := val.(*ast.CallExpr)
			if !isCall || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() || !isNilIdent(p, call.Args[0]) {
				return false
			}
			ptr, isPtr := types.Unalias(p.TypesInfo.Types[call.Fun].Type).(*types.Pointer)
			if !isPtr || !types.IsInterface(ptr.Elem()) {
				return false
			}
		case "Methods", "Streams":
			slComp, isComp := val.(*ast.CompositeLit)
			if !isComp {
				return false
			}
			for _, item := range slComp.Elts {
				itemComp, isIC := ast.Unparen(item).(*ast.CompositeLit)
				if !isIC || !verifyGrpcEntryCompositeLit(p, itemComp) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func verifyGrpcEntryCompositeLit(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "MethodName", "StreamName", "ServerStreams", "ClientStreams":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil {
				return false
			}
		case "Handler":
			id, isID := val.(*ast.Ident)
			if !isID {
				return false
			}
			fn, isFn := p.TypesInfo.Uses[id].(*types.Func)
			if !isFn || fn.Pkg() != p.Types {
				return false
			}
			if sig, okSig := fn.Type().(*types.Signature); !okSig || sig.Recv() != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func verifyGrpcServiceVarUses(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	for _, id := range idx.usesOf[v] {
		// Direct assignment, range-assign, or ++ to v is forbidden; &v IS allowed (e.g. s.RegisterService(&Svc_ServiceDesc, srv))
		// because *ptr = ... and ptr.Field = ... are tracked globally in MutatedStructTypes.
		par := idx.parentUnparen(id)
		if as, isAs := par.(*ast.AssignStmt); isAs {
			for _, lhs := range as.Lhs {
				if ast.Unparen(lhs) == id {
					return false
				}
			}
		}
		if inc, isInc := par.(*ast.IncDecStmt); isInc && ast.Unparen(inc.X) == id {
			return false
		}
		if rng, isRng := par.(*ast.RangeStmt); isRng && rng.Tok == token.ASSIGN &&
			((rng.Key != nil && ast.Unparen(rng.Key) == id) || (rng.Value != nil && ast.Unparen(rng.Value) == id)) {
			return false
		}
		// Walk outward through field/index chains rooted at id to ensure v.Field or v.Methods[i] is never mutated in place.
		cur := ast.Node(id)
		for {
			next := idx.parentUnparen(cur)
			switch nx := next.(type) {
			case *ast.SelectorExpr:
				if ast.Unparen(nx.X) == cur {
					cur = nx
					continue
				}
			case *ast.IndexExpr:
				if ast.Unparen(nx.X) == cur {
					cur = nx
					continue
				}
			case *ast.SliceExpr:
				if ast.Unparen(nx.X) == cur {
					return false
				}
			case *ast.UnaryExpr:
				if nx.Op == token.AND && cur != id && ast.Unparen(nx.X) == cur {
					// &Desc.Streams[0] / &Desc.Methods[0] is *StreamDesc / *MethodDesc (pointer to a named struct
					// governed globally by MutatedStructTypes, as emitted by protoc-gen-go-grpc streaming stubs);
					// taking the address of a slice/scalar field (&Desc.Methods, &Desc.ServiceName) is rejected.
					curExpr, isExpr := cur.(ast.Expr)
					if !isExpr {
						return false
					}
					curType := types.Unalias(p.TypesInfo.TypeOf(curExpr))
					if _, isPtr := curType.(*types.Pointer); isPtr || derefNamedStruct(curType) == nil {
						return false
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range nx.Lhs {
					if ast.Unparen(lhs) == cur && cur != id {
						return false
					}
				}
			case *ast.IncDecStmt:
				if ast.Unparen(nx.X) == cur {
					return false
				}
			case *ast.RangeStmt:
				if nx.Tok == token.ASSIGN &&
					((nx.Key != nil && ast.Unparen(nx.Key) == cur) || (nx.Value != nil && ast.Unparen(nx.Value) == cur)) {
					return false
				}
			case *ast.CallExpr:
				isArg := false
				for _, arg := range nx.Args {
					if ast.Unparen(arg) == cur {
						isArg = true
						break
					}
				}
				if isArg {
					if cid, isID := ast.Unparen(nx.Fun).(*ast.Ident); isID {
						if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && (b.Name() == "len" || b.Name() == "cap") {
							break
						}
					}
					curExpr, isExpr := cur.(ast.Expr)
					if !isExpr {
						return false
					}
					if b, isBasic := types.Unalias(p.TypesInfo.TypeOf(curExpr)).Underlying().(*types.Basic); !isBasic || b.Kind() == types.UnsafePointer {
						return false
					}
				}
			}
			break
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Cross-package struct-mutation summary (MutatedStructTypes)
// -----------------------------------------------------------------------------

func collectMutatedStructTypes(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
) ([]TypeRef, []ConditionalStructMutation) {
	seen := map[TypeRef]bool{}
	condSeen := map[ConditionalStructMutation]bool{}
	recordStructAt := func(at ast.Node, t types.Type) {
		ref, named, st, ok := typeRefOfStruct(t)
		if !ok || st == nil || (named == nil && st.NumFields() == 0) || !ref.Valid() {
			return
		}
		if named != nil {
			if syncFD := idx.syncEnclFuncDecl(at); syncFD != nil && exemptFamilyByFunc[syncFD][named] {
				return
			}
		}
		seen[ref] = true
	}
	recordNamedContainerAt := func(_ ast.Node, t types.Type) {
		if t == nil {
			return
		}
		n, isN := types.Unalias(t).(*types.Named)
		if !isN || n.Obj() == nil || n.Obj().Pkg() == nil || n.Obj().Parent() != n.Obj().Pkg().Scope() {
			return
		}
		switch n.Underlying().(type) {
		case *types.Slice, *types.Map:
			ref := TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
			if ref.Valid() {
				seen[ref] = true
			}
		}
	}
	recordEscapedArgTypes := func(at ast.Node, root types.Type, includeUnexportedFields bool) {
		syncFD := idx.syncEnclFuncDecl(at)
		type visitKey struct {
			t           types.Type
			addressable bool
		}
		visited := map[visitKey]bool{}
		var walk func(t types.Type, addressable bool)
		walk = func(t types.Type, addressable bool) {
			if t == nil {
				return
			}
			t = types.Unalias(t)
			if named, isNamed := t.(*types.Named); isNamed && syncFD != nil && exemptFamilyByFunc[syncFD][named] {
				return
			}
			vk := visitKey{t: t, addressable: addressable}
			if visited[vk] {
				return
			}
			visited[vk] = true
			if addressable {
				if _, isSt := t.Underlying().(*types.Struct); isSt {
					recordStructAt(at, t)
				}
			}
			switch u := t.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem(), true)
			case *types.Slice:
				recordNamedContainerAt(at, t)
				walk(u.Elem(), true)
			case *types.Map:
				recordNamedContainerAt(at, t)
				walk(u.Key(), false)
				walk(u.Elem(), true)
			case *types.Chan:
				walk(u.Elem(), false)
			case *types.Array:
				walk(u.Elem(), addressable)
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					f := u.Field(i)
					if !includeUnexportedFields && !f.Exported() && !f.Embedded() {
						if addressable {
							forEachValueContainedStructType(f.Type(), func(vt types.Type) {
								recordStructAt(at, vt)
							})
						} else if TypeCarriesMutableRef(f.Type()) {
							if tNamed, isTN := t.(*types.Named); isTN && tNamed.Obj() != nil && !tNamed.Obj().Exported() {
								recordStructAt(at, t)
							}
						}
						continue
					}
					walk(f.Type(), addressable)
				}
			}
		}
		walk(root, false)
	}
	recordReflectiveArgTypes := func(at ast.Node, root types.Type) {
		recordEscapedArgTypes(at, root, false)
	}
	recordGenericArgTypes := func(at ast.Node, root types.Type) {
		recordEscapedArgTypes(at, root, true)
	}

	pkgFresh := computePackageFreshConstructors(p, idx)
	for cm := range pkgFresh.condGuards {
		if cm.Valid() {
			condSeen[cm] = true
		}
	}

	type freshFuncInfo struct {
		vars      map[*types.Var]bool
		escapePos map[*types.Var]token.Pos
	}
	freshLocalsByFunc := map[*ast.FuncDecl]freshFuncInfo{}
	getFresh := func(fd *ast.FuncDecl) (map[*types.Var]bool, map[*types.Var]token.Pos) {
		if fd == nil {
			return nil, nil
		}
		if info, ok := freshLocalsByFunc[fd]; ok {
			return info.vars, info.escapePos
		}
		vars, esc := collectFreshLocalStructVars(p, idx, fd)
		freshLocalsByFunc[fd] = freshFuncInfo{vars: vars, escapePos: esc}
		return vars, esc
	}
	isFreshMutTarget := func(fd *ast.FuncDecl, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if isRootedAtFreshLocal(p, expr, fresh, freshEsc) {
			return true
		}
		return pkgFresh.isFreshMutationTarget(fd, expr)
	}
	isFreshAddrTarget := func(fd *ast.FuncDecl, inner ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) bool {
		if isRootedAtFreshLocal(p, inner, fresh, freshEsc) {
			return true
		}
		return pkgFresh.isFreshAddrOrValue(fd, inner)
	}

	recordMutatedExpr := func(at ast.Node, expr ast.Expr, fresh map[*types.Var]bool, freshEsc map[*types.Var]token.Pos) {
		syncFD := idx.syncEnclFuncDecl(at)
		if isFreshMutTarget(syncFD, expr, fresh, freshEsc) {
			return
		}
		if syncFD != nil && isByValueFieldChainOnExemptFamily(p, expr, exemptFamilyByFunc[syncFD]) {
			return
		}
		cur := ast.Unparen(expr)
		first := true
		for {
			switch e := cur.(type) {
			case *ast.StarExpr:
				if first {
					forEachValueContainedStructType(p.TypesInfo.TypeOf(e.X), func(vt types.Type) {
						recordStructAt(at, vt)
					})
					if ptr, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).Underlying().(*types.Pointer); isPtr {
						elem := types.Unalias(ptr.Elem())
						forEachValueContainedStructType(elem, func(vt types.Type) {
							recordStructAt(at, vt)
						})
						if sl, isSl := elem.Underlying().(*types.Slice); isSl {
							forEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
								recordStructAt(at, vt)
							})
						}
					}
				}
				return
			case *ast.SelectorExpr:
				if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					forEachSelectionHopStructType(selInfo, func(vt types.Type) {
						recordStructAt(at, vt)
					})
					if first {
						forEachValueContainedStructType(selInfo.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
					if selectionCrossesEmbeddedPointer(selInfo) {
						return
					}
					if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
						return
					}
					cur = ast.Unparen(e.X)
					first = false
					continue
				}
				// Package-qualified variable: pkg.Desc = ...
				if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
						recordNamedContainerAt(at, v.Type())
						forEachValueContainedStructType(v.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
				}
				return
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() &&
					v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
						recordNamedContainerAt(at, v.Type())
						forEachValueContainedStructType(v.Type(), func(vt types.Type) {
							recordStructAt(at, vt)
						})
					}
				}
				return
			case *ast.IndexExpr:
				// Writing slice[i] = ... mutates the slice's struct element type (if []S), any named container type, AND any enclosing struct holding that slice/map field!
				if first {
					forEachValueContainedStructType(p.TypesInfo.TypeOf(e), func(vt types.Type) {
						recordStructAt(at, vt)
					})
				}
				recordNamedContainerAt(at, p.TypesInfo.TypeOf(e.X))
				cur = ast.Unparen(e.X)
				first = false
				continue
			case *ast.SliceExpr:
				recordNamedContainerAt(at, p.TypesInfo.TypeOf(e.X))
				cur = ast.Unparen(e.X)
				first = false
				continue
			default:
				return
			}
		}
	}

	recordUnsafeSliceArg := func(at ast.Node, arg ast.Expr) {
		argT := p.TypesInfo.TypeOf(arg)
		recordStructAt(at, argT)
		if ptr, isPtr := types.Unalias(argT).Underlying().(*types.Pointer); isPtr {
			forEachValueContainedStructType(ptr.Elem(), func(vt types.Type) {
				recordStructAt(at, vt)
			})
		}
	}

	unexportedForeignRecvStruct := func(callee *types.Func) *types.Named {
		if callee == nil {
			return nil
		}
		orig := callee.Origin()
		if orig.Pkg() == nil || orig.Pkg() == p.Types {
			return nil
		}
		sig, okSig := orig.Type().(*types.Signature)
		if !okSig || sig.Recv() == nil {
			return nil
		}
		ptr, isPtr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
		if !isPtr {
			return nil
		}
		named, isN := types.Unalias(ptr.Elem()).(*types.Named)
		if !isN || named.Obj() == nil || named.Obj().Exported() {
			return nil
		}
		if _, isSt := named.Underlying().(*types.Struct); !isSt {
			return nil
		}
		return named
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if exempted[n] {
				return true
			}
			syncEncl := idx.syncEnclFuncDecl(n)
			fresh, freshEsc := getFresh(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					recordMutatedExpr(x, lhs, fresh, freshEsc)
					if (syncEncl == nil || syncEncl.Name == nil || syncEncl.Name.Name != "init") && rootPkgScopeVar(p, lhs) != nil {
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) {
							rhs := x.Rhs[i]
							if !isFreshAddrTarget(syncEncl, rhs, fresh, freshEsc) && !isNilIdent(p, rhs) && !isTypedNilSliceConv(p, rhs) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(rhs))
							}
						}
					}
				}
			case *ast.IncDecStmt:
				recordMutatedExpr(x, x.X, fresh, freshEsc)
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if x.Key != nil {
						recordMutatedExpr(x, x.Key, fresh, freshEsc)
					}
					if x.Value != nil {
						recordMutatedExpr(x, x.Value, fresh, freshEsc)
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && !isFreshAddrTarget(syncEncl, x.X, fresh, freshEsc) {
					inner := ast.Unparen(x.X)
					switch in := inner.(type) {
					case *ast.SelectorExpr:
						if selInfo := p.TypesInfo.Selections[in]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							_, _, subSt, isSubStruct := typeRefOfStruct(selInfo.Type())
							if !(isSubStruct && subSt.NumFields() > 0 && !selInfo.Obj().Exported()) && !isPureAtomicLoadArg(p, idx, x) {
								recordMutatedExpr(x, in, fresh, freshEsc)
							}
						}
					case *ast.IndexExpr:
						_, _, elemSt, isElemStruct := typeRefOfStruct(p.TypesInfo.TypeOf(in))
						if !(isElemStruct && elemSt.NumFields() > 0) {
							recordMutatedExpr(x, in, fresh, freshEsc)
						}
					}
				}
			case *ast.CallExpr:
				if tv := p.TypesInfo.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
					dstT := types.Unalias(tv.Type)
					srcT := types.Unalias(p.TypesInfo.TypeOf(x.Args[0]))
					if _, isSrcNamed := srcT.(*types.Named); isSrcNamed && !types.Identical(dstT, srcT) &&
						!isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !isNilIdent(p, x.Args[0]) && !isTypedNilSliceConv(p, x.Args[0]) {
						recordNamedContainerAt(x, srcT)
					}
					if b, isB := dstT.Underlying().(*types.Basic); isB && b.Kind() == types.UnsafePointer {
						if !isSafeAtomicPointerValueArg(p, idx, x) && !isPureAtomicLoadInnerConv(p, idx, x) && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							if ptr, isPtr := types.Unalias(p.TypesInfo.TypeOf(x.Args[0])).Underlying().(*types.Pointer); isPtr {
								forEachValueContainedStructType(ptr.Elem(), func(vt types.Type) {
									recordStructAt(x, vt)
								})
							}
						}
					} else if dstPtr, isDstPtr := dstT.Underlying().(*types.Pointer); isDstPtr {
						if srcPtr, isSrcPtr := types.Unalias(p.TypesInfo.TypeOf(x.Args[0])).Underlying().(*types.Pointer); isSrcPtr {
							dstElem := types.Unalias(dstPtr.Elem())
							srcElem := types.Unalias(srcPtr.Elem())
							if !types.Identical(dstElem, srcElem) && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
								if _, isSt := srcElem.Underlying().(*types.Struct); isSt {
									forEachValueContainedStructType(srcElem, func(vt types.Type) {
										recordStructAt(x, vt)
									})
								}
							}
						}
					}
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if len(x.Args) > 0 {
								recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
								if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !isNilIdent(p, x.Args[0]) && !isTypedNilSliceConv(p, x.Args[0]) {
									recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
								}
								if (b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
									if sl, isSl := types.Unalias(p.TypesInfo.TypeOf(x.Args[0])).Underlying().(*types.Slice); isSl {
										forEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
											recordStructAt(x, vt)
										})
									}
								}
							}
						case "SliceData":
							if len(x.Args) > 0 && !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !isNilIdent(p, x.Args[0]) && !isTypedNilSliceConv(p, x.Args[0]) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
							}
						case "Slice":
							if len(x.Args) > 0 {
								recordUnsafeSliceArg(x, x.Args[0])
							}
						}
						return true
					}
				} else if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if b, isB := p.TypesInfo.Uses[sel.Sel].(*types.Builtin); isB && len(x.Args) > 0 {
						switch b.Name() {
						case "Slice":
							recordUnsafeSliceArg(x, x.Args[0])
							return true
						case "SliceData":
							if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !isNilIdent(p, x.Args[0]) && !isTypedNilSliceConv(p, x.Args[0]) {
								recordNamedContainerAt(x, p.TypesInfo.TypeOf(x.Args[0]))
							}
							return true
						}
					}
				}
				if callee := resolveCalledFuncObj(p, x.Fun); callee != nil {
					if recvSt := unexportedForeignRecvStruct(callee); recvSt != nil {
						if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
							if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil {
								switch selInfo.Kind() {
								case types.MethodVal:
									if !isFreshAddrTarget(syncEncl, sel.X, fresh, freshEsc) {
										recordStructAt(x, recvSt)
										recordMutatedExpr(x, sel.X, fresh, freshEsc)
									}
								case types.MethodExpr:
									if len(x.Args) == 0 || !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
										recordStructAt(x, recvSt)
										if len(x.Args) > 0 {
											recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
										}
									}
								}
							}
						}
					}
					if callee.Pkg() != nil && callee.Pkg().Path() == "reflect" && callee.Name() == "ValueOf" && len(x.Args) == 1 {
						if !isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							recordReflectiveArgTypes(x, p.TypesInfo.TypeOf(x.Args[0]))
						}
					} else {
						origSig, _ := callee.Type().(*types.Signature)
						isGeneric := origSig != nil && (origSig.TypeParams().Len() > 0 || origSig.RecvTypeParams().Len() > 0)
						isCmp := callee.Pkg() != nil && callee.Pkg().Path() == "cmp"
						if sig, okSig := p.TypesInfo.TypeOf(x.Fun).(*types.Signature); okSig {
							type argEntry struct {
								expr ast.Expr
								typ  types.Type
							}
							var argEntries []argEntry
							if len(x.Args) == 1 {
								if tup, isTup := p.TypesInfo.TypeOf(x.Args[0]).(*types.Tuple); isTup {
									for ti := 0; ti < tup.Len(); ti++ {
										argEntries = append(argEntries, argEntry{typ: tup.At(ti).Type()})
									}
								}
							}
							if argEntries == nil {
								for _, arg := range x.Args {
									argEntries = append(argEntries, argEntry{expr: arg, typ: p.TypesInfo.TypeOf(arg)})
								}
							}
							for ai, ae := range argEntries {
								if ae.expr != nil && isFreshAddrTarget(syncEncl, ae.expr, fresh, freshEsc) {
									continue
								}
								pi := ai
								if sig.Variadic() && ai >= sig.Params().Len()-1 {
									pi = sig.Params().Len() - 1
								}
								if pi < sig.Params().Len() {
									pt := types.Unalias(sig.Params().At(pi).Type())
									if sig.Variadic() && ai >= sig.Params().Len()-1 && !x.Ellipsis.IsValid() {
										if sl, isSl := pt.Underlying().(*types.Slice); isSl {
											pt = types.Unalias(sl.Elem())
										}
									}
									if isGeneric && !isCmp && origSig != nil && pi < origSig.Params().Len() {
										origPT := types.Unalias(origSig.Params().At(pi).Type())
										if origSig.Variadic() && ai >= origSig.Params().Len()-1 && !x.Ellipsis.IsValid() {
											if sl, isSl := origPT.Underlying().(*types.Slice); isSl {
												origPT = types.Unalias(sl.Elem())
											}
										}
										if typeMentionsTypeParam(origPT) {
											recordGenericArgTypes(x, ae.typ)
											continue
										}
									}
									if !isReadOnlyEmptyInterfaceCallee(callee) {
										if iface, isIf := pt.Underlying().(*types.Interface); isIf && iface.NumMethods() == 0 {
											recordReflectiveArgTypes(x, ae.typ)
										}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}

	// Also account for generic functions or methods instantiated as first-class function values
	// (e.g. fn := setPtr[grpc.ServiceDesc]; fn(&pb.Svc_ServiceDesc, ...)).
	directCallFuns := map[ast.Node]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				cur := ast.Unparen(call.Fun)
				directCallFuns[cur] = true
				switch e := cur.(type) {
				case *ast.IndexExpr:
					directCallFuns[ast.Unparen(e.X)] = true
				case *ast.IndexListExpr:
					directCallFuns[ast.Unparen(e.X)] = true
				}
			}
			return true
		})
	}
	for id, inst := range p.TypesInfo.Instances {
		if directCallFuns[id] {
			continue
		}
		fnObj, ok := p.TypesInfo.Uses[id].(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		orig := fnObj.Origin()
		if orig.Pkg() != nil && orig.Pkg().Path() == "cmp" {
			continue
		}
		instSig, okInst := types.Unalias(inst.Type).Underlying().(*types.Signature)
		origSig, okOrig := orig.Type().(*types.Signature)
		if !okInst || !okOrig {
			continue
		}
		for pi := 0; pi < instSig.Params().Len() && pi < origSig.Params().Len(); pi++ {
			if typeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				recordGenericArgTypes(id, instSig.Params().At(pi).Type())
			}
		}
	}
	for selExpr, selInfo := range p.TypesInfo.Selections {
		if directCallFuns[selExpr] || selInfo == nil || (selInfo.Kind() != types.MethodVal && selInfo.Kind() != types.MethodExpr) {
			continue
		}
		fnObj, ok := selInfo.Obj().(*types.Func)
		if !ok || fnObj == nil {
			continue
		}
		if recvSt := unexportedForeignRecvStruct(fnObj); recvSt != nil {
			syncEncl := idx.syncEnclFuncDecl(selExpr)
			fresh, freshEsc := getFresh(syncEncl)
			recordStructAt(selExpr, recvSt)
			if selInfo.Kind() == types.MethodVal {
				recordMutatedExpr(selExpr, selExpr.X, fresh, freshEsc)
			}
		}
		orig := fnObj.Origin()
		origSig, okOrig := orig.Type().(*types.Signature)
		instSig, okInst := types.Unalias(selInfo.Type()).Underlying().(*types.Signature)
		if !okOrig || !okInst || origSig.RecvTypeParams().Len() == 0 {
			continue
		}
		offset := 0
		if selInfo.Kind() == types.MethodExpr {
			offset = 1
		}
		for pi := 0; pi < origSig.Params().Len() && pi+offset < instSig.Params().Len(); pi++ {
			if typeMentionsTypeParam(origSig.Params().At(pi).Type()) {
				recordGenericArgTypes(selExpr, instSig.Params().At(pi+offset).Type())
			}
		}
	}

	// Track aliased mutations on exported reference-carrying fields whose element is
	// not a non-empty struct (such as MessageInfo.OneofWrappers []any), where
	// element-level mutations cannot be observed via a distinct element struct TypeRef.
	// Pointers to non-empty structs (*S) are already tracked directly by their own
	// struct TypeRef in MutatedStructTypes.
	exportedRefSelsByOwner := map[TypeRef]map[*ast.SelectorExpr]bool{}
	isStructTrackedPtr := func(t types.Type) bool {
		if t == nil {
			return false
		}
		ptr, isP := types.Unalias(t).(*types.Pointer)
		if !isP {
			return false
		}
		_, _, st, ok := typeRefOfStruct(ptr.Elem())
		return ok && st != nil && st.NumFields() > 0
	}
	isNonEmptyStructElemSeq := func(t types.Type) bool {
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Slice:
			_, _, elemSt, isSt := typeRefOfStruct(u.Elem())
			return isSt && elemSt.NumFields() > 0
		case *types.Array:
			_, _, elemSt, isSt := typeRefOfStruct(u.Elem())
			return isSt && elemSt.NumFields() > 0
		}
		return false
	}
	for selExpr, selInfo := range p.TypesInfo.Selections {
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || !selInfo.Obj().Exported() {
			continue
		}
		if fv, isFV := selInfo.Obj().(*types.Var); isFV && exemptReadFields[fv] {
			continue
		}
		ft := selInfo.Type()
		if !TypeCarriesMutableRefWith(ft, isStructTrackedPtr) || isNonEmptyStructElemSeq(ft) {
			continue
		}
		if isInsideExemptWriteOrAddr(idx, selExpr, exempted) {
			continue
		}
		if parAs, isAs := idx.parentUnparen(selExpr).(*ast.AssignStmt); isAs {
			onLHS := false
			for _, lhs := range parAs.Lhs {
				if ast.Unparen(lhs) == selExpr {
					onLHS = true
					break
				}
			}
			if onLHS {
				continue
			}
		}
		syncEncl := idx.syncEnclFuncDecl(selExpr)
		fresh, freshEsc := getFresh(syncEncl)
		if isFreshAddrTarget(syncEncl, selExpr, fresh, freshEsc) {
			continue
		}
		forEachSelectionHopStruct(selInfo, func(hop *types.Named) {
			if hop == nil || (syncEncl != nil && exemptFamilyByFunc[syncEncl][hop]) {
				return
			}
			ref, _, hopSt, okHop := typeRefOfStruct(hop)
			if !okHop || !ref.Valid() || hopSt.NumFields() == 0 || seen[ref] {
				return
			}
			if exportedRefSelsByOwner[ref] == nil {
				exportedRefSelsByOwner[ref] = map[*ast.SelectorExpr]bool{}
			}
			exportedRefSelsByOwner[ref][selExpr] = true
		})
	}
	for ownerRef, selSet := range exportedRefSelsByOwner {
		if seen[ownerRef] {
			continue
		}
		var pendingConds []ConditionalStructMutation
		if !VerifyReadOnlyRefConfinement(p, RefConfineConfig{
			IsImmutablePtr:                isStructTrackedPtr,
			AllowReturnFromUnexportedFunc: true,
			IsExemptField: func(fv *types.Var) bool {
				return fv != nil && exemptReadFields[fv]
			},
			AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
				ct := p.TypesInfo.TypeOf(containerExpr)
				if ct == nil {
					return false
				}
				var elemT types.Type
				switch u := types.Unalias(ct).Underlying().(type) {
				case *types.Slice:
					elemT = u.Elem()
				case *types.Array:
					elemT = u.Elem()
				case *types.Map:
					elemT = u.Elem()
				default:
					return false
				}
				iface, okI := types.Unalias(elemT).Underlying().(*types.Interface)
				return okI && iface.NumMethods() > 0
			},
			AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
				if callee == nil || call.Ellipsis.IsValid() {
					return false
				}
				orig := callee.Origin()
				sig, okSig := orig.Type().(*types.Signature)
				if !okSig || sig.Recv() == nil {
					return false
				}
				recvT := types.Unalias(sig.Recv().Type())
				if _, isPtr := recvT.(*types.Pointer); isPtr {
					return false
				}
				rn, isRN := recvT.(*types.Named)
				if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
					return false
				}
				if _, isSl := rn.Underlying().(*types.Slice); !isSl {
					return false
				}
				for _, a := range call.Args {
					at := p.TypesInfo.TypeOf(a)
					if typeContainsRefOrPointerWith(at, isStructTrackedPtr) && !types.Identical(types.Unalias(at), rn) {
						return false
					}
				}
				for ri := 0; ri < sig.Results().Len(); ri++ {
					if typeContainsRefOrPointerWith(sig.Results().At(ri).Type(), isStructTrackedPtr) {
						return false
					}
				}
				sliceRef := TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
				if !sliceRef.Valid() {
					return false
				}
				guardPkg := ""
				if orig.Pkg() != nil {
					guardPkg = orig.Pkg().Path()
				}
				pendingConds = append(pendingConds, ConditionalStructMutation{
					Struct:      ownerRef,
					GuardPkg:    guardPkg,
					GuardStruct: sliceRef,
				})
				return true
			},
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel || !selSet[sel] {
					return false, false
				}
				ft := p.TypesInfo.TypeOf(sel)
				return IsDirectMutableRefWith(ft, isStructTrackedPtr), true
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
				return argIdx == 0 && len(call.Args) == 1 && !call.Ellipsis.IsValid() && isReflectTypeOfCall(p, call)
			},
			AllowAssignTarget: func(lhs, _ ast.Expr, rhsIsRef bool) bool {
				if rhsIsRef {
					return false
				}
				sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !isSel {
					return false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false
				}
				syncEncl := idx.syncEnclFuncDecl(lhs)
				fresh, freshEsc := getFresh(syncEncl)
				if !isFreshMutTarget(syncEncl, lhs, fresh, freshEsc) {
					return false
				}
				stNamed, isN := types.Unalias(p.TypesInfo.TypeOf(lhs)).(*types.Named)
				if !isN || !isOpaqueUnexportedForeignStruct(p.Types, stNamed) {
					return false
				}
				guardRef := TypeRef{Pkg: stNamed.Obj().Pkg().Path(), Name: stNamed.Obj().Name()}
				if !guardRef.Valid() {
					return false
				}
				pendingConds = append(pendingConds, ConditionalStructMutation{
					Struct:                  ownerRef,
					GuardStruct:             guardRef,
					RequireDescBuilderGuard: true,
				})
				return true
			},
		}) {
			seen[ownerRef] = true
		} else {
			for _, cm := range pendingConds {
				if cm.Valid() {
					condSeen[cm] = true
				}
			}
		}
	}

	var out []TypeRef
	if len(seen) > 0 {
		out = make([]TypeRef, 0, len(seen))
		for ref := range seen {
			out = append(out, ref)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	}
	var condOut []ConditionalStructMutation
	if len(condSeen) > 0 {
		condOut = make([]ConditionalStructMutation, 0, len(condSeen))
		for cm := range condSeen {
			if !seen[cm.Struct] {
				condOut = append(condOut, cm)
			}
		}
		if len(condOut) == 0 {
			condOut = nil
		} else {
			slices.SortFunc(condOut, ConditionalStructMutation.Compare)
		}
	}
	return out, condOut
}

// collectFreshLocalStructVars returns local (non-global) variables in fd whose
// every assignment/initialization in fd.Body constructs a fresh, unaliased struct
// value or pointer (var v S, v := S{...}, v := &S{...}, v := new(S), or a
// non-address-taken stack-private carrier-free value struct parameter/result),
// along with each variable's first non-selection escape position in fd.Body.
func collectFreshLocalStructVars(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
) (map[*types.Var]bool, map[*types.Var]token.Pos) {
	if fd == nil || fd.Body == nil {
		return nil, nil
	}
	if funcBodyHasGoto(fd.Body) {
		return nil, nil
	}

	hasNonEmptyStructElem := func(t types.Type) bool {
		_, st := derefAnyStructType(t)
		return st != nil && st.NumFields() > 0
	}
	isStackPrivateValueStruct := func(t types.Type) bool {
		if t == nil {
			return false
		}
		if _, isPtr := types.Unalias(t).(*types.Pointer); isPtr {
			return false
		}
		return hasNonEmptyStructElem(t) && !TypeContainsRefOrPointer(t)
	}

	params := map[*types.Var]bool{}
	stackValueVars := map[*types.Var]bool{}
	if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() != nil {
				v := sig.Recv()
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
			for i := 0; i < sig.Params().Len(); i++ {
				v := sig.Params().At(i)
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
			for i := 0; i < sig.Results().Len(); i++ {
				v := sig.Results().At(i)
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
		}
	}
	candidates := map[*types.Var]bool{}
	disqualified := map[*types.Var]bool{}
	declPos := map[*types.Var]token.Pos{}
	for v := range stackValueVars {
		candidates[v] = true
		declPos[v] = fd.Body.Pos()
	}

	isAliasableFieldType := func(t types.Type) bool {
		return TypeCarriesMutableRef(t)
	}
	var isFreshFieldInit func(expr ast.Expr) bool
	isFreshFieldInit = func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if isNilIdent(p, expr) {
			return true
		}
		switch e := expr.(type) {
		case *ast.CompositeLit:
			for _, elt := range e.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					val = kv.Value
				}
				if isAliasableFieldType(p.TypesInfo.TypeOf(val)) && !isFreshFieldInit(val) {
					return false
				}
			}
			return true
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
					return isFreshFieldInit(cl)
				}
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
				if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && (b.Name() == "new" || b.Name() == "make") {
					return true
				}
			}
		}
		return false
	}

	isFreshStructAlloc := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.CompositeLit:
			return hasNonEmptyStructElem(p.TypesInfo.TypeOf(e)) && isFreshFieldInit(e)
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
					return hasNonEmptyStructElem(p.TypesInfo.TypeOf(cl)) && isFreshFieldInit(cl)
				}
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok && len(e.Args) == 1 {
				if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "new" {
					return hasNonEmptyStructElem(p.TypesInfo.TypeOf(e))
				}
			}
		}
		return false
	}

	rootLocalIdent := func(expr ast.Expr) *types.Var {
		cur := ast.Unparen(expr)
		for {
			switch e := cur.(type) {
			case *ast.Ident:
				v, _ := p.TypesInfo.Uses[e].(*types.Var)
				return v
			case *ast.SelectorExpr:
				cur = ast.Unparen(e.X)
			case *ast.IndexExpr:
				cur = ast.Unparen(e.X)
			case *ast.SliceExpr:
				cur = ast.Unparen(e.X)
			case *ast.StarExpr:
				cur = ast.Unparen(e.X)
			default:
				return nil
			}
		}
	}

	addrTaken := map[*types.Var]bool{}
	var loops []ast.Node
	var defers []*ast.DeferStmt

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			loops = append(loops, s)
		case *ast.RangeStmt:
			loops = append(loops, s)
			if s.Key != nil {
				if v := lookupIdentVar(p, s.Key); v != nil && !stackValueVars[v] {
					disqualified[v] = true
				}
			}
			if s.Value != nil {
				if v := lookupIdentVar(p, s.Value); v != nil && !stackValueVars[v] {
					disqualified[v] = true
				}
			}
		case *ast.DeferStmt:
			defers = append(defers, s)
		case *ast.ValueSpec:
			for i, nm := range s.Names {
				v, ok := p.TypesInfo.Defs[nm].(*types.Var)
				if !ok || v == nil || params[v] || v.Parent() == p.Types.Scope() {
					continue
				}
				if idx.defCounts[v] != 1 || idx.inFuncLit[nm] || idx.inGoStmt[nm] {
					disqualified[v] = true
					continue
				}
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
					candidates[v] = true
					declPos[v] = nm.Pos()
					continue
				}
				if len(s.Values) == 0 {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && hasNonEmptyStructElem(v.Type()) {
						candidates[v] = true
						declPos[v] = nm.Pos()
					} else {
						disqualified[v] = true
					}
				} else if i < len(s.Values) && isFreshStructAlloc(s.Values[i]) {
					candidates[v] = true
					declPos[v] = nm.Pos()
				} else {
					disqualified[v] = true
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := lookupIdentVar(p, s.X); v != nil {
					disqualified[v] = true
				}
				if rv := rootLocalIdent(s.X); rv != nil {
					addrTaken[rv] = true
				}
			}
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				for _, l := range s.Lhs {
					if v := lookupIdentVar(p, l); v != nil && !stackValueVars[v] {
						disqualified[v] = true
					}
				}
				return true
			}
			for i, l := range s.Lhs {
				if v := lookupIdentVar(p, l); v != nil && v.Parent() != p.Types.Scope() {
					if stackValueVars[v] {
						if idx.inFuncLit[l] || idx.inGoStmt[l] {
							disqualified[v] = true
						}
						continue
					}
					if params[v] {
						disqualified[v] = true
						continue
					}
					lid, isID := ast.Unparen(l).(*ast.Ident)
					if !isID || p.TypesInfo.Defs[lid] != v || s.Tok == token.ASSIGN ||
						idx.defCounts[v] != 1 || idx.inFuncLit[l] || idx.inGoStmt[l] || !isFreshStructAlloc(s.Rhs[i]) {
						disqualified[v] = true
					} else {
						candidates[v] = true
						declPos[v] = lid.Pos()
					}
					continue
				}
				// If assigning an aliasable field on a candidate local (v.sub = ptrOrSlice), require fresh RHS!
				if rv := rootLocalIdent(l); rv != nil && isAliasableFieldType(p.TypesInfo.TypeOf(l)) && !isFreshFieldInit(s.Rhs[i]) {
					disqualified[rv] = true
				}
			}
		}
		return true
	})

	escapePos := map[*types.Var]token.Pos{}
	for v := range candidates {
		if disqualified[v] {
			delete(candidates, v)
			continue
		}
		if stackValueVars[v] {
			if addrTaken[v] {
				delete(candidates, v)
				continue
			}
			badClosure := false
			for _, id := range idx.usesOf[v] {
				if idx.inFuncLit[id] || idx.inGoStmt[id] {
					badClosure = true
					break
				}
			}
			if badClosure {
				delete(candidates, v)
			}
			continue
		}
		dpos := declPos[v]
		usedInDefer := false
		for _, id := range idx.usesOf[v] {
			if idx.inFuncLit[id] || idx.inGoStmt[id] {
				delete(candidates, v)
				delete(escapePos, v)
				break
			}
			for _, df := range defers {
				if df.Pos() <= id.Pos() && id.Pos() < df.End() {
					usedInDefer = true
					break
				}
			}
			par := idx.parentUnparen(id)
			if sel, isSel := par.(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == id {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					continue
				}
			}
			if star, isStar := par.(*ast.StarExpr); isStar && ast.Unparen(star.X) == id {
				continue
			}
			useEsc := id.Pos()
			for _, lp := range loops {
				if lp.Pos() <= id.Pos() && id.Pos() < lp.End() && !(lp.Pos() <= dpos && dpos < lp.End()) {
					if lp.Pos() < useEsc {
						useEsc = lp.Pos()
					}
				}
			}
			if prev, exists := escapePos[v]; !exists || useEsc < prev {
				escapePos[v] = useEsc
			}
		}
		if _, hasEsc := escapePos[v]; hasEsc && (addrTaken[v] || usedInDefer) {
			delete(candidates, v)
			delete(escapePos, v)
		}
	}
	return candidates, escapePos
}

func isRootedAtFreshLocal(
	p *packages.Package,
	expr ast.Expr,
	fresh map[*types.Var]bool,
	escapePos map[*types.Var]token.Pos,
) bool {
	if len(fresh) == 0 {
		return false
	}
	checkVar := func(v *types.Var) bool {
		if v == nil || !fresh[v] {
			return false
		}
		if esc, hasEsc := escapePos[v]; hasEsc && esc != token.NoPos && expr.Pos() >= esc {
			return false
		}
		return true
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			return checkVar(v)
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				if selectionCrossesEmbeddedPointer(selInfo) {
					return false
				}
				// Do not cross pointer fields on a fresh local (except the root local pointer itself).
				if _, isIdent := ast.Unparen(e.X).(*ast.Ident); !isIdent {
					if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
						return false
					}
				}
				cur = ast.Unparen(e.X)
				continue
			}
			return false
		case *ast.IndexExpr:
			if _, isArr := types.Unalias(p.TypesInfo.TypeOf(e.X)).Underlying().(*types.Array); isArr {
				cur = ast.Unparen(e.X)
				continue
			}
			return false
		case *ast.StarExpr:
			if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
				v, _ := p.TypesInfo.Uses[id].(*types.Var)
				return checkVar(v)
			}
			return false
		default:
			return false
		}
	}
}

func funcBodyHasGoto(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	hasGoto := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hasGoto || n == nil {
			return false
		}
		if br, ok := n.(*ast.BranchStmt); ok && br.Tok == token.GOTO {
			hasGoto = true
			return false
		}
		return true
	})
	return hasGoto
}

// -----------------------------------------------------------------------------
// Intra-package fresh constructor tree analysis (computePackageFreshConstructors)
// -----------------------------------------------------------------------------

type freshVarState struct {
	rootVar    *types.Var // root fresh variable (either v itself or the parent slice/struct v aliases via &parent[i] / &parent.Field)
	declPos    token.Pos  // position where freshness begins (for dominating top-level overwrite fd = &slice[n], stmt.End())
	escapePos  token.Pos  // earliest external escape position in fd.Body (token.NoPos if never escapes externally)
	isValSlice bool       // true when v has []Struct or StructSlice type
}

type freshFuncSummary struct {
	fd             *ast.FuncDecl
	fn             *types.Func
	vars           map[*types.Var]*freshVarState
	nonFreshFields map[*types.Var]bool // reference fields (*T, []T, map[K]V) ever assigned non-fresh values or &field-taken in this cone
	coneCallees    map[*types.Func]bool
	condGuards     map[ConditionalStructMutation]bool
}

type pkgFreshConstructors struct {
	p          *packages.Package
	idx        *pkgSyntaxIndex
	funcs      map[*ast.FuncDecl]*freshFuncSummary
	condGuards map[ConditionalStructMutation]bool
}

func recordFreshVarGuardPkg(sum *freshFuncSummary, v *types.Var, guardPkg string) {
	if sum == nil || v == nil || guardPkg == "" || isStandardLibraryPkgPath(guardPkg) {
		return
	}
	if sum.condGuards == nil {
		sum.condGuards = map[ConditionalStructMutation]bool{}
	}
	addForType := func(t types.Type) {
		if t == nil {
			return
		}
		u := types.Unalias(t)
		if named, isN := u.(*types.Named); isN && named.Obj() != nil && named.Obj().Pkg() != nil {
			if sl, isSl := named.Underlying().(*types.Slice); isSl && !TypeContainsRefOrPointer(sl.Elem()) {
				cm := ConditionalStructMutation{
					Struct:   TypeRef{Pkg: named.Obj().Pkg().Path(), Name: named.Obj().Name()},
					GuardPkg: guardPkg,
				}
				if cm.Valid() {
					sum.condGuards[cm] = true
				}
			}
		}
		if sl, isSl := u.Underlying().(*types.Slice); isSl {
			u = types.Unalias(sl.Elem())
		}
		ref, _, st, ok := typeRefOfStruct(u)
		if ok && st != nil && st.NumFields() > 0 && ref.Valid() {
			cm := ConditionalStructMutation{Struct: ref, GuardPkg: guardPkg}
			if cm.Valid() {
				sum.condGuards[cm] = true
			}
		}
	}
	addForType(v.Type())
	if st := sum.vars[v]; st != nil && st.rootVar != nil && st.rootVar != v {
		addForType(st.rootVar.Type())
	}
}

func (pf *pkgFreshConstructors) isFreshMutationTarget(fd *ast.FuncDecl, expr ast.Expr) bool {
	if pf == nil || fd == nil || expr == nil {
		return false
	}
	sum := pf.funcs[fd]
	if sum == nil || len(sum.vars) == 0 {
		return false
	}
	// Assigning lhs = rhs mutates the container/struct owning the outermost step of lhs:
	//   - base.Field = rhs mutates base (without needing Field itself to hold a fresh ref!)
	//   - slice[i] = rhs mutates slice
	//   - *ptr = rhs mutates ptr's pointee
	cur := ast.Unparen(expr)
	switch e := cur.(type) {
	case *ast.SelectorExpr:
		selInfo := pf.p.TypesInfo.Selections[e]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.IndexExpr:
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.SliceExpr:
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.StarExpr:
		if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
			v, _ := pf.p.TypesInfo.Uses[id].(*types.Var)
			return pf.checkVarLiveAt(sum, v, expr.Pos())
		}
		return false
	}
	return false
}

func (pf *pkgFreshConstructors) isFreshAddrOrValue(fd *ast.FuncDecl, expr ast.Expr) bool {
	if pf == nil || fd == nil || expr == nil {
		return false
	}
	sum := pf.funcs[fd]
	if sum == nil || len(sum.vars) == 0 {
		return false
	}
	return pf.isFreshContainerAt(sum, expr, expr.Pos())
}

func (pf *pkgFreshConstructors) checkVarLiveAt(sum *freshFuncSummary, v *types.Var, pos token.Pos) bool {
	if sum == nil || v == nil {
		return false
	}
	st := sum.vars[v]
	if st == nil {
		return false
	}
	if st.declPos != token.NoPos && pos < st.declPos {
		return false
	}
	rootSt := sum.vars[st.rootVar]
	if rootSt == nil {
		rootSt = st
	}
	if st.escapePos != token.NoPos && pos >= st.escapePos {
		return false
	}
	if rootSt.escapePos != token.NoPos && pos >= rootSt.escapePos {
		return false
	}
	return true
}

func (pf *pkgFreshConstructors) isFreshContainerAt(sum *freshFuncSummary, expr ast.Expr, pos token.Pos) bool {
	cur := ast.Unparen(expr)
	first := true
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := pf.p.TypesInfo.Uses[e].(*types.Var)
			return pf.checkVarLiveAt(sum, v, pos) && pf.checkVarLiveAt(sum, v, e.Pos())
		case *ast.UnaryExpr:
			if e.Op == token.AND && first {
				cur = ast.Unparen(e.X)
				first = false
				continue
			}
			return false
		case *ast.StarExpr:
			if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
				v, _ := pf.p.TypesInfo.Uses[id].(*types.Var)
				return pf.checkVarLiveAt(sum, v, pos) && pf.checkVarLiveAt(sum, v, id.Pos())
			}
			return false
		case *ast.SelectorExpr:
			selInfo := pf.p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
				return false
			}
			fObj, _ := selInfo.Obj().(*types.Var)
			if fObj == nil {
				return false
			}
			if isRefOrContainerType(fObj.Type()) && sum.nonFreshFields[fObj] {
				return false
			}
			// If e.X is a pointer and not a root local Ident, e.X must itself be a fresh-verified pointer field SelectorExpr!
			if _, isPtr := types.Unalias(pf.p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
				if _, isID := ast.Unparen(e.X).(*ast.Ident); !isID {
					xSel, isXSel := ast.Unparen(e.X).(*ast.SelectorExpr)
					if !isXSel {
						return false
					}
					xInfo := pf.p.TypesInfo.Selections[xSel]
					if xInfo == nil || xInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(xInfo) {
						return false
					}
					xfObj, _ := xInfo.Obj().(*types.Var)
					if xfObj == nil || sum.nonFreshFields[xfObj] {
						return false
					}
				}
			}
			cur = ast.Unparen(e.X)
			first = false
			continue
		case *ast.IndexExpr:
			xt := types.Unalias(pf.p.TypesInfo.TypeOf(e.X)).Underlying()
			switch u := xt.(type) {
			case *types.Array:
				cur = ast.Unparen(e.X)
				first = false
				continue
			case *types.Slice:
				// Only cross by-value struct elements of a fresh slice (never []*Ptr elements).
				if _, isPtrElem := types.Unalias(u.Elem()).(*types.Pointer); isPtrElem {
					return false
				}
				_, elemSt := derefAnyStructType(u.Elem())
				if elemSt == nil || elemSt.NumFields() == 0 {
					return false
				}
				cur = ast.Unparen(e.X)
				first = false
				continue
			}
			return false
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
			first = false
			continue
		default:
			return false
		}
	}
}

func isRefOrContainerType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Interface:
		return true
	}
	return false
}

func isFreshConstructableRootType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if ptr, isPtr := u.Underlying().(*types.Pointer); isPtr {
		_, st := derefAnyStructType(ptr.Elem())
		return st != nil && st.NumFields() > 0
	}
	if sl, isSl := u.Underlying().(*types.Slice); isSl {
		if _, isPtrElem := types.Unalias(sl.Elem()).(*types.Pointer); isPtrElem {
			return false
		}
		if _, st := derefAnyStructType(sl.Elem()); st != nil && st.NumFields() > 0 {
			return true
		}
		if _, isNamed := u.(*types.Named); isNamed && !TypeContainsRefOrPointer(sl.Elem()) {
			return true
		}
		return false
	}
	_, st := derefAnyStructType(u)
	return st != nil && st.NumFields() > 0
}

func computePackageFreshConstructors(p *packages.Package, idx *pkgSyntaxIndex) *pkgFreshConstructors {
	pf := &pkgFreshConstructors{
		p:     p,
		idx:   idx,
		funcs: map[*ast.FuncDecl]*freshFuncSummary{},
	}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return pf
	}

	// Step 1: Identify mutex-confined intra-package cycle-breaking constructor caches
	// (such as aberrantMessageDescCache guarded by aberrantMessageDescLock in impl).
	confinedCacheMaps := findMutexConfinedConstructorCaches(p, idx)

	// Step 2: Collect eligible intra-package functions (no goto, no go stmt).
	var allFDs []*ast.FuncDecl
	eligibleUnexported := map[*types.Func]*ast.FuncDecl{}
	for fn, fd := range idx.funcDecls {
		if fn == nil || fd == nil || fd.Body == nil || funcBodyHasGoto(fd.Body) {
			continue
		}
		hasGo := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if hasGo || n == nil {
				return false
			}
			if _, isGo := n.(*ast.GoStmt); isGo {
				hasGo = true
				return false
			}
			return true
		})
		if hasGo {
			continue
		}
		allFDs = append(allFDs, fd)
		if !fn.Exported() && fn.Pkg() == p.Types {
			allDirectCalls := true
			for _, uid := range idx.usesOf[fn] {
				if idx.inGoStmt[uid] || idx.inFuncLit[uid] {
					allDirectCalls = false
					break
				}
				par := idx.parentUnparen(uid)
				var call *ast.CallExpr
				if c, isC := par.(*ast.CallExpr); isC && ast.Unparen(c.Fun) == uid {
					call = c
				} else if sel, isS := par.(*ast.SelectorExpr); isS && sel.Sel == uid {
					if c, isC := idx.parentUnparen(sel).(*ast.CallExpr); isC && ast.Unparen(c.Fun) == sel {
						call = c
					}
				}
				if call == nil {
					allDirectCalls = false
					break
				}
			}
			if allDirectCalls {
				eligibleUnexported[fn] = fd
			}
		}
	}

	// Step 3: Identify non-escaping local auxiliary containers (such as r1 := make(descsByName)
	// and r2 := &resolver{local: r1}) and initialize candidate unexported intra-package non-escaping
	// observer/tree helper parameters (refined jointly in Step 4's greatest fixed point).
	nonEscAuxVars := computeLocalNonEscapingAuxVars(p, idx, allFDs, eligibleUnexported)
	nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs := initNonEscapingIntraParams(eligibleUnexported)

	// Step 4: Greatest fixed point for:
	//   - freshReturnFuncs[fn]: unexported intra-package functions returning a fresh struct/slice at result 0
	//   - freshParamFuncs[fn][paramIdx]: unexported intra-package functions whose every call passes a fresh node at paramIdx
	//   - nonEscParams / mapStoreParams / retStructParams / paramGuardPkgs: per-parameter intra-package non-escape summaries
	freshReturnFuncs := map[*types.Func]bool{}
	freshParamFuncs := map[*types.Func]map[int]bool{}
	for fn, fd := range eligibleUnexported {
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig {
			continue
		}
		if sig.Results().Len() == 1 || (sig.Results().Len() == 2 && isErrorType(sig.Results().At(1).Type())) {
			if isFreshConstructableRootType(sig.Results().At(0).Type()) && funcHasReturnStmt(fd.Body) {
				freshReturnFuncs[fn] = true
			}
		}
		if len(idx.usesOf[fn]) > 0 {
			for pi := 0; pi < sig.Params().Len(); pi++ {
				if isFreshConstructableRootType(sig.Params().At(pi).Type()) {
					if freshParamFuncs[fn] == nil {
						freshParamFuncs[fn] = map[int]bool{}
					}
					freshParamFuncs[fn][pi] = true
				}
			}
		}
	}

	buildAllSummaries := func() {
		pf.funcs = make(map[*ast.FuncDecl]*freshFuncSummary, len(allFDs))
		for _, fd := range allFDs {
			fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
			pf.funcs[fd] = analyzeSingleFreshConstructorFunc(
				p,
				idx,
				fd,
				fn,
				freshReturnFuncs,
				freshParamFuncs,
				nonEscParams,
				mapStoreParams,
				retStructParams,
				paramGuardPkgs,
				nonEscAuxVars,
				confinedCacheMaps,
			)
		}
		// Propagate nonFreshFields across intra-package constructor helper call edges to fixed point.
		changedNF := true
		for changedNF {
			changedNF = false
			for _, sum := range pf.funcs {
				if sum == nil {
					continue
				}
				for callee := range sum.coneCallees {
					cfd := idx.funcDecls[callee]
					csum := pf.funcs[cfd]
					if csum == nil {
						continue
					}
					for f := range csum.nonFreshFields {
						if !sum.nonFreshFields[f] {
							sum.nonFreshFields[f] = true
							changedNF = true
						}
					}
					for f := range sum.nonFreshFields {
						if !csum.nonFreshFields[f] {
							csum.nonFreshFields[f] = true
							changedNF = true
						}
					}
				}
			}
		}
	}

	for {
		buildAllSummaries()
		changed := stepNonEscapingIntraParams(
			p,
			idx,
			pf,
			eligibleUnexported,
			freshReturnFuncs,
			nonEscAuxVars,
			confinedCacheMaps,
			nonEscParams,
			mapStoreParams,
			retStructParams,
			paramGuardPkgs,
		)

		// Validate freshReturnFuncs: every ReturnStmt in fn must return nil, a fresh alloc, or a live fresh root var!
		for fn := range freshReturnFuncs {
			fd := eligibleUnexported[fn]
			sum := pf.funcs[fd]
			sig, _ := fn.Type().(*types.Signature)
			if sum == nil || sig == nil {
				delete(freshReturnFuncs, fn)
				changed = true
				continue
			}
			var res0Var *types.Var
			if sig.Results().Len() > 0 {
				res0Var = sig.Results().At(0)
			}
			okRet := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !okRet || n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				if len(ret.Results) == 0 {
					if res0Var == nil || !pf.checkVarLiveAt(sum, res0Var, ret.Pos()) {
						okRet = false
					}
					return false
				}
				r0 := ast.Unparen(ret.Results[0])
				if isNilIdent(p, r0) || isDirectFreshConstructExpr(p, r0, freshReturnFuncs) {
					return false
				}
				if id, isID := r0.(*ast.Ident); isID {
					v, _ := p.TypesInfo.Uses[id].(*types.Var)
					st := sum.vars[v]
					// Must be a fresh root (not an interior &slice[i] alias unless returning the root itself)
					// whose escapePos is not strictly before ret.Pos()!
					if st != nil && st.rootVar == v && (st.declPos == token.NoPos || ret.Pos() >= st.declPos) &&
						(st.escapePos == token.NoPos || ret.Pos() <= st.escapePos) {
						return false
					}
				}
				okRet = false
				return false
			})
			if !okRet {
				delete(freshReturnFuncs, fn)
				changed = true
			}
		}

		// Validate freshParamFuncs: inside fn itself pv must remain unescaped (escapePos == token.NoPos),
		// AND every call site in p.Syntax must pass a fresh container at call.Pos()!
		for fn, pset := range freshParamFuncs {
			if len(pset) == 0 {
				continue
			}
			fnFD := eligibleUnexported[fn]
			fnSum := pf.funcs[fnFD]
			sig, _ := fn.Type().(*types.Signature)
			for pi := range pset {
				if fnSum == nil || sig == nil || pi < 0 || pi >= sig.Params().Len() {
					delete(pset, pi)
					changed = true
					continue
				}
				pv := sig.Params().At(pi)
				pvSt := fnSum.vars[pv]
				if pvSt == nil || pvSt.escapePos != token.NoPos {
					delete(pset, pi)
					changed = true
				}
			}
			if len(pset) == 0 {
				delete(freshParamFuncs, fn)
				continue
			}
			for _, uid := range idx.usesOf[fn] {
				call := enclosingCallOfCalleeIdent(idx, uid)
				callerFD := idx.syncEnclFuncDecl(uid)
				callerSum := pf.funcs[callerFD]
				for pi := range pset {
					offset := 0
					if call != nil {
						if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
							if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodExpr {
								offset = 1
							}
						}
					}
					if call == nil || callerSum == nil || call.Ellipsis.IsValid() || pi+offset >= len(call.Args) ||
						!pf.isFreshContainerAt(callerSum, call.Args[pi+offset], call.Pos()) {
						delete(pset, pi)
						changed = true
					}
				}
			}
			if len(pset) == 0 {
				delete(freshParamFuncs, fn)
			}
		}

		if !changed {
			break
		}
	}
	pf.condGuards = map[ConditionalStructMutation]bool{}
	for _, sum := range pf.funcs {
		if sum == nil {
			continue
		}
		for cm := range sum.condGuards {
			pf.condGuards[cm] = true
		}
	}
	return pf
}

func isErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if n, isN := u.(*types.Named); isN && n.Obj() != nil && n.Obj().Pkg() == nil && n.Obj().Name() == "error" {
		return true
	}
	return false
}

func funcHasReturnStmt(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if _, isRet := n.(*ast.ReturnStmt); isRet {
			found = true
			return false
		}
		return true
	})
	return found
}

func enclosingCallOfCalleeIdent(idx *pkgSyntaxIndex, uid *ast.Ident) *ast.CallExpr {
	par := idx.parentUnparen(uid)
	if c, isC := par.(*ast.CallExpr); isC && ast.Unparen(c.Fun) == uid {
		return c
	}
	if sel, isS := par.(*ast.SelectorExpr); isS && sel.Sel == uid {
		if c, isC := idx.parentUnparen(sel).(*ast.CallExpr); isC && ast.Unparen(c.Fun) == sel {
			return c
		}
	}
	return nil
}

func isDirectFreshConstructExpr(p *packages.Package, expr ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return isFreshConstructableRootType(p.TypesInfo.TypeOf(e)) && cl != nil
			}
		}
	case *ast.CallExpr:
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "new" || b.Name() == "make" {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
				if b.Name() == "append" && len(e.Args) >= 1 && isTypedNilSliceConv(p, e.Args[0]) {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
			}
		}
		if callee := resolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func isTypedNilSliceConv(p *packages.Package, expr ast.Expr) bool {
	conv, isConv := ast.Unparen(expr).(*ast.CallExpr)
	if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !isNilIdent(p, conv.Args[0]) {
		return false
	}
	_, isSl := types.Unalias(p.TypesInfo.Types[conv.Fun].Type).Underlying().(*types.Slice)
	return isSl
}

func isFreshFieldAssignRHS(p *packages.Package, lhs, rhs ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	rhs = ast.Unparen(rhs)
	if isNilIdent(p, rhs) || isTypedNilSliceConv(p, rhs) {
		return true
	}
	switch e := rhs.(type) {
	case *ast.CompositeLit:
		return true
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			_, ok := ast.Unparen(e.X).(*ast.CompositeLit)
			return ok
		}
	case *ast.CallExpr:
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "new" || b.Name() == "make" {
					return true
				}
				if b.Name() == "append" && len(e.Args) >= 1 &&
					(isTypedNilSliceConv(p, e.Args[0]) || (lhs != nil && sameFieldTargetExpr(p, lhs, e.Args[0]))) {
					return true
				}
			}
		}
		if callee := resolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func sameFieldTargetExpr(p *packages.Package, a, b ast.Expr) bool {
	a = ast.Unparen(a)
	b = ast.Unparen(b)
	switch ea := a.(type) {
	case *ast.Ident:
		eb, ok := b.(*ast.Ident)
		return ok && p.TypesInfo.Uses[ea] != nil && p.TypesInfo.Uses[ea] == p.TypesInfo.Uses[eb]
	case *ast.SelectorExpr:
		eb, ok := b.(*ast.SelectorExpr)
		if !ok || ea.Sel.Name != eb.Sel.Name {
			return false
		}
		sa := p.TypesInfo.Selections[ea]
		sb := p.TypesInfo.Selections[eb]
		if sa == nil || sb == nil || sa.Obj() != sb.Obj() {
			return false
		}
		return sameFieldTargetExpr(p, ea.X, eb.X)
	case *ast.IndexExpr:
		eb, ok := b.(*ast.IndexExpr)
		if !ok || !sameFieldTargetExpr(p, ea.X, eb.X) {
			return false
		}
		tva := p.TypesInfo.Types[ea.Index]
		tvb := p.TypesInfo.Types[eb.Index]
		if tva.Value != nil && tvb.Value != nil {
			return tva.Value.Kind() == tvb.Value.Kind() && constant.Compare(tva.Value, token.EQL, tvb.Value)
		}
		ia, okA := ast.Unparen(ea.Index).(*ast.Ident)
		ib, okB := ast.Unparen(eb.Index).(*ast.Ident)
		if !okA || !okB {
			return false
		}
		iv, okV := p.TypesInfo.Uses[ia].(*types.Var)
		return okV && iv != nil && iv == p.TypesInfo.Uses[ib] && !iv.IsField() && iv.Parent() != p.Types.Scope()
	}
	return false
}

func markValueContainedRefFieldsNonFresh(t types.Type, out map[*types.Var]bool) {
	seen := map[types.Type]bool{}
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if isRefOrContainerType(f.Type()) {
					out[f] = true
				}
				walk(f.Type())
			}
		case *types.Array:
			walk(u.Elem())
		}
	}
	walk(t)
}

func recordCompositeLitNonFreshFields(p *packages.Package, cl *ast.CompositeLit, freshReturnFuncs map[*types.Func]bool, nonFresh map[*types.Var]bool) {
	if cl == nil {
		return
	}
	_, st := derefAnyStructType(p.TypesInfo.TypeOf(cl))
	if st == nil {
		return
	}
	for i, elt := range cl.Elts {
		var fObj *types.Var
		val := elt
		if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
			val = kv.Value
			if kid, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
				fObj, _ = p.TypesInfo.Uses[kid].(*types.Var)
			}
		} else if i < st.NumFields() {
			fObj = st.Field(i)
		}
		if fObj == nil {
			continue
		}
		if isRefOrContainerType(fObj.Type()) {
			if !isFreshFieldAssignRHS(p, nil, val, freshReturnFuncs) {
				nonFresh[fObj] = true
			}
		}
		if subCL := unwrapCompositeLit(val); subCL != nil {
			recordCompositeLitNonFreshFields(p, subCL, freshReturnFuncs, nonFresh)
		} else if _, subSt := derefAnyStructType(fObj.Type()); subSt != nil && !isRefOrContainerType(fObj.Type()) {
			markValueContainedRefFieldsNonFresh(fObj.Type(), nonFresh)
		}
	}
}

func unwrapCompositeLit(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if cl, ok := expr.(*ast.CompositeLit); ok {
		return cl
	}
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.AND {
		if cl, okC := ast.Unparen(un.X).(*ast.CompositeLit); okC {
			return cl
		}
	}
	return nil
}

func analyzeSingleFreshConstructorFunc(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	fn *types.Func,
	freshReturnFuncs map[*types.Func]bool,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) *freshFuncSummary {
	sum := &freshFuncSummary{
		fd:             fd,
		fn:             fn,
		vars:           map[*types.Var]*freshVarState{},
		nonFreshFields: map[*types.Var]bool{},
		coneCallees:    map[*types.Func]bool{},
	}

	params := map[*types.Var]bool{}
	namedResults := map[*types.Var]bool{}
	if fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() != nil {
				params[sig.Recv()] = true
			}
			for i := 0; i < sig.Params().Len(); i++ {
				pv := sig.Params().At(i)
				params[pv] = true
				if freshParamFuncs[fn][i] {
					_, isSl := types.Unalias(pv.Type()).Underlying().(*types.Slice)
					sum.vars[pv] = &freshVarState{
						rootVar:    pv,
						declPos:    fd.Body.Pos(),
						escapePos:  token.NoPos,
						isValSlice: isSl,
					}
				}
			}
			for i := 0; i < sig.Results().Len(); i++ {
				rv := sig.Results().At(i)
				params[rv] = true
				namedResults[rv] = true
			}
		}
	}

	// Candidate named result slice/struct (e.g. es []filedesc.Enum in initEnumDeclarations).
	disqualified := map[*types.Var]bool{}
	for rv := range namedResults {
		if isFreshConstructableRootType(rv.Type()) {
			_, isSl := types.Unalias(rv.Type()).Underlying().(*types.Slice)
			sum.vars[rv] = &freshVarState{
				rootVar:    rv,
				declPos:    fd.Body.Pos(),
				escapePos:  token.NoPos,
				isValSlice: isSl,
			}
		}
	}

	// Track top-level statement indices for dominating single rebinding (e.g. fd = &md.L2.Fields.List[n]).
	topStmtIndex := map[ast.Stmt]int{}
	for i, st := range fd.Body.List {
		topStmtIndex[st] = i
	}
	initialDefTopIdx := map[*types.Var]int{}
	rebindTopIdx := map[*types.Var]int{}
	rebindAssign := map[*types.Var]*ast.AssignStmt{}
	assignCount := map[*types.Var]int{}

	var loops []ast.Node
	var defers []*ast.DeferStmt
	var aliasDefs []struct {
		v       *types.Var
		pos     token.Pos
		addrArg ast.Expr
	}

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		switch s := n.(type) {
		case *ast.ForStmt:
			loops = append(loops, s)
		case *ast.RangeStmt:
			loops = append(loops, s)
			if s.Key != nil {
				if v := lookupIdentVar(p, s.Key); v != nil {
					disqualified[v] = true
				}
			}
			if s.Value != nil {
				if v := lookupIdentVar(p, s.Value); v != nil {
					disqualified[v] = true
				}
			}
		case *ast.DeferStmt:
			defers = append(defers, s)
		case *ast.ValueSpec:
			for i, nm := range s.Names {
				v, ok := p.TypesInfo.Defs[nm].(*types.Var)
				if !ok || v == nil || params[v] || v.Parent() == p.Types.Scope() {
					continue
				}
				if idx.defCounts[v] != 1 || idx.inFuncLit[nm] || idx.inGoStmt[nm] {
					disqualified[v] = true
					continue
				}
				if len(s.Values) == 0 {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && isFreshConstructableRootType(v.Type()) {
						_, isSl := types.Unalias(v.Type()).Underlying().(*types.Slice)
						sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
					}
				} else if i < len(s.Values) {
					rhs := s.Values[i]
					if isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) {
						_, isSl := types.Unalias(v.Type()).Underlying().(*types.Slice)
						sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
						if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
						}
					} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
						aliasDefs = append(aliasDefs, struct {
							v       *types.Var
							pos     token.Pos
							addrArg ast.Expr
						}{v: v, pos: nm.Pos(), addrArg: un.X})
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				// Taking &v directly on a local pointer/slice variable disqualifies v unless v is only returned inside a field-assigned closure (handled below for &optionImports).
				if v := lookupIdentVar(p, s.X); v != nil {
					if _, isSl := types.Unalias(v.Type()).Underlying().(*types.Slice); !isSl {
						disqualified[v] = true
					}
				}
				if sel, isSel := ast.Unparen(s.X).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
						if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && isRefOrContainerType(fObj.Type()) {
							sum.nonFreshFields[fObj] = true
						}
					}
				}
			}
		case *ast.AssignStmt:
			// Handle multi-return (x, err = freshReturnCallee(...) or a, b, c, err = r.findTarget(...))!
			if len(s.Lhs) >= 2 && len(s.Rhs) == 1 {
				if call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); isCall {
					if callee := resolveCalledFuncObj(p, call.Fun); callee != nil {
						orig := callee.Origin()
						if orig.Pkg() == p.Types {
							sum.coneCallees[orig] = true
						}
						if len(s.Lhs) == 2 && freshReturnFuncs[orig] {
							l0 := s.Lhs[0]
							if lid, isID := ast.Unparen(l0).(*ast.Ident); isID {
								if v, _ := p.TypesInfo.Defs[lid].(*types.Var); v != nil && !params[v] && v.Parent() != p.Types.Scope() && idx.defCounts[v] == 1 {
									_, isSl := types.Unalias(v.Type()).Underlying().(*types.Slice)
									sum.vars[v] = &freshVarState{rootVar: v, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
								} else if v, _ := p.TypesInfo.Uses[lid].(*types.Var); v != nil && namedResults[v] && s.Tok == token.ASSIGN {
									// Named result assigned from freshReturnFuncs: keep candidate!
								} else if v != nil {
									disqualified[v] = true
								}
							}
							if v1 := lookupIdentVar(p, s.Lhs[1]); v1 != nil {
								disqualified[v1] = true
							}
							return true
						}
					}
				}
				// Mark any field assigned on LHS (e.g. e.L0, err = r.makeBase(...) or f.L1.Kind, f.L1.Enum, f.L1.Message, err = r.findTarget(...)) non-fresh!
				for _, l := range s.Lhs {
					if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
						if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
								if isRefOrContainerType(fObj.Type()) {
									sum.nonFreshFields[fObj] = true
								}
								markValueContainedRefFieldsNonFresh(fObj.Type(), sum.nonFreshFields)
							}
						}
					}
					if v := lookupIdentVar(p, l); v != nil {
						disqualified[v] = true
					}
				}
				return true
			}
			if len(s.Lhs) != len(s.Rhs) {
				for _, l := range s.Lhs {
					if v := lookupIdentVar(p, l); v != nil {
						disqualified[v] = true
					}
				}
				return true
			}
			topIdx, isTop := topStmtIndex[s]
			for i, l := range s.Lhs {
				rhs := s.Rhs[i]
				if call, isCall := ast.Unparen(rhs).(*ast.CallExpr); isCall {
					if callee := resolveCalledFuncObj(p, call.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
						sum.coneCallees[callee.Origin()] = true
					}
				}
				if lid, isID := ast.Unparen(l).(*ast.Ident); isID {
					if defV, isDef := p.TypesInfo.Defs[lid].(*types.Var); isDef && defV != nil && !params[defV] && defV.Parent() != p.Types.Scope() {
						if isTop {
							initialDefTopIdx[defV] = topIdx
						}
						if idx.defCounts[defV] != 1 {
							disqualified[defV] = true
							continue
						}
						if isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) {
							_, isSl := types.Unalias(defV.Type()).Underlying().(*types.Slice)
							sum.vars[defV] = &freshVarState{rootVar: defV, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
							if cl := unwrapCompositeLit(rhs); cl != nil {
								recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
							}
						} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
							aliasDefs = append(aliasDefs, struct {
								v       *types.Var
								pos     token.Pos
								addrArg ast.Expr
							}{v: defV, pos: lid.Pos(), addrArg: un.X})
						}
						continue
					}
					if useV, isUse := p.TypesInfo.Uses[lid].(*types.Var); isUse && useV != nil {
						assignCount[useV]++
						if namedResults[useV] {
							if !isNilIdent(p, rhs) && !isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) && !isFreshFieldAssignRHS(p, l, rhs, freshReturnFuncs) {
								disqualified[useV] = true
							} else if cl := unwrapCompositeLit(rhs); cl != nil {
								recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
							}
							continue
						}
						if isTop && assignCount[useV] == 1 {
							if _, hasInit := initialDefTopIdx[useV]; hasInit && topIdx > initialDefTopIdx[useV] {
								rebindTopIdx[useV] = topIdx
								rebindAssign[useV] = s
								continue
							}
						}
						disqualified[useV] = true
						continue
					}
				}
				// Field / element assignment: track nonFreshFields!
				if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
						if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
							if isRefOrContainerType(fObj.Type()) {
								if !isFreshFieldAssignRHS(p, l, rhs, freshReturnFuncs) {
									sum.nonFreshFields[fObj] = true
								} else if cl := unwrapCompositeLit(rhs); cl != nil {
									recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
								} else if call, isCall := ast.Unparen(rhs).(*ast.CallExpr); isCall && len(call.Args) >= 2 {
									if cid, isCID := ast.Unparen(call.Fun).(*ast.Ident); isCID {
										if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "append" {
											for _, elemArg := range call.Args[1:] {
												if cl := unwrapCompositeLit(elemArg); cl != nil {
													recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
												} else {
													markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(elemArg), sum.nonFreshFields)
												}
											}
										}
									}
								}
							} else if _, subSt := derefAnyStructType(fObj.Type()); subSt != nil {
								if cl := unwrapCompositeLit(rhs); cl != nil {
									recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
								} else {
									markValueContainedRefFieldsNonFresh(fObj.Type(), sum.nonFreshFields)
								}
							}
						}
					}
				} else if ix, isIx := ast.Unparen(l).(*ast.IndexExpr); isIx {
					if _, isSl := types.Unalias(p.TypesInfo.TypeOf(ix.X)).Underlying().(*types.Slice); isSl {
						if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
						} else {
							markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(ix), sum.nonFreshFields)
						}
					}
				}
			}
		case *ast.ReturnStmt:
			if len(s.Results) > 0 {
				if cl := unwrapCompositeLit(s.Results[0]); cl != nil {
					recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
				}
				if call, isCall := ast.Unparen(s.Results[0]).(*ast.CallExpr); isCall {
					if callee := resolveCalledFuncObj(p, call.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
						sum.coneCallees[callee.Origin()] = true
					}
				}
			}
		case *ast.CallExpr:
			if callee := resolveCalledFuncObj(p, s.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
				sum.coneCallees[callee.Origin()] = true
			}
		}
		return true
	})

	for v := range disqualified {
		delete(sum.vars, v)
	}

	// Resolve dominating single top-level rebinding (fd = &md.L2.Fields.List[n]):
	for v := range rebindTopIdx {
		if disqualified[v] || assignCount[v] != 1 {
			delete(sum.vars, v)
			continue
		}
		as := rebindAssign[v]
		if as == nil || len(as.Rhs) != 1 {
			delete(sum.vars, v)
			continue
		}
		// Ensure zero writes to v's fields/pointee prior to as.Pos()!
		wroteBefore := false
		for _, uid := range idx.usesOf[v] {
			if uid.Pos() < as.Pos() && identReachesMutatedOrAddrPrefix(p, idx, uid) {
				wroteBefore = true
				break
			}
		}
		if wroteBefore {
			delete(sum.vars, v)
			continue
		}
		delete(sum.vars, v)
		if un, isUn := ast.Unparen(as.Rhs[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			aliasDefs = append(aliasDefs, struct {
				v       *types.Var
				pos     token.Pos
				addrArg ast.Expr
			}{v: v, pos: as.End(), addrArg: un.X})
		}
	}

	// Iteratively resolve local element/subfield pointer aliases (e := &es[i], f := &m.L2.Fields.List[j], fd = &md.L2.Fields.List[n]).
	resolveRootOfExpr := func(expr ast.Expr) *types.Var {
		cur := ast.Unparen(expr)
		for {
			switch e := cur.(type) {
			case *ast.Ident:
				v, _ := p.TypesInfo.Uses[e].(*types.Var)
				if st := sum.vars[v]; st != nil {
					return st.rootVar
				}
				return nil
			case *ast.SelectorExpr:
				cur = ast.Unparen(e.X)
			case *ast.IndexExpr:
				cur = ast.Unparen(e.X)
			case *ast.SliceExpr:
				cur = ast.Unparen(e.X)
			case *ast.StarExpr:
				cur = ast.Unparen(e.X)
			case *ast.UnaryExpr:
				if e.Op == token.AND {
					cur = ast.Unparen(e.X)
				} else {
					return nil
				}
			default:
				return nil
			}
		}
	}
	dummyPF := &pkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}}
	for pass := 0; pass < 4; pass++ {
		added := false
		for _, ad := range aliasDefs {
			if disqualified[ad.v] || sum.vars[ad.v] != nil {
				continue
			}
			// Interior `&` aliases must be pointers to non-empty structs (never scalar pointers like `*string`
			// whose subsequent `*p = ...` dereference writes would bypass struct-type mutation tracking).
			ptr, isPtr := types.Unalias(ad.v.Type()).Underlying().(*types.Pointer)
			if !isPtr {
				continue
			}
			if _, elemSt := derefAnyStructType(ptr.Elem()); elemSt == nil || elemSt.NumFields() == 0 {
				continue
			}
			if dummyPF.isFreshContainerAt(sum, ad.addrArg, ad.pos) {
				rv := resolveRootOfExpr(ad.addrArg)
				if rv != nil && sum.vars[rv] != nil {
					sum.vars[ad.v] = &freshVarState{
						rootVar:   rv,
						declPos:   ad.pos,
						escapePos: token.NoPos,
					}
					added = true
				}
			}
		}
		if !added {
			break
		}
	}

	// Step 5: Compute earliest external escape position for each root variable in sum.vars,
	// propagating escape coupling (dst.Field = src => escapePos[src] <= escapePos[dst]) to fixed point,
	// and evicting any interior `&` alias (`st.rootVar != v`) that escapes or remains live at/after
	// `rootSt.escapePos`.
	clampToLoops := func(rootDeclPos, usePos token.Pos) token.Pos {
		esc := usePos
		for _, lp := range loops {
			if lp.Pos() <= usePos && usePos < lp.End() && !(lp.Pos() <= rootDeclPos && rootDeclPos < lp.End()) {
				if lp.Pos() < esc {
					esc = lp.Pos()
				}
			}
		}
		return esc
	}
	recordEscape := func(v *types.Var, pos token.Pos) bool {
		st := sum.vars[v]
		if st == nil {
			return false
		}
		rootSt := sum.vars[st.rootVar]
		if rootSt == nil {
			rootSt = st
		}
		clamped := clampToLoops(rootSt.declPos, pos)
		changed := false
		if st.escapePos == token.NoPos || clamped < st.escapePos {
			st.escapePos = clamped
			changed = true
		}
		if rootSt.escapePos == token.NoPos || clamped < rootSt.escapePos {
			rootSt.escapePos = clamped
			changed = true
		}
		return changed
	}

	for {
		for _, st := range sum.vars {
			st.escapePos = token.NoPos
		}
		var couplings []freshEscapeCoupling

		// Inspect every use of every v in sum.vars.
		for v, st := range sum.vars {
			usedInDefer := false
			for _, id := range idx.usesOf[v] {
				if st.declPos != token.NoPos && id.Pos() < st.declPos {
					// Prior to dominating rebind (e.g. append(..., *fd) before fd = &md.L2.Fields.List[n]).
					continue
				}
				if idx.inGoStmt[id] {
					recordEscape(v, fd.Body.Pos())
					continue
				}
				for _, df := range defers {
					if df.Pos() <= id.Pos() && id.Pos() < df.End() {
						usedInDefer = true
						break
					}
				}
				if idx.inFuncLit[id] {
					lit := enclosingFuncLit(idx, id)
					ownerRoot, readOnlyFieldClosure, returnsAddrOnly := classifyFieldAssignedClosureUse(p, idx, lit, v, resolveRootOfExpr)
					if readOnlyFieldClosure && ownerRoot != nil {
						if returnsAddrOnly {
							recordEscape(v, lit.Pos())
						} else {
							couplings = append(couplings, freshEscapeCoupling{srcRoot: st.rootVar, dstRoot: ownerRoot, atPos: lit.Pos()})
						}
						continue
					}
					if lit != nil {
						recordEscape(v, lit.Pos())
					} else {
						recordEscape(v, fd.Body.Pos())
					}
					continue
				}

				if useIsNonEscapingOnFreshVar(
					p,
					idx,
					fd,
					sum,
					v,
					id,
					freshParamFuncs,
					nonEscParams,
					mapStoreParams,
					retStructParams,
					paramGuardPkgs,
					nonEscAuxVars,
					confinedCacheMaps,
					resolveRootOfExpr,
					&couplings,
				) {
					continue
				}
				// If a non-input-parameter fresh root (`(!params[v] || namedResults[v]) && st.rootVar == v`)
				// is returned at result 0 in a side-effect-free `return v[, err]` statement with zero `defer`s,
				// returning immediately exits `fd` so no statement in `fd` executes after `return` on that path
				// (while `freshReturnFuncs` still inspects every `ReturnStmt` independently).
				if (!params[v] || namedResults[v]) && st.rootVar == v && len(defers) == 0 {
					if retStmt, isRet := idx.parentUnparen(id).(*ast.ReturnStmt); isRet &&
						len(retStmt.Results) >= 1 && ast.Unparen(retStmt.Results[0]) == id {
						pureRet := true
						for ri, re := range retStmt.Results {
							u := ast.Unparen(re)
							if ri > 0 && u == id {
								pureRet = false
								break
							}
							switch u.(type) {
							case *ast.Ident, *ast.BasicLit:
							default:
								pureRet = false
							}
						}
						if pureRet {
							continue
						}
					}
				}
				recordEscape(v, id.Pos())
			}
			if usedInDefer {
				recordEscape(v, fd.Body.Pos())
			}
		}

		// Also check bare `return` for namedResults.
		if len(namedResults) > 0 {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				if ret, isRet := n.(*ast.ReturnStmt); isRet && len(ret.Results) == 0 {
					for rv := range namedResults {
						if sum.vars[rv] != nil {
							recordEscape(rv, ret.Pos())
						}
					}
				}
				return true
			})
		}

		// Propagate escape couplings (dst.Field = src => escapePos[src] <= escapePos[dst]).
		for {
			changed := false
			for _, cp := range couplings {
				dstSt := sum.vars[cp.dstRoot]
				if dstSt == nil {
					if recordEscape(cp.srcRoot, cp.atPos) {
						changed = true
					}
					continue
				}
				if dstSt.escapePos != token.NoPos {
					targetPos := dstSt.escapePos
					if cp.atPos >= dstSt.escapePos {
						targetPos = cp.atPos
					}
					if recordEscape(cp.srcRoot, targetPos) {
						changed = true
					}
				}
			}
			if !changed {
				break
			}
		}

		// Verify every interior `&` alias (`st.rootVar != v`) stays unescaped and strictly precedes `rootSt.escapePos`.
		evictedAlias := false
		for v, st := range sum.vars {
			if st.rootVar == v {
				continue
			}
			rootSt := sum.vars[st.rootVar]
			bad := st.escapePos != token.NoPos || rootSt == nil
			if !bad && rootSt.escapePos != token.NoPos {
				for _, uid := range idx.usesOf[v] {
					if st.declPos != token.NoPos && uid.Pos() < st.declPos {
						continue
					}
					if clampToLoops(rootSt.declPos, uid.Pos()) >= rootSt.escapePos {
						bad = true
						break
					}
				}
			}
			if bad {
				delete(sum.vars, v)
				evictedAlias = true
			}
		}
		if !evictedAlias {
			break
		}
	}

	return sum
}

type freshEscapeCoupling struct {
	srcRoot *types.Var
	dstRoot *types.Var
	atPos   token.Pos
}

func isBlankIdentExpr(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == "_"
}

func isByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, okB := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return okB && (b.Kind() == types.Byte || b.Kind() == types.Uint8)
}

func identReachesMutatedOrAddrPrefix(p *packages.Package, idx *pkgSyntaxIndex, id *ast.Ident) bool {
	cur := ast.Node(id)
	for {
		par := idx.parentUnparen(cur)
		switch x := par.(type) {
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					continue
				}
			}
			return false
		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
			return false
		case *ast.UnaryExpr:
			return x.Op == token.AND
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if ast.Unparen(lhs) == cur {
					return true
				}
			}
			return false
		case *ast.IncDecStmt:
			return ast.Unparen(x.X) == cur
		default:
			return false
		}
	}
}

func enclosingFuncLit(idx *pkgSyntaxIndex, n ast.Node) *ast.FuncLit {
	cur := idx.parentMap[n]
	var outer *ast.FuncLit
	for cur != nil {
		if lit, isLit := cur.(*ast.FuncLit); isLit {
			outer = lit
		}
		if _, isFD := cur.(*ast.FuncDecl); isFD {
			break
		}
		cur = idx.parentMap[cur]
	}
	return outer
}

func classifyFieldAssignedClosureUse(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	lit *ast.FuncLit,
	v *types.Var,
	resolveRoot func(ast.Expr) *types.Var,
) (ownerRoot *types.Var, ok bool, returnsAddrOnly bool) {
	if lit == nil || lit.Body == nil {
		return nil, false, false
	}
	// lit must be assigned directly to a func-typed field on a fresh node:
	//   owner.Field = func() ... { ... }
	// or local var optsFunc := func() ... assigned only to append(owner.Field, optsFunc) (handled conservatively via lit.Pos() if local).
	as, isAs := idx.parentUnparen(lit).(*ast.AssignStmt)
	if !isAs || len(as.Lhs) != len(as.Rhs) {
		return nil, false, false
	}
	lhsIdx := -1
	for i, r := range as.Rhs {
		if ast.Unparen(r) == lit {
			lhsIdx = i
			break
		}
	}
	if lhsIdx < 0 {
		return nil, false, false
	}
	lhsSel, isSel := ast.Unparen(as.Lhs[lhsIdx]).(*ast.SelectorExpr)
	if !isSel {
		return nil, false, false
	}
	selInfo := p.TypesInfo.Selections[lhsSel]
	if selInfo == nil || selInfo.Kind() != types.FieldVal {
		return nil, false, false
	}
	ownerRoot = resolveRoot(lhsSel.X)
	if ownerRoot == nil {
		return nil, false, false
	}
	// Inside lit.Body, v may ONLY have scalar fields read, OR be returned as `return &v`!
	for _, uid := range idx.usesOf[v] {
		if !(lit.Body.Pos() <= uid.Pos() && uid.Pos() < lit.Body.End()) {
			continue
		}
		if identReachesMutatedOrAddrPrefix(p, idx, uid) {
			par := idx.parentUnparen(uid)
			if un, isUn := par.(*ast.UnaryExpr); isUn && un.Op == token.AND {
				if _, isRet := idx.parentUnparen(un).(*ast.ReturnStmt); isRet {
					returnsAddrOnly = true
					continue
				}
			}
			return nil, false, false
		}
		// Walk selector chain on uid; ensure final read expression is carrier-free scalar!
		cur := ast.Expr(uid)
		for {
			sel, isS := idx.parentUnparen(cur).(*ast.SelectorExpr)
			if !isS || ast.Unparen(sel.X) != cur {
				break
			}
			si := p.TypesInfo.Selections[sel]
			if si == nil || si.Kind() != types.FieldVal {
				return nil, false, false
			}
			cur = sel
		}
		if cur == uid || TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return nil, false, false
		}
	}
	return ownerRoot, true, returnsAddrOnly
}

func useIsNonEscapingOnFreshVar(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	sum *freshFuncSummary,
	v *types.Var,
	id *ast.Ident,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	resolveRoot func(ast.Expr) *types.Var,
	couplings *[]freshEscapeCoupling,
) bool {
	// Walk outward through field selections, array/slice indexings, and *id dereferences
	// to find the expression boundary where the fresh access chain is consumed!
	cur := ast.Expr(id)
	for {
		par := idx.parentUnparen(cur)
		switch x := par.(type) {
		case *ast.StarExpr:
			if cur == id && ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				selInfo := p.TypesInfo.Selections[x]
				if selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					continue
				}
				if selInfo != nil && selInfo.Kind() == types.MethodVal {
					// Direct method call cur.Method(args...)!
					call, isCall := idx.parentUnparen(x).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != x {
						return false
					}
					return isNonEscapingMethodOrHelperCallOnFresh(
						p, idx, fd, sum, call, -1, v,
						freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
					)
				}
			}
		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.SliceExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && ast.Unparen(x.X) == cur {
				// Taking &cur: non-escaping ONLY if bound to a verified local alias in sum.vars
				// OR passed as a non-escaping call argument (e.g. CheckOverlap(&m.L2.ReservedRanges, ...))!
				switch up := idx.parentUnparen(x).(type) {
				case *ast.ValueSpec:
					for i, val := range up.Values {
						if ast.Unparen(val) == x && i < len(up.Names) {
							av, _ := p.TypesInfo.Defs[up.Names[i]].(*types.Var)
							if av != nil && sum.vars[av] != nil {
								return true
							}
						}
					}
					return false
				case *ast.AssignStmt:
					if len(up.Lhs) == len(up.Rhs) {
						for i, r := range up.Rhs {
							if ast.Unparen(r) == x {
								if lid, isID := ast.Unparen(up.Lhs[i]).(*ast.Ident); isID {
									var av *types.Var
									if dv, okD := p.TypesInfo.Defs[lid].(*types.Var); okD {
										av = dv
									} else if uv, okU := p.TypesInfo.Uses[lid].(*types.Var); okU {
										av = uv
									}
									if av != nil && sum.vars[av] != nil {
										return true
									}
								}
							}
						}
					}
					return false
				case *ast.CallExpr:
					for ai, arg := range up.Args {
						if ast.Unparen(arg) == x {
							return isNonEscapingMethodOrHelperCallOnFresh(
								p, idx, fd, sum, up, ai, v,
								freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
							)
						}
					}
					return false
				default:
					return false
				}
			}
		}
		break
	}

	// Now inspect how `cur` is used at `idx.parentUnparen(cur)`:
	par := idx.parentUnparen(cur)
	switch x := par.(type) {
	case *ast.AssignStmt:
		// 1. Is `cur` on LHS?
		for _, lhs := range x.Lhs {
			if ast.Unparen(lhs) == cur {
				return cur != id || sum.vars[v] != nil
			}
		}
		// 2. Is `cur` on RHS?
		if len(x.Lhs) == len(x.Rhs) {
			for i, rhs := range x.Rhs {
				if ast.Unparen(rhs) == cur {
					lhs := ast.Unparen(x.Lhs[i])
					// (a) Assigned to a carrier-free scalar value (`!TypeContainsRefOrPointer(TypeOf(cur))`): copies scalar by value!
					if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
						return true
					}
					// (b) Assigned into a mutex-confined cycle-breaking constructor cache (`aberrantMessageDescCache[t] = md`)!
					if ix, isIx := lhs.(*ast.IndexExpr); isIx {
						if mv := lookupPkgScopeVar(p, ix.X); mv != nil && confinedCacheMaps[mv][fd] {
							return true
						}
					}
					// (c) Assigned into a field of a fresh node in the same function (`f.L2.Locations.File = f`, `od.L0.Parent = md`): couple escapes!
					if sel, isSel := lhs.(*ast.SelectorExpr); isSel {
						if dstRoot := resolveRoot(sel.X); dstRoot != nil && sum.vars[dstRoot] != nil {
							*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[v].rootVar, dstRoot: dstRoot, atPos: x.Pos()})
							return true
						}
					}
				}
			}
		}
		return false
	case *ast.IncDecStmt:
		return ast.Unparen(x.X) == cur && cur != id
	case *ast.RangeStmt:
		// Ranging over a fresh slice/field (`for i := range p.List` or `for _, x := range cur` when element is carrier-free)!
		if ast.Unparen(x.X) == cur {
			if x.Value == nil || isBlankIdentExpr(x.Value) || !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x.Value)) {
				return true
			}
		}
		return false
	case *ast.BinaryExpr:
		if x.Op == token.EQL || x.Op == token.NEQ || !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return true
		}
		return false
	case *ast.CallExpr:
		// Builtin calls: len, cap, append, clear, copy, delete
		if cid, isCID := ast.Unparen(x.Fun).(*ast.Ident); isCID {
			if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
				switch b.Name() {
				case "len", "cap":
					return true
				case "clear":
					return len(x.Args) == 1 && ast.Unparen(x.Args[0]) == cur
				case "copy":
					if len(x.Args) == 2 && (ast.Unparen(x.Args[0]) == cur || ast.Unparen(x.Args[1]) == cur) {
						if sl, isSl := types.Unalias(p.TypesInfo.TypeOf(cur)).Underlying().(*types.Slice); isSl && !TypeContainsRefOrPointer(sl.Elem()) {
							return true
						}
					}
					return false
				case "append":
					if len(x.Args) >= 1 && ast.Unparen(x.Args[0]) == cur {
						// Self-append: lhs = append(cur, ...) where lhs is the same target!
						if as, isAs := idx.parentUnparen(x).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && sameFieldTargetExpr(p, as.Lhs[0], cur) {
							return true
						}
					}
					// Appending a fresh pointer onto a fresh slice field (`od.L1.Fields.List = append(od.L1.Fields.List, fd)`)!
					for ai := 1; ai < len(x.Args); ai++ {
						if ast.Unparen(x.Args[ai]) == cur {
							if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								return true
							}
							if dstRoot := resolveRoot(x.Args[0]); dstRoot != nil && sum.vars[dstRoot] != nil {
								*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[v].rootVar, dstRoot: dstRoot, atPos: x.Pos()})
								return true
							}
						}
					}
					return false
				}
			}
		}
		for ai, arg := range x.Args {
			if ast.Unparen(arg) == cur {
				if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
					return true
				}
				if isNonEscapingMethodOrHelperCallOnFresh(
					p, idx, fd, sum, x, ai, v,
					freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
				) {
					return true
				}
				// Reading a type-disjoint non-empty interface field on `v` (such as `messageset.IsMessageSet(xd.L1.Extendee)`
				// where neither `Extension` nor `ExtensionL2` implements `protoreflect.MessageDescriptor`) cannot alias any
				// fresh node in `sum.vars` provided no fresh variable in `sum.vars` implements that interface and the callee
				// returns only scalar/error results without retaining carriers!
				if cur != id && !x.Ellipsis.IsValid() {
					if iface, isIface := types.Unalias(p.TypesInfo.TypeOf(cur)).Underlying().(*types.Interface); isIface && iface.NumMethods() > 0 {
						anyFreshImplements := false
						for fv := range sum.vars {
							if fv == nil || fv.Type() == nil {
								continue
							}
							ft := types.Unalias(fv.Type())
							if types.Implements(ft, iface) {
								anyFreshImplements = true
								break
							}
							if ptr, isP := ft.Underlying().(*types.Pointer); isP && types.Implements(ptr.Elem(), iface) {
								anyFreshImplements = true
								break
							}
							if !types.IsInterface(ft) && types.Implements(types.NewPointer(ft), iface) {
								anyFreshImplements = true
								break
							}
						}
						if !anyFreshImplements {
							callee := resolveCalledFuncObj(p, x.Fun)
							if callee != nil && callee.Origin().Pkg() != nil && callee.Origin().Pkg() != p.Types {
								sig, okSig := p.TypesInfo.TypeOf(x.Fun).(*types.Signature)
								if okSig {
									argsOK := true
									for oai, oa := range x.Args {
										if oai == ai {
											continue
										}
										if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(oa)) {
											argsOK = false
											break
										}
									}
									resOK := true
									for ri := 0; ri < sig.Results().Len(); ri++ {
										rt := sig.Results().At(ri).Type()
										if TypeContainsRefOrPointer(rt) && !isErrorType(rt) {
											resOK = false
											break
										}
									}
									if argsOK && resOK {
										recordFreshVarGuardPkg(sum, v, callee.Origin().Pkg().Path())
										return true
									}
								}
							}
						}
					}
				}
				return false
			}
		}
		return false
	default:
		// Any scalar subexpression read (e.g. `!f.L1.IsProto3Optional`, `switch f.L1.Syntax`, `int(f.L1.Kind)`) cannot escape pointers!
		if cur != id && !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return true
		}
		return false
	}
}

func isNonEscapingMethodOrHelperCallOnFresh(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	sum *freshFuncSummary,
	call *ast.CallExpr,
	argIdx int, // -1 for MethodVal receiver, >= 0 for call.Args[argIdx]
	srcVar *types.Var,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	resolveRoot func(ast.Expr) *types.Var,
	couplings *[]freshEscapeCoupling,
) bool {
	if call == nil || call.Ellipsis.IsValid() {
		return false
	}
	callee := resolveCalledFuncObj(p, call.Fun)
	if callee == nil {
		return false
	}
	orig := callee.Origin()
	if orig.Pkg() == p.Types {
		if orig.Exported() {
			return false
		}
		slot := argIdx
		if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
			if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodExpr {
				slot = argIdx - 1
			}
		}
		if slot >= 0 && freshParamFuncs[orig][slot] {
			return true
		}
		if !nonEscParams[orig][slot] {
			return false
		}
		for gPkg := range paramGuardPkgs[orig][slot] {
			recordFreshVarGuardPkg(sum, srcVar, gPkg)
		}
		// If orig stores `slot` into a map parameter/receiver `mSlot` (e.g. `r[fullName] = child` in `makeBase`),
		// verify the caller's argument for `mSlot` is a non-escaping local container!
		if mSlot, hasMap := mapStoreParams[orig][slot]; hasMap {
			var mapArg ast.Expr
			if mSlot == -1 {
				if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
					if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
						mapArg = sel.X
					} else if si != nil && si.Kind() == types.MethodExpr && len(call.Args) > 0 {
						mapArg = call.Args[0]
					}
				}
			} else if mSlot >= 0 && mSlot < len(call.Args) {
				mapArg = call.Args[mSlot]
			}
			mv := lookupIdentVar(p, mapArg)
			if mv == nil || !nonEscAuxVars[mv] {
				return false
			}
		}
		// If orig returns `slot` (or a derived sub-descriptor) at result(s) (e.g. `e.L0, err = r.makeBase(e, parent, ...)`
		// or `v, ev, err := unmarshalDefault(..., f, ...); ...; f.L1.Default = filedesc.DefaultValue(v, ev)`),
		// verify the call result is assigned into a fresh node in fd and couple escapes!
		if retStructParams[orig][slot] {
			as, isAs := idx.parentUnparen(call).(*ast.AssignStmt)
			if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call || len(as.Lhs) == 0 {
				return false
			}
			if sel, isSel := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr); isSel {
				dstRoot := resolveRoot(sel.X)
				if dstRoot == nil || sum.vars[dstRoot] == nil {
					return false
				}
				*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[srcVar].rootVar, dstRoot: dstRoot, atPos: call.Pos()})
				return true
			}
			// Check local forwarding into `dst.Field = extCtor(v, ev)` (such as `filedesc.DefaultValue(v, ev)`).
			var targetAssign *ast.AssignStmt
			var dstRoot *types.Var
			sawCarrierOut := false
			for _, lhs := range as.Lhs {
				if isBlankIdentExpr(lhs) {
					continue
				}
				lt := p.TypesInfo.TypeOf(lhs)
				if (!TypeContainsRefOrPointer(lt) && !containsUintptr(lt)) || isErrorType(lt) {
					continue
				}
				lid, isID := ast.Unparen(lhs).(*ast.Ident)
				if !isID {
					return false
				}
				lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
				if !isDef || lv == nil || idx.defCounts[lv] != 1 || len(idx.usesOf[lv]) == 0 {
					return false
				}
				sawCarrierOut = true
				for _, uid := range idx.usesOf[lv] {
					if idx.inFuncLit[uid] || idx.inGoStmt[uid] {
						return false
					}
					extCall, isEC := idx.parentUnparen(uid).(*ast.CallExpr)
					if !isEC || extCall.Ellipsis.IsValid() {
						return false
					}
					isArg := false
					for _, ea := range extCall.Args {
						if ast.Unparen(ea) == uid {
							isArg = true
							break
						}
					}
					if !isArg {
						return false
					}
					extCtor := resolveCalledFuncObj(p, extCall.Fun)
					if extCtor == nil || extCtor.Origin().Pkg() == nil {
						return false
					}
					as2, isAs2 := idx.parentUnparen(extCall).(*ast.AssignStmt)
					if !isAs2 || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 || ast.Unparen(as2.Rhs[0]) != extCall {
						return false
					}
					sel2, isSel2 := ast.Unparen(as2.Lhs[0]).(*ast.SelectorExpr)
					if !isSel2 {
						return false
					}
					dr := resolveRoot(sel2.X)
					if dr == nil || sum.vars[dr] == nil {
						return false
					}
					if targetAssign != nil && targetAssign != as2 {
						return false
					}
					targetAssign = as2
					dstRoot = dr
					if extCtor.Origin().Pkg() != p.Types {
						recordFreshVarGuardPkg(sum, srcVar, extCtor.Origin().Pkg().Path())
						recordFreshVarGuardPkg(sum, dr, extCtor.Origin().Pkg().Path())
					}
				}
			}
			if !sawCarrierOut || dstRoot == nil {
				return false
			}
			*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[srcVar].rootVar, dstRoot: dstRoot, atPos: targetAssign.Pos()})
		}
		return true
	}

	// Foreign method call on the fresh object (e.g. f.Path(), f.FullName(), f.L1.StringName.InitJSON(s),
	// m.L2.ReservedNames.CheckValid(), (*filedesc.FieldRanges).CheckOverlap(&r1, &r2)):
	// Only receiver (argIdx == -1) or MethodExpr/CheckOverlap fresh args are admitted when ALL call args
	// are carrier-free or fresh in sum, AND the call result does not escape fd!
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel {
		return false
	}
	selInfo := p.TypesInfo.Selections[sel]
	if selInfo == nil || (selInfo.Kind() != types.MethodVal && selInfo.Kind() != types.MethodExpr) {
		return false
	}
	if selInfo.Kind() == types.MethodVal && argIdx >= 0 {
		// Passing a fresh object as a non-receiver argument to a foreign method is only safe when that method's
		// receiver is ALSO fresh (e.g. CheckOverlap(&r1, &r2))!
		dummyPF := &pkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}}
		if !dummyPF.isFreshContainerAt(sum, sel.X, call.Pos()) {
			return false
		}
	}
	dummyPF := &pkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}}
	for _, a := range call.Args {
		if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(a)) && !dummyPF.isFreshContainerAt(sum, a, call.Pos()) {
			return false
		}
	}
	sig, okSig := p.TypesInfo.TypeOf(call.Fun).(*types.Signature)
	if !okSig {
		return false
	}
	if sig.Results().Len() == 0 {
		return true
	}
	allScalarOrErr := true
	for ri := 0; ri < sig.Results().Len(); ri++ {
		rt := sig.Results().At(ri).Type()
		if TypeContainsRefOrPointer(rt) && !isErrorType(rt) {
			allScalarOrErr = false
			break
		}
	}
	if allScalarOrErr {
		return true
	}
	// If result carries a descriptor/list interface (e.g. f.Parent().FullName(), m.Fields().Len(), imp.Imports()),
	// verify the call expression is not returned from fd or stored into a global!
	return callResultStaysLocal(p, idx, call, nonEscAuxVars)
}

func callResultStaysLocal(p *packages.Package, idx *pkgSyntaxIndex, call *ast.CallExpr, nonEscAuxVars map[*types.Var]bool) bool {
	return exprResultStaysLocalWithDepth(p, idx, call, nonEscAuxVars, 0)
}

func exprResultStaysLocalWithDepth(p *packages.Package, idx *pkgSyntaxIndex, start ast.Expr, nonEscAuxVars map[*types.Var]bool, depth int) bool {
	if depth > 4 {
		return false
	}
	checkBoundLocalVar := func(v *types.Var) bool {
		if v == nil || idx.defCounts[v] != 1 {
			return false
		}
		for _, uid := range idx.usesOf[v] {
			if idx.inFuncLit[uid] || idx.inGoStmt[uid] {
				return false
			}
			up := idx.parentUnparen(uid)
			if bs, isBin := up.(*ast.BinaryExpr); isBin && (bs.Op == token.EQL || bs.Op == token.NEQ) {
				continue
			}
			if usel, isUS := up.(*ast.SelectorExpr); isUS && ast.Unparen(usel.X) == uid {
				if mc, isMC := idx.parentUnparen(usel).(*ast.CallExpr); isMC && ast.Unparen(mc.Fun) == usel {
					if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) || exprResultStaysLocalWithDepth(p, idx, mc, nonEscAuxVars, depth+1) {
						continue
					}
				}
			}
			if upTA, isTA := up.(*ast.TypeAssertExpr); isTA && ast.Unparen(upTA.X) == uid && upTA.Type != nil {
				if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(upTA)) || exprResultStaysLocalWithDepth(p, idx, upTA, nonEscAuxVars, depth+1) {
					continue
				}
			}
			if upAs, isUpAs := up.(*ast.AssignStmt); isUpAs && len(upAs.Lhs) == 1 && len(upAs.Rhs) == 1 && ast.Unparen(upAs.Rhs[0]) == uid {
				if ix, isIx := ast.Unparen(upAs.Lhs[0]).(*ast.IndexExpr); isIx {
					mv := lookupIdentVar(p, ix.X)
					enclFD := idx.syncEnclFuncDecl(uid)
					if mv != nil && nonEscAuxVars[mv] && idx.defCounts[mv] == 1 && mv.Parent() != p.Types.Scope() &&
						enclFD != nil && enclFD.Body != nil && enclFD.Body.Pos() <= mv.Pos() && mv.Pos() < enclFD.Body.End() {
						allMapReadsLocal := true
						for _, muid := range idx.usesOf[mv] {
							if idx.inFuncLit[muid] || idx.inGoStmt[muid] {
								allMapReadsLocal = false
								break
							}
							mix, isMix := idx.parentUnparen(muid).(*ast.IndexExpr)
							if !isMix || ast.Unparen(mix.X) != muid {
								allMapReadsLocal = false
								break
							}
							if mAs, isMAs := idx.parentUnparen(mix).(*ast.AssignStmt); isMAs && len(mAs.Lhs) == 1 && ast.Unparen(mAs.Lhs[0]) == mix {
								continue
							}
							if !exprResultStaysLocalWithDepth(p, idx, mix, nonEscAuxVars, depth+1) {
								allMapReadsLocal = false
								break
							}
						}
						if allMapReadsLocal {
							continue
						}
					}
				}
			}
			return false
		}
		return true
	}

	cur := ast.Unparen(start)
	for {
		par := idx.parentUnparen(cur)
		switch x := par.(type) {
		case *ast.TypeAssertExpr:
			if ast.Unparen(x.X) == cur && x.Type != nil {
				if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x)) {
					return true
				}
				cur = x
				continue
			}
			return false
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				si := p.TypesInfo.Selections[x]
				if si != nil && si.Kind() == types.MethodVal {
					mc, isMC := idx.parentUnparen(x).(*ast.CallExpr)
					if !isMC || ast.Unparen(mc.Fun) != x {
						return false
					}
					for _, ma := range mc.Args {
						if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
							return false
						}
					}
					if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) {
						return true
					}
					cur = mc
					continue
				}
			}
			return false
		case *ast.BinaryExpr:
			return x.Op == token.EQL || x.Op == token.NEQ
		case *ast.CallExpr:
			// E.g. imps.importPublic(imp.Imports()) where imps is a nonEscAuxVars local!
			if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
				if mv := lookupIdentVar(p, sel.X); mv != nil && nonEscAuxVars[mv] {
					callee := resolveCalledFuncObj(p, x.Fun)
					if callee != nil && callee.Pkg() == p.Types && !callee.Exported() {
						return true
					}
				}
			}
			return false
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && ast.Unparen(x.Rhs[0]) == cur {
				if len(x.Lhs) == 2 && (isBlankIdentExpr(x.Lhs[1]) || !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x.Lhs[1]))) {
					if isBlankIdentExpr(x.Lhs[0]) {
						return true
					}
					if lid, isID := ast.Unparen(x.Lhs[0]).(*ast.Ident); isID {
						v, _ := p.TypesInfo.Defs[lid].(*types.Var)
						return checkBoundLocalVar(v)
					}
				}
				if len(x.Lhs) == 1 {
					if isBlankIdentExpr(x.Lhs[0]) {
						return true
					}
					if lid, isID := ast.Unparen(x.Lhs[0]).(*ast.Ident); isID {
						v, _ := p.TypesInfo.Defs[lid].(*types.Var)
						return checkBoundLocalVar(v)
					}
				}
			}
			return false
		default:
			return false
		}
	}
}

func computeLocalNonEscapingAuxVars(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	allFDs []*ast.FuncDecl,
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
) map[*types.Var]bool {
	// Track local maps/structs (such as r1 := make(descsByName), imps := importSet{...},
	// r2 := &resolver{local: r1, ...}) that never escape to globals, returns, closures, or foreign calls,
	// plus receiver/parameter vars of unexported helpers whose every caller passes a nonEscAuxVar!
	cands := map[*types.Var]bool{}
	for _, fd := range allFDs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Lhs) == len(s.Rhs) && s.Tok == token.DEFINE {
					for i, l := range s.Lhs {
						if lid, isID := ast.Unparen(l).(*ast.Ident); isID {
							v, _ := p.TypesInfo.Defs[lid].(*types.Var)
							if v != nil && idx.defCounts[v] == 1 && !idx.inFuncLit[lid] && !idx.inGoStmt[lid] && isAuxLocalInit(p, s.Rhs[i]) {
								cands[v] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	for fn := range eligibleUnexported {
		sig, okS := fn.Type().(*types.Signature)
		if !okS || len(idx.usesOf[fn]) == 0 {
			continue
		}
		if sig.Recv() != nil {
			cands[sig.Recv()] = true
		}
		for i := 0; i < sig.Params().Len(); i++ {
			cands[sig.Params().At(i)] = true
		}
	}

	for {
		changed := false
		// Check local uses of every candidate v:
		for v := range cands {
			bad := false
			for _, uid := range idx.usesOf[v] {
				if idx.inFuncLit[uid] || idx.inGoStmt[uid] {
					bad = true
					break
				}
				par := idx.parentUnparen(uid)
				switch x := par.(type) {
				case *ast.IndexExpr:
					if ast.Unparen(x.X) == uid {
						// Map lookup/store r[k]: ensure looked-up value is not mutated!
						if identReachesMutatedOrAddrPrefix(p, idx, uid) {
							// Store `r[k] = val` is fine; mutating `r[k].Field = ...` is NOT!
							if as, isAs := idx.parentUnparen(x).(*ast.AssignStmt); !isAs || len(as.Lhs) != 1 || ast.Unparen(as.Lhs[0]) != x {
								bad = true
							}
						}
						continue
					}
					bad = true
				case *ast.SelectorExpr:
					if ast.Unparen(x.X) == uid {
						si := p.TypesInfo.Selections[x]
						if si != nil && si.Kind() == types.FieldVal {
							// Reading/writing field on local resolver struct (`r.local[s]`, `r.allowUnresolvable`, `r.imports[...]`):
							continue
						}
						if si != nil && si.Kind() == types.MethodVal {
							mc, isMC := idx.parentUnparen(x).(*ast.CallExpr)
							if isMC && ast.Unparen(mc.Fun) == x {
								callee := resolveCalledFuncObj(p, mc.Fun)
								if callee != nil && eligibleUnexported[callee.Origin()] != nil {
									if cSig, okCS := callee.Origin().Type().(*types.Signature); okCS && cSig.Recv() != nil && cands[cSig.Recv()] {
										continue
									}
								}
							}
						}
					}
					bad = true
				case *ast.KeyValueExpr:
					if ast.Unparen(x.Value) == uid {
						if cl, isCL := idx.parentUnparen(x).(*ast.CompositeLit); isCL {
							holder := cl
							var holderNode ast.Expr = holder
							if un, isUn := idx.parentUnparen(cl).(*ast.UnaryExpr); isUn && un.Op == token.AND {
								holderNode = un
							}
							if as, isAs := idx.parentUnparen(holderNode).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && as.Tok == token.DEFINE {
								if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
									if dv, _ := p.TypesInfo.Defs[lid].(*types.Var); dv != nil && cands[dv] {
										continue
									}
								}
							}
						}
					}
					bad = true
				case *ast.CallExpr:
					callee := resolveCalledFuncObj(p, x.Fun)
					if callee != nil && eligibleUnexported[callee.Origin()] != nil && !x.Ellipsis.IsValid() {
						cSig, _ := callee.Origin().Type().(*types.Signature)
						matchedParam := false
						for ai, a := range x.Args {
							if ast.Unparen(a) == uid && cSig != nil && ai < cSig.Params().Len() && cands[cSig.Params().At(ai)] {
								matchedParam = true
							}
						}
						if matchedParam {
							continue
						}
					}
					bad = true
				default:
					bad = true
				}
				if bad {
					break
				}
			}
			if bad {
				delete(cands, v)
				changed = true
			}
		}
		// Check parameter/receiver candidates: every call site of fn must pass a candidate in cands!
		for fn := range eligibleUnexported {
			sig, okS := fn.Type().(*types.Signature)
			if !okS {
				continue
			}
			if rv := sig.Recv(); rv != nil && cands[rv] {
				for _, uid := range idx.usesOf[fn] {
					call := enclosingCallOfCalleeIdent(idx, uid)
					okSite := false
					if call != nil {
						if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
							if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
								if mv := lookupIdentVar(p, sel.X); mv != nil && cands[mv] {
									okSite = true
								}
							}
						}
					}
					if !okSite {
						delete(cands, rv)
						changed = true
						break
					}
				}
			}
			for pi := 0; pi < sig.Params().Len(); pi++ {
				pv := sig.Params().At(pi)
				if !cands[pv] {
					continue
				}
				for _, uid := range idx.usesOf[fn] {
					call := enclosingCallOfCalleeIdent(idx, uid)
					if call == nil || call.Ellipsis.IsValid() || pi >= len(call.Args) {
						delete(cands, pv)
						changed = true
						break
					}
					mv := lookupIdentVar(p, call.Args[pi])
					if mv == nil || !cands[mv] {
						delete(cands, pv)
						changed = true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	return cands
}

func isAuxLocalInit(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return true
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			_, ok := ast.Unparen(e.X).(*ast.CompositeLit)
			return ok
		}
	case *ast.CallExpr:
		if id, isID := ast.Unparen(e.Fun).(*ast.Ident); isID {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && (b.Name() == "make" || b.Name() == "new") {
				return true
			}
		}
	}
	return false
}

func initNonEscapingIntraParams(
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
) (
	nonEsc map[*types.Func]map[int]bool,
	mapStore map[*types.Func]map[int]int,
	retStruct map[*types.Func]map[int]bool,
	guardPkgs map[*types.Func]map[int]map[string]bool,
) {
	nonEsc = map[*types.Func]map[int]bool{}
	mapStore = map[*types.Func]map[int]int{}
	retStruct = map[*types.Func]map[int]bool{}
	guardPkgs = map[*types.Func]map[int]map[string]bool{}

	for fn := range eligibleUnexported {
		sig, okS := fn.Type().(*types.Signature)
		if !okS {
			continue
		}
		nonEsc[fn] = map[int]bool{}
		if sig.Recv() != nil {
			nonEsc[fn][-1] = true
		}
		for i := 0; i < sig.Params().Len(); i++ {
			nonEsc[fn][i] = true
		}
	}
	return nonEsc, mapStore, retStruct, guardPkgs
}

func resolveSummaryRootVar(p *packages.Package, sum *freshFuncSummary, expr ast.Expr) *types.Var {
	if sum == nil {
		return nil
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if st := sum.vars[v]; st != nil {
				return st.rootVar
			}
			return nil
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
				return nil
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		default:
			return nil
		}
	}
}

func stepNonEscapingIntraParams(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	pf *pkgFreshConstructors,
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
	freshReturnFuncs map[*types.Func]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	nonEsc map[*types.Func]map[int]bool,
	mapStore map[*types.Func]map[int]int,
	retStruct map[*types.Func]map[int]bool,
	guardPkgs map[*types.Func]map[int]map[string]bool,
) bool {
	isMethodChainFromTracked := func(expr ast.Expr, tracked map[*types.Var]bool) bool {
		cur := ast.Unparen(expr)
		sawCall := false
		for {
			mc, isMC := cur.(*ast.CallExpr)
			if !isMC || mc.Ellipsis.IsValid() {
				break
			}
			for _, ma := range mc.Args {
				if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
					return false
				}
			}
			sel, isSel := ast.Unparen(mc.Fun).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			si := p.TypesInfo.Selections[sel]
			if si == nil || si.Kind() != types.MethodVal {
				return false
			}
			sawCall = true
			cur = ast.Unparen(sel.X)
		}
		if !sawCall {
			return false
		}
		for {
			sel, isSel := cur.(*ast.SelectorExpr)
			if !isSel {
				break
			}
			si := p.TypesInfo.Selections[sel]
			if si == nil || si.Kind() != types.FieldVal {
				return false
			}
			cur = ast.Unparen(sel.X)
		}
		v := lookupIdentVar(p, cur)
		return v != nil && tracked[v]
	}

	anyChanged := false
	for {
		changed := false
		for fn, fd := range eligibleUnexported {
			sig, _ := fn.Type().(*types.Signature)
			slots := nonEsc[fn]
			if len(slots) == 0 || sig == nil {
				continue
			}
			paramSlotOfVar := map[*types.Var]int{}
			if sig.Recv() != nil {
				paramSlotOfVar[sig.Recv()] = -1
			}
			for i := 0; i < sig.Params().Len(); i++ {
				paramSlotOfVar[sig.Params().At(i)] = i
			}

			checkSlot := func(slot int, pv *types.Var) (ok bool, needMapSlot int, hasMap bool, needRet bool, slotGuards map[string]bool) {
				hasMap = false
				slotGuards = map[string]bool{}
				trackedVars := map[*types.Var]bool{pv: true}
				returnOnlyVars := map[*types.Var]bool{}

				// Close trackedVars over TypeSwitchStmt implicit vars and local interface variables
				// initialized/assigned exclusively from method chains on trackedVars (e.g. md := fd.Message(),
				// kf := md.Fields().Get(0), var evs ...; evs = fd.Enum().Values()).
				for {
					addedTracked := false
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						switch s := n.(type) {
						case *ast.TypeSwitchStmt:
							var switchedExpr ast.Expr
							if as, isAs := s.Assign.(*ast.AssignStmt); isAs && len(as.Rhs) == 1 {
								if ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr); isTA {
									switchedExpr = ta.X
								}
							}
							if sv := lookupIdentVar(p, switchedExpr); sv != nil && trackedVars[sv] && s.Body != nil {
								for _, st := range s.Body.List {
									if cc, isCC := st.(*ast.CaseClause); isCC {
										if imp, okI := p.TypesInfo.Implicits[cc].(*types.Var); okI && imp != nil && !trackedVars[imp] {
											trackedVars[imp] = true
											addedTracked = true
										}
									}
								}
							}
						case *ast.AssignStmt:
							if len(s.Lhs) == 1 && len(s.Rhs) == 1 && isMethodChainFromTracked(s.Rhs[0], trackedVars) {
								if lid, isID := ast.Unparen(s.Lhs[0]).(*ast.Ident); isID {
									var lv *types.Var
									if dv, okD := p.TypesInfo.Defs[lid].(*types.Var); okD && dv != nil && idx.defCounts[dv] == 1 {
										lv = dv
									} else if uv, okU := p.TypesInfo.Uses[lid].(*types.Var); okU && uv != nil && uv.Parent() != p.Types.Scope() && !paramSlotHas(paramSlotOfVar, uv) && idx.defCounts[uv] == 1 {
										lv = uv
									}
									if lv != nil && types.IsInterface(lv.Type()) && !trackedVars[lv] {
										// Ensure every assignment to lv in fd.Body is a method chain from trackedVars.
										allFromTracked := true
										for _, uid := range idx.usesOf[lv] {
											if upAs, isUpAs := idx.parentUnparen(uid).(*ast.AssignStmt); isUpAs {
												for _, lhs := range upAs.Lhs {
													if ast.Unparen(lhs) == uid {
														if len(upAs.Lhs) != 1 || len(upAs.Rhs) != 1 || !isMethodChainFromTracked(upAs.Rhs[0], trackedVars) {
															allFromTracked = false
														}
													}
												}
											}
										}
										if allFromTracked {
											trackedVars[lv] = true
											addedTracked = true
										}
									}
								}
							}
						}
						return true
					})
					if !addedTracked {
						break
					}
				}

				mcResultAccounted := func(mc *ast.CallExpr) bool {
					if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) && !containsUintptr(p.TypesInfo.TypeOf(mc)) {
						return true
					}
					if callResultStaysLocal(p, idx, mc, nil) {
						return true
					}
					// Assigned into a trackedVars local (e.g. md := fd.Message() or evs = fd.Enum().Values())!
					curOut := ast.Expr(mc)
					for {
						upSel, isUS := idx.parentUnparen(curOut).(*ast.SelectorExpr)
						if !isUS || ast.Unparen(upSel.X) != curOut {
							break
						}
						si := p.TypesInfo.Selections[upSel]
						if si == nil || si.Kind() != types.MethodVal {
							break
						}
						upMC, isUMC := idx.parentUnparen(upSel).(*ast.CallExpr)
						if !isUMC || ast.Unparen(upMC.Fun) != upSel {
							return false
						}
						for _, ma := range upMC.Args {
							if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
								return false
							}
						}
						if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(upMC)) && !containsUintptr(p.TypesInfo.TypeOf(upMC)) {
							return true
						}
						curOut = upMC
					}
					if as, isAs := idx.parentUnparen(curOut).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == curOut {
						if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
							var lv *types.Var
							if dv, okD := p.TypesInfo.Defs[lid].(*types.Var); okD {
								lv = dv
							} else if uv, okU := p.TypesInfo.Uses[lid].(*types.Var); okU {
								lv = uv
							}
							if lv != nil && trackedVars[lv] {
								return true
							}
						}
					}
					// Returned inside a CompositeLit at result 0 (with optional type assertion `.(*filedesc.File)` as in `makeBase`)!
					kvParent := idx.parentUnparen(curOut)
					if ta, isTA := kvParent.(*ast.TypeAssertExpr); isTA && ast.Unparen(ta.X) == curOut && ta.Type != nil {
						kvParent = idx.parentUnparen(ta)
					}
					if kv, isKV := kvParent.(*ast.KeyValueExpr); isKV {
						if cl, isCL := idx.parentUnparen(kv).(*ast.CompositeLit); isCL {
							if ret, isRet := idx.parentUnparen(cl).(*ast.ReturnStmt); isRet && len(ret.Results) >= 1 && ast.Unparen(ret.Results[0]) == cl {
								needRet = true
								return true
							}
						}
					}
					return false
				}

				for tv := range trackedVars {
					for _, uid := range idx.usesOf[tv] {
						if idx.inFuncLit[uid] || idx.inGoStmt[uid] {
							return false, 0, false, false, nil
						}
						// Skip LHS occurrence of a tracked local `evs = fd.Enum().Values()` (already verified above).
						if tv != pv {
							if upAs, isUpAs := idx.parentUnparen(uid).(*ast.AssignStmt); isUpAs && len(upAs.Lhs) == 1 && ast.Unparen(upAs.Lhs[0]) == uid {
								continue
							}
						}
						cur := ast.Expr(uid)
						methodHandled := false
						for {
							par := idx.parentUnparen(cur)
							if sel, isS := par.(*ast.SelectorExpr); isS && ast.Unparen(sel.X) == cur {
								si := p.TypesInfo.Selections[sel]
								if si != nil && si.Kind() == types.FieldVal {
									cur = sel
									continue
								}
								if si != nil && si.Kind() == types.MethodVal {
									mc, isMC := idx.parentUnparen(sel).(*ast.CallExpr)
									if !isMC || ast.Unparen(mc.Fun) != sel || mc.Ellipsis.IsValid() {
										return false, 0, false, false, nil
									}
									for _, ma := range mc.Args {
										if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
											return false, 0, false, false, nil
										}
									}
									if !mcResultAccounted(mc) {
										return false, 0, false, false, nil
									}
									methodHandled = true
								}
							}
							break
						}
						if methodHandled {
							continue
						}
						par := idx.parentUnparen(cur)
						switch x := par.(type) {
						case *ast.TypeAssertExpr:
							if ast.Unparen(x.X) == cur {
								if x.Type == nil {
									// `switch x := pv.(type)` header!
									continue
								}
								// `_, ok := parent.(protoreflect.EnumDescriptor)` boolean check!
								if as, isAs := idx.parentUnparen(x).(*ast.AssignStmt); isAs && len(as.Lhs) == 2 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == x && isBlankIdentExpr(as.Lhs[0]) {
									continue
								}
							}
							return false, 0, false, false, nil
						case *ast.AssignStmt:
							for _, l := range x.Lhs {
								if ast.Unparen(l) == cur {
									// Non-fresh helper must not mutate pv (unless freshParamFuncs handles it separately)!
									return false, 0, false, false, nil
								}
							}
							if len(x.Lhs) == 1 && len(x.Rhs) == 1 && ast.Unparen(x.Rhs[0]) == cur {
								if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
									continue
								}
								// Check `r[k] = pv` (e.g. `r[fullName] = child` in `makeBase`)!
								if ix, isIx := ast.Unparen(x.Lhs[0]).(*ast.IndexExpr); isIx && cur == uid {
									if mv := lookupIdentVar(p, ix.X); mv != nil {
										if ms, okMS := paramSlotOfVar[mv]; okMS {
											if hasMap && needMapSlot != ms {
												return false, 0, false, false, nil
											}
											hasMap = true
											needMapSlot = ms
											continue
										}
									}
								}
							}
							return false, 0, false, false, nil
						case *ast.KeyValueExpr:
							// `return BaseL0{..., Parent: parent}` in `makeBase`!
							if ast.Unparen(x.Value) == cur && cur == uid {
								if cl, isCL := idx.parentUnparen(x).(*ast.CompositeLit); isCL {
									if ret, isRet := idx.parentUnparen(cl).(*ast.ReturnStmt); isRet && len(ret.Results) >= 1 && ast.Unparen(ret.Results[0]) == cl {
										needRet = true
										continue
									}
								}
							}
							return false, 0, false, false, nil
						case *ast.BinaryExpr:
							if x.Op == token.EQL || x.Op == token.NEQ || !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							return false, 0, false, false, nil
						case *ast.CallExpr:
							if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							callee := resolveCalledFuncObj(p, x.Fun)
							if callee == nil || x.Ellipsis.IsValid() {
								return false, 0, false, false, nil
							}
							orig := callee.Origin()
							if orig.Pkg() != nil && orig.Pkg() != p.Types {
								// Guarded external helper call (e.g. `v, ev, err := defval.Unmarshal(s, fd.Kind(), evs, defval.Descriptor)`):
								// record `orig.Pkg().Path()` in `slotGuards` and verify any non-error carrier result is returned only via `needRet`!
								slotGuards[orig.Pkg().Path()] = true
								if !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x)) && !containsUintptr(p.TypesInfo.TypeOf(x)) {
									continue
								}
								as, isAs := idx.parentUnparen(x).(*ast.AssignStmt)
								if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != x {
									return false, 0, false, false, nil
								}
								for _, lhs := range as.Lhs {
									if isBlankIdentExpr(lhs) {
										continue
									}
									lt := p.TypesInfo.TypeOf(lhs)
									if (!TypeContainsRefOrPointer(lt) && !containsUintptr(lt)) || isErrorType(lt) {
										continue
									}
									lid, isID := ast.Unparen(lhs).(*ast.Ident)
									if !isID {
										return false, 0, false, false, nil
									}
									lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
									if !isDef || lv == nil || idx.defCounts[lv] != 1 {
										return false, 0, false, false, nil
									}
									returnOnlyVars[lv] = true
									needRet = true
								}
								continue
							}
							if orig.Pkg() != p.Types || eligibleUnexported[orig] == nil {
								return false, 0, false, false, nil
							}
							matched := false
							calleeNeedsRet := false
							for ai, a := range x.Args {
								if ast.Unparen(a) == cur {
									cSlot := ai
									if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
										if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodExpr {
											cSlot = ai - 1
										}
									}
									if !nonEsc[orig][cSlot] {
										matched = false
										break
									}
									matched = true
									for g := range guardPkgs[orig][cSlot] {
										slotGuards[g] = true
									}
									if origMSlot, hasOrigMap := mapStore[orig][cSlot]; hasOrigMap {
										var mapArg ast.Expr
										if origMSlot == -1 {
											if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
												if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
													mapArg = sel.X
												} else if si != nil && si.Kind() == types.MethodExpr && len(x.Args) > 0 {
													mapArg = x.Args[0]
												}
											}
										} else if origMSlot >= 0 && origMSlot < len(x.Args) {
											mapArg = x.Args[origMSlot]
										}
										mv := lookupIdentVar(p, mapArg)
										if mv == nil {
											matched = false
											break
										}
										if !nonEscAuxVars[mv] {
											callerMSlot, okCMS := paramSlotOfVar[mv]
											if !okCMS || (hasMap && needMapSlot != callerMSlot) {
												matched = false
												break
											}
											hasMap = true
											needMapSlot = callerMSlot
										}
									}
									if retStruct[orig][cSlot] {
										calleeNeedsRet = true
									}
								}
							}
							if !matched {
								return false, 0, false, false, nil
							}
							if calleeNeedsRet {
								callParent := idx.parentUnparen(x)
								if ret, isRet := callParent.(*ast.ReturnStmt); isRet {
									if len(ret.Results) == 0 || ast.Unparen(ret.Results[0]) != x {
										return false, 0, false, false, nil
									}
									needRet = true
									continue
								}
								as, isAs := callParent.(*ast.AssignStmt)
								if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != x || len(as.Lhs) == 0 {
									return false, 0, false, false, nil
								}
								fnSum := pf.funcs[fd]
								for _, lhs := range as.Lhs {
									if isBlankIdentExpr(lhs) {
										continue
									}
									lt := p.TypesInfo.TypeOf(lhs)
									if (!TypeContainsRefOrPointer(lt) && !containsUintptr(lt)) || isErrorType(lt) {
										continue
									}
									if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID {
										lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
										if !isDef || lv == nil || idx.defCounts[lv] != 1 {
											return false, 0, false, false, nil
										}
										returnOnlyVars[lv] = true
										needRet = true
										continue
									}
									sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
									if !isSel || !freshReturnFuncs[fn] || fdInConfinedCache(fd, confinedCacheMaps) || fnSum == nil {
										return false, 0, false, false, nil
									}
									if !pf.isFreshContainerAt(fnSum, sel.X, as.Pos()) {
										return false, 0, false, false, nil
									}
									dstRoot := resolveSummaryRootVar(p, fnSum, sel.X)
									if dstRoot == nil || paramSlotHas(paramSlotOfVar, dstRoot) {
										return false, 0, false, false, nil
									}
									rootSt := fnSum.vars[dstRoot]
									if rootSt == nil || rootSt.rootVar != dstRoot || rootSt.escapePos != token.NoPos {
										return false, 0, false, false, nil
									}
									needRet = true
								}
							}
							continue
						default:
							if cur != uid && !TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							return false, 0, false, false, nil
						}
					}
				}

				// Verify every `returnOnlyVars` variable (`v`, `ev` from `defval.Unmarshal`) is only
				// returned from `fn` or reassigned from a scalar-arg external constructor (`filedesc.PlaceholderEnumValue`).
				for rv := range returnOnlyVars {
					for _, uid := range idx.usesOf[rv] {
						if idx.inFuncLit[uid] || idx.inGoStmt[uid] {
							return false, 0, false, false, nil
						}
						par := idx.parentUnparen(uid)
						if _, isRet := par.(*ast.ReturnStmt); isRet {
							continue
						}
						if as, isAs := par.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Lhs[0]) == uid {
							rhs := ast.Unparen(as.Rhs[0])
							if c, isC := rhs.(*ast.CallExpr); isC && !c.Ellipsis.IsValid() {
								extFn := resolveCalledFuncObj(p, c.Fun)
								if extFn != nil && extFn.Origin().Pkg() != nil {
									allScalarArgs := true
									for _, ca := range c.Args {
										if TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ca)) || containsUintptr(p.TypesInfo.TypeOf(ca)) {
											allScalarArgs = false
											break
										}
									}
									if allScalarArgs {
										if extFn.Origin().Pkg() != p.Types {
											slotGuards[extFn.Origin().Pkg().Path()] = true
										}
										continue
									}
								}
							}
						}
						return false, 0, false, false, nil
					}
				}

				return true, needMapSlot, hasMap, needRet, slotGuards
			}

			for slot := range slots {
				var pv *types.Var
				if slot == -1 {
					pv = sig.Recv()
				} else if slot >= 0 && slot < sig.Params().Len() {
					pv = sig.Params().At(slot)
				}
				if pv == nil {
					delete(slots, slot)
					changed = true
					continue
				}
				ok, mSlot, hasMap, needRet, sGuards := checkSlot(slot, pv)
				if !ok {
					delete(slots, slot)
					if mapStore[fn] != nil {
						delete(mapStore[fn], slot)
					}
					if retStruct[fn] != nil {
						delete(retStruct[fn], slot)
					}
					if guardPkgs[fn] != nil {
						delete(guardPkgs[fn], slot)
					}
					changed = true
					continue
				}
				if hasMap {
					if mapStore[fn] == nil {
						mapStore[fn] = map[int]int{}
					}
					if prev, had := mapStore[fn][slot]; !had || prev != mSlot {
						mapStore[fn][slot] = mSlot
						changed = true
					}
				}
				if needRet {
					if retStruct[fn] == nil {
						retStruct[fn] = map[int]bool{}
					}
					if !retStruct[fn][slot] {
						retStruct[fn][slot] = true
						changed = true
					}
				}
				if len(sGuards) > 0 {
					if guardPkgs[fn] == nil {
						guardPkgs[fn] = map[int]map[string]bool{}
					}
					if guardPkgs[fn][slot] == nil {
						guardPkgs[fn][slot] = map[string]bool{}
					}
					for g := range sGuards {
						if !guardPkgs[fn][slot][g] {
							guardPkgs[fn][slot][g] = true
							changed = true
						}
					}
				}
			}
		}
		if changed {
			anyChanged = true
		} else {
			break
		}
	}
	return anyChanged
}

func paramSlotHas(m map[*types.Var]int, v *types.Var) bool {
	_, ok := m[v]
	return ok
}

func findMutexConfinedConstructorCaches(p *packages.Package, idx *pkgSyntaxIndex) map[*types.Var]map[*ast.FuncDecl]bool {
	out := map[*types.Var]map[*ast.FuncDecl]bool{}
	for _, name := range p.Types.Scope().Names() {
		mv, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || mv == nil || mv.Exported() {
			continue
		}
		mapT, isMap := types.Unalias(mv.Type()).Underlying().(*types.Map)
		if !isMap || !isNamedInPkg(mapT.Key(), "reflect", "Type") {
			continue
		}
		if len(idx.usesOf[mv]) == 0 {
			continue
		}
		// Find an entry function fd whose stmts[0] is mu.Lock() and stmts[1] is defer mu.Unlock()
		// on an unexported package-scope sync.Mutex mu, such that EVERY use of mu and mv across
		// p.Syntax lies synchronously inside {entryFD} U computeExclusiveHelperCone(p, idx, entryFn),
		// mv is initialized solely via `if mv == nil { mv = make(...) }`, and every read of mv[k]
		// is a comma-ok early-return hit check `if v, ok := mv[k]; ok { return v }`.
		for entryFn, entryFD := range idx.funcDecls {
			if entryFn == nil || entryFD == nil || entryFD.Body == nil || len(entryFD.Body.List) < 3 {
				continue
			}
			muVar := matchPkgMutexLockDeferUnlock(p, entryFD.Body.List[0], entryFD.Body.List[1])
			if muVar == nil || muVar.Exported() {
				continue
			}
			coneFuncs := computeExclusiveHelperCone(p, idx, entryFn)
			coneFDs := map[*ast.FuncDecl]bool{entryFD: true}
			for cf := range coneFuncs {
				if cfd := idx.funcDecls[cf]; cfd != nil {
					coneFDs[cfd] = true
				}
			}
			// Verify muVar is ONLY used at entryFD.Body.List[0] and entryFD.Body.List[1]!
			if len(idx.usesOf[muVar]) != 2 {
				continue
			}
			allMuInEntry := true
			for _, u := range idx.usesOf[muVar] {
				if !idx.isSyncInFuncDecl(u, entryFD) ||
					!((entryFD.Body.List[0].Pos() <= u.Pos() && u.Pos() < entryFD.Body.List[0].End()) ||
						(entryFD.Body.List[1].Pos() <= u.Pos() && u.Pos() < entryFD.Body.List[1].End())) {
					allMuInEntry = false
					break
				}
			}
			if !allMuInEntry {
				continue
			}
			// Verify mv is ONLY used synchronously inside coneFDs, initialized only when nil,
			// and never &mv-taken or mutated on lookup!
			allMapOK := true
			for _, u := range idx.usesOf[mv] {
				encl := idx.syncEnclFuncDecl(u)
				if !coneFDs[encl] {
					allMapOK = false
					break
				}
				par := idx.parentUnparen(u)
				switch x := par.(type) {
				case *ast.BinaryExpr:
					if (x.Op != token.EQL && x.Op != token.NEQ) || (!isNilIdent(p, x.X) && !isNilIdent(p, x.Y)) {
						allMapOK = false
					}
				case *ast.AssignStmt:
					if len(x.Lhs) == 1 && len(x.Rhs) == 1 && ast.Unparen(x.Lhs[0]) == u {
						cid, isID := ast.Unparen(x.Rhs[0]).(*ast.CallExpr)
						blk, isBlk := idx.parentMap[x].(*ast.BlockStmt)
						var enclosingIf *ast.IfStmt
						if isBlk && len(blk.List) == 1 {
							enclosingIf, _ = idx.parentMap[blk].(*ast.IfStmt)
						}
						condNil := false
						if enclosingIf != nil && enclosingIf.Else == nil {
							if bc, isBC := ast.Unparen(enclosingIf.Cond).(*ast.BinaryExpr); isBC && bc.Op == token.EQL {
								condNil = (lookupPkgScopeVar(p, bc.X) == mv && isNilIdent(p, bc.Y)) ||
									(lookupPkgScopeVar(p, bc.Y) == mv && isNilIdent(p, bc.X))
							}
						}
						if !isID || !isMakeCall(p, cid) || !condNil {
							allMapOK = false
						}
					} else {
						allMapOK = false
					}
				case *ast.IndexExpr:
					if ast.Unparen(x.X) != u {
						allMapOK = false
						break
					}
					up := idx.parentUnparen(x)
					if as, isAs := up.(*ast.AssignStmt); isAs {
						if len(as.Lhs) == 1 && ast.Unparen(as.Lhs[0]) == x {
							continue
						}
						if len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == x && len(as.Lhs) == 2 {
							lid, isID0 := ast.Unparen(as.Lhs[0]).(*ast.Ident)
							okID, isID1 := ast.Unparen(as.Lhs[1]).(*ast.Ident)
							ifStmt, isIfInit := idx.parentMap[as].(*ast.IfStmt)
							if isID0 && isID1 && isIfInit && ifStmt.Init == as && ifStmt.Else == nil && ifStmt.Body != nil && len(ifStmt.Body.List) == 1 {
								lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
								okV, _ := p.TypesInfo.Defs[okID].(*types.Var)
								condIdent, isCondID := ast.Unparen(ifStmt.Cond).(*ast.Ident)
								retSt, isRet := ifStmt.Body.List[0].(*ast.ReturnStmt)
								if lv != nil && okV != nil && isCondID && p.TypesInfo.Uses[condIdent] == okV &&
									isRet && len(retSt.Results) == 1 {
									if rid, isRID := ast.Unparen(retSt.Results[0]).(*ast.Ident); isRID && p.TypesInfo.Uses[rid] == lv {
										for _, lu := range idx.usesOf[lv] {
											if identReachesMutatedOrAddrPrefix(p, idx, lu) {
												allMapOK = false
												break
											}
										}
										continue
									}
								}
							}
						}
					}
					allMapOK = false
				default:
					allMapOK = false
				}
				if !allMapOK {
					break
				}
			}
			if allMapOK {
				out[mv] = coneFDs
				break
			}
		}
	}
	return out
}

func matchPkgMutexLockDeferUnlock(p *packages.Package, s0, s1 ast.Stmt) *types.Var {
	es0, ok0 := s0.(*ast.ExprStmt)
	df1, ok1 := s1.(*ast.DeferStmt)
	if !ok0 || !ok1 {
		return nil
	}
	c0, okC0 := ast.Unparen(es0.X).(*ast.CallExpr)
	if !okC0 || len(c0.Args) != 0 || len(df1.Call.Args) != 0 {
		return nil
	}
	sel0, okS0 := ast.Unparen(c0.Fun).(*ast.SelectorExpr)
	sel1, okS1 := ast.Unparen(df1.Call.Fun).(*ast.SelectorExpr)
	if !okS0 || !okS1 || sel0.Sel.Name != "Lock" || sel1.Sel.Name != "Unlock" {
		return nil
	}
	v0 := lookupPkgScopeVar(p, sel0.X)
	v1 := lookupPkgScopeVar(p, sel1.X)
	if v0 == nil || v0 != v1 || !isNamedInPkg(v0.Type(), "sync", "Mutex") {
		return nil
	}
	return v0
}

func isMakeCall(p *packages.Package, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
	return isB && b.Name() == "make"
}

func fdInConfinedCache(fd *ast.FuncDecl, confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool) bool {
	if fd == nil {
		return false
	}
	for _, fds := range confinedCacheMaps {
		if fds[fd] {
			return true
		}
	}
	return false
}

func isOpaqueUnexportedForeignStruct(curPkg *types.Package, named *types.Named) bool {
	if named == nil || named.Obj() == nil || named.Obj().Exported() ||
		named.Obj().Pkg() == nil || named.Obj().Pkg() == curPkg {
		return false
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() || f.Embedded() {
			return false
		}
	}
	mset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < mset.Len(); i++ {
		if mset.At(i).Obj().Exported() {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Shared AST / types helpers for discharges_proto.go
// -----------------------------------------------------------------------------

func lookupPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := p.TypesInfo.Uses[id].(*types.Var)
	if !ok || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() {
		return nil
	}
	return v
}

func isAnySliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	iface, ok := types.Unalias(sl.Elem()).Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0
}

func sliceElemNamedStruct(t types.Type) (TypeRef, *types.Named, bool) {
	if t == nil {
		return TypeRef{}, nil, false
	}
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return TypeRef{}, nil, false
	}
	if _, isPtr := types.Unalias(sl.Elem()).(*types.Pointer); isPtr {
		return TypeRef{}, nil, false
	}
	return typeRefOfNamedStruct(sl.Elem())
}

func sliceElemStructRef(t types.Type) (TypeRef, bool) {
	ref, _, ok := sliceElemNamedStruct(t)
	return ref, ok
}

func extractSliceVarOrSubslice(p *packages.Package, expr ast.Expr) (*types.Var, *ast.Ident, bool) {
	expr = ast.Unparen(expr)
	if id, ok := expr.(*ast.Ident); ok {
		v := lookupPkgScopeVar(p, id)
		return v, id, v != nil
	}
	if se, ok := expr.(*ast.SliceExpr); ok && !se.Slice3 {
		if id, okID := ast.Unparen(se.X).(*ast.Ident); okID {
			v := lookupPkgScopeVar(p, id)
			return v, id, v != nil
		}
	}
	return nil, nil, false
}

func isNonNegConstInt(p *packages.Package, expr ast.Expr) bool {
	tv, ok := p.TypesInfo.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	return constant.Sign(tv.Value) >= 0
}

func isTypedNilStructPtrInPkg(p *packages.Package, expr ast.Expr, pkg *types.Package) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() || !isNilIdent(p, call.Args[0]) {
		return false
	}
	ptr, ok := types.Unalias(p.TypesInfo.Types[call.Fun].Type).(*types.Pointer)
	if !ok {
		return false
	}
	st := derefNamedStruct(ptr.Elem())
	return st != nil && st.Obj() != nil && st.Obj().Pkg() == pkg
}

func isMakeFixedSliceCall(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := p.TypesInfo.Uses[id].(*types.Builtin)
	if !ok || b.Name() != "make" || !isNonNegConstInt(p, call.Args[1]) {
		return false
	}
	_, isSlice := types.Unalias(p.TypesInfo.TypeOf(call)).Underlying().(*types.Slice)
	return isSlice
}

func identIsWrittenOrAddrTaken(idx *pkgSyntaxIndex, id *ast.Ident) bool {
	par := idx.parentUnparen(id)
	if pn, ok := par.(*ast.UnaryExpr); ok && pn.Op == token.AND {
		return true
	}
	return identOrExprIsWritten(idx, id)
}

func identOrExprIsWritten(idx *pkgSyntaxIndex, target ast.Expr) bool {
	par := idx.parentUnparen(target)
	switch pn := par.(type) {
	case *ast.AssignStmt:
		for _, lhs := range pn.Lhs {
			if ast.Unparen(lhs) == target {
				return true
			}
		}
	case *ast.IncDecStmt:
		if ast.Unparen(pn.X) == target {
			return true
		}
	case *ast.RangeStmt:
		if pn.Tok == token.ASSIGN {
			if (pn.Key != nil && ast.Unparen(pn.Key) == target) ||
				(pn.Value != nil && ast.Unparen(pn.Value) == target) {
				return true
			}
		}
	}
	return false
}

func structHasExportedIfaceField(st *types.Struct, name string) bool {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() && f.Name() == name && types.IsInterface(f.Type()) {
			return true
		}
	}
	return false
}

func touchesAnyNamedStruct(p *packages.Package, expr ast.Expr, targets map[*types.Named]bool) bool {
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.StarExpr:
			if st := derefNamedStruct(p.TypesInfo.TypeOf(e.X)); st != nil && targets[st] {
				return true
			}
			return false
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				hit := false
				forEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if targets[st] {
						hit = true
					}
				})
				if hit {
					return true
				}
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			if st := derefNamedStruct(p.TypesInfo.TypeOf(e)); st != nil && targets[st] {
				return true
			}
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		default:
			return false
		}
	}
}

func exprIsFuncLit(expr ast.Expr) bool {
	_, ok := ast.Unparen(expr).(*ast.FuncLit)
	return ok
}

func pkgHasAnyMutationOnStructs(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	targets map[*types.Named]bool,
	exempt map[ast.Node]bool,
) bool {
	hit := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			if exempt != nil && exempt[n] {
				return true
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if touchesAnyNamedStruct(p, lhs, targets) {
						hit = true
						return false
					}
				}
			case *ast.IncDecStmt:
				if touchesAnyNamedStruct(p, x.X, targets) {
					hit = true
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && touchesAnyNamedStruct(p, x.Key, targets)) ||
						(x.Value != nil && touchesAnyNamedStruct(p, x.Value, targets)) {
						hit = true
						return false
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if touchesAnyNamedStruct(p, x.Args[0], targets) {
								hit = true
								return false
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if touchesAnyNamedStruct(p, x.X, targets) {
						hit = true
						return false
					}
				}
			}
			return true
		})
	}
	_ = idx
	return hit
}

func resolveCalledFuncObj(p *packages.Package, fun ast.Expr) *types.Func {
	cur := ast.Unparen(fun)
	switch e := cur.(type) {
	case *ast.IndexExpr:
		cur = ast.Unparen(e.X)
	case *ast.IndexListExpr:
		cur = ast.Unparen(e.X)
	}
	switch fn := cur.(type) {
	case *ast.Ident:
		if f, ok := p.TypesInfo.Uses[fn].(*types.Func); ok {
			return f.Origin()
		}
	case *ast.SelectorExpr:
		if f, ok := p.TypesInfo.Uses[fn.Sel].(*types.Func); ok {
			return f.Origin()
		}
	}
	return nil
}

func isReadOnlyEmptyInterfaceCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	firstSeg, _, _ := strings.Cut(pkgPath, "/")
	if strings.Contains(firstSeg, ".") {
		return false
	}
	switch pkgPath {
	case "sync", "sync/atomic", "errors", "log", "log/slog", "testing", "runtime", "context", "cmp":
		return true
	case "reflect":
		return fn.Name() == "TypeOf" || fn.Name() == "DeepEqual"
	case "fmt":
		switch fn.Name() {
		case "Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln", "Sscan", "Sscanf", "Sscanln":
			return false
		default:
			return true
		}
	}
	return false
}

func typeMentionsTypeParam(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		if alias, isAlias := t.(*types.Alias); isAlias {
			if targs := alias.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			t = types.Unalias(t)
		}
		if _, isTP := t.(*types.TypeParam); isTP {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
			if targs := named.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		case *types.Signature:
			walk(u.Params())
			walk(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
			for i := 0; i < u.NumExplicitMethods(); i++ {
				walk(u.ExplicitMethod(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func isSafeAtomicPointerValueArg(p *packages.Package, idx *pkgSyntaxIndex, conv *ast.CallExpr) bool {
	call, ok := idx.parentUnparen(conv).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" {
		return false
	}
	switch fn.Name() {
	case "StorePointer", "SwapPointer":
		return len(call.Args) == 2 && ast.Unparen(call.Args[1]) == conv
	case "CompareAndSwapPointer":
		return len(call.Args) == 3 && ast.Unparen(call.Args[2]) == conv
	}
	return false
}

func isPureAtomicLoadInnerConv(p *packages.Package, idx *pkgSyntaxIndex, conv *ast.CallExpr) bool {
	outerConv, ok := idx.parentUnparen(conv).(*ast.CallExpr)
	if !ok || len(outerConv.Args) != 1 || ast.Unparen(outerConv.Args[0]) != conv || !p.TypesInfo.Types[outerConv.Fun].IsType() {
		return false
	}
	ptr, isPtr := types.Unalias(p.TypesInfo.Types[outerConv.Fun].Type).(*types.Pointer)
	if !isPtr {
		return false
	}
	b, isB := types.Unalias(ptr.Elem()).Underlying().(*types.Basic)
	if !isB || b.Kind() != types.UnsafePointer {
		return false
	}
	call, ok := idx.parentUnparen(outerConv).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != outerConv {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic" && fn.Name() == "LoadPointer"
}

func isFieldMutexCallStmt(p *packages.Package, st ast.Stmt, recvVar, muField *types.Var, method string, wantDefer bool) bool {
	var callExpr ast.Expr
	if wantDefer {
		ds, ok := st.(*ast.DeferStmt)
		if !ok {
			return false
		}
		callExpr = ds.Call
	} else {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			return false
		}
		callExpr = es.X
	}
	call, ok := ast.Unparen(callExpr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	msel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || msel.Sel.Name != method {
		return false
	}
	fn, ok := p.TypesInfo.Uses[msel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
		return false
	}
	fsel, ok := ast.Unparen(msel.X).(*ast.SelectorExpr)
	return ok && isIdentUsingObj(p, fsel.X, recvVar) && p.TypesInfo.Uses[fsel.Sel] == muField
}

func exprMentionsFieldOnRecv(p *packages.Package, expr ast.Expr, recvVar, fld *types.Var) bool {
	hit := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if isIdentUsingObj(p, sel.X, recvVar) && p.TypesInfo.Uses[sel.Sel] == fld {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func isAtomicUint32Call(p *packages.Package, call *ast.CallExpr, name string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic"
}

func isPureAtomicLoadArg(p *packages.Package, idx *pkgSyntaxIndex, addrExpr *ast.UnaryExpr) bool {
	arg := ast.Expr(addrExpr)
	par := idx.parentUnparen(addrExpr)
	for range 2 {
		conv, isConv := par.(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || ast.Unparen(conv.Args[0]) != arg || !p.TypesInfo.Types[conv.Fun].IsType() {
			break
		}
		convT := types.Unalias(p.TypesInfo.Types[conv.Fun].Type)
		if b, isB := convT.Underlying().(*types.Basic); isB && b.Kind() == types.UnsafePointer {
			arg = conv
			par = idx.parentUnparen(conv)
			continue
		}
		if ptr, isPtr := convT.(*types.Pointer); isPtr {
			if b, isB := types.Unalias(ptr.Elem()).Underlying().(*types.Basic); isB && b.Kind() == types.UnsafePointer {
				arg = conv
				par = idx.parentUnparen(conv)
				continue
			}
		}
		break
	}
	call, ok := par.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != arg {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" {
		return false
	}
	switch fn.Name() {
	case "LoadInt32", "LoadInt64", "LoadUint32", "LoadUint64", "LoadUintptr", "LoadPointer":
		return true
	}
	return false
}

func isAddrOfRecvField(p *packages.Package, expr ast.Expr, recvVar, fld *types.Var) bool {
	un, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	sel, ok := ast.Unparen(un.X).(*ast.SelectorExpr)
	return ok && isIdentUsingObj(p, sel.X, recvVar) && p.TypesInfo.Uses[sel.Sel] == fld
}

func isByValueFieldChainOnExemptFamily(p *packages.Package, expr ast.Expr, exemptFam map[*types.Named]bool) bool {
	if len(exemptFam) == 0 {
		return false
	}
	cur := ast.Unparen(expr)
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		hitExempt := false
		forEachSelectionHopStruct(selInfo, func(st *types.Named) {
			if exemptFam[st] {
				hitExempt = true
			}
		})
		if hitExempt {
			fld, _ := selInfo.Obj().(*types.Var)
			if fld == nil || fld.Exported() {
				return false
			}
			_, isPtr := types.Unalias(fld.Type()).(*types.Pointer)
			return !isPtr
		}
		if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(sel.X)).(*types.Pointer); isPtr {
			return false
		}
		cur = ast.Unparen(sel.X)
	}
}
