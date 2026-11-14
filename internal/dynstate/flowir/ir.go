// Package flowir lowers Go function, closure, and block AST bodies into a
// normalized intra-procedural representation of places, values, and memory or
// control-flow operations.
//
// Fact derivation in dynstate summarizes each package before downstream
// importers or generic type instantiations exist, including uninstantiated
// generic declarations whose bodies go/ssa leaves empty. Lowering AST +
// go/types once per body lets confinement, freshness, and aliasing analyses
// operate on canonical places and operations instead of re-decoding Go's
// surface syntax independently.
package flowir

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// Body is the lowered intra-procedural representation of a function, function
// literal, or statement block.
type Body struct {
	AST        ast.Node
	Block      *ast.BlockStmt
	FuncLit    *ast.FuncLit
	ScopeStart token.Pos
	ScopeEnd   token.Pos
	BodyStart  token.Pos
	BodyEnd    token.Pos

	Recv       *types.Var
	Params     []*types.Var
	ParamIndex map[*types.Var]int
	Results    []*types.Var
	ResultSet  map[*types.Var]bool

	Ops      []Op
	FreeVars map[*types.Var]bool
}

// OwnsVar reports whether v is lexically declared within b's scope.
func (b *Body) OwnsVar(v *types.Var) bool {
	if b == nil || v == nil {
		return false
	}
	if v == b.Recv || b.ResultSet[v] {
		return true
	}
	if _, ok := b.ParamIndex[v]; ok {
		return true
	}
	return v.Pos() >= b.ScopeStart && v.Pos() <= b.ScopeEnd
}

// ForEachSyncOp visits every synchronous operation in b in lexical order,
// descending into range-loop bodies while leaving OpGo and uncalled closures
// isolated on their own operations.
func (b *Body) ForEachSyncOp(fn func(op *Op) bool) bool {
	if b == nil {
		return true
	}
	for i := range b.Ops {
		op := &b.Ops[i]
		if !fn(op) {
			return false
		}
		if op.Kind == OpAssign && op.AssignKind == AssignRange && op.RangeBody != nil {
			if !op.RangeBody.ForEachSyncOp(fn) {
				return false
			}
		}
	}
	return true
}

// RootKind classifies the root of a normalized Place.
type RootKind uint8

const (
	RootInvalid RootKind = iota
	RootLocal
	RootParam
	RootRecv
	RootResult
	RootOuterVar
	RootPkgGlobal
	RootFunc
	RootBlank
	RootConstOrNil
	RootTransient
)

// ProjKind classifies one left-to-right projection step on a Place.
type ProjKind uint8

const (
	ProjField ProjKind = iota + 1
	ProjIndex
	ProjSlice
	ProjDeref
)

// Proj is a single projection step from BaseType to Type.
type Proj struct {
	Kind      ProjKind
	Field     *types.Var
	Selection *types.Selection
	Indirect  bool
	Key       *Value
	Low       *Value
	High      *Value
	Max       *Value
	BaseType  types.Type
	Type      types.Type
}

// Place is a normalized memory location or addressable/projected path.
// Projections are ordered left-to-right from Root (Projs[0]) to outermost
// (Projs[len(Projs)-1]).
type Place struct {
	Root         RootKind
	Obj          *types.Var
	ConstOrNil   types.Object
	Func         *types.Func
	FuncPkg      string
	IsMethodExpr bool
	Base         *Value
	Projs        []Proj
	Type         types.Type
	Raw          ast.Expr
}

// IsBareVar reports whether p names a variable directly with zero projections.
func (p Place) IsBareVar() bool {
	return p.Obj != nil && len(p.Projs) == 0
}

// IsBlank reports whether p is the blank identifier `_`.
func (p Place) IsBlank() bool {
	return p.Root == RootBlank && len(p.Projs) == 0
}

// IsLocalRoot reports whether p's root is a non-package-global variable.
func (p Place) IsLocalRoot() bool {
	switch p.Root {
	case RootLocal, RootParam, RootRecv, RootResult, RootOuterVar:
		return p.Obj != nil
	default:
		return false
	}
}

// AsMapWrite reports whether writing to p inserts or overwrites a map entry at
// its outermost index step (m[k] = v, s.m[k]++, a[0][k] = v, or generic M[k] = v),
// returning the target map place and key expression. Indexing a slice inside a
// map (m[k][0] = v) writes a slice element rather than inserting a map key and
// returns ok == false.
func (p Place) AsMapWrite() (mapPlace Place, key *Value, ok bool) {
	if len(p.Projs) == 0 {
		return Place{}, nil, false
	}
	last := p.Projs[len(p.Projs)-1]
	if last.Kind != ProjIndex || !syntaxutil.TypeMayBeMap(last.BaseType) {
		return Place{}, nil, false
	}
	prefix := p
	prefix.Projs = p.Projs[:len(p.Projs)-1]
	prefix.Type = last.BaseType
	return prefix, last.Key, true
}

// ForEachChildValue visits every embedded Value inside p (transient base, index
// keys, and slice bounds).
func (p Place) ForEachChildValue(fn func(*Value) bool) bool {
	if p.Root == RootTransient && p.Base != nil {
		if !fn(p.Base) {
			return false
		}
	}
	for i := range p.Projs {
		pr := &p.Projs[i]
		if pr.Key != nil && !fn(pr.Key) {
			return false
		}
		if pr.Low != nil && !fn(pr.Low) {
			return false
		}
		if pr.High != nil && !fn(pr.High) {
			return false
		}
		if pr.Max != nil && !fn(pr.Max) {
			return false
		}
	}
	return true
}

// ValueKind classifies a normalized Value expression.
type ValueKind uint8

const (
	ValInvalid ValueKind = iota
	ValPlace
	ValAddrOf
	ValMethodVal
	ValAllocFresh
	ValMakeClosure
	ValCall
	ValConvert
	ValCompare
	ValChanRecv
	ValScalarLitOrConst
	ValCompositeExpr
)

// AllocKind classifies a fresh allocation expression.
type AllocKind uint8

const (
	AllocCompositeLit AllocKind = iota + 1
	AllocMake
	AllocBuiltinNewType
	AllocBuiltinNewExpr
)

// CallKind classifies a call expression.
type CallKind uint8

const (
	CallPlain CallKind = iota + 1
	CallMethod
	CallBuiltin
	CallIndirect
	CallIIFE
)

// CompositeElt is one element of a composite literal.
type CompositeElt struct {
	Field  *types.Var
	MapKey *Value
	Index  *Value
	Value  *Value
}

// Value is a normalized rvalue expression.
type Value struct {
	Kind ValueKind
	Type types.Type
	Raw  ast.Expr

	// ValPlace
	Place Place

	// ValAddrOf (&place when not &CompositeLit, or value-array slicing arr[lo:hi])
	AddrPlace    Place
	IsArraySlice bool
	Low          *Value
	High         *Value
	Max          *Value

	// ValMethodVal (bound method value x.M outside direct call callee position)
	Recv         *Value
	RecvPlace    Place
	HasRecvPlace bool
	Method       *types.Func
	Selection    *types.Selection
	AutoAddr     bool

	// ValAllocFresh
	AllocKind     AllocKind
	ElemType      types.Type
	CompositeElts []CompositeElt
	Args          []*Value
	Ellipsis      bool

	// ValMakeClosure
	Lit     *ast.FuncLit
	Closure *Body

	// ValCall (also reuses Recv, RecvPlace, HasRecvPlace, Selection, Args, Ellipsis)
	CallKind         CallKind
	CallAST          *ast.CallExpr
	BuiltinName      string
	CalleeFunc       *types.Func
	CalleePkg        string
	CalleeSig        *types.Signature
	IsMethodExprCall bool
	AutoAddrRecv     bool
	Callee           *Value
	IIFE             *Body

	// ValConvert (T(x) or x.(T))
	Arg          *Value
	IsTypeAssert bool

	// ValCompare (x == y or x != y)
	CompareOp token.Token
	Left      *Value
	Right     *Value

	// ValChanRecv (<-ch)
	Chan *Value
}

// ForEachChildValue visits the immediate child Value expressions of v (without
// descending into Closure or IIFE bodies).
func (v *Value) ForEachChildValue(fn func(*Value) bool) bool {
	if v == nil {
		return true
	}
	switch v.Kind {
	case ValPlace:
		return v.Place.ForEachChildValue(fn)
	case ValAddrOf:
		if !v.AddrPlace.ForEachChildValue(fn) {
			return false
		}
		if v.Low != nil && !fn(v.Low) {
			return false
		}
		if v.High != nil && !fn(v.High) {
			return false
		}
		if v.Max != nil && !fn(v.Max) {
			return false
		}
		return true
	case ValMethodVal:
		return v.Recv == nil || fn(v.Recv)
	case ValAllocFresh:
		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if elt.MapKey != nil && !fn(elt.MapKey) {
				return false
			}
			if elt.Index != nil && !fn(elt.Index) {
				return false
			}
			if elt.Value != nil && !fn(elt.Value) {
				return false
			}
		}
		for _, a := range v.Args {
			if a != nil && !fn(a) {
				return false
			}
		}
		return true
	case ValCall:
		if v.Recv != nil && !fn(v.Recv) {
			return false
		}
		if v.Callee != nil && !fn(v.Callee) {
			return false
		}
		for _, a := range v.Args {
			if a != nil && !fn(a) {
				return false
			}
		}
		return true
	case ValConvert:
		return v.Arg == nil || fn(v.Arg)
	case ValCompare:
		if v.Left != nil && !fn(v.Left) {
			return false
		}
		return v.Right == nil || fn(v.Right)
	case ValChanRecv:
		return v.Chan == nil || fn(v.Chan)
	case ValCompositeExpr:
		for _, a := range v.Args {
			if a != nil && !fn(a) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// WalkValues visits v and all nested sub-values pre-order; if visit returns
// false for a node, its children are skipped. Does not descend into ValMakeClosure
// or CallIIFE bodies unless the caller inspects Closure/IIFE explicitly.
func (v *Value) WalkValues(visit func(*Value) bool) {
	if v == nil || !visit(v) {
		return
	}
	v.ForEachChildValue(func(child *Value) bool {
		child.WalkValues(visit)
		return true
	})
}

// ParamIndexForArg maps call argument index argIdx to its formal parameter
// index on CalleeSig, accounting for variadic parameters without `...`.
func (v *Value) ParamIndexForArg(argIdx int) (int, bool) {
	if v == nil || v.CalleeSig == nil || v.CalleeSig.Params() == nil || v.CalleeSig.Params().Len() == 0 || argIdx < 0 {
		return 0, false
	}
	n := v.CalleeSig.Params().Len()
	if v.CalleeSig.Variadic() && argIdx >= n-1 {
		return n - 1, true
	}
	if argIdx >= n {
		return 0, false
	}
	return argIdx, true
}

// OpKind classifies a lowered statement operation.
type OpKind uint8

const (
	OpAssign OpKind = iota + 1
	OpTypeSwitchBind
	OpChanSend
	OpReturn
	OpDefer
	OpGo
	OpBranch
	OpExpr
)

// AssignKind classifies an OpAssign statement.
type AssignKind uint8

const (
	AssignPlain AssignKind = iota + 1
	AssignMulti
	AssignCompound
	AssignIncDec
	AssignZeroDecl
	AssignRange
)

// Op is one normalized statement-level operation inside a Body.
type Op struct {
	Kind           OpKind
	StmtAST        ast.Node
	TopLevelInBody bool

	// OpAssign
	AssignKind AssignKind
	Dsts       []Place
	DstDefs    []bool
	Srcs       []*Value
	RangeBody  *Body

	// OpTypeSwitchBind
	SwitchDst *types.Var
	SwitchSrc *Value
	CaseAST   *ast.CaseClause
	SwitchAST *ast.TypeSwitchStmt

	// OpChanSend
	ChanPlace Place
	ChanVal   *Value
	SendVal   *Value

	// OpReturn
	Results []*Value
	IsNaked bool

	// OpDefer, OpGo, OpExpr
	Call *Value
	Expr *Value
}

// ForEachAssignPair calls fn for each (dst, isDef, src) binding pair of an
// OpAssign. For AssignMulti (such as `v, ok := m[k]` or `a, b := call()`),
// Srcs[0] is paired with each Dst; for AssignZeroDecl, src is nil.
func (op *Op) ForEachAssignPair(fn func(idx int, dst Place, isDef bool, src *Value) bool) bool {
	if op == nil || op.Kind != OpAssign {
		return true
	}
	for i, dst := range op.Dsts {
		isDef := i < len(op.DstDefs) && op.DstDefs[i]
		var src *Value
		if len(op.Dsts) == len(op.Srcs) {
			src = op.Srcs[i]
		} else if len(op.Srcs) == 1 {
			src = op.Srcs[0]
		}
		if !fn(i, dst, isDef, src) {
			return false
		}
	}
	return true
}
