package rta

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

func TestContainsTypeParamAndStaggeredMasks(t *testing.T) {
	const src = `package p

type Node struct {
	Next *Node
}

func (n *Node) Step() *Node { return n.Next }

type Stepper interface {
	Step() *Node
}

func Gen[T any]() any {
	type Local struct {
		Self *Local
		V    T
	}
	return Local{}
}

func RootA() *Node {
	var s Stepper = &Node{}
	return s.Step()
}

func RootB() *Node {
	var s Stepper = &Node{}
	return s.Step()
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	files := []*ast.File{f}
	pkg := types.NewPackage("example.com/p", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, files, ssa.InstantiateGenerics)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	prog := ssaPkg.Prog

	nodeType := pkg.Scope().Lookup("Node").Type()
	if ContainsTypeParam(nodeType, make(map[types.Type]bool)) {
		t.Fatalf("ContainsTypeParam(Node) = true, want false")
	}

	genFn := ssaPkg.Func("Gen")
	if genFn == nil {
		t.Fatal("missing Gen function")
	}
	var localType types.Type
	for _, b := range genFn.Blocks {
		for _, instr := range b.Instrs {
			if mi, ok := instr.(*ssa.MakeInterface); ok {
				localType = mi.X.Type()
			}
		}
	}
	if localType == nil {
		t.Fatal("missing MakeInterface in Gen")
	}
	if !ContainsTypeParam(localType, make(map[types.Type]bool)) {
		t.Fatalf("ContainsTypeParam(%v) = false, want true", localType)
	}

	if _, err := Analyze(context.Background(), map[*ssa.Function]uint64{genFn: 1}, nil); err == nil {
		t.Fatal("Analyze accepted parameterized origin root Gen")
	}

	rootA := ssaPkg.Func("RootA")
	rootB := ssaPkg.Func("RootB")
	step := prog.LookupMethod(types.NewPointer(nodeType), pkg, "Step")
	if rootA == nil || rootB == nil || step == nil {
		t.Fatalf("missing functions: rootA=%v rootB=%v step=%v", rootA, rootB, step)
	}

	res, err := Analyze(context.Background(), map[*ssa.Function]uint64{
		rootA: 1 << 0,
		rootB: 1 << 1,
	}, &Seeds{
		RuntimeTypes: []TypeSeed{
			{Type: localType, Masks: 1 << 0},
			{Type: nodeType, Masks: 1 << 0},
			{Type: nodeType, Masks: 1 << 1},
		},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	const wantMask = uint64(1<<0 | 1<<1)
	if got := res.Reachable[step]; got != wantMask {
		t.Fatalf("Reachable[(*Node).Step] = %#b, want %#b", got, wantMask)
	}
}
