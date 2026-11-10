package toolchain

import (
	"go/ast"
	"slices"
	"testing"
)

func TestDiscoverRuntimeInactiveGates(t *testing.T) {
	src := `package runtime

import "internal/runtime/atomic"

var (
	traceState atomic.Uint32
	flagState  atomic.Bool
	leakedVar  atomic.Uint32
)

func enableTrace() {
	traceState.Store(1)
}

func resetTrace() {
	traceState.Store(0)
}

func enableFlag() {
	flagState.Store(true)
}

func traceActive() bool {
	return traceState.Load() != 0
}

func flagActive() bool {
	return flagState.Load()
}

func compositeActive() bool {
	return traceActive() || flagActive()
}

func leakUser() uint32 {
	p := &leakedVar
	return p.Load()
}

func leakedGate() bool {
	return leakedVar.Load() != 0
}
`
	files := mustParseTestFiles(t, src)
	gates := DiscoverRuntimeInactiveGates(files, []string{src}, nil)
	if !slices.Equal(gates["runtime.traceActive"], []string{"runtime.enableTrace", "runtime.traceState"}) {
		t.Fatalf("runtime.traceActive mutators = %v", gates["runtime.traceActive"])
	}
	if !slices.Equal(gates["runtime.flagActive"], []string{"runtime.enableFlag", "runtime.flagState"}) {
		t.Fatalf("runtime.flagActive mutators = %v", gates["runtime.flagActive"])
	}
	if !slices.Equal(gates["runtime.compositeActive"], []string{"runtime.enableFlag", "runtime.enableTrace", "runtime.flagState", "runtime.traceState"}) {
		t.Fatalf("runtime.compositeActive mutators = %v", gates["runtime.compositeActive"])
	}
	if _, ok := gates["runtime.leakedGate"]; ok {
		t.Fatalf("expected runtime.leakedGate to be excluded when &leakedVar escapes, got %v", gates["runtime.leakedGate"])
	}

	// Referencing traceState in nonGoIdents disqualifies traceActive.
	gatesWithAsmRef := DiscoverRuntimeInactiveGates(files, []string{src}, map[string]bool{"traceState": true})
	if _, ok := gatesWithAsmRef["runtime.traceActive"]; ok {
		t.Fatalf("expected runtime.traceActive to be excluded when traceState is in nonGoIdents, got %v", gatesWithAsmRef)
	}
}

func TestVerifyTestingSubVerifiers(t *testing.T) {
	files := mustParseTestFiles(t, `package testing

import (
	"fmt"
	"io"
)

type chattyPrinter struct {
	w io.Writer
}

func (p *chattyPrinter) Printf(testName, format string, args ...any) {
	fmt.Fprintf(p.w, format, args...)
}

type highWaterWriter struct {
	w io.Writer
}

func (hw *highWaterWriter) Write(b []byte) (int, error) {
	return hw.w.Write(b)
}
`)
	idx, err := indexPackageAST("testing", files, nil, map[string]bool{"fmt": true, "io": true})
	if err != nil {
		t.Fatalf("indexPackageAST: %v", err)
	}
	if _, _, ok := idx.VerifyStructFields("chattyPrinter", map[string]func(ast.Expr) bool{
		"w": func(e ast.Expr) bool { _, ok := isSelectorBaseField(e, "io", "Writer"); return ok },
	}, false); !ok {
		t.Fatal("expected chattyPrinter struct to satisfy VerifyStructFields")
	}
	fnWrite := idx.typeMethods["highWaterWriter"]["Write"]
	retStmt := fnWrite.Body.List[0].(*ast.ReturnStmt)
	if call, ok := retStmt.Results[0].(*ast.CallExpr); !ok || syscallWriteSinkKind(call) != "" {
		t.Fatal("expected hw.w.Write(b) not to be classified as a raw syscall write sink")
	}
	if err := VerifyTestingPackageAST(files, nil, nil); err == nil {
		t.Fatal("expected incomplete testing package AST to be rejected by VerifyTestingPackageAST")
	}
}
