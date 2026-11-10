package toolchain

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func mustParseTestFiles(t *testing.T, srcs ...string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := make([]*ast.File, 0, len(srcs))
	for i, src := range srcs {
		f, err := parser.ParseFile(fset, "f"+string(rune('0'+i))+".go", src, 0)
		if err != nil {
			t.Fatalf("ParseFile(%d): %v\n%s", i, err, src)
		}
		out = append(out, f)
	}
	return out
}

func TestIndexPackageASTAndPrimitives(t *testing.T) {
	files := mustParseTestFiles(t, `package sample

import (
	"io"
	"syscall"
)

const bufSize = 4096

var (
	zeroFlag bool
	initVal  = 1
)

type ValidStruct struct {
	w io.Writer
	n int
}

type ExtraStruct struct {
	w     io.Writer
	extra string
}

type EmbeddedStruct struct {
	io.Writer
	n int
}

type GenericStruct[T any] struct {
	v T
}

type AliasStruct = ValidStruct

func TopHelper(x int) int {
	return x + 1
}

func (v *ValidStruct) PtrMethod() int {
	return v.n
}

func (v ValidStruct) ValMethod() int {
	return v.n
}

func ShadowingFunc(nil int) int {
	return nil
}

func BypassFunc(x int) int {
	goto done
done:
	return x
}

func RecoverFunc() {
	_ = recover()
}

func ignoringEINTR(fn func() error) error {
	for {
		err := fn()
		if err != syscall.EINTR {
			return err
		}
	}
}

func ignoringEINTR2[T any](fn func() (T, error)) (T, error) {
	for {
		v, err := fn()
		if err != syscall.EINTR {
			return v, err
		}
	}
}

func badIgnoringEINTR(fn func() error) error {
	for {
		err := fn()
		if err == syscall.EINTR {
			return err
		}
	}
}
`)

	reserved := map[string]bool{"nil": true, "error": true, "syscall": true}
	idx, err := indexPackageAST("sample", files, reserved, map[string]bool{"io": true, "syscall": true})
	if err != nil {
		t.Fatalf("indexPackageAST: %v", err)
	}
	if !idx.hasAnyImport("io") || !idx.hasFileImport(files[0], "syscall") {
		t.Fatal("expected unaliased io and syscall imports to be indexed")
	}
	if !idx.constPosInt["bufSize"] || !idx.zeroInitBoolVars["zeroFlag"] || idx.initPkgVars["initVal"] == nil {
		t.Fatal("expected constPosInt, zeroInitBoolVars, and initPkgVars to be populated")
	}

	req := map[string]func(ast.Expr) bool{
		"w": func(e ast.Expr) bool { _, ok := isSelectorBaseField(e, "io", "Writer"); return ok },
		"n": func(e ast.Expr) bool { _, ok := isIdentNamed(e, "int"); return ok },
	}
	if _, _, ok := idx.VerifyStructFields("ValidStruct", req, false); !ok {
		t.Fatal("expected ValidStruct to satisfy VerifyStructFields")
	}
	if _, _, ok := idx.VerifyStructFields("ExtraStruct", map[string]func(ast.Expr) bool{
		"w": req["w"],
	}, false); ok {
		t.Fatal("expected ExtraStruct to fail when allowExtra is false")
	}
	if _, _, ok := idx.VerifyStructFields("ExtraStruct", map[string]func(ast.Expr) bool{
		"w": req["w"],
	}, true); !ok {
		t.Fatal("expected ExtraStruct to succeed when allowExtra is true")
	}
	if _, _, ok := idx.VerifyStructFields("EmbeddedStruct", map[string]func(ast.Expr) bool{
		"n": req["n"],
	}, true); ok {
		t.Fatal("expected EmbeddedStruct to be rejected even when allowExtra is true")
	}
	if _, _, ok := idx.VerifyStructFields("GenericStruct", nil, true); ok {
		t.Fatal("expected GenericStruct to be rejected")
	}
	if _, _, ok := idx.VerifyStructFields("AliasStruct", req, false); ok {
		t.Fatal("expected AliasStruct to be rejected")
	}

	if _, _, ok := idx.VerifyFuncPreamble("", "TopHelper", false, reserved); !ok {
		t.Fatal("expected TopHelper to pass VerifyFuncPreamble")
	}
	if _, _, ok := idx.VerifyFuncPreamble("ValidStruct", "PtrMethod", true, reserved); !ok {
		t.Fatal("expected PtrMethod to pass VerifyFuncPreamble with wantPtrRecv=true")
	}
	if _, _, ok := idx.VerifyFuncPreamble("ValidStruct", "ValMethod", true, reserved); ok {
		t.Fatal("expected ValMethod to fail VerifyFuncPreamble with wantPtrRecv=true")
	}
	if _, _, ok := idx.VerifyFuncPreamble("", "ShadowingFunc", false, reserved); ok {
		t.Fatal("expected ShadowingFunc to fail VerifyFuncPreamble")
	}
	if _, _, ok := idx.VerifyFuncPreamble("", "BypassFunc", false, reserved); ok {
		t.Fatal("expected BypassFunc to fail VerifyFuncPreamble")
	}
	if _, _, ok := idx.VerifyFuncPreamble("", "RecoverFunc", false, reserved); ok {
		t.Fatal("expected RecoverFunc to fail VerifyFuncPreamble")
	}

	if !VerifyIgnoringEINTRHelper(idx.topFuncs["ignoringEINTR"], true, reserved, 1) {
		t.Fatal("expected ignoringEINTR to pass VerifyIgnoringEINTRHelper(arity=1)")
	}
	if !VerifyIgnoringEINTRHelper(idx.topFuncs["ignoringEINTR2"], true, reserved, 2) {
		t.Fatal("expected ignoringEINTR2 to pass VerifyIgnoringEINTRHelper(arity=2)")
	}
	if VerifyIgnoringEINTRHelper(idx.topFuncs["badIgnoringEINTR"], true, reserved, 1) {
		t.Fatal("expected badIgnoringEINTR to fail VerifyIgnoringEINTRHelper")
	}
}

func TestScopeControlFlowAndReceiverHelpers(t *testing.T) {
	files := mustParseTestFiles(t, `package scope

func (r *Box[T]) AlwaysLoop(flag bool) int {
	if flag {
		return 1
	} else {
		for {
			return 2
		}
	}
}

func (r *Box[T]) BreakLoop() int {
	for {
		break
	}
	return 0
}

func SelectOnly(s *State) int {
	return s.count
}

func EscapesIdent(s *State) *State {
	return s
}
`)
	f := files[0]
	fnAlways := f.Decls[0].(*ast.FuncDecl)
	if got := RecvBaseTypeName(fnAlways.Recv.List[0].Type); got != "Box" {
		t.Fatalf("RecvBaseTypeName = %q, want Box", got)
	}
	if !blockAlwaysReturns(fnAlways.Body.List) {
		t.Fatal("expected AlwaysLoop to satisfy blockAlwaysReturns")
	}
	fnBreak := f.Decls[1].(*ast.FuncDecl)
	if blockAlwaysReturns(fnBreak.Body.List[:1]) {
		t.Fatal("expected loop with break not to satisfy blockAlwaysReturns on its own")
	}
	fnSel := f.Decls[2].(*ast.FuncDecl)
	if !blockOnlySelectsOnIdent(fnSel.Body, "s") {
		t.Fatal("expected SelectOnly to only select on s")
	}
	fnEsc := f.Decls[3].(*ast.FuncDecl)
	if blockOnlySelectsOnIdent(fnEsc.Body, "s") {
		t.Fatal("expected EscapesIdent to fail blockOnlySelectsOnIdent")
	}
}

func TestDirectivesOffSurfaceAndPurePackageAST(t *testing.T) {
	if err := scanGoDirectiveComments("package p\n/*go:linkname foo bar*/\n", func(string) error { return nil }); err == nil {
		t.Fatal("expected block /*go: directive to be rejected")
	}
	if err := VerifyFileLinknameDirectives("bytes", "package bytes\n//go:linkname evil runtime.exit\n"); err == nil {
		t.Fatal("expected unapproved linkname target in bytes to be rejected")
	}
	if err := VerifyHarnessFileDirectives("testing/internal/testdeps", "package testdeps\n//go:linkname x y\n", map[string]bool{}, map[string]bool{}, nil, nil); err == nil {
		t.Fatal("expected linkname in testing/internal/testdeps to be rejected")
	}

	pureFiles := mustParseTestFiles(t, `package bytes

import "sync"

type pool struct {
	once sync.Once
}

func PureAdd(a, b int) int {
	return a + b
}
`)
	if err := VerifyPurePackageAST("bytes", pureFiles); err != nil {
		t.Fatalf("VerifyPurePackageAST(valid): %v", err)
	}

	impureImport := mustParseTestFiles(t, `package bytes

import "os"

func Touch() {
	_ = os.Getenv("X")
}
`)
	if err := VerifyPurePackageAST("bytes", impureImport); err == nil || !strings.Contains(err.Error(), "forbidden import") {
		t.Fatalf("expected os import in pure package to be rejected, got %v", err)
	}

	impureFmt := mustParseTestFiles(t, `package bytes

import "fmt"

func Log() {
	fmt.Println("hi")
}
`)
	if err := VerifyPurePackageAST("bytes", impureFmt); err == nil || !strings.Contains(err.Error(), "fmt.Println") {
		t.Fatalf("expected fmt.Println in pure package to be rejected, got %v", err)
	}

	offFiles := mustParseTestFiles(t, `package offpkg

import _ "unsafe"

func init() {
	bootHelper()
}

func bootHelper() {
	rtHook()
}

func rtHook()
`)
	var links []OffSurfaceLinkDirective
	directRT := map[string]bool{}
	ScanOffSurfaceGoDirectives("package offpkg\n//go:linkname rtHook runtime.enableHook\n", directRT, func(localSym, target string) {
		links = append(links, OffSurfaceLinkDirective{LocalSym: localSym, Target: target})
	})
	verdict := BuildOffSurfaceGraph("internal/offpkg", offFiles, links, directRT, nil)
	pulled := map[string]bool{}
	PropagateOffSurfaceRuntimePulls(
		[]string{"internal/offpkg"},
		map[string]OffSurfaceVerdict{"internal/offpkg": verdict},
		func(raw string) (string, bool) { return raw, true },
		nil,
		pulled,
	)
	if !pulled["runtime.enableHook"] {
		t.Fatalf("expected runtime.enableHook to be pulled via init -> bootHelper -> rtHook, got %v", pulled)
	}
}
