package toolchain

import (
	"go/ast"
	"strings"
	"testing"
)

func TestVerifyOSFileStructTypesAndHelpers(t *testing.T) {
	validOS := mustParseTestFiles(t, `package os

import (
	"internal/poll"
	"internal/testlog"
	"syscall"
)

type File struct {
	*file
}

type file struct {
	pfd         poll.FD
	name        string
	stdoutOrErr bool
}

func runtime_beforeExit(exitCode int)

func Exit(code int) {
	if code == 0 && testlog.PanicOnExit0() {
		panic("unexpected call to os.Exit(0) during test")
	}
	runtime_beforeExit(code)
	syscall.Exit(code)
}

func sigpipe()

func epipecheck(file *File, e error) {
	if e == syscall.EPIPE && file.stdoutOrErr {
		sigpipe()
	}
}
`)

	osReserved := map[string]bool{
		"syscall": true, "testlog": true, "poll": true, "File": true, "file": true,
		"nil": true, "error": true, "int": true, "string": true, "bool": true, "panic": true,
	}
	idx, err := indexPackageAST("os", validOS, map[string]bool{"nil": true}, map[string]bool{
		"internal/poll": true, "internal/testlog": true, "syscall": true,
	})
	if err != nil {
		t.Fatalf("indexPackageAST: %v", err)
	}
	if err := verifyOSFileStructTypes(idx); err != nil {
		t.Fatalf("verifyOSFileStructTypes(valid): %v", err)
	}
	if err := verifyOSExitIntegrity(validOS, idx.topFuncs["Exit"], idx.funcFile, idx.fileImportSet("internal/testlog"), idx.fileImportSet("syscall"), osReserved); err != nil {
		t.Fatalf("verifyOSExitIntegrity(valid): %v", err)
	}
	osNoFileReserved := map[string]bool{
		"syscall": true, "testlog": true, "poll": true, "File": true,
		"nil": true, "error": true, "int": true, "string": true, "bool": true, "panic": true,
	}
	if err := verifyOSEpipecheck(idx.topFuncs["epipecheck"], idx.funcFile, idx.fileImportSet("syscall"), osNoFileReserved, nil); err != nil {
		t.Fatalf("verifyOSEpipecheck(valid): %v", err)
	}

	// Mutate File struct to add an extra field: must be rejected.
	badFileStruct := mustParseTestFiles(t, `package os

import "internal/poll"

type File struct {
	*file
	extra int
}

type file struct {
	pfd  poll.FD
	name string
}
`)
	badIdx, err := indexPackageAST("os", badFileStruct, nil, nil)
	if err != nil {
		t.Fatalf("indexPackageAST(badFileStruct): %v", err)
	}
	if err := verifyOSFileStructTypes(badIdx); err == nil || !strings.Contains(err.Error(), "File") {
		t.Fatalf("expected extra field on os.File to fail verifyOSFileStructTypes, got %v", err)
	}

	// Mutate Exit to omit PanicOnExit0 check: must be rejected.
	badExit := mustParseTestFiles(t, `package os

import (
	"internal/testlog"
	"syscall"
)

var _ = testlog.PanicOnExit0

func Exit(code int) {
	syscall.Exit(code)
}
`)
	badExitIdx, err := indexPackageAST("os", badExit, nil, map[string]bool{
		"internal/testlog": true, "syscall": true,
	})
	if err != nil {
		t.Fatalf("indexPackageAST(badExit): %v", err)
	}
	if err := verifyOSExitIntegrity(badExit, badExitIdx.topFuncs["Exit"], badExitIdx.funcFile, badExitIdx.fileImportSet("internal/testlog"), badExitIdx.fileImportSet("syscall"), osReserved); err == nil {
		t.Fatal("expected Exit without PanicOnExit0 guard to be rejected")
	}
}

func TestDiscoverOSInactiveStateWithSharedIndex(t *testing.T) {
	files := mustParseTestFiles(t, `package os

const (
	disabledConst = false
	enabledConst  = true
)

func rtGate() bool

func isInactivePred(name string) bool {
	return disabledConst || rtGate()
}
`)
	idx, err := indexPackageAST("os", files, nil, nil)
	if err != nil {
		t.Fatalf("indexPackageAST: %v", err)
	}
	inact := discoverOSInactiveState(idx, files, map[string]string{"rtGate": "runtime.simActive"}, map[string]bool{"rtGate": true})
	if !inact.falseConsts["disabledConst"] || !inact.trueConsts["enabledConst"] {
		t.Fatalf("expected disabledConst in falseConsts and enabledConst in trueConsts, got falseConsts=%v trueConsts=%v", inact.falseConsts, inact.trueConsts)
	}
	if inact.osGateFuncs["rtGate"] != "runtime.simActive" {
		t.Fatalf("expected rtGate -> runtime.simActive, got %v", inact.osGateFuncs)
	}
	if _, ok := inact.falsePreds["isInactivePred"]; !ok {
		t.Fatalf("expected isInactivePred in falsePreds, got %v", inact.falsePreds)
	}
	if _, _, ok := idx.VerifyStructFields("NonExistent", map[string]func(ast.Expr) bool{}, false); ok {
		t.Fatal("expected NonExistent struct check to fail")
	}
}
