//go:build linux && amd64 && !android

package closure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/gotool"
)

func TestAssemblyCaptureExactTestVariant(t *testing.T) {
	if testing.Short() {
		t.Skip("typed test-variant current-action capture")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":      "module example.com/assemblytest\n\ngo 1.27.0\n",
		"ops.go":      "package assemblytest\nfunc Swap(p *uint64,old,next uint64) bool\n",
		"ops_test.go": "package assemblytest\nimport \"testing\"\nfunc TestOp(t *testing.T){var x uint64;if !Swap(&x,0,1){t.Fatal(x)}}\n",
		"ops.s":       "#include \"textflag.h\"\nTEXT ·Swap(SB),NOSPLIT,$0-25\nMOVQ p+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ next+16(FP),CX\nLOCK\nCMPXCHGQ CX,(BX)\nSETEQ ret+24(FP)\nRET\n",
	})
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env = gotool.SetEnv(env, "CGO_ENABLED", "0")
	source, err := loadSelectedSource(t.Context(), gotool.NewEnvReader(gotool.Runner{}, dir, env), nil, true, ".")
	if err != nil {
		t.Fatal(err)
	}
	var provider *packages.Package
	for _, p := range source.prog.Pkgs {
		if p.PkgPath == "example.com/assemblytest" && p.ForTest == "example.com/assemblytest" {
			provider = p
		}
	}
	if provider == nil {
		t.Fatal("exact selected test variant absent")
	}
	packet, err := acquireSelectedAssembly(t.Context(), source.owner, provider, assemblyCaptureLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if !packet.boundTo(source, provider) {
		t.Fatal("packet lost exact typed owner")
	}
	clone := *provider
	if packet.boundTo(source, &clone) {
		t.Fatal("borrowed equal package instance accepted")
	}
	texts := packet.providerTexts()
	if len(texts) != 1 || texts[0].Source != filepath.Join(dir, "ops.s") || texts[0].Invocation.Instance != provider.ID || texts[0].Invocation.Package != provider.PkgPath {
		t.Fatalf("variant invocation=%+v", texts)
	}
}
