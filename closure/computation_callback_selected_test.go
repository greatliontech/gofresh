package closure

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

func TestComputationCallbackSelectedTestBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and builds default-optimized selected package-test callbacks")
	}
	const pkg = "example.com/callbacksource"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.27\n",
		"p.go":   "package p\nimport \"unicode/utf16\"\nfunc F(r rune)bool{return utf16.IsSurrogate(r)}\n",
		"p_test.go": `package p
import ("testing"; "os")
func TestSibling(t *testing.T){}
func TestScalar(t *testing.T){if !F(0xd800){t.Fail()}}
func TestUnproven(t *testing.T){if F(0){t.Fail()}else{t.Fail()}}
var unknown rune
func TestRuntimeUnknown(t *testing.T){if !F(unknown){t.Fail()}}
func TestAmbient(t *testing.T){os.Getenv("CALLBACK_SOURCE")}
`,
	})
	env := os.Environ()
	for key, value := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOWORK": "off"} {
		env = gotool.SetEnv(env, key, value)
	}
	h, err := newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, pkg)
	metas, err := h.list(pkg)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	artifact := filepath.Join(dir, "callback.test")
	command := append([]string{"test", "-c", "-o", artifact}, h.buildFlags...)
	command = append(command, ".")
	if _, err := (gotool.Runner{}).Run(t.Context(), dir, h.packageEnv, command...); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	image, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]uint64{}
	for _, symbol := range syms {
		entries[symbol.Name] = symbol.Value
	}
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	face := correspondenceFace(args, nil)
	for _, name := range []string{"TestSibling", "TestScalar"} {
		t.Run(name, func(t *testing.T) {
			root := source.prog.Roots[name]
			entry := entries[pkg+"."+name]
			if root == nil || entry == 0 {
				t.Fatal("actual selected callback absent")
			}
			c, err := deriveComputationCorrespondence(t.Context(), source, root, image, entry, face, args, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireCorrespondenceWitnesses(t, c, 0)
			if c.source.root.parameters[0].name != "*testing.T" || c.source.root.parameters[0].pointerBits != 64 {
				t.Fatal("lost selected testing pointer interface")
			}
			bound, ok := c.native.Bound()
			if !ok || bound.Entry != entry || len(bound.Instructions) != 1 || bound.Interface.Results != (nativeproof.Masks{}) {
				t.Fatalf("default-optimized callback did not prove its RET: %+v", bound)
			}
			if name == "TestScalar" {
				requireSourceExclusions(t, c.source)
				found := false
				for _, dep := range c.source.dependencies {
					found = found || dep.function == "unicode/utf16.IsSurrogate"
				}
				if !found {
					t.Fatal("constant failure-branch proof bypassed actual selected callee")
				}
			}
			if c.open != (computationCorrespondenceObligations{true, true, true, true, true}) || c.source.open != (computationRelationObligations{true, true, true, true, true}) {
				t.Fatal("body theorem acquired startup/harness/runtime authority")
			}
		})
	}
	for _, name := range []string{"TestUnproven", "TestRuntimeUnknown", "TestAmbient"} {
		if c, err := deriveComputationCorrespondence(t.Context(), source, source.prog.Roots[name], image, entries[pkg+".TestSibling"], face, args, nil); c != nil || err == nil {
			t.Fatal("reachable source effect corresponded to RET", name)
		}
	}
}
