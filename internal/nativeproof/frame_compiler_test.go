package nativeproof

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

const frameCompilerSource = `package fieldkernels
type Fields struct { Pad, Value uint64; Small uint32; Byte uint8 }
func Get(p *Fields) uint64 { return p.Value }
func Put(p *Fields, x uint64) { p.Value=x }
func Copy(dst, src *Fields) { dst.Value=src.Value }
func GetSmall(p *Fields) uint32 { return p.Small }
func PutSmall(p *Fields, x uint32) { p.Small=x }
func GetByte(p *Fields) uint8 { return p.Byte }
func PutByte(p *Fields, x uint8) { p.Byte=x }
`

const frameCompilerTest = `package fieldkernels
import("os";"testing")
var gets=map[string]func(*Fields)uint64{"get":Get}
var puts=map[string]func(*Fields,uint64){"put":Put}
var copies=map[string]func(*Fields,*Fields){"copy":Copy}
var smallGets=map[string]func(*Fields)uint32{"get":GetSmall}
var smallPuts=map[string]func(*Fields,uint32){"put":PutSmall}
var byteGets=map[string]func(*Fields)uint8{"get":GetByte}
var bytePuts=map[string]func(*Fields,uint8){"put":PutByte}
func TestFieldKernels(t *testing.T) {
 var dst,src Fields
 for _,f:=range gets { dst.Value=f(&src) }
 for _,f:=range puts { f(&dst,uint64(len(os.Getenv("FIELD_VALUE")))) }
 for _,f:=range copies { f(&dst,&src) }
 for _,f:=range smallGets { dst.Small=f(&src) }
 for _,f:=range smallPuts { f(&dst,uint32(dst.Value)) }
 for _,f:=range byteGets { dst.Byte=f(&src) }
 for _,f:=range bytePuts { f(&dst,uint8(dst.Small)) }
 if dst.Byte!=0 { t.Fatal(dst) }
}
`

func TestFrameDefaultOptimizedFieldKernels(t *testing.T) {
	if testing.Short() {
		t.Skip("builds an ordinary optimized package-test artifact")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module example.com/fieldkernels\n\ngo 1.27\n", "fields.go": frameCompilerSource, "fields_test.go": frameCompilerTest} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := os.Environ()
	for key, val := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, key, val)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	if _, err := runner.Run(t.Context(), dir, env, "test", "-c", "-o", "fields.test", "."); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fields.test"))
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
	for _, s := range syms {
		entries[s.Name] = s.Value
	}
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Get", "Put", "Copy", "GetSmall", "PutSmall", "GetByte", "PutByte"} {
		t.Run(name, func(t *testing.T) {
			entry := entries["example.com/fieldkernels."+name]
			if entry == 0 {
				t.Fatal("ordinary fixture did not retain candidate", name)
			}
			face := memoryFace()
			if name == "Copy" {
				// The source pointer may alias the destination at either the same
				// field or overlapping neighboring bytes, not an assumed fresh object.
				face.Pointers = append(face.Pointers, RegisterPointer{RBX, RegionPointer{0, 0, 8}})
			}
			c, err := proveFrame(t, im, entry, face)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			checkFrameOracle(t, im, b, 100)
			reads, writes := 0, 0
			for _, a := range b.Accesses {
				if a.Kind == FrameRead {
					reads++
				}
				if a.Kind == FrameWrite {
					writes++
				}
			}
			if name == "Copy" && (reads != 1 || writes != 1) {
				t.Fatal("copy accesses incomplete", b.Accesses)
			}
			if name[:3] == "Get" && (reads != 1 || writes != 0) {
				t.Fatal("getter accesses incomplete", b.Accesses)
			}
			if name[:3] == "Put" && (reads != 0 || writes != 1) {
				t.Fatal("setter accesses incomplete", b.Accesses)
			}
			t.Logf("checked %s entry=%#x instructions=%d data-reads=%d writes=%d", name, entry, len(b.Instructions), reads, writes)
		})
	}
}
