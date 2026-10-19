//go:build linux && amd64 && !android

package closure

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// The ordinary driver refuses user @ arguments before invoking toolexec. This
// fixture instead transports the final assembler's unchanged arguments through
// response files inside the test's private shim, before both its handshake and
// actual exec. It tests the real tool interface, not a driver admission route.
// The alternate backslash filename contains valid opposite-Boolean assembly.
func TestAssemblyResponseSelectedReference(t *testing.T) {
	if testing.Short() {
		t.Skip("actual assembler response selection and checked reference")
	}
	for _, mode := range []string{"ordinary", "response", "nested-trailing-escape"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			body := "TEXT ·Swap(SB),4,$0-25\nMOVQ ptr+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ replacement+16(FP),CX\nLOCK\nCMPXCHGQ CX,(BX)\nSETEQ ret+24(FP)\nRET\n"
			files := map[string]string{"go.mod": "module example.com/response\n\ngo 1.27.0\n", "p.go": "package p\nfunc Swap(ptr *uint64,old,replacement uint64) bool\n"}
			files["body_amd64.s"] = body
			writeTree(t, dir, files)
			runner := gotool.Runner{}
			responseDir := t.TempDir()
			var instrumented bool
			var prepareErr error
			if mode != "ordinary" {
				runner.Prepare = func(cmd *exec.Cmd) {
					if len(cmd.Args) == 0 || cmd.Args[len(cmd.Args)-1] != filepath.Join(cmd.Dir, "main.go") {
						return
					}
					name := cmd.Args[len(cmd.Args)-1]
					data, err := os.ReadFile(name)
					if err != nil {
						prepareErr = err
						return
					}
					const seam = "args := append([]string{tool}, os.Args[4:]...)"
					if strings.Count(string(data), seam) != 1 {
						prepareErr = fmt.Errorf("response fixture seam absent")
						return
					}
					text := strings.Replace(string(data), seam, "fixtureResponse(tool)\n\t"+seam, 1)
					text += responseTransportFixture(filepath.Join(dir, "body_amd64.s"), responseDir, mode == "nested-trailing-escape")
					prepareErr = os.WriteFile(name, []byte(text), 0600)
					instrumented = prepareErr == nil
				}
			}
			source, err := loadSelectedSource(t.Context(), gotool.NewEnvReader(runner, dir, os.Environ()), nil, false, ".")
			if err != nil {
				t.Fatal(err)
			}
			target := source.prog.Roots["Swap"]
			provider, err := source.owner.packageFor(target)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := acquireSelectedAssembly(t.Context(), source.owner, provider, assemblyCaptureLimits{})
			if prepareErr != nil {
				t.Fatal(prepareErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			reference, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
			if err != nil {
				t.Fatal(err)
			}
			for _, sample := range []struct {
				current, old uint64
				result       bool
				value        uint64
			}{{5, 5, true, 9}, {5, 7, false, 5}} {
				got, err := reference.evaluate(t.Context(), sample.current, sample.old, 9)
				if err != nil {
					t.Fatal(err)
				}
				if assemblyReferenceBool(t, got.Result) != sample.result || got.Value != sample.value {
					t.Fatalf("real action/reference disagreement: %+v", got)
				}
			}
			for _, text := range packet.providerTexts() {
				for _, line := range text.Lines {
					if strings.Contains(line.Text, "SETNE") {
						t.Fatal("captured alternate response interpretation", line)
					}
				}
			}
			if mode != "ordinary" {
				if !instrumented {
					t.Fatal("response transport was not installed")
				}
				owned := packet.packet.Files()
				responses := 0
				for path := range owned {
					switch filepath.Base(path) {
					case "outer.rsp", "inner.rsp":
						responses++
					case "inner.rsp\\":
						t.Fatal("unselected alternate response file entered packet")
					}
				}
				if responses != 2 {
					t.Fatalf("actual response transport not captured: %d files", responses)
				}
			}
		})
	}
}

// Encode independently of capture's parser: quote each argv word, escaping only
// the four special bytes inside double quotes. Every ordinary word ends in LF;
// only the explicitly adversarial outer word ends in an unquoted backslash.
func responseTransportFixture(source, directory string, trailing bool) string {
	return `
func fixtureResponse(tool string) {
 if len(tool)<4 || tool[len(tool)-4:]!="/asm" || len(os.Args)<5 || os.Args[len(os.Args)-1]!=` + strconv.Quote(source) + ` { return }
 for _,arg:=range os.Args[4:] { if arg=="-gensymabis" {return} }
 dir:=` + strconv.Quote(directory) + `
 var err error
 inner,outer:=dir+"/inner.rsp",dir+"/outer.rsp"
 words:=append([]string(nil),os.Args[4:]...)
 encode:=func(words []string)[]byte {
  var out []byte
  for _,word:=range words {
   out=append(out,'"')
   for i:=0;i<len(word);i++ {c:=word[i];if c=='\\'||c=='"'||c=='$'||c=='` + "`" + `' {out=append(out,'\\')};out=append(out,c)}
   out=append(out,'"','\n')
  }
  return out
 }
 if err=os.WriteFile(inner,encode(words),0600);err!=nil {fatal(err)}
 alternate:=append([]string(nil),words[:len(words)-1]...)
 alternate=append(alternate,"-D","SETEQ=SETNE",words[len(words)-1])
 if err=os.WriteFile(inner+"\\",encode(alternate),0600);err!=nil {fatal(err)}
 data:=encode([]string{"@"+inner})
 if ` + strconv.FormatBool(trailing) + ` {data=append(data[:len(data)-1],'\\')}
 if err=os.WriteFile(outer,data,0600);err!=nil {fatal(err)}
 os.Args=append(os.Args[:4],"@"+outer)
}
`
}
