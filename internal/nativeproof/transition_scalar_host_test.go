package nativeproof

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// This standalone hardware observation complements the ISA contract. It does
// not establish universal processor behavior or borrow the symbolic kernel's
// arithmetic. Undefined flags are excluded from the deciding comparison.
func TestTransitionScalarAssemblyOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes an independent amd64 assembly fixture")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("requires amd64 instruction execution")
	}
	dir := t.TempDir()
	assembly := "#include \"textflag.h\"\n"
	for _, op := range []struct{ name, instruction, result string }{
		{"shiftDX", "SHLL CX, DX", "DX"}, {"shiftCX", "MOVQ DX, CX\n SHLL CX, CX", "CX"},
		{"inc64", "INCQ DX", "DX"}, {"sbbSelf", "SBBL DX, DX", "DX"},
		{"sbb32", "SBBL BX, DX", "DX"}, {"and32", "ANDL BX, DX", "DX"},
	} {
		// The balanced PUSHFQ/POPQ pairs finish before any ABI0 FP access.
		assembly += fmt.Sprintf(`TEXT ·%s(SB), NOSPLIT, $0-48
 MOVQ a+0(FP), DX
 MOVQ b+8(FP), BX
 MOVQ BX, CX
 MOVQ setup+16(FP), R10
 TESTQ R10, R10
 JZ clear
 MOVL $0x7fffffff, AX
 ADDL $1, AX
 STC
 JMP capture
clear:
 MOVL $0, AX
 SUBL $0, AX
capture:
 PUSHFQ
 POPQ R8
 %s
 PUSHFQ
 POPQ R9
 MOVQ R8, before+24(FP)
 MOVQ R9, after+32(FP)
 MOVQ %s, result+40(FP)
 RET
`, op.name, op.instruction, op.result)
	}
	files := map[string]string{
		"go.mod":         "module example.com/scalaroracle\n\ngo 1.27\n",
		"oracle_amd64.s": assembly,
		"main.go": `package main
import ("fmt"; "math/bits")
func shiftDX(a,b,setup uint64) (before,after,result uint64)
func shiftCX(a,b,setup uint64) (before,after,result uint64)
func inc64(a,b,setup uint64) (before,after,result uint64)
func sbbSelf(a,b,setup uint64) (before,after,result uint64)
func sbb32(a,b,setup uint64) (before,after,result uint64)
func and32(a,b,setup uint64) (before,after,result uint64)
const arithmetic = uint64(0x8d5)
var cases int
func flag(v bool, bit uint) uint64 { if v { return 1<<bit }; return 0 }
func common(z uint64, sign uint) uint64 {
 return flag(z==0,6)|flag(z&(1<<sign)!=0,7)|flag(bits.OnesCount8(byte(z))%2==0,2)
}
func check(name string,a,b,setup,before,after,result,want,mask,flags uint64) {
 cases++
 incoming:=uint64(0x44); if setup!=0 { incoming=0x895 }
 if before&arithmetic!=incoming || result!=want || after&mask!=flags&mask {
  panic(fmt.Sprintf("%s a=%x b=%x setup=%d before=%x after=%x result=%x want=%x mask=%x flags=%x",name,a,b,setup,before,after,result,want,mask,flags))
 }
}
func shift(alias bool,a,b,setup uint64) {
 before,after,result:=shiftDX(a,b,setup)
 if alias { before,after,result=shiftCX(a,b,setup); b=a&255 }
 n:=b&31; z:=uint64(uint32(a)<<n); mask,flags:=arithmetic,before
 if n!=0 {
  cf:=(a>>(32-n))&1
  mask,flags=0xc5,common(z,31)|cf
  if n==1 { mask|=0x800; flags|=((z>>31)^cf)<<11 }
 }
 // Full result equality decides zero extension even for masked count zero.
 check("SHL",a,b,setup,before,after,result,z,mask,flags)
}
func main() {
 counts:=[]uint64{0,1,2,31,32,33,63,64,255}
 for _,setup:=range []uint64{0,1} {
  for _,a:=range []uint64{0xdeadbeef89abcdef,0x1234567880000001,0xabcdef0100000000} {
   for _,n:=range counts { shift(false,a,n,setup) }
  }
  for _,a:=range []uint64{0xdeadbeef89abcd00,0xfedcba9876543200} {
   for _,n:=range counts { shift(true,a|n,0,setup) }
  }
  for _,a:=range []uint64{0,0x7fffffffffffffff,0xffffffffffffffff,0xdeadbeef89abcdef} {
   before,after,result:=inc64(a,0,setup); z:=a+1
   flags:=common(z,63)|(before&1)|flag(a==0x7fffffffffffffff,11)|flag(a&15==15,4)
   check("INC",a,0,setup,before,after,result,z,arithmetic,flags)
   before,after,result=sbbSelf(a,0,setup); z=uint64(uint32(0-uint32(setup)))
   flags=common(z,31)|setup|flag(setup!=0,4)
   check("SBB/self",a,a,setup,before,after,result,z,arithmetic,flags)
  }
  values:=[]uint64{0,1,15,0x7fffffff,0x80000000,0xffffffffffffffff}
  for _,a:=range values { for _,b:=range values {
   before,after,result:=sbb32(a,b,setup)
   x,y:=uint64(uint32(a)),uint64(uint32(b)); z:=uint64(uint32(x-y-setup))
   flags:=common(z,31)|flag(x<y+setup,0)|flag((x^y)&(x^z)&0x80000000!=0,11)|flag(x&15<(y&15)+setup,4)
   check("SBB",a,b,setup,before,after,result,z,arithmetic,flags)
   before,after,result=and32(a,b,setup); z=x&y
   check("AND",a,b,setup,before,after,result,z,arithmetic &^ 16,common(z,31))
  } }
 }
 if cases!=250 { panic(cases) }; fmt.Println("250 scalar hardware cases passed")
}
`,
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := os.Environ()
	for key, value := range map[string]string{"GOOS": runtime.GOOS, "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, key, value)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	binary := filepath.Join(dir, "oracle")
	if _, err := runner.Run(t.Context(), dir, env, "build", "-o", binary, "."); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "250 scalar hardware cases passed" {
		t.Fatalf("assembly oracle: %s %v", output, err)
	}
}
