package closure

import (
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/gotool"
)

func assemblyReferenceSelectedSource(t testing.TB, dir string) computationSource {
	t.Helper()
	source, err := loadSelectedSource(t.Context(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), nil, false, ".")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func assemblyReferenceSelectedPacket(t testing.TB, source computationSource, target *ssa.Function) *selectedAssemblyPacket {
	t.Helper()
	provider, err := source.owner.packageFor(target)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := acquireSelectedAssembly(t.Context(), source.owner, provider, assemblyCaptureLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestAssemblyReferenceSelectedOwnedProviders(t *testing.T) {
	if testing.Short() {
		t.Skip("loads typed source and acquires actual final assembler actions")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	dir := t.TempDir()
	cases := []struct {
		name, body string
		accept     bool
		value      uint64
		result     bool
	}{
		{"Swap", assemblyReferenceUnitBody, true, 9, true},
		{"Inverted", strings.Replace(assemblyReferenceUnitBody, "SETEQ", "SETNE", 1), true, 9, false},
		{"CompareReplacement", strings.Replace(assemblyReferenceUnitBody, "old+8(FP)", "old+16(FP)", 1), true, 5, false},
		{"ExtraWrite", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $91, (BX)\n\tRET", 1), true, 91, true},
		{"WrongResult", strings.Replace(assemblyReferenceUnitBody, "ret+24(FP)", "ret+25(FP)", 1), false, 0, false},
		{"WrongSize", strings.Replace(assemblyReferenceUnitBody, "$0-25", "$0-24", 1), false, 0, false},
		{"WriteReturn", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $0, 0(SP)\n\tRET", 1), false, 0, false},
		{"WriteFrameContext", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $0, BP\n\tRET", 1), false, 0, false},
		{"Escape", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ BX, (BX)\n\tRET", 1), false, 0, false},
	}
	goSource := "package p\n"
	assembly := "#include \"textflag.h\"\n#include \"operation.h\"\n"
	for _, tc := range cases {
		goSource += "//go:noescape\nfunc " + tc.name + "(ptr *uint64, old, replacement uint64) bool\n"
		body := strings.Replace(tc.body, "·Swap(SB)", "·"+tc.name+"(SB)", 1)
		body = strings.Replace(body, ",4,", ",NOSPLIT,", 1)
		if tc.name == "Swap" {
			body = strings.Replace(body, "SETEQ", "RESULT", 1)
		}
		assembly += body
	}
	goSource += "func Missing(ptr *uint64, old, replacement uint64) bool\nfunc LocalOnly(ptr *uint64, old, replacement uint64) bool\n"
	goSource += "func DifferentWidth(ptr *uint32, old, replacement uint64) bool\nfunc ByteResult(ptr *uint64, old, replacement uint64) uint8\n"
	assembly += strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "LocalOnly<>(SB)", 1)
	assembly += strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "·DifferentWidth(SB)", 1)
	byteResult := strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "·ByteResult(SB)", 1)
	assembly += strings.Replace(byteResult, "SETEQ ret+24(FP)", "MOVB $128, ret+24(FP)", 1)
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/asmref\n\ngo 1.27\n", "p.go": goSource, "linkname.go": "package p\nimport _ \"unsafe\"\n//go:linknamestd Swap\n", "body_amd64.s": assembly, "operation.h": "#define RESULT SETEQ\n"})
	source := assemblyReferenceSelectedSource(t, dir)
	target := source.prog.Roots["Swap"]
	packet := assemblyReferenceSelectedPacket(t, source, target)
	var original *assemblyReference
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := checkAssemblyReference(t.Context(), source, source.prog.Roots[tc.name], packet, assemblyReferenceLimits{})
			if !tc.accept {
				if err == nil || r != nil {
					t.Fatal("invalid owned assembly acquired reference")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.evaluate(t.Context(), 5, 5, 9)
			if err != nil {
				t.Fatal(err)
			}
			if got.Value != tc.value || assemblyReferenceBool(t, got.Result) != tc.result {
				t.Fatalf("actual selected body produced %+v", got)
			}
			if tc.name == "Swap" {
				original = r
			}
		})
	}
	if original == nil {
		t.Fatal("baseline reference missing")
	}
	for _, name := range []string{"Missing", "LocalOnly", "DifferentWidth"} {
		if r, err := checkAssemblyReference(t.Context(), source, source.prog.Roots[name], packet, assemblyReferenceLimits{}); err == nil || r != nil {
			t.Fatalf("%s acquired external provider", name)
		}
	}
	byteReference, err := checkAssemblyReference(t.Context(), source, source.prog.Roots["ByteResult"], packet, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal("selected integer-byte result refused:", err)
	}
	byteOutcome, err := byteReference.evaluate(t.Context(), 5, 5, 9)
	if err != nil || byteOutcome.Value != 9 || byteOutcome.Result.kind != regionConstant || !types.Identical(byteOutcome.Result.typ, types.Typ[types.Uint8]) || byteOutcome.Result.scalar == nil || byteOutcome.Result.scalar.Kind() != constant.Int {
		t.Fatalf("selected byte result was interpreted as Boolean: %+v %v", byteOutcome, err)
	}
	if bits, exact := constant.Uint64Val(byteOutcome.Result.scalar); !exact || bits != 128 {
		t.Fatal("selected byte result lost its non-Boolean value")
	}
	for range 2 {
		if err := original.boundTo(source, target); err != nil {
			t.Fatal("identity check mutated the reference:", err)
		}
	}
	copyTarget := *target
	if err := original.boundTo(source, &copyTarget); err == nil {
		t.Fatal("copied declaration acquired exact target authority")
	}
	projections := packet.providerTexts()
	for i := range projections {
		for j := range projections[i].Lines {
			projections[i].Lines[j].Text = "RET"
			for k := range projections[i].Lines[j].Tokens {
				projections[i].Lines[j].Tokens[k] = "RET"
			}
		}
	}
	r, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal("caller projection mutated packet:", err)
	}
	got, err := r.evaluate(t.Context(), 5, 7, 9)
	if err != nil {
		t.Fatal(err)
	}
	if assemblyReferenceBool(t, got.Result) || got.Value != 5 || !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, 5, 8}, {true, true, 5, 8}}) {
		t.Fatal("failure writeback disappeared", got)
	}
	other := assemblyReferenceSelectedSource(t, dir)
	if err := original.boundTo(other, other.prog.Roots["Swap"]); err == nil {
		t.Fatal("equal-content foreign owner acquired reference")
	}
	if r, err := checkAssemblyReference(t.Context(), other, other.prog.Roots["Swap"], packet, assemblyReferenceLimits{}); err == nil || r != nil {
		t.Fatal("foreign typed owner borrowed acquisition")
	}
	// A changed include is acquired with a fresh owner/action and changes the
	// derived result even though the top-level provider still names RESULT.
	if err := os.WriteFile(filepath.Join(dir, "operation.h"), []byte("#define RESULT SETNE\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed := assemblyReferenceSelectedSource(t, dir)
	changedTarget := changed.prog.Roots["Swap"]
	changedPacket := assemblyReferenceSelectedPacket(t, changed, changedTarget)
	changedReference, err := checkAssemblyReference(t.Context(), changed, changedTarget, changedPacket, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got, err = changedReference.evaluate(t.Context(), 5, 5, 9)
	if err != nil {
		t.Fatal(err)
	}
	if assemblyReferenceBool(t, got.Result) || got.Value != 9 {
		t.Fatal("changed captured include did not change relation", got)
	}
}

func TestAssemblyReferenceSelectedRedirectRefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires the selected directive and complete assembler unit")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":       "module example.com/redirect\n\ngo 1.27\n",
		"p.go":         "package p\nfunc Swap(ptr *uint64, old, replacement uint64) bool\n",
		"linkname.go":  "package p\nimport _ \"unsafe\"\n//go:linkname Swap remote.Swap\n",
		"body_amd64.s": assemblyReferenceUnitBody,
	})
	source := assemblyReferenceSelectedSource(t, dir)
	target := source.prog.Roots["Swap"]
	packet := assemblyReferenceSelectedPacket(t, source, target)
	if r, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{}); err == nil || r != nil {
		t.Fatal("redirected typed declaration acquired a default-name assembly reference")
	}
}

func TestAssemblyReferenceSelectedCompetingProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires complete final assembler provider membership")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("selected assembly acquisition uses Linux amd64")
	}
	dir := t.TempDir()
	// DUPOK permits object construction; it does not give the source reference a
	// unique provider. Both selected files must participate in the refusal.
	body := strings.Replace(assemblyReferenceUnitBody, ",4,", ",6,", 1)
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/providers\n\ngo 1.27\n", "p.go": "package p\nfunc Swap(ptr *uint64, old, replacement uint64) bool\n", "one_amd64.s": body, "two_amd64.s": body})
	source := assemblyReferenceSelectedSource(t, dir)
	target := source.prog.Roots["Swap"]
	packet := assemblyReferenceSelectedPacket(t, source, target)
	if len(packet.providerTexts()) != 2 {
		t.Fatal("selected provider membership was incomplete")
	}
	if r, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{}); err == nil || r != nil {
		t.Fatal("competing weak providers acquired a reference")
	}
}
