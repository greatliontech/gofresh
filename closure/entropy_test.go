package closure

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// crypto/rand's operations are the entropy class — an external system
// call named as such in the one classification table both tiers
// consult, never the unaudited fallback; the exported Reader refuses as
// an unaudited selector at the file fold; the unseeded math/rand sources
// keep the unaudited fallback at both tiers until their own audit, the
// fold binding math/rand/v2's declared name as a secondary beside its
// last element, never shadowing a primary; and two imports binding one
// identifier — what the language forbids — refuse the file fail-closed
// (REQ-closure-observability-analysis's entropy class).
func TestCryptoRandIsTheEntropyClass(t *testing.T) {
	for _, name := range []string{"Read", "Text", "Int", "Prime"} {
		effect, ok := classBEffect("crypto/rand", name)
		if !ok || effect.kind != externalEffectNative || !strings.HasPrefix(effect.reason, "reaches crypto/rand."+name+" (entropy)") || effect.observable {
			t.Errorf("crypto/rand.%s = %+v ok=%v, want the entropy class", name, effect, ok)
		}
		if classBPureStandard(true, "crypto/rand", name) {
			t.Errorf("crypto/rand.%s admitted as pure", name)
		}
	}
	if _, ok := classBEffect("crypto/rand", "Reader"); ok {
		t.Error("crypto/rand.Reader classified as an operation — it is a selector the file fold refuses on its own")
	}
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/entropy\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"read", "package read\n\nimport \"crypto/rand\"\n\nfunc Subject() int {\n\tb := make([]byte, 4)\n\tn, _ := rand.Read(b)\n\treturn n\n}\n", "package scan: reaches crypto/rand.Read (entropy)"},
		{"text", "package text\n\nimport \"crypto/rand\"\n\nfunc Subject() string { return rand.Text() }\n", "package scan: reaches crypto/rand.Text (entropy)"},
		// Int reads the reader it is given — fail-closed on an unproven operand, in the same class.
		{"intop", "package intop\n\nimport (\n\t\"bytes\"\n\t\"crypto/rand\"\n\t\"math/big\"\n)\n\nfunc Subject() int64 {\n\tn, _ := rand.Int(bytes.NewReader([]byte{1, 2, 3, 4}), big.NewInt(10))\n\treturn n.Int64()\n}\n", "package scan: reaches crypto/rand.Int (entropy)"},
		{"prime", "package prime\n\nimport (\n\t\"bytes\"\n\t\"crypto/rand\"\n)\n\nfunc Subject() int {\n\tp, _ := rand.Prime(bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}), 8)\n\treturn p.BitLen()\n}\n", "package scan: reaches crypto/rand.Prime (entropy)"},
		{"reader", "package reader\n\nimport (\n\t\"crypto/rand\"\n\t\"io\"\n)\n\nfunc Subject() int {\n\tb := make([]byte, 4)\n\tn, _ := io.ReadFull(rand.Reader, b)\n\treturn n\n}\n", "package scan: reaches unaudited standard operation crypto/rand.Reader"},
		// The unseeded math/rand sources keep the fallback at both tiers: the fold binds the unnamed v2 import to rand, so a sibling declaration's reach refuses the package at the fold as v1's does.
		{"mathrand", "package mathrand\n\nimport \"math/rand/v2\"\n\nfunc Subject() int { return rand.IntN(3) }\n", "package scan: reaches unaudited standard operation math/rand/v2.IntN"},
		{"mathrandsibling", "package mathrandsibling\n\nimport \"math/rand/v2\"\n\nfunc Subject() int { return 3 }\n\nfunc Other() int { return rand.IntN(3) }\n", "package scan: reaches unaudited standard operation math/rand/v2.IntN"},
		{"mathrandv1", "package mathrandv1\n\nimport \"math/rand\"\n\nfunc Subject() int { return 3 }\n\nfunc Other() int { return rand.Int() }\n", "package scan: reaches unaudited standard operation math/rand.Int"},
		// A guessed secondary name never shadows a primary: net stays the standard package beside an API-version directory whose last element is v1, so a sibling's net.Dial keeps its classification.
		{"collide", "package collide\n\nimport (\n\t\"net\"\n\n\t\"example.com/entropy/collide/net/v1\"\n)\n\nfunc Subject() int { return v1.N() }\n\nfunc Other() {\n\tc, _ := net.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		// Two modules at the same major version bind alpha and beta as the compiler does; their version-element primaries clash on v2 but neither is a name source spells, so nothing records and the pure file proves observable.
		{"twomods", "package twomods\n\nimport (\n\t\"example.com/entropy/twomods/alpha/v2\"\n\t\"example.com/entropy/twomods/beta/v2\"\n)\n\nfunc Subject() int { return alpha.N() + beta.N() }\n", ""},
		// An explicit alias is ground truth: a derived version-element primary never displaces it, so the sibling's dial through the alias keeps its classification in either import order.
		{"aliasver", "package aliasver\n\nimport (\n\tv2 \"net\"\n\n\t\"example.com/entropy/aliasver/mod/v2\"\n)\n\nfunc Subject() int { return mod.N() }\n\nfunc Other() {\n\tc, _ := v2.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		{"aliasverlate", "package aliasverlate\n\nimport (\n\t\"example.com/entropy/aliasverlate/mod/v2\"\n\n\tv2 \"net\"\n)\n\nfunc Subject() int { return mod.N() }\n\nfunc Other() {\n\tc, _ := v2.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		// Two API versions of one group bind v1 and v2 as the compiler does; the secondary they would share binds nothing, and the pure file proves observable.
		{"apiver", "package apiver\n\nimport (\n\t\"example.com/entropy/apiver/core/v1\"\n\t\"example.com/entropy/apiver/core/v2\"\n)\n\nfunc Subject() int { return v1.N() + v2.N() }\n", ""},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/entropy/" + tc.pkg, Symbol: "Subject"})
	}
	if err := os.MkdirAll(filepath.Join(dir, "collide", "net", "v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "collide/net/v1/v1.go", "package v1\n\nfunc N() int { return 1 }\n")
	for _, sub := range []string{"apiver/core/v1", "apiver/core/v2"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, sub+"/"+path.Base(sub)+".go", "package "+path.Base(sub)+"\n\nfunc N() int { return 1 }\n")
	}
	for _, mod := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(filepath.Join(dir, "twomods", mod, "v2"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "twomods/"+mod+"/v2/"+mod+".go", "package "+mod+"\n\nfunc N() int { return 1 }\n")
	}
	for _, pkg := range []string{"aliasver", "aliasverlate"} {
		if err := os.MkdirAll(filepath.Join(dir, pkg, "mod", "v2"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, pkg+"/mod/v2/mod.go", "package mod\n\nfunc N() int { return 1 }\n")
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/entropy/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.HasPrefix(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
		if strings.Contains(tc.refusal, "(entropy)") && !strings.HasSuffix(proof.Reason, " (dischargeable by restructuring the subject away from the reach, or by "+PurityResponsibility+")") {
			t.Errorf("%s = %q, want the entropy refusal to carry the ambient discharge channel", tc.pkg, proof.Reason)
		}
	}
}

// The classifier is gated on the classified-package set the maximal
// tier's dot-import backstop reads, so the two cannot disagree; this
// pins the direction the gate leaves open — every listed package has
// an arm that classifies at least one name — and spot-checks the gate.
// The gate's own deletion is not test-distinguishable while no arm for
// an unlisted package exists; the table collapse that removes the gate
// with the hazard is docs/issues/classb-arms-one-table.md
// (REQ-closure-observability-analysis).
func TestClassBPackagesMatchTheArms(t *testing.T) {
	samples := map[string]string{
		"fmt": "Println", "os": "Getenv", "syscall": "Mkdir", "golang.org/x/sys/unix": "Mkdir", "testing": "Short",
		"net": "Dial", "net/http": "Get", "html/template": "ParseFiles", "text/template": "ParseFiles", "plugin": "Open",
		"crypto/rand": "Read",
	}
	for pkgPath := range classBPackages {
		name, ok := samples[pkgPath]
		if !ok {
			t.Errorf("%s is listed but this test carries no sample name for it — add one", pkgPath)
			continue
		}
		if _, classified := classBEffect(pkgPath, name); !classified {
			t.Errorf("%s is listed but %s.%s does not classify", pkgPath, pkgPath, name)
		}
		if !packageHasClassifiedExternalAPI(pkgPath) {
			t.Errorf("%s classifies but the dot-import backstop does not list it", pkgPath)
		}
	}
	for pkgPath := range samples {
		if !classBPackages[pkgPath] {
			t.Errorf("%s carries a sample but is not listed", pkgPath)
		}
	}
	for _, pkgPath := range []string{"math/rand", "math/rand/v2", "strings", "encoding/json/v2"} {
		if packageHasClassifiedExternalAPI(pkgPath) {
			t.Errorf("%s listed as classified", pkgPath)
		}
	}
}

// An unnamed import binds the identifier the toolchain's package
// clause declares for a major-versioned path: the last element past
// the version (REQ-closure-observability-analysis).
func TestImplicitImportNameSkipsMajorVersionElements(t *testing.T) {
	for pkgPath, want := range map[string]string{
		"math/rand/v2": "rand", "math/rand": "rand", "encoding/json/v2": "json", "fmt": "fmt",
		"example.com/mod/v3": "mod", "example.com/v": "v", "example.com/v2x": "v2x", "v2": "v2",
	} {
		if got := implicitImportName(pkgPath); got != want {
			t.Errorf("implicitImportName(%q) = %q, want %q", pkgPath, got, want)
		}
	}
}

// The fold's unnamed-import binding is pinned against the toolchain's
// own package names: for every importable standard package the derived
// identifier is the declared one, so a release adding a path whose
// declared name the rule cannot derive fails here instead of opening a
// silent fold hole (REQ-closure-observability-analysis).
func TestImplicitImportNameMatchesTheToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}} {{.Name}}", "std").Output()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] == "main" || strings.HasPrefix(fields[0], "internal/") || strings.Contains(fields[0], "/internal/") || strings.HasPrefix(fields[0], "vendor/") {
			continue
		}
		checked++
		if got := implicitImportName(fields[0]); got != fields[1] {
			t.Errorf("implicitImportName(%q) = %q, the toolchain declares %q", fields[0], got, fields[1])
		}
	}
	if checked < 100 {
		t.Fatalf("checked %d importable standard packages, want the whole library", checked)
	}
}
