package closure

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// genCompartment draws one package's files from the seeded source: the
// base file, then 1-5 test-only members over the member-kind surface — an
// in-package or external test file, a build constraint drawn from a small
// tag set, an embed of a generated data file, an embed of a constrained
// sibling (the shape that makes a member's kind follow the selection), and
// a dual compiled-and-embedded member. A compiled non-Go member is not
// drawn: the listing splits only .go files by the _test suffix, so an
// assembly file lands in the base package and is never a compartment
// member. The returned non-members are what the twin may vary: the base
// file's body, an extra base file, an unembedded data file.
func genCompartment(r *rand.Rand) (members, nonMembers map[string]string) {
	members = map[string]string{}
	nonMembers = map[string]string{
		"go.mod": "module example.com/gen\n\ngo 1.26\n",
		"gen.go": "package gen\n\nfunc F() int { return 1 }\n",
	}
	n := 1 + r.Intn(5)
	var constrained []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("m%d_%d_test.go", i, r.Intn(1000))
		pkg := "gen"
		if r.Intn(4) == 0 {
			pkg = "gen_test"
		}
		body := ""
		if r.Intn(3) == 0 {
			body = "//go:build " + []string{"extra", "other", "extra && other"}[r.Intn(3)] + "\n\n"
			constrained = append(constrained, name)
		}
		body += "package " + pkg + "\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n"
		if pkg == "gen_test" {
			body = strings.Replace(body, "\t\"testing\"\n", "\t\"testing\"\n\n\t\"example.com/gen\"\n", 1)
		}
		switch r.Intn(4) {
		case 0:
			data := fmt.Sprintf("data%d.txt", i)
			members[data] = fmt.Sprintf("payload %d\n", r.Intn(100000))
			body += "//go:embed " + data + "\nvar blob" + fmt.Sprint(i) + " string\n\n"
		case 1:
			if len(constrained) > 0 {
				body += "//go:embed " + constrained[r.Intn(len(constrained))] + "\nvar sibling" + fmt.Sprint(i) + " string\n\n"
			}
		case 2:
			// A dual member: this file embeds itself.
			body += "//go:embed " + name + "\nvar self" + fmt.Sprint(i) + " string\n\n"
		}
		call := "F()"
		if pkg == "gen_test" {
			call = "gen.F()"
		}
		for j, k := 0, r.Intn(3); j <= k; j++ {
			body += fmt.Sprintf("func Test%d_%d(t *testing.T) { if %s != 1 { t.Fatal(%d) } }\n\n", i, j, call, r.Intn(1000))
		}
		members[name] = body
	}
	return members, nonMembers
}

func union(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// Under one listing configuration the compartment ledger is a function
// of the compartment hash: twins that share every member's bytes and
// differ in every non-member — the base file's body, an extra base file,
// an unembedded data file — give equal hashes and equal ledgers, and one
// member's edit moves the hash (REQ-closure-test-variant-compartment).
func TestCompartmentLedgerIsAFunctionOfTheHashUnderOneListingConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("lists generated modules through the toolchain")
	}
	r := rand.New(rand.NewSource(168))
	const pkg = "example.com/gen"
	subject := Subject{Package: pkg, Symbol: "F"}
	for i := 0; i < 12; i++ {
		members, nonMembers := genCompartment(r)
		twin := map[string]string{}
		for k, v := range nonMembers {
			twin[k] = v
		}
		twin["gen.go"] = "package gen\n\n// a different base body\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n"
		twin["extra.go"] = "package gen\n\nvar extra = 3\n"
		twin["loose.txt"] = "unembedded data\n"
		a, b := writeTestVariantModule(t, union(nonMembers, members)), writeTestVariantModule(t, union(twin, members))
		ha, hb := computeAt(t, a, subject)[subject].TestVariants, computeAt(t, b, subject)[subject].TestVariants
		if ha == "" || ha != hb {
			t.Fatalf("draw %d: hashes %q vs %q over the same members\n%v", i, ha, hb, members)
		}
		la, filesA := ledgerUnder(t, a, nil, nil, pkg)
		lb, _ := ledgerUnder(t, b, nil, nil, pkg)
		if !reflect.DeepEqual(la, lb) {
			t.Fatalf("draw %d: equal hashes, differing ledgers:\n%+v\n%+v", i, la, lb)
		}
		// One member's edit moves the hash: a member the listing itself
		// names, so a constrained-out file is never the one edited.
		if len(filesA) == 0 {
			// Every member constrained out under the plain selection: an
			// empty compartment, the defined empty identity — nothing to
			// edit; the equality arms above still held.
			continue
		}
		member := filesA[r.Intn(len(filesA))]
		body, known := members[member]
		if !known {
			t.Fatalf("draw %d: the listing names %s, which the generator did not write", i, member)
		}
		if err := os.WriteFile(filepath.Join(b, member), []byte(body+"\n// edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if hc := computeAt(t, b, subject)[subject].TestVariants; hc == ha {
			t.Fatalf("draw %d: an edited member %s kept the hash %q", i, member, ha)
		}
	}
}

// envWith is the process environment with one variable set, one entry.
func envWith(key, value string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, key+"=") {
			env = append(env, kv)
		}
	}
	return append(env, key+"="+value)
}

// The compartment hash is unsalted by the listing configuration and the
// ledger is not: a constrained test file embedded by a compiled sibling
// is a compartment member under both configurations — embedded data
// under one, a dual compiled-and-embedded member under the other — so
// the same members and bytes give one hash and two ledgers, on the
// build-selection axis (a tag), the platform axis (GOOS), and the cgo
// axis (CGO_ENABLED) alike; the reason the entailment is stated per
// listing configuration (REQ-closure-test-variant-compartment).
func TestCompartmentHashIsUnsaltedByTheListingConfigurationAndTheLedgerIsNot(t *testing.T) {
	if testing.Short() {
		t.Skip("lists a module through the toolchain six times")
	}
	const pkg = "example.com/sel"
	subject := Subject{Package: pkg, Symbol: "F"}
	type arm struct {
		name, member, constraint string
		envA, envB               []string
		flagsA, flagsB           []string
	}
	arms := []arm{
		{name: "tag", member: "extra_test.go", constraint: "//go:build extra\n\n", flagsB: []string{"-tags=extra"}},
		{name: "platform", member: "extra_linux_test.go", envA: envWith("GOOS", "darwin"), envB: envWith("GOOS", "linux")},
		// cgo cannot appear in a test file; the axis reaches a test-only
		// member through the `cgo` build tag CGO_ENABLED sets.
		{name: "cgo", member: "extra_cgo_test.go", constraint: "//go:build cgo\n\n", envA: envWith("CGO_ENABLED", "0"), envB: envWith("CGO_ENABLED", "1")},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			dir := writeTestVariantModule(t, map[string]string{
				"go.mod":      "module example.com/sel\n\ngo 1.26\n",
				"sel.go":      "package sel\n\nfunc F() int { return 1 }\n",
				"sel_test.go": "package sel\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed " + a.member + "\nvar sibling string\n\nfunc TestF(t *testing.T) { if F() != 1 || sibling == \"\" { t.Fatal(1) } }\n",
				a.member:      a.constraint + "package sel\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { if F() != 1 { t.Fatal(2) } }\n",
			})
			ca := computeUnder(t, dir, a.envA, a.flagsA, subject)[subject].TestVariants
			cb := computeUnder(t, dir, a.envB, a.flagsB, subject)[subject].TestVariants
			if ca == "" || ca != cb {
				t.Fatalf("the configuration salted the compartment hash: %q vs %q", ca, cb)
			}
			la, _ := ledgerUnder(t, dir, a.envA, a.flagsA, pkg)
			lb, _ := ledgerUnder(t, dir, a.envB, a.flagsB, pkg)
			if reflect.DeepEqual(la, lb) {
				t.Fatalf("two configurations, one ledger: %+v", la)
			}
			has := func(l TestVariantLedger) bool {
				for _, d := range l.Declarations {
					if d.Name == "TestExtra" {
						return true
					}
				}
				return false
			}
			if has(la) || !has(lb) {
				t.Fatalf("the constrained member's declaration: excluded-side %v, included-side %v", has(la), has(lb))
			}
			// The member is a member under both, its header the whole
			// content marked embedded either way: embedded data under the
			// excluding configuration, a dual member under the including one.
			headerOf := func(l TestVariantLedger) (TestVariantFileHeader, bool) {
				for _, h := range l.FileHeaders {
					if h.File == a.member {
						return h, true
					}
				}
				return TestVariantFileHeader{}, false
			}
			hp, okp := headerOf(la)
			ht, okt := headerOf(lb)
			if !okp || !okt || !hp.Embedded || !ht.Embedded || hp.Hash == "" || hp.Hash != ht.Hash {
				t.Fatalf("constrained member's headers: %+v (%v), %+v (%v); want both embedded over the same bytes", hp, okp, ht, okt)
			}
		})
	}
}
