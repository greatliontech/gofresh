package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/rand"
	"slices"
	"sort"
	"sync"
	"testing"
)

// This is the original non-memoized identity rule. Keep the reference separate
// from the lookup encoding and miss implementation: cache history cannot alter
// the native policy identity (REQ-fresh-toolchain-dependencies).
func originalPolicyIdentity(in policyInputs) string {
	rows := make([]string, 0, len(in.rows))
	for _, row := range in.rows {
		data, _ := json.Marshal(rowChain(in.rows, row.Label))
		rows = append(rows, string(data))
	}
	sort.Strings(rows)
	rows = slices.Compact(rows)
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@1", in.audit,
		in.packages, in.linknames, seeds, rows})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPolicyMemoPreservesIdentityAndOwnsItsInputs(t *testing.T) {
	const published = "4b700d927dd865ee4c660db25cc1d52802c0bb0c951de5552dd63453538571a3"
	in := capturePolicyInputs()
	if got := originalPolicyIdentity(in); got != published {
		t.Fatalf("the admission inventory changed: got %q, golden %q", got, published)
	}
	var memo policyMemo
	if got := memo.value(in); got != published || memo.value(in) != published {
		t.Fatalf("cold/warm policy differs from the published identity: %q", got)
	}
	in.packages["snapshot-only"] = true
	in.linknames["snapshot-only.Symbol"] = true
	in.rows[0].Packages["snapshot-only"] = "digest"
	in.seeds[0] = "snapshot-only"
	if got := memo.value(capturePolicyInputs()); got != published {
		t.Fatalf("a captured input aliases a source inventory: %q", got)
	}
	if got := memo.value(in); got == published || got != originalPolicyIdentity(in) {
		t.Fatalf("changed captured input did not move independently: %q", got)
	}
}

func TestPolicyMemoKeysEveryInput(t *testing.T) {
	base := policyInputs{
		audit: "audit", packages: map[string]bool{"pure": true},
		linknames: map[string]bool{"runtime.fn": true}, seeds: []string{"runtime", "pure"},
		rows: []toolchainSourceRow{
			{Label: "a", Packages: map[string]string{"p": "first"}},
			{Label: "b", Packages: map[string]string{"p": "second"}},
			{Label: "child", Base: "a", Packages: map[string]string{"q": "third"}},
		},
	}
	clone := func(in policyInputs) policyInputs {
		in.packages, in.linknames = maps.Clone(in.packages), maps.Clone(in.linknames)
		in.seeds, in.rows = slices.Clone(in.seeds), slices.Clone(in.rows)
		for i := range in.rows {
			in.rows[i].Packages = maps.Clone(in.rows[i].Packages)
		}
		return in
	}
	for name, change := range map[string]func(*policyInputs){
		"audit":         func(in *policyInputs) { in.audit += "-changed" },
		"package value": func(in *policyInputs) { in.packages["pure"] = false },
		"package name":  func(in *policyInputs) { delete(in.packages, "pure"); in.packages["other"] = true },
		"link value":    func(in *policyInputs) { in.linknames["runtime.fn"] = false },
		"link name":     func(in *policyInputs) { delete(in.linknames, "runtime.fn"); in.linknames["runtime.other"] = true },
		"seed":          func(in *policyInputs) { in.seeds[0] = "other" },
		"row label":     func(in *policyInputs) { in.rows[0].Label = "unreferenced" },
		"row base":      func(in *policyInputs) { in.rows[2].Base = "b" },
		"row key":       func(in *policyInputs) { delete(in.rows[0].Packages, "p"); in.rows[0].Packages["other"] = "first" },
		"row value":     func(in *policyInputs) { in.rows[0].Packages["p"] = "moved" },
		"row omitted":   func(in *policyInputs) { in.rows = in.rows[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := clone(base)
			change(&changed)
			want, moved := originalPolicyIdentity(base), originalPolicyIdentity(changed)
			if want == moved {
				t.Fatal("test mutation did not move the policy identity")
			}
			var memo policyMemo
			for _, in := range []policyInputs{base, base, changed, changed, base} {
				if got := memo.value(in); got != originalPolicyIdentity(in) {
					t.Fatalf("cache history changed the answer: %q", got)
				}
			}
		})
	}
	for name, set := range map[string]func(*policyInputs, bool){
		"packages": func(in *policyInputs, empty bool) {
			in.packages = nil
			if empty {
				in.packages = map[string]bool{}
			}
		},
		"linknames": func(in *policyInputs, empty bool) {
			in.linknames = nil
			if empty {
				in.linknames = map[string]bool{}
			}
		},
		"seeds": func(in *policyInputs, empty bool) {
			in.seeds = nil
			if empty {
				in.seeds = []string{}
			}
		},
	} {
		t.Run(name+" nil versus empty", func(t *testing.T) {
			nilForm, emptyForm := clone(base), clone(base)
			set(&nilForm, false)
			set(&emptyForm, true)
			if originalPolicyIdentity(nilForm) == originalPolicyIdentity(emptyForm) {
				t.Fatal("nil/empty control has identical policy identities")
			}
			var memo policyMemo
			for _, in := range []policyInputs{nilForm, nilForm, emptyForm, emptyForm, nilForm} {
				if got := memo.value(in); got != originalPolicyIdentity(in) {
					t.Fatalf("nil/empty transition reused %q", got)
				}
			}
		})
	}
	// Labels are raw strings for base resolution, before JSON replaces invalid
	// UTF-8. The extra q entry makes the child's two possible chains distinct.
	a, b := clone(base), clone(base)
	for _, in := range []*policyInputs{&a, &b} {
		in.rows[0].Label, in.rows[1].Label = "\xff", "\xfe"
	}
	a.rows[2].Base, b.rows[2].Base = "\xff", "\xfe"
	if a.key() == b.key() || originalPolicyIdentity(a) == originalPolicyIdentity(b) {
		t.Fatal("raw-label distinction lost")
	}
	var memo policyMemo
	if memo.value(a) != originalPolicyIdentity(a) || memo.value(b) != originalPolicyIdentity(b) {
		t.Fatal("JSON-equivalent raw labels reused the wrong chain")
	}
}

func TestPolicyMemoGeneratedHistories(t *testing.T) {
	r := rand.New(rand.NewSource(7331))
	var variants []policyInputs
	var expected []string
	word := func() string {
		data := make([]byte, r.Intn(6))
		for i := range data {
			data[i] = []byte{0, 'a', 'b', 0xfe, 0xff}[r.Intn(5)]
		}
		return string(data)
	}
	for draw := 0; draw < 64; draw++ {
		in := policyInputs{audit: word()}
		if r.Intn(2) == 0 {
			in.packages = map[string]bool{}
			in.linknames = map[string]bool{}
			for n := r.Intn(4); n > 0; n-- {
				in.packages[word()] = r.Intn(2) == 0
				in.linknames[word()] = r.Intn(2) == 0
			}
		}
		if r.Intn(2) == 0 {
			in.seeds = []string{}
			for n := r.Intn(4); n > 0; n-- {
				in.seeds = append(in.seeds, word())
			}
		}
		if r.Intn(2) == 0 {
			in.rows = []toolchainSourceRow{}
			for n := r.Intn(4); n > 0; n-- {
				row := toolchainSourceRow{Label: word(), Base: word()}
				if r.Intn(2) == 0 {
					row.Packages = map[string]string{}
					for k := r.Intn(4); k > 0; k-- {
						row.Packages[word()] = word()
					}
				}
				in.rows = append(in.rows, row)
			}
		}
		variants = append(variants, in)
		expected = append(expected, originalPolicyIdentity(in))
	}
	var memo policyMemo
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Go(func() {
			for offset := range 128 {
				i := (offset + worker) % len(variants)
				if got := memo.value(variants[i]); got != expected[i] {
					t.Errorf("variant %d: got %s want %s", i, got, expected[i])
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkAdmissionPolicy(b *testing.B) {
	b.ReportAllocs()
	var result string
	for b.Loop() {
		result = admissionPolicy()
	}
	if result == "" {
		b.Fatal("missing policy identity")
	}
	b.Logf("policy=%s", result)
}
