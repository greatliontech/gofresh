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

// Reference non-memoized identity rule. Keep the reference separate from the
// lookup encoding and miss implementation: cache history cannot alter the
// native policy identity (REQ-fresh-toolchain-dependencies).
func originalPolicyIdentity(in policyInputs) string {
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@2", in.verifier, in.audit,
		in.packages, in.linknames, seeds})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPolicyMemoPreservesIdentityAndOwnsItsInputs(t *testing.T) {
	in := capturePolicyInputs()
	published := originalPolicyIdentity(in)
	if published == "" {
		t.Fatal("empty policy identity")
	}
	var memo policyMemo
	if got := memo.value(in); got != published || memo.value(in) != published {
		t.Fatalf("cold/warm policy differs from the published identity: %q", got)
	}
	in.packages["snapshot-only"] = true
	in.linknames["snapshot-only.Symbol"] = true
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
		verifier: "gofresh/toolchain-verifier@1", audit: "audit",
		packages:  map[string]bool{"pure": true},
		linknames: map[string]bool{"runtime.fn": true}, seeds: []string{"runtime", "pure"},
	}
	clone := func(in policyInputs) policyInputs {
		in.packages, in.linknames = maps.Clone(in.packages), maps.Clone(in.linknames)
		in.seeds = slices.Clone(in.seeds)
		return in
	}
	for name, change := range map[string]func(*policyInputs){
		"verifier":      func(in *policyInputs) { in.verifier += "-changed" },
		"audit":         func(in *policyInputs) { in.audit += "-changed" },
		"package value": func(in *policyInputs) { in.packages["pure"] = false },
		"package name":  func(in *policyInputs) { delete(in.packages, "pure"); in.packages["other"] = true },
		"link value":    func(in *policyInputs) { in.linknames["runtime.fn"] = false },
		"link name":     func(in *policyInputs) { delete(in.linknames, "runtime.fn"); in.linknames["runtime.other"] = true },
		"seed":          func(in *policyInputs) { in.seeds[0] = "other" },
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
		in := policyInputs{verifier: word(), audit: word()}
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
