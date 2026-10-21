package closure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestMaximalFactsRetainHiddenBlockers(t *testing.T) {
	identity := MaximalIdentity{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules"}
	network := trueExternalEffect("net")
	environment, ok := classBEffect("os", "Getenv")
	if !ok {
		t.Fatal("missing environment classification")
	}
	one := newMaximalFacts(identity, []externalEffect{network}, network.reason)
	complete := newMaximalFacts(identity, []externalEffect{network, environment}, network.reason)
	if one.Closure() != complete.Closure() {
		t.Fatal("fixture must hide the environment blocker behind the same preferred reason")
	}
	if one.Equal(complete) || complete.Equal(one) {
		t.Fatal("equal legacy projections hid a changed blocker inventory")
	}
	if !complete.Equal(newMaximalFacts(identity, []externalEffect{environment, network}, network.reason)) {
		t.Fatal("scan traversal order changed complete facts")
	}
	want := []Blocker{
		{Kind: BlockerEnvironment, Package: "os", Symbol: "Getenv", Reason: environment.reason},
		{Kind: BlockerNetwork, Package: "net", Reason: network.reason},
	}
	if got := complete.Effects; !slices.Equal(got, want) {
		t.Fatalf("blockers = %+v, want %+v", got, want)
	}
	if complete.Identity != identity {
		t.Fatalf("identity = %+v, want %+v", complete.Identity, identity)
	}
	// Change every retained field independently, while holding the selected
	// reason and identity fixed. No field may disappear through projection.
	for name, change := range map[string]func(*externalEffect){
		"kind":        func(e *externalEffect) { e.kind = externalEffectFileIO },
		"package":     func(e *externalEffect) { e.packagePath = "other" },
		"symbol":      func(e *externalEffect) { e.symbol = "LookupEnv" },
		"detail":      func(e *externalEffect) { e.detail = "detail" },
		"reason":      func(e *externalEffect) { e.reason = "different diagnostic" },
		"observable":  func(e *externalEffect) { e.observable = true },
		"unrefinable": func(e *externalEffect) { e.unrefinable = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := environment
			change(&changed)
			other := newMaximalFacts(identity, []externalEffect{network, changed}, network.reason)
			if complete.Equal(other) || slices.Equal(complete.Effects, other.Effects) {
				t.Fatalf("changed %s disappeared from retained/projected facts", name)
			}
		})
	}
	for name, change := range map[string]func(*MaximalIdentity){
		"hash":     func(i *MaximalIdentity) { i.Hash += "x" },
		"variants": func(i *MaximalIdentity) { i.TestVariants += "x" },
		"content":  func(i *MaximalIdentity) { i.ToolchainContent += "x" },
		"policy":   func(i *MaximalIdentity) { i.AdmissionPolicy += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := identity
			change(&changed)
			if complete.Equal(newMaximalFacts(changed, []externalEffect{environment, network}, network.reason)) {
				t.Fatalf("changed %s disappeared from identity equality", name)
			}
		})
	}
	if complete.Equal(newMaximalFacts(identity, []externalEffect{environment, network}, "another preferred diagnostic")) {
		t.Fatal("preferred diagnostic disappeared from full equality")
	}
}

func TestMaximalFactsOwnTheirInputsAndProjections(t *testing.T) {
	effect := externalEffect{kind: externalEffectNative, packagePath: "native", symbol: "F", detail: "body", reason: "native body", observable: true, unrefinable: true}
	input := []externalEffect{effect}
	facts := newMaximalFacts(MaximalIdentity{Hash: "core"}, input, effect.reason)
	want := Blocker{Kind: BlockerNative, Package: "native", Symbol: "F", Detail: "body", Reason: "native body", Observable: true, Unrefinable: true}
	input[0] = externalEffect{}
	copyOfFacts := facts.Clone()
	if len(facts.Effects) != 1 || facts.Effects[0] != want {
		t.Fatalf("constructor retained caller storage or lost fields: %+v", facts.Effects)
	}
	identity := facts.Identity
	identity.Hash = "changed"
	closure := facts.Closure()
	closure.Unverifiable = false
	closure.Hash = "changed"
	for _, retained := range []MaximalFacts{facts, copyOfFacts} {
		if got := retained.Effects; len(got) != 1 || got[0] != want {
			t.Fatalf("caller changed retained facts: %+v", got)
		}
		if retained.Identity.Hash != "core" || !retained.Closure().Unverifiable {
			t.Fatal("caller changed identity or closure through a projection")
		}
	}
	facts.Effects[0] = Blocker{}
	facts.Identity.Hash = "changed"
	facts.Diagnostic = "changed"
	if copyOfFacts.Effects[0] != want || copyOfFacts.Identity.Hash != "core" || copyOfFacts.Diagnostic != effect.reason {
		t.Fatal("caller changed cloned facts")
	}
}

func TestMaximalFactsAvailabilityAndDiagnosticOnlyCandidate(t *testing.T) {
	for _, facts := range []MaximalFacts{{}, {Identity: MaximalIdentity{TestVariants: "partial"}}} {
		if got := facts.Closure(); !got.Unverifiable || got.Reason == "" {
			t.Fatalf("unavailable facts supplied a positive projection: %+v", got)
		}
	}
	// An unused plain import can be a diagnostic candidate without being a
	// blocker. Preserve that distinction rather than reading Reason as evidence.
	scan, err := maximalFileEffectsContent(true, "candidate.go", []byte("package p\nimport \"net\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.effects) != 0 || scan.preferred == "" {
		t.Fatalf("fixture did not produce a diagnostic-only candidate: %+v", scan)
	}
	identity := MaximalIdentity{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules"}
	facts := newMaximalFacts(identity, scan.effects, scan.preferred)
	want := Closure{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules", Reason: scan.preferred}
	if got := facts.Closure(); got != want || len(facts.Effects) != 0 {
		t.Fatalf("diagnostic-only projection = %+v, want %+v", got, want)
	}
}

func TestComputeMaximalFactsBatchPreservesCompleteScanAndProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the maximal fold")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/facts\n\ngo 1.26\n",
		"p.go": `package facts
import ("os"; "net"; "crypto/rand")
func Pure() {}
func Effects() { _ = os.Getenv("INPUT"); _, _ = net.Dial("tcp", "example.invalid:1"); _, _ = rand.Read(nil) }
`,
		"p_test.go": "package facts\nimport (\"testing\"; \"os\")\nfunc TestPure(t *testing.T) { Pure(); _ = os.Getenv(\"OTHER\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{{Package: "example.com/facts", Symbol: "Pure"}, {Package: "example.com/facts", Symbol: "TestPure"}}
	facts, sources, err := h.ComputeMaximalFactsBatch(append(slices.Clone(subjects), subjects[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != len(subjects) || len(sources) != len(subjects) {
		t.Fatalf("batch membership = %d facts, %d sources", len(facts), len(sources))
	}
	for _, subject := range subjects {
		got := facts[subject]
		if !got.Closure().Unverifiable {
			t.Fatalf("package-wide effects disappeared for %s", subject.Symbol)
		}
		for _, want := range []Blocker{
			{Kind: BlockerEnvironment, Package: "os", Symbol: "Getenv"},
			{Kind: BlockerNetwork, Package: "net", Symbol: "Dial"},
			{Kind: BlockerNative, Package: "crypto/rand", Symbol: "Read"},
		} {
			count := 0
			for _, blocker := range got.Effects {
				if blocker.Kind == want.Kind && blocker.Package == want.Package && blocker.Symbol == want.Symbol {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("%s: classification %+v has %d entries in %+v", subject.Symbol, want, count, got.Effects)
			}
		}
		if len(sources[subject]) != 2 {
			t.Fatalf("%s: incomplete source set: %v", subject.Symbol, sources[subject])
		}
	}
	if facts[subjects[0]].Identity.Hash == facts[subjects[1]].Identity.Hash ||
		!slices.Equal(facts[subjects[0]].Effects, facts[subjects[1]].Effects) {
		t.Fatal("subjects must retain distinct identities beside shared package-wide classifications")
	}
	legacy, legacySources, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if got := facts[subject].Closure(); got != legacy[subject] || !reflect.DeepEqual(sources[subject], legacySources[subject]) {
			t.Fatalf("%s: facts and legacy projections differ: %+v / %+v", subject.Symbol, got, legacy[subject])
		}
	}
	sources[subjects[0]][0] = "caller-owned"
	if sources[subjects[1]][0] == "caller-owned" {
		t.Fatal("subjects share mutable source slices")
	}
	// A later pass on the same hasher cannot rewrite the facts already returned.
	if !slices.Equal(facts[subjects[0]].Effects, facts[subjects[1]].Effects) {
		t.Fatal("later computation mutated retained facts")
	}
	facts[subjects[0]].Effects[0] = Blocker{}
	if facts[subjects[1]].Effects[0] == (Blocker{}) {
		t.Fatal("subjects share caller-mutable effect slices")
	}
}

func TestComputeMaximalFactsBatchCancellationReturnsNoFacts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &Hasher{ctx: ctx}
	facts, sources, err := h.ComputeMaximalFactsBatch([]Subject{{Package: "example.com/facts", Symbol: "F"}})
	if !errors.Is(err, context.Canceled) || facts != nil || sources != nil {
		t.Fatalf("cancelled batch = %v, %v, %v", facts, sources, err)
	}
}
