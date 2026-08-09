package gofresh

import (
	"context"
	"strings"
	"testing"
)

// explainView builds a view over the module tree and returns the
// chain for the named culprit.
func explainView(t *testing.T, dir, pkgPath, varName string) Chain {
	t.Helper()
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{{Package: pkgPath, Symbol: "Count"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := view.ExplainDynamicState(context.Background(), pkgPath, varName)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

//gofresh:pure
func TestExplainChains(t *testing.T) {
	goMod := "module example.com/explain\n\ngo 1.26\n"

	t.Run("environment-audit chain reaches the refusing expression", func(t *testing.T) {
		// The registration stores an unjudged method value through a
		// constructor: the chain must carry the store, the dependency
		// edge into the constructor, and the innermost refusal with
		// its position.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q, want environment-audit; chain %+v", chain.Arm, chain)
		}
		var haveEdge, haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Callee, "gen") {
				haveEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "gen" {
				haveRefusal = true
				if !strings.Contains(l.Pos, "reg.go:") {
					t.Fatalf("refusal position missing: %+v", l)
				}
				if l.Clause == "" {
					t.Fatalf("refusal clause empty: %+v", l)
				}
			}
		}
		if !haveEdge || !haveRefusal {
			t.Fatalf("chain lacks edge or refusal: %+v", chain)
		}
	})
	t.Run("cross-package edge chain names the foreign refusal", func(t *testing.T) {
		files := map[string]string{
			"go.mod":      goMod,
			"law/law.go":  "package law\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype Handler func(n int) int\n\nfunc Build() []Handler {\n\tc := &counter{}\n\treturn []Handler{c.Next}\n}\n",
			"reg/reg.go":  "package reg\n\nimport \"example.com/explain/law\"\n\nfunc gen() []law.Handler { return law.Build() }\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var crossEdge, foreignRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Callee, "law.Build") {
				crossEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "Build" && strings.Contains(l.Package, "law") {
				foreignRefusal = true
			}
		}
		if !crossEdge || !foreignRefusal {
			t.Fatalf("cross-package chain incomplete: %+v", chain)
		}
	})
	t.Run("direct registration store carries the store link", func(t *testing.T) {
		// A carrying value stored at the registration itself (no
		// constructor in between): the chain's store link names the
		// site.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nvar shared = &counter{}\n\nvar Registry = map[string]handler{\"k\": shared.Next}\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var haveStore bool
		for _, l := range chain.Links {
			if l.Kind == "store" && strings.Contains(l.Pos, "reg.go:") {
				haveStore = true
			}
		}
		if !haveStore {
			t.Fatalf("chain lacks a positioned store link: %+v", chain)
		}
	})
	t.Run("mutation chain names the deciding site", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]handler{\"d\": double}\n\nfunc Add(h handler) { Registry[\"x\"] = h }\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		if len(chain.Links) == 0 || !strings.Contains(chain.Links[0].Pos, "reg.go:") {
			t.Fatalf("mutation chain lacks a positioned site: %+v", chain)
		}
	})
	t.Run("a proven constructor yields an empty chain", func(t *testing.T) {
		// The registration's every dependency edge resolves: no chain,
		// even though a dependency edge exists.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() map[string]handler {\n\treturn map[string]handler{\"d\": double}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("expected empty chain for a proven constructor, got %+v", chain)
		}
	})
	t.Run("a test-file culprit chains from the test variant", func(t *testing.T) {
		// The verdict's scope includes test variants; explain must see
		// the same declarations.
		files := map[string]string{
			"go.mod":          goMod,
			"reg/reg.go":      "package reg\n\nfunc Count() int { return 0 }\n",
			"reg/reg_test.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Hooks = map[string]handler{\"d\": double}\n\nfunc install(h handler) { Hooks[\"x\"] = h }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Hooks")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("test-file culprit not chained: %+v", chain)
		}
		if !strings.Contains(chain.Links[0].Pos, "reg_test.go:") {
			t.Fatalf("mutation site not in the test file: %+v", chain.Links[0])
		}
	})
	t.Run("an importer's mutation chains against the owning package", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\nfunc Install(h reg.Handler) { reg.Registry[\"x\"] = h }\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		engine, err := New(WithDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/explain/user", Symbol: "F"}}, dir)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry")
		if err != nil {
			t.Fatal(err)
		}
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("importer mutation not chained: %+v", chain)
		}
		if !strings.Contains(chain.Links[0].Pos, "user.go:") {
			t.Fatalf("mutation site not in the importing package: %+v", chain.Links[0])
		}
	})
	t.Run("refusal clauses stay in the spec vocabulary", func(t *testing.T) {
		// REQ-explain-vocabulary: every emitted clause is one of the
		// spec's enumerated families.
		allowed := map[string]bool{
			"write or capture broke the binding":                 true,
			"a binding source refused":                           true,
			"a stored value refused":                             true,
			"callee outside the audited set and dependency channel": true,
			"a literal element refused":                          true,
			"an unadmitted derivation shape":                     true,
			"an unrecognized return shape":                       true,
		}
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		var sawRefusal bool
		for _, l := range chain.Links {
			if l.Kind != "refusal" {
				continue
			}
			sawRefusal = true
			if !allowed[l.Clause] {
				t.Fatalf("clause %q outside the spec vocabulary", l.Clause)
			}
		}
		if !sawRefusal {
			t.Fatalf("no refusal link to check: %+v", chain)
		}
	})
	t.Run("a foreign direct registration chains with its store", func(t *testing.T) {
		// An importing package's init stores a method value straight
		// into the culprit: the store link lands from the foreign
		// package's analysis.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc init() {\n\tc := &counter{}\n\treg.Registry[\"k\"] = c.Next\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		engine, err := New(WithDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/explain/user", Symbol: "F"}}, dir)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry")
		if err != nil {
			t.Fatal(err)
		}
		if chain.Arm != "environment-audit" || len(chain.Links) == 0 {
			t.Fatalf("foreign registration not chained: %+v", chain)
		}
		var haveForeign bool
		for _, l := range chain.Links {
			if l.Kind == "store" && strings.Contains(l.Package, "user") && strings.Contains(l.Pos, "user.go:") {
				haveForeign = true
			}
		}
		if !haveForeign {
			t.Fatalf("foreign store link missing: %+v", chain)
		}
	})
	t.Run("a foreign constructor registration chains its edge", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc mk() reg.Handler {\n\tc := &counter{}\n\treturn c.Next\n}\n\nfunc init() {\n\treg.Registry[\"k\"] = mk()\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		engine, err := New(WithDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/explain/user", Symbol: "F"}}, dir)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry")
		if err != nil {
			t.Fatal(err)
		}
		var haveEdge, haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Package, "user") && strings.Contains(l.Callee, "mk") {
				haveEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "mk" {
				haveRefusal = true
			}
		}
		if !haveEdge || !haveRefusal {
			t.Fatalf("foreign constructor chain incomplete: %+v", chain)
		}
	})
	t.Run("a test-file constructor refusal keeps its link", func(t *testing.T) {
		// The refused function exists only in the test variant; the
		// refusal re-derivation must run that variant.
		files := map[string]string{
			"go.mod":          goMod,
			"reg/reg.go":      "package reg\n\nfunc Count() int { return 0 }\n",
			"reg/reg_test.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc mk() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Hooks = mk()\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Hooks")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "refusal" && l.Symbol == "mk" && strings.Contains(l.Pos, "reg_test.go:") {
				haveRefusal = true
			}
		}
		if !haveRefusal {
			t.Fatalf("test-variant refusal link missing: %+v", chain)
		}
	})
	t.Run("a non-culprit yields an empty chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("expected empty chain for a non-culprit, got %+v", chain)
		}
	})
}

//gofresh:pure
func TestExplainChainBound(t *testing.T) {
	// The production shape: stores and edges first, refusals appended
	// innermost-first, the protected index at the first refusal.
	long := Chain{Arm: "environment-audit"}
	for i := 0; i < chainLinkCap+6; i++ {
		long.Links = append(long.Links, ChainLink{Kind: "edge", Symbol: "fn"})
	}
	protect := len(long.Links)
	long.Links = append(long.Links,
		ChainLink{Kind: "refusal", Symbol: "innermost"},
		ChainLink{Kind: "refusal", Symbol: "outer"},
	)
	got := boundChain(long, protect)
	if len(got.Links) != chainLinkCap {
		t.Fatalf("bound kept %d links, want %d", len(got.Links), chainLinkCap)
	}
	if got.Omitted != len(long.Links)-chainLinkCap {
		t.Fatalf("omitted = %d, want %d", got.Omitted, len(long.Links)-chainLinkCap)
	}
	if got.Links[len(got.Links)-1].Symbol != "innermost" {
		t.Fatalf("the innermost refusal was dropped: %+v", got.Links[len(got.Links)-1])
	}
	// A protected link already inside the kept head keeps the chain's
	// tail instead.
	short := Chain{Arm: "mutation"}
	for i := 0; i < chainLinkCap+3; i++ {
		short.Links = append(short.Links, ChainLink{Kind: "culprit", Symbol: "s"})
	}
	short.Links[len(short.Links)-1].Symbol = "tail"
	got = boundChain(short, 0)
	if got.Links[len(got.Links)-1].Symbol != "tail" {
		t.Fatalf("head-protected bound dropped the tail: %+v", got.Links[len(got.Links)-1])
	}
}
