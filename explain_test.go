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
			"go.mod":     goMod,
			"law/law.go": "package law\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype Handler func(n int) int\n\nfunc Build() []Handler {\n\tc := &counter{}\n\treturn []Handler{c.Next}\n}\n",
			"reg/reg.go": "package reg\n\nimport \"example.com/explain/law\"\n\nfunc gen() []law.Handler { return law.Build() }\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
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
			"write or capture broke the binding":                    true,
			"a binding source refused":                              true,
			"a stored value refused":                                true,
			"callee outside the audited set and dependency channel": true,
			"a literal element refused":                             true,
			"an unadmitted derivation shape":                        true,
			"an unrecognized return shape":                          true,
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
func TestExplainDeferralChains(t *testing.T) {
	goMod := "module example.com/explain\n\ngo 1.26\n"

	t.Run("unproven argument deferral names the callee parameter", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar sink []entry\n\nfunc grab(es []entry) int {\n\tsink = es\n\treturn len(es)\n}\n\nfunc Count() int { return grab(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "a deferred argument's parameter unproven" {
			t.Fatalf("clause = %q - the deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the unproven parameter named", link.Callee)
		}
		if link.Pos == "" || !strings.Contains(link.Pos, "reg.go") {
			t.Fatalf("pos = %q, want the deferring use site", link.Pos)
		}
	})
	t.Run("unproven method deferral is a mutation chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nfunc Count() int { return Registry.Bump() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want a mutation deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "a deferred method use unproven" {
			t.Fatalf("clause = %q - the deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "counter.Bump") {
			t.Fatalf("callee = %q, want the unproven method named", link.Callee)
		}
	})
	t.Run("refused field position names the failing registrant", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: grab}}\n}\n\nfunc Count() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "the registered population refused the field position" {
			t.Fatalf("clause = %q - the field deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "Build parameter 0") || !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the field position and failing registrant named", link.Callee)
		}
	})
	t.Run("object-closed sentinel yields no chain despite unproven deferrals", func(t *testing.T) {
		// The verdict discharges escapes of an opaque interface variable
		// (audited immutable construction); the chain must apply the
		// same proof state - a Valid verdict has no chain.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"boom\")\n\nvar sink error\n\nfunc grab(e error) error {\n\tsink = e\n\treturn e\n}\n\nfunc Count() int {\n\tif grab(ErrX) != nil {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "ErrX")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - an opacity-discharged sentinel earned a chain", chain)
		}
	})
	t.Run("opacity discharge covers direct escape sites", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"boom\")\n\nvar sink []error\n\nfunc Count() int {\n\tsink = append(sink, ErrX)\n\treturn len(sink)\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "ErrX")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - an opacity-discharged direct escape earned a chain", chain)
		}
	})
	t.Run("mixed unproven deferrals rank mutation first", func(t *testing.T) {
		// A carrier with both an unproven argument deferral and an
		// unproven method deferral chains as mutation - the arm the
		// verdict ranking would name.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nvar sink *counter\n\nfunc grab(c *counter) int {\n\tsink = c\n\treturn c.n\n}\n\nfunc Count() int { return Registry.Bump() + grab(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want a mutation chain for mixed deferrals", chain)
		}
	})
	t.Run("direct escape with unproven method deferral ranks mutation", func(t *testing.T) {
		// The verdict reason would say "is mutated" - mutation outranks
		// escape - so the chain's arm must match, the method deferral
		// leading the links.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nvar sink []*counter\n\nfunc Count() int {\n\tsink = append(sink, Registry)\n\treturn Registry.Bump()\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) < 2 {
			t.Fatalf("chain = %+v, want a mutation-armed chain carrying both the deferral and the escape site", chain)
		}
		if chain.Links[0].Clause != "a deferred method use unproven" {
			t.Fatalf("links[0] = %+v, want the mutation-kind deferral leading", chain.Links[0])
		}
	})
	t.Run("refused element position names the owner and registrant", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nvar Legs = map[string]func(v *inv) int{\"w\": grab}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Count() int {\n\treturn Legs[\"w\"](Shared)\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Shared")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "the element population refused the position" {
			t.Fatalf("clause = %q - the element deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "example.com/explain/reg.Legs element parameter 0") || !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the owner and failing registrant named", link.Callee)
		}
	})
	t.Run("resolved deferral contributes no chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc width(es []entry) int { return len(es) }\n\nfunc Count() int { return width(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - a proven deferral earned a chain", chain)
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
