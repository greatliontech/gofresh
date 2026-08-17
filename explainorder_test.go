package gofresh

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The chain's link order is the derivation's own: the registration
// store first, then each unresolved dependency edge in walk order, then
// the innermost refusing expression — a permutation is a different
// derivation and must not pass (REQ-explain-chain's "names, in order").
func TestExplainChainLinkOrder(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc inner() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nfunc gen() map[string]handler {\n\treturn inner()\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm != "environment-audit" {
		t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
	}
	// Derivation order: the edge into gen precedes the edge into inner
	// (walk depth), and every edge precedes every refusal.
	genEdgeAt, innerEdgeAt, firstRefusalAt := -1, -1, -1
	lastEdgeAt := -1
	for i, l := range chain.Links {
		switch l.Kind {
		case "edge":
			lastEdgeAt = i
			if strings.HasSuffix(l.Callee, ".gen") && genEdgeAt == -1 {
				genEdgeAt = i
			}
			if strings.HasSuffix(l.Callee, ".inner") && innerEdgeAt == -1 {
				innerEdgeAt = i
			}
		case "refusal":
			if firstRefusalAt == -1 {
				firstRefusalAt = i
			}
		}
	}
	if genEdgeAt == -1 || innerEdgeAt == -1 || firstRefusalAt == -1 {
		t.Fatalf("chain lacks the expected links: %+v", chain)
	}
	if !(genEdgeAt < innerEdgeAt && lastEdgeAt < firstRefusalAt) {
		t.Fatalf("links out of derivation order (gen=%d inner=%d lastEdge=%d refusal=%d): %+v",
			genEdgeAt, innerEdgeAt, lastEdgeAt, firstRefusalAt, chain)
	}
}

// When a store link exists (a direct registration-literal store), it
// leads the chain: the registration store site is named first
// (REQ-explain-chain's "names, in order, the registration store site").
func TestExplainChainStoreLinkLeads(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": `package reg

type counter struct{ n int }

func (c *counter) Next(n int) int {
	c.n += n
	return c.n
}

type handler func(n int) int

var shared = &counter{}

var Registry = map[string]handler{"k": shared.Next}

func Count() int { return len(Registry) }
`,
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if len(chain.Links) == 0 || chain.Links[0].Kind != "store" {
		t.Fatalf("store link does not lead the chain: %+v", chain)
	}
}

// A refusal that is the fixed point of a dependency cycle has no single
// refusing expression: the chain ends at the edges — no refusal link,
// the deepest link an edge (REQ-explain-chain's edge termination).
func TestExplainChainCycleEndsAtEdges(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc gen(depth int) []handler {\n\tif depth > 0 {\n\t\treturn more(depth - 1)\n\t}\n\treturn nil\n}\n\nfunc more(depth int) []handler {\n\treturn gen(depth)\n}\n\nvar Registry = gen(3)\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm == "" {
		t.Fatal("cycle fixture did not refuse (chain empty) - the registration proved; the cycle clause's only pin is dead, strengthen the fixture")
	}
	for _, l := range chain.Links {
		if l.Kind == "refusal" {
			t.Fatalf("a cycle fixed point produced a refusal link: %+v", chain)
		}
	}
	if len(chain.Links) == 0 || chain.Links[len(chain.Links)-1].Kind != "edge" {
		t.Fatalf("cycle chain does not end at the edges: %+v", chain)
	}
}

// A replaced local dependency is IN the loaded scope: its syntax loads
// and the refusal lands inside it with a position — pinning that the
// edge-termination clause's "outside the loaded scope" never silently
// widens to swallow loadable dependencies. (The genuinely-outside
// shape — an export-data-only module-cache dependency — is not
// fixturable hermetically: a replaced dep loads with syntax and a
// parse-broken dep refuses the whole view.)
func TestExplainChainReplacedDepIsInScope(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/explain\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./depstub\n",
		"depstub/go.mod":    "module example.com/dep\n\ngo 1.26\n",
		"depstub/dep.go":    "package dep\n\ntype Handler func(n int) int\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc Make() []Handler {\n\tc := &counter{}\n\treturn []Handler{c.Next}\n}\n",
		"reg/reg.go":        "package reg\n\nimport \"example.com/dep\"\n\nfunc gen() []dep.Handler { return dep.Make() }\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm != "environment-audit" {
		t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
	}
	sawDepEdge, sawDepRefusal := false, false
	for _, l := range chain.Links {
		if l.Kind == "edge" && strings.Contains(l.Callee, "example.com/dep") {
			sawDepEdge = true
		}
		if l.Kind == "refusal" && strings.Contains(l.Package, "example.com/dep") {
			sawDepRefusal = true
			if !strings.Contains(l.Pos, "dep.go:") {
				t.Fatalf("in-scope dependency refusal lacks its position: %+v", l)
			}
		}
	}
	if !sawDepEdge || !sawDepRefusal {
		t.Fatalf("replaced dependency not treated as in-scope: %+v", chain)
	}
}

// A refusing function whose package is outside the loaded scope has no
// derivable refusing expression: the walk terminates at the edge with
// no refusal site (REQ-explain-chain's edge termination, outside-scope
// shape). The contrast arm pins that the termination comes from the
// scope boundary, not from a walk defect: the same dependency shape
// with the package loaded names its refusal site. Unit-level because
// the shape is not fixturable hermetically - a replaced dependency
// loads with syntax and a parse-broken dependency refuses the whole
// view (see TestExplainChainReplacedDepIsInScope).
func TestExplainEnvAuditOutsideScopeEndsAtEdges(t *testing.T) {
	const culprit = "example.com/reg.Registry"
	facts := map[string][]dynamicStateFact{
		"example.com/reg": {{
			EnvCarrying: []string{culprit},
			EnvCallUses: []string{culprit + "\x01example.com/dep\x00Make"},
		}},
	}
	edges, refusedFn, refusedPath := envAuditTrail(map[string][]*packages.Package{}, facts, culprit, "Registry")
	if len(edges) == 0 {
		t.Fatalf("outside-scope callee produced no edge: %+v", edges)
	}
	if refusedFn != "" || refusedPath != "" {
		t.Fatalf("outside-scope callee produced a refusal site: %q in %q", refusedFn, refusedPath)
	}
	edges, refusedFn, refusedPath = envAuditTrail(map[string][]*packages.Package{"example.com/dep": {{}}}, facts, culprit, "Registry")
	if len(edges) == 0 || refusedFn != "Make" || refusedPath != "example.com/dep" {
		t.Fatalf("in-scope contrast arm did not name the refusal site: edges=%+v fn=%q path=%q", edges, refusedFn, refusedPath)
	}
}

// The deferral arm's bound is real: a culprit with more deferral
// observations than the link cap truncates with the omission counted
// and the deepest deciding site kept (REQ-explain-bounded's deferral
// arm).
func TestExplainDeferralChainBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar sink []entry\n\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "func grab%d(es []entry) int {\n\tsink = es\n\treturn len(es)\n}\n\n", i)
	}
	b.WriteString("func Count() int {\n\tn := 0\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "\tn += grab%d(Registry)\n", i)
	}
	b.WriteString("\treturn n\n}\n")
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": b.String(),
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm == "" || len(chain.Links) == 0 {
		t.Fatalf("deferral fixture produced no chain: %+v", chain)
	}
	if len(chain.Links) > chainLinkCap {
		t.Fatalf("chain exceeds the link cap: %d > %d", len(chain.Links), chainLinkCap)
	}
	if chain.Omitted == 0 {
		t.Fatalf("30 deferral observations did not trip the bound: links=%d omitted=%d", len(chain.Links), chain.Omitted)
	}
	// The deepest deciding site survives the bound: naive tail
	// truncation would end at an interior grab; the protected last link
	// is the final deferral site (REQ-explain-bounded's deepest-kept).
	if last := chain.Links[len(chain.Links)-1]; !strings.Contains(last.Callee, "grab29") {
		t.Fatalf("deepest deciding site did not survive the bound: %+v", last)
	}
}
