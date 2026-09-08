package gofresh

import (
	"strings"
	"testing"
)

// A dispatch of an exported method through the receiver's own closed
// interface field chains into every member's declaration: the field
// is closed when every store in the package carries a concrete
// in-package type, a constructor's parameter resolving through its
// direct call sites. Any store of another shape, an escape of the
// field's address, a variadic or escaped or exported constructor, or a
// member promoting the method leaves the dispatch an escape
// (REQ-closure-shared-dynamic-state).
func TestClosedInterfaceFieldDispatchChains(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture (measured heavy under the fast tier)")
	}
	const head = "package view\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.impl.String() }\n\n"
	cases := []struct {
		name, rest string
		valid      bool
	}{
		{"literal store of a concrete type", "var G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", true},
		{"positional literal store", "var G = &gen{lit(\"x\"), nil}\n\nfunc F() string { return G.String() }\n", true},
		{"constructor parameter resolved through its call sites", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", true},
		{"generic constructor", "type box[T any] struct{ v T }\n\nfunc (b box[T]) String() string { return \"box\" }\n\nfunc newGen2[T any](i impl, _ T) *gen { return &gen{impl: i} }\n\nvar G = newGen2[int](box[int]{}, 1)\n\nfunc F() string { return G.String() }\n", true},
		{"assignment store in init", "var G = &gen{impl: lit(\"x\")}\n\nfunc init() { G.impl = lit(\"y\") }\n\nfunc F() string { return G.String() }\n", true},
		{"a member writing a carrier", "type bad struct{ cb func() }\n\nfunc (b *bad) String() string {\n\tb.cb = nil\n\treturn \"bad\"\n}\n\nvar G = &gen{impl: lit(\"x\")}\n\nvar H = &gen{impl: &bad{}}\n\nfunc F() string { return G.String() }\n", false},
		{"store of an interface-typed call result", "func pick() impl { return lit(\"p\") }\n\nvar G = &gen{impl: pick()}\n\nfunc F() string { return G.String() }\n", false},
		{"constructor parameter fed an interface value", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nfunc pick() impl { return lit(\"p\") }\n\nvar G = newGen(pick())\n\nfunc F() string { return G.String() }\n", false},
		{"variadic constructor", "func newGen(is ...impl) *gen { return &gen{impl: is[0]} }\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"exported constructor", "func NewGen(i impl) *gen { return &gen{impl: i} }\n\nvar G = NewGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"escaped constructor value", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nvar mk = newGen\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"field address taken", "var G = &gen{impl: lit(\"x\")}\n\nvar p = &G.impl\n\nfunc F() string { return G.String() }\n", false},
		{"member promoting the method", "type base struct{}\n\nfunc (base) String() string { return \"b\" }\n\ntype promoted struct{ base }\n\nvar G = &gen{impl: promoted{}}\n\nfunc F() string { return G.String() }\n", false},
		{"conversion from an identical struct type", "type other struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc pick() impl { return lit(\"p\") }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc init() { *G = gen(other{impl: pick()}) }\n\nfunc F() string { return G.String() }\n", false},
		{"store through an embedded promotion", "type outer struct{ gen }\n\nfunc pick() impl { return lit(\"p\") }\n\nvar O = &outer{gen: gen{impl: lit(\"x\")}}\n\nfunc init() { O.impl = pick() }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", false},
		{"parameter reassigned in its body", "func pick() impl { return lit(\"p\") }\n\nfunc newGen(i impl) *gen {\n\tif i == nil {\n\t\ti = pick()\n\t}\n\treturn &gen{impl: i}\n}\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"fixed parameter of a variadic constructor", "func newGen(i impl, rest ...int) *gen { return &gen{impl: i} }\n\nvar G = newGen(lit(\"x\"), 1, 2)\n\nfunc F() string { return G.String() }\n", true},
		{"constructor never called", "func unused(i impl) *gen { return &gen{impl: i} }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", false},
		{"promoted store of a concrete type", "type outer struct{ gen }\n\nvar O = &outer{gen: gen{impl: lit(\"x\")}}\n\nfunc init() { O.impl = lit(\"y\") }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", true},
		{"field read into a local", "var G = &gen{impl: lit(\"x\")}\n\nfunc (g *gen) Via() string {\n\tv := g.impl\n\treturn v.String()\n}\n\nfunc F() string { return G.Via() }\n", false},
		{"method parameter store", "type factory struct{}\n\nfunc (factory) make(i impl) *gen { return &gen{impl: i} }\n\nvar G = factory{}.make(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
	}
	t.Run("a foreign concrete member opens the field", func(t *testing.T) {
		source := "package view\n\nimport \"time\"\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.impl.String() }\n\nvar G = &gen{impl: lit(\"x\")}\n\nvar H = &gen{impl: time.Month(1)}\n\nfunc F() string { return G.String() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a foreign member's method was chained", verdict)
		}
	})
	t.Run("an exported field is never closed", func(t *testing.T) {
		source := "package view\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\tImpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.Impl.String() }\n\nvar G = &gen{Impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — an exported field, writable from any importer, was closed", verdict)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeViewModule(t, head+tc.rest)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a closed field's exported dispatch broke the proof", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G")) {
				t.Fatalf("verdict = %+v, want the refusal naming G — an open field's dispatch was chained", verdict)
			}
		})
	}
}
