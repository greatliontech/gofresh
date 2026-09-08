package gofresh

import (
	"strings"
	"testing"
)

// The once-filled memo keeps the receiver-effect proof: a data-plane
// field written directly in the literal a receiver-rooted sync.Once's
// Do runs fills once per receiver, so a call on the package-level
// carrier marks nothing. Every other receiver write — a counter, a
// data slice element, a fill through a bound method or a local Once, a
// carrier field inside the Do — keeps the mark. A dispatch of an
// unexported interface method chains into every in-package declaration
// of that name; an exported method's dispatch chains through the
// receiver's closed interface field (REQ-closure-shared-dynamic-state).
func TestOnceFilledMemoKeepsTheProof(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture (measured heavy under the fast tier)")
	}
	const gen = "package view\n\nimport \"sync\"\n\ntype impl interface {\n\tString() string\n\tvalue() int\n\tslice() []int\n}\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\nfunc (l lit) value() int { return len(l) }\n\nfunc (l lit) slice() []int { return nil }\n\ntype gen struct {\n\timpl  impl\n\tonce  sync.Once\n\tstr   string\n\tn     int\n\tnames []string\n\tfns   []func() int\n\tcb    func()\n\tm     map[string]int\n\thooks map[string]func()\n}\n\n"
	cases := []struct {
		name, methods, subject string
		valid                  bool
	}{
		{"once-filled data field", "func (g *gen) Value() int {\n\tg.once.Do(func() { g.n = g.impl.value() })\n\treturn g.n\n}\n", "func F() int { return G.Value() }\n", true},
		// The exported dispatch chains through the closed field: the
		// fixture stores one concrete type into impl.
		{"exported dispatch through the closed field", "func (g *gen) String() string { return g.impl.String() }\n", "func F() string { return G.String() }\n", true},
		{"once-filled counter", "func (g *gen) Count() int {\n\tg.once.Do(func() { g.n++ })\n\treturn g.n\n}\n", "func F() int { return G.Count() }\n", true},
		{"once-filled data slice element", "func (g *gen) Name() string {\n\tg.once.Do(func() { g.names[0] = \"x\" })\n\treturn g.names[0]\n}\n", "func F() string { return G.Name() }\n", true},
		{"counter outside the once", "func (g *gen) Next() int {\n\tg.n++\n\treturn g.n\n}\n", "func F() int { return G.Next() }\n", false},
		{"data slice element outside the once", "func (g *gen) Set() string {\n\tg.names[0] = \"x\"\n\treturn g.names[0]\n}\n", "func F() string { return G.Set() }\n", false},
		{"once-filled carrier field", "func (g *gen) Swap() int {\n\tg.once.Do(func() { g.impl = lit(\"y\") })\n\treturn 1\n}\n", "func F() int { return G.Swap() }\n", false},
		{"once fill through a bound method", "func (g *gen) fill() { g.str = \"f\" }\n\nfunc (g *gen) Bound() string {\n\tg.once.Do(g.fill)\n\treturn g.str\n}\n", "func F() string { return G.Bound() }\n", false},
		{"fill under a local once", "func (g *gen) Local() string {\n\tvar once sync.Once\n\tonce.Do(func() { g.str = \"l\" })\n\treturn g.str\n}\n", "func F() string { return G.Local() }\n", false},
		{"nested fill inside the once", "func (g *gen) Nested() string {\n\tg.once.Do(func() {\n\t\tif g.str == \"\" {\n\t\t\tg.str = \"n\"\n\t\t}\n\t})\n\treturn g.str\n}\n", "func F() string { return G.Nested() }\n", false},
		{"unexported dispatch", "func (g *gen) Value() int { return g.impl.value() }\n", "func F() int { return G.Value() }\n", true},
		// The result of an unexported dispatch handing out mutable
		// reach escapes outside a governed bind, as a sibling call's does.
		{"unexported dispatch result escapes", "func (g *gen) Slice() int {\n\tg.impl.slice()\n\treturn 1\n}\n", "func F() int { return G.Slice() }\n", false},
		{"interface field write", "func (g *gen) Reset() int {\n\tg.impl = lit(\"y\")\n\treturn 1\n}\n", "func F() int { return G.Reset() }\n", false},
		{"func field write", "func (g *gen) Hook() int {\n\tg.cb = func() {}\n\treturn 1\n}\n", "func F() int { return G.Hook() }\n", false},
		{"func slice element write", "func (g *gen) Slot() int {\n\tg.fns[0] = nil\n\treturn 1\n}\n", "func F() int { return G.Slot() }\n", false},
		{"whole receiver write", "func (g *gen) Zero() int {\n\t*g = gen{}\n\treturn 1\n}\n", "func F() int { return G.Zero() }\n", false},
		// A consuming read allows only its own node: the carrier
		// write after it is refused at its own.
		{"carrier write after a consuming read", "func (g *gen) Both() int {\n\tn := len(g.names)\n\tg.impl = lit(\"y\")\n\treturn n\n}\n", "func F() int { return G.Both() }\n", false},
		// A fill through a tainted alias is judged by the element it
		// writes: data admits, a carrier refuses — the alias's read was
		// consumed, so the element type is the fill's only guard.
		{"once fill through a data alias", "func (g *gen) Alias() int {\n\tg.once.Do(func() {\n\t\tm := g.m\n\t\tm[\"k\"] = 1\n\t})\n\treturn len(g.m)\n}\n", "func F() int { return G.Alias() }\n", true},
		{"once fill through a carrier alias", "func (g *gen) Hooks() int {\n\tg.once.Do(func() {\n\t\th := g.hooks\n\t\th[\"k\"] = func() {}\n\t})\n\treturn len(g.hooks)\n}\n", "func F() int { return G.Hooks() }\n", false},
		// One Once, two literals: the field holds whichever a subject's
		// order fired first — no fill for that Once anywhere.
		{"two Do sites on one once", "func (g *gen) First() string {\n\tg.once.Do(func() { g.str = \"a\" })\n\treturn g.str\n}\n\nfunc (g *gen) Second() string {\n\tg.once.Do(func() { g.str = \"b\" })\n\treturn g.str\n}\n", "func F() string { return G.First() }\n", false},
		// A plain function can fire the Once too: a second site.
		{"Do site outside any method", "func (g *gen) Fill() string {\n\tg.once.Do(func() { g.str = \"a\" })\n\treturn g.str\n}\n\nfunc prime() { G.once.Do(func() {}) }\n", "func F() string {\n\tprime()\n\treturn G.Fill()\n}\n", false},
		// A fill that rewrites the Once re-arms it: refused.
		{"fill re-arming the once", "func (g *gen) Rearm() string {\n\tg.once.Do(func() {\n\t\tg.str = \"r\"\n\t\tg.once = sync.Once{}\n\t})\n\treturn g.str\n}\n", "func F() string { return G.Rearm() }\n", false},
		// A parenthesized target is no selection: refused even in the once.
		{"parenthesized once fill", "func (g *gen) Paren() string {\n\tg.once.Do(func() { (g.str) = \"p\" })\n\treturn g.str\n}\n", "func F() string { return G.Paren() }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeViewModule(t, gen+tc.methods+"\nvar G = &gen{impl: lit(\"x\"), names: []string{\"a\"}, fns: []func() int{nil}, m: map[string]int{}, hooks: map[string]func(){}}\n\n"+tc.subject)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a once-filled memo or an unexported dispatch broke the proof", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G")) {
				t.Fatalf("verdict = %+v, want the refusal naming G — a receiver write outside the once-filled memo was proven read-only", verdict)
			}
		})
	}
	t.Run("composite implementer's carrier-writing declaration is chained", func(t *testing.T) {
		// An unnamed composite promotes the unexported method from an
		// in-package declaration: that declaration is a chain target
		// whatever type promotes it.
		source := "package view\n\ntype impl interface {\n\tString() string\n\tvalue() int\n}\n\ntype a struct{ cb func() }\n\nfunc (x *a) value() int {\n\tx.cb = nil\n\treturn 1\n}\n\ntype b struct{}\n\nfunc (b) String() string { return \"b\" }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: struct {\n\t*a\n\tb\n}{a: &a{}}}\n\nfunc F() int { return G.Value() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a composite's promoted carrier write was not chained", verdict)
		}
	})
	t.Run("promoted implementer's clean declaration is chained", func(t *testing.T) {
		source := "package view\n\ntype impl interface {\n\tString() string\n\tvalue() int\n}\n\ntype base struct{}\n\nfunc (base) String() string { return \"b\" }\n\nfunc (base) value() int { return 1 }\n\ntype promoted struct{ base }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: promoted{}}\n\nfunc F() int { return G.Value() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid — the promoted declaration is base's own, proven", verdict)
		}
	})
	t.Run("a shared, reachable, or copied once hosts no fill", func(t *testing.T) {
		for name, source := range map[string]string{
			"pointer once":               "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonce *sync.Once\n\tcb   func()\n\tstr  string\n}\n\nfunc (g *gen) Fill() string {\n\tg.once.Do(func() { g.str = \"p\" })\n\treturn g.str\n}\n\nvar G = &gen{once: new(sync.Once)}\n\nfunc F() string { return G.Fill() }\n",
			"exported once":              "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tOnce sync.Once\n\tcb   func()\n\tstr  string\n}\n\nfunc (g *gen) Fill() string {\n\tg.Once.Do(func() { g.str = \"e\" })\n\treturn g.str\n}\n\nvar G = &gen{}\n\nfunc F() string { return G.Fill() }\n",
			"once behind a pointer step": "package view\n\nimport \"sync\"\n\ntype inner struct{ once sync.Once }\n\ntype gen struct {\n\tp   *inner\n\tcb  func()\n\tstr string\n}\n\nfunc (g *gen) Fill() string {\n\tg.p.once.Do(func() { g.str = \"s\" })\n\treturn g.str\n}\n\nvar shared = &inner{}\n\nvar G = &gen{p: shared}\n\nvar H = &gen{p: shared}\n\nfunc F() string { return G.Fill() + H.Fill() }\n",
			"two onces on one receiver":  "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonceA, onceB sync.Once\n\tcb           func()\n\ta, b         int\n}\n\nfunc (g *gen) A() int {\n\tg.onceA.Do(func() { g.a = 1 })\n\treturn g.a\n}\n\nfunc (g *gen) B() int {\n\tg.onceB.Do(func() { g.b = g.a })\n\treturn g.b\n}\n\nvar G = &gen{}\n\nfunc F() int { return G.B() }\n",
			"value receiver":             "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonce sync.Once\n\tcb   func()\n\tm    map[string]int\n}\n\nfunc (g gen) Fill() int {\n\tg.once.Do(func() { g.m[\"k\"] = len(g.m) })\n\treturn g.m[\"k\"]\n}\n\nvar G = &gen{m: map[string]int{}}\n\nfunc F() int { return G.Fill() }\n",
			"embedded once":              "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tsync.Once\n\tcb  func()\n\tstr string\n}\n\nfunc (g *gen) Fill() string {\n\tg.Do(func() { g.str = \"m\" })\n\treturn g.str\n}\n\nvar G = &gen{}\n\nfunc F() string { return G.Fill() }\n",
		} {
			t.Run(name, func(t *testing.T) {
				dir := writeViewModule(t, source)
				verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
				if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
					t.Fatalf("verdict = %+v, want the refusal naming G — a shared or reachable Once hosted a fill", verdict)
				}
			})
		}
	})
	t.Run("a test-file declaration installed at init is chained", func(t *testing.T) {
		// The proof is enumerated over the variant's own declarations,
		// and the view's cone takes the test variant alone when one
		// exists: the plain compilation's proof, blind to the test-file
		// fake, is never served for the test binary that links it.
		files := map[string]string{
			"go.mod":            "module example.com/xesc\n\ngo 1.26\n",
			"view/view.go":      "package view\n\ntype impl interface{ value() int }\n\ntype lit struct{}\n\nfunc (lit) value() int { return 1 }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: lit{}}\n\nfunc F() int { return G.Value() }\n",
			"view/view_test.go": "package view\n\ntype fake struct{ cb func() }\n\nfunc (f *fake) value() int {\n\tf.cb = nil\n\treturn 2\n}\n\nfunc init() { G.impl = &fake{} }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/xesc/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — the plain compilation's proof served for the test binary", verdict)
		}
	})
	t.Run("unexported method nobody declares keeps the escape", func(t *testing.T) {
		source := "package view\n\ntype impl interface{ other() int }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Other() int {\n\tif g.impl == nil {\n\t\treturn 0\n\t}\n\treturn g.impl.other()\n}\n\nvar G = &gen{}\n\nfunc F() int { return G.Other() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a dispatch with no declaration was chained into nothing", verdict)
		}
	})
}
