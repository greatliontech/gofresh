package gofresh

import (
	"strings"
	"testing"
)

// A data memo — an unexported by-value sync.Map whose every use is a
// Load, Store, or LoadOrStore with carrier-free key and value static
// types — holds no dynamic carrier and marks nothing; an
// interface-typed key parameter resolves through its direct call
// sites. Any other use, a carrier stored, an exported or pointer
// variable keeps the mark (REQ-closure-shared-dynamic-state).
func TestDataMemoMarksNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture (measured heavy under the fast tier)")
	}
	const head = "package view\n\nimport \"sync\"\n\nvar memo sync.Map\n\n"
	cases := []struct {
		name, rest string
		valid      bool
	}{
		{"load and store of data", "func expand(key string) []rune {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.([]rune)\n\t}\n\tr := []rune(key)\n\tmemo.Store(key, r)\n\treturn r\n}\n\nfunc F() int { return len(expand(\"ab\")) }\n", true},
		{"load or store of data", "func name(key int) string {\n\tv, _ := memo.LoadOrStore(key, \"n\")\n\treturn v.(string)\n}\n\nfunc F() string { return name(1) }\n", true},
		{"interface-typed key parameter resolved through its call sites", "func expand(key any) []rune {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.([]rune)\n\t}\n\tr := []rune(\"x\")\n\tmemo.Store(key, r)\n\treturn r\n}\n\nfunc F() int { return len(expand(\"ab\")) + len(expand(7)) }\n", true},
		{"a carrier value stored", "func hook(key string) func() {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.(func())\n\t}\n\tf := func() {}\n\tmemo.Store(key, f)\n\treturn f\n}\n\nfunc F() int {\n\thook(\"k\")\n\treturn 1\n}\n", false},
		{"a carrier key parameter fed a carrier", "func expand(key any) int {\n\tmemo.Store(key, 1)\n\treturn 1\n}\n\nfunc F() int { return expand(func() {}) }\n", false},
		{"range use", "func F() int {\n\tn := 0\n\tmemo.Range(func(k, v any) bool {\n\t\tn++\n\t\treturn true\n\t})\n\treturn n\n}\n", false},
		{"delete use", "func F() int {\n\tmemo.Store(\"k\", 1)\n\tmemo.Delete(\"k\")\n\treturn 1\n}\n", false},
		{"variable passed to a helper", "func use(m *sync.Map) {}\n\nfunc F() int {\n\tuse(&memo)\n\tmemo.Store(\"k\", 1)\n\treturn 1\n}\n", false},
		{"variadic value parameter", "func h() int { return 1 }\n\nfunc fill(key string, vals ...any) { memo.Store(key, vals) }\n\nfunc F() int {\n\tfill(\"k\", \"a\", h)\n\treturn 1\n}\n", false},
		{"parenthesized receiver", "func h() int { return 1 }\n\nfunc F() int {\n\t(memo).Store(\"k\", h)\n\treturn 1\n}\n", false},
		{"init-flow alias fill", "func h() int { return 1 }\n\nfunc register(m *sync.Map) { m.Store(\"k\", h) }\n\nfunc init() { register(&memo) }\n\nfunc F() int {\n\tv, _ := memo.Load(\"k\")\n\tif v == nil {\n\t\treturn 0\n\t}\n\treturn 1\n}\n", false},
		{"fixed parameter of a variadic function", "func fill(key any, rest ...int) int {\n\tmemo.Store(key, len(rest))\n\treturn 1\n}\n\nfunc F() int { return fill(\"k\", 1, 2) }\n", true},
		{"key parameter reassigned", "func expand(key any) int {\n\tkey = func() {}\n\tmemo.Store(key, 1)\n\treturn 1\n}\n\nfunc F() int { return expand(\"k\") }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeViewModule(t, head+tc.rest)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a data memo marked", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.memo")) {
				t.Fatalf("verdict = %+v, want the refusal naming memo — an open sync.Map was judged a data memo", verdict)
			}
		})
	}
	for name, source := range map[string]string{
		"exported variable": "package view\n\nimport \"sync\"\n\nvar Memo sync.Map\n\nfunc F() int {\n\tMemo.Store(\"k\", 1)\n\treturn 1\n}\n",
		"pointer variable":  "package view\n\nimport \"sync\"\n\nvar memo = &sync.Map{}\n\nfunc F() int {\n\tmemo.Store(\"k\", 1)\n\treturn 1\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.") {
				t.Fatalf("verdict = %+v, want a refusal — a reachable or shared sync.Map was judged a data memo", verdict)
			}
		})
	}
}
