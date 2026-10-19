package bitrelation

import (
	"context"
	"fmt"
)

// RuleModel identifies the scalar language and independently checked calculus.
// Its dependencies are process-local; there is deliberately no persisted format.
const RuleModel = "gofresh/scalar-bitrelation@3"

// Code distinguishes absence of proof from a malformed proposal or cancellation.
type Code string

const (
	Malformed   Code = "malformed"
	Budget      Code = "budget"
	Cancelled   Code = "cancelled"
	Unsupported Code = "unsupported"
	Endpoint    Code = "endpoint"
	InvalidRule Code = "invalid-rule"
)

// Refusal describes a failed obligation. No refusal carries a partial witness.
type Refusal struct {
	Code   Code
	Detail string
	Step   int
	Rule   Rule
	Cause  error
}

func (r *Refusal) Error() string               { return fmt.Sprintf("bitrelation %s: %s", r.Code, r.Detail) }
func (r *Refusal) Unwrap() error               { return r.Cause }
func refuse(code Code, detail string) *Refusal { return &Refusal{Code: code, Detail: detail, Step: -1} }

// Limits bound unique graph nodes, certificate steps, and traversal/search work.
// Zero fields select defaults; negative fields refuse. Work counts graph visits,
// structural comparisons and proposer operations, not elapsed time.
type Limits struct{ Nodes, Steps, Work int }

// DefaultLimits is a finite, deliberately small proof budget.
func DefaultLimits() Limits { return Limits{Nodes: 4096, Steps: 16384, Work: 1_000_000} }

type meter struct {
	ctx    context.Context
	limits Limits
	work   int
}

// normalizeLimits performs no caller callbacks, so ownership boundaries can
// reject oversized input before allocating its private snapshot.
func normalizeLimits(l Limits) (Limits, error) {
	d := DefaultLimits()
	if l.Nodes == 0 {
		l.Nodes = d.Nodes
	}
	if l.Steps == 0 {
		l.Steps = d.Steps
	}
	if l.Work == 0 {
		l.Work = d.Work
	}
	if l.Nodes < 0 || l.Steps < 0 || l.Work < 0 {
		return Limits{}, refuse(Malformed, "invalid limits")
	}
	return l, nil
}

func newMeter(ctx context.Context, l Limits) (*meter, error) {
	l, err := normalizeLimits(l)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, refuse(Malformed, "invalid context")
	}
	m := &meter{ctx: ctx, limits: l}
	return m, m.tick()
}
func (m *meter) tick() error {
	if err := m.ctx.Err(); err != nil {
		return &Refusal{Code: Cancelled, Detail: "context cancelled", Step: -1, Cause: err}
	}
	if m.work >= m.limits.Work {
		return refuse(Budget, "work budget")
	}
	m.work++
	return nil
}

type pair struct{ a, b *node }
type equality struct {
	m    *meter
	seen map[pair]bool
}

func (e *equality) same(a, b *node) (bool, error) {
	if err := e.m.tick(); err != nil {
		return false, err
	}
	if a == b {
		return a != nil, nil
	}
	if a == nil || b == nil {
		return false, nil
	}
	if e.seen[pair{a, b}] {
		return true, nil
	}
	if !sameHead(a, b) {
		return false, nil
	}
	for i := 0; i < int(a.arity); i++ {
		ok, err := e.same(a.args[i], b.args[i])
		if err != nil || !ok {
			return false, err
		}
	}
	e.seen[pair{a, b}] = true
	return true, nil
}
func sameHead(a, b *node) bool {
	return a.op == b.op && a.sort == b.sort && a.imm == b.imm && a.scope == b.scope && a.scratch == b.scratch && a.arity == b.arity
}

// graph visits immutable DAGs iteratively. The fixed depth ceiling bounds the
// recursive local proof search/comparison even with caller-enlarged node limits.
func graph(m *meter, roots []Term) error {
	type visit struct {
		n     *node
		depth int
	}
	seen := make(map[*node]int)
	stack := make([]visit, 0, len(roots))
	for _, r := range roots {
		if !r.Valid() {
			return refuse(Malformed, "invalid term")
		}
		stack = append(stack, visit{r.n, 1})
	}
	for len(stack) > 0 {
		if err := m.tick(); err != nil {
			return err
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if v.depth > 512 {
			return refuse(Budget, "expression depth budget")
		}
		if seen[v.n] >= v.depth {
			continue
		}
		seen[v.n] = v.depth
		if len(seen) > m.limits.Nodes {
			return refuse(Budget, "graph node budget")
		}
		for i := 0; i < int(v.n.arity); i++ {
			stack = append(stack, visit{v.n.args[i], v.depth + 1})
		}
	}
	return nil
}
