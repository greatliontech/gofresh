package bitrelation

import "context"

// Assignment supplies a value for one exact typed variable. Duplicate entries,
// non-variable handles, missing variables and out-of-range values refuse.
type Assignment struct {
	Variable Term
	Value    uint64
}
type variableKey struct {
	scope   Scope
	slot    uint64
	scratch bool
	sort    Sort
}

func varKey(n *node) variableKey { return variableKey{n.scope, n.imm, n.scratch, n.sort} }

// Eval evaluates a pure expression exactly. It is a diagnostic/testing operation,
// never a proof from samples. It owns a copy of assignments before calling context.
func Eval(ctx context.Context, t Term, assignments []Assignment, limits Limits) (uint64, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return 0, err
	}
	if ctx == nil {
		return 0, refuse(Malformed, "invalid context")
	}
	if len(assignments) > limits.Nodes {
		return 0, refuse(Budget, "assignment budget")
	}
	owned := append([]Assignment(nil), assignments...)
	m, err := newMeter(ctx, limits)
	if err != nil {
		return 0, err
	}
	if err = graph(m, []Term{t}); err != nil {
		return 0, err
	}
	values := make(map[variableKey]uint64, len(owned))
	for _, a := range owned {
		n := a.Variable.n
		if n == nil || n.op != Variable || n.sort.IsBool() && a.Value > 1 || !n.sort.IsBool() && a.Value & ^mask(n.sort.width) != 0 {
			return 0, refuse(Malformed, "invalid assignment")
		}
		k := varKey(n)
		if _, ok := values[k]; ok {
			return 0, refuse(Malformed, "duplicate assignment")
		}
		values[k] = a.Value
	}
	cache := make(map[*node]uint64)
	var eval func(*node) (uint64, error)
	eval = func(n *node) (uint64, error) {
		if err := m.tick(); err != nil {
			return 0, err
		}
		if v, ok := cache[n]; ok {
			return v, nil
		}
		if n.op == Variable {
			v, ok := values[varKey(n)]
			if !ok {
				return 0, refuse(Malformed, "missing variable assignment")
			}
			cache[n] = v
			return v, nil
		}
		var args [3]uint64
		for i := 0; i < int(n.arity); i++ {
			var err error
			args[i], err = eval(n.args[i])
			if err != nil {
				return 0, err
			}
		}
		v := primitive(n, args)
		cache[n] = v
		return v, nil
	}
	v, err := eval(t.n)
	if err != nil {
		return 0, err
	}
	if err = m.tick(); err != nil {
		return 0, err
	}
	return v, nil
}
