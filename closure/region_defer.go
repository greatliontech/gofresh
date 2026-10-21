package closure

import (
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// Unknown entry may itself be a deferred invocation during an outer panic.
// A fresh local stack therefore establishes nothing about recover's outcome.
type regionUnwindScope uint8

const (
	regionUnknownUnwind regionUnwindScope = iota
	regionNoActiveUnwind
)

type regionDeferStack struct {
	known    bool
	captures []regionDeferredCall
}

// Captures are immutable language values. Pointer and closure-cell identities
// refer to the current shared heap, never a registration-time copy of it.
type regionDeferredCall struct {
	site         *ssa.Defer
	registration regionEffectOccurrence
	callable     regionValue
	arguments    []regionValue
}

func (m *regionMeter) copyDefers(s regionDeferStack) (regionDeferStack, error) {
	if len(s.captures) > m.limits.nodes {
		return regionDeferStack{}, regionError("defer stack budget exhausted")
	}
	s.captures = slices.Clone(s.captures)
	for i := range s.captures {
		c := &s.captures[i]
		if len(c.arguments) > m.limits.locations {
			return regionDeferStack{}, regionError("deferred argument budget exhausted")
		}
		var err error
		c.callable, err = m.copyValue(c.callable, 0)
		if err != nil {
			return regionDeferStack{}, err
		}
		c.arguments = slices.Clone(c.arguments)
		for j := range c.arguments {
			c.arguments[j], err = m.copyValue(c.arguments[j], 0)
			if err != nil {
				return regionDeferStack{}, err
			}
		}
	}
	return s, nil
}

// Control shapes cannot widen to unknown: that would erase pending execution.
// Requiring exact captures also preserves their relation to each whole heap.
func (k *regionKernel) sameDefers(a, b regionDeferStack) (bool, error) {
	if a.known != b.known || len(a.captures) != len(b.captures) {
		return false, nil
	}
	for i, x := range a.captures {
		y := b.captures[i]
		if err := k.chargeValue(x.callable); err != nil {
			return false, err
		}
		if x.site != y.site || x.registration != y.registration || !regionSameValue(x.callable, y.callable) || len(x.arguments) != len(y.arguments) {
			return false, nil
		}
		for j, v := range x.arguments {
			if err := k.chargeValue(v); err != nil {
				return false, err
			}
			if !regionSameValue(v, y.arguments[j]) {
				return false, nil
			}
		}
	}
	return true, nil
}

func (k *regionKernel) validateDefers(s regionDeferStack) error {
	if !s.known && len(s.captures) != 0 || len(s.captures) > k.meter.limits.nodes {
		return regionError("invalid pending defer stack")
	}
	seen := map[*ssa.Defer]bool{}
	for _, c := range s.captures {
		// A retained local-stack premise cannot retarget an actual registration
		// on another frame, even when entry is after the registration itself.
		if c.site != nil && c.site.DeferStack != nil {
			return regionError("alternate defer stack has no checked target provenance")
		}
		if c.site == nil || c.site.Parent() != k.input.root || c.site.Block() == nil || !slices.Contains(c.site.Block().Instrs, ssa.Instruction(c.site)) || seen[c.site] || k.cycle[c.site.Block()] || c.registration.instruction != c.site || c.registration.invocation != k.invocation {
			return regionError("defer capture lacks its actual registration")
		}
		seen[c.site] = true
		if err := k.validateValue(c.callable, 0); err != nil {
			return err
		}
		args := c.site.Common().Args
		offset := 0
		if c.site.Common().IsInvoke() {
			offset = 1
		}
		if len(c.arguments) != len(args)+offset {
			return regionError("defer capture argument count differs")
		}
		for i, v := range c.arguments {
			if err := k.validateValue(v, 0); err != nil {
				return err
			}
			if i >= offset && !types.Identical(v.typ, args[i-offset].Type()) {
				return regionError("defer capture argument type differs")
			}
		}
	}
	return nil
}

func (k *regionKernel) registerDefer(s *regionState, site *ssa.Defer) error {
	registration := k.current
	if k.trace == nil {
		registration = regionEffectOccurrence{instruction: site, invocation: k.invocation}
	}
	return k.registerDeferOccurrence(s, site, registration)
}

// registerDeferOccurrence shares capture semantics with outcome execution, whose
// occurrence ledger does not carry strict/native effect-trace authority.
func (k *regionKernel) registerDeferOccurrence(s *regionState, site *ssa.Defer, registration regionEffectOccurrence) error {
	if registration.instruction != site || registration.invocation != k.invocation {
		return regionError("defer registration occurrence differs")
	}
	if site.DeferStack != nil {
		return regionError("alternate defer stack has no checked target provenance")
	}
	if k.input.normalReturns || !s.pending.known || k.cycle[site.Block()] || k.session.contexts[k.invocation].repeated {
		return regionError("defer registration lacks bounded known activation control")
	}
	for _, c := range s.pending.captures {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if c.site == site {
			return regionError("recurrent defer registration")
		}
	}
	if len(s.pending.captures) >= k.meter.limits.nodes {
		return regionError("defer stack budget exhausted")
	}
	callable, actual, err := k.callOperands(site, *s)
	if err != nil {
		return err
	}
	// Price the new immutable spine and argument container before allocating.
	k.meter.locations += len(s.pending.captures) + len(actual) + 1
	if k.meter.locations > k.meter.limits.locations {
		return regionError("defer capture storage budget exhausted")
	}
	s.pending.captures = append(slices.Clone(s.pending.captures), regionDeferredCall{site, registration, callable, actual})
	return nil
}

func (k *regionKernel) drainDefers(s regionState, site *ssa.RunDefers) ([]regionState, error) {
	if k.input.normalReturns || !s.pending.known || k.cycle[site.Block()] || k.session.contexts[k.invocation].repeated {
		return nil, regionError("defer drain lacks bounded known activation control")
	}
	states := []regionState{s}
	for remaining := len(s.pending.captures); remaining > 0; remaining-- {
		var next []regionState
		for _, state := range states {
			if err := k.meter.tick(); err != nil {
				return nil, err
			}
			capture := state.pending.captures[remaining-1]
			// Pop before dispatch; the parent remainder stays suspended and rooted.
			state.pending.captures = state.pending.captures[:remaining-1]
			outcomes, err := k.invoke(capture.site, state, capture.callable, capture.arguments, &capture, site)
			if err != nil {
				return nil, err
			}
			for _, outcome := range outcomes {
				next, _, err = k.join(next, outcome)
				if err != nil {
					return nil, err
				}
			}
		}
		states = next
	}
	return states, nil
}

func regionInvocationResult(call ssa.CallInstruction) types.Type {
	results := call.Common().Signature().Results()
	if results.Len() == 1 {
		return results.At(0).Type()
	}
	return results
}

// Existing native/reference relations have no deferred-control or unwind model.
// They must not infer applicability from final heap agreement alone.
func regionNativeControl(packet *checkedRegion) error {
	if packet == nil || packet.input.unwind != regionUnknownUnwind || packet.input.pendingAntecedent || len(packet.input.initial.pending.captures) != 0 {
		return regionError("native consumer cannot account for source control antecedents")
	}
	for _, out := range packet.observations {
		if len(out.state.pending.captures) != 0 {
			return regionError("native consumer cannot account for pending defers")
		}
	}
	return regionNativeTraceControl(packet.trace)
}

func regionNativeTraceControl(trace *regionEffectTrace) error {
	if trace == nil {
		return regionError("native consumer lacks complete source effects")
	}
	for _, occurrence := range trace.instructions {
		switch x := occurrence.instruction.(type) {
		case *ssa.Defer, *ssa.RunDefers, *ssa.MakeClosure, *ssa.MakeInterface, *ssa.ChangeInterface:
			return regionError("native consumer cannot account for deferred or callable source control")
		case *ssa.Call:
			if b, ok := x.Call.Value.(*ssa.Builtin); ok && b.Name() == "recover" {
				return regionError("native consumer cannot account for recover")
			}
			if x.Call.IsInvoke() || x.Call.StaticCallee() == nil {
				if _, builtin := x.Call.Value.(*ssa.Builtin); !builtin {
					return regionError("native consumer cannot account for dynamic source call")
				}
			}
		}
	}
	return nil
}
