package closure

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/greatliontech/gofresh/internal/nativeproof"
)

const callbackCallEntry = uint64(0x401000)
const callbackDescriptor = callbackCallEntry + 0x20
const callbackCallee = callbackCallEntry + 0x40

func computationCallbackImage(t *testing.T, target string) *nativeproof.Image {
	return computationCallbackImageWithFragment(t, "488b0a488b442410ffd1c3", target)
}

func computationCallbackImageWithFragment(t *testing.T, fragmentCode, target string) *nativeproof.Image {
	t.Helper()
	code := make([]byte, 0x51)
	fragment, err := hex.DecodeString(fragmentCode)
	if err != nil {
		t.Fatal(err)
	}
	copy(code, fragment)
	binary.LittleEndian.PutUint64(code[0x20:], callbackCallee)
	binary.LittleEndian.PutUint64(code[0x28:], callbackCallEntry+0x50)
	callee, err := hex.DecodeString(target)
	if err != nil {
		t.Fatal(err)
	}
	copy(code[0x40:], callee)
	code[0x50] = 0xc3
	return correspondenceImage(t, hex.EncodeToString(code))
}

func callbackRequest(results []computationScalarLocation) computationCallbackRequest {
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	face := correspondenceFace(args, results)
	return computationCallbackRequest{
		calleeEntry: callbackCallee, descriptor: callbackDescriptor, callEntry: callbackCallEntry, continuation: callbackCallEntry + 10,
		callee: face, arguments: args, results: results,
		descriptorConditions: nativeproof.DescriptorConditions{Machine: nativeproof.MachineModel, ReadonlyMapping: true},
		call: nativeproof.CallInterface{
			DescriptorRegister: nativeproof.RDX, ContextRegister: nativeproof.RDX,
			Arguments: []nativeproof.ArgumentTransfer{{From: nativeproof.Location{Kind: nativeproof.EntryStackWord, Offset: 16}, To: nativeproof.RAX, Bits: math.MaxUint64}},
			Results:   face.Results, Preserved: face.Preserved,
			Conditions: nativeproof.CallConditions{Machine: nativeproof.MachineModel, InstructionMapping: true, IsolatedInvocation: true, EntryState: true,
				Stack: nativeproof.CallStack{Pointer: 0x70000000, Region: nativeproof.Span{Start: 0x6ffff000, End: 0x70001000}, Readable: true, Writable: true, Protected: true, NoAliases: true}},
		},
	}
}

func assertCallbackOpen(t testing.TB, c *computationCallbackAssembly) {
	t.Helper()
	if c == nil || c.correspondence == nil || c.open != (computationCallbackObligations{true, true, true, true}) ||
		c.correspondence.open != (computationCorrespondenceObligations{true, true, true, true, true}) ||
		c.correspondence.source.open != (computationRelationObligations{true, true, true, true, true}) {
		t.Fatal("local callback assembly lost surrounding obligations")
	}
	b, ok := c.transfer.Bound()
	if !ok || !b.Interface.Conditions.IsolatedInvocation || !b.Interface.Conditions.EntryState || !b.Interface.Conditions.Stack.Protected || !b.Interface.Conditions.Stack.Writable || !b.Descriptor.Conditions.ReadonlyMapping {
		t.Fatal("local callback assembly lost conditional machine/frame/provenance premises")
	}
}

func TestComputationCallbackAssembly(t *testing.T) {
	for _, tc := range []struct {
		name, source, code string
		results            []computationScalarLocation
	}{
		{"void", "func F(p *int){}", "c3", nil},
		{"scalar", "func F(x uint64)uint64{return x+1}", "4883c001c3", []computationScalarLocation{{nativeproof.RAX, 0, 64}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.source, 64)
			image := computationCallbackImage(t, tc.code)
			request := callbackRequest(tc.results)
			c, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], image, request)
			if err != nil {
				t.Fatal(err)
			}
			assertCallbackOpen(t, c)
			requireCorrespondenceWitnesses(t, c.correspondence, len(tc.results))
			body, _ := c.correspondence.native.Bound()
			call, _ := c.transfer.Bound()
			if !reflect.DeepEqual(body, call.Descriptor.Target) || call.Call != callbackCallEntry+8 || call.Continuation.Span.Start != request.continuation || call.Interface.Results != request.callee.Results {
				t.Fatal("composed target/interface/continuation differs")
			}
			// This is an opaque checked handle, not a reconstruction from Bound.
			effects := c.correspondence.native.Effects()
			d, err := nativeproof.CheckDescriptor(t.Context(), image, request.descriptor, effects, request.descriptorConditions)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := d.Bound(); !ok {
				t.Fatal("relation lost its checked effect certificate")
			}
		})
	}
	if _, ok := (nativeproof.Relation{}).Effects().Bound(); ok {
		t.Fatal("zero relation manufactured effect evidence")
	}
}

func TestComputationCallbackAssemblyRefusals(t *testing.T) {
	source := relationFixture(t, "func F(p *int){}", 64)
	image := computationCallbackImage(t, "c3")
	for _, tc := range []struct {
		name   string
		change func(*computationCallbackRequest)
	}{
		{"alternate-descriptor", func(r *computationCallbackRequest) { r.descriptor += 8 }},
		{"alternate-callee", func(r *computationCallbackRequest) { r.calleeEntry = callbackCallEntry + 0x50 }},
		{"argument-location", func(r *computationCallbackRequest) { r.call.Arguments[0].To = nativeproof.RBX }},
		{"argument-width", func(r *computationCallbackRequest) { r.call.Arguments[0].Bits = 0xffffffff }},
		{"argument-origin", func(r *computationCallbackRequest) {
			r.call.Arguments[0].From = nativeproof.Location{Kind: nativeproof.EntryRegister, Register: nativeproof.RAX}
		}},
		{"argument-missing", func(r *computationCallbackRequest) { r.call.Arguments = nil }},
		{"context", func(r *computationCallbackRequest) { r.call.ContextRegister = nativeproof.R8 }},
		{"descriptor-register", func(r *computationCallbackRequest) { r.call.DescriptorRegister = nativeproof.RBX }},
		{"continuation", func(r *computationCallbackRequest) { r.continuation++ }},
		{"omitted-load", func(r *computationCallbackRequest) { r.callEntry += 8 }},
		{"omitted-call", func(r *computationCallbackRequest) { r.callEntry = r.continuation }},
		{"push-slot", func(r *computationCallbackRequest) { r.call.Conditions.Stack.Writable = false }},
		{"isolation", func(r *computationCallbackRequest) { r.call.Conditions.IsolatedInvocation = false }},
		{"target-return", func(r *computationCallbackRequest) { r.callee.Conditions.ReturnSlot = false }},
		{"invented-result", func(r *computationCallbackRequest) { r.call.Results[nativeproof.RAX] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := callbackRequest(nil)
			tc.change(&r)
			if c, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], image, r); c != nil || err == nil {
				t.Fatal("invalid composition acquired evidence")
			}
		})
	}
	t.Run("weakened-scalar-result", func(t *testing.T) {
		s := relationFixture(t, "func F(x uint64)uint64{return x+1}", 64)
		r := callbackRequest([]computationScalarLocation{{nativeproof.RAX, 0, 64}})
		r.call.Results = nativeproof.Masks{}
		if c, err := deriveComputationCallback(t.Context(), s, s.prog.Roots["F"], computationCallbackImage(t, "4883c001c3"), r); c != nil || err == nil {
			t.Fatal("call projection discarded a source result")
		}
	})
	t.Run("reachable-source-effect", func(t *testing.T) {
		s := relationFixture(t, "func F(p *int){*p=7}", 64)
		if c, err := deriveComputationCallback(t.Context(), s, s.prog.Roots["F"], image, callbackRequest(nil)); c != nil || err == nil {
			t.Fatal("reachable effect used a RET candidate")
		}
	})
	t.Run("wrong-pure-computation", func(t *testing.T) {
		s := relationFixture(t, "func F(x uint64)uint64{return x+1}", 64)
		r := callbackRequest([]computationScalarLocation{{nativeproof.RAX, 0, 64}})
		if c, err := deriveComputationCallback(t.Context(), s, s.prog.Roots["F"], image, r); c != nil || err == nil {
			t.Fatal("pure identity target used for increment source")
		}
	})
}

func TestComputationCallbackCannotBorrowImageEvidence(t *testing.T) {
	source := relationFixture(t, "func F(p *int){}", 64)
	a, b := computationCallbackImage(t, "c3"), computationCallbackImage(t, "c3")
	r := callbackRequest(nil)
	first, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], a, r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], b, r)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := first.transfer.Bound()
	right, _ := second.transfer.Bound()
	if !reflect.DeepEqual(left, right) {
		t.Fatal("borrowing control requires byte-identical genuine inputs and projections")
	}
	foreign, err := nativeproof.CheckDescriptor(t.Context(), b, r.descriptor, first.correspondence.native.Effects(), r.descriptorConditions)
	if _, ok := foreign.Bound(); ok || err == nil {
		t.Fatal("matching bytes/entry/interface borrowed another image's callee evidence")
	}
	own, err := nativeproof.CheckDescriptor(t.Context(), a, r.descriptor, first.correspondence.native.Effects(), r.descriptorConditions)
	if err != nil {
		t.Fatal(err)
	}
	call, err := nativeproof.CheckCall(t.Context(), b, r.callEntry, r.continuation, own, r.call, 0)
	if _, ok := call.Bound(); ok || err == nil {
		t.Fatal("foreign descriptor borrowed for same-address CALL")
	}
	// Independent same-image derivation remains available; borrowing is the
	// rejected operation, not semantic equality of independently checked code.
	assertCallbackOpen(t, second)
}

func TestComputationCallbackFormalArgumentOrder(t *testing.T) {
	source := relationFixture(t, "func F(x,y uint64)uint64{return x}", 64)
	image := computationCallbackImageWithFragment(t, "488b0a488b442410488b5c2418ffd1c3", "c3")
	r := callbackRequest([]computationScalarLocation{{nativeproof.RAX, 0, 64}})
	r.arguments = append(r.arguments, computationScalarLocation{nativeproof.RBX, 0, 64})
	r.callee = correspondenceFace(r.arguments, r.results)
	r.call.Arguments = append(r.call.Arguments, nativeproof.ArgumentTransfer{From: nativeproof.Location{Kind: nativeproof.EntryStackWord, Offset: 24}, To: nativeproof.RBX, Bits: math.MaxUint64})
	r.continuation = callbackCallEntry + 15
	good, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], image, r)
	if err != nil {
		t.Fatal(err)
	}
	r.call.Arguments[0], r.call.Arguments[1] = r.call.Arguments[1], r.call.Arguments[0]
	// Native bit transport is order-independent. The assembly also promises
	// source-formal order: swapping these would bind returned x to stack y.
	d, err := nativeproof.CheckDescriptor(t.Context(), image, r.descriptor, good.correspondence.native.Effects(), r.descriptorConditions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativeproof.CheckCall(t.Context(), image, r.callEntry, r.continuation, d, r.call, 0); err != nil {
		t.Fatal(err)
	}
	if c, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], image, r); c != nil || err == nil {
		t.Fatal("source-formal order was replaced by native mask-set agreement")
	}
}

type callbackAssemblyContext struct {
	context.Context
	calls int
	onErr func(int)
}

func (c *callbackAssemblyContext) Err() error {
	c.calls++
	if c.onErr != nil {
		c.onErr(c.calls)
	}
	return c.Context.Err()
}

func TestComputationCallbackOwnsInputsAndCancellation(t *testing.T) {
	source := relationFixture(t, "func F(x uint64)uint64{return x+1}", 64)
	image := computationCallbackImage(t, "4883c001c3")
	request := func() computationCallbackRequest {
		return callbackRequest([]computationScalarLocation{{nativeproof.RAX, 0, 64}})
	}
	count := &callbackAssemblyContext{Context: t.Context()}
	want, err := deriveComputationCallback(count, source, source.prog.Roots["F"], image, request())
	if err != nil {
		t.Fatal(err)
	}
	wantBound, _ := want.transfer.Bound()
	for at := 1; at <= count.calls; at++ {
		supplied := *image
		r := request()
		ctx := &callbackAssemblyContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = nativeproof.Image{}
				r.arguments[0] = computationScalarLocation{}
				r.results[0] = computationScalarLocation{}
				r.call.Arguments[0].From.Offset = 9999
			}
		}}
		c, err := deriveComputationCallback(ctx, source, source.prog.Roots["F"], &supplied, r)
		if err != nil {
			t.Fatalf("ownership callback %d: %v", at, err)
		}
		b, _ := c.transfer.Bound()
		if !reflect.DeepEqual(b, wantBound) {
			t.Fatal("caller callback replaced retained inputs")
		}
		assertCallbackOpen(t, c)
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &callbackAssemblyContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		c, err = deriveComputationCallback(ctx, source, source.prog.Roots["F"], image, request())
		cancel()
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled assembly %d: %v", at, err)
		}
	}
	r := request()
	r.call.Arguments = make([]nativeproof.ArgumentTransfer, 1025)
	if c, err := deriveComputationCallback(t.Context(), source, source.prog.Roots["F"], image, r); c != nil || err == nil {
		t.Fatal("unbounded caller inventory copied")
	}
}
