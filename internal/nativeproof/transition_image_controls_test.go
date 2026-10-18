package nativeproof

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Supply an otherwise complete candidate independently of the refusing proposer.
// Both the old unsupported cut and the following mapped instruction have their
// actual lengths validated before any negative result is accepted.
func assertCPUQueryExecutionRefused(t testing.TB, im *Image, face TransitionInterface, prefix TransitionProposal, prior TransitionCertificate) {
	t.Helper()
	boundary := prior.checked.bound.Boundary
	if boundary.PC != prefix.Cut || !bytes.Equal(boundary.Bytes, []byte{0x0f, 0xa2}) {
		t.Fatal("control is not the checked, unexecuted CPUID")
	}
	next := boundary.PC + 2
	raw, err := im.instructionBytes(next)
	if err != nil {
		t.Fatal("following boundary must be mapped", err)
	}
	instruction, valid := cutReference(raw)
	if !valid || instruction.Len <= 0 {
		t.Fatal("following boundary must independently decode")
	}
	attempt := lifecycleProposal(prefix)
	attempt.Cut = next
	found := false
	for j := range attempt.Nodes {
		if attempt.Nodes[j].PC == boundary.PC {
			if attempt.Nodes[j].Size != 2 || len(attempt.Nodes[j].Successors) != 0 {
				t.Fatal("old cut inventory differs")
			}
			attempt.Nodes[j].Successors = []uint64{next}
			found = true
		}
	}
	if !found {
		t.Fatal("missing old cut")
	}
	attempt.Nodes = append(attempt.Nodes, Node{PC: next, Size: uint8(instruction.Len)})
	proposed, err := ProposeTransition(t.Context(), im, next, TransitionLimits{})
	var refusal *Refusal
	if !reflect.DeepEqual(proposed, TransitionProposal{}) || !errors.As(err, &refusal) || refusal.Premise != "transition-form" || refusal.PC != boundary.PC {
		t.Fatal("proposer did not refuse CPUID specifically", err)
	}
	direct, err := CheckTransition(t.Context(), im, face, attempt, TransitionLimits{})
	sequenceRefused(t, direct, err, "transition-form", boundary.PC)
	continued, err := CheckTransitionContinuation(t.Context(), prior, attempt)
	sequenceRefused(t, continued, err, "transition-form", boundary.PC)
}

// Each negative removes exactly one premise from a successful full interface.
// In particular, the narrow envelope retains the adequate S bound and image
// footprint; absence of permission is tested with the broad envelope intact.
func assertImagePrefixMissingPremises(t testing.TB, im *Image, face TransitionInterface, proposal TransitionProposal, ripPC uint64) {
	t.Helper()
	raw, err := im.instructionBytes(ripPC)
	if err != nil {
		t.Fatal(err)
	}
	rip, err := to.Parse(raw, ripPC)
	if err != nil || rip.Intent.Operation != to.LEARIP {
		t.Fatal("RIP control", err)
	}
	raw, err = im.instructionBytes(rip.Next)
	if err != nil {
		t.Fatal(err)
	}
	stack, err := to.Parse(raw, rip.Next)
	if err != nil || stack.Intent.Operation != to.LEA || stack.Intent.Base != 4 || stack.Intent.SignedDisp != -65536 {
		t.Fatal("stack LEA control", err)
	}
	for _, kind := range []string{"envelope", "permission"} {
		bad := cloneTransitionInterface(face)
		pc, premise := rip.Next, "transition-envelope"
		if kind == "envelope" {
			bad.Envelope.Start = -48
		} else {
			bad.ImageRegions = nil
			pc, premise = stack.Next, "transition-permission"
		}
		root := continuationRoot(t, im, ripPC, bad, TransitionLimits{})
		direct, err := CheckTransition(t.Context(), im, bad, proposal, TransitionLimits{})
		sequenceRefused(t, direct, err, premise, pc)
		continued, err := CheckTransitionContinuation(t.Context(), root, proposal)
		sequenceRefused(t, continued, err, premise, pc)
	}
}
