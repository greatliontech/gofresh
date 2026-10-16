package closure

import (
	"context"
	"fmt"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// computationCallbackRequest selects conditional proof coordinates and interfaces,
// not an observed invocation. call.Arguments is in source-parameter order and
// transports exactly each corresponding arguments interval; its From locations
// are the conditional incoming values for those formals. call.Results must cover
// exactly the source/native result interface, rather than a weaker projection.
type computationCallbackRequest struct {
	calleeEntry, descriptor, callEntry, continuation uint64
	callee                                           nativeproof.Interface
	arguments, results                               []computationScalarLocation
	descriptorConditions                             nativeproof.DescriptorConditions
	call                                             nativeproof.CallInterface
	callLimit                                        int
}

// computationCallbackAssembly joins checked source correspondence and actual native
// descriptor/CALL transfer over one captured image. The native relation's exact
// effect certificate is the descriptor's target; the transfer owns that descriptor
// and its dependencies. There is no second callee certificate or caller-supplied
// semantic summary to compare by name, address string or digest.
//
// The correspondence retains source scope, typed arguments/results, equality
// witnesses and its initialization/harness/actual-use/applicability/span gaps.
// The transfer retains incoming descriptor provenance, frame/isolation/stack
// premises, decoded instructions and continuation. This local assembly supplies
// no source-call/native-fragment association or ordinary-Go invocation authority.
type computationCallbackAssembly struct {
	correspondence *computationCorrespondence
	transfer       nativeproof.CallCertificate
	open           computationCallbackObligations
}

type computationCallbackObligations struct {
	registrationUse, sourceCallAssociation, ordinaryGoLifting, producingCurrentHistory bool
}

// deriveComputationCallback captures every caller-owned container before context
// callbacks, then derives all subordinate evidence itself. Cross-image evidence
// borrowing is unrepresentable in this constructor. Selected source remains under
// its loader owner's control, as required by deriveComputationCorrespondence.
// Symbol/registration metadata may propose coordinates only. In particular, a
// body equality at an alternate equivalent entry establishes no source-instance
// or registration-use coverage. Failure or cancellation returns no assembly.
func deriveComputationCallback(ctx context.Context, source computationSource, root *ssa.Function, image *nativeproof.Image, request computationCallbackRequest) (*computationCallbackAssembly, error) {
	if image == nil || len(request.arguments) > 1024 || len(request.results) > 1024 || len(request.call.Arguments) > 1024 {
		return nil, fmt.Errorf("callback: missing image or oversized argument/result inventory")
	}
	ownedImage := *image
	request.arguments = slices.Clone(request.arguments)
	request.results = slices.Clone(request.results)
	request.call.Arguments = slices.Clone(request.call.Arguments)
	if ctx == nil {
		return nil, fmt.Errorf("callback: missing context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	correspondence, err := deriveComputationCorrespondence(ctx, source, root, &ownedImage, request.calleeEntry, request.callee, request.arguments, request.results)
	if err != nil {
		return nil, fmt.Errorf("callback correspondence: %w", err)
	}
	if len(request.call.Arguments) != len(correspondence.arguments) {
		return nil, fmt.Errorf("callback: call transfer must cover each source argument exactly once")
	}
	for j, location := range correspondence.arguments {
		// Correspondence already checked the selected type, interval bounds and
		// nonoverlap. This is the exact transport projection of that same formal.
		bits := (^uint64(0) >> (64 - location.width)) << location.offset
		actual := request.call.Arguments[j]
		if actual.To != location.register || actual.Bits != bits {
			return nil, fmt.Errorf("callback: argument %d transfer differs from source/native location", j)
		}
	}
	if request.call.Results != request.callee.Results {
		return nil, fmt.Errorf("callback: call results differ from the exact source/native projection")
	}
	descriptor, err := nativeproof.CheckDescriptor(ctx, &ownedImage, request.descriptor, correspondence.native.Effects(), request.descriptorConditions)
	if err != nil {
		return nil, fmt.Errorf("callback descriptor: %w", err)
	}
	transfer, err := nativeproof.CheckCall(ctx, &ownedImage, request.callEntry, request.continuation, descriptor, request.call, request.callLimit)
	if err != nil {
		return nil, fmt.Errorf("callback transfer: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &computationCallbackAssembly{correspondence: correspondence, transfer: transfer,
		open: computationCallbackObligations{true, true, true, true}}, nil
}
