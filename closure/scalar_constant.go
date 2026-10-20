package closure

import (
	"context"
	"errors"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

var (
	errScalarConstantEndpoints = errors.New("scalar specialization proof endpoints differ")
	errScalarConstantUnknown   = errors.New("scalar specialization retains unproved arbitrary state")
)

// checkedScalarConstant obtains a candidate normal form from search, then checks
// equality at the original term and that exact constant endpoint. The caller's
// context owns cancellation and cumulative costs across subordinate proof calls.
func checkedScalarConstant(ctx context.Context, term br.Term, limits br.Limits) (uint64, error) {
	proposal, err := br.Propose(ctx, term, term, limits)
	if err != nil {
		return 0, err
	}
	for i, step := range proposal.Steps {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		v := step.Right.View()
		if step.Left != term || v.Op != br.Constant || step.Right.Sort() != term.Sort() {
			continue
		}
		w, err := br.Check(ctx, term, step.Right, br.Proof{Steps: proposal.Steps[:i+1]}, limits)
		if err != nil {
			return 0, err
		}
		left, right := w.Roots()
		if !w.Valid() || left != term || right != step.Right {
			return 0, errScalarConstantEndpoints
		}
		return v.Immediate, nil
	}
	return 0, errScalarConstantUnknown
}
