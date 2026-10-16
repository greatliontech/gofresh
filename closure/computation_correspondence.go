package closure

import (
	"context"
	"fmt"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// computationScalarLocation maps one complete source scalar, in declaration
// order, to exactly one native interval. Boolean storage is canonical one-byte
// 0/1; integers retain their exact-width bit pattern, including signed values.
type computationScalarLocation struct {
	register      nativeproof.Register
	offset, width int
}

// computationCorrespondence is pass-local subordinate evidence, never a runtime
// grant. The source owner is an identity token; interpretation uses the frozen
// source relation. The native relation owns its inspected image and mandatory
// effect/frame certificate. No caller-authored expected output is accepted.
//
// Source/build-to-artifact provenance and closing are still executor obligations:
// composing these local facts does not authenticate their common production.
type computationCorrespondence struct {
	source             *computationRelation
	native             nativeproof.Relation
	arguments, results []computationScalarLocation
	equalities         []bitrelation.Witness
	rules              string
	open               computationCorrespondenceObligations
}

type computationCorrespondenceObligations struct {
	initialization, harness, actualUse, applicability, sourceArtifactSpan bool
}

// A failed equality retains the independent immutable endpoints for diagnosis,
// without manufacturing partial correspondence evidence.
type computationCorrespondenceEqualityRefusal struct {
	result         int
	source, native bitrelation.Term
	cause          error
}

func (r *computationCorrespondenceEqualityRefusal) Error() string {
	return fmt.Sprintf("correspondence equality %d: %v", r.result, r.cause)
}

func (r *computationCorrespondenceEqualityRefusal) Unwrap() error { return r.cause }

// deriveComputationCorrespondence owns the scalar namespace and independently
// derives both endpoints. Maps and the opaque image container are captured before
// context callbacks. Source is the owner's selected loader graph, not a public
// editable proposal; it must remain under that owner's control during derivation.
func deriveComputationCorrespondence(ctx context.Context, source computationSource, root *ssa.Function, image *nativeproof.Image, entry uint64, face nativeproof.Interface, arguments, results []computationScalarLocation) (*computationCorrespondence, error) {
	// A valid nonoverlapping interface cannot contain more intervals than bits.
	if len(arguments) > 1024 || len(results) > 1024 || image == nil {
		return nil, fmt.Errorf("correspondence: missing image or oversized mapping")
	}
	ownedImage := *image
	arguments, results = slices.Clone(arguments), slices.Clone(results)
	if source.prog == nil || root == nil || root.Prog != source.prog.Prog || root.Pkg == nil {
		return nil, fmt.Errorf("correspondence: root is not owned by selected source")
	}
	if len(arguments) != len(root.Params) || len(results) != root.Signature.Results().Len() || len(results) == 0 {
		return nil, fmt.Errorf("correspondence: exact scalar arity required")
	}
	var parameterTypes []computationRelationType
	for _, p := range source.prog.Pkgs {
		if p != nil && p.Types == root.Pkg.Pkg && p.TypesSizes != nil {
			for _, param := range root.Params {
				parameterTypes = append(parameterTypes, computationRelationTypeOf(param.Type(), p.TypesSizes))
			}
			break
		}
	}
	if len(parameterTypes) != len(arguments) {
		return nil, fmt.Errorf("correspondence: selected input type metadata absent")
	}
	builder := bitrelation.NewBuilder(0)
	scope := bitrelation.NewScope()
	inputs := make([]bitrelation.Term, len(arguments))
	nativeInputs := make([]nativeproof.InputBinding, len(arguments))
	var inputMask nativeproof.Masks
	for i, location := range arguments {
		if err := correspondenceLocation(parameterTypes[i], location, &inputMask); err != nil {
			return nil, fmt.Errorf("correspondence argument %d: %w", i, err)
		}
		input, err := builder.Input(parameterTypes[i].sort, scope, uint64(i))
		if err != nil {
			return nil, err
		}
		inputs[i] = input
		storage, err := correspondenceStorage(builder, parameterTypes[i], input)
		if err != nil {
			return nil, err
		}
		nativeInputs[i] = nativeproof.InputBinding{Register: location.register, Offset: location.offset, Value: storage}
	}
	if inputMask != face.Inputs {
		return nil, fmt.Errorf("correspondence: input mapping differs from conditional interface")
	}
	local, err := deriveComputationRelation(ctx, source, root, scope, inputs, computationRelationLimits{})
	if err != nil {
		return nil, fmt.Errorf("correspondence source: %w", err)
	}
	if local.owner != source.prog || local.rules != computationRelationRules || len(local.outputs) != len(results) || len(local.root.results) != len(results) || len(local.root.parameters) != len(arguments) {
		return nil, fmt.Errorf("correspondence: source scope or typed arity disagrees")
	}
	for i := range arguments {
		if local.inputs[i] != inputs[i] || local.root.parameters[i] != parameterTypes[i] {
			return nil, fmt.Errorf("correspondence: source formal input changed")
		}
	}
	var resultMask nativeproof.Masks
	projected := make([]bitrelation.Term, len(results))
	for i, location := range results {
		if err := correspondenceLocation(local.root.results[i], location, &resultMask); err != nil {
			return nil, fmt.Errorf("correspondence result %d: %w", i, err)
		}
		projected[i], err = correspondenceStorage(builder, local.root.results[i], local.outputs[i])
		if err != nil {
			return nil, err
		}
	}
	if resultMask != face.Results {
		return nil, fmt.Errorf("correspondence: result mapping differs from conditional interface")
	}
	native, err := nativeproof.DeriveRelation(ctx, &ownedImage, entry, face, nativeInputs, nativeproof.RelationLimits{})
	if err != nil {
		return nil, fmt.Errorf("correspondence native: %w", err)
	}
	bound, ok := native.Bound()
	if !ok || native.Rules() != nativeproof.ValueRules || bound.Rules != nativeproof.RuleModel || bound.Entry != entry || bound.Interface != face || !slices.Equal(native.Inputs(), nativeInputs) {
		return nil, fmt.Errorf("correspondence: native effect/frame scope or inputs disagree")
	}
	outputs := native.Results()
	if len(outputs) != len(results) {
		return nil, fmt.Errorf("correspondence: native result interval arity disagrees")
	}
	witnesses := make([]bitrelation.Witness, len(results))
	for i, output := range outputs {
		location := results[i]
		if output.Register != location.register || output.Offset != location.offset || output.Value.Sort() != bitrelation.Bits(location.width) {
			return nil, fmt.Errorf("correspondence: native result %d order, offset or width disagrees", i)
		}
		witnesses[i], err = bitrelation.Prove(ctx, projected[i], output.Value, bitrelation.Limits{})
		if err != nil {
			return nil, &computationCorrespondenceEqualityRefusal{result: i, source: projected[i], native: output.Value, cause: err}
		}
	}
	return &computationCorrespondence{source: local, native: native, arguments: arguments, results: results, equalities: witnesses,
		rules: computationRelationRules + ";" + nativeproof.ValueRules,
		open:  computationCorrespondenceObligations{true, true, true, true, true}}, nil
}

func correspondenceLocation(typ computationRelationType, location computationScalarLocation, covered *nativeproof.Masks) error {
	width := typ.sort.Width()
	if typ.sort.IsBool() {
		width = 8
	}
	if width == 0 || location.width != width || location.register > nativeproof.R15 || location.offset < 0 || location.offset > 64-width {
		return fmt.Errorf("typed scalar width or register interval disagrees")
	}
	mask := (^uint64(0) >> (64 - width)) << location.offset
	if covered[location.register]&mask != 0 {
		return fmt.Errorf("overlapping scalar intervals")
	}
	covered[location.register] |= mask
	return nil
}

func correspondenceStorage(builder *bitrelation.Builder, typ computationRelationType, value bitrelation.Term) (bitrelation.Term, error) {
	if !value.Valid() || value.Sort() != typ.sort {
		return bitrelation.Term{}, fmt.Errorf("correspondence: source value disagrees with selected type")
	}
	if typ.sort.IsBool() {
		return builder.Make(bitrelation.BoolToBits, bitrelation.Bits(8), 0, value)
	}
	if typ.sort.Width() == 0 {
		return bitrelation.Term{}, fmt.Errorf("correspondence: unsupported scalar storage")
	}
	return value, nil
}
