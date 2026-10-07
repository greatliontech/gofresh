package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/outcome"
)

// OutcomeSupport is an opaque analysis-derived prerequisite for one execution.
// Only the analysis view constructs support; the zero value grants none.
type OutcomeSupport = outcome.Support

// CompletionReceipt records the result owner's terminal harness judgment.
// Normal completion includes ordinarily completed failing tests; it does not
// establish operation outcomes. The zero value grants no completion premise.
type CompletionReceipt struct {
	binding outcome.Binding
	reason  string
}

// Completion records the caller's verified terminal disposition for this frame,
// process and complete environment. Empty reason asserts normal completion and
// a flushed capture; a nonempty reason records abnormal or incomplete execution.
func (f ProducerFrame) Completion(process string, env []string, reason string) (CompletionReceipt, error) {
	binding, err := f.OutcomeBinding(process, env)
	if err != nil {
		return CompletionReceipt{}, err
	}
	return CompletionReceipt{binding: binding, reason: reason}, nil
}

// OutcomeBinding exposes the module-private binding used by the analysis view.
// Its value is not a support constructor; it supplies execution coordinates only.
func (f ProducerFrame) OutcomeBinding(process string, env []string) (outcome.Binding, error) {
	if err := validateProcess(process); err != nil {
		return outcome.Binding{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return outcome.Binding{}, err
	}
	// NormalizeEnv rejects NUL bytes, so this delimiter frames the original
	// bytes injectively, including Linux environment values that are not UTF-8.
	// JSON strings would replace those bytes and equate distinct executions.
	digest := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	return outcome.Binding{Span: f.span, Process: process, Environment: hex.EncodeToString(digest[:]), Root: f.Root, Directory: f.PkgDir}, nil
}

// HasOutcomeSupport reports whether a canonical manifest retains support for
// the exact recorded subject identity. Malformed and older records grant none.
func HasOutcomeSupport(encoded, subject string) bool {
	m, err := decode(encoded)
	// Canonical decoding already requires a recognized method whenever the
	// subject set is nonempty; membership is the remaining premise.
	return err == nil && slices.Contains(m.Subjects, subject)
}

func (f ProducerFrame) outcomePremise(in ProducerIngest) string {
	if in.Completion.binding.Process == "" {
		return "process completion receipt unavailable"
	}
	binding, err := f.OutcomeBinding(in.Identity, in.Env)
	if err != nil {
		return fmt.Sprintf("process binding invalid: %v", err)
	}
	if in.Completion.binding != binding {
		return "process completion receipt belongs to a different execution or environment"
	}
	if in.Completion.reason != "" {
		return in.Completion.reason
	}
	return in.Outcome.Reason(binding)
}

func environmentLog(ctx context.Context, log []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(log), "\n") {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if line == "" || line == "# test log" {
			continue
		}
		if !strings.HasPrefix(line, "getenv ") {
			return false, nil
		}
	}
	return true, nil
}
