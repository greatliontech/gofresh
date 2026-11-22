package runtimeinput

import "testing"

func TestSupportOwnsItsSubjectsAndRequiresPremises(t *testing.T) {
	binding := bindOutcome(new(outcomeSpan), "worker", "environment", "", "")
	for _, invalid := range []struct {
		binding  OutcomeBinding
		subjects []string
	}{
		{OutcomeBinding{}, []string{"subject"}},
		{bindOutcome(nil, "worker", "", "", ""), []string{"subject"}},
		{bindOutcome(new(outcomeSpan), "", "", "", ""), []string{"subject"}},
		{binding, nil},
	} {
		prepared := PrepareOutcomeSupport(invalid.binding, invalid.subjects, "")
		if got := prepared.Reason(invalid.binding); got == "" || len(prepared.Subjects()) != 0 {
			t.Fatal("missing premise produced support")
		}
	}
	subjects := []string{"b", "a", "b"}
	support := PrepareOutcomeSupport(binding, subjects, "")
	subjects[0] = "changed"
	got := support.Subjects()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("owned subject set = %v", got)
	}
	if got := support.Reason(binding); got != "" {
		t.Fatalf("supported binding refused: %q", got)
	}
	if got := support.Reason(bindOutcome(new(outcomeSpan), "worker", "environment", "", "")); got == "" {
		t.Fatal("mismatched binding accepted")
	}
	if got := PrepareOutcomeSupport(binding, []string{"a"}, "unsupported operation").Reason(binding); got != "unsupported operation" {
		t.Fatalf("lost refusal: %q", got)
	}
}
