package outcome

import "testing"

func TestSupportOwnsItsSubjectsAndRequiresPremises(t *testing.T) {
	binding := Binding{Span: new(Span), Process: "worker", Environment: "environment"}
	for _, invalid := range []struct {
		binding  Binding
		subjects []string
	}{
		{Binding{}, []string{"subject"}},
		{Binding{Process: "worker"}, []string{"subject"}},
		{Binding{Span: new(Span)}, []string{"subject"}},
		{binding, nil},
	} {
		prepared := Prepare(invalid.binding, invalid.subjects, "")
		if got := prepared.Reason(invalid.binding); got == "" || len(prepared.Subjects()) != 0 {
			t.Fatal("missing premise produced support")
		}
	}
	subjects := []string{"b", "a", "b"}
	support := Prepare(binding, subjects, "")
	subjects[0] = "changed"
	got := support.Subjects()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("owned subject set = %v", got)
	}
	if got := support.Reason(binding); got != "" {
		t.Fatalf("supported binding refused: %q", got)
	}
	if got := Prepare(binding, []string{"a"}, "unsupported operation").Reason(binding); got != "unsupported operation" {
		t.Fatalf("lost refusal: %q", got)
	}
}
