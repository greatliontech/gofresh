package guard

import "testing"

func TestCompareFactsRetainsAxisAndMissingEvidence(t *testing.T) {
	base := Guards{Toolchain: "t", BuildConfig: "b", Machine: "m", RuntimeConfig: "r"}
	for _, tc := range []struct {
		axis Axis
		set  func(*Guards, string)
	}{
		{ToolchainAxis, func(g *Guards, s string) { g.Toolchain = s }},
		{BuildConfigAxis, func(g *Guards, s string) { g.BuildConfig = s }},
		{MachineAxis, func(g *Guards, s string) { g.Machine = s }},
		{RuntimeConfigAxis, func(g *Guards, s string) { g.RuntimeConfig = s }},
	} {
		for _, value := range []string{"", "changed"} {
			for _, producing := range []bool{true, false} {
				rec, cur := base, base
				if producing {
					tc.set(&rec, value)
				} else {
					tc.set(&cur, value)
				}
				got := CompareFacts(rec, cur, Measurement)
				want := Mismatch{Axis: tc.axis, Missing: value == ""}
				if got != want || Compare(rec, cur, Measurement) != tc.axis.String() {
					t.Fatalf("comparison = %+v, want %+v", got, want)
				}
				if tc.axis == MachineAxis || tc.axis == RuntimeConfigAxis {
					if got := CompareFacts(rec, cur, CodeResult); got != (Mismatch{}) {
						t.Fatalf("code judgment read measurement guard: %+v", got)
					}
				}
			}
		}
	}
	if got := CompareFacts(base, base, Kind(99)); got != (Mismatch{Axis: KindAxis}) {
		t.Fatalf("unsupported kind = %+v", got)
	}
	if got := CompareFacts(Guards{}, base, Measurement); got != (Mismatch{Axis: ToolchainAxis, Missing: true}) {
		t.Fatalf("first missing guard = %+v", got)
	}
}
