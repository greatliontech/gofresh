package render

import "testing"

// CappedList shows every name up to the cap and folds the remainder
// into a count exactly when there is one: at the cap itself nothing is
// folded, one past it one is.
func TestCappedListFoldsOnlyPastTheCap(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}
	cases := []struct {
		n    int
		want string
	}{
		{0, ""},
		{1, "a"},
		{ListCap - 1, "a, b"},
		{ListCap, "a, b, c"},
		{ListCap + 1, "a, b, c, and 1 more"},
		{ListCap + 2, "a, b, c, and 2 more"},
	}
	for _, c := range cases {
		if got := CappedList(names[:c.n]); got != c.want {
			t.Errorf("CappedList(%d names) = %q, want %q", c.n, got, c.want)
		}
	}
}
