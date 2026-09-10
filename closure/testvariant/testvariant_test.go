package testvariant

import (
	"sort"
	"testing"
)

// The ledger's canonical declaration order is total and lexicographic
// over file, kind, receiver, name — the order every persisted ledger
// and every delta carries, so two ledgers of one compartment compare
// declaration by declaration.
//
//gofresh:pure
func TestLessDeclarationOrdersByFileKindReceiverName(t *testing.T) {
	decl := func(file, kind, receiver, name string) TestVariantDeclaration {
		return TestVariantDeclaration{File: file, Kind: kind, Receiver: receiver, Name: name}
	}
	want := []TestVariantDeclaration{
		decl("a_test.go", "func", "", "B"),
		decl("a_test.go", "func", "", "C"),
		decl("a_test.go", "func", "T", "A"),
		decl("a_test.go", "type", "", "A"),
		decl("b_test.go", "const", "", "A"),
	}
	got := []TestVariantDeclaration{want[4], want[3], want[2], want[1], want[0]}
	sort.Slice(got, func(i, j int) bool { return LessDeclaration(got[i], got[j]) })
	for i := range want {
		if got[i].File != want[i].File || got[i].Kind != want[i].Kind || got[i].Receiver != want[i].Receiver || got[i].Name != want[i].Name {
			t.Fatalf("position %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for i := range want {
		if LessDeclaration(want[i], want[i]) {
			t.Fatalf("a declaration ordered before itself: %+v", want[i])
		}
	}
}
