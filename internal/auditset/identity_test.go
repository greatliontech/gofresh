package auditset

import (
	"slices"
	"testing"
)

func TestIdentityCoversAdmissionInventories(t *testing.T) {
	base := Identity()
	for _, table := range []map[string]bool{purePackages, reflectImmutableTypes, symbolTables["reflect"]} {
		defer delete(table, "identity-test")
		table["identity-test"] = true
		changed := Identity()
		delete(table, "identity-test")
		if changed == base || Identity() != base {
			t.Fatal("admission membership did not key its identity")
		}
	}
	for _, table := range []map[string][]string{syncMethods, poolMethods, memoMethods, timeMethods, reflectMethods} {
		defer delete(table, "identity-test")
		table["identity-test"] = []string{"Second", "First"}
		changed := Identity()
		slices.Reverse(table["identity-test"])
		if Identity() != changed {
			t.Fatal("method ordering changed membership identity")
		}
		delete(table, "identity-test")
		if changed == base || Identity() != base {
			t.Fatal("receiver membership did not key its identity")
		}
	}
}
