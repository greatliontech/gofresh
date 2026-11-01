package testenv

import (
	"reflect"
	"slices"
	"testing"
)

// AssertAllFieldsPopulated reflects over every field of struct T (or *T) and
// fails the test if any field not named in exempt has its zero value. Use this
// in clone, round-trip, and copy tests to guarantee that newly added struct
// fields are exercised without manual test maintenance.
func AssertAllFieldsPopulated[T any](t testing.TB, v T, exempt ...string) {
	t.Helper()
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			t.Fatalf("AssertAllFieldsPopulated(%T): nil pointer", v)
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		t.Fatalf("AssertAllFieldsPopulated(%T): expected struct, got %s", v, rv.Kind())
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if slices.Contains(exempt, field.Name) {
			continue
		}
		if rv.Field(i).IsZero() {
			t.Fatalf("%s.%s is zero-valued (populate it in the test fixture or add %q to exempt)", rt.Name(), field.Name, field.Name)
		}
	}
}
