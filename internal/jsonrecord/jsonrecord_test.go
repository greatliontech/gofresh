package jsonrecord

import (
	"testing"
)

func TestCanonicalEqualWhitespaceModes(t *testing.T) {
	canonical := []byte(`{"a":1,"b":"x"}`)
	indented := []byte("{\n  \"a\": 1,\n  \"b\": \"x\"\n}")
	if !CanonicalEqual(canonical, indented, true) {
		t.Fatal("compacted mode rejected indented canonical object")
	}
	if CanonicalEqual(canonical, indented, false) {
		t.Fatal("raw mode accepted indented object")
	}
	if !CanonicalEqual(canonical, canonical, false) {
		t.Fatal("raw mode rejected exact canonical bytes")
	}
}
