package processenv

import (
	"path/filepath"
	"testing"
)

func TestForCommandDerivesPWDFromWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := ForCommand([]string{"PATH=/bin", "PWD=/wrong"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	pwd, ok := Lookup(got, "PWD")
	if !ok || pwd != filepath.Clean(dir) {
		t.Fatalf("PWD = %q/%v, want %s", pwd, ok, dir)
	}
}

func TestForCommandPreservesPWDWithoutWorkingDirectory(t *testing.T) {
	got, err := ForCommand([]string{"PATH=/bin", "PWD=/caller/path"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pwd, ok := Lookup(got, "PWD"); !ok || pwd != "/caller/path" {
		t.Fatalf("PWD = %q/%v, want caller value", pwd, ok)
	}
}

func TestForGoPackagesDisablesExternalDrivers(t *testing.T) {
	for _, env := range [][]string{
		{"PATH=/bin"},
		{"PATH=/bin", "GOPACKAGESDRIVER="},
		{"PATH=/bin", "gopackagesdriver=off"},
	} {
		got, err := ForGoPackages(env)
		if err != nil {
			t.Fatal(err)
		}
		if driver, ok := Lookup(got, "GOPACKAGESDRIVER"); !ok || driver != "off" {
			t.Fatalf("ForGoPackages(%v) GOPACKAGESDRIVER = %q/%v, want off", env, driver, ok)
		}
		foundCanonical := false
		for _, entry := range got {
			foundCanonical = foundCanonical || entry == "GOPACKAGESDRIVER=off"
		}
		if !foundCanonical {
			t.Fatalf("ForGoPackages(%v) = %v, missing canonical safety pin", env, got)
		}
	}
	if _, err := ForGoPackages([]string{"PATH=/bin", "GOPACKAGESDRIVER=custom"}); err == nil {
		t.Fatal("external package driver accepted")
	}
}
