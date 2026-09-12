package gotool

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestForCommandDerivesPWDFromWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := EnvForCommand([]string{"PATH=/bin", "PWD=/wrong"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	pwd, ok := LookupEnv(got, "PWD")
	if !ok || pwd != filepath.Clean(dir) {
		t.Fatalf("PWD = %q/%v, want %s", pwd, ok, dir)
	}
}

func TestForCommandPreservesPWDWithoutWorkingDirectory(t *testing.T) {
	got, err := EnvForCommand([]string{"PATH=/bin", "PWD=/caller/path"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pwd, ok := LookupEnv(got, "PWD"); !ok || pwd != "/caller/path" {
		t.Fatalf("PWD = %q/%v, want caller value", pwd, ok)
	}
}

func TestForGoPackagesDisablesExternalDrivers(t *testing.T) {
	for _, env := range [][]string{
		{"PATH=/bin"},
		{"PATH=/bin", "GOPACKAGESDRIVER="},
		{"PATH=/bin", "gopackagesdriver=off"},
	} {
		got, err := EnvForPackages(env)
		if err != nil {
			t.Fatal(err)
		}
		if driver, ok := LookupEnv(got, "GOPACKAGESDRIVER"); !ok || driver != "off" {
			t.Fatalf("EnvForPackages(%v) GOPACKAGESDRIVER = %q/%v, want off", env, driver, ok)
		}
		foundCanonical := false
		for _, entry := range got {
			foundCanonical = foundCanonical || entry == "GOPACKAGESDRIVER=off"
		}
		if !foundCanonical {
			t.Fatalf("EnvForPackages(%v) = %v, missing canonical safety pin", env, got)
		}
	}
	if _, err := EnvForPackages([]string{"PATH=/bin", "GOPACKAGESDRIVER=custom"}); err == nil {
		t.Fatal("external package driver accepted")
	}
}

// A duplicate key is refused, never resolved by first- or last-entry
// platform behaviour: the policy's environment is one binding per key.
func TestNormalizeEnvRefusesDuplicateKeys(t *testing.T) {
	if _, err := NormalizeEnv([]string{"A=1", "B=2", "A=3"}); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
	if _, err := EnvForCommand([]string{"PWD=/x", "PWD=/y"}, ""); err == nil {
		t.Fatal("duplicate PWD accepted through EnvForCommand")
	}
}
