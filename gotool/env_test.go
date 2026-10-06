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

// UnsetEnv removes every entry under the key as the policy judges keys
// and keeps the rest in order — SetEnv's exact inverse, so setting then
// unsetting a key returns the environment less that key, and unsetting
// an absent key changes nothing (REQ-fresh-go-command-policy).
func TestUnsetEnvRemovesEveryEntryUnderTheKey(t *testing.T) {
	env := []string{"A=1", "B=2", "a=3", "C=4"}
	got := UnsetEnv(env, "A")
	want := []string{"B=2", "a=3", "C=4"}
	if len(got) != len(want) {
		t.Fatalf("UnsetEnv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("UnsetEnv = %v, want %v", got, want)
		}
	}
	if same := UnsetEnv(env, "ZZ"); len(same) != len(env) {
		t.Fatalf("an absent key changed the environment: %v", same)
	}
	set := SetEnv(env, "B", "9")
	back := UnsetEnv(set, "B")
	if len(back) != 3 || back[0] != "A=1" || back[1] != "a=3" || back[2] != "C=4" {
		t.Fatalf("set then unset = %v, want the environment less B", back)
	}
}
